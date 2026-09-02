//! Device identity secrets and wrapping of vault epoch keys.
//!
//! Custody is fail-closed: platform store or `--passphrase`. File wrap
//! (`wrap.key`, mode 0600) is only created when the caller passes
//! `allow_file_key`. iOS never uses file wrap.

mod enroll;
mod platform;
mod recovery;
mod vault;

pub use enroll::{
    ShelfGrant, ShelfJoin, approve_join, approve_join_store, ensure_local_root, export_join,
    export_join_store, grant_sas, import_grant, import_grant_store,
};
pub use recovery::{RecoveryBundle, apply_recovery, export_recovery, export_recovery_store};
pub use vault::{
    DeviceListEntry, Vault, ensure_home_layout, list_devices_store, open_or_create_vault,
    revoke_device, revoke_device_store,
};

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use shelf_core::{
    DeviceId, DevicePublicIdentity, MlKem768PublicKey, SigningPublicKey, X25519PublicKey,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Failures loading or using a device keystore.
#[derive(Debug, Error)]
pub enum KeystoreError {
    /// Filesystem I/O.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// JSON identity file was corrupt.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// AEAD wrap/unwrap failed (wrong wrap key or corrupt blob).
    #[error("keystore wrap failed")]
    Wrap,
    /// Passphrase KDF failed.
    #[error("passphrase KDF failed")]
    Passphrase,
    /// Identity bytes were not valid key material.
    #[error("invalid key material: {0}")]
    Identity(String),
    /// No platform store, no passphrase, and file wrap is not allowed.
    #[error("no wrap-key custody: use a platform store, --passphrase, or --allow-file-key")]
    NoCustody,
    /// Enrollment request or grant signature was invalid or expired.
    #[error("enrollment signature: {0}")]
    Signature(String),
    /// Recovery bundle could not be opened (wrong passphrase or corrupt file).
    #[error("recovery bundle: wrong passphrase or corrupt file")]
    Recovery,
    /// `recovery apply` was pointed at a home that already has an identity.
    #[error("recovery apply requires an empty home (no identity.json)")]
    RecoveryHomeNotEmpty,
}

/// How the local wrap key is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Custody {
    /// 0600 file next to the vault. Hardware-backed protection is unavailable.
    File,
    /// Argon2id-wrapped wrap key (passphrase).
    Passphrase,
    /// Platform store: Keychain, Secret Service, or DPAPI.
    Platform,
}

/// Replica/metadata signer. Does not include wrap keys.
#[derive(Clone)]
pub struct DeviceSigner {
    device_id: DeviceId,
    signing: SigningKey,
    x25519: x25519_dalek::StaticSecret,
    ml_kem_dk: Vec<u8>,
    wrap_key: [u8; 32],
}

impl DeviceSigner {
    /// Device id bound into signed replica ops.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Sign `data`.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing.sign(data).to_bytes()
    }

    /// Corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> SigningPublicKey {
        SigningPublicKey::from(self.signing.verifying_key())
    }

    /// Unwrap a hybrid epoch wrap addressed to this device.
    pub fn unwrap_epoch(
        &self,
        wrap: &shelf_protocol::HybridEpochWrap,
        aad: &[u8],
    ) -> Result<[u8; 32], KeystoreError> {
        shelf_protocol::unwrap_epoch_key(wrap, &self.x25519, &self.ml_kem_dk, aad)
            .map_err(|e| KeystoreError::Identity(e.to_string()))
    }

    /// Wrap a secret under the device wrap key.
    pub fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        aead_wrap(&self.wrap_key, b"shelf/keystore/v1", secret)
    }
}

/// Verify `sig` over `msg` with `pk`.
#[must_use]
pub fn verify_signature(pk: &SigningPublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::try_from(*pk) else {
        return false;
    };
    let signature = Signature::from_bytes(sig);
    vk.verify_strict(msg, &signature).is_ok()
}

/// Opened device keystore. Secrets never appear in `Debug`.
pub struct DeviceKeystore {
    home: PathBuf,
    identity: DevicePublicIdentity,
    signing: SigningKey,
    x25519: x25519_dalek::StaticSecret,
    ml_kem_dk: Vec<u8>,
    wrap_key: [u8; 32],
    custody: Custody,
}

impl std::fmt::Debug for DeviceKeystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKeystore")
            .field("device_id", &self.identity.device_id)
            .field("custody", &self.custody)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u16,
    identity: DevicePublicIdentity,
    wrapped_secrets: Vec<u8>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SecretBlob {
    signing: [u8; 32],
    x25519: [u8; 32],
    ml_kem_dk: Vec<u8>,
}

impl DeviceKeystore {
    /// Create a new identity in `home` (or return the existing one).
    ///
    /// `allow_file_key` permits a 0600 `wrap.key` only when platform custody is
    /// unavailable. Existing file-key vaults still load without the flag.
    pub fn open_or_init(
        home: impl AsRef<Path>,
        device_name: Option<&str>,
        passphrase: Option<&str>,
        allow_file_key: bool,
    ) -> Result<Self, KeystoreError> {
        let home = home.as_ref().to_path_buf();
        crate::vault::ensure_home_layout(&home)?;
        let id_path = home.join("identity.json");
        if id_path.exists() {
            return Self::load(&home, passphrase);
        }
        Self::init(&home, device_name, passphrase, allow_file_key)
    }

    /// Load an existing identity.
    pub fn load(home: impl AsRef<Path>, passphrase: Option<&str>) -> Result<Self, KeystoreError> {
        let home = home.as_ref().to_path_buf();
        let file: IdentityFile =
            serde_json::from_str(&fs::read_to_string(home.join("identity.json"))?)?;
        let (wrap_key, custody) = load_wrap_key(&home, passphrase)?;
        let secrets = unwrap_secrets(&wrap_key, &file.wrapped_secrets)?;
        let signing = SigningKey::from_bytes(&secrets.signing);
        let x25519 = x25519_dalek::StaticSecret::from(secrets.x25519);
        let identity =
            identity_from_secrets(&file.identity, &signing, &x25519, &secrets.ml_kem_dk)?;
        Ok(Self {
            home,
            identity,
            signing,
            x25519,
            ml_kem_dk: secrets.ml_kem_dk.clone(),
            wrap_key,
            custody,
        })
    }

    fn init(
        home: &Path,
        device_name: Option<&str>,
        passphrase: Option<&str>,
        allow_file_key: bool,
    ) -> Result<Self, KeystoreError> {
        let signing = SigningKey::from_bytes(&rand::random());
        let verifying: VerifyingKey = signing.verifying_key();
        let x25519 = x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>());
        let x_pub = x25519_dalek::PublicKey::from(&x25519);
        let (ml_dk, ml_ek) = generate_ml_kem()?;
        let identity = DevicePublicIdentity::new(
            DeviceId::new(),
            SigningPublicKey::from(verifying),
            X25519PublicKey::from_bytes(x_pub.to_bytes()),
            MlKem768PublicKey::from_bytes(ml_ek)
                .map_err(|e| KeystoreError::Identity(e.to_string()))?,
            device_name.map(str::to_owned),
        );
        let secrets = SecretBlob {
            signing: signing.to_bytes(),
            x25519: x25519.to_bytes(),
            ml_kem_dk: ml_dk,
        };
        let (wrap_key, custody) = create_wrap_key(home, passphrase, allow_file_key)?;
        let wrapped = wrap_secrets(&wrap_key, &secrets)?;
        let file = IdentityFile {
            version: 1,
            identity: identity.clone(),
            wrapped_secrets: wrapped,
        };
        let mut f = create_private_file(&home.join("identity.json"))?;
        f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
        Ok(Self {
            home: home.to_path_buf(),
            identity,
            signing,
            x25519,
            ml_kem_dk: secrets.ml_kem_dk.clone(),
            wrap_key,
            custody,
        })
    }

    /// Public identity (no secrets).
    #[must_use]
    pub fn public_identity(&self) -> &DevicePublicIdentity {
        &self.identity
    }

    /// Custody mode in use.
    #[must_use]
    pub fn custody(&self) -> Custody {
        self.custody
    }

    /// Sign `data` with the device signing key.
    #[must_use]
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing.sign(data).to_bytes()
    }

    /// Clone a signer for replica metadata ops (no wrap keys).
    #[must_use]
    pub fn device_signer(&self) -> DeviceSigner {
        DeviceSigner {
            device_id: self.identity.device_id,
            signing: self.signing.clone(),
            x25519: self.x25519.clone(),
            ml_kem_dk: self.ml_kem_dk.clone(),
            wrap_key: self.wrap_key,
        }
    }

    /// Wrap `secret` under the device wrap key (epoch keys, etc.).
    pub fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        aead_wrap(&self.wrap_key, b"shelf/keystore/v1", secret)
    }

    /// Unwrap a blob produced by [`Self::wrap_secret`].
    pub fn unwrap_secret(&self, blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
        aead_open(&self.wrap_key, b"shelf/keystore/v1", blob)
    }

    /// Static X25519 secret for hybrid enrollment wrap.
    #[must_use]
    pub fn x25519_secret(&self) -> &x25519_dalek::StaticSecret {
        &self.x25519
    }

    /// ML-KEM-768 decapsulation key bytes.
    #[must_use]
    pub fn ml_kem_decapsulation_key(&self) -> &[u8] {
        &self.ml_kem_dk
    }

    /// Shelf home this keystore was opened from.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn secret_blob(&self) -> SecretBlob {
        SecretBlob {
            signing: self.signing.to_bytes(),
            x25519: self.x25519.to_bytes(),
            ml_kem_dk: self.ml_kem_dk.clone(),
        }
    }

    /// Install recovered identity secrets into an empty home.
    pub(crate) fn install(
        home: &Path,
        stored: DevicePublicIdentity,
        secrets: &SecretBlob,
        wrap_passphrase: Option<&str>,
        allow_file_key: bool,
    ) -> Result<Self, KeystoreError> {
        crate::vault::ensure_home_layout(home)?;
        if home.join("identity.json").exists() {
            return Err(KeystoreError::RecoveryHomeNotEmpty);
        }
        let signing = SigningKey::from_bytes(&secrets.signing);
        let x25519 = x25519_dalek::StaticSecret::from(secrets.x25519);
        let identity = identity_from_secrets(&stored, &signing, &x25519, &secrets.ml_kem_dk)?;
        if identity.device_id != stored.device_id {
            return Err(KeystoreError::Identity(
                "recovered identity device id mismatch".into(),
            ));
        }
        let (wrap_key, custody) = create_wrap_key(home, wrap_passphrase, allow_file_key)?;
        let wrapped = wrap_secrets(&wrap_key, secrets)?;
        let file = IdentityFile {
            version: 1,
            identity: identity.clone(),
            wrapped_secrets: wrapped,
        };
        let mut f = create_private_file(&home.join("identity.json"))?;
        f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
        Ok(Self {
            home: home.to_path_buf(),
            identity,
            signing,
            x25519,
            ml_kem_dk: secrets.ml_kem_dk.clone(),
            wrap_key,
            custody,
        })
    }
}

impl Drop for DeviceKeystore {
    fn drop(&mut self) {
        self.wrap_key.zeroize();
        self.ml_kem_dk.zeroize();
    }
}

fn wrap_key_path(home: &Path) -> PathBuf {
    home.join("wrap.key")
}

fn create_private_file(path: &Path) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        fs::File::create(path)
    }
}

fn identity_from_secrets(
    stored: &DevicePublicIdentity,
    signing: &SigningKey,
    x25519: &x25519_dalek::StaticSecret,
    ml_kem_dk: &[u8],
) -> Result<DevicePublicIdentity, KeystoreError> {
    let x_pub = x25519_dalek::PublicKey::from(x25519);
    Ok(DevicePublicIdentity::new(
        stored.device_id,
        SigningPublicKey::from(signing.verifying_key()),
        X25519PublicKey::from_bytes(x_pub.to_bytes()),
        ml_kem_ek_from_dk(ml_kem_dk)?,
        stored.device_name.clone(),
    ))
}

fn ml_kem_ek_from_dk(seed: &[u8]) -> Result<MlKem768PublicKey, KeystoreError> {
    use ml_kem::kem::KeyExport;
    use ml_kem::{DecapsulationKey, MlKem768, Seed};

    if seed.len() != 64 {
        return Err(KeystoreError::Identity(
            "ml-kem dk must be 64-byte seed".into(),
        ));
    }
    let mut seed_arr = Seed::default();
    seed_arr.copy_from_slice(seed);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed_arr);
    MlKem768PublicKey::from_bytes(dk.encapsulation_key().to_bytes().to_vec())
        .map_err(|e| KeystoreError::Identity(e.to_string()))
}

fn create_wrap_key(
    home: &Path,
    passphrase: Option<&str>,
    allow_file_key: bool,
) -> Result<([u8; 32], Custody), KeystoreError> {
    if let Some(pass) = passphrase {
        let key = argon2_key(pass, home)?;
        return Ok((key, Custody::Passphrase));
    }
    let mut key: [u8; 32] = rand::random();
    if platform::store_wrap_key(home, &key)? {
        return Ok((key, Custody::Platform));
    }
    if cfg!(target_os = "ios") || !allow_file_key {
        key.zeroize();
        return Err(KeystoreError::NoCustody);
    }
    let path = wrap_key_path(home);
    let mut f = create_private_file(&path)?;
    f.write_all(&key)?;
    Ok((key, Custody::File))
}

fn load_wrap_key(
    home: &Path,
    passphrase: Option<&str>,
) -> Result<([u8; 32], Custody), KeystoreError> {
    if let Some(pass) = passphrase {
        return Ok((argon2_key(pass, home)?, Custody::Passphrase));
    }
    if let Some(key) = platform::load_wrap_key(home)? {
        return Ok((key, Custody::Platform));
    }
    let bytes = fs::read(wrap_key_path(home))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::Identity("wrap.key must be 32 bytes".into()))?;
    Ok((key, Custody::File))
}

fn argon2_key(pass: &str, home: &Path) -> Result<[u8; 32], KeystoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let salt_path = home.join("wrap.salt");
    let salt = if salt_path.exists() {
        fs::read(salt_path)?
    } else {
        let s: [u8; 16] = rand::random();
        let mut f = create_private_file(&home.join("wrap.salt"))?;
        f.write_all(&s)?;
        s.to_vec()
    };
    if salt.len() < 16 {
        return Err(KeystoreError::Passphrase);
    }
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|_| KeystoreError::Passphrase)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), &salt, &mut out)
        .map_err(|_| KeystoreError::Passphrase)?;
    Ok(out)
}

fn wrap_secrets(wrap_key: &[u8; 32], secrets: &SecretBlob) -> Result<Vec<u8>, KeystoreError> {
    let json = serde_json::to_vec(secrets)?;
    aead_wrap(wrap_key, b"shelf/identity/v1", &json)
}

fn unwrap_secrets(wrap_key: &[u8; 32], blob: &[u8]) -> Result<SecretBlob, KeystoreError> {
    let json = aead_open(wrap_key, b"shelf/identity/v1", blob)?;
    Ok(serde_json::from_slice(&json)?)
}

pub(crate) fn aead_wrap(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let nonce: [u8; 24] = rand::random();
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| KeystoreError::Wrap)?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub(crate) fn aead_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if blob.len() < 24 {
        return Err(KeystoreError::Wrap);
    }
    let nonce: [u8; 24] = blob[..24].try_into().map_err(|_| KeystoreError::Wrap)?;
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &blob[24..],
                aad,
            },
        )
        .map_err(|_| KeystoreError::Wrap)
}

fn generate_ml_kem() -> Result<(Vec<u8>, Vec<u8>), KeystoreError> {
    use ml_kem::kem::KeyExport;
    use ml_kem::{Kem, MlKem768};

    let (dk, ek) = MlKem768::generate_keypair();
    Ok((dk.to_bytes().to_vec(), ek.to_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::ML_KEM_768_PUBLIC_KEY_LEN;

    #[test]
    fn init_and_reload_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = DeviceKeystore::open_or_init(dir.path(), Some("testdev"), None, true).unwrap();
        assert!(matches!(ks.custody(), Custody::File | Custody::Platform));
        let id = ks.public_identity().device_id;
        let wrapped = ks.wrap_secret(b"epoch-key-material-32-bytes!!").unwrap();
        drop(ks);
        let ks2 = DeviceKeystore::load(dir.path(), None).unwrap();
        assert_eq!(ks2.public_identity().device_id, id);
        assert_eq!(
            ks2.unwrap_secret(&wrapped).unwrap(),
            b"epoch-key-material-32-bytes!!"
        );
        assert_eq!(
            ks2.public_identity().ml_kem_pubkey.as_bytes().len(),
            ML_KEM_768_PUBLIC_KEY_LEN
        );
    }

    #[test]
    fn passphrase_custody_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ks =
            DeviceKeystore::open_or_init(dir.path(), None, Some("correct horse"), false).unwrap();
        assert_eq!(ks.custody(), Custody::Passphrase);
        let blob = ks.wrap_secret(&[7u8; 32]).unwrap();
        drop(ks);
        let ks2 = DeviceKeystore::load(dir.path(), Some("correct horse")).unwrap();
        assert_eq!(ks2.unwrap_secret(&blob).unwrap(), vec![7u8; 32]);
        assert!(DeviceKeystore::load(dir.path(), Some("wrong")).is_err());
    }

    #[test]
    fn enroll_offline_files_share_epoch() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let mut member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let (join, request_sas) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (grant, grant_sas) = crate::approve_join(&member, &join).unwrap();
        assert_ne!(request_sas, grant_sas);
        crate::import_grant(&mut joiner, &grant, &grant_sas).unwrap();
        assert_eq!(joiner.store.vault_id(), member.store.vault_id());
        assert_eq!(joiner.store.epoch(), member.store.epoch());
        assert!(
            joiner
                .store
                .members()
                .unwrap()
                .iter()
                .any(|c| c.device_id == member.keys.public_identity().device_id),
            "joiner must import the approver certificate"
        );
        let payload = b"from-member";
        let (id, created) = member
            .store
            .put(payload.to_vec(), shelf_core::ContentKind::Text, None)
            .unwrap();
        let env = shelf_protocol::seal(
            payload,
            id,
            member.store.epoch(),
            member.store.epoch_key(),
            shelf_core::ContentKind::Text,
            member.store.device_id(),
        )
        .unwrap();
        joiner
            .store
            .ingest_envelope(env, created, false, None, None)
            .unwrap();
        let opened = joiner.store.get(&shelf_store::ItemTarget::Id(id)).unwrap();
        assert_eq!(opened.bytes, payload);
    }

    #[test]
    fn list_then_root_revoke_drops_joiner() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let mut member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let joiner_id = joiner.keys.public_identity().device_id;
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (grant, grant_sas) = crate::approve_join(&member, &join).unwrap();
        crate::import_grant(&mut joiner, &grant, &grant_sas).unwrap();

        let listed = crate::list_devices_store(&member.keys, &member.store).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|d| d.is_root));
        assert!(
            listed
                .iter()
                .any(|d| d.device_id == joiner_id && !d.is_root)
        );

        crate::revoke_device(&mut member, joiner_id).unwrap();
        let after = crate::list_devices_store(&member.keys, &member.store).unwrap();
        assert_eq!(after.len(), 1);
        assert!(after[0].is_root);
        assert_ne!(after[0].device_id, joiner_id);
    }

    #[test]
    fn non_root_revoke_fails_typed() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let root_id = member.keys.public_identity().device_id;
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (grant, grant_sas) = crate::approve_join(&member, &join).unwrap();
        crate::import_grant(&mut joiner, &grant, &grant_sas).unwrap();

        let err = crate::revoke_device(&mut joiner, root_id).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("only the vault root can revoke a device"),
            "typed root-only failure, got {msg:?}"
        );
        assert!(!msg.contains("wrap.key"));
        assert!(!msg.contains("correct horse"));
    }

    #[test]
    fn approve_rejects_tampered_join_signature() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let (mut join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        join.request.device_name = "attacker".into();
        assert!(crate::approve_join(&member, &join).is_err());
    }

    #[test]
    fn import_rejects_tampered_grant_signature() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (mut grant, sas) = crate::approve_join(&member, &join).unwrap();
        grant.grant.certificate.serial = 99;
        assert!(crate::import_grant(&mut joiner, &grant, &sas).is_err());
    }

    #[test]
    fn import_rejects_wrong_sas() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (grant, _) = crate::approve_join(&member, &join).unwrap();
        assert!(crate::import_grant(&mut joiner, &grant, "able acid acre aged aide aims").is_err());
    }

    #[test]
    fn import_rejects_attacker_grant_when_sas_is_the_real_approver() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let attacker_dir = tempfile::tempdir().unwrap();
        let member =
            crate::open_or_create_vault(member_dir.path(), Some("mac"), None, true).unwrap();
        let mut joiner =
            crate::open_or_create_vault(join_dir.path(), Some("linux"), None, true).unwrap();
        let attacker =
            crate::open_or_create_vault(attacker_dir.path(), Some("evil"), None, true).unwrap();
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (legitimate, sas) = crate::approve_join(&member, &join).unwrap();
        let (hostile, hostile_sas) = crate::approve_join(&attacker, &join).unwrap();
        assert_ne!(sas, hostile_sas);
        assert!(crate::import_grant(&mut joiner, &hostile, &sas).is_err());
        crate::import_grant(&mut joiner, &legitimate, &sas).unwrap();
        assert_eq!(joiner.store.vault_id(), member.store.vault_id());
    }

    #[test]
    fn file_key_requires_flag_when_platform_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        match DeviceKeystore::open_or_init(dir.path(), Some("x"), None, false) {
            Ok(ks) => assert_eq!(ks.custody(), Custody::Platform),
            Err(KeystoreError::NoCustody) => {}
            Err(other) => panic!("unexpected {other}"),
        }
    }

    /// iOS must never persist `wrap.key`, even if the caller passes
    /// `allow_file_key`. Compiled only for `target_os = "ios"`.
    #[cfg(target_os = "ios")]
    #[test]
    fn ios_never_writes_file_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let wrap_path = dir.path().join("wrap.key");
        match DeviceKeystore::open_or_init(dir.path(), Some("ios"), None, true) {
            Ok(ks) => {
                assert_eq!(ks.custody(), Custody::Platform);
                assert!(!wrap_path.exists(), "iOS must not write wrap.key");
            }
            Err(KeystoreError::NoCustody) => {
                assert!(!wrap_path.exists(), "iOS must not write wrap.key");
            }
            Err(other) => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn vault_persists_wrapped_epoch_not_raw_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = crate::open_or_create_vault(dir.path(), Some("t"), None, true).unwrap();
        let loaded = shelf_store::SqliteStore::load_identity(&dir.path().join("state.db"))
            .unwrap()
            .unwrap();
        assert_ne!(loaded.3.as_slice(), vault.store.epoch_key().as_bytes());
        assert!(
            loaded.3.len() > 32,
            "wrapped blob should be nonce+ciphertext, not 32 raw bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn home_layout_is_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("shelf");
        let _ = crate::open_or_create_vault(&home, Some("t"), None, true).unwrap();
        let mode = std::fs::metadata(&home).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let runtime = std::fs::metadata(home.join("runtime"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        assert_eq!(runtime, 0o700);
    }

    #[test]
    fn revoke_keeps_old_epoch_key_locally() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = crate::open_or_create_vault(dir.path(), Some("t"), None, true).unwrap();
        let old_epoch = vault.store.epoch();
        let victim = shelf_core::DeviceId::new();
        let new_epoch = crate::revoke_device(&mut vault, victim).unwrap();
        assert!(new_epoch > old_epoch);
        assert_eq!(vault.store.epoch(), new_epoch);
        assert!(vault.store.key_for(old_epoch).is_ok());
        assert!(vault.store.key_for(new_epoch).is_ok());
        drop(vault);
        let reopened = crate::open_or_create_vault(dir.path(), Some("t"), None, true).unwrap();
        assert!(reopened.store.key_for(old_epoch).is_ok());
        assert!(reopened.store.key_for(new_epoch).is_ok());
        assert_eq!(reopened.store.epoch(), new_epoch);
    }
}
