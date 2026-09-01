//! Device identity secrets and wrapping of vault epoch keys.
//!
//! Hardware-backed custody is preferred. This crate always provides a
//! locked-down file wrap key (`wrap.key`, mode 0600) when a platform store is
//! unavailable, and uses Argon2id when the caller supplies a passphrase.

mod enroll;
mod vault;

pub use enroll::{ShelfGrant, ShelfJoin, approve_join, export_join, import_grant};
pub use vault::{Vault, ensure_home_layout, open_or_create_vault};

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
    /// Enrollment request or grant signature was invalid or expired.
    #[error("enrollment signature: {0}")]
    Signature(String),
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
    pub fn open_or_init(
        home: impl AsRef<Path>,
        device_name: Option<&str>,
        passphrase: Option<&str>,
    ) -> Result<Self, KeystoreError> {
        let home = home.as_ref().to_path_buf();
        fs::create_dir_all(&home)?;
        let id_path = home.join("identity.json");
        if id_path.exists() {
            return Self::load(&home, passphrase);
        }
        Self::init(&home, device_name, passphrase)
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
        Ok(Self {
            home,
            identity: file.identity,
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
        let (wrap_key, custody) = create_wrap_key(home, passphrase)?;
        let wrapped = wrap_secrets(&wrap_key, &secrets)?;
        let file = IdentityFile {
            version: 1,
            identity: identity.clone(),
            wrapped_secrets: wrapped,
        };
        let mut f = fs::File::create(home.join("identity.json"))?;
        f.write_all(serde_json::to_string_pretty(&file)?.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                home.join("identity.json"),
                fs::Permissions::from_mode(0o600),
            )?;
        }
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
}

fn wrap_key_path(home: &Path) -> PathBuf {
    home.join("wrap.key")
}

fn create_wrap_key(
    home: &Path,
    passphrase: Option<&str>,
) -> Result<([u8; 32], Custody), KeystoreError> {
    if let Some(pass) = passphrase {
        let key = argon2_key(pass, home)?;
        return Ok((key, Custody::Passphrase));
    }
    let key: [u8; 32] = rand::random();
    let path = wrap_key_path(home);
    let mut f = fs::File::create(&path)?;
    f.write_all(&key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok((key, Custody::File))
}

fn load_wrap_key(
    home: &Path,
    passphrase: Option<&str>,
) -> Result<([u8; 32], Custody), KeystoreError> {
    if let Some(pass) = passphrase {
        return Ok((argon2_key(pass, home)?, Custody::Passphrase));
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
        fs::write(home.join("wrap.salt"), s)?;
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

fn aead_wrap(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
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

fn aead_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
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
        let ks = DeviceKeystore::open_or_init(dir.path(), Some("testdev"), None).unwrap();
        assert_eq!(ks.custody(), Custody::File);
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
        let ks = DeviceKeystore::open_or_init(dir.path(), None, Some("correct horse")).unwrap();
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
        let mut member = crate::open_or_create_vault(member_dir.path(), Some("mac"), None).unwrap();
        let mut joiner = crate::open_or_create_vault(join_dir.path(), Some("linux"), None).unwrap();
        let (join, sas_a) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (grant, sas_b) = crate::approve_join(&member, &join).unwrap();
        assert_eq!(sas_a, sas_b);
        crate::import_grant(&mut joiner, &grant).unwrap();
        assert_eq!(joiner.store.vault_id(), member.store.vault_id());
        assert_eq!(joiner.store.epoch(), member.store.epoch());
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
    fn approve_rejects_tampered_join_signature() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member = crate::open_or_create_vault(member_dir.path(), Some("mac"), None).unwrap();
        let joiner = crate::open_or_create_vault(join_dir.path(), Some("linux"), None).unwrap();
        let (mut join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        join.request.device_name = "attacker".into();
        assert!(crate::approve_join(&member, &join).is_err());
    }

    #[test]
    fn import_rejects_tampered_grant_signature() {
        let member_dir = tempfile::tempdir().unwrap();
        let join_dir = tempfile::tempdir().unwrap();
        let member = crate::open_or_create_vault(member_dir.path(), Some("mac"), None).unwrap();
        let mut joiner = crate::open_or_create_vault(join_dir.path(), Some("linux"), None).unwrap();
        let (join, _) = crate::export_join(&joiner, Vec::new()).unwrap();
        let (mut grant, _) = crate::approve_join(&member, &join).unwrap();
        grant.grant.certificate.serial = 99;
        assert!(crate::import_grant(&mut joiner, &grant).is_err());
    }
}
