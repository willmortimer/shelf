//! Passphrase-wrapped vault recovery bundles (`.shelfrecovery`).
//!
//! Recovery is a separate trust path from enrollment. A mailbox cannot recover
//! a vault. Apply restores the existing [`VaultRoot`] onto an empty home so the
//! recovered device can decrypt and issue v1 root-only grants.

use serde::{Deserialize, Serialize};
use shelf_core::enrollment::{MembershipSnapshot, VaultRoot};
use shelf_core::{DOMAIN_RECOVERY, DevicePublicIdentity, EpochId, Transcript, VaultId};
use shelf_protocol::EpochKey;
use shelf_store::{SealedRecord, SqliteStore};
use zeroize::Zeroize;

use crate::DeviceKeystore;
use crate::KeystoreError;
use crate::SecretBlob;
use crate::vault::Vault;

/// On-disk recovery bundle (`shelf/recovery/v1`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryBundle {
    /// Format version. Currently `1`.
    pub version: u16,
    /// Domain label bound into AEAD AAD.
    pub domain: String,
    /// Vault id (also bound into AAD; not secret).
    pub vault_id: VaultId,
    /// Argon2id memory parameter in KiB.
    pub argon2_m_kib: u32,
    /// Argon2id iterations.
    pub argon2_t: u32,
    /// Argon2id parallelism.
    pub argon2_p: u32,
    /// Random KDF salt.
    pub salt: Vec<u8>,
    /// XChaCha20-Poly1305 nonce || ciphertext of [`RecoveryPlaintext`].
    pub wrapped: Vec<u8>,
}

const RECOVERY_VERSION: u16 = 1;
const ARGON2_M_KIB: u32 = 19_456;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

#[derive(Serialize, Deserialize)]
struct RecoveryPlaintext {
    identity: DevicePublicIdentity,
    secrets: SecretBlob,
    epoch: EpochId,
    vault_id: VaultId,
    epoch_key: [u8; 32],
    vault_root: VaultRoot,
    snapshot: MembershipSnapshot,
    objects: Vec<SealedRecord>,
}

impl Drop for RecoveryPlaintext {
    fn drop(&mut self) {
        self.epoch_key.zeroize();
    }
}

/// Export a passphrase-wrapped recovery bundle from a vault.
pub fn export_recovery(vault: &Vault, passphrase: &str) -> Result<RecoveryBundle, KeystoreError> {
    export_recovery_store(&vault.keys, &vault.store, passphrase)
}

/// Export a recovery bundle from an already-open store and keystore.
pub fn export_recovery_store(
    keys: &DeviceKeystore,
    store: &SqliteStore,
    passphrase: &str,
) -> Result<RecoveryBundle, KeystoreError> {
    if passphrase.is_empty() {
        return Err(KeystoreError::Recovery);
    }
    let root = store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| KeystoreError::Signature("vault has no root".into()))?;
    if keys.public_identity().signing_pubkey != root.root_signing_pubkey {
        return Err(KeystoreError::Signature(
            "only the vault root device may export recovery".into(),
        ));
    }
    let snapshot = store
        .membership_snapshot()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| KeystoreError::Identity("vault has no membership snapshot".into()))?;
    let objects = store
        .export_objects()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let mut plaintext = RecoveryPlaintext {
        identity: keys.public_identity().clone(),
        secrets: keys.secret_blob(),
        epoch: store.epoch(),
        vault_id: store.vault_id(),
        epoch_key: *store.epoch_key().as_bytes(),
        vault_root: root,
        snapshot,
        objects,
    };
    let json = serde_json::to_vec(&plaintext)?;
    plaintext.epoch_key.zeroize();
    drop(plaintext);
    let salt: [u8; 16] = rand::random();
    let key = argon2_recovery_key(passphrase, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)?;
    let aad = recovery_aad(&store.vault_id());
    let wrapped = crate::aead_wrap(&key, &aad, &json)?;
    Ok(RecoveryBundle {
        version: RECOVERY_VERSION,
        domain: DOMAIN_RECOVERY.to_owned(),
        vault_id: store.vault_id(),
        argon2_m_kib: ARGON2_M_KIB,
        argon2_t: ARGON2_T,
        argon2_p: ARGON2_P,
        salt: salt.to_vec(),
        wrapped,
    })
}

/// Restore a vault onto an empty `home` from a recovery bundle.
///
/// `wrap_passphrase` is the new home's wrap-key custody (not the recovery
/// passphrase). Pass `allow_file_key` when platform custody is unavailable.
pub fn apply_recovery(
    home: impl AsRef<std::path::Path>,
    bundle: &RecoveryBundle,
    recovery_passphrase: &str,
    wrap_passphrase: Option<&str>,
    allow_file_key: bool,
) -> Result<Vault, KeystoreError> {
    let home = home.as_ref();
    if home.join("identity.json").exists() || home.join("state.db").exists() {
        return Err(KeystoreError::RecoveryHomeNotEmpty);
    }
    let plaintext = unwrap_bundle(bundle, recovery_passphrase)?;
    let keys = DeviceKeystore::install(
        home,
        plaintext.identity.clone(),
        &plaintext.secrets,
        wrap_passphrase,
        allow_file_key,
    )?;
    let wrapped_epoch = keys.wrap_secret(&plaintext.epoch_key)?;
    let db = home.join("state.db");
    let mut store = SqliteStore::open(
        &db,
        EpochKey::from_bytes(plaintext.epoch_key),
        keys.public_identity().device_id,
        plaintext.epoch,
        plaintext.vault_id,
        &wrapped_epoch,
    )
    .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .save_vault_root(&plaintext.vault_root)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    for cert in &plaintext.snapshot.certificates {
        store
            .put_member(cert)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
    store
        .save_membership_snapshot(&plaintext.snapshot)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .save_wrapped_epoch_key(&wrapped_epoch)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    for rec in &plaintext.objects {
        store
            .ingest_envelope(
                rec.envelope.clone(),
                rec.created,
                rec.pinned,
                rec.expires_at,
                rec.name.clone(),
            )
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
    Ok(Vault { keys, store })
}

fn unwrap_bundle(
    bundle: &RecoveryBundle,
    passphrase: &str,
) -> Result<RecoveryPlaintext, KeystoreError> {
    if bundle.version != RECOVERY_VERSION || bundle.domain != DOMAIN_RECOVERY {
        return Err(KeystoreError::Recovery);
    }
    if passphrase.is_empty() || bundle.salt.len() < 16 {
        return Err(KeystoreError::Recovery);
    }
    let key = argon2_recovery_key(
        passphrase,
        &bundle.salt,
        bundle.argon2_m_kib,
        bundle.argon2_t,
        bundle.argon2_p,
    )?;
    let aad = recovery_aad(&bundle.vault_id);
    let json =
        crate::aead_open(&key, &aad, &bundle.wrapped).map_err(|_| KeystoreError::Recovery)?;
    let plaintext: RecoveryPlaintext =
        serde_json::from_slice(&json).map_err(|_| KeystoreError::Recovery)?;
    if plaintext.vault_id != bundle.vault_id {
        return Err(KeystoreError::Recovery);
    }
    Ok(plaintext)
}

fn recovery_aad(vault_id: &VaultId) -> Vec<u8> {
    let mut t = Transcript::new(DOMAIN_RECOVERY);
    t.push_u16(RECOVERY_VERSION);
    t.push_fixed(vault_id.as_bytes());
    t.as_bytes().to_vec()
}

fn argon2_recovery_key(
    pass: &str,
    salt: &[u8],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Result<[u8; 32], KeystoreError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t, p, Some(32)).map_err(|_| KeystoreError::Passphrase)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| KeystoreError::Passphrase)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{approve_join, export_join, open_or_create_vault};

    fn unique_passphrase() -> String {
        format!("recovery-{}", hex_8(rand::random::<[u8; 8]>()))
    }

    fn hex_8(bytes: [u8; 8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn export_apply_round_trip_decrypts_and_keeps_root_grants() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let mut vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let payload = b"recover-me";
        vault
            .store
            .put(payload.to_vec(), shelf_core::ContentKind::Text, None)
            .unwrap();
        let pass = unique_passphrase();
        let bundle = export_recovery(&vault, &pass).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(!json.contains(&pass));
        assert!(!json.contains("recover-me"));
        drop(vault);

        let recovered = apply_recovery(dst.path(), &bundle, &pass, None, true).unwrap();
        let opened = recovered.store.latest().unwrap();
        assert_eq!(opened.bytes, payload);
        let root = recovered.store.vault_root().unwrap().unwrap();
        assert_eq!(
            recovered.keys.public_identity().signing_pubkey,
            root.root_signing_pubkey
        );

        let joiner_dir = tempfile::tempdir().unwrap();
        let mut joiner =
            open_or_create_vault(joiner_dir.path(), Some("phone"), None, true).unwrap();
        let (join, _) = export_join(&joiner, Vec::new()).unwrap();
        let (grant, sas) = approve_join(&recovered, &join).unwrap();
        crate::import_grant(&mut joiner, &grant, &sas).unwrap();
        assert_eq!(joiner.store.vault_id(), recovered.store.vault_id());
    }

    #[test]
    fn wrong_recovery_passphrase_is_typed() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let pass = unique_passphrase();
        let bundle = export_recovery(&vault, &pass).unwrap();
        let err = match apply_recovery(dst.path(), &bundle, "not-the-passphrase", None, true) {
            Err(err) => err,
            Ok(_) => panic!("wrong passphrase must fail"),
        };
        assert!(matches!(err, KeystoreError::Recovery));
        let msg = err.to_string();
        assert!(!msg.contains(&pass));
        assert!(!msg.contains("not-the-passphrase"));
    }

    #[test]
    fn apply_rejects_occupied_home() {
        let src = tempfile::tempdir().unwrap();
        let occupied = tempfile::tempdir().unwrap();
        let _ = open_or_create_vault(occupied.path(), Some("existing"), None, true).unwrap();
        let vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let pass = unique_passphrase();
        let bundle = export_recovery(&vault, &pass).unwrap();
        let err = match apply_recovery(occupied.path(), &bundle, &pass, None, true) {
            Err(err) => err,
            Ok(_) => panic!("occupied home must fail"),
        };
        assert!(matches!(err, KeystoreError::RecoveryHomeNotEmpty));
    }
}
