//! Passphrase-wrapped vault recovery bundles (`.shelfrecovery`).
//!
//! Recovery is a separate trust path from enrollment. A mailbox cannot recover
//! a vault. Apply restores the existing [`VaultRoot`] onto an empty home so the
//! recovered device can decrypt and issue v1 root-only grants.

use std::collections::HashSet;

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
    /// Historical (and current) epoch secrets. Absent on pre-keyring bundles.
    #[serde(default)]
    epoch_keys: Vec<(u64, [u8; 32])>,
    vault_root: VaultRoot,
    snapshot: MembershipSnapshot,
    objects: Vec<SealedRecord>,
}

impl Drop for RecoveryPlaintext {
    fn drop(&mut self) {
        self.epoch_key.zeroize();
        for (_, key) in &mut self.epoch_keys {
            key.zeroize();
        }
        self.epoch_keys.clear();
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
    let epoch_keys = collect_epoch_keys(keys, store)?;
    let mut plaintext = RecoveryPlaintext {
        identity: keys.public_identity().clone(),
        secrets: keys.secret_blob(),
        epoch: store.epoch(),
        vault_id: store.vault_id(),
        epoch_key: *store.epoch_key().as_bytes(),
        epoch_keys,
        vault_root: root,
        snapshot,
        objects,
    };
    let json = serde_json::to_vec(&plaintext)?;
    plaintext.epoch_key.zeroize();
    for (_, key) in &mut plaintext.epoch_keys {
        key.zeroize();
    }
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
    for (epoch, key_bytes) in &plaintext.epoch_keys {
        let epoch = EpochId::new(*epoch);
        store
            .add_epoch_key(epoch, EpochKey::from_bytes(*key_bytes))
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
        let wrapped = keys.wrap_secret(key_bytes)?;
        store
            .save_epoch_wrap(epoch, &wrapped)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
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
    // v1 apply only accepts the export-time KDF. Attacker-chosen m/t/p would
    // otherwise let a crafted bundle DoS apply with unbounded Argon2 memory.
    if bundle.argon2_m_kib != ARGON2_M_KIB
        || bundle.argon2_t != ARGON2_T
        || bundle.argon2_p != ARGON2_P
    {
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

/// Unwrap every local epoch wrap under the current device wrap key, then
/// include the in-memory current epoch if it was missing from the table.
fn collect_epoch_keys(
    keys: &DeviceKeystore,
    store: &SqliteStore,
) -> Result<Vec<(u64, [u8; 32])>, KeystoreError> {
    let mut seen = HashSet::new();
    let mut epoch_keys = Vec::new();
    for (epoch, wrapped) in store
        .list_epoch_wraps()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        let mut raw = keys.unwrap_secret(&wrapped)?;
        let copied: Result<[u8; 32], _> = raw.as_slice().try_into();
        raw.zeroize();
        let bytes =
            copied.map_err(|_| KeystoreError::Identity("epoch key must be 32 bytes".into()))?;
        let id = epoch.as_u64();
        if seen.insert(id) {
            epoch_keys.push((id, bytes));
        }
    }
    let current = store.epoch().as_u64();
    if seen.insert(current) {
        epoch_keys.push((current, *store.epoch_key().as_bytes()));
    }
    Ok(epoch_keys)
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
    use crate::{approve_join, export_join, open_or_create_vault, revoke_device};
    use shelf_store::ItemTarget;

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

    #[test]
    fn apply_rejects_attacker_chosen_argon2_params() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let pass = unique_passphrase();
        let mut bundle = export_recovery(&vault, &pass).unwrap();
        bundle.argon2_m_kib = ARGON2_M_KIB.saturating_mul(64);
        let err = match apply_recovery(dst.path(), &bundle, &pass, None, true) {
            Err(err) => err,
            Ok(_) => panic!("inflated Argon2 memory must fail"),
        };
        assert!(matches!(err, KeystoreError::Recovery));
    }

    #[test]
    fn recovery_decrypts_objects_from_prior_epochs() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let mut vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let old_epoch = vault.store.epoch();
        let payload_a = b"object-a-old-epoch";
        let (id_a, _) = vault
            .store
            .put(payload_a.to_vec(), shelf_core::ContentKind::Text, None)
            .unwrap();
        let victim = shelf_core::DeviceId::new();
        let new_epoch = revoke_device(&mut vault, victim).unwrap();
        assert!(new_epoch > old_epoch);
        let payload_b = b"object-b-new-epoch";
        let (id_b, _) = vault
            .store
            .put(payload_b.to_vec(), shelf_core::ContentKind::Text, None)
            .unwrap();
        let pass = unique_passphrase();
        let bundle = export_recovery(&vault, &pass).unwrap();
        drop(vault);

        let recovered = apply_recovery(dst.path(), &bundle, &pass, None, true).unwrap();
        let opened_a = recovered.store.get(&ItemTarget::Id(id_a)).unwrap();
        let opened_b = recovered.store.get(&ItemTarget::Id(id_b)).unwrap();
        assert_eq!(opened_a.bytes, payload_a);
        assert_eq!(opened_b.bytes, payload_b);
        assert_eq!(recovered.store.latest().unwrap().bytes, payload_b);
        assert!(recovered.store.key_for(old_epoch).is_ok());
        assert!(recovered.store.key_for(new_epoch).is_ok());
        drop(recovered);

        let reopened = open_or_create_vault(dst.path(), Some("root"), None, true).unwrap();
        assert_eq!(
            reopened.store.get(&ItemTarget::Id(id_a)).unwrap().bytes,
            payload_a
        );
        assert_eq!(
            reopened.store.get(&ItemTarget::Id(id_b)).unwrap().bytes,
            payload_b
        );
    }

    #[test]
    fn apply_bundle_missing_epoch_keys_field() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let mut vault = open_or_create_vault(src.path(), Some("root"), None, true).unwrap();
        let payload = b"current-epoch-only";
        vault
            .store
            .put(payload.to_vec(), shelf_core::ContentKind::Text, None)
            .unwrap();
        let pass = unique_passphrase();
        let mut bundle = export_recovery(&vault, &pass).unwrap();
        let plaintext = unwrap_bundle(&bundle, &pass).unwrap();
        let mut value = serde_json::to_value(&plaintext).unwrap();
        value
            .as_object_mut()
            .expect("plaintext object")
            .remove("epoch_keys");
        let json = serde_json::to_vec(&value).unwrap();
        let key =
            argon2_recovery_key(&pass, &bundle.salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P).unwrap();
        let aad = recovery_aad(&bundle.vault_id);
        bundle.wrapped = crate::aead_wrap(&key, &aad, &json).unwrap();
        drop(vault);

        let recovered = apply_recovery(dst.path(), &bundle, &pass, None, true).unwrap();
        assert_eq!(recovered.store.latest().unwrap().bytes, payload);
    }
}
