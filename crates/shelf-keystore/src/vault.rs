//! Open or create a durable vault under a Shelf home directory.

use std::fs;
use std::path::Path;

use shelf_core::{DeviceId, EpochId, VaultId};
use shelf_protocol::{
    DeviceEpochWrap, EpochKey, EpochTransitionPayload, epoch_transition_aad, wrap_epoch_key,
};
use shelf_store::SqliteStore;

use crate::enroll::sign_snapshot;
use crate::{DeviceKeystore, KeystoreError};

/// Combined keystore + SQLite vault.
pub struct Vault {
    /// Device keystore.
    pub keys: DeviceKeystore,
    /// Durable object store.
    pub store: SqliteStore,
}

/// One membership row for `shelf devices`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceListEntry {
    /// Member device id (hex on the wire).
    pub device_id: DeviceId,
    /// Display name when this row is the local device and a name was set at init.
    /// Membership certificates do not carry a name.
    pub name: Option<String>,
    /// Whether this device holds the vault root signing key.
    pub is_root: bool,
}

/// Create `~/.shelf/` layout (`config.toml`, `state.db` parent dirs, runtime).
///
/// Directories are created with mode 0700 on Unix.
pub fn ensure_home_layout(home: &Path) -> Result<(), KeystoreError> {
    create_dir_private(home)?;
    for dir in [
        "objects",
        "chunks",
        "logs",
        "runtime",
        "cache",
        "export",
        "enrollment",
    ] {
        create_dir_private(&home.join(dir))?;
    }
    let cfg = home.join("config.toml");
    if !cfg.exists() {
        fs::write(
            cfg,
            "# Shelf local preferences. Do not put secrets here.\n\
             # mailbox_url = \"127.0.0.1:8743\"\n\
             # lan_port = 18732\n\
             # lan_address = \"192.0.2.10:18732\"\n\
             # peer_port = 18733\n",
        )?;
    }
    Ok(())
}

fn create_dir_private(path: &Path) -> Result<(), KeystoreError> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Open an existing vault or create a new one under `home`.
///
/// `allow_file_key` is only consulted when creating a new identity.
pub fn open_or_create_vault(
    home: impl AsRef<Path>,
    device_name: Option<&str>,
    passphrase: Option<&str>,
    allow_file_key: bool,
) -> Result<Vault, KeystoreError> {
    let home = home.as_ref();
    ensure_home_layout(home)?;
    let keys = DeviceKeystore::open_or_init(home, device_name, passphrase, allow_file_key)?;
    let db = home.join("state.db");
    let mut store = if let Some((device_id, epoch, vault_id, wrapped)) =
        SqliteStore::load_identity(&db).map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        let raw = keys.unwrap_secret(&wrapped)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Identity("epoch key must be 32 bytes".into()))?;
        SqliteStore::open(
            &db,
            EpochKey::from_bytes(bytes),
            device_id,
            epoch,
            vault_id,
            &wrapped,
        )
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    } else {
        let epoch_key = EpochKey::new();
        let wrapped = keys.wrap_secret(epoch_key.as_bytes())?;
        SqliteStore::open(
            &db,
            epoch_key,
            keys.public_identity().device_id,
            EpochId::new(1),
            VaultId::new(),
            &wrapped,
        )
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    };
    load_epoch_keyring(&keys, &mut store)?;
    let mut vault = Vault { keys, store };
    crate::ensure_local_root(&mut vault)?;
    Ok(vault)
}

fn load_epoch_keyring(keys: &DeviceKeystore, store: &mut SqliteStore) -> Result<(), KeystoreError> {
    for (epoch, wrapped) in store
        .list_epoch_wraps()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        let raw = keys.unwrap_secret(&wrapped)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Identity("epoch key must be 32 bytes".into()))?;
        store
            .add_epoch_key(epoch, EpochKey::from_bytes(bytes))
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    }
    Ok(())
}

/// List current vault members.
///
/// Certificates do not store a display name. When `keys` is the local
/// identity, that device's init name is filled in.
pub fn list_devices_store(
    keys: &DeviceKeystore,
    store: &SqliteStore,
) -> Result<Vec<DeviceListEntry>, KeystoreError> {
    let root_pk = store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .map(|r| r.root_signing_pubkey);
    let local = keys.public_identity();
    let mut out = Vec::new();
    for cert in store
        .members()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        let name = if cert.device_id == local.device_id {
            local
                .device_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        out.push(DeviceListEntry {
            device_id: cert.device_id,
            name,
            is_root: root_pk == Some(cert.signing_pubkey),
        });
    }
    out.sort_by(|a, b| match (b.is_root, a.is_root) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => a.device_id.as_bytes().cmp(b.device_id.as_bytes()),
    });
    Ok(out)
}

/// Rotate the vault epoch and drop `device_id` from membership.
///
/// Only the vault root may call this. Remaining members receive a hybrid wrap of
/// the new epoch key via a queued [`EpochTransitionPayload`].
pub fn revoke_device(vault: &mut Vault, device_id: DeviceId) -> Result<EpochId, KeystoreError> {
    revoke_device_store(&vault.keys, &mut vault.store, device_id)
}

/// [`revoke_device`] against an already-open store and keystore (daemon IPC).
pub fn revoke_device_store(
    keys: &DeviceKeystore,
    store: &mut SqliteStore,
    device_id: DeviceId,
) -> Result<EpochId, KeystoreError> {
    let root = store
        .vault_root()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .ok_or_else(|| KeystoreError::Identity("vault has no root".into()))?;
    if keys.public_identity().signing_pubkey != root.root_signing_pubkey {
        return Err(KeystoreError::Signature(
            "only the vault root can revoke a device".into(),
        ));
    }
    let old_epoch = store.epoch();
    let remaining: Vec<_> = store
        .members()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .into_iter()
        .filter(|c| c.device_id != device_id)
        .collect();
    let new_key = EpochKey::new();
    let new_epoch = old_epoch.next();
    let aad = epoch_transition_aad(store.vault_id(), old_epoch, new_epoch, device_id);
    let mut envelopes = Vec::new();
    for cert in &remaining {
        let wrap = wrap_epoch_key(new_key.as_bytes(), &cert.kem_pubkey, &aad)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
        envelopes.push(DeviceEpochWrap {
            device_id: cert.device_id,
            wrap,
        });
    }
    let applied = store
        .revoke_device(device_id, new_key.clone())
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    if applied != new_epoch {
        return Err(KeystoreError::Identity(
            "epoch after revoke did not match wrap AAD".into(),
        ));
    }
    let wrapped = keys.wrap_secret(new_key.as_bytes())?;
    store
        .save_wrapped_epoch_key(&wrapped)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let generation = store
        .membership_snapshot()
        .map_err(|e| KeystoreError::Identity(e.to_string()))?
        .map(|s| s.generation.saturating_add(1))
        .unwrap_or(1);
    let snapshot = sign_snapshot(
        keys,
        store,
        &root,
        remaining,
        generation,
        None,
        Some(device_id),
    )?;
    store
        .save_membership_snapshot(&snapshot)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    let payload = EpochTransitionPayload {
        old_epoch,
        new_epoch,
        revoked: device_id,
        snapshot,
        envelopes,
    };
    let json = serde_json::to_vec(&payload).map_err(|e| KeystoreError::Identity(e.to_string()))?;
    store
        .save_pending_epoch_transition(&json)
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
    Ok(new_epoch)
}
