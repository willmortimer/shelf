//! Open or create a durable vault under a Shelf home directory.

use std::fs;
use std::path::Path;

use shelf_core::{EpochId, VaultId};
use shelf_protocol::EpochKey;
use shelf_store::SqliteStore;

use crate::{DeviceKeystore, KeystoreError};

/// Combined keystore + SQLite vault.
pub struct Vault {
    /// Device keystore.
    pub keys: DeviceKeystore,
    /// Durable object store.
    pub store: SqliteStore,
}

/// Create `~/.shelf/` layout (`config.toml`, `state.db` parent dirs, runtime).
pub fn ensure_home_layout(home: &Path) -> Result<(), KeystoreError> {
    for dir in [
        "objects",
        "chunks",
        "logs",
        "runtime",
        "cache",
        "export",
        "enrollment",
    ] {
        fs::create_dir_all(home.join(dir))?;
    }
    let cfg = home.join("config.toml");
    if !cfg.exists() {
        fs::write(
            cfg,
            "# Shelf local preferences. Do not put secrets here.\n\
             # mailbox_url = \"127.0.0.1:8743\"\n\
             # lan_port = 18732\n\
             # peer_port = 18733\n",
        )?;
    }
    Ok(())
}

/// Open an existing vault or create a new one under `home`.
pub fn open_or_create_vault(
    home: impl AsRef<Path>,
    device_name: Option<&str>,
    passphrase: Option<&str>,
) -> Result<Vault, KeystoreError> {
    let home = home.as_ref();
    ensure_home_layout(home)?;
    let keys = DeviceKeystore::open_or_init(home, device_name, passphrase)?;
    let db = home.join("state.db");
    let store = if let Some((device_id, epoch, vault_id, wrapped)) =
        SqliteStore::load_identity(&db).map_err(|e| KeystoreError::Identity(e.to_string()))?
    {
        let raw = keys.unwrap_secret(&wrapped)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Identity("epoch key must be 32 bytes".into()))?;
        SqliteStore::open(&db, EpochKey::from_bytes(bytes), device_id, epoch, vault_id)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?
    } else {
        let epoch_key = EpochKey::new();
        let wrapped = keys.wrap_secret(epoch_key.as_bytes())?;
        let store = SqliteStore::open(
            &db,
            epoch_key,
            keys.public_identity().device_id,
            EpochId::new(1),
            VaultId::new(),
        )
        .map_err(|e| KeystoreError::Identity(e.to_string()))?;
        store
            .save_wrapped_epoch_key(&wrapped)
            .map_err(|e| KeystoreError::Identity(e.to_string()))?;
        store
    };
    Ok(Vault { keys, store })
}
