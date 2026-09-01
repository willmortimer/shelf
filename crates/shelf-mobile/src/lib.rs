//! In-process Shelf core for iOS (no always-on daemon).
//!
//! The iOS app and Share Sheet / App Intent targets link this crate and call
//! [`MobileSession`] on foreground / extension opportunities.

#![deny(missing_docs)]

use std::path::Path;
use std::sync::Mutex;

use shelf_core::ContentKind;
use shelf_keystore::{Vault, open_or_create_vault};
use shelf_store::ItemTarget;
use thiserror::Error;

/// Failures from the embedded iOS session.
#[derive(Debug, Error)]
pub enum MobileError {
    /// Vault / keystore.
    #[error("{0}")]
    Keystore(#[from] shelf_keystore::KeystoreError),
    /// Store.
    #[error("{0}")]
    Store(#[from] shelf_store::StoreError),
}

/// One-process vault for iOS (Share Sheet, App Intents). Not a network daemon.
pub struct MobileSession {
    vault: Mutex<Vault>,
}

impl MobileSession {
    /// Open or create the vault under `home` (the app's Application Support dir).
    pub fn open(home: impl AsRef<Path>) -> Result<Self, MobileError> {
        let vault = open_or_create_vault(home.as_ref(), Some("ios"), None)?;
        Ok(Self {
            vault: Mutex::new(vault),
        })
    }

    /// Put UTF-8 text (Share Sheet / App Intent).
    pub fn put_text(&self, text: &str) -> Result<String, MobileError> {
        let mut vault = self
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (id, _) = vault
            .store
            .put(text.as_bytes().to_vec(), ContentKind::Text, None)?;
        Ok(id.to_string())
    }

    /// Newest plaintext, if any.
    pub fn latest(&self) -> Result<Vec<u8>, MobileError> {
        let vault = self
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(vault.store.latest()?.bytes)
    }

    /// Get by 1-based index.
    pub fn get_index(&self, index: u64) -> Result<Vec<u8>, MobileError> {
        let vault = self
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(vault.store.get(&ItemTarget::Index(index))?.bytes)
    }
}

/// Convenience: open `home`, put text, return object id hex.
pub fn put_text_at(home: impl AsRef<Path>, text: &str) -> Result<String, MobileError> {
    MobileSession::open(home)?.put_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_latest_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open(dir.path()).unwrap();
        let id = session.put_text("from-share-sheet").unwrap();
        assert_eq!(id.len(), 64);
        assert_eq!(session.latest().unwrap(), b"from-share-sheet");
    }
}
