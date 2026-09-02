//! In-process Shelf core for iOS (no always-on daemon).
//!
//! The iOS app and Share Sheet / App Intent targets link this crate and call
//! [`MobileSession`] on foreground / extension opportunities. A thin C ABI
//! (`include/shelf_mobile.h`) is the Swift call surface.

#![deny(missing_docs)]

mod ffi;
mod mailbox;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use shelf_core::ContentKind;
use shelf_keystore::{Vault, open_or_create_vault};
use shelf_store::ItemTarget;
use shelf_transport::{MailboxError, parse_home_config};
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
    /// Mailbox protocol.
    #[error("{0}")]
    Mailbox(#[from] MailboxError),
    /// Tokio runtime for opportunistic mailbox I/O.
    #[error("async runtime: {0}")]
    Runtime(String),
}

/// One-process vault for iOS (Share Sheet, App Intents). Not a network daemon.
pub struct MobileSession {
    home: PathBuf,
    vault: Mutex<Vault>,
}

impl MobileSession {
    /// Open or create the vault under `home` (the app's Application Support dir).
    ///
    /// File wrap is never used. Platform Keychain or a passphrase is required.
    pub fn open(home: impl AsRef<Path>) -> Result<Self, MobileError> {
        Self::open_with(home, None)
    }

    /// Open with an optional Argon2id passphrase (tests and recovery).
    pub fn open_with(
        home: impl AsRef<Path>,
        passphrase: Option<&str>,
    ) -> Result<Self, MobileError> {
        let home = home.as_ref().to_path_buf();
        let vault = open_or_create_vault(&home, Some("ios"), passphrase, false)?;
        Ok(Self {
            home,
            vault: Mutex::new(vault),
        })
    }

    /// Put UTF-8 text (Share Sheet / App Intent).
    pub fn put_text(&self, text: &str) -> Result<String, MobileError> {
        let mut vault = self.lock_vault();
        let (id, _) = vault
            .store
            .put(text.as_bytes().to_vec(), ContentKind::Text, None)?;
        Ok(id.to_string())
    }

    /// Newest plaintext, if any.
    pub fn latest(&self) -> Result<Vec<u8>, MobileError> {
        let vault = self.lock_vault();
        Ok(vault.store.latest()?.bytes)
    }

    /// Get by 1-based index.
    pub fn get_index(&self, index: u64) -> Result<Vec<u8>, MobileError> {
        let vault = self.lock_vault();
        Ok(vault.store.get(&ItemTarget::Index(index))?.bytes)
    }

    /// One opportunistic mailbox pass when `config.toml` has `mailbox_url`.
    ///
    /// GET signed replica frames, ingest Put/Pin/Tombstone/Scratch/Chunk via
    /// store APIs, ACK, then PUT local signed Put ops to peer mailbox bindings.
    /// No-op when `mailbox_url` is unset. Does not run the `shelfd` replica
    /// loop (no Tailscale/LAN, no epoch-transition apply, no NeedChunks replies).
    pub fn sync_once(&self) -> Result<(), MobileError> {
        let cfg = parse_home_config(&self.home.join("config.toml"));
        let Some(url) = cfg.mailbox_url.filter(|u| !u.is_empty()) else {
            return Ok(());
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| MobileError::Runtime(e.to_string()))?;
        rt.block_on(self.sync_mailbox(&url))
    }

    async fn sync_mailbox(&self, url: &str) -> Result<(), MobileError> {
        let client = shelf_transport::MailboxClient::connect(url).await?;
        let (mailbox_id, read_cap, local_id, bindings, local_ops) = {
            let vault = self.lock_vault();
            let signer = vault.keys.device_signer();
            mailbox::ensure_local_put_ops(&vault.store, &signer);
            let mailbox_id = vault.store.mailbox_id()?;
            let read_cap = vault.store.mailbox_read_cap()?;
            let bindings = vault
                .store
                .membership_snapshot()
                .ok()
                .flatten()
                .map(|s| s.mailbox_bindings)
                .unwrap_or_default();
            let local_ops = vault.store.export_ops_json().unwrap_or_default();
            (
                mailbox_id,
                read_cap,
                signer.device_id(),
                bindings,
                local_ops,
            )
        };

        let items = client.get(&mailbox_id, &read_cap).await?;
        {
            let mut vault = self.lock_vault();
            for item in &items {
                mailbox::ingest_signed_frame(&mut vault.store, &item.ciphertext);
            }
        }
        for item in &items {
            let _ = client.ack(&mailbox_id, &read_cap, &item.object_id).await;
        }

        for json in &local_ops {
            let Ok(frame) = serde_json::from_str::<shelf_transport::SignedOperation>(json) else {
                continue;
            };
            let Ok(line) = serde_json::to_vec(&frame) else {
                continue;
            };
            for bind in &bindings {
                if bind.device_id == local_id {
                    continue;
                }
                let _ = client
                    .put(
                        &bind.mailbox_id,
                        &bind.write_cap,
                        &frame.op_id,
                        &line,
                        86_400,
                    )
                    .await;
            }
        }
        Ok(())
    }

    fn lock_vault(&self) -> MutexGuard<'_, Vault> {
        self.vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Convenience: open `home`, put text, return object id hex.
pub fn put_text_at(home: impl AsRef<Path>, text: &str) -> Result<String, MobileError> {
    MobileSession::open(home)?.put_text(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use shelf_core::{
        ContentKind, DeviceCapabilities, HybridKemPublicKey, MailboxBinding, MemberRole,
        MembershipCertificate, MembershipSnapshot, MlKem768PublicKey, ObjectId, SignatureBytes,
        Timestamp, X25519PublicKey,
    };
    use shelf_keystore::DeviceKeystore;
    use shelf_mailbox::{Mailbox, accept_loop};
    use shelf_protocol::{EpochKey, seal};
    use shelf_transport::{OpBody, SignedOperation, new_op_id, sig_hex};
    use tokio::net::TcpListener;

    #[test]
    fn put_then_latest_in_process() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();
        let id = session.put_text("from-share-sheet").unwrap();
        assert_eq!(id.len(), 64);
        assert_eq!(session.latest().unwrap(), b"from-share-sheet");
    }

    #[test]
    fn open_never_allows_file_key() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();
        assert!(
            !dir.path().join("wrap.key").exists(),
            "iOS must not write wrap.key"
        );
        drop(session);
    }

    #[test]
    fn sync_once_noop_without_mailbox_url() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();
        session.sync_once().unwrap();
        session.put_text("local-only").unwrap();
        assert_eq!(session.latest().unwrap(), b"local-only");
    }

    fn peer_cert(
        vault_id: shelf_core::VaultId,
        signer: &shelf_keystore::DeviceSigner,
    ) -> MembershipCertificate {
        MembershipCertificate {
            vault_id,
            device_id: signer.device_id(),
            signing_pubkey: signer.verifying_key(),
            kem_pubkey: HybridKemPublicKey::new(
                X25519PublicKey::from_bytes([0; 32]),
                MlKem768PublicKey::from_bytes(vec![0u8; 1184]).unwrap(),
            ),
            role: MemberRole::Member,
            capabilities: DeviceCapabilities::default(),
            serial: 2,
            epoch: shelf_core::EpochId::new(1),
            issuer: signer.device_id(),
            issuer_signing_pubkey: signer.verifying_key(),
            issued_at: Timestamp::now(),
            expires_at: None,
            request_hash: [0; 32],
            issuer_signature: SignatureBytes::from_bytes([0; 64]),
        }
    }

    #[test]
    fn sync_once_mailbox_get_ingests_signed_put() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();

        let peer_dir = tempfile::tempdir().unwrap();
        let peer_ks =
            DeviceKeystore::open_or_init(peer_dir.path(), Some("peer"), None, true).unwrap();
        let peer_signer = peer_ks.device_signer();

        let (vault_id, epoch, key_bytes, mailbox_id) = {
            let vault = session.lock_vault();
            vault
                .store
                .put_member(&peer_cert(vault.store.vault_id(), &peer_signer))
                .unwrap();
            // Ingest trusts the root-signed snapshot, not loose member rows.
            let root = vault.store.vault_root().unwrap().expect("local root");
            let mut snapshot = MembershipSnapshot {
                vault_root: root,
                generation: 2,
                epoch: vault.store.epoch(),
                certificates: vault.store.members().unwrap(),
                mailbox_bindings: vec![],
                routing_hints: vec![],
                snapshot_signature: SignatureBytes::from_bytes([0; 64]),
            };
            let body = snapshot.transcript();
            snapshot.snapshot_signature =
                SignatureBytes::from_bytes(vault.keys.sign(body.as_bytes()));
            vault.store.save_membership_snapshot(&snapshot).unwrap();
            (
                vault.store.vault_id(),
                vault.store.epoch(),
                *vault.store.epoch_key().as_bytes(),
                vault.store.mailbox_id().unwrap(),
            )
        };

        let envelope = seal(
            b"from-peer",
            ObjectId::new(),
            epoch,
            &EpochKey::from_bytes(key_bytes),
            ContentKind::Text,
            peer_signer.device_id(),
        )
        .unwrap();
        let mut frame = SignedOperation {
            seq: 1,
            op_id: new_op_id(),
            vault_id,
            epoch,
            origin: peer_signer.device_id(),
            body: OpBody::Put { envelope },
            signature: String::new(),
        };
        frame.set_signature(sig_hex(&peer_signer.sign(&frame.unsigned_bytes())));
        let line = serde_json::to_vec(&frame).unwrap();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap();
        let mailbox = Arc::new(Mailbox::new());
        let addr = rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(accept_loop(listener, Arc::clone(&mailbox)));
            let client = shelf_transport::MailboxClient::connect(addr.to_string())
                .await
                .unwrap();
            client
                .put(&mailbox_id, "write", &frame.op_id, &line, 60)
                .await
                .unwrap();
            addr
        });

        std::fs::write(
            dir.path().join("config.toml"),
            format!("mailbox_url = \"{addr}\"\n"),
        )
        .unwrap();

        // Keep `rt` alive so the accept loop can serve sync_once's client.
        session.sync_once().unwrap();
        assert_eq!(session.latest().unwrap(), b"from-peer");
        drop(rt);
    }

    #[test]
    fn sync_once_mailbox_put_exports_signed_local_put() {
        let dir = tempfile::tempdir().unwrap();
        let session = MobileSession::open_with(dir.path(), Some("test-pass")).unwrap();
        session.put_text("ios-out").unwrap();

        let peer_id = shelf_core::DeviceId::new();
        {
            let vault = session.lock_vault();
            let root = vault.store.vault_root().unwrap().expect("local root");
            let snap = MembershipSnapshot {
                vault_root: root,
                generation: 1,
                epoch: vault.store.epoch(),
                certificates: vec![],
                mailbox_bindings: vec![MailboxBinding {
                    device_id: peer_id,
                    mailbox_id: "peer-mb".into(),
                    write_cap: "peer-write".into(),
                }],
                routing_hints: vec![],
                snapshot_signature: SignatureBytes::from_bytes([0; 64]),
            };
            vault.store.save_membership_snapshot(&snap).unwrap();
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .unwrap();
        let mailbox = Arc::new(Mailbox::new());
        let addr = rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(accept_loop(listener, Arc::clone(&mailbox)));
            addr
        });

        std::fs::write(
            dir.path().join("config.toml"),
            format!("mailbox_url = \"{addr}\"\n"),
        )
        .unwrap();
        session.sync_once().unwrap();

        let items = rt.block_on(async {
            let client = shelf_transport::MailboxClient::connect(addr.to_string())
                .await
                .unwrap();
            client.get("peer-mb", "read").await.unwrap()
        });
        assert!(!items.is_empty(), "local signed Put should be PUTted");
        let frame: SignedOperation = serde_json::from_slice(&items[0].ciphertext).unwrap();
        assert!(matches!(frame.body, OpBody::Put { .. }));
        drop(rt);
    }
}
