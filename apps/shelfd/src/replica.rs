//! Replica fan-out: sealed envelopes over Tailscale, LAN, and mailbox.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::store::MemoryStore;
use shelf_store::SqliteStore;
use shelf_transport::{LanTransport, MailboxClient, parse_home_config, tailscale_status};

/// Background replica task. Safe to ignore if transports are absent.
pub fn spawn_replica(store: Arc<Mutex<SqliteStore>>, home: PathBuf) {
    tokio::spawn(async move {
        if let Err(err) = replica_loop(store, &home).await {
            tracing::warn!(error = %err, "replica loop exited");
        }
    });
}

async fn replica_loop(store: Arc<Mutex<MemoryStore>>, home: &Path) -> Result<(), std::io::Error> {
    let cfg = parse_home_config(&home.join("config.toml"));
    let mailbox = match cfg.mailbox_url.as_deref() {
        Some(addr) if !addr.is_empty() => MailboxClient::connect(addr).await.ok(),
        _ => None,
    };
    let lan = LanTransport::bind(cfg.lan_port).await.ok();
    let mailbox_id = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        hex_id(store.vault_id().as_bytes())
    };

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        if let Ok(status) = tailscale_status() {
            tracing::debug!(
                online = status.self_online,
                peers = status.peers.len(),
                "tailscale status"
            );
        }
        let (objects, chunks, scratch) = {
            let store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                store.export_objects().unwrap_or_default(),
                store.export_chunks().unwrap_or_default(),
                store.export_scratch().unwrap_or_default(),
            )
        };
        if let Some(client) = &mailbox {
            for rec in &objects {
                let bytes = serde_json::to_vec(rec).unwrap_or_default();
                let _ = client
                    .put(
                        &mailbox_id,
                        &rec.envelope.object_id.to_string(),
                        &bytes,
                        86_400,
                    )
                    .await;
            }
            for env in &chunks {
                let bytes = serde_json::to_vec(env).unwrap_or_default();
                let _ = client
                    .put(
                        &mailbox_id,
                        &format!("chunk-{}", env.object_id),
                        &bytes,
                        86_400,
                    )
                    .await;
            }
            for (name, blob) in &scratch {
                let _ = client
                    .put(&mailbox_id, &format!("scratch-{name}"), blob, 86_400)
                    .await;
            }
            if let Ok(items) = client.get(&mailbox_id).await {
                {
                    let mut store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    for item in &items {
                        ingest_mailbox_item(&mut store, &item.object_id, &item.ciphertext);
                    }
                }
                for item in items {
                    let _ = client.ack(&mailbox_id, &item.object_id).await;
                }
            }
        }
        if let Some(lan) = &lan {
            let _ = lan.announce().await;
            for rec in &objects {
                let _ = lan.broadcast_object(rec).await;
            }
        }
    }
}

fn ingest_mailbox_item(store: &mut SqliteStore, object_id: &str, ciphertext: &[u8]) {
    if let Ok(rec) = serde_json::from_slice::<shelf_store::SealedRecord>(ciphertext) {
        let _ = store.ingest_envelope(
            rec.envelope,
            rec.created,
            rec.pinned,
            rec.expires_at,
            rec.name.clone(),
        );
        return;
    }
    if let Ok(env) = serde_json::from_slice::<shelf_protocol::EncryptedObject>(ciphertext) {
        let _ = store.ingest_chunk(env);
        return;
    }
    if let Some(name) = object_id.strip_prefix("scratch-") {
        let _ = store.scratch_apply(name, ciphertext);
    }
}

fn hex_id(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
