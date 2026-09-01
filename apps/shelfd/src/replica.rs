//! Replica fan-out: signed frames over Tailscale TCP, LAN, and mailbox.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::store::MemoryStore;
#[cfg(test)]
use shelf_core::ObjectId;
use shelf_core::{DeviceId, SigningPublicKey, Timestamp};
use shelf_keystore::{DeviceSigner, verify_signature};
use shelf_store::SqliteStore;
use shelf_transport::{
    LanTransport, MailboxClient, ReplicaFrame, parse_home_config, parse_sig_hex, send_replica_line,
    sig_hex, tailscale_status,
};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Background replica task. Safe to ignore if transports are absent.
pub fn spawn_replica(
    store: Arc<Mutex<SqliteStore>>,
    home: PathBuf,
    notify: Arc<Notify>,
    signer: DeviceSigner,
) {
    tokio::spawn(async move {
        if let Err(err) = replica_loop(store, &home, notify, signer).await {
            tracing::warn!(error = %err, "replica loop exited");
        }
    });
}

async fn replica_loop(
    store: Arc<Mutex<MemoryStore>>,
    home: &Path,
    notify: Arc<Notify>,
    signer: DeviceSigner,
) -> Result<(), std::io::Error> {
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

    if let Ok(listener) = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], cfg.peer_port))).await {
        let store_in = Arc::clone(&store);
        tokio::spawn(async move {
            accept_peer_sessions(listener, store_in).await;
        });
    }

    loop {
        tokio::select! {
            _ = notify.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(30)) => {}
        }
        let _ = push_now(
            &store,
            &signer,
            mailbox.as_ref(),
            &mailbox_id,
            lan.as_ref(),
            cfg.peer_port,
        )
        .await;
        if let Some(client) = &mailbox
            && let Ok(items) = client.get(&mailbox_id).await
        {
            {
                let mut store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for item in &items {
                    if let Ok(frame) = serde_json::from_slice::<ReplicaFrame>(&item.ciphertext) {
                        apply_frame(&mut store, frame);
                    } else {
                        ingest_mailbox_item(&mut store, &item.object_id, &item.ciphertext);
                    }
                }
            }
            for item in items {
                let _ = client.ack(&mailbox_id, &item.object_id).await;
            }
        }
    }
}

async fn accept_peer_sessions(listener: TcpListener, store: Arc<Mutex<SqliteStore>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                if let Ok(frame) = serde_json::from_str::<ReplicaFrame>(line.trim_end()) {
                    let mut store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_frame(&mut store, frame);
                }
                line.clear();
            }
        });
    }
}

async fn push_now(
    store: &Arc<Mutex<SqliteStore>>,
    signer: &DeviceSigner,
    mailbox: Option<&MailboxClient>,
    mailbox_id: &str,
    lan: Option<&LanTransport>,
    peer_port: u16,
) -> Result<(), std::io::Error> {
    let (objects, tombstones) = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (
            store.export_objects().unwrap_or_default(),
            store.export_tombstones().unwrap_or_default(),
        )
    };
    let mut frames = Vec::new();
    for rec in &objects {
        let mut frame = ReplicaFrame::Object {
            record: Box::new(rec.clone()),
            origin: signer.device_id(),
            signature: String::new(),
        };
        sign_frame(&mut frame, signer);
        frames.push(frame);
    }
    for (id, at) in tombstones {
        let mut frame = ReplicaFrame::Tombstone {
            object_id: id,
            origin: signer.device_id(),
            at,
            signature: String::new(),
        };
        sign_frame(&mut frame, signer);
        frames.push(frame);
    }
    for rec in &objects {
        if rec.pinned {
            let mut frame = ReplicaFrame::Pin {
                object_id: rec.envelope.object_id,
                origin: signer.device_id(),
                at: Timestamp::now(),
                signature: String::new(),
            };
            sign_frame(&mut frame, signer);
            frames.push(frame);
        }
    }

    let addrs = tailscale_peer_addrs(peer_port);
    for frame in &frames {
        let Ok(line) = serde_json::to_vec(frame) else {
            continue;
        };
        if let Some(client) = mailbox {
            let id = match frame {
                ReplicaFrame::Object { record, .. } => record.envelope.object_id.to_string(),
                ReplicaFrame::Pin { object_id, .. } | ReplicaFrame::Tombstone { object_id, .. } => {
                    format!("op-{object_id}")
                }
            };
            let _ = client.put(mailbox_id, &id, &line, 86_400).await;
        }
        if let Some(lan) = lan
            && let ReplicaFrame::Object { record, .. } = frame
        {
            let _ = lan.broadcast_object(record).await;
        }
        for addr in &addrs {
            let _ = send_replica_line(*addr, &line).await;
        }
    }
    Ok(())
}

fn tailscale_peer_addrs(peer_port: u16) -> Vec<SocketAddr> {
    let Ok(status) = tailscale_status() else {
        return Vec::new();
    };
    let mut addrs = Vec::new();
    for peer in status.peers.into_iter().filter(|p| p.online) {
        for ip in peer.ips {
            if let Ok(addr) = format!("{ip}:{peer_port}").parse() {
                addrs.push(addr);
            }
        }
    }
    addrs
}

fn sign_frame(frame: &mut ReplicaFrame, signer: &DeviceSigner) {
    let Ok(body) = frame.unsigned_bytes() else {
        return;
    };
    frame.set_signature(sig_hex(&signer.sign(&body)));
}

fn apply_frame(store: &mut SqliteStore, frame: ReplicaFrame) {
    if !frame_trusted(store, &frame) {
        return;
    }
    match frame {
        ReplicaFrame::Object { record, .. } => {
            let _ = store.ingest_envelope(
                record.envelope,
                record.created,
                record.pinned,
                record.expires_at,
                record.name,
            );
        }
        ReplicaFrame::Pin { object_id, .. } => {
            let _ = store.pin_id(object_id);
        }
        ReplicaFrame::Tombstone { object_id, at, .. } => {
            let _ = store.apply_tombstone(object_id, at);
        }
    }
}

fn frame_trusted(store: &SqliteStore, frame: &ReplicaFrame) -> bool {
    let Some(sig) = parse_sig_hex(frame.signature_hex()) else {
        return false;
    };
    let Ok(body) = frame.unsigned_bytes() else {
        return false;
    };
    let origin = frame.origin();
    if origin == store.device_id() {
        return false;
    }
    let pk = member_pubkey(store, origin);
    let Some(pk) = pk else {
        return false;
    };
    verify_signature(&pk, &body, &sig)
}

fn member_pubkey(store: &SqliteStore, origin: DeviceId) -> Option<SigningPublicKey> {
    let members = store.members().ok()?;
    members
        .into_iter()
        .find(|c| c.device_id == origin)
        .map(|c| c.signing_pubkey)
}

fn ingest_mailbox_item(store: &mut SqliteStore, object_id: &str, ciphertext: &[u8]) {
    if let Ok(rec) = serde_json::from_slice::<shelf_store::SealedRecord>(ciphertext) {
        let _ = store.ingest_envelope(
            rec.envelope,
            rec.created,
            rec.pinned,
            rec.expires_at,
            rec.name,
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

/// Apply a signed pin locally and return a frame for tests / push-on-put.
#[cfg(test)]
pub fn signed_pin_frame(signer: &DeviceSigner, object_id: ObjectId) -> ReplicaFrame {
    let mut frame = ReplicaFrame::Pin {
        object_id,
        origin: signer.device_id(),
        at: Timestamp::now(),
        signature: String::new(),
    };
    sign_frame(&mut frame, signer);
    frame
}

/// Apply a signed tombstone locally and return a frame.
#[cfg(test)]
pub fn signed_tombstone_frame(signer: &DeviceSigner, object_id: ObjectId) -> ReplicaFrame {
    let mut frame = ReplicaFrame::Tombstone {
        object_id,
        origin: signer.device_id(),
        at: Timestamp::now(),
        signature: String::new(),
    };
    sign_frame(&mut frame, signer);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::{ContentKind, DeviceCapabilities, MemberRole, MembershipCertificate};
    use shelf_core::{EpochId, VaultId};
    use shelf_keystore::DeviceKeystore;
    use shelf_store::ItemTarget;

    fn member_cert(vault: VaultId, signer: &DeviceSigner, serial: u64) -> MembershipCertificate {
        MembershipCertificate {
            vault_id: vault,
            device_id: signer.device_id(),
            signing_pubkey: signer.verifying_key(),
            kem_pubkey: {
                use shelf_core::{HybridKemPublicKey, MlKem768PublicKey, X25519PublicKey};
                HybridKemPublicKey::new(
                    X25519PublicKey::from_bytes([0; 32]),
                    MlKem768PublicKey::from_bytes(vec![0u8; 1184]).unwrap(),
                )
            },
            role: MemberRole::Member,
            capabilities: DeviceCapabilities::default(),
            serial,
            epoch: EpochId::new(1),
            issuer: signer.device_id(),
            issuer_signing_pubkey: signer.verifying_key(),
            issued_at: Timestamp::now(),
            expires_at: None,
            issuer_signature: shelf_core::SignatureBytes::from_bytes([0; 64]),
        }
    }

    #[test]
    fn signed_tombstone_and_pin_round_trip_two_stores() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None).unwrap();
        let sa = ka.device_signer();
        let sb = kb.device_signer();
        let key_bytes = *EpochKey::new().as_bytes();
        let vault = VaultId::new();
        let epoch = EpochId::new(1);
        let mut a = SqliteStore::open(
            &dir_a.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sa.device_id(),
            epoch,
            vault,
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.put_member(&member_cert(vault, &sb, 2)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sb, 2)).unwrap();

        let (id, created) = a.put(b"sync-me".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let mut obj = ReplicaFrame::Object {
            record: Box::new(rec),
            origin: sa.device_id(),
            signature: String::new(),
        };
        sign_frame(&mut obj, &sa);
        apply_frame(&mut b, obj);
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, b"sync-me");

        let pin = signed_pin_frame(&sa, id);
        apply_frame(&mut b, pin);
        assert!(b.ls().unwrap()[0].pinned);

        let tomb = signed_tombstone_frame(&sa, id);
        apply_frame(&mut b, tomb);
        assert!(b.is_tombstoned(id).unwrap());
        let _ = created;
    }

    #[test]
    fn unsigned_pin_from_peer_is_rejected() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None).unwrap();
        let sa = ka.device_signer();
        let sb = kb.device_signer();
        let key_bytes = *EpochKey::new().as_bytes();
        let vault = VaultId::new();
        let epoch = EpochId::new(1);
        let mut a = SqliteStore::open(
            &dir_a.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sa.device_id(),
            epoch,
            vault,
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.put_member(&member_cert(vault, &sb, 2)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sb, 2)).unwrap();
        let (id, _) = a.put(b"sync-me".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let mut obj = ReplicaFrame::Object {
            record: Box::new(rec),
            origin: sa.device_id(),
            signature: String::new(),
        };
        sign_frame(&mut obj, &sa);
        apply_frame(&mut b, obj);
        apply_frame(
            &mut b,
            ReplicaFrame::Pin {
                object_id: id,
                origin: sa.device_id(),
                at: Timestamp::now(),
                signature: String::new(),
            },
        );
        assert!(!b.ls().unwrap()[0].pinned);
    }
}
