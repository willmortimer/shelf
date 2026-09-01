//! Replica fan-out: signed frames over Tailscale TCP, LAN, and mailbox.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::store::MemoryStore;
use shelf_core::{DeviceId, ObjectId, SigningPublicKey, Timestamp};
#[cfg(test)]
use shelf_core::VaultId;
use shelf_keystore::{DeviceSigner, verify_signature};
use shelf_protocol::EncryptedObject;
use shelf_store::SqliteStore;
use shelf_transport::{
    LanTransport, MailboxClient, OpBody, ReplicaFrame, SessionHello, SignedOperation, accept_tls,
    connect_tls, hello_transcript, new_op_id, parse_home_config, parse_sig_hex, read_bounded_line,
    sig_hex, tailscale_status, tls_exporter_client, tls_exporter_server, write_bounded_line,
};
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
        store
            .mailbox_id()
            .unwrap_or_else(|_| hex_id(store.vault_id().as_bytes()))
    };

    if let Ok(listener) = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], cfg.peer_port))).await {
        let store_in = Arc::clone(&store);
        let signer_in = signer.clone();
        tokio::spawn(async move {
            accept_peer_sessions(listener, store_in, signer_in).await;
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
            let mut replies = Vec::new();
            {
                let mut store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for item in &items {
                    replies.extend(ingest_network_ciphertext(&mut store, &item.ciphertext));
                }
            }
            for item in items {
                let _ = client.ack(&mailbox_id, &item.object_id).await;
            }
            let reply_frames = {
                let store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                replies
                    .into_iter()
                    .filter_map(|(parent, envelope)| {
                        let seq = store.allocate_seq().ok()?;
                        let mut frame =
                            mint_op(&store, &signer, seq, OpBody::Chunk { parent, envelope });
                        sign_frame(&mut frame, &signer);
                        Some(frame)
                    })
                    .collect::<Vec<_>>()
            };
            for frame in &reply_frames {
                let Ok(line) = serde_json::to_vec(frame) else {
                    continue;
                };
                let _ = client.put(&mailbox_id, &frame.op_id, &line, 86_400).await;
            }
        }
    }
}

async fn accept_peer_sessions(
    listener: TcpListener,
    store: Arc<Mutex<SqliteStore>>,
    signer: DeviceSigner,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let store = Arc::clone(&store);
        let signer = signer.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = accept_tls(stream).await else {
                return;
            };
            let Ok(exporter) = tls_exporter_server(&tls) else {
                return;
            };
            let Ok(Some(hello_bytes)) = read_bounded_line(&mut tls).await else {
                return;
            };
            let Ok(hello) = serde_json::from_slice::<SessionHello>(
                hello_bytes.strip_suffix(b"\n").unwrap_or(&hello_bytes),
            ) else {
                return;
            };
            let reply_line = {
                let store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !hello_trusted(&store, &hello, &exporter) {
                    return;
                }
                let reply = local_hello(&store, &signer, &exporter);
                serde_json::to_vec(&reply).ok()
            };
            let Some(line) = reply_line else {
                return;
            };
            if write_bounded_line(&mut tls, &line).await.is_err() {
                return;
            }
            while let Ok(Some(buf)) = read_bounded_line(&mut tls).await {
                let slice = buf.strip_suffix(b"\n").unwrap_or(&buf);
                let replies = if let Ok(frame) = serde_json::from_slice::<ReplicaFrame>(slice) {
                    let mut store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_frame(&mut store, frame)
                } else {
                    Vec::new()
                };
                for (parent, envelope) in replies {
                    let line = {
                        let store = store
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let seq = store.allocate_seq().unwrap_or(1);
                        let mut frame =
                            mint_op(&store, &signer, seq, OpBody::Chunk { parent, envelope });
                        sign_frame(&mut frame, &signer);
                        serde_json::to_vec(&frame).ok()
                    };
                    if let Some(line) = line {
                        let _ = write_bounded_line(&mut tls, &line).await;
                    }
                }
            }
        });
    }
}

fn local_hello(store: &SqliteStore, signer: &DeviceSigner, exporter: &[u8; 32]) -> SessionHello {
    let transcript = hello_transcript(store.vault_id(), signer.device_id(), exporter);
    SessionHello {
        vault_id: store.vault_id(),
        device_id: signer.device_id(),
        exporter: exporter.iter().map(|b| format!("{b:02x}")).collect(),
        signature: sig_hex(&signer.sign(&transcript)),
    }
}

fn hello_trusted(store: &SqliteStore, hello: &SessionHello, exporter: &[u8; 32]) -> bool {
    if hello.vault_id != store.vault_id() {
        return false;
    }
    let Some(sig) = parse_sig_hex(&hello.signature) else {
        return false;
    };
    let transcript = hello_transcript(hello.vault_id, hello.device_id, exporter);
    let Some(pk) = member_pubkey(store, hello.device_id) else {
        return false;
    };
    verify_signature(&pk, &transcript, &sig)
}

async fn push_now(
    store: &Arc<Mutex<SqliteStore>>,
    signer: &DeviceSigner,
    mailbox: Option<&MailboxClient>,
    mailbox_id: &str,
    lan: Option<&LanTransport>,
    peer_port: u16,
) -> Result<(), std::io::Error> {
    let frames = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_op_log(&store, signer);
        let mut frames: Vec<SignedOperation> = store
            .export_ops_json()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();
        let objects = store.export_objects().unwrap_or_default();
        for rec in objects {
            if let Ok(missing) = store.missing_chunks(rec.envelope.object_id)
                && !missing.is_empty()
            {
                let seq = store.allocate_seq().unwrap_or(0);
                let mut frame = mint_op(
                    &store,
                    signer,
                    seq,
                    OpBody::NeedChunks {
                        parent: rec.envelope.object_id,
                        chunk_ids: missing,
                    },
                );
                sign_frame(&mut frame, signer);
                frames.push(frame);
            }
        }
        frames
    };

    if let Some(lan) = lan {
        let _ = lan.announce().await;
    }
    let addrs = tailscale_peer_addrs(peer_port);
    for frame in &frames {
        let Ok(line) = serde_json::to_vec(frame) else {
            continue;
        };
        if let Some(client) = mailbox {
            let _ = client.put(mailbox_id, &frame.op_id, &line, 86_400).await;
        }
        for addr in &addrs {
            let _ = send_signed_session(*addr, signer, store, &line).await;
        }
    }
    Ok(())
}

fn ensure_op_log(store: &SqliteStore, signer: &DeviceSigner) {
    let objects = store.export_objects().unwrap_or_default();
    let tombstones = store.export_tombstones().unwrap_or_default();
    let scratch = store.export_scratch().unwrap_or_default();
    let chunks = store.export_chunk_bindings().unwrap_or_default();
    for rec in objects {
        record_op(
            store,
            signer,
            &format!("put:{}", rec.envelope.object_id),
            OpBody::Put {
                envelope: rec.envelope.clone(),
            },
        );
        if rec.pinned {
            record_op(
                store,
                signer,
                &format!("pin:{}", rec.envelope.object_id),
                OpBody::Pin {
                    object_id: rec.envelope.object_id,
                    at: Timestamp::now(),
                },
            );
        }
    }
    for (id, at) in tombstones {
        record_op(
            store,
            signer,
            &format!("tomb:{id}"),
            OpBody::Tombstone { object_id: id, at },
        );
    }
    for envelope in scratch {
        record_op(
            store,
            signer,
            &format!("scratch:{}", envelope.object_id),
            OpBody::Scratch { envelope },
        );
    }
    for (parent, envelope) in chunks {
        record_op(
            store,
            signer,
            &format!("chunk:{}", envelope.object_id),
            OpBody::Chunk { parent, envelope },
        );
    }
}

fn record_op(store: &SqliteStore, signer: &DeviceSigner, dedupe: &str, body: OpBody) {
    if store.has_op_dedupe(dedupe).unwrap_or(true) {
        return;
    }
    let seq = store.allocate_seq().unwrap_or(0);
    let mut frame = mint_op(store, signer, seq, body);
    sign_frame(&mut frame, signer);
    if let Ok(json) = serde_json::to_string(&frame) {
        let _ = store.append_op_json(dedupe, &json);
    }
}

fn mint_op(store: &SqliteStore, signer: &DeviceSigner, seq: u64, body: OpBody) -> SignedOperation {
    SignedOperation {
        seq,
        op_id: new_op_id(),
        vault_id: store.vault_id(),
        epoch: store.epoch(),
        origin: signer.device_id(),
        body,
        signature: String::new(),
    }
}

async fn send_signed_session(
    addr: SocketAddr,
    signer: &DeviceSigner,
    store: &Arc<Mutex<SqliteStore>>,
    line: &[u8],
) -> Result<(), std::io::Error> {
    let connect = tokio::net::TcpStream::connect(addr);
    let stream = tokio::time::timeout(Duration::from_secs(2), connect)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "peer connect timed out")
        })??;
    let mut tls = connect_tls(stream).await?;
    let exporter = tls_exporter_client(&tls)?;
    let hello = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        local_hello(&store, signer, &exporter)
    };
    let hello_line = serde_json::to_vec(&hello).map_err(std::io::Error::other)?;
    write_bounded_line(&mut tls, &hello_line).await?;
    let Some(peer_bytes) = read_bounded_line(&mut tls).await? else {
        return Err(std::io::Error::other("peer dropped during handshake"));
    };
    let peer: SessionHello =
        serde_json::from_slice(peer_bytes.strip_suffix(b"\n").unwrap_or(&peer_bytes))
            .map_err(std::io::Error::other)?;
    {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hello_trusted(&store, &peer, &exporter) {
            return Err(std::io::Error::other("peer handshake rejected"));
        }
    }
    write_bounded_line(&mut tls, line).await
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

fn apply_frame(store: &mut SqliteStore, frame: ReplicaFrame) -> Vec<(ObjectId, EncryptedObject)> {
    if !frame_trusted(store, &frame) {
        return Vec::new();
    }
    if frame.vault_id != store.vault_id() {
        return Vec::new();
    }
    match frame.body {
        OpBody::Put { envelope } => {
            let meta = store.open_envelope(&envelope).ok();
            let created = meta
                .as_ref()
                .and_then(|o| o.created)
                .unwrap_or_else(shelf_core::HybridTimestamp::now);
            let name = meta.and_then(|o| o.name);
            let _ = store.ingest_envelope(envelope, created, false, None, name);
            Vec::new()
        }
        OpBody::Pin { object_id, .. } => {
            let _ = store.pin_id(object_id);
            Vec::new()
        }
        OpBody::Tombstone { object_id, at } => {
            let _ = store.apply_tombstone(object_id, at);
            Vec::new()
        }
        OpBody::Scratch { envelope } => {
            let _ = store.ingest_scratch_envelope(envelope);
            Vec::new()
        }
        OpBody::Chunk { parent, envelope } => {
            let _ = store.ingest_chunk(parent, envelope);
            Vec::new()
        }
        OpBody::NeedChunks { parent, chunk_ids } => store
            .chunk_envelopes(parent, &chunk_ids)
            .unwrap_or_default(),
        OpBody::Revoke { device_id, .. } => {
            let _ = store.remove_member(device_id);
            Vec::new()
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

fn ingest_network_ciphertext(
    store: &mut SqliteStore,
    ciphertext: &[u8],
) -> Vec<(ObjectId, EncryptedObject)> {
    let Ok(frame) = serde_json::from_slice::<ReplicaFrame>(ciphertext) else {
        return Vec::new();
    };
    apply_frame(store, frame)
}

fn hex_id(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Apply a signed pin locally and return a frame for tests / push-on-put.
#[cfg(test)]
pub fn signed_pin_frame(
    signer: &DeviceSigner,
    vault_id: VaultId,
    object_id: ObjectId,
) -> ReplicaFrame {
    let mut frame = SignedOperation {
        seq: 1,
        op_id: new_op_id(),
        vault_id,
        epoch: shelf_core::EpochId::new(1),
        origin: signer.device_id(),
        body: OpBody::Pin {
            object_id,
            at: Timestamp::now(),
        },
        signature: String::new(),
    };
    sign_frame(&mut frame, signer);
    frame
}

/// Apply a signed tombstone locally and return a frame.
#[cfg(test)]
pub fn signed_tombstone_frame(
    signer: &DeviceSigner,
    vault_id: VaultId,
    object_id: ObjectId,
) -> ReplicaFrame {
    let mut frame = SignedOperation {
        seq: 1,
        op_id: new_op_id(),
        vault_id,
        epoch: shelf_core::EpochId::new(1),
        origin: signer.device_id(),
        body: OpBody::Tombstone {
            object_id,
            at: Timestamp::now(),
        },
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
            request_hash: [0; 32],
            issuer_signature: shelf_core::SignatureBytes::from_bytes([0; 64]),
        }
    }

    #[test]
    fn signed_tombstone_and_pin_round_trip_two_stores() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None, true).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None, true).unwrap();
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
            &[0xEE; 32],
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.put_member(&member_cert(vault, &sb, 2)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sb, 2)).unwrap();

        let (id, created) = a.put(b"sync-me".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let mut obj = mint_op(
            &a,
            &sa,
            1,
            OpBody::Put {
                envelope: rec.envelope,
            },
        );
        sign_frame(&mut obj, &sa);
        apply_frame(&mut b, obj);
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, b"sync-me");

        let pin = signed_pin_frame(&sa, vault, id);
        apply_frame(&mut b, pin);
        assert!(b.ls().unwrap()[0].pinned);

        let tomb = signed_tombstone_frame(&sa, vault, id);
        apply_frame(&mut b, tomb);
        assert!(b.is_tombstoned(id).unwrap());
        let _ = created;
    }

    #[test]
    fn unsigned_pin_from_peer_is_rejected() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None, true).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None, true).unwrap();
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
            &[0xEE; 32],
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.put_member(&member_cert(vault, &sb, 2)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sb, 2)).unwrap();
        let (id, _) = a.put(b"sync-me".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let mut obj = mint_op(
            &a,
            &sa,
            1,
            OpBody::Put {
                envelope: rec.envelope,
            },
        );
        sign_frame(&mut obj, &sa);
        apply_frame(&mut b, obj);
        apply_frame(
            &mut b,
            SignedOperation {
                seq: 2,
                op_id: new_op_id(),
                vault_id: vault,
                epoch,
                origin: sa.device_id(),
                body: OpBody::Pin {
                    object_id: id,
                    at: Timestamp::now(),
                },
                signature: String::new(),
            },
        );
        assert!(!b.ls().unwrap()[0].pinned);
    }

    #[test]
    fn unsigned_mailbox_blob_is_ignored() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None, true).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None, true).unwrap();
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
            &[0xEE; 32],
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        let (id, _) = a.put(b"secret".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let blob = serde_json::to_vec(&rec).unwrap();
        ingest_network_ciphertext(&mut b, &blob);
        assert!(b.get(&ItemTarget::Id(id)).is_err());
    }

    #[test]
    fn signed_scratch_frame_merges() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None, true).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None, true).unwrap();
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
            &[0xEE; 32],
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.scratch_append("Scratch", "hello ").unwrap();
        let envelope = a.scratch_envelope("Scratch").unwrap().unwrap();
        let mut frame = mint_op(&a, &sa, 1, OpBody::Scratch { envelope });
        sign_frame(&mut frame, &sa);
        apply_frame(&mut b, frame);
        assert_eq!(b.scratch_text("Scratch").unwrap(), "hello ");
    }

    #[test]
    fn need_chunks_replies_with_local_envelopes() {
        use shelf_protocol::EpochKey;
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir_a.path(), Some("a"), None, true).unwrap();
        let kb = DeviceKeystore::open_or_init(dir_b.path(), Some("b"), None, true).unwrap();
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
            &[0xEE; 32],
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir_b.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sb.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        a.put_member(&member_cert(vault, &sa, 1)).unwrap();
        a.put_member(&member_cert(vault, &sb, 2)).unwrap();
        b.put_member(&member_cert(vault, &sa, 1)).unwrap();
        b.put_member(&member_cert(vault, &sb, 2)).unwrap();
        let payload = vec![0xABu8; 64];
        let (id, _) = a
            .put_file(
                "notes.bin".into(),
                "application/octet-stream".into(),
                payload.clone(),
            )
            .unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let mut put = mint_op(
            &a,
            &sa,
            1,
            OpBody::Put {
                envelope: rec.envelope,
            },
        );
        sign_frame(&mut put, &sa);
        apply_frame(&mut b, put);
        let missing = b.missing_chunks(id).unwrap();
        assert!(!missing.is_empty());
        let mut need = mint_op(
            &b,
            &sb,
            1,
            OpBody::NeedChunks {
                parent: id,
                chunk_ids: missing,
            },
        );
        sign_frame(&mut need, &sb);
        let replies = apply_frame(&mut a, need);
        assert!(!replies.is_empty());
        for (parent, envelope) in replies {
            let mut chunk = mint_op(&a, &sa, 2, OpBody::Chunk { parent, envelope });
            sign_frame(&mut chunk, &sa);
            apply_frame(&mut b, chunk);
        }
        assert!(b.missing_chunks(id).unwrap().is_empty());
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, payload);
    }
}
