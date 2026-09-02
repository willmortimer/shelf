//! Replica fan-out: signed frames over Tailscale TCP, LAN, and mailbox.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::store::MemoryStore;
#[cfg(test)]
use shelf_core::VaultId;
use shelf_core::{DeviceId, ObjectId, SigningPublicKey, Timestamp, TransportHint};
use shelf_keystore::{DeviceSigner, verify_signature};
use shelf_protocol::EncryptedObject;
use shelf_store::SqliteStore;
use shelf_transport::{
    LanTransport, MailboxClient, OpBody, OriginCursor, PeerClientTls, PeerFrame, PeerMessage,
    ReplicaFrame, SessionHello, SignedOperation, accept_tls_v2, connect_tls_v2, dial_addrs,
    hello_transcript, new_op_id, parse_home_config, parse_sig_hex, read_peer_frame, sig_hex,
    tailscale_status, tls_exporter_client, tls_exporter_server, write_peer_frame,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

/// How long a pooled peer wait (Have reply or handshake frame) may block.
const PEER_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Outbound rustls sessions keyed by the T1 dial set (`SocketAddr`).
#[derive(Default)]
struct OutboundPool {
    sessions: HashMap<SocketAddr, PeerClientTls>,
    #[cfg(test)]
    connect_count: u32,
}

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
    let lan = LanTransport::bind(cfg.lan_port, cfg.peer_port).await.ok();
    let mailbox_id = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store
            .mailbox_id()
            .unwrap_or_else(|_| hex_id(store.vault_id().as_bytes()))
    };
    let mailbox_read_cap = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.mailbox_read_cap().unwrap_or_default()
    };

    if let Ok(listener) = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], cfg.peer_port))).await {
        let store_in = Arc::clone(&store);
        let signer_in = signer.clone();
        tokio::spawn(async move {
            accept_peer_sessions(listener, store_in, signer_in).await;
        });
    }

    let mut pool = OutboundPool::default();
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
            &mut pool,
        )
        .await;
        if let Some(client) = &mailbox
            && let Ok(items) = client.get(&mailbox_id, &mailbox_read_cap).await
        {
            let mut replies = Vec::new();
            {
                let mut store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for item in &items {
                    replies.extend(ingest_network_ciphertext(
                        &mut store,
                        Some(&signer),
                        &item.ciphertext,
                    ));
                }
            }
            for item in items {
                let _ = client
                    .ack(&mailbox_id, &mailbox_read_cap, &item.object_id)
                    .await;
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
                let bindings = {
                    let store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    store
                        .membership_snapshot()
                        .ok()
                        .flatten()
                        .map(|s| s.mailbox_bindings)
                        .unwrap_or_default()
                };
                for bind in bindings {
                    if bind.device_id == signer.device_id() {
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
            serve_peer_connection(stream, store, signer).await;
        });
    }
}

/// Inbound `shelf/2` session: Hello, then Have/Op until EOF. Bare SignedOperation JSON is not a frame.
async fn serve_peer_connection(
    stream: TcpStream,
    store: Arc<Mutex<SqliteStore>>,
    signer: DeviceSigner,
) {
    let Ok(mut tls) = accept_tls_v2(stream).await else {
        return;
    };
    let Ok(exporter) = tls_exporter_server(&tls) else {
        return;
    };
    let Ok(Some(PeerFrame::Hello(hello))) = read_peer_frame(&mut tls).await else {
        return;
    };
    let reply = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hello_trusted(&store, &hello, &exporter) {
            return;
        }
        local_hello(&store, &signer, &exporter)
    };
    if write_peer_frame(&mut tls, &PeerFrame::Hello(reply))
        .await
        .is_err()
    {
        return;
    }
    while let Ok(Some(frame)) = read_peer_frame(&mut tls).await {
        match frame {
            PeerFrame::Hello(_) => return,
            PeerFrame::Message(PeerMessage::Have { cursors }) => {
                let (have, missing) = {
                    let store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let ours = store
                        .op_cursors()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(origin, seq)| OriginCursor { origin, seq })
                        .collect::<Vec<_>>();
                    let want: Vec<(DeviceId, u64)> =
                        cursors.iter().map(|c| (c.origin, c.seq)).collect();
                    let missing = store.export_ops_after(&want).unwrap_or_default();
                    (ours, missing)
                };
                if write_peer_frame(
                    &mut tls,
                    &PeerFrame::Message(PeerMessage::Have { cursors: have }),
                )
                .await
                .is_err()
                {
                    return;
                }
                for json in missing {
                    if let Ok(op) = serde_json::from_str::<SignedOperation>(&json)
                        && write_peer_frame(
                            &mut tls,
                            &PeerFrame::Message(PeerMessage::Op { op: Box::new(op) }),
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            PeerFrame::Message(PeerMessage::Op { op }) => {
                let replies = {
                    let mut store = store
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    apply_frame(&mut store, Some(&signer), *op)
                };
                for (parent, envelope) in replies {
                    let frame = {
                        let store = store
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let seq = store.allocate_seq().unwrap_or(1);
                        let mut frame =
                            mint_op(&store, &signer, seq, OpBody::Chunk { parent, envelope });
                        sign_frame(&mut frame, &signer);
                        frame
                    };
                    if write_peer_frame(
                        &mut tls,
                        &PeerFrame::Message(PeerMessage::Op {
                            op: Box::new(frame),
                        }),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}

fn local_hello(store: &SqliteStore, signer: &DeviceSigner, exporter: &[u8; 32]) -> SessionHello {
    let transcript = hello_transcript(store.vault_id(), signer.device_id(), exporter);
    SessionHello {
        vault_id: store.vault_id(),
        device_id: signer.device_id(),
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
    _mailbox_id: &str,
    lan: Option<&LanTransport>,
    peer_port: u16,
    pool: &mut OutboundPool,
) -> Result<(), std::io::Error> {
    let (need_frames, our_cursors, bindings, member_hints) = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ensure_op_log(&store, signer);
        let mut need_frames = Vec::new();
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
                need_frames.push(frame);
            }
        }
        let our_cursors = store
            .op_cursors()
            .unwrap_or_default()
            .into_iter()
            .map(|(origin, seq)| OriginCursor { origin, seq })
            .collect::<Vec<_>>();
        let bindings = store
            .membership_snapshot()
            .ok()
            .flatten()
            .map(|s| s.mailbox_bindings)
            .unwrap_or_default();
        let member_hints = validated_member_hints(&store);
        (need_frames, our_cursors, bindings, member_hints)
    };

    // LAN discovery is a separate dial path; do not feed these into dial_addrs.
    let mut lan_addrs = Vec::new();
    if let Some(lan) = lan {
        for peer in lan.discover().await {
            for addr in peer.addrs {
                if !lan_addrs.contains(&addr) {
                    lan_addrs.push(addr);
                }
            }
        }
    }

    if let Some(client) = mailbox {
        let ops = {
            let store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            store.export_ops_json().unwrap_or_default()
        };
        for json in &ops {
            let Ok(frame) = serde_json::from_str::<SignedOperation>(json) else {
                continue;
            };
            let Ok(line) = serde_json::to_vec(&frame) else {
                continue;
            };
            for bind in &bindings {
                if bind.device_id == signer.device_id() {
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
        for frame in &need_frames {
            let Ok(line) = serde_json::to_vec(frame) else {
                continue;
            };
            for bind in &bindings {
                if bind.device_id == signer.device_id() {
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
    }

    let mut addrs = tailscale_peer_addrs(&member_hints, peer_port);
    for addr in lan_addrs {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    pool.sessions.retain(|addr, _| addrs.contains(addr));
    for addr in addrs {
        let _ = sync_peer(pool, addr, signer, store, &our_cursors, &need_frames).await;
    }
    Ok(())
}

fn ensure_op_log(store: &SqliteStore, signer: &DeviceSigner) {
    if let Ok(Some(bytes)) = store.take_pending_epoch_transition()
        && let Ok(payload) =
            serde_json::from_slice::<shelf_protocol::EpochTransitionPayload>(&bytes)
    {
        record_op(
            store,
            signer,
            &format!("epoch:{}", payload.new_epoch.as_u64()),
            OpBody::EpochTransition {
                old_epoch: payload.old_epoch,
                new_epoch: payload.new_epoch,
                revoked: payload.revoked,
                snapshot: payload.snapshot,
                envelopes: payload.envelopes,
            },
        );
    }
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
            &format!(
                "scratch:{}:{}",
                envelope.object_id, envelope.ciphertext_hash
            ),
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
        let _ = store.persist_signed_op(frame.origin, frame.seq, &frame.op_id, Some(dedupe), &json);
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

async fn sync_peer(
    pool: &mut OutboundPool,
    addr: SocketAddr,
    signer: &DeviceSigner,
    store: &Arc<Mutex<SqliteStore>>,
    our_cursors: &[OriginCursor],
    need_frames: &[SignedOperation],
) -> Result<(), std::io::Error> {
    if !pool.sessions.contains_key(&addr) {
        let tls = open_outbound_session(addr, signer, store).await?;
        note_connect(pool);
        pool.sessions.insert(addr, tls);
    }
    {
        let Some(reused) = pool.sessions.get_mut(&addr) else {
            return Err(std::io::Error::other("missing pooled session"));
        };
        if exchange_have(reused, signer, store, our_cursors, need_frames)
            .await
            .is_ok()
        {
            return Ok(());
        }
    }
    pool.sessions.remove(&addr);
    let mut tls = open_outbound_session(addr, signer, store).await?;
    note_connect(pool);
    exchange_have(&mut tls, signer, store, our_cursors, need_frames).await?;
    pool.sessions.insert(addr, tls);
    Ok(())
}

fn note_connect(#[cfg_attr(not(test), allow(unused_variables))] pool: &mut OutboundPool) {
    #[cfg(test)]
    {
        pool.connect_count = pool.connect_count.saturating_add(1);
    }
}

async fn open_outbound_session(
    addr: SocketAddr,
    signer: &DeviceSigner,
    store: &Arc<Mutex<SqliteStore>>,
) -> Result<PeerClientTls, std::io::Error> {
    let connect = TcpStream::connect(addr);
    let stream = tokio::time::timeout(Duration::from_secs(2), connect)
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "peer connect timed out")
        })??;
    let mut tls = connect_tls_v2(stream).await?;
    let exporter = tls_exporter_client(&tls)?;
    let hello = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        local_hello(&store, signer, &exporter)
    };
    write_peer_frame(&mut tls, &PeerFrame::Hello(hello)).await?;
    let peer = match read_frame_timed(&mut tls).await? {
        Some(PeerFrame::Hello(hello)) => hello,
        Some(_) => {
            return Err(std::io::Error::other(
                "peer sent non-hello during handshake",
            ));
        }
        None => return Err(std::io::Error::other("peer dropped during handshake")),
    };
    {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !hello_trusted(&store, &peer, &exporter) {
            return Err(std::io::Error::other("peer handshake rejected"));
        }
    }
    Ok(tls)
}

async fn exchange_have(
    tls: &mut PeerClientTls,
    signer: &DeviceSigner,
    store: &Arc<Mutex<SqliteStore>>,
    our_cursors: &[OriginCursor],
    need_frames: &[SignedOperation],
) -> Result<(), std::io::Error> {
    write_peer_frame(
        tls,
        &PeerFrame::Message(PeerMessage::Have {
            cursors: our_cursors.to_vec(),
        }),
    )
    .await?;
    let peer_cursors = loop {
        match read_frame_timed(tls).await? {
            Some(PeerFrame::Hello(_)) => {
                return Err(std::io::Error::other("unexpected hello after handshake"));
            }
            Some(PeerFrame::Message(PeerMessage::Have { cursors })) => {
                break cursors
                    .into_iter()
                    .map(|c| (c.origin, c.seq))
                    .collect::<Vec<_>>();
            }
            Some(PeerFrame::Message(PeerMessage::Op { op })) => {
                let mut store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = apply_frame(&mut store, Some(signer), *op);
            }
            None => return Err(std::io::Error::other("peer closed during have")),
        }
    };
    let missing = {
        let store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        store.export_ops_after(&peer_cursors).unwrap_or_default()
    };
    for json in missing {
        if let Ok(op) = serde_json::from_str::<SignedOperation>(&json) {
            write_peer_frame(
                tls,
                &PeerFrame::Message(PeerMessage::Op { op: Box::new(op) }),
            )
            .await?;
        }
    }
    for frame in need_frames {
        write_peer_frame(
            tls,
            &PeerFrame::Message(PeerMessage::Op {
                op: Box::new(frame.clone()),
            }),
        )
        .await?;
    }
    Ok(())
}

async fn read_frame_timed(tls: &mut PeerClientTls) -> Result<Option<PeerFrame>, std::io::Error> {
    tokio::time::timeout(PEER_IO_TIMEOUT, read_peer_frame(tls))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "peer i/o timed out"))?
}

fn validated_member_hints(store: &SqliteStore) -> Vec<TransportHint> {
    let Ok(members) = store.validated_members() else {
        return Vec::new();
    };
    if members.is_empty() {
        return Vec::new();
    }
    let local = store.device_id();
    let ids: std::collections::BTreeSet<_> = members
        .into_iter()
        .map(|c| c.device_id)
        .filter(|id| *id != local)
        .collect();
    let Ok(Some(snap)) = store.membership_snapshot() else {
        return Vec::new();
    };
    snap.routing_hints
        .into_iter()
        .filter(|b| ids.contains(&b.device_id))
        .flat_map(|b| b.hints)
        .collect()
}

fn tailscale_peer_addrs(member_hints: &[TransportHint], peer_port: u16) -> Vec<SocketAddr> {
    let Ok(status) = tailscale_status() else {
        return Vec::new();
    };
    dial_addrs(&status, member_hints, peer_port)
}

fn sign_frame(frame: &mut ReplicaFrame, signer: &DeviceSigner) {
    let body = frame.unsigned_bytes();
    frame.set_signature(sig_hex(&signer.sign(&body)));
}

fn apply_frame(
    store: &mut SqliteStore,
    signer: Option<&DeviceSigner>,
    frame: ReplicaFrame,
) -> Vec<(ObjectId, EncryptedObject)> {
    if frame.vault_id != store.vault_id() {
        return Vec::new();
    }
    if !frame_trusted(store, &frame) {
        return Vec::new();
    }
    if matches!(frame.body, OpBody::EpochTransition { .. }) && !origin_is_root(store, &frame) {
        return Vec::new();
    }
    if matches!(frame.body, OpBody::EpochTransition { .. })
        && !epoch_wrap_for_local(store, signer, &frame)
    {
        return Vec::new();
    }
    if let Some(dedupe) = frame.dedupe_key() {
        let Ok(json) = serde_json::to_string(&frame) else {
            return Vec::new();
        };
        match store.persist_signed_op(frame.origin, frame.seq, &frame.op_id, Some(&dedupe), &json) {
            Ok(false) => return Vec::new(),
            Ok(true) => {}
            Err(_) => return Vec::new(),
        }
    }
    match frame.body {
        OpBody::Put { envelope } => {
            let meta = store.open_envelope(&envelope).ok();
            let created = meta
                .as_ref()
                .and_then(|o| o.created)
                .unwrap_or_else(shelf_core::HybridTimestamp::now);
            let expires = meta.as_ref().and_then(|o| o.expires_at);
            let name = meta.and_then(|o| o.name);
            let _ = store.ingest_envelope(envelope, created, false, expires, name);
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
        OpBody::EpochTransition {
            old_epoch,
            new_epoch,
            revoked,
            snapshot,
            envelopes,
        } => {
            let Some(signer) = signer else {
                return Vec::new();
            };
            let Some(mine) = envelopes.iter().find(|e| e.device_id == signer.device_id()) else {
                return Vec::new();
            };
            let aad = shelf_protocol::epoch_transition_aad(
                store.vault_id(),
                old_epoch,
                new_epoch,
                revoked,
            );
            let Ok(raw) = signer.unwrap_epoch(&mine.wrap, &aad) else {
                return Vec::new();
            };
            let Ok(wrapped) = signer.wrap_secret(&raw) else {
                return Vec::new();
            };
            let key = shelf_protocol::EpochKey::from_bytes(raw);
            let _ = store.add_epoch_key(new_epoch, key.clone());
            let _ = store.adopt_membership(key, new_epoch, store.vault_id());
            let _ = store.save_wrapped_epoch_key(&wrapped);
            let _ = store.remove_member(revoked);
            let _ = store.save_membership_snapshot(&snapshot);
            Vec::new()
        }
    }
}

fn origin_is_root(store: &SqliteStore, frame: &ReplicaFrame) -> bool {
    let Ok(Some(root)) = store.vault_root() else {
        return false;
    };
    let Some(pk) = member_pubkey(store, frame.origin()) else {
        return false;
    };
    pk == root.root_signing_pubkey
}

fn epoch_wrap_for_local(
    store: &SqliteStore,
    signer: Option<&DeviceSigner>,
    frame: &ReplicaFrame,
) -> bool {
    let OpBody::EpochTransition {
        old_epoch,
        new_epoch,
        revoked,
        envelopes,
        ..
    } = &frame.body
    else {
        return true;
    };
    let Some(signer) = signer else {
        return false;
    };
    let Some(mine) = envelopes.iter().find(|e| e.device_id == signer.device_id()) else {
        return false;
    };
    let aad =
        shelf_protocol::epoch_transition_aad(store.vault_id(), *old_epoch, *new_epoch, *revoked);
    signer.unwrap_epoch(&mine.wrap, &aad).is_ok()
}

fn frame_trusted(store: &SqliteStore, frame: &ReplicaFrame) -> bool {
    let Some(sig) = parse_sig_hex(frame.signature_hex()) else {
        return false;
    };
    let body = frame.unsigned_bytes();
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
    let members = store
        .validated_members()
        .ok()
        .filter(|m| !m.is_empty())
        .or_else(|| store.members().ok())?;
    members
        .into_iter()
        .find(|c| c.device_id == origin)
        .map(|c| c.signing_pubkey)
}

fn ingest_network_ciphertext(
    store: &mut SqliteStore,
    signer: Option<&DeviceSigner>,
    ciphertext: &[u8],
) -> Vec<(ObjectId, EncryptedObject)> {
    let Ok(frame) = serde_json::from_slice::<ReplicaFrame>(ciphertext) else {
        return Vec::new();
    };
    apply_frame(store, signer, frame)
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
        seq: 2,
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
        seq: 3,
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
    fn validated_member_hints_empty_without_signed_snapshot() {
        use shelf_protocol::EpochKey;
        let dir = tempfile::tempdir().unwrap();
        let ka = DeviceKeystore::open_or_init(dir.path(), Some("a"), None, true).unwrap();
        let sa = ka.device_signer();
        let store = SqliteStore::open(
            &dir.path().join("state.db"),
            EpochKey::from_bytes(*EpochKey::new().as_bytes()),
            sa.device_id(),
            EpochId::new(1),
            VaultId::new(),
            &[0xEE; 32],
        )
        .unwrap();
        assert!(validated_member_hints(&store).is_empty());
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
        apply_frame(&mut b, Some(&sb), obj);
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, b"sync-me");

        let pin = signed_pin_frame(&sa, vault, id);
        apply_frame(&mut b, Some(&sb), pin);
        assert!(b.ls().unwrap()[0].pinned);

        let tomb = signed_tombstone_frame(&sa, vault, id);
        apply_frame(&mut b, Some(&sb), tomb);
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
        apply_frame(&mut b, Some(&sb), obj);
        apply_frame(
            &mut b,
            Some(&sb),
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
        ingest_network_ciphertext(&mut b, None, &blob);
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
        apply_frame(&mut b, Some(&sb), frame);
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
        apply_frame(&mut b, Some(&sb), put);
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
        let replies = apply_frame(&mut a, Some(&sa), need);
        assert!(!replies.is_empty());
        for (parent, envelope) in replies {
            let mut chunk = mint_op(&a, &sa, 2, OpBody::Chunk { parent, envelope });
            sign_frame(&mut chunk, &sa);
            apply_frame(&mut b, Some(&sb), chunk);
        }
        assert!(b.missing_chunks(id).unwrap().is_empty());
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, payload);
    }

    #[test]
    fn subsequent_scratch_edits_replicate() {
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
        let env1 = a.scratch_envelope("Scratch").unwrap().unwrap();
        let mut f1 = mint_op(&a, &sa, 1, OpBody::Scratch { envelope: env1 });
        sign_frame(&mut f1, &sa);
        apply_frame(&mut b, Some(&sb), f1);
        a.scratch_append("Scratch", "world").unwrap();
        let env2 = a.scratch_envelope("Scratch").unwrap().unwrap();
        let mut f2 = mint_op(&a, &sa, 2, OpBody::Scratch { envelope: env2 });
        sign_frame(&mut f2, &sa);
        apply_frame(&mut b, Some(&sb), f2);
        assert_eq!(b.scratch_text("Scratch").unwrap(), "hello world");
    }

    #[test]
    fn inbound_put_preserves_authenticated_expiry() {
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
        let (_id, _) = a.put(b"ttl".to_vec(), ContentKind::Text, None).unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        assert!(rec.expires_at.is_some());
        let mut obj = mint_op(
            &a,
            &sa,
            1,
            OpBody::Put {
                envelope: rec.envelope,
            },
        );
        sign_frame(&mut obj, &sa);
        apply_frame(&mut b, Some(&sb), obj);
        assert!(b.ls().unwrap()[0].expires_at.is_some());
    }

    #[test]
    fn duplicate_op_id_is_ignored_and_seq_conflict_rejected() {
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
        let (id, _) = a.put(b"once".to_vec(), ContentKind::Text, None).unwrap();
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
        apply_frame(&mut b, Some(&sb), obj.clone());
        apply_frame(&mut b, Some(&sb), obj.clone());
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, b"once");
        let mut pin = mint_op(
            &a,
            &sa,
            1,
            OpBody::Pin {
                object_id: id,
                at: Timestamp::now(),
            },
        );
        sign_frame(&mut pin, &sa);
        apply_frame(&mut b, Some(&sb), pin);
        assert!(!b.ls().unwrap()[0].pinned);
    }

    struct TwoStores {
        _dir_a: tempfile::TempDir,
        _dir_b: tempfile::TempDir,
        sa: DeviceSigner,
        sb: DeviceSigner,
        a: Arc<Mutex<SqliteStore>>,
        b: Arc<Mutex<SqliteStore>>,
    }

    fn two_member_stores() -> TwoStores {
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
        let a = SqliteStore::open(
            &dir_a.path().join("state.db"),
            EpochKey::from_bytes(key_bytes),
            sa.device_id(),
            epoch,
            vault,
            &[0xEE; 32],
        )
        .unwrap();
        let b = SqliteStore::open(
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
        TwoStores {
            _dir_a: dir_a,
            _dir_b: dir_b,
            sa,
            sb,
            a: Arc::new(Mutex::new(a)),
            b: Arc::new(Mutex::new(b)),
        }
    }

    fn put_logged(
        store: &Arc<Mutex<SqliteStore>>,
        signer: &DeviceSigner,
        bytes: &[u8],
    ) -> (ObjectId, Vec<OriginCursor>) {
        let mut store = store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (id, _) = store.put(bytes.to_vec(), ContentKind::Text, None).unwrap();
        ensure_op_log(&store, signer);
        let cursors = store
            .op_cursors()
            .unwrap_or_default()
            .into_iter()
            .map(|(origin, seq)| OriginCursor { origin, seq })
            .collect();
        (id, cursors)
    }

    async fn wait_bytes(store: &Arc<Mutex<SqliteStore>>, id: ObjectId, expected: &[u8]) {
        for _ in 0..100 {
            {
                let store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Ok(got) = store.get(&ItemTarget::Id(id))
                    && got.bytes == expected
                {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for replicated object");
    }

    #[tokio::test]
    async fn two_have_batches_reuse_one_tls_connection() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pair = two_member_stores();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connects = Arc::new(AtomicUsize::new(0));
        let store_in = Arc::clone(&pair.b);
        let signer_in = pair.sb.clone();
        let connects_in = Arc::clone(&connects);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                connects_in.fetch_add(1, Ordering::SeqCst);
                let store = Arc::clone(&store_in);
                let signer = signer_in.clone();
                tokio::spawn(async move {
                    serve_peer_connection(stream, store, signer).await;
                });
            }
        });

        let mut pool = OutboundPool::default();
        let (id1, cursors) = put_logged(&pair.a, &pair.sa, b"batch-one");
        sync_peer(&mut pool, addr, &pair.sa, &pair.a, &cursors, &[])
            .await
            .unwrap();
        wait_bytes(&pair.b, id1, b"batch-one").await;
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(pool.connect_count, 1);

        let (id2, cursors) = put_logged(&pair.a, &pair.sa, b"batch-two");
        sync_peer(&mut pool, addr, &pair.sa, &pair.a, &cursors, &[])
            .await
            .unwrap();
        wait_bytes(&pair.b, id2, b"batch-two").await;
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(pool.connect_count, 1);
        assert_eq!(pool.sessions.len(), 1);
    }

    #[tokio::test]
    async fn outbound_pool_reconnects_after_io_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pair = two_member_stores();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connects = Arc::new(AtomicUsize::new(0));
        let store_in = Arc::clone(&pair.b);
        let signer_in = pair.sb.clone();
        let connects_in = Arc::clone(&connects);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                connects_in.fetch_add(1, Ordering::SeqCst);
                let store = Arc::clone(&store_in);
                let signer = signer_in.clone();
                let drop_after_have = connects_in.load(Ordering::SeqCst) == 1;
                tokio::spawn(async move {
                    if drop_after_have {
                        serve_one_have_then_drop(stream, store, signer).await;
                    } else {
                        serve_peer_connection(stream, store, signer).await;
                    }
                });
            }
        });

        let mut pool = OutboundPool::default();
        let (id1, cursors) = put_logged(&pair.a, &pair.sa, b"first");
        sync_peer(&mut pool, addr, &pair.sa, &pair.a, &cursors, &[])
            .await
            .unwrap();
        wait_bytes(&pair.b, id1, b"first").await;
        assert_eq!(pool.connect_count, 1);

        let (id2, cursors) = put_logged(&pair.a, &pair.sa, b"second");
        sync_peer(&mut pool, addr, &pair.sa, &pair.a, &cursors, &[])
            .await
            .unwrap();
        wait_bytes(&pair.b, id2, b"second").await;
        assert_eq!(connects.load(Ordering::SeqCst), 2);
        assert_eq!(pool.connect_count, 2);
    }

    async fn serve_one_have_then_drop(
        stream: tokio::net::TcpStream,
        store: Arc<Mutex<SqliteStore>>,
        signer: DeviceSigner,
    ) {
        let Ok(mut tls) = accept_tls_v2(stream).await else {
            return;
        };
        let Ok(exporter) = tls_exporter_server(&tls) else {
            return;
        };
        let Ok(Some(PeerFrame::Hello(hello))) = read_peer_frame(&mut tls).await else {
            return;
        };
        let reply = {
            let store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !hello_trusted(&store, &hello, &exporter) {
                return;
            }
            local_hello(&store, &signer, &exporter)
        };
        if write_peer_frame(&mut tls, &PeerFrame::Hello(reply))
            .await
            .is_err()
        {
            return;
        }
        if let Ok(Some(PeerFrame::Message(PeerMessage::Have { cursors }))) =
            read_peer_frame(&mut tls).await
        {
            let (have, missing) = {
                let store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let ours = store
                    .op_cursors()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(origin, seq)| OriginCursor { origin, seq })
                    .collect::<Vec<_>>();
                let want: Vec<(DeviceId, u64)> =
                    cursors.iter().map(|c| (c.origin, c.seq)).collect();
                let missing = store.export_ops_after(&want).unwrap_or_default();
                (ours, missing)
            };
            let _ = write_peer_frame(
                &mut tls,
                &PeerFrame::Message(PeerMessage::Have { cursors: have }),
            )
            .await;
            for json in missing {
                if let Ok(op) = serde_json::from_str::<SignedOperation>(&json) {
                    let _ = write_peer_frame(
                        &mut tls,
                        &PeerFrame::Message(PeerMessage::Op { op: Box::new(op) }),
                    )
                    .await;
                }
            }
            if let Ok(Some(PeerFrame::Message(PeerMessage::Op { op }))) =
                read_peer_frame(&mut tls).await
            {
                let mut store = store
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = apply_frame(&mut store, Some(&signer), *op);
            }
        }
    }
}
