//! Mailbox-frame ingest and local Put op minting for opportunistic iOS sync.
//!
//! Uses store ingest APIs (`ingest_envelope`, `persist_signed_op`, …) instead of
//! copying `apps/shelfd/src/replica.rs`. Epoch transitions and NeedChunks
//! replies stay on `shelfd`.

use shelf_core::{DeviceId, SigningPublicKey};
use shelf_keystore::{DeviceSigner, verify_signature};
use shelf_store::SqliteStore;
use shelf_transport::{OpBody, ReplicaFrame, SignedOperation, new_op_id, parse_sig_hex, sig_hex};

/// Record signed Put ops for local objects not yet in the op log.
pub(crate) fn ensure_local_put_ops(store: &SqliteStore, signer: &DeviceSigner) {
    for rec in store.export_objects().unwrap_or_default() {
        let dedupe = format!("put:{}", rec.envelope.object_id);
        if store.has_op_dedupe(&dedupe).unwrap_or(true) {
            continue;
        }
        let seq = store.allocate_seq().unwrap_or(0);
        let mut frame = SignedOperation {
            seq,
            op_id: new_op_id(),
            vault_id: store.vault_id(),
            epoch: store.epoch(),
            origin: signer.device_id(),
            body: OpBody::Put {
                envelope: rec.envelope,
            },
            signature: String::new(),
        };
        frame.set_signature(sig_hex(&signer.sign(&frame.unsigned_bytes())));
        if let Ok(json) = serde_json::to_string(&frame) {
            let _ = store.persist_signed_op(
                frame.origin,
                frame.seq,
                &frame.op_id,
                Some(&dedupe),
                &json,
            );
        }
    }
}

/// Verify and apply a signed replica JSON frame using store ingest APIs.
pub(crate) fn ingest_signed_frame(store: &mut SqliteStore, ciphertext: &[u8]) {
    let Ok(frame) = serde_json::from_slice::<ReplicaFrame>(ciphertext) else {
        return;
    };
    if frame.vault_id != store.vault_id() {
        return;
    }
    if !frame_trusted(store, &frame) {
        return;
    }
    if matches!(
        frame.body,
        OpBody::EpochTransition { .. } | OpBody::NeedChunks { .. }
    ) {
        return;
    }
    if let Some(dedupe) = frame.dedupe_key() {
        let Ok(json) = serde_json::to_string(&frame) else {
            return;
        };
        match store.persist_signed_op(frame.origin, frame.seq, &frame.op_id, Some(&dedupe), &json) {
            Ok(false) => return,
            Ok(true) => {}
            Err(_) => return,
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
        }
        OpBody::Pin { object_id, .. } => {
            let _ = store.pin_id(object_id);
        }
        OpBody::Tombstone { object_id, at } => {
            let _ = store.apply_tombstone(object_id, at);
        }
        OpBody::Scratch { envelope } => {
            let _ = store.ingest_scratch_envelope(envelope);
        }
        OpBody::Chunk { parent, envelope } => {
            let _ = store.ingest_chunk(parent, envelope);
        }
        OpBody::NeedChunks { .. } | OpBody::EpochTransition { .. } => {}
    }
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
    let Some(pk) = member_pubkey(store, origin) else {
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
