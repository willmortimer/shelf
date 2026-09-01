//! Signed canonical replica operations.

use serde::{Deserialize, Serialize};
use shelf_core::{
    ChunkId, DeviceId, EpochId, MembershipSnapshot, ObjectId, Timestamp, Transcript, VaultId,
};
use shelf_protocol::{DeviceEpochWrap, EncryptedObject};

/// Domain for replica operation signatures.
pub const DOMAIN_OP: &str = "shelf/op/v1";
/// Transcript version bound into [`SignedOperation::transcript`].
pub const OP_TRANSCRIPT_VERSION: u16 = 1;

/// One signed replica operation (canonical log entry).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedOperation {
    /// Per-origin sequence number.
    pub seq: u64,
    /// Random unique operation id (hex).
    pub op_id: String,
    /// Vault this op belongs to.
    pub vault_id: VaultId,
    /// Epoch at issuance.
    pub epoch: EpochId,
    /// Origin device.
    pub origin: DeviceId,
    /// Operation body.
    pub body: OpBody,
    /// Hex Ed25519 signature over [`Self::transcript`].
    pub signature: String,
}

/// Replica frame on the wire is a signed operation.
pub type ReplicaFrame = SignedOperation;

/// Session control plus signed ops on a TLS peer stream.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PeerMessage {
    /// A signed replica operation.
    Op {
        /// Signed operation.
        op: Box<SignedOperation>,
    },
    /// Anti-entropy cursor vector: highest contiguous seq per origin.
    Have {
        /// Highest applied seq per origin device.
        cursors: Vec<OriginCursor>,
    },
}

/// Highest applied sequence for one origin.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct OriginCursor {
    /// Origin device.
    pub origin: DeviceId,
    /// Highest applied seq from that origin.
    pub seq: u64,
}

/// Mutation carried by a [`SignedOperation`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OpBody {
    /// Sealed object (ciphertext only; metadata is inside the envelope).
    Put {
        /// Encrypted object envelope.
        envelope: EncryptedObject,
    },
    /// Pin an object.
    Pin {
        /// Object id.
        object_id: ObjectId,
        /// Wall time.
        at: Timestamp,
    },
    /// Tombstone an object (anti-resurrection).
    Tombstone {
        /// Object id.
        object_id: ObjectId,
        /// Wall time.
        at: Timestamp,
    },
    /// Sealed scratch pad envelope (never raw Yrs). Each edit is a new op.
    Scratch {
        /// Encrypted pad body.
        envelope: EncryptedObject,
    },
    /// File chunk bound to a parent object.
    Chunk {
        /// Parent file object id.
        parent: ObjectId,
        /// Chunk envelope.
        envelope: EncryptedObject,
    },
    /// Request missing chunks for a parent object.
    NeedChunks {
        /// Parent file object id.
        parent: ObjectId,
        /// Missing chunk ids.
        chunk_ids: Vec<ChunkId>,
    },
    /// Root-authorized epoch rotation with per-remaining-device key wraps.
    EpochTransition {
        /// Epoch before rotation.
        old_epoch: EpochId,
        /// Epoch after rotation.
        new_epoch: EpochId,
        /// Device removed from the vault.
        revoked: DeviceId,
        /// Root-signed membership after the revoke.
        snapshot: MembershipSnapshot,
        /// Hybrid wraps of the new epoch key, one per remaining device.
        envelopes: Vec<DeviceEpochWrap>,
    },
}

impl SignedOperation {
    /// Canonical binary transcript (signature not included).
    #[must_use]
    pub fn transcript(&self) -> Transcript {
        let mut t = Transcript::new(DOMAIN_OP);
        t.push_u16(OP_TRANSCRIPT_VERSION);
        t.push_fixed(self.vault_id.as_bytes());
        t.push_u64(self.epoch.as_u64());
        t.push_fixed(self.origin.as_bytes());
        t.push_u64(self.seq);
        t.push_bytes(self.op_id.as_bytes());
        match &self.body {
            OpBody::Put { envelope } => {
                t.push_u8(1);
                push_envelope(&mut t, envelope);
            }
            OpBody::Pin { object_id, at } => {
                t.push_u8(2);
                t.push_fixed(object_id.as_bytes());
                t.push_u64(at.as_millis());
            }
            OpBody::Tombstone { object_id, at } => {
                t.push_u8(3);
                t.push_fixed(object_id.as_bytes());
                t.push_u64(at.as_millis());
            }
            OpBody::Scratch { envelope } => {
                t.push_u8(4);
                push_envelope(&mut t, envelope);
            }
            OpBody::Chunk { parent, envelope } => {
                t.push_u8(5);
                t.push_fixed(parent.as_bytes());
                push_envelope(&mut t, envelope);
            }
            OpBody::NeedChunks { parent, chunk_ids } => {
                t.push_u8(6);
                t.push_fixed(parent.as_bytes());
                t.push_u16(u16::try_from(chunk_ids.len()).unwrap_or(u16::MAX));
                for id in chunk_ids {
                    t.push_fixed(id.as_bytes());
                }
            }
            OpBody::EpochTransition {
                old_epoch,
                new_epoch,
                revoked,
                snapshot,
                envelopes,
            } => {
                t.push_u8(7);
                t.push_u64(old_epoch.as_u64());
                t.push_u64(new_epoch.as_u64());
                t.push_fixed(revoked.as_bytes());
                t.push_bytes(snapshot.transcript().as_bytes());
                t.push_u16(u16::try_from(envelopes.len()).unwrap_or(u16::MAX));
                for env in envelopes {
                    t.push_fixed(env.device_id.as_bytes());
                    t.push_fixed(&env.wrap.x25519_ephemeral);
                    t.push_bytes(&env.wrap.ml_kem_ciphertext);
                }
            }
        }
        t
    }

    /// Bytes used as the signature transcript.
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        self.transcript().as_bytes().to_vec()
    }

    /// Origin device id.
    #[must_use]
    pub fn origin(&self) -> DeviceId {
        self.origin
    }

    /// Hex signature.
    #[must_use]
    pub fn signature_hex(&self) -> &str {
        &self.signature
    }

    /// Apply a signature hex string.
    pub fn set_signature(&mut self, hex: String) {
        self.signature = hex;
    }

    /// Dedupe key for the local op log (ephemeral ops return `None`).
    #[must_use]
    pub fn dedupe_key(&self) -> Option<String> {
        match &self.body {
            OpBody::Put { envelope } => Some(format!("put:{}", envelope.object_id)),
            OpBody::Pin { object_id, .. } => Some(format!("pin:{object_id}")),
            OpBody::Tombstone { object_id, .. } => Some(format!("tomb:{object_id}")),
            OpBody::Scratch { envelope } => Some(format!(
                "scratch:{}:{}",
                envelope.object_id, envelope.ciphertext_hash
            )),
            OpBody::Chunk { envelope, .. } => Some(format!("chunk:{}", envelope.object_id)),
            OpBody::NeedChunks { .. } => None,
            OpBody::EpochTransition { new_epoch, .. } => {
                Some(format!("epoch:{}", new_epoch.as_u64()))
            }
        }
    }
}

fn push_envelope(t: &mut Transcript, envelope: &EncryptedObject) {
    t.push_fixed(envelope.object_id.as_bytes());
    t.push_fixed(envelope.ciphertext_hash.as_bytes());
}

/// Encode 64 signature bytes as lowercase hex.
#[must_use]
pub fn sig_hex(sig: &[u8; 64]) -> String {
    sig.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a 128-character hex signature.
pub fn parse_sig_hex(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for i in 0..64 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Random 16-byte op id as hex.
#[must_use]
pub fn new_op_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
