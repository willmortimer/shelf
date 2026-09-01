//! Signed canonical replica operations.

use serde::{Deserialize, Serialize};
use shelf_core::{ChunkId, DeviceId, EpochId, ObjectId, Timestamp, VaultId};
use shelf_protocol::EncryptedObject;

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
    /// Hex Ed25519 signature over the unsigned operation.
    pub signature: String,
}

/// Replica frame on the wire is a signed operation.
pub type ReplicaFrame = SignedOperation;

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
    /// Sealed scratch pad envelope (never raw Yrs).
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
    /// Revoke a device and announce a new epoch (key not included).
    Revoke {
        /// Device removed from the vault.
        device_id: DeviceId,
        /// Epoch after rotation.
        new_epoch: EpochId,
    },
}

impl SignedOperation {
    /// JSON bytes used as the signature transcript (signature field empty).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.signature.clear();
        serde_json::to_vec(&copy)
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
