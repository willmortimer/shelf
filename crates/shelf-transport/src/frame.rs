//! Signed replica frames (objects, pins, tombstones).

use serde::{Deserialize, Serialize};
use shelf_core::{DeviceId, ObjectId, Timestamp};
use shelf_store::SealedRecord;

/// One signed replica operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ReplicaFrame {
    /// Sealed object (ciphertext).
    Object {
        /// Envelope plus replica metadata.
        record: Box<SealedRecord>,
        /// Origin device.
        origin: DeviceId,
        /// Hex Ed25519 signature over the unsigned frame.
        signature: String,
    },
    /// Pin an object.
    Pin {
        /// Object id.
        object_id: ObjectId,
        /// Origin device.
        origin: DeviceId,
        /// Wall time.
        at: Timestamp,
        /// Hex Ed25519 signature over the unsigned frame.
        signature: String,
    },
    /// Tombstone an object (anti-resurrection).
    Tombstone {
        /// Object id.
        object_id: ObjectId,
        /// Origin device.
        origin: DeviceId,
        /// Wall time.
        at: Timestamp,
        /// Hex Ed25519 signature over the unsigned frame.
        signature: String,
    },
}

impl ReplicaFrame {
    /// JSON bytes used as the signature transcript (signature field empty).
    pub fn unsigned_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.clear_signature();
        serde_json::to_vec(&copy)
    }

    fn clear_signature(&mut self) {
        match self {
            Self::Object { signature, .. }
            | Self::Pin { signature, .. }
            | Self::Tombstone { signature, .. } => signature.clear(),
        }
    }

    /// Origin device id.
    #[must_use]
    pub fn origin(&self) -> DeviceId {
        match self {
            Self::Object { origin, .. }
            | Self::Pin { origin, .. }
            | Self::Tombstone { origin, .. } => *origin,
        }
    }

    /// Hex signature.
    #[must_use]
    pub fn signature_hex(&self) -> &str {
        match self {
            Self::Object { signature, .. }
            | Self::Pin { signature, .. }
            | Self::Tombstone { signature, .. } => signature,
        }
    }

    /// Apply a signature hex string.
    pub fn set_signature(&mut self, hex: String) {
        match self {
            Self::Object { signature, .. }
            | Self::Pin { signature, .. }
            | Self::Tombstone { signature, .. } => *signature = hex,
        }
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
