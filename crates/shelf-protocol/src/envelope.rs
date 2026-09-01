//! Versioned encrypted object envelopes.

use serde::{Deserialize, Serialize};
use shelf_core::{
    AeadAlgorithm, ContentKind, Dek, DeviceId, EpochId, HybridTimestamp, ObjectId, PREFERRED_AEAD,
    RetentionPolicy, Timestamp,
};

use crate::aad::object_aad;
use crate::b64;
use crate::cipher::{open_xchacha, seal_xchacha, xnonce_bytes};
use crate::error::ProtocolError;
use crate::wrap::{EpochKey, KeyEnvelope, unwrap_dek, wrap_dek};

/// Envelope format version written by [`seal`] (retention inside AEAD).
pub const ENVELOPE_VERSION: u16 = 3;
/// Legacy envelope that carried kind/origin in JSON.
pub const ENVELOPE_VERSION_V1: u16 = 1;
/// v2: kind/origin/name/created inside AEAD, no retention.
pub const ENVELOPE_VERSION_V2: u16 = 2;

/// BLAKE3-256 digest of ciphertext (never of plaintext).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash([u8; 32]);

impl Hash {
    /// Wrap a 32-byte digest.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// BLAKE3 of `ciphertext` only.
    #[must_use]
    pub fn of_ciphertext(ciphertext: &[u8]) -> Self {
        Self(*blake3::hash(ciphertext).as_bytes())
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Hash")
            .field(&format_args!("{}", hex(self.as_bytes())))
            .finish()
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex(self.as_bytes()))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Encrypted object envelope for storage and replication.
///
/// v2 keeps kind, origin, name, and created timestamps inside the AEAD
/// plaintext. JSON on the wire is object id, epoch, wrap, and ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedObject {
    /// Envelope format version. Currently [`ENVELOPE_VERSION`].
    pub version: u16,
    /// Random opaque object identifier (not a plaintext hash).
    pub object_id: ObjectId,
    /// Vault epoch whose key wraps [`Self::wrapped_dek`].
    pub epoch: EpochId,
    /// Payload AEAD algorithm. v1 seals with XChaCha20-Poly1305 only.
    pub algorithm: AeadAlgorithm,
    /// Payload nonce (24 bytes for XChaCha20-Poly1305).
    #[serde(with = "b64")]
    pub nonce: Vec<u8>,
    /// DEK wrapped under the epoch key.
    pub wrapped_dek: KeyEnvelope,
    /// AEAD ciphertext of the object plaintext (and, for v2+, inner metadata).
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
    /// BLAKE3 of [`Self::ciphertext`], never of the plaintext.
    pub ciphertext_hash: Hash,
    /// v1 only: content class. Omitted on v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_kind: Option<ContentKind>,
    /// v1 only: originating device. Omitted on v2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<DeviceId>,
}

/// Opened envelope: plaintext plus authenticated inner metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedPayload {
    /// Object bytes (Yrs update, file chunk, or user payload).
    pub plaintext: Vec<u8>,
    /// Authenticated content class.
    pub content_kind: ContentKind,
    /// Authenticated origin device.
    pub origin: DeviceId,
    /// Optional display name (v2).
    pub name: Option<String>,
    /// Creation timestamp from the inner envelope (v2+) or unknown (v1).
    pub created: Option<HybridTimestamp>,
    /// Authenticated absolute expiry (v3).
    pub expires_at: Option<Timestamp>,
    /// Authenticated retention class (v3).
    pub retention_policy: Option<RetentionPolicy>,
}

/// Seal `plaintext` under a fresh DEK wrapped by `epoch_key`.
///
/// Uses [`PREFERRED_AEAD`] (XChaCha20-Poly1305). AES-256-GCM is rejected.
pub fn seal(
    plaintext: &[u8],
    object_id: ObjectId,
    epoch: EpochId,
    epoch_key: &EpochKey,
    content_kind: ContentKind,
    origin: DeviceId,
) -> Result<EncryptedObject, ProtocolError> {
    seal_named(
        plaintext,
        object_id,
        epoch,
        epoch_key,
        content_kind,
        origin,
        None,
        None,
    )
}

/// Seal with optional name and creation timestamp bound into the inner body.
#[allow(clippy::too_many_arguments)]
pub fn seal_named(
    plaintext: &[u8],
    object_id: ObjectId,
    epoch: EpochId,
    epoch_key: &EpochKey,
    content_kind: ContentKind,
    origin: DeviceId,
    name: Option<&str>,
    created: Option<HybridTimestamp>,
) -> Result<EncryptedObject, ProtocolError> {
    let algorithm = PREFERRED_AEAD;
    require_payload_algorithm(algorithm)?;

    let dek = Dek::new();
    let nonce: [u8; 24] = rand::random();
    let inner = encode_inner(content_kind, origin, name, created, plaintext);
    let aad = object_aad(ENVELOPE_VERSION, object_id, epoch, algorithm, None, None);
    let ciphertext = seal_xchacha(dek.as_bytes(), &nonce, &aad, &inner)?;
    let ciphertext_hash = Hash::of_ciphertext(&ciphertext);
    let wrapped_dek = wrap_dek(&dek, object_id, epoch, epoch_key)?;

    Ok(EncryptedObject {
        version: ENVELOPE_VERSION,
        object_id,
        epoch,
        algorithm,
        nonce: nonce.to_vec(),
        wrapped_dek,
        ciphertext,
        ciphertext_hash,
        content_kind: None,
        origin: None,
    })
}

/// Open `envelope` and recover plaintext plus inner metadata.
pub fn open(
    envelope: &EncryptedObject,
    epoch_key: &EpochKey,
) -> Result<OpenedPayload, ProtocolError> {
    require_payload_algorithm(envelope.algorithm)?;
    let expected_hash = Hash::of_ciphertext(&envelope.ciphertext);
    if expected_hash != envelope.ciphertext_hash {
        return Err(ProtocolError::HashMismatch);
    }

    let expected_nonce = envelope.algorithm.nonce_len();
    let nonce = xnonce_bytes(&envelope.nonce, expected_nonce)?;
    let dek = unwrap_dek(
        &envelope.wrapped_dek,
        envelope.object_id,
        envelope.epoch,
        epoch_key,
    )?;

    match envelope.version {
        ENVELOPE_VERSION_V1 => {
            let kind = envelope.content_kind.ok_or(ProtocolError::AeadFailure)?;
            let origin = envelope.origin.ok_or(ProtocolError::AeadFailure)?;
            let aad = object_aad(
                ENVELOPE_VERSION_V1,
                envelope.object_id,
                envelope.epoch,
                envelope.algorithm,
                Some(kind),
                Some(origin),
            );
            let plaintext = open_xchacha(dek.as_bytes(), &nonce, &aad, &envelope.ciphertext)?;
            Ok(OpenedPayload {
                plaintext,
                content_kind: kind,
                origin,
                name: None,
                created: None,
                expires_at: None,
                retention_policy: None,
            })
        }
        ENVELOPE_VERSION_V2 => {
            let aad = object_aad(
                ENVELOPE_VERSION_V2,
                envelope.object_id,
                envelope.epoch,
                envelope.algorithm,
                None,
                None,
            );
            let inner = open_xchacha(dek.as_bytes(), &nonce, &aad, &envelope.ciphertext)?;
            decode_inner(&inner, false)
        }
        ENVELOPE_VERSION => {
            let aad = object_aad(
                ENVELOPE_VERSION,
                envelope.object_id,
                envelope.epoch,
                envelope.algorithm,
                None,
                None,
            );
            let inner = open_xchacha(dek.as_bytes(), &nonce, &aad, &envelope.ciphertext)?;
            decode_inner(&inner, true)
        }
        version => Err(ProtocolError::UnsupportedVersion { version }),
    }
}

fn encode_inner(
    kind: ContentKind,
    origin: DeviceId,
    name: Option<&str>,
    created: Option<HybridTimestamp>,
    plaintext: &[u8],
) -> Vec<u8> {
    let kind_bytes = kind.as_wire_str().as_bytes();
    let name_bytes = name.unwrap_or("").as_bytes();
    let created = created.unwrap_or_else(HybridTimestamp::now);
    let retention = shelf_core::Retention::normal(created.wall());
    let mut out = Vec::with_capacity(
        1 + kind_bytes.len() + 32 + 2 + name_bytes.len() + 16 + 1 + 8 + plaintext.len(),
    );
    out.push(u8::try_from(kind_bytes.len()).unwrap_or(0));
    out.extend_from_slice(kind_bytes);
    out.extend_from_slice(origin.as_bytes());
    let name_len = u16::try_from(name_bytes.len()).unwrap_or(0);
    out.extend_from_slice(&name_len.to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(&created.logical().to_be_bytes());
    out.extend_from_slice(&created.wall().as_millis().to_be_bytes());
    out.push(match retention.policy() {
        RetentionPolicy::Ephemeral => 0,
        RetentionPolicy::Normal => 1,
        RetentionPolicy::Pinned => 2,
        RetentionPolicy::Custom => 3,
    });
    let exp = retention.expires_at().map(|t| t.as_millis()).unwrap_or(0);
    out.extend_from_slice(&exp.to_be_bytes());
    out.extend_from_slice(plaintext);
    out
}

fn decode_inner(bytes: &[u8], with_retention: bool) -> Result<OpenedPayload, ProtocolError> {
    if bytes.is_empty() {
        return Err(ProtocolError::AeadFailure);
    }
    let kind_len = usize::from(bytes[0]);
    let mut i = 1;
    if bytes.len() < i + kind_len + 32 + 2 {
        return Err(ProtocolError::AeadFailure);
    }
    let kind_str =
        std::str::from_utf8(&bytes[i..i + kind_len]).map_err(|_| ProtocolError::AeadFailure)?;
    let kind = ContentKind::from_wire_str(kind_str).ok_or(ProtocolError::AeadFailure)?;
    i += kind_len;
    let mut origin_bytes = [0u8; 32];
    origin_bytes.copy_from_slice(&bytes[i..i + 32]);
    i += 32;
    let name_len = u16::from_be_bytes(bytes[i..i + 2].try_into().unwrap()) as usize;
    i += 2;
    if bytes.len() < i + name_len + 16 {
        return Err(ProtocolError::AeadFailure);
    }
    let name = if name_len == 0 {
        None
    } else {
        let s =
            std::str::from_utf8(&bytes[i..i + name_len]).map_err(|_| ProtocolError::AeadFailure)?;
        Some(s.to_owned())
    };
    i += name_len;
    let logical = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap());
    i += 8;
    let wall = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap());
    i += 8;
    let (expires_at, retention_policy, plaintext) = if with_retention {
        if bytes.len() < i + 1 + 8 {
            return Err(ProtocolError::AeadFailure);
        }
        let policy = match bytes[i] {
            0 => RetentionPolicy::Ephemeral,
            1 => RetentionPolicy::Normal,
            2 => RetentionPolicy::Pinned,
            _ => RetentionPolicy::Custom,
        };
        i += 1;
        let exp = u64::from_be_bytes(bytes[i..i + 8].try_into().unwrap());
        i += 8;
        let expires = if exp == 0 {
            None
        } else {
            Some(Timestamp::from_millis(exp))
        };
        (expires, Some(policy), bytes[i..].to_vec())
    } else {
        (None, None, bytes[i..].to_vec())
    };
    Ok(OpenedPayload {
        plaintext,
        content_kind: kind,
        origin: DeviceId::from_bytes(origin_bytes),
        name,
        created: Some(HybridTimestamp::new(logical, Timestamp::from_millis(wall))),
        expires_at,
        retention_policy,
    })
}

fn require_payload_algorithm(algorithm: AeadAlgorithm) -> Result<(), ProtocolError> {
    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => Ok(()),
        AeadAlgorithm::Aes256Gcm => Err(ProtocolError::UnsupportedAlgorithm { algorithm }),
    }
}
