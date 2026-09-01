//! Versioned encrypted object envelopes.

use serde::{Deserialize, Serialize};
use shelf_core::{AeadAlgorithm, ContentKind, Dek, DeviceId, EpochId, ObjectId, PREFERRED_AEAD};

use crate::aad::object_aad;
use crate::cipher::{open_xchacha, seal_xchacha, xnonce_bytes};
use crate::error::ProtocolError;
use crate::wrap::{EpochKey, KeyEnvelope, unwrap_dek, wrap_dek};

/// Envelope format version written by [`seal`].
pub const ENVELOPE_VERSION: u16 = 1;

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
/// Payload AEAD additional data binds protocol version, object id, epoch,
/// algorithm, content kind, and origin device id. `content_kind` and `origin`
/// are carried on the envelope so honest replicas can reconstruct AAD; they
/// are authenticated, not trusted as plaintext metadata.
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
    pub nonce: Vec<u8>,
    /// DEK wrapped under the epoch key.
    pub wrapped_dek: KeyEnvelope,
    /// AEAD ciphertext of the object plaintext.
    pub ciphertext: Vec<u8>,
    /// BLAKE3 of [`Self::ciphertext`], never of the plaintext.
    pub ciphertext_hash: Hash,
    /// Content class bound into AAD.
    pub content_kind: ContentKind,
    /// Originating device bound into AAD.
    pub origin: DeviceId,
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
    let algorithm = PREFERRED_AEAD;
    require_payload_algorithm(algorithm)?;

    let dek = Dek::new();
    let nonce: [u8; 24] = rand::random();
    let aad = object_aad(
        ENVELOPE_VERSION,
        object_id,
        epoch,
        algorithm,
        content_kind,
        origin,
    );
    let ciphertext = seal_xchacha(dek.as_bytes(), &nonce, &aad, plaintext)?;
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
        content_kind,
        origin,
    })
}

/// Open `envelope` and recover the plaintext.
///
/// `content_kind` and `origin` must match the values used at [`seal`]. They
/// are compared to the envelope fields and then rebound into AAD so a mismatch
/// cannot decrypt.
pub fn open(
    envelope: &EncryptedObject,
    epoch_key: &EpochKey,
    content_kind: ContentKind,
    origin: DeviceId,
) -> Result<Vec<u8>, ProtocolError> {
    if envelope.version != ENVELOPE_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            version: envelope.version,
        });
    }
    require_payload_algorithm(envelope.algorithm)?;
    if envelope.content_kind != content_kind || envelope.origin != origin {
        return Err(ProtocolError::AeadFailure);
    }

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
    let aad = object_aad(
        envelope.version,
        envelope.object_id,
        envelope.epoch,
        envelope.algorithm,
        content_kind,
        origin,
    );
    open_xchacha(dek.as_bytes(), &nonce, &aad, &envelope.ciphertext)
}

fn require_payload_algorithm(algorithm: AeadAlgorithm) -> Result<(), ProtocolError> {
    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => Ok(()),
        AeadAlgorithm::Aes256Gcm => Err(ProtocolError::UnsupportedAlgorithm { algorithm }),
    }
}
