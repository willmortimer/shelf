//! Software wrapping of object DEKs under an epoch key.
//!
//! This is **not** the hybrid ML-KEM wrap used for long-term device identity.
//! Wrap keys are derived with BLAKE3 `derive_key` so they never collide with
//! per-object keys derived under [`shelf_core::DOMAIN_OBJECT`].

use std::fmt;

use serde::{Deserialize, Serialize};
use shelf_core::{AeadAlgorithm, Dek, EpochId, ObjectId, PREFERRED_AEAD};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aad::wrap_aad;
use crate::cipher::{open_xchacha, seal_xchacha, xnonce_bytes};
use crate::error::ProtocolError;

/// BLAKE3 `derive_key` context for software DEK wrapping under an epoch key.
///
/// Distinct from `shelf/object/v1` so wrap keys cannot collide with object-key
/// derivation that uses that domain label.
pub const DOMAIN_DEK_WRAP: &str = "shelf/dek-wrap/v1";

/// Wrap envelope version written by [`wrap_dek`].
pub const WRAP_VERSION: u16 = 1;

const DEK_LEN: usize = 32;

/// 32-byte software epoch secret used to wrap object DEKs.
///
/// Debug/Display omit the key bytes so logs cannot leak epoch material.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochKey([u8; 32]);

impl EpochKey {
    /// Generate a fresh random 256-bit epoch secret.
    #[must_use]
    pub fn new() -> Self {
        Self(rand::random())
    }

    /// Wrap existing key bytes. Caller must ensure they are random key material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the key for wrapping. Do not log this slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for EpochKey {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochKey([REDACTED])")
    }
}

impl fmt::Display for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Wrapped object DEK. Ciphertext is XChaCha20-Poly1305 of the 32-byte DEK.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEnvelope {
    /// Wrap format version. Currently [`WRAP_VERSION`].
    pub version: u16,
    /// Epoch whose secret wrapped this DEK.
    pub epoch: EpochId,
    /// AEAD used for the wrap. v1 is XChaCha20-Poly1305 only.
    pub algorithm: AeadAlgorithm,
    /// Wrap nonce (24 bytes for XChaCha20-Poly1305).
    #[serde(with = "crate::b64")]
    pub nonce: Vec<u8>,
    /// AEAD ciphertext of the DEK (32-byte plaintext plus 16-byte tag).
    #[serde(with = "crate::b64")]
    pub ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    /// Wrap `dek` under `epoch_key` for `(object_id, epoch)`.
    pub fn wrap(
        dek: &Dek,
        object_id: ObjectId,
        epoch: EpochId,
        epoch_key: &EpochKey,
    ) -> Result<Self, ProtocolError> {
        wrap_dek(dek, object_id, epoch, epoch_key)
    }

    /// Recover the DEK. `object_id` and `epoch` must match the wrap AAD.
    pub fn unwrap_dek(
        &self,
        object_id: ObjectId,
        epoch: EpochId,
        epoch_key: &EpochKey,
    ) -> Result<Dek, ProtocolError> {
        unwrap_dek(self, object_id, epoch, epoch_key)
    }
}

/// Wrap a DEK under `epoch_key` using XChaCha20-Poly1305.
pub fn wrap_dek(
    dek: &Dek,
    object_id: ObjectId,
    epoch: EpochId,
    epoch_key: &EpochKey,
) -> Result<KeyEnvelope, ProtocolError> {
    let algorithm = PREFERRED_AEAD;
    require_wrap_algorithm(algorithm)?;
    let nonce: [u8; 24] = rand::random();
    let wrap_key = derive_wrap_key(epoch_key);
    let aad = wrap_aad(WRAP_VERSION, object_id, epoch, algorithm);
    let ciphertext = seal_xchacha(&wrap_key, &nonce, &aad, dek.as_bytes())
        .map_err(|_| ProtocolError::WrapFailure)?;
    Ok(KeyEnvelope {
        version: WRAP_VERSION,
        epoch,
        algorithm,
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Unwrap a DEK. Fails if the epoch key, object id, or epoch do not match.
pub fn unwrap_dek(
    envelope: &KeyEnvelope,
    object_id: ObjectId,
    epoch: EpochId,
    epoch_key: &EpochKey,
) -> Result<Dek, ProtocolError> {
    if envelope.version != WRAP_VERSION {
        return Err(ProtocolError::UnsupportedVersion {
            version: envelope.version,
        });
    }
    require_wrap_algorithm(envelope.algorithm)?;
    if envelope.epoch != epoch {
        return Err(ProtocolError::WrapFailure);
    }
    let expected_nonce = envelope.algorithm.nonce_len();
    let nonce = xnonce_bytes(&envelope.nonce, expected_nonce)?;
    let wrap_key = derive_wrap_key(epoch_key);
    let aad = wrap_aad(envelope.version, object_id, epoch, envelope.algorithm);
    let plaintext = open_xchacha(&wrap_key, &nonce, &aad, &envelope.ciphertext)
        .map_err(|_| ProtocolError::WrapFailure)?;
    let bytes: [u8; DEK_LEN] =
        plaintext
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidDekLength {
                expected: DEK_LEN,
                actual: plaintext.len(),
            })?;
    Ok(Dek::from_bytes(bytes))
}

fn derive_wrap_key(epoch_key: &EpochKey) -> [u8; 32] {
    blake3::derive_key(DOMAIN_DEK_WRAP, epoch_key.as_bytes())
}

fn require_wrap_algorithm(algorithm: AeadAlgorithm) -> Result<(), ProtocolError> {
    match algorithm {
        AeadAlgorithm::XChaCha20Poly1305 => Ok(()),
        AeadAlgorithm::Aes256Gcm => Err(ProtocolError::UnsupportedAlgorithm { algorithm }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn epoch_key_debug_does_not_leak_hex() {
        let key = EpochKey::new();
        let hex = hex(key.as_bytes());
        let debug = format!("{key:?}");
        let display = format!("{key}");
        assert_eq!(debug, "EpochKey([REDACTED])");
        assert_eq!(display, "[REDACTED]");
        assert!(!debug.to_lowercase().contains(&hex));
        assert!(!display.to_lowercase().contains(&hex));
        let decimal = format!("{:?}", key.as_bytes());
        assert!(!debug.contains(&decimal));
    }

    #[test]
    fn wrap_round_trip() {
        let epoch_key = EpochKey::new();
        let dek = Dek::new();
        let object_id = ObjectId::new();
        let epoch = EpochId::new(1);
        let env = wrap_dek(&dek, object_id, epoch, &epoch_key).unwrap();
        let opened = unwrap_dek(&env, object_id, epoch, &epoch_key).unwrap();
        assert_eq!(dek, opened);
    }

    #[test]
    fn wrap_wrong_object_id_fails() {
        let epoch_key = EpochKey::new();
        let dek = Dek::new();
        let epoch = EpochId::new(1);
        let env = wrap_dek(&dek, ObjectId::new(), epoch, &epoch_key).unwrap();
        let err = unwrap_dek(&env, ObjectId::new(), epoch, &epoch_key).unwrap_err();
        assert_eq!(err, ProtocolError::WrapFailure);
    }

    #[test]
    fn unwrap_rejects_non_dek_length() {
        let epoch_key = EpochKey::new();
        let object_id = ObjectId::new();
        let epoch = EpochId::new(1);
        let wrap_key = derive_wrap_key(&epoch_key);
        let nonce: [u8; 24] = rand::random();
        let aad = crate::aad::wrap_aad(WRAP_VERSION, object_id, epoch, PREFERRED_AEAD);
        let ciphertext = crate::cipher::seal_xchacha(&wrap_key, &nonce, &aad, b"short").unwrap();
        let env = KeyEnvelope {
            version: WRAP_VERSION,
            epoch,
            algorithm: PREFERRED_AEAD,
            nonce: nonce.to_vec(),
            ciphertext,
        };
        let err = unwrap_dek(&env, object_id, epoch, &epoch_key).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::InvalidDekLength {
                expected: DEK_LEN,
                actual: 5,
            }
        );
    }

    #[test]
    fn unwrap_rejects_unsupported_wrap_version() {
        let epoch_key = EpochKey::new();
        let dek = Dek::new();
        let object_id = ObjectId::new();
        let epoch = EpochId::new(1);
        let mut env = wrap_dek(&dek, object_id, epoch, &epoch_key).unwrap();
        env.version = 2;
        let err = unwrap_dek(&env, object_id, epoch, &epoch_key).unwrap_err();
        assert_eq!(err, ProtocolError::UnsupportedVersion { version: 2 });
    }
}
