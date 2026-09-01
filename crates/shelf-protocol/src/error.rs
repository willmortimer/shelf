//! Typed errors for envelope seal/open and DEK wrap.

use shelf_core::AeadAlgorithm;
use thiserror::Error;

/// Failures while sealing, opening, wrapping, or unwrapping protocol envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ProtocolError {
    /// Envelope or wrap version is not implemented by this crate.
    #[error("unsupported envelope version {version}")]
    UnsupportedVersion {
        /// Version byte that was rejected.
        version: u16,
    },
    /// Algorithm identifier exists for migration but is not implemented yet.
    #[error("unsupported AEAD algorithm {algorithm:?}")]
    UnsupportedAlgorithm {
        /// Algorithm that was rejected.
        algorithm: AeadAlgorithm,
    },
    /// XChaCha20-Poly1305 seal or open failed (including AAD mismatch).
    #[error("AEAD seal or open failed")]
    AeadFailure,
    /// DEK wrap or unwrap failed (wrong epoch key, AAD mismatch, or corrupt wrap).
    #[error("DEK wrap or unwrap failed")]
    WrapFailure,
    /// `ciphertext_hash` was not BLAKE3 of the stored ciphertext.
    #[error("ciphertext hash mismatch")]
    HashMismatch,
    /// Nonce was not the length required by the selected AEAD.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Required nonce length in bytes.
        expected: usize,
        /// Length that was supplied.
        actual: usize,
    },
    /// Unwrapped DEK plaintext was not 32 bytes.
    #[error("invalid DEK length: expected {expected}, got {actual}")]
    InvalidDekLength {
        /// Required DEK length in bytes.
        expected: usize,
        /// Length that was supplied.
        actual: usize,
    },
}
