//! Crypto identifiers, domain labels, and DEK handling.
//!
//! Envelope construction lives in `shelf-protocol` (T2). This module only
//! names algorithms, domain-separation labels, and key types.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain label for per-object key derivation.
pub const DOMAIN_OBJECT: &str = "shelf/object/v1";
/// Domain label for file-chunk key derivation.
pub const DOMAIN_CHUNK: &str = "shelf/chunk/v1";
/// Domain label for metadata key derivation.
pub const DOMAIN_METADATA: &str = "shelf/metadata/v1";
/// Domain label for enrollment transcripts.
pub const DOMAIN_ENROLLMENT: &str = "shelf/enrollment/v1";
/// Domain label for membership/grant material.
pub const DOMAIN_MEMBERSHIP: &str = "shelf/membership/v1";
/// Domain label for search-index keys.
pub const DOMAIN_SEARCH: &str = "shelf/search/v1";

/// Preferred AEAD: XChaCha20-Poly1305.
pub const PREFERRED_AEAD: AeadAlgorithm = AeadAlgorithm::XChaCha20Poly1305;

/// Concrete preferred AEAD type (sealing is implemented outside this crate).
pub type PreferredAead = chacha20poly1305::XChaCha20Poly1305;

/// Preferred post-quantum KEM parameter set.
pub type PreferredMlKem = ml_kem::MlKem768;

/// All domain-separation labels in a stable order.
#[must_use]
pub const fn all_domain_labels() -> [&'static str; 6] {
    [
        DOMAIN_OBJECT,
        DOMAIN_CHUNK,
        DOMAIN_METADATA,
        DOMAIN_ENROLLMENT,
        DOMAIN_MEMBERSHIP,
        DOMAIN_SEARCH,
    ]
}

/// AEAD algorithm identifier stored on every envelope for migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    /// XChaCha20-Poly1305 (preferred). 24-byte nonce.
    #[serde(rename = "xchacha20-poly1305-v1")]
    XChaCha20Poly1305,
    /// AES-256-GCM when hardware acceleration is required. 12-byte nonce.
    #[serde(rename = "aes-256-gcm-v1")]
    Aes256Gcm,
}

impl AeadAlgorithm {
    /// Nonce length in bytes for this algorithm.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::XChaCha20Poly1305 => 24,
            Self::Aes256Gcm => 12,
        }
    }

    /// Whether this is the currently preferred algorithm.
    #[must_use]
    pub const fn is_preferred(self) -> bool {
        matches!(self, Self::XChaCha20Poly1305)
    }
}

/// Hybrid KEM profile for device identity and grant wrapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HybridKemProfile {
    /// X25519 + ML-KEM-768 (preferred).
    #[default]
    #[serde(rename = "x25519-mlkem768-v1")]
    X25519MlKem768,
}

impl HybridKemProfile {
    /// Wire name for the only currently defined profile.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::X25519MlKem768 => "x25519-mlkem768-v1",
        }
    }
}

/// Vault key-epoch identifier. Advances when a device is revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochId(u64);

impl EpochId {
    /// Epoch `0` is unused; the first epoch is `1` by convention.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Integer form.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Next epoch after a revocation.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// 256-bit data-encryption key. Random per object; never derived from plaintext.
///
/// Debug/Display omit the key bytes so logs cannot leak DEKs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; 32]);

impl Dek {
    /// Generate a fresh random 256-bit key.
    #[must_use]
    pub fn new() -> Self {
        Self(rand::random())
    }

    /// Wrap existing key bytes. Caller must ensure they are random key material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the key for AEAD use. Do not log this slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Default for Dek {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Dek {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Dek {}

impl fmt::Debug for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Dek([REDACTED])")
    }
}

impl fmt::Display for Dek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn domain_labels_are_unique_and_match_spec() {
        let labels = all_domain_labels();
        assert_eq!(
            labels,
            [
                "shelf/object/v1",
                "shelf/chunk/v1",
                "shelf/metadata/v1",
                "shelf/enrollment/v1",
                "shelf/membership/v1",
                "shelf/search/v1",
            ]
        );
        let unique: BTreeSet<_> = labels.into_iter().collect();
        assert_eq!(unique.len(), 6);
    }

    #[test]
    fn dek_is_32_bytes_and_debug_hides_key() {
        let dek = Dek::new();
        assert_eq!(dek.as_bytes().len(), 32);
        let hex = crate::hexutil::encode(dek.as_bytes());
        let debug = format!("{dek:?}");
        let display = format!("{dek}");
        assert!(!debug.to_lowercase().contains(&hex));
        assert!(!display.to_lowercase().contains(&hex));
        let decimal = format!("{:?}", dek.as_bytes());
        assert!(!debug.contains(&decimal));
        assert_eq!(debug, "Dek([REDACTED])");
        assert_eq!(PREFERRED_AEAD, AeadAlgorithm::XChaCha20Poly1305);
        assert!(PREFERRED_AEAD.is_preferred());
        let _ = HybridKemProfile::X25519MlKem768.as_wire_str();
    }

    #[test]
    fn aead_serde_is_versioned() {
        let json = serde_json::to_string(&AeadAlgorithm::XChaCha20Poly1305).unwrap();
        assert_eq!(json, "\"xchacha20-poly1305-v1\"");
        let back: AeadAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AeadAlgorithm::XChaCha20Poly1305);
        let aes = serde_json::to_string(&AeadAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(aes, "\"aes-256-gcm-v1\"");
    }
}
