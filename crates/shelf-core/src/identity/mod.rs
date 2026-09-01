//! Device identity: public keys only.
//!
//! Private material belongs in `shelf-keystore`, never in these structs.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::hexutil::define_id32;

/// ML-KEM-768 encapsulation-key length in bytes (FIPS 203).
pub const ML_KEM_768_PUBLIC_KEY_LEN: usize = 1184;

define_id32! {
    /// Random opaque device identifier. Distinct from any transport (Tailscale) node id.
    pub struct DeviceId;
}

define_id32! {
    /// Vault identifier bound into membership certificates.
    pub struct VaultId;
}

/// Errors for public-key constructors.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum IdentityError {
    /// ML-KEM-768 encapsulation key was not 1184 bytes.
    #[error("ML-KEM-768 public key must be {expected} bytes, got {actual}")]
    InvalidMlKemPublicKeyLength {
        /// Required length.
        expected: usize,
        /// Length that was supplied.
        actual: usize,
    },
    /// Bytes were not a valid Ed25519 compressed verifying key.
    #[error("invalid Ed25519 verifying key")]
    InvalidSigningPublicKey,
}

/// Ed25519 verifying key bytes (32).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SigningPublicKey(#[serde(with = "crate::hexutil")] [u8; 32]);

impl SigningPublicKey {
    /// Wrap 32 raw bytes without curve checks.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<SigningPublicKey> for ed25519_dalek::VerifyingKey {
    type Error = IdentityError;

    fn try_from(value: SigningPublicKey) -> Result<Self, Self::Error> {
        Self::from_bytes(&value.0).map_err(|_| IdentityError::InvalidSigningPublicKey)
    }
}

/// Verify an Ed25519 signature over `msg`.
#[must_use]
pub fn verify_ed25519(pk: &SigningPublicKey, msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let Ok(vk) = VerifyingKey::try_from(*pk) else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

impl From<ed25519_dalek::VerifyingKey> for SigningPublicKey {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        Self(value.to_bytes())
    }
}

impl fmt::Debug for SigningPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningPublicKey")
            .field(&format_args!("{}", crate::hexutil::encode(&self.0)))
            .finish()
    }
}

/// X25519 public key bytes (32).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X25519PublicKey(#[serde(with = "crate::hexutil")] [u8; 32]);

impl X25519PublicKey {
    /// Wrap 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<x25519_dalek::PublicKey> for X25519PublicKey {
    fn from(value: x25519_dalek::PublicKey) -> Self {
        Self(*value.as_bytes())
    }
}

impl From<X25519PublicKey> for x25519_dalek::PublicKey {
    fn from(value: X25519PublicKey) -> Self {
        Self::from(value.0)
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("X25519PublicKey")
            .field(&format_args!("{}", crate::hexutil::encode(&self.0)))
            .finish()
    }
}

/// ML-KEM-768 encapsulation key bytes.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MlKem768PublicKey(Vec<u8>);

impl MlKem768PublicKey {
    /// Accept encoded encapsulation-key bytes. Length must be 1184.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, IdentityError> {
        let bytes = bytes.into();
        if bytes.len() != ML_KEM_768_PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidMlKemPublicKeyLength {
                expected: ML_KEM_768_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Borrow the encoded key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MlKem768PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlKem768PublicKey")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Hybrid KEM public key: X25519 + ML-KEM-768.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HybridKemPublicKey {
    /// Classical ECDH public key.
    pub x25519: X25519PublicKey,
    /// Post-quantum encapsulation key.
    pub ml_kem_768: MlKem768PublicKey,
}

impl HybridKemPublicKey {
    /// Combine the two public halves of the preferred hybrid profile.
    #[must_use]
    pub fn new(x25519: X25519PublicKey, ml_kem_768: MlKem768PublicKey) -> Self {
        Self { x25519, ml_kem_768 }
    }
}

/// Public identity of a device. Contains no private key material.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DevicePublicIdentity {
    /// Stable device identifier.
    pub device_id: DeviceId,
    /// Ed25519 verifying key.
    pub signing_pubkey: SigningPublicKey,
    /// X25519 public key.
    pub x25519_pubkey: X25519PublicKey,
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_pubkey: MlKem768PublicKey,
    /// Optional human-readable name.
    pub device_name: Option<String>,
}

impl DevicePublicIdentity {
    /// Assemble a public identity from already-generated public keys.
    #[must_use]
    pub fn new(
        device_id: DeviceId,
        signing_pubkey: SigningPublicKey,
        x25519_pubkey: X25519PublicKey,
        ml_kem_pubkey: MlKem768PublicKey,
        device_name: Option<String>,
    ) -> Self {
        Self {
            device_id,
            signing_pubkey,
            x25519_pubkey,
            ml_kem_pubkey,
            device_name,
        }
    }
}

#[cfg(test)]
pub(crate) fn test_public_identity(device_name: Option<&str>) -> DevicePublicIdentity {
    use zeroize::Zeroize;

    let secret_bytes: [u8; 32] = rand::random();
    let signing = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let verifying = signing.verifying_key();
    drop(signing);
    let mut secret_bytes = secret_bytes;
    secret_bytes.zeroize();

    DevicePublicIdentity::new(
        DeviceId::new(),
        SigningPublicKey::from(verifying),
        X25519PublicKey::from_bytes(rand::random()),
        MlKem768PublicKey::from_bytes(vec![0x11; ML_KEM_768_PUBLIC_KEY_LEN])
            .expect("fixture length"),
        device_name.map(str::to_owned),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_random() {
        assert_ne!(DeviceId::new(), DeviceId::new());
    }

    #[test]
    fn public_identity_has_no_secret_fields() {
        let id = test_public_identity(Some("optiprox3"));
        assert_eq!(id.device_name.as_deref(), Some("optiprox3"));
        assert_eq!(id.ml_kem_pubkey.as_bytes().len(), ML_KEM_768_PUBLIC_KEY_LEN);
    }

    #[test]
    fn ml_kem_rejects_wrong_length() {
        let err = MlKem768PublicKey::from_bytes(vec![0u8; 3]).unwrap_err();
        assert_eq!(
            err,
            IdentityError::InvalidMlKemPublicKeyLength {
                expected: ML_KEM_768_PUBLIC_KEY_LEN,
                actual: 3,
            }
        );
    }

    #[test]
    fn invalid_signing_key_bytes_error() {
        // y = 2 is not on ed25519; ZIP-215 still rejects encodings that fail decompression.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        let bogus = SigningPublicKey::from_bytes(bytes);
        let err = ed25519_dalek::VerifyingKey::try_from(bogus).unwrap_err();
        assert_eq!(err, IdentityError::InvalidSigningPublicKey);
    }
}
