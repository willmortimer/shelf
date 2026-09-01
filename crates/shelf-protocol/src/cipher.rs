//! Shared XChaCha20-Poly1305 helpers. AES-256-GCM is rejected by callers.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};

use crate::error::ProtocolError;

/// Encrypt `plaintext` with `aad` under a 32-byte key and 24-byte nonce.
pub(crate) fn seal_xchacha(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = XNonce::from(*nonce);
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ProtocolError::AeadFailure)
}

/// Decrypt `ciphertext` with `aad` under a 32-byte key and 24-byte nonce.
pub(crate) fn open_xchacha(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let nonce = XNonce::from(*nonce);
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| ProtocolError::AeadFailure)
}

/// Parse a 24-byte XChaCha20-Poly1305 nonce from a slice.
pub(crate) fn xnonce_bytes(nonce: &[u8], expected: usize) -> Result<[u8; 24], ProtocolError> {
    nonce
        .try_into()
        .map_err(|_| ProtocolError::InvalidNonceLength {
            expected,
            actual: nonce.len(),
        })
}
