//! Versioned encrypted object envelopes (XChaCha20-Poly1305).
//!
//! Seals and opens [`EncryptedObject`] values with per-object DEKs wrapped
//! under a software [`EpochKey`]. Hybrid ML-KEM wrapping, mailbox, and
//! transports are out of scope for this crate.

#![deny(missing_docs)]

mod aad;
mod cipher;
mod envelope;
mod error;
mod wrap;

pub use envelope::{ENVELOPE_VERSION, EncryptedObject, Hash, open, seal};
pub use error::ProtocolError;
pub use wrap::{DOMAIN_DEK_WRAP, EpochKey, KeyEnvelope, WRAP_VERSION, unwrap_dek, wrap_dek};

#[cfg(test)]
mod tests;
