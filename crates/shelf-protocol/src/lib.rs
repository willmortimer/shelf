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
mod hybrid;
mod sas;
mod wrap;

pub use envelope::{
    ENVELOPE_VERSION, ENVELOPE_VERSION_V1, EncryptedObject, Hash, OpenedPayload, open, seal,
    seal_named,
};
pub use error::ProtocolError;
pub use hybrid::{HybridEpochWrap, unwrap_epoch_key, wrap_epoch_key};
pub use sas::{sas_display, sas_words};
pub use wrap::{DOMAIN_DEK_WRAP, EpochKey, KeyEnvelope, WRAP_VERSION, unwrap_dek, wrap_dek};

#[cfg(test)]
mod tests;
