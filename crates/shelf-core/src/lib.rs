//! Core model, identity, enrollment, crypto identifiers, retention, blobs,
//! scratch CRDTs, and the peer-transport trait.
//!
//! This crate does not implement protocol envelopes, transports, mailbox,
//! `shelfd`, or GUI.

#![deny(missing_docs)]

mod hexutil;

pub mod blob;
pub mod crdt;
pub mod crypto;
pub mod enrollment;
pub mod identity;
pub mod model;
pub mod retention;
pub mod sync;

pub use blob::{ChunkId, DEFAULT_CHUNK_SIZE, FileManifest};
pub use crdt::{CrdtError, ScratchPad};
pub use crypto::{
    AeadAlgorithm, DOMAIN_CHUNK, DOMAIN_ENROLLMENT, DOMAIN_MEMBERSHIP, DOMAIN_METADATA,
    DOMAIN_OBJECT, DOMAIN_SEARCH, Dek, EpochId, HybridKemProfile, PREFERRED_AEAD, PreferredAead,
    PreferredMlKem, all_domain_labels,
};
pub use enrollment::{
    DeviceCapabilities, ENROLLMENT_PROTOCOL_VERSION, EncryptedMembershipState,
    EncryptedVaultKeyEnvelope, EnrollmentError, EnrollmentEvent, EnrollmentRequest,
    EnrollmentState, MemberRole, MembershipCertificate, MembershipGrant, SignatureBytes,
    TransportHint,
};
pub use identity::{
    DeviceId, DevicePublicIdentity, HybridKemPublicKey, IdentityError, ML_KEM_768_PUBLIC_KEY_LEN,
    MlKem768PublicKey, SigningPublicKey, VaultId, X25519PublicKey,
};
pub use model::{ContentKind, ContentRef, HybridTimestamp, Label, ObjectId, ShelfItem, Timestamp};
pub use retention::{EPHEMERAL_TTL, ExpireObject, NORMAL_TTL, Retention, RetentionPolicy};
pub use sync::{Peer, PeerId, PeerTransport};

#[cfg(test)]
mod tests;
