//! Core model, identity, enrollment, crypto identifiers, retention, blobs,
//! scratch CRDTs, and the peer-transport trait.
//!
//! This crate does not implement protocol envelopes, transports, mailbox,
//! `shelfd`, or GUI.

#![deny(missing_docs)]

mod bounded;
mod hexutil;

pub mod blob;
pub mod crdt;
pub mod crypto;
pub mod enrollment;
pub mod identity;
pub mod model;
pub mod retention;
pub mod sync;
pub mod transcript;

pub use blob::{ChunkId, DEFAULT_CHUNK_SIZE, FileManifest};
pub use crdt::{CrdtError, ScratchId, ScratchPad, scratch_id_for};
pub use crypto::{
    AeadAlgorithm, DOMAIN_CHUNK, DOMAIN_ENROLLMENT, DOMAIN_MEMBERSHIP, DOMAIN_METADATA,
    DOMAIN_OBJECT, DOMAIN_SEARCH, Dek, EpochId, HybridKemProfile, PREFERRED_AEAD, PreferredAead,
    PreferredMlKem, all_domain_labels,
};
pub use enrollment::{
    DeviceCapabilities, ENROLLMENT_PROTOCOL_VERSION, EncryptedMembershipState,
    EncryptedVaultKeyEnvelope, EnrollmentError, EnrollmentEvent, EnrollmentRequest,
    EnrollmentState, MailboxBinding, MemberRole, MembershipCertificate, MembershipGrant,
    MembershipSnapshot, SignatureBytes, TransportHint, VaultRoot,
};
pub use identity::{
    DeviceId, DevicePublicIdentity, HybridKemPublicKey, IdentityError, ML_KEM_768_PUBLIC_KEY_LEN,
    MlKem768PublicKey, SigningPublicKey, VaultId, X25519PublicKey, verify_ed25519,
};
pub use model::{
    ContentKind, ContentRef, HlcClock, HybridTimestamp, Label, ObjectId, ShelfItem, Timestamp,
};

/// Maximum newline-delimited JSON frame on IPC, mailbox, and peer sockets.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub use bounded::{BoundedLine, FrameTooLarge};
pub use retention::{EPHEMERAL_TTL, ExpireObject, NORMAL_TTL, Retention, RetentionPolicy};
pub use sync::{Peer, PeerId, PeerTransport};
pub use transcript::{
    DOMAIN_ENROLL_CERT, DOMAIN_ENROLL_GENESIS, DOMAIN_ENROLL_REQUEST, DOMAIN_ENROLL_SAS,
    DOMAIN_ENROLL_SNAPSHOT, DOMAIN_ENROLL_WRAP, DOMAIN_EPOCH_TRANSITION, Transcript,
};

#[cfg(test)]
mod tests;
