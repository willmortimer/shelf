//! Shelf objects: immutable content plus mutable metadata.

use std::collections::BTreeSet;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::hexutil::define_id32;
use crate::identity::DeviceId;
use crate::retention::{Retention, RetentionPolicy};

define_id32! {
    /// Random opaque object identifier.
    ///
    /// Default construction is 32 random bytes. This is deliberately **not**
    /// `BLAKE3(plaintext)` so object IDs never publish a raw content hash.
    pub struct ObjectId;
}

impl ObjectId {
    /// Keyed BLAKE3 identifier using a vault index key.
    ///
    /// The result is domain-separated from unkeyed `BLAKE3(plaintext)` and must
    /// not be used as a public content address.
    #[must_use]
    pub fn from_keyed_plaintext(index_key: &[u8; 32], plaintext: &[u8]) -> Self {
        let hash = blake3::keyed_hash(index_key, plaintext);
        Self::from_bytes(*hash.as_bytes())
    }
}

/// UTC milliseconds since the Unix epoch.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Current wall-clock time as UTC milliseconds.
    #[must_use]
    pub fn now() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_millis();
        Self(millis.min(u128::from(u64::MAX)) as u64)
    }

    /// Construct from UTC milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// UTC milliseconds since the Unix epoch.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Saturating addition of a duration.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        let extra = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        Self(self.0.saturating_add(extra))
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Timestamp").field(&self.0).finish()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Hybrid logical clock: physical wall time plus a logical counter.
///
/// The pair orders events when wall clocks collide without requiring a
/// globally linearizable log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HybridTimestamp {
    logical: u64,
    wall: Timestamp,
}

impl HybridTimestamp {
    /// Capture the current wall clock with logical counter `0`.
    ///
    /// Replicas must use [`HlcClock`] so successive events on the same
    /// millisecond are strictly ordered.
    #[must_use]
    pub fn now() -> Self {
        Self {
            logical: 0,
            wall: Timestamp::now(),
        }
    }

    /// Construct a hybrid timestamp from parts.
    #[must_use]
    pub const fn new(logical: u64, wall: Timestamp) -> Self {
        Self { logical, wall }
    }

    /// Logical component (monotonic per wall-clock tick on one replica).
    #[must_use]
    pub const fn logical(self) -> u64 {
        self.logical
    }

    /// Physical wall-clock component.
    #[must_use]
    pub const fn wall(self) -> Timestamp {
        self.wall
    }
}

impl PartialOrd for HybridTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HybridTimestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.wall
            .cmp(&other.wall)
            .then(self.logical.cmp(&other.logical))
    }
}

/// Stateful hybrid logical clock. Tick and observe remote timestamps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HlcClock {
    last: HybridTimestamp,
}

impl Default for HlcClock {
    fn default() -> Self {
        Self {
            last: HybridTimestamp::new(0, Timestamp::from_millis(0)),
        }
    }
}

impl HlcClock {
    /// Construct from a previously persisted timestamp.
    #[must_use]
    pub const fn from_last(last: HybridTimestamp) -> Self {
        Self { last }
    }

    /// Last issued timestamp.
    #[must_use]
    pub const fn last(&self) -> HybridTimestamp {
        self.last
    }

    /// Issue a timestamp strictly greater than the last local or observed one.
    pub fn now(&mut self) -> HybridTimestamp {
        let wall = Timestamp::now();
        if wall > self.last.wall() {
            self.last = HybridTimestamp::new(0, wall);
        } else {
            let wall = wall.max(self.last.wall());
            self.last = HybridTimestamp::new(self.last.logical().saturating_add(1), wall);
        }
        self.last
    }

    /// Merge a remote timestamp into the clock (receive path).
    pub fn observe(&mut self, remote: HybridTimestamp) {
        if remote > self.last {
            self.last = remote;
        } else if remote.wall() == self.last.wall() {
            self.last = HybridTimestamp::new(
                self.last.logical().max(remote.logical()).saturating_add(1),
                self.last.wall(),
            );
        }
    }
}

/// Initial content classification for a Shelf object.
///
/// Wire names are kebab-case to match the design contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentKind {
    /// UTF-8 text.
    Text,
    /// Markdown document.
    Markdown,
    /// URL / URI.
    Url,
    /// Image bytes.
    Image,
    /// File (often via a [`crate::blob::FileManifest`]).
    File,
    /// JSON document.
    Json,
    /// Uninterpreted bytes.
    OpaqueBytes,
    /// Encrypted scratch pad (Yrs update). Not a `shelf put` kind.
    Scratch,
}

impl ContentKind {
    /// Stable kebab-case wire name matching serde.
    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Markdown => "markdown",
            Self::Url => "url",
            Self::Image => "image",
            Self::File => "file",
            Self::Json => "json",
            Self::OpaqueBytes => "opaque-bytes",
            Self::Scratch => "scratch",
        }
    }

    /// Parse a kebab-case wire name.
    #[must_use]
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "text" => Some(Self::Text),
            "markdown" => Some(Self::Markdown),
            "url" => Some(Self::Url),
            "image" => Some(Self::Image),
            "file" => Some(Self::File),
            "json" => Some(Self::Json),
            "opaque-bytes" => Some(Self::OpaqueBytes),
            "scratch" => Some(Self::Scratch),
            _ => None,
        }
    }
}

/// Immutable handle to object payload bytes.
///
/// v1 stores owned bytes. Later revisions may swap this for a content address
/// without changing [`ObjectId`].
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentRef {
    bytes: Vec<u8>,
}

impl ContentRef {
    /// Wrap owned payload bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow the payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for ContentRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentRef")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// User-facing label attached to an object's mutable metadata.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Label(String);

impl Label {
    /// Create a label from any string-like value.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Label {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Label {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for Label {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// A Shelf object: immutable content plus mutable replicated metadata.
///
/// Pinning, archive state, expiration, and labels may change. [`Self::content`]
/// and [`Self::id`] never change after construction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShelfItem {
    id: ObjectId,
    content: ContentRef,
    kind: ContentKind,
    created: HybridTimestamp,
    origin: DeviceId,
    pinned: bool,
    archived: bool,
    expires_at: Option<Timestamp>,
    labels: BTreeSet<Label>,
}

impl ShelfItem {
    /// Create an item with Normal retention (expires 7 days from `created`)
    /// unless `pinned`, in which case there is no expiry.
    #[must_use]
    pub fn new(content: ContentRef, kind: ContentKind, origin: DeviceId, pinned: bool) -> Self {
        let created = HybridTimestamp::now();
        let policy = if pinned {
            RetentionPolicy::Pinned
        } else {
            RetentionPolicy::Normal
        };
        let retention = Retention::for_policy(policy, created.wall());
        Self {
            id: ObjectId::new(),
            content,
            kind,
            created,
            origin,
            pinned,
            archived: false,
            expires_at: retention.expires_at(),
            labels: BTreeSet::new(),
        }
    }

    /// Object identifier (stable for the lifetime of the item).
    #[must_use]
    pub const fn id(&self) -> ObjectId {
        self.id
    }

    /// Immutable content handle.
    #[must_use]
    pub const fn content(&self) -> &ContentRef {
        &self.content
    }

    /// Content classification.
    #[must_use]
    pub const fn kind(&self) -> ContentKind {
        self.kind
    }

    /// Creation timestamp.
    #[must_use]
    pub const fn created(&self) -> HybridTimestamp {
        self.created
    }

    /// Originating device.
    #[must_use]
    pub const fn origin(&self) -> DeviceId {
        self.origin
    }

    /// Whether the item is pinned (durable retention).
    #[must_use]
    pub const fn pinned(&self) -> bool {
        self.pinned
    }

    /// Whether the item is archived.
    #[must_use]
    pub const fn archived(&self) -> bool {
        self.archived
    }

    /// Absolute expiration, if any.
    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Metadata labels.
    #[must_use]
    pub const fn labels(&self) -> &BTreeSet<Label> {
        &self.labels
    }

    /// Mutable access to labels. Does not affect content or id.
    #[must_use]
    pub fn labels_mut(&mut self) -> &mut BTreeSet<Label> {
        &mut self.labels
    }

    /// Pin or unpin. Pinning clears expiry; unpinning restores Normal TTL from `created`.
    pub fn set_pinned(&mut self, pinned: bool) {
        self.pinned = pinned;
        if pinned {
            self.expires_at = None;
        } else if self.expires_at.is_none() {
            self.expires_at = Retention::normal(self.created.wall()).expires_at();
        }
    }

    /// Set archive flag. Does not affect content or id.
    pub fn set_archived(&mut self, archived: bool) {
        self.archived = archived;
    }

    /// Override expiration. Does not affect content or id.
    pub fn set_expires_at(&mut self, expires_at: Option<Timestamp>) {
        self.expires_at = expires_at;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_new_is_random_and_unequal() {
        let a = ObjectId::new();
        let b = ObjectId::new();
        assert_ne!(a, b);
        assert_ne!(a.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn keyed_plaintext_id_is_not_raw_blake3() {
        let plaintext = b"shelf-object-plaintext";
        let index_key = [0x42u8; 32];
        let id = ObjectId::from_keyed_plaintext(&index_key, plaintext);
        let raw = blake3::hash(plaintext);
        assert_ne!(id.as_bytes(), raw.as_bytes());
        let other_key = [0x43u8; 32];
        let id2 = ObjectId::from_keyed_plaintext(&other_key, plaintext);
        assert_ne!(id, id2);
    }

    #[test]
    fn object_id_display_is_hex() {
        let id = ObjectId::from_bytes([0xab; 32]);
        let text = id.to_string();
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(format!("{id:?}").contains(&text));
    }
}
