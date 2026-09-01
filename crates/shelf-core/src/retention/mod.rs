//! Retention policies and the expire-object operation payload.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::{ObjectId, Timestamp};

/// Default retention for a normal Shelf object: 7 days.
pub const NORMAL_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Default retention for an explicit ephemeral object: 1 hour.
pub const EPHEMERAL_TTL: Duration = Duration::from_secs(60 * 60);

/// First-class retention class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPolicy {
    /// Short-lived (default 1 hour).
    Ephemeral,
    /// Default object lifetime (7 days).
    Normal,
    /// No expiry until explicitly unpinned.
    Pinned,
    /// Caller-supplied expiry.
    Custom,
}

/// Retention metadata attached to an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    /// When the object was created.
    pub created_at: Timestamp,
    /// Absolute expiry, or `None` if the object does not expire.
    pub expires_at: Option<Timestamp>,
    /// Policy that produced `expires_at`.
    pub policy: RetentionPolicy,
}

impl Retention {
    /// Normal policy: expires 7 days after `created_at`.
    #[must_use]
    pub fn normal(created_at: Timestamp) -> Self {
        Self {
            created_at,
            expires_at: Some(created_at.saturating_add(NORMAL_TTL)),
            policy: RetentionPolicy::Normal,
        }
    }

    /// Ephemeral policy: expires 1 hour after `created_at`.
    #[must_use]
    pub fn ephemeral(created_at: Timestamp) -> Self {
        Self {
            created_at,
            expires_at: Some(created_at.saturating_add(EPHEMERAL_TTL)),
            policy: RetentionPolicy::Ephemeral,
        }
    }

    /// Pinned policy: no expiry.
    #[must_use]
    pub fn pinned(created_at: Timestamp) -> Self {
        Self {
            created_at,
            expires_at: None,
            policy: RetentionPolicy::Pinned,
        }
    }

    /// Custom policy with an explicit expiry (or none).
    #[must_use]
    pub fn custom(created_at: Timestamp, expires_at: Option<Timestamp>) -> Self {
        Self {
            created_at,
            expires_at,
            policy: RetentionPolicy::Custom,
        }
    }

    /// Build retention from a policy. `Custom` yields no expiry until filled in.
    #[must_use]
    pub fn for_policy(policy: RetentionPolicy, created_at: Timestamp) -> Self {
        match policy {
            RetentionPolicy::Ephemeral => Self::ephemeral(created_at),
            RetentionPolicy::Normal => Self::normal(created_at),
            RetentionPolicy::Pinned => Self::pinned(created_at),
            RetentionPolicy::Custom => Self::custom(created_at, None),
        }
    }

    /// Creation time.
    #[must_use]
    pub const fn created_at(self) -> Timestamp {
        self.created_at
    }

    /// Expiration time, if any.
    #[must_use]
    pub const fn expires_at(self) -> Option<Timestamp> {
        self.expires_at
    }

    /// Policy tag.
    #[must_use]
    pub const fn policy(self) -> RetentionPolicy {
        self.policy
    }
}

/// Signed expire-op *payload* (signature is applied by protocol/keystore layers).
///
/// Replicas apply this operation and retain a tombstone so stale peers cannot
/// resurrect the object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpireObject {
    /// Object to expire.
    pub object_id: ObjectId,
    /// When expiration takes effect.
    pub effective_at: Timestamp,
}

impl ExpireObject {
    /// Construct an expire-op payload.
    #[must_use]
    pub const fn new(object_id: ObjectId, effective_at: Timestamp) -> Self {
        Self {
            object_id,
            effective_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_defaults() {
        let created = Timestamp::from_millis(1_700_000_000_000);
        let normal = Retention::normal(created);
        assert_eq!(normal.policy(), RetentionPolicy::Normal);
        assert_eq!(
            normal.expires_at(),
            Some(created.saturating_add(Duration::from_secs(7 * 24 * 60 * 60)))
        );

        let ephemeral = Retention::ephemeral(created);
        assert_eq!(ephemeral.policy(), RetentionPolicy::Ephemeral);
        assert_eq!(
            ephemeral.expires_at(),
            Some(created.saturating_add(Duration::from_secs(60 * 60)))
        );

        let pinned = Retention::pinned(created);
        assert_eq!(pinned.policy(), RetentionPolicy::Pinned);
        assert_eq!(pinned.expires_at(), None);
    }

    #[test]
    fn expire_object_carries_id_and_time() {
        let object_id = ObjectId::from_bytes([0x11; 32]);
        let effective_at = Timestamp::from_millis(99);
        let op = ExpireObject::new(object_id, effective_at);
        assert_eq!(op.object_id, object_id);
        assert_eq!(op.effective_at, effective_at);
    }
}
