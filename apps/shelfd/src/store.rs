//! IPC mapping onto [`shelf_store::SqliteStore`].

use shelf_client::{GetTarget, ListedItem};
use shelf_store::ItemTarget;

/// In-memory or on-disk vault. Tests use [`shelf_store::SqliteStore::memory`].
pub type MemoryStore = shelf_store::SqliteStore;

pub(crate) fn ipc_target(t: &GetTarget) -> ItemTarget {
    match t {
        GetTarget::Id { id } => ItemTarget::Id(*id),
        GetTarget::Index { index } => ItemTarget::Index(*index),
    }
}

pub(crate) fn listed(item: shelf_store::ListedItem) -> ListedItem {
    ListedItem {
        id: item.id,
        kind: item.kind,
        created: item.created,
        pinned: item.pinned,
        expires_at: item.expires_at,
    }
}
