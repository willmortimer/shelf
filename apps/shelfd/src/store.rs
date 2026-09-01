//! In-memory encrypted object store.
//!
//! Plaintext is sealed with [`shelf_protocol::seal`] before insert and only
//! recovered with [`shelf_protocol::open`] on `latest` / `get`. The socket-
//! adjacent store never retains plaintext.

use shelf_client::{GetTarget, ListedItem, ObjectPayload};
use shelf_core::{ContentKind, DeviceId, EpochId, HybridTimestamp, ObjectId, Retention, Timestamp};
use shelf_protocol::{EncryptedObject, EpochKey, ProtocolError, open, seal};

/// Failures from store operations (mapped to IPC error codes by the server).
#[derive(Debug)]
pub(crate) enum StoreError {
    NotFound,
    Protocol(ProtocolError),
}

/// One sealed object plus mutable metadata (no plaintext payload).
struct StoredItem {
    envelope: EncryptedObject,
    created: HybridTimestamp,
    pinned: bool,
    expires_at: Option<Timestamp>,
    /// Optional put-time name; not listed in this slice.
    #[allow(dead_code)]
    name: Option<String>,
}

/// Daemon-local store: software [`EpochKey`] and sealed objects in memory.
///
/// A fresh [`DeviceId`] and epoch key are generated per instance.
pub struct MemoryStore {
    epoch_key: EpochKey,
    device_id: DeviceId,
    epoch: EpochId,
    items: Vec<StoredItem>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Create an empty store with a random replica id and epoch key.
    #[must_use]
    pub fn new() -> Self {
        Self {
            epoch_key: EpochKey::new(),
            device_id: DeviceId::new(),
            epoch: EpochId::new(1),
            items: Vec::new(),
        }
    }

    /// Seal `bytes` under the daemon epoch key and retain ciphertext only.
    pub(crate) fn put(
        &mut self,
        bytes: Vec<u8>,
        kind: ContentKind,
        name: Option<String>,
    ) -> Result<(ObjectId, HybridTimestamp), StoreError> {
        let object_id = ObjectId::new();
        let created = HybridTimestamp::now();
        let envelope = seal(
            &bytes,
            object_id,
            self.epoch,
            &self.epoch_key,
            kind,
            self.device_id,
        )
        .map_err(StoreError::Protocol)?;
        let expires_at = Retention::normal(created.wall()).expires_at();
        self.items.push(StoredItem {
            envelope,
            created,
            pinned: false,
            expires_at,
            name,
        });
        Ok((object_id, created))
    }

    /// Metadata only, newest first. Does not decrypt.
    pub(crate) fn ls(&self) -> Vec<ListedItem> {
        self.ordered_newest_first()
            .into_iter()
            .map(|item| ListedItem {
                id: item.envelope.object_id,
                kind: item.envelope.content_kind,
                created: item.created,
                pinned: item.pinned,
                expires_at: item.expires_at,
            })
            .collect()
    }

    /// Decrypt the newest object.
    pub(crate) fn latest(&self) -> Result<ObjectPayload, StoreError> {
        let item = self
            .ordered_newest_first()
            .into_iter()
            .next()
            .ok_or(StoreError::NotFound)?;
        self.open_item(item)
    }

    /// Decrypt by hex id or 1-based newest-first index.
    pub(crate) fn get(&self, target: &GetTarget) -> Result<ObjectPayload, StoreError> {
        match target {
            GetTarget::Id { id } => {
                let item = self
                    .items
                    .iter()
                    .find(|item| item.envelope.object_id == *id)
                    .ok_or(StoreError::NotFound)?;
                self.open_item(item)
            }
            GetTarget::Index { index } => {
                if *index == 0 {
                    return Err(StoreError::NotFound);
                }
                let idx = usize::try_from(index.saturating_sub(1)).unwrap_or(usize::MAX);
                let ordered = self.ordered_newest_first();
                let item = ordered.get(idx).copied().ok_or(StoreError::NotFound)?;
                self.open_item(item)
            }
        }
    }

    fn ordered_newest_first(&self) -> Vec<&StoredItem> {
        let mut items: Vec<(usize, &StoredItem)> = self.items.iter().enumerate().collect();
        items.sort_by(|(i, a), (j, b)| b.created.cmp(&a.created).then(j.cmp(i)));
        items.into_iter().map(|(_, item)| item).collect()
    }

    /// Pin by hex id or 1-based newest-first index. Clears expiry.
    pub(crate) fn pin(&mut self, target: &GetTarget) -> Result<ObjectId, StoreError> {
        let id = self.resolve_id(target)?;
        let item = self
            .items
            .iter_mut()
            .find(|item| item.envelope.object_id == id)
            .ok_or(StoreError::NotFound)?;
        item.pinned = true;
        item.expires_at = None;
        Ok(id)
    }

    /// Remove by hex id or 1-based newest-first index.
    pub(crate) fn rm(&mut self, target: &GetTarget) -> Result<ObjectId, StoreError> {
        let id = self.resolve_id(target)?;
        let pos = self
            .items
            .iter()
            .position(|item| item.envelope.object_id == id)
            .ok_or(StoreError::NotFound)?;
        self.items.remove(pos);
        Ok(id)
    }

    fn resolve_id(&self, target: &GetTarget) -> Result<ObjectId, StoreError> {
        match target {
            GetTarget::Id { id } => {
                if self.items.iter().any(|item| item.envelope.object_id == *id) {
                    Ok(*id)
                } else {
                    Err(StoreError::NotFound)
                }
            }
            GetTarget::Index { index } => {
                if *index == 0 {
                    return Err(StoreError::NotFound);
                }
                let idx = usize::try_from(index.saturating_sub(1)).unwrap_or(usize::MAX);
                self.ordered_newest_first()
                    .get(idx)
                    .map(|item| item.envelope.object_id)
                    .ok_or(StoreError::NotFound)
            }
        }
    }

    fn open_item(&self, item: &StoredItem) -> Result<ObjectPayload, StoreError> {
        let bytes = open(
            &item.envelope,
            &self.epoch_key,
            item.envelope.content_kind,
            item.envelope.origin,
        )
        .map_err(StoreError::Protocol)?;
        Ok(ObjectPayload {
            id: item.envelope.object_id,
            kind: item.envelope.content_kind,
            bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::ContentKind;

    #[test]
    fn put_then_get_round_trips_without_keeping_plaintext_in_store() {
        let mut store = MemoryStore::new();
        let payload = b"not-in-the-store-vec";
        let (id, _) = store
            .put(payload.to_vec(), ContentKind::Text, None)
            .unwrap();
        let opened = store.get(&GetTarget::Id { id }).unwrap();
        assert_eq!(opened.bytes, payload);
        let envelope_json = serde_json::to_string(&store.items[0].envelope).unwrap();
        assert!(
            !envelope_json.contains("not-in-the-store-vec"),
            "plaintext must not appear in the persisted envelope"
        );
    }

    #[test]
    fn latest_is_newest_and_index_one_matches() {
        let mut store = MemoryStore::new();
        store
            .put(b"first".to_vec(), ContentKind::Text, None)
            .unwrap();
        let (id2, _) = store
            .put(b"second".to_vec(), ContentKind::Text, None)
            .unwrap();
        let latest = store.latest().unwrap();
        assert_eq!(latest.id, id2);
        assert_eq!(latest.bytes, b"second");
        let by_index = store.get(&GetTarget::Index { index: 1 }).unwrap();
        assert_eq!(by_index.id, id2);
        let older = store.get(&GetTarget::Index { index: 2 }).unwrap();
        assert_eq!(older.bytes, b"first");
    }

    #[test]
    fn missing_id_and_zero_index_are_not_found() {
        let store = MemoryStore::new();
        assert!(matches!(
            store.get(&GetTarget::Id {
                id: ObjectId::from_bytes([0x22; 32])
            }),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            store.get(&GetTarget::Index { index: 0 }),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(store.latest(), Err(StoreError::NotFound)));
    }

    #[test]
    fn pin_sets_flag_and_rm_removes() {
        let mut store = MemoryStore::new();
        let (id, _) = store
            .put(b"keep-me".to_vec(), ContentKind::Text, None)
            .unwrap();
        assert!(!store.ls()[0].pinned);

        store.pin(&GetTarget::Index { index: 1 }).unwrap();
        let listed = store.ls();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].pinned);
        assert_eq!(listed[0].id, id);
        assert_eq!(listed[0].expires_at, None);

        store.rm(&GetTarget::Id { id }).unwrap();
        assert!(store.ls().is_empty());
        assert!(matches!(
            store.get(&GetTarget::Id { id }),
            Err(StoreError::NotFound)
        ));
    }
}
