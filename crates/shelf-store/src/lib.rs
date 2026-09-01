//! Encrypted SQLite vault: objects, tombstones, scratch, membership.

#![deny(missing_docs)]

use std::collections::BTreeMap;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use shelf_core::enrollment::MembershipCertificate;
use shelf_core::{
    ChunkId, ContentKind, DEFAULT_CHUNK_SIZE, DeviceId, EpochId, FileManifest, HlcClock,
    HybridTimestamp, ObjectId, Retention, ScratchPad, Timestamp, VaultId, scratch_id_for,
};
use shelf_protocol::{EncryptedObject, EpochKey, ProtocolError, open, seal_named};
use thiserror::Error;

/// Failures from vault persistence or envelope seal/open.
#[derive(Debug, Error)]
pub enum StoreError {
    /// No matching live object (or the id is tombstoned).
    #[error("object not found")]
    NotFound,
    /// Envelope seal/open failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// SQLite failure.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// Filesystem failure while creating the vault directory.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON (de)serialization of a stored envelope failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Scratch CRDT merge failed.
    #[error(transparent)]
    Crdt(#[from] shelf_core::CrdtError),
    /// Scratch envelope was not a sealed pad.
    #[error("invalid scratch envelope")]
    InvalidScratch,
    /// Envelope epoch is not in the local keyring.
    #[error("unknown epoch")]
    UnknownEpoch,
    /// Operation log rejected a duplicate or foreign vault op.
    #[error("invalid replica operation")]
    InvalidOp,
}

/// Selector used by the daemon IPC (id or 1-based newest-first index).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemTarget {
    /// Hex object identifier.
    Id(ObjectId),
    /// 1-based index into the newest-first listing. `0` is not found.
    Index(u64),
}

/// Metadata row: no plaintext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedItem {
    /// Object identifier.
    pub id: ObjectId,
    /// Content classification.
    pub kind: ContentKind,
    /// Creation hybrid timestamp.
    pub created: HybridTimestamp,
    /// Durable pin.
    pub pinned: bool,
    /// Absolute expiration, if any.
    pub expires_at: Option<Timestamp>,
}

/// Decrypted object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedObject {
    /// Object identifier.
    pub id: ObjectId,
    /// Content classification.
    pub kind: ContentKind,
    /// Plaintext payload.
    pub bytes: Vec<u8>,
}

/// Sealed object plus replica metadata (no plaintext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRecord {
    /// Encrypted envelope.
    pub envelope: EncryptedObject,
    /// Creation hybrid timestamp.
    pub created: HybridTimestamp,
    /// Durable pin.
    pub pinned: bool,
    /// Absolute expiration, if any.
    pub expires_at: Option<Timestamp>,
    /// Optional put-time name.
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredRow {
    envelope: EncryptedObject,
    created: HybridTimestamp,
    pinned: bool,
    expires_at: Option<Timestamp>,
    name: Option<String>,
}

/// Identity fields loaded from an existing `state.db`.
pub type StoredIdentity = (DeviceId, EpochId, VaultId, Vec<u8>);

/// Durable encrypted object store.
pub struct SqliteStore {
    conn: Connection,
    epoch_key: EpochKey,
    epoch_keys: BTreeMap<u64, EpochKey>,
    device_id: DeviceId,
    epoch: EpochId,
    vault_id: VaultId,
    hlc: HlcClock,
}

impl SqliteStore {
    /// In-memory vault with a fresh identity and epoch. Used by tests.
    #[must_use]
    pub fn new() -> Self {
        Self::memory()
    }

    /// In-memory SQLite vault.
    #[must_use]
    pub fn memory() -> Self {
        let conn = open_conn_memory();
        let epoch_key = EpochKey::new();
        let device_id = DeviceId::new();
        let epoch = EpochId::new(1);
        let vault_id = VaultId::new();
        init_schema(&conn).expect("schema");
        // Never persist the raw epoch key; tests do not unwrap this blob.
        persist_identity(&conn, device_id, epoch, vault_id, &[0xEE; 32]).expect("identity");
        migrate_epoch_wraps(&conn, epoch).expect("epoch wraps");
        let mut epoch_keys = BTreeMap::new();
        epoch_keys.insert(epoch.as_u64(), epoch_key.clone());
        Self {
            conn,
            epoch_key,
            epoch_keys,
            device_id,
            epoch,
            vault_id,
            hlc: HlcClock::default(),
        }
    }

    /// Open or create `path`. `epoch_key` is held in memory only.
    /// `wrapped_epoch_key` is the keystore ciphertext persisted on first create.
    pub fn open(
        path: &std::path::Path,
        epoch_key: EpochKey,
        device_id: DeviceId,
        epoch: EpochId,
        vault_id: VaultId,
        wrapped_epoch_key: &[u8],
    ) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = open_conn_file(path)?;
        init_schema(&conn)?;
        persist_identity(&conn, device_id, epoch, vault_id, wrapped_epoch_key)?;
        migrate_epoch_wraps(&conn, epoch)?;
        let hlc = load_hlc(&conn).unwrap_or_default();
        let mut epoch_keys = BTreeMap::new();
        epoch_keys.insert(epoch.as_u64(), epoch_key.clone());
        let mut store = Self {
            conn,
            epoch_key,
            epoch_keys,
            device_id,
            epoch,
            vault_id,
            hlc,
        };
        store.load_keyring()?;
        store.gc_expired()?;
        Ok(store)
    }

    /// Load identity fields from an existing database, if initialized.
    pub fn load_identity(path: &std::path::Path) -> Result<Option<StoredIdentity>, StoreError> {
        if !path.exists() {
            return Ok(None);
        }
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        let device = meta_blob(&conn, "device_id")?;
        let epoch = meta_blob(&conn, "epoch")?;
        let vault = meta_blob(&conn, "vault_id")?;
        let wrapped = meta_blob(&conn, "wrapped_epoch_key")?;
        match (device, epoch, vault, wrapped) {
            (Some(d), Some(e), Some(v), Some(w))
                if d.len() == 32 && e.len() == 8 && v.len() == 32 =>
            {
                let mut epoch_bytes = [0u8; 8];
                epoch_bytes.copy_from_slice(&e);
                Ok(Some((
                    DeviceId::from_bytes(d.try_into().unwrap()),
                    EpochId::new(u64::from_le_bytes(epoch_bytes)),
                    VaultId::from_bytes(v.try_into().unwrap()),
                    w,
                )))
            }
            _ => Ok(None),
        }
    }

    /// Replace the in-memory epoch key after importing a membership grant.
    pub fn adopt_epoch_key(&mut self, epoch_key: EpochKey) {
        self.epoch_keys
            .insert(self.epoch.as_u64(), epoch_key.clone());
        self.epoch_key = epoch_key;
    }

    /// Persist vault id and epoch from a membership grant, plus the in-memory epoch key.
    pub fn adopt_membership(
        &mut self,
        epoch_key: EpochKey,
        epoch: EpochId,
        vault_id: VaultId,
    ) -> Result<(), StoreError> {
        self.epoch_keys.insert(epoch.as_u64(), epoch_key.clone());
        self.epoch_key = epoch_key;
        self.epoch = epoch;
        self.vault_id = vault_id;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('epoch', ?1)",
            params![epoch.as_u64().to_le_bytes().as_slice()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('vault_id', ?1)",
            params![vault_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Persist the vault root (first-device authority).
    pub fn save_vault_root(&self, root: &shelf_core::VaultRoot) -> Result<(), StoreError> {
        let json = serde_json::to_vec(root)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('vault_root', ?1)",
            params![json],
        )?;
        Ok(())
    }

    /// Loaded vault root, if this vault has been initialized with one.
    pub fn vault_root(&self) -> Result<Option<shelf_core::VaultRoot>, StoreError> {
        match meta_blob(&self.conn, "vault_root")? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Remember the last exported enrollment request hash until import.
    pub fn save_pending_request_hash(&self, hash: &[u8; 32]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('pending_request_hash', ?1)",
            params![hash.as_slice()],
        )?;
        Ok(())
    }

    /// Pending join request hash, if `shelf enroll export` ran on this vault.
    pub fn pending_request_hash(&self) -> Result<Option<[u8; 32]>, StoreError> {
        match meta_blob(&self.conn, "pending_request_hash")? {
            Some(bytes) if bytes.len() == 32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Some(out))
            }
            _ => Ok(None),
        }
    }

    /// Clear the pending join request after a successful import.
    pub fn clear_pending_request_hash(&self) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM meta WHERE k = 'pending_request_hash'", [])?;
        Ok(())
    }

    /// Tombstones for replica fan-out.
    pub fn export_tombstones(&self) -> Result<Vec<(ObjectId, Timestamp)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT object_id, effective_at FROM tombstones")?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            let at: i64 = row.get(1)?;
            Ok((id, at))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, at) = row?;
            if let Ok(oid) = id_from_vec(&id) {
                out.push((oid, Timestamp::from_millis(millis_from_sql(at))));
            }
        }
        Ok(out)
    }

    /// Apply a peer tombstone even if the object was never seen locally.
    pub fn apply_tombstone(&mut self, id: ObjectId, at: Timestamp) -> Result<(), StoreError> {
        let _ = self.conn.execute(
            "DELETE FROM objects WHERE object_id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO tombstones(object_id, effective_at) VALUES (?1, ?2)",
            params![id.as_bytes().as_slice(), at.as_millis() as i64],
        )?;
        Ok(())
    }

    /// Pin by object id (replica / signed op).
    pub fn pin_id(&mut self, id: ObjectId) -> Result<(), StoreError> {
        let n = self.conn.execute(
            "UPDATE objects SET pinned = 1, expires_at = NULL WHERE object_id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Persist the wrapped epoch-key blob (keystore ciphertext) for the current epoch.
    pub fn save_wrapped_epoch_key(&self, blob: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('wrapped_epoch_key', ?1)",
            params![blob],
        )?;
        self.save_epoch_wrap(self.epoch, blob)
    }

    /// Persist a wrapped epoch key for `epoch` (historical keys stay decryptable).
    pub fn save_epoch_wrap(&self, epoch: EpochId, wrapped: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO epoch_wraps(epoch, wrapped) VALUES (?1, ?2)",
            params![epoch.as_u64() as i64, wrapped],
        )?;
        Ok(())
    }

    /// Wrapped epoch-key blobs for every epoch in the local keyring.
    pub fn list_epoch_wraps(&self) -> Result<Vec<(EpochId, Vec<u8>)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT epoch, wrapped FROM epoch_wraps")?;
        let rows = stmt.query_map([], |row| {
            let epoch: i64 = row.get(0)?;
            let wrapped: Vec<u8> = row.get(1)?;
            Ok((epoch, wrapped))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (epoch, wrapped) = row?;
            out.push((EpochId::new(epoch as u64), wrapped));
        }
        Ok(out)
    }

    /// This replica's device id.
    #[must_use]
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    /// Current vault epoch.
    #[must_use]
    pub fn epoch(&self) -> EpochId {
        self.epoch
    }

    /// Vault id bound into membership certificates.
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Borrow the epoch key for wrapping grants. Do not log.
    #[must_use]
    pub fn epoch_key(&self) -> &EpochKey {
        &self.epoch_key
    }

    /// Opaque mailbox identifier (not the vault id).
    pub fn mailbox_id(&self) -> Result<String, StoreError> {
        match meta_blob(&self.conn, "mailbox_id")? {
            Some(bytes) => Ok(bytes.iter().map(|b| format!("{b:02x}")).collect()),
            None => Ok(hex_id(self.vault_id.as_bytes())),
        }
    }

    /// Epoch key for `epoch`, or [`StoreError::UnknownEpoch`].
    pub fn key_for(&self, epoch: EpochId) -> Result<&EpochKey, StoreError> {
        self.epoch_keys
            .get(&epoch.as_u64())
            .ok_or(StoreError::UnknownEpoch)
    }

    /// Install an additional historical epoch key (kept after revocation).
    pub fn add_epoch_key(&mut self, epoch: EpochId, key: EpochKey) -> Result<(), StoreError> {
        self.epoch_keys.insert(epoch.as_u64(), key);
        Ok(())
    }

    /// Remove a member and rotate to a new epoch. Old epoch keys stay local.
    pub fn revoke_device(
        &mut self,
        device_id: DeviceId,
        new_key: EpochKey,
    ) -> Result<EpochId, StoreError> {
        let new_epoch = self.epoch.next();
        self.epoch_keys.insert(new_epoch.as_u64(), new_key.clone());
        self.epoch_key = new_key;
        self.epoch = new_epoch;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('epoch', ?1)",
            params![new_epoch.as_u64().to_le_bytes().as_slice()],
        )?;
        self.conn.execute(
            "DELETE FROM members WHERE device_id = ?1",
            params![device_id.as_bytes().as_slice()],
        )?;
        Ok(new_epoch)
    }

    fn load_keyring(&mut self) -> Result<(), StoreError> {
        Ok(())
    }

    fn tick(&mut self) -> HybridTimestamp {
        let ts = self.hlc.now();
        let _ = persist_hlc(&self.conn, ts);
        ts
    }

    fn open_env(
        &self,
        envelope: &EncryptedObject,
    ) -> Result<shelf_protocol::OpenedPayload, StoreError> {
        let key = self.key_for(envelope.epoch)?;
        Ok(open(envelope, key)?)
    }

    /// Decrypt envelope metadata (kind, origin, name) with the matching epoch key.
    pub fn open_envelope(
        &self,
        envelope: &EncryptedObject,
    ) -> Result<shelf_protocol::OpenedPayload, StoreError> {
        self.open_env(envelope)
    }

    /// Drop a member certificate after a signed revoke op.
    pub fn remove_member(&self, device_id: DeviceId) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM members WHERE device_id = ?1",
            params![device_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Seal and insert. Expired live objects are collected first.
    pub fn put(
        &mut self,
        bytes: Vec<u8>,
        kind: ContentKind,
        name: Option<String>,
    ) -> Result<(ObjectId, HybridTimestamp), StoreError> {
        self.gc_expired()?;
        let object_id = ObjectId::new();
        let created = self.tick();
        let envelope = seal_named(
            &bytes,
            object_id,
            self.epoch,
            &self.epoch_key,
            kind,
            self.device_id,
            name.as_deref(),
            Some(created),
        )?;
        let expires_at = Retention::normal(created.wall()).expires_at();
        self.insert_row(StoredRow {
            envelope,
            created,
            pinned: false,
            expires_at,
            name,
        })?;
        Ok((object_id, created))
    }

    /// Seal a file as a [`FileManifest`] plus independently encrypted 4 MiB chunks.
    ///
    /// Chunks are stored outside the object listing so `ls` stays a user-facing
    /// object list. [`Self::get`] reassembles plaintext for `ContentKind::File`.
    pub fn put_file(
        &mut self,
        filename: String,
        mime: String,
        bytes: Vec<u8>,
    ) -> Result<(ObjectId, HybridTimestamp), StoreError> {
        self.gc_expired()?;
        let parent = ObjectId::new();
        let created = self.tick();
        let expires_at = Retention::normal(created.wall()).expires_at();
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut chunk_ids = Vec::new();
        let chunk_size = usize::try_from(DEFAULT_CHUNK_SIZE).unwrap_or(4 * 1024 * 1024);
        for chunk in bytes.chunks(chunk_size.max(1)) {
            let chunk_id = ChunkId::new();
            chunk_ids.push(chunk_id);
            let chunk_oid = ObjectId::from_bytes(*chunk_id.as_bytes());
            let envelope = seal_named(
                chunk,
                chunk_oid,
                self.epoch,
                &self.epoch_key,
                ContentKind::OpaqueBytes,
                self.device_id,
                None,
                Some(created),
            )?;
            self.insert_chunk(chunk_id, parent, envelope, expires_at)?;
        }
        let manifest = FileManifest::new(filename.clone(), mime, size, chunk_ids);
        let json = serde_json::to_vec(&manifest)?;
        let envelope = seal_named(
            &json,
            parent,
            self.epoch,
            &self.epoch_key,
            ContentKind::File,
            self.device_id,
            Some(&filename),
            Some(created),
        )?;
        self.insert_row(StoredRow {
            envelope,
            created,
            pinned: false,
            expires_at,
            name: Some(filename),
        })?;
        Ok((parent, created))
    }

    /// Live sealed objects for replica fan-out (metadata + ciphertext, no plaintext).
    pub fn export_objects(&self) -> Result<Vec<SealedRecord>, StoreError> {
        self.gc_expired()?;
        let mut stmt = self.conn.prepare(
            "SELECT envelope, created_logical, created_wall, pinned, expires_at, name
             FROM objects",
        )?;
        let rows = stmt.query_map([], |row| {
            let envelope_json: String = row.get(0)?;
            let logical: i64 = row.get(1)?;
            let wall: i64 = row.get(2)?;
            let pinned: i64 = row.get(3)?;
            let expires: Option<i64> = row.get(4)?;
            let name: Option<String> = row.get(5)?;
            Ok((envelope_json, logical, wall, pinned, expires, name))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (envelope_json, logical, wall, pinned, expires, name) = row?;
            let envelope: EncryptedObject = serde_json::from_str(&envelope_json)?;
            out.push(SealedRecord {
                envelope,
                created: HybridTimestamp::new(logical as u64, Timestamp::from_millis(wall as u64)),
                pinned: pinned != 0,
                expires_at: expires.map(|m| Timestamp::from_millis(millis_from_sql(m))),
                name,
            });
        }
        Ok(out)
    }

    /// Sealed file chunks for replica fan-out.
    pub fn export_chunks(&self) -> Result<Vec<EncryptedObject>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT envelope FROM chunks")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// Insert a peer chunk envelope bound to `parent`. Tombstoned parents are skipped.
    pub fn ingest_chunk(
        &mut self,
        parent: ObjectId,
        envelope: EncryptedObject,
    ) -> Result<(), StoreError> {
        let chunk_id = ChunkId::from_bytes(*envelope.object_id.as_bytes());
        if self.is_tombstoned(parent)? {
            return Ok(());
        }
        let expires = self.parent_expires(parent)?;
        self.insert_chunk(chunk_id, parent, envelope, expires)
    }

    /// Chunk ids listed in `parent`'s file manifest that are not local.
    ///
    /// Reads the sealed manifest, not the reassembled file bytes.
    pub fn missing_chunks(&self, parent: ObjectId) -> Result<Vec<ChunkId>, StoreError> {
        let Some(manifest) = self.file_manifest(parent)? else {
            return Ok(Vec::new());
        };
        let mut missing = Vec::new();
        for id in manifest.chunk_ids {
            let n: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM chunks WHERE chunk_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )?;
            if n == 0 {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    /// Sealed chunk envelopes for `ids` bound to `parent` (NeedChunks replies).
    pub fn chunk_envelopes(
        &self,
        parent: ObjectId,
        ids: &[ChunkId],
    ) -> Result<Vec<(ObjectId, EncryptedObject)>, StoreError> {
        if self.is_tombstoned(parent)? {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for id in ids {
            let json: Option<String> = self
                .conn
                .query_row(
                    "SELECT envelope FROM chunks WHERE chunk_id = ?1 AND parent = ?2",
                    params![id.as_bytes().as_slice(), parent.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(json) = json {
                out.push((parent, serde_json::from_str(&json)?));
            }
        }
        Ok(out)
    }

    /// All local chunk bindings for replica fan-out.
    pub fn export_chunk_bindings(&self) -> Result<Vec<(ObjectId, EncryptedObject)>, StoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT parent, envelope FROM chunks WHERE parent IS NOT NULL")?;
        let rows = stmt.query_map([], |row| {
            let parent: Vec<u8> = row.get(0)?;
            let json: String = row.get(1)?;
            Ok((parent, json))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (parent, json) = row?;
            let parent = id_from_vec(&parent)?;
            out.push((parent, serde_json::from_str(&json)?));
        }
        Ok(out)
    }

    /// True when a durable op with `dedupe` already exists.
    pub fn has_op_dedupe(&self, dedupe: &str) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM ops WHERE dedupe = ?1",
            params![dedupe],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    /// Next local sequence number (persisted).
    pub fn allocate_seq(&self) -> Result<u64, StoreError> {
        let current = meta_blob(&self.conn, "op_seq")?;
        let last = match current {
            Some(b) if b.len() == 8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&b);
                u64::from_le_bytes(buf)
            }
            _ => 0,
        };
        let next = last.saturating_add(1);
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('op_seq', ?1)",
            params![next.to_le_bytes().as_slice()],
        )?;
        Ok(next)
    }

    /// Persist a signed operation JSON keyed by `dedupe` (insert-or-ignore).
    pub fn append_op_json(&self, dedupe: &str, json: &str) -> Result<(), StoreError> {
        let parsed: serde_json::Value = serde_json::from_str(json)?;
        let op_id = parsed
            .get("op_id")
            .and_then(|v| v.as_str())
            .ok_or(StoreError::InvalidOp)?;
        let seq = parsed
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .ok_or(StoreError::InvalidOp)?;
        let origin = parsed.get("origin").cloned().ok_or(StoreError::InvalidOp)?;
        let origin_bytes = serde_json::from_value::<DeviceId>(origin)?
            .as_bytes()
            .to_vec();
        self.conn.execute(
            "INSERT OR IGNORE INTO ops(op_id, seq, origin, body, dedupe) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![op_id, seq as i64, origin_bytes, json, dedupe],
        )?;
        Ok(())
    }

    /// Signed operation JSON in sequence order.
    pub fn export_ops_json(&self) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT body FROM ops ORDER BY seq ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Sealed scratch envelopes for replica (never raw Yrs).
    pub fn export_scratch(&self) -> Result<Vec<EncryptedObject>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT envelope FROM scratch_pads")?;
        let rows = stmt.query_map([], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            out.push(serde_json::from_str(&json)?);
        }
        Ok(out)
    }

    /// Insert a sealed envelope from a peer. Skips tombstoned ids (anti-resurrection).
    pub fn ingest_envelope(
        &mut self,
        envelope: EncryptedObject,
        created: HybridTimestamp,
        pinned: bool,
        expires_at: Option<Timestamp>,
        name: Option<String>,
    ) -> Result<(), StoreError> {
        if self.is_tombstoned(envelope.object_id)? {
            return Ok(());
        }
        self.insert_row(StoredRow {
            envelope,
            created,
            pinned,
            expires_at,
            name,
        })
    }

    /// Metadata only, newest first. Does not decrypt.
    pub fn ls(&self) -> Result<Vec<ListedItem>, StoreError> {
        self.gc_expired()?;
        let mut stmt = self.conn.prepare(
            "SELECT envelope, created_logical, created_wall, pinned, expires_at
             FROM objects ORDER BY created_wall DESC, created_logical DESC, rowid DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let envelope_json: String = row.get(0)?;
            let logical: i64 = row.get(1)?;
            let wall: i64 = row.get(2)?;
            let pinned: i64 = row.get(3)?;
            let expires: Option<i64> = row.get(4)?;
            Ok((envelope_json, logical, wall, pinned, expires))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (envelope_json, logical, wall, pinned, expires) = row?;
            let envelope: EncryptedObject = serde_json::from_str(&envelope_json)?;
            let kind = self
                .open_env(&envelope)
                .map(|o| o.content_kind)
                .unwrap_or(ContentKind::OpaqueBytes);
            out.push(ListedItem {
                id: envelope.object_id,
                kind,
                created: HybridTimestamp::new(logical as u64, Timestamp::from_millis(wall as u64)),
                pinned: pinned != 0,
                expires_at: expires.map(|m| Timestamp::from_millis(millis_from_sql(m))),
            });
        }
        Ok(out)
    }

    /// Decrypt the newest live object.
    pub fn latest(&self) -> Result<OpenedObject, StoreError> {
        self.gc_expired()?;
        let id = self
            .ls()?
            .into_iter()
            .next()
            .ok_or(StoreError::NotFound)?
            .id;
        self.open_id(id)
    }

    /// Decrypt by id or 1-based index.
    pub fn get(&self, target: &ItemTarget) -> Result<OpenedObject, StoreError> {
        self.gc_expired()?;
        let id = self.resolve_id(target)?;
        self.open_id(id)
    }

    /// Pin and clear expiry.
    pub fn pin(&mut self, target: &ItemTarget) -> Result<ObjectId, StoreError> {
        let id = self.resolve_id(target)?;
        let n = self.conn.execute(
            "UPDATE objects SET pinned = 1, expires_at = NULL WHERE object_id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(id)
    }

    /// Remove ciphertext and record a tombstone so stale replicas cannot resurrect it.
    pub fn rm(&mut self, target: &ItemTarget) -> Result<ObjectId, StoreError> {
        let id = self.resolve_id(target)?;
        self.delete_and_tombstone(id, Timestamp::now())?;
        Ok(id)
    }

    /// Append text to a named scratchpad and persist a sealed envelope (never raw Yrs).
    pub fn scratch_append(&mut self, name: &str, content: &str) -> Result<String, StoreError> {
        let _ = self.tick();
        let mut pad = self.load_scratch(name)?;
        pad.insert_text(content);
        self.persist_scratch(name, &pad)?;
        Ok(pad.text())
    }

    /// Current scratchpad plaintext.
    pub fn scratch_text(&self, name: &str) -> Result<String, StoreError> {
        Ok(self.load_scratch(name)?.text())
    }

    /// Merge a remote sealed scratch envelope into a pad.
    pub fn ingest_scratch_envelope(
        &mut self,
        envelope: EncryptedObject,
    ) -> Result<String, StoreError> {
        let opened = self.open_env(&envelope)?;
        if opened.content_kind != ContentKind::Scratch {
            return Err(StoreError::InvalidScratch);
        }
        let (name, update) = decode_scratch_body(&opened.plaintext)?;
        let mut pad = self.load_scratch(&name)?;
        pad.apply_update(&update)?;
        self.persist_scratch(&name, &pad)?;
        Ok(pad.text())
    }

    /// Sealed envelope for a pad, if it exists.
    pub fn scratch_envelope(&self, name: &str) -> Result<Option<EncryptedObject>, StoreError> {
        let id = scratch_id_for(self.vault_id, name);
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT envelope FROM scratch_pads WHERE scratch_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(Some(serde_json::from_str(&j)?)),
            None => Ok(None),
        }
    }

    /// Record a membership certificate.
    pub fn put_member(&self, cert: &MembershipCertificate) -> Result<(), StoreError> {
        let json = serde_json::to_string(cert)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO members(device_id, certificate) VALUES (?1, ?2)",
            params![cert.device_id.as_bytes().as_slice(), json],
        )?;
        Ok(())
    }

    /// Known membership certificates.
    pub fn members(&self) -> Result<Vec<MembershipCertificate>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT certificate FROM members")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// Whether `object_id` has a tombstone.
    pub fn is_tombstoned(&self, object_id: ObjectId) -> Result<bool, StoreError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tombstones WHERE object_id = ?1",
            params![object_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        Ok(n > 0)
    }

    fn load_scratch(&self, name: &str) -> Result<ScratchPad, StoreError> {
        let id = scratch_id_for(self.vault_id, name);
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT envelope FROM scratch_pads WHERE scratch_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let mut pad = ScratchPad::new(name);
        if let Some(json) = json {
            let env: EncryptedObject = serde_json::from_str(&json)?;
            let pt = self.open_env(&env)?;
            if pt.content_kind != ContentKind::Scratch {
                return Err(StoreError::InvalidScratch);
            }
            let (stored_name, update) = decode_scratch_body(&pt.plaintext)?;
            if stored_name != name {
                return Err(StoreError::InvalidScratch);
            }
            pad.apply_update(&update)?;
        }
        Ok(pad)
    }

    fn persist_scratch(&self, name: &str, pad: &ScratchPad) -> Result<(), StoreError> {
        let id = scratch_id_for(self.vault_id, name);
        let body = encode_scratch_body(name, &pad.encode_update());
        let object_id = ObjectId::from_bytes(*id.as_bytes());
        let env = seal_named(
            &body,
            object_id,
            self.epoch,
            &self.epoch_key,
            ContentKind::Scratch,
            self.device_id,
            Some(name),
            Some(self.hlc.last()),
        )?;
        let json = serde_json::to_string(&env)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO scratch_pads(scratch_id, envelope) VALUES (?1, ?2)",
            params![id.as_bytes().as_slice(), json],
        )?;
        Ok(())
    }

    fn insert_row(&self, row: StoredRow) -> Result<(), StoreError> {
        if self.is_tombstoned(row.envelope.object_id)? {
            return Ok(());
        }
        let json = serde_json::to_string(&row.envelope)?;
        let expires = row.expires_at.map(|t| t.as_millis() as i64);
        self.conn.execute(
            "INSERT OR REPLACE INTO objects
             (object_id, envelope, created_logical, created_wall, pinned, expires_at, name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.envelope.object_id.as_bytes().as_slice(),
                json,
                row.created.logical() as i64,
                row.created.wall().as_millis() as i64,
                i64::from(row.pinned),
                expires,
                row.name,
            ],
        )?;
        Ok(())
    }

    fn file_manifest(&self, parent: ObjectId) -> Result<Option<FileManifest>, StoreError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT envelope FROM objects WHERE object_id = ?1",
                params![parent.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(json) = json else {
            return Ok(None);
        };
        let envelope: EncryptedObject = serde_json::from_str(&json)?;
        let opened = self.open_env(&envelope)?;
        if opened.content_kind != ContentKind::File {
            return Ok(None);
        }
        Ok(Some(serde_json::from_slice(&opened.plaintext)?))
    }

    fn open_id(&self, id: ObjectId) -> Result<OpenedObject, StoreError> {
        let json: String = self
            .conn
            .query_row(
                "SELECT envelope FROM objects WHERE object_id = ?1",
                params![id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let envelope: EncryptedObject = serde_json::from_str(&json)?;
        let opened = self.open_env(&envelope)?;
        if opened.content_kind == ContentKind::File
            && let Ok(manifest) = serde_json::from_slice::<FileManifest>(&opened.plaintext)
        {
            let mut assembled = Vec::new();
            for chunk_id in &manifest.chunk_ids {
                assembled.extend(self.open_chunk(*chunk_id)?);
            }
            return Ok(OpenedObject {
                id: envelope.object_id,
                kind: ContentKind::File,
                bytes: assembled,
            });
        }
        Ok(OpenedObject {
            id: envelope.object_id,
            kind: opened.content_kind,
            bytes: opened.plaintext,
        })
    }

    fn open_chunk(&self, chunk_id: ChunkId) -> Result<Vec<u8>, StoreError> {
        let json: String = self
            .conn
            .query_row(
                "SELECT envelope FROM chunks WHERE chunk_id = ?1",
                params![chunk_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let envelope: EncryptedObject = serde_json::from_str(&json)?;
        Ok(self.open_env(&envelope)?.plaintext)
    }

    fn insert_chunk(
        &self,
        chunk_id: ChunkId,
        parent: ObjectId,
        envelope: EncryptedObject,
        expires_at: Option<Timestamp>,
    ) -> Result<(), StoreError> {
        if self.is_tombstoned(parent)? {
            return Ok(());
        }
        let json = serde_json::to_string(&envelope)?;
        let expires = expires_at.map(|t| t.as_millis() as i64);
        self.conn.execute(
            "INSERT OR REPLACE INTO chunks(chunk_id, parent, envelope, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                chunk_id.as_bytes().as_slice(),
                parent.as_bytes().as_slice(),
                json,
                expires,
            ],
        )?;
        Ok(())
    }

    fn parent_expires(&self, parent: ObjectId) -> Result<Option<Timestamp>, StoreError> {
        let expires: Option<i64> = self
            .conn
            .query_row(
                "SELECT expires_at FROM objects WHERE object_id = ?1",
                params![parent.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(expires.map(|m| Timestamp::from_millis(millis_from_sql(m))))
    }

    fn resolve_id(&self, target: &ItemTarget) -> Result<ObjectId, StoreError> {
        match target {
            ItemTarget::Id(id) => {
                let n: i64 = self.conn.query_row(
                    "SELECT COUNT(*) FROM objects WHERE object_id = ?1",
                    params![id.as_bytes().as_slice()],
                    |row| row.get(0),
                )?;
                if n == 0 {
                    Err(StoreError::NotFound)
                } else {
                    Ok(*id)
                }
            }
            ItemTarget::Index(index) => {
                if *index == 0 {
                    return Err(StoreError::NotFound);
                }
                let listing = self.ls()?;
                let idx = usize::try_from(index.saturating_sub(1)).unwrap_or(usize::MAX);
                listing
                    .get(idx)
                    .map(|item| item.id)
                    .ok_or(StoreError::NotFound)
            }
        }
    }

    fn delete_and_tombstone(&self, id: ObjectId, at: Timestamp) -> Result<(), StoreError> {
        let n = self.conn.execute(
            "DELETE FROM objects WHERE object_id = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        if n == 0 {
            return Err(StoreError::NotFound);
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO tombstones(object_id, effective_at) VALUES (?1, ?2)",
            params![id.as_bytes().as_slice(), at.as_millis() as i64],
        )?;
        self.conn.execute(
            "DELETE FROM chunks WHERE parent = ?1",
            params![id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    fn gc_expired(&self) -> Result<(), StoreError> {
        let now = Timestamp::now().as_millis() as i64;
        let ids: Vec<Vec<u8>> = {
            let mut stmt = self.conn.prepare(
                "SELECT object_id FROM objects
                 WHERE pinned = 0 AND expires_at IS NOT NULL AND expires_at <= ?1",
            )?;
            let rows = stmt.query_map(params![now], |row| row.get(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for id in ids {
            if let Ok(oid) = id_from_vec(&id) {
                let _ = self.delete_and_tombstone(oid, Timestamp::now());
            }
        }
        self.conn.execute(
            "DELETE FROM chunks WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(())
    }
}

fn id_from_vec(id: &[u8]) -> Result<ObjectId, StoreError> {
    let bytes: [u8; 32] = id.try_into().map_err(|_| StoreError::NotFound)?;
    Ok(ObjectId::from_bytes(bytes))
}

fn millis_from_sql(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn init_schema(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB NOT NULL);
         CREATE TABLE IF NOT EXISTS objects (
           object_id BLOB PRIMARY KEY,
           envelope TEXT NOT NULL,
           created_logical INTEGER NOT NULL,
           created_wall INTEGER NOT NULL,
           pinned INTEGER NOT NULL,
           expires_at INTEGER,
           name TEXT
         );
         CREATE TABLE IF NOT EXISTS tombstones (
           object_id BLOB PRIMARY KEY,
           effective_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS scratch_pads (
           scratch_id BLOB PRIMARY KEY,
           envelope TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS members (
           device_id BLOB PRIMARY KEY,
           certificate TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS chunks (
           chunk_id BLOB PRIMARY KEY,
           parent BLOB,
           envelope TEXT NOT NULL,
           expires_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS ops (
           op_id TEXT PRIMARY KEY,
           seq INTEGER NOT NULL,
           origin BLOB NOT NULL,
           body TEXT NOT NULL,
           dedupe TEXT
         );
         CREATE TABLE IF NOT EXISTS epoch_wraps (
           epoch INTEGER PRIMARY KEY,
           wrapped BLOB NOT NULL
         );",
    )?;
    let _ = conn.execute("ALTER TABLE chunks ADD COLUMN parent BLOB", []);
    let _ = conn.execute("ALTER TABLE chunks ADD COLUMN expires_at INTEGER", []);
    let _ = conn.execute("ALTER TABLE ops ADD COLUMN dedupe TEXT", []);
    let _ = conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ops_dedupe ON ops(dedupe) WHERE dedupe IS NOT NULL",
        [],
    );
    Ok(())
}

fn open_conn_memory() -> Connection {
    let conn = Connection::open_in_memory().expect("in-memory sqlite");
    configure_conn(&conn).expect("pragma");
    conn
}

fn open_conn_file(path: &std::path::Path) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)?;
    configure_conn(&conn)?;
    Ok(conn)
}

fn configure_conn(conn: &Connection) -> Result<(), StoreError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "foreign_keys", "ON");
    Ok(())
}

fn encode_scratch_body(name: &str, update: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut out = Vec::with_capacity(4 + name_bytes.len() + update.len());
    let len = u32::try_from(name_bytes.len()).unwrap_or(0);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(update);
    out
}

fn decode_scratch_body(bytes: &[u8]) -> Result<(String, Vec<u8>), StoreError> {
    if bytes.len() < 4 {
        return Err(StoreError::InvalidScratch);
    }
    let n = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if bytes.len() < 4 + n {
        return Err(StoreError::InvalidScratch);
    }
    let name = std::str::from_utf8(&bytes[4..4 + n]).map_err(|_| StoreError::InvalidScratch)?;
    Ok((name.to_owned(), bytes[4 + n..].to_vec()))
}

fn persist_identity(
    conn: &Connection,
    device_id: DeviceId,
    epoch: EpochId,
    vault_id: VaultId,
    wrapped_epoch_key: &[u8],
) -> Result<(), StoreError> {
    let existing: Option<Vec<u8>> = conn
        .query_row("SELECT v FROM meta WHERE k = 'device_id'", [], |row| {
            row.get(0)
        })
        .optional()?;
    if existing.is_some() {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('device_id', ?1)",
        params![device_id.as_bytes().as_slice()],
    )?;
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('epoch', ?1)",
        params![epoch.as_u64().to_le_bytes().as_slice()],
    )?;
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('vault_id', ?1)",
        params![vault_id.as_bytes().as_slice()],
    )?;
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('wrapped_epoch_key', ?1)",
        params![wrapped_epoch_key],
    )?;
    let mailbox: [u8; 32] = rand::random();
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('mailbox_id', ?1)",
        params![mailbox.as_slice()],
    )?;
    conn.execute(
        "INSERT INTO epoch_wraps(epoch, wrapped) VALUES (?1, ?2)",
        params![epoch.as_u64() as i64, wrapped_epoch_key],
    )?;
    Ok(())
}

fn migrate_epoch_wraps(conn: &Connection, epoch: EpochId) -> Result<(), StoreError> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM epoch_wraps", [], |row| row.get(0))?;
    if n == 0
        && let Some(wrapped) = meta_blob(conn, "wrapped_epoch_key")?
    {
        conn.execute(
            "INSERT INTO epoch_wraps(epoch, wrapped) VALUES (?1, ?2)",
            params![epoch.as_u64() as i64, wrapped],
        )?;
    }
    Ok(())
}

fn hex_id(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load_hlc(conn: &Connection) -> Result<HlcClock, StoreError> {
    let logical = meta_blob(conn, "hlc_logical")?;
    let wall = meta_blob(conn, "hlc_wall")?;
    match (logical, wall) {
        (Some(l), Some(w)) if l.len() == 8 && w.len() == 8 => {
            let mut lb = [0u8; 8];
            let mut wb = [0u8; 8];
            lb.copy_from_slice(&l);
            wb.copy_from_slice(&w);
            Ok(HlcClock::from_last(HybridTimestamp::new(
                u64::from_le_bytes(lb),
                Timestamp::from_millis(u64::from_le_bytes(wb)),
            )))
        }
        _ => Ok(HlcClock::default()),
    }
}

fn persist_hlc(conn: &Connection, ts: HybridTimestamp) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES ('hlc_logical', ?1)",
        params![ts.logical().to_le_bytes().as_slice()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO meta(k, v) VALUES ('hlc_wall', ?1)",
        params![ts.wall().as_millis().to_le_bytes().as_slice()],
    )?;
    Ok(())
}

fn meta_blob(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(conn
        .query_row("SELECT v FROM meta WHERE k = ?1", params![key], |row| {
            row.get(0)
        })
        .optional()?)
}

impl Default for SqliteStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::ContentKind;

    #[test]
    fn put_then_get_round_trips_without_plaintext_in_db() {
        let mut store = SqliteStore::memory();
        let payload = b"not-in-the-sqlite-row";
        let (id, _) = store
            .put(payload.to_vec(), ContentKind::Text, None)
            .unwrap();
        let opened = store.get(&ItemTarget::Id(id)).unwrap();
        assert_eq!(opened.bytes, payload);
        let json: String = store
            .conn
            .query_row("SELECT envelope FROM objects", [], |row| row.get(0))
            .unwrap();
        assert!(!json.contains("not-in-the-sqlite-row"));
    }

    #[test]
    fn file_round_trip_survives_reopen_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let epoch_key = EpochKey::new();
        let device_id = DeviceId::new();
        let epoch = EpochId::new(1);
        let vault_id = VaultId::new();
        let key_bytes = *epoch_key.as_bytes();
        let mut store =
            SqliteStore::open(&path, epoch_key, device_id, epoch, vault_id, &[0xEE; 32]).unwrap();
        let (id, _) = store
            .put(b"persisted".to_vec(), ContentKind::Text, None)
            .unwrap();
        drop(store);

        let loaded = SqliteStore::load_identity(&path).unwrap().unwrap();
        assert_eq!(loaded.0, device_id);
        assert_eq!(loaded.3, vec![0xEE; 32]);
        assert_ne!(loaded.3.as_slice(), key_bytes.as_slice());
        let store = SqliteStore::open(
            &path,
            EpochKey::from_bytes(key_bytes),
            loaded.0,
            loaded.1,
            loaded.2,
            &[0xEE; 32],
        )
        .unwrap();
        let opened = store.get(&ItemTarget::Id(id)).unwrap();
        assert_eq!(opened.bytes, b"persisted");
    }

    #[test]
    fn rm_writes_tombstone_and_ingest_does_not_resurrect() {
        let mut store = SqliteStore::memory();
        let (id, created) = store
            .put(b"secret".to_vec(), ContentKind::Text, None)
            .unwrap();
        let envelope = {
            let json: String = store
                .conn
                .query_row(
                    "SELECT envelope FROM objects WHERE object_id = ?1",
                    params![id.as_bytes().as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            serde_json::from_str(&json).unwrap()
        };
        store.rm(&ItemTarget::Id(id)).unwrap();
        assert!(store.is_tombstoned(id).unwrap());
        store
            .ingest_envelope(envelope, created, false, None, None)
            .unwrap();
        assert!(matches!(
            store.get(&ItemTarget::Id(id)),
            Err(StoreError::NotFound)
        ));
    }

    #[test]
    fn scratch_append_and_merge() {
        let mut a = SqliteStore::memory();
        a.scratch_append("Scratch", "hello ").unwrap();
        let env = a.scratch_envelope("Scratch").unwrap().unwrap();
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            !json.contains("hello"),
            "Yrs plaintext must not appear in the scratch envelope"
        );
        let mut b = SqliteStore::memory();
        // Same vault/epoch so the envelope DEK unwraps; different device id is fine.
        b = {
            let key = *a.epoch_key().as_bytes();
            let vault = a.vault_id();
            let epoch = a.epoch();
            drop(b);
            SqliteStore::open(
                &std::env::temp_dir().join(format!(
                    "shelf-scratch-{}-{}.db",
                    std::process::id(),
                    "b"
                )),
                shelf_protocol::EpochKey::from_bytes(key),
                DeviceId::new(),
                epoch,
                vault,
                &[0xEE; 32],
            )
            .unwrap()
        };
        b.ingest_scratch_envelope(env).unwrap();
        assert_eq!(b.scratch_text("Scratch").unwrap(), "hello ");
    }

    #[test]
    fn pin_and_index() {
        let mut store = SqliteStore::memory();
        store.put(b"a".to_vec(), ContentKind::Text, None).unwrap();
        let (id2, _) = store.put(b"b".to_vec(), ContentKind::Json, None).unwrap();
        assert_eq!(store.latest().unwrap().id, id2);
        store.pin(&ItemTarget::Index(1)).unwrap();
        assert!(store.ls().unwrap()[0].pinned);
    }

    #[test]
    fn put_file_reassembles_and_hides_chunks_from_ls() {
        let mut store = SqliteStore::memory();
        let payload = vec![0xABu8; 64];
        let (id, _) = store
            .put_file(
                "notes.bin".into(),
                "application/octet-stream".into(),
                payload.clone(),
            )
            .unwrap();
        let listed = store.ls().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, ContentKind::File);
        assert_eq!(listed[0].id, id);
        let opened = store.get(&ItemTarget::Id(id)).unwrap();
        assert_eq!(opened.bytes, payload);
        assert_eq!(store.export_chunks().unwrap().len(), 1);
        let json: String = store
            .conn
            .query_row("SELECT envelope FROM objects", [], |row| row.get(0))
            .unwrap();
        assert!(
            !json.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "file plaintext must not appear in the object envelope"
        );
    }

    #[test]
    fn adopt_membership_persists_vault_and_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let epoch_key = EpochKey::new();
        let key_bytes = *epoch_key.as_bytes();
        let mut store = SqliteStore::open(
            &path,
            epoch_key,
            DeviceId::new(),
            EpochId::new(1),
            VaultId::new(),
            &[0xEE; 32],
        )
        .unwrap();
        let new_vault = VaultId::new();
        store
            .adopt_membership(EpochKey::from_bytes(key_bytes), EpochId::new(9), new_vault)
            .unwrap();
        drop(store);
        let loaded = SqliteStore::load_identity(&path).unwrap().unwrap();
        assert_eq!(loaded.1, EpochId::new(9));
        assert_eq!(loaded.2, new_vault);
    }

    #[test]
    fn successive_puts_advance_hlc() {
        let mut store = SqliteStore::memory();
        let (_, a) = store.put(b"a".to_vec(), ContentKind::Text, None).unwrap();
        let (_, b) = store.put(b"b".to_vec(), ContentKind::Text, None).unwrap();
        assert!(b > a);
    }

    #[test]
    fn mailbox_id_is_not_vault_id() {
        let store = SqliteStore::memory();
        let mid = store.mailbox_id().unwrap();
        let vault = store
            .vault_id()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_ne!(mid, vault);
        assert_eq!(mid.len(), 64);
    }

    #[test]
    fn file_chunks_have_parent_and_gc_with_rm() {
        let mut store = SqliteStore::memory();
        let (id, _) = store
            .put_file(
                "n.bin".into(),
                "application/octet-stream".into(),
                vec![7; 8],
            )
            .unwrap();
        assert!(store.missing_chunks(id).unwrap().is_empty());
        store.rm(&ItemTarget::Id(id)).unwrap();
        assert!(store.export_chunks().unwrap().is_empty());
    }

    #[test]
    fn allocate_seq_is_monotonic_and_ops_dedupe() {
        let store = SqliteStore::memory();
        let a = store.allocate_seq().unwrap();
        let b = store.allocate_seq().unwrap();
        assert!(b > a);
        let json = serde_json::json!({
            "seq": 1,
            "op_id": "aabbccdd",
            "vault_id": store.vault_id(),
            "epoch": store.epoch(),
            "origin": store.device_id(),
            "body": {
                "kind": "pin",
                "object_id": ObjectId::new(),
                "at": 0
            },
            "signature": ""
        })
        .to_string();
        store.append_op_json("pin:x", &json).unwrap();
        store.append_op_json("pin:x", &json).unwrap();
        assert_eq!(store.export_ops_json().unwrap().len(), 1);
        assert!(store.has_op_dedupe("pin:x").unwrap());
    }
}
