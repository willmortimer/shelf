//! Encrypted SQLite vault: objects, tombstones, scratch, membership.

#![deny(missing_docs)]

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use shelf_core::enrollment::MembershipCertificate;
use shelf_core::{
    ChunkId, ContentKind, DEFAULT_CHUNK_SIZE, DeviceId, EpochId, FileManifest, HybridTimestamp,
    ObjectId, Retention, ScratchPad, Timestamp, VaultId,
};
use shelf_protocol::{EncryptedObject, EpochKey, ProtocolError, open, seal};
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
    device_id: DeviceId,
    epoch: EpochId,
    vault_id: VaultId,
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
        persist_identity(&conn, &epoch_key, device_id, epoch, vault_id).expect("identity");
        Self {
            conn,
            epoch_key,
            device_id,
            epoch,
            vault_id,
        }
    }

    /// Open or create `path`. `epoch_key` / ids must match the wrapped meta, or
    /// this is a brand-new file (empty schema then persist identity).
    pub fn open(
        path: &std::path::Path,
        epoch_key: EpochKey,
        device_id: DeviceId,
        epoch: EpochId,
        vault_id: VaultId,
    ) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = open_conn_file(path)?;
        init_schema(&conn)?;
        persist_identity(&conn, &epoch_key, device_id, epoch, vault_id)?;
        let store = Self {
            conn,
            epoch_key,
            device_id,
            epoch,
            vault_id,
        };
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
        self.epoch_key = epoch_key;
    }

    /// Persist the wrapped epoch-key blob (keystore ciphertext).
    pub fn save_wrapped_epoch_key(&self, blob: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('wrapped_epoch_key', ?1)",
            params![blob],
        )?;
        Ok(())
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

    /// Seal and insert. Expired live objects are collected first.
    pub fn put(
        &mut self,
        bytes: Vec<u8>,
        kind: ContentKind,
        name: Option<String>,
    ) -> Result<(ObjectId, HybridTimestamp), StoreError> {
        self.gc_expired()?;
        let object_id = ObjectId::new();
        let created = HybridTimestamp::now();
        let envelope = seal(
            &bytes,
            object_id,
            self.epoch,
            &self.epoch_key,
            kind,
            self.device_id,
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
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let mut chunk_ids = Vec::new();
        let chunk_size = usize::try_from(DEFAULT_CHUNK_SIZE).unwrap_or(4 * 1024 * 1024);
        for chunk in bytes.chunks(chunk_size.max(1)) {
            let chunk_id = ChunkId::new();
            chunk_ids.push(chunk_id);
            let object_id = ObjectId::from_bytes(*chunk_id.as_bytes());
            let created = HybridTimestamp::now();
            let envelope = seal(
                chunk,
                object_id,
                self.epoch,
                &self.epoch_key,
                ContentKind::OpaqueBytes,
                self.device_id,
            )?;
            self.insert_chunk(chunk_id, envelope, created)?;
        }
        let manifest = FileManifest::new(filename.clone(), mime, size, chunk_ids);
        let json = serde_json::to_vec(&manifest)?;
        self.put(json, ContentKind::File, Some(filename))
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

    /// Insert a peer chunk envelope. Tombstoned object ids are skipped.
    pub fn ingest_chunk(&mut self, envelope: EncryptedObject) -> Result<(), StoreError> {
        let chunk_id = ChunkId::from_bytes(*envelope.object_id.as_bytes());
        if self.is_tombstoned(envelope.object_id)? {
            return Ok(());
        }
        self.insert_chunk(chunk_id, envelope, HybridTimestamp::now())
    }

    /// Named scratch pads as Yrs update blobs for replica merge.
    pub fn export_scratch(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT name, update_blob FROM scratch")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((name, blob))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
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
            out.push(ListedItem {
                id: envelope.object_id,
                kind: envelope.content_kind,
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

    /// Append text to a named scratchpad and persist the Yrs update (sealed as metadata blob).
    pub fn scratch_append(&mut self, name: &str, content: &str) -> Result<String, StoreError> {
        let mut pad = self.load_scratch(name)?;
        pad.insert_text(content);
        let update = pad.encode_update();
        self.conn.execute(
            "INSERT OR REPLACE INTO scratch(name, update_blob) VALUES (?1, ?2)",
            params![name, update.as_slice()],
        )?;
        Ok(pad.text())
    }

    /// Current scratchpad plaintext.
    pub fn scratch_text(&self, name: &str) -> Result<String, StoreError> {
        Ok(self.load_scratch(name)?.text())
    }

    /// Merge a remote Yrs update into a named pad.
    pub fn scratch_apply(&mut self, name: &str, update: &[u8]) -> Result<String, StoreError> {
        let mut pad = self.load_scratch(name)?;
        pad.apply_update(update)?;
        let encoded = pad.encode_update();
        self.conn.execute(
            "INSERT OR REPLACE INTO scratch(name, update_blob) VALUES (?1, ?2)",
            params![name, encoded.as_slice()],
        )?;
        Ok(pad.text())
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
        let blob: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT update_blob FROM scratch WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?;
        let mut pad = ScratchPad::new(name);
        if let Some(update) = blob {
            pad.apply_update(&update)?;
        }
        Ok(pad)
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
        let bytes = open(
            &envelope,
            &self.epoch_key,
            envelope.content_kind,
            envelope.origin,
        )?;
        if envelope.content_kind == ContentKind::File
            && let Ok(manifest) = serde_json::from_slice::<FileManifest>(&bytes)
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
            kind: envelope.content_kind,
            bytes,
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
        Ok(open(
            &envelope,
            &self.epoch_key,
            envelope.content_kind,
            envelope.origin,
        )?)
    }

    fn insert_chunk(
        &self,
        chunk_id: ChunkId,
        envelope: EncryptedObject,
        _created: HybridTimestamp,
    ) -> Result<(), StoreError> {
        if self.is_tombstoned(envelope.object_id)? {
            return Ok(());
        }
        let json = serde_json::to_string(&envelope)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO chunks(chunk_id, envelope) VALUES (?1, ?2)",
            params![chunk_id.as_bytes().as_slice(), json],
        )?;
        Ok(())
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
         CREATE TABLE IF NOT EXISTS scratch (
           name TEXT PRIMARY KEY,
           update_blob BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS members (
           device_id BLOB PRIMARY KEY,
           certificate TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS chunks (
           chunk_id BLOB PRIMARY KEY,
           envelope TEXT NOT NULL
         );",
    )?;
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

fn persist_identity(
    conn: &Connection,
    epoch_key: &EpochKey,
    device_id: DeviceId,
    epoch: EpochId,
    vault_id: VaultId,
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
    // Placeholder; keystore overwrites with a real wrap.
    conn.execute(
        "INSERT INTO meta(k, v) VALUES ('wrapped_epoch_key', ?1)",
        params![epoch_key.as_bytes().as_slice()],
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
        let mut store = SqliteStore::open(&path, epoch_key, device_id, epoch, vault_id).unwrap();
        let (id, _) = store
            .put(b"persisted".to_vec(), ContentKind::Text, None)
            .unwrap();
        drop(store);

        let loaded = SqliteStore::load_identity(&path).unwrap().unwrap();
        assert_eq!(loaded.0, device_id);
        let store = SqliteStore::open(
            &path,
            EpochKey::from_bytes(key_bytes),
            loaded.0,
            loaded.1,
            loaded.2,
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
        let mut b = SqliteStore::memory();
        let update = {
            // encode from a via public text+update stored
            a.scratch_text("Scratch").unwrap();
            let blob: Vec<u8> = a
                .conn
                .query_row(
                    "SELECT update_blob FROM scratch WHERE name = 'Scratch'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            blob
        };
        b.scratch_apply("Scratch", &update).unwrap();
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
}
