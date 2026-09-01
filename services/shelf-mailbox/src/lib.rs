//! Optional zero-knowledge store-and-forward mailbox.
//!
//! The mailbox stores opaque ciphertext keyed by mailbox-id and object-id.
//! It has no vault keys and cannot enroll devices.

#![deny(missing_docs)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Mailbox failures.
#[derive(Debug, Error)]
pub enum MailboxError {
    /// Socket I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON framing.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Mailbox is over quota.
    #[error("mailbox over quota")]
    Quota,
}

/// One ciphertext item. The mailbox never inspects the payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailboxItem {
    /// Opaque object id (hex or other caller-chosen key).
    pub object_id: String,
    /// Sealed envelope bytes (Base64 on the wire).
    #[serde(with = "b64")]
    pub ciphertext: Vec<u8>,
}

mod b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            bytes,
        ))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Wire request. Intentionally dumb: PUT / GET / ACK.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MailboxRequest {
    /// Store ciphertext until `ttl_secs` elapses.
    Put {
        /// Opaque mailbox identifier (not a vault secret).
        mailbox_id: String,
        /// Opaque object id.
        object_id: String,
        /// Ciphertext (Base64 on the wire).
        #[serde(with = "b64")]
        ciphertext: Vec<u8>,
        /// Time to live in seconds.
        ttl_secs: u64,
    },
    /// List items for a mailbox.
    Get {
        /// Opaque mailbox identifier.
        mailbox_id: String,
    },
    /// Drop an item after a replica has ingested it.
    Ack {
        /// Opaque mailbox identifier.
        mailbox_id: String,
        /// Opaque object id.
        object_id: String,
    },
}

/// Wire response.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum MailboxResponse {
    /// PUT or ACK succeeded.
    Ok,
    /// GET result.
    Items {
        /// Ciphertext items. Empty when the mailbox is unused.
        items: Vec<MailboxItem>,
    },
    /// Typed failure.
    Error {
        /// Human-readable detail (no secrets).
        message: String,
    },
}

struct Stored {
    ciphertext: Vec<u8>,
    expires_unix: u64,
}

#[derive(Serialize, Deserialize)]
struct DiskMailbox {
    v: u16,
    slots: HashMap<String, HashMap<String, DiskItem>>,
}

#[derive(Serialize, Deserialize)]
struct DiskItem {
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    expires_unix: u64,
}

/// Maximum ciphertext bytes per item.
pub const MAX_ITEM_BYTES: usize = 8 * 1024 * 1024;
/// Maximum items per mailbox id.
pub const MAX_ITEMS: usize = 4096;
/// Maximum total bytes per mailbox id.
pub const MAX_MAILBOX_BYTES: usize = 64 * 1024 * 1024;

/// Ciphertext queue with caps and optional disk persist.
pub struct Mailbox {
    path: Option<PathBuf>,
    inner: Mutex<HashMap<String, HashMap<String, Stored>>>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            path: None,
            inner: Mutex::new(HashMap::new()),
        }
    }
}

impl Mailbox {
    /// Empty in-memory mailbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open or create a persisted mailbox at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MailboxError> {
        let path = path.as_ref().to_path_buf();
        let inner = if path.exists() {
            load_disk(&path)?
        } else {
            HashMap::new()
        };
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }

    fn persist(path: Option<&Path>, map: &HashMap<String, HashMap<String, Stored>>) {
        let Some(path) = path else {
            return;
        };
        let disk = DiskMailbox {
            v: 1,
            slots: map
                .iter()
                .map(|(mid, slot)| {
                    (
                        mid.clone(),
                        slot.iter()
                            .map(|(oid, stored)| {
                                (
                                    oid.clone(),
                                    DiskItem {
                                        ciphertext: stored.ciphertext.clone(),
                                        expires_unix: stored.expires_unix,
                                    },
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
        };
        let Ok(bytes) = serde_json::to_vec(&disk) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, bytes).is_ok() {
            let _ = fs::remove_file(path);
            let _ = fs::rename(&tmp, path);
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn gc(map: &mut HashMap<String, Stored>, now: u64) {
        map.retain(|_, v| v.expires_unix > now);
    }

    /// PUT.
    pub fn put(
        &self,
        mailbox_id: &str,
        object_id: String,
        ciphertext: Vec<u8>,
        ttl_secs: u64,
    ) -> Result<(), MailboxError> {
        if ciphertext.len() > MAX_ITEM_BYTES {
            return Err(MailboxError::Quota);
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Self::now();
        let slot = inner.entry(mailbox_id.to_owned()).or_default();
        Self::gc(slot, now);
        let used: usize = slot.values().map(|s| s.ciphertext.len()).sum();
        if slot.len() >= MAX_ITEMS || used.saturating_add(ciphertext.len()) > MAX_MAILBOX_BYTES {
            return Err(MailboxError::Quota);
        }
        slot.insert(
            object_id,
            Stored {
                ciphertext,
                expires_unix: now.saturating_add(ttl_secs),
            },
        );
        Self::persist(self.path.as_deref(), &inner);
        Ok(())
    }

    /// GET (does not remove).
    pub fn get(&self, mailbox_id: &str) -> Vec<MailboxItem> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Self::now();
        let Some(slot) = inner.get_mut(mailbox_id) else {
            return Vec::new();
        };
        Self::gc(slot, now);
        slot.iter()
            .map(|(id, stored)| MailboxItem {
                object_id: id.clone(),
                ciphertext: stored.ciphertext.clone(),
            })
            .collect()
    }

    /// ACK.
    pub fn ack(&self, mailbox_id: &str, object_id: &str) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = inner.get_mut(mailbox_id) {
            slot.remove(object_id);
        }
        Self::persist(self.path.as_deref(), &inner);
    }
}

fn load_disk(path: &Path) -> Result<HashMap<String, HashMap<String, Stored>>, MailboxError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }
    let disk: DiskMailbox = serde_json::from_slice(&bytes)?;
    Ok(disk
        .slots
        .into_iter()
        .map(|(mid, slot)| {
            (
                mid,
                slot.into_iter()
                    .map(|(oid, item)| {
                        (
                            oid,
                            Stored {
                                ciphertext: item.ciphertext,
                                expires_unix: item.expires_unix,
                            },
                        )
                    })
                    .collect(),
            )
        })
        .collect())
}

/// Serve newline-delimited JSON on `addr`.
pub async fn serve(addr: impl ToSocketAddrs, mailbox: Arc<Mailbox>) -> Result<(), MailboxError> {
    let listener = TcpListener::bind(addr).await?;
    accept_loop(listener, mailbox).await
}

/// Accept loop on an already-bound listener (tests).
pub async fn accept_loop(listener: TcpListener, mailbox: Arc<Mailbox>) -> Result<(), MailboxError> {
    loop {
        let (stream, _) = listener.accept().await?;
        let mailbox = Arc::clone(&mailbox);
        tokio::spawn(async move {
            if let Err(err) = handle(stream, mailbox).await {
                tracing_warn(err);
            }
        });
    }
}

fn tracing_warn(err: MailboxError) {
    eprintln!("shelf-mailbox: {err}");
}

async fn handle(stream: TcpStream, mailbox: Arc<Mailbox>) -> Result<(), MailboxError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 || line.len() > MAX_ITEM_BYTES {
        return Ok(());
    }
    let response = match serde_json::from_str::<MailboxRequest>(line.trim_end()) {
        Ok(MailboxRequest::Put {
            mailbox_id,
            object_id,
            ciphertext,
            ttl_secs,
        }) => mailbox
            .put(&mailbox_id, object_id, ciphertext, ttl_secs)
            .map_or_else(
                |e| MailboxResponse::Error {
                    message: e.to_string(),
                },
                |()| MailboxResponse::Ok,
            ),
        Ok(MailboxRequest::Get { mailbox_id }) => MailboxResponse::Items {
            items: mailbox.get(&mailbox_id),
        },
        Ok(MailboxRequest::Ack {
            mailbox_id,
            object_id,
        }) => {
            mailbox.ack(&mailbox_id, &object_id);
            MailboxResponse::Ok
        }
        Err(err) => MailboxResponse::Error {
            message: err.to_string(),
        },
    };
    let mut json = serde_json::to_string(&response)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

/// Client for a mailbox listener.
#[derive(Clone, Debug)]
pub struct MailboxClient {
    addr: String,
}

impl MailboxClient {
    /// Resolve `addr` (`host:port`) and remember it. Does not connect yet.
    pub async fn connect(addr: impl Into<String>) -> Result<Self, MailboxError> {
        let addr = addr.into();
        let _ = tokio::net::TcpStream::connect(&addr).await?;
        Ok(Self { addr })
    }

    /// PUT ciphertext.
    pub async fn put(
        &self,
        mailbox_id: &str,
        object_id: &str,
        ciphertext: &[u8],
        ttl_secs: u64,
    ) -> Result<(), MailboxError> {
        let req = MailboxRequest::Put {
            mailbox_id: mailbox_id.to_owned(),
            object_id: object_id.to_owned(),
            ciphertext: ciphertext.to_vec(),
            ttl_secs,
        };
        match rpc(&self.addr, &req).await? {
            MailboxResponse::Ok => Ok(()),
            MailboxResponse::Items { .. } => Err(MailboxError::Io(std::io::Error::other(
                "unexpected mailbox response",
            ))),
            MailboxResponse::Error { message } => {
                Err(MailboxError::Io(std::io::Error::other(message)))
            }
        }
    }

    /// GET items.
    pub async fn get(&self, mailbox_id: &str) -> Result<Vec<MailboxItem>, MailboxError> {
        let req = MailboxRequest::Get {
            mailbox_id: mailbox_id.to_owned(),
        };
        match rpc(&self.addr, &req).await? {
            MailboxResponse::Items { items } => Ok(items),
            MailboxResponse::Ok => Ok(Vec::new()),
            MailboxResponse::Error { message } => {
                Err(MailboxError::Io(std::io::Error::other(message)))
            }
        }
    }

    /// ACK an item.
    pub async fn ack(&self, mailbox_id: &str, object_id: &str) -> Result<(), MailboxError> {
        let req = MailboxRequest::Ack {
            mailbox_id: mailbox_id.to_owned(),
            object_id: object_id.to_owned(),
        };
        match rpc(&self.addr, &req).await? {
            MailboxResponse::Ok => Ok(()),
            MailboxResponse::Items { .. } => Ok(()),
            MailboxResponse::Error { message } => {
                Err(MailboxError::Io(std::io::Error::other(message)))
            }
        }
    }
}

async fn rpc(addr: &str, req: &MailboxRequest) -> Result<MailboxResponse, MailboxError> {
    let stream = TcpStream::connect(addr).await?;
    let (reader, mut writer) = stream.into_split();
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Err(MailboxError::Io(std::io::Error::other(
            "empty mailbox response",
        )));
    }
    Ok(serde_json::from_str(line.trim_end())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn put_get_ack_round_trip() {
        let mailbox = Arc::new(Mailbox::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mb = Arc::clone(&mailbox);
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let mb = Arc::clone(&mb);
                tokio::spawn(async move {
                    let _ = handle(stream, mb).await;
                });
            }
        });
        let client = MailboxClient::connect(addr.to_string()).await.unwrap();
        client
            .put("mid", "obj1", b"ciphertext-only", 60)
            .await
            .unwrap();
        let items = client.get("mid").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ciphertext, b"ciphertext-only");
        assert!(!String::from_utf8_lossy(&serde_json::to_vec(&items[0]).unwrap()).is_empty());
        client.ack("mid", "obj1").await.unwrap();
        assert!(client.get("mid").await.unwrap().is_empty());
    }

    #[test]
    fn put_rejects_oversize_item() {
        let mailbox = Mailbox::new();
        let big = vec![1u8; MAX_ITEM_BYTES + 1];
        assert!(matches!(
            mailbox.put("mid", "x".into(), big, 60),
            Err(MailboxError::Quota)
        ));
    }

    #[test]
    fn persist_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("shelf-mb-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mailbox.json");
        let mailbox = Mailbox::open(&path).unwrap();
        mailbox
            .put("mid", "obj1".into(), b"ciphertext-only".to_vec(), 60)
            .unwrap();
        drop(mailbox);
        let reopened = Mailbox::open(&path).unwrap();
        let items = reopened.get("mid");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ciphertext, b"ciphertext-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
