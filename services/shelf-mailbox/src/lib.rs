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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
    /// Write or read capability did not match.
    #[error("mailbox capability denied")]
    Denied,
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
        /// Capability required to deposit (bound on first PUT).
        write_cap: String,
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
        /// Capability required to drain (bound on first GET).
        read_cap: String,
    },
    /// Drop an item after a replica has ingested it.
    Ack {
        /// Opaque mailbox identifier.
        mailbox_id: String,
        /// Capability required to drain.
        read_cap: String,
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

#[derive(Default)]
struct Slot {
    write_cap: Option<String>,
    read_cap: Option<String>,
    items: HashMap<String, Stored>,
}

#[derive(Serialize, Deserialize)]
struct DiskMailbox {
    v: u16,
    slots: HashMap<String, DiskSlot>,
}

#[derive(Serialize, Deserialize)]
struct DiskSlot {
    #[serde(default)]
    write_cap: Option<String>,
    #[serde(default)]
    read_cap: Option<String>,
    items: HashMap<String, DiskItem>,
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
    inner: Mutex<HashMap<String, Slot>>,
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

    fn persist(path: Option<&Path>, map: &HashMap<String, Slot>) {
        let Some(path) = path else {
            return;
        };
        let disk = DiskMailbox {
            v: 2,
            slots: map
                .iter()
                .map(|(mid, slot)| {
                    (
                        mid.clone(),
                        DiskSlot {
                            write_cap: slot.write_cap.clone(),
                            read_cap: slot.read_cap.clone(),
                            items: slot
                                .items
                                .iter()
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
                        },
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

    /// PUT. First PUT binds `write_cap`; later PUTs must match.
    pub fn put(
        &self,
        mailbox_id: &str,
        write_cap: &str,
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
        if let Some(bound) = slot.write_cap.as_deref() {
            if bound != write_cap {
                return Err(MailboxError::Denied);
            }
        } else {
            slot.write_cap = Some(write_cap.to_owned());
        }
        Self::gc(&mut slot.items, now);
        let used: usize = slot.items.values().map(|s| s.ciphertext.len()).sum();
        if slot.items.len() >= MAX_ITEMS
            || used.saturating_add(ciphertext.len()) > MAX_MAILBOX_BYTES
        {
            return Err(MailboxError::Quota);
        }
        slot.items.insert(
            object_id,
            Stored {
                ciphertext,
                expires_unix: now.saturating_add(ttl_secs),
            },
        );
        Self::persist(self.path.as_deref(), &inner);
        Ok(())
    }

    /// GET (does not remove). First GET binds `read_cap`.
    pub fn get(&self, mailbox_id: &str, read_cap: &str) -> Result<Vec<MailboxItem>, MailboxError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Self::now();
        let slot = inner.entry(mailbox_id.to_owned()).or_default();
        if let Some(bound) = slot.read_cap.as_deref() {
            if bound != read_cap {
                return Err(MailboxError::Denied);
            }
        } else if !read_cap.is_empty() {
            slot.read_cap = Some(read_cap.to_owned());
        } else {
            return Err(MailboxError::Denied);
        }
        Self::gc(&mut slot.items, now);
        let items: Vec<MailboxItem> = slot
            .items
            .iter()
            .map(|(id, stored)| MailboxItem {
                object_id: id.clone(),
                ciphertext: stored.ciphertext.clone(),
            })
            .collect();
        Self::persist(self.path.as_deref(), &inner);
        Ok(items)
    }

    /// ACK.
    pub fn ack(
        &self,
        mailbox_id: &str,
        read_cap: &str,
        object_id: &str,
    ) -> Result<(), MailboxError> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let slot = inner.entry(mailbox_id.to_owned()).or_default();
        if let Some(bound) = slot.read_cap.as_deref() {
            if bound != read_cap {
                return Err(MailboxError::Denied);
            }
        } else if !read_cap.is_empty() {
            slot.read_cap = Some(read_cap.to_owned());
        } else {
            return Err(MailboxError::Denied);
        }
        slot.items.remove(object_id);
        Self::persist(self.path.as_deref(), &inner);
        Ok(())
    }
}

fn load_disk(path: &Path) -> Result<HashMap<String, Slot>, MailboxError> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() {
        return Ok(HashMap::new());
    }
    if let Ok(disk) = serde_json::from_slice::<DiskMailbox>(&bytes) {
        return Ok(disk
            .slots
            .into_iter()
            .map(|(mid, slot)| {
                (
                    mid,
                    Slot {
                        write_cap: slot.write_cap,
                        read_cap: slot.read_cap,
                        items: slot
                            .items
                            .into_iter()
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
                    },
                )
            })
            .collect());
    }
    #[derive(Deserialize)]
    struct DiskV1 {
        slots: HashMap<String, HashMap<String, DiskItem>>,
    }
    let disk: DiskV1 = serde_json::from_slice(&bytes)?;
    Ok(disk
        .slots
        .into_iter()
        .map(|(mid, items)| {
            (
                mid,
                Slot {
                    write_cap: None,
                    read_cap: None,
                    items: items
                        .into_iter()
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
                },
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

async fn read_bounded_line(stream: &mut TcpStream) -> Result<Option<Vec<u8>>, MailboxError> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(MailboxError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "truncated mailbox frame",
                )))
            };
        }
        if buf.len() >= MAX_ITEM_BYTES {
            return Err(MailboxError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mailbox frame exceeds MAX_ITEM_BYTES",
            )));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(Some(buf));
        }
    }
}

async fn handle(mut stream: TcpStream, mailbox: Arc<Mailbox>) -> Result<(), MailboxError> {
    let Some(line) = read_bounded_line(&mut stream).await? else {
        return Ok(());
    };
    let slice = line.strip_suffix(b"\n").unwrap_or(&line);
    let response = match serde_json::from_slice::<MailboxRequest>(slice) {
        Ok(MailboxRequest::Put {
            mailbox_id,
            write_cap,
            object_id,
            ciphertext,
            ttl_secs,
        }) => mailbox
            .put(&mailbox_id, &write_cap, object_id, ciphertext, ttl_secs)
            .map_or_else(
                |e| MailboxResponse::Error {
                    message: e.to_string(),
                },
                |()| MailboxResponse::Ok,
            ),
        Ok(MailboxRequest::Get {
            mailbox_id,
            read_cap,
        }) => mailbox.get(&mailbox_id, &read_cap).map_or_else(
            |e| MailboxResponse::Error {
                message: e.to_string(),
            },
            |items| MailboxResponse::Items { items },
        ),
        Ok(MailboxRequest::Ack {
            mailbox_id,
            read_cap,
            object_id,
        }) => mailbox.ack(&mailbox_id, &read_cap, &object_id).map_or_else(
            |e| MailboxResponse::Error {
                message: e.to_string(),
            },
            |()| MailboxResponse::Ok,
        ),
        Err(err) => MailboxResponse::Error {
            message: err.to_string(),
        },
    };
    let mut json = serde_json::to_string(&response)?;
    json.push('\n');
    stream.write_all(json.as_bytes()).await?;
    stream.flush().await?;
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

    /// PUT ciphertext using the mailbox write capability.
    pub async fn put(
        &self,
        mailbox_id: &str,
        write_cap: &str,
        object_id: &str,
        ciphertext: &[u8],
        ttl_secs: u64,
    ) -> Result<(), MailboxError> {
        let req = MailboxRequest::Put {
            mailbox_id: mailbox_id.to_owned(),
            write_cap: write_cap.to_owned(),
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

    /// GET items using the mailbox read capability.
    pub async fn get(
        &self,
        mailbox_id: &str,
        read_cap: &str,
    ) -> Result<Vec<MailboxItem>, MailboxError> {
        let req = MailboxRequest::Get {
            mailbox_id: mailbox_id.to_owned(),
            read_cap: read_cap.to_owned(),
        };
        match rpc(&self.addr, &req).await? {
            MailboxResponse::Items { items } => Ok(items),
            MailboxResponse::Ok => Ok(Vec::new()),
            MailboxResponse::Error { message } => {
                Err(MailboxError::Io(std::io::Error::other(message)))
            }
        }
    }

    /// ACK an item using the mailbox read capability.
    pub async fn ack(
        &self,
        mailbox_id: &str,
        read_cap: &str,
        object_id: &str,
    ) -> Result<(), MailboxError> {
        let req = MailboxRequest::Ack {
            mailbox_id: mailbox_id.to_owned(),
            read_cap: read_cap.to_owned(),
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
    let mut stream = TcpStream::connect(addr).await?;
    let mut json = serde_json::to_string(req)?;
    json.push('\n');
    stream.write_all(json.as_bytes()).await?;
    stream.flush().await?;
    let Some(line) = read_bounded_line(&mut stream).await? else {
        return Err(MailboxError::Io(std::io::Error::other(
            "empty mailbox response",
        )));
    };
    let slice = line.strip_suffix(b"\n").unwrap_or(&line);
    Ok(serde_json::from_slice(slice)?)
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
            .put("mid", "write", "obj1", b"ciphertext-only", 60)
            .await
            .unwrap();
        let items = client.get("mid", "read").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ciphertext, b"ciphertext-only");
        assert!(!String::from_utf8_lossy(&serde_json::to_vec(&items[0]).unwrap()).is_empty());
        client.ack("mid", "read", "obj1").await.unwrap();
        assert!(client.get("mid", "read").await.unwrap().is_empty());
    }

    #[test]
    fn put_rejects_oversize_item() {
        let mailbox = Mailbox::new();
        let big = vec![1u8; MAX_ITEM_BYTES + 1];
        assert!(matches!(
            mailbox.put("mid", "w", "x".into(), big, 60),
            Err(MailboxError::Quota)
        ));
    }

    #[test]
    fn wrong_write_cap_is_denied() {
        let mailbox = Mailbox::new();
        mailbox
            .put("mid", "w1", "x".into(), b"ct".to_vec(), 60)
            .unwrap();
        assert!(matches!(
            mailbox.put("mid", "w2", "y".into(), b"ct".to_vec(), 60),
            Err(MailboxError::Denied)
        ));
    }

    #[test]
    fn persist_survives_reopen() {
        let dir = std::env::temp_dir().join(format!("shelf-mb-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("mailbox.json");
        let mailbox = Mailbox::open(&path).unwrap();
        mailbox
            .put("mid", "w", "obj1".into(), b"ciphertext-only".to_vec(), 60)
            .unwrap();
        drop(mailbox);
        let reopened = Mailbox::open(&path).unwrap();
        let items = reopened.get("mid", "r").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].ciphertext, b"ciphertext-only");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
