//! Optional zero-knowledge store-and-forward mailbox.
//!
//! The mailbox stores opaque ciphertext keyed by mailbox-id and object-id.
//! It has no vault keys and cannot enroll devices.

#![deny(missing_docs)]

use std::collections::HashMap;
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

/// In-memory ciphertext queue.
#[derive(Default)]
pub struct Mailbox {
    inner: Mutex<HashMap<String, HashMap<String, Stored>>>,
}

impl Mailbox {
    /// Empty mailbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
    pub fn put(&self, mailbox_id: &str, object_id: String, ciphertext: Vec<u8>, ttl_secs: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Self::now();
        let slot = inner.entry(mailbox_id.to_owned()).or_default();
        Self::gc(slot, now);
        slot.insert(
            object_id,
            Stored {
                ciphertext,
                expires_unix: now.saturating_add(ttl_secs),
            },
        );
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
    }
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
    if n == 0 || line.trim().is_empty() {
        return Ok(());
    }
    let response = match serde_json::from_str::<MailboxRequest>(line.trim_end()) {
        Ok(MailboxRequest::Put {
            mailbox_id,
            object_id,
            ciphertext,
            ttl_secs,
        }) => {
            mailbox.put(&mailbox_id, object_id, ciphertext, ttl_secs);
            MailboxResponse::Ok
        }
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
}
