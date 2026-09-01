//! Newline-delimited JSON IPC types shared by `shelfd`, `shelf-client`, and
//! later the CLI.
//!
//! # Framing
//!
//! Each connection carries **one** request and **one** response:
//!
//! 1. Client writes a single JSON object, then a newline (`\n`).
//! 2. Daemon writes a single JSON object, then a newline.
//! 3. Either side may close the socket.
//!
//! `bytes` fields are standard Base64 (RFC 4648) strings, never raw JSON
//! arrays. `ls` responses contain metadata only — no payload bytes.

use std::fmt;

use serde::{Deserialize, Serialize};
use shelf_core::{ContentKind, HybridTimestamp, ObjectId, Timestamp};

use crate::b64;

/// JSON request sent by a local client.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Seal and store an object.
    Put {
        /// Plaintext payload (Base64 on the wire).
        #[serde(with = "b64")]
        bytes: Vec<u8>,
        /// Content classification.
        kind: ContentKind,
        /// Optional display name (not returned by `ls` in this slice).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// List object metadata, newest first. No plaintext.
    Ls,
    /// Decrypt the newest object by [`HybridTimestamp`].
    Latest,
    /// Decrypt one object by id or 1-based index (newest first).
    Get {
        /// Id or 1-based listing index.
        #[serde(flatten)]
        target: GetTarget,
    },
    /// Pin an object by id or 1-based index (newest first).
    Pin {
        /// Id or 1-based listing index.
        #[serde(flatten)]
        target: GetTarget,
    },
    /// Remove an object by id or 1-based index (newest first).
    Rm {
        /// Id or 1-based listing index.
        #[serde(flatten)]
        target: GetTarget,
    },
    /// Read a named scratch pad (Yrs CRDT plaintext).
    ScratchGet {
        /// Pad name. Defaults to `Scratch`.
        #[serde(default = "default_scratch_name")]
        name: String,
    },
    /// Append text to a named scratch pad.
    ScratchAppend {
        /// Pad name. Defaults to `Scratch`.
        #[serde(default = "default_scratch_name")]
        name: String,
        /// Text to insert at the current end.
        text: String,
    },
    /// Seal a local file by path (daemon streams 4 MiB chunks; the IPC line
    /// never carries the file bytes).
    PutFile {
        /// Absolute path the daemon can open.
        path: String,
        /// Display filename stored in the file manifest.
        filename: String,
        /// MIME type. Defaults to `application/octet-stream`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mime: Option<String>,
    },
}

fn default_scratch_name() -> String {
    "Scratch".into()
}

impl fmt::Debug for IpcRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put { bytes, kind, name } => f
                .debug_struct("Put")
                .field("bytes_len", &bytes.len())
                .field("kind", kind)
                .field("name", name)
                .finish(),
            Self::Ls => write!(f, "Ls"),
            Self::Latest => write!(f, "Latest"),
            Self::Get { target } => f.debug_tuple("Get").field(target).finish(),
            Self::Pin { target } => f.debug_tuple("Pin").field(target).finish(),
            Self::Rm { target } => f.debug_tuple("Rm").field(target).finish(),
            Self::ScratchGet { name } => f.debug_tuple("ScratchGet").field(name).finish(),
            Self::ScratchAppend { name, text } => f
                .debug_struct("ScratchAppend")
                .field("name", name)
                .field("text_len", &text.len())
                .finish(),
            Self::PutFile {
                path,
                filename,
                mime,
            } => f
                .debug_struct("PutFile")
                .field("path", path)
                .field("filename", filename)
                .field("mime", mime)
                .finish(),
        }
    }
}

/// Selector for [`IpcRequest::Get`].
///
/// Indices are **1-based** into the newest-first listing (`shelf get 4`).
/// Index `0` is not found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetTarget {
    /// Hex object identifier.
    Id {
        /// Object id.
        id: ObjectId,
    },
    /// 1-based index into the newest-first listing.
    Index {
        /// Position starting at 1.
        index: u64,
    },
}

/// JSON response from the daemon.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum IpcResponse {
    /// Successful put.
    Put {
        /// New object id.
        id: ObjectId,
        /// Creation hybrid timestamp.
        created: HybridTimestamp,
    },
    /// Successful list (metadata only).
    Ls {
        /// Newest-first metadata rows.
        items: Vec<ListedItem>,
    },
    /// Successful latest.
    Latest {
        /// Object id.
        id: ObjectId,
        /// Content classification.
        kind: ContentKind,
        /// Decrypted payload (Base64 on the wire).
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// Successful get.
    Get {
        /// Object id.
        id: ObjectId,
        /// Content classification.
        kind: ContentKind,
        /// Decrypted payload (Base64 on the wire).
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// Successful pin.
    Pin {
        /// Object id that is now pinned.
        id: ObjectId,
    },
    /// Successful remove.
    Rm {
        /// Object id that was removed.
        id: ObjectId,
    },
    /// Successful scratch read or append.
    Scratch {
        /// Pad name.
        name: String,
        /// Current pad plaintext.
        text: String,
    },
    /// Typed failure.
    Error {
        /// Stable error class.
        code: IpcErrorCode,
        /// Human-readable detail (no secrets).
        message: String,
    },
}

impl fmt::Debug for IpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put { id, created } => f
                .debug_struct("Put")
                .field("id", id)
                .field("created", created)
                .finish(),
            Self::Ls { items } => f.debug_struct("Ls").field("items", items).finish(),
            Self::Latest { id, kind, bytes } => f
                .debug_struct("Latest")
                .field("id", id)
                .field("kind", kind)
                .field("bytes_len", &bytes.len())
                .finish(),
            Self::Get { id, kind, bytes } => f
                .debug_struct("Get")
                .field("id", id)
                .field("kind", kind)
                .field("bytes_len", &bytes.len())
                .finish(),
            Self::Pin { id } => f.debug_struct("Pin").field("id", id).finish(),
            Self::Rm { id } => f.debug_struct("Rm").field("id", id).finish(),
            Self::Scratch { name, text } => f
                .debug_struct("Scratch")
                .field("name", name)
                .field("text_len", &text.len())
                .finish(),
            Self::Error { code, message } => f
                .debug_struct("Error")
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

/// Wire error class. Matches [`crate::ClientError`] variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpcErrorCode {
    /// Object id or index did not match a stored item.
    NotFound,
    /// JSON or Base64 decode failed.
    Decode,
    /// Envelope seal/open failed, or the response did not match the request.
    Protocol,
    /// Daemon-side I/O.
    Io,
    /// Feature not implemented on this OS.
    UnsupportedOs,
}

/// Metadata row returned by `ls`. Contains no payload bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedItem {
    /// Object identifier.
    pub id: ObjectId,
    /// Content classification.
    pub kind: ContentKind,
    /// Creation hybrid timestamp.
    pub created: HybridTimestamp,
    /// Whether the item is pinned.
    pub pinned: bool,
    /// Absolute expiration, if any.
    pub expires_at: Option<Timestamp>,
}

/// Result of a successful put.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutResult {
    /// New object id.
    pub id: ObjectId,
    /// Creation hybrid timestamp.
    pub created: HybridTimestamp,
}

/// Decrypted object returned by `latest` / `get`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPayload {
    /// Object identifier.
    pub id: ObjectId,
    /// Content classification.
    pub kind: ContentKind,
    /// Plaintext payload.
    #[serde(with = "b64")]
    pub bytes: Vec<u8>,
}

impl fmt::Debug for ObjectPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObjectPayload")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

impl ObjectPayload {
    pub(crate) fn from_parts(id: ObjectId, kind: ContentKind, bytes: Vec<u8>) -> Self {
        Self { id, kind, bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::ContentKind;

    #[test]
    fn ls_and_latest_request_json_shape() {
        assert_eq!(
            serde_json::to_string(&IpcRequest::Ls).unwrap(),
            r#"{"op":"ls"}"#
        );
        assert_eq!(
            serde_json::to_string(&IpcRequest::Latest).unwrap(),
            r#"{"op":"latest"}"#
        );
    }

    #[test]
    fn get_id_and_index_json_shape() {
        let id = ObjectId::from_bytes([0xab; 32]);
        let req = IpcRequest::Get {
            target: GetTarget::Id { id },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.starts_with(r#"{"op":"get","id":""#));
        let back: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let idx = IpcRequest::Get {
            target: GetTarget::Index { index: 4 },
        };
        assert_eq!(
            serde_json::to_string(&idx).unwrap(),
            r#"{"op":"get","index":4}"#
        );
    }

    #[test]
    fn pin_and_rm_request_json_shape() {
        let pin = IpcRequest::Pin {
            target: GetTarget::Index { index: 2 },
        };
        assert_eq!(
            serde_json::to_string(&pin).unwrap(),
            r#"{"op":"pin","index":2}"#
        );
        let rm = IpcRequest::Rm {
            target: GetTarget::Index { index: 5 },
        };
        assert_eq!(
            serde_json::to_string(&rm).unwrap(),
            r#"{"op":"rm","index":5}"#
        );
    }

    #[test]
    fn put_bytes_are_base64_not_json_array() {
        let req = IpcRequest::Put {
            bytes: b"hi".to_vec(),
            kind: ContentKind::Text,
            name: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""bytes":"aGk=""#));
        assert!(!json.contains("[104,105]"));
        let back: IpcRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn listed_item_has_no_bytes_field() {
        let item = ListedItem {
            id: ObjectId::from_bytes([0x11; 32]),
            kind: ContentKind::Text,
            created: HybridTimestamp::new(0, Timestamp::from_millis(1)),
            pinned: false,
            expires_at: None,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("bytes"));
        assert!(!json.contains("plaintext"));
    }

    #[test]
    fn request_debug_redacts_payload() {
        let req = IpcRequest::Put {
            bytes: b"secret-payload".to_vec(),
            kind: ContentKind::Text,
            name: None,
        };
        let debug = format!("{req:?}");
        assert!(!debug.contains("secret-payload"));
        assert!(debug.contains("bytes_len"));
    }
}
