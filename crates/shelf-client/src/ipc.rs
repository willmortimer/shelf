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
use shelf_core::{ContentKind, DeviceId, EpochId, HybridTimestamp, Label, ObjectId, Timestamp};

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
    Ls {
        /// When true, include archived objects. Default `ls` hides them.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        include_archived: bool,
    },
    /// Local decrypted-in-memory substring search (non-archived live objects).
    Search {
        /// Case-insensitive needle. Never log this field.
        query: String,
    },
    /// Archive an object by id or 1-based index (newest first).
    Archive {
        /// Id or 1-based listing index.
        #[serde(flatten)]
        target: GetTarget,
    },
    /// Attach a label to an object by id or 1-based index (newest first).
    Label {
        /// Id or 1-based listing index.
        #[serde(flatten)]
        target: GetTarget,
        /// Label text.
        name: String,
    },
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
    /// Export a `.shelfjoin` from the daemon's open vault.
    EnrollExport,
    /// Approve a `.shelfjoin` using the daemon's open vault.
    EnrollApprove {
        /// Parsed `.shelfjoin` JSON (public enrollment request).
        join: serde_json::Value,
    },
    /// Import a `.shelfgrant` into the daemon's open vault.
    EnrollImport {
        /// Parsed `.shelfgrant` JSON.
        grant: serde_json::Value,
        /// Caller-confirmed two-way SAS.
        expect_sas: String,
    },
    /// Export a passphrase-wrapped `.shelfrecovery` from the daemon vault.
    RecoveryExport {
        /// Recovery-bundle passphrase. Never log this field.
        passphrase: String,
    },
    /// Apply a recovery bundle. The CLI never sends this: apply is local
    /// against an empty `--home`. The daemon rejects it.
    RecoveryApply {
        /// Parsed `.shelfrecovery` JSON.
        bundle: serde_json::Value,
        /// Recovery-bundle passphrase. Never log this field.
        passphrase: String,
    },
    /// List current vault members. Does not mutate the store.
    DevicesList,
    /// Revoke a member by hex device id. Vault root only; rotates the epoch.
    DevicesRevoke {
        /// Hex [`DeviceId`].
        device_id: String,
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
            Self::EnrollExport => write!(f, "EnrollExport"),
            Self::EnrollApprove { .. } => write!(f, "EnrollApprove"),
            Self::EnrollImport { .. } => write!(f, "EnrollImport"),
            Self::RecoveryExport { .. } => write!(f, "RecoveryExport"),
            Self::RecoveryApply { .. } => write!(f, "RecoveryApply"),
            Self::DevicesList => write!(f, "DevicesList"),
            Self::DevicesRevoke { device_id } => f
                .debug_struct("DevicesRevoke")
                .field("device_id", device_id)
                .finish(),
            Self::Ls { include_archived } => f
                .debug_struct("Ls")
                .field("include_archived", include_archived)
                .finish(),
            Self::Search { query } => f
                .debug_struct("Search")
                .field("query_len", &query.len())
                .finish(),
            Self::Archive { target } => f.debug_tuple("Archive").field(target).finish(),
            Self::Label { target, name } => f
                .debug_struct("Label")
                .field("target", target)
                .field("name", name)
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
    /// Successful search (metadata only; same shape as `ls` rows).
    Search {
        /// Hits, newest first.
        items: Vec<ListedItem>,
    },
    /// Successful archive.
    Archive {
        /// Object id that is now archived.
        id: ObjectId,
    },
    /// Successful label attach.
    Label {
        /// Object id that received the label.
        id: ObjectId,
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
    /// Successful enroll export.
    EnrollExport {
        /// `.shelfjoin` JSON to write on the client.
        join: serde_json::Value,
        /// Human-verifiable SAS (print on stderr).
        sas: String,
    },
    /// Successful enroll approve.
    EnrollApprove {
        /// `.shelfgrant` JSON to write on the client.
        grant: serde_json::Value,
        /// Two-way SAS (print on stderr).
        sas: String,
    },
    /// Successful enroll import.
    EnrollImport,
    /// Successful recovery export.
    RecoveryExport {
        /// `.shelfrecovery` JSON to write on the client.
        bundle: serde_json::Value,
    },
    /// Successful recovery apply (unused: apply is CLI-direct).
    RecoveryApply,
    /// Successful member list.
    DevicesList {
        /// Current members.
        devices: Vec<ListedDevice>,
    },
    /// Successful revoke (new vault epoch).
    DevicesRevoke {
        /// Epoch after rotation.
        new_epoch: EpochId,
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
            Self::Search { items } => f.debug_struct("Search").field("items", items).finish(),
            Self::Archive { id } => f.debug_struct("Archive").field("id", id).finish(),
            Self::Label { id } => f.debug_struct("Label").field("id", id).finish(),
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
            Self::EnrollExport { sas, .. } => {
                f.debug_struct("EnrollExport").field("sas", sas).finish()
            }
            Self::EnrollApprove { sas, .. } => {
                f.debug_struct("EnrollApprove").field("sas", sas).finish()
            }
            Self::EnrollImport => write!(f, "EnrollImport"),
            Self::RecoveryExport { .. } => write!(f, "RecoveryExport"),
            Self::RecoveryApply => write!(f, "RecoveryApply"),
            Self::DevicesList { devices } => f
                .debug_struct("DevicesList")
                .field("devices", devices)
                .finish(),
            Self::DevicesRevoke { new_epoch } => f
                .debug_struct("DevicesRevoke")
                .field("new_epoch", new_epoch)
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

/// One vault member returned by `devices` list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedDevice {
    /// Hex device identifier.
    pub device_id: DeviceId,
    /// Display name when present (local init name; certificates do not carry one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether this device is the vault root.
    pub is_root: bool,
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
    /// Hidden from default `ls` when true.
    #[serde(default)]
    pub archived: bool,
    /// User labels (not payload).
    #[serde(default)]
    pub labels: Vec<Label>,
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
            serde_json::to_string(&IpcRequest::Ls {
                include_archived: false,
            })
            .unwrap(),
            r#"{"op":"ls"}"#
        );
        assert_eq!(
            serde_json::to_string(&IpcRequest::Latest).unwrap(),
            r#"{"op":"latest"}"#
        );
        assert_eq!(
            serde_json::to_string(&IpcRequest::EnrollExport).unwrap(),
            r#"{"op":"enroll_export"}"#
        );
        assert_eq!(
            serde_json::to_string(&IpcRequest::RecoveryExport {
                passphrase: "secret".into(),
            })
            .unwrap(),
            r#"{"op":"recovery_export","passphrase":"secret"}"#
        );
        assert_eq!(
            serde_json::to_string(&IpcRequest::DevicesList).unwrap(),
            r#"{"op":"devices_list"}"#
        );
        let revoke = IpcRequest::DevicesRevoke {
            device_id: "ab".repeat(32),
        };
        assert_eq!(
            serde_json::to_string(&revoke).unwrap(),
            format!(
                r#"{{"op":"devices_revoke","device_id":"{}"}}"#,
                "ab".repeat(32)
            )
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
            archived: false,
            labels: Vec::new(),
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("bytes"));
        assert!(!json.contains("plaintext"));
        assert!(json.contains("archived"));
        assert!(json.contains("labels"));
    }

    #[test]
    fn listed_device_omits_absent_name() {
        let row = ListedDevice {
            device_id: DeviceId::from_bytes([0x11; 32]),
            name: None,
            is_root: true,
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(!json.contains("name"));
        assert!(json.contains("is_root"));
        let named = ListedDevice {
            device_id: DeviceId::from_bytes([0x22; 32]),
            name: Some("mac".into()),
            is_root: false,
        };
        assert!(serde_json::to_string(&named).unwrap().contains("mac"));
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

        let rec = IpcRequest::RecoveryExport {
            passphrase: "bundle-passphrase".into(),
        };
        let rec_debug = format!("{rec:?}");
        assert!(!rec_debug.contains("bundle-passphrase"));
        assert_eq!(rec_debug, "RecoveryExport");
        let apply = IpcRequest::RecoveryApply {
            bundle: serde_json::json!({}),
            passphrase: "bundle-passphrase".into(),
        };
        assert!(!format!("{apply:?}").contains("bundle-passphrase"));

        let list = IpcRequest::DevicesList;
        assert_eq!(format!("{list:?}"), "DevicesList");
        let revoke = IpcRequest::DevicesRevoke {
            device_id: "ab".repeat(32),
        };
        let revoke_debug = format!("{revoke:?}");
        assert!(revoke_debug.contains("DevicesRevoke"));
        assert!(revoke_debug.contains("device_id"));

        let search = IpcRequest::Search {
            query: "secret-query-text".into(),
        };
        let search_debug = format!("{search:?}");
        assert!(!search_debug.contains("secret-query-text"));
        assert!(search_debug.contains("query_len"));
        let archive = IpcRequest::Archive {
            target: GetTarget::Index { index: 1 },
        };
        assert!(format!("{archive:?}").contains("Archive"));
        let label = IpcRequest::Label {
            target: GetTarget::Index { index: 2 },
            name: "ops".into(),
        };
        assert!(format!("{label:?}").contains("Label"));
    }

    #[test]
    fn search_archive_label_request_json_shape() {
        let search = IpcRequest::Search {
            query: "kubernetes".into(),
        };
        assert_eq!(
            serde_json::to_string(&search).unwrap(),
            r#"{"op":"search","query":"kubernetes"}"#
        );
        let archive = IpcRequest::Archive {
            target: GetTarget::Index { index: 3 },
        };
        assert_eq!(
            serde_json::to_string(&archive).unwrap(),
            r#"{"op":"archive","index":3}"#
        );
        let label = IpcRequest::Label {
            target: GetTarget::Index { index: 1 },
            name: "ops".into(),
        };
        assert_eq!(
            serde_json::to_string(&label).unwrap(),
            r#"{"op":"label","index":1,"name":"ops"}"#
        );
        let ls_archived = IpcRequest::Ls {
            include_archived: true,
        };
        assert_eq!(
            serde_json::to_string(&ls_archived).unwrap(),
            r#"{"op":"ls","include_archived":true}"#
        );
    }
}
