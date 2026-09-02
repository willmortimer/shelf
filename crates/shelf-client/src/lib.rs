//! Local IPC client used by the CLI, GUI, and adapters.
//!
//! Speaks newline-delimited JSON to `shelfd` over a Unix domain socket
//! or a Windows named pipe. See [`ipc`] for the request/response contract.

#![deny(missing_docs)]

mod b64;
mod client;
mod error;
pub mod ipc;
mod path;

pub use client::Client;
pub use error::ClientError;
pub use ipc::{
    GetTarget, IpcErrorCode, IpcRequest, IpcResponse, ListedDevice, ListedItem, ObjectPayload,
    PutResult,
};
pub use path::{
    RUNTIME_DIR_NAME, SOCKET_FILE_NAME, default_shelf_home, default_socket_path,
    resolve_shelf_home, resolve_socket_path, socket_path_in,
};
