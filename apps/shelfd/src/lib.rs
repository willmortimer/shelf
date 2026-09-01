//! Per-user Shelf replica daemon.
//!
//! Listens on a Unix domain socket and serves newline-delimited JSON IPC
//! defined by [`shelf_client`]. Objects are sealed before they are stored.
//! Enrollment is file-based (`shelf enroll`) against the same home directory.

#![deny(missing_docs)]

mod error;
mod replica;
mod serve;
mod store;

pub use error::DaemonError;
pub use replica::spawn_replica;
pub use serve::{serve, serve_with_replica};
pub use shelf_client::{
    Client, ClientError, GetTarget, IpcErrorCode, IpcRequest, IpcResponse, ListedItem,
    ObjectPayload, PutResult, default_shelf_home, default_socket_path, resolve_socket_path,
    socket_path_in,
};
pub use store::MemoryStore;
