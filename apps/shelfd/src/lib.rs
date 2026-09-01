//! Per-user Shelf replica daemon.
//!
//! Listens on a Unix domain socket and serves newline-delimited JSON IPC
//! defined by [`shelf_client`]. Objects are sealed with
//! [`shelf_protocol::seal`] before they are stored. The GUI, CLI, and
//! enrollment flows are out of scope for this crate.

#![deny(missing_docs)]

mod error;
mod serve;
mod store;

pub use error::DaemonError;
pub use serve::serve;
pub use shelf_client::{
    Client, ClientError, GetTarget, IpcErrorCode, IpcRequest, IpcResponse, ListedItem,
    ObjectPayload, PutResult, default_shelf_home, default_socket_path, resolve_socket_path,
    socket_path_in,
};
pub use store::MemoryStore;
