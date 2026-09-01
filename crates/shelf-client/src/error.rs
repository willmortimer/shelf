//! Typed errors for local IPC.

use std::io;

use thiserror::Error;

use crate::ipc::IpcErrorCode;

/// Failures talking to `shelfd` over local IPC.
#[derive(Debug, Error)]
pub enum ClientError {
    /// No matching object (missing id, out-of-range index, or empty shelf).
    #[error("{0}")]
    NotFound(String),
    /// Request or response JSON could not be decoded.
    #[error("decode error: {0}")]
    Decode(String),
    /// The daemon reported a protocol/envelope failure, or the response
    /// did not match the request.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Socket I/O failed (connect, read, or write).
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Local IPC is not available on this OS.
    #[error("local IPC is not supported on this operating system")]
    UnsupportedOs,
}

impl ClientError {
    pub(crate) fn from_ipc(code: IpcErrorCode, message: String) -> Self {
        match code {
            IpcErrorCode::NotFound => Self::NotFound(message),
            IpcErrorCode::Decode => Self::Decode(message),
            IpcErrorCode::Protocol => Self::Protocol(message),
            IpcErrorCode::Io => Self::Io(io::Error::other(message)),
            IpcErrorCode::UnsupportedOs => Self::UnsupportedOs,
        }
    }
}
