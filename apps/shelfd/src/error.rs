//! Daemon errors.

use std::io;

use thiserror::Error;

/// Failures binding or serving the local IPC socket.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Socket or filesystem I/O.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Unix domain sockets are not available on this OS.
    #[error("Unix domain sockets are not supported on this operating system")]
    UnsupportedOs,
}
