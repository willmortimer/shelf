//! Default `~/.shelf/` layout and Unix socket path.

use std::path::{Path, PathBuf};

/// Filename of the daemon Unix domain socket under `runtime/`.
pub const SOCKET_FILE_NAME: &str = "shelfd.sock";

/// Directory name under the Shelf home that holds the runtime socket.
pub const RUNTIME_DIR_NAME: &str = "runtime";

/// Resolve the userland Shelf home.
///
/// Order: `$SHELF_HOME`, else `$HOME/.shelf` (or `%USERPROFILE%\.shelf` on
/// Windows), else `./.shelf`.
#[must_use]
pub fn default_shelf_home() -> PathBuf {
    if let Some(dir) = std::env::var_os("SHELF_HOME") {
        return PathBuf::from(dir);
    }
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(base).join(".shelf")
}

/// Socket path inside a Shelf home: `<home>/runtime/shelfd.sock`.
///
/// On Windows this is a named pipe `\\.\pipe\shelf-<hash>` derived from `home`.
#[must_use]
pub fn socket_path_in(home: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in home.to_string_lossy().bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        PathBuf::from(format!(r"\\.\pipe\shelf-{h:016x}"))
    }
    #[cfg(not(windows))]
    {
        home.join(RUNTIME_DIR_NAME).join(SOCKET_FILE_NAME)
    }
}

/// Production default socket: `$SHELF_HOME/runtime/shelfd.sock` or
/// `~/.shelf/runtime/shelfd.sock`.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    socket_path_in(&default_shelf_home())
}

/// Choose a socket path from optional `--socket` / `--home` overrides.
///
/// `--socket` wins. Otherwise the socket is `socket_path_in(home)` with
/// [`default_shelf_home`] when `home` is `None`.
#[must_use]
pub fn resolve_socket_path(socket: Option<PathBuf>, home: Option<PathBuf>) -> PathBuf {
    if let Some(socket) = socket {
        return socket;
    }
    socket_path_in(&home.unwrap_or_else(default_shelf_home))
}

/// Shelf home from `--home` or [`default_shelf_home`].
#[must_use]
pub fn resolve_shelf_home(home: Option<PathBuf>) -> PathBuf {
    home.unwrap_or_else(default_shelf_home)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn socket_path_in_appends_runtime_sock() {
        let p = socket_path_in(Path::new("/var/shelf-home"));
        assert_eq!(
            p,
            Path::new("/var/shelf-home")
                .join(RUNTIME_DIR_NAME)
                .join(SOCKET_FILE_NAME)
        );
    }

    #[cfg(windows)]
    #[test]
    fn socket_path_in_is_named_pipe() {
        let p = socket_path_in(Path::new(r"C:\Users\x\.shelf"));
        let s = p.to_string_lossy();
        assert!(s.starts_with(r"\\.\pipe\shelf-"), "{s}");
    }

    #[test]
    fn resolve_prefers_explicit_socket() {
        let socket = PathBuf::from("/tmp/custom.sock");
        let home = PathBuf::from("/unused");
        assert_eq!(
            resolve_socket_path(Some(socket.clone()), Some(home)),
            socket
        );
    }

    #[test]
    fn resolve_uses_home_when_socket_absent() {
        let home = PathBuf::from("/opt/shelf");
        assert_eq!(
            resolve_socket_path(None, Some(home.clone())),
            socket_path_in(&home)
        );
    }
}
