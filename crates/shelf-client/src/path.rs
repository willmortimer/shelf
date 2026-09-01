//! Default `~/.shelf/` layout and Unix socket path.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

/// Filename of the daemon Unix domain socket under `runtime/`.
pub const SOCKET_FILE_NAME: &str = "shelfd.sock";

/// Directory name under the Shelf home that holds the runtime socket.
pub const RUNTIME_DIR_NAME: &str = "runtime";

/// Resolve the userland Shelf home.
///
/// Order: `$SHELF_HOME`, else `$HOME/.shelf` (or `%USERPROFILE%\.shelf` on
/// Windows). Never falls back to `./.shelf`.
pub fn default_shelf_home() -> io::Result<PathBuf> {
    shelf_home_from(
        std::env::var_os("SHELF_HOME"),
        std::env::var_os("HOME"),
        std::env::var_os("USERPROFILE"),
    )
}

/// Home directory from environment values. `CWD/.shelf` is never used.
pub(crate) fn shelf_home_from(
    shelf_home: Option<OsString>,
    home: Option<OsString>,
    userprofile: Option<OsString>,
) -> io::Result<PathBuf> {
    if let Some(dir) = shelf_home {
        return Ok(PathBuf::from(dir));
    }
    let base = home.or(userprofile).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "SHELF_HOME, HOME, or USERPROFILE must be set; refusing CWD .shelf",
        )
    })?;
    Ok(PathBuf::from(base).join(".shelf"))
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
pub fn default_socket_path() -> io::Result<PathBuf> {
    Ok(socket_path_in(&default_shelf_home()?))
}

/// Choose a socket path from optional `--socket` / `--home` overrides.
///
/// `--socket` wins. Otherwise the socket is `socket_path_in(home)` with
/// [`default_shelf_home`] when `home` is `None`.
pub fn resolve_socket_path(socket: Option<PathBuf>, home: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(socket) = socket {
        return Ok(socket);
    }
    let home = match home {
        Some(home) => home,
        None => default_shelf_home()?,
    };
    Ok(socket_path_in(&home))
}

/// Shelf home from `--home` or [`default_shelf_home`].
pub fn resolve_shelf_home(home: Option<PathBuf>) -> io::Result<PathBuf> {
    match home {
        Some(home) => Ok(home),
        None => default_shelf_home(),
    }
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
            resolve_socket_path(Some(socket.clone()), Some(home)).unwrap(),
            socket
        );
    }

    #[test]
    fn resolve_uses_home_when_socket_absent() {
        let home = PathBuf::from("/opt/shelf");
        assert_eq!(
            resolve_socket_path(None, Some(home.clone())).unwrap(),
            socket_path_in(&home)
        );
    }

    #[test]
    fn refuses_cwd_when_no_home_env() {
        let err = shelf_home_from(None, None, None).unwrap_err();
        assert!(err.to_string().contains("refusing CWD"), "{}", err);
    }

    #[test]
    fn shelf_home_env_wins() {
        let p = shelf_home_from(Some("/custom".into()), Some("/unused".into()), None).unwrap();
        assert_eq!(p, PathBuf::from("/custom"));
    }
}
