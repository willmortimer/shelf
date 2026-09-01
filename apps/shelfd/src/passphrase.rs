//! Unlock sources for a passphrase-protected wrap key.
//!
//! Order: systemd `CREDENTIALS_DIRECTORY` / `shelf.passphrase`, `--passphrase-fd`,
//! `SHELF_PASSPHRASE`, then a hidden TTY prompt. The passphrase is never taken
//! from argv and is never logged.

use std::io;
#[cfg(unix)]
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use crate::DaemonError;

/// systemd credential filename under `CREDENTIALS_DIRECTORY`.
const SYSTEMD_CREDENTIAL_NAME: &str = "shelf.passphrase";

/// Resolve a wrap-key passphrase from the documented unlock sources.
///
/// Returns `Ok(None)` when no source applies so vault open can fall through to
/// platform custody / `NoCustody`.
pub fn read_passphrase(fd: Option<i32>) -> Result<Option<String>, DaemonError> {
    if let Some(pass) = read_systemd_credential()? {
        return Ok(Some(pass));
    }
    if let Some(pass) = read_passphrase_fd(fd)? {
        return Ok(Some(pass));
    }
    if let Some(pass) = std::env::var("SHELF_PASSPHRASE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(pass));
    }
    #[cfg(unix)]
    if io::stdin().is_terminal() {
        return read_hidden_tty_prompt();
    }
    Ok(None)
}

fn read_systemd_credential() -> Result<Option<String>, DaemonError> {
    let Some(dir) = std::env::var_os("CREDENTIALS_DIRECTORY").filter(|d| !d.is_empty()) else {
        return Ok(None);
    };
    read_credential_file(Path::new(&dir))
}

fn read_credential_file(dir: &Path) -> Result<Option<String>, DaemonError> {
    let path = dir.join(SYSTEMD_CREDENTIAL_NAME);
    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let trimmed = raw.trim_end_matches(['\n', '\r']).to_owned();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn read_passphrase_fd(fd: Option<i32>) -> Result<Option<String>, DaemonError> {
    let Some(fd) = fd else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::io::{FromRawFd, RawFd};
        // SAFETY: `--passphrase-fd` is an open descriptor the caller transfers to us.
        let mut file = unsafe { std::fs::File::from_raw_fd(fd as RawFd) };
        let mut s = String::new();
        file.read_to_string(&mut s)?;
        let s = s.trim_end_matches(['\n', '\r']).to_owned();
        if s.is_empty() {
            return Err(DaemonError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty passphrase on --passphrase-fd",
            )));
        }
        Ok(Some(s))
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        Err(DaemonError::UnsupportedOs)
    }
}

#[cfg(unix)]
fn read_hidden_tty_prompt() -> Result<Option<String>, DaemonError> {
    eprint!("Passphrase: ");
    io::stderr().flush()?;
    let line = {
        let _echo = DisableEcho::new()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    eprintln!();
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

/// Disables stdin echo and restores it on drop (including panic unwind).
#[cfg(unix)]
struct DisableEcho {
    fd: libc::c_int,
    saved: libc::termios,
}

#[cfg(unix)]
impl DisableEcho {
    fn new() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;
        let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `fd` is stdin; `tcgetattr` writes a full `termios` on success.
        if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `tcgetattr` succeeded, so `saved` is initialized.
        let saved = unsafe { saved.assume_init() };
        let mut silent = saved;
        silent.c_lflag &= !libc::ECHO;
        // SAFETY: `silent` is a copy of the attributes we just read from this fd.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &silent) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, saved })
    }
}

#[cfg(unix)]
impl Drop for DisableEcho {
    fn drop(&mut self) {
        // SAFETY: `saved` came from `tcgetattr` on this fd in `new`.
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::io::IsTerminal;
    use std::sync::{Mutex, MutexGuard};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvRestore {
        _guard: MutexGuard<'static, ()>,
        old_cred: Option<OsString>,
        old_pass: Option<OsString>,
    }

    impl EnvRestore {
        fn acquire() -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            Self {
                _guard: guard,
                old_cred: std::env::var_os("CREDENTIALS_DIRECTORY"),
                old_pass: std::env::var_os("SHELF_PASSPHRASE"),
            }
        }

        fn clear_passphrase_sources(&self) {
            // SAFETY: `ENV_LOCK` serializes env mutation in these tests; Drop restores.
            unsafe {
                std::env::remove_var("CREDENTIALS_DIRECTORY");
                std::env::remove_var("SHELF_PASSPHRASE");
            }
        }

        fn set_credentials_dir(&self, dir: &Path) {
            // SAFETY: `ENV_LOCK` serializes env mutation in these tests; Drop restores.
            unsafe {
                std::env::set_var("CREDENTIALS_DIRECTORY", dir);
                std::env::remove_var("SHELF_PASSPHRASE");
            }
        }

        fn set_env_passphrase(&self, value: &str) {
            // SAFETY: `ENV_LOCK` serializes env mutation in these tests; Drop restores.
            unsafe {
                std::env::set_var("SHELF_PASSPHRASE", value);
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            // SAFETY: same lock as `acquire`; restoring the process-wide values we saved.
            unsafe {
                match &self.old_cred {
                    Some(v) => std::env::set_var("CREDENTIALS_DIRECTORY", v),
                    None => std::env::remove_var("CREDENTIALS_DIRECTORY"),
                }
                match &self.old_pass {
                    Some(v) => std::env::set_var("SHELF_PASSPHRASE", v),
                    None => std::env::remove_var("SHELF_PASSPHRASE"),
                }
            }
        }
    }

    fn generated_secret() -> String {
        format!(
            "t7pass-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )
    }

    #[test]
    fn systemd_credentials_file_is_read_and_trimmed() {
        let env = EnvRestore::acquire();
        let dir = tempfile::tempdir().unwrap();
        let secret = generated_secret();
        std::fs::write(
            dir.path().join(SYSTEMD_CREDENTIAL_NAME),
            format!("{secret}\n"),
        )
        .unwrap();
        env.set_credentials_dir(dir.path());

        let got = read_passphrase(None).unwrap();
        assert_eq!(got.as_deref(), Some(secret.as_str()));
    }

    #[test]
    fn empty_systemd_credential_falls_through() {
        let env = EnvRestore::acquire();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SYSTEMD_CREDENTIAL_NAME), "\n").unwrap();
        env.set_credentials_dir(dir.path());

        if io::stdin().is_terminal() {
            // Do not block on a hidden prompt when running tests from a TTY.
            assert!(read_credential_file(dir.path()).unwrap().is_none());
            return;
        }
        assert_eq!(read_passphrase(None).unwrap(), None);
    }

    #[test]
    fn missing_systemd_credential_falls_through() {
        let env = EnvRestore::acquire();
        let dir = tempfile::tempdir().unwrap();
        env.set_credentials_dir(dir.path());

        if io::stdin().is_terminal() {
            assert!(read_credential_file(dir.path()).unwrap().is_none());
            return;
        }
        assert_eq!(read_passphrase(None).unwrap(), None);
    }

    #[test]
    fn no_sources_without_tty_yields_none() {
        let env = EnvRestore::acquire();
        env.clear_passphrase_sources();
        if io::stdin().is_terminal() {
            // Interactive TTY is skipped in CI; do not prompt from unit tests.
            return;
        }
        assert_eq!(read_passphrase(None).unwrap(), None);
    }

    #[test]
    fn env_passphrase_used_when_credentials_absent() {
        let env = EnvRestore::acquire();
        env.clear_passphrase_sources();
        let secret = generated_secret();
        env.set_env_passphrase(&secret);
        assert_eq!(
            read_passphrase(None).unwrap().as_deref(),
            Some(secret.as_str())
        );
    }

    #[test]
    fn systemd_credential_wins_over_env() {
        let env = EnvRestore::acquire();
        let dir = tempfile::tempdir().unwrap();
        let cred = generated_secret();
        let from_env = generated_secret();
        std::fs::write(
            dir.path().join(SYSTEMD_CREDENTIAL_NAME),
            format!("{cred}\r\n"),
        )
        .unwrap();
        env.set_credentials_dir(dir.path());
        env.set_env_passphrase(&from_env);
        assert_eq!(
            read_passphrase(None).unwrap().as_deref(),
            Some(cred.as_str())
        );
    }
}
