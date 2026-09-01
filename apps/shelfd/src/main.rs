//! `shelfd` binary: bind a Unix domain socket and serve local IPC.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use shelf_client::{default_shelf_home, resolve_socket_path};
use shelf_keystore::open_or_create_vault;
use shelfd::{DaemonError, serve_with_replica};

/// Per-user Shelf replica daemon.
#[derive(Debug, Parser)]
#[command(name = "shelfd", about = "Per-user Shelf replica daemon")]
struct Args {
    /// Unix domain socket path (overrides `--home`).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Shelf home directory (`$SHELF_HOME` or `~/.shelf` by default).
    #[arg(long)]
    home: Option<PathBuf>,
    /// Allow 0600 `wrap.key` if the platform store is unavailable (unsafe).
    #[arg(long)]
    allow_file_key: bool,
    /// Read a passphrase from this file descriptor (not argv).
    #[arg(long)]
    passphrase_fd: Option<i32>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("shelfd: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), DaemonError> {
    let args = Args::parse();
    let home = match args.home.clone() {
        Some(home) => home,
        None => default_shelf_home()?,
    };
    let socket = resolve_socket_path(args.socket, args.home)?;
    let passphrase = read_passphrase(args.passphrase_fd)?;
    let vault = open_or_create_vault(&home, None, passphrase.as_deref(), args.allow_file_key)?;
    serve_with_replica(socket, vault.store, home, vault.keys).await
}

fn read_passphrase(fd: Option<i32>) -> Result<Option<String>, DaemonError> {
    if let Some(fd) = fd {
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
                return Err(DaemonError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "empty passphrase on --passphrase-fd",
                )));
            }
            return Ok(Some(s));
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            return Err(DaemonError::UnsupportedOs);
        }
    }
    Ok(std::env::var("SHELF_PASSPHRASE")
        .ok()
        .filter(|s| !s.is_empty()))
}
