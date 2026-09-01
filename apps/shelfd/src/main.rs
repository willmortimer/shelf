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
    let vault = open_or_create_vault(&home, None, None, args.allow_file_key)?;
    let signer = vault.keys.device_signer();
    serve_with_replica(socket, vault.store, home, signer).await
}
