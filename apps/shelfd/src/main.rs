//! `shelfd` binary: bind a Unix domain socket and serve local IPC.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use shelfd::{DaemonError, MemoryStore, resolve_socket_path, serve};

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
    let socket = resolve_socket_path(args.socket, args.home);
    serve(socket, MemoryStore::new()).await
}
