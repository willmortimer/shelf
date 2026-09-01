//! `shelf-mailbox` binary: ciphertext-only store-and-forward.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use shelf_mailbox::{Mailbox, serve};

/// Optional zero-knowledge mailbox.
#[derive(Debug, Parser)]
#[command(name = "shelf-mailbox", about = "Ciphertext-only store-and-forward")]
struct Args {
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8743")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    match serve(args.bind, Arc::new(Mailbox::new())).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("shelf-mailbox: {err}");
            ExitCode::FAILURE
        }
    }
}
