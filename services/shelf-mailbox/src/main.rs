//! `shelf-mailbox` binary: ciphertext-only store-and-forward.

use std::net::SocketAddr;
use std::path::PathBuf;
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
    /// JSON persist path (opaque ciphertext only).
    #[arg(long, default_value = "shelf-mailbox.json")]
    data: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let mailbox = match Mailbox::open(&args.data) {
        Ok(mailbox) => Arc::new(mailbox),
        Err(err) => {
            eprintln!("shelf-mailbox: {err}");
            return ExitCode::FAILURE;
        }
    };
    match serve(args.bind, mailbox).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("shelf-mailbox: {err}");
            ExitCode::FAILURE
        }
    }
}
