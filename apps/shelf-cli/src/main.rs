//! `shelf` binary: stdin/stdout client for a local `shelfd`.

use std::process::ExitCode;

use clap::Parser;
use shelf_cli::{Cli, run};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("shelf: {err}");
            err.exit_code()
        }
    }
}
