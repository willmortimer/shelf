//! `shelf` CLI: stdin/stdout client for a local `shelfd`.
//!
//! The binary is named `shelf`. This library exists so the clap surface and
//! helpers can be unit-tested without spawning a process.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use shelf_client::{Client, ClientError, GetTarget, ListedItem, resolve_socket_path};
use shelf_core::{ContentKind, ObjectId};
use thiserror::Error;

/// Failures from CLI I/O, usage, or talking to `shelfd`.
#[derive(Debug, Error)]
pub enum CliError {
    /// Daemon reported a typed IPC failure, or the socket could not be used.
    #[error("{0}")]
    Client(#[from] ClientError),
    /// stdin/stdout failed.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// User-supplied argument could not be parsed.
    #[error("{0}")]
    Usage(String),
    /// `--json` serialization failed.
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

impl CliError {
    /// Process exit status. [`ClientError::NotFound`] and every other CLI
    /// failure map to `1`; clap usage errors exit `2` before `run`.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        ExitCode::from(1)
    }
}

/// `shelf` command line.
#[derive(Debug, Parser)]
#[command(
    name = "shelf",
    about = "stdin/stdout client for a local shelfd",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Unix domain socket path (overrides `--home`).
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,
    /// Shelf home directory (`$SHELF_HOME` or `~/.shelf` by default).
    #[arg(long, global = true)]
    pub home: Option<PathBuf>,
    /// Subcommand.
    #[command(subcommand)]
    pub command: Command,
}

/// `shelf` subcommands matching the design CLI vocabulary.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Seal stdin and store it. Kind defaults to `text` if UTF-8, else `opaque-bytes`.
    Put {
        /// Optional display name.
        #[arg(long)]
        name: Option<String>,
        /// Content kind override (`text`, `markdown`, `url`, `image`, `file`, `json`, `opaque-bytes`).
        #[arg(long, value_name = "KIND", value_parser = parse_kind)]
        kind: Option<ContentKind>,
    },
    /// Write the newest object's plaintext to stdout (no extra newline).
    Latest,
    /// List metadata, newest first. No plaintext.
    Ls {
        /// Emit a JSON array instead of the default `id kind created` lines.
        #[arg(long)]
        json: bool,
    },
    /// Write one object's plaintext to stdout (no extra newline).
    Get {
        /// 1-based newest-first index, or 64-character hex id.
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Pin an object (durable retention).
    Pin {
        /// 1-based newest-first index, or 64-character hex id.
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Remove an object.
    Rm {
        /// 1-based newest-first index, or 64-character hex id.
        #[arg(value_name = "TARGET")]
        target: String,
    },
}

/// Execute a parsed `shelf` invocation.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    let socket = resolve_socket_path(cli.socket, cli.home);
    match cli.command {
        Command::Put { name, kind } => cmd_put(&socket, name, kind).await,
        Command::Latest => cmd_latest(&socket).await,
        Command::Ls { json } => cmd_ls(&socket, json).await,
        Command::Get { target } => cmd_get(&socket, &target).await,
        Command::Pin { target } => cmd_pin(&socket, &target).await,
        Command::Rm { target } => cmd_rm(&socket, &target).await,
    }
}

async fn cmd_put(
    socket: &Path,
    name: Option<String>,
    kind: Option<ContentKind>,
) -> Result<(), CliError> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    let kind = kind.unwrap_or_else(|| infer_kind(&bytes));
    let client = Client::connect(socket).await?;
    let result = client.put(&bytes, kind, name.as_deref()).await?;
    writeln!(io::stdout(), "{}", result.id)?;
    Ok(())
}

async fn cmd_latest(socket: &Path) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let obj = client.latest().await?;
    write_stdout(&obj.bytes)
}

async fn cmd_ls(socket: &Path, json: bool) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let items = client.ls().await?;
    if json {
        writeln!(io::stdout(), "{}", serde_json::to_string(&items)?)?;
    } else {
        let mut out = io::stdout().lock();
        for item in &items {
            writeln!(out, "{}", format_ls_line(item))?;
        }
        out.flush()?;
    }
    Ok(())
}

async fn cmd_get(socket: &Path, target: &str) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let obj = client.get(parse_target(target)?).await?;
    write_stdout(&obj.bytes)
}

async fn cmd_pin(socket: &Path, target: &str) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let _id = client.pin(parse_target(target)?).await?;
    Ok(())
}

async fn cmd_rm(socket: &Path, target: &str) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let _id = client.rm(parse_target(target)?).await?;
    Ok(())
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut out = io::stdout().lock();
    out.write_all(bytes)?;
    out.flush()?;
    Ok(())
}

fn infer_kind(bytes: &[u8]) -> ContentKind {
    if std::str::from_utf8(bytes).is_ok() {
        ContentKind::Text
    } else {
        ContentKind::OpaqueBytes
    }
}

fn parse_kind(s: &str) -> Result<ContentKind, String> {
    match s {
        "text" => Ok(ContentKind::Text),
        "markdown" => Ok(ContentKind::Markdown),
        "url" => Ok(ContentKind::Url),
        "image" => Ok(ContentKind::Image),
        "file" => Ok(ContentKind::File),
        "json" => Ok(ContentKind::Json),
        "opaque-bytes" => Ok(ContentKind::OpaqueBytes),
        other => Err(format!(
            "unknown kind '{other}' (expected text, markdown, url, image, file, json, opaque-bytes)"
        )),
    }
}

fn parse_target(s: &str) -> Result<GetTarget, CliError> {
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(GetTarget::Id {
            id: parse_object_id(s)?,
        });
    }
    if let Ok(index) = s.parse::<u64>() {
        return Ok(GetTarget::Index { index });
    }
    Err(CliError::Usage(
        "expected a 1-based index or a 64-character hex id".into(),
    ))
}

fn parse_object_id(s: &str) -> Result<ObjectId, CliError> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return Err(CliError::Usage(
            "object id must be 64 hex characters".into(),
        ));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let hex = std::str::from_utf8(&raw[i * 2..i * 2 + 2])
            .map_err(|_| CliError::Usage("object id must be 64 hex characters".into()))?;
        bytes[i] = u8::from_str_radix(hex, 16)
            .map_err(|_| CliError::Usage("object id must be 64 hex characters".into()))?;
    }
    Ok(ObjectId::from_bytes(bytes))
}

/// One scriptable line: `id kind created` (hex id, kebab-case kind, wall millis).
/// Pinned items append ` pinned`.
fn format_ls_line(item: &ListedItem) -> String {
    let pin = if item.pinned { " pinned" } else { "" };
    format!(
        "{} {} {}{pin}",
        item.id,
        item.kind.as_wire_str(),
        item.created.wall().as_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use shelf_core::{HybridTimestamp, Timestamp};

    #[test]
    fn infer_kind_utf8_is_text_else_opaque() {
        assert_eq!(infer_kind(b"hello"), ContentKind::Text);
        assert_eq!(infer_kind(&[0xff, 0xfe]), ContentKind::OpaqueBytes);
        assert_eq!(infer_kind(b""), ContentKind::Text);
    }

    #[test]
    fn parse_kind_accepts_every_variant() {
        fn check(kind: ContentKind) {
            match kind {
                ContentKind::Text
                | ContentKind::Markdown
                | ContentKind::Url
                | ContentKind::Image
                | ContentKind::File
                | ContentKind::Json
                | ContentKind::OpaqueBytes => {
                    assert_eq!(parse_kind(kind.as_wire_str()).unwrap(), kind);
                }
            }
        }
        check(ContentKind::Text);
        check(ContentKind::Markdown);
        check(ContentKind::Url);
        check(ContentKind::Image);
        check(ContentKind::File);
        check(ContentKind::Json);
        check(ContentKind::OpaqueBytes);
    }

    #[test]
    fn parse_target_index_or_hex_id() {
        match parse_target("4").unwrap() {
            GetTarget::Index { index } => assert_eq!(index, 4),
            GetTarget::Id { .. } => panic!("expected index"),
        }
        let hex = "ab".repeat(32);
        match parse_target(&hex).unwrap() {
            GetTarget::Id { id } => assert_eq!(id, ObjectId::from_bytes([0xab; 32])),
            GetTarget::Index { .. } => panic!("expected id"),
        }
        assert!(parse_target("not-an-id").is_err());
    }

    #[test]
    fn ls_line_has_id_kind_created_and_optional_pinned() {
        let item = ListedItem {
            id: ObjectId::from_bytes([0x11; 32]),
            kind: ContentKind::Text,
            created: HybridTimestamp::new(0, Timestamp::from_millis(42)),
            pinned: false,
            expires_at: None,
        };
        let line = format_ls_line(&item);
        assert_eq!(line, format!("{} text 42", item.id));
        assert!(!line.contains("pinned"));
        assert!(!line.contains("hello"));

        let mut pinned = item.clone();
        pinned.pinned = true;
        let pinned_line = format_ls_line(&pinned);
        assert!(pinned_line.ends_with(" pinned"));
        assert!(pinned_line.contains(&item.id.to_string()));
    }
}
