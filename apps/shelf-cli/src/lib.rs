//! `shelf` CLI: stdin/stdout client for a local `shelfd`.
//!
//! The binary is named `shelf`. This library exists so the clap surface and
//! helpers can be unit-tested without spawning a process.

use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use clap::{Parser, Subcommand};
use shelf_client::{
    Client, ClientError, GetTarget, ListedItem, resolve_shelf_home, resolve_socket_path,
};
use shelf_core::{ContentKind, ObjectId};
use shelf_keystore::{
    KeystoreError, ShelfGrant, ShelfJoin, approve_join, export_join, grant_sas, import_grant,
    open_or_create_vault,
};
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
    /// Identity or enrollment failed.
    #[error("{0}")]
    Keystore(#[from] KeystoreError),
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
    /// Create identity and vault under `--home` (or `~/.shelf`).
    Init {
        /// Human-readable device name.
        #[arg(long)]
        name: Option<String>,
        /// Optional wrap passphrase (Argon2id).
        #[arg(long)]
        passphrase: Option<String>,
        /// Allow 0600 `wrap.key` if the platform store is unavailable (unsafe).
        #[arg(long)]
        allow_file_key: bool,
    },
    /// Offline enrollment via `.shelfjoin` / `.shelfgrant` files.
    Enroll {
        /// Enrollment action.
        #[command(subcommand)]
        action: EnrollAction,
    },
    /// Seal stdin (or `--file`) and store it. Kind defaults to `text` if UTF-8, else `opaque-bytes`.
    Put {
        /// Optional display name.
        #[arg(long)]
        name: Option<String>,
        /// Content kind override (`text`, `markdown`, `url`, `image`, `file`, `json`, `opaque-bytes`).
        #[arg(long, value_name = "KIND", value_parser = parse_kind)]
        kind: Option<ContentKind>,
        /// Read bytes from this path instead of stdin. Large files are chunked at 4 MiB.
        #[arg(long)]
        file: Option<PathBuf>,
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
    /// Print or append a named Yrs scratch pad.
    Scratch {
        /// Pad name.
        #[arg(long, default_value = "Scratch")]
        name: String,
        /// Append this text (otherwise print the pad).
        #[arg(long)]
        append: Option<String>,
    },
    /// Put the current system clipboard (explicit capture, not surveillance).
    Capture,
}

/// Offline enrollment subcommands.
#[derive(Debug, Subcommand)]
pub enum EnrollAction {
    /// Write a `.shelfjoin` and print a SAS phrase on stderr.
    Export {
        /// Output path.
        #[arg(long, default_value = "device.shelfjoin")]
        out: PathBuf,
    },
    /// Approve a join file and write a `.shelfgrant`.
    Approve {
        /// Join request file.
        #[arg(long)]
        join: PathBuf,
        /// Output path.
        #[arg(long, default_value = "device.shelfgrant")]
        out: PathBuf,
    },
    /// Import a grant into this device's vault.
    Import {
        /// Grant file.
        #[arg(long)]
        grant: PathBuf,
        /// Expected two-way SAS (required when stdin is not a TTY).
        #[arg(long)]
        expect_sas: Option<String>,
    },
}

/// Execute a parsed `shelf` invocation.
pub async fn run(cli: Cli) -> Result<(), CliError> {
    let home = resolve_shelf_home(cli.home.clone())?;
    let socket = resolve_socket_path(cli.socket, cli.home)?;
    match cli.command {
        Command::Init {
            name,
            passphrase,
            allow_file_key,
        } => cmd_init(&home, name, passphrase, allow_file_key),
        Command::Enroll { action } => cmd_enroll(&home, &socket, action),
        Command::Put { name, kind, file } => cmd_put(&socket, name, kind, file).await,
        Command::Latest => cmd_latest(&socket).await,
        Command::Ls { json } => cmd_ls(&socket, json).await,
        Command::Get { target } => cmd_get(&socket, &target).await,
        Command::Pin { target } => cmd_pin(&socket, &target).await,
        Command::Rm { target } => cmd_rm(&socket, &target).await,
        Command::Scratch { name, append } => cmd_scratch(&socket, &name, append).await,
        Command::Capture => cmd_capture(&socket).await,
    }
}

fn cmd_init(
    home: &Path,
    name: Option<String>,
    passphrase: Option<String>,
    allow_file_key: bool,
) -> Result<(), CliError> {
    let vault = open_or_create_vault(home, name.as_deref(), passphrase.as_deref(), allow_file_key)?;
    writeln!(io::stdout(), "{}", vault.keys.public_identity().device_id)?;
    Ok(())
}

fn cmd_enroll(home: &Path, socket: &Path, action: EnrollAction) -> Result<(), CliError> {
    refuse_if_daemon_running(socket)?;
    match action {
        EnrollAction::Export { out } => {
            let vault = open_or_create_vault(home, None, None, false)?;
            let (join, sas) = export_join(&vault, Vec::new())?;
            fs::write(&out, serde_json::to_vec_pretty(&join)?)?;
            writeln!(io::stderr(), "SAS: {sas}")?;
            writeln!(io::stderr(), "wrote {}", out.display())?;
            Ok(())
        }
        EnrollAction::Approve { join, out } => {
            let vault = open_or_create_vault(home, None, None, false)?;
            let body = fs::read(&join)?;
            let join: ShelfJoin = serde_json::from_slice(&body)?;
            let (grant, sas) = approve_join(&vault, &join)?;
            fs::write(&out, serde_json::to_vec_pretty(&grant)?)?;
            writeln!(io::stderr(), "SAS: {sas}")?;
            writeln!(io::stderr(), "wrote {}", out.display())?;
            Ok(())
        }
        EnrollAction::Import { grant, expect_sas } => {
            let mut vault = open_or_create_vault(home, None, None, false)?;
            let body = fs::read(&grant)?;
            let grant: ShelfGrant = serde_json::from_slice(&body)?;
            let sas = grant_sas(&grant.grant)?;
            writeln!(
                io::stderr(),
                "Vault: {}\nApprover: {}\nSAS: {sas}",
                grant.grant.vault_root.fingerprint(),
                grant.grant.certificate.issuer
            )?;
            let confirmed = if let Some(expect) = expect_sas {
                expect
            } else if io::stdin().is_terminal() {
                eprint!("Confirm SAS matches trusted device? [y/N] ");
                io::stderr().flush()?;
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                if !line.trim().eq_ignore_ascii_case("y") {
                    return Err(CliError::Usage("enrollment import cancelled".into()));
                }
                sas.clone()
            } else {
                return Err(CliError::Usage(
                    "pass --expect-sas when stdin is not a TTY".into(),
                ));
            };
            import_grant(&mut vault, &grant, &confirmed)?;
            writeln!(io::stderr(), "imported grant")?;
            Ok(())
        }
    }
}

fn refuse_if_daemon_running(socket: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return Err(CliError::Usage(
                "shelfd is running; stop it before `shelf enroll` (file enrollment cannot share state.db with the daemon yet)".into(),
            ));
        }
    }
    #[cfg(windows)]
    {
        if std::fs::File::open(socket).is_ok() {
            return Err(CliError::Usage(
                "shelfd is running; stop it before `shelf enroll` (file enrollment cannot share state.db with the daemon yet)".into(),
            ));
        }
    }
    Ok(())
}

async fn cmd_put(
    socket: &Path,
    name: Option<String>,
    kind: Option<ContentKind>,
    file: Option<PathBuf>,
) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let result = if let Some(path) = file {
        let filename = name
            .or_else(|| path.file_name().and_then(|s| s.to_str()).map(str::to_owned))
            .unwrap_or_else(|| "file".into());
        client
            .put_file(&path, &filename, Some("application/octet-stream"))
            .await?
    } else {
        let mut bytes = Vec::new();
        io::stdin().read_to_end(&mut bytes)?;
        let kind = kind.unwrap_or_else(|| infer_kind(&bytes));
        client.put(&bytes, kind, name.as_deref()).await?
    };
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

async fn cmd_scratch(socket: &Path, name: &str, append: Option<String>) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let text = if let Some(append) = append {
        client.scratch_append(name, &append).await?
    } else {
        client.scratch_get(name).await?
    };
    write_stdout(text.as_bytes())
}

async fn cmd_capture(socket: &Path) -> Result<(), CliError> {
    let bytes = read_clipboard()?;
    if bytes.is_empty() {
        return Err(CliError::Usage("clipboard is empty".into()));
    }
    let kind = infer_kind(&bytes);
    let client = Client::connect(socket).await?;
    let result = client.put(&bytes, kind, Some("clipboard")).await?;
    writeln!(io::stdout(), "{}", result.id)?;
    Ok(())
}

fn read_clipboard() -> Result<Vec<u8>, CliError> {
    let output = clipboard_paste_command()
        .ok_or_else(|| CliError::Usage("no clipboard tool on this platform".into()))?
        .output()?;
    if !output.status.success() {
        return Err(CliError::Usage(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(output.stdout)
}

/// Copy bytes to the system clipboard (used by the desktop palette).
pub fn write_clipboard(bytes: &[u8]) -> Result<(), CliError> {
    let mut cmd = clipboard_copy_command()
        .ok_or_else(|| CliError::Usage("no clipboard tool on this platform".into()))?;
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::null());
    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(bytes)?;
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(CliError::Usage("clipboard copy failed".into()));
    }
    Ok(())
}

const LINUX_PASTE: &[(&str, &[&str])] = &[
    ("wl-paste", &["--no-newline"]),
    ("xclip", &["-selection", "clipboard", "-o"]),
    ("xsel", &["--clipboard", "--output"]),
];

const LINUX_COPY: &[(&str, &[&str])] = &[
    ("wl-copy", &[]),
    ("xclip", &["-selection", "clipboard", "-i"]),
    ("xsel", &["--clipboard", "--input"]),
];

fn clipboard_paste_command() -> Option<ProcessCommand> {
    if cfg!(target_os = "macos") {
        return Some(ProcessCommand::new("pbpaste"));
    }
    if cfg!(target_os = "linux") {
        for (bin, args) in LINUX_PASTE {
            if command_exists(bin) {
                let mut cmd = ProcessCommand::new(bin);
                cmd.args(*args);
                return Some(cmd);
            }
        }
    }
    if cfg!(windows) {
        let mut cmd = ProcessCommand::new("powershell");
        cmd.args(["-NoProfile", "-Command", "Get-Clipboard -Raw"]);
        return Some(cmd);
    }
    None
}

fn clipboard_copy_command() -> Option<ProcessCommand> {
    if cfg!(target_os = "macos") {
        return Some(ProcessCommand::new("pbcopy"));
    }
    if cfg!(target_os = "linux") {
        for (bin, args) in LINUX_COPY {
            if command_exists(bin) {
                let mut cmd = ProcessCommand::new(bin);
                cmd.args(*args);
                return Some(cmd);
            }
        }
    }
    if cfg!(windows) {
        return Some(ProcessCommand::new("clip"));
    }
    None
}

fn command_exists(name: &str) -> bool {
    which_ok(name)
}

fn which_ok(name: &str) -> bool {
    ProcessCommand::new("which")
        .arg(name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
                ContentKind::Scratch => {
                    assert!(parse_kind("scratch").is_err());
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
        check(ContentKind::Scratch);
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

    #[test]
    fn linux_clipboard_falls_back_past_wl_paste() {
        assert_eq!(
            LINUX_PASTE.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
            vec!["wl-paste", "xclip", "xsel"]
        );
        assert_eq!(
            LINUX_COPY.iter().map(|(b, _)| *b).collect::<Vec<_>>(),
            vec!["wl-copy", "xclip", "xsel"]
        );
    }
}
