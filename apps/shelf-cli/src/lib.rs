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
    Client, ClientError, GetTarget, ListedDevice, ListedItem, resolve_shelf_home,
    resolve_socket_path,
};
use shelf_core::{ContentKind, DeviceId, ObjectId};
use shelf_keystore::{
    KeystoreError, RecoveryBundle, ShelfGrant, ShelfJoin, apply_recovery, approve_join,
    export_join, export_recovery, grant_sas, import_grant, list_devices_store,
    open_or_create_vault, revoke_device,
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
        /// Include archived objects (hidden by default).
        #[arg(long)]
        archived: bool,
    },
    /// Search decrypted non-archived objects (local substring, not indexed).
    Search {
        /// Case-insensitive needle over plaintext and optional name.
        #[arg(value_name = "QUERY")]
        query: String,
    },
    /// Archive an object (hidden from default `ls`).
    Archive {
        /// 1-based newest-first index, or 64-character hex id.
        #[arg(value_name = "TARGET")]
        target: String,
    },
    /// Attach a label to an object.
    Label {
        /// 1-based newest-first index, or 64-character hex id.
        #[arg(value_name = "TARGET")]
        target: String,
        /// Label text.
        #[arg(value_name = "NAME")]
        name: String,
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
    /// List vault members, or revoke one (vault root only).
    Devices {
        /// Emit a JSON array instead of one device per line.
        #[arg(long)]
        json: bool,
        /// Devices action. Omitted means list.
        #[command(subcommand)]
        action: Option<DevicesAction>,
    },
    /// Export or apply a passphrase-wrapped recovery bundle.
    Recovery {
        /// Recovery action.
        #[command(subcommand)]
        action: RecoveryAction,
    },
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

/// `shelf devices` actions.
#[derive(Debug, Subcommand)]
pub enum DevicesAction {
    /// List vault members.
    List {
        /// Emit a JSON array instead of one device per line.
        #[arg(long)]
        json: bool,
    },
    /// Revoke a member by hex device id. Only the vault root may revoke.
    Revoke {
        /// Hex device identifier.
        #[arg(value_name = "ID")]
        device_id: String,
    },
}

/// Recovery subcommands. Bundle passphrase is TTY or `SHELF_RECOVERY_PASSPHRASE`.
#[derive(Debug, Subcommand)]
pub enum RecoveryAction {
    /// Write a `.shelfrecovery` for the vault root.
    Export {
        /// Output path.
        #[arg(long)]
        out: PathBuf,
    },
    /// Restore a vault onto an empty `--home`.
    Apply {
        /// Recovery bundle path.
        #[arg(long)]
        from: PathBuf,
        /// Allow 0600 `wrap.key` for the restored identity if the platform store is unavailable.
        #[arg(long)]
        allow_file_key: bool,
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
        Command::Enroll { action } => cmd_enroll(&home, &socket, action).await,
        Command::Put { name, kind, file } => cmd_put(&socket, name, kind, file).await,
        Command::Latest => cmd_latest(&socket).await,
        Command::Ls { json, archived } => cmd_ls(&socket, json, archived).await,
        Command::Search { query } => cmd_search(&socket, &query).await,
        Command::Get { target } => cmd_get(&socket, &target).await,
        Command::Pin { target } => cmd_pin(&socket, &target).await,
        Command::Rm { target } => cmd_rm(&socket, &target).await,
        Command::Archive { target } => cmd_archive(&socket, &target).await,
        Command::Label { target, name } => cmd_label(&socket, &target, &name).await,
        Command::Scratch { name, append } => cmd_scratch(&socket, &name, append).await,
        Command::Capture => cmd_capture(&socket).await,
        Command::Devices { json, action } => {
            let action = match action {
                None => DevicesAction::List { json },
                Some(DevicesAction::List { json: list_json }) => DevicesAction::List {
                    json: json || list_json,
                },
                Some(DevicesAction::Revoke { device_id }) => DevicesAction::Revoke { device_id },
            };
            cmd_devices(&home, &socket, action).await
        }
        Command::Recovery { action } => cmd_recovery(&home, &socket, action).await,
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

async fn cmd_enroll(home: &Path, socket: &Path, action: EnrollAction) -> Result<(), CliError> {
    if Client::connect(socket).await.is_ok() {
        cmd_enroll_ipc(socket, action).await
    } else {
        cmd_enroll_direct(home, action)
    }
}

async fn cmd_enroll_ipc(socket: &Path, action: EnrollAction) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    match action {
        EnrollAction::Export { out } => {
            let (join, sas) = client.enroll_export().await?;
            fs::write(&out, serde_json::to_vec_pretty(&join)?)?;
            writeln!(io::stderr(), "SAS: {sas}")?;
            writeln!(io::stderr(), "wrote {}", out.display())?;
            Ok(())
        }
        EnrollAction::Approve { join, out } => {
            let body = fs::read(&join)?;
            let join: serde_json::Value = serde_json::from_slice(&body)?;
            let (grant, sas) = client.enroll_approve(join).await?;
            fs::write(&out, serde_json::to_vec_pretty(&grant)?)?;
            writeln!(io::stderr(), "SAS: {sas}")?;
            writeln!(io::stderr(), "wrote {}", out.display())?;
            Ok(())
        }
        EnrollAction::Import { grant, expect_sas } => {
            let body = fs::read(&grant)?;
            let grant: ShelfGrant = serde_json::from_slice(&body)?;
            let confirmed = confirm_import_sas(&grant, expect_sas)?;
            let value = serde_json::to_value(&grant)?;
            client.enroll_import(value, &confirmed).await?;
            writeln!(io::stderr(), "imported grant")?;
            Ok(())
        }
    }
}

fn cmd_enroll_direct(home: &Path, action: EnrollAction) -> Result<(), CliError> {
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
            let confirmed = confirm_import_sas(&grant, expect_sas)?;
            import_grant(&mut vault, &grant, &confirmed)?;
            writeln!(io::stderr(), "imported grant")?;
            Ok(())
        }
    }
}

async fn cmd_devices(home: &Path, socket: &Path, action: DevicesAction) -> Result<(), CliError> {
    if Client::connect(socket).await.is_ok() {
        cmd_devices_ipc(socket, action).await
    } else {
        cmd_devices_direct(home, action)
    }
}

async fn cmd_devices_ipc(socket: &Path, action: DevicesAction) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    match action {
        DevicesAction::List { json } => {
            let devices = client.devices_list().await?;
            write_devices(&devices, json)
        }
        DevicesAction::Revoke { device_id } => {
            let _ = parse_device_id(&device_id)?;
            let new_epoch = client.devices_revoke(&device_id).await?;
            writeln!(io::stdout(), "{}", new_epoch.as_u64())?;
            Ok(())
        }
    }
}

fn cmd_devices_direct(home: &Path, action: DevicesAction) -> Result<(), CliError> {
    match action {
        DevicesAction::List { json } => {
            let vault = open_or_create_vault(home, None, None, false)?;
            let entries = list_devices_store(&vault.keys, &vault.store)?;
            let devices: Vec<ListedDevice> = entries
                .into_iter()
                .map(|e| ListedDevice {
                    device_id: e.device_id,
                    name: e.name,
                    is_root: e.is_root,
                })
                .collect();
            write_devices(&devices, json)
        }
        DevicesAction::Revoke { device_id } => {
            let id = parse_device_id(&device_id)?;
            let mut vault = open_or_create_vault(home, None, None, false)?;
            let new_epoch = revoke_device(&mut vault, id)?;
            writeln!(io::stdout(), "{}", new_epoch.as_u64())?;
            Ok(())
        }
    }
}

fn write_devices(devices: &[ListedDevice], json: bool) -> Result<(), CliError> {
    if json {
        writeln!(io::stdout(), "{}", serde_json::to_string(devices)?)?;
    } else {
        let mut out = io::stdout().lock();
        for device in devices {
            writeln!(out, "{}", format_device_line(device))?;
        }
        out.flush()?;
    }
    Ok(())
}

async fn cmd_recovery(home: &Path, socket: &Path, action: RecoveryAction) -> Result<(), CliError> {
    match action {
        RecoveryAction::Export { out } => {
            let passphrase = read_recovery_passphrase()?;
            if Client::connect(socket).await.is_ok() {
                let client = Client::connect(socket).await?;
                let bundle = client.recovery_export(&passphrase).await?;
                fs::write(&out, serde_json::to_vec_pretty(&bundle)?)?;
            } else {
                let vault = open_or_create_vault(home, None, None, false)?;
                let bundle = export_recovery(&vault, &passphrase)?;
                fs::write(&out, serde_json::to_vec_pretty(&bundle)?)?;
            }
            writeln!(io::stderr(), "wrote {}", out.display())?;
            Ok(())
        }
        RecoveryAction::Apply {
            from,
            allow_file_key,
        } => {
            // Apply always opens `--home` directly. A running daemon belongs to
            // another vault and must not receive this bundle.
            let passphrase = read_recovery_passphrase()?;
            let body = fs::read(&from)?;
            let bundle: RecoveryBundle = serde_json::from_slice(&body)?;
            apply_recovery(home, &bundle, &passphrase, None, allow_file_key)?;
            writeln!(io::stderr(), "applied recovery to {}", home.display())?;
            Ok(())
        }
    }
}

/// Recovery-bundle passphrase: hidden TTY, else `SHELF_RECOVERY_PASSPHRASE`.
fn read_recovery_passphrase() -> Result<String, CliError> {
    if let Ok(pass) = std::env::var("SHELF_RECOVERY_PASSPHRASE") {
        let pass = pass.trim_end_matches(['\n', '\r']).to_owned();
        if !pass.is_empty() {
            return Ok(pass);
        }
    }
    #[cfg(unix)]
    if io::stdin().is_terminal() {
        return read_hidden_recovery_tty();
    }
    Err(CliError::Usage(
        "set SHELF_RECOVERY_PASSPHRASE or run on a TTY".into(),
    ))
}

#[cfg(unix)]
fn read_hidden_recovery_tty() -> Result<String, CliError> {
    eprint!("Recovery passphrase: ");
    io::stderr().flush()?;
    let line = {
        let _echo = DisableEcho::new()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line
    };
    eprintln!();
    let trimmed = line.trim_end_matches(['\n', '\r']).to_owned();
    if trimmed.is_empty() {
        return Err(CliError::Usage("empty recovery passphrase".into()));
    }
    Ok(trimmed)
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

fn confirm_import_sas(grant: &ShelfGrant, expect_sas: Option<String>) -> Result<String, CliError> {
    let sas = grant_sas(&grant.grant)?;
    writeln!(
        io::stderr(),
        "Vault: {}\nApprover: {}\nSAS: {sas}",
        grant.grant.vault_root.fingerprint(),
        grant.grant.certificate.issuer
    )?;
    if let Some(expect) = expect_sas {
        return Ok(expect);
    }
    if io::stdin().is_terminal() {
        eprint!("Confirm SAS matches trusted device? [y/N] ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        if !line.trim().eq_ignore_ascii_case("y") {
            return Err(CliError::Usage("enrollment import cancelled".into()));
        }
        return Ok(sas);
    }
    Err(CliError::Usage(
        "pass --expect-sas when stdin is not a TTY".into(),
    ))
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

async fn cmd_ls(socket: &Path, json: bool, archived: bool) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let items = client.ls_with_archived(archived).await?;
    write_listed(&items, json)
}

async fn cmd_search(socket: &Path, query: &str) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let items = client.search(query).await?;
    write_listed(&items, false)
}

fn write_listed(items: &[ListedItem], json: bool) -> Result<(), CliError> {
    if json {
        writeln!(io::stdout(), "{}", serde_json::to_string(items)?)?;
    } else {
        let mut out = io::stdout().lock();
        for item in items {
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

async fn cmd_archive(socket: &Path, target: &str) -> Result<(), CliError> {
    let client = Client::connect(socket).await?;
    let _id = client.archive(parse_target(target)?).await?;
    Ok(())
}

async fn cmd_label(socket: &Path, target: &str, name: &str) -> Result<(), CliError> {
    if name.is_empty() {
        return Err(CliError::Usage("label name must not be empty".into()));
    }
    let client = Client::connect(socket).await?;
    let _id = client.label(parse_target(target)?, name).await?;
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
    Ok(ObjectId::from_bytes(parse_hex32(s, "object id")?))
}

fn parse_device_id(s: &str) -> Result<DeviceId, CliError> {
    Ok(DeviceId::from_bytes(parse_hex32(s, "device id")?))
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], CliError> {
    let raw = s.as_bytes();
    if raw.len() != 64 {
        return Err(CliError::Usage(format!("{what} must be 64 hex characters")));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let hex = std::str::from_utf8(&raw[i * 2..i * 2 + 2])
            .map_err(|_| CliError::Usage(format!("{what} must be 64 hex characters")))?;
        bytes[i] = u8::from_str_radix(hex, 16)
            .map_err(|_| CliError::Usage(format!("{what} must be 64 hex characters")))?;
    }
    Ok(bytes)
}

/// One scriptable line: `id kind created` (hex id, kebab-case kind, wall millis).
/// Pinned items append ` pinned`. Archived items append ` archived`.
fn format_ls_line(item: &ListedItem) -> String {
    let pin = if item.pinned { " pinned" } else { "" };
    let archived = if item.archived { " archived" } else { "" };
    format!(
        "{} {} {}{pin}{archived}",
        item.id,
        item.kind.as_wire_str(),
        item.created.wall().as_millis()
    )
}

/// One scriptable line: hex id, optional name, and `(root)` for the vault root.
fn format_device_line(device: &ListedDevice) -> String {
    let mut line = device.device_id.to_string();
    if let Some(name) = &device.name {
        line.push(' ');
        line.push_str(name);
    }
    if device.is_root {
        line.push_str(" (root)");
    }
    line
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
            archived: false,
            labels: Vec::new(),
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

        let mut archived = item.clone();
        archived.archived = true;
        assert!(format_ls_line(&archived).ends_with(" archived"));
    }

    #[test]
    fn device_line_marks_root_and_optional_name() {
        let root = ListedDevice {
            device_id: DeviceId::from_bytes([0x11; 32]),
            name: Some("mac".into()),
            is_root: true,
        };
        assert_eq!(
            format_device_line(&root),
            format!("{} mac (root)", root.device_id)
        );
        let member = ListedDevice {
            device_id: DeviceId::from_bytes([0x22; 32]),
            name: None,
            is_root: false,
        };
        assert_eq!(format_device_line(&member), member.device_id.to_string());
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
