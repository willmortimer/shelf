//! Local IPC accept loop (Unix sockets or Windows named pipes).

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(any(unix, windows))]
use std::sync::{Arc, Mutex};

use crate::error::DaemonError;
use crate::store::MemoryStore;
#[cfg(any(unix, windows))]
use crate::store::{ipc_target, listed};
#[cfg(any(unix, windows))]
use shelf_client::{IpcErrorCode, IpcRequest, IpcResponse};
#[cfg(any(unix, windows))]
use shelf_core::ContentKind;
use shelf_keystore::DeviceSigner;
#[cfg(any(unix, windows))]
use shelf_store::StoreError;
#[cfg(any(unix, windows))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(any(unix, windows))]
use tokio::sync::Notify;

/// Bind `socket_path` and accept newline-delimited JSON IPC connections.
///
/// Framing: one JSON request object + `\n`, then one JSON response object +
/// `\n`, then the connection is closed. A stale socket file is replaced.
/// Parent directories are created if missing.
///
/// On platforms other than Unix or Windows this returns [`DaemonError::UnsupportedOs`].
pub async fn serve(socket_path: impl AsRef<Path>, store: MemoryStore) -> Result<(), DaemonError> {
    serve_inner(socket_path, store, None, None).await
}

/// Serve IPC and fan sealed envelopes out over configured transports.
pub async fn serve_with_replica(
    socket_path: impl AsRef<Path>,
    store: MemoryStore,
    home: std::path::PathBuf,
    signer: DeviceSigner,
) -> Result<(), DaemonError> {
    serve_inner(socket_path, store, Some(home), Some(signer)).await
}

async fn serve_inner(
    socket_path: impl AsRef<Path>,
    store: MemoryStore,
    home: Option<std::path::PathBuf>,
    signer: Option<DeviceSigner>,
) -> Result<(), DaemonError> {
    #[cfg(unix)]
    {
        serve_unix(socket_path.as_ref(), store, home, signer).await
    }
    #[cfg(windows)]
    {
        serve_windows(socket_path.as_ref(), store, home, signer).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (socket_path.as_ref(), store, home, signer);
        Err(DaemonError::UnsupportedOs)
    }
}

#[cfg(unix)]
async fn serve_unix(
    socket_path: &Path,
    store: MemoryStore,
    home: Option<std::path::PathBuf>,
    signer: Option<DeviceSigner>,
) -> Result<(), DaemonError> {
    if let Some(parent) = socket_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    let listener = tokio::net::UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;

    let store = Arc::new(Mutex::new(store));
    let notify = Arc::new(Notify::new());
    if let (Some(home), Some(signer)) = (home, signer) {
        crate::replica::spawn_replica(Arc::clone(&store), home, Arc::clone(&notify), signer);
    }
    loop {
        let (stream, _) = listener.accept().await?;
        let store = Arc::clone(&store);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, store, notify).await {
                tracing::warn!(error = %err, "ipc connection failed");
            }
        });
    }
}

#[cfg(unix)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    store: Arc<Mutex<MemoryStore>>,
    notify: Arc<Notify>,
) -> Result<(), DaemonError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = reader;
    let Some(line) = read_bounded_utf8(&mut reader).await? else {
        return Ok(());
    };
    if line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<IpcRequest>(line.trim_end()) {
        Ok(req) => {
            let mutated = matches!(
                req,
                IpcRequest::Put { .. }
                    | IpcRequest::PutFile { .. }
                    | IpcRequest::Pin { .. }
                    | IpcRequest::Rm { .. }
                    | IpcRequest::ScratchAppend { .. }
            );
            let mut store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let response = dispatch(req, &mut store);
            drop(store);
            if mutated {
                notify.notify_waiters();
            }
            response
        }
        Err(err) => IpcResponse::Error {
            code: IpcErrorCode::Decode,
            message: err.to_string(),
        },
    };

    let mut json = serde_json::to_string(&response).map_err(io_from_json)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(any(unix, windows))]
fn io_from_json(err: serde_json::Error) -> std::io::Error {
    std::io::Error::other(err)
}

#[cfg(any(unix, windows))]
async fn read_bounded_utf8<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<String>, DaemonError> {
    let mut acc = shelf_core::BoundedLine::new();
    let mut any = false;
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return if any {
                Err(
                    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated IPC frame")
                        .into(),
                )
            } else {
                Ok(None)
            };
        }
        any = true;
        match acc.push(byte[0]) {
            Ok(Some(buf)) => {
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
            }
            Ok(None) => {}
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "IPC frame exceeds MAX_FRAME_BYTES",
                )
                .into());
            }
        }
    }
}

#[cfg(any(unix, windows))]
fn dispatch(req: IpcRequest, store: &mut MemoryStore) -> IpcResponse {
    match req {
        IpcRequest::Put { bytes, kind, name } => {
            let result = if kind == ContentKind::File {
                let filename = name.clone().unwrap_or_else(|| "file".into());
                store.put_file(filename, "application/octet-stream".into(), bytes)
            } else {
                store.put(bytes, kind, name)
            };
            match result {
                Ok((id, created)) => IpcResponse::Put { id, created },
                Err(err) => store_error(err),
            }
        }
        IpcRequest::PutFile {
            path,
            filename,
            mime,
        } => {
            let mime = mime.unwrap_or_else(|| "application/octet-stream".into());
            match std::fs::File::open(&path) {
                Ok(file) => match store.put_file_reader(filename, mime, file) {
                    Ok((id, created)) => IpcResponse::Put { id, created },
                    Err(err) => store_error(err),
                },
                Err(err) => IpcResponse::Error {
                    code: IpcErrorCode::Io,
                    message: err.to_string(),
                },
            }
        }
        IpcRequest::Ls => match store.ls() {
            Ok(items) => IpcResponse::Ls {
                items: items.into_iter().map(listed).collect(),
            },
            Err(err) => store_error(err),
        },
        IpcRequest::Latest => match store.latest() {
            Ok(obj) => IpcResponse::Latest {
                id: obj.id,
                kind: obj.kind,
                bytes: obj.bytes,
            },
            Err(err) => store_error(err),
        },
        IpcRequest::Get { target } => match store.get(&ipc_target(&target)) {
            Ok(obj) => IpcResponse::Get {
                id: obj.id,
                kind: obj.kind,
                bytes: obj.bytes,
            },
            Err(err) => store_error(err),
        },
        IpcRequest::Pin { target } => match store.pin(&ipc_target(&target)) {
            Ok(id) => IpcResponse::Pin { id },
            Err(err) => store_error(err),
        },
        IpcRequest::Rm { target } => match store.rm(&ipc_target(&target)) {
            Ok(id) => IpcResponse::Rm { id },
            Err(err) => store_error(err),
        },
        IpcRequest::ScratchGet { name } => match store.scratch_text(&name) {
            Ok(text) => IpcResponse::Scratch { name, text },
            Err(err) => store_error(err),
        },
        IpcRequest::ScratchAppend { name, text } => match store.scratch_append(&name, &text) {
            Ok(text) => IpcResponse::Scratch { name, text },
            Err(err) => store_error(err),
        },
    }
}

#[cfg(any(unix, windows))]
fn store_error(err: StoreError) -> IpcResponse {
    match err {
        StoreError::NotFound => IpcResponse::Error {
            code: IpcErrorCode::NotFound,
            message: "object not found".into(),
        },
        StoreError::Protocol(err) => IpcResponse::Error {
            code: IpcErrorCode::Protocol,
            message: err.to_string(),
        },
        StoreError::Sqlite(err) => IpcResponse::Error {
            code: IpcErrorCode::Io,
            message: err.to_string(),
        },
        StoreError::Io(err) => IpcResponse::Error {
            code: IpcErrorCode::Io,
            message: err.to_string(),
        },
        StoreError::Json(err) => IpcResponse::Error {
            code: IpcErrorCode::Protocol,
            message: err.to_string(),
        },
        StoreError::Crdt(err) => IpcResponse::Error {
            code: IpcErrorCode::Protocol,
            message: err.to_string(),
        },
        StoreError::InvalidScratch => IpcResponse::Error {
            code: IpcErrorCode::Protocol,
            message: "invalid scratch envelope".into(),
        },
        StoreError::UnknownEpoch | StoreError::InvalidOp => IpcResponse::Error {
            code: IpcErrorCode::Protocol,
            message: err.to_string(),
        },
    }
}

#[cfg(windows)]
async fn serve_windows(
    pipe_path: &Path,
    store: MemoryStore,
    home: Option<std::path::PathBuf>,
    signer: Option<DeviceSigner>,
) -> Result<(), DaemonError> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let store = Arc::new(Mutex::new(store));
    let notify = Arc::new(Notify::new());
    if let (Some(home), Some(signer)) = (home, signer) {
        crate::replica::spawn_replica(Arc::clone(&store), home, Arc::clone(&notify), signer);
    }

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_path)?;
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().create(pipe_path)?;
        let store = Arc::clone(&store);
        let notify = Arc::clone(&notify);
        tokio::spawn(async move {
            if let Err(err) = handle_windows_pipe(connected, store, notify).await {
                tracing::warn!(error = %err, "ipc connection failed");
            }
        });
    }
}

#[cfg(windows)]
async fn handle_windows_pipe(
    mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
    store: Arc<Mutex<MemoryStore>>,
    notify: Arc<Notify>,
) -> Result<(), DaemonError> {
    let Some(line) = read_bounded_utf8(&mut stream).await? else {
        return Ok(());
    };
    if line.trim().is_empty() {
        return Ok(());
    }
    let response = match serde_json::from_str::<IpcRequest>(line.trim_end()) {
        Ok(req) => {
            let mutated = matches!(
                req,
                IpcRequest::Put { .. }
                    | IpcRequest::PutFile { .. }
                    | IpcRequest::Pin { .. }
                    | IpcRequest::Rm { .. }
                    | IpcRequest::ScratchAppend { .. }
            );
            let mut store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let response = dispatch(req, &mut store);
            drop(store);
            if mutated {
                notify.notify_waiters();
            }
            response
        }
        Err(err) => IpcResponse::Error {
            code: IpcErrorCode::Decode,
            message: err.to_string(),
        },
    };
    let mut json = serde_json::to_string(&response).map_err(io_from_json)?;
    json.push('\n');
    stream.write_all(json.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}
