//! Unix domain socket accept loop.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
#[cfg(unix)]
use std::sync::{Arc, Mutex};

use crate::error::DaemonError;
use crate::store::MemoryStore;
#[cfg(unix)]
use crate::store::{ipc_target, listed};
#[cfg(unix)]
use shelf_client::{IpcErrorCode, IpcRequest, IpcResponse};
#[cfg(unix)]
use shelf_core::ContentKind;
#[cfg(unix)]
use shelf_store::StoreError;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Bind `socket_path` and accept newline-delimited JSON IPC connections.
///
/// Framing: one JSON request object + `\n`, then one JSON response object +
/// `\n`, then the connection is closed. A stale socket file is replaced.
/// Parent directories are created if missing.
///
/// On non-Unix platforms this returns [`DaemonError::UnsupportedOs`].
pub async fn serve(socket_path: impl AsRef<Path>, store: MemoryStore) -> Result<(), DaemonError> {
    serve_inner(socket_path, store, None).await
}

/// Serve IPC and fan sealed envelopes out over configured transports.
pub async fn serve_with_replica(
    socket_path: impl AsRef<Path>,
    store: MemoryStore,
    home: std::path::PathBuf,
) -> Result<(), DaemonError> {
    serve_inner(socket_path, store, Some(home)).await
}

async fn serve_inner(
    socket_path: impl AsRef<Path>,
    store: MemoryStore,
    home: Option<std::path::PathBuf>,
) -> Result<(), DaemonError> {
    #[cfg(not(unix))]
    {
        let _ = (socket_path.as_ref(), store, home);
        Err(DaemonError::UnsupportedOs)
    }
    #[cfg(unix)]
    {
        serve_unix(socket_path.as_ref(), store, home).await
    }
}

#[cfg(unix)]
async fn serve_unix(
    socket_path: &Path,
    store: MemoryStore,
    home: Option<std::path::PathBuf>,
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
    if let Some(home) = home {
        crate::replica::spawn_replica(Arc::clone(&store), home);
    }
    loop {
        let (stream, _) = listener.accept().await?;
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, store).await {
                tracing::warn!(error = %err, "ipc connection failed");
            }
        });
    }
}

#[cfg(unix)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    store: Arc<Mutex<MemoryStore>>,
) -> Result<(), DaemonError> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 || line.trim().is_empty() {
        return Ok(());
    }

    let response = match serde_json::from_str::<IpcRequest>(line.trim_end()) {
        Ok(req) => {
            let mut store = store
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            dispatch(req, &mut store)
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

#[cfg(unix)]
fn io_from_json(err: serde_json::Error) -> std::io::Error {
    std::io::Error::other(err)
}

#[cfg(unix)]
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

#[cfg(unix)]
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
    }
}
