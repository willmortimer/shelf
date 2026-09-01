//! Unix-domain client for `shelfd`.

use std::path::{Path, PathBuf};

use shelf_core::{ContentKind, ObjectId};
#[cfg(any(unix, windows))]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::error::ClientError;
use crate::ipc::{GetTarget, IpcRequest, IpcResponse, ListedItem, ObjectPayload, PutResult};

/// Local IPC client. Each RPC opens a new connection (one request / one
/// response per socket).
#[derive(Clone, Debug)]
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Connect to a running daemon at `path`.
    ///
    /// The socket is opened to verify the daemon is reachable, then dropped.
    /// Subsequent calls reconnect. On platforms other than Unix and Windows
    /// this returns [`ClientError::UnsupportedOs`].
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, ClientError> {
        let path = path.as_ref().to_path_buf();
        probe(&path).await?;
        Ok(Self { path })
    }

    /// Socket path this client uses.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Seal and store `bytes` as `kind`. `name` is optional metadata.
    pub async fn put(
        &self,
        bytes: &[u8],
        kind: ContentKind,
        name: Option<&str>,
    ) -> Result<PutResult, ClientError> {
        let req = IpcRequest::Put {
            bytes: bytes.to_vec(),
            kind,
            name: name.map(str::to_owned),
        };
        match rpc(&self.path, &req).await? {
            IpcResponse::Put { id, created } => Ok(PutResult { id, created }),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. }
            | IpcResponse::Scratch { .. } => {
                Err(ClientError::Protocol("unexpected response for put".into()))
            }
        }
    }

    /// List metadata for stored objects, newest first. No plaintext.
    pub async fn ls(&self) -> Result<Vec<ListedItem>, ClientError> {
        match rpc(&self.path, &IpcRequest::Ls).await? {
            IpcResponse::Ls { items } => Ok(items),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. }
            | IpcResponse::Scratch { .. } => {
                Err(ClientError::Protocol("unexpected response for ls".into()))
            }
        }
    }

    /// Decrypt the newest object (by creation timestamp).
    pub async fn latest(&self) -> Result<ObjectPayload, ClientError> {
        match rpc(&self.path, &IpcRequest::Latest).await? {
            IpcResponse::Latest { id, kind, bytes } => {
                Ok(ObjectPayload::from_parts(id, kind, bytes))
            }
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. }
            | IpcResponse::Scratch { .. } => Err(ClientError::Protocol(
                "unexpected response for latest".into(),
            )),
        }
    }

    /// Decrypt one object by id or 1-based newest-first index.
    pub async fn get(&self, target: GetTarget) -> Result<ObjectPayload, ClientError> {
        match rpc(&self.path, &IpcRequest::Get { target }).await? {
            IpcResponse::Get { id, kind, bytes } => Ok(ObjectPayload::from_parts(id, kind, bytes)),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. }
            | IpcResponse::Scratch { .. } => {
                Err(ClientError::Protocol("unexpected response for get".into()))
            }
        }
    }

    /// Pin an object by id or 1-based newest-first index.
    ///
    /// Pinning is durable retention: the item stays until explicitly removed.
    pub async fn pin(&self, target: GetTarget) -> Result<ObjectId, ClientError> {
        match rpc(&self.path, &IpcRequest::Pin { target }).await? {
            IpcResponse::Pin { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Rm { .. }
            | IpcResponse::Scratch { .. } => {
                Err(ClientError::Protocol("unexpected response for pin".into()))
            }
        }
    }

    /// Remove an object by id or 1-based newest-first index.
    pub async fn rm(&self, target: GetTarget) -> Result<ObjectId, ClientError> {
        match rpc(&self.path, &IpcRequest::Rm { target }).await? {
            IpcResponse::Rm { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Scratch { .. } => {
                Err(ClientError::Protocol("unexpected response for rm".into()))
            }
        }
    }

    /// Current plaintext of a named scratch pad.
    pub async fn scratch_get(&self, name: &str) -> Result<String, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::ScratchGet {
                name: name.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::Scratch { text, .. } => Ok(text),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. } => Err(ClientError::Protocol(
                "unexpected response for scratch get".into(),
            )),
        }
    }

    /// Append `text` to a named scratch pad and return the new plaintext.
    pub async fn scratch_append(&self, name: &str, text: &str) -> Result<String, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::ScratchAppend {
                name: name.to_owned(),
                text: text.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::Scratch { text, .. } => Ok(text),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. }
            | IpcResponse::Ls { .. }
            | IpcResponse::Latest { .. }
            | IpcResponse::Get { .. }
            | IpcResponse::Pin { .. }
            | IpcResponse::Rm { .. } => Err(ClientError::Protocol(
                "unexpected response for scratch append".into(),
            )),
        }
    }
}

async fn probe(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    {
        let _ = tokio::net::UnixStream::connect(path).await?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let _ = open_windows_pipe(path)?;
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(ClientError::UnsupportedOs)
    }
}

async fn rpc(path: &Path, req: &IpcRequest) -> Result<IpcResponse, ClientError> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(path).await?;
        let (reader, mut writer) = stream.into_split();
        let mut json =
            serde_json::to_string(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;

        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line.len() > shelf_core::MAX_FRAME_BYTES {
            return Err(ClientError::Protocol(
                "empty or oversized response from daemon".into(),
            ));
        }
        serde_json::from_str(line.trim_end()).map_err(|e| ClientError::Decode(e.to_string()))
    }
    #[cfg(windows)]
    {
        let mut stream = open_windows_pipe(path)?;
        let mut json =
            serde_json::to_string(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        json.push('\n');
        stream.write_all(json.as_bytes()).await?;
        stream.flush().await?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        if n == 0 || line.len() > shelf_core::MAX_FRAME_BYTES {
            return Err(ClientError::Protocol(
                "empty or oversized response from daemon".into(),
            ));
        }
        serde_json::from_str(line.trim_end()).map_err(|e| ClientError::Decode(e.to_string()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, req);
        Err(ClientError::UnsupportedOs)
    }
}

#[cfg(windows)]
fn open_windows_pipe(
    path: &Path,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, ClientError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    Ok(ClientOptions::new().open(path)?)
}
