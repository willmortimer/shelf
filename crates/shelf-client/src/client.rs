//! Unix-domain client for `shelfd`.

use std::path::{Path, PathBuf};

use shelf_core::ContentKind;
#[cfg(unix)]
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
    /// Subsequent calls reconnect. On non-Unix platforms this returns
    /// [`ClientError::UnsupportedOs`].
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
            IpcResponse::Ls { .. } | IpcResponse::Latest { .. } | IpcResponse::Get { .. } => {
                Err(ClientError::Protocol("unexpected response for put".into()))
            }
        }
    }

    /// List metadata for stored objects, newest first. No plaintext.
    pub async fn ls(&self) -> Result<Vec<ListedItem>, ClientError> {
        match rpc(&self.path, &IpcRequest::Ls).await? {
            IpcResponse::Ls { items } => Ok(items),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. } | IpcResponse::Latest { .. } | IpcResponse::Get { .. } => {
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
            IpcResponse::Put { .. } | IpcResponse::Ls { .. } | IpcResponse::Get { .. } => Err(
                ClientError::Protocol("unexpected response for latest".into()),
            ),
        }
    }

    /// Decrypt one object by id or 1-based newest-first index.
    pub async fn get(&self, target: GetTarget) -> Result<ObjectPayload, ClientError> {
        match rpc(&self.path, &IpcRequest::Get { target }).await? {
            IpcResponse::Get { id, kind, bytes } => Ok(ObjectPayload::from_parts(id, kind, bytes)),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            IpcResponse::Put { .. } | IpcResponse::Ls { .. } | IpcResponse::Latest { .. } => {
                Err(ClientError::Protocol("unexpected response for get".into()))
            }
        }
    }
}

async fn probe(path: &Path) -> Result<(), ClientError> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ClientError::UnsupportedOs)
    }
    #[cfg(unix)]
    {
        let _ = tokio::net::UnixStream::connect(path).await?;
        Ok(())
    }
}

async fn rpc(path: &Path, req: &IpcRequest) -> Result<IpcResponse, ClientError> {
    #[cfg(not(unix))]
    {
        let _ = (path, req);
        Err(ClientError::UnsupportedOs)
    }
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
        if n == 0 {
            return Err(ClientError::Protocol("empty response from daemon".into()));
        }
        serde_json::from_str(line.trim_end()).map_err(|e| ClientError::Decode(e.to_string()))
    }
}
