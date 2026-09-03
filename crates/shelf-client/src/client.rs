//! Unix-domain client for `shelfd`.

#[cfg(windows)]
use std::io;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::{Duration, Instant};

use shelf_core::{ContentKind, EpochId, ObjectId};
#[cfg(any(unix, windows))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ClientError;
use crate::ipc::{
    GetTarget, IpcRequest, IpcResponse, ListedDevice, ListedItem, ObjectPayload, PutResult,
};

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
    /// Subsequent calls reconnect. Windows retries `ERROR_PIPE_BUSY` because
    /// the probe and the RPC each consume a waiting pipe instance. On platforms
    /// other than Unix and Windows this returns [`ClientError::UnsupportedOs`].
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
            _ => Err(unexpected("put")),
        }
    }

    /// Ask the daemon to stream-seal a local file (never sent over IPC).
    pub async fn put_file(
        &self,
        path: &Path,
        filename: &str,
        mime: Option<&str>,
    ) -> Result<PutResult, ClientError> {
        let req = IpcRequest::PutFile {
            path: path.to_string_lossy().into_owned(),
            filename: filename.to_owned(),
            mime: mime.map(str::to_owned),
        };
        match rpc(&self.path, &req).await? {
            IpcResponse::Put { id, created } => Ok(PutResult { id, created }),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("put_file")),
        }
    }

    /// List metadata for stored objects, newest first. No plaintext.
    /// Archived objects are omitted.
    pub async fn ls(&self) -> Result<Vec<ListedItem>, ClientError> {
        self.ls_inner(false).await
    }

    /// List metadata, optionally including archived objects.
    pub async fn ls_with_archived(
        &self,
        include_archived: bool,
    ) -> Result<Vec<ListedItem>, ClientError> {
        self.ls_inner(include_archived).await
    }

    async fn ls_inner(&self, include_archived: bool) -> Result<Vec<ListedItem>, ClientError> {
        match rpc(&self.path, &IpcRequest::Ls { include_archived }).await? {
            IpcResponse::Ls { items } => Ok(items),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("ls")),
        }
    }

    /// Decrypt live non-archived objects and return metadata for substring hits.
    pub async fn search(&self, query: &str) -> Result<Vec<ListedItem>, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::Search {
                query: query.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::Search { items } => Ok(items),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("search")),
        }
    }

    /// Archive an object by id or 1-based newest-first index.
    pub async fn archive(&self, target: GetTarget) -> Result<ObjectId, ClientError> {
        match rpc(&self.path, &IpcRequest::Archive { target }).await? {
            IpcResponse::Archive { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("archive")),
        }
    }

    /// Attach a label to an object by id or 1-based newest-first index.
    pub async fn label(&self, target: GetTarget, name: &str) -> Result<ObjectId, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::Label {
                target,
                name: name.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::Label { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("label")),
        }
    }

    /// Decrypt the newest object (by creation timestamp).
    pub async fn latest(&self) -> Result<ObjectPayload, ClientError> {
        match rpc(&self.path, &IpcRequest::Latest).await? {
            IpcResponse::Latest { id, kind, bytes } => {
                Ok(ObjectPayload::from_parts(id, kind, bytes))
            }
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("latest")),
        }
    }

    /// Decrypt one object by id or 1-based newest-first index.
    pub async fn get(&self, target: GetTarget) -> Result<ObjectPayload, ClientError> {
        match rpc(&self.path, &IpcRequest::Get { target }).await? {
            IpcResponse::Get { id, kind, bytes } => Ok(ObjectPayload::from_parts(id, kind, bytes)),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("get")),
        }
    }

    /// Pin an object by id or 1-based newest-first index.
    ///
    /// Pinning is durable retention: the item stays until explicitly removed.
    pub async fn pin(&self, target: GetTarget) -> Result<ObjectId, ClientError> {
        match rpc(&self.path, &IpcRequest::Pin { target }).await? {
            IpcResponse::Pin { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("pin")),
        }
    }

    /// Remove an object by id or 1-based newest-first index.
    pub async fn rm(&self, target: GetTarget) -> Result<ObjectId, ClientError> {
        match rpc(&self.path, &IpcRequest::Rm { target }).await? {
            IpcResponse::Rm { id } => Ok(id),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("rm")),
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
            _ => Err(unexpected("scratch get")),
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
            _ => Err(unexpected("scratch append")),
        }
    }

    /// Export a `.shelfjoin` from the daemon vault.
    pub async fn enroll_export(&self) -> Result<(serde_json::Value, String), ClientError> {
        match rpc(&self.path, &IpcRequest::EnrollExport).await? {
            IpcResponse::EnrollExport { join, sas } => Ok((join, sas)),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("enroll export")),
        }
    }

    /// Approve a `.shelfjoin` using the daemon vault.
    pub async fn enroll_approve(
        &self,
        join: serde_json::Value,
    ) -> Result<(serde_json::Value, String), ClientError> {
        match rpc(&self.path, &IpcRequest::EnrollApprove { join }).await? {
            IpcResponse::EnrollApprove { grant, sas } => Ok((grant, sas)),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("enroll approve")),
        }
    }

    /// Import a `.shelfgrant` into the daemon vault.
    pub async fn enroll_import(
        &self,
        grant: serde_json::Value,
        expect_sas: &str,
    ) -> Result<(), ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::EnrollImport {
                grant,
                expect_sas: expect_sas.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::EnrollImport => Ok(()),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("enroll import")),
        }
    }

    /// Export a `.shelfrecovery` from the daemon vault.
    pub async fn recovery_export(
        &self,
        passphrase: &str,
    ) -> Result<serde_json::Value, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::RecoveryExport {
                passphrase: passphrase.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::RecoveryExport { bundle } => Ok(bundle),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("recovery export")),
        }
    }

    /// Apply a recovery bundle through the daemon.
    ///
    /// The CLI never calls this: apply is local against an empty `--home`.
    pub async fn recovery_apply(
        &self,
        bundle: serde_json::Value,
        passphrase: &str,
    ) -> Result<(), ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::RecoveryApply {
                bundle,
                passphrase: passphrase.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::RecoveryApply => Ok(()),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("recovery apply")),
        }
    }

    /// List vault members (device id, optional name, root flag).
    pub async fn devices_list(&self) -> Result<Vec<ListedDevice>, ClientError> {
        match rpc(&self.path, &IpcRequest::DevicesList).await? {
            IpcResponse::DevicesList { devices } => Ok(devices),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("devices list")),
        }
    }

    /// Revoke a member by hex device id. Vault root only.
    pub async fn devices_revoke(&self, device_id: &str) -> Result<EpochId, ClientError> {
        match rpc(
            &self.path,
            &IpcRequest::DevicesRevoke {
                device_id: device_id.to_owned(),
            },
        )
        .await?
        {
            IpcResponse::DevicesRevoke { new_epoch } => Ok(new_epoch),
            IpcResponse::Error { code, message } => Err(ClientError::from_ipc(code, message)),
            _ => Err(unexpected("devices revoke")),
        }
    }
}

fn unexpected(op: &str) -> ClientError {
    ClientError::Protocol(format!("unexpected response for {op}"))
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
        let (mut reader, mut writer) = stream.into_split();
        let mut json =
            serde_json::to_string(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
        writer.flush().await?;

        let Some(line) = read_bounded_utf8(&mut reader).await? else {
            return Err(ClientError::Protocol(
                "empty or oversized response from daemon".into(),
            ));
        };
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
        let Some(line) = read_bounded_utf8(&mut stream).await? else {
            return Err(ClientError::Protocol(
                "empty or oversized response from daemon".into(),
            ));
        };
        serde_json::from_str(line.trim_end()).map_err(|e| ClientError::Decode(e.to_string()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, req);
        Err(ClientError::UnsupportedOs)
    }
}

#[cfg(any(unix, windows))]
async fn read_bounded_utf8<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<String>, ClientError> {
    let mut acc = shelf_core::BoundedLine::new();
    let mut any = false;
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return if any {
                Err(ClientError::Protocol("truncated IPC frame".into()))
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
                return Err(ClientError::Protocol(
                    "empty or oversized response from daemon".into(),
                ));
            }
        }
    }
}

#[cfg(windows)]
fn open_windows_pipe(
    path: &Path,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, ClientError> {
    use tokio::net::windows::named_pipe::ClientOptions;
    let deadline = Instant::now() + Duration::from_millis(1000);
    loop {
        match ClientOptions::new().open(path) {
            Ok(stream) => return Ok(stream),
            Err(err) if is_pipe_busy(&err) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(err) => return Err(err.into()),
        }
    }
}

#[cfg(windows)]
fn is_pipe_busy(err: &io::Error) -> bool {
    // ERROR_PIPE_BUSY
    err.raw_os_error() == Some(231)
}

#[cfg(all(test, windows))]
mod windows_pipe_tests {
    use super::is_pipe_busy;
    use std::io;

    #[test]
    fn recognizes_error_pipe_busy() {
        assert!(is_pipe_busy(&io::Error::from_raw_os_error(231)));
        assert!(!is_pipe_busy(&io::Error::from_raw_os_error(2)));
    }
}
