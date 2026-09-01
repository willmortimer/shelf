//! Authenticated TLS peer sessions and bounded newline frames.

use std::io;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use serde::{Deserialize, Serialize};
use shelf_core::{DeviceId, MAX_FRAME_BYTES, VaultId};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::server::TlsStream as ServerTlsStream;

/// First application record after TLS: membership binding.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionHello {
    /// Vault the speaker belongs to.
    pub vault_id: VaultId,
    /// Speaker device id (must match a membership certificate).
    pub device_id: DeviceId,
    /// Hex Ed25519 signature over `vault_id || device_id || exporter`.
    ///
    /// The exporter is taken from the live TLS connection, never from the wire.
    pub signature: String,
}

/// Transcript signed in [`SessionHello`].
#[must_use]
pub fn hello_transcript(vault_id: VaultId, device_id: DeviceId, exporter: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(32 + 32 + 32);
    t.extend_from_slice(vault_id.as_bytes());
    t.extend_from_slice(device_id.as_bytes());
    t.extend_from_slice(exporter);
    t
}

/// Read one newline-delimited frame, rejecting payloads over [`MAX_FRAME_BYTES`].
pub async fn read_bounded_line<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame",
                ))
            };
        }
        buf.push(byte[0]);
        if buf.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds MAX_FRAME_BYTES",
            ));
        }
        if byte[0] == b'\n' {
            return Ok(Some(buf));
        }
    }
}

/// Write `line` plus a trailing newline. Rejects oversized payloads.
pub async fn write_bounded_line<W: AsyncWrite + Unpin>(
    writer: &mut W,
    line: &[u8],
) -> io::Result<()> {
    if line.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds MAX_FRAME_BYTES",
        ));
    }
    writer.write_all(line).await?;
    if !line.ends_with(b"\n") {
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;
    Ok(())
}

fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed() -> Result<(Vec<CertificateDer<'static>>, PrivatePkcs8KeyDer<'static>), io::Error> {
    let pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;
    let params =
        rcgen::CertificateParams::new(vec!["shelf-peer".into()]).map_err(io::Error::other)?;
    let cert = params.self_signed(&pair).map_err(io::Error::other)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key = PrivatePkcs8KeyDer::from(pair.serialize_der());
    Ok((vec![cert_der], key))
}

#[derive(Debug)]
struct AcceptAnyServer;

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS server config: self-signed, no WebPKI client check (membership is out of band).
pub fn server_config() -> Result<Arc<ServerConfig>, io::Error> {
    install_provider();
    let (certs, key) = self_signed()?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key.into())
        .map_err(io::Error::other)?;
    cfg.alpn_protocols = vec![b"shelf/1".to_vec()];
    Ok(Arc::new(cfg))
}

/// TLS client config: encrypts the session; membership is verified after hello.
pub fn client_config() -> Result<Arc<ClientConfig>, io::Error> {
    install_provider();
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"shelf/1".to_vec()];
    Ok(Arc::new(cfg))
}

/// Accept a TLS session on an already-connected TCP stream.
pub async fn accept_tls(stream: TcpStream) -> Result<ServerTlsStream<TcpStream>, io::Error> {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config()?);
    acceptor.accept(stream).await.map_err(io::Error::other)
}

/// Connect TLS to `stream`. Server name is unused (custom verifier).
pub async fn connect_tls(
    stream: TcpStream,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, io::Error> {
    let connector = TlsConnector::from(client_config()?);
    let name = ServerName::try_from("shelf-peer").map_err(io::Error::other)?;
    connector
        .connect(name, stream)
        .await
        .map_err(io::Error::other)
}

/// TLS exporter bound into [`SessionHello`].
pub fn tls_exporter_server(tls: &ServerTlsStream<TcpStream>) -> Result<[u8; 32], io::Error> {
    let mut out = [0u8; 32];
    tls.get_ref()
        .1
        .export_keying_material(&mut out, b"shelf-session-v1", None)
        .map_err(io::Error::other)?;
    Ok(out)
}

/// TLS exporter on the client half.
pub fn tls_exporter_client(
    tls: &tokio_rustls::client::TlsStream<TcpStream>,
) -> Result<[u8; 32], io::Error> {
    let mut out = [0u8; 32];
    tls.get_ref()
        .1
        .export_keying_material(&mut out, b"shelf-session-v1", None)
        .map_err(io::Error::other)?;
    Ok(out)
}
