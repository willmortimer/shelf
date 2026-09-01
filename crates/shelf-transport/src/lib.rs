//! Tailscale (host CLI), LAN UDP, and mailbox transports.
//!
//! Membership is never conferred by discovery. The mailbox is ciphertext-only.
//! Tailscale uses the host `tailscale` binary; this crate does not embed tsnet.

#![deny(missing_docs)]

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shelf_core::{Peer, PeerId, PeerTransport};
use shelf_store::SealedRecord;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;

mod frame;

pub use frame::{ReplicaFrame, parse_sig_hex, sig_hex};
pub use shelf_mailbox::{MailboxClient, MailboxError, MailboxItem};

/// Transport failures.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Socket I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Host Tailscale CLI missing or unusable.
    #[error("tailscale unavailable: {0}")]
    Tailscale(String),
}

/// Non-secret preferences from `~/.shelf/config.toml`.
#[derive(Clone, Debug, Default)]
pub struct HomeConfig {
    /// `host:port` of an optional mailbox. Empty means disabled.
    pub mailbox_url: Option<String>,
    /// UDP port for LAN announce/object broadcast.
    pub lan_port: u16,
    /// TCP port for framed Tailscale/LAN peer sessions.
    pub peer_port: u16,
}

/// Parse a tiny TOML subset: `key = "value"` and `key = 123`.
#[must_use]
pub fn parse_home_config(path: &Path) -> HomeConfig {
    let mut cfg = HomeConfig {
        mailbox_url: None,
        lan_port: 18732,
        peer_port: 18733,
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return cfg;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"');
        match key {
            "mailbox_url" => {
                if !val.is_empty() {
                    cfg.mailbox_url = Some(val.to_owned());
                }
            }
            "lan_port" => {
                if let Ok(p) = val.parse() {
                    cfg.lan_port = p;
                }
            }
            "peer_port" => {
                if let Ok(p) = val.parse() {
                    cfg.peer_port = p;
                }
            }
            _ => {}
        }
    }
    cfg
}

/// Host Tailscale snapshot (`tailscale status --json`).
#[derive(Clone, Debug, Default)]
pub struct TailscaleStatus {
    /// Whether this node believes it is online.
    pub self_online: bool,
    /// Discovered tailnet peers (connectivity, not membership).
    pub peers: Vec<TailscalePeer>,
}

/// One Tailscale peer.
#[derive(Clone, Debug)]
pub struct TailscalePeer {
    /// Stable peer id derived from the node public key.
    pub peer_id: PeerId,
    /// MagicDNS or hostname.
    pub dns_name: String,
    /// Tailscale IPs.
    pub ips: Vec<String>,
    /// Online flag from the host CLI.
    pub online: bool,
    /// True when the current path is a DERP relay.
    pub relayed: bool,
}

/// Parse `tailscale status --json`. Missing binary is an error.
pub fn tailscale_status() -> Result<TailscaleStatus, TransportError> {
    let output = Command::new("tailscale")
        .arg("status")
        .arg("--json")
        .output()
        .map_err(|e| TransportError::Tailscale(e.to_string()))?;
    if !output.status.success() {
        return Err(TransportError::Tailscale(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    parse_tailscale_json(&output.stdout)
}

fn parse_tailscale_json(bytes: &[u8]) -> Result<TailscaleStatus, TransportError> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let self_online = v
        .get("Self")
        .and_then(|s| s.get("Online"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut peers = Vec::new();
    if let Some(map) = v.get("Peer").and_then(serde_json::Value::as_object) {
        for (key, peer) in map {
            let dns_name = peer
                .get("DNSName")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .trim_end_matches('.')
                .to_owned();
            let online = peer
                .get("Online")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let relayed = peer
                .get("CurAddr")
                .and_then(serde_json::Value::as_str)
                .map(|s| s.is_empty())
                .unwrap_or(true);
            let ips = peer
                .get("TailscaleIPs")
                .and_then(serde_json::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            peers.push(TailscalePeer {
                peer_id: peer_id_from_key(key.as_bytes()),
                dns_name,
                ips,
                online,
                relayed,
            });
        }
    }
    Ok(TailscaleStatus { self_online, peers })
}

fn peer_id_from_key(key: &[u8]) -> PeerId {
    PeerId::from_bytes(*blake3::hash(key).as_bytes())
}

/// Tailscale transport: discovery via host CLI. Connect returns a MagicDNS name.
pub struct TailscaleTransport;

impl PeerTransport for TailscaleTransport {
    type Connection = String;
    type Error = TransportError;

    async fn discover(&self) -> Vec<Peer> {
        match tailscale_status() {
            Ok(status) => status
                .peers
                .into_iter()
                .filter(|p| p.online)
                .map(|p| Peer::new(p.peer_id))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    async fn connect(&self, peer: PeerId) -> Result<Self::Connection, Self::Error> {
        let status = tailscale_status()?;
        status
            .peers
            .into_iter()
            .find(|p| p.peer_id == peer)
            .map(|p| p.dns_name)
            .ok_or_else(|| TransportError::Tailscale("peer not in tailscale status".into()))
    }
}

/// Send one newline-delimited replica frame to `addr` (Tailscale or loopback).
pub async fn send_replica_line(addr: SocketAddr, line: &[u8]) -> Result<(), TransportError> {
    let connect = tokio::net::TcpStream::connect(addr);
    let mut stream = tokio::time::timeout(Duration::from_secs(2), connect)
        .await
        .map_err(|_| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "peer connect timed out",
            ))
        })??;
    stream.write_all(line).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct LanPacket {
    v: u16,
    kind: String,
    payload: serde_json::Value,
}

/// LAN UDP transport. Discovery does not confer membership.
pub struct LanTransport {
    socket: UdpSocket,
    port: u16,
}

impl LanTransport {
    /// Bind `0.0.0.0:port` (or ephemeral if `port` is 0).
    pub async fn bind(port: u16) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?;
        socket.set_broadcast(true)?;
        let port = socket.local_addr()?.port();
        Ok(Self { socket, port })
    }

    /// Broadcast a presence packet (`_shelf._udp` analogue).
    pub async fn announce(&self) -> Result<(), TransportError> {
        let pkt = LanPacket {
            v: 1,
            kind: "announce".into(),
            payload: serde_json::json!({ "port": self.port }),
        };
        let bytes = serde_json::to_vec(&pkt)?;
        let _ = self
            .socket
            .send_to(&bytes, SocketAddr::from(([255, 255, 255, 255], self.port)))
            .await;
        Ok(())
    }

    /// Broadcast a sealed object record (ciphertext JSON).
    pub async fn broadcast_object(&self, record: &SealedRecord) -> Result<(), TransportError> {
        let pkt = LanPacket {
            v: 1,
            kind: "object".into(),
            payload: serde_json::to_value(record)?,
        };
        let bytes = serde_json::to_vec(&pkt)?;
        let _ = self
            .socket
            .send_to(&bytes, SocketAddr::from(([255, 255, 255, 255], self.port)))
            .await;
        Ok(())
    }
}

impl PeerTransport for LanTransport {
    type Connection = SocketAddr;
    type Error = TransportError;

    async fn discover(&self) -> Vec<Peer> {
        let _ = self.announce().await;
        Vec::new()
    }

    async fn connect(&self, _peer: PeerId) -> Result<Self::Connection, Self::Error> {
        Err(TransportError::Io(std::io::Error::other(
            "LAN connect requires an explicit address hint",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config_mailbox_and_port() {
        let dir = std::env::temp_dir().join(format!("shelf-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            "mailbox_url = \"127.0.0.1:8743\"\nlan_port = 19000\npeer_port = 19100\n",
        )
        .unwrap();
        let cfg = parse_home_config(&path);
        assert_eq!(cfg.mailbox_url.as_deref(), Some("127.0.0.1:8743"));
        assert_eq!(cfg.lan_port, 19000);
        assert_eq!(cfg.peer_port, 19100);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tailscale_json_maps_peer_keys() {
        let json = br#"{
            "Self": {"Online": true},
            "Peer": {
                "nodekey:abc": {
                    "DNSName": "laptop.tailnet.ts.net.",
                    "Online": true,
                    "CurAddr": "1.2.3.4:123",
                    "TailscaleIPs": ["100.64.0.1"]
                }
            }
        }"#;
        let status = parse_tailscale_json(json).unwrap();
        assert!(status.self_online);
        assert_eq!(status.peers.len(), 1);
        assert_eq!(status.peers[0].dns_name, "laptop.tailnet.ts.net");
        assert!(!status.peers[0].relayed);
        assert_eq!(status.peers[0].ips, vec!["100.64.0.1"]);
    }

    #[tokio::test]
    async fn mailbox_moves_sealed_record_between_stores() {
        use shelf_core::{ContentKind, DeviceId, EpochId, VaultId};
        use shelf_mailbox::{Mailbox, MailboxClient, accept_loop};
        use shelf_protocol::EpochKey;
        use shelf_store::{ItemTarget, SqliteStore};
        use std::sync::Arc;
        use tokio::net::TcpListener;

        let key_bytes = *EpochKey::new().as_bytes();
        let vault = VaultId::new();
        let epoch = EpochId::new(1);
        let dir = std::env::temp_dir().join(format!("shelf-repl-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut a = SqliteStore::open(
            &dir.join("a.db"),
            EpochKey::from_bytes(key_bytes),
            DeviceId::new(),
            epoch,
            vault,
        )
        .unwrap();
        let mut b = SqliteStore::open(
            &dir.join("b.db"),
            EpochKey::from_bytes(key_bytes),
            DeviceId::new(),
            epoch,
            vault,
        )
        .unwrap();
        let (id, _) = a
            .put(b"replicated".to_vec(), ContentKind::Text, None)
            .unwrap();
        let rec = a.export_objects().unwrap().into_iter().next().unwrap();
        let payload = serde_json::to_vec(&rec).unwrap();

        let mailbox = Arc::new(Mailbox::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(accept_loop(listener, Arc::clone(&mailbox)));
        let client = MailboxClient::connect(addr.to_string()).await.unwrap();
        client
            .put("vault", &id.to_string(), &payload, 60)
            .await
            .unwrap();
        let items = client.get("vault").await.unwrap();
        assert_eq!(items.len(), 1);
        let rec: shelf_store::SealedRecord = serde_json::from_slice(&items[0].ciphertext).unwrap();
        b.ingest_envelope(
            rec.envelope,
            rec.created,
            rec.pinned,
            rec.expires_at,
            rec.name,
        )
        .unwrap();
        assert_eq!(b.get(&ItemTarget::Id(id)).unwrap().bytes, b"replicated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn send_replica_line_is_newline_framed() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            buf
        });
        send_replica_line(addr, br#"{"op":"x"}"#).await.unwrap();
        let buf = server.await.unwrap();
        assert_eq!(buf, b"{\"op\":\"x\"}\n");
    }
}
