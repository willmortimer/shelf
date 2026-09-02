//! LAN UDP announce plus DNS-SD `_shelf._udp.local`.
//!
//! Discovery is metadata only: object ciphertext and replica ops stay on
//! rustls `shelf/2`. Discovery does not confer membership.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};

use mdns_sd::{ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use shelf_core::{Peer, PeerId, PeerTransport};
use shelf_store::SealedRecord;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::TransportError;

/// DNS-SD type registered and browsed by [`LanTransport`].
pub(crate) const SHELF_MDNS_TYPE: &str = "_shelf._udp.local.";

#[derive(Serialize, Deserialize)]
struct LanPacket {
    v: u16,
    kind: String,
    payload: serde_json::Value,
}

#[derive(Default)]
struct LanCache {
    /// Instance or DNS-SD fullname → dial addresses (peer_port).
    peers: HashMap<String, Vec<SocketAddr>>,
}

/// LAN UDP transport. Discovery does not confer membership.
pub struct LanTransport {
    socket: Arc<UdpSocket>,
    port: u16,
    peer_port: u16,
    instance: String,
    fullname: String,
    cache: Arc<Mutex<LanCache>>,
    mdns: Option<ServiceDaemon>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl LanTransport {
    /// Bind UDP `lan_port` (ephemeral if 0) and advertise `peer_port` via DNS-SD.
    pub async fn bind(lan_port: u16, peer_port: u16) -> Result<Self, TransportError> {
        Self::bind_inner(lan_port, peer_port, None, true).await
    }

    async fn bind_inner(
        lan_port: u16,
        peer_port: u16,
        mdns_port: Option<u16>,
        auto_addrs: bool,
    ) -> Result<Self, TransportError> {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], lan_port))).await?;
        socket.set_broadcast(true)?;
        let port = socket.local_addr()?.port();
        let socket = Arc::new(socket);
        let instance = format!("s{:016x}", rand::random::<u64>());
        let fullname = format!("{instance}.{SHELF_MDNS_TYPE}");
        let cache = Arc::new(Mutex::new(LanCache::default()));
        let mut tasks = Vec::new();

        let recv_socket = Arc::clone(&socket);
        let recv_cache = Arc::clone(&cache);
        let recv_instance = instance.clone();
        tasks.push(tokio::spawn(async move {
            recv_udp_announces(recv_socket, recv_cache, recv_instance).await;
        }));

        let mdns = start_mdns(
            mdns_port,
            &instance,
            peer_port,
            auto_addrs,
            Arc::clone(&cache),
            &mut tasks,
        );

        Ok(Self {
            socket,
            port,
            peer_port,
            instance,
            fullname,
            cache,
            mdns,
            tasks: Mutex::new(tasks),
        })
    }

    /// Broadcast a presence packet (UDP fallback analogue of `_shelf._udp.local`).
    pub async fn announce(&self) -> Result<(), TransportError> {
        let pkt = LanPacket {
            v: 1,
            kind: "announce".into(),
            payload: serde_json::json!({
                "port": self.peer_port,
                "id": self.instance,
            }),
        };
        let bytes = serde_json::to_vec(&pkt)?;
        let _ = self
            .socket
            .send_to(&bytes, SocketAddr::from(([255, 255, 255, 255], self.port)))
            .await;
        Ok(())
    }

    /// Broadcast a sealed object record (ciphertext JSON). Unused by the replica.
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

    /// Announce and return cached LAN peers with usable dial addresses.
    ///
    /// Results confer no membership. Callers must handshake-or-drop on `shelf/2`.
    pub async fn discover(&self) -> Vec<Peer> {
        let _ = self.announce().await;
        self.cached_peers()
    }

    fn cached_peers(&self) -> Vec<Peer> {
        let cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache
            .peers
            .iter()
            .filter(|(name, _)| *name != &self.instance && *name != &self.fullname)
            .map(|(name, addrs)| {
                let mut addrs = addrs.clone();
                addrs.sort();
                addrs.dedup();
                Peer::with_addrs(crate::peer_id_from_key(name.as_bytes()), addrs)
            })
            .filter(|p| !p.addrs.is_empty())
            .collect()
    }
}

impl Drop for LanTransport {
    fn drop(&mut self) {
        if let Some(mdns) = &self.mdns {
            let _ = mdns.unregister(&self.fullname);
            let _ = mdns.shutdown();
        }
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

impl PeerTransport for LanTransport {
    type Connection = SocketAddr;
    type Error = TransportError;

    async fn discover(&self) -> Vec<Peer> {
        LanTransport::discover(self).await
    }

    async fn connect(&self, _peer: PeerId) -> Result<Self::Connection, Self::Error> {
        Err(TransportError::Io(std::io::Error::other(
            "LAN connect requires an explicit address hint",
        )))
    }
}

fn start_mdns(
    mdns_port: Option<u16>,
    instance: &str,
    peer_port: u16,
    auto_addrs: bool,
    cache: Arc<Mutex<LanCache>>,
    tasks: &mut Vec<JoinHandle<()>>,
) -> Option<ServiceDaemon> {
    let mdns = match mdns_port {
        Some(port) => ServiceDaemon::new_with_port(port).ok()?,
        None => ServiceDaemon::new().ok()?,
    };
    let host_name = format!("{instance}.local.");
    let ip = if auto_addrs { "" } else { "127.0.0.1" };
    let mut info =
        ServiceInfo::new(SHELF_MDNS_TYPE, instance, &host_name, ip, peer_port, None).ok()?;
    if auto_addrs {
        info = info.enable_addr_auto();
    } else {
        info.set_requires_probe(false);
    }
    if mdns.register(info).is_err() {
        let _ = mdns.shutdown();
        return None;
    }
    let receiver = match mdns.browse(SHELF_MDNS_TYPE) {
        Ok(rx) => rx,
        Err(_) => {
            let _ = mdns.shutdown();
            return None;
        }
    };
    let our_fullname = format!("{instance}.{SHELF_MDNS_TYPE}");
    tasks.push(tokio::spawn(async move {
        while let Ok(event) = receiver.recv_async().await {
            apply_mdns_event(&cache, &our_fullname, event);
        }
    }));
    Some(mdns)
}

fn apply_mdns_event(cache: &Mutex<LanCache>, our_fullname: &str, event: ServiceEvent) {
    match event {
        ServiceEvent::ServiceResolved(info) => {
            if info.fullname == our_fullname {
                return;
            }
            let addrs: Vec<SocketAddr> = info
                .addresses
                .iter()
                .filter_map(|ip| scoped_socket(ip, info.port))
                .collect();
            if addrs.is_empty() {
                return;
            }
            let mut cache = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.peers.insert(info.fullname.clone(), addrs);
        }
        ServiceEvent::ServiceRemoved(_, name) => {
            let mut cache = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.peers.remove(&name);
        }
        _ => {}
    }
}

fn scoped_socket(ip: &ScopedIp, port: u16) -> Option<SocketAddr> {
    match ip {
        ScopedIp::V6(v6) => {
            let addr = *v6.addr();
            if !usable_ip(IpAddr::V6(addr)) || port == 0 {
                return None;
            }
            Some(SocketAddr::V6(SocketAddrV6::new(
                addr,
                port,
                0,
                v6.scope_id().index,
            )))
        }
        other => usable_socket(other.to_ip_addr(), port),
    }
}

fn usable_socket(ip: IpAddr, port: u16) -> Option<SocketAddr> {
    if port == 0 || !usable_ip(ip) {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

fn usable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_unspecified() || v.is_multicast() || v.is_broadcast()),
        IpAddr::V6(v) => !(v.is_unspecified() || v.is_multicast()),
    }
}

async fn recv_udp_announces(socket: Arc<UdpSocket>, cache: Arc<Mutex<LanCache>>, instance: String) {
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            break;
        };
        let Ok(pkt) = serde_json::from_slice::<LanPacket>(&buf[..n]) else {
            continue;
        };
        if pkt.kind != "announce" {
            continue;
        }
        let Some(peer_port) = pkt.payload.get("port").and_then(serde_json::Value::as_u64) else {
            continue;
        };
        let peer_port = u16::try_from(peer_port).ok().filter(|p| *p != 0);
        let Some(peer_port) = peer_port else {
            continue;
        };
        let Some(addr) = usable_socket(from.ip(), peer_port) else {
            continue;
        };
        let key = pkt
            .payload
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        if key == instance {
            continue;
        }
        let key = if key.is_empty() {
            from.to_string()
        } else {
            key
        };
        let mut cache = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let addrs = cache.peers.entry(key).or_default();
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
}

#[cfg(test)]
impl LanTransport {
    /// Bind with a private mDNS UDP port and loopback A records (in-process tests).
    pub(crate) async fn bind_for_test(
        lan_port: u16,
        peer_port: u16,
        mdns_port: u16,
    ) -> Result<Self, TransportError> {
        Self::bind_inner(lan_port, peer_port, Some(mdns_port), false).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ephemeral_udp_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        socket.local_addr().expect("local addr").port()
    }

    fn ephemeral_tcp_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        listener.local_addr().expect("local addr").port()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn discover_sees_other_peer_port() {
        let mdns_port = ephemeral_udp_port();
        let peer_a = ephemeral_tcp_port();
        let peer_b = ephemeral_tcp_port();
        let a = LanTransport::bind_for_test(0, peer_a, mdns_port)
            .await
            .expect("bind A");
        let b = LanTransport::bind_for_test(0, peer_b, mdns_port)
            .await
            .expect("bind B");

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen_b = false;
        while Instant::now() < deadline {
            let peers = a.discover().await;
            seen_b = peers
                .iter()
                .any(|p| p.addrs.iter().any(|addr| addr.port() == peer_b));
            if seen_b {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(
            seen_b,
            "A should discover B's peer_port {peer_b} via {SHELF_MDNS_TYPE}"
        );
        drop((a, b));
    }
}
