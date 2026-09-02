//! Peer identifiers and the transport trait.
//!
//! Implementations (Tailscale, LAN, mailbox) live outside this crate.
//! Enrollment is not implemented inside any transport.

use std::future::Future;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::hexutil::define_id32;

define_id32! {
    /// Identifier of a reachable peer. Distinct from membership trust.
    pub struct PeerId;
}

/// A discovered peer. Discovery is not authorization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Peer {
    /// Peer identifier.
    pub id: PeerId,
    /// Usable dial addresses from discovery (empty if the transport has none).
    #[serde(default)]
    pub addrs: Vec<SocketAddr>,
}

impl Peer {
    /// Wrap a peer id with no addresses.
    #[must_use]
    pub const fn new(id: PeerId) -> Self {
        Self {
            id,
            addrs: Vec::new(),
        }
    }

    /// Wrap a peer id and its discovered dial addresses.
    #[must_use]
    pub const fn with_addrs(id: PeerId, addrs: Vec<SocketAddr>) -> Self {
        Self { id, addrs }
    }
}

/// Transport abstraction matching `docs/ARCHITECTURE.md`.
///
/// `discover` and `connect` are the only operations. No default implementation
/// is provided here so `shelf-core` stays transport-independent.
pub trait PeerTransport: Send + Sync {
    /// Session type returned by [`Self::connect`].
    type Connection;
    /// Transport-level error.
    type Error;

    /// Discover currently reachable peers. Results confer no membership.
    fn discover(&self) -> impl Future<Output = Vec<Peer>> + Send;

    /// Open a connection to `peer`.
    fn connect(
        &self,
        peer: PeerId,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_is_random() {
        assert_ne!(PeerId::new(), PeerId::new());
        let peer = Peer::new(PeerId::from_bytes([1; 32]));
        assert_eq!(peer.id.as_bytes(), &[1; 32]);
    }
}
