//! Event loops that drive sanstun nodes over an in-memory network.
//!
//! Each [`Driver`] runs the same WireGuard node with a different concurrency design:
//!
//! - [`Driver::SansIo`]: one task owns the [`Interface`] and every [`Tunnel`] and selects over
//!   the network, the TUN device and the earliest tunnel deadline.
//! - [`Driver::Channels`]: a demultiplexer task owns the [`Interface`] and forwards parsed
//!   messages over channels to one task per tunnel.
//! - [`Driver::Mutex`]: tasks for the network, the TUN device and each tunnel's timers share the
//!   [`Interface`] and tunnels behind mutexes.
//!
//! The drivers share the per-tunnel logic in [`peer`], so they differ only in how state is
//! shared and how work is scheduled. Given the same seeds and the same schedule of inputs, they
//! must produce byte-identical traffic. The tests in `tests/equivalence.rs` check this under
//! tokio's paused clock.
//!
//! [`Tunnel`]: sanstun::Tunnel

use std::net::SocketAddr;
use std::time::Duration;

use sanstun::{Interface, PublicKey, StaticSecret, Tunnel, TunnelConfig};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

mod channels;
mod mutex;
pub mod net;
mod peer;
pub mod polls;
pub mod pool;
pub use peer::ip_packet_len;
mod sansio;
pub mod scenario;

/// Identifies a peer by its position in [`NodeConfig::peers`].
pub type PeerId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Driver {
    SansIo,
    Channels,
    Mutex,
}

impl Driver {
    pub const ALL: [Driver; 3] = [Driver::SansIo, Driver::Channels, Driver::Mutex];

    pub fn name(self) -> &'static str {
        match self {
            Driver::SansIo => "sans-io",
            Driver::Channels => "channels",
            Driver::Mutex => "mutex",
        }
    }

    /// Spawns a node on the current tokio runtime.
    pub fn spawn(self, config: NodeConfig, io: NodeIo) -> JoinHandle<()> {
        let node = Node::new(config);

        match self {
            Driver::SansIo => tokio::spawn(polls::timed(sansio::run(node, io))),
            Driver::Channels => tokio::spawn(polls::timed(channels::run(node, io))),
            Driver::Mutex => tokio::spawn(polls::timed(mutex::run(node, io))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Seeds the interface's random number generator, which derives all keys and nonces.
    pub seed: [u8; 32],
    pub static_secret: [u8; 32],
    /// The Unix time at the node's start, used for handshake timestamps.
    pub unix: Duration,
    pub handshake_limit: u64,
    pub peers: Vec<PeerConfig>,
    /// Encrypts and decrypts data messages on rayon's thread pool instead of in the tasks that
    /// own the tunnels.
    pub offload: bool,
}

impl NodeConfig {
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&StaticSecret::from(Zeroizing::new(self.static_secret)))
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    pub addr: SocketAddr,
    pub persistent_keepalive: Option<Duration>,
}

/// The node's side of its network and TUN device.
pub struct NodeIo {
    /// Datagrams from the network, with their source address.
    pub udp_rx: UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    /// Datagrams to the network, with their destination address.
    pub udp_tx: UnboundedSender<(SocketAddr, Vec<u8>)>,
    /// IP packets to encrypt, already routed to a peer.
    pub tun_rx: UnboundedReceiver<(PeerId, Vec<u8>)>,
    /// Decrypted IP packets, with the peer that sent them.
    pub tun_tx: UnboundedSender<(PeerId, Vec<u8>)>,
    pub events: UnboundedSender<(PeerId, NodeEvent)>,
}

/// Something a node reports besides traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    Established,
    Expired,
    /// An error from sanstun, formatted with `Debug`.
    Error(String),
}

/// The state every driver starts from.
pub(crate) struct Node {
    interface: Interface,
    peers: Vec<peer::Peer>,
    offload: bool,
}

impl Node {
    fn new(config: NodeConfig) -> Self {
        let now = peer::now();
        let mut interface = Interface::new(Zeroizing::new(config.seed), now, config.unix)
            .with_static_private(StaticSecret::from(Zeroizing::new(config.static_secret)))
            .with_handshake_limit(config.handshake_limit);
        let peers = config
            .peers
            .iter()
            .enumerate()
            .map(|(id, peer)| {
                let mut tunnel_config = TunnelConfig::default();
                if let Some(interval) = peer.persistent_keepalive {
                    tunnel_config = tunnel_config.with_persistent_keepalive(interval);
                }
                let mut tunnel: Tunnel = interface
                    .new_tunnel(peer.public_key, tunnel_config, now)
                    .expect("peer keys are valid");
                tunnel.set_defer_handshake_crypto(config.offload);

                peer::Peer::new(id, peer.addr, tunnel)
            })
            .collect();

        Node {
            interface,
            peers,
            offload: config.offload,
        }
    }
}
