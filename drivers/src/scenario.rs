//! Scripted runs of a star of nodes, shared by the tests and benchmarks.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use sanstun::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::net::{Network, NodeHandle, Transcript};
use crate::{Driver, NodeConfig, PeerConfig, PeerId};

/// A hub at index 0 with a tunnel to each spoke. Spoke `i` has a single tunnel, peer 0, to the
/// hub, and the hub reaches spoke `i` as peer `i - 1`.
#[derive(Debug, Clone)]
pub struct Star {
    pub nodes: Vec<NodeConfig>,
}

impl Star {
    /// Derives every key and seed from `seed`, so equal seeds give byte-identical traffic.
    pub fn new(spokes: usize, seed: u8) -> Self {
        let secret = |node: usize| {
            // x25519 clamps the first and last bytes, so the node goes in the middle.
            let mut secret = [seed; 32];
            secret[8..16].copy_from_slice(&(node as u64).to_le_bytes());
            secret
        };
        let public =
            |node: usize| PublicKey::from(&StaticSecret::from(Zeroizing::new(secret(node))));
        let node = |node: usize, peers: Vec<PeerConfig>| {
            let mut seed = secret(node);
            seed[31] ^= 0xff;

            NodeConfig {
                seed,
                static_secret: secret(node),
                unix: Duration::from_secs(1_700_000_000),
                handshake_limit: 100,
                peers,
            }
        };

        let hub = node(
            0,
            (1..=spokes)
                .map(|spoke| PeerConfig {
                    public_key: public(spoke),
                    addr: addr(spoke),
                    persistent_keepalive: None,
                })
                .collect(),
        );
        let spokes = (1..=spokes).map(|spoke| {
            node(
                spoke,
                vec![PeerConfig {
                    public_key: public(0),
                    addr: addr(0),
                    persistent_keepalive: None,
                }],
            )
        });

        Star {
            nodes: std::iter::once(hub).chain(spokes).collect(),
        }
    }

    pub fn spokes(&self) -> usize {
        self.nodes.len() - 1
    }

    pub fn addr(&self, node: usize) -> SocketAddr {
        addr(node)
    }

    /// Returns the peer `from` uses to reach `to`. One of them must be the hub.
    pub fn peer(&self, from: usize, to: usize) -> PeerId {
        match (from, to) {
            (0, spoke) => spoke - 1,
            (_, 0) => 0,
            _ => panic!("spokes only have a tunnel to the hub"),
        }
    }

    /// Spawns the network and every node with `driver`.
    pub fn spawn(&self, driver: Driver, network: crate::net::NetworkBuilder) -> Running {
        let network = (0..self.nodes.len()).fold(network, |network, i| network.node(addr(i)));
        let (network, nodes) = network.build();

        let handles = nodes
            .into_iter()
            .zip(&self.nodes)
            .map(|((io, handle), config)| {
                driver.spawn(config.clone(), io);
                handle
            })
            .collect();

        Running { network, handles }
    }
}

fn addr(node: usize) -> SocketAddr {
    let [_, _, hi, lo] = (node as u32).to_be_bytes();

    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, hi, lo), 51820))
}

pub struct Running {
    pub network: Network,
    pub handles: Vec<NodeHandle>,
}

/// One step of a scripted run.
#[derive(Debug, Clone)]
pub enum Step {
    Wait(Duration),
    /// Sends an IP packet from node `from` to node `to`. One of them must be the hub.
    Send {
        from: usize,
        to: usize,
        payload: Vec<u8>,
    },
    Cut,
    Heal,
}

/// Runs `steps` against `star` and returns the recorded transcript.
///
/// Call on a current-thread runtime with a paused clock: the run then takes as long as the
/// computation, regardless of how much time it simulates.
///
/// Inputs that coincide with a node's timer or an arriving datagram leave the order of the
/// two to the scheduler, which may legitimately differ between drivers. Keep inputs on
/// multiples of 10ms and the latency off them, so that only random handshake jitter can
/// line up with an input.
pub async fn run(driver: Driver, star: &Star, latency: Duration, steps: &[Step]) -> Transcript {
    let running = star.spawn(driver, Network::builder().latency(latency).record());

    for step in steps {
        match step {
            Step::Wait(duration) => tokio::time::sleep(*duration).await,
            Step::Send { from, to, payload } => {
                let peer = star.peer(*from, *to);
                running.handles[*from]
                    .tun_in
                    .send((peer, ip_packet(payload)))
                    .unwrap();
            }
            Step::Cut => running.network.cut(),
            Step::Heal => running.network.heal(),
        }
    }
    // Let everything in flight settle.
    tokio::time::sleep(latency + Duration::from_millis(1)).await;

    running.network.transcript()
}

/// Builds an IPv4 packet around `payload` whose header declares its length.
pub fn ip_packet(payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(20 + payload.len()).expect("payload fits in an IP packet");
    let mut packet = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ];
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet.extend_from_slice(payload);

    packet
}
