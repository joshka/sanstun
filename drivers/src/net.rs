//! An in-memory network that connects nodes and optionally records their traffic.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;

use crate::{NodeEvent, NodeIo, PeerId};

/// Something observable at a node's boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A datagram sent by `from`, whether or not the link delivered it.
    Wire {
        from: SocketAddr,
        to: SocketAddr,
        bytes: Vec<u8>,
    },
    /// An IP packet a node decrypted.
    Tun {
        node: SocketAddr,
        peer: PeerId,
        bytes: Vec<u8>,
    },
    Event {
        node: SocketAddr,
        peer: PeerId,
        event: NodeEvent,
    },
}

/// What happened, and when relative to the start of the network.
pub type Transcript = Vec<(Duration, Record)>;

#[derive(Clone)]
struct Recorder {
    start: Instant,
    records: Arc<Mutex<Transcript>>,
}

impl Recorder {
    fn record(&self, record: Record) {
        let at = self.start.elapsed();
        self.records.lock().unwrap().push((at, record));
    }
}

/// The test's or benchmark's side of a node's TUN device.
pub struct NodeHandle {
    pub addr: SocketAddr,
    /// Sends IP packets for the node to encrypt.
    pub tun_in: UnboundedSender<(PeerId, Vec<u8>)>,
    /// Receives the packets the node decrypted, unless the network records them.
    pub tun_out: Option<UnboundedReceiver<(PeerId, Vec<u8>)>>,
    pub events: Option<UnboundedReceiver<(PeerId, NodeEvent)>>,
}

pub struct NetworkBuilder {
    latency: Duration,
    record: bool,
    nodes: Vec<SocketAddr>,
}

impl NetworkBuilder {
    /// Delays every datagram by `latency`.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = latency;
        self
    }

    /// Records traffic, decrypted packets and events into [`Network::transcript`].
    pub fn record(mut self) -> Self {
        self.record = true;
        self
    }

    pub fn node(mut self, addr: SocketAddr) -> Self {
        self.nodes.push(addr);
        self
    }

    /// Spawns the network's tasks and returns each node's IO in the order they were added.
    pub fn build(self) -> (Network, Vec<(NodeIo, NodeHandle)>) {
        let link_up = Arc::new(AtomicBool::new(true));
        let recorder = self.record.then(|| Recorder {
            start: Instant::now(),
            records: Arc::default(),
        });

        let mut inbound = Inbound::default();
        let mut nodes = Vec::new();
        let mut outbound = Vec::new();
        let mut ports = Vec::new();
        for &addr in &self.nodes {
            let port = Arc::new(AtomicU16::new(addr.port()));
            ports.push((addr, port.clone()));
            let (udp_in_tx, udp_rx) = mpsc::unbounded_channel();
            let (udp_tx, udp_out_rx) = mpsc::unbounded_channel();
            let (tun_in, tun_rx) = mpsc::unbounded_channel();
            let (tun_tx, mut tun_out) = mpsc::unbounded_channel();
            let (events_tx, mut events) = mpsc::unbounded_channel();

            inbound.insert(addr.ip(), (udp_in_tx, port.clone()));
            outbound.push((addr, port, udp_out_rx));

            let (tun_out, events) = match &recorder {
                Some(recorder) => {
                    let recorder = recorder.clone();
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                biased;

                                Some((peer, bytes)) = tun_out.recv() => {
                                    recorder.record(Record::Tun { node: addr, peer, bytes });
                                }
                                Some((peer, event)) = events.recv() => {
                                    recorder.record(Record::Event { node: addr, peer, event });
                                }
                                else => return,
                            }
                        }
                    });

                    (None, None)
                }
                None => (Some(tun_out), Some(events)),
            };

            let io = NodeIo {
                udp_rx,
                udp_tx,
                tun_rx,
                tun_tx,
                events: events_tx,
            };
            let handle = NodeHandle {
                addr,
                tun_in,
                tun_out,
                events,
            };
            nodes.push((io, handle));
        }

        let inbound = Arc::new(inbound);
        for (from, port, rx) in outbound {
            tokio::spawn(link(
                from,
                port,
                rx,
                inbound.clone(),
                self.latency,
                link_up.clone(),
                recorder.clone(),
            ));
        }

        let network = Network {
            link_up,
            recorder,
            ports,
        };

        (network, nodes)
    }
}

/// Each node's inbound datagram queue and current port, by address.
type Inbound =
    crate::pool::FastMap<IpAddr, (UnboundedSender<(SocketAddr, Vec<u8>)>, Arc<AtomicU16>)>;

/// Carries one node's outbound datagrams to their destinations.
async fn link(
    from: SocketAddr,
    port: Arc<AtomicU16>,
    mut rx: UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    inbound: Arc<Inbound>,
    latency: Duration,
    link_up: Arc<AtomicBool>,
    recorder: Option<Recorder>,
) {
    // A node only receives on its current port, as behind a NAT that rebound it.
    let deliver = |from: SocketAddr, to: SocketAddr, bytes: Vec<u8>| {
        if let Some((tx, port)) = inbound.get(&to.ip())
            && port.load(Ordering::Relaxed) == to.port()
        {
            let _ = tx.send((from, bytes));
        }
    };
    let mut in_flight = VecDeque::<(Instant, SocketAddr, SocketAddr, Vec<u8>)>::new();

    loop {
        let next_arrival = in_flight.front().map(|(at, ..)| *at);

        tokio::select! {
            biased;

            () = async {
                match next_arrival {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => {
                let (_, from, to, bytes) = in_flight.pop_front().unwrap();
                deliver(from, to, bytes);
            }
            datagram = rx.recv() => {
                let Some((to, bytes)) = datagram else { return };
                let from = SocketAddr::new(from.ip(), port.load(Ordering::Relaxed));

                if let Some(recorder) = &recorder {
                    recorder.record(Record::Wire { from, to, bytes: bytes.clone() });
                }
                if !link_up.load(Ordering::Relaxed) {
                    continue;
                }

                if latency.is_zero() {
                    deliver(from, to, bytes);
                } else {
                    in_flight.push_back((Instant::now() + latency, from, to, bytes));
                }
            }
        }
    }
}

pub struct Network {
    link_up: Arc<AtomicBool>,
    recorder: Option<Recorder>,
    /// Each node's current port.
    ports: Vec<(SocketAddr, Arc<AtomicU16>)>,
}

impl Network {
    pub fn builder() -> NetworkBuilder {
        NetworkBuilder {
            latency: Duration::ZERO,
            record: false,
            nodes: Vec::new(),
        }
    }

    /// Drops every datagram sent from now on, in both directions.
    pub fn cut(&self) {
        self.link_up.store(false, Ordering::Relaxed);
    }

    pub fn heal(&self) {
        self.link_up.store(true, Ordering::Relaxed);
    }

    /// Moves the node at `addr` to `port`, as a NAT rebinding does: it sends from the new port,
    /// and datagrams to the old one are lost.
    pub fn rebind(&self, addr: SocketAddr, port: u16) {
        let (_, current) = self
            .ports
            .iter()
            .find(|(node, _)| *node == addr)
            .expect("the node is on this network");
        current.store(port, Ordering::Relaxed);
    }

    /// Returns everything recorded so far.
    ///
    /// Records from different tasks at the same instant are ordered by node and kind, keeping
    /// the order each node produced them in. That order is what drivers must agree on.
    pub fn transcript(&self) -> Transcript {
        let recorder = self.recorder.as_ref().expect("the network records traffic");
        let mut transcript = recorder.records.lock().unwrap().clone();
        transcript.sort_by_key(|(at, record)| (*at, sort_key(record)));

        transcript
    }
}

/// Orders records by node, then kind, then the peer they concern.
fn sort_key(record: &Record) -> (SocketAddr, u8, Option<SocketAddr>, PeerId) {
    match record {
        Record::Wire { from, to, .. } => (*from, 0, Some(*to), 0),
        Record::Tun { node, peer, .. } => (*node, 1, None, *peer),
        Record::Event { node, peer, .. } => (*node, 2, None, *peer),
    }
}
