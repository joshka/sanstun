//! Per-tunnel logic shared by every driver.
//!
//! Drivers decide which task owns a [`Peer`] and when its methods run. Everything a peer does
//! in response is defined here, so drivers that call these methods in the same order produce the
//! same traffic.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Instant;

use sanstun::{
    Committed, Error, Event, Interface, PublicKey, Received, ReceivedMessage, Tunnel, TunnelId,
};
use tokio::sync::mpsc::UnboundedSender;

use crate::{NodeEvent, NodeIo, PeerId};

/// Packets queued per peer while a handshake is in progress. WireGuard's reference
/// implementations also queue a small number of packets per peer.
const MAX_PENDING: usize = 64;

/// The current time on tokio's clock, which tests pause and advance.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

pub(crate) async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

/// Aborts a task when dropped.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Where a peer sends its output. Cloned into every task that handles peers.
#[derive(Clone)]
pub(crate) struct Output {
    udp: UnboundedSender<(SocketAddr, Vec<u8>)>,
    tun: UnboundedSender<(PeerId, Vec<u8>)>,
    events: UnboundedSender<(PeerId, NodeEvent)>,
}

impl Output {
    pub(crate) fn new(io: &NodeIo) -> Self {
        Output {
            udp: io.udp_tx.clone(),
            tun: io.tun_tx.clone(),
            events: io.events.clone(),
        }
    }

    pub(crate) fn datagram(&self, dst: SocketAddr, bytes: Vec<u8>) {
        // The receiving end only closes when the node is shutting down.
        let _ = self.udp.send((dst, bytes));
    }

    pub(crate) fn event(&self, peer: PeerId, event: NodeEvent) {
        let _ = self.events.send((peer, event));
    }

    pub(crate) fn error(&self, peer: PeerId, error: Error) {
        self.event(peer, NodeEvent::Error(format!("{error:?}")));
    }

    pub(crate) fn ip(&self, peer: PeerId, packet: Vec<u8>) {
        let _ = self.tun.send((peer, packet));
    }
}

pub(crate) struct Peer {
    id: PeerId,
    addr: SocketAddr,
    tunnel: Tunnel,
    pending: VecDeque<Vec<u8>>,
}

impl Peer {
    pub(crate) fn new(id: PeerId, addr: SocketAddr, tunnel: Tunnel) -> Self {
        Peer {
            id,
            addr,
            tunnel,
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn id(&self) -> PeerId {
        self.id
    }

    pub(crate) fn into_parts(self) -> (PeerId, SocketAddr, Tunnel) {
        (self.id, self.addr, self.tunnel)
    }

    pub(crate) fn tunnel_id(&self) -> TunnelId {
        self.tunnel.id()
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        self.tunnel.remote_static_public()
    }

    pub(crate) fn poll_timeout(&self) -> Option<Instant> {
        self.tunnel.poll_timeout()
    }

    /// Encrypts an IP packet, or queues it and starts a handshake if there is no session.
    pub(crate) fn send_ip(&mut self, packet: Vec<u8>, now: Instant, out: &Output) {
        if !self.pending.is_empty() {
            self.queue(packet, now, out);
        } else if let Err(packet) = self.encrypt(packet, now, out) {
            self.queue(packet, now, out);
        }

        self.drain_events(now, out);
    }

    /// Handles a message that [`Interface::receive`] routed to this peer.
    pub(crate) fn receive(
        &mut self,
        message: ReceivedMessage,
        datagram: &[u8],
        now: Instant,
        out: &Output,
    ) {
        let result = match message {
            ReceivedMessage::HandshakeInitiation(init) => self
                .tunnel
                .handle_handshake_initiation(init, now)
                .map(|response| out.datagram(self.addr, response.to_vec())),
            ReceivedMessage::HandshakeResponse(response) => self
                .tunnel
                .handle_handshake_response(response, now)
                .map(|keepalive| out.datagram(self.addr, keepalive.to_vec())),
            ReceivedMessage::CookieReply(reply) => self.tunnel.handle_cookie_reply(reply, now),
            ReceivedMessage::TransportData(data) => self.decrypt(data, datagram, now, out),
        };
        if let Err(e) = result {
            out.error(self.id, e);
        }

        self.drain_events(now, out);
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant, out: &Output) {
        self.tunnel.handle_timeout(now);
        self.drain_events(now, out);
    }

    fn decrypt(
        &mut self,
        data: sanstun::TransportData,
        datagram: &[u8],
        now: Instant,
        out: &Output,
    ) -> Result<(), Error> {
        let decrypted = self
            .tunnel
            .begin_decapsulate(data, now)?
            .decrypt(datagram, vec![0; datagram.len()]);

        match self.tunnel.commit_decapsulate(decrypted, now)? {
            Committed::Data { mut buffer, len } => {
                buffer.truncate(ip_packet_len(&buffer[..len]));
                out.ip(self.id, buffer);
            }
            Committed::Keepalive => {}
        }

        Ok(())
    }

    /// Encrypts and sends a packet, returning it if there is no session to encrypt it with.
    fn encrypt(&mut self, packet: Vec<u8>, now: Instant, out: &Output) -> Result<(), Vec<u8>> {
        let pending = match self.tunnel.begin_encapsulate(now) {
            Ok(pending) => pending,
            Err(Error::NoCurrentSession) => return Err(packet),
            Err(e) => {
                out.error(self.id, e);
                return Ok(());
            }
        };

        let mut buf = vec![0; packet.len().next_multiple_of(16) + 32];
        match pending.encrypt(&packet, &mut buf) {
            Ok(message) => {
                let len = message.len();
                buf.truncate(len);
                out.datagram(self.addr, buf);
            }
            Err(e) => out.error(self.id, e),
        }

        Ok(())
    }

    fn queue(&mut self, packet: Vec<u8>, now: Instant, out: &Output) {
        if self.pending.len() == MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(packet);

        if let Some(init) = self.tunnel.initiate_handshake(now) {
            out.datagram(self.addr, init.to_vec());
        }
    }

    /// Forwards the tunnel's events, then sends queued packets if a session is available.
    fn drain_events(&mut self, now: Instant, out: &Output) {
        while let Some(event) = self.tunnel.poll_event() {
            match event {
                Event::SendHandshakeInitiation(datagram) | Event::SendKeepalive(datagram) => {
                    out.datagram(self.addr, datagram.to_vec());
                }
                Event::Established { .. } => out.event(self.id, NodeEvent::Established),
                Event::ConnectionExpired => {
                    self.pending.clear();
                    out.event(self.id, NodeEvent::Expired);
                }
            }
        }

        while let Some(packet) = self.pending.pop_front() {
            if let Err(packet) = self.encrypt(packet, now, out) {
                self.pending.push_front(packet);
                break;
            }
        }
    }
}

/// Finds the peer for each message from [`Interface::receive`].
pub(crate) struct Routes {
    by_tunnel: HashMap<TunnelId, PeerId>,
    by_key: HashMap<PublicKey, PeerId>,
}

impl Routes {
    pub(crate) fn new<'a>(peers: impl IntoIterator<Item = &'a Peer>) -> Self {
        let mut routes = Routes {
            by_tunnel: HashMap::new(),
            by_key: HashMap::new(),
        };
        for peer in peers {
            routes.by_tunnel.insert(peer.tunnel_id(), peer.id());
            routes.by_key.insert(peer.public_key(), peer.id());
        }

        routes
    }

    /// Parses a datagram, answering cookie replies and reporting errors directly.
    ///
    /// Returns the peer to pass the message to. Errors before routing are reported for the
    /// peer at `src` if there is one, otherwise they are dropped like traffic from strangers.
    pub(crate) fn receive(
        &self,
        interface: &mut Interface,
        src: SocketAddr,
        datagram: &[u8],
        now: Instant,
        out: &Output,
    ) -> Option<(PeerId, ReceivedMessage)> {
        let message = match interface.receive(src, datagram, now) {
            Ok(Received::Message(message)) => message,
            Ok(Received::SendCookieReply(reply)) => {
                out.datagram(src, reply.to_vec());
                return None;
            }
            Err(_) => return None,
        };

        let peer = match &message {
            ReceivedMessage::HandshakeInitiation(init) => {
                self.by_key.get(&init.peer_static_public())
            }
            ReceivedMessage::HandshakeResponse(response) => {
                self.by_tunnel.get(&response.tunnel_id())
            }
            ReceivedMessage::CookieReply(reply) => self.by_tunnel.get(&reply.tunnel_id()),
            ReceivedMessage::TransportData(data) => self.by_tunnel.get(&data.tunnel_id()),
        }?;

        Some((*peer, message))
    }
}

/// Returns the length of an IP packet, excluding WireGuard's zero padding.
///
/// Falls back to the whole buffer for anything that is not IPv4 or IPv6.
pub fn ip_packet_len(buffer: &[u8]) -> usize {
    let declared = match buffer.first().map(|b| b >> 4) {
        Some(4) if buffer.len() >= 4 => usize::from(u16::from_be_bytes([buffer[2], buffer[3]])),
        Some(6) if buffer.len() >= 6 => {
            40 + usize::from(u16::from_be_bytes([buffer[4], buffer[5]]))
        }
        _ => buffer.len(),
    };

    declared.min(buffer.len())
}
