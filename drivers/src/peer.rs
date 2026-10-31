//! Per-tunnel logic shared by every driver.
//!
//! Drivers decide which task owns a [`Peer`] and when its methods run. Everything a peer does
//! in response is defined here, so drivers that call these methods in the same order produce the
//! same traffic.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Instant;

use sanstun::{
    Committed, Decrypted, Error, Event, Interface, PendingDecapsulate, PendingEncapsulate,
    PublicKey, Received, ReceivedMessage, Tunnel, TunnelId,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::pool::{self, FastMap};
use crate::{NodeEvent, NodeIo, PeerId};

/// Inputs a task takes from a channel at once.
pub(crate) const BATCH: usize = 64;

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

/// Sends to a tunnel's inbox, waiting only if it is full.
///
/// `try_send` skips the future and semaphore that `send` sets up, which is most of the cost of a
/// channel hop when the receiver keeps up.
pub(crate) async fn forward<T>(
    inbox: &tokio::sync::mpsc::Sender<T>,
    message: T,
) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
    match inbox.try_send(message) {
        Ok(()) => Ok(()),
        Err(tokio::sync::mpsc::error::TrySendError::Full(message)) => inbox.send(message).await,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(message)) => {
            Err(tokio::sync::mpsc::error::SendError(message))
        }
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
pub(crate) struct Output {
    udp: UnboundedSender<(SocketAddr, Vec<u8>)>,
    tun: UnboundedSender<(PeerId, Vec<u8>)>,
    events: UnboundedSender<(PeerId, NodeEvent)>,
    /// Crypto work batched for rayon, if this task offloads it.
    offload: Option<Offload>,
}

/// A task's batches of data messages to encrypt and decrypt on rayon's pool.
pub(crate) struct Offload {
    // Only the owning task touches these, but `&Output` crosses `.await`s, so it must be
    // `Sync`. The locks are never contended.
    encrypts: Mutex<Vec<(PendingEncapsulate, Vec<u8>, SocketAddr)>>,
    decrypts: Mutex<Vec<(PeerId, PendingDecapsulate, Vec<u8>)>>,
    /// Returns decrypted messages to the task, which owns the tunnels that commit them.
    decrypted: UnboundedSender<(PeerId, Decrypted<Vec<u8>>)>,
}

/// Decrypted messages for a task to commit.
pub(crate) type DecryptedRx = UnboundedReceiver<(PeerId, Decrypted<Vec<u8>>)>;

/// Receives decrypted messages, or never completes if the task does not offload.
pub(crate) async fn recv_decrypted(
    decrypted: &mut Option<DecryptedRx>,
    commits: &mut Vec<(PeerId, Decrypted<Vec<u8>>)>,
) -> usize {
    match decrypted {
        Some(decrypted) => decrypted.recv_many(commits, BATCH).await,
        None => std::future::pending().await,
    }
}

/// Clones share the channels but not the batches: a clone offloads nothing until it gets its
/// own [`Output::offloading`].
impl Clone for Output {
    fn clone(&self) -> Self {
        Output {
            udp: self.udp.clone(),
            tun: self.tun.clone(),
            events: self.events.clone(),
            offload: None,
        }
    }
}

impl Output {
    pub(crate) fn new(io: &NodeIo) -> Self {
        Output {
            udp: io.udp_tx.clone(),
            tun: io.tun_tx.clone(),
            events: io.events.clone(),
            offload: None,
        }
    }

    /// Returns an output that batches crypto for rayon if `offload`, and the channel that
    /// decrypted messages come back on.
    pub(crate) fn offloading(&self, offload: bool) -> (Output, Option<DecryptedRx>) {
        let mut out = self.clone();
        if !offload {
            return (out, None);
        }

        let (decrypted, rx) = tokio::sync::mpsc::unbounded_channel();
        out.offload = Some(Offload {
            encrypts: Mutex::default(),
            decrypts: Mutex::default(),
            decrypted,
        });

        (out, Some(rx))
    }

    /// Hands the batched crypto work to rayon. Call after each batch of inputs.
    pub(crate) fn flush_offload(&self) {
        let Some(offload) = &self.offload else {
            return;
        };

        let encrypts = std::mem::take(&mut *offload.encrypts.lock().unwrap());
        if !encrypts.is_empty() {
            let udp = self.udp.clone();
            rayon::spawn(move || {
                for (pending, packet, dst) in encrypts {
                    let mut buf = pool::take(packet.len().next_multiple_of(16) + 32);
                    if let Ok(len) = pending.encrypt(&packet, &mut buf).map(|m| m.len()) {
                        buf.truncate(len);
                        let _ = udp.send((dst, buf));
                    }
                    pool::recycle(packet);
                }
            });
        }

        let decrypts = std::mem::take(&mut *offload.decrypts.lock().unwrap());
        if !decrypts.is_empty() {
            let decrypted = offload.decrypted.clone();
            rayon::spawn(move || {
                for (peer, pending, datagram) in decrypts {
                    let result = pending.decrypt(&datagram, pool::take(datagram.len()));
                    pool::recycle(datagram);
                    let _ = decrypted.send((peer, result));
                }
            });
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

    /// Handles a message that [`Interface::receive`] routed to this peer, recycling its
    /// datagram.
    pub(crate) fn receive(
        &mut self,
        message: ReceivedMessage,
        datagram: Vec<u8>,
        now: Instant,
        out: &Output,
    ) {
        let result = match message {
            ReceivedMessage::TransportData(data) => self.decrypt(data, datagram, now, out),
            message => {
                pool::recycle(datagram);
                self.handle_handshake_message(message, now, out)
            }
        };
        if let Err(e) = result {
            out.error(self.id, e);
        }

        self.drain_events(now, out);
    }

    fn handle_handshake_message(
        &mut self,
        message: ReceivedMessage,
        now: Instant,
        out: &Output,
    ) -> Result<(), Error> {
        match message {
            ReceivedMessage::HandshakeInitiation(init) => self
                .tunnel
                .handle_handshake_initiation(init, now)
                .map(|response| out.datagram(self.addr, response.to_vec())),
            ReceivedMessage::HandshakeResponse(response) => self
                .tunnel
                .handle_handshake_response(response, now)
                .map(|keepalive| out.datagram(self.addr, keepalive.to_vec())),
            ReceivedMessage::CookieReply(reply) => self.tunnel.handle_cookie_reply(reply, now),
            ReceivedMessage::TransportData(_) => unreachable!("data is decrypted"),
        }
    }

    pub(crate) fn handle_timeout(&mut self, now: Instant, out: &Output) {
        self.tunnel.handle_timeout(now);
        self.drain_events(now, out);
    }

    /// Decrypts a data message, or hands it to rayon if the output offloads, in which case
    /// [`Peer::commit`] finishes it.
    fn decrypt(
        &mut self,
        data: sanstun::TransportData,
        datagram: Vec<u8>,
        now: Instant,
        out: &Output,
    ) -> Result<(), Error> {
        let pending = match self.tunnel.begin_decapsulate(data, now) {
            Ok(pending) => pending,
            Err(e) => {
                pool::recycle(datagram);
                return Err(e);
            }
        };
        if let Some(offload) = &out.offload {
            offload
                .decrypts
                .lock()
                .unwrap()
                .push((self.id, pending, datagram));
            return Ok(());
        }

        let decrypted = pending.decrypt(&datagram, pool::take(datagram.len()));
        pool::recycle(datagram);
        self.commit_decrypted(decrypted, now, out)
    }

    /// Accepts a message that rayon decrypted.
    pub(crate) fn commit(&mut self, decrypted: Decrypted<Vec<u8>>, now: Instant, out: &Output) {
        if let Err(e) = self.commit_decrypted(decrypted, now, out) {
            out.error(self.id, e);
        }

        self.drain_events(now, out);
    }

    fn commit_decrypted(
        &mut self,
        decrypted: Decrypted<Vec<u8>>,
        now: Instant,
        out: &Output,
    ) -> Result<(), Error> {
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

        if let Some(offload) = &out.offload {
            offload
                .encrypts
                .lock()
                .unwrap()
                .push((pending, packet, self.addr));
            return Ok(());
        }

        let mut buf = pool::take(packet.len().next_multiple_of(16) + 32);
        let encrypted = pending
            .encrypt(&packet, &mut buf)
            .map(|message| message.len());
        pool::recycle(packet);
        match encrypted {
            Ok(len) => {
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
    by_tunnel: FastMap<TunnelId, PeerId>,
    by_key: FastMap<PublicKey, PeerId>,
}

impl Routes {
    pub(crate) fn new<'a>(peers: impl IntoIterator<Item = &'a Peer>) -> Self {
        let mut routes = Routes {
            by_tunnel: FastMap::default(),
            by_key: FastMap::default(),
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
