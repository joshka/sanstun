//! (d) The demultiplexer from the channels driver, feeding async tunnels.

use std::net::SocketAddr;

use sanstun::aio::{self, Input, Notice};
use sanstun::{PendingDecapsulate, PendingEncapsulate, PendingResponse};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::peer::{BATCH, Batches, Offloaded, Output, Routes, ip_packet_len, now, recv_offloaded};
use crate::{Node, NodeEvent, NodeIo, PeerId};

/// Bounds each tunnel's inbox, so a slow tunnel applies backpressure instead of buffering.
const INBOX: usize = 1024;

pub(crate) async fn run(node: Node, io: NodeIo) {
    let Node {
        mut interface,
        peers,
        offload,
    } = node;
    let out = Output::new(&io);
    let NodeIo {
        mut udp_rx,
        mut tun_rx,
        ..
    } = io;
    let routes = Routes::new(&peers);

    // Dropping the set when the node stops aborts the tunnel tasks.
    let mut tunnels = JoinSet::new();
    let inboxes = peers
        .into_iter()
        .map(|peer| {
            let (id, addr, tunnel) = peer.into_parts();
            let (tx, rx) = mpsc::channel(INBOX);
            let out = PeerOutput {
                id,
                addr,
                out: out.clone(),
                offload,
            };
            tunnels.spawn(crate::polls::timed(tunnel.into_async().run(rx, out)));
            tx
        })
        .collect::<Vec<_>>();

    // One router reads both the network and the TUN device, and forwards what it read to
    // each tunnel as a single batch.
    // The router parses initiations on rayon if offloading; tunnels offload the rest.
    let (mut out, mut offloaded) = out.offloading(offload);
    let mut batches = Batches::new(inboxes.len());
    let mut datagrams = Vec::with_capacity(BATCH);
    let mut packets = Vec::with_capacity(BATCH);
    let mut parsed = Vec::with_capacity(BATCH);
    loop {
        tokio::select! {
            biased;

            _ = recv_offloaded(&mut offloaded, &mut parsed) => {
                for done in parsed.drain(..) {
                    if let Offloaded::Initiation(Ok(init)) = done
                        && let Some((id, message)) = routes.accept(&mut interface, init)
                    {
                        batches.push(id, Input::Message(message, Vec::new()));
                    }
                }
            }
            received = udp_rx.recv_many(&mut datagrams, BATCH) => {
                if received == 0 {
                    return;
                }
                let now = now();
                for (src, datagram) in datagrams.drain(..) {
                    if let Some((id, message)) =
                        routes.receive(&mut interface, src, &datagram, now, &mut out)
                    {
                        batches.push(id, Input::Message(message, datagram));
                    }
                }
            }
            received = tun_rx.recv_many(&mut packets, BATCH) => {
                // The node stops once the TUN device closes.
                if received == 0 {
                    return;
                }
                for (id, packet) in packets.drain(..) {
                    batches.push(id, Input::Ip(packet));
                }
            }
        }
        out.flush_offload();
        if batches.forward(&inboxes).await.is_err() {
            return;
        }
    }
}

/// Addresses one tunnel's output to its peer.
pub(crate) struct PeerOutput {
    pub(crate) id: PeerId,
    pub(crate) addr: SocketAddr,
    pub(crate) out: Output,
    /// Encrypts and decrypts on rayon's pool.
    pub(crate) offload: bool,
}

impl sanstun::aio::Output for PeerOutput {
    fn datagram(&self, datagram: Vec<u8>) {
        self.out.datagram(self.addr, datagram);
    }

    fn ip(&self, mut buffer: Vec<u8>, len: usize) {
        buffer.truncate(ip_packet_len(&buffer[..len]));
        self.out.ip(self.id, buffer);
    }

    fn buffer(&self, len: usize) -> Vec<u8> {
        crate::pool::take(len)
    }

    fn recycle(&self, buffer: Vec<u8>) {
        crate::pool::recycle(buffer);
    }

    fn offloads(&self) -> bool {
        self.offload
    }

    fn offload_encrypt(&self, batch: Vec<(PendingEncapsulate, Vec<u8>)>) {
        let (out, addr) = (self.out.clone(), self.addr);
        rayon::spawn(move || {
            for (pending, packet) in batch {
                let mut buf = crate::pool::take(packet.len().next_multiple_of(16) + 32);
                if let Ok(len) = pending.encrypt(&packet, &mut buf).map(|m| m.len()) {
                    buf.truncate(len);
                    out.datagram(addr, buf);
                }
                crate::pool::recycle(packet);
            }
        });
    }

    fn offload_decrypt(
        &self,
        batch: Vec<(PendingDecapsulate, Vec<u8>)>,
        done: mpsc::UnboundedSender<aio::Offloaded>,
    ) {
        rayon::spawn(move || {
            for (pending, datagram) in batch {
                let decrypted = pending.decrypt(&datagram, crate::pool::take(datagram.len()));
                crate::pool::recycle(datagram);
                let _ = done.send(aio::Offloaded::Decrypted(decrypted));
            }
        });
    }

    fn offload_response(
        &self,
        pending: PendingResponse,
        done: mpsc::UnboundedSender<aio::Offloaded>,
    ) {
        rayon::spawn(move || {
            let _ = done.send(aio::Offloaded::Response(pending.compute().map(Box::new)));
        });
    }

    fn notice(&self, notice: Notice) {
        let event = match notice {
            Notice::Established => NodeEvent::Established,
            Notice::Expired => NodeEvent::Expired,
            Notice::Error(e) => NodeEvent::Error(format!("{e:?}")),
        };
        self.out.event(self.id, event);
    }
}
