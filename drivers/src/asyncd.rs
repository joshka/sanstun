//! (d) The demultiplexer from the channels driver, feeding async tunnels.

use std::net::SocketAddr;

use sanstun::aio::{Input, Notice};
use sanstun::{Decrypted, PendingDecapsulate, PendingEncapsulate};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::peer::{AbortOnDrop, BATCH, Output, Routes, forward, ip_packet_len, now};
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

    // Stops the node once the TUN device closes.
    let tun_inboxes = inboxes.clone();
    let mut tun = tokio::spawn(crate::polls::timed(async move {
        let mut packets = Vec::with_capacity(BATCH);
        while tun_rx.recv_many(&mut packets, BATCH).await > 0 {
            for (id, packet) in packets.drain(..) {
                if forward(&tun_inboxes[id], Input::Ip(packet)).await.is_err() {
                    return;
                }
            }
        }
    }));
    let _tun = AbortOnDrop(tun.abort_handle());

    let mut datagrams = Vec::with_capacity(BATCH);
    loop {
        tokio::select! {
            biased;

            _ = &mut tun => return,
            received = udp_rx.recv_many(&mut datagrams, BATCH) => {
                if received == 0 {
                    return;
                }
                let now = now();
                for (src, datagram) in datagrams.drain(..) {
                    let Some((id, message)) =
                        routes.receive(&mut interface, src, &datagram, now, &out)
                    else {
                        continue;
                    };
                    if forward(&inboxes[id], Input::Message(message, datagram))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
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
        done: mpsc::UnboundedSender<Decrypted<Vec<u8>>>,
    ) {
        rayon::spawn(move || {
            for (pending, datagram) in batch {
                let decrypted = pending.decrypt(&datagram, crate::pool::take(datagram.len()));
                crate::pool::recycle(datagram);
                let _ = done.send(decrypted);
            }
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
