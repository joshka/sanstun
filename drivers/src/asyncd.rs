//! (d) The demultiplexer from the channels driver, feeding async tunnels.

use std::net::SocketAddr;

use sanstun::aio::{Input, Notice};
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
            };
            tunnels.spawn(tunnel.into_async().run(rx, out));
            tx
        })
        .collect::<Vec<_>>();

    // Stops the node once the TUN device closes.
    let tun_inboxes = inboxes.clone();
    let mut tun = tokio::spawn(async move {
        let mut packets = Vec::with_capacity(BATCH);
        while tun_rx.recv_many(&mut packets, BATCH).await > 0 {
            for (id, packet) in packets.drain(..) {
                if forward(&tun_inboxes[id], Input::Ip(packet)).await.is_err() {
                    return;
                }
            }
        }
    });
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
}

impl sanstun::aio::Output for PeerOutput {
    fn datagram(&self, datagram: Vec<u8>) {
        self.out.datagram(self.addr, datagram);
    }

    fn ip(&self, mut buffer: Vec<u8>, len: usize) {
        buffer.truncate(ip_packet_len(&buffer[..len]));
        self.out.ip(self.id, buffer);
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
