//! (d) The demultiplexer from the channels driver, feeding async tunnels.

use std::net::SocketAddr;

use sanstun::aio::{Input, Notice};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::peer::{AbortOnDrop, Output, Routes, ip_packet_len, now};
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
        while let Some((id, packet)) = tun_rx.recv().await {
            if tun_inboxes[id].send(Input::Ip(packet)).await.is_err() {
                return;
            }
        }
    });
    let _tun = AbortOnDrop(tun.abort_handle());

    loop {
        tokio::select! {
            biased;

            _ = &mut tun => return,
            datagram = udp_rx.recv() => {
                let Some((src, datagram)) = datagram else { return };
                let Some((id, message)) =
                    routes.receive(&mut interface, src, &datagram, now(), &out)
                else {
                    continue;
                };
                if inboxes[id].send(Input::Message(message, datagram)).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Addresses one tunnel's output to its peer.
struct PeerOutput {
    id: PeerId,
    addr: SocketAddr,
    out: Output,
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
