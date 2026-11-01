//! (b) One task per tunnel, fed by a demultiplexer over channels.
//!
//! The demultiplexer owns the [`Interface`](sanstun::Interface), which every inbound datagram
//! has to pass through for its rate limiter and replay checks. It also reads IP packets from the
//! TUN device, and forwards each tunnel's inputs to its task in batches.

use sanstun::ReceivedMessage;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::peer::{
    BATCH, Batches, Offloaded, OffloadedRx, Output, Peer, Routes, now, recv_offloaded, sleep_until,
};
use crate::{Node, NodeIo};

/// Bounds each tunnel's inbox, so a slow tunnel applies backpressure instead of buffering.
const INBOX: usize = 1024;

enum Input {
    Message(ReceivedMessage, Vec<u8>, std::net::SocketAddr),
    Ip(Vec<u8>),
}

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
            let (tx, rx) = mpsc::channel(INBOX);
            let (out, decrypted) = out.offloading(offload);
            tunnels.spawn(crate::polls::timed(tunnel(peer, rx, out, decrypted)));
            tx
        })
        .collect::<Vec<_>>();

    // One router reads both the network and the TUN device, and forwards what it read to
    // each tunnel as a single batch.
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
                    if let Offloaded::Initiation(Ok(init), src) = done
                        && let Some((id, message)) = routes.accept(&mut interface, init)
                    {
                        batches.push(id, Input::Message(message, Vec::new(), src));
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
                        batches.push(id, Input::Message(message, datagram, src));
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

async fn tunnel(
    mut peer: Peer,
    mut inbox: mpsc::Receiver<Vec<Input>>,
    mut out: Output,
    mut offloaded: Option<OffloadedRx>,
) {
    let mut inputs = Vec::with_capacity(BATCH);
    let mut commits = Vec::with_capacity(BATCH);
    loop {
        tokio::select! {
            biased;

            () = sleep_until(peer.poll_timeout()) => peer.handle_timeout(now(), &mut out),
            _ = recv_offloaded(&mut offloaded, &mut commits) => {
                let now = now();
                for done in commits.drain(..) {
                    peer.commit(done, now, &mut out);
                }
            }
            received = inbox.recv_many(&mut inputs, BATCH) => {
                if received == 0 {
                    return;
                }
                let now = now();
                for input in inputs.drain(..).flatten() {
                    match input {
                        Input::Message(message, datagram, src) => {
                            peer.receive(message, datagram, src, now, &mut out);
                        }
                        Input::Ip(packet) => peer.send_ip(packet, now, &mut out),
                    }
                }
            }
        }
        out.flush_offload();
    }
}
