//! (b) One task per tunnel, fed by a demultiplexer over channels.
//!
//! The demultiplexer owns the [`Interface`](sanstun::Interface), which every inbound datagram
//! has to pass through for its rate limiter and replay checks, and forwards each parsed message
//! to its tunnel's task. A second task forwards IP packets from the TUN device.

use sanstun::ReceivedMessage;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::peer::{
    AbortOnDrop, BATCH, DecryptedRx, Output, Peer, Routes, forward, now, recv_decrypted,
    sleep_until,
};
use crate::{Node, NodeIo};

/// Bounds each tunnel's inbox, so a slow tunnel applies backpressure instead of buffering.
const INBOX: usize = 1024;

enum Input {
    Message(ReceivedMessage, Vec<u8>),
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

async fn tunnel(
    mut peer: Peer,
    mut inbox: mpsc::Receiver<Input>,
    out: Output,
    mut decrypted: Option<DecryptedRx>,
) {
    let mut inputs = Vec::with_capacity(BATCH);
    let mut commits = Vec::with_capacity(BATCH);
    loop {
        tokio::select! {
            biased;

            () = sleep_until(peer.poll_timeout()) => peer.handle_timeout(now(), &out),
            _ = recv_decrypted(&mut decrypted, &mut commits) => {
                let now = now();
                for (_, decrypted) in commits.drain(..) {
                    peer.commit(decrypted, now, &out);
                }
            }
            received = inbox.recv_many(&mut inputs, BATCH) => {
                if received == 0 {
                    return;
                }
                let now = now();
                for input in inputs.drain(..) {
                    match input {
                        Input::Message(message, datagram) => {
                            peer.receive(message, datagram, now, &out);
                        }
                        Input::Ip(packet) => peer.send_ip(packet, now, &out),
                    }
                }
            }
        }
        out.flush_offload();
    }
}
