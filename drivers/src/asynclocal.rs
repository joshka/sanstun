//! (e) Async tunnels hosted in the router's own task, instead of spawned.
//!
//! The router and every [`AsyncTunnel`](sanstun::aio::AsyncTunnel) run as futures in one task,
//! with the tunnels in a [`FuturesUnordered`]. Waking a tunnel only queues its future, so
//! routing a packet costs a channel push but no switch between tasks. Like the sans-IO driver,
//! this keeps a node on one thread; shard nodes across threads to use more cores.

use futures_util::StreamExt as _;
use futures_util::stream::FuturesUnordered;
use sanstun::aio::Input;
use tokio::sync::mpsc;

use crate::asyncd::PeerOutput;
use crate::peer::{BATCH, Batches, Offloaded, Output, Routes, now, recv_offloaded};
use crate::{Node, NodeIo};

/// Bounds each tunnel's inbox. The router cannot wait for space, since the tunnel that would
/// make space runs in the same task, so it drops what does not fit, as a full socket buffer
/// would.
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

    let mut tunnels = FuturesUnordered::new();
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
            tunnels.push(tunnel.into_async().run(rx, out));
            tx
        })
        .collect::<Vec<_>>();

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
            Some(()) = tunnels.next() => {}
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
                if received == 0 {
                    return;
                }
                for (id, packet) in packets.drain(..) {
                    batches.push(id, Input::Ip(packet));
                }
            }
        }
        out.flush_offload();
        batches.try_forward(&inboxes);
    }
}
