//! (c) Tasks share the interface and tunnels behind mutexes.
//!
//! One task reads the network and one reads the TUN device; each locks the state it needs.
//! Each tunnel also has a timer task, which inputs wake whenever they may have moved the
//! tunnel's deadline.

use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::peer::{AbortOnDrop, BATCH, Output, Peer, Routes, now, sleep_until};
use crate::{Node, NodeIo};

struct Shared {
    peer: Mutex<Peer>,
    /// Signals that the deadline may have changed.
    deadline_changed: Notify,
}

pub(crate) async fn run(node: Node, io: NodeIo) {
    let Node { interface, peers } = node;
    let out = Output::new(&io);
    let NodeIo {
        mut udp_rx,
        mut tun_rx,
        ..
    } = io;
    let routes = Arc::new(Routes::new(&peers));
    let interface = Arc::new(Mutex::new(interface));
    let peers = peers
        .into_iter()
        .map(|peer| {
            Arc::new(Shared {
                peer: Mutex::new(peer),
                deadline_changed: Notify::new(),
            })
        })
        .collect::<Arc<[_]>>();

    // Dropping the set when the node stops aborts the other tasks.
    let mut tasks = JoinSet::new();
    for shared in peers.iter() {
        tasks.spawn(timer(shared.clone(), out.clone()));
    }

    // Stops the node once the TUN device closes.
    let mut tun = tokio::spawn({
        let peers = peers.clone();
        let out = out.clone();
        async move {
            let mut packets = Vec::with_capacity(BATCH);
            while tun_rx.recv_many(&mut packets, BATCH).await > 0 {
                let now = now();
                for (id, packet) in packets.drain(..) {
                    let shared = &peers[id];
                    shared.peer.lock().unwrap().send_ip(packet, now, &out);
                    shared.deadline_changed.notify_one();
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
                    let routed =
                        routes.receive(&mut interface.lock().unwrap(), src, &datagram, now, &out);
                    if let Some((id, message)) = routed {
                        let shared = &peers[id];
                        shared
                            .peer
                            .lock()
                            .unwrap()
                            .receive(message, &datagram, now, &out);
                        shared.deadline_changed.notify_one();
                    }
                }
            }
        }
    }
}

async fn timer(shared: Arc<Shared>, out: Output) {
    loop {
        let deadline = shared.peer.lock().unwrap().poll_timeout();

        tokio::select! {
            biased;

            () = sleep_until(deadline) => {
                shared.peer.lock().unwrap().handle_timeout(now(), &out);
            }
            () = shared.deadline_changed.notified() => {}
        }
    }
}
