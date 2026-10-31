//! (a) One task owns all state, as sans-IO intends.
//!
//! Modelled on Firezone's own event loop: a hand-written poll function that drains every ready
//! input in batches, keeps one timer for the earliest deadline, and yields after a budget of
//! iterations so that other tasks get to run.

use std::collections::BTreeSet;
use std::future::Future as _;
use std::pin::pin;
use std::task::Poll;
use std::time::Instant;

use crate::peer::{BATCH, Offloaded, Output, Peer, Routes, now};
use crate::{Node, NodeIo, PeerId};

/// Iterations before the loop yields to other tasks.
const BUDGET: usize = 16;

pub(crate) async fn run(node: Node, mut io: NodeIo) {
    let Node {
        mut interface,
        mut peers,
        offload,
    } = node;
    let (mut out, mut offloaded) = Output::new(&io).offloading(offload);
    let routes = Routes::new(&peers);
    let mut timers = Timers::new(&peers);
    let mut timer = pin!(tokio::time::sleep_until(tokio::time::Instant::now()));
    let mut timer_at = None;
    let mut datagrams = Vec::with_capacity(BATCH);
    let mut packets = Vec::with_capacity(BATCH);
    let mut commits = Vec::with_capacity(BATCH);

    std::future::poll_fn(|cx| {
        for _ in 0..BUDGET {
            let mut progress = false;

            if let Some(next) = timers.next() {
                if timer_at != Some(next) {
                    timer.as_mut().reset(next.into());
                    timer_at = Some(next);
                }
                if timer.as_mut().poll(cx).is_ready() {
                    let now = now();
                    while let Some(id) = timers.pop_due(now) {
                        peers[id].handle_timeout(now, &mut out);
                        timers.update(&peers[id]);
                    }
                    timer_at = None;
                    progress = true;
                }
            }

            match io.udp_rx.poll_recv_many(cx, &mut datagrams, BATCH) {
                Poll::Ready(0) => return Poll::Ready(()),
                Poll::Ready(_) => {
                    let now = now();
                    for (src, datagram) in datagrams.drain(..) {
                        if let Some((id, message)) =
                            routes.receive(&mut interface, src, &datagram, now, &mut out)
                        {
                            peers[id].receive(message, datagram, now, &mut out);
                            timers.touch(id);
                        }
                    }
                    progress = true;
                }
                Poll::Pending => {}
            }

            match io.tun_rx.poll_recv_many(cx, &mut packets, BATCH) {
                Poll::Ready(0) => return Poll::Ready(()),
                Poll::Ready(_) => {
                    let now = now();
                    for (id, packet) in packets.drain(..) {
                        peers[id].send_ip(packet, now, &mut out);
                        timers.touch(id);
                    }
                    progress = true;
                }
                Poll::Pending => {}
            }

            if let Some(offloaded) = &mut offloaded
                && let Poll::Ready(received) = offloaded.poll_recv_many(cx, &mut commits, BATCH)
                && received > 0
            {
                let now = now();
                for done in commits.drain(..) {
                    if let Some(id) = done.peer() {
                        peers[id].commit(done, now, &mut out);
                        timers.touch(id);
                    } else if let Offloaded::Initiation(Ok(init)) = done
                        && let Some((id, message)) = routes.accept(&mut interface, init)
                    {
                        peers[id].receive(message, Vec::new(), now, &mut out);
                        timers.touch(id);
                    }
                }
                progress = true;
            }
            out.flush_offload();

            // Ask touched tunnels for their deadlines once per batch rather than per packet.
            timers.update_touched(&peers);

            if !progress {
                return Poll::Pending;
            }
        }

        // Out of budget with work left: run again after other tasks.
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await
}

/// Each peer's next deadline, ordered so the earliest is found without scanning every peer.
struct Timers {
    deadlines: Vec<Option<Instant>>,
    queue: BTreeSet<(Instant, PeerId)>,
    /// Peers whose deadlines may have changed since the last update.
    touched: Vec<PeerId>,
    is_touched: Vec<bool>,
}

impl Timers {
    fn new(peers: &[Peer]) -> Self {
        let mut timers = Timers {
            deadlines: vec![None; peers.len()],
            queue: BTreeSet::new(),
            touched: Vec::new(),
            is_touched: vec![false; peers.len()],
        };
        for peer in peers {
            timers.update(peer);
        }

        timers
    }

    fn next(&self) -> Option<Instant> {
        self.queue.first().map(|(at, _)| *at)
    }

    fn pop_due(&mut self, now: Instant) -> Option<PeerId> {
        let &(at, id) = self.queue.first()?;
        if at > now {
            return None;
        }
        self.queue.pop_first();
        self.deadlines[id] = None;

        Some(id)
    }

    fn touch(&mut self, id: PeerId) {
        if !std::mem::replace(&mut self.is_touched[id], true) {
            self.touched.push(id);
        }
    }

    fn update_touched(&mut self, peers: &[Peer]) {
        let mut touched = std::mem::take(&mut self.touched);
        for id in touched.drain(..) {
            self.is_touched[id] = false;
            self.update(&peers[id]);
        }
        self.touched = touched;
    }

    fn update(&mut self, peer: &Peer) {
        let id = peer.id();
        let deadline = peer.poll_timeout();
        if self.deadlines[id] == deadline {
            return;
        }

        if let Some(old) = self.deadlines[id] {
            self.queue.remove(&(old, id));
        }
        if let Some(new) = deadline {
            self.queue.insert((new, id));
        }
        self.deadlines[id] = deadline;
    }
}
