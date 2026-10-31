//! (a) One task owns all state, as sans-IO intends.

use std::collections::BTreeSet;
use std::time::Instant;

use crate::peer::{Output, Peer, Routes, now, sleep_until};
use crate::{Node, NodeIo, PeerId};

pub(crate) async fn run(node: Node, mut io: NodeIo) {
    let Node {
        mut interface,
        mut peers,
    } = node;
    let out = Output::new(&io);
    let routes = Routes::new(&peers);
    let mut timers = Timers::new(&peers);

    loop {
        tokio::select! {
            biased;

            () = sleep_until(timers.next()) => {
                let now = now();
                while let Some(id) = timers.pop_due(now) {
                    peers[id].handle_timeout(now, &out);
                    timers.update(&peers[id]);
                }
            }
            datagram = io.udp_rx.recv() => {
                let Some((src, datagram)) = datagram else { return };
                let now = now();
                if let Some((id, message)) =
                    routes.receive(&mut interface, src, &datagram, now, &out)
                {
                    peers[id].receive(message, &datagram, now, &out);
                    timers.update(&peers[id]);
                }
            }
            packet = io.tun_rx.recv() => {
                let Some((id, packet)) = packet else { return };
                peers[id].send_ip(packet, now(), &out);
                timers.update(&peers[id]);
            }
        }
    }
}

/// Each peer's next deadline, ordered so the earliest is found without scanning every peer.
struct Timers {
    deadlines: Vec<Option<Instant>>,
    queue: BTreeSet<(Instant, PeerId)>,
}

impl Timers {
    fn new(peers: &[Peer]) -> Self {
        let mut timers = Timers {
            deadlines: vec![None; peers.len()],
            queue: BTreeSet::new(),
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
