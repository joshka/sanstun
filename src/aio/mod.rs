//! Tunnels that run WireGuard's timers as async timers.
//!
//! An [`AsyncTunnel`] owns its state in a single task. Every timer from the
//! [whitepaper](https://www.wireguard.com/papers/wireguard.pdf) (§6) is a named [`Timer`], armed
//! and disarmed by the protocol events that the whitepaper ties it to:
//!
//! | Timer                  | Armed when                         | Disarmed when                 |
//! | ---------------------- | ---------------------------------- | ----------------------------- |
//! | `retransmit_handshake` | an initiation is sent              | a handshake completes         |
//! | `send_keepalive`       | data arrives without a reply       | any packet is sent            |
//! | `new_handshake`        | data is sent without a reply       | any packet arrives            |
//! | `persistent_keepalive` | any packet is sent or arrives      |                               |
//! | `zero_key_material`    | a session is derived               |                               |
//!
//! Rekeying by age or message count happens on sending or receiving, as §6.2 describes, so it
//! needs no timer. [`AsyncTunnel::run`] selects over the inbox and the timers and handles
//! whichever is ready.
//!
//! The tunnel is an actor: it owns its state, and the rest of the program talks to it through
//! its inbox and [`Output`].
//!
//! - [`timers`]: the timers and the events that arm and disarm them.
//! - [`send`]: encrypting data, or queueing it behind a handshake.
//! - [`receive`]: decrypting data.
//! - [`handshake`]: initiating, answering and completing handshakes.

mod handshake;
mod receive;
mod send;
mod timers;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::handshake::Handshake;
use crate::handshake::{ComputedResponse, PendingResponse};
use crate::message::DATA_OVERHEAD_SZ;
use crate::message::ReceivedMessage;
use crate::rng::ForwardSecureRng;
use crate::session::Sessions;
use crate::session::{Decrypted, PendingDecapsulate, PendingEncapsulate};
use crate::timers::TimerName;
use crate::{Error, Tunnel};
use timers::Timers;

/// Packets queued while a handshake is in progress.
const MAX_PENDING: usize = 64;

/// Inputs taken from the inbox at once.
const BATCH: usize = 64;

/// Something for an [`AsyncTunnel`] to handle.
pub enum Input {
    /// A message that [`Interface::receive`](crate::Interface::receive) routed to this tunnel,
    /// with the datagram it came from.
    Message(ReceivedMessage, Vec<u8>),
    /// An IP packet to encrypt and send to the peer.
    Ip(Vec<u8>),
}

/// Something an [`AsyncTunnel`] reports besides traffic.
#[derive(Debug)]
pub enum Notice {
    Established,
    /// The connection expired. The tunnel answers further inputs with errors.
    Expired,
    Error(Error),
}

/// Where an [`AsyncTunnel`] sends its output.
pub trait Output {
    /// Sends a datagram to the peer.
    fn datagram(&self, datagram: Vec<u8>);
    /// Delivers a decrypted packet: the first `len` bytes of `buffer`, including padding.
    fn ip(&self, buffer: Vec<u8>, len: usize);
    fn notice(&self, notice: Notice);

    /// Returns a buffer of `len` bytes for encrypting or decrypting into. Its contents are
    /// overwritten.
    fn buffer(&self, len: usize) -> Vec<u8> {
        vec![0; len]
    }

    /// Takes back a buffer the tunnel is done with, such as a decrypted datagram.
    fn recycle(&self, buffer: Vec<u8>) {
        drop(buffer);
    }

    /// Returns whether to hand data messages to [`Output::offload_encrypt`] and
    /// [`Output::offload_decrypt`] rather than encrypt and decrypt them in the tunnel's task.
    fn offloads(&self) -> bool {
        false
    }

    /// Encrypts a batch of data messages, for example on another thread, and sends them.
    fn offload_encrypt(&self, batch: Vec<(PendingEncapsulate, Vec<u8>)>) {
        for (pending, packet) in batch {
            let mut buf = self.buffer(packet.len().next_multiple_of(16) + DATA_OVERHEAD_SZ);
            if let Ok(len) = pending.encrypt(&packet, &mut buf).map(|m| m.len()) {
                buf.truncate(len);
                self.datagram(buf);
            }
            self.recycle(packet);
        }
    }

    /// Decrypts a batch of data messages, for example on another thread, and sends the results
    /// to `done` for the tunnel to commit.
    fn offload_decrypt(
        &self,
        batch: Vec<(PendingDecapsulate, Vec<u8>)>,
        done: mpsc::UnboundedSender<Offloaded>,
    ) {
        for (pending, datagram) in batch {
            let decrypted = pending.decrypt(&datagram, self.buffer(datagram.len()));
            self.recycle(datagram);
            let _ = done.send(Offloaded::Decrypted(decrypted));
        }
    }

    /// Computes a handshake response, for example on another thread, and sends it to `done`
    /// for the tunnel to commit.
    fn offload_response(&self, pending: PendingResponse, done: mpsc::UnboundedSender<Offloaded>) {
        let _ = done.send(Offloaded::Response(pending.compute().map(Box::new)));
    }
}

/// Work an [`Output`] finished off the tunnel's task, for the tunnel to commit.
pub enum Offloaded {
    Decrypted(Decrypted<Vec<u8>>),
    Response(Result<Box<ComputedResponse>, Error>),
}

/// A tunnel that runs its own timers. Create one with [`Tunnel::into_async`].
pub struct AsyncTunnel {
    handshake: Handshake,
    sessions: Sessions,
    rng: ForwardSecureRng,
    config: Config,
    timers: Timers,
    /// When the current round of handshake attempts began.
    handshake_started_at: Instant,
    pending: VecDeque<Vec<u8>>,
    /// Data messages waiting for [`Output::offload_encrypt`] and [`Output::offload_decrypt`].
    encrypts: Vec<(PendingEncapsulate, Vec<u8>)>,
    decrypts: Vec<(PendingDecapsulate, Vec<u8>)>,
    responses: Vec<PendingResponse>,
    established: bool,
    _index_lease: Arc<()>,
}

struct Config {
    persistent_keepalive: Option<Duration>,
    keepalive_timeout: Duration,
    rekey_timeout: Duration,
    rekey_attempt_time: Duration,
}

impl Tunnel {
    /// Converts this tunnel into one that runs its own timers.
    pub fn into_async(self) -> AsyncTunnel {
        let created_at = self.timers[TimerName::TimeLastUpdate];
        let mut tunnel = AsyncTunnel {
            handshake: self.handshake,
            sessions: self.sessions,
            rng: self.rng,
            config: Config {
                persistent_keepalive: self.timers.persistent_keepalive(),
                keepalive_timeout: self.timers.keepalive_timeout,
                rekey_timeout: self.timers.rekey_timeout,
                rekey_attempt_time: self.timers.rekey_attempt_time_setting(),
            },
            timers: Timers::default(),
            handshake_started_at: created_at,
            pending: VecDeque::new(),
            encrypts: Vec::new(),
            decrypts: Vec::new(),
            responses: Vec::new(),
            established: false,
            _index_lease: self._index_lease,
        };
        // Like sanstun's tunnels, one that never completes a handshake still expires.
        tunnel.session_derived(created_at);
        tunnel.timers.new_handshake_jitter = tunnel.jitter();

        tunnel
    }
}

impl AsyncTunnel {
    /// Runs the tunnel until `inbox` closes. The inbox carries batches, so that whoever routes
    /// inputs to tunnels pays one channel operation per batch rather than per input.
    ///
    /// Returns an `async move` block rather than being an `async fn`: the block keeps the tunnel
    /// once, where an `async fn` would keep both its argument and the moved-from local.
    #[expect(
        clippy::manual_async_fn,
        reason = "An `async fn` future would hold the tunnel twice."
    )]
    pub fn run(
        mut self,
        mut inbox: mpsc::Receiver<Vec<Input>>,
        out: impl Output,
    ) -> impl Future<Output = ()> {
        async move {
            let mut inputs = Vec::with_capacity(BATCH);
            let (done, mut offloaded) = mpsc::unbounded_channel();
            let mut commits = Vec::with_capacity(BATCH);

            loop {
                let timers = &mut self.timers;

                tokio::select! {
                    biased;

                    () = timers.retransmit_handshake.expired() => self.retransmit_handshake(now(), &out),
                    () = timers.send_keepalive.expired() => self.send_keepalive(now(), &out),
                    () = timers.new_handshake.expired() => self.new_handshake(now(), &out),
                    () = timers.persistent_keepalive.expired() => self.send_keepalive(now(), &out),
                    () = timers.zero_key_material.expired() => self.expire(&out),
                    _ = offloaded.recv_many(&mut commits, BATCH) => {
                        let now = now();
                        for done in commits.drain(..) {
                            let result = match done {
                                Offloaded::Decrypted(decrypted) => {
                                    self.commit(decrypted, now, &out)
                                }
                                Offloaded::Response(computed) => computed
                                    .and_then(|computed| self.commit_response(*computed, now, &out)),
                            };
                            if let Err(e) = result {
                                out.notice(Notice::Error(e));
                            }
                        }
                    }
                    received = inbox.recv_many(&mut inputs, BATCH) => {
                        if received == 0 {
                            return;
                        }
                        let now = now();
                        for input in inputs.drain(..).flatten() {
                            self.handle(input, now, &out);
                        }
                    }
                }

                self.flush(now(), &out);
                if !self.encrypts.is_empty() {
                    out.offload_encrypt(std::mem::take(&mut self.encrypts));
                }
                if !self.decrypts.is_empty() {
                    out.offload_decrypt(std::mem::take(&mut self.decrypts), done.clone());
                }
                for pending in self.responses.drain(..) {
                    out.offload_response(pending, done.clone());
                }
            }
        }
    }

    fn handle(&mut self, input: Input, now: Instant, out: &impl Output) {
        let result = match input {
            Input::Ip(packet) => {
                self.send_ip(packet, now, out);
                Ok(())
            }
            Input::Message(ReceivedMessage::HandshakeInitiation(init), _) => {
                self.handle_handshake_initiation(init, now, out)
            }
            Input::Message(ReceivedMessage::HandshakeResponse(response), _) => {
                self.handle_handshake_response(response, now, out)
            }
            Input::Message(ReceivedMessage::CookieReply(reply), _) => {
                self.handle_cookie_reply(reply, now)
            }
            Input::Message(ReceivedMessage::TransportData(data), datagram) => {
                self.decapsulate(data, datagram, now, out)
            }
        };
        if let Err(e) = result {
            out.notice(Notice::Error(e));
        }
    }

    fn ensure_not_expired(&self) -> Result<(), Error> {
        if self.handshake.is_expired() {
            return Err(Error::ConnectionExpired);
        }

        Ok(())
    }
}

fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, TunnelConfig};
    use zeroize::Zeroizing;

    struct Discard;

    impl Output for Discard {
        fn datagram(&self, _: Vec<u8>) {}
        fn ip(&self, _: Vec<u8>, _: usize) {}
        fn notice(&self, _: Notice) {}
    }

    /// A tunnel task's future should hold the tunnel once, not once per suspension state.
    #[tokio::test]
    async fn run_holds_the_tunnel_once() {
        let now = Instant::now();
        let mut a = Interface::new(Zeroizing::new([1; 32]), now, Duration::ZERO);
        let b = Interface::new(Zeroizing::new([2; 32]), now, Duration::ZERO);
        let tunnel = a
            .new_tunnel(b.static_public(), TunnelConfig::default(), now)
            .unwrap()
            .into_async();
        let tunnel_size = size_of_val(&tunnel);
        let (_tx, rx) = mpsc::channel(1);

        let future = tunnel.run(rx, Discard);

        assert!(
            size_of_val(&future) < tunnel_size + 1024,
            "{} bytes for a {tunnel_size}-byte tunnel",
            size_of_val(&future)
        );
    }
}
