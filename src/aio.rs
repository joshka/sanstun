//! Tunnels whose timers run as async loops instead of [`Tunnel::handle_timeout`].
//!
//! [`AsyncTunnel::run`] owns a tunnel for its whole life. It handles inputs as they arrive and
//! runs each of WireGuard's timer rules (§6) as its own loop, concurrently in the same task:
//!
//! - `scheduled_handshakes` sends initiations once their jitter has elapsed.
//! - `expiry` drops expired sessions, cookies and connections.
//! - `retries` retries unanswered initiations and gives up after `REKEY_ATTEMPT_TIME`.
//! - `rekeys` starts handshakes before sessions get too old.
//! - `keepalives` sends passive and persistent keepalives.
//!
//! The loops share the tunnel's state through a mutex and wake each other after every change,
//! so each can recompute its deadline. They are polled in the order above, which decides which
//! rule wins when several are due at once.
//!
//! [`Tunnel::handle_timeout`]: crate::Tunnel::handle_timeout

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::sync::{Notify, mpsc};

use crate::handshake::Handshake;
use crate::index::Index;
use crate::message::{DATA_OVERHEAD_SZ, ReceivedMessage, TransportData};
use crate::rng::ForwardSecureRng;
use crate::session::{Decrypted, Plaintext, Role, Session, Sessions};
use crate::timers::{MAX_JITTER, REJECT_AFTER_TIME, TimerName};
use crate::{CookieReply, Error, HandshakeInitiation, HandshakeResponse, Tunnel};

/// Packets queued while a handshake is in progress.
const MAX_PENDING: usize = 64;

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
pub trait Output: Sync {
    /// Sends a datagram to the peer.
    fn datagram(&self, datagram: Vec<u8>);
    /// Delivers a decrypted packet: the first `len` bytes of `buffer`, including padding.
    fn ip(&self, buffer: Vec<u8>, len: usize);
    fn notice(&self, notice: Notice);
}

/// A tunnel that runs its own timers. Create one with [`Tunnel::into_async`].
pub struct AsyncTunnel {
    state: Mutex<State>,
    /// Wakes the timer loops when their deadlines may have moved.
    changed: Notify,
}

impl Tunnel {
    /// Converts this tunnel into one that runs its timers as async loops.
    pub fn into_async(self) -> AsyncTunnel {
        let created_at = self.timers[TimerName::TimeLastUpdate];

        AsyncTunnel {
            state: Mutex::new(State {
                handshake: self.handshake,
                sessions: self.sessions,
                rng: self.rng,
                persistent_keepalive: self.timers.persistent_keepalive(),
                keepalive_timeout: self.timers.keepalive_timeout,
                rekey_timeout: self.timers.rekey_timeout,
                rekey_attempt_time: self.timers.rekey_attempt_time_setting(),
                handshake_completed_at: created_at,
                handshake_started_at: created_at,
                last_sent_at: created_at,
                persistent_keepalive_at: created_at,
                data_received_without_reply: None,
                data_sent_without_reply: None,
                handshake_at: None,
                established: false,
                pending: VecDeque::new(),
                notices: Vec::new(),
                _index_lease: self._index_lease,
            }),
            changed: Notify::new(),
        }
    }
}

impl AsyncTunnel {
    /// Runs the tunnel until `inbox` closes.
    pub async fn run(self, mut inbox: mpsc::Receiver<Input>, out: impl Output) {
        let inputs = async {
            while let Some(input) = inbox.recv().await {
                self.update(&out, |state, now| state.handle(input, now, &out));
            }
        };

        tokio::select! {
            biased;

            () = self.scheduled_handshakes(&out) => {}
            () = self.expiry(&out) => {}
            () = self.retries(&out) => {}
            () = self.rekeys(&out) => {}
            () = self.keepalives(&out) => {}
            () = inputs => {}
        }
    }

    /// Sends each scheduled handshake initiation once its jitter has elapsed.
    async fn scheduled_handshakes(&self, out: &impl Output) {
        loop {
            self.wait_for(|state| state.live()?.handshake_at).await;
            self.update(out, |state, now| {
                state.handshake_at = None;
                state.restart_handshake(now, out);
            });
        }
    }

    /// Drops sessions after `REJECT_AFTER_TIME`, cookies after `COOKIE_EXPIRATION_TIME`, and
    /// the whole connection `REJECT_AFTER_TIME * 3` after its last handshake.
    async fn expiry(&self, out: &impl Output) {
        loop {
            self.wait_for(|state| {
                let state = state.idle()?;

                [
                    state.sessions.next_expiry(),
                    state.handshake.cookie_expiration(),
                    Some(state.handshake_completed_at + REJECT_AFTER_TIME * 3),
                ]
                .into_iter()
                .flatten()
                .min()
            })
            .await;

            self.update(out, |state, now| {
                let mut rekey = false;
                if let Some(expired) = state.sessions.expire(now) {
                    // A session that sent data should have been replaced before it expired.
                    if expired.sent_data() && state.sessions.is_empty() {
                        return state.expire(out);
                    }
                    rekey = expired.role() == Role::Initiator && !state.handshake.is_in_progress();
                }
                if state
                    .handshake
                    .cookie_expiration()
                    .is_some_and(|deadline| now >= deadline)
                {
                    state.handshake.clear_cookie();
                }
                if now >= state.handshake_completed_at + REJECT_AFTER_TIME * 3 {
                    return state.expire(out);
                }
                if rekey {
                    state.schedule_handshake(now);
                }
            });
        }
    }

    /// Retries an unanswered initiation every `REKEY_TIMEOUT`, until `REKEY_ATTEMPT_TIME` after
    /// the first one.
    async fn retries(&self, out: &impl Output) {
        loop {
            self.wait_for(|state| {
                let state = state.idle()?;
                let (sent_at, _) = state.handshake.in_flight_initiation()?;

                Some((sent_at + state.rekey_timeout).min(state.give_up_at()))
            })
            .await;

            self.update(out, |state, now| {
                if now >= state.give_up_at() {
                    state.expire(out);
                } else {
                    state.schedule_handshake(now);
                }
            });
        }
    }

    /// Starts a handshake when the current session is due for replacement.
    async fn rekeys(&self, out: &impl Output) {
        loop {
            self.wait_for(|state| state.settled()?.rekey_at()).await;
            self.update(out, |state, now| state.schedule_handshake(now));
        }
    }

    /// Replies to data with a keepalive if nothing else was sent within `KEEPALIVE_TIMEOUT`,
    /// and sends persistent keepalives.
    async fn keepalives(&self, out: &impl Output) {
        loop {
            self.wait_for(|state| {
                let state = state.settled()?;
                let persistent = state
                    .sessions
                    .current()
                    .and_then(|_| state.next_persistent_keepalive());

                state.passive_keepalive_at().into_iter().chain(persistent).min()
            })
            .await;

            self.update(out, |state, now| {
                let mut due = false;
                if state.passive_keepalive_at().is_some_and(|at| now >= at) {
                    state.data_received_without_reply = None;
                    due = true;
                }
                if state.next_persistent_keepalive().is_some_and(|at| now >= at) {
                    state.persistent_keepalive_at = now;
                    due = true;
                }
                if due {
                    // A keepalive never waits for a session.
                    if let Ok(keepalive) = state.encrypt_keepalive(now) {
                        out.datagram(keepalive);
                    }
                }
            });
        }
    }

    /// Waits until the deadline `f` computes from the state, recomputing it on every change.
    /// `None` waits for a change.
    async fn wait_for(&self, f: impl Fn(&State) -> Option<Instant>) {
        loop {
            let changed = self.changed.notified();
            let deadline = f(&self.lock());

            match deadline {
                Some(deadline) => tokio::select! {
                    biased;

                    () = tokio::time::sleep_until(deadline.into()) => return,
                    () = changed => {}
                },
                None => changed.await,
            }
        }
    }

    /// Changes the state, then reports what happened and wakes the timer loops.
    fn update(&self, out: &impl Output, change: impl FnOnce(&mut State, Instant)) {
        let now = tokio::time::Instant::now().into_std();
        let mut state = self.lock();

        change(&mut state, now);
        for notice in state.notices.drain(..) {
            out.notice(notice);
        }
        state.flush(now, out);

        drop(state);
        self.changed.notify_waiters();
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }
}

struct State {
    handshake: Handshake,
    sessions: Sessions,
    rng: ForwardSecureRng,

    persistent_keepalive: Option<Duration>,
    keepalive_timeout: Duration,
    rekey_timeout: Duration,
    rekey_attempt_time: Duration,

    handshake_completed_at: Instant,
    /// When the current round of handshake attempts began.
    handshake_started_at: Instant,
    last_sent_at: Instant,
    persistent_keepalive_at: Instant,
    /// When we last received data that we have not replied to.
    data_received_without_reply: Option<Instant>,
    /// When we first sent data that the peer has not replied to.
    data_sent_without_reply: Option<Instant>,
    /// When the next handshake initiation is due, after its jitter.
    handshake_at: Option<Instant>,

    established: bool,
    pending: VecDeque<Vec<u8>>,
    /// Notices to report after the current change.
    notices: Vec<Notice>,

    _index_lease: Arc<()>,
}

impl State {
    /// Returns the state unless the connection expired.
    fn live(&self) -> Option<&Self> {
        (!self.handshake.is_expired()).then_some(self)
    }

    /// Returns the state unless it expired or a handshake is scheduled, which every other
    /// timer waits for.
    fn idle(&self) -> Option<&Self> {
        self.live().filter(|state| state.handshake_at.is_none())
    }

    /// Returns the state if it is idle and no initiation awaits a response.
    fn settled(&self) -> Option<&Self> {
        self.idle()
            .filter(|state| state.handshake.in_flight_initiation().is_none())
    }

    fn give_up_at(&self) -> Instant {
        self.handshake_started_at + self.rekey_attempt_time
    }

    /// Returns when the current session needs replacing, by age, message count or silence.
    fn rekey_at(&self) -> Option<Instant> {
        let current = self.sessions.current();
        let after_messages = current
            .filter(|session| session.rekey_after_messages_reached())
            .map(|_| self.last_sent_at);
        let without_response = self
            .data_sent_without_reply
            .map(|at| at + self.keepalive_timeout + self.rekey_timeout);

        [
            current.and_then(Session::rekey_after_time_on_send),
            after_messages,
            current.and_then(|session| {
                session.reject_after_time_on_receive(self.keepalive_timeout, self.rekey_timeout)
            }),
            without_response,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    fn passive_keepalive_at(&self) -> Option<Instant> {
        Some(self.data_received_without_reply? + self.keepalive_timeout)
    }

    fn next_persistent_keepalive(&self) -> Option<Instant> {
        Some(self.persistent_keepalive_at + self.persistent_keepalive?)
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
                self.decapsulate(data, &datagram, now, out)
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

    /// Encrypts a packet, or queues it and starts a handshake if there is no session.
    fn send_ip(&mut self, packet: Vec<u8>, now: Instant, out: &impl Output) {
        if !self.pending.is_empty() {
            self.queue(packet, now, out);
        } else if let Err(packet) = self.encrypt(packet, now, out) {
            self.queue(packet, now, out);
        }
    }

    fn queue(&mut self, packet: Vec<u8>, now: Instant, out: &impl Output) {
        if self.pending.len() == MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back(packet);

        if !self.handshake.is_in_progress() {
            self.restart_handshake(now, out);
        }
    }

    /// Sends queued packets while a session is available.
    fn flush(&mut self, now: Instant, out: &impl Output) {
        while let Some(packet) = self.pending.pop_front() {
            if let Err(packet) = self.encrypt(packet, now, out) {
                self.pending.push_front(packet);
                break;
            }
        }
    }

    /// Encrypts and sends a packet, returning it if there is no session to encrypt it with.
    fn encrypt(&mut self, packet: Vec<u8>, now: Instant, out: &impl Output) -> Result<(), Vec<u8>> {
        if let Err(e) = self.ensure_not_expired() {
            out.notice(Notice::Error(e));
            return Ok(());
        }
        let Some(session) = self.sending_session(now) else {
            return Err(packet);
        };
        let pending = session.prepare_packet_data();
        self.sent(now);
        self.data_sent_without_reply.get_or_insert(now);

        let mut buf = vec![0; packet.len().next_multiple_of(16) + DATA_OVERHEAD_SZ];
        match pending.encrypt(&packet, &mut buf) {
            Ok(message) => {
                let len = message.len();
                buf.truncate(len);
                out.datagram(buf);
            }
            Err(e) => out.notice(Notice::Error(e)),
        }

        Ok(())
    }

    fn encrypt_keepalive(&mut self, now: Instant) -> Result<Vec<u8>, Error> {
        let mut message = vec![0; DATA_OVERHEAD_SZ];
        self.sending_session(now)
            .ok_or(Error::NoCurrentSession)?
            .prepare_keepalive()
            .encrypt_payload(&[], &mut message)?;
        self.sent(now);

        Ok(message)
    }

    /// Returns a session that can still send, if one exists.
    fn sending_session(&mut self, now: Instant) -> Option<&mut Session> {
        let keepalive_timeout = self.keepalive_timeout;
        let session = self.sessions.current_mut()?;

        if session.sending_counter_exhausted() || session.expired_at(now) {
            return None;
        }
        // Initiators stop early, leaving time for the packet to arrive before expiry.
        if !session.should_use_at(now, keepalive_timeout) && session.role() == Role::Initiator {
            return None;
        }

        Some(session)
    }

    fn handle_handshake_initiation(
        &mut self,
        init: HandshakeInitiation,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        if init.0.replayed {
            return Err(Error::ReplayedHandshakeInitiation);
        }
        self.ensure_not_expired()?;

        let local_idx = self.sessions.next_index();
        let (response, session) =
            self.handshake
                .receive_handshake_initialization(&init, local_idx, &mut self.rng, now)?;
        self.sessions.insert(session);

        self.received();
        self.sent(now);
        self.handshake_completed_at = now;
        out.datagram(response.to_vec());

        Ok(())
    }

    fn handle_handshake_response(
        &mut self,
        response: HandshakeResponse,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let local_idx = Index::from_peer(response.receiver_idx);
        let session = self.handshake.receive_handshake_response(response, now)?;
        self.sessions.insert(session);

        self.received();
        self.handshake_completed_at = now;
        self.sessions.set_current(local_idx);
        self.confirm_first_session();

        // Confirms the session to the responder.
        out.datagram(self.encrypt_keepalive(now)?);

        Ok(())
    }

    fn handle_cookie_reply(&mut self, reply: CookieReply, now: Instant) -> Result<(), Error> {
        self.ensure_not_expired()?;

        self.handshake.receive_cookie_reply(reply, now)
    }

    fn decapsulate(
        &mut self,
        data: TransportData,
        datagram: &[u8],
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let remote_idx = Index::from_peer(data.receiver_idx);
        let Decrypted {
            session: session_id,
            counter,
            plaintext,
            ..
        } = self
            .sessions
            .in_slot_of(remote_idx)
            .filter(|session| !session.expired_at(now))
            .ok_or(Error::NoCurrentSession)?
            .prepare_receive_packet_data(data)?
            .decrypt(datagram, vec![0; datagram.len()]);

        let session = self
            .sessions
            .get_mut(remote_idx)
            .filter(|session| session.id() == session_id && !session.expired_at(now))
            .ok_or(Error::NoCurrentSession)?;
        let plaintext = session.finish_receive_packet_data(counter, plaintext)?;

        self.sessions.set_current(remote_idx);
        self.received();
        self.confirm_first_session();

        if let Plaintext::Data { buffer, len } = plaintext {
            self.data_received_without_reply = Some(now);
            out.ip(buffer, len);
        }

        Ok(())
    }

    /// Sends a new handshake initiation, replacing any in progress.
    fn restart_handshake(&mut self, now: Instant, out: &impl Output) {
        if self.handshake.is_expired() {
            return;
        }
        if !self.handshake.is_in_progress() {
            self.handshake_started_at = now;
        }

        let local_idx = self.sessions.next_index();
        let initiation = self
            .handshake
            .initiate_handshake(local_idx, &mut self.rng, now);
        self.sent(now);
        out.datagram(initiation.to_vec());
    }

    /// Schedules a handshake after a random jitter, so peers do not initiate simultaneously.
    fn schedule_handshake(&mut self, now: Instant) {
        let jitter = self.rng.random_range(Duration::ZERO..=MAX_JITTER);
        self.handshake_at = Some(now + jitter);
    }

    fn confirm_first_session(&mut self) {
        if !self.established {
            self.established = true;
            self.notices.push(Notice::Established);
        }
    }

    fn expire(&mut self, out: &impl Output) {
        self.handshake.set_expired();
        self.sessions.clear();
        self.pending.clear();
        self.data_received_without_reply = None;
        self.data_sent_without_reply = None;
        out.notice(Notice::Expired);
    }

    /// Records that a packet was sent, which answers any data received.
    fn sent(&mut self, now: Instant) {
        self.last_sent_at = now;
        self.data_received_without_reply = None;
    }

    /// Records that an authenticated packet arrived, which answers any data sent.
    fn received(&mut self) {
        self.data_sent_without_reply = None;
    }
}
