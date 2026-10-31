//! Handshakes: initiating, responding and completing them (§5.4).

use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::timers::jitter;
use super::{AsyncTunnel, Output, Spawn, now};
use crate::handshake::Initiator;
use crate::index::Index;
use crate::message::HANDSHAKE_INIT_SZ;
use crate::rng::ForwardSecureRng;
use crate::session::Session;
use crate::{ComputedResponse, CookieReply, Error, HandshakeInitiation, HandshakeResponse};

impl AsyncTunnel {
    /// Starts a round of handshake attempts unless one is in progress (§6.4).
    pub(super) fn initiate_handshake(&mut self) {
        if self.round.is_some() || self.handshake.is_expired() {
            return;
        }

        let (responses, rx) = mpsc::unbounded_channel();
        let (tx, initiations) = mpsc::unbounded_channel();
        let attempts = attempts(
            self.handshake.initiator(),
            self.spawn.clone(),
            ForwardSecureRng::new(&mut self.rng),
            self.sessions.next_index(),
            (self.config.rekey_timeout, self.config.rekey_attempt_time),
            rx,
            tx,
        );
        self.round = Some(Round {
            attempts: Box::pin(attempts),
            responses,
            initiations,
        });
    }

    /// Adds MACs to an initiation from the round and sends it.
    pub(super) fn send_initiation(
        &mut self,
        (local_idx, mut initiation): (Index, [u8; HANDSHAKE_INIT_SZ]),
        now: Instant,
        out: &impl Output,
    ) {
        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            self.handshake.clear_cookie();
        }
        self.handshake
            .append_mac1_and_mac2(local_idx, &mut initiation);
        out.datagram(self.endpoint, initiation.to_vec());
        self.packet_sent(now);
    }

    /// Takes the session a round of attempts completed, or expires if the round gave up.
    pub(super) fn round_finished(
        &mut self,
        session: Option<Box<Session>>,
        now: Instant,
        out: &impl Output,
    ) {
        self.round = None;
        let Some(session) = session else {
            return self.expire(out);
        };
        if self.handshake.is_expired() {
            return;
        }

        let local_idx = session.receiving_index();
        self.sessions.insert(*session);
        self.sessions.set_current(local_idx);

        self.session_derived(now);
        self.packet_received(now);
        self.confirm_first_session(out);

        // Confirms the session to the responder.
        self.send_keepalive(now, out);
    }

    pub(super) fn handle_handshake_initiation(
        &mut self,
        init: HandshakeInitiation,
        src: SocketAddr,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        if init.0.replayed {
            return Err(Error::ReplayedHandshakeInitiation);
        }
        self.ensure_not_expired()?;

        let local_idx = self.sessions.next_index();
        let pending = self
            .handshake
            .begin_response(&init, local_idx, &mut self.rng, now)?;
        // The interface authenticated the initiation, so the peer is at `src`.
        self.endpoint = src;
        if out.offloads() {
            self.responses.push(pending);
            return Ok(());
        }

        self.commit_response(pending.compute()?, now, out)
    }

    /// Establishes the session of a computed response and sends it.
    pub(super) fn commit_response(
        &mut self,
        computed: ComputedResponse,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let (response, session) = self.handshake.commit_response(computed);
        self.sessions.insert(session);
        out.datagram(self.endpoint, response.to_vec());

        self.session_derived(now);
        self.packet_received(now);
        self.packet_sent(now);

        Ok(())
    }

    /// Passes a response to the round of attempts it may answer.
    pub(super) fn handle_handshake_response(
        &mut self,
        response: HandshakeResponse,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let round = self.round.as_ref().ok_or(Error::UnexpectedPacket)?;
        let _ = round.responses.send(response);

        Ok(())
    }

    pub(super) fn handle_cookie_reply(
        &mut self,
        reply: CookieReply,
        now: Instant,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        self.handshake.receive_cookie_reply(reply, now)
    }
}

/// A round of handshake attempts in progress.
pub(super) struct Round {
    pub(super) attempts: Pin<Box<dyn Future<Output = Option<Session>> + Send>>,
    /// Responses for the round to try against its initiations.
    responses: mpsc::UnboundedSender<HandshakeResponse>,
    /// Initiations for the tunnel to add MACs to and send.
    pub(super) initiations: mpsc::UnboundedReceiver<(Index, [u8; HANDSHAKE_INIT_SZ])>,
}

/// What a round of attempts asks of its tunnel.
pub(super) enum RoundEvent {
    Initiation((Index, [u8; HANDSHAKE_INIT_SZ])),
    Finished(Option<Box<Session>>),
}

impl Round {
    /// Waits for the round's next initiation to send, or for it to finish.
    pub(super) async fn next(round: &mut Option<Round>) -> RoundEvent {
        let Some(round) = round else {
            return std::future::pending().await;
        };

        tokio::select! {
            biased;

            Some(initiation) = round.initiations.recv() => RoundEvent::Initiation(initiation),
            session = &mut round.attempts => RoundEvent::Finished(session.map(Box::new)),
        }
    }
}

/// Sends an initiation, and another every `REKEY_TIMEOUT` plus jitter, until a response
/// completes the handshake. Gives up once a retry is due `REKEY_ATTEMPT_TIME` after the first
/// (§6.4).
///
/// Every attempt in a round shares its local index. A late response may answer the attempt
/// before the latest, so both are tried.
async fn attempts(
    initiator: Initiator,
    spawn: Option<Spawn>,
    mut rng: ForwardSecureRng,
    local_idx: Index,
    (rekey_timeout, rekey_attempt_time): (Duration, Duration),
    mut responses: mpsc::UnboundedReceiver<HandshakeResponse>,
    initiations: mpsc::UnboundedSender<(Index, [u8; HANDSHAKE_INIT_SZ])>,
) -> Option<Session> {
    let started = now();
    let mut previous = None;

    loop {
        let (job, mut job_rng, sent_at) =
            (initiator.clone(), ForwardSecureRng::new(&mut rng), now());
        let (initiation, sent) = compute(&spawn, move || {
            job.initiate(local_idx, &mut job_rng, sent_at)
        })
        .await;
        let sent = Arc::new(sent);
        initiations.send((local_idx, initiation)).ok()?;
        let retry = tokio::time::sleep(rekey_timeout + jitter(&mut rng));
        tokio::pin!(retry);

        loop {
            tokio::select! {
                biased;

                () = &mut retry => break,
                Some(response) = responses.recv() => {
                    let (job, sent, previous, received_at) =
                        (initiator.clone(), sent.clone(), previous.clone(), now());
                    let session = compute(&spawn, move || {
                        [Some(sent), previous]
                            .into_iter()
                            .flatten()
                            .find_map(|sent| job.complete(&sent, &response, received_at).ok())
                    })
                    .await;
                    if session.is_some() {
                        return session;
                    }
                }
            }
        }

        if now() >= started + rekey_attempt_time {
            return None;
        }
        previous = Some(sent);
    }
}

/// Runs `job` with `spawn` and waits for its result, or runs it here if there is no `spawn`.
async fn compute<T: Send + 'static>(
    spawn: &Option<Spawn>,
    job: impl FnOnce() -> T + Send + 'static,
) -> T {
    let Some(spawn) = spawn else {
        return job();
    };

    let (tx, rx) = oneshot::channel();
    spawn(Box::new(move || {
        let _ = tx.send(job());
    }));
    rx.await.expect("spawned jobs run to completion")
}
