//! Handshakes: initiating, responding and completing them (§5.4).

use std::time::Instant;

use super::{AsyncTunnel, Output};
use crate::index::Index;
use crate::{CookieReply, Error, HandshakeInitiation, HandshakeResponse};

impl AsyncTunnel {
    /// Starts a handshake unless one is in progress.
    pub(super) fn initiate_handshake(&mut self, now: Instant, out: &impl Output) {
        if !self.handshake.is_in_progress() {
            self.handshake_started_at = now;
            self.send_initiation(now, out);
        }
    }

    pub(super) fn send_initiation(&mut self, now: Instant, out: &impl Output) {
        if self.handshake.is_expired() {
            return;
        }
        if self
            .handshake
            .cookie_expiration()
            .is_some_and(|deadline| now >= deadline)
        {
            self.handshake.clear_cookie();
        }

        let local_idx = self.sessions.next_index();
        let initiation = self
            .handshake
            .initiate_handshake(local_idx, &mut self.rng, now);
        out.datagram(initiation.to_vec());
        self.initiation_sent(now);
    }

    pub(super) fn handle_handshake_initiation(
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
        let (response, session) = self.handshake.receive_handshake_initialization(
            &init,
            local_idx,
            &mut self.rng,
            now,
        )?;
        self.sessions.insert(session);
        out.datagram(response.to_vec());

        self.session_derived(now);
        self.packet_received(now);
        self.packet_sent(now);

        Ok(())
    }

    pub(super) fn handle_handshake_response(
        &mut self,
        response: HandshakeResponse,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let local_idx = Index::from_peer(response.receiver_idx);
        let session = self.handshake.receive_handshake_response(response, now)?;
        self.sessions.insert(session);
        self.sessions.set_current(local_idx);

        self.session_derived(now);
        self.handshake_complete();
        self.packet_received(now);
        self.confirm_first_session(out);

        // Confirms the session to the responder.
        self.send_keepalive(now, out);

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
