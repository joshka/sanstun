//! Sending data, queued behind handshakes when there is no session (§6.2, §6.4).

use std::time::Instant;

use super::{AsyncTunnel, MAX_PENDING, Notice, Output};
use crate::Error;
use crate::message::DATA_OVERHEAD_SZ;
use crate::session::{Role, Session};
use crate::timers::REKEY_AFTER_TIME;

impl AsyncTunnel {
    /// Encrypts a packet, or queues it and starts a handshake if there is no session (§6.4).
    pub(super) fn send_ip(&mut self, packet: Vec<u8>, now: Instant, out: &impl Output) {
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
        self.initiate_handshake(now, out);
    }

    /// Sends queued packets while a session is available.
    pub(super) fn flush(&mut self, now: Instant, out: &impl Output) {
        while let Some(packet) = self.pending.pop_front() {
            if let Err(packet) = self.encrypt(packet, now, out) {
                self.pending.push_front(packet);
                break;
            }
        }
    }

    /// Encrypts and sends a packet, returning it if there is no session to encrypt it with.
    fn encrypt(&mut self, packet: Vec<u8>, now: Instant, out: &impl Output) -> Result<(), Vec<u8>> {
        if self.handshake.is_expired() {
            out.notice(Notice::Error(Error::ConnectionExpired));
            return Ok(());
        }
        let Some(session) = self.sending_session(now) else {
            return Err(packet);
        };
        let pending = session.prepare_packet_data();
        // §6.2: the initiator rekeys after sending with an old or overused key.
        let rekey = session.role() == Role::Initiator
            && (now >= session.established_at() + REKEY_AFTER_TIME
                || session.rekey_after_messages_reached());

        if out.offloads() {
            self.encrypts.push((pending, packet));
            self.packet_sent(now);
            self.data_sent(now);
            if rekey {
                self.initiate_handshake(now, out);
            }
            return Ok(());
        }

        let mut buf = out.buffer(packet.len().next_multiple_of(16) + DATA_OVERHEAD_SZ);
        let encrypted = pending
            .encrypt(&packet, &mut buf)
            .map(|message| message.len());
        out.recycle(packet);
        match encrypted {
            Ok(len) => {
                buf.truncate(len);
                out.datagram(buf);
            }
            Err(e) => out.notice(Notice::Error(e)),
        }
        self.packet_sent(now);
        self.data_sent(now);
        if rekey {
            self.initiate_handshake(now, out);
        }

        Ok(())
    }

    /// Returns a session that can still send, if one exists (§6.2).
    pub(super) fn sending_session(&mut self, now: Instant) -> Option<&mut Session> {
        let keepalive_timeout = self.config.keepalive_timeout;
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

    /// Sends an empty data message to confirm that we are alive (§6.5).
    pub(super) fn send_keepalive(&mut self, now: Instant, out: &impl Output) {
        let Some(session) = self.sending_session(now) else {
            return;
        };
        let mut keepalive = vec![0; DATA_OVERHEAD_SZ];
        if session
            .prepare_keepalive()
            .encrypt_payload(&[], &mut keepalive)
            .is_ok()
        {
            out.datagram(keepalive);
            self.packet_sent(now);
        }
    }
}
