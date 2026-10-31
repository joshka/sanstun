//! Receiving data (§5.4.6).

use std::time::Instant;

use super::{AsyncTunnel, Notice, Output};
use crate::Error;
use crate::index::Index;
use crate::message::TransportData;
use crate::session::{Decrypted, Plaintext, Role};
use crate::timers::REJECT_AFTER_TIME;

impl AsyncTunnel {
    pub(super) fn decapsulate(
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
        // §6.2: the initiator rekeys before its key gets too old to receive with.
        let rekey = session.role() == Role::Initiator
            && now
                >= session.established_at() + REJECT_AFTER_TIME
                    - self.config.keepalive_timeout
                    - self.config.rekey_timeout;

        self.sessions.set_current(remote_idx);
        self.packet_received(now);
        self.confirm_first_session(out);
        if let Plaintext::Data { buffer, len } = plaintext {
            out.ip(buffer, len);
            self.data_received(now);
        }
        if rekey {
            self.initiate_handshake(now, out);
        }

        Ok(())
    }

    pub(super) fn confirm_first_session(&mut self, out: &impl Output) {
        if !self.established {
            self.established = true;
            out.notice(Notice::Established);
        }
    }
}
