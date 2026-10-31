//! Receiving data (§5.4.6).

use std::time::Instant;

use super::{AsyncTunnel, Notice, Output};
use crate::Error;
use crate::index::Index;
use crate::message::TransportData;
use crate::session::{Decrypted, Plaintext, Role};
use crate::timers::REJECT_AFTER_TIME;

impl AsyncTunnel {
    /// Decrypts a data message, or hands it to [`Output::offload_decrypt`] if the output
    /// offloads, in which case [`AsyncTunnel::commit`] finishes it.
    pub(super) fn decapsulate(
        &mut self,
        data: TransportData,
        datagram: Vec<u8>,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        let pending = self.ensure_not_expired().and_then(|()| {
            let remote_idx = Index::from_peer(data.receiver_idx);
            self.sessions
                .in_slot_of(remote_idx)
                .filter(|session| !session.expired_at(now))
                .ok_or(Error::NoCurrentSession)?
                .prepare_receive_packet_data(data)
        });
        let pending = match pending {
            Ok(pending) => pending,
            Err(e) => {
                out.recycle(datagram);
                return Err(e);
            }
        };
        if out.offloads() {
            self.decrypts.push((pending, datagram));
            return Ok(());
        }

        let decrypted = pending.decrypt(&datagram, out.buffer(datagram.len()));
        out.recycle(datagram);
        self.commit(decrypted, now, out)
    }

    /// Accepts a decrypted data message.
    pub(super) fn commit(
        &mut self,
        decrypted: Decrypted<Vec<u8>>,
        now: Instant,
        out: &impl Output,
    ) -> Result<(), Error> {
        self.ensure_not_expired()?;

        let remote_idx = decrypted.receiving_index;
        let Decrypted {
            session: session_id,
            counter,
            plaintext,
            ..
        } = decrypted;
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
