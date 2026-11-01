//! WireGuard's timers (§6), and the protocol events that arm and disarm them.

use std::pin::Pin;
use std::time::{Duration, Instant};

use rand::RngExt;
use tokio::time::Sleep;

use super::{AsyncTunnel, Notice, Output};
use crate::timers::{MAX_JITTER, REJECT_AFTER_TIME};

#[derive(Default)]
pub(super) struct Timers {
    pub(super) send_keepalive: Timer,
    pub(super) new_handshake: Timer,
    pub(super) persistent_keepalive: Timer,
    pub(super) zero_key_material: Timer,
    /// Jitter added to `new_handshake`, drawn each time it fires.
    pub(super) new_handshake_jitter: Duration,
}

impl AsyncTunnel {
    /// Drops all key material, `REJECT_AFTER_TIME * 3` after the last session was derived.
    pub(super) fn expire(&mut self, out: &impl Output) {
        self.handshake.set_expired();
        self.sessions.clear();
        self.pending.clear();
        self.round = None;
        self.timers = Timers::default();
        out.notice(Notice::Expired);
    }

    pub(super) fn packet_sent(&mut self, now: Instant) {
        self.timers.send_keepalive.disarm();
        self.traversal(now);
    }

    pub(super) fn packet_received(&mut self, now: Instant) {
        self.timers.new_handshake.disarm();
        self.traversal(now);
    }

    pub(super) fn data_sent(&mut self, now: Instant) {
        if !self.timers.new_handshake.is_armed() {
            let timeout = self.config.keepalive_timeout
                + self.config.rekey_timeout
                + self.timers.new_handshake_jitter;
            self.timers.new_handshake.arm(now + timeout);
        }
    }

    /// Starts a handshake when data went unanswered (§6.5).
    pub(super) fn new_handshake(&mut self) {
        // Re-arming happens on almost every packet, so jitter is drawn once per firing.
        self.timers.new_handshake_jitter = jitter(&mut self.rng);
        self.initiate_handshake();
    }

    pub(super) fn data_received(&mut self, now: Instant) {
        if !self.timers.send_keepalive.is_armed() {
            self.timers
                .send_keepalive
                .arm(now + self.config.keepalive_timeout);
        }
    }

    fn traversal(&mut self, now: Instant) {
        if let Some(interval) = self.config.persistent_keepalive {
            self.timers.persistent_keepalive.arm(now + interval);
        }
    }

    pub(super) fn session_derived(&mut self, now: Instant) {
        self.timers
            .zero_key_material
            .arm(now + REJECT_AFTER_TIME * 3);
    }
}

/// Draws the jitter that §6.1 adds to handshake timers.
pub(super) fn jitter(rng: &mut impl rand::Rng) -> Duration {
    rng.random_range(Duration::ZERO..=MAX_JITTER)
}

/// A timer that can be armed for a deadline and disarmed.
///
/// Protocol events re-arm timers on almost every packet, nearly always to a later deadline.
/// Re-arming to a later deadline only records it: the sleep wakes at the earlier one and goes
/// back to sleep until the new deadline. Disarming keeps the sleep registered. Both leave
/// tokio's timer wheel alone on the hot path.
pub(super) struct Timer {
    sleep: Pin<Box<Sleep>>,
    /// When the timer fires, if armed.
    deadline: Option<Instant>,
    /// When the sleep wakes, if registered. Never later than `deadline`.
    wakes_at: Option<Instant>,
}

impl Default for Timer {
    fn default() -> Self {
        Timer {
            sleep: Box::pin(tokio::time::sleep(Duration::ZERO)),
            deadline: None,
            wakes_at: None,
        }
    }
}

impl Timer {
    fn arm(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
        if self.wakes_at.is_none_or(|wakes_at| deadline < wakes_at) {
            self.sleep.as_mut().reset(deadline.into());
            self.wakes_at = Some(deadline);
        }
    }

    fn disarm(&mut self) {
        self.deadline = None;
    }

    fn is_armed(&self) -> bool {
        self.deadline.is_some()
    }

    /// Completes when the armed deadline passes, and never while disarmed.
    pub(super) async fn expired(&mut self) {
        loop {
            let Some(deadline) = self.deadline else {
                return std::future::pending().await;
            };
            if self.wakes_at.is_none() {
                self.sleep.as_mut().reset(deadline.into());
                self.wakes_at = Some(deadline);
            }

            self.sleep.as_mut().await;
            self.wakes_at = None;
            if self
                .deadline
                .is_some_and(|deadline| deadline <= super::now())
            {
                self.deadline = None;
                return;
            }
        }
    }
}
