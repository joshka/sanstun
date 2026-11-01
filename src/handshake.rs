use super::index::Index;
use super::timers::COOKIE_EXPIRATION_TIME;
use crate::crypto::{
    SharedKey, aead_chacha20_open, aead_chacha20_seal, b2s_hash, b2s_hmac, b2s_hmac2,
    b2s_keyed_mac_16, dh, xaead_open,
};
use crate::errors::Error;
use crate::keys::{PresharedKey, PublicKey, StaticSecret};
use crate::message::{
    CookieReply, HANDSHAKE_INIT, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP, HANDSHAKE_RESP_SZ,
    HandshakeInitiation, HandshakeResponse, InnerHandshakeInitiation,
};
use crate::session::{Role, Session};
use crate::tai64n::{Tai64N, TimeStamper};
use rand::CryptoRng;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";
const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

/// Long-lived parameters for the Noise handshake.
struct NoiseParams {
    static_public: PublicKey,
    static_private: StaticSecret,
    peer_static_public: PublicKey,
    /// The precomputed X25519 shared secret for the two static keys.
    static_shared: SharedKey,
    /// The precomputed `mac1` key for messages sent to this peer.
    sending_mac1_key: [u8; KEY_LEN],
    /// The preshared key, or all zeros if none was configured.
    preshared_key: PresharedKey,
}

impl std::fmt::Debug for NoiseParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseParams")
            .field("static_public", &self.static_public)
            .field("peer_static_public", &self.peer_static_public)
            .field("sending_mac1_key", &self.sending_mac1_key)
            .finish_non_exhaustive()
    }
}

/// What an initiator keeps of an initiation it sent, to complete the handshake with its
/// response.
#[derive(Clone)]
pub(crate) struct HandshakeInitSentState {
    local_index: Index,
    hash: [u8; KEY_LEN],
    chaining_key: Zeroizing<[u8; KEY_LEN]>,
    ephemeral_private: x25519_dalek::ReusableSecret,
    time_sent: Instant,
}

impl std::fmt::Debug for HandshakeInitSentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeInitSentState")
            .field("local_index", &self.local_index)
            .field("hash", &self.hash)
            .field("time_sent", &self.time_sent)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
enum HandshakeState {
    None,
    /// An initiation whose crypto [`PendingOutgoingInitiation::compute`] is computing.
    InitComputing {
        local_index: Index,
        time_sent: Instant,
    },
    /// An initiation awaiting a response.
    InitSent(HandshakeInitSentState),
    /// The connection has expired and cannot start another handshake.
    Expired,
}

/// Handshake state and cookie tracking for one peer.
pub(crate) struct Handshake {
    params: Arc<NoiseParams>,
    /// Keeps the previous initiation available for delayed responses.
    previous: HandshakeState,
    state: HandshakeState,
    cookies: Cookies,
    stamper: TimeStamper,
}

#[derive(Default)]
struct Cookies {
    last_mac1: Option<[u8; 16]>,
    index: Index,
    write_cookie: Option<WriteCookie>,
}

#[derive(Clone, Copy)]
struct WriteCookie {
    value: [u8; 16],
    received_at: Instant,
}

/// Static-static shared secrets with known peers, which never change.
pub(crate) type StaticShared = std::collections::HashMap<PublicKey, Zeroizing<[u8; KEY_LEN]>>;

/// Returns the static-static shared secret with `peer`, to cache for [`parse_handshake_init`].
pub(crate) fn static_shared(
    static_private: &StaticSecret,
    peer: &PublicKey,
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    Ok(Zeroizing::new(*dh(static_private, peer)?.as_bytes()))
}

/// Parses and authenticates a handshake initiation addressed to `static_public`.
///
/// Uses the cached static-static secret for known peers, which saves one of its two DHs.
pub(crate) fn parse_handshake_init(
    static_private: &StaticSecret,
    static_public: &PublicKey,
    known: &StaticShared,
    datagram: &[u8; HANDSHAKE_INIT_SZ],
) -> Result<HandshakeInitiation, Error> {
    let sender_idx = u32::from_le_bytes(datagram[4..8].try_into().unwrap());
    let unencrypted_ephemeral: [u8; KEY_LEN] = datagram[8..40].try_into().unwrap();
    let encrypted_static = &datagram[40..88];
    let encrypted_timestamp = &datagram[88..116];

    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, static_public.as_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    let peer_ephemeral_public = PublicKey::from(unencrypted_ephemeral);
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, peer_ephemeral_public.as_bytes());
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(
        &b2s_hmac(&chaining_key, peer_ephemeral_public.as_bytes()),
        &[0x01],
    );
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = dh(static_private, &peer_ephemeral_public)?;
    let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);

    let mut peer_static_public = [0u8; KEY_LEN];
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_open(&mut peer_static_public, &key, 0, encrypted_static, &hash)?;
    let peer_static_public = PublicKey::from(peer_static_public);
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    hash = b2s_hash(&hash, encrypted_static);

    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let static_shared = match known.get(&peer_static_public) {
        Some(shared) => shared.clone(),
        None => self::static_shared(static_private, &peer_static_public)?,
    };
    let temp = b2s_hmac(&chaining_key, &*static_shared);
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    aead_chacha20_open(&mut timestamp, &key, 0, encrypted_timestamp, &hash)?;
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    hash = b2s_hash(&hash, encrypted_timestamp);

    Ok(HandshakeInitiation(Box::new(InnerHandshakeInitiation {
        sender_idx,
        peer_static_public,
        peer_ephemeral_public,
        chaining_key,
        hash,
        timestamp: Tai64N::parse(&timestamp),
        replayed: false,
    })))
}

/// Returns `(initiator.sending_key, initiator.receiving_key)` for the final chaining key.
fn derive_transport_keys(
    chaining_key: &[u8; KEY_LEN],
) -> (Zeroizing<[u8; KEY_LEN]>, Zeroizing<[u8; KEY_LEN]>) {
    // temp1 = HMAC(initiator.chaining_key, [empty])
    // temp2 = HMAC(temp1, 0x1)
    // temp3 = HMAC(temp1, temp2 || 0x2)
    // initiator.sending_key = temp2
    // initiator.receiving_key = temp3
    let temp1 = b2s_hmac(chaining_key, &[]);
    let temp2 = b2s_hmac(&temp1, &[0x01]);
    let temp3 = b2s_hmac2(&temp1, &temp2, &[0x02]);

    (temp2, temp3)
}

impl NoiseParams {
    fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        preshared_key: Option<PresharedKey>,
    ) -> Result<NoiseParams, Error> {
        let static_shared = dh(&static_private, &peer_static_public)?;
        let initial_sending_mac_key = b2s_hash(LABEL_MAC1, peer_static_public.as_bytes());

        Ok(NoiseParams {
            static_public,
            static_private,
            peer_static_public,
            static_shared,
            sending_mac1_key: initial_sending_mac_key,
            preshared_key: preshared_key
                .unwrap_or_else(|| PresharedKey::from(Zeroizing::new([0u8; 32]))),
        })
    }
}

impl Handshake {
    pub(crate) fn new(
        static_private: StaticSecret,
        static_public: PublicKey,
        peer_static_public: PublicKey,
        preshared_key: Option<PresharedKey>,
        stamper: TimeStamper,
    ) -> Result<Handshake, Error> {
        let params = NoiseParams::new(
            static_private,
            static_public,
            peer_static_public,
            preshared_key,
        )?;

        Ok(Handshake {
            params: Arc::new(params),
            previous: HandshakeState::None,
            state: HandshakeState::None,
            stamper,
            cookies: Default::default(),
        })
    }

    pub(crate) fn initiator(&self) -> Initiator {
        Initiator {
            params: self.params.clone(),
            stamper: self.stamper.clone(),
        }
    }

    pub(crate) fn remote_static_public(&self) -> PublicKey {
        self.params.peer_static_public
    }

    pub(crate) fn is_in_progress(&self) -> bool {
        matches!(
            self.state,
            HandshakeState::InitSent(_) | HandshakeState::InitComputing { .. }
        )
    }

    pub(crate) fn in_flight_initiation(&self) -> Option<(Instant, Index)> {
        match self.state {
            HandshakeState::InitSent(HandshakeInitSentState {
                time_sent,
                local_index,
                ..
            })
            | HandshakeState::InitComputing {
                time_sent,
                local_index,
            } => Some((time_sent, local_index)),
            _ => None,
        }
    }

    pub(crate) fn set_expired(&mut self) {
        self.previous = HandshakeState::Expired;
        self.state = HandshakeState::Expired;
    }

    pub(crate) fn is_expired(&self) -> bool {
        matches!(self.state, HandshakeState::Expired)
    }

    pub(crate) fn cookie_expiration(&self) -> Option<Instant> {
        Some(self.cookies.write_cookie?.received_at + COOKIE_EXPIRATION_TIME)
    }

    pub(crate) fn clear_cookie(&mut self) {
        self.cookies.write_cookie = None;
    }

    /// Starts a new handshake and draws its ephemeral key, leaving the initiation's DHs to
    /// [`PendingOutgoingInitiation::compute`].
    pub(super) fn begin_initiation(
        &mut self,
        local_index: Index,
        rng: &mut impl CryptoRng,
        now: Instant,
    ) -> PendingOutgoingInitiation {
        let ephemeral_private = x25519_dalek::ReusableSecret::random_from_rng(rng);
        let computing = HandshakeState::InitComputing {
            local_index,
            time_sent: now,
        };
        self.previous = std::mem::replace(&mut self.state, computing);

        PendingOutgoingInitiation {
            initiator: self.initiator(),
            ephemeral_private,
            local_index,
            now,
        }
    }

    /// Returns a computed initiation with its MACs, or `None` if a newer handshake replaced it.
    pub(super) fn commit_initiation(
        &mut self,
        computed: ComputedOutgoingInitiation,
    ) -> Option<[u8; HANDSHAKE_INIT_SZ]> {
        let local_index = computed.state.local_index;
        if !matches!(self.state, HandshakeState::InitComputing { local_index: i, .. } if i == local_index)
        {
            return None;
        }

        let mut initiation = computed.initiation;
        self.state = HandshakeState::InitSent(computed.state);
        self.append_mac1_and_mac2(local_index, &mut initiation);

        Some(initiation)
    }

    /// Checks an initiation and draws the response's ephemeral key, leaving its DHs to
    /// [`PendingResponse::compute`].
    pub(super) fn begin_response(
        &self,
        packet: &HandshakeInitiation,
        local_index: Index,
        rng: &mut impl CryptoRng,
        now: Instant,
    ) -> Result<PendingResponse, Error> {
        let InnerHandshakeInitiation {
            // msg.sender_index = little_endian(initiator.sender_index)
            sender_idx: peer_index,
            peer_static_public,
            peer_ephemeral_public,
            ref chaining_key,
            hash,
            timestamp: _,
            replayed: _,
        } = *packet.0;

        if !bool::from(
            self.params
                .peer_static_public
                .as_bytes()
                .ct_eq(peer_static_public.as_bytes()),
        ) {
            return Err(Error::WrongKey);
        }

        Ok(PendingResponse {
            hash,
            chaining_key: chaining_key.clone(),
            peer_ephemeral_public,
            peer_static_public,
            preshared_key: Zeroizing::new(*self.params.preshared_key.as_bytes()),
            // responder.ephemeral_private = DH_GENERATE()
            ephemeral_private: x25519_dalek::ReusableSecret::random_from_rng(rng),
            local_index,
            peer_index,
            sending_mac1_key: self.params.sending_mac1_key,
            write_cookie: self.cookies.write_cookie.map(|cookie| cookie.value),
            now,
        })
    }

    /// Records a computed response's `mac1` for cookie replies, and returns it with its session.
    pub(super) fn commit_response(
        &mut self,
        computed: ComputedResponse,
    ) -> ([u8; HANDSHAKE_RESP_SZ], Session) {
        self.cookies.index = computed.local_index;
        self.cookies.last_mac1 = Some(computed.mac1);

        (computed.response, computed.session)
    }

    /// Finds the initiation a response answers, leaving its DHs to
    /// [`PendingCompletion::compute`]. A delayed response may answer the previous initiation.
    pub(super) fn begin_completion(
        &self,
        response: HandshakeResponse,
        now: Instant,
    ) -> Result<PendingCompletion, Error> {
        let local_index = Index::from_peer(response.receiver_idx);
        let sent = [&self.state, &self.previous]
            .into_iter()
            .find_map(|state| match state {
                HandshakeState::InitSent(s) if s.local_index == local_index => Some(s.clone()),
                _ => None,
            })
            .ok_or(Error::UnexpectedPacket)?;

        Ok(PendingCompletion {
            initiator: self.initiator(),
            sent,
            response,
            now,
        })
    }

    /// Ends the handshake a computed response completed, returning its session.
    pub(super) fn commit_completion(
        &mut self,
        completed: CompletedHandshake,
    ) -> Result<Session, Error> {
        let local_index = completed.session.receiving_index();
        let answered = [&mut self.state, &mut self.previous]
            .into_iter()
            .find(|state| matches!(state, HandshakeState::InitSent(s) if s.local_index == local_index))
            .ok_or(Error::UnexpectedPacket)?;
        *answered = HandshakeState::None;

        Ok(completed.session)
    }

    pub(super) fn receive_cookie_reply(
        &mut self,
        packet: CookieReply,
        now: Instant,
    ) -> Result<(), Error> {
        let mac1 = match self.cookies.last_mac1 {
            Some(mac) => mac,
            None => {
                return Err(Error::UnexpectedPacket);
            }
        };

        let local_index = self.cookies.index;
        if Index::from_peer(packet.receiver_idx) != local_index {
            return Err(Error::WrongIndex);
        }
        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        let key = b2s_hash(LABEL_COOKIE, self.params.peer_static_public.as_bytes()); // TODO: Precompute this key.

        let mut cookie = [0u8; 16];
        xaead_open(
            &mut cookie,
            &key,
            &packet.nonce,
            &packet.encrypted_cookie,
            &mac1[0..16],
        )?;

        self.cookies.last_mac1 = None;
        self.cookies.write_cookie = Some(WriteCookie {
            value: cookie,
            received_at: now,
        });
        Ok(())
    }

    /// Formats a handshake response without its MACs.
    /// Appends `mac1` and `mac2` to a handshake message.
    pub(crate) fn append_mac1_and_mac2(&mut self, local_index: Index, dst: &mut [u8]) {
        let cookie = self.cookies.write_cookie.map(|cookie| cookie.value);
        let msg_mac1 = append_macs(&self.params.sending_mac1_key, cookie, dst);

        self.cookies.index = local_index;
        self.cookies.last_mac1 = Some(msg_mac1);
    }
}

/// Formats a handshake initiation without its MACs.
fn format_handshake_initiation(
    params: &NoiseParams,
    stamper: &TimeStamper,
    local_index: Index,
    ephemeral_private: x25519_dalek::ReusableSecret,
    now: Instant,
) -> ([u8; HANDSHAKE_INIT_SZ], HandshakeInitSentState) {
    let mut dst = [0u8; HANDSHAKE_INIT_SZ];

    let (message_type, rest) = dst.split_at_mut(4);
    let (sender_index, rest) = rest.split_at_mut(4);
    let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
    let (encrypted_static, rest) = rest.split_at_mut(32 + 16);
    let (encrypted_timestamp, _) = rest.split_at_mut(12 + 16);

    // initiator.chaining_key = HASH(CONSTRUCTION)
    let mut chaining_key = Zeroizing::new(INITIAL_CHAIN_KEY);
    // initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public)
    let mut hash = INITIAL_CHAIN_HASH;
    hash = b2s_hash(&hash, params.peer_static_public.as_bytes());
    // msg.message_type = 1
    // msg.reserved_zero = { 0, 0, 0 }
    message_type.copy_from_slice(&HANDSHAKE_INIT.to_le_bytes());
    // msg.sender_index = little_endian(initiator.sender_index)
    sender_index.copy_from_slice(&local_index.to_le_bytes());
    // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    unencrypted_ephemeral
        .copy_from_slice(x25519_dalek::PublicKey::from(&ephemeral_private).as_bytes());
    // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
    hash = b2s_hash(&hash, unencrypted_ephemeral);
    // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&b2s_hmac(&chaining_key, unencrypted_ephemeral), &[0x01]);
    // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    let ephemeral_shared = dh(&ephemeral_private, &params.peer_static_public)
        .expect("`Handshake::new` rejects a low-order peer static key");
    let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
    // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    aead_chacha20_seal(
        encrypted_static,
        &key,
        0,
        params.static_public.as_bytes(),
        &hash,
    );
    // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
    hash = b2s_hash(&hash, encrypted_static);
    // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    let temp = b2s_hmac(&chaining_key, params.static_shared.as_bytes());
    // initiator.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // key = HMAC(temp, initiator.chaining_key || 0x2)
    let key = b2s_hmac2(&temp, &chaining_key, &[0x02]);
    // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    let timestamp = stamper.stamp(now);
    aead_chacha20_seal(encrypted_timestamp, &key, 0, &timestamp, &hash);
    // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
    hash = b2s_hash(&hash, encrypted_timestamp);

    let state = HandshakeInitSentState {
        local_index,
        chaining_key,
        hash,
        ephemeral_private,
        time_sent: now,
    };

    (dst, state)
}

/// Completes the handshake of an initiation we sent with the peer's response.
fn complete_initiation(
    params: &NoiseParams,
    state: &HandshakeInitSentState,
    packet: &HandshakeResponse,
    now: Instant,
) -> Result<Session, Error> {
    let peer_index = packet.sender_idx;
    let local_index = state.local_index;

    let unencrypted_ephemeral = PublicKey::from(packet.unencrypted_ephemeral);
    // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
    // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
    let mut hash = b2s_hash(&state.hash, unencrypted_ephemeral.as_bytes());
    // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
    let temp = b2s_hmac(&state.chaining_key, unencrypted_ephemeral.as_bytes());
    // responder.chaining_key = HMAC(temp, 0x1)
    let mut chaining_key = b2s_hmac(&temp, &[0x01]);
    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
    let ephemeral_shared = dh(&state.ephemeral_private, &unencrypted_ephemeral)?;
    let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
    let static_shared = dh(&params.static_private, &unencrypted_ephemeral)?;
    let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // temp = HMAC(responder.chaining_key, preshared_key)
    let temp = b2s_hmac(&chaining_key, params.preshared_key.as_bytes());
    // responder.chaining_key = HMAC(temp, 0x1)
    chaining_key = b2s_hmac(&temp, &[0x01]);
    // temp2 = HMAC(temp, responder.chaining_key || 0x2)
    let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
    // key = HMAC(temp, temp2 || 0x3)
    let key = b2s_hmac2(&temp, &temp2, &[0x03]);
    // responder.hash = HASH(responder.hash || temp2)
    hash = b2s_hash(&hash, &*temp2);
    // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
    aead_chacha20_open(&mut [], &key, 0, &packet.encrypted_nothing, &hash)?;

    let (temp2, temp3) = derive_transport_keys(&chaining_key);

    Ok(Session::new(
        local_index,
        Index::from_peer(peer_index),
        &temp3,
        &temp2,
        Role::Initiator,
        now,
    ))
}

/// Formats initiations and completes their handshakes without borrowing the [`Handshake`], so
/// that a round of attempts can own one.
#[derive(Clone)]
pub(crate) struct Initiator {
    params: Arc<NoiseParams>,
    stamper: TimeStamper,
}

impl Initiator {
    pub(crate) fn complete(
        &self,
        sent: &HandshakeInitSentState,
        response: &HandshakeResponse,
        now: Instant,
    ) -> Result<Session, Error> {
        complete_initiation(&self.params, sent, response, now)
    }
}

/// Appends `mac1` and `mac2` to a handshake message, and returns `mac1`.
fn append_macs(mac1_key: &[u8; KEY_LEN], cookie: Option<[u8; 16]>, dst: &mut [u8]) -> [u8; 16] {
    let mac1_off = dst.len() - 32;
    let mac2_off = dst.len() - 16;

    // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    let msg_mac1 = b2s_keyed_mac_16(mac1_key, &dst[..mac1_off]);
    dst[mac1_off..mac2_off].copy_from_slice(&msg_mac1[..]);

    // msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
    let msg_mac2: [u8; 16] = match cookie {
        Some(cookie) => b2s_keyed_mac_16(&cookie, &dst[..mac2_off]),
        None => [0u8; 16],
    };
    dst[mac2_off..].copy_from_slice(&msg_mac2[..]);

    msg_mac1
}

/// A handshake response whose DHs have not been computed yet.
///
/// Created by [`Tunnel::begin_handshake_response`](crate::Tunnel::begin_handshake_response),
/// which has already drawn its randomness, so it can be computed on any thread.
#[must_use = "the response is not sent until it is computed and committed"]
pub struct PendingResponse {
    hash: [u8; KEY_LEN],
    chaining_key: Zeroizing<[u8; KEY_LEN]>,
    peer_ephemeral_public: PublicKey,
    peer_static_public: PublicKey,
    preshared_key: Zeroizing<[u8; KEY_LEN]>,
    ephemeral_private: x25519_dalek::ReusableSecret,
    local_index: Index,
    peer_index: u32,
    sending_mac1_key: [u8; KEY_LEN],
    write_cookie: Option<[u8; 16]>,
    now: Instant,
}

impl std::fmt::Debug for PendingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingResponse")
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

/// A handshake response ready for
/// [`Tunnel::commit_handshake_response`](crate::Tunnel::commit_handshake_response).
#[must_use = "the response is not sent until it is committed"]
pub struct ComputedResponse {
    response: [u8; HANDSHAKE_RESP_SZ],
    mac1: [u8; 16],
    local_index: Index,
    session: Session,
}

impl std::fmt::Debug for ComputedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputedResponse")
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

impl PendingResponse {
    /// Computes the response's DHs and session keys.
    pub fn compute(self) -> Result<ComputedResponse, Error> {
        let PendingResponse {
            mut hash,
            mut chaining_key,
            peer_ephemeral_public,
            peer_static_public,
            preshared_key,
            ephemeral_private,
            local_index,
            peer_index,
            sending_mac1_key,
            write_cookie,
            now,
        } = self;
        let mut dst = [0u8; HANDSHAKE_RESP_SZ];

        let (message_type, rest) = dst.split_at_mut(4);
        let (sender_index, rest) = rest.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (unencrypted_ephemeral, rest) = rest.split_at_mut(32);
        let (encrypted_nothing, _) = rest.split_at_mut(16);

        // msg.message_type = 2
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&HANDSHAKE_RESP.to_le_bytes());
        // msg.sender_index = little_endian(responder.sender_index)
        sender_index.copy_from_slice(&local_index.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&peer_index.to_le_bytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(responder.ephemeral_private)
        unencrypted_ephemeral
            .copy_from_slice(x25519_dalek::PublicKey::from(&ephemeral_private).as_bytes());
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = b2s_hash(&hash, unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        let temp = b2s_hmac(&chaining_key, unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        let ephemeral_shared = dh(&ephemeral_private, &peer_ephemeral_public)?;
        let temp = b2s_hmac(&chaining_key, ephemeral_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        let static_shared = dh(&ephemeral_private, &peer_static_public)?;
        let temp = b2s_hmac(&chaining_key, static_shared.as_bytes());
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp = HMAC(responder.chaining_key, preshared_key)
        let temp = b2s_hmac(&chaining_key, &*preshared_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = b2s_hmac(&temp, &[0x01]);
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        let temp2 = b2s_hmac2(&temp, &chaining_key, &[0x02]);
        // key = HMAC(temp, temp2 || 0x3)
        let key = b2s_hmac2(&temp, &temp2, &[0x03]);
        // responder.hash = HASH(responder.hash || temp2)
        hash = b2s_hash(&hash, &*temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        aead_chacha20_seal(encrypted_nothing, &key, 0, &[], &hash);

        let (temp2, temp3) = derive_transport_keys(&chaining_key);
        let mac1 = append_macs(&sending_mac1_key, write_cookie, &mut dst);

        Ok(ComputedResponse {
            response: dst,
            mac1,
            local_index,
            session: Session::new(
                local_index,
                Index::from_peer(peer_index),
                &temp2,
                &temp3,
                Role::Responder,
                now,
            ),
        })
    }
}

/// An initiation whose ephemeral key is drawn, ready for [`PendingOutgoingInitiation::compute`],
/// which can run on another thread.
///
/// Pass the result to [`Tunnel::commit_handshake_initiation`](crate::Tunnel::commit_handshake_initiation).
pub struct PendingOutgoingInitiation {
    initiator: Initiator,
    ephemeral_private: x25519_dalek::ReusableSecret,
    local_index: Index,
    now: Instant,
}

impl std::fmt::Debug for PendingOutgoingInitiation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingOutgoingInitiation")
            .field("local_index", &self.local_index)
            .finish_non_exhaustive()
    }
}

impl PendingOutgoingInitiation {
    /// Computes the initiation's DHs and encrypts it.
    pub fn compute(self) -> ComputedOutgoingInitiation {
        let (initiation, state) = format_handshake_initiation(
            &self.initiator.params,
            &self.initiator.stamper,
            self.local_index,
            self.ephemeral_private,
            self.now,
        );

        ComputedOutgoingInitiation { initiation, state }
    }
}

/// An initiation from [`PendingOutgoingInitiation::compute`], without its MACs.
pub struct ComputedOutgoingInitiation {
    initiation: [u8; HANDSHAKE_INIT_SZ],
    state: HandshakeInitSentState,
}

/// A response matched to the initiation it answers, ready for [`PendingCompletion::compute`],
/// which can run on another thread.
///
/// Pass the result to [`Tunnel::commit_handshake_completion`](crate::Tunnel::commit_handshake_completion).
pub struct PendingCompletion {
    initiator: Initiator,
    sent: HandshakeInitSentState,
    response: HandshakeResponse,
    now: Instant,
}

impl PendingCompletion {
    /// Computes the response's DHs and derives the session.
    pub fn compute(self) -> Result<CompletedHandshake, Error> {
        let session = self
            .initiator
            .complete(&self.sent, &self.response, self.now)?;

        Ok(CompletedHandshake { session })
    }
}

/// A session from [`PendingCompletion::compute`].
pub struct CompletedHandshake {
    session: Session,
}
