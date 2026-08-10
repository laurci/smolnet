use std::time::{Duration, Instant};

use snow::{HandshakeState, TransportState};
use thiserror::Error;

use crate::keys::{Keypair, PATTERN, PublicKey};
use crate::replay::ReplayWindow;

/// Rekey well before any counter could wrap, and often enough that a compromised
/// session key exposes only a short window of traffic.
pub const REKEY_AFTER: Duration = Duration::from_secs(120);
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 40;

/// A handshake that gets no answer is retried; give up long before a peer that
/// is simply gone can hold a slot forever.
pub const HANDSHAKE_RETRY: Duration = Duration::from_secs(2);
pub const HANDSHAKE_GIVE_UP: Duration = Duration::from_secs(30);

pub const TAG_SIZE: usize = 16;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("the noise layer refused the message: {0}")]
    Noise(String),

    #[error("the packet is a replay or too old to prove otherwise")]
    Replay,

    #[error("the peer did not present the static key we expected")]
    WrongPeer,

    #[error("the buffer is too small for the result")]
    TooSmall,
}

fn noise(error: snow::Error) -> SessionError {
    SessionError::Noise(format!("{error:?}"))
}

fn builder<'a>() -> Result<snow::Builder<'a>, SessionError> {
    Ok(snow::Builder::new(
        PATTERN.parse().map_err(|e| SessionError::Noise(format!("{e:?}")))?,
    ))
}

/// A handshake we started and are waiting on an answer for.
pub struct Pending {
    state: HandshakeState,
    peer: PublicKey,
    local_index: u32,
    started: Instant,
    last_sent: Instant,
}

impl Pending {
    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn expired(&self) -> bool {
        self.started.elapsed() > HANDSHAKE_GIVE_UP
    }

    pub fn should_retry(&self) -> bool {
        self.last_sent.elapsed() > HANDSHAKE_RETRY
    }

    pub fn retried(&mut self) {
        self.last_sent = Instant::now();
    }

    /// Finish as the initiator, given the responder's reply.
    pub fn accept(mut self, reply: &[u8], remote_index: u32) -> Result<Session, SessionError> {
        let mut discard = [0u8; 256];

        self.state.read_message(reply, &mut discard).map_err(noise)?;

        let transport = self.state.into_transport_mode().map_err(noise)?;

        Ok(Session::new(transport, self.peer, self.local_index, remote_index))
    }
}

/// An established, encrypted channel with one peer.
pub struct Session {
    transport: TransportState,
    peer: PublicKey,
    local_index: u32,
    remote_index: u32,
    sending: u64,
    replay: ReplayWindow,
    opened: Instant,
}

impl Session {
    fn new(
        transport: TransportState,
        peer: PublicKey,
        local_index: u32,
        remote_index: u32,
    ) -> Session {
        Session {
            transport,
            peer,
            local_index,
            remote_index,
            sending: 0,
            replay: ReplayWindow::new(),
            opened: Instant::now(),
        }
    }

    pub fn peer(&self) -> PublicKey {
        self.peer
    }

    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    pub fn remote_index(&self) -> u32 {
        self.remote_index
    }

    pub fn stale(&self) -> bool {
        self.opened.elapsed() > REKEY_AFTER || self.sending > REKEY_AFTER_MESSAGES
    }

    /// Encrypt one packet, returning the counter that must travel with it.
    pub fn seal(&mut self, plaintext: &[u8], out: &mut [u8]) -> Result<(u64, usize), SessionError> {
        if out.len() < plaintext.len() + TAG_SIZE {
            return Err(SessionError::TooSmall);
        }

        // snow advances the sending nonce itself; read it first so the counter
        // we put in the header is the one the tag was computed under.
        let counter = self.transport.sending_nonce();
        let written = self.transport.write_message(plaintext, out).map_err(noise)?;

        self.sending += 1;

        Ok((counter, written))
    }

    /// Decrypt one packet. The counter is carried in the header because UDP
    /// reorders, so it is checked against the replay window before we trust it.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, SessionError> {
        if !self.replay.accept(counter) {
            return Err(SessionError::Replay);
        }

        self.transport.set_receiving_nonce(counter);

        self.transport
            .read_message(ciphertext, out)
            .map_err(noise)
    }
}

/// Start a handshake with a peer whose static key we already know from the
/// control plane. That is what lets this be one round trip.
pub fn initiate(
    keys: &Keypair,
    peer: PublicKey,
    local_index: u32,
) -> Result<(Pending, Vec<u8>), SessionError> {
    let mut state = builder()?
        .local_private_key(keys.private())
        .map_err(noise)?
        .remote_public_key(peer.as_bytes())
        .map_err(noise)?
        .build_initiator()
        .map_err(noise)?;

    let mut message = vec![0u8; 256];
    let written = state.write_message(&[], &mut message).map_err(noise)?;
    message.truncate(written);

    let now = Instant::now();

    Ok((
        Pending {
            state,
            peer,
            local_index,
            started: now,
            last_sent: now,
        },
        message,
    ))
}

/// Answer a handshake. The initiator's static key arrives encrypted inside the
/// message, so we learn who it is only after decrypting — which is exactly what
/// keeps identities off the wire.
pub fn respond(
    keys: &Keypair,
    initiation: &[u8],
    local_index: u32,
    remote_index: u32,
) -> Result<(Session, Vec<u8>), SessionError> {
    let mut state = builder()?
        .local_private_key(keys.private())
        .map_err(noise)?
        .build_responder()
        .map_err(noise)?;

    let mut discard = [0u8; 256];
    state.read_message(initiation, &mut discard).map_err(noise)?;

    let peer = state
        .get_remote_static()
        .ok_or(SessionError::WrongPeer)
        .and_then(|bytes| PublicKey::from_slice(bytes).map_err(|_| SessionError::WrongPeer))?;

    let mut reply = vec![0u8; 256];
    let written = state.write_message(&[], &mut reply).map_err(noise)?;
    reply.truncate(written);

    let transport = state.into_transport_mode().map_err(noise)?;

    Ok((
        Session::new(transport, peer, local_index, remote_index),
        reply,
    ))
}

/// When both ends start a handshake at once, keep one deterministically rather
/// than flapping between two half open sessions. The larger key wins; both sides
/// compute the same answer.
pub fn wins_tiebreak(ours: &PublicKey, theirs: &PublicKey) -> bool {
    ours.as_bytes() > theirs.as_bytes()
}

#[cfg(test)]
mod test {
    use crate::keys::Keypair;
    use crate::session::{SessionError, initiate, respond, wins_tiebreak};

    fn pair() -> (Keypair, Keypair) {
        (Keypair::generate().unwrap(), Keypair::generate().unwrap())
    }

    #[test]
    fn a_handshake_gives_both_sides_a_working_channel() {
        let (alice, bob) = pair();

        let (pending, initiation) = initiate(&alice, bob.public(), 11).unwrap();
        let (mut on_bob, reply) = respond(&bob, &initiation, 22, 11).unwrap();
        let mut on_alice = pending.accept(&reply, 22).unwrap();

        assert_eq!(on_bob.peer(), alice.public(), "bob learns who called");
        assert_eq!(on_alice.peer(), bob.public());

        let mut sealed = [0u8; 128];
        let (counter, len) = on_alice.seal(b"over the mesh", &mut sealed).unwrap();

        let mut opened = [0u8; 128];
        let read = on_bob.open(counter, &sealed[..len], &mut opened).unwrap();

        assert_eq!(&opened[..read], b"over the mesh");
    }

    #[test]
    fn traffic_flows_in_both_directions() {
        let (alice, bob) = pair();

        let (pending, initiation) = initiate(&alice, bob.public(), 1).unwrap();
        let (mut on_bob, reply) = respond(&bob, &initiation, 2, 1).unwrap();
        let mut on_alice = pending.accept(&reply, 2).unwrap();

        let mut sealed = [0u8; 128];
        let mut opened = [0u8; 128];

        let (counter, len) = on_bob.seal(b"and back", &mut sealed).unwrap();
        let read = on_alice.open(counter, &sealed[..len], &mut opened).unwrap();

        assert_eq!(&opened[..read], b"and back");
    }

    #[test]
    fn packets_may_arrive_out_of_order() {
        let (alice, bob) = pair();

        let (pending, initiation) = initiate(&alice, bob.public(), 1).unwrap();
        let (mut on_bob, reply) = respond(&bob, &initiation, 2, 1).unwrap();
        let mut on_alice = pending.accept(&reply, 2).unwrap();

        let mut first = [0u8; 128];
        let mut second = [0u8; 128];
        let mut third = [0u8; 128];

        let (c1, l1) = on_alice.seal(b"one", &mut first).unwrap();
        let (c2, l2) = on_alice.seal(b"two", &mut second).unwrap();
        let (c3, l3) = on_alice.seal(b"three", &mut third).unwrap();

        let mut out = [0u8; 128];

        // deliver third, first, second
        let read = on_bob.open(c3, &third[..l3], &mut out).unwrap();
        assert_eq!(&out[..read], b"three");

        let read = on_bob.open(c1, &first[..l1], &mut out).unwrap();
        assert_eq!(&out[..read], b"one");

        let read = on_bob.open(c2, &second[..l2], &mut out).unwrap();
        assert_eq!(&out[..read], b"two");
    }

    #[test]
    fn a_replayed_packet_is_refused() {
        let (alice, bob) = pair();

        let (pending, initiation) = initiate(&alice, bob.public(), 1).unwrap();
        let (mut on_bob, reply) = respond(&bob, &initiation, 2, 1).unwrap();
        let mut on_alice = pending.accept(&reply, 2).unwrap();

        let mut sealed = [0u8; 128];
        let (counter, len) = on_alice.seal(b"only once", &mut sealed).unwrap();

        let mut out = [0u8; 128];
        assert!(on_bob.open(counter, &sealed[..len], &mut out).is_ok());

        assert!(
            matches!(
                on_bob.open(counter, &sealed[..len], &mut out),
                Err(SessionError::Replay)
            ),
            "the same packet must never be accepted twice"
        );
    }

    #[test]
    fn a_tampered_packet_does_not_decrypt() {
        let (alice, bob) = pair();

        let (pending, initiation) = initiate(&alice, bob.public(), 1).unwrap();
        let (mut on_bob, reply) = respond(&bob, &initiation, 2, 1).unwrap();
        let mut on_alice = pending.accept(&reply, 2).unwrap();

        let mut sealed = [0u8; 128];
        let (counter, len) = on_alice.seal(b"do not touch", &mut sealed).unwrap();

        sealed[3] ^= 0x40;

        let mut out = [0u8; 128];
        assert!(
            on_bob.open(counter, &sealed[..len], &mut out).is_err(),
            "the tag must catch a flipped bit"
        );
    }

    #[test]
    fn a_stranger_cannot_open_the_conversation() {
        let (alice, bob) = pair();
        let mallory = Keypair::generate().unwrap();

        let (pending, initiation) = initiate(&alice, bob.public(), 1).unwrap();

        assert!(
            respond(&mallory, &initiation, 2, 1).is_err(),
            "an initiation addressed to bob must not open for anyone else"
        );

        let (mut on_bob, reply) = respond(&bob, &initiation, 2, 1).unwrap();
        let mut on_alice = pending.accept(&reply, 2).unwrap();

        let mut sealed = [0u8; 128];
        let (counter, len) = on_alice.seal(b"private", &mut sealed).unwrap();

        // a session mallory sets up with bob must not decrypt alice's traffic
        let (other, initiation) = initiate(&mallory, bob.public(), 3).unwrap();
        let (_, reply) = respond(&bob, &initiation, 4, 3).unwrap();
        let mut theirs = other.accept(&reply, 4).unwrap();

        let mut out = [0u8; 128];
        assert!(theirs.open(counter, &sealed[..len], &mut out).is_err());
        assert!(on_bob.open(counter, &sealed[..len], &mut out).is_ok());
    }

    #[test]
    fn two_sessions_between_the_same_pair_do_not_share_keys() {
        let (alice, bob) = pair();

        let (first, one) = initiate(&alice, bob.public(), 1).unwrap();
        let (_, reply) = respond(&bob, &one, 2, 1).unwrap();
        let mut early = first.accept(&reply, 2).unwrap();

        let (second, two) = initiate(&alice, bob.public(), 3).unwrap();
        let (mut later_bob, reply) = respond(&bob, &two, 4, 3).unwrap();
        let _later = second.accept(&reply, 4).unwrap();

        let mut sealed = [0u8; 128];
        let (counter, len) = early.seal(b"old session", &mut sealed).unwrap();

        let mut out = [0u8; 128];
        assert!(
            later_bob.open(counter, &sealed[..len], &mut out).is_err(),
            "a rekey must not leave the old traffic readable by the new session"
        );
    }

    #[test]
    fn the_tiebreak_is_the_same_on_both_sides_and_never_a_draw() {
        let (alice, bob) = pair();

        let alice_wins = wins_tiebreak(&alice.public(), &bob.public());
        let bob_wins = wins_tiebreak(&bob.public(), &alice.public());

        assert_ne!(alice_wins, bob_wins, "exactly one side must win");
    }
}

use std::collections::HashMap;

/// Every session this node holds, indexed the way the wire needs it: by the
/// four byte index we handed the peer, so a data packet is one lookup.
pub struct Sessions {
    keys: Keypair,
    live: HashMap<u32, Session>,
    by_peer: HashMap<PublicKey, u32>,
    pending: HashMap<PublicKey, Pending>,
}

impl Sessions {
    pub fn new(keys: Keypair) -> Sessions {
        Sessions {
            keys,
            live: HashMap::new(),
            by_peer: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub fn public(&self) -> PublicKey {
        self.keys.public()
    }

    fn free_index(&self) -> u32 {
        loop {
            let mut bytes = [0u8; 4];
            rand::fill(&mut bytes);

            let index = u32::from_be_bytes(bytes);

            if index != 0 && !self.live.contains_key(&index) {
                return index;
            }
        }
    }

    pub fn established(&mut self, peer: &PublicKey) -> Option<&mut Session> {
        let index = *self.by_peer.get(peer)?;

        self.live.get_mut(&index)
    }

    pub fn by_index(&mut self, index: u32) -> Option<&mut Session> {
        self.live.get_mut(&index)
    }

    /// Begin a handshake, or hand back the retry if one is already in flight.
    pub fn begin(&mut self, peer: PublicKey) -> Option<(u32, Vec<u8>)> {
        if let Some(waiting) = self.pending.get_mut(&peer) {
            if waiting.expired() {
                self.pending.remove(&peer);
            } else if waiting.should_retry() {
                waiting.retried();
                // snow cannot re-emit message one, so start over with a fresh
                // handshake rather than sending a stale initiation.
                self.pending.remove(&peer);
            } else {
                return None;
            }
        }

        let index = self.free_index();
        let (waiting, message) = initiate(&self.keys, peer, index).ok()?;

        self.pending.insert(peer, waiting);

        Some((index, message))
    }

    pub fn on_initiation(
        &mut self,
        initiation: &[u8],
        remote_index: u32,
    ) -> Option<(u32, Vec<u8>)> {
        let index = self.free_index();
        let (session, reply) = respond(&self.keys, initiation, index, remote_index).ok()?;

        let peer = session.peer();

        // If we were mid handshake with this peer too, keep one deterministically.
        if self.pending.contains_key(&peer) && wins_tiebreak(&self.keys.public(), &peer) {
            return None;
        }

        self.pending.remove(&peer);
        self.retire(&peer);

        self.by_peer.insert(peer, index);
        self.live.insert(index, session);

        Some((index, reply))
    }

    pub fn on_reply(&mut self, peer: PublicKey, reply: &[u8], remote_index: u32) -> bool {
        let Some(waiting) = self.pending.remove(&peer) else {
            return false;
        };

        let index = waiting.local_index();

        match waiting.accept(reply, remote_index) {
            Ok(session) => {
                self.retire(&peer);

                self.by_peer.insert(peer, index);
                self.live.insert(index, session);

                true
            }
            Err(e) => {
                tracing::debug!(?peer, "handshake reply refused: {e}");
                false
            }
        }
    }

    fn retire(&mut self, peer: &PublicKey) {
        if let Some(old) = self.by_peer.remove(peer) {
            self.live.remove(&old);
        }
    }

    pub fn waiting_on(&self, peer: &PublicKey) -> bool {
        self.pending.contains_key(peer)
    }

    pub fn count(&self) -> usize {
        self.live.len()
    }
}

#[cfg(test)]
mod table_test {
    use crate::keys::Keypair;
    use crate::session::Sessions;

    #[test]
    fn two_nodes_reach_a_session_through_the_table() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let mut on_alice = Sessions::new(alice.clone());
        let mut on_bob = Sessions::new(bob.clone());

        let (alice_index, initiation) = on_alice.begin(bob.public()).unwrap();
        let (bob_index, reply) = on_bob.on_initiation(&initiation, alice_index).unwrap();

        assert!(on_alice.on_reply(bob.public(), &reply, bob_index));

        let mut sealed = [0u8; 128];
        let (counter, len) = on_alice
            .established(&bob.public())
            .unwrap()
            .seal(b"through the table", &mut sealed)
            .unwrap();

        let mut out = [0u8; 128];
        let read = on_bob
            .by_index(bob_index)
            .unwrap()
            .open(counter, &sealed[..len], &mut out)
            .unwrap();

        assert_eq!(&out[..read], b"through the table");
    }

    #[test]
    fn a_second_handshake_replaces_the_first_without_leaking_a_slot() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let mut on_alice = Sessions::new(alice.clone());
        let mut on_bob = Sessions::new(bob.clone());

        for _ in 0..3 {
            let (alice_index, initiation) = on_alice.begin(bob.public()).unwrap();
            let (bob_index, reply) = on_bob.on_initiation(&initiation, alice_index).unwrap();

            assert!(on_alice.on_reply(bob.public(), &reply, bob_index));
        }

        assert_eq!(on_alice.count(), 1, "rekeying must not pile up sessions");
        assert_eq!(on_bob.count(), 1);
    }

    #[test]
    fn a_handshake_already_in_flight_is_not_restarted_immediately() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let mut on_alice = Sessions::new(alice);

        assert!(on_alice.begin(bob.public()).is_some());
        assert!(
            on_alice.begin(bob.public()).is_none(),
            "a retry must wait for the retry interval, not spin"
        );
        assert!(on_alice.waiting_on(&bob.public()));
    }

    #[test]
    fn garbage_never_becomes_a_session() {
        let bob = Keypair::generate().unwrap();
        let mut on_bob = Sessions::new(bob);

        assert!(on_bob.on_initiation(b"not a handshake at all", 7).is_none());
        assert_eq!(on_bob.count(), 0);
    }
}
