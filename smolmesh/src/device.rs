use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use smolnet::device::{Device, DeviceCapabilities, DeviceError, Medium};
use thiserror::Error;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::watch;

use crate::{
    id::{NetworkId, NodeId},
    membership::Membership,
    keys::Keypair,
    peer::{Peer, Peers},
    session::Sessions,
    stun,
    wire::{
        Datagram, DatagramParseError, ENDPOINT_SIZE, HEADER_SIZE, MessageType, as_ipv4_endpoint,
        decode_endpoint, encode_endpoint,
    },
};

pub const MESH_MTU: usize = 1280;

/// Enough to cover a handshake round trip without letting a silent peer soak up
/// memory.
const QUEUE_DEPTH: usize = 16;

/// How many of a peer's published addresses to try at once. Enough to cover a
/// public address, a nat reflection and a local one, without turning a single
/// dropped packet into a burst.
const HANDSHAKE_FANOUT: usize = 4;

pub const MESH_SOCKET_BUFFER: usize = 4 * 1024 * 1024;

pub const MAX_DATAGRAM_SIZE: usize = HEADER_SIZE + MESH_MTU;

const IPV4_HEADER_SIZE: usize = 20;
const IPV4_SOURCE_OFFSET: usize = 12;
const IPV4_DESTINATION_OFFSET: usize = 16;

fn enlarge(socket: &UdpSocket, option: libc::c_int, bytes: usize) {
    use std::os::fd::AsRawFd;

    let size = bytes as libc::c_int;

    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            &size as *const libc::c_int as *const libc::c_void,
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result != 0 {
        tracing::debug!(option, bytes, "could not enlarge the mesh socket buffer");
    }
}

fn ipv4_address_at(packet: &[u8], offset: usize) -> Option<Ipv4Addr> {
    if packet.len() < IPV4_HEADER_SIZE || packet[0] >> 4 != 4 {
        return None;
    }

    let bytes: [u8; 4] = packet.get(offset..offset + 4)?.try_into().ok()?;

    Some(Ipv4Addr::from(bytes))
}

fn ipv4_source(packet: &[u8]) -> Option<Ipv4Addr> {
    ipv4_address_at(packet, IPV4_SOURCE_OFFSET)
}

fn ipv4_destination(packet: &[u8]) -> Option<Ipv4Addr> {
    ipv4_address_at(packet, IPV4_DESTINATION_OFFSET)
}

#[derive(Debug, Error)]
enum Discard {
    #[error("no session holds index {0}")]
    NoSession(u32),

    #[error("the session belongs to a peer we no longer know")]
    Unrecognised,

    #[error("the packet did not decrypt: {0}")]
    Undecryptable(String),

    #[error("the peer refused or produced no handshake")]
    HandshakeRefused,

    #[error("peer {0} has published no public key yet")]
    NoKey(NodeId),

    #[error("malformed datagram:\n{0}")]
    Malformed(DatagramParseError),

    #[error("datagram belongs to network {got} but we are on {expected}")]
    ForeignNetwork { expected: NetworkId, got: NetworkId },

    #[error("datagram claims to come from us")]
    SelfSourced,

    #[error("{0} is not a member of this network")]
    UnknownPeer(NodeId),

    #[error("reflection does not carry an endpoint")]
    MalformedReflection,

    #[error("payload is not an ipv4 packet")]
    NotIpv4,

    #[error("source {claimed} does not belong to the sending peer ({expected})")]
    SpoofedSource {
        claimed: Ipv4Addr,
        expected: Ipv4Addr,
    },

}

enum Handled {
    Frame(usize),
    Probe(SocketAddr),
    /// A handshake message that must be answered to the endpoint it came from.
    Answer(SocketAddr, Vec<u8>),
    /// A session just came up, so anything held for it can go now.
    Ready(crate::keys::PublicKey, SocketAddr),
    Nothing,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    pub reflected: Option<SocketAddr>,
    pub stun: Option<SocketAddr>,
}

impl Observed {
    pub fn candidates(&self) -> impl Iterator<Item = SocketAddr> {
        [self.stun, self.reflected].into_iter().flatten()
    }

    pub fn is_empty(&self) -> bool {
        self.stun.is_none() && self.reflected.is_none()
    }
}

pub struct MeshDevice {
    socket: Arc<UdpSocket>,

    network: NetworkId,
    node: NodeId,
    broadcast: Ipv4Addr,

    peers: Peers,
    sessions: Sessions,
    /// Packets that arrived before a session existed. Held briefly so the first
    /// packet to a peer is not simply lost while the handshake completes.
    waiting: std::collections::HashMap<crate::keys::PublicKey, Vec<Vec<u8>>>,
    observed: Arc<watch::Sender<Observed>>,
    transaction: stun::Transaction,

    capabilities: DeviceCapabilities,

    rx: Box<[u8]>,
    tx: Box<[u8]>,
}

impl MeshDevice {
    pub async fn bind(
        addr: impl ToSocketAddrs,
        membership: &Membership,
        keys: Keypair,
    ) -> io::Result<(MeshDevice, MeshHandle)> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);

        for option in [libc::SO_RCVBUF, libc::SO_SNDBUF] {
            enlarge(&socket, option, MESH_SOCKET_BUFFER);
        }
        let peers = membership.peers.iter().cloned().collect::<Peers>();
        let observed = Arc::new(watch::Sender::new(Observed::default()));
        let transaction = stun::transaction();

        tracing::info!(
            local = %socket.local_addr()?,
            network = %membership.network,
            node = %membership.node,
            ip = %membership.ip,
            peers = peers.len(),
            "mesh device bound"
        );

        let device = MeshDevice {
            sessions: Sessions::new(keys.clone()),
            waiting: std::collections::HashMap::new(),
            socket: socket.clone(),
            network: membership.network,
            node: membership.node,
            broadcast: membership.broadcast(),
            peers: peers.clone(),
            observed: observed.clone(),
            transaction,
            capabilities: DeviceCapabilities {
                medium: Medium::Ip,
                mtu: MESH_MTU,
            },
            rx: vec![0u8; MAX_DATAGRAM_SIZE].into_boxed_slice(),
            tx: vec![0u8; MAX_DATAGRAM_SIZE].into_boxed_slice(),
        };

        let handle = MeshHandle {
            socket,
            network: membership.network,
            node: membership.node,
            peers,
            observed,
            transaction,
        };

        Ok((device, handle))
    }

    pub fn peers(&self) -> Peers {
        self.peers.clone()
    }

    /// Shorten how long a session lives before it is replaced.
    pub fn rekey_after(&mut self, after: std::time::Duration) {
        self.sessions.rekey_after(after);
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn record_reflection(&self, endpoint: SocketAddr) {
        let changed = self.observed.send_if_modified(|current| {
            if current.reflected == Some(endpoint) {
                return false;
            }

            current.reflected = Some(endpoint);

            true
        });

        if changed {
            tracing::info!(%endpoint, "the reflector reported our endpoint");
        }
    }

    fn record_stun(&self, endpoint: SocketAddr) {
        let changed = self.observed.send_if_modified(|current| {
            if current.stun == Some(endpoint) {
                return false;
            }

            current.stun = Some(endpoint);

            true
        });

        if changed {
            tracing::info!(%endpoint, "stun reported our public endpoint");
        }
    }

    fn member(&self, sender: &NodeId, from: SocketAddr) -> Result<Peer, Discard> {
        let Some(peer) = self.peers.get(sender) else {
            return Err(Discard::UnknownPeer(*sender));
        };

        if self.peers.learn_endpoint(sender, from) {
            tracing::info!(ip = %peer.ip, endpoint = %from, "peer endpoint learned");
        }

        Ok(peer)
    }

    fn accept(&mut self, size: usize, from: SocketAddr, out: &mut [u8]) -> Result<Handled, Discard> {
        // Encrypted data carries no node id, so it is recognised by its own
        // compact header before the plaintext control forms are parsed.
        if let Some(sealed) = crate::wire::Sealed::parse(&self.rx[..size]) {
            let Some(session) = self.sessions.by_index(sealed.index) else {
                return Err(Discard::NoSession(sealed.index));
            };

            let peer_key = session.peer();

            let len = session
                .open(sealed.counter, sealed.ciphertext, out)
                .map_err(|e| Discard::Undecryptable(format!("{e}")))?;

            let Some(peer) = self.peers.by_key(&peer_key) else {
                return Err(Discard::Unrecognised);
            };

            if self.peers.learn_endpoint(&peer.node, from) {
                tracing::info!(ip = %peer.ip, endpoint = %from, "peer endpoint learned");
            }

            let Some(source) = ipv4_source(&out[..len]) else {
                return Err(Discard::NotIpv4);
            };

            if source != peer.ip {
                return Err(Discard::SpoofedSource {
                    claimed: source,
                    expected: peer.ip,
                });
            }

            return Ok(Handled::Frame(len));
        }

        let datagram = Datagram::parse(&self.rx[..size]).map_err(Discard::Malformed)?;

        if datagram.network != self.network {
            return Err(Discard::ForeignNetwork {
                expected: self.network,
                got: datagram.network,
            });
        }

        if datagram.sender == self.node {
            return Err(Discard::SelfSourced);
        }

        match datagram.message {
            MessageType::Probe => Ok(Handled::Probe(from)),
            MessageType::Reflection => {
                let Some(observed) = decode_endpoint(datagram.payload) else {
                    return Err(Discard::MalformedReflection);
                };

                self.record_reflection(SocketAddr::V4(observed));

                Ok(Handled::Nothing)
            }
            MessageType::Keepalive => {
                self.member(&datagram.sender, from)?;

                Ok(Handled::Nothing)
            }
            MessageType::HandshakeInit => {
                // [..4] is the initiator's index, the rest is noise message one
                let Some((index, rest)) = datagram.payload.split_at_checked(4) else {
                    return Err(Discard::MalformedReflection);
                };

                let remote = u32::from_be_bytes(index.try_into().unwrap_or_default());

                let Some((ours, reply)) = self.sessions.on_initiation(rest, remote) else {
                    return Err(Discard::HandshakeRefused);
                };

                self.member(&datagram.sender, from).ok();

                let mut framed = Vec::with_capacity(8 + reply.len());
                framed.extend_from_slice(&remote.to_be_bytes());
                framed.extend_from_slice(&ours.to_be_bytes());
                framed.extend_from_slice(&reply);

                tracing::info!(peer = %datagram.sender, "answered a handshake");

                if let Some(peer) = self.peers.get(&datagram.sender)
                    && let Some(key) = peer.key
                    && let Some(held) = self.waiting.remove(&key)
                {
                    tracing::debug!(
                        held = held.len(),
                        "dropping packets held for a peer that called first"
                    );
                }

                Ok(Handled::Answer(from, framed))
            }
            MessageType::HandshakeReply => {
                let Some((indices, rest)) = datagram.payload.split_at_checked(8) else {
                    return Err(Discard::MalformedReflection);
                };

                let remote = u32::from_be_bytes(indices[4..8].try_into().unwrap_or_default());

                let Some(peer) = self.peers.get(&datagram.sender) else {
                    return Err(Discard::UnknownPeer(datagram.sender));
                };

                let Some(key) = peer.key else {
                    return Err(Discard::NoKey(datagram.sender));
                };

                if !self.sessions.on_reply(key, rest, remote) {
                    return Err(Discard::HandshakeRefused);
                }

                // The reply came back from whichever candidate could actually
                // carry it, which is now the address we should be using.
                self.member(&datagram.sender, from).ok();

                tracing::info!(
                    peer = %datagram.sender,
                    ip = %peer.ip,
                    endpoint = %from,
                    "session established"
                );

                Ok(Handled::Ready(key, from))
            }
}
    }

    fn reply_to_probe(&mut self, from: SocketAddr) {
        let Some(endpoint) = as_ipv4_endpoint(from) else {
            tracing::debug!(%from, "ignoring probe from a non ipv4 endpoint");
            return;
        };

        let payload = encode_endpoint(endpoint);
        let datagram = Datagram::new(
            MessageType::Reflection,
            self.network,
            self.node,
            &payload[..],
        );

        let size = datagram.write(&mut self.tx);

        if let Err(e) = self.socket.try_send_to(&self.tx[..size], from) {
            tracing::debug!(%from, "could not answer probe: {e}");
        }
    }

    /// Send anything that was waiting on this session being established.
    fn flush_waiting(&mut self, key: crate::keys::PublicKey, endpoint: SocketAddr) {
        let Some(queued) = self.waiting.remove(&key) else {
            return;
        };

        tracing::debug!(held = queued.len(), "flushing packets held for the handshake");

        for packet in queued {
            if let Err(e) = self.send_to(&packet, endpoint, key) {
                tracing::debug!("could not send a held packet: {e}");
            }
        }
    }

    /// Ask a peer for a session. Data cannot flow until it answers, so the
    /// packet that triggered this is dropped rather than sent in the clear.
    fn start_handshake(&mut self, key: crate::keys::PublicKey, endpoint: SocketAddr) {
        let Some((index, message)) = self.sessions.begin(key) else {
            return;
        };

        // A peer publishes every address it might be reachable at, and only it
        // knows which one works from here: a peer behind our own nat, or on this
        // machine, is unreachable at the public address stun handed it. Ask at
        // all of them at once and keep whichever answers.
        let mut targets = match self.peers.by_key(&key) {
            Some(peer) => peer.reachable_at(),
            None => vec![],
        };

        if !targets.contains(&endpoint) {
            targets.insert(0, endpoint);
        }

        targets.truncate(HANDSHAKE_FANOUT);

        let mut payload = Vec::with_capacity(4 + message.len());
        payload.extend_from_slice(&index.to_be_bytes());
        payload.extend_from_slice(&message);

        let datagram = Datagram::new(
            MessageType::HandshakeInit,
            self.network,
            self.node,
            &payload,
        );

        if datagram.size() > self.tx.len() {
            return;
        }

        let size = datagram.write(&mut self.tx);
        let mut asked = vec![];

        for target in targets {
            match self.socket.try_send_to(&self.tx[..size], target) {
                Ok(_) => asked.push(target),
                Err(e) => tracing::debug!(endpoint = %target, "could not start a handshake: {e}"),
            }
        }

        if !asked.is_empty() {
            tracing::info!(candidates = ?asked, "asked a peer for a session");
        }
    }

    /// Encrypt and send. There is no plaintext path: without a session the
    /// packet is dropped and a handshake is started instead.
    fn send_to(
        &mut self,
        packet: &[u8],
        endpoint: SocketAddr,
        key: crate::keys::PublicKey,
    ) -> Result<(), DeviceError> {
        let header = crate::wire::DATA_HEADER_SIZE;

        if header + packet.len() + crate::session::TAG_SIZE > self.tx.len() {
            return Err(DeviceError::BufferTooSmall {
                need: header + packet.len() + crate::session::TAG_SIZE,
                got: self.tx.len(),
            });
        }

        // A session that has run its course is replaced before it is a problem.
        // The handshake happens alongside the traffic: this packet, and every
        // one until the peer answers, still goes out under the current session.
        if self.sessions.needs_rekey(&key) {
            tracing::debug!(%endpoint, "session is due for a rekey");

            self.start_handshake(key, endpoint);
        }

        let Some(session) = self.sessions.established(&key) else {
            let queue = self.waiting.entry(key).or_default();

            if queue.len() < QUEUE_DEPTH {
                queue.push(packet.to_vec());
            }

            self.start_handshake(key, endpoint);

            return Ok(());
        };

        let index = session.remote_index();

        let (counter, written) = session
            .seal(packet, &mut self.tx[header..])
            .map_err(|e| DeviceError::Io(Box::new(io::Error::other(e.to_string()))))?;

        crate::wire::Sealed::write_header(index, counter, &mut self.tx);

        let size = header + written;

        match self.socket.try_send_to(&self.tx[..size], endpoint) {
            Ok(_) => {
                tracing::trace!(len = packet.len(), %endpoint, "packet sent to peer");
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(DeviceError::WouldBlock),
            Err(e) => Err(DeviceError::Io(Box::new(e))),
        }
    }

    fn flood(&mut self, packet: &[u8]) -> Result<(), DeviceError> {
        for (endpoint, key) in self.peers.reachable() {
            if let Err(e) = self.send_to(packet, endpoint, key) {
                tracing::debug!(%endpoint, "dropping broadcast for peer: {e}");
            }
        }

        Ok(())
    }
}

impl Device for MeshDevice {
    fn capabilities(&self) -> DeviceCapabilities {
        self.capabilities
    }

    fn read_frame(&mut self, data: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            let (size, from) = match self.socket.try_recv_from(&mut self.rx) {
                Ok(received) => received,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Err(DeviceError::WouldBlock);
                }
                Err(e) => return Err(DeviceError::Io(Box::new(e))),
            };

            if stun::is_stun(&self.rx[..size]) {
                match stun::parse_response(&self.rx[..size], &self.transaction) {
                    Some(endpoint) => self.record_stun(SocketAddr::V4(endpoint)),
                    None => tracing::debug!(%from, "ignoring an unusable stun message"),
                }

                continue;
            }

            match self.accept(size, from, data) {
                Ok(Handled::Frame(len)) => {
                    tracing::trace!(len, %from, "packet received from peer");
                    return Ok(len);
                }
                Ok(Handled::Probe(from)) => self.reply_to_probe(from),
                Ok(Handled::Answer(to, payload)) => {
                    let datagram = Datagram::new(
                        MessageType::HandshakeReply,
                        self.network,
                        self.node,
                        &payload,
                    );

                    if datagram.size() <= self.tx.len() {
                        let size = datagram.write(&mut self.tx);

                        if let Err(e) = self.socket.try_send_to(&self.tx[..size], to) {
                            tracing::debug!(%to, "could not answer a handshake: {e}");
                        }
                    }

                    continue;
                }
                Ok(Handled::Ready(key, endpoint)) => {
                    self.flush_waiting(key, endpoint);
                    continue;
                }
                Ok(Handled::Nothing) => continue,
                Err(reason) => {
                    tracing::debug!(%from, "discarding datagram: {reason}");
                    continue;
                }
            }
        }
    }

    fn write_frame(&mut self, data: &[u8]) -> Result<(), DeviceError> {
        let Some(destination) = ipv4_destination(data) else {
            tracing::debug!(
                len = data.len(),
                "dropping frame that is not an ipv4 packet"
            );
            return Ok(());
        };

        if destination == self.broadcast || destination == Ipv4Addr::BROADCAST {
            return self.flood(data);
        }

        let Some(peer) = self.peers.for_ip(&destination) else {
            tracing::debug!(%destination, "dropping frame for an unreachable destination");
            return Ok(());
        };

        let (Some(endpoint), Some(key)) = (peer.endpoint, peer.key) else {
            // Fail closed: with no endpoint or no published key there is no way
            // to send this without putting it on the wire in the clear.
            tracing::debug!(%destination, "dropping frame, no encrypted path to that peer yet");
            return Ok(());
        };

        self.send_to(data, endpoint, key)
    }

    fn poll_readable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_recv_ready(cx)
    }

    fn poll_writable(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

#[derive(Clone)]
pub struct MeshHandle {
    socket: Arc<UdpSocket>,

    network: NetworkId,
    node: NodeId,

    peers: Peers,
    observed: Arc<watch::Sender<Observed>>,
    transaction: stun::Transaction,
}

impl MeshHandle {
    pub fn peers(&self) -> Peers {
        self.peers.clone()
    }

    pub fn network(&self) -> NetworkId {
        self.network
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn observed(&self) -> Observed {
        *self.observed.borrow()
    }

    pub fn observe(&self) -> watch::Receiver<Observed> {
        self.observed.subscribe()
    }

    async fn send(&self, message: MessageType, payload: &[u8], to: SocketAddr) -> io::Result<()> {
        let mut bytes = [0u8; HEADER_SIZE + ENDPOINT_SIZE];
        let size = Datagram::new(message, self.network, self.node, payload).write(&mut bytes);

        self.socket.send_to(&bytes[..size], to).await?;

        Ok(())
    }

    pub async fn probe(&self, reflector: SocketAddr) -> io::Result<()> {
        self.send(MessageType::Probe, &[], reflector).await?;

        tracing::debug!(%reflector, "probing the reflector for our endpoint");

        Ok(())
    }

    pub async fn stun(&self, server: SocketAddr) -> io::Result<()> {
        self.socket
            .send_to(&stun::request(&self.transaction), server)
            .await?;

        tracing::debug!(%server, "sent a stun binding request");

        Ok(())
    }

    pub async fn keepalive(&self, endpoint: SocketAddr) -> io::Result<()> {
        self.send(MessageType::Keepalive, &[], endpoint).await?;

        tracing::trace!(%endpoint, "keepalive sent");

        Ok(())
    }

    pub async fn keepalive_all(&self) -> io::Result<usize> {
        let endpoints = self.peers.endpoints();

        for endpoint in &endpoints {
            self.keepalive(*endpoint).await?;
        }

        Ok(endpoints.len())
    }
}

impl std::fmt::Debug for MeshHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshHandle")
            .field("network", &self.network)
            .field("node", &self.node)
            .field("local_addr", &self.socket.local_addr().ok())
            .field("observed", &self.observed())
            .field("peers", &self.peers.len())
            .finish()
    }
}

#[cfg(test)]
mod test {
    use std::net::Ipv4Addr;

    use crate::device::{ipv4_destination, ipv4_source};

    fn packet() -> [u8; 20] {
        let mut bytes = [0u8; 20];

        bytes[0] = 0x45;
        bytes[12..16].copy_from_slice(&[10, 30, 0, 2]);
        bytes[16..20].copy_from_slice(&[10, 30, 0, 3]);

        bytes
    }

    #[test]
    fn addresses_are_read_from_the_ipv4_header() {
        let packet = packet();

        assert_eq!(ipv4_source(&packet), Some(Ipv4Addr::new(10, 30, 0, 2)));
        assert_eq!(ipv4_destination(&packet), Some(Ipv4Addr::new(10, 30, 0, 3)));
    }

    #[test]
    fn a_short_packet_has_no_addresses() {
        let packet = packet();

        for len in 0..20 {
            assert_eq!(ipv4_source(&packet[..len]), None, "len = {len}");
            assert_eq!(ipv4_destination(&packet[..len]), None, "len = {len}");
        }
    }

    #[test]
    fn a_foreign_ip_version_is_rejected() {
        let mut packet = packet();
        packet[0] = 0x60;

        assert_eq!(ipv4_source(&packet), None);
        assert_eq!(ipv4_destination(&packet), None);
    }
}
