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
    peer::{Peer, Peers},
    stun,
    wire::{
        Datagram, DatagramParseError, ENDPOINT_SIZE, HEADER_SIZE, MessageType, as_ipv4_endpoint,
        decode_endpoint, encode_endpoint,
    },
};

pub const MESH_MTU: usize = 1280;

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

    #[error("payload of {payload} bytes exceeds the receive buffer ({buffer})")]
    Oversized { payload: usize, buffer: usize },
}

enum Handled {
    Frame(usize),
    Probe(SocketAddr),
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

    fn accept(&self, size: usize, from: SocketAddr, out: &mut [u8]) -> Result<Handled, Discard> {
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
            MessageType::Data => {
                let peer = self.member(&datagram.sender, from)?;

                let Some(source) = ipv4_source(datagram.payload) else {
                    return Err(Discard::NotIpv4);
                };

                if source != peer.ip {
                    return Err(Discard::SpoofedSource {
                        claimed: source,
                        expected: peer.ip,
                    });
                }

                if datagram.payload.len() > out.len() {
                    return Err(Discard::Oversized {
                        payload: datagram.payload.len(),
                        buffer: out.len(),
                    });
                }

                out[..datagram.payload.len()].copy_from_slice(datagram.payload);

                Ok(Handled::Frame(datagram.payload.len()))
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

    fn send_to(&mut self, packet: &[u8], endpoint: SocketAddr) -> Result<(), DeviceError> {
        let datagram = Datagram::new(MessageType::Data, self.network, self.node, packet);

        if datagram.size() > self.tx.len() {
            return Err(DeviceError::BufferTooSmall {
                need: datagram.size(),
                got: self.tx.len(),
            });
        }

        let size = datagram.write(&mut self.tx);

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
        for endpoint in self.peers.endpoints() {
            if let Err(e) = self.send_to(packet, endpoint) {
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

        let Some(endpoint) = self.peers.route(&destination) else {
            tracing::debug!(%destination, "dropping frame for an unreachable destination");
            return Ok(());
        };

        self.send_to(data, endpoint)
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
