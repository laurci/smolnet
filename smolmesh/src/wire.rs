use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use thiserror::Error;

use crate::id::{NetworkId, NodeId};

pub const MESH_VERSION: u8 = 0x40;

pub const HEADER_SIZE: usize = 2 + NetworkId::SIZE + NodeId::SIZE;

const NETWORK_OFFSET: usize = 2;
const SENDER_OFFSET: usize = NETWORK_OFFSET + NetworkId::SIZE;

pub const ENDPOINT_SIZE: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Data,
    Keepalive,
    Probe,
    Reflection,
}

impl MessageType {
    pub fn code(&self) -> u8 {
        match self {
            MessageType::Data => 1,
            MessageType::Keepalive => 2,
            MessageType::Probe => 3,
            MessageType::Reflection => 4,
        }
    }

    pub fn from_code(code: u8) -> Option<MessageType> {
        match code {
            1 => Some(MessageType::Data),
            2 => Some(MessageType::Keepalive),
            3 => Some(MessageType::Probe),
            4 => Some(MessageType::Reflection),
            _ => None,
        }
    }
}

pub fn encode_endpoint(endpoint: SocketAddrV4) -> [u8; ENDPOINT_SIZE] {
    let mut bytes = [0u8; ENDPOINT_SIZE];

    bytes[..4].copy_from_slice(&endpoint.ip().octets());
    bytes[4..].copy_from_slice(&endpoint.port().to_be_bytes());

    bytes
}

pub fn decode_endpoint(bytes: &[u8]) -> Option<SocketAddrV4> {
    let address: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let port: [u8; 2] = bytes.get(4..ENDPOINT_SIZE)?.try_into().ok()?;

    Some(SocketAddrV4::new(
        Ipv4Addr::from(address),
        u16::from_be_bytes(port),
    ))
}

pub fn as_ipv4_endpoint(endpoint: SocketAddr) -> Option<SocketAddrV4> {
    match endpoint {
        SocketAddr::V4(endpoint) => Some(endpoint),
        SocketAddr::V6(_) => None,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DatagramParseError {
    #[error("datagram is shorter than the mesh header (expected >= {HEADER_SIZE}; got = {0})")]
    TooShort(usize),

    #[error("unsupported mesh version (expected {MESH_VERSION}; got {0})")]
    UnsupportedVersion(u8),

    #[error("unknown message type {0}")]
    UnknownMessage(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub message: MessageType,
    pub network: NetworkId,
    pub sender: NodeId,
    pub payload: &'a [u8],
}

impl<'a> Datagram<'a> {
    pub fn new(
        message: MessageType,
        network: NetworkId,
        sender: NodeId,
        payload: &'a [u8],
    ) -> Datagram<'a> {
        Datagram {
            message,
            network,
            sender,
            payload,
        }
    }

    pub fn parse(bytes: &'a [u8]) -> Result<Datagram<'a>, DatagramParseError> {
        if bytes.len() < HEADER_SIZE {
            return Err(DatagramParseError::TooShort(bytes.len()));
        }

        if bytes[0] != MESH_VERSION {
            return Err(DatagramParseError::UnsupportedVersion(bytes[0]));
        }

        let message =
            MessageType::from_code(bytes[1]).ok_or(DatagramParseError::UnknownMessage(bytes[1]))?;

        let network = NetworkId::from_slice(&bytes[NETWORK_OFFSET..SENDER_OFFSET])
            .expect("the network id is bounded by the header size check");
        let sender = NodeId::from_slice(&bytes[SENDER_OFFSET..HEADER_SIZE])
            .expect("the sender id is bounded by the header size check");

        Ok(Datagram {
            message,
            network,
            sender,
            payload: &bytes[HEADER_SIZE..],
        })
    }

    pub fn size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        bytes[0] = MESH_VERSION;
        bytes[1] = self.message.code();
        bytes[NETWORK_OFFSET..SENDER_OFFSET].copy_from_slice(self.network.as_bytes());
        bytes[SENDER_OFFSET..HEADER_SIZE].copy_from_slice(self.sender.as_bytes());

        let end = self.size();
        bytes[HEADER_SIZE..end].copy_from_slice(self.payload);

        end
    }
}

#[cfg(test)]
mod test {
    use crate::{
        id::{NetworkId, NodeId},
        wire::{
            Datagram, DatagramParseError, ENDPOINT_SIZE, HEADER_SIZE, MESH_VERSION, MessageType,
            as_ipv4_endpoint, decode_endpoint, encode_endpoint,
        },
    };

    #[test]
    fn the_version_byte_can_never_look_like_stun() {
        assert_ne!(
            MESH_VERSION & 0xc0,
            0,
            "stun requires the top two bits of its first byte to be zero"
        );
    }

    #[test]
    fn the_header_is_fifty_bytes() {
        assert_eq!(HEADER_SIZE, 50);
    }

    #[test]
    fn codec_round_trip() {
        let datagram = Datagram::new(
            MessageType::Data,
            NetworkId::random(),
            NodeId::random(),
            b"an ipv4 packet would live here",
        );

        let mut bytes = [0u8; 128];
        let size = datagram.write(&mut bytes);

        assert_eq!(size, datagram.size());
        assert_eq!(Datagram::parse(&bytes[..size]), Ok(datagram));
    }

    #[test]
    fn a_keepalive_carries_no_payload() {
        let datagram = Datagram::new(
            MessageType::Keepalive,
            NetworkId::random(),
            NodeId::random(),
            &[],
        );

        let mut bytes = [0u8; HEADER_SIZE];
        let size = datagram.write(&mut bytes);

        assert_eq!(size, HEADER_SIZE);

        let parsed = Datagram::parse(&bytes).unwrap();
        assert_eq!(parsed.message, MessageType::Keepalive);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn rejects_truncated() {
        let datagram = Datagram::new(
            MessageType::Data,
            NetworkId::random(),
            NodeId::random(),
            b"payload",
        );

        let mut bytes = [0u8; 128];
        datagram.write(&mut bytes);

        for len in 0..HEADER_SIZE {
            assert_eq!(
                Datagram::parse(&bytes[..len]),
                Err(DatagramParseError::TooShort(len))
            );
        }
    }

    #[test]
    fn rejects_a_foreign_version() {
        let mut bytes = [0u8; HEADER_SIZE];
        Datagram::new(
            MessageType::Data,
            NetworkId::random(),
            NodeId::random(),
            &[],
        )
        .write(&mut bytes);

        bytes[0] = MESH_VERSION + 1;

        assert_eq!(
            Datagram::parse(&bytes),
            Err(DatagramParseError::UnsupportedVersion(MESH_VERSION + 1))
        );
    }

    #[test]
    fn rejects_an_unknown_message_type() {
        let mut bytes = [0u8; HEADER_SIZE];
        Datagram::new(
            MessageType::Data,
            NetworkId::random(),
            NodeId::random(),
            &[],
        )
        .write(&mut bytes);

        bytes[1] = 200;

        assert_eq!(
            Datagram::parse(&bytes),
            Err(DatagramParseError::UnknownMessage(200))
        );
    }

    #[test]
    fn message_codes_are_stable() {
        assert_eq!(MessageType::Data.code(), 1);
        assert_eq!(MessageType::Keepalive.code(), 2);
        assert_eq!(MessageType::Probe.code(), 3);
        assert_eq!(MessageType::Reflection.code(), 4);

        assert_eq!(MessageType::from_code(0), None);
        assert_eq!(MessageType::from_code(5), None);
    }

    #[test]
    fn endpoints_round_trip() {
        let endpoint = "203.0.113.7:51820".parse().unwrap();

        assert_eq!(decode_endpoint(&encode_endpoint(endpoint)), Some(endpoint));
    }

    #[test]
    fn a_truncated_endpoint_is_rejected() {
        let bytes = encode_endpoint("203.0.113.7:51820".parse().unwrap());

        for len in 0..ENDPOINT_SIZE {
            assert_eq!(decode_endpoint(&bytes[..len]), None, "len = {len}");
        }
    }

    #[test]
    fn only_ipv4_endpoints_can_be_reflected() {
        assert!(as_ipv4_endpoint("127.0.0.1:1".parse().unwrap()).is_some());
        assert!(as_ipv4_endpoint("[::1]:1".parse().unwrap()).is_none());
    }
}
