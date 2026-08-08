use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    device::MAX_FRAME_SIZE,
    parser::{
        icmp::{IcmpFrame, IcmpFrameParseError},
        udp::{UdpFrame, UdpFrameParseError},
    },
    stack::StackIdentity,
};

const IPV4_TX_VERSION_IHL: u8 = 0x4_5; // version = 4; ihl = 5;

const IPV4_FLAG_DONT_FRAGMENT: u16 = 0x4000;

const IPV4_PROTOCOL_ICMP: u8 = 1;
const IPV4_PROTOCOL_TCP: u8 = 6;
const IPV4_PROTOCOL_UDP: u8 = 17;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "ip4")]
pub struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,

    identification: u16,
    flags: u16,

    ttl: u8,
    protocol: u8,

    #[header(checksum)]
    hdr_checksum: u16,

    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

impl Ipv4Header {
    pub fn ihl(&self) -> u8 {
        return self.version_ihl & 0x0f;
    }

    pub fn version(&self) -> u8 {
        return (self.version_ihl >> 4) & 0x0f;
    }
}

#[derive(Debug, Error)]
pub enum Ipv4FrameParseError {
    #[error("failed to parse ipv4 header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("invalid version for ipv4 header (expected = 4; got = {0})")]
    InvalidVersion(u8),

    #[error("invalid header len for ipv4 header (expected >= 20 && <= 60; got = {0})")]
    InvalidHeaderLen(u8),

    #[error("invalid header checksum for ipv4 header {0}")]
    InvalidHeaderChecksum(u16),

    #[error("invalid payload let from ipv4 header: {0}")]
    InvalidPayloadLen(u16),

    #[error("invalid payload (udp) checksum for ipv4 header {0}")]
    InvalidUdpPayloadChecksum(u16),

    #[error("invalid payload (tcp) checksum for ipv4 header {0}")]
    InvalidTcpPayloadChecksum(u16),

    #[error("unknown ipv4 protocol {0:x}")]
    UnknownProtocol(u8),

    #[error("failed to parse icmp frame:\n{0}")]
    IcmpFrameParseError(IcmpFrameParseError),

    #[error("failed to parse udp frame:\n{0}")]
    UdpFrameParseError(UdpFrameParseError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv4Payload {
    ICMP(IcmpFrame),
    UDP(UdpFrame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv4Frame {
    header: Ipv4Header,
    pub payload: Ipv4Payload,
}

impl Ipv4Frame {
    pub fn parse(bytes: &[u8]) -> Result<Self, Ipv4FrameParseError> {
        let header =
            Ipv4Header::from_bytes(bytes).map_err(|e| Ipv4FrameParseError::HeaderParseError(e))?;

        if header.version() != 4 {
            return Err(Ipv4FrameParseError::InvalidVersion(header.version()));
        }

        let header_len = header.ihl() * 4;
        if header_len < 20 || header_len > 60 {
            return Err(Ipv4FrameParseError::InvalidHeaderLen(header_len));
        }

        let header_bytes = &bytes[..header_len as usize];
        let header_checksum = net_header::checksum(header_bytes);
        if header_checksum != 0 {
            return Err(Ipv4FrameParseError::InvalidHeaderChecksum(header_checksum));
        }

        let payload_len = header.total_length - header_len as u16;
        let payload_offset = header_len as usize;
        let payload_end = payload_offset + payload_len as usize;

        if payload_end > bytes.len() {
            return Err(Ipv4FrameParseError::InvalidPayloadLen(payload_len));
        }

        let payload_bytes = &bytes[payload_offset..payload_end];

        let payload = match header.protocol {
            IPV4_PROTOCOL_ICMP => {
                let frame = IcmpFrame::parse(payload_bytes)
                    .map_err(|e| Ipv4FrameParseError::IcmpFrameParseError(e))?;

                Ipv4Payload::ICMP(frame)
            }
            IPV4_PROTOCOL_TCP => {
                tracing::warn!("tcp is not implemented");
                return Err(Ipv4FrameParseError::UnknownProtocol(IPV4_PROTOCOL_TCP));
            }
            IPV4_PROTOCOL_UDP => {
                let checksum = pseudo_header_checksum(
                    &header.src_addr,
                    &header.dst_addr,
                    IPV4_PROTOCOL_UDP,
                    &payload_bytes,
                );

                let frame = UdpFrame::parse(payload_bytes)
                    .map_err(|e| Ipv4FrameParseError::UdpFrameParseError(e))?;

                if !frame.validate_checksum(checksum) {
                    return Err(Ipv4FrameParseError::InvalidUdpPayloadChecksum(checksum));
                }

                Ipv4Payload::UDP(frame)
            }
            unknown_value => return Err(Ipv4FrameParseError::UnknownProtocol(unknown_value)),
        };

        let frame = Ipv4Frame { header, payload };

        Ok(frame)
    }

    pub fn write(self, bytes: &mut [u8]) -> usize {
        let size = self.header.write(bytes);

        let src = self.src().clone();
        let dst = self.dst().clone();
        let payload_size = match self.payload {
            Ipv4Payload::ICMP(frame) => frame.write(&mut bytes[Ipv4Header::SIZE..]),
            Ipv4Payload::UDP(frame) => {
                let size = frame.write(&mut bytes[Ipv4Header::SIZE..]);

                let end = Ipv4Header::SIZE + size;

                let mut checksum = pseudo_header_checksum(
                    &src,
                    &dst,
                    IPV4_PROTOCOL_UDP,
                    &bytes[Ipv4Header::SIZE..end],
                );

                if checksum == 0 {
                    checksum = 0xffff;
                }

                let checksum_offset = Ipv4Header::SIZE + UdpFrame::CHECKSUM_OFFSET;
                bytes[checksum_offset..checksum_offset + 2]
                    .copy_from_slice(&checksum.to_be_bytes());

                size
            }
        };

        size + payload_size
    }

    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, payload: Ipv4Payload) -> Ipv4Frame {
        let (protocol, payload_size) = match &payload {
            Ipv4Payload::ICMP(frame) => (IPV4_PROTOCOL_ICMP, frame.size()),
            Ipv4Payload::UDP(frame) => (IPV4_PROTOCOL_UDP, frame.size()),
        };

        let header = Ipv4Header {
            version_ihl: IPV4_TX_VERSION_IHL,
            tos: 0,
            total_length: (Ipv4Header::SIZE + payload_size) as u16,

            identification: 0,
            flags: IPV4_FLAG_DONT_FRAGMENT,

            ttl: 64,
            protocol,

            hdr_checksum: 0,

            src_addr: src,
            dst_addr: dst,
        };

        Ipv4Frame { header, payload }
    }

    pub fn reply(&self, identity: &StackIdentity, payload: Ipv4Payload) -> Ipv4Frame {
        Ipv4Frame::new(identity.ip, *self.src(), payload)
    }

    pub fn src(&self) -> &Ipv4Addr {
        &self.header.src_addr
    }

    pub fn dst(&self) -> &Ipv4Addr {
        &self.header.dst_addr
    }
}

pub fn pseudo_header_checksum(
    src_addr: &Ipv4Addr,
    dst_addr: &Ipv4Addr,
    protocol: u8,
    data: &[u8],
) -> u16 {
    const PSEUDO_HEADER_SIZE: usize = 12;
    let mut buffer = [0u8; MAX_FRAME_SIZE + PSEUDO_HEADER_SIZE];

    buffer[0..4].copy_from_slice(src_addr);
    buffer[4..8].copy_from_slice(dst_addr);
    buffer[8] = 0x00;
    buffer[9] = protocol;

    buffer[10..12].copy_from_slice(&(data.len() as u16).to_be_bytes());

    let end = data.len() + PSEUDO_HEADER_SIZE;
    buffer[12..end].copy_from_slice(data);

    net_header::checksum(&buffer[..end])
}

#[cfg(test)]
mod test {
    use net_header::NetHeader;

    use crate::parser::ipv4::Ipv4Header;

    #[test]
    fn ip_hdr_checksum() {
        let header = Ipv4Header {
            version_ihl: 0x43,
            tos: 0x02,
            total_length: 0x03,
            identification: 0x04,
            flags: 0x05,
            ttl: 0x06,
            protocol: 0x07,
            hdr_checksum: 0,
            src_addr: [0x08, 0x08, 0x08, 0x08],
            dst_addr: [0x09, 0x09, 0x09, 0x09],
        };

        let mut bytes = [0u8; Ipv4Header::SIZE];
        let size = header.write(&mut bytes);
        assert_eq!(bytes.len(), size);

        let checksum = net_header::checksum(&bytes);

        assert_eq!(checksum, 0);

        assert_eq!(header.ihl(), 0x03);
        assert_eq!(header.version(), 0x04);
    }
}
