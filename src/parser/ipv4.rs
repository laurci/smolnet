use net_header::{NetHeader, parse::HeaderParseError, write::HeaderWriteError};
use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    parser::icmp::{IcmpFrame, IcmpFrameParseError},
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

    #[error("unknown ipv4 protocol {0:x}")]
    UnknownProtocol(u8),

    #[error("failed to parse icmp frame:\n{0}")]
    IcmpFrameParseError(IcmpFrameParseError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv4Payload {
    ICMP(IcmpFrame),
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
                tracing::warn!("udp is not implemented");
                return Err(Ipv4FrameParseError::UnknownProtocol(IPV4_PROTOCOL_UDP));
            }
            unknown_value => return Err(Ipv4FrameParseError::UnknownProtocol(unknown_value)),
        };

        let frame = Ipv4Frame { header, payload };

        Ok(frame)
    }

    pub fn write(self, bytes: &mut [u8]) -> Result<usize, HeaderWriteError> {
        let size = self.header.write(bytes)?;

        let payload_size = match self.payload {
            Ipv4Payload::ICMP(frame) => frame.write(&mut bytes[Ipv4Header::SIZE..])?,
        };

        Ok(size + payload_size)
    }

    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, payload: Ipv4Payload) -> Ipv4Frame {
        let (protocol, payload_size) = match &payload {
            Ipv4Payload::ICMP(frame) => (IPV4_PROTOCOL_ICMP, frame.size()), // TODO: when ICMP implemented
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
        let size = header.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), size);

        let checksum = net_header::checksum(&bytes);

        assert_eq!(checksum, 0);

        assert_eq!(header.ihl(), 0x03);
        assert_eq!(header.version(), 0x04);
    }
}
