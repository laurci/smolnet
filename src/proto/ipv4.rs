use std::borrow::Cow;

use net_header::{Checksum, NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::{
    addr::Ipv4Addr,
    proto::{
        icmp::{IcmpFrame, IcmpFrameParseError},
        options::{Ipv4Options, OptionsTooLong},
        tcp::wire::{TcpFrame, TcpFrameParseError},
        udp::wire::{UdpFrame, UdpFrameParseError},
    },
};

const IPV4_VERSION: u8 = 4;

const IPV4_FLAG_DONT_FRAGMENT: u16 = 0x4000;
const IPV4_FLAG_MORE_FRAGMENTS: u16 = 0x2000;
const IPV4_FRAG_OFFSET_MASK: u16 = 0x1fff;

pub const IPV4_MIN_HEADER_SIZE: u8 = 20;
pub const IPV4_MAX_HEADER_SIZE: u8 = 60;

pub const IPV4_DEFAULT_TTL: u8 = 64;

pub const IPV4_PROTOCOL_ICMP: u8 = 1;
pub const IPV4_PROTOCOL_TCP: u8 = 6;
pub const IPV4_PROTOCOL_UDP: u8 = 17;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "ip4")]
pub struct Ipv4Header {
    version_ihl: u8,
    tos: u8,
    total_length: u16,

    identification: u16,
    flags_frag_offset: u16,

    ttl: u8,
    protocol: u8,

    #[header(checksum)]
    hdr_checksum: u16,

    src_addr: [u8; 4],
    dst_addr: [u8; 4],
}

impl Ipv4Header {
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0f
    }

    pub fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0x0f
    }

    pub fn header_len(&self) -> u8 {
        self.ihl().saturating_mul(4)
    }

    pub fn dscp(&self) -> u8 {
        self.tos >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.tos & 0x03
    }

    pub fn dont_fragment(&self) -> bool {
        self.flags_frag_offset & IPV4_FLAG_DONT_FRAGMENT != 0
    }

    pub fn more_fragments(&self) -> bool {
        self.flags_frag_offset & IPV4_FLAG_MORE_FRAGMENTS != 0
    }

    pub fn fragment_offset(&self) -> u16 {
        self.flags_frag_offset & IPV4_FRAG_OFFSET_MASK
    }

    pub fn is_fragment(&self) -> bool {
        self.more_fragments() || self.fragment_offset() != 0
    }

    fn pseudo_header_seed(&self, transport_len: u16) -> Checksum {
        let mut checksum = Checksum::new();
        checksum.push_ipv4_pseudo_header(
            &self.src_addr,
            &self.dst_addr,
            self.protocol,
            transport_len,
        );

        checksum
    }

    fn transport_checksum(&self, payload: &[u8]) -> u16 {
        let mut checksum = self.pseudo_header_seed(payload.len() as u16);
        checksum.push(payload);

        checksum.finish()
    }
}

#[derive(Debug, Error)]
pub enum Ipv4FrameParseError {
    #[error("failed to parse ipv4 header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("invalid version for ipv4 header (expected = {IPV4_VERSION}; got = {0})")]
    InvalidVersion(u8),

    #[error(
        "invalid header len for ipv4 header (expected >= {IPV4_MIN_HEADER_SIZE} && <= {IPV4_MAX_HEADER_SIZE}; got = {0})"
    )]
    InvalidHeaderLen(u8),

    #[error("ipv4 total length {total_length} is smaller than the header length {header_len}")]
    InvalidTotalLength { total_length: u16, header_len: u8 },

    #[error("invalid header checksum for ipv4 header {0}")]
    InvalidHeaderChecksum(u16),

    #[error("truncated ipv4 datagram (expected = {expected}; got = {got})")]
    Truncated { expected: usize, got: usize },

    #[error("ipv4 reassembly is not supported (fragment offset = {offset}; more = {more})")]
    Fragmented { offset: u16, more: bool },

    #[error("ipv4 options are too long:\n{0}")]
    OptionsTooLong(OptionsTooLong),

    #[error("invalid payload (udp) checksum for ipv4 frame {0}")]
    InvalidUdpPayloadChecksum(u16),

    #[error("invalid payload (tcp) checksum for ipv4 frame {0}")]
    InvalidTcpPayloadChecksum(u16),

    #[error("failed to parse icmp frame:\n{0}")]
    IcmpFrameParseError(IcmpFrameParseError),

    #[error("failed to parse udp frame:\n{0}")]
    UdpFrameParseError(UdpFrameParseError),

    #[error("failed to parse tcp frame:\n{0}")]
    TcpFrameParseError(TcpFrameParseError),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Ipv4Payload<'a> {
    Icmp(IcmpFrame<'a>),
    Udp(UdpFrame<'a>),
    Tcp(TcpFrame<'a>),
    Unknown { protocol: u8, data: Cow<'a, [u8]> },
}

impl<'a> Ipv4Payload<'a> {
    pub fn protocol(&self) -> u8 {
        match self {
            Ipv4Payload::Icmp(_) => IPV4_PROTOCOL_ICMP,
            Ipv4Payload::Udp(_) => IPV4_PROTOCOL_UDP,
            Ipv4Payload::Tcp(_) => IPV4_PROTOCOL_TCP,
            Ipv4Payload::Unknown { protocol, .. } => *protocol,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Ipv4Payload::Icmp(frame) => frame.size(),
            Ipv4Payload::Udp(frame) => frame.size(),
            Ipv4Payload::Tcp(frame) => frame.size(),
            Ipv4Payload::Unknown { data, .. } => data.len(),
        }
    }

    pub fn into_owned(self) -> Ipv4Payload<'static> {
        match self {
            Ipv4Payload::Icmp(frame) => Ipv4Payload::Icmp(frame.into_owned()),
            Ipv4Payload::Udp(frame) => Ipv4Payload::Udp(frame.into_owned()),
            Ipv4Payload::Tcp(frame) => Ipv4Payload::Tcp(frame.into_owned()),
            Ipv4Payload::Unknown { protocol, data } => Ipv4Payload::Unknown {
                protocol,
                data: Cow::Owned(data.into_owned()),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Ipv4Frame<'a> {
    header: Ipv4Header,
    options: Ipv4Options,
    payload: Ipv4Payload<'a>,
}

impl<'a> Ipv4Frame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Ipv4Frame<'a>, Ipv4FrameParseError> {
        let header =
            Ipv4Header::from_bytes(bytes).map_err(Ipv4FrameParseError::HeaderParseError)?;

        if header.version() != IPV4_VERSION {
            return Err(Ipv4FrameParseError::InvalidVersion(header.version()));
        }

        let header_len = header.header_len();
        if header_len < IPV4_MIN_HEADER_SIZE || header_len > IPV4_MAX_HEADER_SIZE {
            return Err(Ipv4FrameParseError::InvalidHeaderLen(header_len));
        }

        let Some(header_bytes) = bytes.get(..header_len as usize) else {
            return Err(Ipv4FrameParseError::Truncated {
                expected: header_len as usize,
                got: bytes.len(),
            });
        };

        let header_checksum = net_header::checksum(header_bytes);
        if header_checksum != 0 {
            return Err(Ipv4FrameParseError::InvalidHeaderChecksum(header_checksum));
        }

        if header.is_fragment() {
            return Err(Ipv4FrameParseError::Fragmented {
                offset: header.fragment_offset(),
                more: header.more_fragments(),
            });
        }

        if header.total_length < header_len as u16 {
            return Err(Ipv4FrameParseError::InvalidTotalLength {
                total_length: header.total_length,
                header_len,
            });
        }

        let options = Ipv4Options::from_slice(&header_bytes[IPV4_MIN_HEADER_SIZE as usize..])
            .map_err(Ipv4FrameParseError::OptionsTooLong)?;

        let payload_len = (header.total_length - header_len as u16) as usize;
        let payload_offset = header_len as usize;

        let Some(payload_bytes) = bytes.get(payload_offset..payload_offset + payload_len) else {
            return Err(Ipv4FrameParseError::Truncated {
                expected: payload_offset + payload_len,
                got: bytes.len(),
            });
        };

        let payload = match header.protocol {
            IPV4_PROTOCOL_ICMP => {
                let frame = IcmpFrame::parse(payload_bytes)
                    .map_err(Ipv4FrameParseError::IcmpFrameParseError)?;

                Ipv4Payload::Icmp(frame)
            }
            IPV4_PROTOCOL_TCP => {
                let frame = TcpFrame::parse(payload_bytes)
                    .map_err(Ipv4FrameParseError::TcpFrameParseError)?;

                let sum = header.transport_checksum(payload_bytes);
                if sum != 0 {
                    return Err(Ipv4FrameParseError::InvalidTcpPayloadChecksum(sum));
                }

                Ipv4Payload::Tcp(frame)
            }
            IPV4_PROTOCOL_UDP => {
                let frame = UdpFrame::parse(payload_bytes)
                    .map_err(Ipv4FrameParseError::UdpFrameParseError)?;

                if frame.checksum() != 0 {
                    let sum = header.transport_checksum(payload_bytes);
                    if sum != 0 {
                        return Err(Ipv4FrameParseError::InvalidUdpPayloadChecksum(sum));
                    }
                }

                Ipv4Payload::Udp(frame)
            }
            protocol => {
                tracing::trace!(
                    protocol,
                    len = payload_bytes.len(),
                    "retaining ipv4 payload with an unknown protocol"
                );

                Ipv4Payload::Unknown {
                    protocol,
                    data: Cow::Borrowed(payload_bytes),
                }
            }
        };

        Ok(Ipv4Frame {
            header,
            options,
            payload,
        })
    }

    pub fn new(src: Ipv4Addr, dst: Ipv4Addr, payload: Ipv4Payload<'a>) -> Ipv4Frame<'a> {
        let header = Ipv4Header {
            version_ihl: (IPV4_VERSION << 4) | (IPV4_MIN_HEADER_SIZE / 4),
            tos: 0,
            total_length: (IPV4_MIN_HEADER_SIZE as usize + payload.size()) as u16,

            identification: 0,
            flags_frag_offset: IPV4_FLAG_DONT_FRAGMENT,

            ttl: IPV4_DEFAULT_TTL,
            protocol: payload.protocol(),

            hdr_checksum: 0,

            src_addr: src,
            dst_addr: dst,
        };

        Ipv4Frame {
            header,
            options: Ipv4Options::EMPTY,
            payload,
        }
    }

    pub fn with_options(mut self, options: Ipv4Options) -> Ipv4Frame<'a> {
        self.options = options;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Ipv4Frame<'a> {
        self.header.ttl = ttl;
        self
    }

    pub fn with_tos(mut self, tos: u8) -> Ipv4Frame<'a> {
        self.header.tos = tos;
        self
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        let header_len = self.header_len();

        let mut header = self.header.clone();
        header.version_ihl = (IPV4_VERSION << 4) | (header_len / 4);
        header.total_length = self.size() as u16;

        let mut header_checksum = Checksum::new();
        header.fold(&mut header_checksum);
        header_checksum.push(self.options.as_slice());
        header.hdr_checksum = header_checksum.finish();

        let mut offset = header.write(bytes);

        let options_end = offset + self.options.len();
        bytes[offset..options_end].copy_from_slice(self.options.as_slice());
        offset = options_end;

        let seed = header.pseudo_header_seed(self.payload.size() as u16);

        let payload_size = match &self.payload {
            Ipv4Payload::Icmp(frame) => frame.write(&mut bytes[offset..], Checksum::new()),
            Ipv4Payload::Udp(frame) => frame.write(&mut bytes[offset..], seed),
            Ipv4Payload::Tcp(frame) => frame.write(&mut bytes[offset..], seed),
            Ipv4Payload::Unknown { data, .. } => {
                bytes[offset..offset + data.len()].copy_from_slice(data);
                data.len()
            }
        };

        offset + payload_size
    }

    pub fn header_len(&self) -> u8 {
        IPV4_MIN_HEADER_SIZE + self.options.len() as u8
    }

    pub fn size(&self) -> usize {
        self.header_len() as usize + self.payload.size()
    }

    pub fn src(&self) -> &Ipv4Addr {
        &self.header.src_addr
    }

    pub fn dst(&self) -> &Ipv4Addr {
        &self.header.dst_addr
    }

    pub fn protocol(&self) -> u8 {
        self.payload.protocol()
    }

    pub fn ttl(&self) -> u8 {
        self.header.ttl
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.header.ttl = ttl;
    }

    pub fn tos(&self) -> u8 {
        self.header.tos
    }

    pub fn set_tos(&mut self, tos: u8) {
        self.header.tos = tos;
    }

    pub fn identification(&self) -> u16 {
        self.header.identification
    }

    pub fn set_identification(&mut self, identification: u16) {
        self.header.identification = identification;
    }

    pub fn dont_fragment(&self) -> bool {
        self.header.dont_fragment()
    }

    pub fn options(&self) -> &[u8] {
        self.options.as_slice()
    }

    pub fn payload(&self) -> &Ipv4Payload<'a> {
        &self.payload
    }

    pub fn into_payload(self) -> Ipv4Payload<'a> {
        self.payload
    }

    pub fn into_owned(self) -> Ipv4Frame<'static> {
        Ipv4Frame {
            header: self.header,
            options: self.options,
            payload: self.payload.into_owned(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use net_header::{Checksum, NetHeader};

    use crate::proto::{
        icmp::IcmpFrame,
        ipv4::{IPV4_PROTOCOL_UDP, Ipv4Frame, Ipv4FrameParseError, Ipv4Header, Ipv4Payload},
        options::Ipv4Options,
        udp::wire::UdpFrame,
    };

    const SRC: [u8; 4] = [10, 30, 0, 2];
    const DST: [u8; 4] = [10, 30, 0, 3];

    fn test_header() -> Ipv4Header {
        Ipv4Header {
            version_ihl: 0x45,
            tos: 0,
            total_length: 28,
            identification: 0,
            flags_frag_offset: 0x4000,
            ttl: 64,
            protocol: IPV4_PROTOCOL_UDP,
            hdr_checksum: 0,
            src_addr: SRC,
            dst_addr: DST,
        }
    }

    fn encode_header(header: &Ipv4Header) -> [u8; Ipv4Header::SIZE] {
        let mut header = header.clone();

        let mut checksum = Checksum::new();
        header.fold(&mut checksum);
        header.hdr_checksum = checksum.finish();

        let mut bytes = [0u8; Ipv4Header::SIZE];
        header.write(&mut bytes);

        bytes
    }

    fn encode(frame: &Ipv4Frame<'_>) -> Vec<u8> {
        let mut bytes = vec![0u8; frame.size()];
        let size = frame.write(&mut bytes);

        assert_eq!(size, frame.size());

        bytes
    }

    #[test]
    fn header_accessors() {
        let header = test_header();

        assert_eq!(header.version(), 4);
        assert_eq!(header.ihl(), 5);
        assert_eq!(header.header_len(), 20);
        assert!(header.dont_fragment());
        assert!(!header.more_fragments());
        assert_eq!(header.fragment_offset(), 0);
        assert!(!header.is_fragment());
    }

    #[test]
    fn udp_datagram_roundtrip() {
        let udp = UdpFrame::new(1000, 2000, &b"payload"[..]);
        let frame = Ipv4Frame::new(SRC, DST, Ipv4Payload::Udp(udp));

        let bytes = encode(&frame);
        let parsed = Ipv4Frame::parse(&bytes).unwrap();

        assert_eq!(parsed.src(), &SRC);
        assert_eq!(parsed.dst(), &DST);
        assert_eq!(parsed.ttl(), 64);
        assert_eq!(parsed.header_len(), 20);

        let Ipv4Payload::Udp(udp) = parsed.payload() else {
            panic!("expected a udp payload");
        };
        assert_eq!(udp.payload(), b"payload");
    }

    #[test]
    fn ttl_tos_and_identification_are_controllable() {
        let icmp = IcmpFrame::echo_request(1, 2, b"x");
        let mut frame = Ipv4Frame::new(SRC, DST, Ipv4Payload::Icmp(icmp))
            .with_ttl(7)
            .with_tos(0xb8);
        frame.set_identification(0x1234);

        let bytes = encode(&frame);
        let parsed = Ipv4Frame::parse(&bytes).unwrap();

        assert_eq!(parsed.ttl(), 7);
        assert_eq!(parsed.tos(), 0xb8);
        assert_eq!(parsed.identification(), 0x1234);
    }

    #[test]
    fn options_are_preserved_and_covered_by_the_checksum() {
        let options = Ipv4Options::from_slice(&[0x83, 0x07, 0x04, 1, 2, 3, 4, 0x00]).unwrap();

        let udp = UdpFrame::new(1000, 2000, &b"payload"[..]);
        let frame = Ipv4Frame::new(SRC, DST, Ipv4Payload::Udp(udp)).with_options(options);

        assert_eq!(frame.header_len(), 28);

        let bytes = encode(&frame);
        assert_eq!(net_header::checksum(&bytes[..28]), 0);

        let parsed = Ipv4Frame::parse(&bytes).unwrap();
        assert_eq!(parsed.header_len(), 28);
        assert_eq!(parsed.options(), frame.options());

        let Ipv4Payload::Udp(udp) = parsed.payload() else {
            panic!("expected a udp payload");
        };
        assert_eq!(udp.payload(), b"payload");
    }

    #[test]
    fn unknown_protocols_are_retained() {
        let frame = Ipv4Frame::new(
            SRC,
            DST,
            Ipv4Payload::Unknown {
                protocol: 89,
                data: Cow::Borrowed(b"ospf body"),
            },
        );

        let bytes = encode(&frame);
        let parsed = Ipv4Frame::parse(&bytes).unwrap();

        let Ipv4Payload::Unknown { protocol, data } = parsed.payload() else {
            panic!("expected an unknown protocol payload");
        };

        assert_eq!(*protocol, 89);
        assert_eq!(data.as_ref(), b"ospf body");
    }

    #[test]
    fn parse_borrows_the_payload() {
        let udp = UdpFrame::new(1000, 2000, &b"borrowed"[..]);
        let frame = Ipv4Frame::new(SRC, DST, Ipv4Payload::Udp(udp));

        let bytes = encode(&frame);
        let parsed = Ipv4Frame::parse(&bytes).unwrap();

        let Ipv4Payload::Udp(udp) = parsed.clone().into_payload() else {
            panic!("expected a udp payload");
        };
        assert!(matches!(udp.into_payload(), Cow::Borrowed(_)));

        let Ipv4Payload::Udp(udp) = parsed.into_owned().into_payload() else {
            panic!("expected a udp payload");
        };
        assert!(matches!(udp.into_payload(), Cow::Owned(_)));
    }

    #[test]
    fn rejects_fragments() {
        let mut header = test_header();
        header.flags_frag_offset = 0x2000;

        let bytes = encode_header(&header);
        assert!(matches!(
            Ipv4Frame::parse(&bytes),
            Err(Ipv4FrameParseError::Fragmented { .. })
        ));

        let mut header = test_header();
        header.flags_frag_offset = 0x0001;

        let bytes = encode_header(&header);
        assert!(matches!(
            Ipv4Frame::parse(&bytes),
            Err(Ipv4FrameParseError::Fragmented { .. })
        ));
    }

    #[test]
    fn rejects_total_length_below_header_length() {
        let mut header = test_header();
        header.total_length = 8;

        let bytes = encode_header(&header);
        assert!(matches!(
            Ipv4Frame::parse(&bytes),
            Err(Ipv4FrameParseError::InvalidTotalLength { .. })
        ));
    }

    #[test]
    fn rejects_truncated_input() {
        let bytes = encode_header(&test_header());

        for len in 0..bytes.len() {
            assert!(Ipv4Frame::parse(&bytes[..len]).is_err(), "len = {len}");
        }
    }

    #[test]
    fn rejects_bad_header_checksum() {
        let mut bytes = encode_header(&test_header());
        bytes[10] ^= 0xff;

        assert!(matches!(
            Ipv4Frame::parse(&bytes),
            Err(Ipv4FrameParseError::InvalidHeaderChecksum(_))
        ));
    }
}
