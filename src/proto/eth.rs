use std::borrow::Cow;

use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::{
    addr::{MacAddr, is_group_mac},
    proto::{
        arp::wire::{ArpFrame, ArpFrameParseError},
        ipv4::{Ipv4Frame, Ipv4FrameParseError},
    },
};

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;
pub const ETHER_TYPE_IPV6: u16 = 0x86dd;
pub const ETHER_TYPE_VLAN: u16 = 0x8100;

#[derive(NetHeader, Clone, Debug, PartialEq, Eq)]
#[header(name = "eth")]
pub struct EthernetHeader {
    dst: [u8; 6],
    src: [u8; 6],

    ethertype: u16,
}

impl EthernetHeader {
    pub fn new(src: MacAddr, dst: MacAddr, ethertype: u16) -> EthernetHeader {
        EthernetHeader {
            dst,
            src,
            ethertype,
        }
    }

    pub fn src(&self) -> &MacAddr {
        &self.src
    }

    pub fn dst(&self) -> &MacAddr {
        &self.dst
    }

    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }
}

pub fn accepts_dst(dst: &MacAddr, local: &MacAddr) -> bool {
    dst == local || is_group_mac(dst)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EthernetPayload<'a> {
    Arp(ArpFrame),
    Ipv4(Ipv4Frame<'a>),
    Unknown { ethertype: u16, data: Cow<'a, [u8]> },
}

impl<'a> EthernetPayload<'a> {
    pub fn ethertype(&self) -> u16 {
        match self {
            EthernetPayload::Arp(_) => ETHER_TYPE_ARP,
            EthernetPayload::Ipv4(_) => ETHER_TYPE_IPV4,
            EthernetPayload::Unknown { ethertype, .. } => *ethertype,
        }
    }

    pub fn size(&self) -> usize {
        match self {
            EthernetPayload::Arp(frame) => frame.size(),
            EthernetPayload::Ipv4(frame) => frame.size(),
            EthernetPayload::Unknown { data, .. } => data.len(),
        }
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        match self {
            EthernetPayload::Arp(frame) => frame.write(bytes),
            EthernetPayload::Ipv4(frame) => frame.write(bytes),
            EthernetPayload::Unknown { data, .. } => {
                bytes[..data.len()].copy_from_slice(data);
                data.len()
            }
        }
    }

    pub fn into_owned(self) -> EthernetPayload<'static> {
        match self {
            EthernetPayload::Arp(frame) => EthernetPayload::Arp(frame),
            EthernetPayload::Ipv4(frame) => EthernetPayload::Ipv4(frame.into_owned()),
            EthernetPayload::Unknown { ethertype, data } => EthernetPayload::Unknown {
                ethertype,
                data: Cow::Owned(data.into_owned()),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EthernetFrame<'a> {
    header: EthernetHeader,
    payload: EthernetPayload<'a>,
}

#[derive(Debug, Error)]
pub enum EthernetFrameParseError {
    #[error("failed to parse ethernet header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("failed to parse arp frame:\n{0}")]
    ArpFrameParseError(ArpFrameParseError),

    #[error("failed to parse ipv4 frame:\n{0}")]
    Ipv4FrameParseError(Ipv4FrameParseError),
}

impl<'a> EthernetFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<EthernetFrame<'a>, EthernetFrameParseError> {
        let header =
            EthernetHeader::from_bytes(bytes).map_err(EthernetFrameParseError::HeaderParseError)?;

        let payload_bytes = &bytes[EthernetHeader::SIZE..];

        let payload = match header.ethertype {
            ETHER_TYPE_ARP => {
                let frame = ArpFrame::parse(payload_bytes)
                    .map_err(EthernetFrameParseError::ArpFrameParseError)?;

                EthernetPayload::Arp(frame)
            }
            ETHER_TYPE_IPV4 => {
                let frame = Ipv4Frame::parse(payload_bytes)
                    .map_err(EthernetFrameParseError::Ipv4FrameParseError)?;

                EthernetPayload::Ipv4(frame)
            }
            ethertype => {
                tracing::trace!(
                    ethertype = format_args!("{ethertype:#06x}"),
                    len = payload_bytes.len(),
                    "retaining ethernet payload with an unknown ethertype"
                );

                EthernetPayload::Unknown {
                    ethertype,
                    data: Cow::Borrowed(payload_bytes),
                }
            }
        };

        Ok(EthernetFrame { header, payload })
    }

    pub fn new(src: MacAddr, dst: MacAddr, payload: EthernetPayload<'a>) -> EthernetFrame<'a> {
        let header = EthernetHeader::new(src, dst, payload.ethertype());

        EthernetFrame { header, payload }
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        let offset = self.header.write(bytes);

        offset + self.payload.write(&mut bytes[offset..])
    }

    pub fn size(&self) -> usize {
        EthernetHeader::SIZE + self.payload.size()
    }

    pub fn src(&self) -> &MacAddr {
        &self.header.src
    }

    pub fn dst(&self) -> &MacAddr {
        &self.header.dst
    }

    pub fn ethertype(&self) -> u16 {
        self.header.ethertype
    }

    pub fn payload(&self) -> &EthernetPayload<'a> {
        &self.payload
    }

    pub fn into_payload(self) -> EthernetPayload<'a> {
        self.payload
    }

    pub fn into_owned(self) -> EthernetFrame<'static> {
        EthernetFrame {
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use net_header::NetHeader;

    use crate::{
        addr::BROADCAST_MAC,
        proto::eth::{
            ETHER_TYPE_IPV6, EthernetFrame, EthernetHeader, EthernetPayload, accepts_dst,
        },
    };

    const LOCAL_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const PEER_MAC: [u8; 6] = [0x02, 0x29, 0x39, 0x49, 0x59, 0x69];

    #[test]
    fn parse_eth_header_basic() {
        let ety = 0x01_02u16.to_be_bytes();
        let bytes: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ety[0], ety[1]];

        let header = EthernetHeader::from_bytes(bytes).unwrap();
        assert_eq!(header.dst, [0, 1, 2, 3, 4, 5]);
        assert_eq!(header.src, [6, 7, 8, 9, 10, 11]);
        assert_eq!(header.ethertype, u16::from_be_bytes([1, 2]));
    }

    #[test]
    fn parse_eth_header_short_input() {
        assert!(EthernetHeader::from_bytes(&[0, 1, 2]).is_err());
    }

    #[test]
    fn eth_codec_complete() {
        let header = EthernetHeader {
            dst: [0, 1, 2, 3, 4, 5],
            src: [6, 7, 8, 9, 10, 11],
            ethertype: 0x01_02,
        };

        let mut bytes = [0u8; EthernetHeader::SIZE];
        let offset = header.write(&mut bytes);
        assert_eq!(offset, EthernetHeader::SIZE);

        let parsed = EthernetHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header, parsed);
    }

    #[test]
    fn unknown_ethertypes_are_retained() {
        let frame = EthernetFrame::new(
            LOCAL_MAC,
            PEER_MAC,
            EthernetPayload::Unknown {
                ethertype: ETHER_TYPE_IPV6,
                data: Cow::Borrowed(b"an ipv6 packet would go here"),
            },
        );

        let mut bytes = vec![0u8; frame.size()];
        let size = frame.write(&mut bytes);

        let parsed = EthernetFrame::parse(&bytes[..size]).unwrap();
        assert_eq!(parsed.ethertype(), ETHER_TYPE_IPV6);

        let EthernetPayload::Unknown { data, .. } = parsed.payload() else {
            panic!("expected an unknown payload");
        };
        assert_eq!(data.as_ref(), b"an ipv6 packet would go here");
    }

    #[test]
    fn dst_filter() {
        assert!(accepts_dst(&LOCAL_MAC, &LOCAL_MAC));
        assert!(accepts_dst(&BROADCAST_MAC, &LOCAL_MAC));
        assert!(accepts_dst(
            &[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01],
            &LOCAL_MAC
        ));

        assert!(!accepts_dst(&PEER_MAC, &LOCAL_MAC));
    }
}
