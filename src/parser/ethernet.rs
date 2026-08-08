use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::{
    addr::MacAddr,
    parser::{
        arp::{ArpFrame, ArpFrameParseError},
        ipv4::{Ipv4Frame, Ipv4FrameParseError},
    },
    stack::StackIdentity,
};

pub const ETHER_TYPE_IPV4: u16 = 0x0800;
pub const ETHER_TYPE_ARP: u16 = 0x0806;

#[derive(NetHeader, Clone, Debug, PartialEq, Eq)]
#[header(name = "eth")]
pub struct EthernetHeader {
    dst: [u8; 6],
    src: [u8; 6],

    ethertype: u16,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EthernetPayload {
    Arp(ArpFrame),
    Ipv4(Ipv4Frame),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EthernetFrame {
    header: EthernetHeader,
    pub payload: EthernetPayload,
}

#[derive(Debug, Error)]
pub enum EthernetFrameParseEerror {
    #[error("failed to parse ethernet header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("failed to parse arp frame:\n{0}")]
    ArpFrameParseError(ArpFrameParseError),

    #[error("failed to parse ipv4 frame:\n{0}")]
    Ipv4FrameParseError(Ipv4FrameParseError),

    #[error("unknown ethernet protocol {0:x}")]
    UnknownProtocol(u16),
}

impl EthernetFrame {
    pub fn parse(bytes: &[u8]) -> Result<Self, EthernetFrameParseEerror> {
        let header = EthernetHeader::from_bytes(bytes)
            .map_err(|e| EthernetFrameParseEerror::HeaderParseError(e))?;

        let payload = match header.ethertype {
            ETHER_TYPE_ARP => {
                let frame = ArpFrame::parse(&bytes[EthernetHeader::SIZE..])
                    .map_err(|e| EthernetFrameParseEerror::ArpFrameParseError(e))?;

                EthernetPayload::Arp(frame)
            }
            ETHER_TYPE_IPV4 => {
                let frame = Ipv4Frame::parse(&bytes[EthernetHeader::SIZE..])
                    .map_err(|e| EthernetFrameParseEerror::Ipv4FrameParseError(e))?;

                EthernetPayload::Ipv4(frame)
            }
            unknown_value => return Err(EthernetFrameParseEerror::UnknownProtocol(unknown_value)),
        };

        let frame = EthernetFrame { header, payload };

        Ok(frame)
    }

    pub fn write(self, bytes: &mut [u8]) -> usize {
        let size = self.header.write(bytes);

        let payload_size = match self.payload {
            EthernetPayload::Arp(frame) => frame.write(&mut bytes[EthernetHeader::SIZE..]),
            EthernetPayload::Ipv4(frame) => frame.write(&mut bytes[EthernetHeader::SIZE..]),
        };

        size + payload_size
    }

    pub fn new(src: MacAddr, dst: MacAddr, payload: EthernetPayload) -> EthernetFrame {
        let ethertype = match payload {
            EthernetPayload::Arp(_) => ETHER_TYPE_ARP,
            EthernetPayload::Ipv4(_) => ETHER_TYPE_IPV4,
        };

        let header = EthernetHeader {
            dst,
            src,
            ethertype,
        };

        return EthernetFrame { header, payload };
    }

    pub fn reply(&self, identity: &StackIdentity, payload: EthernetPayload) -> EthernetFrame {
        EthernetFrame::new(identity.mac, *self.src(), payload)
    }

    pub fn src(&self) -> &MacAddr {
        &self.header.src
    }

    pub fn dst(&self) -> &MacAddr {
        &self.header.dst
    }
}

#[cfg(test)]
mod test {
    use net_header::NetHeader;

    use crate::parser::ethernet::EthernetHeader;

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
    fn write_eth_header() {
        let header = EthernetHeader {
            dst: [0, 1, 2, 3, 4, 5],
            src: [6, 7, 8, 9, 10, 11],
            ethertype: 0x01_02,
        };

        let mut bytes = [0u8; EthernetHeader::SIZE];
        let offset = header.write(&mut bytes);
        assert_eq!(offset, EthernetHeader::SIZE);

        let ety = 0x01_02u16.to_be_bytes();
        assert_eq!(
            bytes,
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ety[0], ety[1]]
        )
    }

    #[test]
    fn eth_codec_complete() {
        let header = EthernetHeader {
            dst: [0, 1, 2, 3, 4, 5],
            src: [6, 7, 8, 9, 10, 11],
            ethertype: 0x01_02,
        };

        let mut bytes = [0u8; EthernetHeader::SIZE];
        header.write(&mut bytes);

        let parsed = EthernetHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header, parsed);
    }
}
