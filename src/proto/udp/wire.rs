use std::borrow::Cow;

use net_header::{Checksum, NetHeader, parse::HeaderParseError};
use thiserror::Error;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "udp")]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,

    total_length: u16,

    #[header(checksum)]
    checksum: u16,
}

#[derive(Debug, Error)]
pub enum UdpFrameParseError {
    #[error("failed to parse udp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("invalid len for udp header (expected >= {header_size}; got = {0})", header_size = UdpHeader::SIZE)]
    InvalidLen(u16),

    #[error("truncated udp datagram (declared = {declared}; got = {got})")]
    Truncated { declared: u16, got: usize },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpFrame<'a> {
    header: UdpHeader,
    payload: Cow<'a, [u8]>,
}

impl<'a> UdpFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<UdpFrame<'a>, UdpFrameParseError> {
        let header = UdpHeader::from_bytes(bytes).map_err(UdpFrameParseError::HeaderParseError)?;

        if header.total_length < UdpHeader::SIZE as u16 {
            return Err(UdpFrameParseError::InvalidLen(header.total_length));
        }

        let Some(payload) = bytes.get(UdpHeader::SIZE..header.total_length as usize) else {
            return Err(UdpFrameParseError::Truncated {
                declared: header.total_length,
                got: bytes.len(),
            });
        };

        Ok(UdpFrame {
            header,
            payload: Cow::Borrowed(payload),
        })
    }

    pub fn new(src_port: u16, dst_port: u16, payload: impl Into<Cow<'a, [u8]>>) -> UdpFrame<'a> {
        let payload = payload.into();

        let header = UdpHeader {
            src_port,
            dst_port,
            checksum: 0,
            total_length: (payload.len() + UdpHeader::SIZE) as u16,
        };

        UdpFrame { header, payload }
    }

    pub fn write(&self, bytes: &mut [u8], seed: Checksum) -> usize {
        let mut header = self.header.clone();
        header.total_length = self.size() as u16;

        let mut checksum = seed;
        header.fold(&mut checksum);
        checksum.push(&self.payload);

        header.checksum = match checksum.finish() {
            0 => 0xffff,
            value => value,
        };

        let offset = header.write(bytes);
        let end = offset + self.payload.len();
        bytes[offset..end].copy_from_slice(&self.payload);

        end
    }

    pub fn reply(&self, payload: impl Into<Cow<'a, [u8]>>) -> UdpFrame<'a> {
        UdpFrame::new(self.header.dst_port, self.header.src_port, payload)
    }

    pub fn size(&self) -> usize {
        UdpHeader::SIZE + self.payload.len()
    }

    pub fn src_port(&self) -> u16 {
        self.header.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.header.dst_port
    }

    pub fn checksum(&self) -> u16 {
        self.header.checksum
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Cow<'a, [u8]> {
        self.payload
    }

    pub fn into_owned(self) -> UdpFrame<'static> {
        UdpFrame {
            header: self.header,
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use net_header::{Checksum, NetHeader};

    use crate::proto::udp::wire::{UdpFrame, UdpHeader};

    #[test]
    fn codec_roundtrip() {
        let frame = UdpFrame::new(1234, 5678, &b"hello"[..]);

        let mut bytes = [0u8; 64];
        let size = frame.write(&mut bytes, Checksum::new());
        assert_eq!(size, frame.size());

        let parsed = UdpFrame::parse(&bytes[..size]).unwrap();
        assert_eq!(parsed.src_port(), 1234);
        assert_eq!(parsed.dst_port(), 5678);
        assert_eq!(parsed.payload(), b"hello");
        assert!(matches!(parsed.into_payload(), Cow::Borrowed(_)));
    }

    #[test]
    fn checksum_covers_pseudo_header() {
        let frame = UdpFrame::new(1234, 5678, &b"hello"[..]);

        let src = [10, 30, 0, 2];
        let dst = [10, 30, 0, 3];

        let mut seed = Checksum::new();
        seed.push_ipv4_pseudo_header(&src, &dst, 17, frame.size() as u16);

        let mut bytes = [0u8; 64];
        let size = frame.write(&mut bytes, seed);

        let mut verify = Checksum::new();
        verify.push_ipv4_pseudo_header(&src, &dst, 17, size as u16);
        verify.push(&bytes[..size]);
        assert_eq!(verify.finish(), 0);

        let mut wrong = Checksum::new();
        wrong.push_ipv4_pseudo_header(&src, &[10, 30, 0, 4], 17, size as u16);
        wrong.push(&bytes[..size]);
        assert_ne!(wrong.finish(), 0);
    }

    #[test]
    fn rejects_truncated() {
        let frame = UdpFrame::new(1234, 5678, &b"hello"[..]);

        let mut bytes = [0u8; 64];
        let size = frame.write(&mut bytes, Checksum::new());

        for len in 0..size {
            assert!(UdpFrame::parse(&bytes[..len]).is_err(), "len = {len}");
        }
    }

    #[test]
    fn rejects_length_below_header() {
        let header = UdpHeader {
            src_port: 1,
            dst_port: 2,
            total_length: 4,
            checksum: 0,
        };

        let mut bytes = [0u8; UdpHeader::SIZE];
        header.write(&mut bytes);

        assert!(UdpFrame::parse(&bytes).is_err());
    }
}
