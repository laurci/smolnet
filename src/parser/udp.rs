use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "udp")]
pub struct UdpHeader {
    src_port: u16,
    dst_port: u16,

    total_length: u16,

    checksum: u16,
}

#[derive(Debug, Error)]
pub enum UdpFrameParseError {
    #[error("failed to parse udp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("invalid len for udp header (expected >= {header_size}; got = {0})", header_size = UdpHeader::SIZE)]
    InvalidLen(u16),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpFrame {
    header: UdpHeader,
    pub payload: Vec<u8>,
}

impl UdpFrame {
    pub const CHECKSUM_OFFSET: usize = 6;

    pub fn parse(bytes: &[u8]) -> Result<Self, UdpFrameParseError> {
        let header =
            UdpHeader::from_bytes(bytes).map_err(|e| UdpFrameParseError::HeaderParseError(e))?;

        if header.total_length < UdpHeader::SIZE as u16 {
            return Err(UdpFrameParseError::InvalidLen(header.total_length));
        }

        let payload = &bytes[UdpHeader::SIZE..];

        let frame = UdpFrame {
            header,
            payload: payload.to_owned(),
        };

        Ok(frame)
    }

    pub fn new(src_port: u16, dst_port: u16, payload: Vec<u8>) -> UdpFrame {
        let header = UdpHeader {
            src_port,
            dst_port,
            checksum: 0,
            total_length: (payload.len() + UdpHeader::SIZE) as u16,
        };

        UdpFrame { header, payload }
    }

    pub fn write(self, bytes: &mut [u8]) -> usize {
        self.header.write(bytes);

        let payload_len = self.payload.len();
        let end = UdpHeader::SIZE + payload_len;

        bytes[UdpHeader::SIZE..end].copy_from_slice(&self.payload);

        end
    }

    pub fn reply(&self, payload: Vec<u8>) -> UdpFrame {
        UdpFrame::new(self.header.dst_port, self.header.src_port, payload)
    }

    pub fn size(&self) -> usize {
        return UdpHeader::SIZE + self.payload.len();
    }

    pub fn src_port(&self) -> u16 {
        self.header.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.header.dst_port
    }

    pub fn validate_checksum(&self, value: u16) -> bool {
        self.header.checksum == 0 || value == 0
    }
}
