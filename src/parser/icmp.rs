use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
const ICMP_TYPE_ECHO_REPLY: u8 = 0;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "icmp")]
pub struct IcmpHeader {
    type_: u8,
    code: u8,

    checksum: u16,
}

#[derive(Debug, Error)]
pub enum IcmpFrameParseError {
    #[error("failed to parse icmp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("unknown icmp type {0:x}")]
    UnknownType(u8),

    #[error("invalid checksum for icmp message {0}")]
    InvalidChecksum(u16),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IcmpFrame {
    header: IcmpHeader,
    type_: IcmpType,
    pub payload: Vec<u8>,
}

impl IcmpFrame {
    pub fn parse(data: &[u8]) -> Result<Self, IcmpFrameParseError> {
        let checksum = net_header::checksum(data);
        if checksum != 0 {
            return Err(IcmpFrameParseError::InvalidChecksum(checksum));
        }

        let header =
            IcmpHeader::from_bytes(data).map_err(|e| IcmpFrameParseError::HeaderParseError(e))?;

        let type_ = match header.type_ {
            ICMP_TYPE_ECHO_REQUEST => IcmpType::EchoRequest,
            ICMP_TYPE_ECHO_REPLY => IcmpType::EchoReply,
            unknown_value => return Err(IcmpFrameParseError::UnknownType(unknown_value)),
        };

        let payload = data[IcmpHeader::SIZE..].to_owned();

        let frame = IcmpFrame {
            header,
            type_,
            payload,
        };

        Ok(frame)
    }

    pub fn write(self, bytes: &mut [u8]) -> usize {
        let hdr_size = self.header.write(bytes);
        let end = hdr_size + self.payload.len();
        bytes[hdr_size..end].copy_from_slice(&self.payload);

        let checksum = net_header::checksum(&bytes[..end]);
        net_header::write::write_field_u16(checksum, "icmp.checksum", bytes, 2);

        end
    }

    pub fn new(type_: IcmpType, payload: &[u8]) -> IcmpFrame {
        let type_value = match type_ {
            IcmpType::EchoRequest => ICMP_TYPE_ECHO_REQUEST,
            IcmpType::EchoReply => ICMP_TYPE_ECHO_REPLY,
        };

        let header = IcmpHeader {
            type_: type_value,
            code: 0,
            checksum: 0,
        };

        IcmpFrame {
            header,
            type_,
            payload: payload.to_owned(),
        }
    }

    pub fn type_(&self) -> &IcmpType {
        &self.type_
    }

    pub fn size(&self) -> usize {
        IcmpHeader::SIZE + self.payload.len()
    }
}
