use std::borrow::Cow;

use net_header::{Checksum, NetHeader, parse::HeaderParseError};
use thiserror::Error;

pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;
pub const ICMP_TYPE_DEST_UNREACHABLE: u8 = 3;
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
pub const ICMP_TYPE_TIME_EXCEEDED: u8 = 11;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "icmp")]
pub struct IcmpHeader {
    type_: u8,
    code: u8,

    #[header(checksum)]
    checksum: u16,

    rest: [u8; 4],
}

#[derive(Debug, Error)]
pub enum IcmpFrameParseError {
    #[error("failed to parse icmp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("invalid checksum for icmp message {0}")]
    InvalidChecksum(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestUnreachableCode {
    Net,
    Host,
    Protocol,
    Port,
    FragmentationNeeded,
    SourceRouteFailed,
    Other(u8),
}

impl DestUnreachableCode {
    pub fn from_u8(code: u8) -> DestUnreachableCode {
        match code {
            0 => DestUnreachableCode::Net,
            1 => DestUnreachableCode::Host,
            2 => DestUnreachableCode::Protocol,
            3 => DestUnreachableCode::Port,
            4 => DestUnreachableCode::FragmentationNeeded,
            5 => DestUnreachableCode::SourceRouteFailed,
            other => DestUnreachableCode::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            DestUnreachableCode::Net => 0,
            DestUnreachableCode::Host => 1,
            DestUnreachableCode::Protocol => 2,
            DestUnreachableCode::Port => 3,
            DestUnreachableCode::FragmentationNeeded => 4,
            DestUnreachableCode::SourceRouteFailed => 5,
            DestUnreachableCode::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeExceededCode {
    TtlExpired,
    FragmentReassembly,
    Other(u8),
}

impl TimeExceededCode {
    pub fn from_u8(code: u8) -> TimeExceededCode {
        match code {
            0 => TimeExceededCode::TtlExpired,
            1 => TimeExceededCode::FragmentReassembly,
            other => TimeExceededCode::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            TimeExceededCode::TtlExpired => 0,
            TimeExceededCode::FragmentReassembly => 1,
            TimeExceededCode::Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpMessage<'a> {
    EchoRequest {
        id: u16,
        seq: u16,
        data: Cow<'a, [u8]>,
    },
    EchoReply {
        id: u16,
        seq: u16,
        data: Cow<'a, [u8]>,
    },
    DestUnreachable {
        code: DestUnreachableCode,
        next_hop_mtu: u16,
        original: Cow<'a, [u8]>,
    },
    TimeExceeded {
        code: TimeExceededCode,
        original: Cow<'a, [u8]>,
    },
    Other {
        type_: u8,
        code: u8,
        rest: [u8; 4],
        body: Cow<'a, [u8]>,
    },
}

impl<'a> IcmpMessage<'a> {
    pub fn type_(&self) -> u8 {
        match self {
            IcmpMessage::EchoRequest { .. } => ICMP_TYPE_ECHO_REQUEST,
            IcmpMessage::EchoReply { .. } => ICMP_TYPE_ECHO_REPLY,
            IcmpMessage::DestUnreachable { .. } => ICMP_TYPE_DEST_UNREACHABLE,
            IcmpMessage::TimeExceeded { .. } => ICMP_TYPE_TIME_EXCEEDED,
            IcmpMessage::Other { type_, .. } => *type_,
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            IcmpMessage::EchoRequest { .. } | IcmpMessage::EchoReply { .. } => 0,
            IcmpMessage::DestUnreachable { code, .. } => code.to_u8(),
            IcmpMessage::TimeExceeded { code, .. } => code.to_u8(),
            IcmpMessage::Other { code, .. } => *code,
        }
    }

    pub fn rest(&self) -> [u8; 4] {
        match self {
            IcmpMessage::EchoRequest { id, seq, .. } | IcmpMessage::EchoReply { id, seq, .. } => {
                let id = id.to_be_bytes();
                let seq = seq.to_be_bytes();

                [id[0], id[1], seq[0], seq[1]]
            }
            IcmpMessage::DestUnreachable { next_hop_mtu, .. } => {
                let mtu = next_hop_mtu.to_be_bytes();

                [0, 0, mtu[0], mtu[1]]
            }
            IcmpMessage::TimeExceeded { .. } => [0; 4],
            IcmpMessage::Other { rest, .. } => *rest,
        }
    }

    pub fn body(&self) -> &[u8] {
        match self {
            IcmpMessage::EchoRequest { data, .. } | IcmpMessage::EchoReply { data, .. } => data,
            IcmpMessage::DestUnreachable { original, .. } => original,
            IcmpMessage::TimeExceeded { original, .. } => original,
            IcmpMessage::Other { body, .. } => body,
        }
    }

    pub fn into_owned(self) -> IcmpMessage<'static> {
        match self {
            IcmpMessage::EchoRequest { id, seq, data } => IcmpMessage::EchoRequest {
                id,
                seq,
                data: Cow::Owned(data.into_owned()),
            },
            IcmpMessage::EchoReply { id, seq, data } => IcmpMessage::EchoReply {
                id,
                seq,
                data: Cow::Owned(data.into_owned()),
            },
            IcmpMessage::DestUnreachable {
                code,
                next_hop_mtu,
                original,
            } => IcmpMessage::DestUnreachable {
                code,
                next_hop_mtu,
                original: Cow::Owned(original.into_owned()),
            },
            IcmpMessage::TimeExceeded { code, original } => IcmpMessage::TimeExceeded {
                code,
                original: Cow::Owned(original.into_owned()),
            },
            IcmpMessage::Other {
                type_,
                code,
                rest,
                body,
            } => IcmpMessage::Other {
                type_,
                code,
                rest,
                body: Cow::Owned(body.into_owned()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpFrame<'a> {
    message: IcmpMessage<'a>,
}

impl<'a> IcmpFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<IcmpFrame<'a>, IcmpFrameParseError> {
        let header =
            IcmpHeader::from_bytes(bytes).map_err(IcmpFrameParseError::HeaderParseError)?;

        let checksum = net_header::checksum(bytes);
        if checksum != 0 {
            return Err(IcmpFrameParseError::InvalidChecksum(checksum));
        }

        let rest = header.rest;
        let body = &bytes[IcmpHeader::SIZE..];

        let id = u16::from_be_bytes([rest[0], rest[1]]);
        let seq = u16::from_be_bytes([rest[2], rest[3]]);

        let message = match header.type_ {
            ICMP_TYPE_ECHO_REQUEST => IcmpMessage::EchoRequest {
                id,
                seq,
                data: Cow::Borrowed(body),
            },
            ICMP_TYPE_ECHO_REPLY => IcmpMessage::EchoReply {
                id,
                seq,
                data: Cow::Borrowed(body),
            },
            ICMP_TYPE_DEST_UNREACHABLE => IcmpMessage::DestUnreachable {
                code: DestUnreachableCode::from_u8(header.code),
                next_hop_mtu: u16::from_be_bytes([rest[2], rest[3]]),
                original: Cow::Borrowed(body),
            },
            ICMP_TYPE_TIME_EXCEEDED => IcmpMessage::TimeExceeded {
                code: TimeExceededCode::from_u8(header.code),
                original: Cow::Borrowed(body),
            },
            type_ => {
                tracing::trace!(
                    type_,
                    code = header.code,
                    len = body.len(),
                    "retaining icmp message with an unknown type"
                );

                IcmpMessage::Other {
                    type_,
                    code: header.code,
                    rest,
                    body: Cow::Borrowed(body),
                }
            }
        };

        Ok(IcmpFrame { message })
    }

    pub fn new(message: IcmpMessage<'a>) -> IcmpFrame<'a> {
        IcmpFrame { message }
    }

    pub fn echo_request(id: u16, seq: u16, data: &'a [u8]) -> IcmpFrame<'a> {
        IcmpFrame::new(IcmpMessage::EchoRequest {
            id,
            seq,
            data: Cow::Borrowed(data),
        })
    }

    pub fn write(&self, bytes: &mut [u8], seed: Checksum) -> usize {
        let body = self.message.body();

        let mut header = IcmpHeader {
            type_: self.message.type_(),
            code: self.message.code(),
            checksum: 0,
            rest: self.message.rest(),
        };

        let mut checksum = seed;
        header.fold(&mut checksum);
        checksum.push(body);
        header.checksum = checksum.finish();

        let offset = header.write(bytes);
        let end = offset + body.len();
        bytes[offset..end].copy_from_slice(body);

        end
    }

    pub fn size(&self) -> usize {
        IcmpHeader::SIZE + self.message.body().len()
    }

    pub fn message(&self) -> &IcmpMessage<'a> {
        &self.message
    }

    pub fn into_message(self) -> IcmpMessage<'a> {
        self.message
    }

    pub fn echo_reply(&self) -> Option<IcmpFrame<'a>> {
        let IcmpMessage::EchoRequest { id, seq, data } = &self.message else {
            return None;
        };

        Some(IcmpFrame::new(IcmpMessage::EchoReply {
            id: *id,
            seq: *seq,
            data: data.clone(),
        }))
    }

    pub fn into_owned(self) -> IcmpFrame<'static> {
        IcmpFrame {
            message: self.message.into_owned(),
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use net_header::Checksum;

    use crate::proto::icmp::{DestUnreachableCode, IcmpFrame, IcmpMessage, TimeExceededCode};

    fn roundtrip(frame: &IcmpFrame<'_>) -> Vec<u8> {
        let mut bytes = vec![0u8; frame.size()];
        let size = frame.write(&mut bytes, Checksum::new());

        assert_eq!(size, frame.size());
        assert_eq!(net_header::checksum(&bytes[..size]), 0);

        bytes
    }

    #[test]
    fn echo_carries_identifier_and_sequence() {
        let frame = IcmpFrame::echo_request(0xbeef, 7, b"payload data");
        let bytes = roundtrip(&frame);

        let parsed = IcmpFrame::parse(&bytes).unwrap();
        let IcmpMessage::EchoRequest { id, seq, data } = parsed.message() else {
            panic!("expected an echo request");
        };

        assert_eq!(*id, 0xbeef);
        assert_eq!(*seq, 7);
        assert_eq!(data.as_ref(), b"payload data");
    }

    #[test]
    fn echo_reply_mirrors_identity_and_payload() {
        let request = IcmpFrame::echo_request(0x1234, 9, b"abc");
        let reply = request.echo_reply().expect("echo request has a reply");

        let IcmpMessage::EchoReply { id, seq, data } = reply.message() else {
            panic!("expected an echo reply");
        };

        assert_eq!(*id, 0x1234);
        assert_eq!(*seq, 9);
        assert_eq!(data.as_ref(), b"abc");

        assert_eq!(reply.echo_reply(), None);
    }

    #[test]
    fn dest_unreachable_roundtrip() {
        let frame = IcmpFrame::new(IcmpMessage::DestUnreachable {
            code: DestUnreachableCode::Port,
            next_hop_mtu: 0,
            original: Cow::Borrowed(b"original datagram header"),
        });

        let bytes = roundtrip(&frame);
        let parsed = IcmpFrame::parse(&bytes).unwrap();

        let IcmpMessage::DestUnreachable {
            code,
            next_hop_mtu,
            original,
        } = parsed.message()
        else {
            panic!("expected destination unreachable");
        };

        assert_eq!(*code, DestUnreachableCode::Port);
        assert_eq!(*next_hop_mtu, 0);
        assert_eq!(original.as_ref(), b"original datagram header");
    }

    #[test]
    fn fragmentation_needed_carries_the_next_hop_mtu() {
        let frame = IcmpFrame::new(IcmpMessage::DestUnreachable {
            code: DestUnreachableCode::FragmentationNeeded,
            next_hop_mtu: 1400,
            original: Cow::Borrowed(b"x"),
        });

        let bytes = roundtrip(&frame);
        let parsed = IcmpFrame::parse(&bytes).unwrap();

        let IcmpMessage::DestUnreachable {
            code, next_hop_mtu, ..
        } = parsed.message()
        else {
            panic!("expected destination unreachable");
        };

        assert_eq!(*code, DestUnreachableCode::FragmentationNeeded);
        assert_eq!(*next_hop_mtu, 1400);
    }

    #[test]
    fn time_exceeded_roundtrip() {
        let frame = IcmpFrame::new(IcmpMessage::TimeExceeded {
            code: TimeExceededCode::TtlExpired,
            original: Cow::Borrowed(b"original"),
        });

        let bytes = roundtrip(&frame);
        let parsed = IcmpFrame::parse(&bytes).unwrap();

        let IcmpMessage::TimeExceeded { code, original } = parsed.message() else {
            panic!("expected time exceeded");
        };

        assert_eq!(*code, TimeExceededCode::TtlExpired);
        assert_eq!(original.as_ref(), b"original");
    }

    #[test]
    fn unknown_types_are_retained_verbatim() {
        let frame = IcmpFrame::new(IcmpMessage::Other {
            type_: 13,
            code: 2,
            rest: [1, 2, 3, 4],
            body: Cow::Borrowed(b"timestamp"),
        });

        let bytes = roundtrip(&frame);
        let parsed = IcmpFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.message(), frame.message());
    }

    #[test]
    fn parse_borrows_from_the_input() {
        let frame = IcmpFrame::echo_request(1, 1, b"borrowed");
        let bytes = roundtrip(&frame);

        let parsed = IcmpFrame::parse(&bytes).unwrap();
        let IcmpMessage::EchoRequest { data, .. } = parsed.message() else {
            panic!("expected an echo request");
        };

        assert!(matches!(data, Cow::Borrowed(_)));

        let owned = parsed.into_owned();
        let IcmpMessage::EchoRequest { data, .. } = owned.message() else {
            panic!("expected an echo request");
        };

        assert!(matches!(data, Cow::Owned(_)));
    }

    #[test]
    fn rejects_corrupt_checksum_and_truncated_input() {
        let frame = IcmpFrame::echo_request(1, 2, b"payload");
        let mut bytes = roundtrip(&frame);

        for len in 0..bytes.len() {
            assert!(IcmpFrame::parse(&bytes[..len]).is_err(), "len = {len}");
        }

        bytes[9] ^= 0xff;
        assert!(IcmpFrame::parse(&bytes).is_err());
    }
}
