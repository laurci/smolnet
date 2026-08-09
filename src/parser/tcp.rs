use net_header::{NetHeader, parse::HeaderParseError};
use thiserror::Error;

const TCP_OPTION_MSS: u8 = 0x02;
const TCP_OPTION_WND_SCALE: u8 = 0x03;
const TCP_OPTION_SACK: u8 = 0x04;
const TCP_OPTION_TIMESTAMPS: u8 = 0x08;

const TCP_MSS_DEFAULT: u16 = 1460;

pub const TCP_FLAG_FIN: u8 = 1 << 0;
pub const TCP_FLAG_SYN: u8 = 1 << 1;
pub const TCP_FLAG_RST: u8 = 1 << 2;
pub const TCP_FLAG_PSH: u8 = 1 << 3;
pub const TCP_FLAG_ACK: u8 = 1 << 4;
pub const TCP_FLAG_URG: u8 = 1 << 5;
pub const TCP_FLAG_ECE: u8 = 1 << 6;
pub const TCP_FLAG_CWR: u8 = 1 << 7;

#[derive(NetHeader, Debug, Clone, PartialEq, Eq)]
#[header(name = "tcp")]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,

    data_offset_reserved: u8,

    flags: u8,
    window: u16,

    checksum: u16,
    urgent_ptr: u16,
}

impl TcpHeader {
    pub fn data_offset(&self) -> u8 {
        self.data_offset_reserved >> 4
    }
}

#[derive(Debug, Error)]
pub enum TcpFrameParseError {
    #[error("failed to parse tcp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("tcp data offset {0} is below the minimum of 5")]
    DataOffsetTooSmall(u8),

    #[error("tcp data offset {offset} exceeds segment length {len}")]
    DataOffsetTooLarge { offset: usize, len: usize },

    #[error("tcp option kind {kind} declares invalid length {length}")]
    InvalidOptionLength { kind: u8, length: u8 },

    #[error("tcp option kind {0} is truncated")]
    TruncatedOption(u8),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TcpOption {
    Mss(u16),
    WindowScale(u8),
    SACK,
    Timestamps(u32, u32),
}

impl TcpOption {
    pub fn parse(kind: u8, data: &[u8]) -> Option<TcpOption> {
        match kind {
            TCP_OPTION_MSS => {
                if data.len() != 2 {
                    return None;
                }

                let len = u16::from_be_bytes([data[0], data[1]]);

                Some(TcpOption::Mss(len))
            }
            TCP_OPTION_WND_SCALE => {
                if data.len() != 1 {
                    return None;
                }

                Some(TcpOption::WindowScale(data[0]))
            }
            TCP_OPTION_SACK => Some(TcpOption::SACK),
            TCP_OPTION_TIMESTAMPS => {
                if data.len() != 8 {
                    return None;
                }

                let tsval = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let tsecr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

                Some(TcpOption::Timestamps(tsval, tsecr))
            }
            _ => None,
        }
    }

    pub fn write(&self, data: &mut [u8]) {
        match self {
            TcpOption::Mss(len) => {
                data[0] = TCP_OPTION_MSS;
                data[1] = 4;
                data[2..4].copy_from_slice(&len.to_be_bytes());
            }
            TcpOption::WindowScale(scale) => {
                data[0] = TCP_OPTION_WND_SCALE;
                data[1] = 3;
                data[2] = *scale;
            }
            TcpOption::SACK => {
                data[0] = TCP_OPTION_SACK;
                data[1] = 2;
            }
            TcpOption::Timestamps(tsval, tsecr) => {
                data[0] = TCP_OPTION_TIMESTAMPS;
                data[1] = 10;
                data[2..6].copy_from_slice(&tsval.to_be_bytes());
                data[6..10].copy_from_slice(&tsecr.to_be_bytes());
            }
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            TcpOption::Mss(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SACK => 2,
            TcpOption::Timestamps(_, _) => 10,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TcpSegment {
    Syn {
        iss: u32,
    },
    SynAck {
        iss: u32,
        ack: u32,
    },
    Ack {
        seq: u32,
        ack: u32,
    },
    Data {
        seq: u32,
        ack: u32,
        payload: Vec<u8>,
    },
    Fin {
        seq: u32,
        ack: u32,
    },
    Rst {
        seq: u32,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpFrame {
    header: TcpHeader,
    pub options: Vec<TcpOption>,
    pub payload: Vec<u8>,
}

impl TcpFrame {
    pub const CHECKSUM_OFFSET: usize = 16;

    pub fn parse(bytes: &[u8]) -> Result<Self, TcpFrameParseError> {
        let header = TcpHeader::from_bytes(bytes).map_err(TcpFrameParseError::HeaderParseError)?;

        let data_offset_words = header.data_offset();
        if (data_offset_words as usize) < 5 {
            return Err(TcpFrameParseError::DataOffsetTooSmall(data_offset_words));
        }

        let data_offset = data_offset_words as usize * 4;
        if data_offset > bytes.len() {
            return Err(TcpFrameParseError::DataOffsetTooLarge {
                offset: data_offset,
                len: bytes.len(),
            });
        }

        let options_bytes = &bytes[TcpHeader::SIZE..data_offset];

        let mut options = vec![];
        let mut i = 0;
        while i < options_bytes.len() {
            let kind = options_bytes[i];
            match kind {
                0x00 => break,
                0x01 => {
                    i += 1;
                    continue;
                }
                _ => {
                    let Some(&length) = options_bytes.get(i + 1) else {
                        return Err(TcpFrameParseError::TruncatedOption(kind));
                    };

                    if length < 2 {
                        return Err(TcpFrameParseError::InvalidOptionLength { kind, length });
                    }

                    let end = i + length as usize;
                    if end > options_bytes.len() {
                        return Err(TcpFrameParseError::TruncatedOption(kind));
                    }

                    let data = &options_bytes[i + 2..end];
                    if let Some(option) = TcpOption::parse(kind, data) {
                        options.push(option);
                    } else {
                        tracing::trace!("unsupported tcp option kind {}", kind);
                    }

                    i = end;
                }
            }
        }

        let payload = bytes[data_offset..].to_vec();

        Ok(TcpFrame {
            header,
            options,
            payload,
        })
    }

    pub fn new(src_port: u16, dst_port: u16, window: u16, segment: TcpSegment) -> TcpFrame {
        let (seq, ack, flags, payload, options) = match segment {
            TcpSegment::Syn { iss } => (iss, 0, TCP_FLAG_SYN, vec![], vec![TcpOption::Mss(1460)]),
            TcpSegment::SynAck { iss, ack } => (
                iss,
                ack,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
                vec![],
                vec![TcpOption::Mss(TCP_MSS_DEFAULT)],
            ),
            TcpSegment::Ack { seq, ack } => (seq, ack, TCP_FLAG_ACK, vec![], vec![]),
            TcpSegment::Data { seq, ack, payload } => {
                (seq, ack, TCP_FLAG_ACK | TCP_FLAG_PSH, payload, vec![])
            }
            TcpSegment::Fin { seq, ack } => (seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK, vec![], vec![]),
            TcpSegment::Rst { seq } => (seq, 0, TCP_FLAG_RST, vec![], vec![]),
        };

        TcpFrame {
            header: TcpHeader {
                src_port,
                dst_port,
                seq,
                ack,
                data_offset_reserved: 0,
                flags,
                window,
                checksum: 0,
                urgent_ptr: 0,
            },
            options,
            payload,
        }
    }

    pub fn reply(&self, window: u16, segment: TcpSegment) -> TcpFrame {
        TcpFrame::new(self.header.dst_port, self.header.src_port, window, segment)
    }

    fn options_size(&self) -> usize {
        if self.options.len() == 0 {
            return 0;
        }

        let mut options_len = 0; // at least one eol
        for option in &self.options {
            options_len += option.encoded_len();
        }
        options_len.next_multiple_of(4)
    }

    pub fn write(&self, bytes: &mut [u8]) -> usize {
        let options_len = self.options_size();

        let data_offset_words = (TcpHeader::SIZE + options_len) / 4;
        debug_assert!(data_offset_words <= 15, "tcp options exceed 40 bytes");

        let total = TcpHeader::SIZE + options_len + self.payload.len();
        debug_assert!(bytes.len() >= total, "buffer too small for tcp segment");

        let mut header = self.header.clone();
        header.data_offset_reserved = (data_offset_words as u8) << 4;
        header.checksum = 0;
        header.write(bytes);

        let mut off = TcpHeader::SIZE;
        for option in &self.options {
            option.write(&mut bytes[off..]);
            off += option.encoded_len();
        }
        while off < TcpHeader::SIZE + options_len {
            bytes[off] = 0x01;
            off += 1;
        }

        bytes[off..off + self.payload.len()].copy_from_slice(&self.payload);

        total
    }

    pub fn validate_checksum(&self, value: u16) -> bool {
        self.header.checksum == 0 || value == 0
    }

    pub fn size(&self) -> usize {
        let options_size = self.options_size();
        return TcpHeader::SIZE + options_size + self.payload.len();
    }

    pub fn seq(&self) -> u32 {
        self.header.seq
    }

    pub fn ack(&self) -> u32 {
        self.header.ack
    }

    pub fn flags(&self) -> u8 {
        self.header.flags
    }

    pub fn window(&self) -> u16 {
        self.header.window
    }
}
