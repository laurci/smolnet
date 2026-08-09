use std::borrow::Cow;

use net_header::{Checksum, NetHeader, parse::HeaderParseError};
use thiserror::Error;

use crate::proto::options::{OptionsTooLong, TcpOptions};

pub const TCP_OPTION_END: u8 = 0;
pub const TCP_OPTION_NOP: u8 = 1;
pub const TCP_OPTION_MSS: u8 = 2;
pub const TCP_OPTION_WND_SCALE: u8 = 3;
pub const TCP_OPTION_SACK_PERMITTED: u8 = 4;
pub const TCP_OPTION_SACK_BLOCKS: u8 = 5;
pub const TCP_OPTION_TIMESTAMPS: u8 = 8;

pub const TCP_MSS_DEFAULT: u16 = 1460;

const TCP_MIN_DATA_OFFSET: u8 = 5;
const TCP_MAX_DATA_OFFSET: u8 = 15;

const SACK_BLOCK_SIZE: usize = 8;

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

    #[header(checksum)]
    checksum: u16,
    urgent_ptr: u16,
}

impl TcpHeader {
    fn data_offset(&self) -> u8 {
        self.data_offset_reserved >> 4
    }
}

#[derive(Debug, Error)]
pub enum TcpFrameParseError {
    #[error("failed to parse tcp header:\n{0}")]
    HeaderParseError(HeaderParseError),

    #[error("tcp data offset {0} is below the minimum of {TCP_MIN_DATA_OFFSET}")]
    DataOffsetTooSmall(u8),

    #[error("tcp data offset {offset} exceeds segment length {len}")]
    DataOffsetTooLarge { offset: usize, len: usize },

    #[error("tcp option kind {kind} declares invalid length {length}")]
    InvalidOptionLength { kind: u8, length: u8 },

    #[error("tcp option kind {0} is truncated")]
    TruncatedOption(u8),

    #[error("tcp options are too long:\n{0}")]
    OptionsTooLong(OptionsTooLong),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SackBlocks<'a>(pub &'a [u8]);

impl<'a> SackBlocks<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len() / SACK_BLOCK_SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.0.len() < SACK_BLOCK_SIZE
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, u32)> + 'a {
        self.0.chunks_exact(SACK_BLOCK_SIZE).map(|block| {
            let left = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
            let right = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);

            (left, right)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpOption<'a> {
    Mss(u16),
    WindowScale(u8),
    SackPermitted,
    SackBlocks(SackBlocks<'a>),
    Timestamps { tsval: u32, tsecr: u32 },
    Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
    pub fn kind(&self) -> u8 {
        match self {
            TcpOption::Mss(_) => TCP_OPTION_MSS,
            TcpOption::WindowScale(_) => TCP_OPTION_WND_SCALE,
            TcpOption::SackPermitted => TCP_OPTION_SACK_PERMITTED,
            TcpOption::SackBlocks(_) => TCP_OPTION_SACK_BLOCKS,
            TcpOption::Timestamps { .. } => TCP_OPTION_TIMESTAMPS,
            TcpOption::Unknown { kind, .. } => *kind,
        }
    }

    pub fn encoded_len(&self) -> usize {
        match self {
            TcpOption::Mss(_) => 4,
            TcpOption::WindowScale(_) => 3,
            TcpOption::SackPermitted => 2,
            TcpOption::SackBlocks(blocks) => 2 + blocks.as_bytes().len(),
            TcpOption::Timestamps { .. } => 10,
            TcpOption::Unknown { data, .. } => 2 + data.len(),
        }
    }

    fn decode(kind: u8, data: &'a [u8]) -> TcpOption<'a> {
        match kind {
            TCP_OPTION_MSS => TcpOption::Mss(u16::from_be_bytes([data[0], data[1]])),
            TCP_OPTION_WND_SCALE => TcpOption::WindowScale(data[0]),
            TCP_OPTION_SACK_PERMITTED => TcpOption::SackPermitted,
            TCP_OPTION_SACK_BLOCKS => TcpOption::SackBlocks(SackBlocks(data)),
            TCP_OPTION_TIMESTAMPS => TcpOption::Timestamps {
                tsval: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                tsecr: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            },
            kind => TcpOption::Unknown { kind, data },
        }
    }

    fn encode(&self, out: &mut TcpOptions) -> Result<(), OptionsTooLong> {
        let len = self.encoded_len();
        if len > TcpOptions::MAX {
            return Err(OptionsTooLong {
                max: TcpOptions::MAX,
                got: len,
            });
        }

        out.push(&[self.kind(), len as u8])?;

        match self {
            TcpOption::Mss(mss) => out.push(&mss.to_be_bytes()),
            TcpOption::WindowScale(scale) => out.push(&[*scale]),
            TcpOption::SackPermitted => Ok(()),
            TcpOption::SackBlocks(blocks) => out.push(blocks.as_bytes()),
            TcpOption::Timestamps { tsval, tsecr } => {
                out.push(&tsval.to_be_bytes())?;
                out.push(&tsecr.to_be_bytes())
            }
            TcpOption::Unknown { data, .. } => out.push(data),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpOptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for TcpOptionIter<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<TcpOption<'a>> {
        loop {
            let kind = *self.bytes.get(self.offset)?;

            match kind {
                TCP_OPTION_END => return None,
                TCP_OPTION_NOP => {
                    self.offset += 1;
                    continue;
                }
                _ => {
                    let length = *self.bytes.get(self.offset + 1)? as usize;
                    if length < 2 {
                        return None;
                    }

                    let end = self.offset + length;
                    let data = self.bytes.get(self.offset + 2..end)?;
                    self.offset = end;

                    return Some(TcpOption::decode(kind, data));
                }
            }
        }
    }
}

fn validate_options(bytes: &[u8]) -> Result<(), TcpFrameParseError> {
    let mut offset = 0;

    while offset < bytes.len() {
        let kind = bytes[offset];

        match kind {
            TCP_OPTION_END => break,
            TCP_OPTION_NOP => {
                offset += 1;
                continue;
            }
            _ => {}
        }

        let Some(&length) = bytes.get(offset + 1) else {
            return Err(TcpFrameParseError::TruncatedOption(kind));
        };

        if length < 2 {
            return Err(TcpFrameParseError::InvalidOptionLength { kind, length });
        }

        let end = offset + length as usize;
        if end > bytes.len() {
            return Err(TcpFrameParseError::TruncatedOption(kind));
        }

        let data_len = length as usize - 2;
        let valid = match kind {
            TCP_OPTION_MSS => data_len == 2,
            TCP_OPTION_WND_SCALE => data_len == 1,
            TCP_OPTION_SACK_PERMITTED => data_len == 0,
            TCP_OPTION_SACK_BLOCKS => data_len > 0 && data_len.is_multiple_of(SACK_BLOCK_SIZE),
            TCP_OPTION_TIMESTAMPS => data_len == 8,
            _ => true,
        };

        if !valid {
            return Err(TcpFrameParseError::InvalidOptionLength { kind, length });
        }

        if !matches!(
            kind,
            TCP_OPTION_MSS
                | TCP_OPTION_WND_SCALE
                | TCP_OPTION_SACK_PERMITTED
                | TCP_OPTION_SACK_BLOCKS
                | TCP_OPTION_TIMESTAMPS
        ) {
            tracing::trace!(kind, length, "retaining unknown tcp option");
        }

        offset = end;
    }

    Ok(())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpRepr<'p, 'o> {
    pub src_port: u16,
    pub dst_port: u16,

    pub seq: u32,
    pub ack: u32,

    pub flags: u8,
    pub window: u16,
    pub urgent_ptr: u16,

    pub options: &'o [TcpOption<'o>],
    pub payload: Cow<'p, [u8]>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TcpFrame<'a> {
    header: TcpHeader,
    options: TcpOptions,
    payload: Cow<'a, [u8]>,
}

impl<'a> TcpFrame<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<TcpFrame<'a>, TcpFrameParseError> {
        let header = TcpHeader::from_bytes(bytes).map_err(TcpFrameParseError::HeaderParseError)?;

        let data_offset_words = header.data_offset();
        if data_offset_words < TCP_MIN_DATA_OFFSET {
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
        validate_options(options_bytes)?;

        let options =
            TcpOptions::from_slice(options_bytes).map_err(TcpFrameParseError::OptionsTooLong)?;

        Ok(TcpFrame {
            header,
            options,
            payload: Cow::Borrowed(&bytes[data_offset..]),
        })
    }

    pub fn new(repr: TcpRepr<'a, '_>) -> Result<TcpFrame<'a>, OptionsTooLong> {
        let mut options = TcpOptions::new();
        for option in repr.options {
            option.encode(&mut options)?;
        }
        options.pad_to_word(TCP_OPTION_NOP)?;

        let header = TcpHeader {
            src_port: repr.src_port,
            dst_port: repr.dst_port,
            seq: repr.seq,
            ack: repr.ack,
            data_offset_reserved: 0,
            flags: repr.flags,
            window: repr.window,
            checksum: 0,
            urgent_ptr: repr.urgent_ptr,
        };

        Ok(TcpFrame {
            header,
            options,
            payload: repr.payload,
        })
    }

    pub fn write(&self, bytes: &mut [u8], seed: Checksum) -> usize {
        let data_offset_words = self.data_offset_words();
        debug_assert!(
            data_offset_words <= TCP_MAX_DATA_OFFSET,
            "tcp options exceed 40 bytes"
        );

        let total = self.size();
        debug_assert!(bytes.len() >= total, "buffer too small for tcp segment");

        let mut header = self.header.clone();
        header.data_offset_reserved = data_offset_words << 4;

        let mut checksum = seed;
        header.fold(&mut checksum);
        checksum.push(self.options.as_slice());
        checksum.push(&self.payload);
        header.checksum = checksum.finish();

        let offset = header.write(bytes);

        let options_end = offset + self.options.len();
        bytes[offset..options_end].copy_from_slice(self.options.as_slice());
        bytes[options_end..total].copy_from_slice(&self.payload);

        total
    }

    fn data_offset_words(&self) -> u8 {
        ((TcpHeader::SIZE + self.options.len()) / 4) as u8
    }

    pub fn size(&self) -> usize {
        TcpHeader::SIZE + self.options.len() + self.payload.len()
    }

    pub fn src_port(&self) -> u16 {
        self.header.src_port
    }

    pub fn dst_port(&self) -> u16 {
        self.header.dst_port
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

    pub fn urgent_ptr(&self) -> u16 {
        self.header.urgent_ptr
    }

    pub fn checksum(&self) -> u16 {
        self.header.checksum
    }

    pub fn has_flags(&self, flags: u8) -> bool {
        self.header.flags & flags == flags
    }

    pub fn fin(&self) -> bool {
        self.has_flags(TCP_FLAG_FIN)
    }

    pub fn syn(&self) -> bool {
        self.has_flags(TCP_FLAG_SYN)
    }

    pub fn rst(&self) -> bool {
        self.has_flags(TCP_FLAG_RST)
    }

    pub fn psh(&self) -> bool {
        self.has_flags(TCP_FLAG_PSH)
    }

    pub fn ack_flag(&self) -> bool {
        self.has_flags(TCP_FLAG_ACK)
    }

    pub fn urg(&self) -> bool {
        self.has_flags(TCP_FLAG_URG)
    }

    pub fn options(&self) -> TcpOptionIter<'_> {
        TcpOptionIter {
            bytes: self.options.as_slice(),
            offset: 0,
        }
    }

    pub fn option_bytes(&self) -> &[u8] {
        self.options.as_slice()
    }

    pub fn mss(&self) -> Option<u16> {
        self.options().find_map(|option| match option {
            TcpOption::Mss(mss) => Some(mss),
            _ => None,
        })
    }

    pub fn window_scale(&self) -> Option<u8> {
        self.options().find_map(|option| match option {
            TcpOption::WindowScale(scale) => Some(scale),
            _ => None,
        })
    }

    pub fn sack_permitted(&self) -> bool {
        self.options()
            .any(|option| matches!(option, TcpOption::SackPermitted))
    }

    pub fn timestamps(&self) -> Option<(u32, u32)> {
        self.options().find_map(|option| match option {
            TcpOption::Timestamps { tsval, tsecr } => Some((tsval, tsecr)),
            _ => None,
        })
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn segment_len(&self) -> usize {
        self.payload.len() + usize::from(self.syn()) + usize::from(self.fin())
    }

    pub fn into_owned(self) -> TcpFrame<'static> {
        TcpFrame {
            header: self.header,
            options: self.options,
            payload: Cow::Owned(self.payload.into_owned()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use net_header::Checksum;

    use crate::proto::tcp::wire::{
        SackBlocks, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
        TCP_MSS_DEFAULT, TcpFrame, TcpOption, TcpRepr,
    };

    fn encode(frame: &TcpFrame<'_>) -> Vec<u8> {
        let mut bytes = vec![0u8; frame.size()];
        let size = frame.write(&mut bytes, Checksum::new());

        assert_eq!(size, frame.size());

        bytes
    }

    #[test]
    fn syn_ack_roundtrip() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 7878,
            dst_port: 40000,
            seq: 10245,
            ack: 99,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window: 5000,
            options: &[TcpOption::Mss(TCP_MSS_DEFAULT)],
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&frame);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.src_port(), 7878);
        assert_eq!(parsed.dst_port(), 40000);
        assert_eq!(parsed.seq(), 10245);
        assert_eq!(parsed.ack(), 99);
        assert_eq!(parsed.window(), 5000);
        assert!(parsed.syn() && parsed.ack_flag());
        assert_eq!(parsed.mss(), Some(TCP_MSS_DEFAULT));
    }

    #[test]
    fn flag_combinations_the_old_enum_could_not_express() {
        let fin_with_data = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            seq: 100,
            ack: 200,
            flags: TCP_FLAG_FIN | TCP_FLAG_ACK | TCP_FLAG_PSH,
            window: 1000,
            payload: Cow::Borrowed(b"last bytes"),
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&fin_with_data);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert!(parsed.fin() && parsed.ack_flag() && parsed.psh());
        assert_eq!(parsed.payload(), b"last bytes");
        assert_eq!(parsed.segment_len(), b"last bytes".len() + 1);

        let rst_ack = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            seq: 5,
            ack: 6,
            flags: TCP_FLAG_RST | TCP_FLAG_ACK,
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&rst_ack);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert!(parsed.rst() && parsed.ack_flag());
        assert_eq!(parsed.segment_len(), 0);
    }

    #[test]
    fn full_option_set_roundtrips() {
        let blocks = [0u8, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 30, 0, 0, 0, 40];

        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            flags: TCP_FLAG_ACK,
            options: &[
                TcpOption::Mss(1400),
                TcpOption::WindowScale(7),
                TcpOption::SackPermitted,
                TcpOption::Timestamps {
                    tsval: 0xaabbccdd,
                    tsecr: 0x11223344,
                },
                TcpOption::SackBlocks(SackBlocks(&blocks)),
            ],
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&frame);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.mss(), Some(1400));
        assert_eq!(parsed.window_scale(), Some(7));
        assert!(parsed.sack_permitted());
        assert_eq!(parsed.timestamps(), Some((0xaabbccdd, 0x11223344)));

        let sack = parsed
            .options()
            .find_map(|option| match option {
                TcpOption::SackBlocks(blocks) => Some(blocks),
                _ => None,
            })
            .expect("sack blocks survived");

        assert_eq!(sack.len(), 2);
        assert_eq!(sack.iter().collect::<Vec<_>>(), vec![(10, 20), (30, 40)]);
    }

    #[test]
    fn unknown_options_are_preserved() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            options: &[
                TcpOption::Unknown {
                    kind: 253,
                    data: &[0xde, 0xad, 0xbe, 0xef],
                },
                TcpOption::Mss(1400),
            ],
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&frame);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.option_bytes(), frame.option_bytes());
        assert_eq!(parsed.mss(), Some(1400));

        let unknown = parsed
            .options()
            .find(|option| option.kind() == 253)
            .expect("unknown option survived the round trip");

        assert_eq!(
            unknown,
            TcpOption::Unknown {
                kind: 253,
                data: &[0xde, 0xad, 0xbe, 0xef],
            }
        );
    }

    #[test]
    fn options_are_padded_to_a_word_boundary() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            options: &[TcpOption::WindowScale(7)],
            ..Default::default()
        })
        .unwrap();

        assert_eq!(frame.size() % 4, 0);

        let bytes = encode(&frame);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert_eq!(parsed.window_scale(), Some(7));
    }

    #[test]
    fn checksum_covers_options_and_payload() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 7878,
            dst_port: 40000,
            seq: 1,
            ack: 2,
            flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
            window: 5000,
            options: &[TcpOption::Mss(1400)],
            payload: Cow::Borrowed(b"hello world"),
            ..Default::default()
        })
        .unwrap();

        let src = [10, 30, 0, 2];
        let dst = [10, 30, 0, 3];

        let mut seed = Checksum::new();
        seed.push_ipv4_pseudo_header(&src, &dst, 6, frame.size() as u16);

        let mut bytes = vec![0u8; frame.size()];
        let size = frame.write(&mut bytes, seed);

        let mut verify = Checksum::new();
        verify.push_ipv4_pseudo_header(&src, &dst, 6, size as u16);
        verify.push(&bytes[..size]);
        assert_eq!(verify.finish(), 0);

        bytes[size - 1] ^= 0xff;
        let mut broken = Checksum::new();
        broken.push_ipv4_pseudo_header(&src, &dst, 6, size as u16);
        broken.push(&bytes[..size]);
        assert_ne!(broken.finish(), 0);
    }

    #[test]
    fn rejects_malformed_options() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            options: &[TcpOption::Mss(1400)],
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&frame);

        let mut bad_length = bytes.clone();
        bad_length[21] = 9;
        assert!(TcpFrame::parse(&bad_length).is_err());

        let mut zero_length = bytes.clone();
        zero_length[21] = 0;
        assert!(TcpFrame::parse(&zero_length).is_err());

        let mut runaway = bytes.clone();
        runaway[21] = 40;
        assert!(TcpFrame::parse(&runaway).is_err());
    }

    #[test]
    fn rejects_bad_data_offset_and_truncation() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            ..Default::default()
        })
        .unwrap();

        let mut bytes = encode(&frame);

        bytes[12] = 0x40;
        assert!(TcpFrame::parse(&bytes).is_err());

        bytes[12] = 0xf0;
        assert!(TcpFrame::parse(&bytes).is_err());

        let bytes = encode(&frame);
        for len in 0..bytes.len() {
            assert!(TcpFrame::parse(&bytes[..len]).is_err(), "len = {len}");
        }
    }

    #[test]
    fn parse_borrows_the_payload() {
        let frame = TcpFrame::new(TcpRepr {
            src_port: 1,
            dst_port: 2,
            payload: Cow::Borrowed(b"borrowed"),
            ..Default::default()
        })
        .unwrap();

        let bytes = encode(&frame);
        let parsed = TcpFrame::parse(&bytes).unwrap();

        assert!(matches!(parsed.payload, Cow::Borrowed(_)));
        assert!(matches!(parsed.into_owned().payload, Cow::Owned(_)));
    }
}
