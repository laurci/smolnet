#[derive(Debug, Clone, Copy)]
pub struct Checksum {
    sum: u32,
    carry: Option<u8>,
}

impl Default for Checksum {
    fn default() -> Self {
        Checksum::new()
    }
}

impl Checksum {
    pub const fn new() -> Checksum {
        Checksum {
            sum: 0,
            carry: None,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        let mut bytes = bytes;

        if let Some(carry) = self.carry {
            let Some((first, rest)) = bytes.split_first() else {
                return;
            };

            self.sum += u32::from(u16::from_be_bytes([carry, *first]));
            self.carry = None;
            bytes = rest;
        }

        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            self.sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }

        if let [last] = chunks.remainder() {
            self.carry = Some(*last);
        }

        self.fold();
    }

    pub fn push_u8(&mut self, value: u8) {
        self.push(&[value]);
    }

    pub fn push_u16(&mut self, value: u16) {
        self.push(&value.to_be_bytes());
    }

    pub fn push_u32(&mut self, value: u32) {
        self.push(&value.to_be_bytes());
    }

    pub fn push_ipv4_pseudo_header(
        &mut self,
        src_addr: &[u8; 4],
        dst_addr: &[u8; 4],
        protocol: u8,
        length: u16,
    ) {
        self.push(src_addr);
        self.push(dst_addr);
        self.push_u16(u16::from(protocol));
        self.push_u16(length);
    }

    fn fold(&mut self) {
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
    }

    pub fn finish(mut self) -> u16 {
        if let Some(carry) = self.carry {
            self.sum += u32::from(u16::from_be_bytes([carry, 0]));
            self.carry = None;
            self.fold();
        }

        !(self.sum as u16)
    }
}

pub fn checksum(bytes: &[u8]) -> u16 {
    let mut checksum = Checksum::new();
    checksum.push(bytes);
    checksum.finish()
}

#[cfg(test)]
mod test {
    use crate::checksum::{Checksum, checksum};

    #[test]
    fn split_pushes_match_contiguous() {
        let data: Vec<u8> = (0u8..=64).collect();

        for split in 0..data.len() {
            let mut incremental = Checksum::new();
            incremental.push(&data[..split]);
            incremental.push(&data[split..]);

            assert_eq!(
                incremental.finish(),
                checksum(&data),
                "mismatch when split at {split}"
            );
        }
    }

    #[test]
    fn odd_length_carry() {
        let mut split = Checksum::new();
        split.push(&[0x01]);
        split.push(&[0x02, 0x03]);

        assert_eq!(split.finish(), checksum(&[0x01, 0x02, 0x03]));
    }

    #[test]
    fn known_vector() {
        let bytes = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&bytes), 0x220d);
    }
}
