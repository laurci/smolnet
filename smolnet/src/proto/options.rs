use std::hash::{Hash, Hasher};

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("header options exceed the maximum of {max} bytes (got = {got})")]
pub struct OptionsTooLong {
    pub max: usize,
    pub got: usize,
}

#[derive(Clone, Copy)]
pub struct OptionBytes<const N: usize> {
    buf: [u8; N],
    len: u8,
}

pub type Ipv4Options = OptionBytes<40>;
pub type TcpOptions = OptionBytes<40>;

impl<const N: usize> OptionBytes<N> {
    pub const EMPTY: OptionBytes<N> = OptionBytes {
        buf: [0; N],
        len: 0,
    };

    pub const MAX: usize = N;

    pub fn new() -> OptionBytes<N> {
        OptionBytes::EMPTY
    }

    pub fn from_slice(bytes: &[u8]) -> Result<OptionBytes<N>, OptionsTooLong> {
        let mut options = OptionBytes::EMPTY;
        options.push(bytes)?;

        Ok(options)
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), OptionsTooLong> {
        let end = self.len as usize + bytes.len();
        if end > N {
            return Err(OptionsTooLong { max: N, got: end });
        }

        self.buf[self.len as usize..end].copy_from_slice(bytes);
        self.len = end as u8;

        Ok(())
    }

    pub fn pad_to_word(&mut self, fill: u8) -> Result<(), OptionsTooLong> {
        let padded = (self.len as usize).next_multiple_of(4);
        if padded > N {
            return Err(OptionsTooLong {
                max: N,
                got: padded,
            });
        }

        while (self.len as usize) < padded {
            self.buf[self.len as usize] = fill;
            self.len += 1;
        }

        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<const N: usize> Default for OptionBytes<N> {
    fn default() -> Self {
        OptionBytes::EMPTY
    }
}

impl<const N: usize> PartialEq for OptionBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> Eq for OptionBytes<N> {}

impl<const N: usize> Hash for OptionBytes<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl<const N: usize> std::fmt::Debug for OptionBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

#[cfg(test)]
mod test {
    use crate::proto::options::OptionBytes;

    #[test]
    fn push_accumulates_until_full() {
        let mut options = OptionBytes::<8>::new();

        options.push(&[1, 2, 3]).unwrap();
        options.push(&[4, 5]).unwrap();
        assert_eq!(options.as_slice(), &[1, 2, 3, 4, 5]);

        assert!(options.push(&[6, 7, 8, 9]).is_err());
        assert_eq!(options.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn pad_to_word_rounds_up() {
        let mut options = OptionBytes::<8>::from_slice(&[1, 2, 3]).unwrap();
        options.pad_to_word(0x01).unwrap();

        assert_eq!(options.as_slice(), &[1, 2, 3, 0x01]);
        assert_eq!(options.len() % 4, 0);

        let mut aligned = OptionBytes::<8>::from_slice(&[1, 2, 3, 4]).unwrap();
        aligned.pad_to_word(0x01).unwrap();
        assert_eq!(aligned.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn equality_ignores_the_unused_tail() {
        let a = OptionBytes::<8>::from_slice(&[1, 2]).unwrap();
        let mut b = OptionBytes::<8>::from_slice(&[1, 2, 3]).unwrap();

        assert_ne!(a, b);

        b = OptionBytes::<8>::from_slice(&[1, 2]).unwrap();
        assert_eq!(a, b);
    }
}
