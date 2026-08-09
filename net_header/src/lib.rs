pub mod parse;
pub mod write;

mod checksum;

use crate::parse::HeaderParseError;
pub use meta::NetHeader;

pub use checksum::{Checksum, checksum};

pub trait NetHeader: Sized {
    const SIZE: usize;

    fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderParseError>;

    fn write(&self, bytes: &mut [u8]) -> usize;

    fn fold(&self, checksum: &mut Checksum);
}
