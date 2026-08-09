use std::fmt;
use std::str::FromStr;

use thiserror::Error;

pub const NETWORK_ID_SIZE: usize = 16;

pub const NODE_ID_SIZE: usize = 32;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseIdError {
    #[error("expected {expected} hex characters; got {got}")]
    Length { expected: usize, got: usize },

    #[error("expected lowercase or uppercase hex characters")]
    InvalidHex,
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

macro_rules! byte_id {
    ($name:ident, $size:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $size]);

        impl $name {
            pub const SIZE: usize = $size;

            pub const fn new(bytes: [u8; $size]) -> $name {
                $name(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $size] {
                &self.0
            }

            pub fn from_slice(bytes: &[u8]) -> Option<$name> {
                <[u8; $size]>::try_from(bytes).ok().map($name)
            }

            pub fn random() -> $name {
                $name(rand::random())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }

                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}(", stringify!($name))?;

                for byte in &self.0[..4] {
                    write!(f, "{byte:02x}")?;
                }

                write!(f, "\u{2026})")
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(text: &str) -> Result<$name, ParseIdError> {
                let expected = $size * 2;

                if text.len() != expected {
                    return Err(ParseIdError::Length {
                        expected,
                        got: text.len(),
                    });
                }

                let mut bytes = [0u8; $size];

                for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
                    let high = hex_digit(pair[0]).ok_or(ParseIdError::InvalidHex)?;
                    let low = hex_digit(pair[1]).ok_or(ParseIdError::InvalidHex)?;

                    *byte = high << 4 | low;
                }

                Ok($name(bytes))
            }
        }

        impl From<[u8; $size]> for $name {
            fn from(bytes: [u8; $size]) -> $name {
                $name(bytes)
            }
        }
    };
}

byte_id!(NetworkId, NETWORK_ID_SIZE);
byte_id!(NodeId, NODE_ID_SIZE);

#[cfg(test)]
mod test {
    use crate::id::{NetworkId, NodeId, ParseIdError};

    #[test]
    fn hex_round_trip() {
        let network = NetworkId::random();
        let node = NodeId::random();

        assert_eq!(network.to_string().parse(), Ok(network));
        assert_eq!(node.to_string().parse(), Ok(node));
    }

    #[test]
    fn display_is_full_width_lowercase_hex() {
        let network = NetworkId::new([0xab; 16]);

        assert_eq!(network.to_string(), "ab".repeat(16));
    }

    #[test]
    fn debug_is_abbreviated() {
        let mut bytes = [0xffu8; 32];
        bytes[..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        assert_eq!(
            format!("{:?}", NodeId::new(bytes)),
            "NodeId(01020304\u{2026})"
        );
    }

    #[test]
    fn parsing_rejects_the_wrong_length() {
        assert_eq!(
            "abcd".parse::<NetworkId>(),
            Err(ParseIdError::Length {
                expected: 32,
                got: 4
            })
        );
    }

    #[test]
    fn parsing_rejects_non_hex() {
        assert_eq!(
            "zz".repeat(16).parse::<NetworkId>(),
            Err(ParseIdError::InvalidHex)
        );

        assert_eq!(
            "\u{00e9}".repeat(16).parse::<NetworkId>(),
            Err(ParseIdError::InvalidHex),
            "a multi byte character must not panic on a slice boundary"
        );
    }

    #[test]
    fn parsing_accepts_uppercase() {
        let network = NetworkId::random();

        assert_eq!(network.to_string().to_uppercase().parse(), Ok(network));
    }

    #[test]
    fn from_slice_checks_the_width() {
        assert_eq!(NodeId::from_slice(&[0u8; 32]), Some(NodeId::new([0; 32])));
        assert_eq!(NodeId::from_slice(&[0u8; 31]), None);
        assert_eq!(NodeId::from_slice(&[0u8; 33]), None);
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(NodeId::random(), NodeId::random());
    }
}
