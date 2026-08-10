use std::fmt;

use thiserror::Error;

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

pub const KEY_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("a {KEY_SIZE} byte key was expected, got {0}")]
    Length(usize),

    #[error("the key is not valid hexadecimal")]
    Encoding,

    #[error("could not generate a key pair:\n{0}")]
    Generate(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_SIZE]);

impl PublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<PublicKey, KeyError> {
        let bytes: [u8; KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| KeyError::Length(bytes.len()))?;

        Ok(PublicKey(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }

        Ok(())
    }
}

/// Truncated, so a key in a log line is recognisable without being copyable.
impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PublicKey({}…)", &self.to_string()[..8])
    }
}

impl std::str::FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<PublicKey, KeyError> {
        if text.len() != KEY_SIZE * 2 {
            return Err(KeyError::Length(text.len() / 2));
        }

        let mut bytes = [0u8; KEY_SIZE];

        for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| KeyError::Encoding)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| KeyError::Encoding)?;
        }

        Ok(PublicKey(bytes))
    }
}

/// The device's long term identity. A binary mode device keeps this next to its
/// device id; a library mode device makes a fresh one per process and never
/// writes it down, so its peers simply learn a new key each time it starts.
#[derive(Clone)]
pub struct Keypair {
    private: Vec<u8>,
    public: PublicKey,
}

impl Keypair {
    pub fn generate() -> Result<Keypair, KeyError> {
        let builder = snow::Builder::new(
            PATTERN
                .parse()
                .map_err(|e| KeyError::Generate(format!("{e:?}")))?,
        );

        let pair = builder
            .generate_keypair()
            .map_err(|e| KeyError::Generate(format!("{e:?}")))?;

        Ok(Keypair {
            public: PublicKey::from_slice(&pair.public)?,
            private: pair.private,
        })
    }

    pub fn from_private(private: &[u8]) -> Result<Keypair, KeyError> {
        if private.len() != KEY_SIZE {
            return Err(KeyError::Length(private.len()));
        }

        // snow hands back both halves when it generates, but gives no way to
        // recover the public half from a stored private one, so do the
        // basepoint multiplication ourselves.
        let mut clamped = [0u8; KEY_SIZE];
        clamped.copy_from_slice(private);

        let secret = x25519_dalek::StaticSecret::from(clamped);
        let public = x25519_dalek::PublicKey::from(&secret);

        Ok(Keypair {
            private: private.to_vec(),
            public: PublicKey::from_slice(public.as_bytes())?,
        })
    }

    pub fn from_hex(text: &str) -> Result<Keypair, KeyError> {
        if text.len() != KEY_SIZE * 2 {
            return Err(KeyError::Length(text.len() / 2));
        }

        let mut bytes = [0u8; KEY_SIZE];

        for (slot, pair) in bytes.iter_mut().zip(text.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| KeyError::Encoding)?;
            *slot = u8::from_str_radix(pair, 16).map_err(|_| KeyError::Encoding)?;
        }

        Keypair::from_private(&bytes)
    }

    pub fn private(&self) -> &[u8] {
        &self.private
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    pub fn private_hex(&self) -> String {
        self.private.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Never print the private half, even by accident.
impl fmt::Debug for Keypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Keypair({:?})", self.public)
    }
}

#[cfg(test)]
mod test {
    use crate::keys::{Keypair, PublicKey};

    #[test]
    fn a_key_pair_round_trips_through_hex() {
        let pair = Keypair::generate().unwrap();
        let same = Keypair::from_hex(&pair.private_hex()).unwrap();

        assert_eq!(same.public(), pair.public(), "the same private key gives the same public key");
    }

    #[test]
    fn a_public_key_round_trips_through_text() {
        let pair = Keypair::generate().unwrap();
        let printed = pair.public().to_string();

        assert_eq!(printed.len(), 64);
        assert_eq!(printed.parse::<PublicKey>().unwrap(), pair.public());
    }

    #[test]
    fn two_devices_do_not_share_a_key() {
        let one = Keypair::generate().unwrap();
        let two = Keypair::generate().unwrap();

        assert_ne!(one.public(), two.public());
    }

    #[test]
    fn a_malformed_key_is_refused_rather_than_padded() {
        assert!("nothex".parse::<PublicKey>().is_err());
        assert!("zz".repeat(32).parse::<PublicKey>().is_err());
        assert!(Keypair::from_private(&[0u8; 16]).is_err());
    }

    #[test]
    fn the_private_half_never_reaches_a_log_line() {
        let pair = Keypair::generate().unwrap();
        let printed = format!("{pair:?}");

        assert!(
            !printed.contains(&pair.private_hex()),
            "debug output must not carry the private key"
        );
        assert!(printed.contains("PublicKey"));
    }
}
