use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use smolmesh::{NetworkId, NodeId};
use thiserror::Error;

pub const ISSUER: &str = "smolctl";

pub const DEFAULT_TTL: u64 = 60 * 60 * 24 * 30;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub net: String,
    pub dev: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub network: NetworkId,
    pub node: NodeId,
    pub device: String,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("the system clock is before the unix epoch")]
    Clock,

    #[error("could not sign the token:\n{0}")]
    Sign(jsonwebtoken::errors::Error),

    #[error("the token is not valid:\n{0}")]
    Verify(jsonwebtoken::errors::Error),

    #[error("the token was issued by {0}, not {ISSUER}")]
    ForeignIssuer(String),

    #[error("the token carries a malformed node id")]
    NodeId,

    #[error("the token carries a malformed network id")]
    NetworkId,
}

fn now() -> Result<u64, TokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| TokenError::Clock)
}

pub fn mint(
    secret: &[u8],
    identity: Identity,
    ttl_seconds: u64,
) -> Result<(String, Claims), TokenError> {
    let issued = now()?;

    let claims = Claims {
        iss: ISSUER.to_owned(),
        sub: identity.node.to_string(),
        net: identity.network.to_string(),
        dev: identity.device.clone(),
        iat: issued,
        exp: issued + ttl_seconds,
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(TokenError::Sign)?;

    Ok((token, claims))
}

pub fn verify(secret: &[u8], token: &str) -> Result<Identity, TokenError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "sub"]);

    let data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(TokenError::Verify)?;

    if data.claims.iss != ISSUER {
        return Err(TokenError::ForeignIssuer(data.claims.iss));
    }

    Ok(Identity {
        network: data.claims.net.parse().map_err(|_| TokenError::NetworkId)?,
        node: data.claims.sub.parse().map_err(|_| TokenError::NodeId)?,
        device: data.claims.dev,
    })
}

#[cfg(test)]
mod test {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use smolmesh::{NetworkId, NodeId};

    use crate::token::{Claims, DEFAULT_TTL, ISSUER, Identity, TokenError, mint, verify};

    const SECRET: &[u8] = b"a shared secret that only the control plane knows";

    fn identity() -> Identity {
        Identity {
            network: NetworkId::random(),
            node: NodeId::random(),
            device: "dev".to_owned(),
        }
    }

    #[test]
    fn a_minted_token_verifies() {
        let identity = identity();
        let (token, _) = mint(SECRET, identity.clone(), DEFAULT_TTL).unwrap();

        assert_eq!(verify(SECRET, &token).unwrap(), identity);
    }

    #[test]
    fn another_secret_does_not_verify() {
        let (token, _) = mint(SECRET, identity(), DEFAULT_TTL).unwrap();

        assert!(matches!(
            verify(b"a different secret entirely", &token),
            Err(TokenError::Verify(_))
        ));
    }

    #[test]
    fn an_expired_token_does_not_verify() {
        let identity = identity();
        let issued = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 7200;

        let claims = Claims {
            dev: "dev".to_owned(),
            iss: ISSUER.to_owned(),
            sub: identity.node.to_string(),
            net: identity.network.to_string(),
            iat: issued,
            exp: issued + 3600,
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();

        assert!(
            matches!(verify(SECRET, &token), Err(TokenError::Verify(_))),
            "a token whose expiry has passed is refused"
        );
    }

    #[test]
    fn a_tampered_token_does_not_verify() {
        let (token, _) = mint(SECRET, identity(), DEFAULT_TTL).unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = mint(SECRET, identity(), DEFAULT_TTL).unwrap().0;
        let forged_payload = forged.split('.').nth(1).unwrap();
        parts[1] = forged_payload;

        assert!(
            matches!(verify(SECRET, &parts.join(".")), Err(TokenError::Verify(_))),
            "swapping the claims invalidates the signature"
        );
    }

    #[test]
    fn the_claims_carry_both_identifiers() {
        let identity = identity();
        let (_, claims) = mint(SECRET, identity.clone(), DEFAULT_TTL).unwrap();

        assert_eq!(claims.sub, identity.node.to_string());
        assert_eq!(claims.net, identity.network.to_string());
        assert!(claims.exp > claims.iat);
    }
}
