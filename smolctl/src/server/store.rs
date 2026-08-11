use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::{Row, migrate::MigrateError};

pub const PRIVATE_BASE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 0);
pub const NETWORK_PREFIX: u8 = 24;
const RESERVED_BLOCKS: u32 = 256;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("the store could not be reached:\n{0}")]
    Database(#[from] sqlx::Error),

    #[error("the store schema could not be brought up to date:\n{0}")]
    Migrate(#[from] MigrateError),

    #[error("the {0} subnet has no free addresses left")]
    Exhausted(Ipv4Addr),

    #[error("that auth key is not valid")]
    UnknownKey,

    #[error("that auth key was revoked")]
    RevokedKey,

    #[error("that auth key expired")]
    ExpiredKey,

    #[error("that device belongs to someone else")]
    NotYours,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub subject: String,
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: String,
    pub owner: String,
    pub subnet: Ipv4Addr,
    pub prefix: u8,
}

impl Network {
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX << (32 - self.prefix))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: String,
    pub owner: String,
    pub network: String,
    pub node: String,
    pub ip: Ipv4Addr,
    pub name: Option<String>,
    pub ephemeral: bool,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub version: Option<String>,
    pub last_seen: Option<i64>,
    pub online: bool,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKey {
    pub id: String,
    pub owner: String,
    pub network: String,
    pub label: Option<String>,
    pub device: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub owner: String,
    pub network: String,
    pub session: bool,
    pub device: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Wanted<'a> {
    /// A device the caller already holds. `fallback` is the name to fall back
    /// to when that device is gone, so a machine whose device was deleted comes
    /// back under its own name rather than as an anonymous one.
    Existing {
        device: &'a str,
        fallback: Option<&'a str>,
    },
    /// An exact name the user asked for: reuse the device that holds it.
    Named(&'a str),
    /// A name derived from the machine, so only a hint: normalise it and take
    /// the next free variant rather than colliding with someone else's device.
    Suggested(&'a str),
    Rename { device: &'a str, name: &'a str },
    Throwaway,
    Fresh,
}

#[derive(Debug, Clone)]
pub struct Minted {
    pub key: AuthKey,
    pub secret: String,
}

pub fn digest(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default()
}

fn identifier() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);

    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const ADJECTIVES: &[&str] = &[
    "amber", "brisk", "calm", "dusky", "eager", "faint", "gentle", "hazy", "idle", "jolly",
    "keen", "lively", "mellow", "noble", "olive", "plucky", "quiet", "rapid", "silent", "tidy",
];

const CREATURES: &[&str] = &[
    "otter", "badger", "heron", "marten", "finch", "lynx", "vole", "shrike", "gecko", "ibis",
    "krill", "loon", "mantis", "newt", "osprey", "puffin", "quail", "raven", "stoat", "tapir",
];

/// A throwaway device still deserves something readable in the console.
pub fn random_name() -> String {
    let mut bytes = [0u8; 2];
    rand::fill(&mut bytes);

    format!(
        "{}-{}",
        ADJECTIVES[bytes[0] as usize % ADJECTIVES.len()],
        CREATURES[bytes[1] as usize % CREATURES.len()]
    )
}

/// Names become dns labels, so keep them to what a label may hold: lowercase
/// alphanumerics and single dashes, never leading or trailing.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());

    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }

    let trimmed = out.trim_matches('-');
    let capped: String = trimmed.chars().take(63).collect();

    if capped.is_empty() {
        random_name()
    } else {
        capped.trim_matches('-').to_owned()
    }
}

fn random_subnet() -> Ipv4Addr {
    let mut bytes = [0u8; 4];
    rand::fill(&mut bytes);

    let span = (1u32 << (NETWORK_PREFIX - 8)) - RESERVED_BLOCKS;
    let chosen = u32::from_be_bytes(bytes) % span;

    Ipv4Addr::from(u32::from(PRIVATE_BASE) | ((RESERVED_BLOCKS + chosen) << (32 - NETWORK_PREFIX)))
}

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn open(path: &str) -> Result<Store, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new().connect_with(options).await?;

        Store::prepare(pool).await
    }

    pub async fn memory() -> Result<Store, StoreError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;

        Store::prepare(pool).await
    }

    async fn prepare(pool: SqlitePool) -> Result<Store, StoreError> {
        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Store { pool })
    }

    pub async fn default_network(&self, owner: &str) -> Result<Network, StoreError> {
        let existing = sqlx::query(
            "SELECT id, owner, subnet, prefix FROM networks WHERE owner = ?1 ORDER BY created_at",
        )
        .bind(owner)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = existing {
            return Ok(Network {
                id: row.get(0),
                owner: row.get(1),
                subnet: row
                    .get::<String, _>(2)
                    .parse()
                    .unwrap_or(PRIVATE_BASE),
                prefix: row.get::<i64, _>(3) as u8,
            });
        }

        let id = identifier();
        let subnet = random_subnet();

        sqlx::query(
            "INSERT INTO networks (id, owner, subnet, prefix, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&id)
        .bind(owner)
        .bind(subnet.to_string())
        .bind(i64::from(NETWORK_PREFIX))
        .bind(now())
        .execute(&self.pool)
        .await?;

        tracing::info!(owner, %subnet, prefix = NETWORK_PREFIX, "created a network");

        Ok(Network {
            id,
            owner: owner.to_owned(),
            subnet,
            prefix: NETWORK_PREFIX,
        })
    }

    async fn network(&self, id: &str) -> Result<Network, StoreError> {
        let row = sqlx::query("SELECT id, owner, subnet, prefix FROM networks WHERE id = ?1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;

        Ok(Network {
            id: row.get(0),
            owner: row.get(1),
            subnet: row.get::<String, _>(2).parse().unwrap_or(PRIVATE_BASE),
            prefix: row.get::<i64, _>(3) as u8,
        })
    }

    pub async fn upsert_user(
        &self,
        subject: &str,
        email: &str,
        name: Option<&str>,
    ) -> Result<User, StoreError> {
        let existing: Option<String> = sqlx::query("SELECT id FROM users WHERE subject = ?1")
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?
            .map(|row| row.get(0));

        let id = match existing {
            Some(id) => {
                sqlx::query("UPDATE users SET email = ?2, name = ?3 WHERE id = ?1")
                    .bind(&id)
                    .bind(email)
                    .bind(name)
                    .execute(&self.pool)
                    .await?;

                id
            }
            None => {
                let id = identifier();

                sqlx::query(
                    "INSERT INTO users (id, subject, email, name, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                )
                .bind(&id)
                .bind(subject)
                .bind(email)
                .bind(name)
                .bind(now())
                .execute(&self.pool)
                .await?;

                id
            }
        };

        Ok(User {
            id,
            subject: subject.to_owned(),
            email: email.to_owned(),
            name: name.map(str::to_owned),
        })
    }

    async fn free_address(&self, network: &Network) -> Result<Ipv4Addr, StoreError> {
        let base = u32::from(network.subnet) & u32::from(network.netmask());
        let span = !u32::from(network.netmask());

        let taken: Vec<u32> = sqlx::query("SELECT ip FROM devices WHERE network = ?1")
            .bind(&network.id)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .filter_map(|row| row.get::<String, _>(0).parse::<Ipv4Addr>().ok())
            .map(u32::from)
            .collect();

        let usable = span.saturating_sub(2);

        if usable == 0 || taken.len() as u32 >= usable {
            return Err(StoreError::Exhausted(network.subnet));
        }

        let mut bytes = [0u8; 4];
        rand::fill(&mut bytes);

        let start = u32::from_be_bytes(bytes) % usable;

        for step in 0..usable {
            let candidate = base | (2 + (start + step) % usable);

            if !taken.contains(&candidate) {
                return Ok(Ipv4Addr::from(candidate));
            }
        }

        Err(StoreError::Exhausted(network.subnet))
    }

    pub async fn resolve_device(
        &self,
        owner: &str,
        network: &str,
        wanted: Wanted<'_>,
        node: &str,
    ) -> Result<Device, StoreError> {
        let id = match wanted {
            Wanted::Existing { device, fallback } => {
                let holder: Option<String> = sqlx::query("SELECT owner FROM devices WHERE id = ?1")
                    .bind(device)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|row| row.get(0));

                match holder {
                    Some(holder) if holder == owner => device.to_owned(),
                    Some(_) => return Err(StoreError::NotYours),
                    None => match fallback {
                        Some(name) => {
                            return Box::pin(self.resolve_device(
                                owner,
                                network,
                                Wanted::Suggested(name),
                                node,
                            ))
                            .await;
                        }
                        None => self.insert_device(owner, network, None, false).await?,
                    },
                }
            }

            Wanted::Rename { device, name } => {
                let holder: Option<String> = sqlx::query("SELECT owner FROM devices WHERE id = ?1")
                    .bind(device)
                    .fetch_optional(&self.pool)
                    .await?
                    .map(|row| row.get(0));

                match holder {
                    Some(holder) if holder != owner => return Err(StoreError::NotYours),
                    Some(_) => {
                        sqlx::query("UPDATE devices SET name = ?2 WHERE id = ?1")
                            .bind(device)
                            .bind(name)
                            .execute(&self.pool)
                            .await?;

                        device.to_owned()
                    }
                    None => {
                        return Box::pin(self.resolve_device(
                            owner,
                            network,
                            Wanted::Named(name),
                            node,
                        ))
                        .await;
                    }
                }
            }

            Wanted::Suggested(name) => {
                let wanted = normalize(name);
                let taken: Vec<String> =
                    sqlx::query("SELECT name FROM devices WHERE network = ?1 AND name IS NOT NULL")
                        .bind(network)
                        .fetch_all(&self.pool)
                        .await?
                        .into_iter()
                        .map(|row| row.get(0))
                        .collect();

                let mut candidate = wanted.clone();
                let mut suffix = 1;

                while taken.contains(&candidate) {
                    candidate = format!("{wanted}-{suffix}");
                    suffix += 1;
                }

                self.insert_device(owner, network, Some(&candidate), false)
                    .await?
            }

            Wanted::Named(name) => {
                let existing: Option<String> =
                    sqlx::query("SELECT id FROM devices WHERE network = ?1 AND name = ?2")
                        .bind(network)
                        .bind(name)
                        .fetch_optional(&self.pool)
                        .await?
                        .map(|row| row.get(0));

                match existing {
                    Some(id) => id,
                    None => self.insert_device(owner, network, Some(name), false).await?,
                }
            }

            Wanted::Throwaway => {
                let taken: Vec<String> =
                    sqlx::query("SELECT name FROM devices WHERE network = ?1 AND name IS NOT NULL")
                        .bind(network)
                        .fetch_all(&self.pool)
                        .await?
                        .into_iter()
                        .map(|row| row.get(0))
                        .collect();

                let mut candidate = random_name();
                let mut suffix = 1;

                while taken.contains(&candidate) {
                    candidate = format!("{}-{suffix}", random_name());
                    suffix += 1;
                }

                self.insert_device(owner, network, Some(&candidate), true)
                    .await?
            }

            Wanted::Fresh => self.insert_device(owner, network, None, false).await?,
        };

        sqlx::query("UPDATE devices SET node = ?2 WHERE id = ?1")
            .bind(&id)
            .bind(node)
            .execute(&self.pool)
            .await?;

        self.read_device(&id).await
    }

    async fn insert_device(
        &self,
        owner: &str,
        network: &str,
        name: Option<&str>,
        ephemeral: bool,
    ) -> Result<String, StoreError> {
        let id = identifier();
        let ip = self.free_address(&self.network(network).await?).await?;

        sqlx::query(
            "INSERT INTO devices (id, owner, network, name, ip, ephemeral, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&id)
        .bind(owner)
        .bind(network)
        .bind(name)
        .bind(ip.to_string())
        .bind(i64::from(ephemeral))
        .bind(now())
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    async fn read_device(&self, id: &str) -> Result<Device, StoreError> {
        let row = sqlx::query(
            "SELECT id, owner, network, COALESCE(node, ''), ip, hostname, os, version,
                    last_seen, online, name, ephemeral, public_key
             FROM devices WHERE id = ?1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;

        Ok(Device {
            id: row.get(0),
            owner: row.get(1),
            network: row.get(2),
            node: row.get(3),
            ip: row
                .get::<String, _>(4)
                .parse()
                .unwrap_or(Ipv4Addr::UNSPECIFIED),
            hostname: row.get(5),
            os: row.get(6),
            version: row.get(7),
            last_seen: row.get(8),
            online: row.get::<i64, _>(9) != 0,
            name: row.get(10),
            ephemeral: row.get::<i64, _>(11) != 0,
            public_key: row.get(12),
        })
    }

    pub async fn describe(
        &self,
        id: &str,
        hostname: Option<&str>,
        os: Option<&str>,
        version: Option<&str>,
        public_key: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE devices
             SET hostname = COALESCE(?2, hostname),
                 os = COALESCE(?3, os),
                 version = COALESCE(?4, version),
                 public_key = COALESCE(?5, public_key)
             WHERE id = ?1",
        )
        .bind(id)
        .bind(hostname)
        .bind(os)
        .bind(version)
        .bind(public_key)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn mark(&self, id: &str, online: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE devices SET online = ?2, last_seen = ?3 WHERE id = ?1")
            .bind(id)
            .bind(i64::from(online))
            .bind(now())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn devices(&self, owner: &str) -> Result<Vec<Device>, StoreError> {
        let ids: Vec<String> =
            sqlx::query("SELECT id FROM devices WHERE owner = ?1 ORDER BY created_at")
                .bind(owner)
                .fetch_all(&self.pool)
                .await?
                .into_iter()
                .map(|row| row.get(0))
                .collect();

        let mut devices = Vec::with_capacity(ids.len());

        for id in ids {
            devices.push(self.read_device(&id).await?);
        }

        Ok(devices)
    }

    pub async fn mint_session_key(
        &self,
        owner: &str,
        network: &str,
    ) -> Result<Minted, StoreError> {
        self.issue(owner, network, None, None, "session").await
    }

    pub async fn mint_key(
        &self,
        owner: &str,
        network: &str,
        label: Option<&str>,
        expires_at: Option<i64>,
    ) -> Result<Minted, StoreError> {
        self.issue(owner, network, label, expires_at, "key").await
    }

    async fn issue(
        &self,
        owner: &str,
        network: &str,
        label: Option<&str>,
        expires_at: Option<i64>,
        kind: &str,
    ) -> Result<Minted, StoreError> {
        let secret = format!("smol_{}{}", identifier(), identifier());
        let id = identifier();
        let created_at = now();

        sqlx::query(
            "INSERT INTO auth_keys (id, digest, owner, network, label, kind, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&id)
        .bind(digest(&secret))
        .bind(owner)
        .bind(network)
        .bind(label)
        .bind(kind)
        .bind(created_at)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(Minted {
            key: AuthKey {
                id,
                owner: owner.to_owned(),
                network: network.to_owned(),
                label: label.map(str::to_owned),
                device: None,
                created_at,
                expires_at,
                revoked: false,
            },
            secret,
        })
    }

    pub async fn keys(&self, owner: &str) -> Result<Vec<AuthKey>, StoreError> {
        let keys = sqlx::query(
            "SELECT id, owner, network, label, device, created_at, expires_at, revoked
             FROM auth_keys WHERE owner = ?1 AND kind = 'key' ORDER BY created_at",
        )
        .bind(owner)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| AuthKey {
            id: row.get(0),
            owner: row.get(1),
            network: row.get(2),
            label: row.get(3),
            device: row.get(4),
            created_at: row.get(5),
            expires_at: row.get(6),
            revoked: row.get::<i64, _>(7) != 0,
        })
        .collect();

        Ok(keys)
    }

    pub async fn revoke_key(&self, owner: &str, id: &str) -> Result<bool, StoreError> {
        let changed = sqlx::query("UPDATE auth_keys SET revoked = 1 WHERE id = ?1 AND owner = ?2")
            .bind(id)
            .bind(owner)
            .execute(&self.pool)
            .await?;

        Ok(changed.rows_affected() > 0)
    }

    pub async fn key_holder(&self, secret: &str) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            "SELECT users.email, auth_keys.expires_at, auth_keys.revoked
             FROM auth_keys JOIN users ON users.id = auth_keys.owner
             WHERE auth_keys.digest = ?1",
        )
        .bind(digest(secret))
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        if row.get::<i64, _>(2) != 0 {
            return Ok(None);
        }

        if row.get::<Option<i64>, _>(1).is_some_and(|at| at <= now()) {
            return Ok(None);
        }

        Ok(Some(row.get(0)))
    }

    pub async fn reset_presence(&self) -> Result<u64, StoreError> {
        let cleared = sqlx::query("UPDATE devices SET online = 0 WHERE online = 1")
            .execute(&self.pool)
            .await?;

        let swept = self.sweep_ephemeral().await?;

        Ok(cleared.rows_affected() + swept)
    }

    pub async fn key_owner(&self, secret: &str) -> Result<Holder, StoreError> {
        let row = sqlx::query(
            "SELECT owner, network, expires_at, revoked, kind, device
             FROM auth_keys WHERE digest = ?1",
        )
        .bind(digest(secret))
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::UnknownKey)?;

        if row.get::<i64, _>(3) != 0 {
            return Err(StoreError::RevokedKey);
        }

        if row.get::<Option<i64>, _>(2).is_some_and(|at| at <= now()) {
            return Err(StoreError::ExpiredKey);
        }

        Ok(Holder {
            owner: row.get(0),
            network: row.get(1),
            session: row.get::<String, _>(4) == "session",
            device: row.get(5),
        })
    }

    pub async fn start_connect(&self, ttl: i64) -> Result<(String, String), StoreError> {
        let mut bytes = [0u8; 4];
        rand::fill(&mut bytes);

        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        let raw: String = bytes
            .iter()
            .flat_map(|byte| {
                [
                    ALPHABET[(byte >> 3) as usize % 32],
                    ALPHABET[(byte & 0x1f) as usize],
                ]
            })
            .map(char::from)
            .collect();

        let code = format!("{}-{}", &raw[..4], &raw[4..]);
        let secret = identifier();

        sqlx::query(
            "INSERT INTO connects (code, secret, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&code)
        .bind(&secret)
        .bind(now())
        .bind(now() + ttl)
        .execute(&self.pool)
        .await?;

        Ok((code, secret))
    }

    pub async fn pending_connect(&self, code: &str) -> Result<bool, StoreError> {
        let row = sqlx::query("SELECT owner FROM connects WHERE code = ?1 AND expires_at > ?2")
            .bind(code)
            .bind(now())
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.is_some_and(|row| row.get::<Option<String>, _>(0).is_none()))
    }

    pub async fn approve_connect(
        &self,
        code: &str,
        owner: &str,
        _label: Option<&str>,
    ) -> Result<bool, StoreError> {
        if !self.pending_connect(code).await? {
            return Ok(false);
        }

        let network = self.default_network(owner).await?;
        let minted = self.mint_session_key(owner, &network.id).await?;

        let changed = sqlx::query(
            "UPDATE connects SET owner = ?2, issued = ?3 WHERE code = ?1 AND owner IS NULL",
        )
        .bind(code)
        .bind(owner)
        .bind(&minted.secret)
        .execute(&self.pool)
        .await?;

        Ok(changed.rows_affected() > 0)
    }

    pub async fn claim_connect(
        &self,
        code: &str,
        secret: &str,
    ) -> Result<Option<String>, StoreError> {
        let row = sqlx::query(
            "SELECT issued FROM connects WHERE code = ?1 AND secret = ?2 AND expires_at > ?3",
        )
        .bind(code)
        .bind(secret)
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;

        let issued: Option<String> = match row {
            Some(row) => row.get(0),
            None => return Err(StoreError::UnknownKey),
        };

        if issued.is_some() {
            sqlx::query("DELETE FROM connects WHERE code = ?1")
                .bind(code)
                .execute(&self.pool)
                .await?;
        }

        Ok(issued)
    }

    pub async fn open_session(&self, owner: &str, ttl: i64) -> Result<String, StoreError> {
        let id = format!("{}{}", identifier(), identifier());

        sqlx::query(
            "INSERT INTO sessions (id, owner, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&id)
        .bind(owner)
        .bind(now())
        .bind(now() + ttl)
        .execute(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn session_owner(&self, id: &str) -> Result<Option<User>, StoreError> {
        let row = sqlx::query(
            "SELECT users.id, users.subject, users.email, users.name
             FROM sessions JOIN users ON users.id = sessions.owner
             WHERE sessions.id = ?1 AND sessions.expires_at > ?2",
        )
        .bind(id)
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| User {
            id: row.get(0),
            subject: row.get(1),
            email: row.get(2),
            name: row.get(3),
        }))
    }

    pub async fn close_session(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM sessions WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn device(&self, id: &str) -> Result<Device, StoreError> {
        self.read_device(id).await
    }

    pub async fn release(&self, id: &str) -> Result<bool, StoreError> {
        let removed = sqlx::query("DELETE FROM devices WHERE id = ?1 AND ephemeral = 1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(removed.rows_affected() > 0)
    }

    pub async fn sweep_ephemeral(&self) -> Result<u64, StoreError> {
        let removed = sqlx::query("DELETE FROM devices WHERE ephemeral = 1 AND online = 0")
            .execute(&self.pool)
            .await?;

        Ok(removed.rows_affected())
    }

    pub async fn bind_key(&self, secret: &str, device: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE auth_keys SET device = ?2 WHERE digest = ?1 AND device IS NULL")
            .bind(digest(secret))
            .bind(device)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

}

#[cfg(test)]
mod test {
    use crate::server::store::{Store, StoreError, Wanted};

    async fn store() -> Store {
        Store::memory().await.unwrap()
    }

    async fn owner(store: &Store) -> String {
        store
            .upsert_user("google-sub-1", "someone@example.com", Some("Someone"))
            .await
            .unwrap()
            .id
    }

    async fn network(store: &Store, owner: &str) -> String {
        store.default_network(owner).await.unwrap().id
    }

    #[tokio::test]
    async fn a_user_gets_one_network_on_a_random_private_block() {
        let store = store().await;
        let owner = owner(&store).await;

        let first = store.default_network(&owner).await.unwrap();
        let again = store.default_network(&owner).await.unwrap();

        assert_eq!(first, again, "the default network is created once and reused");
        assert_eq!(first.subnet.octets()[0], 10, "it lives inside 10.0.0.0/8");
        assert_ne!(first.subnet.octets()[1], 0, "and avoids the crowded 10.0.0.0/16");
        assert_eq!(first.subnet.octets()[3], 0, "it is a /24 network address");
    }

    #[tokio::test]
    async fn networks_are_spread_across_the_private_range() {
        let store = store().await;
        let mut seen = std::collections::HashSet::new();

        for index in 0..40 {
            let owner = store
                .upsert_user(&format!("subject-{index}"), "someone@example.com", None)
                .await
                .unwrap()
                .id;

            seen.insert(store.default_network(&owner).await.unwrap().subnet);
        }

        assert!(seen.len() > 30, "expected a wide spread, got {}", seen.len());
    }

    #[tokio::test]
    async fn a_device_is_identity_and_a_mesh_node_is_only_a_session() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Fresh, "node-a")
            .await
            .unwrap();

        let again = store
            .resolve_device(&owner, &network, Wanted::Existing { device: &first.id, fallback: None }, "node-b")
            .await
            .unwrap();

        assert_eq!(first.id, again.id, "the device id is the identity");
        assert_eq!(first.ip, again.ip, "so the address survives a new mesh node");
        assert_eq!(again.node, "node-b", "and the node just follows the live session");

        assert_eq!(store.devices(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn two_machines_may_share_a_mesh_node_without_colliding() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let one = store
            .resolve_device(&owner, &network, Wanted::Named("alpha"), "same-node")
            .await
            .unwrap();
        let two = store
            .resolve_device(&owner, &network, Wanted::Named("beta"), "same-node")
            .await
            .unwrap();

        assert_ne!(one.id, two.id, "a node is not an identifier");
        assert_ne!(one.ip, two.ip);
    }

    #[tokio::test]
    async fn renaming_moves_the_name_rather_than_forking_the_device() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Named("192.168.1.135"), "node-a")
            .await
            .unwrap();

        let renamed = store
            .resolve_device(
                &owner,
                &network,
                Wanted::Rename {
                    device: &first.id,
                    name: "Laurcis-Mac",
                },
                "node-b",
            )
            .await
            .unwrap();

        assert_eq!(renamed.id, first.id, "the same device, corrected");
        assert_eq!(renamed.ip, first.ip, "and it keeps its address");
        assert_eq!(renamed.name.as_deref(), Some("Laurcis-Mac"));

        assert_eq!(
            store.devices(&owner).await.unwrap().len(),
            1,
            "renaming must not leave the old device behind"
        );
    }

    #[tokio::test]
    async fn a_suggested_name_is_normalised_into_a_dns_label() {
        use crate::server::store::normalize;

        assert_eq!(normalize("Laurentius-MacBook-Pro"), "laurentius-macbook-pro");
        assert_eq!(normalize("alpha1.lttle.cloud"), "alpha1-lttle-cloud");
        assert_eq!(normalize("  spaces   here  "), "spaces-here");
        assert_eq!(normalize("--weird--"), "weird");
        assert!(!normalize("!!!").is_empty(), "a name of only junk still gets one");
        assert!(normalize(&"x".repeat(200)).len() <= 63, "labels are capped");
    }

    #[tokio::test]
    async fn a_suggested_name_steps_aside_rather_than_stealing_one() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Suggested("laptop"), "node-a")
            .await
            .unwrap();
        let second = store
            .resolve_device(&owner, &network, Wanted::Suggested("Laptop"), "node-b")
            .await
            .unwrap();
        let third = store
            .resolve_device(&owner, &network, Wanted::Suggested("laptop"), "node-c")
            .await
            .unwrap();

        assert_eq!(first.name.as_deref(), Some("laptop"));
        assert_eq!(second.name.as_deref(), Some("laptop-1"), "same name after normalising");
        assert_eq!(third.name.as_deref(), Some("laptop-2"));

        assert_ne!(first.id, second.id, "a suggestion never takes over a device");
    }

    #[tokio::test]
    async fn a_machine_returns_under_its_own_name_after_its_device_is_deleted() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Suggested("laptop"), "node-a")
            .await
            .unwrap();

        sqlx::query("DELETE FROM devices WHERE id = ?1")
            .bind(&first.id)
            .execute(&store.pool)
            .await
            .unwrap();

        // The machine still asks for the device it was, and is told it is gone.
        let back = store
            .resolve_device(
                &owner,
                &network,
                Wanted::Existing { device: &first.id, fallback: Some("laptop") },
                "node-a",
            )
            .await
            .unwrap();

        assert_ne!(back.id, first.id, "it is a new row");
        assert_eq!(
            back.name.as_deref(),
            Some("laptop"),
            "but the machine comes back as itself, not as an unnamed device"
        );
    }

    #[tokio::test]
    async fn an_explicit_name_reuses_the_device_instead_of_stepping_aside() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Named("minecraft"), "node-a")
            .await
            .unwrap();
        let again = store
            .resolve_device(&owner, &network, Wanted::Named("minecraft"), "node-b")
            .await
            .unwrap();

        assert_eq!(first.id, again.id, "asking for a name by hand means that device");
        assert_eq!(again.name.as_deref(), Some("minecraft"));
        assert_eq!(store.devices(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_throwaway_still_gets_a_readable_unique_name() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let mut seen = std::collections::HashSet::new();

        for _ in 0..20 {
            let device = store
                .resolve_device(&owner, &network, Wanted::Throwaway, "node")
                .await
                .unwrap();

            let name = device.name.expect("a throwaway is still nameable");

            assert!(name.contains('-'), "expected adjective-creature, got {name}");
            assert!(seen.insert(name), "throwaway names must not collide");
        }
    }

    #[tokio::test]
    async fn a_named_device_is_created_once_then_reused() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Named("minecraft"), "node-a")
            .await
            .unwrap();
        let again = store
            .resolve_device(&owner, &network, Wanted::Named("minecraft"), "node-b")
            .await
            .unwrap();

        assert_eq!(first.id, again.id);
        assert_eq!(first.ip, again.ip);
        assert_eq!(store.devices(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_throwaway_is_new_every_time_and_releases_its_address() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let first = store
            .resolve_device(&owner, &network, Wanted::Throwaway, "node-a")
            .await
            .unwrap();
        let second = store
            .resolve_device(&owner, &network, Wanted::Throwaway, "node-b")
            .await
            .unwrap();

        assert_ne!(first.id, second.id);
        assert!(first.ephemeral && second.ephemeral);

        assert!(store.release(&first.id).await.unwrap());

        let left = store.devices(&owner).await.unwrap();

        assert_eq!(left.len(), 1, "releasing one throwaway leaves the other");
        assert_eq!(left[0].id, second.id);
    }

    #[tokio::test]
    async fn a_named_device_is_never_released_as_a_throwaway() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let named = store
            .resolve_device(&owner, &network, Wanted::Named("keep me"), "node-a")
            .await
            .unwrap();

        assert!(!store.release(&named.id).await.unwrap());
        assert_eq!(store.devices(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_device_belonging_to_someone_else_is_refused() {
        let store = store().await;
        let mine = owner(&store).await;
        let network = network(&store, &mine).await;

        let theirs = store
            .upsert_user("other-subject", "other@example.com", None)
            .await
            .unwrap()
            .id;
        let their_network = network_of(&store, &theirs).await;

        let their_device = store
            .resolve_device(&theirs, &their_network, Wanted::Fresh, "node-x")
            .await
            .unwrap();

        assert!(matches!(
            store
                .resolve_device(&mine, &network, Wanted::Existing { device: &their_device.id, fallback: None }, "node-y")
                .await,
            Err(StoreError::NotYours)
        ));
    }

    async fn network_of(store: &Store, owner: &str) -> String {
        store.default_network(owner).await.unwrap().id
    }

    #[tokio::test]
    async fn a_forgotten_device_id_gets_a_fresh_device_rather_than_an_error() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let device = store
            .resolve_device(&owner, &network, Wanted::Existing { device: "no-such-device", fallback: None }, "node-a")
            .await
            .unwrap();

        assert!(!device.id.is_empty());
        assert_eq!(store.devices(&owner).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_signing_in_user_is_matched_on_subject_not_email() {
        let store = store().await;

        let first = store
            .upsert_user("subject", "old@example.com", Some("Old"))
            .await
            .unwrap();
        let renamed = store
            .upsert_user("subject", "new@example.com", Some("New"))
            .await
            .unwrap();

        assert_eq!(first.id, renamed.id);
        assert_eq!(renamed.email, "new@example.com");
    }

    #[tokio::test]
    async fn cli_sessions_do_not_show_up_beside_hand_made_keys() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let session = store.mint_session_key(&owner, &network).await.unwrap();
        store
            .mint_key(&owner, &network, Some("for my library app"), None)
            .await
            .unwrap();

        let listed = store.keys(&owner).await.unwrap();

        assert_eq!(listed.len(), 1, "only keys the user made are listed");
        assert_eq!(listed[0].label.as_deref(), Some("for my library app"));
        assert!(store.key_holder(&session.secret).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_library_key_is_one_device_but_a_cli_session_is_the_whole_account() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let key = store.mint_key(&owner, &network, None, None).await.unwrap();
        let session = store.mint_session_key(&owner, &network).await.unwrap();

        let held = store.key_owner(&key.secret).await.unwrap();
        assert!(!held.session, "a hand made key is device scoped");

        let cli = store.key_owner(&session.secret).await.unwrap();
        assert!(cli.session, "a cli login speaks for the account");

        let first = store
            .resolve_device(&owner, &network, Wanted::Fresh, "node-a")
            .await
            .unwrap();

        store.bind_key(&key.secret, &first.id).await.unwrap();

        let bound = store.key_owner(&key.secret).await.unwrap();
        assert_eq!(
            bound.device.as_deref(),
            Some(first.id.as_str()),
            "the key now names that one device forever"
        );
    }

    #[tokio::test]
    async fn a_revoked_or_expired_key_stops_working() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let revoked = store.mint_key(&owner, &network, None, None).await.unwrap();
        store.revoke_key(&owner, &revoked.key.id).await.unwrap();

        assert!(matches!(
            store.key_owner(&revoked.secret).await,
            Err(StoreError::RevokedKey)
        ));

        let expired = store
            .mint_key(&owner, &network, None, Some(1))
            .await
            .unwrap();

        assert!(matches!(
            store.key_owner(&expired.secret).await,
            Err(StoreError::ExpiredKey)
        ));

        assert!(matches!(
            store.key_owner("smol_nonsense").await,
            Err(StoreError::UnknownKey)
        ));
    }

    #[tokio::test]
    async fn the_secret_is_never_stored_in_the_clear() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let minted = store.mint_key(&owner, &network, None, None).await.unwrap();
        let keys = store.keys(&owner).await.unwrap();

        assert!(!format!("{keys:?}").contains(&minted.secret));
    }

    #[tokio::test]
    async fn hostname_and_version_are_recorded_and_presence_toggles() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let device = store
            .resolve_device(&owner, &network, Wanted::Fresh, "node-a")
            .await
            .unwrap();

        store
            .describe(&device.id, Some("laptop"), Some("macos"), Some("0.1.0"), None)
            .await
            .unwrap();
        store.mark(&device.id, true).await.unwrap();

        let listed = store.devices(&owner).await.unwrap();

        assert_eq!(listed[0].hostname.as_deref(), Some("laptop"));
        assert_eq!(listed[0].version.as_deref(), Some("0.1.0"));
        assert!(listed[0].online);

        store.describe(&device.id, None, None, Some("0.2.0"), None).await.unwrap();
        let listed = store.devices(&owner).await.unwrap();

        assert_eq!(listed[0].hostname.as_deref(), Some("laptop"), "partial updates keep the rest");
        assert_eq!(listed[0].version.as_deref(), Some("0.2.0"));
    }

    #[tokio::test]
    async fn a_restart_clears_presence_it_can_no_longer_vouch_for() {
        let store = store().await;
        let owner = owner(&store).await;
        let network = network(&store, &owner).await;

        let named = store
            .resolve_device(&owner, &network, Wanted::Named("server"), "node-a")
            .await
            .unwrap();
        let throwaway = store
            .resolve_device(&owner, &network, Wanted::Throwaway, "node-b")
            .await
            .unwrap();

        store.mark(&named.id, true).await.unwrap();
        store.mark(&throwaway.id, true).await.unwrap();

        store.reset_presence().await.unwrap();

        let left = store.devices(&owner).await.unwrap();

        assert_eq!(left.len(), 1, "the throwaway is gone, the named device stays");
        assert!(!left[0].online);
    }

    #[tokio::test]
    async fn a_lease_survives_reopening_the_database() {
        let directory = std::env::temp_dir().join(format!("smolctl-store-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();

        let path = directory.join("control.db");
        let path = path.to_str().unwrap();

        let (owner, address, id) = {
            let store = Store::open(path).await.unwrap();
            let owner = store
                .upsert_user("subject", "someone@example.com", None)
                .await
                .unwrap()
                .id;

            let network = store.default_network(&owner).await.unwrap().id;
            let device = store
                .resolve_device(&owner, &network, Wanted::Named("box"), "node-a")
                .await
                .unwrap();

            (owner, device.ip, device.id)
        };

        let reopened = Store::open(path).await.unwrap();
        let network = reopened.default_network(&owner).await.unwrap().id;
        let device = reopened
            .resolve_device(&owner, &network, Wanted::Named("box"), "node-b")
            .await
            .unwrap();

        assert_eq!(device.ip, address, "the address outlives the process");
        assert_eq!(device.id, id, "and so does the identity");

        std::fs::remove_dir_all(&directory).ok();
    }
}
