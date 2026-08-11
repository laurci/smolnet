use std::error::Error;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use smolmesh::keys::Keypair;

pub const SYSTEM_DIR: &str = "/etc/smol";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default)]
    pub control: String,

    #[serde(default)]
    pub mesh: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn render(&self) -> String {
        let body = toml::to_string_pretty(self).unwrap_or_default();

        format!("# written by smol; edit if you know what you are doing\n{body}")
    }

    /// The control port always speaks tls. The certificate is the server's
    /// own, so what makes it trustworthy is the copy handed over the console's
    /// https api at the same time as the join token.
    pub fn mesh_url(&self) -> Option<String> {
        (!self.mesh.is_empty()).then(|| format!("https://{}", self.mesh))
    }

}

fn home_of(user: &str) -> Option<PathBuf> {
    let name = std::ffi::CString::new(user).ok()?;
    let entry = unsafe { libc::getpwnam(name.as_ptr()) };

    if entry.is_null() {
        return None;
    }

    let directory = unsafe { std::ffi::CStr::from_ptr((*entry).pw_dir) };

    Some(PathBuf::from(directory.to_str().ok()?))
}

pub fn home() -> Option<PathBuf> {
    if let Ok(user) = std::env::var("SUDO_USER")
        && !user.is_empty()
        && let Some(home) = home_of(&user)
    {
        return Some(home);
    }

    std::env::var("HOME").ok().map(PathBuf::from)
}

pub fn path() -> PathBuf {
    match home() {
        Some(home) => home.join(".config/smol/config.toml"),
        None => PathBuf::from(SYSTEM_DIR).join("config.toml"),
    }
}

pub fn system_path() -> PathBuf {
    PathBuf::from(SYSTEM_DIR).join("config.toml")
}

pub fn daemon_path() -> PathBuf {
    PathBuf::from(SYSTEM_DIR).join("daemon.toml")
}

/// Where this machine keeps what it is, as opposed to how it is configured.
///
/// The daemon keeps its state under /etc so it does not depend on any one
/// user's home directory being readable at boot; everything a person runs keeps
/// state beside their own config.
pub fn state_dir(system: bool) -> PathBuf {
    if system {
        return PathBuf::from(SYSTEM_DIR);
    }

    match home() {
        Some(home) => home.join(".config/smol"),
        None => PathBuf::from(SYSTEM_DIR),
    }
}

pub fn keys_dir(system: bool) -> PathBuf {
    state_dir(system).join("keys")
}

/// The device this machine is, as the control server named it.
///
/// This is identity, not configuration: it is never merged from several files
/// and never edited by hand. Whoever exchanges a key for a token is told which
/// device they got, and writes it here, so the next start asks for that same
/// device instead of a new one.
pub fn known_device(system: bool) -> Option<String> {
    read_device(&state_dir(system))
}

pub fn remember_device(system: bool, device: &str) -> Result<(), Box<dyn Error>> {
    write_device(&state_dir(system), device)
}

pub fn read_device(directory: &Path) -> Option<String> {
    let found = std::fs::read_to_string(directory.join("device")).ok()?;
    let found = found.trim().to_owned();

    (!found.is_empty()).then_some(found)
}

pub fn write_device(directory: &Path, device: &str) -> Result<(), Box<dyn Error>> {
    // The server always answers with a device; an empty answer would mean the
    // exchange failed, and must not erase what this machine already is.
    if device.is_empty() || read_device(directory).as_deref() == Some(device) {
        return Ok(());
    }

    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join("device"), device)?;

    tracing::info!(device, "this machine is now that device");

    Ok(())
}

/// The key pair that identifies a device on the mesh, made once and then kept.
///
/// It is per device rather than per machine on purpose: a peer is looked up by
/// its public key when a packet is opened, so two devices sharing one key would
/// be indistinguishable to everyone else, and traffic from one would be
/// attributed to the other.
pub fn keys_for(system: bool, device: &str) -> Result<Keypair, Box<dyn Error>> {
    keys_in(&keys_dir(system), device)
}

pub fn keys_in(directory: &Path, device: &str) -> Result<Keypair, Box<dyn Error>> {
    let path = directory.join(format!("{device}.key"));

    if let Ok(stored) = std::fs::read_to_string(&path) {
        match Keypair::from_hex(stored.trim()) {
            Ok(keys) => return Ok(keys),
            Err(e) => tracing::warn!(path = %path.display(), "replacing an unreadable key: {e}"),
        }
    }

    let keys = Keypair::generate()?;

    std::fs::create_dir_all(directory)?;
    write_private(&path, &keys.private_hex())?;

    tracing::info!(device, path = %path.display(), "kept a new mesh key for this device");

    Ok(keys)
}

fn write_private(path: &PathBuf, contents: &str) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(())
}

impl Config {
    fn overlay(&mut self, other: Config) {
        for (slot, value) in [
            (&mut self.control, other.control),
            (&mut self.mesh, other.mesh),
            (&mut self.key, other.key),
        ] {
            if !value.is_empty() {
                *slot = value;
            }
        }
    }
}

/// The endpoint is public and lives in a world readable file; the key and the
/// device it names are secret and live in files only their owner can read.
/// Later sources win, so a personal login overrides the machine wide one.
pub fn load() -> Config {
    let mut config = Config::default();

    for candidate in [system_path(), daemon_path(), path()] {
        if let Ok(text) = std::fs::read_to_string(&candidate)
            && let Ok(parsed) = Config::parse(&text)
        {
            config.overlay(parsed);
        }
    }

    config
}

pub fn save(config: &Config) -> Result<(), Box<dyn Error>> {
    let target = path();

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&target, config.render())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

pub fn resolve(control: Option<String>, key: Option<String>) -> Result<Config, Box<dyn Error>> {
    let mut config = load();

    if let Some(control) = control.or_else(|| std::env::var("SMOLCTL_CONTROL").ok()) {
        config.control = control;
    }

    if let Some(key) = key.or_else(|| std::env::var("SMOL_AUTH_KEY").ok()) {
        config.key = key;
    }

    if config.control.is_empty() {
        return Err(
            "no control server: reinstall with `sudo ./install.sh <host>:<port>`, \
             pass --control, or set SMOLCTL_CONTROL"
                .into(),
        );
    }

    if config.key.is_empty() {
        return Err("not signed in: run `smol login`".into());
    }

    Ok(config)
}

#[cfg(test)]
mod test {
    use std::os::unix::fs::PermissionsExt;

    use crate::config::{Config, keys_in, read_device, write_device};

    #[test]
    fn a_config_round_trips_through_toml() {
        let config = Config {
            control: "https://example.com/api".to_owned(),
            mesh: "example.com:54189".to_owned(),
            key: "smol_abc".to_owned(),
        };

        let parsed = Config::parse(&config.render()).unwrap();

        assert_eq!(parsed, config);
        assert_eq!(
            parsed.mesh_url().as_deref(),
            Some("https://example.com:54189"),
            "the control port is never dialled in the clear"
        );
    }

    #[test]
    fn a_machine_remembers_which_device_it_is() {
        let home = std::env::temp_dir().join(format!("smol-id-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        assert_eq!(read_device(&home), None, "a machine starts out as nobody");

        write_device(&home, "dev123").unwrap();

        assert_eq!(
            read_device(&home).as_deref(),
            Some("dev123"),
            "and the next start asks for that device rather than a new one"
        );
    }

    #[test]
    fn being_told_a_different_device_replaces_the_old_one() {
        let home = std::env::temp_dir().join(format!("smol-id2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();

        write_device(&home, "first").unwrap();
        write_device(&home, "second").unwrap();

        assert_eq!(read_device(&home).as_deref(), Some("second"));

        // An empty answer is not an answer; it must not erase what we know.
        write_device(&home, "").unwrap();

        assert_eq!(read_device(&home).as_deref(), Some("second"));
    }

    #[test]
    fn a_device_keeps_the_same_key_across_restarts() {
        let home = std::env::temp_dir().join(format!("smol-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);

        let first = keys_in(&home, "dev123").unwrap();
        let again = keys_in(&home, "dev123").unwrap();

        assert_eq!(
            first.public(),
            again.public(),
            "a restart must not change who this device is on the mesh"
        );

        // Two devices on one machine are two identities: peers are looked up by
        // public key, so sharing one would make their traffic indistinguishable.
        let other = keys_in(&home, "dev456").unwrap();

        assert_ne!(first.public(), other.public());

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_stored_key_is_readable_only_by_its_owner() {
        let home = std::env::temp_dir().join(format!("smol-keyperm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);

        keys_in(&home, "dev789").unwrap();

        let path = home.join("dev789.key");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();

        assert_eq!(mode & 0o077, 0, "nobody else may read a device's private key");

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn an_endpoint_only_config_is_valid_before_signing_in() {
        let text = "control = \"https://a/api\"\nmesh = \"a:1\"\n";
        let parsed = Config::parse(text).unwrap();

        assert!(parsed.key.is_empty());
    }

    #[test]
    fn secrets_are_left_out_when_they_are_empty() {
        let config = Config {
            control: "https://a/api".to_owned(),
            mesh: "a:1".to_owned(),
            ..Config::default()
        };

        let rendered = config.render();

        assert!(!rendered.contains("key"), "an empty key is not written at all");
        assert!(
            !rendered.contains("device"),
            "identity is state the daemon writes, never config anyone edits"
        );
    }

    #[test]
    fn a_personal_login_wins_over_the_machine_wide_endpoint() {
        let mut config = Config {
            control: "https://machine/api".to_owned(),
            mesh: "machine:1".to_owned(),
            ..Config::default()
        };

        config.overlay(Config {
            key: "smol_mine".to_owned(),
            ..Config::default()
        });

        assert_eq!(config.control, "https://machine/api", "empty fields do not erase");
        assert_eq!(config.key, "smol_mine");

        config.overlay(Config {
            control: "https://other/api".to_owned(),
            ..Config::default()
        });

        assert_eq!(config.control, "https://other/api", "a later source wins");
        assert_eq!(config.key, "smol_mine");
    }

    #[test]
    fn nonsense_is_rejected_rather_than_half_read() {
        assert!(Config::parse("control = ").is_err());
    }
}
