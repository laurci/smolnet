use std::error::Error;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const SYSTEM_DIR: &str = "/etc/smol";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default)]
    pub control: String,

    #[serde(default)]
    pub mesh: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn render(&self) -> String {
        let body = toml::to_string_pretty(self).unwrap_or_default();

        format!("# written by smol; edit if you know what you are doing\n{body}")
    }

    pub fn mesh_url(&self) -> Option<String> {
        (!self.mesh.is_empty()).then(|| format!("http://{}", self.mesh))
    }

    pub fn device(&self) -> Option<&str> {
        (!self.device.is_empty()).then_some(self.device.as_str())
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

impl Config {
    fn overlay(&mut self, other: Config) {
        for (slot, value) in [
            (&mut self.control, other.control),
            (&mut self.mesh, other.mesh),
            (&mut self.key, other.key),
            (&mut self.device, other.device),
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
    use crate::config::Config;

    #[test]
    fn a_config_round_trips_through_toml() {
        let config = Config {
            control: "https://example.com/api".to_owned(),
            mesh: "example.com:54189".to_owned(),
            key: "smol_abc".to_owned(),
            device: "dev123".to_owned(),
        };

        let parsed = Config::parse(&config.render()).unwrap();

        assert_eq!(parsed, config);
        assert_eq!(parsed.mesh_url().as_deref(), Some("http://example.com:54189"));
        assert_eq!(parsed.device(), Some("dev123"));
    }

    #[test]
    fn an_endpoint_only_config_is_valid_before_signing_in() {
        let text = "control = \"https://a/api\"\nmesh = \"a:1\"\n";
        let parsed = Config::parse(text).unwrap();

        assert!(parsed.key.is_empty());
        assert_eq!(parsed.device(), None, "no device until the server names one");
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
        assert!(!rendered.contains("device"));
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
            device: "mine".to_owned(),
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
