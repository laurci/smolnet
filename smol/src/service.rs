use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

pub struct Service {
    pub binary: PathBuf,
}

impl Service {
    pub fn located() -> Result<Service, Box<dyn Error>> {
        Ok(Service {
            binary: std::env::current_exe()?,
        })
    }

    fn stash(&self, control: &str, token: &str, device: Option<&str>) -> Result<(), Box<dyn Error>> {
        let staged = std::env::temp_dir().join("smol-config.toml");

        let config = crate::config::Config {
            control: control.to_owned(),
            mesh: crate::config::load().mesh,
            key: token.to_owned(),
        };

        std::fs::write(&staged, config.render())?;

        elevated(&["install", "-d", "-m", "0755", "/etc/smol"])?;
        elevated(&[
            "install",
            "-m",
            "0600",
            &staged.to_string_lossy(),
            "/etc/smol/daemon.toml",
        ])?;

        std::fs::remove_file(&staged).ok();

        // Hand the daemon the device this person already signed in as, so a
        // machine does not turn up twice. Once it has one of its own it keeps
        // it, and this never has anything to say again.
        if let Some(device) = device
            && crate::config::known_device(true).is_none()
        {
            let staged = std::env::temp_dir().join("smol-device");
            std::fs::write(&staged, device)?;

            elevated(&[
                "install",
                "-m",
                "0644",
                &staged.to_string_lossy(),
                "/etc/smol/device",
            ])?;

            std::fs::remove_file(&staged).ok();
        }

        Ok(())
    }
}

fn run(command: &str, arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new(command).args(arguments).output()?;

    if !output.status.success() {
        return Err(format!(
            "{command} {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn elevated(arguments: &[&str]) -> Result<String, Box<dyn Error>> {
    if unsafe { libc::geteuid() } == 0 {
        return run(arguments[0], &arguments[1..]);
    }

    run("sudo", arguments)
}

#[cfg(target_os = "linux")]
mod platform {
    use super::{Error, PathBuf, Service, elevated, run};

    pub const UNIT: &str = "/etc/systemd/system/smol.service";

    pub fn unit_text(binary: &std::path::Path, environment: &str) -> String {
        format!(
            "[Unit]\n\
             Description=smolmesh node\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} __daemon\n\
             {environment}\
             Restart=on-failure\n\
             RestartSec=3\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            binary.display()
        )
    }

    impl Service {
        pub fn install(
            &self,
            control: &str,
            token: &str,
            device: Option<&str>,
        ) -> Result<(), Box<dyn Error>> {
            self.stash(control, token, device)?;

            let text = unit_text(&self.binary, "");
            let staged = std::env::temp_dir().join("smol.service");

            std::fs::write(&staged, text)?;

            elevated(&["install", "-m", "0644", &staged.to_string_lossy(), UNIT])?;
            std::fs::remove_file(&staged).ok();

            elevated(&["systemctl", "daemon-reload"])?;
            elevated(&["systemctl", "enable", "smol"])?;

            Ok(())
        }

        pub fn start(&self) -> Result<(), Box<dyn Error>> {
            elevated(&["systemctl", "start", "smol"]).map(|_| ())
        }

        pub fn stop(&self) -> Result<(), Box<dyn Error>> {
            elevated(&["systemctl", "stop", "smol"]).map(|_| ())
        }

        pub fn restart(&self) -> Result<(), Box<dyn Error>> {
            elevated(&["systemctl", "restart", "smol"]).map(|_| ())
        }

        pub fn status(&self) -> Result<String, Box<dyn Error>> {
            if !PathBuf::from(UNIT).exists() {
                return Ok("not installed".to_owned());
            }

            let active = run("systemctl", &["is-active", "smol"])
                .unwrap_or_else(|_| "inactive".to_owned());

            Ok(active.trim().to_owned())
        }

        pub fn logs(&self, follow: bool) -> Result<(), Box<dyn Error>> {
            let mut arguments = vec!["journalctl", "-u", "smol", "-n", "100"];

            if follow {
                arguments.push("-f");
            }

            let status = std::process::Command::new("sudo").args(&arguments).status()?;

            if !status.success() {
                return Err("could not read the logs".into());
            }

            Ok(())
        }

        pub fn uninstall(&self) -> Result<(), Box<dyn Error>> {
            let _ = elevated(&["systemctl", "disable", "--now", "smol"]);
            let _ = elevated(&["rm", "-f", UNIT]);

            elevated(&["systemctl", "daemon-reload"]).map(|_| ())
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Error, PathBuf, Service, elevated, run};

    pub const LABEL: &str = "sh.smolnet.smol";

    pub fn plist_path() -> String {
        format!("/Library/LaunchDaemons/{LABEL}.plist")
    }

    pub fn plist_text(binary: &std::path::Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>__daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/smol.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/smol.log</string>
</dict>
</plist>
"#,
            binary.display()
        )
    }

    impl Service {
        pub fn install(
            &self,
            control: &str,
            token: &str,
            device: Option<&str>,
        ) -> Result<(), Box<dyn Error>> {
            self.stash(control, token, device)?;

            let staged = std::env::temp_dir().join(format!("{LABEL}.plist"));
            std::fs::write(&staged, plist_text(&self.binary))?;

            elevated(&[
                "install",
                "-m",
                "0644",
                "-o",
                "root",
                "-g",
                "wheel",
                &staged.to_string_lossy(),
                &plist_path(),
            ])?;

            std::fs::remove_file(&staged).ok();

            let _ = elevated(&["launchctl", "bootstrap", "system", &plist_path()]);

            Ok(())
        }

        pub fn start(&self) -> Result<(), Box<dyn Error>> {
            elevated(&["launchctl", "kickstart", "-k", &format!("system/{LABEL}")]).map(|_| ())
        }

        pub fn stop(&self) -> Result<(), Box<dyn Error>> {
            elevated(&["launchctl", "bootout", &format!("system/{LABEL}")]).map(|_| ())
        }

        pub fn restart(&self) -> Result<(), Box<dyn Error>> {
            self.start()
        }

        pub fn status(&self) -> Result<String, Box<dyn Error>> {
            if !PathBuf::from(plist_path()).exists() {
                return Ok("not installed".to_owned());
            }

            match run("launchctl", &["print", &format!("system/{LABEL}")]) {
                Ok(text) if text.contains("state = running") => Ok("active".to_owned()),
                Ok(_) => Ok("loaded".to_owned()),
                Err(_) => Ok("inactive".to_owned()),
            }
        }

        pub fn logs(&self, follow: bool) -> Result<(), Box<dyn Error>> {
            let mut arguments = vec!["tail", "-n", "100"];

            if follow {
                arguments.push("-f");
            }

            arguments.push("/var/log/smol.log");

            let status = std::process::Command::new("sudo").args(&arguments).status()?;

            if !status.success() {
                return Err("could not read the logs".into());
            }

            Ok(())
        }

        pub fn uninstall(&self) -> Result<(), Box<dyn Error>> {
            let _ = elevated(&["launchctl", "bootout", &format!("system/{LABEL}")]);

            elevated(&["rm", "-f", &plist_path()]).map(|_| ())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::{Error, Service};

    impl Service {
        pub fn install(&self, _: &str, _: &str, _: Option<&str>) -> Result<(), Box<dyn Error>> {
            Err("smol only manages services on linux and macos".into())
        }

        pub fn start(&self) -> Result<(), Box<dyn Error>> {
            Err("smol only manages services on linux and macos".into())
        }

        pub fn stop(&self) -> Result<(), Box<dyn Error>> {
            self.start()
        }

        pub fn restart(&self) -> Result<(), Box<dyn Error>> {
            self.start()
        }

        pub fn status(&self) -> Result<String, Box<dyn Error>> {
            Ok("unsupported".to_owned())
        }

        pub fn logs(&self, _: bool) -> Result<(), Box<dyn Error>> {
            self.start()
        }

        pub fn uninstall(&self) -> Result<(), Box<dyn Error>> {
            self.start()
        }
    }
}
