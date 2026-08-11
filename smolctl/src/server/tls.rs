use std::io;
use std::path::{Path, PathBuf};

/// The name the certificate is issued for. Clients pin this exact certificate,
/// handed to them over the console's own https api, so the name in it never has
/// to match whatever host or address they happen to dial.
pub const CONTROL_NAME: &str = "smol-control";

const CERTIFICATE: &str = "control.crt";
const PRIVATE_KEY: &str = "control.key";

/// The control port's identity: a certificate it signs for itself, kept next to
/// the database so it survives a restart. There is no authority to ask, and no
/// name to prove; a client trusts this one certificate and nothing else.
#[derive(Clone)]
pub struct Material {
    pub certificate: String,
    key: String,
}

impl Material {
    pub fn load_or_create(directory: &Path) -> io::Result<Material> {
        let (certificate, key) = (directory.join(CERTIFICATE), directory.join(PRIVATE_KEY));

        if let (Ok(found), Ok(secret)) = (
            std::fs::read_to_string(&certificate),
            std::fs::read_to_string(&key),
        ) {
            tracing::info!(path = %certificate.display(), "serving control with the stored certificate");

            return Ok(Material {
                certificate: found,
                key: secret,
            });
        }

        let made = Material::generate()?;

        if let Some(parent) = certificate.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&certificate, &made.certificate)?;
        write_private(&key, &made.key)?;

        tracing::info!(
            path = %certificate.display(),
            fingerprint = %made.fingerprint(),
            "issued a control certificate"
        );

        Ok(made)
    }

    fn generate() -> io::Result<Material> {
        let issued = rcgen::generate_simple_self_signed([CONTROL_NAME.to_owned()])
            .map_err(|e| io::Error::other(format!("could not issue a certificate: {e}")))?;

        Ok(Material {
            certificate: issued.cert.pem(),
            key: issued.signing_key.serialize_pem(),
        })
    }

    pub fn identity(&self) -> tonic::transport::Identity {
        tonic::transport::Identity::from_pem(&self.certificate, &self.key)
    }

    /// A short form of the certificate, so an operator can eyeball that the one
    /// a client pinned is the one being served.
    pub fn fingerprint(&self) -> String {
        use sha2::Digest;

        let digest = sha2::Sha256::digest(self.certificate.as_bytes());

        digest
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Only the server may read its own key.
fn write_private(path: &PathBuf, contents: &str) -> io::Result<()> {
    std::fs::write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::server::tls::{CONTROL_NAME, Material};

    #[test]
    fn a_certificate_is_made_once_and_then_reused() {
        let directory = std::env::temp_dir().join(format!("smol-tls-{}", std::process::id()));

        let first = Material::load_or_create(&directory).unwrap();
        let again = Material::load_or_create(&directory).unwrap();

        assert_eq!(
            first.certificate, again.certificate,
            "a restart must not invalidate every client's pin"
        );
        assert_eq!(first.fingerprint(), again.fingerprint());

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn the_private_half_is_not_in_what_clients_are_given() {
        let directory = std::env::temp_dir().join(format!("smol-tls-key-{}", std::process::id()));
        let material = Material::load_or_create(&directory).unwrap();

        assert!(material.certificate.contains("BEGIN CERTIFICATE"));
        assert!(
            !material.certificate.contains("PRIVATE KEY"),
            "the certificate handed out must never carry the key"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn two_servers_do_not_share_an_identity() {
        let one = Material::generate().unwrap();
        let two = Material::generate().unwrap();

        assert_ne!(one.fingerprint(), two.fingerprint());
        assert!(one.certificate.contains("BEGIN CERTIFICATE"));
        assert_eq!(CONTROL_NAME, "smol-control");
    }
}
