//! SFTP remote configuration, authentication, and host-key verification policy.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_SFTP_SINGLE_SHOT_MAX: u64 = 256 * 1024; // 256 KiB
pub const DEFAULT_SFTP_CHUNK_SIZE: u64 = 16 * 1024 * 1024; // 16 MiB resumable checkpoints

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostKeyPolicy {
    /// Verify against `known_hosts` if present; accept and persist previously unseen hosts.
    #[default]
    AcceptNew,
    /// Require an exact match in `known_hosts`.
    Strict,
    /// Skip host-key verification (intended only for ephemeral test/dev environments).
    Insecure,
}

impl HostKeyPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "accept-new" | "accept_new" | "" => Some(Self::AcceptNew),
            "strict" => Some(Self::Strict),
            "insecure" | "none" => Some(Self::Insecure),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptNew => "accept-new",
            Self::Strict => "strict",
            Self::Insecure => "insecure",
        }
    }
}

#[derive(Clone)]
pub enum SftpAuth {
    Password(String),
    KeyFile {
        path: PathBuf,
        passphrase: Option<String>,
    },
    KeyPem {
        pem: String,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for SftpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => f.debug_tuple("Password").field(&"[REDACTED]").finish(),
            Self::KeyFile { path, passphrase } => f
                .debug_struct("KeyFile")
                .field("path", path)
                .field("passphrase", &passphrase.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            Self::KeyPem { passphrase, .. } => f
                .debug_struct("KeyPem")
                .field("pem", &"[REDACTED]")
                .field("passphrase", &passphrase.as_ref().map(|_| "[REDACTED]"))
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SftpConfig {
    pub remote_name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Optional remote root directory (e.g., `/data/backups`, `/`, `~/backups`, or relative `backups`).
    pub root_path: String,
    pub auth: SftpAuth,
    pub host_key_policy: HostKeyPolicy,
    pub known_hosts_path: Option<PathBuf>,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub single_shot_max_bytes: u64,
    pub default_chunk_size: u64,
}

impl SftpConfig {
    pub fn new(
        remote_name: impl Into<String>,
        host: impl Into<String>,
        user: impl Into<String>,
        auth: SftpAuth,
    ) -> Self {
        Self {
            remote_name: remote_name.into(),
            host: host.into(),
            port: 22,
            user: user.into(),
            root_path: String::new(),
            auth,
            host_key_policy: HostKeyPolicy::AcceptNew,
            known_hosts_path: None,
            connect_timeout: Duration::from_secs(15),
            io_timeout: Duration::from_secs(30),
            single_shot_max_bytes: DEFAULT_SFTP_SINGLE_SHOT_MAX,
            default_chunk_size: DEFAULT_SFTP_CHUNK_SIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_policy_roundtrips_and_parses_aliases() {
        assert_eq!(HostKeyPolicy::parse(""), Some(HostKeyPolicy::AcceptNew));
        assert_eq!(
            HostKeyPolicy::parse("accept_new"),
            Some(HostKeyPolicy::AcceptNew)
        );
        assert_eq!(HostKeyPolicy::parse("STRICT"), Some(HostKeyPolicy::Strict));
        assert_eq!(HostKeyPolicy::parse("none"), Some(HostKeyPolicy::Insecure));
        assert_eq!(HostKeyPolicy::parse("bogus"), None);
        assert_eq!(HostKeyPolicy::AcceptNew.as_str(), "accept-new");
        assert_eq!(HostKeyPolicy::Strict.as_str(), "strict");
        assert_eq!(HostKeyPolicy::Insecure.as_str(), "insecure");
    }

    #[test]
    fn sftp_auth_debug_redacts_secrets() {
        let pw = format!("{:?}", SftpAuth::Password("super-secret-pw".into()));
        assert!(!pw.contains("super-secret-pw"));
        assert!(pw.contains("REDACTED"));

        let kf = format!(
            "{:?}",
            SftpAuth::KeyFile {
                path: PathBuf::from("/tmp/id_ed25519"),
                passphrase: Some("key-pass".into()),
            }
        );
        assert!(!kf.contains("key-pass"));
        assert!(kf.contains("REDACTED"));

        let kp = format!(
            "{:?}",
            SftpAuth::KeyPem {
                pem: "PRIVATE-KEY-BODY".into(),
                passphrase: Some("pem-pass".into()),
            }
        );
        assert!(!kp.contains("PRIVATE-KEY-BODY"));
        assert!(!kp.contains("pem-pass"));
        assert!(kp.contains("REDACTED"));
    }
}
