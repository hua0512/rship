//! Parse SFTP (`type = sftp`) remotes from an existing `rclone.conf`,
//! automatically revealing rclone-obscured (`AES-256-CTR`) passwords & key passphrases.

use rship_core::Result;
use rship_core::rclone_ini::{parse_rclone_ini, reveal_or_passthrough_rclone_secret};
use std::path::PathBuf;

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedSftpRemote {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: Option<String>,
    pub key_file: Option<PathBuf>,
    pub key_file_pass: Option<String>,
    pub known_hosts_file: Option<PathBuf>,
    pub key_pem: Option<String>,
}

impl std::fmt::Debug for ImportedSftpRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedSftpRemote")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("pass", &self.pass.as_ref().map(|_| "[REDACTED]"))
            .field("key_file", &self.key_file)
            .field(
                "key_file_pass",
                &self.key_file_pass.as_ref().map(|_| "[REDACTED]"),
            )
            .field("known_hosts_file", &self.known_hosts_file)
            .field("key_pem", &self.key_pem.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct RcloneSftpImportReport {
    pub remotes: Vec<ImportedSftpRemote>,
    pub warnings: Vec<String>,
}

fn current_os_user() -> String {
    ["USER", "LOGNAME", "USERNAME"]
        .into_iter()
        .find_map(|var| {
            std::env::var(var)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "user".to_string())
}

fn home_dir_from_env() -> Option<PathBuf> {
    ["HOME", "USERPROFILE"].into_iter().find_map(|var| {
        std::env::var_os(var)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    })
}

fn expand_tilde(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" {
        return home_dir_from_env().unwrap_or_else(|| PathBuf::from(trimmed));
    }
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
        && let Some(home) = home_dir_from_env()
    {
        let mut out = home;
        for part in rest
            .split(['/', '\\'])
            .filter(|s| !s.is_empty() && *s != ".")
        {
            out.push(part);
        }
        return out;
    }
    PathBuf::from(trimmed)
}

fn normalize_pem_escapes(raw: &str) -> String {
    if !raw.contains('\n') && raw.contains("\\n") {
        raw.replace("\\r\\n", "\n").replace("\\n", "\n")
    } else {
        raw.to_string()
    }
}

/// Parse SFTP sections from a plaintext `rclone.conf`, returning an error on encrypted
/// configs (`RCLONE_ENCRYPT_V0:`) or malformed INI syntax.
pub fn try_parse_rclone_sftp_conf(raw: &str) -> Result<RcloneSftpImportReport> {
    let mut report = RcloneSftpImportReport::default();
    let sections = parse_rclone_ini(raw)?;

    for sec in sections {
        if !sec.kind().eq_ignore_ascii_case("sftp") {
            continue;
        }
        let name = sec.name.clone();
        let Some(host) = sec.get_non_empty("host") else {
            report
                .warnings
                .push(format!("sftp remote `{name}` missing `host`; skipped"));
            continue;
        };
        let port = sec
            .fields
            .get("port")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(22);
        let user = sec.get_non_empty("user").unwrap_or_else(current_os_user);
        let pass = sec
            .get_non_empty("pass")
            .map(|raw| reveal_or_passthrough_rclone_secret(&raw).0);
        let key_file = sec.get_non_empty("key_file").map(|p| expand_tilde(&p));
        let key_file_pass = sec
            .get_non_empty("key_file_pass")
            .map(|raw| reveal_or_passthrough_rclone_secret(&raw).0);
        let known_hosts_file = sec
            .get_non_empty("known_hosts_file")
            .map(|p| expand_tilde(&p));
        let key_pem = sec
            .get_non_empty("key_pem")
            .map(|raw| normalize_pem_escapes(&raw));

        report.remotes.push(ImportedSftpRemote {
            name,
            host,
            port,
            user,
            pass,
            key_file,
            key_file_pass,
            known_hosts_file,
            key_pem,
        });
    }
    Ok(report)
}

/// Backwards-compatible infallible wrapper around [`try_parse_rclone_sftp_conf`].
pub fn parse_rclone_sftp_conf(text: &str) -> RcloneSftpImportReport {
    match try_parse_rclone_sftp_conf(text) {
        Ok(rep) => rep,
        Err(e) => RcloneSftpImportReport {
            remotes: Vec::new(),
            warnings: vec![format!("parse rclone.conf: {e}")],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::rclone_ini::obscure_rclone_secret_with_iv;

    #[test]
    fn imports_sftp_sections_and_reveals_obscured_secrets() {
        let obs_pass = obscure_rclone_secret_with_iv("ssh-login-secret", [0x22; 16]);
        let obs_key_pass = obscure_rclone_secret_with_iv("ed25519-passphrase", [0x33; 16]);
        let conf = format!(
            r#"
[vps]
type = sftp
host = 10.0.0.5
port = 2222
user = deploy
pass = {obs_pass}
key_file = /home/deploy/.ssh/id_ed25519
key_file_pass = {obs_key_pass}
known_hosts_file = /etc/ssh/ssh_known_hosts
"#
        );
        let rep = try_parse_rclone_sftp_conf(&conf).unwrap();
        assert!(rep.warnings.is_empty());
        assert_eq!(rep.remotes.len(), 1);
        let s = &rep.remotes[0];
        assert_eq!(s.host, "10.0.0.5");
        assert_eq!(s.port, 2222);
        assert_eq!(s.pass.as_deref(), Some("ssh-login-secret"));
        assert_eq!(s.key_file_pass.as_deref(), Some("ed25519-passphrase"));
        assert_eq!(
            s.known_hosts_file.as_deref(),
            Some(std::path::Path::new("/etc/ssh/ssh_known_hosts"))
        );
    }

    #[test]
    fn defaults_user_to_os_user_expands_tilde_and_imports_key_pem() {
        let conf = r#"
[sf]
type = sftp
host = 10.0.0.9
key_file = ~/.ssh/id_ed25519
known_hosts_file = ~/.ssh/known_hosts
key_pem = -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----
"#;
        let rep = try_parse_rclone_sftp_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 1);
        let s = &rep.remotes[0];
        assert_eq!(s.user, current_os_user());
        if current_os_user() != "root" {
            assert_ne!(s.user, "root");
        }
        if home_dir_from_env().is_some() {
            let kf = s.key_file.as_ref().unwrap();
            assert!(!kf.starts_with("~"), "expected expanded key_file: {kf:?}");
            assert!(kf.ends_with(PathBuf::from(".ssh").join("id_ed25519")));

            let kh = s.known_hosts_file.as_ref().unwrap();
            assert!(
                !kh.starts_with("~"),
                "expected expanded known_hosts_file: {kh:?}"
            );
            assert!(kh.ends_with(PathBuf::from(".ssh").join("known_hosts")));
        }
        assert_eq!(
            s.key_pem.as_deref(),
            Some("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
        );
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("AAAA"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn try_parse_rejects_encrypted_rclone_conf_while_legacy_warns() {
        let encrypted = "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
        let err = try_parse_rclone_sftp_conf(encrypted).unwrap_err();
        assert!(err.is_config());

        let rep = parse_rclone_sftp_conf(encrypted);
        assert!(rep.remotes.is_empty());
        assert_eq!(rep.warnings.len(), 1);
    }
}
