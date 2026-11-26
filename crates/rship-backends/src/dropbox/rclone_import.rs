//! `rclone.conf` importer for Dropbox (`type = dropbox`) remotes.

use rship_core::rclone_ini::parse_rclone_ini;

use crate::common::http::parse_rclone_oauth_token;
use crate::dropbox::auth::DropboxToken;

#[derive(Clone)]
pub struct ImportedRcloneDropbox {
    pub name: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub token: Option<DropboxToken>,
    pub root_namespace: Option<String>,
    pub impersonate: Option<String>,
    pub shared_folders: bool,
}

impl std::fmt::Debug for ImportedRcloneDropbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRcloneDropbox")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token", &self.token)
            .field("root_namespace", &self.root_namespace)
            .field("impersonate", &self.impersonate)
            .field("shared_folders", &self.shared_folders)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcloneDropboxImportReport {
    pub remotes: Vec<ImportedRcloneDropbox>,
    pub warnings: Vec<String>,
}

/// Parse Dropbox sections from an unencrypted `rclone.conf`, propagating INI /
/// `RCLONE_ENCRYPT_V0:` configuration errors.
pub fn try_parse_rclone_dropbox_conf(raw: &str) -> rship_core::Result<RcloneDropboxImportReport> {
    let mut out = RcloneDropboxImportReport::default();
    let sections = parse_rclone_ini(raw)?;
    for sec in sections {
        if !sec.kind().eq_ignore_ascii_case("dropbox") {
            continue;
        }
        let client_id = sec.get_non_empty("client_id");
        let client_secret = sec.get_non_empty("client_secret");
        let root_namespace = sec.get_non_empty("root_namespace");
        let impersonate = sec.get_non_empty("impersonate");
        let shared_folders = sec.get_bool("shared_folders").unwrap_or(false);
        let token = sec.get_non_empty("token").and_then(|raw_tok| {
            match parse_rclone_oauth_token(&raw_tok) {
                Ok(tok) => Some(tok),
                Err(e) => {
                    out.warnings.push(format!(
                        "dropbox remote `{}` has unreadable token JSON: {e}",
                        sec.name
                    ));
                    None
                }
            }
        });
        if client_id.is_none() {
            out.warnings.push(format!(
                "dropbox remote `{}` is missing `client_id` (rclone's built-in Dropbox App Key is not embedded; configure your own `client_id` before refreshing or re-authorizing)",
                sec.name
            ));
        }
        out.remotes.push(ImportedRcloneDropbox {
            name: sec.name,
            client_id,
            client_secret,
            token,
            root_namespace,
            impersonate,
            shared_folders,
        });
    }
    Ok(out)
}

pub fn parse_rclone_dropbox_conf(raw: &str) -> RcloneDropboxImportReport {
    match try_parse_rclone_dropbox_conf(raw) {
        Ok(rep) => rep,
        Err(e) => {
            let mut out = RcloneDropboxImportReport::default();
            out.warnings.push(format!("parse rclone.conf: {e}"));
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::ErrorKind;

    #[test]
    fn imports_dropbox_sections_from_rclone_conf() {
        let ini = r#"
[my-dbx]
type = dropbox
client_id = dbx-app-key
client_secret = dbx-app-secret
token = {"access_token":"sl.tok123","token_type":"bearer","refresh_token":"ref.xyz","expiry":"2027-01-01T00:00:00Z"}
"#;
        let rep = try_parse_rclone_dropbox_conf(ini).unwrap();
        assert!(rep.warnings.is_empty());
        assert_eq!(rep.remotes.len(), 1);
        assert_eq!(rep.remotes[0].name, "my-dbx");
        assert_eq!(rep.remotes[0].client_id.as_deref(), Some("dbx-app-key"));
        assert!(!rep.remotes[0].shared_folders);
        let tok = rep.remotes[0].token.as_ref().unwrap();
        assert_eq!(tok.access_token, "sl.tok123");
        assert_eq!(tok.refresh_token.as_deref(), Some("ref.xyz"));
    }

    #[test]
    fn imports_team_fields_and_warns_on_missing_client_id_even_with_token() {
        let ini = r#"
[team-dbx]
type = dropbox
root_namespace = 123456789
impersonate = alice@example.com
shared_folders = true
token = {"access_token":"sl.tok123","token_type":"bearer","refresh_token":"ref.xyz","expiry":"2027-01-01T00:00:00Z"}
"#;
        let rep = try_parse_rclone_dropbox_conf(ini).unwrap();
        assert_eq!(rep.remotes.len(), 1);
        let r = &rep.remotes[0];
        assert_eq!(r.root_namespace.as_deref(), Some("123456789"));
        assert_eq!(r.impersonate.as_deref(), Some("alice@example.com"));
        assert!(r.shared_folders);
        assert!(r.token.is_some());
        assert!(
            rep.warnings.iter().any(|w| w.contains("client_id")),
            "missing client_id must warn even when token is present: {:?}",
            rep.warnings
        );
    }

    #[test]
    fn try_parse_rejects_encrypted_rclone_conf() {
        let encrypted = "RCLONE_ENCRYPT_V0:\nbase64encryptedpayload==\n";
        let err = try_parse_rclone_dropbox_conf(encrypted)
            .expect_err("encrypted rclone.conf must return Config error");
        assert_eq!(err.kind, ErrorKind::Config);

        let compat = parse_rclone_dropbox_conf(encrypted);
        assert!(compat.remotes.is_empty());
        assert!(!compat.warnings.is_empty());
    }
}
