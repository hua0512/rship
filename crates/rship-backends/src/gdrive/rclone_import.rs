//! Importer for existing `rclone.conf` Google Drive (`type = drive`) remotes.

use rship_core::rclone_ini::parse_rclone_ini;
use rship_core::{Error, Result};
use std::path::PathBuf;

use crate::common::http::parse_rclone_oauth_token;
use crate::gdrive::auth::OAuthToken;
use crate::gdrive::config::resolve_gdrive_scope;

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedRcloneGdrive {
    pub name: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: String,
    pub root_folder_id: Option<String>,
    pub shared_drive_id: Option<String>,
    pub service_account_file: Option<PathBuf>,
    pub service_account_credentials: Option<String>,
    pub impersonate: Option<String>,
    pub use_trash: Option<bool>,
    pub shared_with_me: bool,
    pub trashed_only: bool,
    pub stop_on_upload_limit: Option<bool>,
    pub token: Option<OAuthToken>,
}

impl std::fmt::Debug for ImportedRcloneGdrive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRcloneGdrive")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scope", &self.scope)
            .field("root_folder_id", &self.root_folder_id)
            .field("shared_drive_id", &self.shared_drive_id)
            .field("service_account_file", &self.service_account_file)
            .field(
                "service_account_credentials",
                &self
                    .service_account_credentials
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("impersonate", &self.impersonate)
            .field("use_trash", &self.use_trash)
            .field("shared_with_me", &self.shared_with_me)
            .field("trashed_only", &self.trashed_only)
            .field("stop_on_upload_limit", &self.stop_on_upload_limit)
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcloneImportReport {
    pub gdrive_remotes: Vec<ImportedRcloneGdrive>,
    pub skipped_remotes: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    if raw == "~" || raw.starts_with("~/") || raw.starts_with("~\\") {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        if let Some(h) = home {
            if raw == "~" {
                return h;
            }
            return h.join(&raw[2..]);
        }
    }
    PathBuf::from(raw)
}

/// Parse an INI-formatted `rclone.conf` string and extract all `type = drive` remotes.
pub fn parse_rclone_conf(content: &str) -> Result<RcloneImportReport> {
    let sections = parse_rclone_ini(content)?;
    let mut report = RcloneImportReport::default();

    for sec in sections {
        let kind = sec.kind().to_string();
        if !kind.eq_ignore_ascii_case("drive") {
            report.skipped_remotes.push((sec.name, kind));
            continue;
        }

        let name = sec.name.clone();
        let client_id = sec.get_non_empty("client_id");
        let client_secret = sec.get_non_empty("client_secret");
        let service_account_file = sec
            .get_non_empty("service_account_file")
            .map(|p| expand_tilde_path(&p));
        let service_account_credentials = sec.get_non_empty("service_account_credentials");
        let impersonate = sec.get_non_empty("impersonate");
        let root_folder_id = sec.get_non_empty("root_folder_id");
        let shared_drive_id = sec.get_non_empty("team_drive");
        let scope = resolve_gdrive_scope(sec.fields.get("scope").map(String::as_str).unwrap_or(""));
        let use_trash = Some(sec.get_bool("use_trash").unwrap_or(true));
        let shared_with_me = sec.get_bool("shared_with_me").unwrap_or(false);
        let trashed_only = sec.get_bool("trashed_only").unwrap_or(false);
        let stop_on_upload_limit = sec.get_bool("stop_on_upload_limit");

        let token = match sec.get_non_empty("token") {
            Some(raw_tok) => {
                let mut parsed = parse_rclone_oauth_token(&raw_tok).map_err(|e| {
                    Error::protocol(format!(
                        "remote `{name}` has invalid rclone token JSON: {e}"
                    ))
                })?;
                if parsed.scope.is_none() {
                    parsed.scope = Some(scope.clone());
                }
                Some(parsed)
            }
            None => None,
        };

        if service_account_file.is_none()
            && service_account_credentials.is_none()
            && client_id.is_none()
        {
            report.warnings.push(format!(
                "remote `{name}` has no `client_id` (shared rclone OAuth client IDs are deprecated); configure your own Google Cloud OAuth Desktop client_id/client_secret and re-run `rship auth gdrive {name}`"
            ));
        }

        report.gdrive_remotes.push(ImportedRcloneGdrive {
            name,
            client_id,
            client_secret,
            scope,
            root_folder_id,
            shared_drive_id,
            service_account_file,
            service_account_credentials,
            impersonate,
            use_trash,
            shared_with_me,
            trashed_only,
            stop_on_upload_limit,
            token,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::ErrorKind;

    #[test]
    fn imports_oauth_and_service_account_drive_remotes_and_skips_others() {
        let conf = r#"
# Sample rclone.conf
[my-gdrive]
type = drive
client_id = 12345.apps.googleusercontent.com
client_secret = GOCSPX-secret
scope = drive
root_folder_id = 1FolderRootXYZ
team_drive = 0ASharedDriveId
use_trash = false
token = {"access_token":"ya29.abc=","token_type":"Bearer","refresh_token":"1//ref==","expiry":"2026-12-01T10:00:00.000000+00:00"}

[corp-sa]
type = drive
scope = drive.readonly
service_account_file = /etc/rship/sa.json
impersonate = ops@corp.example
team_drive = 0ACorpDrive

[my-r2]
type = s3
provider = Cloudflare
"#;
        let report = parse_rclone_conf(conf).unwrap();
        assert_eq!(report.gdrive_remotes.len(), 2);
        assert_eq!(report.skipped_remotes.len(), 1);
        assert_eq!(report.skipped_remotes[0], ("my-r2".into(), "s3".into()));
        assert!(report.warnings.is_empty());

        let g1 = &report.gdrive_remotes[0];
        assert_eq!(g1.name, "my-gdrive");
        assert_eq!(
            g1.client_id.as_deref(),
            Some("12345.apps.googleusercontent.com")
        );
        assert_eq!(g1.client_secret.as_deref(), Some("GOCSPX-secret"));
        assert_eq!(g1.root_folder_id.as_deref(), Some("1FolderRootXYZ"));
        assert_eq!(g1.shared_drive_id.as_deref(), Some("0ASharedDriveId"));
        assert_eq!(g1.use_trash, Some(false));
        assert!(!g1.shared_with_me);
        assert!(!g1.trashed_only);
        assert_eq!(g1.stop_on_upload_limit, None);
        let tok = g1.token.as_ref().unwrap();
        assert_eq!(tok.access_token, "ya29.abc=");
        assert_eq!(tok.refresh_token.as_deref(), Some("1//ref=="));
        assert!(tok.expires_at_unix_secs > 1_700_000_000);

        let g2 = &report.gdrive_remotes[1];
        assert_eq!(g2.name, "corp-sa");
        assert_eq!(g2.scope, "https://www.googleapis.com/auth/drive.readonly");
        assert_eq!(g2.use_trash, Some(true));
        assert_eq!(g2.impersonate.as_deref(), Some("ops@corp.example"));
        assert_eq!(
            g2.service_account_file.as_deref(),
            Some(std::path::Path::new("/etc/rship/sa.json"))
        );
    }

    #[test]
    fn imports_flags_multi_scopes_warns_missing_client_id_and_rejects_encrypted_conf() {
        let encrypted = "RCLONE_ENCRYPT_V0:\nbase64ciphertext==\n";
        let err = parse_rclone_conf(encrypted).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Config);

        let conf = r#"
[gd-filtered]
type = drive
scope = drive.readonly,drive.metadata.readonly
shared_with_me = true
trashed_only = true
stop_on_upload_limit = true
token = {"access_token":"ya29.xyz","token_type":"Bearer","refresh_token":"1//ref","expiry":"2026-12-01T10:00:00Z"}
"#;
        let report = parse_rclone_conf(conf).unwrap();
        assert_eq!(report.gdrive_remotes.len(), 1);
        assert_eq!(
            report.warnings.len(),
            1,
            "missing client_id without SA must warn"
        );
        let g = &report.gdrive_remotes[0];
        assert_eq!(
            g.scope,
            "https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/drive.metadata.readonly"
        );
        assert_eq!(g.use_trash, Some(true));
        assert!(g.shared_with_me);
        assert!(g.trashed_only);
        assert_eq!(g.stop_on_upload_limit, Some(true));
    }
}
