//! Importer for existing `rclone.conf` Google Cloud Storage (`type = google cloud storage`) remotes.

use rship_core::Result;
use rship_core::rclone_ini::parse_rclone_ini;
use std::path::PathBuf;

use crate::common::http::parse_rclone_oauth_token;
use crate::gcs::auth::GcsToken;
use crate::gcs::config::resolve_gcs_scope;

#[derive(Clone)]
pub struct ImportedRcloneGcs {
    pub name: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub project_number: Option<String>,
    pub user_project: Option<String>,
    pub service_account_file: Option<PathBuf>,
    pub service_account_credentials: Option<String>,
    pub storage_class: Option<String>,
    pub endpoint: Option<String>,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub scope: Option<String>,
    pub env_auth: bool,
    pub anonymous: bool,
    pub token: Option<GcsToken>,
}

impl std::fmt::Debug for ImportedRcloneGcs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRcloneGcs")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("project_number", &self.project_number)
            .field("user_project", &self.user_project)
            .field("service_account_file", &self.service_account_file)
            .field(
                "service_account_credentials",
                &self
                    .service_account_credentials
                    .as_ref()
                    .map(|_| "[REDACTED]"),
            )
            .field("storage_class", &self.storage_class)
            .field("endpoint", &self.endpoint)
            .field("auth_url", &self.auth_url)
            .field("token_url", &self.token_url)
            .field("scope", &self.scope)
            .field("env_auth", &self.env_auth)
            .field("anonymous", &self.anonymous)
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcloneGcsImportReport {
    pub remotes: Vec<ImportedRcloneGcs>,
    pub skipped_remotes: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

fn expand_tilde_path_with_home(raw: &str, home: Option<&std::ffi::OsStr>) -> PathBuf {
    let trimmed = raw.trim();
    if (trimmed == "~" || trimmed.starts_with("~/") || trimmed.starts_with("~\\"))
        && let Some(home_dir) = home.filter(|v| !v.is_empty())
    {
        let mut out = PathBuf::from(home_dir);
        if let Some(rest) = trimmed
            .strip_prefix("~/")
            .or_else(|| trimmed.strip_prefix("~\\"))
        {
            for comp in rest.split(['/', '\\']).filter(|c| !c.is_empty()) {
                out.push(comp);
            }
        }
        return out;
    }
    PathBuf::from(trimmed)
}

fn expand_tilde_path(raw: &str) -> PathBuf {
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()));
    expand_tilde_path_with_home(raw, home.as_deref())
}

/// Parse an INI-formatted `rclone.conf` string and extract all `type = google cloud storage` remotes.
pub fn parse_rclone_gcs_conf(content: &str) -> Result<RcloneGcsImportReport> {
    let sections = parse_rclone_ini(content)?;
    let mut report = RcloneGcsImportReport::default();

    for sec in sections {
        let kind = sec.kind().to_ascii_lowercase();
        if kind != "google cloud storage" && kind != "gcs" {
            let orig_kind = sec.kind().to_string();
            report.skipped_remotes.push((sec.name, orig_kind));
            continue;
        }

        let name = sec.name.clone();
        let client_id = sec.get_non_empty("client_id");
        let client_secret = sec.get_non_empty("client_secret");
        let project_number = sec.get_non_empty("project_number");
        let user_project = sec.get_non_empty("user_project");
        let service_account_file = sec
            .get_non_empty("service_account_file")
            .map(|p| expand_tilde_path(&p));
        let service_account_credentials = sec.get_non_empty("service_account_credentials");
        let storage_class = sec.get_non_empty("storage_class");
        let endpoint = sec.get_non_empty("endpoint");
        let auth_url = sec.get_non_empty("auth_url");
        let token_url = sec.get_non_empty("token_url");
        let scope = sec.get_non_empty("scope").map(|s| resolve_gcs_scope(&s));
        let env_auth = sec.get_bool("env_auth").unwrap_or(false);
        let anonymous = sec.get_bool("anonymous").unwrap_or(false);

        let token = match sec.get_non_empty("token") {
            Some(raw_tok) => match parse_rclone_oauth_token(&raw_tok) {
                Ok(tok) => Some(tok),
                Err(e) => {
                    report.warnings.push(format!(
                        "GCS remote `{name}` has malformed OAuth `token` JSON: {e}"
                    ));
                    None
                }
            },
            None => None,
        };

        if !anonymous
            && !env_auth
            && service_account_file.is_none()
            && service_account_credentials.is_none()
            && client_id.is_none()
        {
            report.warnings.push(format!(
                "GCS remote `{name}` has no `client_id`, service account, or anonymous=true (shared rclone OAuth client IDs are deprecated); configure your own Google Cloud OAuth Desktop `client_id`/`client_secret` and run `rship auth gcs {name}`"
            ));
        }

        if env_auth
            && service_account_file.is_none()
            && service_account_credentials.is_none()
            && token.is_none()
        {
            report.warnings.push(format!(
                "GCS remote `{name}` sets `env_auth = true`: automatic ADC/metadata-server credentials are not natively implemented yet; configure explicit credentials or an OAuth token if required"
            ));
        }

        for unsupported_key in [
            "object_acl",
            "bucket_acl",
            "location",
            "bucket_policy_only",
            "decompress",
        ] {
            if sec.get_non_empty(unsupported_key).is_some() {
                report.warnings.push(format!(
                    "GCS remote `{name}` specifies unsupported option `{unsupported_key}` which will not be enforced"
                ));
            }
        }

        report.remotes.push(ImportedRcloneGcs {
            name,
            client_id,
            client_secret,
            project_number,
            user_project,
            service_account_file,
            service_account_credentials,
            storage_class,
            endpoint,
            auth_url,
            token_url,
            scope,
            env_auth,
            anonymous,
            token,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_gcs_service_account_oauth_and_anonymous_remotes() {
        let conf = r#"
[gcs-sa]
type = google cloud storage
project_number = 1234567890
service_account_file = /etc/gcp/sa.json
storage_class = NEARLINE

[gcs-pub]
type = google cloud storage
anonymous = true

[gcs-oauth]
type = google cloud storage
client_id = cid-123
client_secret = csec-456
token = {"access_token":"ya29.tok","token_type":"Bearer","refresh_token":"1//ref","expiry":"2026-12-01T00:00:00Z"}

[other]
type = s3
"#;
        let rep = parse_rclone_gcs_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 3);
        assert_eq!(rep.skipped_remotes, vec![("other".into(), "s3".into())]);
        assert!(rep.warnings.is_empty());

        assert_eq!(rep.remotes[0].name, "gcs-sa");
        assert_eq!(rep.remotes[0].project_number.as_deref(), Some("1234567890"));
        assert_eq!(rep.remotes[0].storage_class.as_deref(), Some("NEARLINE"));
        assert!(rep.remotes[1].anonymous);
        assert!(rep.remotes[2].token.is_some());
        assert_eq!(
            rep.remotes[2]
                .token
                .as_ref()
                .unwrap()
                .refresh_token
                .as_deref(),
            Some("1//ref")
        );
        assert_eq!(
            rep.remotes[2].token.as_ref().unwrap().expires_at_unix_secs,
            1_796_083_200
        );
    }

    #[test]
    fn imports_endpoint_auth_token_urls_scope_user_project_env_auth_and_warnings() {
        let conf = r#"
[gcs_custom]
type = google cloud storage
endpoint = http://127.0.0.1:4443
auth_url = https://auth.example.test/o/oauth2/auth
token_url = https://token.example.test/token
scope = read_write
user_project = billing-proj
env_auth = true
object_acl = publicRead
bucket_acl = private
location = EU
bucket_policy_only = true
decompress = true

[gcs_nocid]
type = google cloud storage
token = {"access_token":"ya29.t","token_type":"Bearer","refresh_token":"r","expiry":"2099-01-01T00:00:00Z"}
"#;
        let rep = parse_rclone_gcs_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 2);

        let custom = &rep.remotes[0];
        assert_eq!(custom.endpoint.as_deref(), Some("http://127.0.0.1:4443"));
        assert_eq!(
            custom.auth_url.as_deref(),
            Some("https://auth.example.test/o/oauth2/auth")
        );
        assert_eq!(
            custom.token_url.as_deref(),
            Some("https://token.example.test/token")
        );
        assert_eq!(
            custom.scope.as_deref(),
            Some("https://www.googleapis.com/auth/devstorage.read_write")
        );
        assert_eq!(custom.user_project.as_deref(), Some("billing-proj"));
        assert!(custom.env_auth);

        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("gcs_custom") && w.contains("env_auth")),
            "expected env_auth note, got {:?}",
            rep.warnings
        );
        for key in [
            "object_acl",
            "bucket_acl",
            "location",
            "bucket_policy_only",
            "decompress",
        ] {
            assert!(
                rep.warnings
                    .iter()
                    .any(|w| w.contains("gcs_custom") && w.contains(key)),
                "expected warning for `{key}`, got {:?}",
                rep.warnings
            );
        }
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("gcs_nocid") && w.contains("client_id")),
            "expected missing client_id warning even when token is present, got {:?}",
            rep.warnings
        );
    }

    #[test]
    fn expands_tilde_paths_and_rejects_encrypted_rclone_conf() {
        let home = std::ffi::OsStr::new("/home/tester");
        assert_eq!(
            expand_tilde_path_with_home("~/creds/gcs_sa.json", Some(home)),
            PathBuf::from("/home/tester")
                .join("creds")
                .join("gcs_sa.json")
        );
        assert_eq!(
            expand_tilde_path_with_home("~\\creds\\gcs_sa.json", Some(home)),
            PathBuf::from("/home/tester")
                .join("creds")
                .join("gcs_sa.json")
        );
        assert_eq!(
            expand_tilde_path_with_home("~", Some(home)),
            PathBuf::from("/home/tester")
        );

        let encrypted = "\u{FEFF}# encrypted\nRCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
        let err = parse_rclone_gcs_conf(encrypted).expect_err("encrypted rclone.conf must fail");
        assert_eq!(err.kind, rship_core::ErrorKind::Config);
    }
}
