//! Importer for existing `rclone.conf` S3 (`type = s3`) remotes.

use rship_core::Result;
use rship_core::rclone_ini::parse_rclone_ini;

use crate::s3::config::S3ServerSideEncryption;
use crate::s3::provider::S3Provider;

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedRcloneS3 {
    pub name: String,
    pub provider: S3Provider,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub env_auth: bool,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub force_path_style: Option<bool>,
    pub storage_class: Option<String>,
    pub server_side_encryption: Option<String>,
    pub kms_key_id: Option<String>,
    pub profile: Option<String>,
    pub disable_checksum: Option<bool>,
}

impl std::fmt::Debug for ImportedRcloneS3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRcloneS3")
            .field("name", &self.name)
            .field("provider", &self.provider)
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("env_auth", &self.env_auth)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("force_path_style", &self.force_path_style)
            .field("storage_class", &self.storage_class)
            .field("server_side_encryption", &self.server_side_encryption)
            .field("kms_key_id", &self.kms_key_id)
            .field("profile", &self.profile)
            .field("disable_checksum", &self.disable_checksum)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcloneS3ImportReport {
    pub s3_remotes: Vec<ImportedRcloneS3>,
    pub skipped_remotes: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// Parse an INI-formatted `rclone.conf` string and extract all `type = s3` remotes.
pub fn parse_rclone_s3_conf(content: &str) -> Result<RcloneS3ImportReport> {
    let sections = parse_rclone_ini(content)?;
    let mut report = RcloneS3ImportReport::default();

    for sec in sections {
        let kind = sec.kind().to_string();
        if !kind.eq_ignore_ascii_case("s3") {
            report.skipped_remotes.push((sec.name, kind));
            continue;
        }

        let name = sec.name.clone();
        let provider = match sec.get_non_empty("provider") {
            Some(raw_p) => match S3Provider::parse(&raw_p) {
                Some(p) => p,
                None => {
                    report.warnings.push(format!(
                        "S3 remote `{name}` has unknown provider `{raw_p}`; falling back to `generic`"
                    ));
                    S3Provider::Generic
                }
            },
            None => S3Provider::Generic,
        };

        let access_key_id = sec.get_non_empty("access_key_id");
        let secret_access_key = sec.get_non_empty("secret_access_key");
        let session_token = sec.get_non_empty("session_token");
        let env_auth = sec.get_bool("env_auth").unwrap_or(false);
        let region = sec.get_non_empty("region");
        let endpoint = sec.get_non_empty("endpoint").map(normalize_endpoint_scheme);
        let force_path_style = sec.get_bool("force_path_style");
        let storage_class = sec.get_non_empty("storage_class");
        let profile = sec.get_non_empty("profile");
        let disable_checksum = sec.get_bool("disable_checksum");
        if disable_checksum.is_none()
            && let Some(raw_dc) = sec.get_non_empty("disable_checksum")
        {
            report.warnings.push(format!(
                "S3 remote `{name}` has non-boolean `disable_checksum = {raw_dc}`"
            ));
        }

        let kms_key_id = sec
            .get_non_empty("sse_kms_key_id")
            .or_else(|| sec.get_non_empty("kms_key_id"));
        let server_side_encryption = match sec.get_non_empty("server_side_encryption") {
            Some(raw_sse) => match S3ServerSideEncryption::parse(&raw_sse, kms_key_id.clone()) {
                Some(S3ServerSideEncryption::Aes256) => {
                    if kms_key_id.is_some() {
                        report.warnings.push(format!(
                            "S3 remote `{name}` specifies `sse_kms_key_id` with `server_side_encryption = AES256`"
                        ));
                    }
                    Some("AES256".to_string())
                }
                Some(S3ServerSideEncryption::AwsKms { .. }) => Some("aws:kms".to_string()),
                _ => {
                    report.warnings.push(format!(
                        "S3 remote `{name}` has unsupported `server_side_encryption = {raw_sse}`"
                    ));
                    None
                }
            },
            None if kms_key_id.is_some() => Some("aws:kms".to_string()),
            None => None,
        };

        if !env_auth
            && profile.is_none()
            && (access_key_id.is_none() || secret_access_key.is_none())
        {
            report.warnings.push(format!(
                "S3 remote `{name}` has neither `env_auth = true`, `profile`, nor static access_key_id/secret_access_key"
            ));
        }

        report.s3_remotes.push(ImportedRcloneS3 {
            name,
            provider,
            access_key_id,
            secret_access_key,
            session_token,
            env_auth,
            region,
            endpoint,
            force_path_style,
            storage_class,
            server_side_encryption,
            kms_key_id,
            profile,
            disable_checksum,
        });
    }

    Ok(report)
}

/// Rclone allows bare host endpoints like `s3.us-west-004.backblazeb2.com` without scheme.
fn normalize_endpoint_scheme(ep: String) -> String {
    let lower = ep.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        ep
    } else {
        format!("https://{ep}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_aws_r2_minio_oss_and_b2_s3_remotes_from_rclone_conf() {
        let conf = r#"
[my-r2]
type = s3
provider = Cloudflare
access_key_id = r2ak
secret_access_key = r2sk
region = auto
endpoint = https://acct123.r2.cloudflarestorage.com

[local-minio]
type = s3
provider = Minio
access_key_id = minioadmin
secret_access_key = minioadmin
endpoint = http://127.0.0.1:9000
force_path_style = true

[aws-prod]
type = s3
provider = AWS
env_auth = true
region = eu-west-1
storage_class = STANDARD_IA

[my-b2]
type = s3
provider = Backblaze
access_key_id = b2ak
secret_access_key = b2sk
endpoint = s3.us-west-004.backblazeb2.com

[gd]
type = drive
"#;
        let rep = parse_rclone_s3_conf(conf).unwrap();
        assert_eq!(rep.s3_remotes.len(), 4);
        assert_eq!(rep.skipped_remotes, vec![("gd".into(), "drive".into())]);
        assert!(rep.warnings.is_empty());

        assert_eq!(rep.s3_remotes[0].provider, S3Provider::R2);
        assert_eq!(rep.s3_remotes[0].region.as_deref(), Some("auto"));
        assert_eq!(rep.s3_remotes[1].provider, S3Provider::Minio);
        assert_eq!(rep.s3_remotes[1].force_path_style, Some(true));
        assert_eq!(rep.s3_remotes[2].provider, S3Provider::Aws);
        assert!(rep.s3_remotes[2].env_auth);
        assert_eq!(rep.s3_remotes[3].provider, S3Provider::B2);
        assert_eq!(
            rep.s3_remotes[3].endpoint.as_deref(),
            Some("https://s3.us-west-004.backblazeb2.com")
        );
    }

    #[test]
    fn imports_sse_kms_profile_disable_checksum_warnings_and_rejects_encrypted_conf() {
        let conf = r#"
[kms-prod]
type = s3
provider = AWS
profile = prod-sso
server_side_encryption = aws:kms
sse_kms_key_id = arn:aws:kms:us-east-1:123456789012:key/abc
disable_checksum = true
endpoint = HTTPS://s3.us-east-1.amazonaws.com

[custom-unknown]
type = s3
provider = SomeCustomVendor
access_key_id = ak
secret_access_key = sk
"#;
        let rep = parse_rclone_s3_conf(conf).unwrap();
        assert_eq!(rep.s3_remotes.len(), 2);

        let kms = &rep.s3_remotes[0];
        assert_eq!(kms.profile.as_deref(), Some("prod-sso"));
        assert_eq!(kms.server_side_encryption.as_deref(), Some("aws:kms"));
        assert_eq!(
            kms.kms_key_id.as_deref(),
            Some("arn:aws:kms:us-east-1:123456789012:key/abc")
        );
        assert_eq!(kms.disable_checksum, Some(true));
        assert_eq!(
            kms.endpoint.as_deref(),
            Some("HTTPS://s3.us-east-1.amazonaws.com")
        );
        assert!(
            !rep.warnings.iter().any(|w| w.contains("kms-prod")),
            "profile-backed remote must not emit missing-creds warning: {:?}",
            rep.warnings
        );

        let unk = &rep.s3_remotes[1];
        assert_eq!(unk.provider, S3Provider::Generic);
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("SomeCustomVendor") && w.contains("generic")),
            "unknown provider must emit fallback warning: {:?}",
            rep.warnings
        );

        let encrypted = "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
        let err = parse_rclone_s3_conf(encrypted).unwrap_err();
        assert_eq!(err.kind, rship_core::ErrorKind::Config);
    }
}
