//! Importer for existing `rclone.conf` Azure Blob Storage (`type = azureblob`) remotes.

use rship_core::Result;
use rship_core::rclone_ini::parse_rclone_ini;

use crate::azureblob::config::{
    AZURITE_ACCOUNT, AZURITE_ENDPOINT, AZURITE_KEY, percent_decode_rfc3986,
};

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedRcloneAzureBlob {
    pub name: String,
    pub account: Option<String>,
    pub key: Option<String>,
    pub sas_url: Option<String>,
    pub endpoint: Option<String>,
    pub access_tier: Option<String>,
    pub use_emulator: bool,
    pub container: Option<String>,
    pub anonymous: bool,
    pub no_check_container: bool,
    pub use_msi: bool,
    pub service_principal_file: Option<String>,
    pub tenant: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub env_auth: bool,
}

impl std::fmt::Debug for ImportedRcloneAzureBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedRcloneAzureBlob")
            .field("name", &self.name)
            .field("account", &self.account)
            .field("key", &self.key.as_ref().map(|_| "[REDACTED]"))
            .field("sas_url", &self.sas_url.as_ref().map(|_| "[REDACTED]"))
            .field("endpoint", &self.endpoint)
            .field("access_tier", &self.access_tier)
            .field("use_emulator", &self.use_emulator)
            .field("container", &self.container)
            .field("anonymous", &self.anonymous)
            .field("no_check_container", &self.no_check_container)
            .field("use_msi", &self.use_msi)
            .field("service_principal_file", &self.service_principal_file)
            .field("tenant", &self.tenant)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("env_auth", &self.env_auth)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct RcloneAzureBlobImportReport {
    pub remotes: Vec<ImportedRcloneAzureBlob>,
    pub skipped_remotes: Vec<(String, String)>,
    pub warnings: Vec<String>,
}

/// Account, service endpoint, and optional container extracted from an Azure Blob SAS URL.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SasUrlMetadata {
    pub account: Option<String>,
    pub endpoint: Option<String>,
    pub container: Option<String>,
}

/// Extract inferred `account`, `endpoint`, and `container` metadata from a full Azure Blob
/// SAS URL — supporting both virtual-host URLs (`https://acct.blob.core.windows.net/cont?sv=...`)
/// and path-style Azurite URLs (`http://127.0.0.1:10000/devstoreaccount1/cont?sv=...`).
pub fn extract_sas_url_metadata(raw_sas: &str) -> SasUrlMetadata {
    let Ok(parsed) = url::Url::parse(raw_sas.trim()) else {
        return SasUrlMetadata::default();
    };
    let Some(host) = parsed.host_str() else {
        return SasUrlMetadata::default();
    };
    let mut origin = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        origin.push_str(&format!(":{port}"));
    }
    let segs: Vec<&str> = parsed
        .path_segments()
        .map(|s| s.filter(|seg| !seg.is_empty()).collect())
        .unwrap_or_default();

    let host_unbracketed = host.trim_matches(['[', ']']);
    let is_path_style = host.eq_ignore_ascii_case("localhost")
        || host_unbracketed.parse::<std::net::IpAddr>().is_ok()
        || !host.contains('.');

    if is_path_style {
        let account = segs.first().map(|s| percent_decode_rfc3986(s));
        let endpoint = Some(match segs.first() {
            Some(acct_seg) => format!("{origin}/{acct_seg}"),
            None => origin,
        });
        let container = segs.get(1).map(|s| percent_decode_rfc3986(s));
        SasUrlMetadata {
            account,
            endpoint,
            container,
        }
    } else {
        let account = host.split_once('.').map(|(acct, _)| acct.to_string());
        let container = segs.first().map(|s| percent_decode_rfc3986(s));
        SasUrlMetadata {
            account,
            endpoint: Some(origin),
            container,
        }
    }
}

/// Extract inferred `(account, endpoint)` metadata from a full Azure Blob SAS URL
/// (e.g. `https://acct.blob.core.windows.net?sv=...` or `http://127.0.0.1:10000/devstoreaccount1/cont?sv=...`).
pub fn extract_sas_account_and_endpoint(raw_sas: &str) -> (Option<String>, Option<String>) {
    let meta = extract_sas_url_metadata(raw_sas);
    (meta.account, meta.endpoint)
}

fn expand_tilde_path(raw: &str) -> String {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned());
    let Some(home) = home else {
        return raw.to_string();
    };
    let home_trimmed = home.trim_end_matches(['/', '\\']);
    if raw == "~" {
        return home_trimmed.to_string();
    }
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        return format!("{home_trimmed}/{rest}");
    }
    raw.to_string()
}

/// Parse an INI-formatted `rclone.conf` string and extract all `type = azureblob` remotes.
pub fn parse_rclone_azureblob_conf(content: &str) -> Result<RcloneAzureBlobImportReport> {
    let sections = parse_rclone_ini(content)?;
    let mut report = RcloneAzureBlobImportReport::default();

    for sec in sections {
        let kind = sec.kind().to_ascii_lowercase();
        if kind != "azureblob" {
            let orig_kind = sec.kind().to_string();
            report.skipped_remotes.push((sec.name, orig_kind));
            continue;
        }

        let name = sec.name.clone();
        let use_emulator = sec.get_bool("use_emulator").unwrap_or(false);
        let mut account = sec.get_non_empty("account");
        let mut key = sec.get_non_empty("key");
        let sas_url = sec.get_non_empty("sas_url");
        let mut endpoint = sec.get_non_empty("endpoint");
        let access_tier = sec.get_non_empty("access_tier");
        let mut container = sec.get_non_empty("container");

        let no_check_container = sec.get_bool("no_check_container").unwrap_or(false);
        let use_msi = sec.get_bool("use_msi").unwrap_or(false);
        let service_principal_file = sec
            .get_non_empty("service_principal_file")
            .map(|p| expand_tilde_path(&p));
        let tenant = sec.get_non_empty("tenant");
        let client_id = sec.get_non_empty("client_id");
        let client_secret = sec.get_non_empty("client_secret");
        let env_auth = sec.get_bool("env_auth").unwrap_or(false);

        // If `sas_url` contains a base endpoint URL (virtual-host or path-style Azurite, with
        // optional container path), infer `account`, `endpoint`, and `container` when omitted.
        if let Some(ref raw_sas) = sas_url {
            let meta = extract_sas_url_metadata(raw_sas);
            if endpoint.is_none() {
                endpoint = meta.endpoint;
            }
            if account.is_none() {
                account = meta.account;
            }
            if container.is_none() {
                container = meta.container;
            }
        }

        if use_emulator {
            if account.is_none() {
                account = Some(AZURITE_ACCOUNT.to_string());
            }
            if key.is_none() && sas_url.is_none() {
                key = Some(AZURITE_KEY.to_string());
            }
            if endpoint.is_none() {
                endpoint = Some(AZURITE_ENDPOINT.to_string());
            }
        }

        let has_entra_or_msi = use_msi
            || service_principal_file.is_some()
            || tenant.is_some()
            || client_id.is_some()
            || client_secret.is_some()
            || env_auth
            || sec.get_non_empty("msi_object_id").is_some()
            || sec.get_non_empty("msi_client_id").is_some()
            || sec.get_non_empty("msi_mi_res_id").is_some()
            || sec.get_non_empty("client_certificate_path").is_some()
            || sec.get_non_empty("username").is_some()
            || sec.get_non_empty("password").is_some();

        let anonymous = sec.get_bool("anonymous").unwrap_or(false)
            || (account.is_some()
                && key.is_none()
                && sas_url.is_none()
                && !use_emulator
                && !has_entra_or_msi);

        if has_entra_or_msi && key.is_none() && sas_url.is_none() {
            report.warnings.push(format!(
                "Azure Blob remote `{name}` uses Entra ID / MSI / Service Principal / env_auth options which are not yet supported at runtime; configure SharedKey (`key`) or SAS (`sas_url`) instead"
            ));
        }

        let ignored_ops: Vec<&str> = [
            "archive_tier_delete",
            "chunk_size",
            "upload_concurrency",
            "memory_pool_flush_time",
            "memory_pool_use_mmap",
            "no_check_container",
        ]
        .into_iter()
        .filter(|k| sec.get_non_empty(k).is_some())
        .collect();
        if !ignored_ops.is_empty() {
            report.warnings.push(format!(
                "Azure Blob remote `{name}` specifies rclone operational options ({}) not mapped by rship",
                ignored_ops.join(", ")
            ));
        }

        if account.is_none() && sas_url.is_none() {
            report.warnings.push(format!(
                "Azure Blob remote `{name}` is missing `account` and `sas_url`"
            ));
        }

        report.remotes.push(ImportedRcloneAzureBlob {
            name,
            account,
            key,
            sas_url,
            endpoint,
            access_tier,
            use_emulator,
            container,
            anonymous,
            no_check_container,
            use_msi,
            service_principal_file,
            tenant,
            client_id,
            client_secret,
            env_auth,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_shared_key_sas_url_and_azurite_remotes() {
        let conf = r#"
[az-prod]
type = azureblob
account = myprodacct
key = dGVzdGtleQ==
access_tier = Cool

[az-sas]
type = azureblob
sas_url = https://pubacct.blob.core.windows.net?sv=2023-11-03&ss=b&sig=abc

[az-local]
type = azureblob
use_emulator = true

[s3-other]
type = s3
"#;
        let rep = parse_rclone_azureblob_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 3);
        assert_eq!(rep.skipped_remotes, vec![("s3-other".into(), "s3".into())]);
        assert!(rep.warnings.is_empty());

        assert_eq!(rep.remotes[0].account.as_deref(), Some("myprodacct"));
        assert_eq!(rep.remotes[0].access_tier.as_deref(), Some("Cool"));
        assert_eq!(rep.remotes[1].account.as_deref(), Some("pubacct"));
        assert_eq!(
            rep.remotes[1].endpoint.as_deref(),
            Some("https://pubacct.blob.core.windows.net")
        );
        assert_eq!(rep.remotes[2].account.as_deref(), Some(AZURITE_ACCOUNT));
        assert_eq!(rep.remotes[2].endpoint.as_deref(), Some(AZURITE_ENDPOINT));
        assert!(rep.remotes[2].use_emulator);
        assert!(!rep.remotes[0].anonymous);
        assert!(!rep.remotes[1].anonymous);
    }

    #[test]
    fn extracts_azurite_ipv4_ipv6_and_virtual_host_container_sas_urls() {
        let az4 = extract_sas_url_metadata(
            "http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sr=c&sig=abc",
        );
        assert_eq!(az4.account.as_deref(), Some("devstoreaccount1"));
        assert_eq!(
            az4.endpoint.as_deref(),
            Some("http://127.0.0.1:10000/devstoreaccount1")
        );
        assert_eq!(az4.container.as_deref(), Some("mycont"));
        assert_eq!(
            extract_sas_account_and_endpoint(
                "http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03"
            ),
            (
                Some("devstoreaccount1".to_string()),
                Some("http://127.0.0.1:10000/devstoreaccount1".to_string())
            )
        );

        let az6 = extract_sas_url_metadata(
            "http://[::1]:10000/devstoreaccount1/cont6?sv=2023-11-03&sig=abc",
        );
        assert_eq!(az6.account.as_deref(), Some("devstoreaccount1"));
        assert_eq!(
            az6.endpoint.as_deref(),
            Some("http://[::1]:10000/devstoreaccount1")
        );
        assert_eq!(az6.container.as_deref(), Some("cont6"));

        let vh = extract_sas_url_metadata(
            "https://myacct.blob.core.windows.net/pubcont?sv=2023-11-03&sr=c&sig=xyz",
        );
        assert_eq!(vh.account.as_deref(), Some("myacct"));
        assert_eq!(
            vh.endpoint.as_deref(),
            Some("https://myacct.blob.core.windows.net")
        );
        assert_eq!(vh.container.as_deref(), Some("pubcont"));
    }

    #[test]
    fn infers_anonymous_warns_on_entra_msi_sp_expands_tilde_and_rejects_encrypted_conf() {
        let conf = r#"
[az-anon]
type = azureblob
account = pubdata

[az-sp]
type = azureblob
account = entract
tenant = t-123
client_id = cid-456
client_secret = super-secret-val
service_principal_file = ~/creds/az-sp.json
use_msi = true
env_auth = true
no_check_container = true
chunk_size = 16Mi
"#;
        let rep = parse_rclone_azureblob_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 2);

        assert!(rep.remotes[0].anonymous);
        assert_eq!(rep.remotes[0].account.as_deref(), Some("pubdata"));

        let sp = &rep.remotes[1];
        assert!(!sp.anonymous);
        assert!(sp.use_msi);
        assert!(sp.env_auth);
        assert!(sp.no_check_container);
        assert_eq!(sp.tenant.as_deref(), Some("t-123"));
        assert_eq!(sp.client_id.as_deref(), Some("cid-456"));
        assert_eq!(sp.client_secret.as_deref(), Some("super-secret-val"));
        let sp_file = sp.service_principal_file.as_deref().unwrap();
        assert!(sp_file.ends_with("/creds/az-sp.json"));
        if std::env::var_os("HOME").is_some() || std::env::var_os("USERPROFILE").is_some() {
            assert!(!sp_file.starts_with("~/"), "tilde should expand: {sp_file}");
        }
        assert!(!format!("{sp:?}").contains("super-secret-val"));
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("Entra ID / MSI / Service Principal"))
        );
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("no_check_container") && w.contains("chunk_size"))
        );

        let encrypted = "RCLONE_ENCRYPT_V0:\nAAAA\n";
        let err = parse_rclone_azureblob_conf(encrypted).unwrap_err();
        assert_eq!(err.kind, rship_core::ErrorKind::Config);
    }
}
