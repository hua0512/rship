//! Parse Microsoft OneDrive (`type = onedrive`) remotes from an existing `rclone.conf`.

use rship_core::Result;
use rship_core::rclone_ini::parse_rclone_ini;

use crate::common::http::parse_rclone_oauth_token;
use crate::onedrive::auth::OnedriveToken;
use crate::onedrive::config::{
    MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveDriveType, OnedriveRegion,
};

#[derive(Clone)]
pub struct ImportedOnedriveRemote {
    pub name: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub drive_id: Option<String>,
    pub region: Option<String>,
    pub drive_type: Option<String>,
    pub chunk_size: Option<u64>,
    pub scope: Option<String>,
    pub token: Option<OnedriveToken>,
}

impl std::fmt::Debug for ImportedOnedriveRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportedOnedriveRemote")
            .field("name", &self.name)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("drive_id", &self.drive_id)
            .field("region", &self.region)
            .field("drive_type", &self.drive_type)
            .field("chunk_size", &self.chunk_size)
            .field("scope", &self.scope)
            .field("token", &self.token)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct RcloneOnedriveImportReport {
    pub remotes: Vec<ImportedOnedriveRemote>,
    pub warnings: Vec<String>,
}

fn parse_rclone_size_suffix(raw: &str) -> std::result::Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty size".to_string());
    }
    let split = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    let (num_str, suffix) = trimmed.split_at(split);
    if num_str.is_empty() {
        return Err(format!("missing numeric prefix in `{trimmed}`"));
    }
    let num: u64 = num_str
        .parse()
        .map_err(|e| format!("invalid number `{num_str}`: {e}"))?;
    let mult: u64 = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "ki" | "kib" => 1024,
        "m" | "mb" | "mi" | "mib" => 1024 * 1024,
        "g" | "gb" | "gi" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "ti" | "tib" => 1024 * 1024 * 1024 * 1024,
        other => return Err(format!("unknown size suffix `{other}`")),
    };
    num.checked_mul(mult)
        .ok_or_else(|| format!("size `{trimmed}` overflows u64"))
}

/// Parse OneDrive sections from plaintext `rclone.conf`, propagating `RCLONE_ENCRYPT_V0:` and
/// INI syntax errors.
pub fn try_parse_rclone_onedrive_conf(text: &str) -> Result<RcloneOnedriveImportReport> {
    let sections = parse_rclone_ini(text)?;
    let mut report = RcloneOnedriveImportReport::default();

    for sec in sections {
        if !sec.kind().eq_ignore_ascii_case("onedrive") {
            continue;
        }
        let name = sec.name.clone();
        let client_id = sec.get_non_empty("client_id");
        if client_id.is_none() {
            report.warnings.push(format!(
                "onedrive remote `{name}` has no `client_id` (shared rclone OAuth client IDs are not bundled); configure your own Microsoft Entra ID `client_id` and re-run `rship auth onedrive {name}`"
            ));
        }
        let token =
            sec.get_non_empty("token")
                .and_then(|raw| match parse_rclone_oauth_token(&raw) {
                    Ok(t) => Some(t),
                    Err(e) => {
                        report
                            .warnings
                            .push(format!("onedrive remote `{name}` invalid token JSON: {e}"));
                        None
                    }
                });
        let region = sec.get_non_empty("region").and_then(|raw| {
            if let Some(parsed) = OnedriveRegion::parse(&raw) {
                Some(parsed.as_str().to_string())
            } else {
                report.warnings.push(format!(
                    "onedrive remote `{name}` has unrecognized region `{raw}`"
                ));
                None
            }
        });
        let drive_type = sec.get_non_empty("drive_type").and_then(|raw| {
            if let Some(parsed) = OnedriveDriveType::parse(&raw) {
                Some(parsed.as_str().to_string())
            } else {
                report.warnings.push(format!(
                    "onedrive remote `{name}` has unrecognized drive_type `{raw}`"
                ));
                None
            }
        });
        let chunk_size = sec.get_non_empty("chunk_size").and_then(|raw| {
            match parse_rclone_size_suffix(&raw) {
                Ok(bytes)
                    if (ONEDRIVE_CHUNK_ALIGN_BYTES..=MAX_ONEDRIVE_CHUNK_BYTES).contains(&bytes)
                        && bytes.is_multiple_of(ONEDRIVE_CHUNK_ALIGN_BYTES) =>
                {
                    Some(bytes)
                }
                Ok(bytes) => {
                    report.warnings.push(format!(
                        "onedrive remote `{name}` chunk_size `{raw}` ({bytes} bytes) must be a multiple of 320 KiB between 320 KiB and 60 MiB"
                    ));
                    None
                }
                Err(e) => {
                    report.warnings.push(format!(
                        "onedrive remote `{name}` invalid chunk_size `{raw}`: {e}"
                    ));
                    None
                }
            }
        });
        report.remotes.push(ImportedOnedriveRemote {
            name,
            client_id,
            client_secret: sec.get_non_empty("client_secret"),
            drive_id: sec.get_non_empty("drive_id"),
            region,
            drive_type,
            chunk_size,
            scope: sec.get_non_empty("scope"),
            token,
        });
    }
    Ok(report)
}

/// Backwards-compatible wrapper around [`try_parse_rclone_onedrive_conf`] that converts INI/encryption
/// errors into report warnings.
pub fn parse_rclone_onedrive_conf(text: &str) -> RcloneOnedriveImportReport {
    match try_parse_rclone_onedrive_conf(text) {
        Ok(report) => report,
        Err(e) => RcloneOnedriveImportReport {
            remotes: Vec::new(),
            warnings: vec![format!("parse rclone.conf: {e}")],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::ErrorKind;

    #[test]
    fn try_parse_rejects_encrypted_conf_and_compat_wrapper_warns() {
        let encrypted = "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
        let err = try_parse_rclone_onedrive_conf(encrypted).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Config);

        let compat = parse_rclone_onedrive_conf(encrypted);
        assert!(compat.remotes.is_empty());
        assert!(!compat.warnings.is_empty());
    }

    #[test]
    fn imports_region_drive_type_chunk_size_and_warns_missing_client_id_with_token() {
        let conf = r#"
[od_biz]
type = onedrive
region = cn
drive_type = business
chunk_size = 5Mi
drive_id = drv-123
token = {"access_token":"tok","refresh_token":"ref","expiry":"2030-01-01T00:00:00Z"}

[od_bad_chunk]
type = onedrive
client_id = cid-2
chunk_size = 100Ki
region = mars
drive_type = custom
"#;
        let rep = try_parse_rclone_onedrive_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 2);

        let biz = &rep.remotes[0];
        assert_eq!(biz.name, "od_biz");
        assert_eq!(biz.region.as_deref(), Some("cn"));
        assert_eq!(biz.drive_type.as_deref(), Some("business"));
        assert_eq!(biz.chunk_size, Some(5 * 1024 * 1024));
        assert_eq!(biz.drive_id.as_deref(), Some("drv-123"));
        assert!(biz.token.is_some());
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("od_biz") && w.contains("client_id")),
            "expected missing client_id warning even with token, warnings={:?}",
            rep.warnings
        );

        let bad = &rep.remotes[1];
        assert_eq!(bad.chunk_size, None);
        assert_eq!(bad.region, None);
        assert_eq!(bad.drive_type, None);
        assert!(rep.warnings.iter().any(|w| w.contains("chunk_size")));
        assert!(rep.warnings.iter().any(|w| w.contains("region")));
        assert!(rep.warnings.iter().any(|w| w.contains("drive_type")));
    }
}
