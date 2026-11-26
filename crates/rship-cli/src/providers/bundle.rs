//! Portable credential export/import envelopes (`rship-remote-v1:` / legacy `rship-auth-v1:`)
//! and `rclone.conf` batch migration.

#![cfg_attr(not(feature = "all-backends"), allow(dead_code, unused_imports))]

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rship::config::{
    AppConfig, AppPaths, default_rclone_conf_path, save_config, write_private_file,
};
use rship_core::path::is_valid_remote_name;
use rship_core::rclone_ini::parse_rclone_ini;
use rship_transport::oauth::OAuthToken;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::errors::config_err;

use super::{cleanup_remote_secrets, find_adapter, registered_providers};

const GENERIC_BUNDLE_PREFIX: &str = "rship-remote-v1:";
const GDRIVE_BUNDLE_PREFIX: &str = "rship-auth-v1:";

/// Provider-agnostic credential export/import envelope (`rship-remote-v1:` and legacy formats).
///
/// New exports serialize provider settings inside `config` (plus optional `token` or
/// `service_account_json`). Legacy `rship-remote-v1:` payloads that used provider-named keys
/// (`s3`, `crypt`, `onedrive`, `onedrive_token`, `webdav`, `sftp`) and `rship-auth-v1:` Google
/// Drive payloads are captured transparently in `extra` for 100% backward-compatible imports.
#[derive(Clone, Serialize, Deserialize)]
pub struct PortableBundle {
    pub version: u32,
    pub remote_name: String,
    pub remote_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<OAuthToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_json: Option<String>,
    #[serde(flatten, default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl std::fmt::Debug for PortableBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableBundle")
            .field("version", &self.version)
            .field("remote_name", &self.remote_name)
            .field("remote_type", &self.remote_type)
            .field("config", &self.config.as_ref().map(|_| "[REDACTED]"))
            .field("token", &self.token)
            .field(
                "service_account_json",
                &self.service_account_json.as_ref().map(|_| "[REDACTED]"),
            )
            .field("extra_keys", &self.extra.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PortableBundle {
    pub(super) fn new(
        remote_name: impl Into<String>,
        remote_type: impl Into<String>,
        config: serde_json::Value,
    ) -> Self {
        Self {
            version: 1,
            remote_name: remote_name.into(),
            remote_type: remote_type.into(),
            config: Some(config),
            token: None,
            service_account_json: None,
            extra: serde_json::Map::new(),
        }
    }

    pub(super) fn with_token(mut self, token: Option<OAuthToken>) -> Self {
        self.token = token;
        self
    }

    pub(super) fn encode(&self, as_json: bool) -> Result<String> {
        if as_json {
            Ok(serde_json::to_string_pretty(self)?)
        } else {
            let raw = serde_json::to_vec(self)?;
            Ok(format!(
                "{GENERIC_BUNDLE_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(raw)
            ))
        }
    }

    pub(super) fn export_config<T: Serialize>(
        remote_name: &str,
        remote_type: &str,
        cfg: &T,
        as_json: bool,
    ) -> Result<String> {
        Self::new(remote_name, remote_type, serde_json::to_value(cfg)?).encode(as_json)
    }

    pub(super) fn export_with_token<T: Serialize>(
        remote_name: &str,
        remote_type: &str,
        cfg: &T,
        token: Option<OAuthToken>,
        sa_json: Option<String>,
        as_json: bool,
    ) -> Result<String> {
        let mut bundle =
            Self::new(remote_name, remote_type, serde_json::to_value(cfg)?).with_token(token);
        bundle.service_account_json = sa_json;
        bundle.encode(as_json)
    }

    pub(super) fn read_optional_sa_json(
        path: Option<&Path>,
        label: &str,
    ) -> Result<Option<String>> {
        match path {
            Some(p) => {
                Ok(Some(std::fs::read_to_string(p).with_context(|| {
                    format!("read {label} `{}`", p.display())
                })?))
            }
            None => Ok(None),
        }
    }

    pub(super) fn write_optional_sa_json(&self, dest: PathBuf) -> Result<Option<PathBuf>> {
        match &self.service_account_json {
            Some(sa_json) => {
                write_private_file(&dest, sa_json.as_bytes())
                    .with_context(|| format!("write service account file `{}`", dest.display()))?;
                Ok(Some(dest))
            }
            None => Ok(None),
        }
    }

    pub(super) fn decode(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if let Some(b64) = trimmed.strip_prefix(GENERIC_BUNDLE_PREFIX) {
            let decoded = URL_SAFE_NO_PAD
                .decode(b64.trim())
                .context("invalid base64 in rship-remote-v1 bundle")?;
            serde_json::from_slice(&decoded).context("invalid JSON in rship-remote-v1 bundle")
        } else if let Some(b64) = trimmed.strip_prefix(GDRIVE_BUNDLE_PREFIX) {
            let decoded = URL_SAFE_NO_PAD
                .decode(b64.trim())
                .context("invalid base64 in rship-auth-v1 bundle")?;
            serde_json::from_slice(&decoded).context("invalid JSON in rship-auth-v1 bundle")
        } else {
            serde_json::from_str(trimmed).context("invalid JSON in auth bundle")
        }
    }

    /// Deserialize the provider config from `config` (new format) or `extra[legacy_key]` (v1 compat).
    pub(super) fn deserialize_config<T: serde::de::DeserializeOwned>(
        &self,
        legacy_key: &str,
    ) -> Result<T> {
        if let Some(cfg) = &self.config {
            return serde_json::from_value(cfg.clone())
                .with_context(|| format!("invalid `{}` config in bundle", self.remote_type));
        }
        if let Some(legacy) = self.extra.get(legacy_key) {
            return serde_json::from_value(legacy.clone())
                .with_context(|| format!("invalid legacy `{legacy_key}` config in bundle"));
        }
        Err(config_err(format!(
            "bundle missing `{}` config block",
            self.remote_type
        )))
    }

    /// Extract OAuth token from `token` (new format) or `extra[legacy_key]` (v1 compat).
    pub(super) fn take_token(&self, legacy_key: Option<&str>) -> Result<Option<OAuthToken>> {
        if let Some(t) = &self.token {
            return Ok(Some(t.clone()));
        }
        if let Some(key) = legacy_key
            && let Some(v) = self.extra.get(key)
        {
            return Ok(Some(
                serde_json::from_value(v.clone())
                    .with_context(|| format!("invalid `{key}` token in bundle"))?,
            ));
        }
        Ok(None)
    }
}

pub fn export_remote_bundle(
    remote: &str,
    as_json: bool,
    output: Option<PathBuf>,
    paths: &AppPaths,
    app_cfg: &AppConfig,
) -> Result<ExitCode> {
    let Some(rcfg) = app_cfg.remotes.get(remote) else {
        return Err(
            rship_core::Error::config(format!("remote `{remote}` is not configured")).into(),
        );
    };
    let adapter = find_adapter(rcfg.kind_str())?;
    let payload = adapter.export_bundle(remote, rcfg, paths, as_json)?;

    if let Some(out_path) = output {
        write_private_file(&out_path, format!("{payload}\n").as_bytes())
            .with_context(|| format!("write export bundle `{}`", out_path.display()))?;
        println!(
            "exported credentials for `{remote}` to {}",
            out_path.display()
        );
    } else {
        println!("{payload}");
    }

    Ok(ExitCode::SUCCESS)
}

pub fn import_remote_bundle(
    input: Option<PathBuf>,
    bundle_inline: Option<String>,
    name_override: Option<String>,
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
) -> Result<ExitCode> {
    let raw = if let Some(inline) = bundle_inline {
        inline
    } else if let Some(path) = input {
        std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read bundle `{}`", path.display()))?
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("failed to read credential bundle from stdin")?;
        buf
    };

    let bundle = PortableBundle::decode(&raw)?;
    let remote_name = name_override.unwrap_or_else(|| bundle.remote_name.clone());
    if !is_valid_remote_name(&remote_name) {
        return Err(config_err(format!("invalid remote name `{remote_name}`")));
    }

    let adapter = find_adapter(&bundle.remote_type)?;
    if let Some(prev) = app_cfg.remotes.get(&remote_name) {
        cleanup_remote_secrets(&remote_name, prev, paths);
    }
    let inserted = adapter.import_bundle(&remote_name, &bundle, paths)?;
    let label = inserted.kind_str();
    app_cfg.remotes.insert(remote_name.clone(), inserted);
    save_config(&paths.config_file, app_cfg)?;
    println!(
        "imported {label} credentials for remote `{remote_name}` into {}",
        paths.config_file.display()
    );
    Ok(ExitCode::SUCCESS)
}

pub fn import_rclone_all(
    explicit_path: Option<PathBuf>,
    overwrite: bool,
    dry_run: bool,
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
) -> Result<ExitCode> {
    let conf_path = match explicit_path {
        Some(p) => p,
        None => default_rclone_conf_path().ok_or_else(|| {
            config_err(
                "could not locate rclone.conf automatically; pass an explicit path: `rship config import-rclone <path>`",
            )
        })?,
    };

    let raw = std::fs::read_to_string(&conf_path)
        .with_context(|| format!("failed to read `{}`", conf_path.display()))?;
    let all_sections = parse_rclone_ini(&raw)?;

    let providers = registered_providers();
    let handled_rclone_types: HashSet<&'static str> =
        providers.iter().filter_map(|p| p.rclone_type()).collect();

    // Validate & preview the full rclone.conf BEFORE deleting any existing keyring secrets
    // or token files so a parse error never destroys existing credentials.
    let preview = {
        let mut dry_cfg = app_cfg.clone();
        rship::factory::import_rclone_conf(&mut dry_cfg, &raw, paths, overwrite, true)?
    };
    let summary = if dry_run {
        preview
    } else {
        if overwrite {
            for (name, _) in &preview.imported {
                if let Some(prev) = app_cfg.remotes.get(name) {
                    cleanup_remote_secrets(name, prev, paths);
                }
            }
        }
        rship::factory::import_rclone_conf(app_cfg, &raw, paths, overwrite, false)?
    };
    for name in &summary.skipped_existing {
        println!("skip `{name}` (already exists in config.toml; pass --overwrite to replace)");
    }
    for (_name, desc) in &summary.imported {
        println!(
            "{} {desc}",
            if dry_run { "would import" } else { "imported" }
        );
    }

    if !dry_run && !summary.imported.is_empty() {
        save_config(&paths.config_file, app_cfg)?;
    }

    let mut unsupported = 0usize;
    for sec in &all_sections {
        let kind = sec.kind().to_ascii_lowercase();
        if !handled_rclone_types.contains(kind.as_str()) {
            println!(
                "skipped unsupported remote `{}` (type=`{}`)",
                sec.name,
                sec.kind()
            );
            unsupported += 1;
        }
    }
    for w in &summary.warnings {
        eprintln!("warning: {w}");
    }

    println!(
        "rclone import complete: imported={} existing_skipped={} unsupported_skipped={unsupported}",
        summary.imported.len(),
        summary.skipped_existing.len()
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship::config::{OnedriveRemoteConfig, S3RemoteConfig};

    #[test]
    fn portable_bundle_supports_new_and_legacy_v1_payloads() {
        // 1. New generic `config` envelope round-trip
        let s3 = S3RemoteConfig::new("r2").with_bucket("bkt");
        let encoded = PortableBundle::new("my-r2", "s3", serde_json::to_value(&s3).unwrap())
            .encode(false)
            .unwrap();
        assert!(encoded.starts_with(GENERIC_BUNDLE_PREFIX));
        let decoded = PortableBundle::decode(&encoded).unwrap();
        let parsed: S3RemoteConfig = decoded.deserialize_config("s3").unwrap();
        assert_eq!(parsed.provider, "r2");
        assert_eq!(parsed.bucket.as_deref(), Some("bkt"));

        // 2. Legacy `rship-remote-v1:` JSON with provider-named fields (`onedrive` + `onedrive_token`)
        let legacy_json = serde_json::json!({
            "version": 1,
            "remote_name": "work-od",
            "remote_type": "onedrive",
            "onedrive": { "client_id": "cid-1", "drive_id": "drv-9" },
            "onedrive_token": {
                "access_token": "tok-abc",
                "refresh_token": "ref-xyz",
                "token_type": "Bearer",
                "expires_at_unix": 1999999999i64
            }
        })
        .to_string();
        let decoded_legacy = PortableBundle::decode(&legacy_json).unwrap();
        let od_cfg: OnedriveRemoteConfig = decoded_legacy.deserialize_config("onedrive").unwrap();
        assert_eq!(od_cfg.client_id.as_deref(), Some("cid-1"));
        assert_eq!(od_cfg.drive_id.as_deref(), Some("drv-9"));
        let tok = decoded_legacy
            .take_token(Some("onedrive_token"))
            .unwrap()
            .unwrap();
        assert_eq!(tok.access_token, "tok-abc");
        assert_eq!(tok.refresh_token.as_deref(), Some("ref-xyz"));
    }
}
