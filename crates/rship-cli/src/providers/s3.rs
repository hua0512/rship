//! S3-compatible [`ProviderAdapter`] and interactive `rship auth s3` handler
//! (AWS S3, Cloudflare R2, MinIO, Alibaba OSS, Backblaze B2, Wasabi, DO Spaces,
//! Tencent COS, Tigris, Scaleway, Hetzner, generic).

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::s3::{PayloadSigningMode, S3Config, S3Credentials, S3Provider};
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;

use crate::cli::S3AuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, RemoteConfig, S3RemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    clear_secret_opt, merge_flag_secret,
};

pub struct S3Adapter;

const S3_PROVIDERS: &[(S3Provider, &str, &str)] = &[
    (
        S3Provider::Aws,
        "AWS S3",
        "Standard Amazon S3 (default region: us-east-1)",
    ),
    (
        S3Provider::R2,
        "Cloudflare R2",
        "Zero-egress S3 (region: auto, requires account endpoint)",
    ),
    (
        S3Provider::Minio,
        "MinIO",
        "Self-hosted S3 server (path-style, requires endpoint)",
    ),
    (
        S3Provider::Oss,
        "Alibaba Cloud OSS",
        "Aliyun Object Storage (default: cn-hangzhou)",
    ),
    (
        S3Provider::B2,
        "Backblaze B2",
        "S3-compatible Backblaze B2 (default: us-west-000)",
    ),
    (
        S3Provider::Wasabi,
        "Wasabi",
        "Hot Cloud Storage (default: us-east-1)",
    ),
    (
        S3Provider::DigitalOcean,
        "DigitalOcean Spaces",
        "Spaces object storage (default: nyc3)",
    ),
    (
        S3Provider::Cos,
        "Tencent Cloud COS",
        "Tencent COS (default: ap-guangzhou)",
    ),
    (
        S3Provider::Tigris,
        "Tigris",
        "Globally distributed S3 (region: auto)",
    ),
    (
        S3Provider::Scaleway,
        "Scaleway",
        "Scaleway Object Storage (default: fr-par)",
    ),
    (
        S3Provider::Hetzner,
        "Hetzner Object Storage",
        "Hetzner S3 (default: fsn1)",
    ),
    (
        S3Provider::Generic,
        "Generic S3-compatible",
        "Ceph, Garage, SeaweedFS, or custom S3 endpoint",
    ),
];

fn provider_requires_endpoint(p: S3Provider) -> bool {
    matches!(p, S3Provider::R2 | S3Provider::Minio | S3Provider::Generic)
}

fn provider_endpoint_hint(p: S3Provider, region: &str) -> String {
    match p {
        S3Provider::R2 => "Example: https://<ACCOUNT_ID>.r2.cloudflarestorage.com".to_string(),
        S3Provider::Minio => {
            "Example: http://127.0.0.1:9000 or https://minio.example.com".to_string()
        }
        S3Provider::Generic => "Example: https://s3.example.com".to_string(),
        other => {
            let dummy =
                S3Config::new("", other, "bucket", S3Credentials::new("", "")).with_region(region);
            format!("Leave empty for default ({})", dummy.effective_endpoint())
        }
    }
}

pub(super) fn handle_auth(args: S3AuthArgs, ctx: &mut AuthContext<'_>) -> Result<AuthOutcome> {
    let any_config_flag = args.provider.is_some()
        || args.bucket.is_some()
        || args.prefix.is_some()
        || args.region.is_some()
        || args.endpoint.is_some()
        || args.access_key_id.is_some()
        || args.secret_access_key.is_some()
        || args.session_token.is_some()
        || args.env_auth
        || args.aws_profile.is_some()
        || args.force_path_style.is_some()
        || args.strict_sigv4
        || args.payload_signing.is_some()
        || args.pin_read_etag.is_some()
        || args.send_upload_checksum.is_some()
        || args.storage_class.is_some()
        || args.sse.is_some()
        || args.kms_key_id.is_some();

    let default_name = args.provider.as_deref().unwrap_or("s3");
    let mut wiz = PromptWizard::begin(args.remote, default_name, "s3", any_config_flag, ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::S3(s)) => Some((**s).clone()),
        _ => None,
    };

    wiz.section(
        &format!("Configure S3 remote `{}`", wiz.remote),
        existing.is_some(),
        "Editing existing remote — press Enter to keep current values",
        "Choose a provider preset, credentials, and optional default bucket",
    );

    // 1. Provider preset
    let existing_prov = existing
        .as_ref()
        .and_then(|s| S3Provider::parse(&s.provider));
    let parsed_provider = wiz.select_flag_or_menu(
        "S3 provider preset",
        args.provider.as_deref(),
        S3Provider::parse,
        |raw| {
            anyhow::anyhow!(
                "unknown S3 provider `{raw}` (supported: aws, r2, minio, oss, b2, wasabi, digitalocean, cos, tigris, scaleway, hetzner, generic)"
            )
        },
        S3_PROVIDERS,
        existing_prov.unwrap_or(S3Provider::Aws),
        existing_prov.unwrap_or(S3Provider::Aws),
    )?;
    let prof = parsed_provider.profile();

    // 2. Authentication mode & credentials
    let mut env_auth = if args.env_auth {
        Some(true)
    } else if args.access_key_id.is_some() || args.secret_access_key.is_some() {
        None
    } else {
        existing.as_ref().and_then(|s| s.env_auth)
    };
    let mut access_key_id = if args.env_auth && args.access_key_id.is_none() {
        None
    } else {
        args.access_key_id
            .clone()
            .or_else(|| existing.as_ref().and_then(|s| s.access_key_id.clone()))
    };
    let mut secret_access_key = if args.env_auth && args.secret_access_key.is_none() {
        clear_secret_opt(
            existing
                .as_ref()
                .and_then(|s| s.secret_access_key.as_deref()),
        )
    } else {
        merge_flag_secret(
            args.secret_access_key.clone(),
            existing
                .as_ref()
                .and_then(|s| s.secret_access_key.as_deref()),
        )?
    };
    let mut session_token = if args.env_auth && args.session_token.is_none() {
        clear_secret_opt(existing.as_ref().and_then(|s| s.session_token.as_deref()))
    } else {
        merge_flag_secret(
            args.session_token.clone(),
            existing.as_ref().and_then(|s| s.session_token.as_deref()),
        )?
    };

    let mut profile = args
        .aws_profile
        .clone()
        .or_else(|| existing.as_ref().and_then(|s| s.profile.clone()));
    let has_creds = env_auth == Some(true)
        || profile.as_deref().is_some_and(|s| !s.trim().is_empty())
        || (access_key_id.as_deref().is_some_and(|s| !s.is_empty())
            && secret_access_key.as_deref().is_some_and(|s| !s.is_empty()));

    if wiz.full_wizard || (wiz.ctx.interactive && !has_creds) {
        wiz.did_prompt = true;
        let use_env = if args.env_auth {
            true
        } else if args.access_key_id.is_some() || args.secret_access_key.is_some() {
            false
        } else {
            let def_auth = usize::from(env_auth == Some(true));
            let auth_items = [
                SelectItem::new("Static Access Key ID & Secret Access Key")
                    .with_desc("Stored in config.toml or migrated into OS Keyring"),
                SelectItem::new("Environment variables (env_auth)")
                    .with_desc("Read AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY at runtime"),
            ];
            prompt::select("Authentication method", &auth_items, def_auth)? == 1
        };

        if use_env {
            env_auth = Some(true);
            access_key_id = None;
            secret_access_key = clear_secret_opt(secret_access_key.as_deref());
            session_token = clear_secret_opt(session_token.as_deref());
        } else {
            env_auth = None;
            if args.access_key_id.is_none() && (wiz.full_wizard || access_key_id.is_none()) {
                access_key_id =
                    prompt::text("Access Key ID", access_key_id.as_deref(), None, true)?;
            }
            if args.secret_access_key.is_none()
                && (wiz.full_wizard || secret_access_key.is_none())
            {
                secret_access_key = wiz.prompt_secret(
                    "Secret Access Key",
                    secret_access_key.as_deref(),
                    true,
                    None,
                )?;
            }
        }
    } else if !has_creds {
        return Err(config_err(format!(
            "S3 remote `{}` requires `--access-key-id` + `--secret-access-key` or `--env-auth` (run interactively in a terminal or pass flags)",
            wiz.remote
        )));
    }

    // 3. Region
    let mut region = args
        .region
        .clone()
        .or_else(|| existing.as_ref().and_then(|s| s.region.clone()));
    if wiz.full_wizard && args.region.is_none() {
        let def_region = region.as_deref().unwrap_or(prof.default_region);
        region = prompt::text(
            "Region",
            Some(def_region),
            Some(&format!("Provider default: {}", prof.default_region)),
            true,
        )?;
        wiz.did_prompt = true;
    }
    let effective_region = region.as_deref().unwrap_or(prof.default_region);

    // 4. Endpoint
    let mut endpoint = args
        .endpoint
        .clone()
        .or_else(|| existing.as_ref().and_then(|s| s.endpoint.clone()));
    let need_endpoint = provider_requires_endpoint(parsed_provider);
    if (wiz.full_wizard && args.endpoint.is_none())
        || (wiz.ctx.interactive && need_endpoint && endpoint.is_none())
    {
        let hint = provider_endpoint_hint(parsed_provider, effective_region);
        endpoint = prompt::text_validated(
            "Custom endpoint URL",
            endpoint.as_deref(),
            Some(&hint),
            need_endpoint,
            |v| {
                if v.starts_with("http://") || v.starts_with("https://") {
                    Ok(())
                } else {
                    Err("endpoint URL must start with `https://` or `http://`".to_string())
                }
            },
        )?;
        wiz.did_prompt = true;
    } else if need_endpoint && endpoint.as_deref().is_none_or(|s| s.trim().is_empty()) {
        return Err(config_err(format!(
            "S3 provider `{}` requires `--endpoint <URL>` (e.g. {})",
            parsed_provider.as_str(),
            provider_endpoint_hint(parsed_provider, effective_region)
        )));
    }

    // 5. Default bucket
    let bucket = wiz.optional_text(
        "Default bucket name",
        args.bucket,
        existing.as_ref().and_then(|s| s.bucket.clone()),
        Some("Optional — leave empty to pass bucket per command (`remote:bucket/path`)"),
    )?;

    // 6. Optional advanced settings
    let mut prefix = args
        .prefix
        .or_else(|| existing.as_ref().and_then(|s| s.prefix.clone()));
    let mut storage_class = args
        .storage_class
        .or_else(|| existing.as_ref().and_then(|s| s.storage_class.clone()));
    let mut force_path_style = args
        .force_path_style
        .or_else(|| existing.as_ref().and_then(|s| s.force_path_style));
    let mut strict_sigv4 = if args.strict_sigv4 {
        Some(true)
    } else if args.payload_signing.is_some() {
        None
    } else {
        existing.as_ref().and_then(|s| s.strict_sigv4)
    };
    let payload_signing = if let Some(ref raw) = args.payload_signing {
        let parsed = PayloadSigningMode::parse(raw).ok_or_else(|| {
            anyhow::anyhow!("invalid --payload-signing `{raw}` (expected: auto, unsigned, sha256)")
        })?;
        Some(parsed.as_str().to_string())
    } else if args.strict_sigv4 {
        Some(PayloadSigningMode::StrictSha256.as_str().to_string())
    } else {
        existing.as_ref().and_then(|s| s.payload_signing.clone())
    };
    let mut pin_read_etag = args
        .pin_read_etag
        .or_else(|| existing.as_ref().and_then(|s| s.pin_read_etag));
    let mut send_upload_checksum = args
        .send_upload_checksum
        .or_else(|| existing.as_ref().and_then(|s| s.send_upload_checksum));

    let explicit_kms_key_id = args
        .kms_key_id
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty() && s.trim() != "-");
    let mut kms_key_id = match args.kms_key_id.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            (!trimmed.is_empty() && trimmed != "-").then(|| trimmed.to_string())
        }
        None => existing
            .as_ref()
            .and_then(|s| s.kms_key_id.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "-")
            .map(str::to_string),
    };
    let mut sse = if let Some(ref raw) = args.sse {
        let parsed = rship_backends::s3::S3ServerSideEncryption::parse(raw, kms_key_id.clone())
            .ok_or_else(|| anyhow::anyhow!("invalid --sse `{raw}` (expected: AES256, aws:kms)"))?;
        if matches!(parsed, rship_backends::s3::S3ServerSideEncryption::Aes256) {
            if explicit_kms_key_id {
                return Err(config_err(
                    "--kms-key-id cannot be combined with --sse AES256 (use --sse aws:kms)",
                ));
            }
            kms_key_id = None;
        }
        Some(parsed.as_header_value().to_string())
    } else if let Some(prev) = existing.as_ref().and_then(|s| s.sse.clone()) {
        if prev.eq_ignore_ascii_case("AES256") && kms_key_id.is_some() {
            return Err(config_err(
                "--kms-key-id conflicts with existing sse=AES256 (pass --sse aws:kms)",
            ));
        }
        Some(prev)
    } else if kms_key_id.is_some() {
        Some("aws:kms".to_string())
    } else {
        None
    };

    if wiz.full_wizard
        && prompt::confirm(
            "Configure advanced options (prefix, profile, storage class, SSE, path-style, checksums)?",
            false,
        )?
    {
        prefix = prompt::text(
            "Default key prefix inside bucket",
            prefix.as_deref(),
            Some("Optional subfolder prefix, e.g. backups/prod"),
            false,
        )?;
        profile = prompt::text(
            "AWS credentials profile (~/.aws/credentials)",
            profile.as_deref(),
            Some("Optional — e.g. prod, default"),
            false,
        )?;
        storage_class = prompt::text(
            "Storage class header (x-amz-storage-class)",
            storage_class.as_deref(),
            Some("Optional, e.g. STANDARD_IA, GLACIER_IR"),
            false,
        )?;
        if env_auth != Some(true) {
            session_token = wiz.prompt_secret(
                "STS Session Token",
                session_token.as_deref(),
                false,
                None,
            )?;
        }
        let ps_default = match force_path_style {
            None => 0,
            Some(true) => 1,
            Some(false) => 2,
        };
        let ps_items = [
            SelectItem::new(format!(
                "Provider default ({})",
                if prof.default_force_path_style {
                    "path-style"
                } else {
                    "virtual-hosted"
                }
            )),
            SelectItem::new("Force path-style (endpoint/bucket/key)"),
            SelectItem::new("Force virtual-hosted-style (bucket.endpoint/key)"),
        ];
        force_path_style = match prompt::select("Addressing style", &ps_items, ps_default)? {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        };
        let strict = prompt::confirm(
            "Force strict SHA-256 payload signing even over HTTPS?",
            strict_sigv4 == Some(true),
        )?;
        strict_sigv4 = strict.then_some(true);

        send_upload_checksum = Some(prompt::confirm(
            "Send hardware upload checksum header (CRC64NVME / CRC32C)?",
            send_upload_checksum.unwrap_or(true),
        )?);
        pin_read_etag = Some(prompt::confirm(
            "Pin S3 range reads with `If-Match: <etag>`?",
            pin_read_etag.unwrap_or(true),
        )?);

        let sse_default = match sse.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("AES256") => 1,
            Some(s) if s.eq_ignore_ascii_case("aws:kms") => 2,
            _ => 0,
        };
        let sse_items = [
            SelectItem::new("None (bucket default)"),
            SelectItem::new("AES256 (SSE-S3)"),
            SelectItem::new("aws:kms (SSE-KMS)"),
        ];
        match prompt::select("Server-Side Encryption (SSE)", &sse_items, sse_default)? {
            1 => {
                sse = Some("AES256".to_string());
                kms_key_id = None;
            }
            2 => {
                sse = Some("aws:kms".to_string());
                kms_key_id = prompt::text(
                    "AWS KMS Key ID or ARN",
                    kms_key_id.as_deref(),
                    Some("Optional — leave empty for account default KMS key"),
                    false,
                )?;
            }
            _ => {
                sse = None;
                kms_key_id = None;
            }
        }
    }

    let mut scfg = S3RemoteConfig::new(parsed_provider.as_str());
    scfg.bucket = bucket;
    scfg.prefix = prefix;
    scfg.region = region;
    scfg.endpoint = endpoint;
    scfg.access_key_id = access_key_id;
    scfg.secret_access_key = secret_access_key;
    scfg.session_token = session_token;
    scfg.env_auth = env_auth;
    scfg.profile = profile;
    scfg.force_path_style = force_path_style;
    scfg.strict_sigv4 = strict_sigv4;
    scfg.payload_signing = payload_signing;
    scfg.pin_read_etag = pin_read_etag;
    scfg.storage_class = storage_class;
    scfg.sse = sse;
    scfg.kms_key_id = kms_key_id;
    scfg.send_upload_checksum = send_upload_checksum;
    scfg.list_prefix_concurrency = existing.as_ref().and_then(|s| s.list_prefix_concurrency);

    let msg = format!(
        "configured S3 remote `{}` (provider={}) in {}",
        wiz.remote,
        parsed_provider.as_str(),
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(scfg.into(), &msg)
}

fn extract_s3_bucket_from_endpoint(dst_endpoint: &str, rcfg: &S3RemoteConfig) -> Option<String> {
    let rest = dst_endpoint.strip_prefix("s3://")?;
    let scheme_sep = rest.find("://")?;
    let after_scheme = scheme_sep + 3;
    let slash_rel = rest[after_scheme..].find('/')?;
    let slash = after_scheme + slash_rel;
    let ep_url = &rest[..slash];
    let provider = S3Provider::parse(&rcfg.provider)?;
    let mut dummy_cfg = S3Config::new("", provider, "placeholder", S3Credentials::new("", ""));
    if let Some(p) = &rcfg.prefix {
        dummy_cfg.prefix = p.clone();
    }
    if let Some(r) = &rcfg.region {
        dummy_cfg.region = r.clone();
    }
    dummy_cfg.endpoint = rcfg.endpoint.clone();
    dummy_cfg.force_path_style = rcfg.force_path_style;
    if dummy_cfg.effective_endpoint() != ep_url {
        return None;
    }
    let bucket_and_prefix = &rest[slash + 1..];
    let bucket = bucket_and_prefix
        .split_once('/')
        .map(|(b, _)| b)
        .unwrap_or(bucket_and_prefix);
    (!bucket.is_empty()).then(|| bucket.to_string())
}

#[async_trait]
impl ProviderAdapter for S3Adapter {
    fn kind(&self) -> &'static str {
        "s3"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("s3")
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            let RemoteConfig::S3(scfg) = rcfg else {
                return None;
            };
            if scfg.bucket.as_deref().is_some_and(|b| !b.trim().is_empty()) {
                Some(RelPath::root())
            } else {
                extract_s3_bucket_from_endpoint(&op.dst_endpoint, scfg)
                    .and_then(|b| RelPath::parse(&b).ok())
            }
        })
        .await;
    }

    fn export_bundle(
        &self,
        remote: &str,
        cfg: &RemoteConfig,
        _paths: &AppPaths,
        as_json: bool,
    ) -> Result<String> {
        let RemoteConfig::S3(scfg) = cfg else {
            bail!("internal mismatch: expected S3 remote config");
        };
        let mut resolved = (**scfg).clone();
        resolved.secret_access_key = resolve_opt_secret(resolved.secret_access_key.as_deref())?;
        resolved.session_token = resolve_opt_secret(resolved.session_token.as_deref())?;
        PortableBundle::export_config(remote, "s3", &resolved, as_json)
    }

    fn import_bundle(
        &self,
        _remote_name: &str,
        bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let scfg: S3RemoteConfig = bundle.deserialize_config("s3")?;
        Ok(RemoteConfig::S3(Box::new(scfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn oss_provider_label_defaults_to_cn_hangzhou() {
        let (_, _, desc) = S3_PROVIDERS
            .iter()
            .find(|(p, _, _)| *p == S3Provider::Oss)
            .unwrap();
        assert!(desc.contains("default: cn-hangzhou"), "{desc}");
        assert!(!desc.contains("oss-cn-hangzhou"), "{desc}");
    }

    #[test]
    fn handle_auth_preserves_sse_kms_profile_and_checksum_on_edit() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "s3-kms".to_string(),
            S3RemoteConfig::new("aws")
                .with_profile("prod")
                .with_sse("aws:kms")
                .with_kms_key_id("arn:aws:kms:us-east-1:111:key/k")
                .with_send_upload_checksum(false)
                .with_pin_read_etag(false)
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            S3AuthArgs {
                remote: Some("s3-kms".to_string()),
                bucket: Some("my-bucket".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::S3(saved) = cfg.remotes.get("s3-kms").unwrap() else {
            panic!("expected S3");
        };
        assert_eq!(saved.bucket.as_deref(), Some("my-bucket"));
        assert_eq!(saved.profile.as_deref(), Some("prod"));
        assert_eq!(saved.sse.as_deref(), Some("aws:kms"));
        assert_eq!(
            saved.kms_key_id.as_deref(),
            Some("arn:aws:kms:us-east-1:111:key/k")
        );
        assert_eq!(saved.send_upload_checksum, Some(false));
        assert_eq!(saved.pin_read_etag, Some(false));
    }

    #[test]
    fn handle_auth_sse_aes256_clears_inherited_kms_key_id_and_rejects_explicit_kms_key_id() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "s3-kms".to_string(),
            S3RemoteConfig::new("aws")
                .with_access_key_id("AK")
                .with_secret_access_key("SK")
                .with_sse("aws:kms")
                .with_kms_key_id("key-123")
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // Switching to --sse AES256 without --kms-key-id succeeds and clears inherited kms_key_id.
        handle_auth(
            S3AuthArgs {
                remote: Some("s3-kms".to_string()),
                sse: Some("AES256".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::S3(saved) = ctx.app_cfg.remotes.get("s3-kms").unwrap() else {
            panic!("expected S3");
        };
        assert_eq!(saved.sse.as_deref(), Some("AES256"));
        assert_eq!(saved.kms_key_id, None);

        // Explicit --sse AES256 + --kms-key-id <id> must still be rejected.
        let err = handle_auth(
            S3AuthArgs {
                remote: Some("s3-kms".to_string()),
                sse: Some("AES256".to_string()),
                kms_key_id: Some("key-456".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--kms-key-id"), "{err}");

        // Explicit --kms-key-id "-" clears kms_key_id cleanly with --sse AES256.
        ctx.app_cfg.remotes.insert(
            "s3-kms".to_string(),
            S3RemoteConfig::new("aws")
                .with_access_key_id("AK")
                .with_secret_access_key("SK")
                .with_sse("aws:kms")
                .with_kms_key_id("key-789")
                .into(),
        );
        handle_auth(
            S3AuthArgs {
                remote: Some("s3-kms".to_string()),
                sse: Some("AES256".to_string()),
                kms_key_id: Some("-".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::S3(saved) = cfg.remotes.get("s3-kms").unwrap() else {
            panic!("expected S3");
        };
        assert_eq!(saved.sse.as_deref(), Some("AES256"));
        assert_eq!(saved.kms_key_id, None);
    }
}
