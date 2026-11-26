//! Google Cloud Storage (GCS) [`ProviderAdapter`] and interactive `rship auth gcs` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::gcs::{
    DEFAULT_GCS_AUTH_URL, DEFAULT_GCS_SCOPE, DEFAULT_GCS_TOKEN_URL, FileGcsTokenStore, GcsPkceFlow,
    GcsTokenStore, resolve_gcs_endpoint_urls, resolve_gcs_scope,
};
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;

use crate::cli::GcsAuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, GcsRemoteConfig, RemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::oauth::{
    OAuthClientPrompt, OAuthPkceRunOpts, print_oauth_save_summary, resolve_oauth_client_creds,
    resolve_oauth_port, resolve_service_account_key, resolve_static_bearer_token,
    run_oauth_pkce_wizard, validate_service_account_key,
};
use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    cleanup_remote_keyring_secrets, clear_secret_opt,
};

pub struct GcsAdapter;

fn select_gcs_scope(existing_scope: Option<&str>) -> Result<String> {
    let def_idx = match existing_scope {
        Some(s) if s.ends_with("/devstorage.read_write") => 1,
        Some(s) if s.ends_with("/devstorage.read_only") => 2,
        Some(s) if s.ends_with("/cloud-platform") => 3,
        _ => 0,
    };
    let items = [
        SelectItem::new("full (devstorage.full_control)")
            .with_desc("Full object + ACL control over GCS buckets"),
        SelectItem::new("read_write (devstorage.read_write)")
            .with_desc("Read & write objects without changing bucket IAM/ACLs"),
        SelectItem::new("read_only (devstorage.read_only)")
            .with_desc("Read-only access to objects"),
        SelectItem::new("cloud-platform").with_desc("Broad Google Cloud Platform OAuth scope"),
    ];
    let idx = prompt::select("GCS OAuth scope", &items, def_idx)?;
    Ok(resolve_gcs_scope(match idx {
        1 => "read_write",
        2 => "read_only",
        3 => "cloud-platform",
        _ => "full",
    }))
}

pub(super) async fn handle_auth(
    args: GcsAuthArgs,
    ctx: &mut AuthContext<'_>,
) -> Result<AuthOutcome> {
    let explicit_auth = args.anonymous
        || args.access_token.is_some()
        || args.service_account_file.is_some()
        || args.client_id.is_some()
        || args.client_secret.is_some();
    let any_meta_flag = args.bucket.is_some()
        || args.prefix.is_some()
        || args.project_number.is_some()
        || args.storage_class.is_some()
        || args.endpoint.is_some()
        || args.impersonate.is_some()
        || args.scope.is_some();

    let mut wiz = PromptWizard::begin(
        args.remote,
        "gcs",
        "gcs",
        explicit_auth || any_meta_flag,
        ctx,
    )?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Gcs(g)) => (**g).clone(),
        _ => GcsRemoteConfig::default(),
    };
    let resolved_scope = args.scope.as_deref().map(resolve_gcs_scope);

    wiz.section(
        &format!("Configure GCS remote `{}`", wiz.remote),
        existing.service_account_file.is_some()
            || existing.client_id.is_some()
            || existing.anonymous == Some(true)
            || existing.access_token.is_some(),
        "Editing existing Google Cloud Storage remote — press Enter to keep current values",
        "Configure GCS with Service Account JSON, OAuth2 PKCE, or anonymous public access",
    );

    #[derive(Clone, Copy)]
    enum GcsMode {
        ServiceAccount,
        OAuthPkce,
        Anonymous,
        StaticToken,
    }

    let mode = if args.anonymous {
        GcsMode::Anonymous
    } else if args.access_token.is_some() {
        GcsMode::StaticToken
    } else if args.service_account_file.is_some() {
        GcsMode::ServiceAccount
    } else if args.client_id.is_some() || args.client_secret.is_some() {
        GcsMode::OAuthPkce
    } else if wiz.full_wizard {
        let def_mode = if existing.anonymous == Some(true) {
            2
        } else if existing.access_token.is_some() && existing.client_id.is_none() {
            3
        } else if existing.client_id.is_some() && existing.service_account_file.is_none() {
            1
        } else {
            0
        };
        let items = [
            SelectItem::new("Service Account JSON key")
                .with_desc("Recommended for servers, automation, and CI"),
            SelectItem::new("OAuth 2.0 Desktop PKCE (browser login)")
                .with_desc("Interactive login with Google Cloud OAuth Desktop client"),
            SelectItem::new("Anonymous (public buckets)")
                .with_desc("Unauthenticated read access to public GCS buckets"),
            SelectItem::new("Static Bearer access token")
                .with_desc("Short-lived token for testing (e.g. `gcloud auth print-access-token`)"),
        ];
        match prompt::select("GCS authentication method", &items, def_mode)? {
            0 => GcsMode::ServiceAccount,
            1 => GcsMode::OAuthPkce,
            2 => GcsMode::Anonymous,
            _ => GcsMode::StaticToken,
        }
    } else if existing.anonymous == Some(true) {
        GcsMode::Anonymous
    } else if existing.service_account_file.is_some() {
        GcsMode::ServiceAccount
    } else if existing.access_token.is_some() && existing.client_id.is_none() {
        GcsMode::StaticToken
    } else if existing.client_id.is_some() {
        GcsMode::OAuthPkce
    } else {
        return Err(config_err(
            "provide `--service-account-file <key.json>`, `--anonymous`, `--access-token`, or `--client-id` for GCS (or run interactively in a terminal)",
        ));
    };

    // Common bucket & optional advanced settings
    let bucket = wiz.optional_text(
        "Default GCS bucket name",
        args.bucket,
        existing.bucket.clone(),
        Some("Optional — leave empty to pass bucket per command (`remote:bucket/path`)"),
    )?;
    let mut prefix = args.prefix.or_else(|| existing.prefix.clone());
    let mut project_number = args
        .project_number
        .or_else(|| existing.project_number.clone());
    let mut user_project = existing.user_project.clone();
    let mut storage_class = args
        .storage_class
        .or_else(|| existing.storage_class.clone());
    let mut endpoint = existing.endpoint.clone();
    let mut api_base_url = existing.api_base_url.clone();
    let mut upload_base_url = existing.upload_base_url.clone();

    if let Some(raw_ep) = args.endpoint.as_deref() {
        let trimmed = raw_ep.trim();
        if trimmed.is_empty() || trimmed == "-" {
            endpoint = None;
            api_base_url = None;
            upload_base_url = None;
        } else {
            let (api, up) = resolve_gcs_endpoint_urls(trimmed);
            endpoint = Some(trimmed.to_string());
            api_base_url = Some(api);
            upload_base_url = Some(up);
        }
    }

    if wiz.full_wizard
        && prompt::confirm(
            "Configure advanced GCS options (prefix, project number, user project, storage class, custom endpoint)?",
            false,
        )?
    {
        prefix = prompt::text(
            "Default object prefix inside bucket",
            prefix.as_deref(),
            None,
            false,
        )?;
        project_number = prompt::text(
            "Google Cloud project number",
            project_number.as_deref(),
            Some("Optional — used when listing buckets under a project"),
            false,
        )?;
        user_project = prompt::text(
            "Requester Pays billing project (userProject)",
            user_project.as_deref(),
            Some("Optional — GCP project ID billed for Requester Pays buckets"),
            false,
        )?;
        let sc_items = [
            SelectItem::new("Bucket default"),
            SelectItem::new("STANDARD"),
            SelectItem::new("NEARLINE"),
            SelectItem::new("COLDLINE"),
            SelectItem::new("ARCHIVE"),
        ];
        let def_sc = match storage_class.as_deref() {
            Some(s) if s.eq_ignore_ascii_case("STANDARD") => 1,
            Some(s) if s.eq_ignore_ascii_case("NEARLINE") => 2,
            Some(s) if s.eq_ignore_ascii_case("COLDLINE") => 3,
            Some(s) if s.eq_ignore_ascii_case("ARCHIVE") => 4,
            _ => 0,
        };
        storage_class = match prompt::select("Default storage class", &sc_items, def_sc)? {
            1 => Some("STANDARD".to_string()),
            2 => Some("NEARLINE".to_string()),
            3 => Some("COLDLINE".to_string()),
            4 => Some("ARCHIVE".to_string()),
            _ => None,
        };
        let existing_ep = endpoint
            .as_deref()
            .or_else(|| api_base_url.as_deref().map(|u| u.trim_end_matches("/storage/v1")));
        let ep = prompt::text(
            "Custom GCS endpoint URL",
            existing_ep,
            Some("Optional — e.g. http://127.0.0.1:4443 for fake-gcs-server"),
            false,
        )?;
        if let Some(ep) = ep {
            let (api, up) = resolve_gcs_endpoint_urls(&ep);
            endpoint = Some(ep);
            api_base_url = Some(api);
            upload_base_url = Some(up);
        } else {
            endpoint = None;
            api_base_url = None;
            upload_base_url = None;
        }
    }

    let apply_common = |updated: &mut GcsRemoteConfig| {
        updated.bucket = bucket.clone();
        updated.prefix = prefix.clone();
        updated.project_number = project_number.clone();
        updated.user_project = user_project.clone();
        updated.storage_class = storage_class.clone();
        updated.endpoint = endpoint.clone();
        updated.api_base_url = api_base_url.clone();
        updated.upload_base_url = upload_base_url.clone();
    };

    let remote = wiz.remote.clone();
    let config_file_display = wiz.ctx.paths.config_file.display().to_string();

    match mode {
        GcsMode::Anonymous => {
            let mut updated = existing;
            apply_common(&mut updated);
            updated.anonymous = Some(true);
            updated.service_account_file = None;
            updated.impersonate = None;
            updated.client_id = None;
            updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
            updated.access_token = clear_secret_opt(updated.access_token.as_deref());
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_token_file_for(&remote));
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_service_account_file_for(&remote));

            wiz.finish(
                RemoteConfig::Gcs(Box::new(updated)),
                &format!("configured anonymous Google Cloud Storage remote `{remote}` in {config_file_display}"),
            )
        }

        GcsMode::StaticToken => {
            let token = resolve_static_bearer_token(
                &mut wiz,
                args.access_token,
                existing.access_token.as_deref(),
                "GCS Bearer access token",
            )?;
            let mut updated = existing;
            apply_common(&mut updated);
            updated.access_token = token;
            updated.anonymous = None;
            updated.service_account_file = None;
            updated.impersonate = None;
            // Clear OAuth client credentials so `factory::build_gcs` activates `StaticBearerAuth`.
            updated.client_id = None;
            updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_token_file_for(&remote));
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_service_account_file_for(&remote));

            wiz.finish(
                RemoteConfig::Gcs(Box::new(updated)),
                &format!("configured GCS static-token remote `{remote}` in {config_file_display}"),
            )
        }

        GcsMode::ServiceAccount => {
            let transport = wiz.ctx.transport()?.clone();
            let (sa_path, sa_key) = resolve_service_account_key(
                &mut wiz,
                args.service_account_file,
                existing.service_account_file.as_ref(),
                &format!("missing `--service-account-file <key.json>` for GCS remote `{remote}`"),
            )?;

            let eff_scope = if let Some(s) = resolved_scope {
                s
            } else if wiz.full_wizard {
                select_gcs_scope(existing.scope.as_deref())?
            } else {
                existing
                    .scope
                    .clone()
                    .unwrap_or_else(|| DEFAULT_GCS_SCOPE.to_string())
            };

            let impersonate = args.impersonate.or(existing.impersonate.clone());
            validate_service_account_key(
                sa_key.clone(),
                eff_scope.clone(),
                impersonate.clone(),
                existing.token_url.clone(),
                transport,
            )?;

            let mut updated = existing;
            apply_common(&mut updated);
            updated.service_account_file = Some(sa_path);
            updated.impersonate = impersonate;
            updated.scope = Some(eff_scope);
            updated.anonymous = None;
            updated.client_id = None;
            updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
            updated.access_token = clear_secret_opt(updated.access_token.as_deref());
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_token_file_for(&remote));

            wiz.finish(
                RemoteConfig::Gcs(Box::new(updated)),
                &format!(
                    "configured GCS Service Account remote `{remote}` ({}) in {config_file_display}",
                    sa_key.client_email
                ),
            )
        }

        GcsMode::OAuthPkce => {
            let prev_cid = existing.client_id.clone();
            let prev_scope = existing.scope.clone();
            let oauth_creds = resolve_oauth_client_creds(
                args.client_id,
                args.client_secret,
                existing.client_id.as_deref(),
                existing.client_secret.as_deref(),
                wiz.full_wizard,
                wiz.ctx.interactive,
                &OAuthClientPrompt {
                    provider_label: "GCS",
                    client_id_prompt: "Google Cloud OAuth Desktop client_id",
                    client_id_hint: None,
                    missing_client_id_err: "missing `--client-id` for GCS OAuth2 PKCE",
                    client_secret_prompt: "Google Cloud OAuth Desktop client_secret",
                    client_secret_hint: Some("Recommended for Google Desktop OAuth clients"),
                    secret_required: false,
                },
            )?;
            let resolved_cid = oauth_creds.client_id;
            let stored_csec = oauth_creds.stored_secret;
            let resolved_csec = oauth_creds.runtime_secret;
            let csec_changed = oauth_creds.secret_changed;
            wiz.did_prompt |= oauth_creds.did_prompt;

            let eff_scope = if let Some(s) = resolved_scope {
                s
            } else if wiz.full_wizard {
                select_gcs_scope(existing.scope.as_deref())?
            } else {
                existing
                    .scope
                    .clone()
                    .unwrap_or_else(|| DEFAULT_GCS_SCOPE.to_string())
            };

            let token_path = wiz.ctx.paths.gcs_token_file_for(&remote);
            let tok_store = FileGcsTokenStore::new(token_path.clone());
            let oauth_creds_changed = prev_cid.as_deref() != Some(resolved_cid.as_str())
                || csec_changed
                || prev_scope.as_deref() != Some(eff_scope.as_str())
                || existing.service_account_file.is_some()
                || existing.access_token.is_some()
                || existing.anonymous == Some(true);

            let auth_url = existing
                .auth_url
                .as_deref()
                .unwrap_or(DEFAULT_GCS_AUTH_URL)
                .to_string();
            let token_url = existing
                .token_url
                .as_deref()
                .unwrap_or(DEFAULT_GCS_TOKEN_URL)
                .to_string();
            let (preferred_port, strict_port) = resolve_oauth_port(args.callback_port);

            let cid_for_flow = resolved_cid.clone();
            let scope_for_flow = eff_scope.clone();
            let need_browser_login = run_oauth_pkce_wizard(
                OAuthPkceRunOpts {
                    display_name: "Google Cloud Storage",
                    confirm_label: "GCS",
                    creds_changed: oauth_creds_changed,
                    explicit_oauth: explicit_auth,
                    no_browser: args.no_browser,
                    manual: args.manual,
                },
                &mut wiz,
                &tok_store,
                || async move {
                    let flow = GcsPkceFlow::start_with_port(
                        cid_for_flow,
                        resolved_csec,
                        &auth_url,
                        &token_url,
                        scope_for_flow,
                        preferred_port,
                        strict_port,
                    )
                    .await?;
                    Ok(flow.into_session())
                },
            )
            .await?;

            let mut updated = existing;
            apply_common(&mut updated);
            updated.client_id = Some(resolved_cid);
            updated.client_secret = stored_csec;
            updated.service_account_file = None;
            updated.impersonate = None;
            updated.access_token = clear_secret_opt(updated.access_token.as_deref());
            updated.scope = Some(eff_scope);
            updated.anonymous = None;
            let _ = std::fs::remove_file(wiz.ctx.paths.gcs_service_account_file_for(&remote));

            super::persist_remote(
                &remote,
                RemoteConfig::Gcs(Box::new(updated)),
                wiz.did_prompt,
                wiz.ctx,
            )?;
            print_oauth_save_summary(
                "GCS",
                &remote,
                need_browser_login,
                &token_path,
                &wiz.ctx.paths.config_file,
            );
            Ok(AuthOutcome {
                remote,
                did_prompt: wiz.did_prompt,
            })
        }
    }
}

fn extract_gcs_bucket_from_endpoint(dst_endpoint: &str, rcfg: &GcsRemoteConfig) -> Option<String> {
    let api_base = rcfg
        .api_base_url
        .as_deref()
        .unwrap_or(rship_backends::gcs::DEFAULT_GCS_API_URL)
        .trim_end_matches('/');
    let prefix = format!("gcs://{api_base}/");
    let rest = dst_endpoint.strip_prefix(&prefix)?;
    let bucket = rest.split_once('/').map(|(b, _)| b).unwrap_or(rest);
    (!bucket.is_empty()).then(|| bucket.to_string())
}

#[async_trait]
impl ProviderAdapter for GcsAdapter {
    fn kind(&self) -> &'static str {
        "gcs"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("google cloud storage")
    }

    fn cleanup_secrets(&self, remote_name: &str, cfg: &RemoteConfig, paths: &AppPaths) {
        cleanup_remote_keyring_secrets(cfg);
        let _ = std::fs::remove_file(paths.gcs_token_file_for(remote_name));
        let _ = std::fs::remove_file(paths.gcs_service_account_file_for(remote_name));
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            let RemoteConfig::Gcs(gcfg) = rcfg else {
                return None;
            };
            if gcfg.bucket.as_deref().is_some_and(|b| !b.trim().is_empty()) {
                Some(RelPath::root())
            } else {
                extract_gcs_bucket_from_endpoint(&op.dst_endpoint, gcfg)
                    .and_then(|b| RelPath::parse(&b).ok())
            }
        })
        .await;
    }

    fn export_bundle(
        &self,
        remote: &str,
        cfg: &RemoteConfig,
        paths: &AppPaths,
        as_json: bool,
    ) -> Result<String> {
        let RemoteConfig::Gcs(gcfg) = cfg else {
            bail!("internal mismatch: expected GCS remote config");
        };
        let mut resolved = (**gcfg).clone();
        resolved.client_secret = resolve_opt_secret(resolved.client_secret.as_deref())?;
        resolved.access_token = resolve_opt_secret(resolved.access_token.as_deref())?;
        let token = FileGcsTokenStore::new(paths.gcs_token_file_for(remote)).load()?;
        let sa_json = PortableBundle::read_optional_sa_json(
            gcfg.service_account_file.as_deref(),
            "GCS service account",
        )?;
        PortableBundle::export_with_token(remote, "gcs", &resolved, token, sa_json, as_json)
    }

    fn import_bundle(
        &self,
        remote_name: &str,
        bundle: &PortableBundle,
        paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let mut gcfg: GcsRemoteConfig = bundle.deserialize_config("gcs")?;
        if let Some(tok) = bundle.take_token(Some("gcs_token"))? {
            FileGcsTokenStore::new(paths.gcs_token_file_for(remote_name)).save(&tok)?;
        }
        if let Some(sa_path) =
            bundle.write_optional_sa_json(paths.gcs_service_account_file_for(remote_name))?
        {
            gcfg.service_account_file = Some(sa_path);
        }
        Ok(RemoteConfig::Gcs(Box::new(gcfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn handle_auth_wires_and_clears_endpoint_and_preserves_user_project_and_env_auth() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "gcs1".to_string(),
            GcsRemoteConfig::new()
                .with_access_token("tok-1")
                .with_user_project("billing-proj")
                .with_env_auth(true)
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            GcsAuthArgs {
                remote: Some("gcs1".to_string()),
                endpoint: Some("http://127.0.0.1:4443".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .await
        .unwrap();

        let RemoteConfig::Gcs(saved) = ctx.app_cfg.remotes.get("gcs1").unwrap() else {
            panic!("expected Gcs");
        };
        assert_eq!(saved.endpoint.as_deref(), Some("http://127.0.0.1:4443"));
        assert_eq!(
            saved.api_base_url.as_deref(),
            Some("http://127.0.0.1:4443/storage/v1")
        );
        assert_eq!(
            saved.upload_base_url.as_deref(),
            Some("http://127.0.0.1:4443/upload/storage/v1")
        );
        assert_eq!(saved.user_project.as_deref(), Some("billing-proj"));
        assert_eq!(saved.env_auth, Some(true));

        // Passing `-` clears endpoint + derived URLs cleanly.
        handle_auth(
            GcsAuthArgs {
                remote: Some("gcs1".to_string()),
                endpoint: Some("-".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .await
        .unwrap();
        let RemoteConfig::Gcs(cleared) = cfg.remotes.get("gcs1").unwrap() else {
            panic!("expected Gcs");
        };
        assert!(cleared.endpoint.is_none());
        assert!(cleared.api_base_url.is_none());
        assert!(cleared.upload_base_url.is_none());
    }
}
