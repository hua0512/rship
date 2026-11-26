//! Microsoft OneDrive / SharePoint [`ProviderAdapter`] and interactive `rship auth onedrive` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::onedrive::{
    DEFAULT_ONEDRIVE_SCOPE, FileOnedriveTokenStore, OnedrivePkceFlow, OnedriveRegion,
    OnedriveTokenStore,
};
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;

use crate::cli::OnedriveAuthArgs;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, OnedriveRemoteConfig, RemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::oauth::{
    OAuthClientPrompt, OAuthPkceRunOpts, print_oauth_save_summary, resolve_oauth_client_creds,
    resolve_oauth_port, resolve_static_bearer_token, run_oauth_pkce_wizard,
};
use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    cleanup_remote_keyring_secrets, clear_secret_opt,
};

pub struct OnedriveAdapter;

pub(crate) fn resolve_onedrive_pkce_urls(existing: &OnedriveRemoteConfig) -> (&str, &str) {
    let region = existing
        .region
        .as_deref()
        .and_then(OnedriveRegion::parse)
        .unwrap_or(OnedriveRegion::Global);
    let (_, region_auth, region_token) = region.endpoints();
    let auth_url = existing.auth_url.as_deref().unwrap_or(region_auth);
    let token_url = existing.token_url.as_deref().unwrap_or(region_token);
    (auth_url, token_url)
}

pub(super) async fn handle_auth(
    args: OnedriveAuthArgs,
    ctx: &mut AuthContext<'_>,
) -> Result<AuthOutcome> {
    let explicit_static = args.access_token.is_some();
    let explicit_oauth = args.client_id.is_some() || args.client_secret.is_some();
    let any_meta_flag = args.drive_id.is_some() || args.scope.is_some();

    let mut wiz = PromptWizard::begin(
        args.remote,
        "onedrive",
        "onedrive",
        explicit_static || explicit_oauth || any_meta_flag,
        ctx,
    )?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Onedrive(o)) => (**o).clone(),
        _ => OnedriveRemoteConfig::default(),
    };

    wiz.section(
        &format!("Configure OneDrive remote `{}`", wiz.remote),
        existing.client_id.is_some() || existing.access_token.is_some(),
        "Editing existing OneDrive / SharePoint remote — press Enter to keep current values",
        "Connect personal OneDrive, OneDrive for Business, or SharePoint via Microsoft Graph",
    );

    let use_static_token = if explicit_static {
        true
    } else if explicit_oauth {
        false
    } else if wiz.full_wizard {
        let def_mode = usize::from(existing.access_token.is_some() && existing.client_id.is_none());
        let items = [
            SelectItem::new("OAuth 2.0 Desktop PKCE (browser login)")
                .with_desc("Recommended — Entra ID App Registration with automatic token refresh"),
            SelectItem::new("Static Bearer access token")
                .with_desc("Non-interactive testing or short-lived automation"),
        ];
        prompt::select("OneDrive authentication method", &items, def_mode)? == 1
    } else {
        existing.access_token.is_some() && existing.client_id.is_none()
    };

    let remote = wiz.remote.clone();
    let config_file_display = wiz.ctx.paths.config_file.display().to_string();

    if use_static_token {
        let token = resolve_static_bearer_token(
            &mut wiz,
            args.access_token,
            existing.access_token.as_deref(),
            "Microsoft Graph access token",
        )?;
        let drive_id = wiz.optional_text(
            "SharePoint / Graph Drive ID",
            args.drive_id,
            existing.drive_id.clone(),
            Some("Optional — leave empty for personal OneDrive (`/me/drive`)"),
        )?;
        let mut updated = existing;
        updated.access_token = token;
        // Clear OAuth client credentials so `factory::build_onedrive` activates `StaticBearerAuth`.
        updated.client_id = None;
        updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
        updated.drive_id = drive_id;
        let _ = std::fs::remove_file(wiz.ctx.paths.onedrive_token_file_for(&remote));

        return wiz.finish(
            RemoteConfig::Onedrive(Box::new(updated)),
            &format!("configured OneDrive static-token remote `{remote}` in {config_file_display}"),
        );
    }

    // OAuth 2.0 Desktop PKCE
    if wiz.ctx.interactive && existing.client_id.is_none() && args.client_id.is_none() {
        prompt::tip(
            "In Microsoft Entra ID → App Registrations → Authentication → Mobile & desktop applications, add `http://127.0.0.1` (loopback redirect).",
        );
    }

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
            provider_label: "OneDrive",
            client_id_prompt: "Microsoft Entra ID Application (client) ID",
            client_id_hint: None,
            missing_client_id_err: "missing `--client-id` for OneDrive OAuth2 PKCE (run interactively in a terminal or pass `--client-id`)",
            client_secret_prompt: "Azure OAuth2 Client Secret",
            client_secret_hint: Some(
                "Optional — press Enter to omit for public Desktop PKCE app registrations",
            ),
            secret_required: false,
        },
    )?;
    let resolved_cid = oauth_creds.client_id;
    let stored_csec = oauth_creds.stored_secret;
    let resolved_csec = oauth_creds.runtime_secret;
    let csec_changed = oauth_creds.secret_changed;
    wiz.did_prompt |= oauth_creds.did_prompt;

    let drive_id = wiz.optional_text(
        "SharePoint / Graph Drive ID",
        args.drive_id,
        existing.drive_id.clone(),
        Some("Optional — leave empty for personal OneDrive (`/me/drive`)"),
    )?;

    let eff_scope = args
        .scope
        .or_else(|| existing.scope.clone())
        .unwrap_or_else(|| DEFAULT_ONEDRIVE_SCOPE.to_string());

    let token_path = wiz.ctx.paths.onedrive_token_file_for(&remote);
    let tok_store = FileOnedriveTokenStore::new(token_path.clone());
    let oauth_creds_changed = prev_cid.as_deref() != Some(resolved_cid.as_str())
        || csec_changed
        || prev_scope.as_deref() != Some(eff_scope.as_str())
        || existing.access_token.is_some();

    let (auth_url_ref, token_url_ref) = resolve_onedrive_pkce_urls(&existing);
    let auth_url = auth_url_ref.to_string();
    let token_url = token_url_ref.to_string();
    let (preferred_port, strict_port) = resolve_oauth_port(args.callback_port);

    let cid_for_flow = resolved_cid.clone();
    let scope_for_flow = eff_scope.clone();
    let need_browser_login = run_oauth_pkce_wizard(
        OAuthPkceRunOpts {
            display_name: "OneDrive",
            confirm_label: "OneDrive",
            creds_changed: oauth_creds_changed,
            explicit_oauth,
            no_browser: args.no_browser,
            manual: args.manual,
        },
        &mut wiz,
        &tok_store,
        || async move {
            let flow = OnedrivePkceFlow::start_with_port(
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
    updated.client_id = Some(resolved_cid);
    updated.client_secret = stored_csec;
    updated.access_token = clear_secret_opt(updated.access_token.as_deref());
    updated.drive_id = drive_id;
    updated.scope = Some(eff_scope);

    super::persist_remote(
        &remote,
        RemoteConfig::Onedrive(Box::new(updated)),
        wiz.did_prompt,
        wiz.ctx,
    )?;
    print_oauth_save_summary(
        "OneDrive",
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

#[async_trait]
impl ProviderAdapter for OnedriveAdapter {
    fn kind(&self) -> &'static str {
        "onedrive"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("onedrive")
    }

    fn cleanup_secrets(&self, remote_name: &str, cfg: &RemoteConfig, paths: &AppPaths) {
        cleanup_remote_keyring_secrets(cfg);
        let _ = std::fs::remove_file(paths.onedrive_token_file_for(remote_name));
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Onedrive(_)).then(RelPath::root)
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
        let RemoteConfig::Onedrive(ocfg) = cfg else {
            bail!("internal mismatch: expected Onedrive remote config");
        };
        let mut resolved = (**ocfg).clone();
        resolved.client_secret = resolve_opt_secret(resolved.client_secret.as_deref())?;
        resolved.access_token = resolve_opt_secret(resolved.access_token.as_deref())?;
        let token = FileOnedriveTokenStore::new(paths.onedrive_token_file_for(remote)).load()?;
        PortableBundle::export_with_token(remote, "onedrive", &resolved, token, None, as_json)
    }

    fn import_bundle(
        &self,
        remote_name: &str,
        bundle: &PortableBundle,
        paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let ocfg: OnedriveRemoteConfig = bundle.deserialize_config("onedrive")?;
        if let Some(tok) = bundle.take_token(Some("onedrive_token"))? {
            FileOnedriveTokenStore::new(paths.onedrive_token_file_for(remote_name)).save(&tok)?;
        }
        Ok(RemoteConfig::Onedrive(Box::new(ocfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn resolve_onedrive_pkce_urls_derives_sovereign_endpoints_and_honors_overrides() {
        let cn = OnedriveRemoteConfig::new().with_region("cn");
        let (auth_cn, tok_cn) = resolve_onedrive_pkce_urls(&cn);
        assert_eq!(
            auth_cn,
            "https://login.chinacloudapi.cn/common/oauth2/v2.0/authorize"
        );
        assert_eq!(
            tok_cn,
            "https://login.chinacloudapi.cn/common/oauth2/v2.0/token"
        );

        let us = OnedriveRemoteConfig::new().with_region("us");
        let (auth_us, tok_us) = resolve_onedrive_pkce_urls(&us);
        assert_eq!(
            auth_us,
            "https://login.microsoftonline.us/common/oauth2/v2.0/authorize"
        );
        assert_eq!(
            tok_us,
            "https://login.microsoftonline.us/common/oauth2/v2.0/token"
        );

        let custom = OnedriveRemoteConfig::new()
            .with_region("cn")
            .with_auth_url("https://mock.local/auth")
            .with_token_url("https://mock.local/token");
        assert_eq!(
            resolve_onedrive_pkce_urls(&custom),
            ("https://mock.local/auth", "https://mock.local/token")
        );
    }

    #[tokio::test]
    async fn handle_auth_preserves_region_drive_type_and_chunk_size_on_edit() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "od".to_string(),
            OnedriveRemoteConfig::new()
                .with_access_token("tok-1")
                .with_region("de")
                .with_drive_type("business")
                .with_chunk_size(5 * 1024 * 1024)
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            OnedriveAuthArgs {
                remote: Some("od".to_string()),
                drive_id: Some("drv-1".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .await
        .unwrap();

        let RemoteConfig::Onedrive(saved) = cfg.remotes.get("od").unwrap() else {
            panic!("expected Onedrive");
        };
        assert_eq!(saved.drive_id.as_deref(), Some("drv-1"));
        assert_eq!(saved.region.as_deref(), Some("de"));
        assert_eq!(saved.drive_type.as_deref(), Some("business"));
        assert_eq!(saved.chunk_size, Some(5 * 1024 * 1024));
    }
}
