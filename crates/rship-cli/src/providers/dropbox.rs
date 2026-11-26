//! Dropbox v2 [`ProviderAdapter`] and interactive `rship auth dropbox` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::dropbox::{
    DEFAULT_DROPBOX_AUTH_URL, DEFAULT_DROPBOX_TOKEN_URL, DropboxPkceFlow, DropboxTokenStore,
    FileDropboxTokenStore,
};
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;
use rship_transport::oauth::DEFAULT_OAUTH_CALLBACK_PORT;

use crate::cli::DropboxAuthArgs;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, DropboxRemoteConfig, RemoteConfig};
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

pub struct DropboxAdapter;

pub(super) async fn handle_auth(
    args: DropboxAuthArgs,
    ctx: &mut AuthContext<'_>,
) -> Result<AuthOutcome> {
    let explicit_static = args.access_token.is_some();
    let explicit_oauth = args.client_id.is_some() || args.client_secret.is_some();
    let any_meta_flag = args.root_path.is_some();

    let mut wiz = PromptWizard::begin(
        args.remote,
        "dropbox",
        "dropbox",
        explicit_static || explicit_oauth || any_meta_flag,
        ctx,
    )?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Dropbox(d)) => (**d).clone(),
        _ => DropboxRemoteConfig::default(),
    };

    wiz.section(
        &format!("Configure Dropbox remote `{}`", wiz.remote),
        existing.client_id.is_some() || existing.access_token.is_some(),
        "Editing existing Dropbox remote — press Enter to keep current values",
        "Authorize Dropbox API v2 with OAuth2 PKCE offline refresh tokens",
    );

    let use_static_token = if explicit_static {
        true
    } else if explicit_oauth {
        false
    } else if wiz.full_wizard {
        let def_mode = usize::from(existing.access_token.is_some() && existing.client_id.is_none());
        let items = [
            SelectItem::new("OAuth 2.0 Desktop PKCE (browser login)")
                .with_desc("Recommended — offline refresh token via Dropbox App Console"),
            SelectItem::new("Static access token").with_desc("Short-lived token for testing or CI"),
        ];
        prompt::select("Dropbox authentication method", &items, def_mode)? == 1
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
            "Dropbox access token",
        )?;
        let root_path = wiz.optional_text(
            "Root folder path inside Dropbox",
            args.root_path,
            existing.root_path.clone(),
            Some("Optional — e.g. `/backups` (leave empty for Dropbox root)"),
        )?;
        let mut updated = existing;
        updated.access_token = token;
        // Clear OAuth client credentials so `factory::build_dropbox` activates `StaticBearerAuth`.
        updated.client_id = None;
        updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
        updated.root_path = root_path;
        let _ = std::fs::remove_file(wiz.ctx.paths.dropbox_token_file_for(&remote));

        return wiz.finish(
            RemoteConfig::Dropbox(Box::new(updated)),
            &format!("configured Dropbox static-token remote `{remote}` in {config_file_display}"),
        );
    }

    let display_port = args.callback_port.unwrap_or(DEFAULT_OAUTH_CALLBACK_PORT);
    if wiz.ctx.interactive && existing.client_id.is_none() && args.client_id.is_none() {
        prompt::tip(&format!(
            "In Dropbox App Console → Settings → OAuth 2 → Redirect URIs, add: http://127.0.0.1:{display_port}/callback"
        ));
    }

    let prev_cid = existing.client_id.clone();
    let oauth_creds = resolve_oauth_client_creds(
        args.client_id,
        args.client_secret,
        existing.client_id.as_deref(),
        existing.client_secret.as_deref(),
        wiz.full_wizard,
        wiz.ctx.interactive,
        &OAuthClientPrompt {
            provider_label: "Dropbox",
            client_id_prompt: "Dropbox App Key (client_id)",
            client_id_hint: None,
            missing_client_id_err: "missing `--client-id` (Dropbox App Key) for Dropbox OAuth2 PKCE (run interactively in a terminal or pass `--client-id`)",
            client_secret_prompt: "Dropbox App Secret",
            client_secret_hint: Some("Optional — press Enter to omit for PKCE-only public apps"),
            secret_required: false,
        },
    )?;
    let resolved_cid = oauth_creds.client_id;
    let stored_csec = oauth_creds.stored_secret;
    let resolved_csec = oauth_creds.runtime_secret;
    let csec_changed = oauth_creds.secret_changed;
    wiz.did_prompt |= oauth_creds.did_prompt;

    let root_path = wiz.optional_text(
        "Root folder path inside Dropbox",
        args.root_path,
        existing.root_path.clone(),
        Some("Optional — e.g. `/backups` (leave empty for Dropbox root)"),
    )?;

    let token_path = wiz.ctx.paths.dropbox_token_file_for(&remote);
    let tok_store = FileDropboxTokenStore::new(token_path.clone());
    let oauth_creds_changed = prev_cid.as_deref() != Some(resolved_cid.as_str())
        || csec_changed
        || existing.access_token.is_some();

    let auth_url = existing
        .auth_url
        .as_deref()
        .unwrap_or(DEFAULT_DROPBOX_AUTH_URL)
        .to_string();
    let token_url = existing
        .token_url
        .as_deref()
        .unwrap_or(DEFAULT_DROPBOX_TOKEN_URL)
        .to_string();
    let explicit_callback_port = args.callback_port;
    let (preferred_port, strict_port) = resolve_oauth_port(explicit_callback_port);

    let cid_for_flow = resolved_cid.clone();
    let need_browser_login = run_oauth_pkce_wizard(
        OAuthPkceRunOpts {
            display_name: "Dropbox",
            confirm_label: "Dropbox",
            creds_changed: oauth_creds_changed,
            explicit_oauth,
            no_browser: args.no_browser,
            manual: args.manual,
        },
        &mut wiz,
        &tok_store,
        || async move {
            let flow = DropboxPkceFlow::start_with_port(
                cid_for_flow,
                resolved_csec,
                &auth_url,
                &token_url,
                preferred_port,
                strict_port,
            )
            .await?;
            let session = flow.into_session();
            if explicit_callback_port.is_none() && session.port() != DEFAULT_OAUTH_CALLBACK_PORT {
                prompt::warn(&format!(
                    "Default port {DEFAULT_OAUTH_CALLBACK_PORT} is busy; bound `{}` instead. Dropbox requires exact Redirect URI registration — add this URI in Dropbox App Console or free port {DEFAULT_OAUTH_CALLBACK_PORT} / pass `--callback-port`.",
                    session.redirect_uri
                ));
            }
            Ok(session)
        },
    )
    .await?;

    let mut updated = existing;
    updated.client_id = Some(resolved_cid);
    updated.client_secret = stored_csec;
    updated.access_token = clear_secret_opt(updated.access_token.as_deref());
    updated.root_path = root_path;

    super::persist_remote(
        &remote,
        RemoteConfig::Dropbox(Box::new(updated)),
        wiz.did_prompt,
        wiz.ctx,
    )?;
    print_oauth_save_summary(
        "Dropbox",
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
impl ProviderAdapter for DropboxAdapter {
    fn kind(&self) -> &'static str {
        "dropbox"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("dropbox")
    }

    fn cleanup_secrets(&self, remote_name: &str, cfg: &RemoteConfig, paths: &AppPaths) {
        cleanup_remote_keyring_secrets(cfg);
        let _ = std::fs::remove_file(paths.dropbox_token_file_for(remote_name));
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Dropbox(_)).then(RelPath::root)
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
        let RemoteConfig::Dropbox(dcfg) = cfg else {
            bail!("internal mismatch: expected Dropbox remote config");
        };
        let mut resolved = (**dcfg).clone();
        resolved.client_secret = resolve_opt_secret(resolved.client_secret.as_deref())?;
        resolved.access_token = resolve_opt_secret(resolved.access_token.as_deref())?;
        let token = FileDropboxTokenStore::new(paths.dropbox_token_file_for(remote)).load()?;
        PortableBundle::export_with_token(remote, "dropbox", &resolved, token, None, as_json)
    }

    fn import_bundle(
        &self,
        remote_name: &str,
        bundle: &PortableBundle,
        paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let dcfg: DropboxRemoteConfig = bundle.deserialize_config("dropbox")?;
        if let Some(tok) = bundle.take_token(Some("dropbox_token"))? {
            FileDropboxTokenStore::new(paths.dropbox_token_file_for(remote_name)).save(&tok)?;
        }
        Ok(RemoteConfig::Dropbox(Box::new(dcfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[tokio::test]
    async fn handle_auth_preserves_team_fields_across_edit() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "dbx".to_string(),
            DropboxRemoteConfig::new()
                .with_access_token("dbx-tok")
                .with_root_namespace("12345")
                .with_impersonate("dbmid:AAA")
                .with_shared_folders(true)
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            DropboxAuthArgs {
                remote: Some("dbx".to_string()),
                root_path: Some("/backups".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .await
        .unwrap();

        let RemoteConfig::Dropbox(saved) = cfg.remotes.get("dbx").unwrap() else {
            panic!("expected Dropbox");
        };
        assert_eq!(saved.root_path.as_deref(), Some("/backups"));
        assert_eq!(saved.root_namespace.as_deref(), Some("12345"));
        assert_eq!(saved.impersonate.as_deref(), Some("dbmid:AAA"));
        assert_eq!(saved.shared_folders, Some(true));
    }
}
