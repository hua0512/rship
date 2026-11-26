//! Google Drive v3 [`ProviderAdapter`] and interactive `rship auth gdrive` handler.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rship_backends::gdrive::config::{DEFAULT_AUTH_URL, DEFAULT_SCOPE, DEFAULT_TOKEN_URL};
use rship_backends::gdrive::{
    AuthExportBundle, FileTokenStore, PkceFlow, TokenStore, resolve_gdrive_scope,
};
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;

use crate::cli::GdriveAuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, GdriveRemoteConfig, RemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::oauth::{
    OAuthClientPrompt, OAuthPkceRunOpts, print_gdrive_oauth_guide, print_oauth_save_summary,
    resolve_oauth_client_creds, resolve_oauth_port, resolve_service_account_key,
    run_oauth_pkce_wizard, validate_service_account_key,
};
use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    cleanup_remote_keyring_secrets, clear_secret_opt,
};

pub struct GdriveAdapter;

fn select_gdrive_scope(existing_scope: Option<&str>) -> Result<String> {
    let def_idx = match existing_scope {
        Some(s) if s.ends_with("/drive.file") => 1,
        Some(s) if s.ends_with("/drive.readonly") => 2,
        _ => 0,
    };
    let items = [
        SelectItem::new("drive (full access)")
            .with_desc("Read & write all files and folders in Google Drive"),
        SelectItem::new("drive.file (app-created only)")
            .with_desc("Non-Sensitive scope — only access files/folders created by rship"),
        SelectItem::new("drive.readonly (read-only)").with_desc("Read-only backup/mirror access"),
    ];
    let idx = prompt::select("Google Drive OAuth scope", &items, def_idx)?;
    Ok(resolve_gdrive_scope(match idx {
        1 => "drive.file",
        2 => "drive.readonly",
        _ => "drive",
    }))
}

pub(super) async fn handle_auth(
    args: GdriveAuthArgs,
    ctx: &mut AuthContext<'_>,
) -> Result<AuthOutcome> {
    let explicit_sa = args.service_account_file.is_some();
    let explicit_oauth = args.client_id.is_some() || args.client_secret.is_some();
    let any_meta_flag = args.root_folder_id.is_some()
        || args.shared_drive_id.is_some()
        || args.impersonate.is_some()
        || args.scope.is_some();

    let mut wiz = PromptWizard::begin(
        args.remote,
        "gdrive",
        "gdrive",
        explicit_sa || explicit_oauth || any_meta_flag,
        ctx,
    )?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Gdrive(g)) => (**g).clone(),
        _ => GdriveRemoteConfig::default(),
    };
    let resolved_scope = args.scope.as_deref().map(resolve_gdrive_scope);

    wiz.section(
        &format!("Configure Google Drive remote `{}`", wiz.remote),
        existing.client_id.is_some() || existing.service_account_file.is_some(),
        "Editing existing Google Drive remote — press Enter to keep current values",
        "Authorize with Desktop OAuth2 PKCE or a Google Service Account JSON key",
    );

    let use_service_account = if explicit_sa {
        true
    } else if explicit_oauth {
        false
    } else if wiz.full_wizard {
        let def_mode = usize::from(existing.service_account_file.is_some());
        let mode_items = [
            SelectItem::new("OAuth 2.0 Desktop PKCE (browser login)")
                .with_desc("Recommended for personal Gmail or Google Workspace accounts"),
            SelectItem::new("Service Account JSON key").with_desc(
                "Headless servers & CI (Shared Drives or Workspace Domain-Wide Delegation)",
            ),
            SelectItem::new("Show 5-minute Google Cloud OAuth setup guide")
                .with_desc("Print step-by-step GCP Console instructions, then return here"),
        ];
        loop {
            match prompt::select("Google Drive authentication method", &mode_items, def_mode)? {
                0 => break false,
                1 => break true,
                _ => {
                    print_gdrive_oauth_guide(&wiz.remote);
                }
            }
        }
    } else {
        existing.service_account_file.is_some() && existing.client_id.is_none()
    };

    let remote = wiz.remote.clone();
    let config_file_display = wiz.ctx.paths.config_file.display().to_string();

    // -----------------------------------------------------------------------
    // Path 1: Service Account JSON
    // -----------------------------------------------------------------------
    if use_service_account {
        let transport = wiz.ctx.transport()?.clone();
        let (sa_path, sa_key) = resolve_service_account_key(
            &mut wiz,
            args.service_account_file,
            existing.service_account_file.as_ref(),
            &format!("missing `--service-account-file <KEY.JSON>` for Google Drive remote `{remote}`"),
        )?;

        let eff_scope = if let Some(s) = resolved_scope {
            s
        } else if wiz.full_wizard {
            select_gdrive_scope(existing.scope.as_deref())?
        } else {
            existing
                .scope
                .clone()
                .unwrap_or_else(|| DEFAULT_SCOPE.to_string())
        };

        let shared_drive_id = wiz.optional_text(
            "Shared Drive (Team Drive) ID",
            args.shared_drive_id,
            existing.shared_drive_id.clone(),
            Some("Optional — recommended for Service Accounts (from Drive folder URL)"),
        )?;
        let impersonate = wiz.optional_text(
            "Impersonate Workspace user email (Domain-Wide Delegation)",
            args.impersonate,
            existing.impersonate.clone(),
            Some("Optional — required if accessing a user's My Drive without a Shared Drive"),
        )?;
        let root_folder_id = wiz.optional_text(
            "Root folder ID",
            args.root_folder_id,
            existing.root_folder_id.clone(),
            Some("Optional — leave empty for Drive root"),
        )?;

        validate_service_account_key(
            sa_key.clone(),
            eff_scope.clone(),
            impersonate.clone(),
            existing.token_url.clone(),
            transport,
        )?;

        if shared_drive_id.is_none() && impersonate.is_none() {
            prompt::warn(
                "Google Service Accounts have 0 GB personal Drive quota (`403 storageQuotaExceeded`).",
            );
            prompt::note(
                "Set `--shared-drive-id <ID>` (Shared Drive) or `--impersonate <user@domain>` (Domain-Wide Delegation).",
            );
        }

        let mut updated = existing;
        updated.service_account_file = Some(sa_path);
        updated.client_id = None;
        updated.client_secret = clear_secret_opt(updated.client_secret.as_deref());
        updated.access_token = clear_secret_opt(updated.access_token.as_deref());
        updated.impersonate = impersonate;
        updated.root_folder_id = root_folder_id;
        updated.shared_drive_id = shared_drive_id;
        updated.scope = Some(eff_scope);
        let _ = std::fs::remove_file(wiz.ctx.paths.token_file_for(&remote));

        return wiz.finish(
            RemoteConfig::Gdrive(Box::new(updated)),
            &format!(
                "configured Google Drive Service Account remote `{remote}` ({}) in {config_file_display}",
                sa_key.client_email
            ),
        );
    }

    // -----------------------------------------------------------------------
    // Path 2: OAuth 2.0 Desktop PKCE
    // -----------------------------------------------------------------------
    if wiz.ctx.interactive && existing.client_id.is_none() && args.client_id.is_none() {
        prompt::tip(
            "Bring Your Own Client ID: create a 'Desktop app' OAuth client in Google Cloud Console (run `rship auth gdrive --guide` for full steps).",
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
            provider_label: "Google Drive",
            client_id_prompt: "Google Cloud OAuth Desktop client_id",
            client_id_hint: Some("Ends with `.apps.googleusercontent.com`"),
            missing_client_id_err: "missing `--client-id` for Google Drive OAuth2 PKCE (run interactively in a terminal, pass `--client-id`, or run `rship auth gdrive --guide`)",
            client_secret_prompt: "Google Cloud OAuth Desktop client_secret",
            client_secret_hint: None,
            secret_required: true,
        },
    )?;
    let resolved_cid = oauth_creds.client_id;
    let stored_csec = oauth_creds
        .stored_secret
        .ok_or_else(|| rship_core::Error::config("missing Google Drive OAuth2 client_secret"))?;
    let resolved_csec = oauth_creds
        .runtime_secret
        .ok_or_else(|| rship_core::Error::config("missing Google Drive OAuth2 client_secret"))?;
    let csec_changed = oauth_creds.secret_changed;
    wiz.did_prompt |= oauth_creds.did_prompt;

    let eff_scope = if let Some(s) = resolved_scope {
        s
    } else if wiz.full_wizard {
        select_gdrive_scope(existing.scope.as_deref())?
    } else {
        existing
            .scope
            .clone()
            .unwrap_or_else(|| DEFAULT_SCOPE.to_string())
    };

    let flag_scoped = args.root_folder_id.is_some() || args.shared_drive_id.is_some();
    let mut root_folder_id = args
        .root_folder_id
        .or_else(|| existing.root_folder_id.clone());
    let mut shared_drive_id = args
        .shared_drive_id
        .or_else(|| existing.shared_drive_id.clone());
    if wiz.full_wizard && !flag_scoped {
        if prompt::confirm(
            "Scope to a specific Shared Drive or root folder ID?",
            shared_drive_id.is_some() || root_folder_id.is_some(),
        )? {
            shared_drive_id = prompt::text(
                "Shared Drive (Team Drive) ID",
                shared_drive_id.as_deref(),
                Some("Optional — leave empty for personal My Drive"),
                false,
            )?;
            root_folder_id = prompt::text(
                "Root folder ID",
                root_folder_id.as_deref(),
                Some("Optional — leave empty for `root`"),
                false,
            )?;
        } else {
            shared_drive_id = None;
            root_folder_id = None;
        }
    }

    let token_path = wiz.ctx.paths.token_file_for(&remote);
    let tok_store = FileTokenStore::new(token_path.clone());
    let oauth_creds_changed = prev_cid.as_deref() != Some(resolved_cid.as_str())
        || csec_changed
        || prev_scope.as_deref() != Some(eff_scope.as_str())
        || existing.service_account_file.is_some();

    let auth_url = existing
        .auth_url
        .as_deref()
        .unwrap_or(DEFAULT_AUTH_URL)
        .to_string();
    let token_url = existing
        .token_url
        .as_deref()
        .unwrap_or(DEFAULT_TOKEN_URL)
        .to_string();
    let (preferred_port, strict_port) = resolve_oauth_port(args.callback_port);

    let cid_for_flow = resolved_cid.clone();
    let scope_for_flow = eff_scope.clone();
    let need_browser_login = run_oauth_pkce_wizard(
        OAuthPkceRunOpts {
            display_name: "Google Drive",
            confirm_label: "Google Drive",
            creds_changed: oauth_creds_changed,
            explicit_oauth,
            no_browser: args.no_browser,
            manual: args.manual,
        },
        &mut wiz,
        &tok_store,
        || async move {
            PkceFlow::start_with_port(
                cid_for_flow,
                resolved_csec,
                &scope_for_flow,
                &auth_url,
                &token_url,
                preferred_port,
                strict_port,
            )
            .await
            .map_err(Into::into)
        },
    )
    .await?;

    let mut updated = existing;
    updated.client_id = Some(resolved_cid);
    updated.client_secret = Some(stored_csec);
    updated.service_account_file = None;
    updated.impersonate = None;
    updated.access_token = clear_secret_opt(updated.access_token.as_deref());
    updated.root_folder_id = root_folder_id;
    updated.shared_drive_id = shared_drive_id;
    updated.scope = Some(eff_scope);
    let _ = std::fs::remove_file(wiz.ctx.paths.service_account_file_for(&remote));

    super::persist_remote(
        &remote,
        RemoteConfig::Gdrive(Box::new(updated)),
        wiz.did_prompt,
        wiz.ctx,
    )?;
    print_oauth_save_summary(
        "Google Drive",
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
impl ProviderAdapter for GdriveAdapter {
    fn kind(&self) -> &'static str {
        "gdrive"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("drive")
    }

    fn cleanup_secrets(&self, remote_name: &str, cfg: &RemoteConfig, paths: &AppPaths) {
        cleanup_remote_keyring_secrets(cfg);
        let _ = std::fs::remove_file(paths.token_file_for(remote_name));
        let _ = std::fs::remove_file(paths.service_account_file_for(remote_name));
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Gdrive(_)).then(RelPath::root)
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
        let RemoteConfig::Gdrive(gcfg) = cfg else {
            bail!("internal mismatch: expected Gdrive remote config");
        };
        let token = FileTokenStore::new(paths.token_file_for(remote)).load()?;
        let service_account_json = PortableBundle::read_optional_sa_json(
            gcfg.service_account_file.as_deref(),
            "service account",
        )?;
        if token.is_none() && service_account_json.is_none() {
            return Err(config_err(format!(
                "remote `{remote}` has neither a saved OAuth token nor a service account file; run `rship auth gdrive {remote}` first"
            )));
        }
        let bundle = AuthExportBundle {
            version: 1,
            remote_name: remote.to_string(),
            remote_type: "gdrive".to_string(),
            client_id: gcfg.client_id.clone(),
            client_secret: resolve_opt_secret(gcfg.client_secret.as_deref())?,
            root_folder_id: gcfg.root_folder_id.clone(),
            shared_drive_id: gcfg.shared_drive_id.clone(),
            scope: gcfg.scope.clone(),
            token,
            service_account_json,
            impersonate: gcfg.impersonate.clone(),
        };
        if as_json {
            Ok(serde_json::to_string_pretty(&bundle)?)
        } else {
            Ok(bundle.encode_compact()?)
        }
    }

    fn import_bundle(
        &self,
        remote_name: &str,
        bundle: &PortableBundle,
        paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let mut gcfg: GdriveRemoteConfig = if bundle.config.is_some() {
            bundle.deserialize_config("gdrive")?
        } else {
            serde_json::from_value(serde_json::Value::Object(bundle.extra.clone()))
                .context("invalid Google Drive fields in auth bundle")?
        };
        if let Some(tok) = bundle.take_token(None)? {
            FileTokenStore::new(paths.token_file_for(remote_name)).save(&tok)?;
        }
        if let Some(sa_path) =
            bundle.write_optional_sa_json(paths.service_account_file_for(remote_name))?
        {
            gcfg.service_account_file = Some(sa_path);
        }
        Ok(RemoteConfig::Gdrive(Box::new(gcfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    const TEST_SA_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDmCGt+/C78UGk0\n\
yeovLQgL8+WSNGb5Z8LQGlZskqYY1utPb/oJmjrZGezy+NCq3aoHnZJskgWip7eB\n\
w975E8d91fr8Y9EU895ZRamGOeiWtv2LWjgi3BCTHykSay661LQnV2jhgTd78gxZ\n\
wGONyX8tvHbri2ppSY4pyWq9bbR6XqiWjU/0IEC9Ldgfilx+i2sWJSWF6+pRiqER\n\
e9InRz/G6LIzaCHqmYDeFNxbeE2AzToE5RNOxBKTP2bzHWYTe7ttrIU/pBhgJnu2\n\
giRNGFUuvp1IJ2Pofl8tEJ1QUbO7O/M+70vcZ1zh4Pux8NC67hhjzuWwx2VTzogd\n\
GrjV2k/tAgMBAAECggEBAM6rp/DaIFi+4hb0hjvGaKFciti1zgKsL8KKtzUq+KH+\n\
jkG7qFjyQYcGnPWbiNbK+tWGw6RZ+UgvCVdEJNOB6szq8GnMQHBjvlRUmz+mTYsD\n\
c369GwxuzVFxQJR0yfI/4nAqP2fDkZcBXAlTKd6ct2/fELUFeCCKXni6pvT0WJ9L\n\
MhynYupx5maG6SG4Z81YeGyI4FJlr4W1Im1K8YwPhgdch/Q4VFJh6+KW2MoVk0IN\n\
jh9sSPm+AqK15DIa++yMxnJGbP1pFd52i29E0UJ6q19Hl6re9+OVqrV9YZUjmmek\n\
g78F2s/PbMwrGlontgtrITFJ7Qj6vytC6HVy5r3QfF0CgYEA/PV8v8oFJY2GhUQ6\n\
dgNy7I+xaVHCKOAsozf86g4KRP6EjBXoct8rMS62kV2uGCuFIM3UqSGqWcusKmbv\n\
Xw+5Gx476a29FjGTXqJH6/5q7G9gfiUDkHlYUZGAWr/fhCGULAE+QPvGT/0in4jO\n\
zD68ubWgu3LczhpoQ30bNLDUDl8CgYEA6Mxf9ZXRYczsak9gm0C1YkYDQ4fclVii\n\
YHakxH6s4JjFrj6TQmQniHXJsZ2y2KvNftbswu5akR7gLvX7R8JT8O9PxtOQ71LG\n\
zw4YkyKLLPUcQfyhD0LdR3m/Dfeb04tP//R/t8w3IvA7FOrTMSCVv4L/eRxJlqVb\n\
sg+K37WjbTMCgYEApNkCTCZGRlu9n5mAE6pZuapG7qC2TFcTH+b7rjgqHx5SmMwq\n\
KLog9rM/jOok62FpJ6CbhwEGd/BQKW3dbvDbK73/Q2DSyeTS6igNgNDTM3O9yVcr\n\
xHofwUB2Ci3iZsRPQIIq5MRvT29iod7RDa+Q4+FmduH63WG+MsUT9rmJ6DcCgYB2\n\
yNGt3eQYoxd+p0ID9eCXZGIF8yz6h19TGTa5jGlpsIotfoBlP/VsC63+kxjOtdsE\n\
/WWRkU1k/vwk+h5dXyq1pWZvbURm2TXYMLkZWmbpaaghg2YrA1MlRVnXJqC8MDmB\n\
wJ/qiKkZirqa0bcxOg8uyQjSIzzpQTaohIW34FajQQKBgD19q6viXt20LVgHlEaT\n\
/MWYAO8E6VBjJLkPab2qbYRBNAWNhPU1Nuk3AVg7IpnXf+jU/SzjPB4lDsBheNCO\n\
sbNZFrHlGXqAs4m6vauY7dLLO3Xe9gHs5pDr5DMD+Me51RU7UknqWcXLGj4iCjt6\n\
l8vTzo35m1efRYleCkqZ2kuP\n\
-----END PRIVATE KEY-----\n";

    #[tokio::test]
    async fn handle_auth_uses_backend_scope_aliases_and_preserves_gdrive_flags() {
        let tmp = TempDir::new().unwrap();
        let sa_path = tmp.path().join("sa.json");
        let payload = serde_json::json!({
            "type": "service_account",
            "project_id": "p",
            "private_key_id": "k",
            "private_key": TEST_SA_PEM,
            "client_email": "svc@example.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token"
        });
        std::fs::write(&sa_path, serde_json::to_vec(&payload).unwrap()).unwrap();

        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "gd".to_string(),
            GdriveRemoteConfig::new()
                .with_service_account_file(&sa_path)
                .with_shared_with_me(true)
                .with_trashed_only(true)
                .with_stop_on_upload_limit(true)
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            GdriveAuthArgs {
                remote: Some("gd".to_string()),
                scope: Some("drive.appfolder, readonly".to_string()),
                shared_drive_id: Some("0AD".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .await
        .unwrap();

        let RemoteConfig::Gdrive(saved) = cfg.remotes.get("gd").unwrap() else {
            panic!("expected Gdrive");
        };
        assert_eq!(
            saved.scope.as_deref(),
            Some("https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/drive.readonly")
        );
        assert!(saved.use_trash.is_none(), "omitted use_trash stays None (defaults to true in factory)");
        assert_eq!(saved.shared_with_me, Some(true));
        assert_eq!(saved.trashed_only, Some(true));
        assert_eq!(saved.stop_on_upload_limit, Some(true));
    }
}
