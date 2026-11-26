//! Azure Blob Storage [`ProviderAdapter`] and interactive `rship auth azureblob` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::azureblob::config::{AZURITE_ACCOUNT, AZURITE_ENDPOINT, AZURITE_KEY};
use rship_backends::azureblob::extract_sas_url_metadata;

use crate::cli::AzureblobAuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, AzureblobRemoteConfig, RemoteConfig};
use rship::secrets::{is_keyring_ref, resolve_opt_secret};

use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, PortableBundle, ProviderAdapter, clear_secret_opt, merge_flag_secret,
};

pub struct AzureblobAdapter;

fn is_clear_flag(val: &str) -> bool {
    let trimmed = val.trim();
    trimmed.is_empty() || trimmed == "-"
}

fn merge_optional_flag(flag: Option<&str>, existing: Option<&str>) -> Option<String> {
    match flag {
        Some(v) => (!is_clear_flag(v)).then(|| v.to_string()),
        None => existing.map(str::to_string),
    }
}

fn is_azurite_endpoint(ep: &str) -> bool {
    ep.trim_end_matches('/') == AZURITE_ENDPOINT
}

fn is_public_azure_endpoint(ep: &str, account: &str) -> bool {
    ep.trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(&format!("https://{account}.blob.core.windows.net"))
}

fn is_sovereign_azure_endpoint(ep: &str, account: &str) -> bool {
    let normalized = ep.trim().trim_end_matches('/');
    [
        "blob.core.chinacloudapi.cn",
        "blob.core.usgovcloudapi.net",
        "blob.core.cloudapi.de",
    ]
    .iter()
    .any(|suffix| normalized.eq_ignore_ascii_case(&format!("https://{account}.{suffix}")))
}

fn is_public_azure_endpoint_opt(ep: &str, account: Option<&str>) -> bool {
    account.is_some_and(|acct| is_public_azure_endpoint(ep, acct))
}

fn is_sovereign_azure_endpoint_opt(ep: &str, account: Option<&str>) -> bool {
    account.is_some_and(|acct| is_sovereign_azure_endpoint(ep, acct))
}

fn is_bare_sas_token(sas: &str) -> bool {
    !is_keyring_ref(sas) && {
        let meta = extract_sas_url_metadata(sas);
        meta.account.is_none() && meta.endpoint.is_none()
    }
}

fn should_prompt_sas_account(
    sas_outcome: &prompt::SecretOutcome,
    existing_sas_url: Option<&str>,
    account: Option<&str>,
    endpoint: Option<&str>,
) -> bool {
    if account.is_none() {
        return true;
    }
    match sas_outcome {
        prompt::SecretOutcome::Value(raw) => is_bare_sas_token(raw),
        prompt::SecretOutcome::KeepExisting => existing_sas_url.is_some_and(|s| {
            if is_keyring_ref(s) {
                endpoint.is_none()
            } else {
                is_bare_sas_token(s)
            }
        }),
        prompt::SecretOutcome::Empty => false,
    }
}

fn cleanup_stale_endpoint(
    endpoint: &mut Option<String>,
    account: Option<&str>,
    existing: Option<&AzureblobRemoteConfig>,
    explicit_endpoint_flag: bool,
    sas_derived_endpoint: bool,
    selected_emulator: bool,
) {
    if explicit_endpoint_flag || sas_derived_endpoint || selected_emulator {
        return;
    }
    let existing_account = existing.and_then(|a| a.account.as_deref());
    let account_changed = account != existing_account;
    let existing_sas_url = existing
        .and_then(|a| a.sas_url.as_deref())
        .filter(|s| !s.trim().is_empty());

    let should_clear_endpoint = if account_changed {
        existing_sas_url.is_some()
            || endpoint.as_deref().is_some_and(|e| {
                is_public_azure_endpoint_opt(e, existing_account)
                    || is_sovereign_azure_endpoint_opt(e, existing_account)
                    || is_azurite_endpoint(e)
            })
    } else {
        endpoint
            .as_deref()
            .is_some_and(|e| is_public_azure_endpoint_opt(e, existing_account))
    };
    if should_clear_endpoint {
        *endpoint = None;
    }
}

pub(super) fn handle_auth(
    args: AzureblobAuthArgs,
    ctx: &mut AuthContext<'_>,
) -> Result<AuthOutcome> {
    let any_config_flag = args.account.is_some()
        || args.container.is_some()
        || args.prefix.is_some()
        || args.key.is_some()
        || args.sas_url.is_some()
        || args.endpoint.is_some()
        || args.access_tier.is_some()
        || args.use_emulator
        || args.anonymous;

    let mut wiz = PromptWizard::begin(args.remote, "azure", "azureblob", any_config_flag, ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Azureblob(a)) => Some((**a).clone()),
        _ => None,
    };

    wiz.section(
        &format!("Configure Azure Blob remote `{}`", wiz.remote),
        existing.is_some(),
        "Editing existing remote — press Enter to keep current values",
        "Choose Shared Key, SAS URL, Azurite emulator, or anonymous access",
    );

    let mut account = merge_optional_flag(
        args.account.as_deref(),
        existing.as_ref().and_then(|a| a.account.as_deref()),
    );
    let mut container = merge_optional_flag(
        args.container.as_deref(),
        existing.as_ref().and_then(|a| a.container.as_deref()),
    );
    let mut endpoint = merge_optional_flag(
        args.endpoint.as_deref(),
        existing.as_ref().and_then(|a| a.endpoint.as_deref()),
    );
    let mut key = merge_flag_secret(
        args.key.clone(),
        existing.as_ref().and_then(|a| a.key.as_deref()),
    )?;
    let mut sas_url = merge_flag_secret(
        args.sas_url.clone(),
        existing.as_ref().and_then(|a| a.sas_url.as_deref()),
    )?;
    let mut anonymous = if args.anonymous {
        Some(true)
    } else if args.key.is_some() || args.sas_url.is_some() || args.use_emulator {
        None
    } else {
        existing.as_ref().and_then(|a| a.anonymous)
    };

    if args.anonymous {
        key = clear_secret_opt(key.as_deref());
        sas_url = clear_secret_opt(sas_url.as_deref());
    }

    let mut selected_emulator = args.use_emulator;
    let mut sas_derived_endpoint = false;

    if args.use_emulator {
        if args.account.is_none() {
            account = Some(AZURITE_ACCOUNT.to_string());
        }
        if args.key.is_none() && args.sas_url.is_none() {
            let _ = clear_secret_opt(key.as_deref());
            key = Some(AZURITE_KEY.to_string());
        }
        if args.endpoint.is_none() {
            endpoint = Some(AZURITE_ENDPOINT.to_string());
        }
        sas_url = clear_secret_opt(sas_url.as_deref());
        anonymous = None;
    }

    if let Some(ref raw_sas) = args.sas_url {
        let meta = extract_sas_url_metadata(raw_sas);
        if args.account.is_none()
            && let Some(a) = meta.account
        {
            account = Some(a);
        }
        if args.endpoint.is_none()
            && let Some(e) = meta.endpoint
        {
            endpoint = Some(e);
            sas_derived_endpoint = true;
        }
        if args.container.is_none()
            && let Some(c) = meta.container
        {
            container = Some(c);
        }
        if args.key.is_none() {
            key = clear_secret_opt(key.as_deref());
        }
    } else if args.key.is_some() {
        sas_url = clear_secret_opt(sas_url.as_deref());
    }

    let has_auth_config = (anonymous == Some(true) && account.is_some())
        || (account.is_some() && key.is_some())
        || sas_url.is_some();

    if wiz.full_wizard || (wiz.ctx.interactive && !has_auth_config) {
        wiz.did_prompt = true;
        let def_mode = if existing.as_ref().and_then(|a| a.anonymous) == Some(true) {
            3
        } else if existing
            .as_ref()
            .and_then(|a| a.endpoint.as_deref())
            .is_some_and(|e| e == AZURITE_ENDPOINT)
        {
            2
        } else if sas_url.is_some() {
            1
        } else {
            0
        };
        let mode_items = [
            SelectItem::new("Storage Account Shared Key")
                .with_desc("Account name + Base64 access key"),
            SelectItem::new("SAS URL or SAS Token").with_desc(
                "Pre-signed URL (`https://acct.blob.core.windows.net?sv=...`) or `?sv=...`",
            ),
            SelectItem::new("Local Azurite Emulator")
                .with_desc("Auto-fills devstoreaccount1 & http://127.0.0.1:10000"),
            SelectItem::new("Anonymous (public containers)")
                .with_desc("Read-only access to public Azure Blob containers"),
        ];
        match prompt::select("Azure Blob authentication method", &mode_items, def_mode)? {
            0 => {
                anonymous = None;
                sas_url = clear_secret_opt(sas_url.as_deref());
                account =
                    prompt::text("Azure Storage Account name", account.as_deref(), None, true)?;
                key = wiz.prompt_secret(
                    "Storage Account Shared Key (Base64)",
                    key.as_deref(),
                    true,
                    None,
                )?;
            }
            1 => {
                anonymous = None;
                key = clear_secret_opt(key.as_deref());
                let has_sas = sas_url.as_deref().is_some_and(|s| !s.is_empty());
                let sas_out = prompt::password(
                    "SAS URL or query token",
                    has_sas,
                    true,
                    Some("Full SAS URL automatically populates account, endpoint & container"),
                )?;
                if let prompt::SecretOutcome::Value(ref raw_sas) = sas_out {
                    let meta = extract_sas_url_metadata(raw_sas);
                    if let Some(a) = meta.account {
                        account = Some(a);
                    }
                    if let Some(e) = meta.endpoint {
                        endpoint = Some(e);
                        sas_derived_endpoint = true;
                    }
                    if args.container.is_none()
                        && let Some(c) = meta.container
                    {
                        container = Some(c);
                    }
                }
                let prompt_account = should_prompt_sas_account(
                    &sas_out,
                    sas_url.as_deref(),
                    account.as_deref(),
                    endpoint.as_deref(),
                );
                sas_url = super::apply_secret_outcome(sas_out, sas_url.as_deref())?;
                if prompt_account && args.account.is_none() {
                    account = prompt::text(
                        "Azure Storage Account name",
                        account.as_deref(),
                        Some("Required for bare `?sv=...` SAS tokens (leave empty only if using a custom endpoint)"),
                        endpoint.is_none(),
                    )?;
                }
            }
            2 => {
                selected_emulator = true;
                anonymous = None;
                sas_url = clear_secret_opt(sas_url.as_deref());
                let _ = clear_secret_opt(key.as_deref());
                account = Some(AZURITE_ACCOUNT.to_string());
                key = Some(AZURITE_KEY.to_string());
                endpoint = Some(AZURITE_ENDPOINT.to_string());
                prompt::tip(
                    "Configured local Azurite emulator (`devstoreaccount1` @ 127.0.0.1:10000)",
                );
            }
            _ => {
                anonymous = Some(true);
                key = clear_secret_opt(key.as_deref());
                sas_url = clear_secret_opt(sas_url.as_deref());
                account =
                    prompt::text("Azure Storage Account name", account.as_deref(), None, true)?;
            }
        }
    } else if !has_auth_config {
        return Err(config_err(format!(
            "Azure Blob remote `{}` requires `--account` + `--key`, `--sas-url`, `--use-emulator`, or `--anonymous --account <NAME>` (or run interactively in a terminal)",
            wiz.remote
        )));
    }

    cleanup_stale_endpoint(
        &mut endpoint,
        account.as_deref(),
        existing.as_ref(),
        args.endpoint.is_some(),
        sas_derived_endpoint,
        selected_emulator,
    );

    let container_flag = args.container.filter(|v| !is_clear_flag(v));
    container = wiz.optional_text(
        "Default container name",
        container_flag,
        container,
        Some("Optional — leave empty to pass container per command (`remote:container/path`)"),
    )?;

    let mut prefix = args
        .prefix
        .or_else(|| existing.as_ref().and_then(|a| a.prefix.clone()));
    let mut access_tier = args
        .access_tier
        .or_else(|| existing.as_ref().and_then(|a| a.access_tier.clone()));
    if wiz.full_wizard
        && prompt::confirm(
            "Configure advanced options (prefix, custom endpoint, access tier)?",
            false,
        )?
    {
        prefix = prompt::text(
            "Default blob prefix inside container",
            prefix.as_deref(),
            None,
            false,
        )?;
        endpoint = prompt::text(
            "Custom Azure Blob service endpoint",
            endpoint.as_deref(),
            Some("Optional, e.g. https://<acct>.blob.core.chinacloudapi.cn"),
            false,
        )?;
        let tier_items = [
            SelectItem::new("Account default"),
            SelectItem::new("Hot"),
            SelectItem::new("Cool"),
            SelectItem::new("Cold"),
            SelectItem::new("Archive"),
        ];
        let def_tier = match access_tier.as_deref() {
            Some(t) if t.eq_ignore_ascii_case("Hot") => 1,
            Some(t) if t.eq_ignore_ascii_case("Cool") => 2,
            Some(t) if t.eq_ignore_ascii_case("Cold") => 3,
            Some(t) if t.eq_ignore_ascii_case("Archive") => 4,
            _ => 0,
        };
        access_tier = match prompt::select("Blob access tier", &tier_items, def_tier)? {
            1 => Some("Hot".to_string()),
            2 => Some("Cool".to_string()),
            3 => Some("Cold".to_string()),
            4 => Some("Archive".to_string()),
            _ => None,
        };
    }

    if sas_url.as_deref().is_some_and(is_bare_sas_token)
        && account.is_none()
        && endpoint.is_none()
    {
        return Err(config_err(
            "Azure Storage Account name (--account) or --endpoint is required when using a bare SAS token",
        ));
    }

    let mut acfg = AzureblobRemoteConfig::new();
    acfg.account = account.clone();
    acfg.container = container;
    acfg.prefix = prefix;
    acfg.key = key;
    acfg.sas_url = sas_url;
    acfg.endpoint = endpoint;
    acfg.access_tier = access_tier;
    acfg.anonymous = anonymous;

    let msg = format!(
        "configured Azure Blob remote `{}` (account={}) in {}",
        wiz.remote,
        account.as_deref().unwrap_or("sas/anonymous"),
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(acfg.into(), &msg)
}

#[async_trait]
impl ProviderAdapter for AzureblobAdapter {
    fn kind(&self) -> &'static str {
        "azureblob"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("azureblob")
    }

    fn export_bundle(
        &self,
        remote: &str,
        cfg: &RemoteConfig,
        _paths: &AppPaths,
        as_json: bool,
    ) -> Result<String> {
        let RemoteConfig::Azureblob(acfg) = cfg else {
            bail!("internal mismatch: expected Azureblob remote config");
        };
        let mut resolved = (**acfg).clone();
        resolved.key = resolve_opt_secret(resolved.key.as_deref())?;
        resolved.sas_url = resolve_opt_secret(resolved.sas_url.as_deref())?;
        PortableBundle::export_config(remote, "azureblob", &resolved, as_json)
    }

    fn import_bundle(
        &self,
        _remote_name: &str,
        bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let acfg: AzureblobRemoteConfig = bundle.deserialize_config("azureblob")?;
        Ok(RemoteConfig::Azureblob(Box::new(acfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn handle_auth_sas_url_populates_account_endpoint_and_container() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-sas".to_string()),
                sas_url: Some(
                    "https://myacct.blob.core.windows.net/mycontainer?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::Azureblob(saved) = cfg.remotes.get("az-sas").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("myacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://myacct.blob.core.windows.net")
        );
        assert_eq!(saved.container.as_deref(), Some("mycontainer"));
    }

    #[test]
    fn handle_auth_azurite_path_style_sas_populates_container_unless_explicitly_set() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu-sas".to_string()),
                sas_url: Some(
                    "http://127.0.0.1:10000/devstoreaccount1/backups?sv=2023-01-01&sig=xyz"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::Azureblob(saved) = cfg.remotes.get("az-emu-sas").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("devstoreaccount1"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("http://127.0.0.1:10000/devstoreaccount1")
        );
        assert_eq!(saved.container.as_deref(), Some("backups"));
    }

    #[test]
    fn handle_auth_sas_url_update_on_existing_remote_updates_metadata_and_respects_flags() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh".to_string()),
                sas_url: Some(
                    "https://acct.blob.core.windows.net/cont?sv=2023-01-01&sig=abc".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        // 1. Rotate to a new full SAS URL without passing --account/--endpoint/--container.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh".to_string()),
                sas_url: Some(
                    "https://newacct.blob.core.windows.net/newcont?sv=2023-01-01&sig=xyz"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-vh").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("newacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://newacct.blob.core.windows.net")
        );
        assert_eq!(saved.container.as_deref(), Some("newcont"));

        // 2. Account-level SAS URL without container keeps existing container fallback.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh".to_string()),
                sas_url: Some(
                    "https://acct3.blob.core.windows.net?sv=2023-01-01&sig=acct3".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-vh").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("acct3"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://acct3.blob.core.windows.net")
        );
        assert_eq!(saved.container.as_deref(), Some("newcont"));

        // 3. Explicit --account/--endpoint/--container override extracted SAS metadata.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh".to_string()),
                account: Some("override-acct".to_string()),
                endpoint: Some("https://override.example".to_string()),
                container: Some("override-cont".to_string()),
                sas_url: Some(
                    "https://acct4.blob.core.windows.net/cont4?sv=2023-01-01&sig=acct4"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-vh").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("override-acct"));
        assert_eq!(saved.endpoint.as_deref(), Some("https://override.example"));
        assert_eq!(saved.container.as_deref(), Some("override-cont"));

        // 4. Clearing flags (`-`) clears container/account/endpoint even when --sas-url has metadata.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh".to_string()),
                container: Some("-".to_string()),
                sas_url: Some(
                    "https://acct5.blob.core.windows.net/cont5?sv=2023-01-01&sig=acct5"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-vh").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("acct5"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://acct5.blob.core.windows.net")
        );
        assert_eq!(saved.container, None);
    }

    #[test]
    fn handle_auth_switching_from_sas_url_to_shared_key_or_anonymous_clears_sas_endpoint() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // 1. Virtual-host SAS URL -> Shared Key on newacct clears sas_url and SAS-derived endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh-sw".to_string()),
                sas_url: Some(
                    "https://oldacct.blob.core.windows.net/oldcont?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-vh-sw".to_string()),
                account: Some("newacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-vh-sw").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("newacct"));
        assert_eq!(saved.key.as_deref(), Some("AQIDBA=="));
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.endpoint, None);
        assert_eq!(saved.anonymous, None);

        // 2. Path-style SAS URL -> Shared Key clears SAS-derived endpoint, while staying in SAS mode
        //    preserves endpoint, and passing explicit --endpoint is respected.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-sw".to_string()),
                sas_url: Some(
                    "http://127.0.0.1:14754/oldacct/oldcont?sv=2023-01-01&sig=abc".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        // Staying in SAS mode while updating container preserves path-style endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-sw".to_string()),
                container: Some("othercont".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-ps-sw").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("http://127.0.0.1:14754/oldacct")
        );
        assert_eq!(saved.container.as_deref(), Some("othercont"));

        // Switch away to Shared Key without --endpoint -> clears path-style SAS endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-sw".to_string()),
                account: Some("newacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-ps-sw").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.endpoint, None);
        assert_eq!(saved.account.as_deref(), Some("newacct"));

        // Re-create path-style SAS remote and switch with explicit --endpoint -> explicit wins.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-exp".to_string()),
                sas_url: Some(
                    "http://127.0.0.1:14754/oldacct/oldcont?sv=2023-01-01&sig=abc".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-exp".to_string()),
                account: Some("newacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                endpoint: Some("http://127.0.0.1:14754/newacct".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-ps-exp").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("http://127.0.0.1:14754/newacct")
        );

        // 3. Virtual-host SAS URL -> --anonymous --account anonacct clears sas_url and endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-anon".to_string()),
                sas_url: Some(
                    "https://oldacct.blob.core.windows.net/oldcont?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-anon".to_string()),
                anonymous: true,
                account: Some("anonacct".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-anon").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.key, None);
        assert_eq!(saved.anonymous, Some(true));
        assert_eq!(saved.account.as_deref(), Some("anonacct"));
        assert_eq!(saved.endpoint, None);
    }

    #[test]
    fn handle_auth_keyring_sas_and_account_coupled_endpoints_switch_cleanly() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();

        // Keyring-backed SAS with custom China endpoint, same account -> custom endpoint preserved.
        let mut china = AzureblobRemoteConfig::new();
        china.account = Some("oldacct".to_string());
        china.sas_url = Some("keyring://rship/test_nonexistent_az_china_sas".to_string());
        china.endpoint = Some("https://oldacct.blob.core.chinacloudapi.cn".to_string());
        cfg.remotes
            .insert("az-kr-china".to_string(), china.into());

        // Keyring-backed SAS with default Azure endpoint, same account -> default endpoint cleared.
        let mut def_kr = AzureblobRemoteConfig::new();
        def_kr.account = Some("oldacct".to_string());
        def_kr.sas_url = Some("keyring://rship/test_nonexistent_az_def_sas".to_string());
        def_kr.endpoint = Some("https://oldacct.blob.core.windows.net".to_string());
        cfg.remotes
            .insert("az-kr-def".to_string(), def_kr.into());

        // Non-SAS Azurite remote switching to prodacct -> AZURITE_ENDPOINT cleared.
        let mut az_prev = AzureblobRemoteConfig::new();
        az_prev.account = Some(AZURITE_ACCOUNT.to_string());
        az_prev.key = Some(AZURITE_KEY.to_string());
        az_prev.endpoint = Some(AZURITE_ENDPOINT.to_string());
        cfg.remotes
            .insert("az-non-sas-emu".to_string(), az_prev.into());

        // Non-SAS custom endpoint remote switching account -> custom endpoint preserved.
        let mut custom_prev = AzureblobRemoteConfig::new();
        custom_prev.account = Some("oldacct".to_string());
        custom_prev.key = Some("OLDKEY==".to_string());
        custom_prev.endpoint = Some("https://custom.proxy.example".to_string());
        cfg.remotes
            .insert("az-non-sas-custom".to_string(), custom_prev.into());

        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-kr-china".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-kr-china").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://oldacct.blob.core.chinacloudapi.cn")
        );

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-kr-def".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-kr-def").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.endpoint, None);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-non-sas-emu".to_string()),
                account: Some("prodacct".to_string()),
                key: Some("PRODKEY==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-non-sas-emu").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("prodacct"));
        assert_eq!(saved.endpoint, None);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-non-sas-custom".to_string()),
                account: Some("newacct".to_string()),
                key: Some("NEWKEY==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-non-sas-custom").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("newacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://custom.proxy.example")
        );
    }

    #[test]
    fn handle_auth_use_emulator_on_existing_remote_overwrites_account_and_endpoint() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu".to_string()),
                sas_url: Some(
                    "https://oldacct.blob.core.windows.net/oldcont?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu".to_string()),
                use_emulator: true,
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-emu").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some(AZURITE_ACCOUNT));
        assert_eq!(saved.endpoint.as_deref(), Some(AZURITE_ENDPOINT));
        assert_eq!(saved.key.as_deref(), Some(AZURITE_KEY));
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.anonymous, None);
        assert_eq!(saved.container.as_deref(), Some("oldcont"));

        // Explicit --endpoint with --use-emulator still wins over AZURITE_ENDPOINT.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu-custom".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                endpoint: Some("https://oldacct.blob.core.windows.net".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu-custom".to_string()),
                use_emulator: true,
                endpoint: Some("http://127.0.0.1:10001/devstoreaccount1".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-emu-custom").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some(AZURITE_ACCOUNT));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("http://127.0.0.1:10001/devstoreaccount1")
        );
        assert_eq!(saved.key.as_deref(), Some(AZURITE_KEY));
    }

    #[test]
    fn handle_auth_same_account_sovereign_and_custom_sas_to_shared_key_or_anon_preserves_endpoint() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // 1. Plaintext Azure China SAS URL -> Shared Key on same account preserves endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-china-same".to_string()),
                sas_url: Some(
                    "https://chinaacct.blob.core.chinacloudapi.cn/cont?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-china-same".to_string()),
                account: Some("chinaacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-china-same").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.account.as_deref(), Some("chinaacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://chinaacct.blob.core.chinacloudapi.cn")
        );

        // 2. Plaintext Azure Gov SAS URL -> Anonymous on same account (omitting --account) preserves endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-gov-same".to_string()),
                sas_url: Some(
                    "https://govacct.blob.core.usgovcloudapi.net/cont?sv=2023-01-01&sig=abc"
                        .to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-gov-same".to_string()),
                anonymous: true,
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-gov-same").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.anonymous, Some(true));
        assert_eq!(saved.account.as_deref(), Some("govacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://govacct.blob.core.usgovcloudapi.net")
        );

        // 3. Plaintext custom path-style SAS URL -> Shared Key on same account preserves endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-same".to_string()),
                sas_url: Some(
                    "http://127.0.0.1:14754/oldacct/oldcont?sv=2023-01-01&sig=abc".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-ps-same".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-ps-same").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.account.as_deref(), Some("oldacct"));
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("http://127.0.0.1:14754/oldacct")
        );

        // 4. Plaintext default public Azure SAS URL -> Shared Key on same account clears redundant default endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-pub-same".to_string()),
                sas_url: Some(
                    "https://pubacct.blob.core.windows.net/cont?sv=2023-01-01&sig=abc".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-pub-same".to_string()),
                account: Some("pubacct".to_string()),
                key: Some("AQIDBA==".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-pub-same").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.sas_url, None);
        assert_eq!(saved.endpoint, None);
    }

    #[test]
    fn handle_auth_switching_to_bare_sas_token_clears_stale_endpoint() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // 1. Azurite (--use-emulator) -> bare ?sv=... SAS token on prodacct clears AZURITE_ENDPOINT.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu-bare".to_string()),
                use_emulator: true,
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-emu-bare".to_string()),
                account: Some("prodacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=abc".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-emu-bare").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("prodacct"));
        assert_eq!(saved.sas_url.as_deref(), Some("?sv=2023-01-01&sig=abc"));
        assert_eq!(saved.key, None);
        assert_eq!(saved.endpoint, None);

        // 2. Full-URL SAS -> bare ?sv=... SAS token on newacct clears old SAS endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-sas-bare".to_string()),
                sas_url: Some(
                    "http://127.0.0.1:14964/oldacct/oldcont?sv=2023-01-01&sig=old".to_string(),
                ),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-sas-bare".to_string()),
                account: Some("newacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=new".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-sas-bare").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("newacct"));
        assert_eq!(saved.endpoint, None);

        // 3. Shared Key (oldacct + default endpoint) -> bare ?sv=... on newacct clears old endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-sk-bare".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("OLDKEY==".to_string()),
                endpoint: Some("https://oldacct.blob.core.windows.net".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-sk-bare".to_string()),
                account: Some("newacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=new".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-sk-bare").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account.as_deref(), Some("newacct"));
        assert_eq!(saved.key, None);
        assert_eq!(saved.endpoint, None);

        // 4. Explicit --endpoint passed alongside bare ?sv=... is always preserved.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-exp".to_string()),
                use_emulator: true,
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-exp".to_string()),
                account: Some("chinaacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=cn".to_string()),
                endpoint: Some("https://chinaacct.blob.core.chinacloudapi.cn".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-bare-exp").unwrap() else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://chinaacct.blob.core.chinacloudapi.cn")
        );
    }

    #[test]
    fn cleanup_stale_endpoint_preserves_interactive_azurite_and_sas_derived_endpoints() {
        let mut prev_sas = AzureblobRemoteConfig::new();
        prev_sas.account = Some("oldacct".to_string());
        prev_sas.sas_url = Some("https://oldacct.blob.core.windows.net/c?sv=2023-01-01".to_string());
        prev_sas.endpoint = Some("https://oldacct.blob.core.windows.net".to_string());

        // Interactive Azurite selection (`selected_emulator = true`, no `--endpoint` flag)
        // must preserve AZURITE_ENDPOINT even when switching from a sas_url remote.
        let mut ep = Some(AZURITE_ENDPOINT.to_string());
        cleanup_stale_endpoint(
            &mut ep,
            Some(AZURITE_ACCOUNT),
            Some(&prev_sas),
            false,
            false,
            true,
        );
        assert_eq!(ep.as_deref(), Some(AZURITE_ENDPOINT));

        // Interactive full-URL SAS selection (`sas_derived_endpoint = true`) preserves derived endpoint.
        let mut ep = Some("https://newacct.blob.core.windows.net".to_string());
        cleanup_stale_endpoint(
            &mut ep,
            Some("newacct"),
            Some(&prev_sas),
            false,
            true,
            false,
        );
        assert_eq!(
            ep.as_deref(),
            Some("https://newacct.blob.core.windows.net")
        );

        // Interactive bare `?sv=...` SAS selection (`sas_derived_endpoint = false`) clears stale endpoint on account change.
        let mut ep = Some(AZURITE_ENDPOINT.to_string());
        let mut prev_az = AzureblobRemoteConfig::new();
        prev_az.account = Some(AZURITE_ACCOUNT.to_string());
        prev_az.endpoint = Some(AZURITE_ENDPOINT.to_string());
        cleanup_stale_endpoint(
            &mut ep,
            Some("prodacct"),
            Some(&prev_az),
            false,
            false,
            false,
        );
        assert_eq!(ep, None);
    }

    #[test]
    fn handle_auth_bare_sas_token_requires_account_or_endpoint() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // 1. Bare ?sv=... without --account or --endpoint must fail with a config error.
        let err = handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-noacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=abc".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--account") && msg.contains("--endpoint"),
            "unexpected bare SAS error: {msg}"
        );
        assert!(
            !ctx.app_cfg.remotes.contains_key("az-bare-noacct"),
            "must not save remote on bare SAS validation failure"
        );

        // 2. Bare ?sv=... with --endpoint (and no --account) succeeds and preserves custom endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-ep-only".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=abc".to_string()),
                endpoint: Some("https://custom.proxy.example".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(saved) = ctx.app_cfg.remotes.get("az-bare-ep-only").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(saved.account, None);
        assert_eq!(
            saved.endpoint.as_deref(),
            Some("https://custom.proxy.example")
        );

        // 3. Clearing --account (`-`) while switching from public Azure remote to bare ?sv=...
        //    clears the stale public endpoint and rejects missing account/endpoint.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-cleared".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("OLDKEY==".to_string()),
                endpoint: Some("https://oldacct.blob.core.windows.net".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let err = handle_auth(
            AzureblobAuthArgs {
                remote: Some("az-bare-cleared".to_string()),
                account: Some("-".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=new".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap_err();
        assert!(err.to_string().contains("--account"));
    }

    #[test]
    fn handle_auth_non_sas_sovereign_endpoints_clear_on_account_change_and_preserve_on_same_account()
    {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        for (name, old_acct, endpoint, switch_bare_sas) in [
            (
                "sk-china",
                "chinaacct",
                "https://chinaacct.blob.core.chinacloudapi.cn",
                true,
            ),
            (
                "sk-gov",
                "govacct",
                "https://GovAcct.BLOB.CORE.USGOVCLOUDAPI.NET/",
                false,
            ),
            (
                "sk-de",
                "deacct",
                "https://deacct.blob.core.cloudapi.de",
                false,
            ),
        ] {
            handle_auth(
                AzureblobAuthArgs {
                    remote: Some(name.to_string()),
                    account: Some(old_acct.to_string()),
                    key: Some("OLDKEY==".to_string()),
                    endpoint: Some(endpoint.to_string()),
                    ..Default::default()
                },
                &mut ctx,
            )
            .unwrap();

            // Same-account key rotation must preserve the sovereign endpoint.
            handle_auth(
                AzureblobAuthArgs {
                    remote: Some(name.to_string()),
                    key: Some("ROTATEDKEY==".to_string()),
                    ..Default::default()
                },
                &mut ctx,
            )
            .unwrap();
            let RemoteConfig::Azureblob(same_saved) = ctx.app_cfg.remotes.get(name).unwrap() else {
                panic!("expected Azureblob remote");
            };
            assert_eq!(same_saved.endpoint.as_deref(), Some(endpoint));

            // Switching to a different account must clear the old account-coupled sovereign endpoint.
            let switch_args = if switch_bare_sas {
                AzureblobAuthArgs {
                    remote: Some(name.to_string()),
                    account: Some("newacct".to_string()),
                    sas_url: Some("?sv=2023-01-01&sig=new".to_string()),
                    ..Default::default()
                }
            } else {
                AzureblobAuthArgs {
                    remote: Some(name.to_string()),
                    account: Some("newacct".to_string()),
                    key: Some("NEWKEY==".to_string()),
                    ..Default::default()
                }
            };
            handle_auth(switch_args, &mut ctx).unwrap();
            let RemoteConfig::Azureblob(diff_saved) = ctx.app_cfg.remotes.get(name).unwrap() else {
                panic!("expected Azureblob remote");
            };
            assert_eq!(diff_saved.account.as_deref(), Some("newacct"));
            assert_eq!(diff_saved.endpoint, None, "stale sovereign endpoint for `{name}`");
        }

        // Non-account-coupled custom proxy endpoint must still be preserved on account change.
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("sk-proxy".to_string()),
                account: Some("oldacct".to_string()),
                key: Some("OLDKEY==".to_string()),
                endpoint: Some("https://custom.proxy.example".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        handle_auth(
            AzureblobAuthArgs {
                remote: Some("sk-proxy".to_string()),
                account: Some("newacct".to_string()),
                sas_url: Some("?sv=2023-01-01&sig=new".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Azureblob(proxy_saved) = ctx.app_cfg.remotes.get("sk-proxy").unwrap()
        else {
            panic!("expected Azureblob remote");
        };
        assert_eq!(proxy_saved.account.as_deref(), Some("newacct"));
        assert_eq!(
            proxy_saved.endpoint.as_deref(),
            Some("https://custom.proxy.example")
        );
    }

    #[test]
    fn should_prompt_sas_account_triggers_only_for_bare_sas_or_missing_account() {
        let bare = prompt::SecretOutcome::Value("?sv=2023-01-01&sig=new".to_string());
        let full = prompt::SecretOutcome::Value(
            "https://newacct.blob.core.windows.net/cont?sv=2023-01-01&sig=new".to_string(),
        );
        let keep = prompt::SecretOutcome::KeepExisting;

        // Switching an existing Azurite / path-style / VH remote to a bare ?sv=... must prompt account.
        assert!(should_prompt_sas_account(
            &bare,
            None,
            Some(AZURITE_ACCOUNT),
            Some(AZURITE_ENDPOINT),
        ));
        assert!(should_prompt_sas_account(
            &bare,
            Some("http://127.0.0.1:14754/oldacct/oldcont?sv=2023-01-01&sig=old"),
            Some("oldacct"),
            Some("http://127.0.0.1:14754/oldacct"),
        ));

        // Entering a full SAS URL with extracted account/endpoint must NOT prompt an extra account line.
        assert!(!should_prompt_sas_account(
            &full,
            Some("https://oldacct.blob.core.windows.net/oldcont?sv=2023-01-01&sig=old"),
            Some("newacct"),
            Some("https://newacct.blob.core.windows.net"),
        ));

        // Keeping an existing bare SAS prompts account; keeping an existing full SAS does not.
        assert!(should_prompt_sas_account(
            &keep,
            Some("?sv=2023-01-01&sig=old"),
            Some("oldacct"),
            None,
        ));
        assert!(!should_prompt_sas_account(
            &keep,
            Some("https://oldacct.blob.core.windows.net/oldcont?sv=2023-01-01&sig=old"),
            Some("oldacct"),
            Some("https://oldacct.blob.core.windows.net"),
        ));

        // Keeping a keyring-backed SAS prompts account when endpoint is absent, not when full metadata is present.
        assert!(should_prompt_sas_account(
            &keep,
            Some("keyring://rship/test.sas_url"),
            Some("oldacct"),
            None,
        ));
        assert!(!should_prompt_sas_account(
            &keep,
            Some("keyring://rship/test.sas_url"),
            Some("oldacct"),
            Some("https://oldacct.blob.core.windows.net"),
        ));

        // Missing account always prompts.
        assert!(should_prompt_sas_account(
            &keep,
            Some("keyring://rship/test.sas_url"),
            None,
            Some("https://custom.proxy.example"),
        ));
    }
}
