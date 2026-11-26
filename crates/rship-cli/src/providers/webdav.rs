//! WebDAV [`ProviderAdapter`] and interactive `rship auth webdav` handler
//! (Nextcloud, OwnCloud, Alist, Synology NAS, InfiniCloud, generic).

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::webdav::WebdavVendor;
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;

use crate::cli::WebdavAuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, RemoteConfig, WebdavRemoteConfig};
use rship::secrets::{delete_secret_if_ref, is_keyring_ref, resolve_secret, store_secret};

use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    cleanup_remote_keyring_secrets_with, clear_secret_opt, merge_flag_secret,
    migrate_remote_secrets_with,
};

pub struct WebdavAdapter;

const WEBDAV_VENDORS: &[(WebdavVendor, &str, &str)] = &[
    (
        WebdavVendor::Nextcloud,
        "Nextcloud",
        "Supports Chunked Upload v2 (`https://cloud.example.com/remote.php/dav/files/<user>`)",
    ),
    (
        WebdavVendor::Owncloud,
        "OwnCloud",
        "Supports Chunked Upload v2 (`https://cloud.example.com/remote.php/dav/files/<user>`)",
    ),
    (
        WebdavVendor::Alist,
        "Alist / OpenList",
        "Alist WebDAV gateway (`https://alist.example.com/dav`)",
    ),
    (
        WebdavVendor::Synology,
        "Synology NAS",
        "DSM WebDAV Server (`https://nas.example.com:5006`)",
    ),
    (
        WebdavVendor::Infinicloud,
        "InfiniCloud",
        "InfiniCloud / TeraCLOUD (`https://<server>.teracloud.jp/dav/`)",
    ),
    (
        WebdavVendor::Generic,
        "Generic RFC 4918 WebDAV",
        "Any standard WebDAV server",
    ),
];

fn vendor_url_hint(vendor: WebdavVendor) -> &'static str {
    match vendor {
        WebdavVendor::Nextcloud | WebdavVendor::Owncloud => {
            "Example: https://cloud.example.com/remote.php/dav/files/<username>"
        }
        WebdavVendor::Alist => "Example: https://alist.example.com/dav",
        WebdavVendor::Synology => "Example: https://nas.example.com:5006",
        WebdavVendor::Infinicloud => "Example: https://<server>.teracloud.jp/dav/",
        WebdavVendor::Generic => "Example: https://dav.example.com/files",
    }
}

pub(super) fn handle_auth(args: WebdavAuthArgs, ctx: &mut AuthContext<'_>) -> Result<AuthOutcome> {
    let any_config_flag = args.url.is_some()
        || args.vendor.is_some()
        || args.username.is_some()
        || args.password.is_some()
        || args.bearer_token.is_some()
        || args.chunked_upload_root.is_some();

    let default_name = args.vendor.as_deref().unwrap_or("webdav");
    let mut wiz = PromptWizard::begin(args.remote, default_name, "webdav", any_config_flag, ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Webdav(w)) => Some((**w).clone()),
        _ => None,
    };

    wiz.section(
        &format!("Configure WebDAV remote `{}`", wiz.remote),
        existing.is_some(),
        "Editing existing remote — press Enter to keep current values",
        "Select WebDAV server vendor, base URL, and credentials",
    );

    // 1. Vendor
    let existing_v = existing
        .as_ref()
        .and_then(|w| w.vendor.as_deref())
        .and_then(WebdavVendor::parse);
    let parsed_vendor = wiz.select_flag_or_menu(
        "WebDAV server vendor",
        args.vendor.as_deref(),
        WebdavVendor::parse,
        |raw| {
            anyhow::anyhow!(
                "unknown WebDAV vendor `{raw}` (supported: nextcloud, owncloud, alist, synology, infinicloud, generic)"
            )
        },
        WEBDAV_VENDORS,
        existing_v.unwrap_or(WebdavVendor::Nextcloud),
        existing_v.unwrap_or(WebdavVendor::Generic),
    )?;

    // 2. URL
    let existing_url = existing
        .as_ref()
        .map(|w| w.url.as_str())
        .filter(|u| !u.is_empty());
    let url = wiz.required_text_validated(
        "WebDAV base URL",
        args.url,
        existing_url,
        Some(vendor_url_hint(parsed_vendor)),
        &format!(
            "missing `--url <URL>` for WebDAV remote `{}` (run interactively in a terminal or pass `--url`)",
            wiz.remote
        ),
        |v| {
            if v.starts_with("http://") || v.starts_with("https://") {
                Ok(())
            } else {
                Err("URL must start with `https://` or `http://`".to_string())
            }
        },
    )?;

    // 3. Authentication
    let mut username = args
        .username
        .clone()
        .or_else(|| existing.as_ref().and_then(|w| w.username.clone()));
    let mut password = merge_flag_secret(
        args.password.clone(),
        existing.as_ref().and_then(|w| w.password.as_deref()),
    )?;
    let mut bearer_token = merge_flag_secret(
        args.bearer_token.clone(),
        existing.as_ref().and_then(|w| w.bearer_token.as_deref()),
    )?;

    let auth_flag_passed =
        args.username.is_some() || args.password.is_some() || args.bearer_token.is_some();

    if wiz.full_wizard {
        let def_auth = if bearer_token.is_some() {
            1
        } else if existing.is_some() && username.is_none() && password.is_none() {
            2
        } else {
            0
        };
        let auth_items = [
            SelectItem::new("Username & Password (HTTP Basic Auth)").with_desc(
                "Standard for Nextcloud/OwnCloud app passwords, Alist, Synology, InfiniCloud",
            ),
            SelectItem::new("Bearer Token").with_desc("Authorization: Bearer <token>"),
            SelectItem::new("No authentication")
                .with_desc("Public / unauthenticated WebDAV endpoint"),
        ];
        match prompt::select("Authentication method", &auth_items, def_auth)? {
            0 => {
                bearer_token = clear_secret_opt(bearer_token.as_deref());
                username = prompt::text("Username", username.as_deref(), None, true)?;
                let pw_hint = if parsed_vendor.supports_chunked_v2() {
                    Some("Tip: Use an App Password if 2FA is enabled on Nextcloud/OwnCloud")
                } else {
                    None
                };
                password = wiz.prompt_secret("Password", password.as_deref(), true, pw_hint)?;
            }
            1 => {
                username = None;
                password = clear_secret_opt(password.as_deref());
                bearer_token =
                    wiz.prompt_secret("Bearer token", bearer_token.as_deref(), true, None)?;
            }
            _ => {
                username = None;
                password = clear_secret_opt(password.as_deref());
                bearer_token = clear_secret_opt(bearer_token.as_deref());
            }
        }
    } else if wiz.ctx.interactive
        && args.username.is_some()
        && password.is_none()
        && bearer_token.is_none()
    {
        password = wiz.prompt_secret("Password", password.as_deref(), true, None)?;
    } else if !wiz.ctx.interactive
        && args.username.is_some()
        && password.is_none()
        && bearer_token.is_none()
    {
        return Err(config_err(format!(
            "missing `--password` for WebDAV Basic Auth remote `{}` (run interactively in a terminal or pass `--password`)",
            wiz.remote
        )));
    } else if auth_flag_passed {
        if args.bearer_token.is_some() && args.username.is_none() && args.password.is_none() {
            username = None;
            password = clear_secret_opt(password.as_deref());
        } else if (args.username.is_some() || args.password.is_some())
            && args.bearer_token.is_none()
        {
            bearer_token = clear_secret_opt(bearer_token.as_deref());
        }
    }

    // 4. Optional Nextcloud/OwnCloud custom chunked upload root
    let mut chunked_upload_root = if !parsed_vendor.supports_chunked_v2() {
        None
    } else {
        args.chunked_upload_root.or_else(|| {
            existing
                .as_ref()
                .and_then(|w| w.chunked_upload_root.clone())
        })
    };
    if wiz.full_wizard
        && parsed_vendor.supports_chunked_v2()
        && prompt::confirm(
            "Customize Nextcloud/OwnCloud chunked upload URL?",
            chunked_upload_root.is_some(),
        )?
    {
        chunked_upload_root = prompt::text(
            "Chunked upload root URL",
            chunked_upload_root.as_deref(),
            Some("Usually auto-derived as /remote.php/dav/uploads/<user>"),
            false,
        )?;
    } else if wiz.full_wizard && parsed_vendor.supports_chunked_v2() {
        chunked_upload_root = None;
    }

    let mut wcfg = WebdavRemoteConfig::new(url).with_vendor(parsed_vendor.as_str());
    wcfg.username = username;
    wcfg.password = password;
    wcfg.bearer_token = bearer_token;
    wcfg.bearer_token_command = existing
        .as_ref()
        .and_then(|w| w.bearer_token_command.clone());
    wcfg.headers = existing
        .as_ref()
        .map(|w| w.headers.clone())
        .unwrap_or_default();
    wcfg.chunked_upload_root = chunked_upload_root;

    let msg = format!(
        "configured WebDAV remote `{}` (vendor={}) in {}",
        wiz.remote,
        parsed_vendor.as_str(),
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(wcfg.into(), &msg)
}

pub(super) fn migrate_webdav_secrets_with<S>(
    remote_name: &str,
    cfg: &mut RemoteConfig,
    mut store_fn: S,
) -> Result<usize>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
{
    let mut count = migrate_remote_secrets_with(remote_name, cfg, &mut store_fn)?;
    if let RemoteConfig::Webdav(wcfg) = cfg {
        for (idx, (name, val)) in wcfg.headers.iter_mut().enumerate() {
            if !val.trim().is_empty() && !is_keyring_ref(val) {
                let safe_name: String = name
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                let slot = format!("{remote_name}.header.{idx}.{safe_name}");
                *val = store_fn(&slot, val)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

pub(super) fn cleanup_webdav_secrets_with<D>(cfg: &RemoteConfig, mut delete_fn: D)
where
    D: FnMut(&str),
{
    cleanup_remote_keyring_secrets_with(cfg, &mut delete_fn);
    if let RemoteConfig::Webdav(wcfg) = cfg {
        for (_, val) in &wcfg.headers {
            delete_fn(val);
        }
    }
}

fn resolve_webdav_bundle_secrets_with<R>(
    wcfg: &WebdavRemoteConfig,
    mut resolve_fn: R,
) -> Result<WebdavRemoteConfig>
where
    R: FnMut(&str) -> rship_core::Result<String>,
{
    let mut resolved = wcfg.clone();
    resolved.password = resolved
        .password
        .as_deref()
        .map(&mut resolve_fn)
        .transpose()?;
    resolved.bearer_token = resolved
        .bearer_token
        .as_deref()
        .map(&mut resolve_fn)
        .transpose()?;
    resolved.bearer_token_command = resolved
        .bearer_token_command
        .as_deref()
        .map(&mut resolve_fn)
        .transpose()?;
    for (_, val) in &mut resolved.headers {
        *val = resolve_fn(val)?;
    }
    Ok(resolved)
}

#[async_trait]
impl ProviderAdapter for WebdavAdapter {
    fn kind(&self) -> &'static str {
        "webdav"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("webdav")
    }

    fn migrate_secrets(&self, remote_name: &str, cfg: &mut RemoteConfig) -> Result<usize> {
        migrate_webdav_secrets_with(remote_name, cfg, store_secret)
    }

    fn cleanup_secrets(&self, _remote_name: &str, cfg: &RemoteConfig, _paths: &AppPaths) {
        cleanup_webdav_secrets_with(cfg, delete_secret_if_ref);
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Webdav(_)).then(RelPath::root)
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
        let RemoteConfig::Webdav(wcfg) = cfg else {
            bail!("internal mismatch: expected Webdav remote config");
        };
        let resolved = resolve_webdav_bundle_secrets_with(wcfg, resolve_secret)?;
        PortableBundle::export_config(remote, "webdav", &resolved, as_json)
    }

    fn import_bundle(
        &self,
        _remote_name: &str,
        bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let wcfg: WebdavRemoteConfig = bundle.deserialize_config("webdav")?;
        Ok(RemoteConfig::Webdav(Box::new(wcfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use rship::secrets::KEYRING_PREFIX;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn handle_auth_preserves_headers_and_bearer_token_command_across_edit() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "dav".to_string(),
            WebdavRemoteConfig::new("https://dav.example/old")
                .with_vendor("nextcloud")
                .with_bearer_token("tok")
                .with_bearer_token_command("pass show dav")
                .with_header("X-Custom", "secret-hdr")
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            WebdavAuthArgs {
                remote: Some("dav".to_string()),
                url: Some("https://dav.example/new".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::Webdav(saved) = cfg.remotes.get("dav").unwrap() else {
            panic!("expected Webdav");
        };
        assert_eq!(saved.url, "https://dav.example/new");
        assert_eq!(
            saved.bearer_token_command.as_deref(),
            Some("pass show dav")
        );
        assert_eq!(
            saved.headers,
            vec![("X-Custom".to_string(), "secret-hdr".to_string())]
        );
    }

    #[test]
    fn webdav_keyring_migration_cleanup_and_bundle_resolution_handle_headers_and_command() {
        let store: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        let mut cfg = RemoteConfig::Webdav(Box::new(
            WebdavRemoteConfig::new("https://dav.example")
                .with_password("pw-1")
                .with_bearer_token_command("cmd-secret")
                .with_header("Authorization-Extra", "hdr-val"),
        ));

        let migrated = migrate_webdav_secrets_with("dav", &mut cfg, |slot, val| {
            store
                .borrow_mut()
                .insert(slot.to_string(), val.to_string());
            Ok(format!("{KEYRING_PREFIX}{slot}"))
        })
        .unwrap();
        assert_eq!(migrated, 3);
        assert_eq!(
            store
                .borrow()
                .get("dav.bearer_token_command")
                .map(String::as_str),
            Some("cmd-secret")
        );
        assert_eq!(
            store
                .borrow()
                .get("dav.header.0.Authorization-Extra")
                .map(String::as_str),
            Some("hdr-val")
        );

        let RemoteConfig::Webdav(ref wcfg) = cfg else {
            panic!("expected Webdav");
        };
        let resolved = resolve_webdav_bundle_secrets_with(wcfg, |raw| {
            if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX) {
                Ok(store.borrow().get(slot).cloned().unwrap())
            } else {
                Ok(raw.to_string())
            }
        })
        .unwrap();
        assert_eq!(resolved.password.as_deref(), Some("pw-1"));
        assert_eq!(
            resolved.bearer_token_command.as_deref(),
            Some("cmd-secret")
        );
        assert_eq!(
            resolved.headers,
            vec![("Authorization-Extra".to_string(), "hdr-val".to_string())]
        );

        cleanup_webdav_secrets_with(&cfg, |raw| {
            if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX) {
                store.borrow_mut().remove(slot);
            }
        });
        assert!(store.borrow().is_empty());
    }
}
