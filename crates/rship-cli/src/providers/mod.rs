//! Trait-based Provider Adapter Registry with per-backend Cargo feature gates.
//!
//! Adding a new cloud provider requires:
//! 1. Adding a feature-gated module `crates/rship-backends/src/<name>/` implementing `StorageBackend`.
//! 2. Wiring its config and factory builder once in `crates/rship` (`config.rs`, `factory.rs`).
//! 3. Adding a self-contained adapter module `providers/<name>.rs` implementing [`ProviderAdapter`]
//!    and its `handle_auth` CLI handler.
//! 4. Adding a single entry to [`define_provider_registry!`] below.
//!
//! Every CLI workflow (`gc`, `keyring-migrate`, `config rm` cleanup, `auth export/import`, and
//! `config import-rclone`) dispatches generically through [`registered_providers`], while backend
//! resolution delegates directly to [`rship::RshipClient`].

#![cfg_attr(not(feature = "all-backends"), allow(dead_code, unused_imports))]

mod bundle;
mod filters;
mod oauth;
mod wizard;

use anyhow::Result;
use async_trait::async_trait;
use rship::config::{AppConfig, AppPaths, RemoteConfig, save_config};
use rship::secrets::{KEYRING_PREFIX, delete_secret_if_ref, is_keyring_ref, store_secret};
use rship_core::path::{RelPath, is_valid_remote_name};
use rship_core::state::{DeltaInventoryStore, OperationRecord};
use rship_transport::HttpTransport;
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::{
    AuthAction, AzureblobAuthArgs, CryptAuthArgs, DropboxAuthArgs, GcsAuthArgs, GdriveAuthArgs,
    LocalAuthArgs, OnedriveAuthArgs, S3AuthArgs, SftpAuthArgs, WebdavAuthArgs,
};
use crate::errors::{cancelled_err, config_err, unsupported_err};
use crate::ops::config_ops::{PostSaveAction, handle_auth_keyring_migrate, post_save_interactive};
use crate::ops::{TransportOverrides, build_transport};
use crate::prompt::{self, SecretOutcome};

pub use bundle::{PortableBundle, export_remote_bundle, import_rclone_all, import_remote_bundle};
pub use filters::{build_filter_options_with_profile, join_raw_prefix, strip_prefix_raw};

macro_rules! define_provider_registry {
    ($(
        $kind:literal => {
            feature: $feat:literal,
            module: $mod_name:ident,
            adapter: $adapter:ident,
            action: $variant:ident($args:ident),
            mode: $mode:tt,
        }
    ),* $(,)?) => {
        $(
            #[cfg(feature = $feat)]
            mod $mod_name;
        )*

        /// Return all providers enabled in this build.
        pub fn registered_providers() -> Vec<&'static dyn ProviderAdapter> {
            [
                $(
                    {
                        #[cfg(feature = $feat)]
                        {
                            Some(&$mod_name::$adapter as &'static dyn ProviderAdapter)
                        }
                        #[cfg(not(feature = $feat))]
                        {
                            None
                        }
                    },
                )*
            ]
            .into_iter()
            .flatten()
            .collect()
        }

        fn build_wizard_action(
            kind: &str,
            remote: Option<String>,
            oauth_prefs: Option<(bool, bool, Option<u16>)>,
        ) -> Option<AuthAction> {
            match kind {
                $(
                    $kind => Some(define_provider_registry!(
                        @make_action $mode, $variant, $args, remote, oauth_prefs
                    )),
                )*
                _ => None,
            }
        }

        async fn dispatch_provider_auth(
            action: AuthAction,
            ctx: &mut AuthContext<'_>,
        ) -> Result<AuthOutcome> {
            let _ = &*ctx;
            match action {
                $(
                    AuthAction::$variant(args) => {
                        define_provider_registry!(@save_oauth $mode, args, ctx);
                        #[cfg(feature = $feat)]
                        {
                            define_provider_registry!(@call $mode, $mod_name, args, ctx)
                        }
                        #[cfg(not(feature = $feat))]
                        {
                            let _ = args;
                            Err(disabled_provider_err($kind))
                        }
                    }
                )*
                AuthAction::KeyringMigrate | AuthAction::Export { .. } | AuthAction::Import { .. } => {
                    unreachable!()
                }
            }
        }
    };

    (@make_action oauth_async, $variant:ident, $args:ident, $remote:expr, $prefs:expr) => {{
        let (no_browser, manual, callback_port) = $prefs.unwrap_or((false, false, None));
        AuthAction::$variant($args {
            remote: $remote,
            no_browser,
            manual,
            callback_port,
            ..Default::default()
        })
    }};
    (@make_action sync, $variant:ident, $args:ident, $remote:expr, $_prefs:expr) => {
        AuthAction::$variant($args {
            remote: $remote,
            ..Default::default()
        })
    };

    (@save_oauth oauth_async, $args:expr, $ctx:expr) => {
        $ctx.oauth_no_browser = $args.no_browser;
        $ctx.oauth_manual = $args.manual;
        $ctx.oauth_callback_port = $args.callback_port;
    };
    (@save_oauth sync, $_args:expr, $_ctx:expr) => {};

    (@call oauth_async, $mod_name:ident, $args:expr, $ctx:expr) => {
        $mod_name::handle_auth($args, $ctx).await
    };
    (@call sync, $mod_name:ident, $args:expr, $ctx:expr) => {
        $mod_name::handle_auth($args, $ctx)
    };
}

define_provider_registry! {
    "local" => {
        feature: "backend-local",
        module: local,
        adapter: LocalAdapter,
        action: Local(LocalAuthArgs),
        mode: sync,
    },
    "gdrive" => {
        feature: "backend-gdrive",
        module: gdrive,
        adapter: GdriveAdapter,
        action: Gdrive(GdriveAuthArgs),
        mode: oauth_async,
    },
    "s3" => {
        feature: "backend-s3",
        module: s3,
        adapter: S3Adapter,
        action: S3(S3AuthArgs),
        mode: sync,
    },
    "onedrive" => {
        feature: "backend-onedrive",
        module: onedrive,
        adapter: OnedriveAdapter,
        action: Onedrive(OnedriveAuthArgs),
        mode: oauth_async,
    },
    "webdav" => {
        feature: "backend-webdav",
        module: webdav,
        adapter: WebdavAdapter,
        action: Webdav(WebdavAuthArgs),
        mode: sync,
    },
    "sftp" => {
        feature: "backend-sftp",
        module: sftp,
        adapter: SftpAdapter,
        action: Sftp(SftpAuthArgs),
        mode: sync,
    },
    "dropbox" => {
        feature: "backend-dropbox",
        module: dropbox,
        adapter: DropboxAdapter,
        action: Dropbox(DropboxAuthArgs),
        mode: oauth_async,
    },
    "gcs" => {
        feature: "backend-gcs",
        module: gcs,
        adapter: GcsAdapter,
        action: Gcs(GcsAuthArgs),
        mode: oauth_async,
    },
    "azureblob" => {
        feature: "backend-azureblob",
        module: azureblob,
        adapter: AzureblobAdapter,
        action: Azureblob(AzureblobAuthArgs),
        mode: sync,
    },
    "crypt" => {
        feature: "backend-crypt",
        module: crypt,
        adapter: CryptAdapter,
        action: Crypt(CryptAuthArgs),
        mode: sync,
    },
}

/// Shared context passed into `rship auth` and `rship config new/edit` handlers.
pub struct AuthContext<'a> {
    pub paths: &'a AppPaths,
    pub app_cfg: &'a mut AppConfig,
    pub t_opts: &'a TransportOverrides,
    pub interactive: bool,
    /// When `true` (`rship config new/edit` or post-test retry), run the full interactive
    /// wizard pre-populated with any existing remote fields as defaults.
    pub force_wizard: bool,
    /// When `true` (`rship config new`), ask for confirmation before overwriting an existing remote.
    pub confirm_overwrite: bool,
    /// Preserved OAuth session preferences across post-test retry-edit iterations.
    pub oauth_no_browser: bool,
    pub oauth_manual: bool,
    pub oauth_callback_port: Option<u16>,
    pub runtime_options: rship::RuntimeOptions,
    transport: Option<HttpTransport>,
}

impl<'a> AuthContext<'a> {
    pub fn new(
        paths: &'a AppPaths,
        app_cfg: &'a mut AppConfig,
        t_opts: &'a TransportOverrides,
        interactive: bool,
    ) -> Self {
        Self {
            paths,
            app_cfg,
            t_opts,
            interactive,
            force_wizard: false,
            confirm_overwrite: false,
            oauth_no_browser: false,
            oauth_manual: false,
            oauth_callback_port: None,
            runtime_options: rship::RuntimeOptions::default(),
            transport: None,
        }
    }

    pub fn with_runtime_options(mut self, opts: rship::RuntimeOptions) -> Self {
        self.runtime_options = opts;
        self
    }

    pub fn with_force_wizard(mut self, force: bool) -> Self {
        self.force_wizard = force;
        self
    }

    pub fn with_confirm_overwrite(mut self, confirm: bool) -> Self {
        self.confirm_overwrite = confirm;
        self
    }

    pub fn transport(&mut self) -> Result<&HttpTransport> {
        if self.transport.is_none() {
            self.transport = Some(build_transport(self.t_opts)?);
        }
        Ok(self.transport.as_ref().expect("transport initialized"))
    }
}

/// Outcome reported by an individual provider auth handler so `handle_auth` can run
/// shared live connectivity verification when interactive.
#[derive(Debug)]
pub(super) struct AuthOutcome {
    pub remote: String,
    pub did_prompt: bool,
}

/// Validate or interactively prompt for a logical remote name.
///
/// When `ctx.confirm_overwrite && ctx.interactive`, prompts for confirmation if the chosen
/// remote name already exists so `rship config new` never silently clobbers another remote.
pub(super) fn resolve_remote_name(
    arg: Option<String>,
    default_name: &str,
    ctx: &AuthContext<'_>,
    provider_kind: &str,
) -> Result<(String, bool)> {
    if let Some(name) = arg {
        if !is_valid_remote_name(&name) {
            return Err(config_err(format!(
                "invalid remote name `{name}` (must be >= 2 chars, [A-Za-z0-9_-])"
            )));
        }
        if ctx.confirm_overwrite
            && ctx.interactive
            && let Some(prev) = ctx.app_cfg.remotes.get(&name)
            && !prompt::confirm(
                &format!(
                    "Remote `{name}` ({}) already exists — overwrite it?",
                    prev.kind_str()
                ),
                false,
            )?
        {
            return Err(cancelled_err("cancelled by user"));
        }
        return Ok((name, false));
    }
    if !ctx.interactive {
        return Err(config_err(format!(
            "missing remote name (usage: `rship auth {provider_kind} <REMOTE>` or run interactively in a terminal)"
        )));
    }
    loop {
        let name = prompt::text_validated_required(
            "Remote name",
            Some(default_name),
            Some("2+ characters: letters, digits, `_`, or `-`"),
            |v| {
                if is_valid_remote_name(v) {
                    Ok(())
                } else {
                    Err(format!(
                        "invalid remote name `{v}` (must be >= 2 chars, [A-Za-z0-9_-])"
                    ))
                }
            },
        )?;
        if ctx.confirm_overwrite
            && let Some(prev) = ctx.app_cfg.remotes.get(&name)
            && !prompt::confirm(
                &format!(
                    "Remote `{name}` ({}) already exists — overwrite it?",
                    prev.kind_str()
                ),
                false,
            )?
        {
            continue;
        }
        return Ok((name, true));
    }
}

/// Persist `new_cfg` under `remote`:
/// 1. Cleans up superseded keyring entries & sidecar files if replacing a remote of a *different*
///    provider kind (preventing orphaned credentials).
/// 2. In interactive mode (when prompted), offers OS Keyring migration **in memory BEFORE**
///    writing `config.toml` so plaintext secrets never hit disk when Keyring storage is chosen.
/// 3. Atomically writes `config.toml` (`0o600` on Unix).
pub(super) fn persist_remote(
    remote: &str,
    mut new_cfg: RemoteConfig,
    did_prompt: bool,
    ctx: &mut AuthContext<'_>,
) -> Result<()> {
    if let Some(prev) = ctx.app_cfg.remotes.get(remote)
        && prev.kind_str() != new_cfg.kind_str()
    {
        cleanup_remote_secrets(remote, prev, ctx.paths);
    }

    if ctx.interactive
        && did_prompt
        && crate::ops::config_ops::count_remote_inline_secrets(&new_cfg) > 0
        && prompt::confirm(
            "Store secret(s) in OS Keyring instead of plaintext config.toml?",
            true,
        )?
    {
        let kind = new_cfg.kind_str();
        if let Ok(adapter) = find_adapter(kind) {
            match adapter.migrate_secrets(remote, &mut new_cfg) {
                Ok(n) if n > 0 => {
                    prompt::ok(&format!(
                        "Stored {n} secret(s) for `{remote}` in OS Keyring"
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    prompt::warn(&format!(
                        "OS Keyring unavailable ({e}); keeping secrets in config.toml (0600)"
                    ));
                }
            }
        }
    }

    ctx.app_cfg.remotes.insert(remote.to_string(), new_cfg);
    save_config(&ctx.paths.config_file, ctx.app_cfg)?;
    Ok(())
}

/// Testable seam for secret rotation/cleanup without touching the real OS keyring.
pub(super) fn preserve_or_rotate_secret_with<S, D>(
    new_val: Option<String>,
    existing: Option<&str>,
    mut store_fn: S,
    mut delete_fn: D,
) -> Result<Option<String>>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
    D: FnMut(&str),
{
    match (new_val, existing) {
        (Some(v), Some(prev))
            if !v.trim().is_empty() && !is_keyring_ref(&v) && prev.starts_with(KEYRING_PREFIX) =>
        {
            let slot = &prev[KEYRING_PREFIX.len()..];
            Ok(Some(store_fn(slot, &v)?))
        }
        (None, Some(prev)) => {
            delete_fn(prev);
            Ok(None)
        }
        (other, _) => Ok(other),
    }
}

pub(super) fn apply_secret_outcome_with<S, D>(
    outcome: SecretOutcome,
    existing: Option<&str>,
    store_fn: S,
    delete_fn: D,
) -> Result<Option<String>>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
    D: FnMut(&str),
{
    match outcome {
        SecretOutcome::KeepExisting => Ok(existing.map(str::to_string)),
        SecretOutcome::Empty => preserve_or_rotate_secret_with(None, existing, store_fn, delete_fn),
        SecretOutcome::Value(new_val) => {
            preserve_or_rotate_secret_with(Some(new_val), existing, store_fn, delete_fn)
        }
    }
}

/// Apply an interactive [`SecretOutcome`] onto an existing optional secret field,
/// rotating in-place if the existing field is a `keyring://rship/<slot>` pointer.
pub(super) fn apply_secret_outcome(
    outcome: SecretOutcome,
    existing: Option<&str>,
) -> Result<Option<String>> {
    apply_secret_outcome_with(outcome, existing, store_secret, delete_secret_if_ref)
}

pub(super) fn merge_flag_secret_with<S, D>(
    flag_val: Option<String>,
    existing: Option<&str>,
    store_fn: S,
    delete_fn: D,
) -> Result<Option<String>>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
    D: FnMut(&str),
{
    let existing = existing.filter(|s| !s.trim().is_empty());
    match flag_val.filter(|s| !s.trim().is_empty()) {
        Some(new_val) => {
            preserve_or_rotate_secret_with(Some(new_val), existing, store_fn, delete_fn)
        }
        None => Ok(existing.map(str::to_string)),
    }
}

/// Merge an optional CLI flag secret onto an existing stored value without accidentally
/// wiping existing secrets when a flag is omitted on re-configuration.
pub(super) fn merge_flag_secret(
    flag_val: Option<String>,
    existing: Option<&str>,
) -> Result<Option<String>> {
    merge_flag_secret_with(flag_val, existing, store_secret, delete_secret_if_ref)
}

pub(super) fn clear_secret_opt_with<D>(existing: Option<&str>, mut delete_fn: D) -> Option<String>
where
    D: FnMut(&str),
{
    if let Some(prev) = existing {
        delete_fn(prev);
    }
    None
}

/// Explicitly clear a superseded secret field (removing any associated OS keyring entry).
pub(super) fn clear_secret_opt(existing: Option<&str>) -> Option<String> {
    clear_secret_opt_with(existing, delete_secret_if_ref)
}

/// Dispatch all `rship auth <subcommand>` actions directly into their owning provider modules,
/// running interactive Keyring & connectivity close-out whenever the wizard prompted the user.
pub async fn handle_auth(action: AuthAction, ctx: &mut AuthContext<'_>) -> Result<ExitCode> {
    match action {
        AuthAction::KeyringMigrate => handle_auth_keyring_migrate(ctx.paths, ctx.app_cfg),
        AuthAction::Export {
            remote,
            json,
            output,
        } => export_remote_bundle(&remote, json, output, ctx.paths, ctx.app_cfg),
        AuthAction::Import {
            input,
            bundle,
            name,
        } => import_remote_bundle(input, bundle, name, ctx.paths, ctx.app_cfg),
        AuthAction::Gdrive(args) if args.guide => {
            oauth::print_gdrive_oauth_guide(args.remote.as_deref().unwrap_or("gdrive"));
            Ok(ExitCode::SUCCESS)
        }
        provider_action => {
            let outcome = dispatch_provider_auth(provider_action, ctx).await?;
            finish_interactive_auth(outcome, ctx).await
        }
    }
}

/// Launch an interactive provider wizard by canonical provider kind (`rship config new/edit`).
pub async fn run_provider_wizard(
    kind: &str,
    remote_name: Option<&str>,
    ctx: &mut AuthContext<'_>,
) -> Result<ExitCode> {
    let action = build_wizard_action(kind, remote_name.map(str::to_string), None)
        .ok_or_else(|| config_err(format!("unknown storage provider `{kind}`")))?;
    let outcome = dispatch_provider_auth(action, ctx).await?;
    finish_interactive_auth(outcome, ctx).await
}

async fn finish_interactive_auth(
    mut outcome: AuthOutcome,
    ctx: &mut AuthContext<'_>,
) -> Result<ExitCode> {
    if !ctx.interactive || !outcome.did_prompt {
        return Ok(ExitCode::SUCCESS);
    }
    loop {
        match post_save_interactive(&outcome.remote, ctx).await? {
            PostSaveAction::Done => return Ok(ExitCode::SUCCESS),
            PostSaveAction::RetryEdit => {
                let Some(kind) = ctx
                    .app_cfg
                    .remotes
                    .get(&outcome.remote)
                    .map(|r| r.kind_str().to_string())
                else {
                    return Ok(ExitCode::SUCCESS);
                };
                ctx.force_wizard = true;
                ctx.confirm_overwrite = false;
                let Some(retry_action) = build_wizard_action(
                    kind.as_str(),
                    Some(outcome.remote.clone()),
                    Some((
                        ctx.oauth_no_browser,
                        ctx.oauth_manual,
                        ctx.oauth_callback_port,
                    )),
                ) else {
                    return Ok(ExitCode::SUCCESS);
                };
                outcome = dispatch_provider_auth(retry_action, ctx).await?;
            }
        }
    }
}

fn disabled_provider_err(kind: &str) -> anyhow::Error {
    unsupported_err(format!(
        "provider `{kind}` is not enabled in this build (recompile with `--features backend-{kind}`)"
    ))
}

/// Shared context passed to [`ProviderAdapter::abort_gc_operation`].
pub struct BuildContext<'a> {
    pub app_cfg: &'a AppConfig,
    pub paths: &'a AppPaths,
    pub transport: Option<&'a HttpTransport>,
    pub inventory: Option<Arc<dyn DeltaInventoryStore>>,
    pub allow_changes_feed: bool,
    pub runtime_options: &'a rship::RuntimeOptions,
}

impl<'a> BuildContext<'a> {
    pub(super) fn resolve_ctx(&self) -> rship::factory::ResolveContext<'_> {
        let mut ctx = rship::factory::ResolveContext::new(self.app_cfg, self.paths)
            .with_inventory(self.inventory.clone())
            .with_allow_changes_feed(self.allow_changes_feed)
            .with_runtime_options(self.runtime_options.clone());
        if let Some(t) = self.transport {
            ctx = ctx.with_transport(t);
        }
        ctx
    }
}

/// Shared best-effort GC upload-session abort helper across configured remotes whose
/// `sub_for_remote` closure yields a backend sub-path (typically `RelPath::root()` or
/// an extracted bucket name for bucketless S3/GCS remotes).
pub(super) async fn abort_gc_for_remotes<F>(
    ctx: &BuildContext<'_>,
    op: &OperationRecord,
    mut sub_for_remote: F,
) where
    F: FnMut(&RemoteConfig) -> Option<RelPath>,
{
    if op.session_token.is_none() {
        return;
    }
    let rctx = ctx.resolve_ctx();
    for (rname, rcfg) in &ctx.app_cfg.remotes {
        if let Some(sub) = sub_for_remote(rcfg)
            && let Ok((b, _)) = rship::factory::build_remote_backend(rname, rcfg, sub, &rctx)
            && b.endpoint_identity() == op.dst_endpoint
        {
            let _ = b.abort_upload(op).await;
            break;
        }
    }
}

/// Uniform self-describing adapter implemented by each compiled storage provider.
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    /// Canonical config type identifier (`"local"`, `"gdrive"`, `"s3"`, `"onedrive"`, `"webdav"`, `"sftp"`, `"crypt"`).
    fn kind(&self) -> &'static str;

    /// Corresponding `type = ...` string in `rclone.conf`, if supported.
    fn rclone_type(&self) -> Option<&'static str> {
        None
    }

    /// Migrate inline secrets to the OS Keyring; returns number of migrated fields.
    fn migrate_secrets(&self, remote_name: &str, cfg: &mut RemoteConfig) -> Result<usize> {
        migrate_remote_secrets(remote_name, cfg)
    }

    /// Delete any OS Keyring entries and sidecar token files when removing a remote.
    fn cleanup_secrets(&self, _remote_name: &str, cfg: &RemoteConfig, _paths: &AppPaths) {
        cleanup_remote_keyring_secrets(cfg);
    }

    /// Best-effort abort of a stale/orphaned upload session during `rship gc`.
    async fn abort_gc_operation(&self, _ctx: &BuildContext<'_>, _op: &OperationRecord) {}

    /// Export portable credentials for headless servers (`rship auth export`).
    fn export_bundle(
        &self,
        remote_name: &str,
        _cfg: &RemoteConfig,
        _paths: &AppPaths,
        _as_json: bool,
    ) -> Result<String> {
        Err(unsupported_err(format!(
            "remote `{remote_name}` ({}) does not support credential export",
            self.kind()
        )))
    }

    /// Import portable credentials into a `RemoteConfig` + any sidecar token/key files (`rship auth import`).
    fn import_bundle(
        &self,
        remote_name: &str,
        _bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        Err(unsupported_err(format!(
            "remote `{remote_name}` ({}) does not support credential import",
            self.kind()
        )))
    }
}

/// Look up an enabled [`ProviderAdapter`] by canonical `kind` (`"s3"`, `"gdrive"`, `"crypt"`, etc.).
/// Accepts legacy `"crypto"` as an alias for `"crypt"` so older `state.db` operations still resolve in `rship gc`.
pub fn find_adapter(kind: &str) -> Result<&'static dyn ProviderAdapter> {
    let canonical = if kind == "crypto" { "crypt" } else { kind };
    registered_providers()
        .into_iter()
        .find(|a| a.kind() == canonical)
        .ok_or_else(|| disabled_provider_err(canonical))
}

fn migrate_opt_with<S>(
    remote: &str,
    field_name: &str,
    field: &mut Option<String>,
    store_fn: &mut S,
) -> Result<usize>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
{
    if let Some(val) = field.as_ref()
        && !val.is_empty()
        && !is_keyring_ref(val)
    {
        let slot = format!("{remote}.{field_name}");
        let reference = store_fn(&slot, val)?;
        *field = Some(reference);
        return Ok(1);
    }
    Ok(0)
}

pub(super) fn migrate_remote_secrets_with<S>(
    remote_name: &str,
    cfg: &mut RemoteConfig,
    mut store_fn: S,
) -> Result<usize>
where
    S: FnMut(&str, &str) -> rship_core::Result<String>,
{
    let mut total = 0usize;
    let mut first_err: Option<anyhow::Error> = None;
    cfg.visit_secrets_mut(|field_name, field| {
        if first_err.is_none() {
            match migrate_opt_with(remote_name, field_name, field, &mut store_fn) {
                Ok(n) => total += n,
                Err(e) => first_err = Some(e),
            }
        }
    });
    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(total)
}

pub(super) fn migrate_remote_secrets(remote_name: &str, cfg: &mut RemoteConfig) -> Result<usize> {
    migrate_remote_secrets_with(remote_name, cfg, store_secret)
}

pub(super) fn cleanup_remote_keyring_secrets_with<D>(cfg: &RemoteConfig, mut delete_fn: D)
where
    D: FnMut(&str),
{
    cfg.visit_secrets(|_, field| {
        if let Some(val) = field.as_deref() {
            delete_fn(val);
        }
    });
}

pub(super) fn cleanup_remote_keyring_secrets(cfg: &RemoteConfig) {
    cleanup_remote_keyring_secrets_with(cfg, delete_secret_if_ref);
}

/// Migrate inline secrets into the OS Keyring across all enabled providers.
pub fn migrate_config_secrets(cfg: &mut AppConfig) -> Result<usize> {
    let mut total = 0usize;
    let providers = registered_providers();
    for (name, remote) in &mut cfg.remotes {
        let kind = remote.kind_str();
        if let Some(adapter) = providers.iter().find(|a| a.kind() == kind) {
            total += adapter.migrate_secrets(name, remote)?;
        }
    }
    Ok(total)
}

/// Clean up OS Keyring entries and sidecar tokens for a removed remote.
pub fn cleanup_remote_secrets(remote_name: &str, cfg: &RemoteConfig, paths: &AppPaths) {
    let kind = cfg.kind_str();
    if let Some(adapter) = registered_providers()
        .into_iter()
        .find(|a| a.kind() == kind)
    {
        adapter.cleanup_secrets(remote_name, cfg, paths);
    }
}

/// Abort a stale/orphaned resumable upload session across ANY registered provider (`rship gc`).
pub async fn abort_operation_for_gc(
    op: &OperationRecord,
    app_cfg: &AppConfig,
    paths: &AppPaths,
    transport: Option<&HttpTransport>,
    runtime_options: &rship::RuntimeOptions,
) {
    let ctx = BuildContext {
        app_cfg,
        paths,
        transport,
        inventory: None,
        allow_changes_feed: false,
        runtime_options,
    };
    if let Ok(adapter) = find_adapter(&op.backend_kind) {
        adapter.abort_gc_operation(&ctx, op).await;
    }
}

#[cfg(test)]
pub(super) fn test_paths(dir: &std::path::Path) -> AppPaths {
    AppPaths::new(dir.join("config.toml"), dir.join("state"))
}

#[cfg(test)]
pub(super) fn test_transport_overrides() -> TransportOverrides {
    TransportOverrides {
        ca_cert: None,
        proxy: None,
        connect_timeout: None,
        stall_timeout: None,
        control_timeout: None,
        tps_limit: None,
        pool_max_idle_per_host: None,
        dump_mode: rship_transport::HttpDumpMode::None,
        stderr_logs_active: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship::config::{S3RemoteConfig, SftpRemoteConfig};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[test]
    fn registered_providers_and_find_adapter_resolve_enabled_kinds() {
        let providers = registered_providers();
        for adapter in &providers {
            let found = find_adapter(adapter.kind()).unwrap();
            assert_eq!(found.kind(), adapter.kind());
        }
        #[cfg(feature = "backend-crypt")]
        {
            assert_eq!(find_adapter("crypto").unwrap().kind(), "crypt");
        }
        assert!(find_adapter("does-not-exist").is_err());
    }

    #[test]
    fn build_wizard_action_roundtrips_all_kinds_and_oauth_prefs() {
        for kind in [
            "local",
            "gdrive",
            "s3",
            "onedrive",
            "webdav",
            "sftp",
            "dropbox",
            "gcs",
            "azureblob",
            "crypt",
        ] {
            let act = build_wizard_action(
                kind,
                Some("rem".to_string()),
                Some((true, true, Some(45678))),
            )
            .expect("known kind must produce AuthAction");
            match act {
                AuthAction::Gdrive(a) => {
                    assert_eq!(a.remote.as_deref(), Some("rem"));
                    assert!(a.no_browser && a.manual);
                    assert_eq!(a.callback_port, Some(45678));
                }
                AuthAction::Onedrive(a) => {
                    assert_eq!(a.remote.as_deref(), Some("rem"));
                    assert!(a.no_browser && a.manual);
                    assert_eq!(a.callback_port, Some(45678));
                }
                AuthAction::Dropbox(a) => {
                    assert_eq!(a.remote.as_deref(), Some("rem"));
                    assert!(a.no_browser && a.manual);
                    assert_eq!(a.callback_port, Some(45678));
                }
                AuthAction::Gcs(a) => {
                    assert_eq!(a.remote.as_deref(), Some("rem"));
                    assert!(a.no_browser && a.manual);
                    assert_eq!(a.callback_port, Some(45678));
                }
                _ => {}
            }
        }
        assert!(build_wizard_action("unknown", None, None).is_none());
    }

    #[tokio::test]
    async fn dispatch_provider_auth_rejects_disabled_feature_cleanly() {
        #[cfg(not(feature = "backend-s3"))]
        {
            let tmp = TempDir::new().unwrap();
            let paths = test_paths(tmp.path());
            let mut cfg = AppConfig::default();
            let t_opts = test_transport_overrides();
            let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);
            let err = dispatch_provider_auth(AuthAction::S3(S3AuthArgs::default()), &mut ctx)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("not enabled"));
        }
        let err = disabled_provider_err("example");
        assert!(err.to_string().contains("backend-example"));
    }

    #[test]
    fn keyring_seams_migrate_rotate_and_cleanup_in_memory_without_os_keyring() {
        let store: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        let store_fn = |slot: &str, val: &str| -> rship_core::Result<String> {
            store.borrow_mut().insert(slot.to_string(), val.to_string());
            Ok(format!("{KEYRING_PREFIX}{slot}"))
        };
        let delete_fn = |raw: &str| {
            if let Some(slot) = raw.strip_prefix(KEYRING_PREFIX) {
                store.borrow_mut().remove(slot);
            }
        };

        let mut cfg = RemoteConfig::Sftp(Box::new(
            SftpRemoteConfig::new("h", "u")
                .with_password("pw-1")
                .with_key_pem("PEM-DATA"),
        ));
        let migrated = migrate_remote_secrets_with("my-ssh", &mut cfg, store_fn).unwrap();
        assert_eq!(migrated, 2);
        assert_eq!(
            store.borrow().get("my-ssh.password").map(String::as_str),
            Some("pw-1")
        );
        assert_eq!(
            store.borrow().get("my-ssh.key_pem").map(String::as_str),
            Some("PEM-DATA")
        );

        let rotated = preserve_or_rotate_secret_with(
            Some("pw-2".to_string()),
            Some("keyring://rship/my-ssh.password"),
            store_fn,
            delete_fn,
        )
        .unwrap();
        assert_eq!(rotated.as_deref(), Some("keyring://rship/my-ssh.password"));
        assert_eq!(
            store.borrow().get("my-ssh.password").map(String::as_str),
            Some("pw-2")
        );

        cleanup_remote_keyring_secrets_with(&cfg, delete_fn);
        assert!(store.borrow().is_empty());

        let mut s3 = RemoteConfig::S3(Box::new(
            S3RemoteConfig::new("aws").with_secret_access_key("sk-1"),
        ));
        assert_eq!(
            migrate_remote_secrets_with("s", &mut s3, store_fn).unwrap(),
            1
        );
        cleanup_remote_keyring_secrets_with(&s3, delete_fn);
        assert!(store.borrow().is_empty());

        let _ = TempDir::new();
    }
}
