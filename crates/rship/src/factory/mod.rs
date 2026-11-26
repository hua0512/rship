//! Feature-gated backend construction, target path resolution, and `rclone.conf`
//! import shared by [`crate::RshipClient`] and `rship-cli`.

mod rclone_import;

pub(crate) use rclone_import::import_rclone_conf_in_memory;
pub use rclone_import::{RcloneImportSummary, import_rclone_conf};

use rship_core::backend::StorageBackend;
use rship_core::path::{RelPath, TargetPath};
use rship_core::state::DeltaInventoryStore;
use rship_core::{Error, Result};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use crate::config::{AppConfig, AppPaths, RemoteConfig, RuntimeOptions};

/// In-memory credential overlay used by ephemeral [`crate::RshipClient`] instances so
/// `rclone.conf` imports never persist OAuth tokens or Service Account keys to disk.
#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct InMemoryCredentials {
    #[cfg(feature = "http")]
    pub(crate) tokens: BTreeMap<String, rship_transport::oauth::OAuthToken>,
    #[cfg(feature = "http")]
    pub(crate) service_accounts: BTreeMap<String, String>,
}

impl std::fmt::Debug for InMemoryCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut ds = f.debug_struct("InMemoryCredentials");
        #[cfg(feature = "http")]
        {
            ds.field("token_remotes", &self.tokens.keys().collect::<Vec<_>>());
            ds.field(
                "service_account_remotes",
                &self.service_accounts.keys().collect::<Vec<_>>(),
            );
        }
        ds.finish()
    }
}

/// Shared runtime context used to instantiate storage backends from [`AppConfig`].
#[must_use]
pub struct ResolveContext<'a> {
    app_cfg: &'a AppConfig,
    #[allow(dead_code)]
    paths: &'a AppPaths,
    #[cfg(feature = "http")]
    transport: Option<&'a rship_transport::HttpTransport>,
    #[allow(dead_code)]
    inventory: Option<Arc<dyn DeltaInventoryStore>>,
    #[allow(dead_code)]
    allow_changes_feed: bool,
    custom_backends: Option<&'a BTreeMap<String, Arc<dyn StorageBackend>>>,
    #[allow(dead_code)]
    clock: Option<Arc<dyn rship_core::clock::Clock>>,
    #[allow(dead_code)]
    buffer_pool: Option<rship_core::buffer::BufferPool>,
    #[allow(dead_code)]
    runtime_options: RuntimeOptions,
    #[allow(dead_code)]
    memory_creds: Option<&'a InMemoryCredentials>,
    depth: u8,
}

impl std::fmt::Debug for ResolveContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveContext")
            .field("remotes", &self.app_cfg.remotes.keys().collect::<Vec<_>>())
            .field("allow_changes_feed", &self.allow_changes_feed)
            .field("runtime_options", &self.runtime_options)
            .field("depth", &self.depth)
            .finish()
    }
}

impl<'a> ResolveContext<'a> {
    /// Create a minimal resolution context with default flags.
    pub fn new(app_cfg: &'a AppConfig, paths: &'a AppPaths) -> Self {
        Self {
            app_cfg,
            paths,
            #[cfg(feature = "http")]
            transport: None,
            inventory: None,
            allow_changes_feed: true,
            custom_backends: None,
            clock: None,
            buffer_pool: None,
            runtime_options: RuntimeOptions::default(),
            memory_creds: None,
            depth: 0,
        }
    }

    /// Attach a shared split-plane HTTP transport for cloud backends.
    #[cfg(feature = "http")]
    pub fn with_transport(mut self, transport: &'a rship_transport::HttpTransport) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Attach an optional durable delta inventory store (used by Google Drive `changes.list`).
    pub fn with_inventory(mut self, inventory: Option<Arc<dyn DeltaInventoryStore>>) -> Self {
        self.inventory = inventory;
        self
    }

    /// Enable or disable incremental change-feed syncing when supported by the backend.
    pub fn with_allow_changes_feed(mut self, allow: bool) -> Self {
        self.allow_changes_feed = allow;
        self
    }

    /// Attach programmatically registered backends overriding `app_cfg.remotes`.
    pub fn with_custom_backends(
        mut self,
        backends: &'a BTreeMap<String, Arc<dyn StorageBackend>>,
    ) -> Self {
        self.custom_backends = Some(backends);
        self
    }

    /// Override the clock used for auth token expiration and backend timestamps.
    pub fn with_clock(mut self, clock: Arc<dyn rship_core::clock::Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Share an engine-level [`rship_core::buffer::BufferPool`] with overlay backends (e.g. `crypt`).
    pub fn with_buffer_pool(mut self, pool: rship_core::buffer::BufferPool) -> Self {
        self.buffer_pool = Some(pool);
        self
    }

    /// Apply ephemeral runtime overrides (e.g. GDrive upload-limit fast-fail, low-level retries).
    pub fn with_runtime_options(mut self, options: RuntimeOptions) -> Self {
        self.runtime_options = options;
        self
    }

    pub(crate) fn with_memory_credentials(mut self, creds: &'a InMemoryCredentials) -> Self {
        self.memory_creds = Some(creds);
        self
    }

    #[cfg(feature = "crypt")]
    fn nested(&self) -> Self {
        Self {
            app_cfg: self.app_cfg,
            paths: self.paths,
            #[cfg(feature = "http")]
            transport: self.transport,
            inventory: self.inventory.clone(),
            allow_changes_feed: self.allow_changes_feed,
            custom_backends: self.custom_backends,
            clock: self.clock.clone(),
            buffer_pool: self.buffer_pool.clone(),
            runtime_options: self.runtime_options.clone(),
            memory_creds: self.memory_creds,
            depth: self.depth + 1,
        }
    }

    #[cfg(any(
        feature = "gdrive",
        feature = "s3",
        feature = "gcs",
        feature = "azureblob"
    ))]
    fn clock_arc(&self) -> Arc<dyn rship_core::clock::Clock> {
        self.clock
            .clone()
            .unwrap_or_else(rship_core::clock::SystemClock::shared)
    }

    #[cfg(any(
        feature = "gdrive",
        feature = "s3",
        feature = "onedrive",
        feature = "webdav",
        feature = "dropbox",
        feature = "gcs",
        feature = "azureblob"
    ))]
    fn require_transport(&self, kind: &str) -> Result<&'a rship_transport::HttpTransport> {
        self.transport.ok_or_else(|| {
            Error::protocol(format!(
                "HTTP transport is required to construct `{kind}` backend"
            ))
        })
    }

    #[cfg(any(
        feature = "gdrive",
        feature = "onedrive",
        feature = "dropbox",
        feature = "gcs"
    ))]
    fn token_store_for(
        &self,
        remote: &str,
        disk_path: std::path::PathBuf,
    ) -> Arc<dyn rship_transport::oauth::TokenStore> {
        if let Some(tok) = self.memory_creds.and_then(|creds| creds.tokens.get(remote)) {
            return Arc::new(rship_transport::oauth::InMemoryTokenStore::new(Some(
                tok.clone(),
            )));
        }
        Arc::new(rship_transport::oauth::FileTokenStore::new(disk_path))
    }

    #[cfg(any(feature = "gdrive", feature = "gcs"))]
    fn in_memory_sa_json(&self, remote: &str) -> Option<&str> {
        self.memory_creds
            .and_then(|creds| creds.service_accounts.get(remote))
            .map(String::as_str)
    }
}

/// Return `true` if resolving `target` requires an initialized HTTP transport.
///
/// Pure local paths and SSH/SFTP remotes return `false`, letting callers skip TLS
/// root-certificate loading and HTTP connection pool allocation when not needed.
pub fn target_needs_transport(target: &TargetPath, cfg: &AppConfig) -> bool {
    let mut current: Option<&str> = None;
    for step in 0..=4 {
        let parsed = if step == 0 {
            target.clone()
        } else {
            let Some(spec) = current else {
                return false;
            };
            let Ok(tp) = TargetPath::parse(spec) else {
                return false;
            };
            tp
        };
        match parsed {
            TargetPath::Local(_) => return false,
            TargetPath::Remote { remote, .. } => match cfg.remotes.get(&remote) {
                Some(RemoteConfig::Local(_) | RemoteConfig::Sftp(_)) | None => return false,
                Some(RemoteConfig::Crypt(c)) => current = Some(c.remote.as_str()),
                Some(_) => return true,
            },
        }
    }
    false
}

/// Return `true` if resolving string spec `spec` requires an initialized HTTP transport.
pub fn spec_needs_transport(spec: &str, cfg: &AppConfig) -> bool {
    let Ok(parsed) = TargetPath::parse(spec) else {
        return false;
    };
    target_needs_transport(&parsed, cfg)
}

/// Return `true` if resolving `target` uses a persistent [`DeltaInventoryStore`] (currently
/// Google Drive with incremental `changes.list` enabled, including through `crypt` overlays).
pub fn target_needs_inventory(
    target: &TargetPath,
    cfg: &AppConfig,
    allow_changes_feed: bool,
) -> bool {
    if !allow_changes_feed {
        return false;
    }
    let mut current: Option<&str> = None;
    for step in 0..=4 {
        let parsed = if step == 0 {
            target.clone()
        } else {
            let Some(spec) = current else {
                return false;
            };
            let Ok(tp) = TargetPath::parse(spec) else {
                return false;
            };
            tp
        };
        match parsed {
            TargetPath::Local(_) => return false,
            TargetPath::Remote { remote, .. } => match cfg.remotes.get(&remote) {
                Some(RemoteConfig::Gdrive(g)) => return g.use_changes_feed.unwrap_or(true),
                Some(RemoteConfig::Crypt(c)) => current = Some(c.remote.as_str()),
                _ => return false,
            },
        }
    }
    false
}

/// Return `true` if resolving string spec `spec` uses a persistent [`DeltaInventoryStore`].
pub fn spec_needs_inventory(spec: &str, cfg: &AppConfig, allow_changes_feed: bool) -> bool {
    let Ok(parsed) = TargetPath::parse(spec) else {
        return false;
    };
    target_needs_inventory(&parsed, cfg, allow_changes_feed)
}

/// Resolve a target spec (`local/path` or `remote:sub/path`) into its [`StorageBackend`]
/// and backend-relative [`RelPath`] prefix.
pub fn resolve_backend(
    spec: &str,
    ctx: &ResolveContext<'_>,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    resolve_target_path(&TargetPath::parse(spec)?, ctx)
}

/// Resolve an already-parsed [`TargetPath`] into its [`StorageBackend`] and relative prefix.
pub fn resolve_target_path(
    target: &TargetPath,
    ctx: &ResolveContext<'_>,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    if ctx.depth > 4 {
        return Err(Error::invalid_path(format!(
            "crypt remote nesting cycle detected while resolving `{target}`"
        )));
    }
    match target {
        TargetPath::Local(path) => {
            let cfg = RemoteConfig::local(path.clone());
            build_remote_backend("local", &cfg, RelPath::root(), ctx)
        }
        TargetPath::Remote { remote, path } => {
            if let Some(custom) = ctx.custom_backends.and_then(|m| m.get(remote)) {
                return Ok((custom.clone(), path.clone()));
            }
            let Some(rcfg) = ctx.app_cfg.remotes.get(remote) else {
                return Err(Error::config(format!(
                    "remote `{remote}` is not configured"
                )));
            };
            build_remote_backend(remote, rcfg, path.clone(), ctx)
        }
    }
}

/// Resolve an explicit single-file target (ensuring local paths map to `(parent_dir, file_name)`
/// so `copy_file` / `move_file` never treat a file name as a directory root).
pub fn resolve_file_target(
    spec: &str,
    ctx: &ResolveContext<'_>,
    create_local_parent: bool,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    resolve_file_target_path(&TargetPath::parse(spec)?, ctx, create_local_parent)
}

/// Resolve an already-parsed single-file [`TargetPath`].
pub fn resolve_file_target_path(
    target: &TargetPath,
    ctx: &ResolveContext<'_>,
    create_local_parent: bool,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    match target {
        TargetPath::Local(path) => {
            let file_name = path.file_name().and_then(|s| s.to_str()).ok_or_else(|| {
                Error::invalid_path(format!(
                    "local file path `{}` has no file name",
                    path.display()
                ))
            })?;
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            if create_local_parent {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::io(format!("create parent `{}`", parent.display()), e))?;
            }
            let cfg = RemoteConfig::local(parent);
            let (backend, _) = build_remote_backend("local", &cfg, RelPath::root(), ctx)?;
            Ok((backend, RelPath::parse(file_name)?))
        }
        TargetPath::Remote { .. } => {
            let (backend, rel) = resolve_target_path(target, ctx)?;
            if rel.is_root() {
                return Err(Error::invalid_path(format!(
                    "file target `{target}` must specify a file path, not remote root"
                )));
            }
            Ok((backend, rel))
        }
    }
}

/// Split bucket/container prefix for bucketless S3/GCS/Azure remotes so callers and
/// backend caches share the exact same key derivation logic.
pub(crate) fn extract_remote_unit(
    remote_name: &str,
    cfg: &RemoteConfig,
    sub_path: RelPath,
) -> Result<(Option<String>, RelPath)> {
    match cfg {
        RemoteConfig::S3(scfg) => {
            let (bucket, rel) = split_bucket_or_container(
                remote_name,
                "S3",
                "bucket",
                scfg.bucket.as_deref(),
                sub_path,
            )?;
            Ok((Some(bucket), rel))
        }
        RemoteConfig::Gcs(gcfg) => {
            let (bucket, rel) = split_bucket_or_container(
                remote_name,
                "GCS",
                "bucket",
                gcfg.bucket.as_deref(),
                sub_path,
            )?;
            Ok((Some(bucket), rel))
        }
        RemoteConfig::Azureblob(acfg) => {
            #[cfg(feature = "azureblob")]
            let (_, _, inferred_container) = resolve_azureblob_sas_and_container(acfg, false)?;
            #[cfg(not(feature = "azureblob"))]
            let inferred_container = acfg
                .container
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let (container, rel) = split_bucket_or_container(
                remote_name,
                "Azure Blob",
                "container",
                inferred_container.as_deref(),
                sub_path,
            )?;
            Ok((Some(container), rel))
        }
        _ => Ok((None, sub_path)),
    }
}

/// Build a concrete [`StorageBackend`] from a declarative [`RemoteConfig`].
#[allow(unused_variables)]
pub fn build_remote_backend(
    remote_name: &str,
    cfg: &RemoteConfig,
    sub_path: RelPath,
    ctx: &ResolveContext<'_>,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    match cfg {
        RemoteConfig::Local(lcfg) => {
            #[cfg(feature = "local")]
            {
                let backend = build_local(ctx, remote_name, lcfg)?;
                Ok((Arc::new(backend), sub_path))
            }
            #[cfg(not(feature = "local"))]
            {
                Err(Error::unsupported(
                    "provider `local` is not enabled in this build (enable feature `local`)",
                ))
            }
        }
        RemoteConfig::Gdrive(gcfg) => {
            #[cfg(feature = "gdrive")]
            {
                let b = build_gdrive(ctx, remote_name, gcfg)?;
                Ok((Arc::new(b), sub_path))
            }
            #[cfg(not(feature = "gdrive"))]
            {
                Err(Error::unsupported(
                    "provider `gdrive` is not enabled in this build (enable feature `gdrive`)",
                ))
            }
        }
        RemoteConfig::S3(scfg) => {
            #[cfg(feature = "s3")]
            {
                let (bucket, rel_path) = split_bucket_or_container(
                    remote_name,
                    "S3",
                    "bucket",
                    scfg.bucket.as_deref(),
                    sub_path,
                )?;
                let b = build_s3(ctx, remote_name, scfg, &bucket)?;
                Ok((Arc::new(b), rel_path))
            }
            #[cfg(not(feature = "s3"))]
            {
                Err(Error::unsupported(
                    "provider `s3` is not enabled in this build (enable feature `s3`)",
                ))
            }
        }
        RemoteConfig::Onedrive(ocfg) => {
            #[cfg(feature = "onedrive")]
            {
                let b = build_onedrive(ctx, remote_name, ocfg)?;
                Ok((Arc::new(b), sub_path))
            }
            #[cfg(not(feature = "onedrive"))]
            {
                Err(Error::unsupported(
                    "provider `onedrive` is not enabled in this build (enable feature `onedrive`)",
                ))
            }
        }
        RemoteConfig::Webdav(wcfg) => {
            #[cfg(feature = "webdav")]
            {
                let b = build_webdav(ctx, remote_name, wcfg)?;
                Ok((Arc::new(b), sub_path))
            }
            #[cfg(not(feature = "webdav"))]
            {
                Err(Error::unsupported(
                    "provider `webdav` is not enabled in this build (enable feature `webdav`)",
                ))
            }
        }
        RemoteConfig::Sftp(scfg) => {
            #[cfg(feature = "sftp")]
            {
                let b = build_sftp(ctx, remote_name, scfg)?;
                Ok((Arc::new(b), sub_path))
            }
            #[cfg(not(feature = "sftp"))]
            {
                Err(Error::unsupported(
                    "provider `sftp` is not enabled in this build (enable feature `sftp`)",
                ))
            }
        }
        RemoteConfig::Dropbox(dcfg) => {
            #[cfg(feature = "dropbox")]
            {
                let b = build_dropbox(ctx, remote_name, dcfg)?;
                Ok((Arc::new(b), sub_path))
            }
            #[cfg(not(feature = "dropbox"))]
            {
                Err(Error::unsupported(
                    "provider `dropbox` is not enabled in this build (enable feature `dropbox`)",
                ))
            }
        }
        RemoteConfig::Gcs(gcfg) => {
            #[cfg(feature = "gcs")]
            {
                let (bucket, rel_path) = split_bucket_or_container(
                    remote_name,
                    "GCS",
                    "bucket",
                    gcfg.bucket.as_deref(),
                    sub_path,
                )?;
                let b = build_gcs(ctx, remote_name, gcfg, &bucket)?;
                Ok((Arc::new(b), rel_path))
            }
            #[cfg(not(feature = "gcs"))]
            {
                Err(Error::unsupported(
                    "provider `gcs` is not enabled in this build (enable feature `gcs`)",
                ))
            }
        }
        RemoteConfig::Azureblob(acfg) => {
            #[cfg(feature = "azureblob")]
            {
                let (resolved_sas, sas_meta, configured_container) =
                    resolve_azureblob_sas_and_container(acfg, true)?;
                let (container, rel_path) = split_bucket_or_container(
                    remote_name,
                    "Azure Blob",
                    "container",
                    configured_container.as_deref(),
                    sub_path,
                )?;
                let b = build_azureblob(
                    ctx,
                    remote_name,
                    acfg,
                    &container,
                    resolved_sas.as_deref(),
                    sas_meta.as_ref(),
                )?;
                Ok((Arc::new(b), rel_path))
            }
            #[cfg(not(feature = "azureblob"))]
            {
                Err(Error::unsupported(
                    "provider `azureblob` is not enabled in this build (enable feature `azureblob`)",
                ))
            }
        }
        RemoteConfig::Crypt(ccfg) => {
            #[cfg(feature = "crypt")]
            {
                build_crypt(ctx, remote_name, ccfg, sub_path)
            }
            #[cfg(not(feature = "crypt"))]
            {
                Err(Error::unsupported(
                    "provider `crypt` is not enabled in this build (enable feature `crypt`)",
                ))
            }
        }
    }
}

fn split_bucket_or_container(
    remote_name: &str,
    provider_label: &str,
    unit_label: &str,
    configured: Option<&str>,
    sub_path: RelPath,
) -> Result<(String, RelPath)> {
    if let Some(val) = configured
        && !val.trim().is_empty()
    {
        return Ok((val.to_string(), sub_path));
    }
    let mut segs = sub_path.segments();
    let Some(first) = segs.next() else {
        return Err(Error::config(format!(
            "{provider_label} remote `{remote_name}` has no default `{unit_label}`; specify `{remote_name}:<{unit_label}>/[path]`"
        )));
    };
    let rest: Vec<&str> = segs.collect();
    let sub = if rest.is_empty() {
        RelPath::root()
    } else {
        RelPath::parse(&rest.join("/"))?
    };
    Ok((first.to_string(), sub))
}

#[cfg(feature = "local")]
fn parse_local_encoding(
    remote_name: &str,
    raw: Option<&str>,
) -> Result<rship_core::encoding::EncodingMode> {
    use rship_core::encoding::EncodingMode;
    match raw.map(str::trim).unwrap_or("") {
        "" => Ok(EncodingMode::Identity),
        s => match s.to_ascii_lowercase().as_str() {
            "identity" | "none" | "raw" => Ok(EncodingMode::Identity),
            "windows_safe" | "windows-safe" | "windowssafe" | "windows" => {
                Ok(EncodingMode::WindowsSafe)
            }
            other => Err(Error::config(format!(
                "unknown local encoding `{other}` for remote `{remote_name}` (expected: identity, windows_safe)"
            ))),
        },
    }
}

#[cfg(feature = "local")]
fn build_local(
    ctx: &ResolveContext<'_>,
    remote_name: &str,
    lcfg: &crate::config::LocalRemoteConfig,
) -> Result<rship_backends::local::LocalBackend> {
    let encoding = parse_local_encoding(remote_name, lcfg.encoding.as_deref())?;
    Ok(
        rship_backends::local::LocalBackend::new(remote_name, &lcfg.root)?
            .with_follow_symlinks(ctx.runtime_options.copy_links)
            .with_fsync_mode(ctx.runtime_options.fsync_mode)
            .with_encoding(encoding),
    )
}

#[cfg(feature = "gdrive")]
fn build_gdrive(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::GdriveRemoteConfig,
) -> Result<rship_backends::gdrive::GdriveBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::gdrive::{
        AuthProvider, GdriveBackend, GdriveConfig, OAuth2AuthProvider, ServiceAccountAuthProvider,
        ServiceAccountKey, StaticBearerAuth,
    };

    let transport = ctx.require_transport("gdrive")?;
    let mut cfg = GdriveConfig::new(remote);
    if let Some(v) = &rcfg.api_base_url {
        cfg.api_base_url = v.clone();
    }
    if let Some(v) = &rcfg.upload_base_url {
        cfg.upload_base_url = v.clone();
    }
    if let Some(v) = &rcfg.token_url {
        cfg.token_url = v.clone();
    }
    if let Some(v) = &rcfg.auth_url {
        cfg.auth_url = v.clone();
    }
    if let Some(v) = &rcfg.root_folder_id {
        cfg.root_folder_id = v.clone();
    }
    cfg.shared_drive_id = rcfg.shared_drive_id.clone();
    if let Some(v) = &rcfg.scope
        && !v.trim().is_empty()
    {
        cfg.scope = rship_backends::gdrive::resolve_gdrive_scope(v);
    }
    cfg.use_trash_on_delete = rcfg.use_trash.unwrap_or(true);
    cfg.shared_with_me = rcfg.shared_with_me.unwrap_or(false);
    cfg.trashed_only = rcfg.trashed_only.unwrap_or(false);
    cfg.use_changes_feed =
        ctx.allow_changes_feed && rcfg.use_changes_feed.unwrap_or(ctx.inventory.is_some());
    if let Some(v) = rcfg.write_qps {
        cfg.write_qps = Some(v);
    }
    cfg.stop_on_upload_limit = ctx.runtime_options.gdrive_stop_on_upload_limit
        || rcfg.stop_on_upload_limit.unwrap_or(false);
    if let Some(retries) = ctx
        .runtime_options
        .gdrive_low_level_retries
        .or(rcfg.max_retries)
    {
        cfg.max_retries = retries;
    }

    let clock = ctx.clock_arc();
    let auth: Arc<dyn AuthProvider> = if let Some(sa_json) = ctx.in_memory_sa_json(remote) {
        let sa_key = ServiceAccountKey::from_json_str(sa_json)?;
        Arc::new(ServiceAccountAuthProvider::new(
            sa_key,
            cfg.scope.clone(),
            rcfg.impersonate.clone(),
            rcfg.token_url.clone(),
            transport.clone(),
            clock.clone(),
        )?)
    } else if let Some(sa_path) = &rcfg.service_account_file {
        let sa_key = ServiceAccountKey::from_file(sa_path)?;
        Arc::new(ServiceAccountAuthProvider::new(
            sa_key,
            cfg.scope.clone(),
            rcfg.impersonate.clone(),
            rcfg.token_url.clone(),
            transport.clone(),
            clock.clone(),
        )?)
    } else if let Some(tok_raw) = &rcfg.access_token
        && rcfg.client_id.is_none()
    {
        Arc::new(StaticBearerAuth::new(remote, resolve_secret(tok_raw)?))
    } else {
        let client_id = rcfg.client_id.clone().ok_or_else(|| {
            Error::permission_denied(format!(
                "gdrive remote `{remote}` is missing `client_id` (configure via OAuth2 or service account)"
            ))
        })?;
        let client_secret = resolve_opt_secret(rcfg.client_secret.as_deref())?.unwrap_or_default();
        let store = ctx.token_store_for(remote, ctx.paths.token_file_for(remote));
        Arc::new(OAuth2AuthProvider::new(
            remote,
            client_id,
            client_secret,
            cfg.token_url.clone(),
            transport.clone(),
            store,
            clock.clone(),
        )?)
    };

    Ok(GdriveBackend::new(
        cfg,
        transport.clone(),
        auth,
        ctx.inventory.clone(),
        Some(clock),
    ))
}

/// Probe connectivity and credentials for a configured remote that has no default bucket or
/// container (e.g. an S3 remote imported from `rclone.conf` with `bucket = None`).
///
/// Returns `Ok(Some(endpoint_identity))` when a service-level probe (such as S3 `ListBuckets`)
/// succeeded, or `Ok(None)` when standard [`resolve_backend`] should be used instead.
#[allow(unused_variables)]
pub async fn probe_bucketless_remote(
    remote_name: &str,
    cfg: &RemoteConfig,
    ctx: &ResolveContext<'_>,
) -> Result<Option<String>> {
    match cfg {
        #[cfg(feature = "s3")]
        RemoteConfig::S3(scfg) if scfg.bucket.as_deref().is_none_or(|b| b.trim().is_empty()) => {
            let transport = ctx.require_transport("s3")?;
            let s3_cfg = build_s3_config(remote_name, scfg, "")?;
            let ep = rship_backends::s3::S3Backend::probe_service(
                &s3_cfg,
                transport,
                Some(ctx.clock_arc()),
            )
            .await?;
            Ok(Some(ep))
        }
        _ => Ok(None),
    }
}

#[cfg(feature = "s3")]
fn build_s3_config(
    remote: &str,
    rcfg: &crate::config::S3RemoteConfig,
    bucket: &str,
) -> Result<rship_backends::s3::S3Config> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::s3::{
        PayloadSigningMode, S3Config, S3CredentialSource, S3Credentials, S3Provider,
        S3ServerSideEncryption,
    };

    let provider = S3Provider::parse(&rcfg.provider).ok_or_else(|| {
        Error::config(format!(
            "unknown S3 provider `{}` for remote `{remote}`",
            rcfg.provider
        ))
    })?;
    let use_chain = (rcfg.env_auth.unwrap_or(false) || rcfg.profile.is_some())
        && (rcfg.access_key_id.is_none() || rcfg.secret_access_key.is_none());
    let (creds, cred_source) = if use_chain {
        (
            S3Credentials::new("", ""),
            Some(S3CredentialSource::aws_chain(rcfg.profile.clone())),
        )
    } else {
        let ak = rcfg.access_key_id.clone().ok_or_else(|| {
            Error::permission_denied(format!("S3 remote `{remote}` missing `access_key_id`"))
        })?;
        let sk_raw = rcfg.secret_access_key.as_deref().ok_or_else(|| {
            Error::permission_denied(format!("S3 remote `{remote}` missing `secret_access_key`"))
        })?;
        let sk = resolve_secret(sk_raw)?;
        let st = resolve_opt_secret(rcfg.session_token.as_deref())?;
        (S3Credentials::new(ak, sk).with_session_token(st), None)
    };

    let mut cfg = S3Config::new(remote, provider, bucket, creds);
    cfg.credential_source = cred_source;
    if let Some(ref sse_raw) = rcfg.sse {
        let parsed = S3ServerSideEncryption::parse(sse_raw, rcfg.kms_key_id.clone()).ok_or_else(
            || {
                Error::config(format!(
                    "unknown S3 SSE mode `{sse_raw}` for remote `{remote}` (expected: AES256, aws:kms)"
                ))
            },
        )?;
        if matches!(parsed, S3ServerSideEncryption::Aes256)
            && rcfg
                .kms_key_id
                .as_deref()
                .is_some_and(|k| !k.trim().is_empty())
        {
            return Err(Error::config(format!(
                "S3 remote `{remote}` specifies `kms_key_id` with `sse = \"AES256\"` (use `sse = \"aws:kms\"`)"
            )));
        }
        cfg.server_side_encryption = Some(parsed);
    } else if let Some(key_id) = rcfg
        .kms_key_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        cfg.server_side_encryption = Some(S3ServerSideEncryption::AwsKms {
            key_id: Some(key_id.to_string()),
        });
    }
    if let Some(p) = &rcfg.prefix {
        cfg.prefix = p.clone();
    }
    if let Some(r) = &rcfg.region {
        cfg.region = r.clone();
    }
    cfg.endpoint = rcfg.endpoint.clone();
    cfg.force_path_style = rcfg.force_path_style;
    if let Some(mode) = &rcfg.payload_signing {
        cfg.payload_signing = PayloadSigningMode::parse(mode).ok_or_else(|| {
            Error::config(format!(
                "unknown S3 payload_signing mode `{mode}` for remote `{remote}` (expected: auto, unsigned, strict_sha256)"
            ))
        })?;
    } else if rcfg.strict_sigv4.unwrap_or(false) {
        cfg.payload_signing = PayloadSigningMode::StrictSha256;
    }
    if let Some(pin) = rcfg.pin_read_etag {
        cfg.pin_read_etag = pin;
    }
    cfg.storage_class = rcfg.storage_class.clone();
    if let Some(ck) = rcfg.send_upload_checksum {
        cfg.send_upload_checksum = ck;
    }
    if let Some(conc) = rcfg.list_prefix_concurrency {
        cfg.list_prefix_concurrency = conc.max(1);
    }
    Ok(cfg)
}

#[cfg(feature = "s3")]
fn build_s3(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::S3RemoteConfig,
    bucket: &str,
) -> Result<rship_backends::s3::S3Backend> {
    let transport = ctx.require_transport("s3")?;
    let mut cfg = build_s3_config(remote, rcfg, bucket)?;
    cfg.spool_dir = Some(ctx.paths.s3_spool_dir());
    rship_backends::s3::S3Backend::new(cfg, transport.clone(), Some(ctx.clock_arc()))
}

#[cfg(feature = "onedrive")]
fn build_onedrive(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::OnedriveRemoteConfig,
) -> Result<rship_backends::onedrive::OnedriveBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::onedrive::{
        MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveAuthProvider,
        OnedriveBackend, OnedriveConfig, OnedriveDriveType, OnedriveOAuth2Auth, OnedriveRegion,
    };

    let transport = ctx.require_transport("onedrive")?;
    let mut cfg = OnedriveConfig::new(remote);
    cfg.drive_id = rcfg.drive_id.clone();
    if let Some(raw_region) = &rcfg.region
        && !raw_region.trim().is_empty()
    {
        let region = OnedriveRegion::parse(raw_region).ok_or_else(|| {
            Error::config(format!(
                "unknown OneDrive region `{raw_region}` for remote `{remote}` (expected: global, us, de, cn)"
            ))
        })?;
        cfg = cfg.with_region(region);
    }
    if let Some(raw_dt) = &rcfg.drive_type
        && !raw_dt.trim().is_empty()
    {
        let dt = OnedriveDriveType::parse(raw_dt).ok_or_else(|| {
            Error::config(format!(
                "unknown OneDrive drive_type `{raw_dt}` for remote `{remote}` (expected: personal, business, documentLibrary)"
            ))
        })?;
        cfg = cfg.with_drive_type(dt);
    }
    if let Some(cs) = rcfg.chunk_size {
        if !(ONEDRIVE_CHUNK_ALIGN_BYTES..=MAX_ONEDRIVE_CHUNK_BYTES).contains(&cs)
            || !cs.is_multiple_of(ONEDRIVE_CHUNK_ALIGN_BYTES)
        {
            return Err(Error::config(format!(
                "invalid OneDrive chunk_size `{cs}` for remote `{remote}` (must be a multiple of {ONEDRIVE_CHUNK_ALIGN_BYTES} bytes between {ONEDRIVE_CHUNK_ALIGN_BYTES} and {MAX_ONEDRIVE_CHUNK_BYTES})"
            )));
        }
        cfg = cfg.with_chunk_size(cs);
    }
    if let Some(v) = &rcfg.api_base_url {
        cfg.api_base_url = v.clone();
    }
    if let Some(v) = &rcfg.auth_url {
        cfg.auth_url = v.clone();
    }
    if let Some(v) = &rcfg.token_url {
        cfg.token_url = v.clone();
    }
    if let Some(v) = &rcfg.scope {
        cfg.scope = v.clone();
    }

    let auth: Arc<dyn OnedriveAuthProvider> = if let Some(tok_raw) = &rcfg.access_token
        && rcfg.client_id.is_none()
    {
        Arc::new(rship_transport::oauth::StaticBearerAuth::new(
            remote,
            resolve_secret(tok_raw)?,
        ))
    } else {
        let client_id = rcfg.client_id.clone().ok_or_else(|| {
            Error::permission_denied(format!("onedrive remote `{remote}` is missing `client_id`"))
        })?;
        let client_secret = resolve_opt_secret(rcfg.client_secret.as_deref())?;
        let store = ctx.token_store_for(remote, ctx.paths.onedrive_token_file_for(remote));
        Arc::new(OnedriveOAuth2Auth::new(
            client_id,
            client_secret,
            cfg.token_url.clone(),
            cfg.scope.clone(),
            remote,
            transport.clone(),
            store,
        )?)
    };

    OnedriveBackend::new(cfg, auth, transport.clone())
}

#[cfg(feature = "webdav")]
fn build_webdav(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::WebdavRemoteConfig,
) -> Result<rship_backends::webdav::WebdavBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::webdav::{WebdavAuth, WebdavBackend, WebdavConfig, WebdavVendor};

    let transport = ctx.require_transport("webdav")?;
    let mut cfg = WebdavConfig::new(remote, &rcfg.url);
    if let Some(v) = &rcfg.vendor {
        cfg.vendor = WebdavVendor::parse(v).ok_or_else(|| {
            Error::config(format!("unknown WebDAV vendor `{v}` for remote `{remote}`"))
        })?;
    }
    cfg.chunked_upload_root = rcfg.chunked_upload_root.clone();
    if !rcfg.headers.is_empty() {
        let mut resolved_headers = Vec::with_capacity(rcfg.headers.len());
        for (name, val) in &rcfg.headers {
            resolved_headers.push((name.clone(), resolve_secret(val)?));
        }
        cfg = cfg.with_headers(resolved_headers);
    }
    if let Some(tok_raw) = &rcfg.bearer_token {
        cfg.auth = WebdavAuth::Bearer {
            token: resolve_secret(tok_raw)?,
        };
    } else if let Some(user) = &rcfg.username {
        let pw = resolve_opt_secret(rcfg.password.as_deref())?.unwrap_or_default();
        cfg.auth = WebdavAuth::Basic {
            username: user.clone(),
            password: pw,
        };
    } else if rcfg
        .bearer_token_command
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return Err(Error::config(format!(
            "WebDAV remote `{remote}` sets `bearer_token_command`, which is not executed automatically; configure `bearer_token` or `username`/`password` instead"
        )));
    }
    WebdavBackend::new(cfg, transport.clone())
}

#[cfg(feature = "sftp")]
fn build_sftp(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::SftpRemoteConfig,
) -> Result<rship_backends::sftp::SftpBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::sftp::{HostKeyPolicy, SftpAuth, SftpBackend, SftpConfig};

    let auth = if let Some(key_path) = &rcfg.key_file {
        SftpAuth::KeyFile {
            path: key_path.clone(),
            passphrase: resolve_opt_secret(rcfg.key_passphrase.as_deref())?,
        }
    } else if let Some(pem_raw) = &rcfg.key_pem {
        SftpAuth::KeyPem {
            pem: resolve_secret(pem_raw)?,
            passphrase: resolve_opt_secret(rcfg.key_passphrase.as_deref())?,
        }
    } else if let Some(pw_raw) = &rcfg.password {
        SftpAuth::Password(resolve_secret(pw_raw)?)
    } else {
        return Err(Error::permission_denied(format!(
            "sftp remote `{remote}` requires `key_file`, `key_pem`, or `password`"
        )));
    };
    let mut cfg = SftpConfig::new(remote, &rcfg.host, &rcfg.user, auth);
    #[cfg(feature = "http")]
    if let Some(t) = ctx.transport {
        cfg.connect_timeout = t.config().connect_timeout;
        cfg.io_timeout = t.config().data_stall_timeout;
    }
    if let Some(d) = ctx.runtime_options.sftp_connect_timeout {
        cfg.connect_timeout = d;
    }
    if let Some(d) = ctx.runtime_options.sftp_io_timeout {
        cfg.io_timeout = d;
    }
    if let Some(port) = rcfg.port {
        cfg.port = port;
    }
    if let Some(rp) = &rcfg.root_path {
        cfg.root_path = rp.clone();
    }
    if let Some(pol) = &rcfg.host_key_policy {
        cfg.host_key_policy = HostKeyPolicy::parse(pol).ok_or_else(|| {
            Error::invalid_path(format!(
                "invalid SFTP host_key_policy `{pol}` (accept-new, strict, insecure)"
            ))
        })?;
    }
    cfg.known_hosts_path = rcfg.known_hosts_path.clone();
    SftpBackend::new(cfg)
}

#[cfg(feature = "dropbox")]
fn build_dropbox(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::DropboxRemoteConfig,
) -> Result<rship_backends::dropbox::DropboxBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::dropbox::{
        DropboxAuthProvider, DropboxBackend, DropboxConfig, DropboxOAuth2Auth,
    };

    let transport = ctx.require_transport("dropbox")?;
    let mut cfg = DropboxConfig::new(remote);
    if let Some(v) = &rcfg.root_path {
        cfg.root_path = v.clone();
    }
    cfg.root_namespace = rcfg.root_namespace.clone();
    cfg.impersonate = rcfg.impersonate.clone();
    if let Some(sf) = rcfg.shared_folders {
        cfg.shared_folders = sf;
    }
    if let Some(v) = &rcfg.api_base_url {
        cfg.api_base_url = v.clone();
    }
    if let Some(v) = &rcfg.content_base_url {
        cfg.content_base_url = v.clone();
    }
    if let Some(v) = &rcfg.auth_url {
        cfg.auth_url = v.clone();
    }
    if let Some(v) = &rcfg.token_url {
        cfg.token_url = v.clone();
    }

    let auth: Arc<dyn DropboxAuthProvider> = if let Some(tok_raw) = &rcfg.access_token
        && rcfg.client_id.is_none()
    {
        Arc::new(rship_transport::oauth::StaticBearerAuth::new(
            remote,
            resolve_secret(tok_raw)?,
        ))
    } else {
        let client_id = rcfg.client_id.clone().ok_or_else(|| {
            Error::permission_denied(format!("dropbox remote `{remote}` is missing `client_id`"))
        })?;
        let client_secret = resolve_opt_secret(rcfg.client_secret.as_deref())?;
        let store = ctx.token_store_for(remote, ctx.paths.dropbox_token_file_for(remote));
        Arc::new(DropboxOAuth2Auth::new(
            client_id,
            client_secret,
            cfg.token_url.clone(),
            remote,
            transport.clone(),
            store,
        )?)
    };

    DropboxBackend::new(cfg, auth, transport.clone())
}

#[cfg(feature = "gcs")]
fn build_gcs(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::GcsRemoteConfig,
    bucket: &str,
) -> Result<rship_backends::gcs::GcsBackend> {
    use crate::secrets::{resolve_opt_secret, resolve_secret};
    use rship_backends::gcs::{
        GcsAuthProvider, GcsBackend, GcsConfig, GcsOAuth2Auth, ServiceAccountAuthProvider,
        ServiceAccountKey,
    };

    let transport = ctx.require_transport("gcs")?;
    let mut cfg = GcsConfig::new(remote, bucket);
    if let Some(p) = &rcfg.prefix {
        cfg.prefix = p.clone();
    }
    cfg.project_number = rcfg.project_number.clone();
    if let Some(up) = &rcfg.user_project {
        cfg = cfg.with_user_project(up);
    }
    cfg.storage_class = rcfg.storage_class.clone();
    if let Some(ep) = &rcfg.endpoint
        && !ep.trim().is_empty()
    {
        cfg = cfg.with_endpoint(ep);
    }
    if let Some(v) = &rcfg.api_base_url {
        cfg.api_base_url = v.clone();
    }
    if let Some(v) = &rcfg.upload_base_url {
        cfg.upload_base_url = v.clone();
    }
    if let Some(v) = &rcfg.auth_url {
        cfg.auth_url = v.clone();
    }
    if let Some(v) = &rcfg.token_url {
        cfg.token_url = v.clone();
    }
    if let Some(v) = &rcfg.scope
        && !v.trim().is_empty()
    {
        cfg.scope = rship_backends::gcs::resolve_gcs_scope(v);
    }
    cfg.anonymous = rcfg.anonymous.unwrap_or(false);

    let auth: Option<Arc<dyn GcsAuthProvider>> = if cfg.anonymous {
        None
    } else if let Some(sa_json) = ctx.in_memory_sa_json(remote) {
        let sa_key = ServiceAccountKey::from_json_str(sa_json)?;
        Some(Arc::new(ServiceAccountAuthProvider::new(
            sa_key,
            cfg.scope.clone(),
            rcfg.impersonate.clone(),
            rcfg.token_url.clone(),
            transport.clone(),
            ctx.clock_arc(),
        )?))
    } else if let Some(sa_path) = &rcfg.service_account_file {
        let sa_key = ServiceAccountKey::from_file(sa_path)?;
        Some(Arc::new(ServiceAccountAuthProvider::new(
            sa_key,
            cfg.scope.clone(),
            rcfg.impersonate.clone(),
            rcfg.token_url.clone(),
            transport.clone(),
            ctx.clock_arc(),
        )?))
    } else if let Some(tok_raw) = &rcfg.access_token
        && rcfg.client_id.is_none()
    {
        Some(Arc::new(rship_transport::oauth::StaticBearerAuth::new(
            remote,
            resolve_secret(tok_raw)?,
        )))
    } else {
        let client_id = rcfg.client_id.clone().ok_or_else(|| {
            if rcfg.env_auth.unwrap_or(false) {
                Error::unsupported(format!(
                    "GCS remote `{remote}` sets `env_auth = true`, but automatic ADC/metadata-server credentials are not yet implemented; configure `service_account_file`, `client_id`, `access_token`, or `anonymous=true`"
                ))
            } else {
                Error::permission_denied(format!(
                    "GCS remote `{remote}` needs `service_account_file`, `client_id`, `access_token`, or `anonymous=true`"
                ))
            }
        })?;
        let client_secret = resolve_opt_secret(rcfg.client_secret.as_deref())?;
        let store = ctx.token_store_for(remote, ctx.paths.gcs_token_file_for(remote));
        Some(Arc::new(GcsOAuth2Auth::new(
            client_id,
            client_secret,
            cfg.token_url.clone(),
            remote,
            transport.clone(),
            store,
        )?))
    };

    GcsBackend::new(cfg, auth, transport.clone())
}

#[cfg(feature = "azureblob")]
fn resolve_azureblob_sas_and_container(
    acfg: &crate::config::AzureblobRemoteConfig,
    resolve_sas_even_if_container_set: bool,
) -> Result<(
    Option<String>,
    Option<rship_backends::azureblob::SasUrlMetadata>,
    Option<String>,
)> {
    let explicit_container = acfg
        .container
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let anonymous = acfg.anonymous.unwrap_or(false);
    let need_sas =
        !anonymous && (resolve_sas_even_if_container_set || explicit_container.is_none());
    let resolved_sas = if need_sas {
        if let Some(raw_sas) = acfg.sas_url.as_deref().filter(|s| !s.trim().is_empty()) {
            Some(crate::secrets::resolve_secret(raw_sas)?)
        } else {
            None
        }
    } else {
        None
    };
    let sas_meta = resolved_sas
        .as_deref()
        .map(rship_backends::azureblob::extract_sas_url_metadata);
    let container = explicit_container.or_else(|| {
        sas_meta
            .as_ref()
            .and_then(|m| m.container.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    });
    Ok((resolved_sas, sas_meta, container))
}

#[cfg(feature = "azureblob")]
fn build_azureblob(
    ctx: &ResolveContext<'_>,
    remote: &str,
    rcfg: &crate::config::AzureblobRemoteConfig,
    container: &str,
    resolved_sas: Option<&str>,
    sas_meta: Option<&rship_backends::azureblob::SasUrlMetadata>,
) -> Result<rship_backends::azureblob::AzureBlobBackend> {
    use crate::secrets::resolve_secret;
    use rship_backends::azureblob::{AzureAuth, AzureBlobBackend, AzureBlobConfig};

    let transport = ctx.require_transport("azureblob")?;
    let account = rcfg
        .account
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| sas_meta.and_then(|m| m.account.clone()))
        .unwrap_or_else(|| "azure".to_string());
    let mut cfg = AzureBlobConfig::new(remote, account.clone(), container);
    if let Some(p) = &rcfg.prefix {
        cfg.prefix = p.clone();
    }
    cfg.endpoint = rcfg
        .endpoint
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| sas_meta.and_then(|m| m.endpoint.clone()));
    cfg.access_tier = rcfg.access_tier.clone();

    let auth = if rcfg.anonymous.unwrap_or(false) {
        AzureAuth::Anonymous
    } else if let Some(sas) = resolved_sas {
        AzureAuth::sas_token(sas)?
    } else if let Some(raw_key) = &rcfg.key {
        let resolved_key = resolve_secret(raw_key)?;
        AzureAuth::shared_key(account, &resolved_key)?
    } else {
        return Err(Error::permission_denied(format!(
            "Azure Blob remote `{remote}` missing credentials (`key`, `sas_url`, or `anonymous=true`)"
        )));
    };

    AzureBlobBackend::new(cfg, auth, transport.clone(), Some(ctx.clock_arc()))
}

#[cfg(feature = "crypt")]
fn build_crypt(
    ctx: &ResolveContext<'_>,
    remote_name: &str,
    ccfg: &crate::config::CryptRemoteConfig,
    sub_path: RelPath,
) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
    use crate::secrets::resolve_opt_secret;
    use rship_crypto::{CryptoBackend, CryptoConfig, FilenameEncryption, MasterKey};

    let nested_ctx = ctx.nested();
    let (inner_backend, inner_prefix) = resolve_backend(&ccfg.remote, &nested_ctx)?;
    let resolved_hex = resolve_opt_secret(ccfg.key_hex.as_deref())?;
    let resolved_pw = resolve_opt_secret(ccfg.password.as_deref())?
        .or_else(|| std::env::var("RSHIP_CRYPT_PASSWORD").ok());
    let master = if let Some(hex_k) = resolved_hex {
        MasterKey::from_hex(&hex_k)?
    } else if let Some(pw) = resolved_pw {
        MasterKey::from_passphrase(&pw, ccfg.salt.as_deref().map(str::as_bytes))?
    } else {
        return Err(Error::permission_denied(format!(
            "crypt remote `{remote_name}` requires `key_hex`, `password`, or `RSHIP_CRYPT_PASSWORD`"
        )));
    };
    let fname_mode = match ccfg
        .filename_encryption
        .as_deref()
        .unwrap_or("standard")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "standard" | "std" => FilenameEncryption::Standard,
        "off" | "none" => FilenameEncryption::Off,
        other => {
            return Err(Error::config(format!(
                "unknown crypt filename_encryption `{other}` for remote `{remote_name}` (expected: standard, off)"
            )));
        }
    };
    let mut crypt_cfg = CryptoConfig::new(remote_name).with_inner_prefix(inner_prefix);
    crypt_cfg.filename_encryption = fname_mode;
    let mut crypto = CryptoBackend::new(inner_backend, crypt_cfg, master.derive_subkeys())?;
    if let Some(pool) = &ctx.buffer_pool {
        crypto = crypto.with_buffer_pool(pool.clone());
    }
    Ok((Arc::new(crypto), sub_path))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use rship_core::ErrorKind;

    #[cfg(feature = "http")]
    mod mock_http {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        #[derive(Clone, Debug)]
        pub(super) struct RecordedReq {
            pub method: String,
            pub target: String,
            pub headers: Vec<(String, String)>,
            pub body: Vec<u8>,
        }

        impl RecordedReq {
            pub fn header(&self, name: &str) -> Option<&str> {
                self.headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
            }

            pub fn path(&self) -> &str {
                self.target
                    .split_once('?')
                    .map(|(p, _)| p)
                    .unwrap_or(&self.target)
            }

            pub fn query(&self) -> &str {
                self.target.split_once('?').map(|(_, q)| q).unwrap_or("")
            }
        }

        pub(super) struct MockServer {
            pub base_url: String,
            pub requests: Arc<Mutex<Vec<RecordedReq>>>,
            _shutdown: tokio::sync::oneshot::Sender<()>,
        }

        pub(super) async fn start<F>(handler: F) -> MockServer
        where
            F: Fn(&RecordedReq) -> (u16, Vec<(&'static str, String)>, Vec<u8>)
                + Send
                + Sync
                + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let requests_c = requests.clone();
            let handler = Arc::new(handler);
            let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut rx => break,
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break };
                            let reqs = requests_c.clone();
                            let h = handler.clone();
                            tokio::spawn(async move {
                                let (reader, mut writer) = stream.into_split();
                                let mut buf = BufReader::new(reader);
                                let mut req_line = String::new();
                                match buf.read_line(&mut req_line).await {
                                    Ok(0) | Err(_) => return,
                                    Ok(_) => {}
                                }
                                let mut parts = req_line.trim_end_matches(['\r', '\n']).splitn(3, ' ');
                                let method = parts.next().unwrap_or("").to_string();
                                let target = parts.next().unwrap_or("").to_string();
                                let mut headers = Vec::new();
                                let mut content_len: usize = 0;
                                loop {
                                    let mut hline = String::new();
                                    if buf.read_line(&mut hline).await.unwrap_or(0) == 0 {
                                        break;
                                    }
                                    let trimmed = hline.trim_end_matches(['\r', '\n']);
                                    if trimmed.is_empty() {
                                        break;
                                    }
                                    if let Some((k, v)) = trimmed.split_once(':') {
                                        let k = k.trim().to_string();
                                        let v = v.trim().to_string();
                                        if k.eq_ignore_ascii_case("content-length") {
                                            content_len = v.parse().unwrap_or(0);
                                        }
                                        headers.push((k, v));
                                    }
                                }
                                let mut body = vec![0u8; content_len];
                                if content_len > 0 && buf.read_exact(&mut body).await.is_err() {
                                    return;
                                }
                                let rec = RecordedReq {
                                    method,
                                    target,
                                    headers,
                                    body,
                                };
                                let (status, resp_headers, resp_body) = h(&rec);
                                reqs.lock().unwrap().push(rec);
                                let mut resp = format!(
                                    "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n",
                                    resp_body.len()
                                );
                                for (hk, hv) in resp_headers {
                                    resp.push_str(&format!("{hk}: {hv}\r\n"));
                                }
                                resp.push_str("\r\n");
                                if writer.write_all(resp.as_bytes()).await.is_err() {
                                    return;
                                }
                                if writer.write_all(&resp_body).await.is_err() {
                                    return;
                                }
                                let _ = writer.flush().await;
                            });
                        }
                    }
                }
            });

            MockServer {
                base_url: format!("http://{addr}"),
                requests,
                _shutdown: tx,
            }
        }
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn local_remote_config_wires_windows_safe_encoding_roundtrip_and_rejects_invalid() {
        use futures::StreamExt;
        use rship_core::backend::ListOptions;

        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("plain.txt"), b"hello-windows-safe").unwrap();

        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "ws",
                crate::config::LocalRemoteConfig::new(&dst).with_encoding("windows_safe"),
            )
            .build()
            .unwrap();

        client
            .copy_file(src.join("plain.txt").as_path(), "ws:CON.txt")
            .run()
            .await
            .unwrap();
        client
            .copy_file(src.join("plain.txt").as_path(), "ws:a:b?.txt")
            .run()
            .await
            .unwrap();

        assert!(dst.join("^43ON.txt").exists());
        assert!(dst.join("a^3Ab^3F.txt").exists());

        let st = client.stat("ws:a:b?.txt").await.unwrap().unwrap();
        assert_eq!(st.size, 18);

        let entries: Vec<_> = client
            .list("ws:", &ListOptions::shallow())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.nfc_path.as_str()).collect();
        assert!(names.contains(&"CON.txt"), "got {names:?}");
        assert!(names.contains(&"a:b?.txt"), "got {names:?}");

        let bad_cfg = AppConfig::new().with_remote(
            "bad_loc",
            crate::config::LocalRemoteConfig::new(&dst).with_encoding("bogus_encoding"),
        );
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let ctx = ResolveContext::new(&bad_cfg, &paths);
        let err = resolve_backend("bad_loc:", &ctx)
            .err()
            .expect("invalid encoding must fail");
        assert_eq!(err.kind, ErrorKind::Config);
    }

    #[cfg(feature = "http")]
    #[test]
    fn static_bearer_auth_takes_principal_first_and_token_second() {
        use rship_transport::oauth::OAuthProvider;
        let auth = rship_transport::oauth::StaticBearerAuth::new("remote-principal", "secret-tok");
        assert_eq!(auth.principal(), "remote-principal");
        let dbg = format!("{auth:?}");
        assert!(dbg.contains("remote-principal"));
        assert!(!dbg.contains("secret-tok"));
    }

    #[cfg(feature = "gdrive")]
    #[tokio::test]
    async fn gdrive_factory_wires_trash_default_true_scope_aliases_filters_and_static_bearer() {
        use futures::StreamExt;
        use rship_core::backend::ListOptions;

        let srv = mock_http::start(|req| {
            if req.method == "GET" && req.path() == "/files" {
                let q = req.query();
                if q.contains("hello.txt") {
                    let body = serde_json::to_vec(&serde_json::json!({
                        "files": [{
                            "id": "file-1",
                            "name": "hello.txt",
                            "mimeType": "text/plain",
                            "size": "5",
                            "parents": ["root"]
                        }]
                    }))
                    .unwrap();
                    return (
                        200,
                        vec![("Content-Type", "application/json".to_string())],
                        body,
                    );
                }
                return (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    br#"{"files":[]}"#.to_vec(),
                );
            }
            if req.method == "PATCH" && req.path() == "/files/file-1" {
                return (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    br#"{"id":"file-1","trashed":true}"#.to_vec(),
                );
            }
            if req.method == "DELETE" && req.path() == "/files/file-1" {
                return (204, vec![], vec![]);
            }
            (404, vec![], vec![])
        })
        .await;

        let client = crate::RshipClient::builder()
            .ephemeral()
            .allow_changes_feed(false)
            .remote(
                "gd_default",
                crate::config::GdriveRemoteConfig::new()
                    .with_api_base_url(&srv.base_url)
                    .with_access_token("secret-gd-token")
                    .with_scope("readonly"),
            )
            .remote(
                "gd_perm",
                crate::config::GdriveRemoteConfig::new()
                    .with_api_base_url(&srv.base_url)
                    .with_access_token("secret-gd-token-2")
                    .with_use_trash(false)
                    .with_shared_with_me(true)
                    .with_trashed_only(true),
            )
            .build()
            .unwrap();

        let (b_def, _) = client.resolve("gd_default:").unwrap();
        assert!(!b_def.endpoint_identity().contains("secret-gd-token"));

        // Default use_trash = None -> PATCH trashed=true, and StaticBearerAuth sends Bearer token.
        client.delete("gd_default:hello.txt").await.unwrap();
        {
            let reqs = srv.requests.lock().unwrap();
            assert!(reqs.iter().any(|r| {
                r.method == "PATCH"
                    && r.path() == "/files/file-1"
                    && r.header("authorization") == Some("Bearer secret-gd-token")
                    && std::str::from_utf8(&r.body)
                        .unwrap_or("")
                        .contains("\"trashed\":true")
            }));
        }
        srv.requests.lock().unwrap().clear();

        // Explicit use_trash = false -> DELETE.
        client.delete("gd_perm:hello.txt").await.unwrap();
        {
            let reqs = srv.requests.lock().unwrap();
            assert!(
                reqs.iter()
                    .any(|r| r.method == "DELETE" && r.path() == "/files/file-1")
            );
        }
        srv.requests.lock().unwrap().clear();

        // shared_with_me + trashed_only appear in Drive q= query.
        let _ = client
            .list("gd_perm:", &ListOptions::shallow())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        {
            let reqs = srv.requests.lock().unwrap();
            let list_req = reqs.iter().find(|r| r.path() == "/files").unwrap();
            assert!(list_req.query().contains("sharedWithMe"));
            assert!(list_req.query().contains("trashed"));
        }

        // Verify resolve_gdrive_scope expands aliases cleanly in build_gdrive.
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let cfg = AppConfig::new();
        let ctx = ResolveContext::new(&cfg, &paths).with_transport(&transport);
        let gd_ro = crate::config::GdriveRemoteConfig::new()
            .with_scope("readonly")
            .with_access_token("t");
        let _ = build_gdrive(&ctx, "gd_ro", &gd_ro).unwrap();
        assert_eq!(
            rship_backends::gdrive::resolve_gdrive_scope("readonly"),
            "https://www.googleapis.com/auth/drive.readonly"
        );
    }

    #[cfg(feature = "onedrive")]
    #[tokio::test]
    async fn onedrive_factory_wires_region_drive_type_chunk_size_and_static_bearer() {
        let srv = mock_http::start(|req| {
            if req.method == "GET" && req.path() == "/me/drive" {
                return (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    br#"{"quota":{"total":100,"used":20,"remaining":80}}"#.to_vec(),
                );
            }
            (404, vec![], vec![])
        })
        .await;

        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let cfg = AppConfig::new();
        let ctx = ResolveContext::new(&cfg, &paths).with_transport(&transport);

        // Sovereign region = cn selects 21Vianet Graph endpoint & static bearer principal.
        let od_cn = crate::config::OnedriveRemoteConfig::new()
            .with_region("cn")
            .with_drive_type("business")
            .with_chunk_size(5 * 1024 * 1024)
            .with_access_token("od-secret-tok");
        let b_cn = build_onedrive(&ctx, "od_cn", &od_cn).unwrap();
        assert!(
            b_cn.endpoint_identity()
                .contains("microsoftgraph.chinacloudapi.cn")
        );
        assert!(!b_cn.endpoint_identity().contains("od-secret-tok"));
        assert_eq!(b_cn.capabilities().default_chunk_size, 5 * 1024 * 1024);
        assert!(b_cn.capabilities().hashes.is_empty());

        // Explicit api_base_url overrides region endpoint and sends StaticBearerAuth header.
        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "od_override",
                crate::config::OnedriveRemoteConfig::new()
                    .with_region("cn")
                    .with_api_base_url(&srv.base_url)
                    .with_access_token("od-wire-tok"),
            )
            .build()
            .unwrap();
        let quota = client.about("od_override:").await.unwrap().unwrap();
        assert_eq!(quota.total_bytes, Some(100));
        let reqs = srv.requests.lock().unwrap();
        assert_eq!(reqs[0].header("authorization"), Some("Bearer od-wire-tok"));

        // Invalid region / drive_type / chunk_size fail with ErrorKind::Config.
        assert_eq!(
            build_onedrive(
                &ctx,
                "bad",
                &crate::config::OnedriveRemoteConfig::new()
                    .with_region("mars")
                    .with_access_token("t"),
            )
            .err()
            .expect("invalid region must fail")
            .kind,
            ErrorKind::Config
        );
        assert_eq!(
            build_onedrive(
                &ctx,
                "bad",
                &crate::config::OnedriveRemoteConfig::new()
                    .with_drive_type("invalid")
                    .with_access_token("t"),
            )
            .err()
            .expect("invalid drive_type must fail")
            .kind,
            ErrorKind::Config
        );
        assert_eq!(
            build_onedrive(
                &ctx,
                "bad",
                &crate::config::OnedriveRemoteConfig::new()
                    .with_chunk_size(12345)
                    .with_access_token("t"),
            )
            .err()
            .expect("invalid chunk_size must fail")
            .kind,
            ErrorKind::Config
        );
    }

    #[cfg(feature = "dropbox")]
    #[tokio::test]
    async fn dropbox_factory_wires_team_headers_shared_folders_and_static_bearer() {
        let srv = mock_http::start(|req| {
            if req.method == "POST" && req.path() == "/files/list_folder" {
                return (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    br#"{"entries":[],"cursor":"c","has_more":false}"#.to_vec(),
                );
            }
            (404, vec![], vec![])
        })
        .await;

        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "dbx_team",
                crate::config::DropboxRemoteConfig::new()
                    .with_api_base_url(&srv.base_url)
                    .with_access_token("dbx-wire-tok")
                    .with_root_namespace("12345")
                    .with_impersonate("dbmid:user1")
                    .with_shared_folders(true),
            )
            .build()
            .unwrap();

        let (b, _) = client.resolve("dbx_team:").unwrap();
        assert!(!b.endpoint_identity().contains("dbx-wire-tok"));

        use futures::StreamExt;
        let _ = client
            .list("dbx_team:", &rship_core::backend::ListOptions::shallow())
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let reqs = srv.requests.lock().unwrap();
        let req = reqs
            .iter()
            .find(|r| r.path() == "/files/list_folder")
            .unwrap();
        assert_eq!(req.header("authorization"), Some("Bearer dbx-wire-tok"));
        assert!(
            req.header("dropbox-api-path-root")
                .is_some_and(|v| v.contains("12345"))
        );
        assert_eq!(req.header("dropbox-api-select-user"), Some("dbmid:user1"));
    }

    #[cfg(feature = "gcs")]
    #[tokio::test]
    async fn gcs_factory_wires_endpoint_user_project_scope_env_auth_and_static_bearer() {
        let srv = mock_http::start(|req| {
            if req.method == "GET" && req.path() == "/storage/v1/b/my-b/o/obj.txt" {
                let body = serde_json::to_vec(&serde_json::json!({
                    "name": "obj.txt",
                    "size": "4",
                    "updated": "2026-01-01T00:00:00Z",
                    "generation": "1"
                }))
                .unwrap();
                return (
                    200,
                    vec![("Content-Type", "application/json".to_string())],
                    body,
                );
            }
            (404, vec![], vec![])
        })
        .await;

        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "gcs_ep",
                crate::config::GcsRemoteConfig::new()
                    .with_bucket("my-b")
                    .with_endpoint(&srv.base_url)
                    .with_user_project("pay-proj")
                    .with_scope("read_only")
                    .with_access_token("gcs-wire-tok"),
            )
            .build()
            .unwrap();

        let (b, _) = client.resolve("gcs_ep:").unwrap();
        assert!(!b.endpoint_identity().contains("gcs-wire-tok"));

        let st = client.stat("gcs_ep:obj.txt").await.unwrap().unwrap();
        assert_eq!(st.size, 4);
        {
            let reqs = srv.requests.lock().unwrap();
            let req = reqs
                .iter()
                .find(|r| r.path() == "/storage/v1/b/my-b/o/obj.txt")
                .unwrap();
            assert_eq!(req.header("authorization"), Some("Bearer gcs-wire-tok"));
            assert!(req.query().contains("userProject=pay-proj"));
        }

        // env_auth = true without explicit credentials fails with ErrorKind::Unsupported.
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let cfg = AppConfig::new();
        let ctx = ResolveContext::new(&cfg, &paths).with_transport(&transport);
        let env_only = crate::config::GcsRemoteConfig::new()
            .with_bucket("b")
            .with_env_auth(true);
        let err = build_gcs(&ctx, "gcs_env", &env_only, "b")
            .err()
            .expect("env_auth without explicit auth must fail");
        assert_eq!(err.kind, ErrorKind::Unsupported);
    }

    #[cfg(feature = "azureblob")]
    #[test]
    fn azureblob_factory_infers_container_account_and_endpoint_from_sas_url() {
        let azurite_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_sas_url("http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sig=x")
            .into();
        let (unit, rel) = extract_remote_unit(
            "az_azurite",
            &azurite_cfg,
            RelPath::parse("dir/f.txt").unwrap(),
        )
        .unwrap();
        assert_eq!(unit.as_deref(), Some("mycont"));
        assert_eq!(rel.as_str(), "dir/f.txt");

        let vh_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_sas_url("https://myacct.blob.core.windows.net/pubcont?sv=2023-11-03&sig=x")
            .into();
        let (unit2, rel2) = extract_remote_unit("az_vh", &vh_cfg, RelPath::root()).unwrap();
        assert_eq!(unit2.as_deref(), Some("pubcont"));
        assert!(rel2.is_root());

        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let app_cfg = AppConfig::new();
        let ctx = ResolveContext::new(&app_cfg, &paths).with_transport(&transport);
        let (b1, _) =
            build_remote_backend("az_azurite", &azurite_cfg, RelPath::root(), &ctx).unwrap();
        assert!(b1.endpoint_identity().contains("127.0.0.1:10000"));
        assert!(b1.endpoint_identity().contains("mycont"));
    }

    #[cfg(feature = "azureblob")]
    #[test]
    fn azureblob_extract_remote_unit_handles_whitespace_container_and_anonymous_sas_url() {
        let inline_sas = "http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sig=x";
        let none_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_sas_url(inline_sas)
            .into();
        let ws_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_container("   ")
            .with_sas_url(inline_sas)
            .into();

        for cfg in [&none_cfg, &ws_cfg] {
            let (u_root, r_root) = extract_remote_unit("az_inline", cfg, RelPath::root()).unwrap();
            assert_eq!(u_root.as_deref(), Some("mycont"));
            assert!(r_root.is_root());

            let (u_sub, r_sub) =
                extract_remote_unit("az_inline", cfg, RelPath::parse("sub/file.txt").unwrap())
                    .unwrap();
            assert_eq!(u_sub.as_deref(), Some("mycont"));
            assert_eq!(r_sub.as_str(), "sub/file.txt");
        }

        // Anonymous mode must ignore sas_url in extract_remote_unit just like build_remote_backend.
        let anon_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_anonymous(true)
            .with_sas_url(inline_sas)
            .into();
        let err = extract_remote_unit("az_anon", &anon_cfg, RelPath::root())
            .expect_err("anonymous azureblob without container must reject root target");
        assert_eq!(err.kind, ErrorKind::Config);

        // Repeated RshipClient::resolve calls with whitespace container must cache-hit cleanly.
        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "az_ws",
                crate::config::AzureblobRemoteConfig::new()
                    .with_container("  ")
                    .with_sas_url(inline_sas),
            )
            .build()
            .unwrap();
        let (b1, r1) = client.resolve("az_ws:sub/file.txt").unwrap();
        let (b2, r2) = client.resolve("az_ws:sub/file.txt").unwrap();
        assert_eq!(r1.as_str(), "sub/file.txt");
        assert_eq!(r2.as_str(), "sub/file.txt");
        assert!(Arc::ptr_eq(&b1, &b2));
    }

    #[cfg(all(feature = "azureblob", feature = "keyring"))]
    #[test]
    fn azureblob_keyring_sas_url_infers_container_and_preserves_cached_rel_path() {
        // Headless CI runners (e.g. Linux without a Secret Service) have no usable
        // OS keyring store, so this end-to-end keyring test cannot run there.
        if keyring::Entry::store_status().is_err() {
            eprintln!("skipping: OS keyring store unavailable on this platform");
            return;
        }

        struct KeyringGuard(String);
        impl Drop for KeyringGuard {
            fn drop(&mut self) {
                crate::secrets::delete_secret_if_ref(&self.0);
            }
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let slot = format!("test.m5a.az_sas.{}.{}", std::process::id(), nanos);
        let keyring_ref = format!("{}{}", crate::secrets::KEYRING_PREFIX, slot);
        let _guard = KeyringGuard(keyring_ref.clone());

        let stored_ref = crate::secrets::store_secret(
            &slot,
            "http://127.0.0.1:10000/devstoreaccount1/krcont?sv=2023-11-03&sig=abc",
        )
        .unwrap();
        assert_eq!(stored_ref, keyring_ref);

        let kr_none_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_sas_url(&keyring_ref)
            .into();
        let kr_ws_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_container("  ")
            .with_sas_url(&keyring_ref)
            .into();

        for cfg in [&kr_none_cfg, &kr_ws_cfg] {
            let (u_root, r_root) = extract_remote_unit("az_kr", cfg, RelPath::root()).unwrap();
            assert_eq!(u_root.as_deref(), Some("krcont"));
            assert!(r_root.is_root());

            let (u_sub, r_sub) =
                extract_remote_unit("az_kr", cfg, RelPath::parse("sub/file.txt").unwrap()).unwrap();
            assert_eq!(u_sub.as_deref(), Some("krcont"));
            assert_eq!(r_sub.as_str(), "sub/file.txt");
        }

        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "az_kr",
                crate::config::AzureblobRemoteConfig::new().with_sas_url(&keyring_ref),
            )
            .build()
            .unwrap();

        let (b_root, r_root) = client.resolve("az_kr:").unwrap();
        assert!(r_root.is_root());
        assert!(b_root.endpoint_identity().contains("krcont"));

        let (b1, r1) = client.resolve("az_kr:sub/file.txt").unwrap();
        assert_eq!(r1.as_str(), "sub/file.txt");
        assert!(Arc::ptr_eq(&b_root, &b1));

        // Second call hits backend cache and must preserve `sub/file.txt`.
        let (b2, r2) = client.resolve("az_kr:sub/file.txt").unwrap();
        assert_eq!(r2.as_str(), "sub/file.txt");
        assert!(Arc::ptr_eq(&b1, &b2));

        let (b3, r3) = client.resolve("az_kr:other/nested.bin").unwrap();
        assert_eq!(r3.as_str(), "other/nested.bin");
        assert!(Arc::ptr_eq(&b_root, &b3));

        // Missing keyring slot must fail consistently instead of splitting path segments.
        let missing_cfg: RemoteConfig = crate::config::AzureblobRemoteConfig::new()
            .with_sas_url(format!(
                "{}missing.{}.{}",
                crate::secrets::KEYRING_PREFIX,
                std::process::id(),
                nanos
            ))
            .into();
        let err = extract_remote_unit(
            "az_missing",
            &missing_cfg,
            RelPath::parse("sub/file.txt").unwrap(),
        )
        .expect_err("missing keyring sas_url must fail");
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
    }

    #[cfg(feature = "webdav")]
    #[tokio::test]
    async fn webdav_factory_wires_headers_and_rejects_bare_bearer_token_command() {
        let srv = mock_http::start(|req| {
            if req.method == "PROPFIND" {
                let xml = format!(
                    r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:"><d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>9</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"#,
                    req.path()
                );
                return (
                    207,
                    vec![("Content-Type", "application/xml".to_string())],
                    xml.into_bytes(),
                );
            }
            (404, vec![], vec![])
        })
        .await;

        let client = crate::RshipClient::builder()
            .ephemeral()
            .remote(
                "dav",
                crate::config::WebdavRemoteConfig::new(format!("{}/dav/", srv.base_url))
                    .with_bearer_token("dav-tok")
                    .with_header("X-Custom-Header", "custom-val"),
            )
            .build()
            .unwrap();
        let _ = client.stat("dav:item.txt").await.unwrap();
        {
            let reqs = srv.requests.lock().unwrap();
            assert_eq!(reqs[0].header("x-custom-header"), Some("custom-val"));
            assert_eq!(reqs[0].header("authorization"), Some("Bearer dav-tok"));
        }

        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let transport = rship_transport::HttpTransport::new(Default::default()).unwrap();
        let cfg = AppConfig::new();
        let ctx = ResolveContext::new(&cfg, &paths).with_transport(&transport);
        let cmd_only = crate::config::WebdavRemoteConfig::new("https://dav.example.com")
            .with_bearer_token_command("/usr/bin/get-token");
        let err = build_webdav(&ctx, "dav_cmd", &cmd_only)
            .err()
            .expect("bare bearer_token_command must fail");
        assert_eq!(err.kind, ErrorKind::Config);
    }

    #[cfg(feature = "sftp")]
    #[test]
    fn sftp_factory_wires_key_pem_and_reports_missing_auth_options() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("c.toml"), tmp.path().join("s"));
        let cfg = AppConfig::new();
        let ctx = ResolveContext::new(&cfg, &paths);

        let pem_cfg = crate::config::SftpRemoteConfig::new("127.0.0.1", "alice")
            .with_key_pem(
                "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----",
            )
            .with_known_hosts_path("/etc/ssh/ssh_known_hosts");
        let backend = build_sftp(&ctx, "sf_pem", &pem_cfg).unwrap();
        assert!(
            backend
                .endpoint_identity()
                .starts_with("sftp://alice@127.0.0.1")
        );

        let empty_cfg = crate::config::SftpRemoteConfig::new("127.0.0.1", "alice");
        let err = build_sftp(&ctx, "sf_empty", &empty_cfg)
            .err()
            .expect("missing sftp auth must fail");
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("key_pem"));
    }
}
