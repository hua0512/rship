//! High-level ergonomic [`RshipClient`], [`ClientBuilder`], [`TransferBuilder`],
//! [`BisyncBuilder`], and [`TransferTarget`] SDK entrypoints.

mod bisync;
mod builder;
mod transfer;

pub use bisync::BisyncBuilder;
pub use builder::ClientBuilder;
pub use transfer::TransferBuilder;

use rship_core::backend::{BackendPath, EntryStream, ListOptions, StorageBackend};
use rship_core::buffer::BufferPool;
use rship_core::clock::Clock;
use rship_core::failover::FailoverPool;
use rship_core::path::{RelPath, TargetPath};
use rship_core::source::DataSource;
use rship_core::state::{
    DeltaInventoryStore, JobMode, JournalStore, MemoryJournalStore, MemorySyncIndex, SyncDiffIndex,
};
use rship_core::types::{ByteRange, Entry, EntryKind, FsyncMode, StorageQuota};
use rship_core::{Error, Result};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(any(feature = "http", feature = "sqlite"))]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::Notify;

use crate::config::{AppConfig, AppPaths, RuntimeOptions};
use crate::factory::{
    InMemoryCredentials, ResolveContext, build_remote_backend, extract_remote_unit,
    resolve_file_target_path, resolve_target_path, target_needs_inventory, target_needs_transport,
};

use transfer::TransferShape;

/// Target specification accepted by [`RshipClient`] transfers and filesystem operations.
///
/// Accepts string specs (`"gdrive2:2026/video.mp4"`, `"./local/dir"`), local [`Path`]s,
/// pre-parsed [`TargetPath`]s, or pre-resolved `(Arc<dyn StorageBackend>, RelPath)` pairs
/// (such as leased backends from [`FailoverPool`] without redundant resolution).
#[derive(Clone)]
#[non_exhaustive]
pub enum TransferTarget {
    /// Unparsed target specification string (`local/path` or `remote:path`).
    Spec(String),
    /// Pre-parsed [`TargetPath`].
    Parsed(TargetPath),
    /// Pre-resolved [`StorageBackend`] with a backend-relative [`RelPath`].
    Backend {
        /// Concrete backend handle to reuse directly.
        backend: Arc<dyn StorageBackend>,
        /// Relative path or prefix within `backend`.
        path: RelPath,
    },
}

impl TransferTarget {
    /// Construct a target from an unparsed string spec.
    pub fn spec(spec: impl Into<String>) -> Self {
        Self::Spec(spec.into())
    }

    /// Construct a target from an already-parsed [`TargetPath`].
    pub fn parsed(target: TargetPath) -> Self {
        Self::Parsed(target)
    }

    /// Construct a target directly from a resolved [`StorageBackend`] and relative path.
    pub fn backend(backend: Arc<dyn StorageBackend>, path: RelPath) -> Self {
        Self::Backend { backend, path }
    }

    pub(super) fn display_label(&self) -> String {
        match self {
            Self::Spec(s) => s.clone(),
            Self::Parsed(tp) => tp.to_string(),
            Self::Backend { backend, path } => {
                if path.is_root() {
                    format!("{}:", backend.name())
                } else {
                    format!("{}:{}", backend.name(), path)
                }
            }
        }
    }
}

impl fmt::Debug for TransferTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spec(s) => f.debug_tuple("Spec").field(s).finish(),
            Self::Parsed(tp) => f.debug_tuple("Parsed").field(tp).finish(),
            Self::Backend { backend, path } => f
                .debug_struct("Backend")
                .field("name", &backend.name())
                .field("kind", &backend.kind())
                .field("path", path)
                .finish(),
        }
    }
}

impl fmt::Display for TransferTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display_label())
    }
}

impl From<&str> for TransferTarget {
    fn from(s: &str) -> Self {
        Self::Spec(s.to_string())
    }
}

impl From<String> for TransferTarget {
    fn from(s: String) -> Self {
        Self::Spec(s)
    }
}

impl From<&String> for TransferTarget {
    fn from(s: &String) -> Self {
        Self::Spec(s.clone())
    }
}

impl From<PathBuf> for TransferTarget {
    fn from(p: PathBuf) -> Self {
        Self::Parsed(TargetPath::Local(p))
    }
}

impl From<&Path> for TransferTarget {
    fn from(p: &Path) -> Self {
        Self::Parsed(TargetPath::Local(p.to_path_buf()))
    }
}

impl From<TargetPath> for TransferTarget {
    fn from(tp: TargetPath) -> Self {
        Self::Parsed(tp)
    }
}

impl From<(Arc<dyn StorageBackend>, RelPath)> for TransferTarget {
    fn from((backend, path): (Arc<dyn StorageBackend>, RelPath)) -> Self {
        Self::Backend { backend, path }
    }
}

/// Result of resolving a target that may point to either a directory/prefix or a single file.
#[derive(Clone)]
#[non_exhaustive]
pub struct ResolvedTarget {
    /// Resolved storage backend handle.
    pub backend: Arc<dyn StorageBackend>,
    /// Backend-relative prefix or single-file path.
    pub prefix: RelPath,
    /// Populated when the target points directly to a single regular file.
    pub single_file: Option<Entry>,
}

impl fmt::Debug for ResolvedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedTarget")
            .field("backend", &self.backend.name())
            .field("kind", &self.backend.kind())
            .field("prefix", &self.prefix)
            .field("single_file", &self.single_file)
            .finish()
    }
}

/// Fallible, thread-safe lazily-initialized shared resource cell.
#[cfg(any(feature = "http", feature = "sqlite"))]
struct LazyResource<T> {
    slot: Mutex<Option<T>>,
}

#[cfg(feature = "sqlite")]
impl<T: Clone> LazyResource<T> {
    fn get_if_init(&self) -> Option<T> {
        self.slot.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[cfg(any(feature = "http", feature = "sqlite"))]
impl<T: Clone> LazyResource<T> {
    fn new(initial: Option<T>) -> Self {
        Self {
            slot: Mutex::new(initial),
        }
    }

    fn get_or_try_init(&self, init: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut guard = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = guard.as_ref() {
            return Ok(existing.clone());
        }
        let created = init()?;
        *guard = Some(created.clone());
        Ok(created)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BackendCacheKey {
    remote: String,
    unit: Option<String>,
    copy_links: bool,
    fsync_mode: FsyncMode,
}

pub(super) struct ActiveJobGuard {
    inner: Arc<ClientInner>,
}

impl Drop for ActiveJobGuard {
    fn drop(&mut self) {
        if self.inner.active_jobs.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.shutdown_notify.notify_waiters();
        }
    }
}

pub(super) struct ClientParts {
    pub(super) app_cfg: AppConfig,
    pub(super) paths: AppPaths,
    pub(super) runtime_options: RuntimeOptions,
    pub(super) memory_creds: InMemoryCredentials,
    pub(super) ephemeral: bool,
    #[cfg(feature = "sqlite")]
    pub(super) ephemeral_index_dir: Option<PathBuf>,
    pub(super) allow_changes_feed: bool,
    pub(super) pool: BufferPool,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) memory_journal: Option<Arc<dyn JournalStore>>,
    #[cfg(feature = "http")]
    pub(super) transport_config: rship_transport::TransportConfig,
    #[cfg(feature = "http")]
    pub(super) explicit_transport: Option<rship_transport::HttpTransport>,
    pub(super) custom_backends: BTreeMap<String, Arc<dyn StorageBackend>>,
}

struct ClientInner {
    app_cfg: AppConfig,
    paths: AppPaths,
    runtime_options: RuntimeOptions,
    memory_creds: InMemoryCredentials,
    ephemeral: bool,
    #[cfg(feature = "sqlite")]
    ephemeral_index_dir: Option<PathBuf>,
    allow_changes_feed: bool,
    pool: BufferPool,
    clock: Arc<dyn Clock>,
    memory_journal: Option<Arc<dyn JournalStore>>,
    #[cfg(feature = "sqlite")]
    state_actor: LazyResource<Arc<rship_state::StateActor>>,
    #[cfg(feature = "http")]
    transport_config: rship_transport::TransportConfig,
    #[cfg(feature = "http")]
    transport: LazyResource<rship_transport::HttpTransport>,
    custom_backends: BTreeMap<String, Arc<dyn StorageBackend>>,
    backend_cache: RwLock<HashMap<BackendCacheKey, Arc<dyn StorageBackend>>>,
    shutting_down: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Notify,
}

/// High-level, cheaply cloneable (`Arc`-backed), thread-safe `rship` SDK client.
///
/// Shares a single [`BufferPool`], durable or ephemeral [`JournalStore`], split-plane
/// HTTP transport (when `http` is enabled), and a synchronized cache of constructed
/// storage backends across concurrent transfers and filesystem operations (preserving
/// Google Drive folder-ID caches, write-QPS limiters, OAuth refresh singleflight state,
/// and SFTP connection pools).
#[derive(Clone)]
pub struct RshipClient {
    inner: Arc<ClientInner>,
}

impl fmt::Debug for RshipClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RshipClient")
            .field("ephemeral", &self.inner.ephemeral)
            .field(
                "remotes",
                &self.inner.app_cfg.remotes.keys().collect::<Vec<_>>(),
            )
            .field(
                "custom_backends",
                &self.inner.custom_backends.keys().collect::<Vec<_>>(),
            )
            .field("buffer_pool_max_bytes", &self.inner.pool.max_bytes())
            .field(
                "active_jobs",
                &self.inner.active_jobs.load(Ordering::Relaxed),
            )
            .field(
                "shutting_down",
                &self.inner.shutting_down.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl RshipClient {
    pub(super) fn from_parts(parts: ClientParts) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                app_cfg: parts.app_cfg,
                paths: parts.paths,
                runtime_options: parts.runtime_options,
                memory_creds: parts.memory_creds,
                ephemeral: parts.ephemeral,
                #[cfg(feature = "sqlite")]
                ephemeral_index_dir: parts.ephemeral_index_dir,
                allow_changes_feed: parts.allow_changes_feed,
                pool: parts.pool,
                clock: parts.clock,
                memory_journal: parts.memory_journal,
                #[cfg(feature = "sqlite")]
                state_actor: LazyResource::new(None),
                #[cfg(feature = "http")]
                transport_config: parts.transport_config,
                #[cfg(feature = "http")]
                transport: LazyResource::new(parts.explicit_transport),
                custom_backends: parts.custom_backends,
                backend_cache: RwLock::new(HashMap::new()),
                shutting_down: AtomicBool::new(false),
                active_jobs: AtomicUsize::new(0),
                shutdown_notify: Notify::new(),
            }),
        }
    }

    /// Start configuring a new [`RshipClient`] with [`ClientBuilder`].
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Construct an in-memory, zero-disk-state client using [`MemoryJournalStore`] and
    /// [`MemorySyncIndex`] (ideal for stateless scripts, local transfers, and tests).
    ///
    /// Note: [`MemorySyncIndex`] holds observed directory entries in RAM during full-tree
    /// `sync`/`copy`/`bisync` scans. For very large directory trees (100k+ entries), either
    /// use a persistent client or configure [`ClientBuilder::ephemeral_index_dir`] (requires
    /// the `sqlite` feature) to spill the diff index to temporary disk.
    #[cfg_attr(not(feature = "sqlite"), allow(rustdoc::broken_intra_doc_links))]
    pub fn ephemeral() -> Result<Self> {
        ClientBuilder::new().ephemeral().build()
    }

    /// Access the resolved declarative configuration.
    pub fn config(&self) -> &AppConfig {
        &self.inner.app_cfg
    }

    /// Access the process-level runtime overrides active on this client.
    pub fn runtime_options(&self) -> &RuntimeOptions {
        &self.inner.runtime_options
    }

    /// Access the resolved config/state directory layout.
    pub fn paths(&self) -> &AppPaths {
        &self.inner.paths
    }

    /// Access the shared memory-bounded [`BufferPool`].
    pub fn buffer_pool(&self) -> &BufferPool {
        &self.inner.pool
    }

    pub(super) fn clock(&self) -> &Arc<dyn Clock> {
        &self.inner.clock
    }

    /// Lazily open (if persistent and not yet initialized) and return the durable SQLite
    /// [`rship_state::StateActor`], or `Ok(None)` in ephemeral mode.
    #[cfg(feature = "sqlite")]
    pub fn state_actor(&self) -> Result<Option<Arc<rship_state::StateActor>>> {
        if self.inner.ephemeral {
            return Ok(None);
        }
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(Error::cancelled("rship client is shutting down"));
        }
        let actor = self.inner.state_actor.get_or_try_init(|| {
            Ok(Arc::new(rship_state::StateActor::open(
                &self.inner.paths.state_dir,
            )?))
        })?;
        Ok(Some(actor))
    }

    /// Return a handle to the shared operation journal and baseline store, lazily opening
    /// `journal.db` on first use in persistent mode.
    pub fn journal(&self) -> Result<Arc<dyn JournalStore>> {
        if let Some(mem) = &self.inner.memory_journal {
            return Ok(mem.clone());
        }
        #[cfg(feature = "sqlite")]
        {
            if let Some(actor) = self.state_actor()? {
                return Ok(actor);
            }
        }
        Ok(Arc::new(MemoryJournalStore::new()))
    }

    fn delta_inventory(&self) -> Result<Option<Arc<dyn DeltaInventoryStore>>> {
        #[cfg(feature = "sqlite")]
        {
            if let Some(actor) = self.state_actor()? {
                return Ok(Some(actor));
            }
        }
        Ok(None)
    }

    /// Lazily initialize and return a cheaply cloned handle to the shared split-plane
    /// HTTP transport.
    #[cfg(feature = "http")]
    pub fn transport(&self) -> Result<rship_transport::HttpTransport> {
        self.inner.transport.get_or_try_init(|| {
            rship_transport::HttpTransport::new(self.inner.transport_config.clone())
        })
    }

    /// Evict all cached remote [`StorageBackend`] instances so subsequent calls rebuild them.
    pub fn clear_backend_cache(&self) {
        if let Ok(mut cache) = self.inner.backend_cache.write() {
            cache.clear();
        }
    }

    /// Flush any pending durable SQLite WAL frames to disk (no-op in ephemeral mode or when
    /// the SQLite actor was never opened).
    pub async fn flush(&self) -> Result<()> {
        #[cfg(feature = "sqlite")]
        if let Some(actor) = self.inner.state_actor.get_if_init() {
            actor.flush().await?;
        }
        Ok(())
    }

    /// Gracefully reject new jobs, wait for all in-flight transfers and bisync runs to
    /// finish, clear cached backends, flush SQLite WAL, and join the background actor thread.
    ///
    /// Returns an error if the final WAL checkpoint fails or the background actor thread
    /// panicked. Safe to call multiple times after a clean shutdown.
    pub async fn shutdown(&self) -> Result<()> {
        self.inner.shutting_down.store(true, Ordering::Release);
        loop {
            let notified = self.inner.shutdown_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.active_jobs.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
        self.clear_backend_cache();
        #[cfg(feature = "sqlite")]
        if let Some(actor) = self.inner.state_actor.get_if_init() {
            actor.shutdown().await?;
        }
        Ok(())
    }

    pub(super) fn acquire_job_guard(&self) -> Result<ActiveJobGuard> {
        if self.inner.shutting_down.load(Ordering::Acquire) {
            return Err(Error::cancelled("rship client is shutting down"));
        }
        self.inner.active_jobs.fetch_add(1, Ordering::AcqRel);
        if self.inner.shutting_down.load(Ordering::Acquire) {
            if self.inner.active_jobs.fetch_sub(1, Ordering::AcqRel) == 1 {
                self.inner.shutdown_notify.notify_waiters();
            }
            return Err(Error::cancelled("rship client is shutting down"));
        }
        Ok(ActiveJobGuard {
            inner: self.inner.clone(),
        })
    }

    fn resolve_ctx_with<'a>(
        &'a self,
        #[cfg(feature = "http")] transport: Option<&'a rship_transport::HttpTransport>,
        inventory: Option<Arc<dyn DeltaInventoryStore>>,
        pool_override: Option<BufferPool>,
        copy_links: bool,
        fsync_mode: FsyncMode,
    ) -> ResolveContext<'a> {
        let mut rt_opts = self.inner.runtime_options.clone();
        rt_opts.copy_links = copy_links;
        rt_opts.fsync_mode = fsync_mode;
        let ctx = ResolveContext::new(&self.inner.app_cfg, &self.inner.paths)
            .with_inventory(inventory)
            .with_allow_changes_feed(self.inner.allow_changes_feed)
            .with_custom_backends(&self.inner.custom_backends)
            .with_clock(self.inner.clock.clone())
            .with_buffer_pool(pool_override.unwrap_or_else(|| self.inner.pool.clone()))
            .with_runtime_options(rt_opts)
            .with_memory_credentials(&self.inner.memory_creds);
        #[cfg(feature = "http")]
        let ctx = if let Some(t) = transport {
            ctx.with_transport(t)
        } else {
            ctx
        };
        ctx
    }

    fn resolve_cached_remote(
        &self,
        remote: &str,
        path: RelPath,
        pool_override: Option<BufferPool>,
        copy_links_override: Option<bool>,
        fsync_mode_override: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        if let Some(custom) = self.inner.custom_backends.get(remote) {
            return Ok((custom.clone(), path));
        }
        let Some(rcfg) = self.inner.app_cfg.remotes.get(remote) else {
            return Err(Error::config(format!(
                "remote `{remote}` is not configured"
            )));
        };
        let copy_links = copy_links_override.unwrap_or(self.inner.runtime_options.copy_links);
        let fsync_mode = fsync_mode_override.unwrap_or(self.inner.runtime_options.fsync_mode);
        let use_cache = pool_override.is_none();
        let (unit, rel) = extract_remote_unit(remote, rcfg, path.clone())?;
        let key = BackendCacheKey {
            remote: remote.to_string(),
            unit,
            copy_links,
            fsync_mode,
        };
        if use_cache
            && let Ok(cache) = self.inner.backend_cache.read()
            && let Some(cached) = cache.get(&key)
        {
            return Ok((cached.clone(), rel));
        }
        let target = TargetPath::Remote {
            remote: remote.to_string(),
            path: path.clone(),
        };
        let need_transport = target_needs_transport(&target, &self.inner.app_cfg);
        let need_inventory =
            target_needs_inventory(&target, &self.inner.app_cfg, self.inner.allow_changes_feed);
        #[cfg(feature = "http")]
        let transport_guard = if need_transport {
            Some(self.transport()?)
        } else {
            None
        };
        #[cfg(not(feature = "http"))]
        let _ = need_transport;
        let inventory = if need_inventory {
            self.delta_inventory()?
        } else {
            None
        };
        let ctx = self.resolve_ctx_with(
            #[cfg(feature = "http")]
            transport_guard.as_ref(),
            inventory,
            pool_override,
            copy_links,
            fsync_mode,
        );
        let (built, built_rel) = build_remote_backend(remote, rcfg, path, &ctx)?;
        if use_cache && let Ok(mut cache) = self.inner.backend_cache.write() {
            let shared = cache.entry(key).or_insert_with(|| built.clone());
            return Ok((shared.clone(), built_rel));
        }
        Ok((built, built_rel))
    }

    /// Resolve a target (string spec, [`Path`], [`TargetPath`], or pre-resolved backend)
    /// to its shared [`StorageBackend`] handle and backend-relative [`RelPath`] prefix.
    pub fn resolve(
        &self,
        target: impl Into<TransferTarget>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_target(&target.into(), None, None, None)
    }

    /// Resolve a target with optional per-call [`BufferPool`] and `copy_links` overrides.
    pub fn resolve_with_options(
        &self,
        target: impl Into<TransferTarget>,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_target(&target.into(), pool_override, copy_links, None)
    }

    /// Resolve a target with optional per-call [`BufferPool`], `copy_links`, and [`FsyncMode`] overrides.
    pub fn resolve_with_fsync(
        &self,
        target: impl Into<TransferTarget>,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_target(&target.into(), pool_override, copy_links, fsync_mode)
    }

    pub(super) fn resolve_target(
        &self,
        target: &TransferTarget,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        match target {
            TransferTarget::Backend { backend, path } => Ok((backend.clone(), path.clone())),
            TransferTarget::Spec(spec) => {
                let parsed = TargetPath::parse(spec)?;
                self.resolve_parsed(&parsed, pool_override, copy_links, fsync_mode)
            }
            TransferTarget::Parsed(parsed) => {
                self.resolve_parsed(parsed, pool_override, copy_links, fsync_mode)
            }
        }
    }

    fn resolve_parsed(
        &self,
        parsed: &TargetPath,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        match parsed {
            TargetPath::Local(_) => {
                let eff_copy_links = copy_links.unwrap_or(self.inner.runtime_options.copy_links);
                let eff_fsync_mode = fsync_mode.unwrap_or(self.inner.runtime_options.fsync_mode);
                let ctx = self.resolve_ctx_with(
                    #[cfg(feature = "http")]
                    None,
                    None,
                    pool_override,
                    eff_copy_links,
                    eff_fsync_mode,
                );
                resolve_target_path(parsed, &ctx)
            }
            TargetPath::Remote { remote, path } => self.resolve_cached_remote(
                remote,
                path.clone(),
                pool_override,
                copy_links,
                fsync_mode,
            ),
        }
    }

    /// Resolve an explicit single-file target specification.
    pub fn resolve_file(
        &self,
        target: impl Into<TransferTarget>,
        create_local_parent: bool,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_file_target(&target.into(), create_local_parent, None, None, None)
    }

    /// Resolve an explicit single-file target with optional per-call [`BufferPool`] and `copy_links` overrides.
    pub fn resolve_file_with_options(
        &self,
        target: impl Into<TransferTarget>,
        create_local_parent: bool,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_file_target(
            &target.into(),
            create_local_parent,
            pool_override,
            copy_links,
            None,
        )
    }

    /// Resolve an explicit single-file target with optional per-call [`BufferPool`], `copy_links`,
    /// and [`FsyncMode`] overrides.
    pub fn resolve_file_with_fsync(
        &self,
        target: impl Into<TransferTarget>,
        create_local_parent: bool,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_file_target(
            &target.into(),
            create_local_parent,
            pool_override,
            copy_links,
            fsync_mode,
        )
    }

    pub(super) fn resolve_file_target(
        &self,
        target: &TransferTarget,
        create_local_parent: bool,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        match target {
            TransferTarget::Backend { backend, path } => {
                if path.is_root() {
                    return Err(Error::invalid_path(format!(
                        "file target `{}:` must specify a file path, not backend root",
                        backend.name()
                    )));
                }
                Ok((backend.clone(), path.clone()))
            }
            TransferTarget::Spec(spec) => {
                let parsed = TargetPath::parse(spec)?;
                self.resolve_file_parsed(
                    &parsed,
                    create_local_parent,
                    pool_override,
                    copy_links,
                    fsync_mode,
                )
            }
            TransferTarget::Parsed(parsed) => self.resolve_file_parsed(
                parsed,
                create_local_parent,
                pool_override,
                copy_links,
                fsync_mode,
            ),
        }
    }

    fn resolve_file_parsed(
        &self,
        parsed: &TargetPath,
        create_local_parent: bool,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        match parsed {
            TargetPath::Local(_) => {
                let eff_copy_links = copy_links.unwrap_or(self.inner.runtime_options.copy_links);
                let eff_fsync_mode = fsync_mode.unwrap_or(self.inner.runtime_options.fsync_mode);
                let ctx = self.resolve_ctx_with(
                    #[cfg(feature = "http")]
                    None,
                    None,
                    pool_override,
                    eff_copy_links,
                    eff_fsync_mode,
                );
                resolve_file_target_path(parsed, &ctx, create_local_parent)
            }
            TargetPath::Remote { remote, path } => {
                let (backend, rel) = self.resolve_cached_remote(
                    remote,
                    path.clone(),
                    pool_override,
                    copy_links,
                    fsync_mode,
                )?;
                if rel.is_root() {
                    return Err(Error::invalid_path(format!(
                        "file target `{parsed}` must specify a file path, not remote root"
                    )));
                }
                Ok((backend, rel))
            }
        }
    }

    /// Resolve a target that may be either a directory/prefix OR an individual file
    /// (local path or `remote:path/to/file`).
    pub async fn resolve_any(&self, target: impl Into<TransferTarget>) -> Result<ResolvedTarget> {
        self.resolve_any_with_options(target, None, None).await
    }

    /// Resolve a directory-or-file target with optional per-call [`BufferPool`] and `copy_links` overrides.
    pub async fn resolve_any_with_options(
        &self,
        target: impl Into<TransferTarget>,
        pool_override: Option<BufferPool>,
        copy_links: Option<bool>,
    ) -> Result<ResolvedTarget> {
        let target = target.into();
        let local_path = match &target {
            TransferTarget::Spec(spec) => match TargetPath::parse(spec) {
                Ok(TargetPath::Local(p)) => Some(p),
                _ => None,
            },
            TransferTarget::Parsed(TargetPath::Local(p)) => Some(p.clone()),
            _ => None,
        };
        if let Some(ref p) = local_path
            && std::fs::symlink_metadata(p).is_ok_and(|m| !m.is_dir())
        {
            let (backend, rel) =
                self.resolve_file_target(&target, false, pool_override, copy_links, None)?;
            let single_file = backend.stat(&BackendPath::from_rel(rel.clone())).await?;
            return Ok(ResolvedTarget {
                backend,
                prefix: rel,
                single_file,
            });
        }

        let (backend, prefix) = self.resolve_target(&target, pool_override, copy_links, None)?;
        if !prefix.is_root()
            && let Some(entry) = backend.stat(&BackendPath::from_rel(prefix.clone())).await?
            && entry.kind == EntryKind::File
        {
            return Ok(ResolvedTarget {
                backend,
                prefix,
                single_file: Some(entry),
            });
        }

        Ok(ResolvedTarget {
            backend,
            prefix,
            single_file: None,
        })
    }

    /// Probe connectivity for a bucketless S3/GCS/Azure remote (`remote:` with no default
    /// bucket/container), returning `Ok(Some(endpoint_identity))` when a service-level probe
    /// succeeded or `Ok(None)` when the remote should be tested via normal directory listing.
    pub async fn probe_bucketless_remote(&self, remote: &str) -> Result<Option<String>> {
        let Some(rcfg) = self.inner.app_cfg.remotes.get(remote) else {
            return Err(Error::config(format!(
                "remote `{remote}` is not configured"
            )));
        };
        let target = TargetPath::Remote {
            remote: remote.to_string(),
            path: RelPath::root(),
        };
        let need_transport = target_needs_transport(&target, &self.inner.app_cfg);
        #[cfg(feature = "http")]
        let transport_guard = if need_transport {
            Some(self.transport()?)
        } else {
            None
        };
        #[cfg(not(feature = "http"))]
        let _ = need_transport;
        let ctx = self.resolve_ctx_with(
            #[cfg(feature = "http")]
            transport_guard.as_ref(),
            None,
            None,
            self.inner.runtime_options.copy_links,
            self.inner.runtime_options.fsync_mode,
        );
        crate::factory::probe_bucketless_remote(remote, rcfg, &ctx).await
    }

    /// Build a multi-account [`FailoverPool`] from named configured or registered remotes
    /// (e.g. `&["gdrive2", "gdrive3", "gdrive4"]`), sharing this client's cached backend instances.
    pub fn failover_pool(&self, remote_names: &[&str]) -> Result<FailoverPool> {
        let mut accounts = Vec::with_capacity(remote_names.len());
        for &name in remote_names {
            let spec = if name.contains(':') {
                name.to_string()
            } else {
                format!("{name}:")
            };
            let (backend, _) = self.resolve(spec)?;
            accounts.push((name.to_string(), backend));
        }
        FailoverPool::with_clock(accounts, self.inner.clock.clone())
    }

    /// Start building a `copy` transfer (copies new/changed files without deleting destination extras).
    pub fn copy(
        &self,
        src: impl Into<TransferTarget>,
        dst: impl Into<TransferTarget>,
    ) -> TransferBuilder<'_> {
        TransferBuilder::new(
            self,
            JobMode::Copy,
            src.into(),
            dst.into(),
            TransferShape::Directory,
        )
    }

    /// Start building a one-way `sync` transfer (mirrors `src` to `dst`, deleting destination extras).
    pub fn sync(
        &self,
        src: impl Into<TransferTarget>,
        dst: impl Into<TransferTarget>,
    ) -> TransferBuilder<'_> {
        TransferBuilder::new(
            self,
            JobMode::Sync,
            src.into(),
            dst.into(),
            TransferShape::Directory,
        )
    }

    /// Start building a verified `move` transfer (deletes each source file only after verified commit).
    pub fn move_path(
        &self,
        src: impl Into<TransferTarget>,
        dst: impl Into<TransferTarget>,
    ) -> TransferBuilder<'_> {
        TransferBuilder::new(
            self,
            JobMode::Move,
            src.into(),
            dst.into(),
            TransferShape::Directory,
        )
    }

    /// Start building an exact single-file `copy_file` (`copyto`) transfer.
    pub fn copy_file(
        &self,
        src: impl Into<TransferTarget>,
        dst: impl Into<TransferTarget>,
    ) -> TransferBuilder<'_> {
        TransferBuilder::new(
            self,
            JobMode::Copy,
            src.into(),
            dst.into(),
            TransferShape::SingleFile,
        )
    }

    /// Start building an exact single-file `move_file` (`moveto`) transfer.
    pub fn move_file(
        &self,
        src: impl Into<TransferTarget>,
        dst: impl Into<TransferTarget>,
    ) -> TransferBuilder<'_> {
        TransferBuilder::new(
            self,
            JobMode::Move,
            src.into(),
            dst.into(),
            TransferShape::SingleFile,
        )
    }

    /// Start building a direct-stat batch `copy_files` transfer over an explicit list of relative
    /// file paths (skips full directory listing and requires no sync diff index).
    pub fn copy_files<I, S>(
        &self,
        src_dir: impl Into<TransferTarget>,
        dst_dir: impl Into<TransferTarget>,
        files: I,
    ) -> TransferBuilder<'_>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let raw_files: Vec<String> = files.into_iter().map(Into::into).collect();
        TransferBuilder::new(
            self,
            JobMode::Copy,
            src_dir.into(),
            dst_dir.into(),
            TransferShape::FileList(raw_files),
        )
    }

    /// Start building a verified direct-stat batch `move_files` transfer over an explicit list of
    /// relative file paths (skips full directory listing and leaves unlisted sibling files untouched).
    pub fn move_files<I, S>(
        &self,
        src_dir: impl Into<TransferTarget>,
        dst_dir: impl Into<TransferTarget>,
        files: I,
    ) -> TransferBuilder<'_>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let raw_files: Vec<String> = files.into_iter().map(Into::into).collect();
        TransferBuilder::new(
            self,
            JobMode::Move,
            src_dir.into(),
            dst_dir.into(),
            TransferShape::FileList(raw_files),
        )
    }

    /// Start building a Three-Tree bidirectional sync (`bisync`) job.
    pub fn bisync(
        &self,
        side_a: impl Into<TransferTarget>,
        side_b: impl Into<TransferTarget>,
    ) -> BisyncBuilder<'_> {
        BisyncBuilder::new(self, side_a.into(), side_b.into())
    }

    /// Query metadata for a single local or remote path.
    pub async fn stat(&self, target: impl Into<TransferTarget>) -> Result<Option<Entry>> {
        let target = target.into();
        let (backend, rel) = self
            .resolve_file_target(&target, false, None, None, None)
            .or_else(|_| self.resolve_target(&target, None, None, None))?;
        backend.stat(&BackendPath::from_rel(rel)).await
    }

    /// Stream entries under `target` using extensible [`ListOptions`].
    pub async fn list(
        &self,
        target: impl Into<TransferTarget>,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let (backend, prefix) = self.resolve(target)?;
        backend.list_with_options(&prefix, options).await
    }

    /// Ensure directory path `target` exists (idempotent).
    pub async fn mkdir(&self, target: impl Into<TransferTarget>) -> Result<()> {
        let (backend, rel) = self.resolve(target)?;
        backend.mkdir(&rel).await
    }

    /// Delete a single file or empty directory at `target`.
    pub async fn delete(&self, target: impl Into<TransferTarget>) -> Result<()> {
        let target = target.into();
        let (backend, rel) = self
            .resolve_file_target(&target, false, None, None, None)
            .or_else(|_| self.resolve_target(&target, None, None, None))?;
        backend.delete(&BackendPath::from_rel(rel)).await
    }

    /// Perform a zero-data-transfer server-side rename within the same parent directory.
    pub async fn rename(&self, target: impl Into<TransferTarget>, new_name: &str) -> Result<Entry> {
        let (backend, rel) = self.resolve_file(target, false)?;
        backend.rename(&BackendPath::from_rel(rel), new_name).await
    }

    /// Query storage capacity and quota information for `target` (if supported by the backend).
    pub async fn about(&self, target: impl Into<TransferTarget>) -> Result<Option<StorageQuota>> {
        let (backend, _) = self.resolve(target)?;
        backend.about().await
    }

    /// Open a local or remote file for streaming or seekable range reads.
    pub async fn open_read(
        &self,
        target: impl Into<TransferTarget>,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        let (backend, rel) = self.resolve_file(target, false)?;
        backend.open_read(&BackendPath::from_rel(rel), range).await
    }

    pub(super) fn open_sync_index(&self, job_id: &str) -> Result<Arc<dyn SyncDiffIndex>> {
        #[cfg(feature = "sqlite")]
        {
            if let Some(dir) = &self.inner.ephemeral_index_dir {
                return Ok(Arc::new(rship_state::SqliteSyncIndex::open_temp(
                    dir, job_id,
                )?));
            }
            if !self.inner.ephemeral {
                return Ok(Arc::new(rship_state::SqliteSyncIndex::open_temp(
                    &self.inner.paths.ephemeral_dir(),
                    job_id,
                )?));
            }
        }
        let _ = job_id;
        Ok(Arc::new(MemorySyncIndex::new()))
    }
}

pub(super) fn next_job_id(prefix: &str) -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    format!(
        "{prefix}-{}-{:x}-{seq}",
        rship_core::time::format_compact_utc(rship_core::time::now_unix_secs()),
        std::process::id()
    )
}
