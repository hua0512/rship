use rship_core::backend::StorageBackend;
use rship_core::buffer::BufferPool;
use rship_core::clock::{Clock, SystemClock};
use rship_core::memory::MemoryBudget;
use rship_core::state::{JournalStore, MemoryJournalStore};
use rship_core::types::FsyncMode;
use rship_core::{Error, Result};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::{AppConfig, AppPaths, RemoteConfig, RuntimeOptions, load_config};
use crate::factory::{InMemoryCredentials, import_rclone_conf, import_rclone_conf_in_memory};

use super::{ClientParts, RshipClient};

/// Fluent builder for constructing an [`RshipClient`].
#[must_use = "builders do nothing unless `.build()` is called"]
pub struct ClientBuilder {
    config_file: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    explicit_config: Option<AppConfig>,
    rclone_conf_path: Option<PathBuf>,
    rclone_conf_raw: Option<String>,
    extra_remotes: BTreeMap<String, RemoteConfig>,
    custom_backends: BTreeMap<String, Arc<dyn StorageBackend>>,
    ephemeral: bool,
    #[cfg(feature = "sqlite")]
    ephemeral_index_dir: Option<PathBuf>,
    allow_changes_feed: bool,
    max_buffer_mem: Option<u64>,
    runtime_options: RuntimeOptions,
    clock: Option<Arc<dyn Clock>>,
    #[cfg(feature = "http")]
    transport_config: rship_transport::TransportConfig,
    #[cfg(feature = "http")]
    explicit_transport: Option<rship_transport::HttpTransport>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("config_file", &self.config_file)
            .field("state_dir", &self.state_dir)
            .field("has_explicit_config", &self.explicit_config.is_some())
            .field("rclone_conf_path", &self.rclone_conf_path)
            .field("has_rclone_conf_raw", &self.rclone_conf_raw.is_some())
            .field(
                "extra_remotes",
                &self.extra_remotes.keys().collect::<Vec<_>>(),
            )
            .field(
                "custom_backends",
                &self.custom_backends.keys().collect::<Vec<_>>(),
            )
            .field("ephemeral", &self.ephemeral)
            .field("allow_changes_feed", &self.allow_changes_feed)
            .field("max_buffer_mem", &self.max_buffer_mem)
            .field("runtime_options", &self.runtime_options)
            .finish()
    }
}

impl ClientBuilder {
    /// Create a builder with default settings.
    pub fn new() -> Self {
        Self {
            config_file: None,
            state_dir: None,
            explicit_config: None,
            rclone_conf_path: None,
            rclone_conf_raw: None,
            extra_remotes: BTreeMap::new(),
            custom_backends: BTreeMap::new(),
            ephemeral: false,
            #[cfg(feature = "sqlite")]
            ephemeral_index_dir: None,
            allow_changes_feed: true,
            max_buffer_mem: None,
            runtime_options: RuntimeOptions::default(),
            clock: None,
            #[cfg(feature = "http")]
            transport_config: rship_transport::TransportConfig::default(),
            #[cfg(feature = "http")]
            explicit_transport: None,
        }
    }

    /// Load declarative remotes from an explicit `config.toml` file path.
    pub fn config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_file = Some(path.into());
        self
    }

    /// Provide an in-memory [`AppConfig`] directly instead of loading from disk.
    pub fn config(mut self, cfg: AppConfig) -> Self {
        self.explicit_config = Some(cfg);
        self
    }

    /// Load and merge remotes from an existing `rclone.conf` file path.
    ///
    /// When [`Self::ephemeral`] is enabled, OAuth tokens and inline service accounts are
    /// loaded strictly into memory with zero credential files written to disk.
    pub fn rclone_conf(mut self, path: impl Into<PathBuf>) -> Self {
        self.rclone_conf_path = Some(path.into());
        self
    }

    /// Load and merge remotes from raw `rclone.conf` INI text.
    ///
    /// When [`Self::ephemeral`] is enabled, OAuth tokens and inline service accounts are
    /// loaded strictly into memory with zero credential files written to disk.
    pub fn rclone_conf_str(mut self, raw: impl Into<String>) -> Self {
        self.rclone_conf_raw = Some(raw.into());
        self
    }

    /// Set an explicit [`AppPaths`] layout (`config_file` + `state_dir`).
    pub fn paths(mut self, paths: AppPaths) -> Self {
        self.config_file = Some(paths.config_file);
        self.state_dir = Some(paths.state_dir);
        self
    }

    /// Set the persistent state directory (`state.db`, `tokens/`, `runs/`).
    pub fn state_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(dir.into());
        self
    }

    /// Use purely in-memory journal, credentials, and sync indexes (zero `state.db` or
    /// token sidecar files written to disk).
    ///
    /// For syncing very large directory trees in ephemeral mode without holding the entire
    /// tree listing in RAM, combine with [`Self::ephemeral_index_dir`] (requires `sqlite`).
    #[cfg_attr(not(feature = "sqlite"), allow(rustdoc::broken_intra_doc_links))]
    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }

    /// Spill ephemeral per-run sync diff indexes to temporary SQLite files under `dir`
    /// (deleted automatically on drop) to keep peak RSS bounded on huge trees without
    /// creating a persistent `state.db`.
    #[cfg(feature = "sqlite")]
    pub fn ephemeral_index_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.ephemeral_index_dir = Some(dir.into());
        self
    }

    /// Register a declarative [`RemoteConfig`] (or any provider `*RemoteConfig`) under `name`.
    pub fn remote(mut self, name: impl Into<String>, cfg: impl Into<RemoteConfig>) -> Self {
        self.extra_remotes.insert(name.into(), cfg.into());
        self
    }

    /// Register a pre-built programmatic [`StorageBackend`] under `name`.
    pub fn register_backend<B: StorageBackend + 'static>(
        mut self,
        name: impl Into<String>,
        backend: B,
    ) -> Self {
        self.custom_backends.insert(name.into(), Arc::new(backend));
        self
    }

    /// Register a shared `Arc<dyn StorageBackend>` under `name`.
    pub fn register_backend_arc(
        mut self,
        name: impl Into<String>,
        backend: Arc<dyn StorageBackend>,
    ) -> Self {
        self.custom_backends.insert(name.into(), backend);
        self
    }

    /// Override the memory-bounded streaming [`BufferPool`] ceiling in bytes.
    pub fn max_buffer_mem(mut self, bytes: u64) -> Self {
        self.max_buffer_mem = Some(bytes);
        self
    }

    /// Enable or disable Google Drive `changes.list` incremental inventory sync.
    pub fn allow_changes_feed(mut self, allow: bool) -> Self {
        self.allow_changes_feed = allow;
        self
    }

    /// Supply process-level [`RuntimeOptions`] without mutating [`AppConfig`].
    pub fn runtime_options(mut self, options: RuntimeOptions) -> Self {
        self.runtime_options = options;
        self
    }

    /// Fast-fail Google Drive uploads with `ErrorKind::QuotaExceeded` on HTTP `403 userRateLimitExceeded`.
    pub fn gdrive_stop_on_upload_limit(mut self, stop: bool) -> Self {
        self.runtime_options.gdrive_stop_on_upload_limit = stop;
        self
    }

    /// Override per-request low-level HTTP retry count on Google Drive backends.
    pub fn gdrive_low_level_retries(mut self, retries: u32) -> Self {
        self.runtime_options.gdrive_low_level_retries = Some(retries);
        self
    }

    /// Follow local filesystem symlinks when reading/listing (`--copy-links` / `-L`).
    pub fn copy_links(mut self, enabled: bool) -> Self {
        self.runtime_options.copy_links = enabled;
        self
    }

    /// Configure the default local filesystem durability policy (`--fsync=always|batch|never`).
    pub fn fsync_mode(mut self, mode: FsyncMode) -> Self {
        self.runtime_options.fsync_mode = mode;
        self
    }

    /// Provide a custom [`Clock`] (e.g. `VirtualClock` for deterministic tests).
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Replace the HTTP transport configuration (requires the `http` feature).
    #[cfg(feature = "http")]
    pub fn transport_config(mut self, cfg: rship_transport::TransportConfig) -> Self {
        self.transport_config = cfg;
        self
    }

    /// Supply an already-built [`rship_transport::HttpTransport`] instance directly.
    #[cfg(feature = "http")]
    pub fn transport(mut self, transport: rship_transport::HttpTransport) -> Self {
        self.explicit_transport = Some(transport);
        self
    }

    /// Set a proactive global API TPS ceiling across all HTTP backends (`--tpslimit`; `0` = unlimited).
    #[cfg(feature = "http")]
    pub fn tps_limit(mut self, tps: f64) -> Self {
        self.transport_config.default_rate_limit.tps_limit =
            (tps.is_finite() && tps > 0.0).then_some(tps);
        self
    }

    /// Set the burst capacity for [`Self::tps_limit`].
    #[cfg(feature = "http")]
    pub fn tps_burst(mut self, burst: f64) -> Self {
        self.transport_config.default_rate_limit.tps_burst = Some(burst);
        self
    }

    /// Configure an explicit HTTP/HTTPS/SOCKS5 proxy URL.
    #[cfg(feature = "http")]
    pub fn proxy(mut self, url: impl Into<String>) -> Self {
        self.transport_config.proxy_url = Some(url.into());
        self
    }

    /// Load additional PEM CA certificates for private endpoints or corporate proxies.
    #[cfg(feature = "http")]
    pub fn ca_cert(mut self, path: impl Into<PathBuf>) -> Self {
        self.transport_config.ca_cert_path = Some(path.into());
        self
    }

    /// Finalize configuration and construct the [`RshipClient`].
    pub fn build(self) -> Result<RshipClient> {
        let paths = AppPaths::resolve(self.config_file.clone(), self.state_dir.clone());
        let mut app_cfg = match self.explicit_config {
            Some(cfg) => cfg,
            None => {
                if self.config_file.is_some() || !self.ephemeral {
                    load_config(&paths.config_file)?
                } else {
                    AppConfig::default()
                }
            }
        };

        let mut memory_creds = InMemoryCredentials::default();
        if let Some(rclone_path) = &self.rclone_conf_path {
            let raw = std::fs::read_to_string(rclone_path).map_err(|e| {
                Error::io(
                    format!("failed to read rclone.conf `{}`", rclone_path.display()),
                    e,
                )
            })?;
            if self.ephemeral {
                import_rclone_conf_in_memory(&mut app_cfg, &raw, true, &mut memory_creds)?;
            } else {
                import_rclone_conf(&mut app_cfg, &raw, &paths, true, false)?;
            }
        }
        if let Some(raw) = &self.rclone_conf_raw {
            if self.ephemeral {
                import_rclone_conf_in_memory(&mut app_cfg, raw, true, &mut memory_creds)?;
            } else {
                import_rclone_conf(&mut app_cfg, raw, &paths, true, false)?;
            }
        }

        for (name, rcfg) in self.extra_remotes {
            app_cfg.remotes.insert(name, rcfg);
        }

        let budget = MemoryBudget::resolve(self.max_buffer_mem);
        let pool = BufferPool::new(budget.buffer_pool_bytes, budget.stream_slice_bytes)?;
        let clock = self.clock.unwrap_or_else(SystemClock::shared);

        #[cfg_attr(not(feature = "http"), allow(unused_mut))]
        let mut runtime_options = self.runtime_options;
        #[cfg(feature = "http")]
        {
            if self.explicit_transport.is_none() {
                if let Some(ca) = self.transport_config.ca_cert_path.as_deref() {
                    rship_transport::validate_ca_cert_path(ca)?;
                }
                if let Some(proxy) = self.transport_config.proxy_url.as_deref() {
                    rship_transport::validate_proxy_url(proxy)?;
                }
            }
            let effective_tcfg = self
                .explicit_transport
                .as_ref()
                .map(|t| t.config())
                .unwrap_or(&self.transport_config);
            if runtime_options.sftp_connect_timeout.is_none() {
                runtime_options.sftp_connect_timeout = Some(effective_tcfg.connect_timeout);
            }
            if runtime_options.sftp_io_timeout.is_none() {
                runtime_options.sftp_io_timeout = Some(effective_tcfg.data_stall_timeout);
            }
        }

        #[cfg(feature = "sqlite")]
        let memory_journal: Option<Arc<dyn JournalStore>> = if self.ephemeral {
            Some(Arc::new(MemoryJournalStore::new()))
        } else {
            None
        };
        #[cfg(not(feature = "sqlite"))]
        let memory_journal: Option<Arc<dyn JournalStore>> =
            Some(Arc::new(MemoryJournalStore::new()));

        Ok(RshipClient::from_parts(ClientParts {
            app_cfg,
            paths,
            runtime_options,
            memory_creds,
            ephemeral: self.ephemeral,
            #[cfg(feature = "sqlite")]
            ephemeral_index_dir: self.ephemeral_index_dir,
            allow_changes_feed: self.allow_changes_feed,
            pool,
            clock,
            memory_journal,
            #[cfg(feature = "http")]
            transport_config: self.transport_config,
            #[cfg(feature = "http")]
            explicit_transport: self.explicit_transport,
            custom_backends: self.custom_backends,
        }))
    }
}
