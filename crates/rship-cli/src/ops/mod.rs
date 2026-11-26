//! High-level CLI operation orchestration modules (`transfer`, `bisync`, `check`, `fs`, `inspect`, `jobs`, `config_ops`).

pub mod bisync;
pub mod check;
pub mod config_ops;
pub mod fs;
pub mod inspect;
pub mod jobs;
pub mod transfer;

use anyhow::{Context, Result};
use futures::StreamExt;
pub use rship::ResolvedTarget;
use rship_core::backend::{ListOptions, StorageBackend};
use rship_core::buffer::BufferPool;
use rship_core::engine::{CancelFlag, TransferErrorInfo};
use rship_core::filter::{FilterSet, parse_duration_nanos};
use rship_core::path::{RelPath, TargetPath};
use rship_core::state::SyncDiffIndex;
use rship_core::types::{Entry, FsyncMode};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpDumpMode, HttpTransport, TransportConfig};
use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::cli::{Cli, Command, FilterArgs};
use crate::providers::{build_filter_options_with_profile, strip_prefix_raw};
use crate::tui::LiveDisplayMode;
use rship::config::{AppConfig, AppPaths, TransferProfile};
use rship_core::filter::FilterOptions;

pub struct TransportOverrides {
    pub ca_cert: Option<PathBuf>,
    pub proxy: Option<String>,
    pub connect_timeout: Option<String>,
    pub stall_timeout: Option<String>,
    pub control_timeout: Option<String>,
    pub tps_limit: Option<f64>,
    pub pool_max_idle_per_host: Option<usize>,
    pub dump_mode: HttpDumpMode,
    pub stderr_logs_active: bool,
}

impl TransportOverrides {
    /// Resolve network/transport settings with `CLI flags > --profile > [defaults]` precedence.
    pub fn from_cli_and_profile(
        cli: &Cli,
        profile: &TransferProfile,
        dump_mode: HttpDumpMode,
    ) -> Result<Self> {
        let raw_tps = cli.tpslimit.or(profile.tpslimit);
        let tps_limit = match raw_tps {
            Some(tps) if !tps.is_finite() || tps < 0.0 => {
                return Err(rship_core::Error::config(format!(
                    "--tpslimit must be a non-negative finite number (0 = unlimited; got {tps})"
                ))
                .into());
            }
            Some(0.0) => None,
            other => other,
        };
        let default_transfers = profile.transfers.unwrap_or(4).max(1);
        let desired_idle_pool = match &cli.command {
            Command::Copy(a) | Command::Copyto(a) | Command::Sync(a) | Command::Moveto(a) => Some(
                a.transfers
                    .unwrap_or(default_transfers)
                    .saturating_mul(2)
                    .clamp(32, 512),
            ),
            Command::Move(m) => Some(
                m.transfer
                    .transfers
                    .unwrap_or(default_transfers)
                    .saturating_mul(2)
                    .clamp(32, 512),
            ),
            Command::Bisync(b) => Some(
                b.transfers
                    .unwrap_or(default_transfers)
                    .saturating_mul(2)
                    .clamp(32, 512),
            ),
            Command::Resume { transfers, .. } => {
                transfers.map(|t| t.saturating_mul(2).clamp(32, 512))
            }
            _ => None,
        };
        let stderr_logs_active =
            cli.log_file.is_none() && (dump_mode != HttpDumpMode::None || cli.verbose > 0);
        Ok(Self {
            ca_cert: cli.ca_cert.clone().or_else(|| profile.ca_cert.clone()),
            proxy: cli.proxy.clone().or_else(|| profile.proxy.clone()),
            connect_timeout: cli
                .connect_timeout
                .clone()
                .or_else(|| profile.connect_timeout.clone()),
            stall_timeout: cli
                .stall_timeout
                .clone()
                .or_else(|| profile.stall_timeout.clone()),
            control_timeout: cli
                .control_timeout
                .clone()
                .or_else(|| profile.control_timeout.clone()),
            tps_limit,
            pool_max_idle_per_host: desired_idle_pool,
            dump_mode,
            stderr_logs_active,
        })
    }

    fn to_transport_config(&self) -> Result<TransportConfig> {
        let mut cfg = TransportConfig::default();
        cfg.ca_cert_path = self.ca_cert.clone();
        cfg.proxy_url = self.proxy.clone();
        if let Some(d) = parse_duration_opt(self.connect_timeout.as_deref(), "--connect-timeout")? {
            cfg.connect_timeout = d;
        }
        if let Some(d) = parse_duration_opt(self.stall_timeout.as_deref(), "--stall-timeout")? {
            cfg.data_stall_timeout = d;
        }
        if let Some(d) = parse_duration_opt(self.control_timeout.as_deref(), "--control-timeout")? {
            cfg.control_timeout = d;
        }
        if let Some(tps) = self.tps_limit {
            if !tps.is_finite() || tps < 0.0 {
                return Err(rship_core::Error::config(format!(
                    "--tpslimit must be a non-negative finite number (0 = unlimited; got {tps})"
                ))
                .into());
            }
            if tps > 0.0 {
                cfg.default_rate_limit.tps_limit = Some(tps);
            }
        }
        if let Some(idle) = self.pool_max_idle_per_host {
            cfg.pool_max_idle_per_host = idle.max(1);
        }
        cfg.dump_mode = self.dump_mode;
        Ok(cfg)
    }
}

/// Lazily initialized per-invocation CLI runtime backed by [`rship::RshipClient`].
///
/// Pure local and SFTP commands skip TLS root-cert loading and HTTP pool allocation;
/// commands that do not touch `journal.db` or Google Drive `changes.list` skip opening
/// `StateActor` and spawning its background SQLite thread completely.
pub struct CliRuntime<'a> {
    pub paths: &'a AppPaths,
    pub app_cfg: &'a AppConfig,
    pub profile: TransferProfile,
    pub t_opts: &'a TransportOverrides,
    pub runtime_options: rship::RuntimeOptions,
    client: rship::RshipClient,
}

impl<'a> CliRuntime<'a> {
    pub fn new(
        paths: &'a AppPaths,
        app_cfg: &'a AppConfig,
        profile: TransferProfile,
        t_opts: &'a TransportOverrides,
        allow_changes_feed: bool,
        runtime_options: rship::RuntimeOptions,
    ) -> Result<Self> {
        let transport_cfg = t_opts.to_transport_config()?;
        let client = rship::RshipClient::builder()
            .paths(paths.clone())
            .config(app_cfg.clone())
            .allow_changes_feed(allow_changes_feed)
            .runtime_options(runtime_options.clone())
            .transport_config(transport_cfg)
            .build()?;
        Ok(Self {
            paths,
            app_cfg,
            profile,
            t_opts,
            runtime_options,
            client,
        })
    }

    /// Access the effective [`TransferProfile`] (`[defaults]` overlaid with `--profile`).
    pub fn profile(&self) -> &TransferProfile {
        &self.profile
    }

    /// Build [`FilterOptions`] layering explicit CLI [`FilterArgs`] over the active profile.
    pub fn build_filter_options(&self, args: &FilterArgs) -> Result<FilterOptions> {
        build_filter_options_with_profile(args, &self.profile)
    }

    /// Access the underlying shared lazy [`rship::RshipClient`].
    pub fn client(&self) -> &rship::RshipClient {
        &self.client
    }

    pub fn transport(&self) -> Result<HttpTransport> {
        Ok(self.client.transport()?)
    }

    pub fn state_actor(&self) -> Result<Arc<StateActor>> {
        self.client
            .state_actor()?
            .ok_or_else(|| anyhow::anyhow!("CLI runtime unexpectedly created without SQLite actor"))
    }

    fn ensure_remote_configured(&self, spec: &str) -> Result<()> {
        if let Ok(TargetPath::Remote { remote, .. }) = TargetPath::parse(spec)
            && !self.app_cfg.remotes.contains_key(&remote)
        {
            let enabled: Vec<&str> = crate::providers::registered_providers()
                .into_iter()
                .map(|p| p.kind())
                .filter(|k| *k != "local")
                .collect();
            return Err(rship_core::Error::config(format!(
                "remote `{remote}` is not configured (run `rship auth {} {remote}` or `rship config import-rclone`)",
                enabled.join("|")
            ))
            .into());
        }
        Ok(())
    }

    pub fn resolve_backend(
        &self,
        spec: &str,
        pool: Option<BufferPool>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_backend_with_copy_links(spec, pool, false)
    }

    pub fn resolve_backend_with_copy_links(
        &self,
        spec: &str,
        pool: Option<BufferPool>,
        copy_links: bool,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_backend_with_options(spec, pool, copy_links, None)
    }

    pub fn resolve_backend_with_options(
        &self,
        spec: &str,
        pool: Option<BufferPool>,
        copy_links: bool,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.ensure_remote_configured(spec)?;
        Ok(self
            .client
            .resolve_with_fsync(spec, pool, Some(copy_links), fsync_mode)?)
    }

    pub fn resolve_file_target(
        &self,
        spec: &str,
        create_local_parent: bool,
        pool: Option<BufferPool>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_file_target_with_options(spec, create_local_parent, pool, false, None)
    }

    pub fn resolve_file_target_with_copy_links(
        &self,
        spec: &str,
        create_local_parent: bool,
        pool: Option<BufferPool>,
        copy_links: bool,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.resolve_file_target_with_options(spec, create_local_parent, pool, copy_links, None)
    }

    pub fn resolve_file_target_with_options(
        &self,
        spec: &str,
        create_local_parent: bool,
        pool: Option<BufferPool>,
        copy_links: bool,
        fsync_mode: Option<FsyncMode>,
    ) -> Result<(Arc<dyn StorageBackend>, RelPath)> {
        self.ensure_remote_configured(spec)?;
        Ok(self.client.resolve_file_with_fsync(
            spec,
            create_local_parent,
            pool,
            Some(copy_links),
            fsync_mode,
        )?)
    }

    /// Resolve a CLI target that may be either a directory/prefix OR a single file
    /// (local path or `remote:path/to/file`), enabling `ls`, `size`, `tree`, `hashsum`,
    /// `check`, and `delete` to work seamlessly on individual files as well as directories.
    pub async fn resolve_any_target(
        &self,
        spec: &str,
        pool: Option<BufferPool>,
    ) -> Result<ResolvedTarget> {
        self.ensure_remote_configured(spec)?;
        Ok(self
            .client
            .resolve_any_with_options(spec, pool, None)
            .await?)
    }

    pub async fn shutdown(self) -> Result<()> {
        Ok(self.client.shutdown().await?)
    }
}

pub fn parse_duration_opt(raw: Option<&str>, flag: &str) -> Result<Option<Duration>> {
    let Some(s) = raw else {
        return Ok(None);
    };
    let ns = parse_duration_nanos(s)
        .map_err(|e| rship_core::Error::config(format!("invalid {flag} `{s}`: {e}")))?;
    if ns <= 0 {
        return Err(rship_core::Error::config(format!("{flag} must be positive")).into());
    }
    Ok(Some(Duration::from_nanos(ns as u64)))
}

pub fn validate_transport_overrides(opts: &TransportOverrides) -> Result<()> {
    if let Some(ca_cert) = opts.ca_cert.as_deref() {
        rship_transport::validate_ca_cert_path(ca_cert)?;
    }
    if let Some(proxy) = opts.proxy.as_deref() {
        rship_transport::validate_proxy_url(proxy)?;
    }
    let _ = opts.to_transport_config()?;
    Ok(())
}

pub fn build_transport(opts: &TransportOverrides) -> Result<HttpTransport> {
    HttpTransport::new(opts.to_transport_config()?).context("failed to initialize HTTP transport")
}

/// Spawn a cooperative cancellation task listening to both `SIGINT` (Ctrl-C) and,
/// on Unix containers/supervisors, `SIGTERM` so `rship` flushes SQLite WAL, preserves
/// resumable upload sessions, and exits cleanly (`130`) without deleting source files.
pub fn spawn_signal_handler(cancel: CancelFlag) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).ok();
            let mut interrupted_once = false;
            loop {
                tokio::select! {
                    res = tokio::signal::ctrl_c() => {
                        if res.is_err() {
                            break;
                        }
                        if !interrupted_once {
                            interrupted_once = true;
                            cancel.cancel();
                        } else {
                            crate::tui::restore_cursor_if_hidden();
                            std::process::exit(130);
                        }
                    }
                    _ = async {
                        if let Some(ref mut s) = sigterm {
                            s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        if !interrupted_once {
                            interrupted_once = true;
                            cancel.cancel();
                        } else {
                            crate::tui::restore_cursor_if_hidden();
                            std::process::exit(143);
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            let mut interrupted_once = false;
            while tokio::signal::ctrl_c().await.is_ok() {
                if !interrupted_once {
                    interrupted_once = true;
                    cancel.cancel();
                } else {
                    crate::tui::restore_cursor_if_hidden();
                    std::process::exit(130);
                }
            }
        }
    });
}

pub fn resolve_display_mode(
    json: bool,
    json_progress: bool,
    stats_interval: Option<Duration>,
    tui: bool,
    progress: bool,
    stderr_logs_active: bool,
) -> LiveDisplayMode {
    if json_progress {
        LiveDisplayMode::JsonLines {
            interval: stats_interval.unwrap_or(Duration::from_secs(1)),
        }
    } else if json || !crate::ui::stderr_supports_ansi() {
        LiveDisplayMode::Off
    } else if tui {
        LiveDisplayMode::MultiTaskTui
    } else if progress {
        LiveDisplayMode::SingleLine
    } else if stderr_logs_active {
        // Avoid ANSI cursor-rewrite collisions with `--dump headers` / `-v` logs on stderr.
        LiveDisplayMode::Off
    } else if io::stderr().is_terminal() {
        LiveDisplayMode::MultiTaskTui
    } else {
        LiveDisplayMode::Off
    }
}

pub(super) async fn observe_into_index(
    backend: &Arc<dyn StorageBackend>,
    prefix: &RelPath,
    filter: &FilterSet,
    now_ns: i64,
    is_src: bool,
    index: &Arc<SqliteSyncIndex>,
) -> (bool, Vec<TransferErrorInfo>) {
    let mut errors = Vec::new();
    let mut complete = true;
    let list_opts = ListOptions::recursive().with_filter_pruning(filter, prefix);
    let mut stream = match backend.list_with_options(prefix, &list_opts).await {
        Ok(s) => s,
        Err(e) => {
            errors.push(TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("list `{}` failed: {e}", backend.name()),
            ));
            return (false, errors);
        }
    };
    let mut batch: Vec<Entry> = Vec::with_capacity(2000);
    while let Some(item) = stream.next().await {
        match item {
            Ok(mut entry) => {
                if !prefix.is_root() {
                    let Some(rel) = entry.nfc_path.strip_prefix(prefix) else {
                        continue;
                    };
                    let old_raw = entry.raw_path.take();
                    entry.nfc_path = rel;
                    if let Some(raw) = old_raw
                        && let Some(raw_rel) = strip_prefix_raw(&raw, prefix.as_str())
                    {
                        entry.set_raw_path(&raw_rel);
                    }
                }
                if entry.nfc_path.is_root() {
                    continue;
                }
                if !filter.matches_entry(&entry, now_ns) {
                    continue;
                }
                batch.push(entry);
                if batch.len() >= 2000 {
                    let flush = std::mem::replace(&mut batch, Vec::with_capacity(2000));
                    let res = if is_src {
                        index.insert_src_batch(flush).await
                    } else {
                        index.insert_dst_batch(flush).await
                    };
                    if let Err(e) = res {
                        errors.push(TransferErrorInfo::from_error_with_message(
                            None,
                            &e,
                            format!("index insert failed: {e}"),
                        ));
                        complete = false;
                        break;
                    }
                }
            }
            Err(e) => {
                complete = false;
                errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &e,
                    format!("list `{}` error: {e}", backend.name()),
                ));
            }
        }
    }
    if !batch.is_empty() {
        let res = if is_src {
            index.insert_src_batch(batch).await
        } else {
            index.insert_dst_batch(batch).await
        };
        if let Err(e) = res {
            errors.push(TransferErrorInfo::from_error_with_message(
                None,
                &e,
                format!("index flush failed: {e}"),
            ));
            complete = false;
        }
    }
    (complete, errors)
}
