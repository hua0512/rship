//! Directory and single-file `copy`, `sync`, `move`, `copyto`, `moveto`, and `resume` orchestration.

use anyhow::{Context, Result};
use rship::config::TransferProfile;
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::bandwidth::BandwidthSchedule;
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, DeleteMode, EngineConfig, TransferEngine};
use rship_core::filter::{FilterOptions, FilterSet};
use rship_core::memory::MemoryBudget;
use rship_core::path::{RelPath, TargetPath};
use rship_core::progress::{TransferProgress, format_human_bytes};
use rship_core::state::{BaselineMode, JobMode, JobRecord};
use rship_core::types::{EntryKind, FsyncMode};
use rship_state::{ProcessLock, SqliteSyncIndex};
use serde::{Deserialize, Serialize};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use crate::cli::{TransferArgs, parse_byte_size, parse_max_delete};
use crate::errors::{EXIT_OK, exit_code_for_category};
use crate::providers::build_filter_options_with_profile;
use crate::tui::{JsonErrorEventSink, LiveDashboardHandle};
use crate::ui::{Style, format_duration_human, format_rate};

use super::{CliRuntime, parse_duration_opt, resolve_display_mode, spawn_signal_handler};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedJobOptions {
    pub transfers: usize,
    pub adaptive: bool,
    pub part_concurrency: usize,
    pub chunk_size: Option<String>,
    pub max_buffer_mem: Option<String>,
    pub max_delete: Option<u64>,
    #[serde(default)]
    pub max_delete_percent: Option<f64>,
    #[serde(default)]
    pub fsync: Option<String>,
    pub checksum: bool,
    pub force_type_replace: bool,
    #[serde(default)]
    pub copy_links: bool,
    #[serde(default)]
    pub backup_dir: Option<String>,
    #[serde(default)]
    pub delete_mode: Option<DeleteMode>,
    pub bwlimit: Option<String>,
    pub strict_source: bool,
    pub strict_source_max_size: Option<String>,
    pub no_server_side_copy: bool,
    #[serde(default)]
    pub retries: Option<u32>,
    #[serde(default)]
    pub no_traverse: bool,
    #[serde(default)]
    pub baseline: Option<String>,
    #[serde(default)]
    pub no_lock: bool,
    pub delete_empty_src_dirs: bool,
    pub single_file_rename: bool,
    pub filters: FilterOptions,
}

/// Optional CLI overrides allowed when resuming an existing job via `rship resume`.
#[derive(Debug, Default)]
pub struct ResumeOverrides {
    pub transfers: Option<usize>,
    pub max_buffer_mem: Option<String>,
    pub bwlimit: Option<String>,
    pub json_progress: bool,
    pub stats: Option<String>,
    pub tui: bool,
    pub json: bool,
}

/// Fully resolved transfer request shared by fresh CLI transfers and `rship resume`.
///
/// Resolving `[defaults] -> [profiles.<name>] -> CLI flags` once into this struct keeps
/// `execute_transfer` and `execute_resume` clean and guarantees resumed jobs preserve
/// their original persisted options verbatim.
pub struct ResolvedTransferRequest {
    pub mode: JobMode,
    pub src: String,
    pub dst: String,
    pub opts: PersistedJobOptions,
    pub dry_run: bool,
    pub json_progress: bool,
    pub stats: Option<String>,
    pub progress: bool,
    pub tui: bool,
    pub json: bool,
    pub existing_job_id: Option<String>,
    pub resume_cursor: Option<String>,
}

impl ResolvedTransferRequest {
    /// Resolve a fresh CLI transfer by layering `args` on top of `profile`.
    pub fn from_cli(
        mode: JobMode,
        args: TransferArgs,
        delete_empty_src_dirs: bool,
        single_file_rename: bool,
        profile: &TransferProfile,
    ) -> Result<Self> {
        let filters = build_filter_options_with_profile(&args.filters, profile)?;
        let transfers = args.transfers.or(profile.transfers).unwrap_or(4).max(1);
        let part_concurrency = args
            .part_concurrency
            .or(profile.part_concurrency)
            .unwrap_or(4)
            .max(1);
        let adaptive = if args.adaptive {
            true
        } else if args.no_adaptive {
            false
        } else {
            profile.adaptive.unwrap_or(false)
        };
        let delete_mode = resolve_delete_mode(&args, profile)?;
        let max_delete_raw = args.max_delete.as_deref().or(profile.max_delete.as_deref());
        let (max_delete, max_delete_percent) = max_delete_raw
            .map(parse_max_delete)
            .transpose()?
            .unwrap_or((None, None));
        let fsync_raw = args
            .fsync
            .as_deref()
            .or(profile.fsync.as_deref())
            .unwrap_or("batch");
        let fsync_mode: FsyncMode = fsync_raw.parse()?;
        let baseline_raw = args
            .baseline
            .as_deref()
            .or(profile.baseline.as_deref())
            .unwrap_or("auto");
        let baseline_mode = BaselineMode::parse(baseline_raw).ok_or_else(|| {
            rship_core::Error::config(format!(
                "invalid --baseline `{baseline_raw}` (expected: auto, all, none)"
            ))
        })?;

        let opts = PersistedJobOptions {
            transfers,
            adaptive,
            part_concurrency,
            chunk_size: args.chunk_size.or_else(|| profile.chunk_size.clone()),
            max_buffer_mem: args
                .max_buffer_mem
                .or_else(|| profile.max_buffer_mem.clone()),
            max_delete,
            max_delete_percent,
            fsync: Some(fsync_mode.as_str().to_string()),
            checksum: args.checksum || profile.checksum.unwrap_or(false),
            force_type_replace: args.force_type_replace
                || profile.force_type_replace.unwrap_or(false),
            copy_links: args.copy_links || profile.copy_links.unwrap_or(false),
            backup_dir: args.backup_dir.or_else(|| profile.backup_dir.clone()),
            delete_mode: Some(delete_mode),
            bwlimit: args.bwlimit.or_else(|| profile.bwlimit.clone()),
            strict_source: args.strict_source || profile.strict_source.unwrap_or(false),
            strict_source_max_size: args
                .strict_source_max_size
                .or_else(|| profile.strict_source_max_size.clone()),
            no_server_side_copy: args.no_server_side_copy
                || profile.no_server_side_copy.unwrap_or(false),
            retries: args.retries.or(profile.retries),
            no_traverse: args.no_traverse,
            baseline: Some(baseline_mode.as_str().to_string()),
            no_lock: args.no_lock || profile.no_lock.unwrap_or(false),
            delete_empty_src_dirs,
            single_file_rename,
            filters,
        };

        Ok(Self {
            mode,
            src: args.src,
            dst: args.dst,
            opts,
            dry_run: args.dry_run,
            json_progress: args.json_progress,
            stats: args.stats,
            progress: args.progress,
            tui: args.tui,
            json: args.json,
            existing_job_id: None,
            resume_cursor: None,
        })
    }

    /// Reconstruct a transfer request from a persisted SQLite job record + explicit `resume` flags.
    pub fn from_persisted(
        job_id: String,
        job: JobRecord,
        mut persisted: PersistedJobOptions,
        overrides: ResumeOverrides,
    ) -> Self {
        persisted.transfers = overrides.transfers.unwrap_or(persisted.transfers).max(1);
        persisted.part_concurrency = persisted.part_concurrency.max(1);
        if let Some(mem) = overrides.max_buffer_mem {
            persisted.max_buffer_mem = Some(mem);
        }
        if let Some(bw) = overrides.bwlimit {
            persisted.bwlimit = Some(bw);
        }
        Self {
            mode: job.mode,
            src: job.src_spec,
            dst: job.dst_spec,
            opts: persisted,
            dry_run: false,
            json_progress: overrides.json_progress,
            stats: overrides.stats,
            progress: false,
            tui: overrides.tui,
            json: overrides.json,
            existing_job_id: Some(job_id),
            resume_cursor: job.resume_cursor,
        }
    }
}

fn resolve_delete_mode(args: &TransferArgs, profile: &TransferProfile) -> Result<DeleteMode> {
    if args.delete_before {
        return Ok(DeleteMode::Before);
    }
    if args.delete_during {
        return Ok(DeleteMode::During);
    }
    if args.delete_after {
        return Ok(DeleteMode::After);
    }
    let raw = args
        .delete_mode
        .as_deref()
        .or(profile.delete_mode.as_deref());
    match raw {
        Some(mode) => DeleteMode::parse(mode).ok_or_else(|| {
            rship_core::Error::config(format!(
                "invalid --delete-mode `{mode}` (expected: after, during, before)"
            ))
            .into()
        }),
        None => Ok(DeleteMode::After),
    }
}

pub async fn execute_transfer(
    mode: JobMode,
    args: TransferArgs,
    delete_empty_src_dirs: bool,
    single_file_rename: bool,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    let req = ResolvedTransferRequest::from_cli(
        mode,
        args,
        delete_empty_src_dirs,
        single_file_rename,
        rt.profile(),
    )?;
    execute_resolved_transfer(req, rt).await
}

pub async fn execute_resolved_transfer(
    req: ResolvedTransferRequest,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    let opts = req.opts;
    let mode = req.mode;
    let filter = FilterSet::from_options(&opts.filters)?;

    let user_buf_cap = opts
        .max_buffer_mem
        .as_deref()
        .map(parse_byte_size)
        .transpose()?;
    let chunk_override = opts
        .chunk_size
        .as_deref()
        .map(parse_byte_size)
        .transpose()?;
    let bwlimit_schedule = opts
        .bwlimit
        .as_deref()
        .map(BandwidthSchedule::parse)
        .transpose()?
        .flatten();
    let delete_mode = opts.delete_mode.unwrap_or(DeleteMode::After);
    let strict_max = opts
        .strict_source_max_size
        .as_deref()
        .map(parse_byte_size)
        .transpose()?;
    let baseline_raw = opts.baseline.as_deref().unwrap_or("auto");
    let baseline_mode = BaselineMode::parse(baseline_raw).ok_or_else(|| {
        rship_core::Error::config(format!(
            "invalid --baseline `{baseline_raw}` (expected: auto, all, none)"
        ))
    })?;
    let fsync_mode: FsyncMode = opts.fsync.as_deref().unwrap_or("batch").parse()?;
    let stats_interval = parse_duration_opt(req.stats.as_deref(), "--stats")?;
    let budget = MemoryBudget::resolve(user_buf_cap);
    let pool = BufferPool::new(budget.buffer_pool_bytes, budget.stream_slice_bytes)?;

    enum TransferResolution {
        SingleFile {
            src_backend: Arc<dyn StorageBackend>,
            src_path: BackendPath,
            dst_backend: Arc<dyn StorageBackend>,
            dst_rel: RelPath,
        },
        Directory {
            src_backend: Arc<dyn StorageBackend>,
            src_prefix: RelPath,
            dst_backend: Arc<dyn StorageBackend>,
            dst_prefix: RelPath,
        },
    }

    let resolution = if opts.single_file_rename {
        let (src_backend, src_rel) = rt.resolve_file_target_with_copy_links(
            &req.src,
            false,
            Some(pool.clone()),
            opts.copy_links,
        )?;
        let (dst_backend, dst_rel) = rt.resolve_file_target_with_options(
            &req.dst,
            !req.dry_run,
            Some(pool.clone()),
            false,
            Some(fsync_mode),
        )?;
        TransferResolution::SingleFile {
            src_backend,
            src_path: BackendPath::from_rel(src_rel),
            dst_backend,
            dst_rel,
        }
    } else {
        let parsed_src =
            TargetPath::parse(&req.src).with_context(|| format!("invalid path `{}`", req.src))?;
        let is_local_file = matches!(&parsed_src, TargetPath::Local(p) if if opts.copy_links { std::fs::metadata(p) } else { std::fs::symlink_metadata(p) }.is_ok_and(|m| m.is_file()));

        if is_local_file && !matches!(mode, JobMode::Sync) {
            let (src_backend, src_rel) = rt.resolve_file_target_with_copy_links(
                &req.src,
                false,
                Some(pool.clone()),
                opts.copy_links,
            )?;
            if !req.dry_run
                && let Ok(TargetPath::Local(dst_dir)) = TargetPath::parse(&req.dst)
            {
                std::fs::create_dir_all(&dst_dir)
                    .with_context(|| format!("create destination `{}`", dst_dir.display()))?;
            }
            let (dst_backend, dst_prefix) = rt.resolve_backend_with_options(
                &req.dst,
                Some(pool.clone()),
                false,
                Some(fsync_mode),
            )?;
            let dst_rel = dst_prefix.join_path(&src_rel);
            TransferResolution::SingleFile {
                src_backend,
                src_path: BackendPath::from_rel(src_rel),
                dst_backend,
                dst_rel,
            }
        } else {
            let (src_backend, src_prefix) =
                rt.resolve_backend_with_copy_links(&req.src, Some(pool.clone()), opts.copy_links)?;
            let remote_single_file = if !matches!(mode, JobMode::Sync) && !src_prefix.is_root() {
                match src_backend
                    .stat(&BackendPath::from_rel(src_prefix.clone()))
                    .await?
                {
                    Some(e) if e.kind == EntryKind::File => Some(e),
                    _ => None,
                }
            } else {
                None
            };

            if let Some(src_entry) = remote_single_file {
                let file_name = src_prefix
                    .segments()
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("invalid single-file source `{}`", req.src))?;
                if !req.dry_run
                    && let Ok(TargetPath::Local(dst_dir)) = TargetPath::parse(&req.dst)
                {
                    std::fs::create_dir_all(&dst_dir)
                        .with_context(|| format!("create destination `{}`", dst_dir.display()))?;
                }
                let (dst_backend, dst_prefix) = rt.resolve_backend_with_options(
                    &req.dst,
                    Some(pool.clone()),
                    false,
                    Some(fsync_mode),
                )?;
                let dst_rel = dst_prefix.join_path(&RelPath::parse(file_name)?);
                TransferResolution::SingleFile {
                    src_backend,
                    src_path: BackendPath::from_entry(&src_entry),
                    dst_backend,
                    dst_rel,
                }
            } else {
                let (dst_backend, dst_prefix) = rt.resolve_backend_with_options(
                    &req.dst,
                    Some(pool.clone()),
                    false,
                    Some(fsync_mode),
                )?;
                TransferResolution::Directory {
                    src_backend,
                    src_prefix,
                    dst_backend,
                    dst_prefix,
                }
            }
        }
    };

    let backup_target = if let Some(ref bd) = opts.backup_dir {
        let (bk_backend, bk_prefix) =
            rt.resolve_backend_with_options(bd, Some(pool.clone()), false, Some(fsync_mode))?;
        Some((bk_backend, bk_prefix))
    } else {
        None
    };

    let state_actor = rt.state_actor()?;
    let paths = rt.paths;
    let stderr_logs_active = rt.t_opts.stderr_logs_active;
    let options_json = serde_json::to_string(&opts).ok();

    let (src_backend, dst_backend, single_file_targets, src_prefix, dst_prefix) = match resolution {
        TransferResolution::SingleFile {
            src_backend,
            src_path,
            dst_backend,
            dst_rel,
        } => (
            src_backend,
            dst_backend,
            Some((src_path, dst_rel)),
            RelPath::root(),
            RelPath::root(),
        ),
        TransferResolution::Directory {
            src_backend,
            src_prefix,
            dst_backend,
            dst_prefix,
        } => (src_backend, dst_backend, None, src_prefix, dst_prefix),
    };

    // Fine-grained advisory destination lock so concurrent subprocesses targeting
    // distinct files, distinct `--files-from` batches, or distinct sub-prefixes on
    // the same cloud remote (e.g. `gdrive2`) never block each other, while still
    // guarding overlapping full-prefix `sync` runs (or disabled via `--no-lock`).
    let _lock = if !req.dry_run && !opts.no_lock {
        let lock_scope = if let Some((_, ref dst_rel)) = single_file_targets {
            format!("{}::file::{}", dst_backend.endpoint_identity(), dst_rel)
        } else if let Some(listed) = filter.files_from_paths() {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            for p in listed {
                p.as_str().hash(&mut h);
            }
            format!(
                "{}::files::{}::{:016x}",
                dst_backend.endpoint_identity(),
                dst_prefix,
                h.finish()
            )
        } else {
            format!(
                "{}::prefix::{}",
                dst_backend.endpoint_identity(),
                dst_prefix
            )
        };
        Some(ProcessLock::try_acquire(&paths.locks_dir(), &lock_scope)?)
    } else {
        None
    };

    let job_id = req.existing_job_id.unwrap_or_else(|| {
        format!(
            "job-{}-{:x}",
            rship_core::time::format_compact_utc(rship_core::time::now_unix_secs()),
            std::process::id()
        )
    });

    let cancel = CancelFlag::new();
    spawn_signal_handler(cancel.clone());

    let mut cfg = EngineConfig::new(job_id.clone(), mode, &req.src, &req.dst);
    cfg.src_prefix = src_prefix;
    cfg.dst_prefix = dst_prefix;
    cfg.transfers = opts.transfers.max(1);
    cfg.adaptive_concurrency = opts.adaptive;
    cfg.part_concurrency = opts.part_concurrency.max(1);
    cfg.chunk_size_override = chunk_override;
    cfg.delete = matches!(mode, JobMode::Sync);
    cfg.delete_mode = delete_mode;
    cfg.delete_source_after_transfer = matches!(mode, JobMode::Move);
    cfg.delete_empty_src_dirs = opts.delete_empty_src_dirs;
    cfg.max_delete = opts.max_delete;
    cfg.max_delete_percent = opts.max_delete_percent;
    if let Some((bk_backend, bk_prefix)) = backup_target {
        cfg = cfg.with_backup_dir(bk_backend, bk_prefix);
    }
    cfg.checksum = opts.checksum;
    cfg.dry_run = req.dry_run;
    cfg.force_type_replace = opts.force_type_replace;
    if let Some(r) = opts.retries {
        cfg.max_retries = r;
    }
    cfg.filter = filter;
    cfg.bwlimit_schedule = bwlimit_schedule;
    let run_dir = rship_state::LazyRunDir::new(paths.ephemeral_dir(), &job_id);

    cfg.strict_source = opts.strict_source;
    cfg.scratch_dir = Some(Arc::new(run_dir.clone()));
    if let Some(m) = strict_max {
        cfg.strict_source_max_bytes = m;
    }
    cfg.allow_server_side_copy = !opts.no_server_side_copy;
    cfg.no_traverse = opts.no_traverse;
    cfg.baseline_mode = baseline_mode;
    cfg.options_json = options_json;
    cfg.resume_cursor = req.resume_cursor;

    let started = Instant::now();
    let progress = TransferProgress::new();
    let display_mode = resolve_display_mode(
        req.json,
        req.json_progress,
        stats_interval,
        req.tui,
        req.progress,
        stderr_logs_active,
    );
    let title = mode.as_str().to_ascii_uppercase();
    let dashboard = LiveDashboardHandle::spawn(display_mode, title, progress.clone(), pool.clone());

    let mut engine = TransferEngine::new(
        src_backend,
        dst_backend,
        state_actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        cancel,
    )
    .with_progress(progress);
    if req.json_progress {
        engine = engine.with_event_sink(JsonErrorEventSink::new(mode.as_str()));
    }

    let _ = rship_state::sweep_stale_runs(&paths.ephemeral_dir());
    let _ = rship_state::sweep_stale_locks(
        &paths.locks_dir(),
        std::time::Duration::from_secs(24 * 3600),
    );
    let run_res = if let Some((src_path, dst_rel)) = single_file_targets {
        engine.run_single_file(&cfg, &src_path, &dst_rel).await
    } else {
        let index = SqliteSyncIndex::open_with_run_dir(
            run_dir.clone(),
            rship_state::DEFAULT_RAM_SPILL_THRESHOLD,
        );
        engine.run(&cfg, Arc::new(index)).await
    };
    drop(run_dir);
    if let Some(d) = dashboard {
        d.stop(run_res.is_ok()).await;
    }
    let report = run_res?;
    state_actor.flush().await?;

    let stats = pool.stats();
    let error_category = report.primary_error_category();
    let exit_code = error_category
        .map(exit_code_for_category)
        .unwrap_or(EXIT_OK);

    if req.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": report.is_success(),
                "exit_code": exit_code,
                "error_category": error_category,
                "job_id": report.job_id,
                "mode": mode.as_str(),
                "files_transferred": report.files_transferred,
                "files_skipped": report.files_skipped,
                "server_side_copies": report.server_side_copies,
                "sources_deleted": report.sources_deleted,
                "dirs_created": report.dirs_created,
                "items_deleted": report.items_deleted,
                "bytes_transferred": report.bytes_transferred,
                "conflicts": report.conflicts,
                "errors": report.errors,
                "error_details": report.error_details,
                "high_delete_warning": report.high_delete_warning,
                "files": report.file_results,
                "files_truncated": report.file_results_truncated,
                "cancelled": report.cancelled,
                "buffer_pool_peak_bytes": stats.peak_bytes(),
                "buffer_pool_cap_bytes": stats.max_bytes(),
                "final_small_concurrency": report.final_small_concurrency,
                "final_large_concurrency": report.final_large_concurrency,
            }))?
        );
    } else {
        let elapsed = started.elapsed();
        let st = Style::stdout();
        let err_st = Style::stderr();
        let sym = if !report.errors.is_empty() {
            st.sym_err()
        } else if report.cancelled || !report.conflicts.is_empty() || req.dry_run {
            st.sym_warn()
        } else {
            st.sym_ok()
        };
        let verb = if req.dry_run {
            format!("{} (dry-run)", mode.as_str())
        } else {
            mode.as_str().to_string()
        };

        let mut parts: Vec<String> = Vec::new();
        parts.push(format!(
            "{} transferred",
            st.bold(&report.files_transferred.to_string())
        ));
        if report.server_side_copies > 0 {
            parts.push(st.accent(&format!("{} server-side", report.server_side_copies)));
        }
        if report.files_skipped > 0 {
            parts.push(st.dim(&format!("{} skipped", report.files_skipped)));
        }
        if report.dirs_created > 0 {
            parts.push(st.dim(&format!("{} dirs", report.dirs_created)));
        }
        if report.items_deleted > 0 {
            parts.push(st.warn(&format!("{} deleted", report.items_deleted)));
        }
        if report.sources_deleted > 0 {
            parts.push(st.dim(&format!("{} moved", report.sources_deleted)));
        }
        if !report.conflicts.is_empty() {
            parts.push(st.warn_bold(&format!("{} conflicts", report.conflicts.len())));
        }
        if !report.errors.is_empty() {
            parts.push(st.err_bold(&format!("{} errors", report.errors.len())));
        }

        let rate_suffix = format_rate(report.bytes_transferred, elapsed)
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        let transfer_perf = format!(
            "{} in {}{}",
            st.bold(&format_human_bytes(report.bytes_transferred)),
            format_duration_human(elapsed),
            st.ok(&rate_suffix),
        );
        let dot = format!(" {} ", st.sym_dot());
        let meta = st.dim(&format!(
            "[pool {}/{} · {}]",
            format_human_bytes(stats.peak_bytes() as u64),
            format_human_bytes(stats.max_bytes() as u64),
            report.job_id,
        ));
        println!(
            "{sym} {}  {}{}  {transfer_perf}  {meta}",
            st.bold(&verb),
            parts.join(&dot),
            if parts.is_empty() { "" } else { " ·" },
        );

        if !req.json_progress {
            if let Some(ref warn_msg) = report.high_delete_warning {
                eprintln!("{} {}", err_st.sym_warn(), err_st.warn_bold(warn_msg));
            }
            for c in &report.conflicts {
                eprintln!(
                    "{} {} `{}`: {}",
                    err_st.sym_warn(),
                    err_st.warn_bold(&format!("conflict [{:?}]", c.kind)),
                    c.nfc_path,
                    c.detail
                );
            }
            for e in &report.errors {
                eprintln!("{} {}", err_st.sym_err(), e);
            }
            if report.cancelled {
                eprintln!(
                    "{} interrupted; resumable state preserved — run: {}",
                    err_st.sym_warn(),
                    err_st.accent_bold(&format!("rship resume {}", report.job_id))
                );
            }
        }
    }

    Ok(ExitCode::from(exit_code))
}
