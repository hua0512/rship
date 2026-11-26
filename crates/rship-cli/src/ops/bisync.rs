//! Safe Three-Tree bidirectional sync (`rship bisync`) orchestration.

use anyhow::Result;
use rship_core::bandwidth::BandwidthSchedule;
use rship_core::bisync::{BisyncConfig, BisyncEngine, ConflictStrategy};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::CancelFlag;
use rship_core::filter::FilterSet;
use rship_core::memory::MemoryBudget;
use rship_core::progress::{TransferProgress, format_human_bytes};
use rship_core::types::FsyncMode;
use rship_state::{ProcessLock, SqliteSyncIndex};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use crate::cli::{BisyncArgs, parse_byte_size, parse_max_delete};
use crate::errors::{EXIT_OK, exit_code_for_category};
use crate::tui::LiveDashboardHandle;
use crate::ui::{Style, format_duration_human};

use super::{CliRuntime, resolve_display_mode, spawn_signal_handler};

pub async fn execute_bisync(args: BisyncArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let profile = rt.profile();
    let strategy_raw = args
        .conflict_strategy
        .as_deref()
        .or(profile.conflict_strategy.as_deref())
        .unwrap_or("keep-both");
    let strategy = ConflictStrategy::parse(strategy_raw).ok_or_else(|| {
        rship_core::Error::config(format!(
            "invalid --conflict-strategy `{strategy_raw}` (expected: keep-both, abort, prefer-a, prefer-b)"
        ))
    })?;

    let transfers = args.transfers.or(profile.transfers).unwrap_or(4).max(1);
    let copy_links = args.copy_links || profile.copy_links.unwrap_or(false);
    let user_buf_cap = args
        .max_buffer_mem
        .as_deref()
        .or(profile.max_buffer_mem.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let bwlimit_schedule = args
        .bwlimit
        .as_deref()
        .or(profile.bwlimit.as_deref())
        .map(BandwidthSchedule::parse)
        .transpose()?
        .flatten();
    let filter = FilterSet::from_options(&rt.build_filter_options(&args.filters)?)?;
    let fsync_mode: FsyncMode = args
        .fsync
        .as_deref()
        .or(profile.fsync.as_deref())
        .unwrap_or("batch")
        .parse()?;
    let parsed_max_delete = args
        .max_delete
        .as_deref()
        .or(profile.max_delete.as_deref())
        .map(parse_max_delete)
        .transpose()?;
    let no_lock = profile.no_lock.unwrap_or(false);

    let budget = MemoryBudget::resolve(user_buf_cap);
    let pool = BufferPool::new(budget.buffer_pool_bytes, budget.stream_slice_bytes)?;

    let (a_backend, a_prefix) = rt.resolve_backend_with_options(
        &args.path_a,
        Some(pool.clone()),
        copy_links,
        Some(fsync_mode),
    )?;
    let (b_backend, b_prefix) = rt.resolve_backend_with_options(
        &args.path_b,
        Some(pool.clone()),
        copy_links,
        Some(fsync_mode),
    )?;
    let state_actor = rt.state_actor()?;
    let paths = rt.paths;

    let _lock = if !args.dry_run && !no_lock {
        let pair_lock_id = format!(
            "bisync::{}::{}",
            a_backend.endpoint_identity(),
            b_backend.endpoint_identity()
        );
        Some(ProcessLock::try_acquire(&paths.locks_dir(), &pair_lock_id)?)
    } else {
        None
    };

    let job_id = format!(
        "bisync-{}-{:x}",
        rship_core::time::format_compact_utc(rship_core::time::now_unix_secs()),
        std::process::id()
    );
    let run_dir = rship_state::LazyRunDir::new(paths.ephemeral_dir(), &job_id);
    let sync_index = Arc::new(SqliteSyncIndex::open_with_run_dir(
        run_dir.clone(),
        rship_state::DEFAULT_RAM_SPILL_THRESHOLD,
    ));

    let cancel = CancelFlag::new();
    spawn_signal_handler(cancel.clone());

    let mut cfg = BisyncConfig::new(job_id.clone(), &args.path_a, &args.path_b);
    cfg.a_prefix = a_prefix;
    cfg.b_prefix = b_prefix;
    cfg.transfers = transfers;
    cfg.conflict_strategy = strategy;
    cfg.resync = args.resync;
    cfg.force_empty_side = args.force_empty_side;
    if let Some((count, pct)) = parsed_max_delete {
        cfg.max_delete = count;
        cfg.max_delete_percent = pct;
    }
    cfg.dry_run = args.dry_run;
    cfg.filter = filter;
    cfg.bwlimit_schedule = bwlimit_schedule;
    cfg.scratch_dir = Some(Arc::new(run_dir.clone()));

    let started = Instant::now();
    let progress = TransferProgress::new();
    let display_mode = resolve_display_mode(
        args.json,
        false,
        None,
        args.tui,
        args.progress,
        rt.t_opts.stderr_logs_active,
    );
    let dashboard =
        LiveDashboardHandle::spawn(display_mode, "BISYNC", progress.clone(), pool.clone());

    let engine = BisyncEngine::new(
        a_backend,
        b_backend,
        state_actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        cancel,
    )
    .with_progress(progress);

    let run_res = engine.run(&cfg, sync_index).await;
    if let Some(d) = dashboard {
        d.stop(run_res.is_ok()).await;
    }
    let report = run_res?;
    state_actor.flush().await?;

    let error_category = report.primary_error_category();
    let exit_code = error_category
        .map(exit_code_for_category)
        .unwrap_or(EXIT_OK);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": report.is_success(),
                "exit_code": exit_code,
                "error_category": error_category,
                "job_id": report.job_id,
                "copied_a_to_b": report.copied_a_to_b,
                "copied_b_to_a": report.copied_b_to_a,
                "deleted_on_a": report.deleted_on_a,
                "deleted_on_b": report.deleted_on_b,
                "dirs_created": report.dirs_created,
                "converged_skipped": report.converged_skipped,
                "conflicts_resolved": report.conflicts_resolved,
                "bytes_transferred": report.bytes_transferred,
                "conflicts": report.conflicts,
                "errors": report.errors,
                "error_details": report.error_details,
                "cancelled": report.cancelled,
            }))?
        );
    } else {
        let elapsed = format_duration_human(started.elapsed());
        let st = Style::stdout();
        let err_st = Style::stderr();
        let sym = if !report.errors.is_empty() {
            st.sym_err()
        } else if report.cancelled || !report.conflicts.is_empty() || args.dry_run {
            st.sym_warn()
        } else {
            st.sym_ok()
        };
        let verb = if args.dry_run {
            "bisync (dry-run)"
        } else {
            "bisync"
        };
        let dot = format!(" {} ", st.sym_dot());
        let mut parts = vec![
            format!("{} a→b", st.bold(&report.copied_a_to_b.to_string())),
            format!("{} b→a", st.bold(&report.copied_b_to_a.to_string())),
        ];
        if report.deleted_on_a > 0 || report.deleted_on_b > 0 {
            parts.push(st.warn(&format!(
                "del {}/{}",
                report.deleted_on_a, report.deleted_on_b
            )));
        }
        if report.converged_skipped > 0 {
            parts.push(st.dim(&format!("{} skipped", report.converged_skipped)));
        }
        if report.conflicts_resolved > 0 {
            parts.push(st.warn(&format!("{} resolved", report.conflicts_resolved)));
        }
        if !report.conflicts.is_empty() {
            parts.push(st.warn_bold(&format!("{} conflicts", report.conflicts.len())));
        }
        if !report.errors.is_empty() {
            parts.push(st.err_bold(&format!("{} errors", report.errors.len())));
        }
        println!(
            "{sym} {}  {} {} {} in {elapsed}  {}",
            st.bold(verb),
            parts.join(&dot),
            st.sym_dot(),
            st.bold(&format_human_bytes(report.bytes_transferred)),
            st.dim(&format!("[{}]", report.job_id))
        );
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
    }

    Ok(ExitCode::from(exit_code))
}
