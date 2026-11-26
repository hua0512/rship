//! Durable SQLite journal & job lifecycle commands: `resume`, `status`, `gc`.

use anyhow::Result;
use futures::StreamExt;
use rship_core::state::{JournalStore, OperationState};
use std::process::ExitCode;

use crate::errors;
use crate::ops::CliRuntime;
use crate::ops::transfer::{
    PersistedJobOptions, ResolvedTransferRequest, ResumeOverrides, execute_resolved_transfer,
};
use crate::providers::abort_operation_for_gc;
use crate::ui;

pub async fn execute_resume(
    job_id: String,
    overrides: ResumeOverrides,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    let actor = rt.state_actor()?;
    let Some(job) = actor.get_job(&job_id).await? else {
        return Err(rship_core::Error::not_found(format!(
            "job `{job_id}` not found in {}",
            rt.paths.journal_db_path().display()
        ))
        .into());
    };
    let mut persisted: PersistedJobOptions = job
        .options_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| PersistedJobOptions {
            transfers: rt.app_cfg.defaults.transfers,
            part_concurrency: rt.app_cfg.defaults.part_concurrency,
            ..Default::default()
        });
    if persisted.filters.files_from.is_none()
        && let Some(ref ff_path) = persisted.filters.files_from_path
    {
        let text = std::fs::read_to_string(ff_path).map_err(|e| {
            rship_core::Error::io(
                format!("reload --files-from manifest `{ff_path}` for resume"),
                e,
            )
        })?;
        persisted.filters.files_from = Some(rship_core::filter::parse_files_from(&text));
    }
    let req = ResolvedTransferRequest::from_persisted(job_id, job, persisted, overrides);
    Box::pin(execute_resolved_transfer(req, rt)).await
}

pub async fn execute_status(limit: usize, json: bool, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let actor = rt.state_actor()?;
    let jobs = actor.list_jobs(limit).await?;
    let ops = actor.list_active_operations().await?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "jobs": jobs,
                "active_operations": ops,
            }))?
        );
    } else {
        let st = ui::Style::stdout();
        println!(
            "{} {}",
            st.bold("Recent jobs"),
            st.dim(&format!("({})", jobs.len()))
        );
        if jobs.is_empty() {
            println!("  {}", st.dim("No recent jobs."));
        } else {
            for j in &jobs {
                let bytes_str = format!(
                    "{}/{}",
                    rship_core::progress::format_human_bytes(j.bytes_done),
                    rship_core::progress::format_human_bytes(j.bytes_total)
                );
                println!(
                    "  {}  {:<4}  {}  {}  {}  {} {} {}",
                    st.dim(&j.job_id),
                    st.bold(j.mode.as_str()),
                    st.status_badge(&format!("{:<18}", j.status.as_str())),
                    st.dim(&format!("{}/{} files", j.files_done, j.files_total)),
                    st.dim(&format!("{bytes_str:>19}")),
                    j.src_spec,
                    st.sym_arrow(),
                    j.dst_spec
                );
            }
        }
        println!(
            "\n{} {}",
            st.bold("Active / resumable operations"),
            st.dim(&format!("({})", ops.len()))
        );
        if ops.is_empty() {
            println!("  {}", st.dim("No active operations."));
        } else {
            for o in &ops {
                let off_str = format!(
                    "{}/{}",
                    rship_core::progress::format_human_bytes(o.confirmed_offset),
                    rship_core::progress::format_human_bytes(o.src_version.size)
                );
                println!(
                    "  {}  {}  {}  {}  {}",
                    st.dim(&o.op_id),
                    st.dim(&format!("job={}", o.job_id)),
                    st.status_badge(&format!("{:<10}", o.state.as_str())),
                    st.dim(&off_str),
                    o.dst_nfc_path
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn execute_gc(
    all: bool,
    remote_multipart: Option<String>,
    older_than: String,
    dry_run: bool,
    json: bool,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    if let Some(target) = remote_multipart {
        let older_than_ns = rship_core::filter::parse_duration_nanos(&older_than)?;
        if older_than_ns < 0 {
            return Err(rship_core::Error::config(format!(
                "--older-than must be non-negative (got `{older_than}`)"
            ))
            .into());
        }
        let older_than_secs = if older_than_ns == 0 {
            0
        } else {
            older_than_ns.saturating_add(999_999_999) / 1_000_000_000
        };
        let now_secs = rship_core::time::now_unix_secs();
        let cutoff_secs = now_secs.saturating_sub(older_than_secs);

        let (backend, prefix) = rt.resolve_backend(&target, None)?;
        let uploads = backend.list_incomplete_uploads(&prefix).await?;
        let mut eligible = Vec::new();
        let mut skipped_recent = 0usize;
        for u in uploads {
            let is_old = if older_than_ns == 0 {
                true
            } else {
                u.initiated_unix_secs.is_some_and(|ts| ts <= cutoff_secs)
            };
            if is_old {
                eligible.push(u);
            } else {
                skipped_recent += 1;
            }
        }

        let mut aborted = 0usize;
        let mut errors: Vec<String> = Vec::new();
        if dry_run {
            aborted = eligible.len();
        } else {
            let b = backend.clone();
            let mut stream = futures::stream::iter(eligible.iter().cloned())
                .map(move |u| {
                    let b = b.clone();
                    async move {
                        let res = b.abort_incomplete_upload(&u).await;
                        (u, res)
                    }
                })
                .buffer_unordered(8);
            while let Some((u, res)) = stream.next().await {
                match res {
                    Ok(()) => aborted += 1,
                    Err(e) => errors.push(format!("abort `{}` ({}): {e}", u.key, u.upload_id)),
                }
            }
        }

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": errors.is_empty(),
                    "target": target,
                    "dry_run": dry_run,
                    "older_than": older_than,
                    "matched": eligible.len(),
                    "aborted": aborted,
                    "skipped_recent": skipped_recent,
                    "errors": errors,
                }))?
            );
        } else {
            let st = ui::Style::stdout();
            let verb = if dry_run { "would abort" } else { "aborted" };
            println!(
                "{} {verb} {} incomplete multipart upload(s) on `{target}` (older than {older_than}, {skipped_recent} recent kept)",
                if errors.is_empty() {
                    st.sym_ok()
                } else {
                    st.sym_warn()
                },
                st.bold(&aborted.to_string()),
            );
            for e in &errors {
                eprintln!("{} {e}", ui::Style::stderr().sym_err());
            }
        }
        return Ok(if errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(errors::EXIT_ERROR)
        });
    }

    let actor = rt.state_actor()?;
    let ops = actor.list_active_operations().await?;
    let mut cleaned = 0usize;
    for op in ops {
        // Integrity markers protect a corrupt destination from being trusted by a later
        // skip or `move`; only a verified transfer of that path may clear them.
        if op.state == OperationState::IntegrityFailed {
            continue;
        }
        if !all
            && matches!(
                op.state,
                OperationState::Active | OperationState::Completing
            )
        {
            continue;
        }
        let app_cfg = rt.app_cfg;
        let paths = rt.paths;
        let rt_opts = rt.runtime_options.clone();
        let transport = if op.backend_kind == "local" || op.backend_kind == "sftp" {
            None
        } else {
            Some(rt.transport()?)
        };
        abort_operation_for_gc(&op, app_cfg, paths, transport.as_ref(), &rt_opts).await;
        actor.delete_operation(&op.op_id).await?;
        cleaned += 1;
    }
    actor.flush().await?;
    let swept_runs = rship_state::sweep_stale_runs(&rt.paths.ephemeral_dir());
    let _ = rship_state::sweep_stale_locks(
        &rt.paths.locks_dir(),
        std::time::Duration::from_secs(24 * 3600),
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "cleaned_operations": cleaned,
                "swept_run_dirs": swept_runs,
            }))?
        );
    } else {
        let st = ui::Style::stdout();
        if swept_runs > 0 {
            println!(
                "{} cleaned {} operation(s) and {} stale run dir(s)",
                st.sym_ok(),
                st.bold(&cleaned.to_string()),
                st.bold(&swept_runs.to_string())
            );
        } else {
            println!(
                "{} cleaned {} operation(s)",
                st.sym_ok(),
                st.bold(&cleaned.to_string())
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
