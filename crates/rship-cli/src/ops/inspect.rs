//! Inspection & maintenance CLI operations (`about`, streaming `hashsum`, `dedupe`).

use anyhow::Result;
use futures::StreamExt;
use rship_core::ErrorCategory;
use rship_core::backend::{BackendPath, ListOptions};
use rship_core::clock::SystemClock;
use rship_core::engine::TransferErrorInfo;
use rship_core::filter::FilterSet;
use rship_core::path::RelPath;
use rship_core::progress::format_human_bytes;
use rship_core::state::{ConflictKind, SyncDiffIndex};
use rship_core::types::{Entry, EntryKind, HashKind};
use rship_state::SqliteSyncIndex;
use std::collections::{BTreeMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::{DedupeArgs, HashsumArgs};
use crate::errors::{EXIT_OK, exit_code_for_category};
use crate::ops::CliRuntime;
use crate::ui::Style;

pub async fn execute_about(target: &str, json: bool, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let (backend, _) = rt.resolve_backend(target, None)?;

    let quota = backend.about().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&quota)?);
    } else if let Some(q) = quota {
        let st = Style::stdout();
        println!("{}  {}", st.bold(target), st.accent(backend.kind()));
        if let (Some(u), Some(t)) = (q.used_bytes, q.total_bytes)
            && t > 0
        {
            let ratio = u as f64 / t as f64;
            println!("  {}  {:>5.1}%", st.quota_bar(ratio, 26), ratio * 100.0);
        }
        if let Some(t) = q.total_bytes {
            println!(
                "  {} {:>10}  {}",
                st.dim("Total  "),
                st.bold(&format_human_bytes(t)),
                st.dim(&format!("({t} B)"))
            );
        }
        if let Some(u) = q.used_bytes {
            println!(
                "  {} {:>10}  {}",
                st.dim("Used   "),
                st.bold(&format_human_bytes(u)),
                st.dim(&format!("({u} B)"))
            );
        }
        if let Some(f) = q.free_bytes {
            println!(
                "  {} {:>10}  {}",
                st.dim("Free   "),
                st.ok(&format_human_bytes(f)),
                st.dim(&format!("({f} B)"))
            );
        }
        if let Some(tr) = q.trashed_bytes {
            println!(
                "  {} {:>10}  {}",
                st.dim("Trashed"),
                st.dim(&format_human_bytes(tr)),
                st.dim(&format!("({tr} B)"))
            );
        }
    } else {
        let st = Style::stdout();
        println!(
            "{} target `{target}` {} does not report storage quota",
            st.dim("·"),
            st.dim(&format!("({})", backend.kind()))
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Stream file hashes with bounded concurrency (`--checkers`).
///
/// In plain text mode, hashes are printed immediately as they finish without buffering all
/// entries in RAM. In `--json` mode, results are collected and sorted for deterministic output.
pub async fn execute_hashsum(args: HashsumArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let kind = HashKind::parse(&args.hash).ok_or_else(|| {
        rship_core::Error::config(format!(
            "unknown hash algorithm `{}` (supported: md5, sha1, sha256, blake3, crc32c, crc64nvme)",
            args.hash
        ))
    })?;

    let resolved = rt.resolve_any_target(&args.target, None).await?;
    let backend = resolved.backend;
    let prefix = resolved.prefix;
    let filter = Arc::new(FilterSet::from_options(
        &rt.build_filter_options(&args.filters)?,
    )?);
    let now_ns = SystemClock::shared().now_unix_nanos();

    let is_single_file = resolved.single_file.is_some();
    let stream: rship_core::backend::EntryStream = match resolved.single_file {
        Some(file_entry) => Box::pin(futures::stream::once(async move { Ok(file_entry) })),
        None => {
            let list_opts = ListOptions::recursive().with_filter_pruning(&filter, &prefix);
            backend.list_with_options(&prefix, &list_opts).await?
        }
    };
    let prefix_arc = Arc::new(prefix);
    let checkers = args.checkers.max(1);
    let b = backend.clone();

    let mut hashed_stream = stream
        .filter_map(move |item| {
            let prefix = prefix_arc.clone();
            let filter = filter.clone();
            let out = match item {
                Err(e) => Some(Err(anyhow::Error::from(e))),
                Ok(entry) => {
                    if entry.kind != EntryKind::File {
                        None
                    } else if is_single_file {
                        let leaf = entry
                            .nfc_path
                            .file_name()
                            .unwrap_or(entry.nfc_path.as_str())
                            .to_string();
                        RelPath::parse(&leaf).ok().and_then(|rel| {
                            let mut filter_entry = entry.clone();
                            filter_entry.nfc_path = rel;
                            filter
                                .matches_entry(&filter_entry, now_ns)
                                .then_some(Ok((leaf, entry)))
                        })
                    } else {
                        let rel = if prefix.is_root() {
                            Some(entry.nfc_path.clone())
                        } else {
                            entry.nfc_path.strip_prefix(&prefix)
                        };
                        rel.filter(|r| !r.is_root()).and_then(|rel| {
                            let mut filter_entry = entry.clone();
                            filter_entry.nfc_path = rel.clone();
                            filter
                                .matches_entry(&filter_entry, now_ns)
                                .then(|| Ok((rel.as_str().to_string(), entry)))
                        })
                    }
                }
            };
            std::future::ready(out)
        })
        .map(move |item| {
            let b = b.clone();
            async move {
                let (display_path, entry) = item?;
                let hash_res = if let Some(ck) = entry.checksum.as_ref()
                    && ck.kind == kind
                {
                    Ok(Some(ck.hex.clone()))
                } else {
                    let bp = BackendPath::from_entry(&entry);
                    b.compute_hash(&bp, kind)
                        .await
                        .map(|opt| opt.map(|c| c.hex))
                };
                Ok::<_, anyhow::Error>((display_path, hash_res))
            }
        })
        .buffered(checkers);

    let mut json_rows: Vec<(String, Option<String>, Option<TransferErrorInfo>)> = Vec::new();
    let mut error_details: Vec<TransferErrorInfo> = Vec::new();
    while let Some(res) = hashed_stream.next().await {
        let (p, hash_res) = res?;
        match hash_res {
            Ok(h) => {
                if args.json {
                    json_rows.push((p, h, None));
                } else {
                    match h {
                        Some(hex) => println!("{hex}  {p}"),
                        None => {
                            eprintln!("warning: hash `{}` unavailable for `{p}`", kind.as_str())
                        }
                    }
                }
            }
            Err(e) => {
                let msg = format!("failed to hash `{p}`: {e}");
                let info =
                    TransferErrorInfo::from_error_with_message(Some(p.clone()), &e, msg.clone());
                if args.json {
                    json_rows.push((p, None, Some(info.clone())));
                } else {
                    eprintln!("error: {msg}");
                }
                error_details.push(info);
            }
        }
    }

    if args.json {
        json_rows.sort_by(|a, b| a.0.cmp(&b.0));
        let out: Vec<serde_json::Value> = json_rows
            .iter()
            .map(|(p, h, err)| {
                let mut row = serde_json::json!({
                    "path": p,
                    "hash_kind": kind.as_str(),
                    "hash": h,
                });
                if let Some(info) = err {
                    row["error"] = serde_json::json!(info.message);
                    row["error_kind"] = serde_json::json!(info.kind.as_str());
                    row["error_category"] = serde_json::json!(info.category.as_str());
                }
                row
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    let exit_code = if error_details.is_empty() {
        EXIT_OK
    } else {
        ErrorCategory::primary(error_details.iter().map(|e| e.category))
            .map(exit_code_for_category)
            .unwrap_or(1)
    };
    Ok(ExitCode::from(exit_code))
}

/// Provider-agnostic duplicate-name resolution (`newest`, `oldest`, `largest`, `rename`, `skip`).
/// Uses `StorageBackend::delete` and `StorageBackend::rename` directly without concrete backend coupling.
pub async fn execute_dedupe(args: DedupeArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let mode = args.mode.trim().to_ascii_lowercase();
    if !matches!(
        mode.as_str(),
        "newest" | "oldest" | "largest" | "rename" | "skip"
    ) {
        return Err(rship_core::Error::config(format!(
            "invalid dedupe --mode `{mode}` (expected: newest, oldest, largest, rename, skip)"
        ))
        .into());
    }

    let (backend, prefix) = rt.resolve_backend(&args.target, None)?;

    // Spill observed entries into a temporary SQLite index so unique files never
    // accumulate in RAM on million-file Google Drive / cloud listings; only paths with
    // >1 entry (`DuplicateSourceName` / `UnicodeNfcCollision`) are materialized!
    let run_id = format!(
        "dedupe-{}-{:x}",
        rship_core::time::format_compact_utc(rship_core::time::now_unix_secs()),
        std::process::id()
    );
    let sync_index = SqliteSyncIndex::open_temp(&rt.paths.ephemeral_dir(), &run_id)?;

    let mut batch: Vec<Entry> = Vec::with_capacity(2000);
    let mut stream = backend.list_stream(&prefix, true).await?;
    while let Some(item) = stream.next().await {
        let entry = item?;
        if entry.kind != EntryKind::File {
            continue;
        }
        batch.push(entry);
        if batch.len() >= 2000 {
            let chunk = std::mem::replace(&mut batch, Vec::with_capacity(2000));
            sync_index.insert_src_batch(chunk).await?;
        }
    }
    if !batch.is_empty() {
        sync_index.insert_src_batch(batch).await?;
    }

    let conflicts = sync_index.finalize_and_detect_conflicts(true).await?;
    let dup_paths: HashSet<RelPath> = conflicts
        .into_iter()
        .filter(|c| {
            matches!(
                c.kind,
                ConflictKind::DuplicateSourceName | ConflictKind::UnicodeNfcCollision
            )
        })
        .map(|c| c.nfc_path)
        .collect();

    let mut groups: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
    if !dup_paths.is_empty() {
        let mut after_id = 0i64;
        loop {
            let page = sync_index.next_src_page(after_id, 512).await?;
            if page.is_empty() {
                break;
            }
            for row in page {
                after_id = row.row_id;
                let Some(entry) = row.src else { continue };
                if dup_paths.contains(&entry.nfc_path) {
                    groups
                        .entry(entry.nfc_path.as_str().to_string())
                        .or_default()
                        .push(entry);
                }
            }
        }
    }

    let mut duplicate_groups = 0u64;
    let mut deleted = 0u64;
    let mut renamed = 0u64;
    let mut skipped = 0u64;
    let mut errors: Vec<String> = Vec::new();
    let mut error_details: Vec<TransferErrorInfo> = Vec::new();

    for (path, mut entries) in groups {
        if entries.len() <= 1 {
            continue;
        }
        duplicate_groups += 1;
        match mode.as_str() {
            "skip" => {
                skipped += (entries.len() - 1) as u64;
                if !args.json {
                    println!("DUPLICATE ({} copies): {path}", entries.len());
                }
            }
            "newest" | "oldest" | "largest" => {
                match mode.as_str() {
                    "newest" => entries.sort_by_key(|e| std::cmp::Reverse(e.mtime_ns)),
                    "oldest" => entries.sort_by_key(|e| e.mtime_ns),
                    "largest" => entries.sort_by_key(|e| std::cmp::Reverse(e.size)),
                    _ => {}
                }
                for dup in entries.into_iter().skip(1) {
                    if args.dry_run {
                        deleted += 1;
                        if !args.json {
                            println!(
                                "would delete duplicate `{path}` (id={})",
                                dup.node_id.as_ref().map(|n| n.as_str()).unwrap_or("-")
                            );
                        }
                        continue;
                    }
                    if let Err(e) = backend.delete(&BackendPath::from_entry(&dup)).await {
                        let msg = format!("delete duplicate `{path}`: {e}");
                        error_details.push(TransferErrorInfo::from_error_with_message(
                            Some(path.clone()),
                            &e,
                            msg.clone(),
                        ));
                        errors.push(msg);
                    } else {
                        deleted += 1;
                    }
                }
            }
            "rename" => {
                entries.sort_by_key(|e| std::cmp::Reverse(e.mtime_ns));
                let orig_name = path.rsplit('/').next().unwrap_or(&path);
                let (stem, ext) = match orig_name.rsplit_once('.') {
                    Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
                    _ => (orig_name, String::new()),
                };
                for (idx, dup) in entries.into_iter().skip(1).enumerate() {
                    let new_name = format!("{stem}-{}{ext}", idx + 1);
                    if args.dry_run {
                        renamed += 1;
                        if !args.json {
                            println!(
                                "would rename duplicate `{path}` (id={}) -> `{new_name}`",
                                dup.node_id.as_ref().map(|n| n.as_str()).unwrap_or("-")
                            );
                        }
                        continue;
                    }
                    if let Err(e) = backend
                        .rename(&BackendPath::from_entry(&dup), &new_name)
                        .await
                    {
                        let msg = format!("rename duplicate `{path}` -> `{new_name}`: {e}");
                        error_details.push(TransferErrorInfo::from_error_with_message(
                            Some(path.clone()),
                            &e,
                            msg.clone(),
                        ));
                        errors.push(msg);
                    } else {
                        renamed += 1;
                    }
                }
            }
            _ => {}
        }
    }

    let error_category = if errors.is_empty() {
        None
    } else {
        ErrorCategory::primary(error_details.iter().map(|e| e.category))
            .or(Some(ErrorCategory::Other))
    };
    let exit_code = error_category
        .map(exit_code_for_category)
        .unwrap_or(EXIT_OK);

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": errors.is_empty(),
                "exit_code": exit_code,
                "error_category": error_category,
                "mode": mode,
                "dry_run": args.dry_run,
                "duplicate_groups": duplicate_groups,
                "deleted": deleted,
                "renamed": renamed,
                "skipped": skipped,
                "errors": errors,
                "error_details": error_details,
            }))?
        );
    } else {
        let st = Style::stdout();
        let sym = if !errors.is_empty() {
            st.sym_err()
        } else if args.dry_run {
            st.sym_warn()
        } else {
            st.sym_ok()
        };
        let dry_tag = if args.dry_run { " (dry-run)" } else { "" };
        println!(
            "{sym} {}  {duplicate_groups} group(s) {} {deleted} deleted {} {renamed} renamed {} {skipped} skipped{}",
            st.bold(&format!("dedupe:{mode}{dry_tag}")),
            st.sym_dot(),
            st.sym_dot(),
            st.sym_dot(),
            if errors.is_empty() {
                String::new()
            } else {
                format!(
                    " {} {}",
                    st.sym_dot(),
                    st.err_bold(&format!("{} error(s)", errors.len()))
                )
            }
        );
        let err_st = Style::stderr();
        for e in &errors {
            eprintln!("{} {}", err_st.sym_err(), e);
        }
    }
    Ok(ExitCode::from(exit_code))
}
