//! Direct filesystem/cloud manipulation & streaming commands: `ls`, `delete`, `purge`, `mkdir`, `cat`, `rcat`.

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use rship_core::ErrorCategory;
use rship_core::backend::{BackendPath, ChunkUpload, CompletedPart, ListOptions, UploadInit};
use rship_core::buffer::BufferPool;
use rship_core::chunking::{UploadPlan, part_byte_range, plan_upload};
use rship_core::clock::SystemClock;
use rship_core::engine::TransferErrorInfo;
use rship_core::filter::FilterSet;
use rship_core::memory::MemoryBudget;
use rship_core::path::TargetPath;
use rship_core::source::{
    ByteStream, DataSource, SeekableSource, SpoolSeekableSource, bounded_range_stream,
};
use rship_core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship_core::types::{ByteRange, EntryKind};
use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

use crate::cli::{CatArgs, DeleteArgs, PurgeArgs, RcatArgs, parse_byte_size};
use crate::errors::{EXIT_OK, exit_code_for_category};
use crate::ops::CliRuntime;
use crate::ui::Style;

pub async fn execute_ls(
    target: &str,
    recursive: bool,
    json: bool,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    let resolved = rt.resolve_any_target(target, None).await?;
    let prefix = resolved.prefix;
    let is_single_file = resolved.single_file.is_some();
    let mut stream: rship_core::backend::EntryStream = match resolved.single_file {
        Some(entry) => Box::pin(futures::stream::once(async move { Ok(entry) })),
        None => resolved.backend.list_stream(&prefix, recursive).await?,
    };
    let st = Style::stdout();
    let mut file_count = 0u64;
    let mut dir_count = 0u64;
    let mut total_bytes = 0u64;
    if json {
        let mut entries = Vec::new();
        while let Some(res) = stream.next().await {
            entries.push(res?);
        }
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(ExitCode::SUCCESS);
    }
    while let Some(res) = stream.next().await {
        let entry = res?;
        let display_path: String = if is_single_file {
            entry
                .nfc_path
                .file_name()
                .unwrap_or(entry.nfc_path.as_str())
                .to_string()
        } else if prefix.is_root() {
            entry.nfc_path.as_str().to_string()
        } else if let Some(rel) = entry.nfc_path.strip_prefix(&prefix) {
            if rel.is_root() {
                continue;
            }
            rel.as_str().to_string()
        } else {
            entry.nfc_path.as_str().to_string()
        };
        if st.is_tty() {
            if entry.kind == EntryKind::Directory {
                dir_count += 1;
                println!(
                    "{}  {}",
                    st.dim(&format!("{:>10}", "—")),
                    st.accent_bold(&format!("{display_path}/"))
                );
            } else {
                file_count += 1;
                total_bytes = total_bytes.saturating_add(entry.size);
                let sz = rship_core::progress::format_human_bytes(entry.size);
                println!("{}  {display_path}", st.dim(&format!("{sz:>10}")));
            }
        } else {
            println!(
                "{:>12}  {:<4}  {display_path}",
                entry.size,
                entry.kind.as_str(),
            );
        }
    }
    if st.is_tty() {
        if file_count == 0 && dir_count == 0 {
            println!("{}", st.dim("(empty)"));
        } else {
            println!(
                "\n{}",
                st.dim(&format!(
                    "{file_count} file(s), {dir_count} dir(s) · {}",
                    rship_core::progress::format_human_bytes(total_bytes)
                ))
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub async fn execute_delete(args: DeleteArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let resolved = rt.resolve_any_target(&args.target, None).await?;
    let backend = resolved.backend;
    let prefix = resolved.prefix;
    let filter = FilterSet::from_options(&rt.build_filter_options(&args.filters)?)?;
    let now_ns = SystemClock::shared().now_unix_nanos();

    const DELETE_CHUNK: usize = 1000;
    let mut targets: Vec<BackendPath> = Vec::new();
    let mut deleted = 0u64;
    let mut errors: Vec<String> = Vec::new();
    let mut error_details: Vec<TransferErrorInfo> = Vec::new();

    let is_single_file = resolved.single_file.is_some();
    let mut stream: ByteEntryStream = match resolved.single_file {
        Some(file_entry) => Box::pin(futures::stream::once(async move { Ok(file_entry) })),
        None => {
            let list_opts = ListOptions::recursive().with_filter_pruning(&filter, &prefix);
            backend.list_with_options(&prefix, &list_opts).await?
        }
    };
    type ByteEntryStream = rship_core::backend::EntryStream;
    while let Some(item) = stream.next().await {
        let mut entry = item?;
        if entry.kind != EntryKind::File {
            continue;
        }
        let bp = BackendPath::from_entry(&entry);
        let rel = if is_single_file {
            let leaf = entry
                .nfc_path
                .file_name()
                .unwrap_or(entry.nfc_path.as_str());
            rship_core::path::RelPath::parse(leaf)?
        } else if prefix.is_root() {
            entry.nfc_path.clone()
        } else if let Some(r) = entry.nfc_path.strip_prefix(&prefix) {
            r
        } else {
            continue;
        };
        if !rel.is_root() {
            entry.nfc_path = rel;
            if !filter.matches_entry(&entry, now_ns) {
                continue;
            }
        }
        if args.max_delete.is_none() && args.dry_run {
            deleted += 1;
            continue;
        }
        targets.push(bp);
        if let Some(limit) = args.max_delete {
            if (targets.len() as u64) > limit {
                return Err(rship_core::Error::precondition_failed(format!(
                    "delete circuit breaker tripped: more than {limit} file(s) matched (--max-delete={limit})"
                ))
                .into());
            }
        } else if targets.len() >= DELETE_CHUNK {
            let chunk = std::mem::replace(&mut targets, Vec::with_capacity(DELETE_CHUNK));
            let failures = backend.delete_batch(&chunk).await?;
            let failed_count = failures.len() as u64;
            for (fbp, e) in failures {
                let msg = format!("delete `{}`: {e}", fbp.nfc_path);
                error_details.push(TransferErrorInfo::from_error_with_message(
                    Some(fbp.nfc_path.as_str().to_string()),
                    &e,
                    msg.clone(),
                ));
                errors.push(msg);
            }
            deleted += (chunk.len() as u64).saturating_sub(failed_count);
        }
    }

    if !targets.is_empty() {
        if args.dry_run {
            deleted += targets.len() as u64;
        } else {
            for chunk in targets.chunks(DELETE_CHUNK) {
                let failures = backend.delete_batch(chunk).await?;
                let failed_count = failures.len() as u64;
                for (fbp, e) in failures {
                    let msg = format!("delete `{}`: {e}", fbp.nfc_path);
                    error_details.push(TransferErrorInfo::from_error_with_message(
                        Some(fbp.nfc_path.as_str().to_string()),
                        &e,
                        msg.clone(),
                    ));
                    errors.push(msg);
                }
                deleted += (chunk.len() as u64).saturating_sub(failed_count);
            }
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
                "deleted": deleted,
                "dry_run": args.dry_run,
                "errors": errors,
                "error_details": error_details,
            }))?
        );
    } else {
        let st = Style::stdout();
        let err_st = Style::stderr();
        let sym = if !errors.is_empty() {
            st.sym_err()
        } else if args.dry_run {
            st.sym_warn()
        } else {
            st.sym_ok()
        };
        println!(
            "{sym} {} {} file(s){}",
            st.bold(if args.dry_run {
                "would delete"
            } else {
                "deleted"
            }),
            st.bold(&deleted.to_string()),
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
        for e in &errors {
            eprintln!("{} {}", err_st.sym_err(), e);
        }
    }

    Ok(ExitCode::from(exit_code))
}

pub async fn execute_purge(args: PurgeArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let (backend, prefix) = rt.resolve_backend(&args.target, None)?;

    let mut files = Vec::new();
    let mut dirs = Vec::new();
    let mut stream = backend.list_stream(&prefix, true).await?;
    while let Some(item) = stream.next().await {
        let entry = item?;
        let bp = BackendPath::from_entry(&entry);
        match entry.kind {
            EntryKind::Directory => dirs.push(bp),
            _ => files.push(bp),
        }
        let total_so_far = (files.len() + dirs.len()) as u64;
        if let Some(limit) = args.max_delete
            && total_so_far > limit
        {
            return Err(rship_core::Error::precondition_failed(format!(
                "purge circuit breaker tripped: more than {limit} item(s) matched (--max-delete={limit})"
            ))
            .into());
        }
    }
    dirs.sort_by_key(|a| std::cmp::Reverse(a.nfc_path.as_str().len()));
    let total_planned = (files.len() + dirs.len()) as u64;

    let mut deleted = 0u64;
    let mut errors: Vec<String> = Vec::new();
    let mut error_details: Vec<TransferErrorInfo> = Vec::new();
    if args.dry_run {
        deleted = total_planned;
    } else {
        if !files.is_empty() {
            let failures = backend.delete_batch(&files).await?;
            let failed_count = failures.len() as u64;
            for (bp, e) in failures {
                let msg = format!("purge `{}`: {e}", bp.nfc_path);
                error_details.push(TransferErrorInfo::from_error_with_message(
                    Some(bp.nfc_path.as_str().to_string()),
                    &e,
                    msg.clone(),
                ));
                errors.push(msg);
            }
            deleted += (files.len() as u64).saturating_sub(failed_count);
        }
        for bp in dirs {
            if let Err(e) = backend.delete(&bp).await {
                let msg = format!("purge `{}`: {e}", bp.nfc_path);
                error_details.push(TransferErrorInfo::from_error_with_message(
                    Some(bp.nfc_path.as_str().to_string()),
                    &e,
                    msg.clone(),
                ));
                errors.push(msg);
            } else {
                deleted += 1;
            }
        }
    }
    if !args.dry_run && errors.is_empty() && !prefix.is_root() {
        let _ = backend.delete(&BackendPath::from_rel(prefix)).await;
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
                "purged": deleted,
                "dry_run": args.dry_run,
                "errors": errors,
                "error_details": error_details,
            }))?
        );
    } else {
        let st = Style::stdout();
        let err_st = Style::stderr();
        let sym = if !errors.is_empty() {
            st.sym_err()
        } else if args.dry_run {
            st.sym_warn()
        } else {
            st.sym_ok()
        };
        println!(
            "{sym} {} {} item(s){}",
            st.bold(if args.dry_run {
                "would purge"
            } else {
                "purged"
            }),
            st.bold(&deleted.to_string()),
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
        for e in &errors {
            eprintln!("{} {}", err_st.sym_err(), e);
        }
    }

    Ok(ExitCode::from(exit_code))
}

pub async fn execute_mkdir(target: &str, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    match TargetPath::parse(target).with_context(|| format!("invalid path `{target}`"))? {
        TargetPath::Local(path) => {
            std::fs::create_dir_all(&path)
                .with_context(|| format!("mkdir `{}`", path.display()))?;
            Ok(ExitCode::SUCCESS)
        }
        TargetPath::Remote { .. } => {
            let (backend, prefix) = rt.resolve_backend(target, None)?;
            backend.mkdir(&prefix).await?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

pub async fn execute_cat(args: CatArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let user_buf_cap = args
        .max_buffer_mem
        .as_deref()
        .or(rt.profile().max_buffer_mem.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let budget = MemoryBudget::resolve(user_buf_cap);
    let pool = BufferPool::new(budget.buffer_pool_bytes, budget.stream_slice_bytes)?;

    let (backend, rel) = rt.resolve_file_target(&args.target, false, Some(pool.clone()))?;

    let bp = BackendPath::from_rel(rel);
    let Some(entry) = backend.stat(&bp).await? else {
        return Err(
            rship_core::Error::not_found(format!("file `{}` not found", args.target)).into(),
        );
    };
    if entry.kind != EntryKind::File {
        return Err(rship_core::Error::invalid_path(format!(
            "target `{}` is a directory, not a file",
            args.target
        ))
        .into());
    }
    if args.offset >= entry.size && entry.size > 0 {
        return Ok(ExitCode::SUCCESS);
    }
    let avail = entry.size.saturating_sub(args.offset);
    let len = args.count.map_or(avail, |c| c.min(avail));
    if len == 0 {
        return Ok(ExitCode::SUCCESS);
    }

    let range = ByteRange {
        offset: args.offset,
        len,
    };
    let entry_bp = BackendPath::from_entry(&entry);
    let mut stream: ByteStream = match backend
        .open_read_entry(&entry, &entry_bp, Some(range))
        .await?
    {
        DataSource::LocalSeekable(src) => bounded_range_stream(src, range.offset, range.len, pool),
        DataSource::RemoteRangeReadable(r) => r.open_range(range).await?,
        DataSource::SequentialStream { stream, .. } => stream,
    };

    let mut stdout = io::stdout().lock();
    while let Some(chunk) = stream.next().await {
        let data = chunk?;
        stdout.write_all(&data)?;
    }
    stdout.flush()?;
    Ok(ExitCode::SUCCESS)
}

pub async fn execute_rcat(args: RcatArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let max_spool = args
        .max_spool
        .as_deref()
        .map(parse_byte_size)
        .transpose()?
        .unwrap_or(256 * 1024 * 1024);
    let chunk_override = args
        .chunk_size
        .as_deref()
        .or(rt.profile().chunk_size.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let user_buf_cap = args
        .max_buffer_mem
        .as_deref()
        .or(rt.profile().max_buffer_mem.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let budget = MemoryBudget::resolve(user_buf_cap);
    let pool = BufferPool::new(budget.buffer_pool_bytes, budget.stream_slice_bytes)?;

    let (backend, rel) = rt.resolve_file_target(&args.target, true, Some(pool.clone()))?;

    let stdin_stream: ByteStream = Box::pin(futures::stream::try_unfold(
        tokio::io::stdin(),
        |mut stdin| async move {
            let mut buf = vec![0u8; 64 * 1024];
            let n = stdin
                .read(&mut buf)
                .await
                .map_err(|e| rship_core::Error::io("read stdin", e))?;
            if n == 0 {
                return Ok(None);
            }
            buf.truncate(n);
            Ok(Some((Bytes::from(buf), stdin)))
        },
    ));

    let clock = SystemClock::shared();
    let now_ns = clock.now_unix_nanos();
    let now_s = clock.now_unix_secs();
    let op_id = format!("rcat-{now_ns:x}-{}", std::process::id());
    let run_dir = rship_state::LazyRunDir::new(rt.paths.ephemeral_dir(), &op_id);
    let spool_dir = run_dir.ensure_subdir_async("spool").await?;
    let spool = SpoolSeekableSource::from_stream(stdin_stream, &spool_dir, max_spool).await?;
    let total_size = spool.total_len();

    let caps = backend.capabilities();
    let plan = plan_upload(total_size, &caps, chunk_override)?;
    let existing = backend.stat(&BackendPath::from_rel(rel.clone())).await?;
    let existing_node_id = existing.as_ref().and_then(|e| e.node_id.clone());

    let planned_chunk_size = match plan {
        UploadPlan::SingleShot { total_size } => total_size.max(1),
        UploadPlan::Resumable { chunk_size, .. } => chunk_size,
    };
    let init = UploadInit {
        op_id: op_id.clone(),
        dst_path: rel.clone(),
        existing_node_id: existing_node_id.clone(),
        pregenerated_id: None,
        total_size,
        src_mtime_ns: now_ns,
        planned_chunk_size,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };

    let seekable: Arc<dyn SeekableSource> = spool;
    match plan {
        UploadPlan::SingleShot { .. } => {
            let body = bounded_range_stream(seekable, 0, total_size, pool);
            let _ = backend.put_single_shot(&init, body).await?;
        }
        UploadPlan::Resumable {
            chunk_size,
            total_parts,
            ..
        } => {
            let opened = backend.begin_upload(&init).await?;
            let op = OperationRecord {
                op_id,
                session_key: String::new(),
                job_id: "rcat".to_string(),
                src_endpoint: "stdin://".to_string(),
                dst_endpoint: backend.endpoint_identity(),
                src_raw_path: "stdin".to_string(),
                dst_raw_path: rel.as_str().to_string(),
                dst_nfc_path: rel,
                src_version: SourceVersion {
                    node_id: None,
                    size: total_size,
                    mtime_ns: now_ns,
                    ctime_ns: None,
                    etag: None,
                },
                dst_precondition: DstPrecondition::Any,
                existing_dst_node_id: existing_node_id,
                remote_op_id: opened.remote_op_id,
                backend_kind: backend.kind().to_string(),
                session_token: Some(opened.session_token),
                backend_meta: opened.backend_meta,
                planned_chunk_size: chunk_size,
                confirmed_offset: 0,
                state: OperationState::Active,
                created_at: now_s,
                updated_at: now_s,
                expires_at: opened.expires_at_unix_secs,
            };

            let mut completed_parts = Vec::new();
            let mut committed = false;
            for pn in 1..=total_parts {
                let (offset, len) = part_byte_range(total_size, chunk_size, pn)?;
                let body = bounded_range_stream(seekable.clone(), offset, len, pool.clone());
                let ack = match backend
                    .upload_chunk(&op, ChunkUpload::new(pn, offset, len, total_size, body))
                    .await
                {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = backend.abort_upload(&op).await;
                        return Err(e.into());
                    }
                };
                if ack.completed.is_some() {
                    committed = true;
                    break;
                }
                if let Some(etag) = ack.etag {
                    completed_parts.push(CompletedPart {
                        part_number: pn,
                        offset,
                        length: len,
                        etag,
                        checksum: ack.checksum,
                    });
                }
            }
            if !committed {
                let _ = backend.finish_upload(&op, &completed_parts).await?;
            }
        }
    }

    Ok(ExitCode::SUCCESS)
}
