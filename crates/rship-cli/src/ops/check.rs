//! Read-only inspection commands: concurrent `check`, `tree`, and `size`.

use anyhow::Result;
use futures::StreamExt;
use rship_core::ErrorCategory;
use rship_core::backend::{BackendPath, ListOptions, StorageBackend};
use rship_core::clock::SystemClock;
use rship_core::engine::diff::{DiffItem, StreamingMergeDiffSource};
use rship_core::engine::{CancelFlag, MAX_REPORT_ERRORS, TransferErrorInfo};
use rship_core::filter::FilterSet;
use rship_core::path::RelPath;
use rship_core::progress::format_human_bytes;
use rship_core::state::{SyncConflict, SyncDiffIndex};
use rship_core::types::{Entry, EntryKind, HashKind};
use rship_state::SqliteSyncIndex;
use std::collections::{BTreeMap, HashSet};
use std::process::ExitCode;
use std::sync::Arc;

use crate::cli::{CheckArgs, SizeArgs, TreeArgs};
use crate::errors::{EXIT_ERROR, EXIT_OK, classify_anyhow_error, exit_code_for_category};
use crate::providers::join_raw_prefix;
use crate::ui::{Style, format_duration_human};
use std::time::Instant;

use super::{CliRuntime, observe_into_index};

/// Maximum per-category items retained in memory for `rship check --json` so checking
/// 40M+ drifted objects never OOMs while exact counts are always preserved.
const MAX_CHECK_JSON_ITEMS: usize = 10_000;

#[inline]
fn push_check_capped<T>(vec: &mut Vec<T>, item: T, cap: usize, truncated: &mut bool) {
    if vec.len() < cap {
        vec.push(item);
    } else {
        *truncated = true;
    }
}

enum HashOutcome {
    Matched,
    Unverified(String),
    Mismatch(String),
}

struct CheckReport {
    json_mode: bool,
    matched: u64,
    unverified: u64,
    differences: u64,
    missing_on_dst_count: u64,
    missing_on_src_count: u64,
    size_mismatch_count: u64,
    hash_mismatch_count: u64,
    type_mismatch_count: u64,
    conflict_count: u64,
    error_count: u64,
    json_truncated: bool,
    missing_on_dst: Vec<String>,
    missing_on_src: Vec<String>,
    size_mismatch: Vec<String>,
    hash_mismatch: Vec<String>,
    type_mismatch: Vec<String>,
    conflicts: Vec<SyncConflict>,
    error_details: Vec<TransferErrorInfo>,
    errors: Vec<String>,
}

impl CheckReport {
    fn new(json_mode: bool) -> Self {
        Self {
            json_mode,
            matched: 0,
            unverified: 0,
            differences: 0,
            missing_on_dst_count: 0,
            missing_on_src_count: 0,
            size_mismatch_count: 0,
            hash_mismatch_count: 0,
            type_mismatch_count: 0,
            conflict_count: 0,
            error_count: 0,
            json_truncated: false,
            missing_on_dst: Vec::new(),
            missing_on_src: Vec::new(),
            size_mismatch: Vec::new(),
            hash_mismatch: Vec::new(),
            type_mismatch: Vec::new(),
            conflicts: Vec::new(),
            error_details: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn record_conflict(&mut self, c: SyncConflict) {
        self.differences += 1;
        self.conflict_count += 1;
        if !self.json_mode {
            eprintln!("CONFLICT ({:?}): {} — {}", c.kind, c.nfc_path, c.detail);
        }
        push_check_capped(
            &mut self.conflicts,
            c,
            MAX_CHECK_JSON_ITEMS,
            &mut self.json_truncated,
        );
    }

    fn record_missing_on_dst(&mut self, label: String) {
        self.differences += 1;
        self.missing_on_dst_count += 1;
        if self.json_mode {
            push_check_capped(
                &mut self.missing_on_dst,
                label,
                MAX_CHECK_JSON_ITEMS,
                &mut self.json_truncated,
            );
        } else {
            eprintln!("MISSING ON DST: {label}");
        }
    }

    fn record_missing_on_src(&mut self, label: String) {
        self.differences += 1;
        self.missing_on_src_count += 1;
        if self.json_mode {
            push_check_capped(
                &mut self.missing_on_src,
                label,
                MAX_CHECK_JSON_ITEMS,
                &mut self.json_truncated,
            );
        } else {
            eprintln!("MISSING ON SRC: {label}");
        }
    }

    fn record_type_mismatch(&mut self, label: String) {
        self.differences += 1;
        self.type_mismatch_count += 1;
        if self.json_mode {
            push_check_capped(
                &mut self.type_mismatch,
                label,
                MAX_CHECK_JSON_ITEMS,
                &mut self.json_truncated,
            );
        } else {
            eprintln!("TYPE MISMATCH:  {label}");
        }
    }

    fn record_size_mismatch(&mut self, label: &str, src_size: u64, dst_size: u64) {
        self.differences += 1;
        self.size_mismatch_count += 1;
        let msg = format!("{label} (src={src_size} dst={dst_size})");
        if self.json_mode {
            push_check_capped(
                &mut self.size_mismatch,
                msg,
                MAX_CHECK_JSON_ITEMS,
                &mut self.json_truncated,
            );
        } else {
            eprintln!("SIZE MISMATCH:  {msg}");
        }
    }

    fn record_unverified(&mut self, msg: &str) {
        self.unverified += 1;
        if !self.json_mode {
            eprintln!("UNVERIFIED:     {msg}");
        }
    }

    fn record_error_info(&mut self, info: TransferErrorInfo) {
        self.error_count += 1;
        if self.errors.len() < MAX_REPORT_ERRORS {
            self.errors.push(info.message.clone());
            self.error_details.push(info);
        } else {
            self.json_truncated = true;
        }
    }

    fn record_hash_result(&mut self, res: Result<HashOutcome>, path: Option<String>) {
        match res {
            Ok(HashOutcome::Mismatch(msg)) => {
                self.differences += 1;
                self.hash_mismatch_count += 1;
                if self.json_mode {
                    push_check_capped(
                        &mut self.hash_mismatch,
                        msg,
                        MAX_CHECK_JSON_ITEMS,
                        &mut self.json_truncated,
                    );
                } else {
                    eprintln!("HASH MISMATCH:  {msg}");
                }
            }
            Ok(HashOutcome::Unverified(msg)) => self.record_unverified(&msg),
            Ok(HashOutcome::Matched) => self.matched += 1,
            Err(e) => {
                let msg = format!("hash check failed: {e}");
                let info = match e.downcast_ref::<rship_core::Error>() {
                    Some(core_err) => {
                        TransferErrorInfo::from_error_with_message(path, core_err, msg)
                    }
                    None => {
                        let c = classify_anyhow_error(&e);
                        TransferErrorInfo::from_error_with_message(
                            path,
                            &rship_core::Error::new(c.kind, c.retry_class, c.detail_message),
                            msg,
                        )
                    }
                };
                self.record_error_info(info);
            }
        }
    }

    /// Compare one matched-size file pair; returns `Some((src, dst))` if it should be queued
    /// for concurrent checksum verification.
    fn classify_file_pair(
        &mut self,
        src_e: Entry,
        dst_e: Entry,
        size_only: bool,
        common_hash: Option<HashKind>,
        src_hashes: &[HashKind],
        dst_hashes: &[HashKind],
    ) -> Option<(Entry, Entry)> {
        if dst_e.kind != EntryKind::File {
            self.record_type_mismatch(src_e.nfc_path.as_str().to_string());
            return None;
        }
        if src_e.size != dst_e.size {
            self.record_size_mismatch(src_e.nfc_path.as_str(), src_e.size, dst_e.size);
            return None;
        }
        if size_only {
            self.matched += 1;
            return None;
        }
        let has_hash = common_hash.is_some()
            || dst_e
                .checksum
                .as_ref()
                .is_some_and(|ck| src_hashes.contains(&ck.kind))
            || src_e
                .checksum
                .as_ref()
                .is_some_and(|ck| dst_hashes.contains(&ck.kind));
        if has_hash {
            Some((src_e, dst_e))
        } else {
            self.record_unverified(&format!("{} (no common hash)", src_e.nfc_path));
            None
        }
    }

    fn finish_and_print(
        self,
        common_hash: Option<HashKind>,
        src_ok: bool,
        dst_ok: bool,
        started: Instant,
    ) -> Result<ExitCode> {
        let ok = self.differences == 0 && self.error_count == 0 && src_ok && dst_ok;
        let error_category = if self.error_count > 0 || !src_ok || !dst_ok {
            ErrorCategory::primary(self.error_details.iter().map(|e| e.category))
                .or(Some(ErrorCategory::Other))
        } else if self.conflict_count > 0 {
            Some(ErrorCategory::Conflict)
        } else {
            None
        };
        let exit_code = if ok {
            EXIT_OK
        } else if let Some(cat) = error_category {
            exit_code_for_category(cat)
        } else {
            EXIT_ERROR
        };

        if self.json_mode {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": ok,
                    "exit_code": exit_code,
                    "error_category": error_category,
                    "matched": self.matched,
                    "unverified": self.unverified,
                    "differences": self.differences,
                    "truncated": self.json_truncated,
                    "counts": {
                        "conflicts": self.conflict_count,
                        "missing_on_dst": self.missing_on_dst_count,
                        "missing_on_src": self.missing_on_src_count,
                        "size_mismatch": self.size_mismatch_count,
                        "hash_mismatch": self.hash_mismatch_count,
                        "type_mismatch": self.type_mismatch_count,
                        "errors": self.error_count,
                    },
                    "conflicts": self.conflicts,
                    "missing_on_dst": self.missing_on_dst,
                    "missing_on_src": self.missing_on_src,
                    "size_mismatch": self.size_mismatch,
                    "hash_mismatch": self.hash_mismatch,
                    "type_mismatch": self.type_mismatch,
                    "hash_algorithm": common_hash.map(|h| format!("{h:?}")),
                    "src_observation_complete": src_ok,
                    "dst_observation_complete": dst_ok,
                    "errors": self.errors,
                    "error_details": self.error_details,
                }))?
            );
        } else {
            let st = Style::stdout();
            let err_st = Style::stderr();
            for e in &self.errors {
                eprintln!("{} {}", err_st.sym_err(), e);
            }
            let elapsed = format_duration_human(started.elapsed());
            let sym = if !ok {
                st.sym_err()
            } else if self.unverified > 0 {
                st.sym_warn()
            } else {
                st.sym_ok()
            };
            let mut parts = vec![format!("{} matched", st.ok_bold(&self.matched.to_string()))];
            if self.unverified > 0 {
                parts.push(st.warn(&format!("{} unverified", self.unverified)));
            }
            if self.differences > 0 {
                parts.push(st.err_bold(&format!("{} differences", self.differences)));
            } else {
                parts.push(st.dim("0 differences"));
            }
            if !self.errors.is_empty() {
                parts.push(st.err_bold(&format!("{} errors", self.errors.len())));
            }
            let dot = format!(" {} ", st.sym_dot());
            println!(
                "{sym} {}  {}  {}",
                st.bold("check"),
                parts.join(&dot),
                st.dim(&format!("({elapsed})"))
            );
        }

        Ok(ExitCode::from(exit_code))
    }
}

/// Choose the cheapest common hash algorithm for `(src_e, dst_e)` — preferring metadata-cached
/// checksums and probing remote hashes before hashing local disk.
#[allow(clippy::too_many_arguments)]
async fn verify_pair_hash(
    sb: &Arc<dyn StorageBackend>,
    db: &Arc<dyn StorageBackend>,
    src_bp: BackendPath,
    dst_bp: BackendPath,
    src_e: &Entry,
    dst_e: &Entry,
    label: &str,
    common_hash: Option<HashKind>,
    src_hashes: &[HashKind],
    dst_hashes: &[HashKind],
) -> Result<HashOutcome> {
    let chosen = dst_e
        .checksum
        .as_ref()
        .filter(|ck| src_hashes.contains(&ck.kind))
        .map(|ck| {
            let src_cached = src_e
                .checksum
                .as_ref()
                .filter(|s| s.kind == ck.kind)
                .map(|s| s.hex.clone());
            (ck.kind, src_cached, Some(ck.hex.clone()))
        })
        .or_else(|| {
            src_e
                .checksum
                .as_ref()
                .filter(|ck| dst_hashes.contains(&ck.kind))
                .map(|ck| (ck.kind, Some(ck.hex.clone()), None))
        })
        .or_else(|| common_hash.map(|hk| (hk, None, None)));

    let Some((hk, cached_src, cached_dst)) = chosen else {
        return Ok(HashOutcome::Unverified(format!("{label} (no common hash)")));
    };

    // Fetch remote hash BEFORE hashing local disk so we skip wasted local I/O if the remote
    // lacks the hash or errors out.
    let fetch_src_first = cached_src.is_none()
        && cached_dst.is_none()
        && db.kind() == "local"
        && sb.kind() != "local";

    let (sh, dh) = if fetch_src_first {
        let Some(sh) = sb.compute_hash(&src_bp, hk).await?.map(|c| c.hex) else {
            return Ok(HashOutcome::Unverified(format!(
                "{label} (src missing {hk:?})"
            )));
        };
        let Some(dh) = db.compute_hash(&dst_bp, hk).await?.map(|c| c.hex) else {
            return Ok(HashOutcome::Unverified(format!(
                "{label} (dst missing {hk:?})"
            )));
        };
        (sh, dh)
    } else {
        let dst_h = match cached_dst {
            Some(h) => Some(h),
            None => db.compute_hash(&dst_bp, hk).await?.map(|c| c.hex),
        };
        let Some(dh) = dst_h else {
            return Ok(HashOutcome::Unverified(format!(
                "{label} (dst missing {hk:?})"
            )));
        };
        let src_h = match cached_src {
            Some(h) => Some(h),
            None => sb.compute_hash(&src_bp, hk).await?.map(|c| c.hex),
        };
        let Some(sh) = src_h else {
            return Ok(HashOutcome::Unverified(format!(
                "{label} (src missing {hk:?})"
            )));
        };
        (sh, dh)
    };

    if !sh.eq_ignore_ascii_case(&dh) {
        return Ok(HashOutcome::Mismatch(format!(
            "{label} ({hk:?} src={sh} dst={dh})"
        )));
    }
    Ok(HashOutcome::Matched)
}

#[allow(clippy::too_many_arguments)]
async fn verify_hash_batch(
    hash_candidates: Vec<(Entry, Entry)>,
    src_backend: &Arc<dyn StorageBackend>,
    dst_backend: &Arc<dyn StorageBackend>,
    src_prefix: &RelPath,
    dst_prefix: &RelPath,
    common_hash: Option<HashKind>,
    src_hashes: &[HashKind],
    dst_hashes: &[HashKind],
    checkers: usize,
    report: &mut CheckReport,
) {
    if hash_candidates.is_empty() {
        return;
    }
    let sb = src_backend.clone();
    let db = dst_backend.clone();
    let sp = src_prefix.clone();
    let dp = dst_prefix.clone();
    let src_hashes = src_hashes.to_vec();
    let dst_hashes = dst_hashes.to_vec();
    let mut results = futures::stream::iter(hash_candidates)
        .map(move |(src_e, dst_e)| {
            let sb = sb.clone();
            let db = db.clone();
            let sp = sp.clone();
            let dp = dp.clone();
            let src_hashes = src_hashes.clone();
            let dst_hashes = dst_hashes.clone();
            async move {
                let src_bp = BackendPath::new(
                    join_raw_prefix(&sp, src_e.raw_path()),
                    sp.join_path(&src_e.nfc_path),
                    src_e.node_id.clone(),
                );
                let dst_bp = BackendPath::new(
                    join_raw_prefix(&dp, dst_e.raw_path()),
                    dp.join_path(&dst_e.nfc_path),
                    dst_e.node_id.clone(),
                );
                let label = src_e.nfc_path.as_str().to_string();
                let outcome = verify_pair_hash(
                    &sb,
                    &db,
                    src_bp,
                    dst_bp,
                    &src_e,
                    &dst_e,
                    &label,
                    common_hash,
                    &src_hashes,
                    &dst_hashes,
                )
                .await;
                (label, outcome)
            }
        })
        .buffer_unordered(checkers);

    while let Some((label, res)) = results.next().await {
        report.record_hash_result(res, Some(label));
    }
}

pub async fn execute_check(args: CheckArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let started = Instant::now();
    let src_res = rt.resolve_any_target(&args.src, None).await?;
    let dst_res = rt.resolve_any_target(&args.dst, None).await?;
    let filter = FilterSet::from_options(&rt.build_filter_options(&args.filters)?)?;

    if src_res.single_file.is_some() || dst_res.single_file.is_some() {
        return execute_single_file_check(args, src_res, dst_res, &filter, started).await;
    }

    let (src_backend, src_prefix) = (src_res.backend, src_res.prefix);
    let (dst_backend, dst_prefix) = (dst_res.backend, dst_res.prefix);

    let now_ns = SystemClock::shared().now_unix_nanos();
    let src_caps = src_backend.capabilities();
    let dst_caps = dst_backend.capabilities();
    let common_hash = if args.size_only {
        None
    } else {
        src_caps.best_common_hash(&dst_caps)
    };

    let can_stream_check = src_caps.supports_ordered_utf8_list
        && dst_caps.supports_ordered_utf8_list
        && src_caps.case_sensitive
        && dst_caps.case_sensitive
        && filter.files_from_paths().is_none();

    let mut report = CheckReport::new(args.json);
    let checkers = args.checkers.max(1);

    let (src_ok, dst_ok) = if can_stream_check {
        let dir_pruner = ListOptions::recursive()
            .with_filter_pruning(&filter, &RelPath::root())
            .dir_pruner()
            .cloned();
        let mut diff = StreamingMergeDiffSource::start(
            src_backend.clone(),
            src_prefix.clone(),
            dst_backend.clone(),
            dst_prefix.clone(),
            None,
            dir_pruner.clone(),
            dir_pruner,
            CancelFlag::new(),
        )
        .await?;

        loop {
            let mut hash_candidates: Vec<(Entry, Entry)> = Vec::new();
            let mut hit_eof = false;
            while hash_candidates.len() < 512 {
                let Some(item) = diff.next_item().await else {
                    hit_eof = true;
                    break;
                };
                match item {
                    DiffItem::Conflict(c) => report.record_conflict(c),
                    DiffItem::SrcOnly(src_e) => {
                        if src_e.kind == EntryKind::File && filter.matches_entry(&src_e, now_ns) {
                            report.record_missing_on_dst(src_e.nfc_path.as_str().to_string());
                        }
                    }
                    DiffItem::DstOnly(dst_e) => {
                        if !args.one_way
                            && dst_e.kind == EntryKind::File
                            && filter.matches_entry(&dst_e, now_ns)
                        {
                            report.record_missing_on_src(dst_e.nfc_path.as_str().to_string());
                        }
                    }
                    DiffItem::Both {
                        src: src_e,
                        dst: dst_e,
                    } => {
                        if src_e.kind != EntryKind::File || !filter.matches_entry(&src_e, now_ns) {
                            continue;
                        }
                        if let Some(pair) = report.classify_file_pair(
                            src_e,
                            dst_e,
                            args.size_only,
                            common_hash,
                            &src_caps.hashes,
                            &dst_caps.hashes,
                        ) {
                            hash_candidates.push(pair);
                        }
                    }
                }
            }

            verify_hash_batch(
                hash_candidates,
                &src_backend,
                &dst_backend,
                &src_prefix,
                &dst_prefix,
                common_hash,
                &src_caps.hashes,
                &dst_caps.hashes,
                checkers,
                &mut report,
            )
            .await;

            if hit_eof {
                break;
            }
        }

        for info in diff.drain_errors() {
            report.record_error_info(info);
        }
        (diff.src_complete(), diff.dst_complete())
    } else {
        let run_id = format!(
            "check-{}-{:x}",
            rship_core::time::format_compact_utc(rship_core::time::now_unix_secs()),
            std::process::id()
        );
        let sync_index = Arc::new(SqliteSyncIndex::open_temp(
            &rt.paths.ephemeral_dir(),
            &run_id,
        )?);

        let ((src_ok, src_errs), (dst_ok, dst_errs)) = tokio::join!(
            observe_into_index(
                &src_backend,
                &src_prefix,
                &filter,
                now_ns,
                true,
                &sync_index
            ),
            observe_into_index(
                &dst_backend,
                &dst_prefix,
                &filter,
                now_ns,
                false,
                &sync_index
            ),
        );
        for info in src_errs.into_iter().chain(dst_errs) {
            report.record_error_info(info);
        }

        let idx_conflicts = sync_index
            .finalize_and_detect_conflicts(dst_caps.case_sensitive)
            .await?;
        let conflict_paths: HashSet<RelPath> =
            idx_conflicts.iter().map(|c| c.nfc_path.clone()).collect();
        for c in idx_conflicts {
            report.record_conflict(c);
        }

        let mut after_id = 0i64;
        loop {
            let page = sync_index.next_src_page(after_id, 512).await?;
            if page.is_empty() {
                break;
            }
            let mut hash_candidates: Vec<(Entry, Entry)> = Vec::new();
            for row in page {
                after_id = row.row_id;
                let Some(src_e) = row.src else { continue };
                if conflict_paths.contains(&src_e.nfc_path) || src_e.kind != EntryKind::File {
                    continue;
                }
                let Some(dst_e) = row.dst else {
                    report.record_missing_on_dst(src_e.nfc_path.as_str().to_string());
                    continue;
                };
                if let Some(pair) = report.classify_file_pair(
                    src_e,
                    dst_e,
                    args.size_only,
                    common_hash,
                    &src_caps.hashes,
                    &dst_caps.hashes,
                ) {
                    hash_candidates.push(pair);
                }
            }

            verify_hash_batch(
                hash_candidates,
                &src_backend,
                &dst_backend,
                &src_prefix,
                &dst_prefix,
                common_hash,
                &src_caps.hashes,
                &dst_caps.hashes,
                checkers,
                &mut report,
            )
            .await;
        }

        if !args.one_way {
            let mut dst_after_id = 0i64;
            loop {
                let page = sync_index.next_dst_only_page(dst_after_id, 512).await?;
                if page.is_empty() {
                    break;
                }
                for row in page {
                    dst_after_id = row.row_id;
                    let Some(dst_e) = row.dst else { continue };
                    if conflict_paths.contains(&dst_e.nfc_path) {
                        continue;
                    }
                    if dst_e.kind == EntryKind::File && filter.matches_entry(&dst_e, now_ns) {
                        report.record_missing_on_src(dst_e.nfc_path.as_str().to_string());
                    }
                }
            }
        }

        (src_ok, dst_ok)
    };

    report.finish_and_print(common_hash, src_ok, dst_ok, started)
}

async fn execute_single_file_check(
    args: CheckArgs,
    src_res: super::ResolvedTarget,
    dst_res: super::ResolvedTarget,
    filter: &FilterSet,
    started: Instant,
) -> Result<ExitCode> {
    let now_ns = SystemClock::shared().now_unix_nanos();
    let src_caps = src_res.backend.capabilities();
    let dst_caps = dst_res.backend.capabilities();
    let common_hash = if args.size_only {
        None
    } else {
        src_caps.best_common_hash(&dst_caps)
    };

    // If `src` is a single file and `dst` was passed as a directory/prefix, probe `dst/<src_leaf>`!
    let mut dst_file = dst_res.single_file;
    if dst_file.is_none()
        && let Some(ref sf) = src_res.single_file
        && let Some(leaf) = sf.nfc_path.file_name()
        && let Ok(leaf_rel) = RelPath::parse(leaf)
        && let Ok(Some(found)) = dst_res
            .backend
            .stat(&BackendPath::from_rel(dst_res.prefix.join_path(&leaf_rel)))
            .await
        && found.kind == EntryKind::File
    {
        dst_file = Some(found);
    }

    let mut report = CheckReport::new(args.json);

    let leaf_label_and_filter_entry = |e: &Entry| -> (String, Entry) {
        let label = e
            .nfc_path
            .file_name()
            .unwrap_or(e.nfc_path.as_str())
            .to_string();
        let mut fe = e.clone();
        if let Ok(rel) = RelPath::parse(&label) {
            fe.nfc_path = rel;
        }
        (label, fe)
    };

    match (src_res.single_file, dst_file) {
        (Some(src_e), None) => {
            let (label, fe) = leaf_label_and_filter_entry(&src_e);
            if filter.matches_entry(&fe, now_ns) {
                report.record_missing_on_dst(label);
            }
        }
        (None, Some(dst_e)) => {
            if !args.one_way {
                let (label, fe) = leaf_label_and_filter_entry(&dst_e);
                if filter.matches_entry(&fe, now_ns) {
                    report.record_missing_on_src(label);
                }
            }
        }
        (Some(src_e), Some(dst_e)) => {
            let (label, fe) = leaf_label_and_filter_entry(&src_e);
            if filter.matches_entry(&fe, now_ns) {
                if src_e.size != dst_e.size {
                    report.record_size_mismatch(&label, src_e.size, dst_e.size);
                } else if args.size_only {
                    report.matched += 1;
                } else {
                    let res = verify_pair_hash(
                        &src_res.backend,
                        &dst_res.backend,
                        BackendPath::from_entry(&src_e),
                        BackendPath::from_entry(&dst_e),
                        &src_e,
                        &dst_e,
                        &label,
                        common_hash,
                        &src_caps.hashes,
                        &dst_caps.hashes,
                    )
                    .await;
                    report.record_hash_result(res, Some(label));
                }
            }
        }
        (None, None) => {}
    }

    report.finish_and_print(common_hash, true, true, started)
}

#[derive(Default)]
struct TreeNode {
    is_dir: bool,
    size: u64,
    children: BTreeMap<String, TreeNode>,
}

pub async fn execute_tree(args: TreeArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let resolved = rt.resolve_any_target(&args.target, None).await?;
    let backend = resolved.backend;
    let prefix = resolved.prefix;
    let filter = FilterSet::from_options(&rt.build_filter_options(&args.filters)?)?;

    let mut root = TreeNode {
        is_dir: true,
        size: 0,
        children: BTreeMap::new(),
    };
    let now_ns = SystemClock::shared().now_unix_nanos();
    let mut dirs = 0u64;
    let mut files = 0u64;
    let mut total_bytes = 0u64;

    if let Some(mut entry) = resolved.single_file {
        let leaf = entry
            .nfc_path
            .file_name()
            .unwrap_or(entry.nfc_path.as_str())
            .to_string();
        if let Ok(rel) = rship_core::path::RelPath::parse(&leaf) {
            entry.nfc_path = rel;
        }
        if !args.dirs_only && filter.matches_entry(&entry, now_ns) {
            files = 1;
            total_bytes = entry.size;
            root.children.insert(
                leaf,
                TreeNode {
                    is_dir: false,
                    size: entry.size,
                    children: BTreeMap::new(),
                },
            );
        }
    } else {
        let mut list_opts = ListOptions::recursive().with_filter_pruning(&filter, &prefix);
        if let Some(max_d) = args.max_depth {
            list_opts = list_opts.with_max_depth(max_d);
        }
        let mut stream = backend.list_with_options(&prefix, &list_opts).await?;
        while let Some(item) = stream.next().await {
            let mut entry = item?;
            let rel = if prefix.is_root() {
                entry.nfc_path.clone()
            } else if let Some(r) = entry.nfc_path.strip_prefix(&prefix) {
                r
            } else {
                continue;
            };
            if rel.is_root() {
                continue;
            }
            let segs: Vec<&str> = rel.segments().collect();
            if let Some(max_d) = args.max_depth
                && segs.len() > max_d
            {
                continue;
            }
            entry.nfc_path = rel.clone();
            if entry.kind == EntryKind::Directory {
                if filter.should_prune_dir(&rel) {
                    continue;
                }
            } else {
                if args.dirs_only || !filter.matches_entry(&entry, now_ns) {
                    continue;
                }
                files += 1;
                total_bytes = total_bytes.saturating_add(entry.size);
            }

            let mut cur = &mut root;
            for (idx, seg) in segs.iter().enumerate() {
                let is_last = idx + 1 == segs.len();
                let node = cur.children.entry((*seg).to_string()).or_insert_with(|| {
                    let is_dir = !is_last || entry.kind == EntryKind::Directory;
                    if is_dir {
                        dirs += 1;
                    }
                    TreeNode {
                        is_dir,
                        size: 0,
                        children: BTreeMap::new(),
                    }
                });
                if is_last && entry.kind == EntryKind::File {
                    node.is_dir = false;
                    node.size = entry.size;
                }
                cur = node;
            }
        }
    }

    let st = Style::stdout();
    println!("{}", st.bold(&args.target));
    print_tree_children(&root, "", args.sizes, st);
    println!(
        "\n{}",
        st.dim(&format!(
            "{dirs} directories, {files} files ({})",
            format_human_bytes(total_bytes)
        ))
    );
    Ok(ExitCode::SUCCESS)
}

fn print_tree_children(node: &TreeNode, indent: &str, show_sizes: bool, st: Style) {
    let total = node.children.len();
    for (idx, (name, child)) in node.children.iter().enumerate() {
        let is_last = idx + 1 == total;
        let branch = if is_last { "└── " } else { "├── " };
        let label = if child.is_dir {
            st.accent_bold(&format!("{name}/"))
        } else if show_sizes {
            format!(
                "{name} {}",
                st.dim(&format!("({})", format_human_bytes(child.size)))
            )
        } else {
            name.clone()
        };
        println!("{}{label}", st.dim(&format!("{indent}{branch}")));
        if child.is_dir && !child.children.is_empty() {
            let next_indent = format!("{indent}{}", if is_last { "    " } else { "│   " });
            print_tree_children(child, &next_indent, show_sizes, st);
        }
    }
}

pub async fn execute_size(args: SizeArgs, rt: &mut CliRuntime<'_>) -> Result<ExitCode> {
    let resolved = rt.resolve_any_target(&args.target, None).await?;
    let backend = resolved.backend;
    let prefix = resolved.prefix;
    let filter = FilterSet::from_options(&rt.build_filter_options(&args.filters)?)?;
    let now_ns = SystemClock::shared().now_unix_nanos();

    let mut count = 0u64;
    let mut bytes = 0u64;
    if let Some(mut entry) = resolved.single_file {
        let leaf = entry
            .nfc_path
            .file_name()
            .unwrap_or(entry.nfc_path.as_str())
            .to_string();
        if let Ok(rel) = rship_core::path::RelPath::parse(&leaf) {
            entry.nfc_path = rel;
        }
        if filter.matches_entry(&entry, now_ns) {
            count = 1;
            bytes = entry.size;
        }
    } else {
        let list_opts = ListOptions::recursive().with_filter_pruning(&filter, &prefix);
        let mut stream = backend.list_with_options(&prefix, &list_opts).await?;
        while let Some(item) = stream.next().await {
            let mut entry = item?;
            if entry.kind != EntryKind::File {
                continue;
            }
            let rel = if prefix.is_root() {
                entry.nfc_path.clone()
            } else if let Some(r) = entry.nfc_path.strip_prefix(&prefix) {
                r
            } else {
                continue;
            };
            if rel.is_root() {
                continue;
            }
            entry.nfc_path = rel;
            if !filter.matches_entry(&entry, now_ns) {
                continue;
            }
            count += 1;
            bytes = bytes.saturating_add(entry.size);
        }
    }

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "count": count,
                "bytes": bytes,
            }))?
        );
    } else {
        let st = Style::stdout();
        println!("{}  {}", st.dim("Objects"), st.bold(&count.to_string()));
        println!(
            "{}     {} {}",
            st.dim("Size"),
            st.bold(&format_human_bytes(bytes)),
            st.dim(&format!("({bytes} B)"))
        );
    }
    Ok(ExitCode::SUCCESS)
}
