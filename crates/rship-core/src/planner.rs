//! Pure deterministic Sync/Copy Planner (Unison + Dropbox Nucleus model).
//!
//! Computes exact actions from observed `(src, dst, baseline)` tuples while
//! enforcing structural safety invariants:
//! - Observation Completeness Gate: any `src` scan error blocks ALL deletions.
//! - Conflict protection: conflicted paths are never mutated or deleted.
//! - Type-flip guard: never silently replaces a directory with a file (or vice versa).
//! - Racily-clean mtime rule: timestamps within filesystem granularity of scan
//!   start are not blindly trusted without verification.
//! - S3 multipart ETag guard: ETags containing `-` are never treated as MD5.

use crate::backend::BackendPath;
use crate::path::RelPath;
use crate::state::{BaselineRecord, ConflictKind, DstPrecondition, SyncConflict};
use crate::types::{Capabilities, Entry, EntryKind, HashKind};

#[derive(Debug, Clone)]
pub struct PlanOptions {
    pub delete: bool,
    pub max_delete: Option<u64>,
    pub checksum_mode: bool,
    pub force_type_replace: bool,
    pub scan_started_unix_ns: i64,
    pub src_observation_complete: bool,
    pub dst_observation_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlannedAction {
    Skip,
    Mkdir {
        path: RelPath,
    },
    /// `--force-type-replace`: delete an existing destination file before creating a directory.
    ReplaceWithDir {
        path: RelPath,
        dst_to_delete: BackendPath,
    },
    Transfer(Box<PlannedTransfer>),
    Delete {
        dst: BackendPath,
        kind: EntryKind,
    },
    Conflict(SyncConflict),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTransfer {
    pub src: Entry,
    pub dst_path: RelPath,
    pub existing_dst_node_id: Option<crate::types::NodeId>,
    pub precondition: DstPrecondition,
    pub needs_checksum_verify: bool,
    /// Set under `--force-type-replace` when replacing a destination directory with a file.
    pub replace_dst_dir: Option<BackendPath>,
}

/// Evaluate one source-side diff row into a deterministic `PlannedAction`.
pub fn plan_source_item(
    src: &Entry,
    dst: Option<&Entry>,
    baseline: Option<&BaselineRecord>,
    src_caps: &Capabilities,
    dst_caps: &Capabilities,
    opts: &PlanOptions,
) -> PlannedAction {
    match (src.kind, dst.map(|d| d.kind)) {
        // Structural invariant: guard file <-> directory type flips.
        (EntryKind::File, Some(EntryKind::Directory)) if !opts.force_type_replace => {
            return PlannedAction::Conflict(SyncConflict {
                nfc_path: src.nfc_path.clone(),
                kind: ConflictKind::TypeFlipFileOverDir,
                detail: "source file would replace destination directory (pass --force-type-replace to override)".into(),
            });
        }
        (EntryKind::Directory, Some(EntryKind::File)) if !opts.force_type_replace => {
            return PlannedAction::Conflict(SyncConflict {
                nfc_path: src.nfc_path.clone(),
                kind: ConflictKind::TypeFlipDirOverFile,
                detail: "source directory would replace destination file (pass --force-type-replace to override)".into(),
            });
        }
        (EntryKind::Directory, Some(EntryKind::File)) => {
            let dst_entry = dst.expect("matched Some(EntryKind::File)");
            return PlannedAction::ReplaceWithDir {
                path: src.nfc_path.clone(),
                dst_to_delete: BackendPath::from_entry(dst_entry),
            };
        }
        (EntryKind::File, Some(EntryKind::Directory)) => {
            let dst_entry = dst.expect("matched Some(EntryKind::Directory)");
            return PlannedAction::Transfer(Box::new(PlannedTransfer {
                src: src.clone(),
                dst_path: src.nfc_path.clone(),
                existing_dst_node_id: None,
                precondition: DstPrecondition::Absent,
                needs_checksum_verify: false,
                replace_dst_dir: Some(BackendPath::from_entry(dst_entry)),
            }));
        }
        (EntryKind::Directory, Some(EntryKind::Directory)) => return PlannedAction::Skip,
        (EntryKind::Directory, None) => {
            return PlannedAction::Mkdir {
                path: src.nfc_path.clone(),
            };
        }
        (EntryKind::Symlink, _) => return PlannedAction::Skip,
        _ => {}
    }

    let Some(dst_entry) = dst else {
        return PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src.clone(),
            dst_path: src.nfc_path.clone(),
            existing_dst_node_id: None,
            precondition: DstPrecondition::Absent,
            needs_checksum_verify: false,
            replace_dst_dir: None,
        }));
    };

    let src_gran_ns = i64::try_from(src_caps.mtime_granularity.as_nanos()).unwrap_or(i64::MAX);
    let dst_gran_ns = i64::try_from(dst_caps.mtime_granularity.as_nanos()).unwrap_or(i64::MAX);
    let tolerance_ns = src_gran_ns.max(dst_gran_ns);

    if src.size != dst_entry.size {
        return PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src.clone(),
            dst_path: src.nfc_path.clone(),
            existing_dst_node_id: dst_entry.node_id.clone(),
            precondition: DstPrecondition::Existing {
                node_id: dst_entry.node_id.clone(),
                etag: dst_entry.etag.clone(),
                mtime_ns: dst_entry.mtime_ns,
                size: dst_entry.size,
            },
            needs_checksum_verify: false,
            replace_dst_dir: None,
        }));
    }

    // Live comparable full-object checksums take priority over `sync_baseline` so
    // authoritative live hashes both skip in O(1) without touching SQLite AND catch
    // silent bitrot/mutation even when timestamps match a stale baseline.
    if let (Some(sh), Some(dh)) = (&src.checksum, &dst_entry.checksum)
        && sh.kind == dh.kind
        && !is_multipart_etag(sh.kind, &sh.hex)
        && !is_multipart_etag(dh.kind, &dh.hex)
    {
        if sh.hex.eq_ignore_ascii_case(&dh.hex) {
            return PlannedAction::Skip;
        }
        return PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src.clone(),
            dst_path: src.nfc_path.clone(),
            existing_dst_node_id: dst_entry.node_id.clone(),
            precondition: DstPrecondition::Existing {
                node_id: dst_entry.node_id.clone(),
                etag: dst_entry.etag.clone(),
                mtime_ns: dst_entry.mtime_ns,
                size: dst_entry.size,
            },
            needs_checksum_verify: false,
            replace_dst_dir: None,
        }));
    }

    // Git racily-clean guard:
    // - Against `sync_baseline`, `base.src_mtime_ns` records the exact source timestamp at
    //   `src_caps.mtime_granularity` resolution (e.g. 100ns on NTFS / 1ns on ext4), so `src` is
    //   only racily-clean relative to `base.src_mtime_ns` within `src_gran_ns`.
    // - Against `dst_entry.mtime_ns` directly, coarse destination truncation requires guarding
    //   within `tolerance_ns` (`max(src, dst)`).
    let src_gran_u64 = u64::try_from(src_gran_ns).unwrap_or(0);
    let dst_gran_u64 = u64::try_from(dst_gran_ns).unwrap_or(0);
    let tolerance_u64 = u64::try_from(tolerance_ns).unwrap_or(0);
    let src_racily_clean_for_base =
        opts.scan_started_unix_ns.abs_diff(src.mtime_ns) <= src_gran_u64;
    let src_racily_clean = opts.scan_started_unix_ns.abs_diff(src.mtime_ns) <= tolerance_u64;

    // Fast skip via dual-side `sync_baseline`: solves S3/WebDAV server-assigned `LastModified`
    // and multipart ETags without re-hashing local files!
    if !opts.checksum_mode
        && !src_racily_clean_for_base
        && let Some(base) = baseline
        && base.kind == EntryKind::File
        && base.size == src.size
        && src.size == dst_entry.size
        && src.mtime_ns.abs_diff(base.src_mtime_ns) <= src_gran_u64
        && dst_entry.mtime_ns.abs_diff(base.dst_mtime_ns) <= dst_gran_u64
        && (base.dst_etag.is_none() || base.dst_etag == dst_entry.etag)
    {
        return PlannedAction::Skip;
    }

    if opts.checksum_mode {
        return PlannedAction::Transfer(Box::new(PlannedTransfer {
            src: src.clone(),
            dst_path: src.nfc_path.clone(),
            existing_dst_node_id: dst_entry.node_id.clone(),
            precondition: DstPrecondition::Existing {
                node_id: dst_entry.node_id.clone(),
                etag: dst_entry.etag.clone(),
                mtime_ns: dst_entry.mtime_ns,
                size: dst_entry.size,
            },
            needs_checksum_verify: true,
            replace_dst_dir: None,
        }));
    }

    // Standard size + precision-aware mtime comparison when destination preserves mtime.
    if dst_caps.can_set_mtime
        && !src_racily_clean
        && src.mtime_ns.abs_diff(dst_entry.mtime_ns) <= tolerance_u64
    {
        return PlannedAction::Skip;
    }

    PlannedAction::Transfer(Box::new(PlannedTransfer {
        src: src.clone(),
        dst_path: src.nfc_path.clone(),
        existing_dst_node_id: dst_entry.node_id.clone(),
        precondition: DstPrecondition::Existing {
            node_id: dst_entry.node_id.clone(),
            etag: dst_entry.etag.clone(),
            mtime_ns: dst_entry.mtime_ns,
            size: dst_entry.size,
        },
        needs_checksum_verify: src_racily_clean || !dst_caps.can_set_mtime,
        replace_dst_dir: None,
    }))
}

/// Evaluate one destination-only item for `--delete`.
///
/// Enforces the **Observation Completeness Gate**: if `src` observation hit ANY
/// error, deletions are unconditionally refused.
pub fn plan_dst_only_item(dst: &Entry, opts: &PlanOptions) -> PlannedAction {
    if !opts.delete || !opts.src_observation_complete || !opts.dst_observation_complete {
        return PlannedAction::Skip;
    }
    PlannedAction::Delete {
        dst: BackendPath::from_entry(dst),
        kind: dst.kind,
    }
}

fn is_multipart_etag(_kind: HashKind, hex_val: &str) -> bool {
    // No valid full-object hex checksum ever contains `-`; S3 multipart ETags (`<md5>-<N>`)
    // and composite multipart checksums (`<b64>-<N>`) always do.
    hex_val.contains('-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChunkAlignment, NodeId, UploadTopology};
    use std::time::Duration;

    fn sample_caps(can_set_mtime: bool) -> Capabilities {
        Capabilities {
            hashes: vec![HashKind::Sha256, HashKind::Md5],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: 1024,
            default_chunk_size: 1024,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
            default_write_qps: None,
        }
    }

    fn file_entry(path: &str, size: u64, mtime_s: i64, etag: Option<&str>) -> Entry {
        Entry {
            node_id: Some(NodeId(format!("id:{path}"))),
            parent_id: None,
            raw_path: crate::types::raw_path_override(&RelPath::parse(path).unwrap(), path),
            nfc_path: RelPath::parse(path).unwrap(),
            kind: EntryKind::File,
            size,
            mtime_ns: mtime_s * 1_000_000_000,
            ctime_ns: None,
            etag: etag.map(str::to_string),
            checksum: None,
        }
    }

    #[test]
    fn observation_completeness_gate_blocks_all_deletes() {
        let dst = file_entry("old.txt", 10, 100, None);
        let opts_incomplete = PlanOptions {
            delete: true,
            max_delete: None,
            checksum_mode: false,
            force_type_replace: false,
            scan_started_unix_ns: 200 * 1_000_000_000,
            src_observation_complete: false,
            dst_observation_complete: true,
        };
        assert_eq!(
            plan_dst_only_item(&dst, &opts_incomplete),
            PlannedAction::Skip
        );
    }

    #[test]
    fn dual_side_baseline_skips_s3_server_mtime_mismatch() {
        let src_caps = sample_caps(true);
        let s3_caps = sample_caps(false);
        let src = file_entry("video.mp4", 5000, 1_700_000_000, None);
        // S3 LastModified is 500s later than local mtime!
        let dst = file_entry("video.mp4", 5000, 1_700_000_500, Some("\"abc-12\""));
        let base = BaselineRecord {
            pair_key: "p".into(),
            nfc_path: src.nfc_path.clone(),
            kind: EntryKind::File,
            src_node_id: src.node_id.clone(),
            dst_node_id: dst.node_id.clone(),
            size: 5000,
            src_mtime_ns: 1_700_000_000 * 1_000_000_000,
            dst_mtime_ns: 1_700_000_500 * 1_000_000_000,
            dst_etag: Some("\"abc-12\"".into()),
            hash_kind: None,
            hash_hex: None,
            updated_at: 1_700_000_501,
        };
        let opts = PlanOptions {
            delete: false,
            max_delete: None,
            checksum_mode: false,
            force_type_replace: false,
            scan_started_unix_ns: 1_700_001_000 * 1_000_000_000,
            src_observation_complete: true,
            dst_observation_complete: true,
        };
        assert_eq!(
            plan_source_item(&src, Some(&dst), Some(&base), &src_caps, &s3_caps, &opts),
            PlannedAction::Skip
        );
    }

    #[test]
    fn blocks_type_flip_without_force_flag() {
        let caps = sample_caps(true);
        let src = file_entry("clash", 10, 100, None);
        let mut dst_dir = file_entry("clash", 0, 100, None);
        dst_dir.kind = EntryKind::Directory;
        let opts = PlanOptions {
            delete: false,
            max_delete: None,
            checksum_mode: false,
            force_type_replace: false,
            scan_started_unix_ns: 200 * 1_000_000_000,
            src_observation_complete: true,
            dst_observation_complete: true,
        };
        assert!(matches!(
            plan_source_item(&src, Some(&dst_dir), None, &caps, &caps, &opts),
            PlannedAction::Conflict(SyncConflict {
                kind: ConflictKind::TypeFlipFileOverDir,
                ..
            })
        ));
    }
}
