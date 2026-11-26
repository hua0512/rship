//! Pure-RAM sorted merge and conflict detection for small/everyday sync runs.

use rship_core::path::RelPath;
use rship_core::state::{ConflictKind, DiffRow, SyncConflict};
use rship_core::types::Entry;
use std::collections::{BTreeMap, HashMap};

pub(super) struct InMemoryReadState {
    src: Vec<Entry>,
    dst: Vec<Entry>,
    conflicts: Vec<SyncConflict>,
    src_idx: usize,
    dst_idx: usize,
    src_seq: i64,
    dst_only_dst_idx: usize,
    dst_only_src_idx: usize,
    dst_only_seq: i64,
}

impl InMemoryReadState {
    pub(super) fn finalize(
        mut src: Vec<Entry>,
        mut dst: Vec<Entry>,
        dst_case_sensitive: bool,
    ) -> (Self, Vec<SyncConflict>) {
        // Preserve insertion order for equal `nfc_path` keys (matching `(nfc_path ASC, id ASC)`).
        src.sort_by(|a, b| a.nfc_path.as_str().cmp(b.nfc_path.as_str()));
        dst.sort_by(|a, b| a.nfc_path.as_str().cmp(b.nfc_path.as_str()));

        let mut conflicts = Vec::new();

        // 1. Intra-source duplicates / NFC collisions.
        let mut i = 0;
        while i < src.len() {
            let mut j = i + 1;
            while j < src.len() && src[j].nfc_path == src[i].nfc_path {
                j += 1;
            }
            if j - i > 1 {
                let first_raw = src[i].raw_path();
                let has_distinct_raw = src[i + 1..j].iter().any(|e| e.raw_path() != first_raw);
                let kind = if has_distinct_raw {
                    ConflictKind::UnicodeNfcCollision
                } else {
                    ConflictKind::DuplicateSourceName
                };
                let nfc = src[i].nfc_path.clone();
                let detail = format!("{} source entries map to NFC path `{nfc}`", j - i);
                conflicts.push(SyncConflict {
                    nfc_path: nfc,
                    kind,
                    detail,
                });
            }
            i = j;
        }

        // 2. Intra-destination duplicates.
        let mut k = 0;
        while k < dst.len() {
            let mut j = k + 1;
            while j < dst.len() && dst[j].nfc_path == dst[k].nfc_path {
                j += 1;
            }
            if j - k > 1 {
                let nfc = dst[k].nfc_path.clone();
                let detail = format!("{} destination entries share path `{nfc}`", j - k);
                conflicts.push(SyncConflict {
                    nfc_path: nfc,
                    kind: ConflictKind::DuplicateDestinationName,
                    detail,
                });
            }
            k = j;
        }

        // 3. Case-insensitive destination collisions (cross-side and same-side).
        if !dst_case_sensitive {
            let mut by_fold: BTreeMap<String, Vec<RelPath>> = BTreeMap::new();
            let mut seen_nfc: HashMap<&str, ()> = HashMap::with_capacity(src.len() + dst.len());
            for entry in src.iter().chain(dst.iter()) {
                if seen_nfc.insert(entry.nfc_path.as_str(), ()).is_none() {
                    let fold = entry.nfc_path.fold_key_cow().into_owned();
                    by_fold
                        .entry(fold)
                        .or_default()
                        .push(entry.nfc_path.clone());
                }
            }
            for (fold, mut members) in by_fold {
                if members.len() > 1 {
                    members.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                    for nfc in members {
                        let detail = format!("`{nfc}` collides case-insensitively on `{fold}`");
                        conflicts.push(SyncConflict {
                            nfc_path: nfc,
                            kind: ConflictKind::CaseInsensitiveCollision,
                            detail,
                        });
                    }
                }
            }
        }

        let returned = conflicts.clone();
        let state = Self {
            src,
            dst,
            conflicts,
            src_idx: 0,
            dst_idx: 0,
            src_seq: 0,
            dst_only_dst_idx: 0,
            dst_only_src_idx: 0,
            dst_only_seq: 0,
        };
        (state, returned)
    }

    pub(super) fn conflicts(&self) -> &[SyncConflict] {
        &self.conflicts
    }

    pub(super) fn next_src_page(&mut self, after_id: i64, limit: usize) -> Vec<DiffRow> {
        if limit == 0 {
            return Vec::new();
        }
        let Self {
            ref src,
            ref dst,
            ref mut src_idx,
            ref mut dst_idx,
            ref mut src_seq,
            ..
        } = *self;

        if after_id <= 0 {
            *src_idx = 0;
            *dst_idx = 0;
            *src_seq = 0;
        } else if *src_seq != after_id {
            let target = (after_id as usize).min(src.len());
            *src_idx = target;
            *src_seq = target as i64;
            *dst_idx = if let Some(cur) = src.get(*src_idx) {
                dst.partition_point(|d| d.nfc_path.as_str() < cur.nfc_path.as_str())
            } else {
                dst.len()
            };
        }

        let mut out = Vec::with_capacity(limit.min(512));
        while out.len() < limit && *src_idx < src.len() {
            let src_entry = src[*src_idx].clone();
            *src_idx += 1;
            while *dst_idx < dst.len()
                && dst[*dst_idx].nfc_path.as_str() < src_entry.nfc_path.as_str()
            {
                *dst_idx += 1;
            }
            let matched_dst = dst
                .get(*dst_idx)
                .filter(|d| d.nfc_path.as_str() == src_entry.nfc_path.as_str())
                .cloned();
            *src_seq += 1;
            out.push(DiffRow {
                row_id: *src_seq,
                src: Some(src_entry),
                dst: matched_dst,
            });
        }
        out
    }

    pub(super) fn next_dst_only_page(&mut self, after_id: i64, limit: usize) -> Vec<DiffRow> {
        if limit == 0 {
            return Vec::new();
        }
        let Self {
            ref src,
            ref dst,
            ref mut dst_only_dst_idx,
            ref mut dst_only_src_idx,
            ref mut dst_only_seq,
            ..
        } = *self;

        let mut skip_count = 0i64;
        if after_id <= 0 {
            *dst_only_dst_idx = 0;
            *dst_only_src_idx = 0;
            *dst_only_seq = 0;
        } else if *dst_only_seq != after_id {
            *dst_only_dst_idx = 0;
            *dst_only_src_idx = 0;
            *dst_only_seq = 0;
            skip_count = after_id;
        }

        let mut out = Vec::with_capacity(limit.min(512));
        while out.len() < limit && *dst_only_dst_idx < dst.len() {
            let dst_entry = &dst[*dst_only_dst_idx];
            *dst_only_dst_idx += 1;
            while *dst_only_src_idx < src.len()
                && src[*dst_only_src_idx].nfc_path.as_str() < dst_entry.nfc_path.as_str()
            {
                *dst_only_src_idx += 1;
            }
            if *dst_only_src_idx < src.len()
                && src[*dst_only_src_idx].nfc_path.as_str() == dst_entry.nfc_path.as_str()
            {
                continue;
            }
            *dst_only_seq += 1;
            if skip_count > 0 {
                skip_count -= 1;
                continue;
            }
            out.push(DiffRow {
                row_id: *dst_only_seq,
                src: None,
                dst: Some(dst_entry.clone()),
            });
        }
        out
    }
}
