//! Unified zero-disk streaming merge-join (`StreamingMergeDiffSource`), Two-Gear
//! skew-proof parallel ordered range listing, hybrid `DeleteSpillLog`, and safe
//! `StartAfter` crash-resume watermarks.
//!
//! Design invariants:
//! - **Small buckets (`<= 1,000` objects/side)**: Gear 1 executes ONE `list_ordered_page`
//!   RPC per side, knows exact totals immediately (`totals_discovered = true`), creates
//!   zero disk files, and begins transferring on the very first page.
//! - **Massive buckets (`40M+` objects, flat UUID OR 99.9%-skewed prefixes)**: Gear 2
//!   anchors 3 seed probes at `LCP(first_key, last_key)` and uses dynamic lexicographic
//!   midpoint work-stealing bisection over disjoint half-open `(lower_exclusive, upper_inclusive]`
//!   shards (provably zero overlap, zero gaps, zero Swift `delimiter="/"` stalls, bounded
//!   `<= 2` pages per shard in RAM).
//! - **Wire-order fidelity**: `cmp_merge_key` treats directories as carrying an implicit
//!   trailing `'/'` (`0x2F`), matching S3/GCS/Azure wire order (`"a-b" < "a.txt" < "a/"`)
//!   in `O(1)` memory.

mod spill;
mod watermark;

pub use spill::{DELETE_SPILL_RAM_CAP, DeleteSpillLog, DeleteSpillReader, DeleteTarget};
pub use watermark::SafeWatermarkTracker;

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::backend::{BackendPath, DirPruner, OrderedListPage, StorageBackend};
use crate::error::Result;
use crate::path::RelPath;
use crate::state::{ConflictKind, SyncConflict};
use crate::types::{Entry, EntryKind};

use super::{CancelFlag, TransferErrorInfo};

const ORDERED_PAGE_MAX_KEYS: u32 = 1000;
const SHARD_CHANNEL_CAP: usize = 2;
const MAX_NFD_TRACKED: usize = 65_536;
/// Sentinel sorting strictly after EVERY valid UTF-8 byte sequence (including 4-byte emoji
/// scalars `U+10000..=U+10FFFF`, lead bytes `0xF0..=0xF4`), used for `start_after` jumps
/// past excluded directory subtrees.
const DIR_JUMP_SENTINEL: &str = "\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}";

/// Canonical wire-order comparator matching S3/GCS/Azure UTF-8 byte order in `O(1)` RAM:
/// directory entries compare as if carrying an implicit trailing `'/'` (`0x2F`), so
/// `"a-b"` (`0x2D`) < `"a.txt"` (`0x2E`) < `"a/"` (`0x2F`) < `"a/0"` < `"a0"` (`0x30`).
#[inline]
pub fn cmp_merge_key(a_path: &str, a_is_dir: bool, b_path: &str, b_is_dir: bool) -> Ordering {
    let ab = a_path.as_bytes();
    let bb = b_path.as_bytes();
    let min_len = ab.len().min(bb.len());
    let mut i = 0;
    while i < min_len {
        if ab[i] != bb[i] {
            return ab[i].cmp(&bb[i]);
        }
        i += 1;
    }
    match ab.len().cmp(&bb.len()) {
        Ordering::Equal => a_is_dir.cmp(&b_is_dir),
        Ordering::Less => {
            if a_is_dir {
                match b'/'.cmp(&bb[min_len]) {
                    Ordering::Equal => Ordering::Less, // `"a/"` < `"a/..."`
                    ord => ord,                        // `"a/"` > `"a-b"`, `"a/"` < `"a0"`
                }
            } else {
                Ordering::Less
            }
        }
        Ordering::Greater => {
            if b_is_dir {
                match ab[min_len].cmp(&b'/') {
                    Ordering::Equal => Ordering::Greater, // `"a/..."` > `"a/"`
                    ord => ord,                           // `"a-b"` < `"a/"`, `"a0"` > `"a/"`
                }
            } else {
                Ordering::Greater
            }
        }
    }
}

/// Wire key representation of an [`Entry`] (retaining trailing `'/'` on directory markers).
#[inline]
pub fn entry_wire_key(entry: &Entry) -> String {
    let raw = entry.raw_path();
    if entry.kind == EntryKind::Directory {
        let mut s = String::with_capacity(raw.len() + 1);
        s.push_str(raw);
        s.push('/');
        s
    } else {
        raw.to_string()
    }
}

/// Canonical slash-terminated comparator: treats BOTH files and directories as carrying an
/// implicit trailing `'/'` (`0x2F`), so `File("app")` and `Directory("app")` occupy the
/// **exact same** merge slot (`"app/"`) after `"app-v2"` (`'-' = 0x2D`) and `"app.conf"`
/// (`'.' = 0x2E`) and before `"app/child"` and `"app0"` (`'0' = 0x30`).
#[inline]
pub fn cmp_slash_key(a_path: &str, b_path: &str) -> Ordering {
    cmp_merge_key(a_path, true, b_path, true)
}

/// Owned sort key implementing [`cmp_slash_key`] ordering for canonical merge buffering.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SlashMergeKey(String);

impl Ord for SlashMergeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_slash_key(&self.0, &other.0)
    }
}

impl PartialOrd for SlashMergeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Compute the longest common UTF-8 prefix of two strings on char boundaries.
fn longest_common_prefix<'a>(a: &'a str, b: &str) -> &'a str {
    let mut last_char_end = 0usize;
    for ((idx, ca), (_, cb)) in a.char_indices().zip(b.char_indices()) {
        if ca != cb {
            break;
        }
        last_char_end = idx + ca.len_utf8();
    }
    &a[..last_char_end]
}

/// Compute a valid UTF-8 string `mid` strictly satisfying `lower < mid` (and `mid < upper`
/// whenever `upper` is `Some`), suitable as an exclusive `start-after` split point for
/// disjoint `(lower, mid]` + `(mid, upper]` range shards.
pub fn utf8_midpoint_key(lower: &str, upper: Option<&str>) -> Option<String> {
    utf8_midpoint_key_with_anchor(lower, upper, 0)
}

/// Like [`utf8_midpoint_key`], but when `upper` is `None` starts scanning at least at
/// `min_anchor` (e.g. `LCP(first_key, lower).len()`) so flat buckets with long shared
/// non-slash prefixes (e.g. `tenant_prod_2026_shard_000001.parquet`) bisect inside the
/// varying suffix immediately without burning empty `ListObjectsV2` probes.
fn utf8_midpoint_key_with_anchor(
    lower: &str,
    upper: Option<&str>,
    min_anchor: usize,
) -> Option<String> {
    if let Some(u) = upper {
        if lower >= u {
            return None;
        }
        let lb = lower.as_bytes();
        let ub = u.as_bytes();
        let min_len = lb.len().min(ub.len());
        let mut diff = 0;
        while diff < min_len && lb[diff] == ub[diff] {
            diff += 1;
        }
        // Only split cleanly on ASCII / UTF-8 char boundaries where prefix is valid UTF-8.
        let mut prefix_end = diff;
        while prefix_end > 0 && !lower.is_char_boundary(prefix_end) {
            prefix_end -= 1;
        }
        let prefix = &lower[..prefix_end];

        if diff < min_len {
            let lo = lb[diff];
            let hi = ub[diff];
            if prefix_end == diff && hi > lo + 1 && hi <= 0x7E {
                let mid_b = lo + (hi - lo) / 2;
                if mid_b > lo && mid_b < hi && mid_b.is_ascii() {
                    let mut out = String::with_capacity(prefix.len() + 1);
                    out.push_str(prefix);
                    out.push(mid_b as char);
                    if out.as_str() > lower && out.as_str() < u {
                        return Some(out);
                    }
                }
            }
            // Adjacent first differing bytes (e.g. "a..." vs "b..."): bisect one byte deeper
            // inside `lower`'s next byte toward `'~'` (0x7E).
            if prefix_end == diff && lo < 0x7E && lower.is_char_boundary(diff + 1) {
                let next_lo = lb.get(diff + 1).copied().unwrap_or(0x20).clamp(0x20, 0x7D);
                let mid_next = next_lo + (0x7E - next_lo).div_ceil(2);
                if mid_next > next_lo && mid_next <= 0x7E {
                    let mut out = String::with_capacity(diff + 2);
                    out.push_str(&lower[..=diff]);
                    out.push(mid_next as char);
                    if out.as_str() > lower && out.as_str() < u {
                        return Some(out);
                    }
                }
            }
            return None;
        }

        // `lower` is a strict prefix of `u`: bisect the first extra byte of `u`.
        if lb.len() < ub.len() && lower.is_char_boundary(lb.len()) {
            let hi = ub[lb.len()];
            let lo = 0x20u8;
            if hi > lo + 1 && hi <= 0x7E {
                let mid_b = lo + (hi - lo) / 2;
                let mut out = String::with_capacity(lower.len() + 1);
                out.push_str(lower);
                out.push(mid_b as char);
                if out.as_str() > lower && out.as_str() < u {
                    return Some(out);
                }
            }
        }
        return None;
    }

    // Unbounded upper (`None`): scan forward from the filename/dir anchor (or `min_anchor`
    // derived from shared flat prefix) for the first ASCII byte `< 'z'` (then `< '~'`,
    // then next Unicode scalar) so `'z'`-prefixed, non-ASCII, and shared-prefix flat keys
    // all bisect cleanly in Gear 2 without empty probe storms.
    let slash_anchor = lower.rfind('/').map(|i| i + 1).unwrap_or(0);
    let mut anchor = slash_anchor.max(min_anchor.min(lower.len()));
    while anchor > 0 && !lower.is_char_boundary(anchor) {
        anchor -= 1;
    }
    for (pos, ch) in lower[anchor..].char_indices() {
        let abs = anchor + pos;
        if ch.is_ascii() {
            let b = ch as u8;
            if b < b'z' {
                let mid_b = b + (b'z' - b).div_ceil(2);
                if mid_b > b && mid_b <= 0x7E {
                    let mut out = String::with_capacity(abs + 1);
                    out.push_str(&lower[..abs]);
                    out.push(mid_b as char);
                    if out.as_str() > lower {
                        return Some(out);
                    }
                }
            }
        }
    }
    for (pos, ch) in lower.char_indices() {
        if ch.is_ascii() {
            let b = ch as u8;
            if b < 0x7E {
                let mid_b = b + (0x7E - b).div_ceil(2);
                if mid_b > b && mid_b <= 0x7E {
                    let mut out = String::with_capacity(pos + 1);
                    out.push_str(&lower[..pos]);
                    out.push(mid_b as char);
                    if out.as_str() > lower {
                        return Some(out);
                    }
                }
            }
        }
    }
    if let Some(ch) = lower[anchor..].chars().next() {
        for step in [64u32, 16, 1] {
            if let Some(next_ch) = char::from_u32((ch as u32).saturating_add(step)) {
                let mut out = String::with_capacity(anchor + next_ch.len_utf8());
                out.push_str(&lower[..anchor]);
                out.push(next_ch);
                if out.as_str() > lower {
                    return Some(out);
                }
            }
        }
    }
    None
}

/// Compute up to `max_seeds` ascending LCP-anchored seed split keys strictly `> last_key`.
fn lcp_seed_splits(first_key: &str, last_key: &str, max_seeds: usize) -> Vec<String> {
    if max_seeds == 0 {
        return Vec::new();
    }
    let lcp = longest_common_prefix(first_key, last_key);
    let mut seeds = Vec::with_capacity(max_seeds);

    if last_key.is_char_boundary(lcp.len()) {
        for (rel_pos, ch) in last_key[lcp.len()..].char_indices() {
            if !ch.is_ascii() {
                continue;
            }
            let b = ch as u8;
            if b >= b'z' {
                continue;
            }
            let abs = lcp.len() + rel_pos;
            let span = (b'z' - b) as usize;
            if span >= 2 {
                let count = max_seeds.min(span - 1);
                let mut prev = last_key.to_string();
                for step in 1..=count {
                    let byte = b + ((span * step) / (count + 1)) as u8;
                    if byte > b && byte <= b'z' {
                        let mut candidate = String::with_capacity(abs + 1);
                        candidate.push_str(&last_key[..abs]);
                        candidate.push(byte as char);
                        if candidate > prev {
                            prev = candidate.clone();
                            seeds.push(candidate);
                        }
                    }
                }
                if !seeds.is_empty() {
                    break;
                }
            }
        }
    }
    if seeds.is_empty()
        && let Some(mid) = utf8_midpoint_key(last_key, None)
    {
        seeds.push(mid);
    }
    seeds
}

/// Check if an entry belongs to a pruned directory subtree; if so, return the exact
/// **raw wire-byte** directory prefix (`"<raw_dir>/"`) so `start_after` fast-forwards
/// strictly over the pruned subtree without ever leaping past unrelated keys on NFD paths.
fn find_pruned_dir_prefix(entry: &Entry, pruner: &DirPruner) -> Option<String> {
    let raw = entry.raw_path();
    let wire = entry_wire_key(entry);
    let raw_bytes = raw.as_bytes();
    let seg_count = entry.nfc_path.segments().count();
    let mut nfc_acc = RelPath::root();
    let mut raw_byte_pos = 0usize;

    for (idx, seg) in entry.nfc_path.segments().enumerate() {
        while raw_byte_pos < raw_bytes.len() && raw_bytes[raw_byte_pos] == b'/' {
            raw_byte_pos += 1;
        }
        let next_slash = raw_bytes[raw_byte_pos..]
            .iter()
            .position(|&b| b == b'/')
            .map(|p| raw_byte_pos + p);
        let is_last = idx + 1 == seg_count;
        let is_dir_level = !is_last || entry.kind == EntryKind::Directory;
        if !is_dir_level {
            break;
        }
        nfc_acc = nfc_acc.join(seg).ok()?;
        if pruner(&nfc_acc) {
            let prefix = if let Some(slash_idx) = next_slash {
                raw[..=slash_idx].to_string()
            } else {
                format!("{raw}/")
            };
            return wire.starts_with(&prefix).then_some(prefix);
        }
        match next_slash {
            Some(slash_idx) => raw_byte_pos = slash_idx + 1,
            None => break,
        }
    }
    None
}

struct ShardBounds {
    upper_inclusive: Option<String>,
    last_key: String,
    truncated: bool,
    pages_fetched: usize,
    done: bool,
}

struct ShardHandle {
    bounds: Arc<Mutex<ShardBounds>>,
    rx: mpsc::Receiver<Result<Vec<Entry>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for ShardHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Two-Gear adaptive parallel ordered range stream for a single backend (`S3`, `GCS`, `Azure`).
///
/// Always starts in **Gear 1** (1 single `list_ordered_page` RPC). Only if Page 1 is truncated
/// and the backend supports `start_after` does it engage **Gear 2** (LCP-anchored 3-way seed
/// + dynamic midpoint work-stealing bisection up to `max_concurrency`).
pub struct OrderedRangeStream {
    backend: Arc<dyn StorageBackend>,
    prefix: RelPath,
    max_concurrency: usize,
    dir_pruner: Option<DirPruner>,
    cancel: CancelFlag,
    supports_start_after: bool,
    /// True when Gear 1 Page 1 was NOT truncated (entire side fits in 1 page).
    single_page_complete: bool,
    shards: VecDeque<ShardHandle>,
    current_page: VecDeque<Entry>,
    eof: bool,
    /// Fallback client-side key skip when `initial_start_after` was supplied to a backend
    /// without native `start_after` support (e.g. Azure Blob).
    skip_lte: Option<String>,
    /// First observed wire key from Gear 1 Page 1, used to skip constant non-slash prefixes
    /// during unbounded Gear 2 bisection (`utf8_midpoint_key_with_anchor`).
    first_wire_key: String,
}

impl OrderedRangeStream {
    /// Start an ordered range stream, immediately issuing Gear 1 Page 1 so callers can inspect
    /// `single_page_complete()` before streaming starts.
    pub async fn start(
        backend: Arc<dyn StorageBackend>,
        prefix: RelPath,
        initial_start_after: Option<String>,
        max_concurrency: usize,
        dir_pruner: Option<DirPruner>,
        cancel: CancelFlag,
    ) -> Result<Self> {
        let mut fallback_skip_lte: Option<String> = None;
        let page1 = match backend
            .list_ordered_page(
                &prefix,
                initial_start_after.as_deref(),
                None,
                ORDERED_PAGE_MAX_KEYS,
            )
            .await
        {
            Ok(p) => p,
            Err(e)
                if initial_start_after.is_some()
                    && e.kind == crate::error::ErrorKind::Unsupported =>
            {
                // Backend (e.g. Azure Blob) does not support arbitrary `start_after`:
                // fall back gracefully to full ordered scan and skip keys `<= cursor`.
                fallback_skip_lte = initial_start_after.clone();
                backend
                    .list_ordered_page(&prefix, None, None, ORDERED_PAGE_MAX_KEYS)
                    .await?
            }
            Err(e) => return Err(e),
        };

        let supports_start_after = page1.supports_start_after;
        let single_page_complete = !page1.is_truncated;

        let mut filtered_p1 = VecDeque::with_capacity(page1.entries.len());
        let mut first_key: Option<String> = None;
        let mut last_pruned_jump: Option<String> = None;

        for e in page1.entries {
            let wk = entry_wire_key(&e);
            if let Some(ref sa) = fallback_skip_lte
                && wk.as_str() <= sa.as_str()
            {
                continue;
            }
            if first_key.is_none() {
                first_key = Some(wk.clone());
            }
            if let Some(ref p) = dir_pruner
                && let Some(pruned_pfx) = find_pruned_dir_prefix(&e, p)
            {
                let jump = format!("{pruned_pfx}{DIR_JUMP_SENTINEL}");
                if wk < jump {
                    last_pruned_jump = Some(jump);
                }
                continue;
            }
            last_pruned_jump = None;
            filtered_p1.push_back(e);
        }

        let first_wire_key = first_key
            .clone()
            .or_else(|| page1.last_wire_key.clone())
            .unwrap_or_default();

        let mut stream = Self {
            backend,
            prefix,
            max_concurrency: max_concurrency.max(1),
            dir_pruner,
            cancel,
            supports_start_after,
            single_page_complete,
            shards: VecDeque::new(),
            current_page: filtered_p1,
            eof: single_page_complete,
            skip_lte: fallback_skip_lte,
            first_wire_key,
        };

        if !single_page_complete {
            let last_key = page1.last_wire_key.unwrap_or_default();
            let first = first_key.as_deref().unwrap_or(last_key.as_str());

            // Check if Gear 1 ended inside an excluded directory subtree -> fast-forward!
            let effective_cursor_key = match last_pruned_jump {
                Some(ref j) if supports_start_after && j.as_str() > last_key.as_str() => j.clone(),
                _ => last_key.clone(),
            };
            let jumped = effective_cursor_key != last_key;

            if supports_start_after
                && stream.max_concurrency > 1
                && !effective_cursor_key.is_empty()
            {
                // Gear 2: LCP-anchored seed split (at most 3 extra probe shards, not 16!).
                let max_seeds = (stream.max_concurrency - 1).min(3);
                let seeds = lcp_seed_splits(first, &effective_cursor_key, max_seeds);
                if seeds.is_empty() {
                    let cont = (!jumped).then_some(page1.next_cursor).flatten();
                    stream.push_shard(effective_cursor_key, cont, None);
                } else {
                    let cont0 = (!jumped).then_some(page1.next_cursor).flatten();
                    stream.push_shard(effective_cursor_key, cont0, Some(seeds[0].clone()));
                    for i in 0..seeds.len() {
                        let lower = seeds[i].clone();
                        let upper = seeds.get(i + 1).cloned();
                        stream.push_shard(lower, None, upper);
                    }
                }
            } else {
                let cont = (!jumped).then_some(page1.next_cursor).flatten();
                stream.push_shard(effective_cursor_key, cont, None);
            }
        }

        Ok(stream)
    }

    pub fn single_page_complete(&self) -> bool {
        self.single_page_complete
    }

    /// True if Gear 1 Page 1 reached EOF immediately AND contains zero `EntryKind::File` entries.
    pub fn known_zero_files(&self) -> bool {
        self.eof
            && self.shards.is_empty()
            && !self.current_page.iter().any(|e| e.kind == EntryKind::File)
    }

    pub fn supports_start_after(&self) -> bool {
        self.supports_start_after
    }

    fn failed_eof(backend: Arc<dyn StorageBackend>, prefix: RelPath, cancel: CancelFlag) -> Self {
        Self {
            backend,
            prefix,
            max_concurrency: 1,
            dir_pruner: None,
            cancel,
            supports_start_after: false,
            single_page_complete: true,
            shards: VecDeque::new(),
            current_page: VecDeque::new(),
            eof: true,
            skip_lte: None,
            first_wire_key: String::new(),
        }
    }

    fn push_shard(
        &mut self,
        lower_exclusive: String,
        initial_continuation: Option<String>,
        upper_inclusive: Option<String>,
    ) {
        let handle = spawn_shard_worker(
            self.backend.clone(),
            self.prefix.clone(),
            lower_exclusive,
            initial_continuation,
            upper_inclusive,
            self.dir_pruner.clone(),
            self.supports_start_after,
            self.cancel.clone(),
        );
        self.shards.push_back(handle);
    }

    /// Dynamic midpoint work-stealing bisection: when active shards < `max_concurrency`,
    /// bisect the first active truncated shard that has already fetched >= 1 page.
    fn maybe_bisect_shards(&mut self) {
        if !self.supports_start_after || self.max_concurrency <= 1 {
            return;
        }
        while self.shards.len() < self.max_concurrency {
            let mut split_plan: Option<(usize, String, Option<String>)> = None;
            for (idx, shard) in self.shards.iter().enumerate() {
                let Ok(mut b) = shard.bounds.lock() else {
                    continue;
                };
                if b.done || !b.truncated || b.pages_fetched == 0 || b.last_key.is_empty() {
                    continue;
                }
                let min_anchor = if b.upper_inclusive.is_none() && !self.first_wire_key.is_empty() {
                    longest_common_prefix(&self.first_wire_key, &b.last_key)
                        .len()
                        .saturating_sub(2)
                } else {
                    0
                };
                if let Some(mid) = utf8_midpoint_key_with_anchor(
                    &b.last_key,
                    b.upper_inclusive.as_deref(),
                    min_anchor,
                ) {
                    let old_upper = b.upper_inclusive.replace(mid.clone());
                    split_plan = Some((idx, mid, old_upper));
                    break;
                }
            }
            let Some((idx, mid, old_upper)) = split_plan else {
                break;
            };
            let new_shard = spawn_shard_worker(
                self.backend.clone(),
                self.prefix.clone(),
                mid,
                None,
                old_upper,
                self.dir_pruner.clone(),
                self.supports_start_after,
                self.cancel.clone(),
            );
            self.shards.insert(idx + 1, new_shard);
        }
    }

    /// Pull the next entry in strictly ascending UTF-8 wire order.
    pub async fn next_entry(&mut self) -> Option<Result<Entry>> {
        loop {
            if let Some(e) = self.current_page.pop_front() {
                if let Some(ref sa) = self.skip_lte {
                    if entry_wire_key(&e).as_str() <= sa.as_str() {
                        continue;
                    }
                    self.skip_lte = None;
                }
                return Some(Ok(e));
            }
            if self.eof {
                return None;
            }
            if self.cancel.is_cancelled() {
                self.eof = true;
                return None;
            }

            self.maybe_bisect_shards();

            let Some(front) = self.shards.front_mut() else {
                self.eof = true;
                return None;
            };

            match front.rx.recv().await {
                Some(Ok(entries)) => {
                    if !entries.is_empty() {
                        self.current_page.extend(entries);
                    }
                    self.maybe_bisect_shards();
                }
                Some(Err(e)) => {
                    self.shards.pop_front();
                    return Some(Err(e));
                }
                None => {
                    // Front shard finished cleanly; move to the next ordered shard and try
                    // work-stealing bisection onto any remaining busy shard.
                    self.shards.pop_front();
                    self.maybe_bisect_shards();
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_shard_worker(
    backend: Arc<dyn StorageBackend>,
    prefix: RelPath,
    lower_exclusive: String,
    initial_continuation: Option<String>,
    upper_inclusive: Option<String>,
    dir_pruner: Option<DirPruner>,
    supports_start_after: bool,
    cancel: CancelFlag,
) -> ShardHandle {
    let bounds = Arc::new(Mutex::new(ShardBounds {
        upper_inclusive,
        last_key: lower_exclusive.clone(),
        truncated: true,
        pages_fetched: 0,
        done: false,
    }));
    let bounds_task = bounds.clone();
    let (tx, rx) = mpsc::channel::<Result<Vec<Entry>>>(SHARD_CHANNEL_CAP);

    let task = tokio::spawn(async move {
        let mut next_start_after: Option<String> = if initial_continuation.is_none() {
            (!lower_exclusive.is_empty()).then_some(lower_exclusive)
        } else {
            None
        };
        let mut continuation: Option<String> = initial_continuation;

        loop {
            if cancel.is_cancelled() || tx.is_closed() {
                if let Ok(mut b) = bounds_task.lock() {
                    b.done = true;
                }
                return;
            }

            let page: OrderedListPage = match backend
                .list_ordered_page(
                    &prefix,
                    next_start_after.as_deref(),
                    continuation.as_deref(),
                    ORDERED_PAGE_MAX_KEYS,
                )
                .await
            {
                Ok(p) => p,
                Err(e) => {
                    if let Ok(mut b) = bounds_task.lock() {
                        b.done = true;
                    }
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            };

            let mut kept = Vec::with_capacity(page.entries.len());
            let mut hit_upper = false;
            let mut last_kept_wire = String::new();
            let mut last_pruned_jump: Option<String> = None;

            // Atomically check `upper_inclusive` and advance `last_key` under lock so a
            // concurrent bisection can NEVER create an overlap or gap.
            let should_finish = {
                let mut b = bounds_task.lock().expect("ShardBounds mutex poisoned");
                let cur_upper = b.upper_inclusive.clone();
                for e in page.entries {
                    let wk = entry_wire_key(&e);
                    if let Some(ref u) = cur_upper
                        && wk.as_str() > u.as_str()
                    {
                        hit_upper = true;
                        break;
                    }
                    last_kept_wire = wk;
                    if let Some(ref p) = dir_pruner
                        && let Some(pruned_pfx) = find_pruned_dir_prefix(&e, p)
                    {
                        let jump = format!("{pruned_pfx}{DIR_JUMP_SENTINEL}");
                        if last_kept_wire < jump {
                            last_pruned_jump = Some(jump);
                        }
                        continue;
                    }
                    last_pruned_jump = None;
                    kept.push(e);
                }
                if let (Some(lw), Some(u)) = (&page.last_wire_key, &cur_upper)
                    && lw.as_str() >= u.as_str()
                {
                    hit_upper = true;
                }
                if !last_kept_wire.is_empty() {
                    b.last_key = last_kept_wire.clone();
                } else if let Some(ref lw) = page.last_wire_key {
                    b.last_key = match cur_upper.as_deref() {
                        Some(u) if lw.as_str() > u => u.to_string(),
                        _ => lw.clone(),
                    };
                }
                b.pages_fetched += 1;
                b.truncated = page.is_truncated && !hit_upper;
                if !b.truncated {
                    b.done = true;
                    true
                } else {
                    false
                }
            };

            if !kept.is_empty() && tx.send(Ok(kept)).await.is_err() {
                if let Ok(mut b) = bounds_task.lock() {
                    b.done = true;
                }
                return;
            }
            if should_finish {
                return;
            }

            // If the page ended inside an excluded subtree and backend supports `start_after`,
            // fast-forward directly past the excluded subtree in 1 RPC.
            if supports_start_after
                && let Some(jump) = last_pruned_jump
                && jump > last_kept_wire
            {
                let cur_upper = bounds_task
                    .lock()
                    .ok()
                    .and_then(|b| b.upper_inclusive.clone());
                if cur_upper.as_deref().is_none_or(|u| jump.as_str() < u) {
                    next_start_after = Some(jump);
                    continuation = None;
                    continue;
                }
            }

            next_start_after = None;
            continuation = page.next_cursor;
            if continuation.is_none() {
                if let Ok(mut b) = bounds_task.lock() {
                    b.done = true;
                }
                return;
            }
        }
    });

    ShardHandle { bounds, rx, task }
}

/// One merged item yielded by [`StreamingMergeDiffSource`].
#[derive(Debug)]
pub enum DiffItem {
    SrcOnly(Entry),
    Both { src: Entry, dst: Entry },
    DstOnly(Entry),
    Conflict(SyncConflict),
}

/// Buffered single-side reader wrapping [`OrderedRangeStream`] with:
/// - Uniform `cmp_slash_key` buffering so `File("app")` and `Directory("app/")` always
///   occupy the exact same merge slot even when `"app-*"` / `"app.*"` siblings exist (P0-3).
/// - Bounded NFD deferral & duplicate detection (`O(1)` RAM on 99.999% ASCII/NFC buckets).
/// - Lossless late reconciliation for rare Unicode singleton/compatibility contractions
///   (`raw > nfc`, e.g., Kelvin `U+212A` -> `'K'`, Angstrom `U+212B` -> `'Å'`) (P1-1).
struct CanonicalSideReader {
    stream: OrderedRangeStream,
    raw_peek: Option<Entry>,
    deferred: BTreeMap<SlashMergeKey, Entry>,
    late_contractions: VecDeque<Entry>,
    nfd_seen: HashSet<RelPath>,
    last_emitted: Option<SlashMergeKey>,
    complete: bool,
    errors: Vec<TransferErrorInfo>,
    backend_name: String,
    conflicts: VecDeque<SyncConflict>,
}

impl CanonicalSideReader {
    fn new(stream: OrderedRangeStream, backend_name: String) -> Self {
        Self {
            stream,
            raw_peek: None,
            deferred: BTreeMap::new(),
            late_contractions: VecDeque::new(),
            nfd_seen: HashSet::new(),
            last_emitted: None,
            complete: true,
            errors: Vec::new(),
            backend_name,
            conflicts: VecDeque::new(),
        }
    }

    /// Minimum raw wire key currently buffered (un-emitted) on this side, used as an
    /// exclusive ceiling for [`SafeWatermarkTracker`] so NFD-deferred or `File`-deferred
    /// keys are NEVER skipped on `StartAfter` resume.
    fn min_buffered_wire_key(&self) -> Option<String> {
        let mut min_wk: Option<String> = None;
        for e in self
            .deferred
            .values()
            .chain(self.raw_peek.iter())
            .chain(self.late_contractions.iter())
        {
            let wk = entry_wire_key(e);
            if min_wk.as_deref().is_none_or(|cur| wk.as_str() < cur) {
                min_wk = Some(wk);
            }
        }
        min_wk
    }

    /// Advance until either `self.stream` reaches EOF or `self.raw_peek`'s wire key is
    /// strictly greater than `self.deferred`'s smallest key (`"{nfc}/"`), guaranteeing no
    /// future raw entry (other than rare `raw > nfc` contractions) can sort before the front.
    async fn advance_until_front_ready(&mut self) {
        loop {
            if let Some(front_key) = self.deferred.keys().next()
                && let Some(ref peek) = self.raw_peek
                && cmp_merge_key(
                    peek.raw_path(),
                    peek.kind == EntryKind::Directory,
                    &front_key.0,
                    true,
                ) == Ordering::Greater
            {
                return;
            }

            if self.raw_peek.is_none() {
                match self.stream.next_entry().await {
                    Some(Ok(next_e)) => self.raw_peek = Some(next_e),
                    Some(Err(err)) => {
                        self.complete = false;
                        if self.errors.len() < super::MAX_REPORT_ERRORS {
                            self.errors.push(TransferErrorInfo::from_error_with_message(
                                None,
                                &err,
                                format!("ordered list `{}` error: {err}", self.backend_name),
                            ));
                        }
                        return;
                    }
                    None => return,
                }
                if let Some(front_key) = self.deferred.keys().next()
                    && let Some(ref peek) = self.raw_peek
                    && cmp_merge_key(
                        peek.raw_path(),
                        peek.kind == EntryKind::Directory,
                        &front_key.0,
                        true,
                    ) == Ordering::Greater
                {
                    return;
                }
            }

            let e = self.raw_peek.take().expect("raw_peek populated above");

            let is_nfd = e.has_distinct_raw_path();
            let cur_key = SlashMergeKey(e.nfc_path.as_str().to_string());

            // 1. Bounded NFD duplicate tracking (check `contains` before `insert`).
            if is_nfd {
                if self.nfd_seen.contains(&e.nfc_path) {
                    self.deferred.remove(&cur_key);
                    self.conflicts.push_back(SyncConflict {
                        nfc_path: e.nfc_path.clone(),
                        kind: ConflictKind::UnicodeNfcCollision,
                        detail: format!(
                            "multiple NFD/NFC keys map to `{}` on `{}`",
                            e.nfc_path, self.backend_name
                        ),
                    });
                    continue;
                }
                if self.nfd_seen.len() < MAX_NFD_TRACKED {
                    self.nfd_seen.insert(e.nfc_path.clone());
                }
            } else if self.nfd_seen.contains(&e.nfc_path) {
                self.deferred.remove(&cur_key);
                self.conflicts.push_back(SyncConflict {
                    nfc_path: e.nfc_path.clone(),
                    kind: ConflictKind::UnicodeNfcCollision,
                    detail: format!(
                        "both NFD and NFC forms of `{}` exist on `{}`",
                        e.nfc_path, self.backend_name
                    ),
                });
                continue;
            }

            // 2. Rare Unicode singleton/compatibility contractions (`raw > nfc/`, e.g.
            //    Kelvin `U+212A` -> `'K'`, CJK compat ideographs): reconcile at EOF via
            //    targeted `stat` instead of falsely dropping as a collision.
            let wire_vs_slash = cmp_merge_key(
                e.raw_path(),
                e.kind == EntryKind::Directory,
                &cur_key.0,
                true,
            );
            if is_nfd
                && wire_vs_slash == Ordering::Greater
                && self
                    .last_emitted
                    .as_ref()
                    .is_some_and(|prev| cur_key <= *prev)
            {
                if self.late_contractions.len() < MAX_NFD_TRACKED {
                    self.late_contractions.push_back(e);
                } else {
                    self.conflicts.push_back(SyncConflict {
                        nfc_path: e.nfc_path,
                        kind: ConflictKind::UnicodeNfcCollision,
                        detail: format!(
                            "exceeded late Unicode contraction buffer on `{}`",
                            self.backend_name
                        ),
                    });
                }
                continue;
            }

            // 3. Guard against already-emitted duplicate or non-monotonic wire anomaly.
            if let Some(ref prev) = self.last_emitted
                && cur_key <= *prev
            {
                self.conflicts.push_back(SyncConflict {
                    nfc_path: e.nfc_path,
                    kind: ConflictKind::UnicodeNfcCollision,
                    detail: format!(
                        "out-of-order or duplicate key relative to `{}` on `{}`",
                        prev.0, self.backend_name
                    ),
                });
                continue;
            }

            // 4. Same-side collision in `deferred` (catches `File("app")` + `Directory("app/")`
            //    even with `"app-v2"` / `"app.conf"` siblings in between!).
            if let Some(existing) = self.deferred.get(&cur_key) {
                let kind = if existing.kind != e.kind {
                    if existing.kind == EntryKind::Directory {
                        ConflictKind::TypeFlipFileOverDir
                    } else {
                        ConflictKind::TypeFlipDirOverFile
                    }
                } else {
                    ConflictKind::UnicodeNfcCollision
                };
                self.deferred.remove(&cur_key);
                self.conflicts.push_back(SyncConflict {
                    nfc_path: e.nfc_path.clone(),
                    kind,
                    detail: format!(
                        "same-side conflicting entries share canonical path `{}` on `{}`",
                        e.nfc_path, self.backend_name
                    ),
                });
                continue;
            }

            // 5. Buffer `e` at its canonical slash-terminated merge slot (cap NFD backlog).
            if !is_nfd || self.deferred.len() < MAX_NFD_TRACKED {
                self.deferred.insert(cur_key, e);
            } else {
                self.conflicts.push_back(SyncConflict {
                    nfc_path: e.nfc_path,
                    kind: ConflictKind::UnicodeNfcCollision,
                    detail: format!(
                        "exceeded deferred NFD buffer capacity ({MAX_NFD_TRACKED}) on `{}`",
                        self.backend_name
                    ),
                });
            }
        }
    }

    async fn peek_next(&mut self) -> Option<&Entry> {
        self.advance_until_front_ready().await;
        self.deferred.values().next()
    }

    async fn pop_next(&mut self) -> Option<Entry> {
        self.advance_until_front_ready().await;
        let (key, entry) = self.deferred.pop_first()?;
        self.last_emitted = Some(key);
        Some(entry)
    }
}

fn strip_entry_prefix(mut entry: Entry, prefix: &RelPath) -> Option<Entry> {
    if prefix.is_root() {
        return Some(entry);
    }
    let rel_nfc = super::strip_rel_prefix(&entry.nfc_path, prefix)?;
    let old_raw = entry.raw_path.take();
    entry.nfc_path = rel_nfc;
    if let Some(raw) = old_raw {
        let pfx = prefix.as_str();
        if let Some(rest) = raw.strip_prefix(pfx).and_then(|r| r.strip_prefix('/')) {
            entry.set_raw_path(rest);
        }
    }
    Some(entry)
}

/// Zero-disk `O(1)`-RAM two-pointer streaming merge-join across two ordered object stores
/// (`S3`, `GCS`, `Azure`).
pub struct StreamingMergeDiffSource {
    src: CanonicalSideReader,
    dst: CanonicalSideReader,
    late_resolved: bool,
    late_items: VecDeque<DiffItem>,
}

impl StreamingMergeDiffSource {
    /// Start concurrent Gear 1 Page 1 fetches on both `src` and `dst`.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        src_backend: Arc<dyn StorageBackend>,
        src_prefix: RelPath,
        dst_backend: Arc<dyn StorageBackend>,
        dst_prefix: RelPath,
        initial_start_after: Option<String>,
        src_pruner: Option<DirPruner>,
        dst_pruner: Option<DirPruner>,
        cancel: CancelFlag,
    ) -> Result<Self> {
        let src_conc = src_backend.ordered_list_concurrency();
        let dst_conc = dst_backend.ordered_list_concurrency();
        let src_name = src_backend.name().to_string();
        let dst_name = dst_backend.name().to_string();

        let (src_res, dst_res) = tokio::join!(
            OrderedRangeStream::start(
                src_backend.clone(),
                src_prefix.clone(),
                initial_start_after.clone(),
                src_conc,
                src_pruner,
                cancel.clone(),
            ),
            OrderedRangeStream::start(
                dst_backend.clone(),
                dst_prefix.clone(),
                initial_start_after,
                dst_conc,
                dst_pruner,
                cancel.clone(),
            ),
        );

        let src = match src_res {
            Ok(s) => CanonicalSideReader::new(s, src_name),
            Err(err) => {
                let mut r = CanonicalSideReader::new(
                    OrderedRangeStream::failed_eof(src_backend, src_prefix, cancel.clone()),
                    src_name.clone(),
                );
                r.complete = false;
                r.errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &err,
                    format!("list `{src_name}` failed: {err}"),
                ));
                r
            }
        };
        let dst = match dst_res {
            Ok(s) => CanonicalSideReader::new(s, dst_name),
            Err(err) => {
                let mut r = CanonicalSideReader::new(
                    OrderedRangeStream::failed_eof(dst_backend, dst_prefix, cancel),
                    dst_name.clone(),
                );
                r.complete = false;
                r.errors.push(TransferErrorInfo::from_error_with_message(
                    None,
                    &err,
                    format!("list `{dst_name}` failed: {err}"),
                ));
                r
            }
        };

        Ok(Self {
            src,
            dst,
            late_resolved: false,
            late_items: VecDeque::new(),
        })
    }

    /// True if BOTH sides fit completely in Gear 1 Page 1 (`<= 1,000` objects each),
    /// meaning exact totals are known immediately.
    pub fn totals_known_immediately(&self) -> bool {
        self.src.stream.single_page_complete() && self.dst.stream.single_page_complete()
    }

    /// True if BOTH sides support arbitrary `start_after` keys (enabling `O(1)` crash resume).
    pub fn supports_resume_cursor(&self) -> bool {
        self.src.stream.supports_start_after() && self.dst.stream.supports_start_after()
    }

    /// Minimum raw wire key still buffered (not yet yielded) on the source side.
    pub fn min_buffered_src_wire_key(&self) -> Option<String> {
        self.src.min_buffered_wire_key()
    }

    pub fn src_complete(&self) -> bool {
        self.src.complete
    }

    pub fn dst_complete(&self) -> bool {
        self.dst.complete
    }

    /// True when the source stream has finished completely and has zero buffered/pending `File` entries.
    pub fn src_known_zero_files(&self) -> bool {
        self.src.stream.known_zero_files()
            && !self
                .src
                .deferred
                .values()
                .any(|e| e.kind == EntryKind::File)
            && !self
                .src
                .raw_peek
                .as_ref()
                .is_some_and(|e| e.kind == EntryKind::File)
            && !self
                .src
                .late_contractions
                .iter()
                .any(|e| e.kind == EntryKind::File)
    }

    /// True when the destination stream has finished completely and has zero buffered/pending `File` entries.
    pub fn dst_known_zero_files(&self) -> bool {
        self.dst.stream.known_zero_files()
            && !self
                .dst
                .deferred
                .values()
                .any(|e| e.kind == EntryKind::File)
            && !self
                .dst
                .raw_peek
                .as_ref()
                .is_some_and(|e| e.kind == EntryKind::File)
            && !self
                .dst
                .late_contractions
                .iter()
                .any(|e| e.kind == EntryKind::File)
    }

    pub fn drain_errors(&mut self) -> Vec<TransferErrorInfo> {
        let mut out = std::mem::take(&mut self.src.errors);
        out.extend(std::mem::take(&mut self.dst.errors));
        out
    }

    async fn resolve_late_contractions(&mut self) {
        if self.late_resolved {
            return;
        }
        self.late_resolved = true;
        if self.src.late_contractions.is_empty() && self.dst.late_contractions.is_empty() {
            return;
        }

        let mut dst_map: HashMap<RelPath, Entry> = HashMap::new();
        while let Some(d) = self.dst.late_contractions.pop_front() {
            if dst_map.insert(d.nfc_path.clone(), d.clone()).is_some() {
                dst_map.remove(&d.nfc_path);
                self.late_items.push_back(DiffItem::Conflict(SyncConflict {
                    nfc_path: d.nfc_path,
                    kind: ConflictKind::UnicodeNfcCollision,
                    detail: format!(
                        "duplicate Unicode contraction key on `{}`",
                        self.dst.backend_name
                    ),
                }));
            }
        }

        let mut seen_src: HashSet<RelPath> = HashSet::new();
        while let Some(s) = self.src.late_contractions.pop_front() {
            if !seen_src.insert(s.nfc_path.clone()) {
                self.late_items.push_back(DiffItem::Conflict(SyncConflict {
                    nfc_path: s.nfc_path,
                    kind: ConflictKind::UnicodeNfcCollision,
                    detail: format!(
                        "duplicate Unicode contraction key on `{}`",
                        self.src.backend_name
                    ),
                }));
                continue;
            }
            if let Some(d) = dst_map.remove(&s.nfc_path) {
                self.late_items.push_back(DiffItem::Both { src: s, dst: d });
                continue;
            }
            let Ok(dst_full) = super::join_prefix(&self.dst.stream.prefix, &s.nfc_path) else {
                self.late_items.push_back(DiffItem::SrcOnly(s));
                continue;
            };
            match self
                .dst
                .stream
                .backend
                .stat(&BackendPath::from_rel(dst_full))
                .await
            {
                Ok(Some(d)) => {
                    if let Some(d_rel) = strip_entry_prefix(d, &self.dst.stream.prefix) {
                        self.late_items
                            .push_back(DiffItem::Both { src: s, dst: d_rel });
                    } else {
                        self.late_items.push_back(DiffItem::SrcOnly(s));
                    }
                }
                Ok(None) => self.late_items.push_back(DiffItem::SrcOnly(s)),
                Err(err) => {
                    self.dst.complete = false;
                    if self.dst.errors.len() < super::MAX_REPORT_ERRORS {
                        self.dst
                            .errors
                            .push(TransferErrorInfo::from_error_with_message(
                                Some(s.nfc_path.as_str().to_string()),
                                &err,
                                format!("stat `{}` failed: {err}", self.dst.backend_name),
                            ));
                    }
                }
            }
        }

        for (_, d) in dst_map {
            let Ok(src_full) = super::join_prefix(&self.src.stream.prefix, &d.nfc_path) else {
                self.late_items.push_back(DiffItem::DstOnly(d));
                continue;
            };
            match self
                .src
                .stream
                .backend
                .stat(&BackendPath::from_rel(src_full))
                .await
            {
                Ok(Some(s)) => {
                    if let Some(s_rel) = strip_entry_prefix(s, &self.src.stream.prefix) {
                        self.late_items
                            .push_back(DiffItem::Both { src: s_rel, dst: d });
                    } else {
                        self.late_items.push_back(DiffItem::DstOnly(d));
                    }
                }
                Ok(None) => self.late_items.push_back(DiffItem::DstOnly(d)),
                Err(err) => {
                    self.src.complete = false;
                    if self.src.errors.len() < super::MAX_REPORT_ERRORS {
                        self.src
                            .errors
                            .push(TransferErrorInfo::from_error_with_message(
                                Some(d.nfc_path.as_str().to_string()),
                                &err,
                                format!("stat `{}` failed: {err}", self.src.backend_name),
                            ));
                    }
                }
            }
        }
    }

    /// Pull the next merged [`DiffItem`] (`SrcOnly | Both | DstOnly | Conflict`).
    pub async fn next_item(&mut self) -> Option<DiffItem> {
        if let Some(c) = self.src.conflicts.pop_front() {
            return Some(DiffItem::Conflict(c));
        }
        if let Some(c) = self.dst.conflicts.pop_front() {
            return Some(DiffItem::Conflict(c));
        }

        let s_nfc = self
            .src
            .peek_next()
            .await
            .map(|e| e.nfc_path.as_str().to_string());
        if let Some(c) = self.src.conflicts.pop_front() {
            return Some(DiffItem::Conflict(c));
        }

        let d_nfc = self
            .dst
            .peek_next()
            .await
            .map(|e| e.nfc_path.as_str().to_string());
        if let Some(c) = self.dst.conflicts.pop_front() {
            return Some(DiffItem::Conflict(c));
        }

        match (s_nfc, d_nfc) {
            (Some(sn), Some(dn)) => match cmp_slash_key(&sn, &dn) {
                Ordering::Less => self.src.pop_next().await.map(DiffItem::SrcOnly),
                Ordering::Greater => self.dst.pop_next().await.map(DiffItem::DstOnly),
                Ordering::Equal => {
                    let s = self.src.pop_next().await?;
                    let d = self.dst.pop_next().await?;
                    Some(DiffItem::Both { src: s, dst: d })
                }
            },
            (Some(_), None) => self.src.pop_next().await.map(DiffItem::SrcOnly),
            (None, Some(_)) => self.dst.pop_next().await.map(DiffItem::DstOnly),
            (None, None) => {
                self.resolve_late_contractions().await;
                self.late_items.pop_front()
            }
        }
    }
}

#[cfg(test)]
mod tests;
