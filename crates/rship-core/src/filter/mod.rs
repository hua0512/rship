use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;

/// Canonical SHA-256 fingerprint of an empty [`FilterOptions`] / [`FilterSet::default()`].
pub const EMPTY_FILTER_FINGERPRINT: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::types::{Entry, EntryKind};

/// One ordered rule in a `--filter-from` / `--exclude-from` rule list.
/// Evaluated top-to-bottom (first match wins, matching rsync/rclone semantics).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    pub include: bool,
    pub pattern: String,
}

/// Complete serializable filter specification (persisted into `jobs.options_json`
/// so `rship resume <job_id>` reproduces identical filtering behavior).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterOptions {
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub excludes: Vec<String>,
    #[serde(default)]
    pub rules: Vec<FilterRule>,
    /// Explicit path allowlist (`--files-from`). Skipped from `jobs.options_json` so
    /// 500k-line manifests never write multi-MiB JSON blobs into `journal.db`; `files_from_path`
    /// records the manifest path for `rship resume`.
    #[serde(skip)]
    pub files_from: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_from_path: Option<String>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub max_size: Option<u64>,
    #[serde(default)]
    pub min_age_ns: Option<i64>,
    #[serde(default)]
    pub max_age_ns: Option<i64>,
}

impl FilterOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_include(mut self, pattern: impl Into<String>) -> Self {
        self.includes.push(pattern.into());
        self
    }

    pub fn with_exclude(mut self, pattern: impl Into<String>) -> Self {
        self.excludes.push(pattern.into());
        self
    }

    pub fn with_rule(mut self, include: bool, pattern: impl Into<String>) -> Self {
        self.rules.push(FilterRule {
            include,
            pattern: pattern.into(),
        });
        self
    }

    pub fn with_files_from<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.files_from = Some(paths.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_min_size(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    pub fn with_min_age_ns(mut self, age_ns: i64) -> Self {
        self.min_age_ns = Some(age_ns);
        self
    }

    pub fn with_max_age_ns(mut self, age_ns: i64) -> Self {
        self.max_age_ns = Some(age_ns);
        self
    }

    pub fn build(&self) -> Result<FilterSet> {
        FilterSet::from_options(self)
    }

    /// Compute a canonical SHA-256 hex fingerprint over all active filter rules,
    /// allowlists, size bounds, and age bounds (used by `bisync` to detect filter
    /// drift across runs and prevent silent deletion of newly-unmatched paths).
    pub fn fingerprint_sha256(&self) -> String {
        let mut h = Sha256::new();
        if !self.includes.is_empty() {
            let mut sorted = self.includes.clone();
            sorted.sort();
            sorted.dedup();
            h.update(b"inc\0");
            for p in &sorted {
                h.update(p.as_bytes());
                h.update([0u8]);
            }
        }
        if !self.excludes.is_empty() {
            let mut sorted = self.excludes.clone();
            sorted.sort();
            sorted.dedup();
            h.update(b"exc\0");
            for p in &sorted {
                h.update(p.as_bytes());
                h.update([0u8]);
            }
        }
        if !self.rules.is_empty() {
            // Ordered filter rules are order-sensitive (`first match wins`).
            h.update(b"rul\0");
            for r in &self.rules {
                h.update([if r.include { b'+' } else { b'-' }]);
                h.update(r.pattern.as_bytes());
                h.update([0u8]);
            }
        }
        if let Some(ref list) = self.files_from {
            let mut norm: Vec<String> = list
                .iter()
                .map(|raw| {
                    RelPath::parse(raw)
                        .map(|r| r.as_str().to_string())
                        .unwrap_or_else(|_| raw.clone())
                })
                .filter(|s| !s.is_empty())
                .collect();
            norm.sort();
            norm.dedup();
            h.update(b"ff\0");
            for p in &norm {
                h.update(p.as_bytes());
                h.update([0u8]);
            }
        } else if let Some(ref path) = self.files_from_path {
            h.update(b"ffp\0");
            h.update(path.as_bytes());
            h.update([0u8]);
        }
        if let Some(v) = self.min_size {
            h.update(b"mins\0");
            h.update(v.to_le_bytes());
        }
        if let Some(v) = self.max_size {
            h.update(b"maxs\0");
            h.update(v.to_le_bytes());
        }
        if let Some(v) = self.min_age_ns {
            h.update(b"mina\0");
            h.update(v.to_le_bytes());
        }
        if let Some(v) = self.max_age_ns {
            h.update(b"maxa\0");
            h.update(v.to_le_bytes());
        }
        hex::encode(h.finalize())
    }
}

#[derive(Debug, Clone)]
struct CompiledRule {
    include: bool,
    dir_only: bool,
    matcher: GlobSet,
}

/// Glob, rule-file, allowlist, size, and age filter applied during both
/// observation (pruning directory descent early) and planning (protecting
/// excluded destination files from `--delete`).
#[derive(Debug, Clone, Default)]
pub struct FilterSet {
    includes: Option<GlobSet>,
    excludes: Option<GlobSet>,
    exclude_dirs: Option<GlobSet>,
    rules: Vec<CompiledRule>,
    /// Deduplicated, order-preserving `--files-from` paths (stored once in `Arc` for `O(1)` clone).
    files_from_ordered: Option<Arc<[RelPath]>>,
    /// Sorted 4-byte index into `files_from_ordered` for `O(log N)` membership checks without
    /// duplicating string allocations.
    files_from_sorted_idx: Option<Arc<[u32]>>,
    files_from_ancestors: Option<Arc<HashSet<Box<str>>>>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    min_age_ns: Option<i64>,
    max_age_ns: Option<i64>,
    /// Canonical SHA-256 fingerprint of the originating [`FilterOptions`] (`None` when empty).
    fingerprint: Option<Arc<str>>,
}

impl FilterSet {
    pub fn new(include_patterns: &[String], exclude_patterns: &[String]) -> Result<Self> {
        Self::from_options(&FilterOptions {
            includes: include_patterns.to_vec(),
            excludes: exclude_patterns.to_vec(),
            ..Default::default()
        })
    }

    pub fn from_options(opts: &FilterOptions) -> Result<Self> {
        let includes = if opts.includes.is_empty() {
            None
        } else {
            Some(build_globset(&opts.includes)?)
        };

        let (excludes, exclude_dirs) = if opts.excludes.is_empty() {
            (None, None)
        } else {
            let mut all = GlobSetBuilder::new();
            let mut dirs = GlobSetBuilder::new();
            let mut has_dir_excludes = false;
            for pat in &opts.excludes {
                let normalized = pat.replace('\\', "/");
                let (anchored, body) = match normalized.strip_prefix('/') {
                    Some(rest) => (true, rest),
                    None => (false, normalized.as_str()),
                };
                if let Some(dir_pat) = body.strip_suffix('/') {
                    has_dir_excludes = true;
                    dirs.add(compile_glob(dir_pat)?);
                    dirs.add(compile_glob(&format!("{dir_pat}/**"))?);
                    all.add(compile_glob(dir_pat)?);
                    all.add(compile_glob(&format!("{dir_pat}/**"))?);
                    if !anchored {
                        dirs.add(compile_glob(&format!("**/{dir_pat}"))?);
                        dirs.add(compile_glob(&format!("**/{dir_pat}/**"))?);
                        all.add(compile_glob(&format!("**/{dir_pat}"))?);
                        all.add(compile_glob(&format!("**/{dir_pat}/**"))?);
                    }
                } else {
                    all.add(compile_glob(body)?);
                    if !anchored && !body.contains('/') {
                        all.add(compile_glob(&format!("**/{body}"))?);
                    }
                }
            }
            let all_set = all
                .build()
                .map_err(|e| Error::invalid_path(format!("invalid exclude globset: {e}")))?;
            let dir_set = if has_dir_excludes {
                Some(dirs.build().map_err(|e| {
                    Error::invalid_path(format!("invalid exclude dir globset: {e}"))
                })?)
            } else {
                None
            };
            (Some(all_set), dir_set)
        };

        let mut compiled_rules = Vec::with_capacity(opts.rules.len());
        for r in &opts.rules {
            let normalized = r.pattern.replace('\\', "/");
            let (anchored, body) = match normalized.strip_prefix('/') {
                Some(rest) => (true, rest),
                None => (false, normalized.as_str()),
            };
            let mut b = GlobSetBuilder::new();
            let dir_only = if let Some(dir_pat) = body.strip_suffix('/') {
                b.add(compile_glob(dir_pat)?);
                b.add(compile_glob(&format!("{dir_pat}/**"))?);
                if !anchored {
                    b.add(compile_glob(&format!("**/{dir_pat}"))?);
                    b.add(compile_glob(&format!("**/{dir_pat}/**"))?);
                }
                true
            } else {
                b.add(compile_glob(body)?);
                if !anchored && !body.contains('/') {
                    b.add(compile_glob(&format!("**/{body}"))?);
                }
                false
            };
            let matcher = b.build().map_err(|e| {
                Error::invalid_path(format!("invalid filter rule `{}`: {e}", r.pattern))
            })?;
            compiled_rules.push(CompiledRule {
                include: r.include,
                dir_only,
                matcher,
            });
        }

        let (files_from_ordered, files_from_sorted_idx, files_from_ancestors) =
            if let Some(list) = &opts.files_from {
                let mut parsed: Vec<RelPath> = Vec::with_capacity(list.len());
                for raw in list {
                    let rel = RelPath::parse(raw)?;
                    if !rel.is_root() {
                        parsed.push(rel);
                    }
                }
                // Deduplicate preserving first-seen order without allocating a duplicate String copy.
                let mut seen: HashSet<RelPath> = HashSet::with_capacity(parsed.len());
                let mut ordered: Vec<RelPath> = Vec::with_capacity(parsed.len());
                let mut ancestors: HashSet<Box<str>> = HashSet::new();
                for rel in parsed {
                    let mut cur = rel.as_str();
                    while let Some((parent, _)) = cur.rsplit_once('/') {
                        if !ancestors.contains(parent) {
                            ancestors.insert(parent.into());
                        }
                        cur = parent;
                    }
                    if seen.insert(rel.clone()) {
                        ordered.push(rel);
                    }
                }
                drop(seen);
                if ordered.len() > u32::MAX as usize {
                    return Err(Error::invalid_path(
                        "--files-from list exceeds maximum supported entry count",
                    ));
                }
                let mut sorted_idx: Vec<u32> = (0..ordered.len() as u32).collect();
                sorted_idx.sort_unstable_by(|&a, &b| {
                    ordered[a as usize]
                        .as_str()
                        .cmp(ordered[b as usize].as_str())
                });
                (
                    Some(Arc::<[RelPath]>::from(ordered)),
                    Some(Arc::<[u32]>::from(sorted_idx)),
                    Some(Arc::new(ancestors)),
                )
            } else {
                (None, None, None)
            };

        let fp = opts.fingerprint_sha256();
        let fingerprint = if fp == EMPTY_FILTER_FINGERPRINT {
            None
        } else {
            Some(Arc::<str>::from(fp))
        };

        Ok(Self {
            includes,
            excludes,
            exclude_dirs,
            rules: compiled_rules,
            files_from_ordered,
            files_from_sorted_idx,
            files_from_ancestors,
            min_size: opts.min_size,
            max_size: opts.max_size,
            min_age_ns: opts.min_age_ns,
            max_age_ns: opts.max_age_ns,
            fingerprint,
        })
    }

    /// Canonical SHA-256 fingerprint of this filter set (identical across runs
    /// iff the effective filter configuration is unchanged).
    pub fn fingerprint_sha256(&self) -> &str {
        self.fingerprint
            .as_deref()
            .unwrap_or(EMPTY_FILTER_FINGERPRINT)
    }

    /// Return the deduplicated, order-preserving list of relative file paths supplied
    /// via `--files-from`, enabling direct-stat (`--no-traverse`) observation without
    /// scanning entire local or remote directory trees.
    pub fn files_from_paths(&self) -> Option<&[RelPath]> {
        self.files_from_ordered.as_deref()
    }

    pub fn is_empty(&self) -> bool {
        self.includes.is_none()
            && self.excludes.is_none()
            && self.rules.is_empty()
            && self.files_from_ordered.is_none()
            && self.min_size.is_none()
            && self.max_size.is_none()
            && self.min_age_ns.is_none()
            && self.max_age_ns.is_none()
    }

    /// Returns `true` if any rule in this filter set can prune directory subtrees early.
    pub fn has_dir_pruning(&self) -> bool {
        self.files_from_ancestors.is_some()
            || self.exclude_dirs.is_some()
            || self
                .rules
                .iter()
                .take_while(|r| !r.include)
                .any(|r| r.dir_only)
    }

    /// Zero-allocation slice variant of [`Self::should_prune_dir`] for already-normalized
    /// relative directory path strings.
    pub fn should_prune_dir_str(&self, dir_str: &str) -> bool {
        if dir_str.is_empty() {
            return false;
        }
        if let Some(ancestors) = &self.files_from_ancestors
            && !ancestors.contains(dir_str)
        {
            return true;
        }
        if let Some(set) = &self.exclude_dirs
            && set.is_match(dir_str)
        {
            return true;
        }
        for rule in &self.rules {
            if rule.include {
                // An earlier include rule might match files inside this directory;
                // stop early so we never falsely prune a needed subtree.
                break;
            }
            if rule.dir_only && rule.matcher.is_match(dir_str) {
                return true;
            }
        }
        false
    }

    /// Returns `true` if the walker can skip descending into `dir_path` entirely.
    pub fn should_prune_dir(&self, dir_path: &RelPath) -> bool {
        self.should_prune_dir_str(dir_path.as_str())
    }

    /// Returns `true` if a file path matches path-based rules (allowlist, excludes,
    /// ordered filter rules, and includes).
    pub fn matches_file(&self, path: &RelPath) -> bool {
        let s = path.as_str();
        if let (Some(ordered), Some(sorted_idx)) =
            (&self.files_from_ordered, &self.files_from_sorted_idx)
            && sorted_idx
                .binary_search_by(|&idx| ordered[idx as usize].as_str().cmp(s))
                .is_err()
        {
            return false;
        }
        if let Some(ex) = &self.excludes
            && ex.is_match(s)
        {
            return false;
        }
        if !self.rules.is_empty() {
            for rule in &self.rules {
                if rule.matcher.is_match(s) {
                    return rule.include;
                }
            }
        }
        if let Some(inc) = &self.includes {
            return inc.is_match(s);
        }
        true
    }

    /// Full entry predicate combining path filtering with `--min-size`, `--max-size`,
    /// `--min-age`, and `--max-age` relative to `now_unix_ns`.
    pub fn matches_entry(&self, entry: &Entry, now_unix_ns: i64) -> bool {
        match entry.kind {
            EntryKind::Directory => !self.should_prune_dir(&entry.nfc_path),
            EntryKind::Symlink => self.matches_file(&entry.nfc_path),
            EntryKind::File => {
                if !self.matches_file(&entry.nfc_path) {
                    return false;
                }
                if let Some(min_sz) = self.min_size
                    && entry.size < min_sz
                {
                    return false;
                }
                if let Some(max_sz) = self.max_size
                    && entry.size > max_sz
                {
                    return false;
                }
                if self.min_age_ns.is_some() || self.max_age_ns.is_some() {
                    let age_ns = now_unix_ns.saturating_sub(entry.mtime_ns);
                    if let Some(min_age) = self.min_age_ns
                        && age_ns < min_age
                    {
                        return false;
                    }
                    if let Some(max_age) = self.max_age_ns
                        && age_ns > max_age
                    {
                        return false;
                    }
                }
                true
            }
        }
    }
}

/// Parse rclone/rsync-style `--filter-from` text (`+ pattern` / `- pattern`).
/// Blank lines and `#` / `;` comments are ignored.
pub fn parse_filter_rules(text: &str) -> Result<Vec<FilterRule>> {
    let mut rules = Vec::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(pat) = line.strip_prefix("+ ") {
            let pat = pat.trim();
            if pat.is_empty() {
                return Err(Error::invalid_path(format!(
                    "filter-from line {}: empty include pattern",
                    idx + 1
                )));
            }
            rules.push(FilterRule {
                include: true,
                pattern: pat.to_string(),
            });
        } else if let Some(pat) = line.strip_prefix("- ") {
            let pat = pat.trim();
            if pat.is_empty() {
                return Err(Error::invalid_path(format!(
                    "filter-from line {}: empty exclude pattern",
                    idx + 1
                )));
            }
            rules.push(FilterRule {
                include: false,
                pattern: pat.to_string(),
            });
        } else {
            return Err(Error::invalid_path(format!(
                "filter-from line {}: expected `+ <pattern>` or `- <pattern>`, got `{line}`",
                idx + 1
            )));
        }
    }
    Ok(rules)
}

/// Parse `--exclude-from` lines (one glob per line, ignoring blanks and `#`/`;` comments).
pub fn parse_exclude_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .map(ToOwned::to_owned)
        .collect()
}

/// Parse `--files-from` lines (one relative file path per line, ignoring blanks and `#`/`;`).
pub fn parse_files_from(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with(';'))
        .map(|l| l.replace('\\', "/").trim_start_matches('/').to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Parse a human-readable duration (`30s`, `15m`, `2h`, `7d`, `2w`, `1h30m`, `500ms`)
/// into nanoseconds.
pub fn parse_duration_nanos(input: &str) -> Result<i64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(Error::invalid_path("empty duration"));
    }
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut total_ns: i128 = 0;

    while i < bytes.len() {
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            return Err(Error::invalid_path(format!(
                "invalid duration `{input}`: expected number"
            )));
        }
        let val: i128 = s[num_start..i]
            .parse()
            .map_err(|_| Error::invalid_path(format!("invalid duration `{input}`")))?;

        let unit_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let unit = s[unit_start..i].to_ascii_lowercase();
        let mult_ns: i128 = match unit.as_str() {
            "ms" => 1_000_000,
            "" | "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3600 * 1_000_000_000,
            "d" => 86_400 * 1_000_000_000,
            "w" => 7 * 86_400 * 1_000_000_000,
            "y" => 365 * 86_400 * 1_000_000_000,
            _ => {
                return Err(Error::invalid_path(format!(
                    "unknown duration unit `{unit}` in `{input}`"
                )));
            }
        };
        total_ns = total_ns
            .checked_add(
                val.checked_mul(mult_ns)
                    .ok_or_else(|| Error::invalid_path(format!("duration `{input}` overflows")))?,
            )
            .ok_or_else(|| Error::invalid_path(format!("duration `{input}` overflows")))?;
    }

    i64::try_from(total_ns)
        .map_err(|_| Error::invalid_path(format!("duration `{input}` overflows i64")))
}

fn compile_glob(pattern: &str) -> Result<Glob> {
    // Match rclone/rsync/POSIX glob semantics: `*` never crosses `/` (only `**` does).
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map_err(|e| Error::invalid_path(format!("invalid glob pattern `{pattern}`: {e}")))
}

fn build_globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        let normalized = pat.replace('\\', "/");
        let (anchored, body) = match normalized.strip_prefix('/') {
            Some(rest) => (true, rest),
            None => (false, normalized.as_str()),
        };
        builder.add(compile_glob(body)?);
        if !anchored && !body.contains('/') {
            builder.add(compile_glob(&format!("**/{body}"))?);
        }
    }
    builder
        .build()
        .map_err(|e| Error::invalid_path(format!("invalid globset: {e}")))
}

#[cfg(test)]
mod tests;
