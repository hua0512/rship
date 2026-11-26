//! Environment-aware memory budget calculation (cgroup v1/v2 + host fallback).

use std::path::Path;

pub const DEFAULT_BUFFER_POOL_CAP_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB
pub const MIN_BUFFER_POOL_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const BUFFER_UNIT_BYTES: usize = 4 * 1024; // 4 KiB semaphore unit
pub const STREAM_SLICE_BYTES: usize = 256 * 1024; // 256 KiB streaming slice (64 units)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBudget {
    pub detected_cgroup_limit: Option<u64>,
    pub buffer_pool_bytes: usize,
    pub stream_slice_bytes: usize,
}

impl MemoryBudget {
    /// Detect container cgroup limits (on Linux) and compute a safe engine-owned
    /// `BufferPool` ceiling, respecting an optional explicit `--max-buffer-mem`.
    pub fn resolve(user_override_bytes: Option<u64>) -> Self {
        let cgroup_limit = detect_cgroup_memory_limit();
        Self::from_limits(cgroup_limit, user_override_bytes)
    }

    pub fn from_limits(cgroup_limit: Option<u64>, user_override_bytes: Option<u64>) -> Self {
        let mut target = match (cgroup_limit, user_override_bytes) {
            (Some(cg), Some(user)) => user.min(cg / 2),
            (None, Some(user)) => user,
            (Some(cg), None) => (cg / 4).min(DEFAULT_BUFFER_POOL_CAP_BYTES),
            (None, None) => DEFAULT_BUFFER_POOL_CAP_BYTES,
        };

        // Ensure floor never violates a tiny container's 25% share.
        let floor = match cgroup_limit {
            Some(cg) if cg < MIN_BUFFER_POOL_BYTES * 4 => (cg / 4).max(STREAM_SLICE_BYTES as u64),
            _ => MIN_BUFFER_POOL_BYTES,
        };
        if target < floor {
            target = floor;
        }

        // Round down to whole 4 KiB units, minimum 1 streaming slice.
        let unit = BUFFER_UNIT_BYTES as u64;
        let rounded = (target / unit) * unit;
        let buffer_pool_bytes = rounded.max(STREAM_SLICE_BYTES as u64) as usize;

        Self {
            detected_cgroup_limit: cgroup_limit,
            buffer_pool_bytes,
            stream_slice_bytes: STREAM_SLICE_BYTES,
        }
    }
}

/// Walks Linux cgroup v2 ancestor limits (from `/proc/self/cgroup`) or falls
/// back to cgroup v1 `/sys/fs/cgroup/memory/memory.limit_in_bytes`.
pub fn detect_cgroup_memory_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        detect_linux_cgroup_limit()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn detect_linux_cgroup_limit() -> Option<u64> {
    const UNLIMITED_THRESHOLD: u64 = 1u64 << 60;
    let mut min_limit: Option<u64> = None;

    // Cgroup v2: parse `0::/some/path` from `/proc/self/cgroup` and walk ancestors.
    if let Ok(proc_cg) = std::fs::read_to_string("/proc/self/cgroup") {
        for line in proc_cg.lines() {
            if let Some(rel) = line.strip_prefix("0::") {
                let mut cur = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
                loop {
                    let mem_max = cur.join("memory.max");
                    if let Some(val) = parse_limit_file(&mem_max, UNLIMITED_THRESHOLD) {
                        min_limit = Some(min_limit.map_or(val, |m| m.min(val)));
                    }
                    if cur == Path::new("/sys/fs/cgroup") {
                        break;
                    }
                    match cur.parent() {
                        Some(p) => cur = p.to_path_buf(),
                        None => break,
                    }
                }
            }
        }
    }

    if min_limit.is_some() {
        return min_limit;
    }

    // Fallback: direct v2 root or cgroup v1 limit file.
    for candidate in [
        Path::new("/sys/fs/cgroup/memory.max"),
        Path::new("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ] {
        if let Some(val) = parse_limit_file(candidate, UNLIMITED_THRESHOLD) {
            min_limit = Some(min_limit.map_or(val, |m| m.min(val)));
        }
    }
    min_limit
}

#[allow(dead_code)]
fn parse_limit_file(path: &Path, unlimited_threshold: u64) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed == "max" || trimmed.is_empty() {
        return None;
    }
    let v: u64 = trimmed.parse().ok()?;
    if v == 0 || v >= unlimited_threshold {
        None
    } else {
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_cgroup_and_small_container_bounds() {
        // 32 MiB container -> 25% = 8 MiB
        let b = MemoryBudget::from_limits(Some(32 * 1024 * 1024), None);
        assert_eq!(b.buffer_pool_bytes, 8 * 1024 * 1024);

        // 2 GiB container -> capped at default 16 MiB
        let b = MemoryBudget::from_limits(Some(2 * 1024 * 1024 * 1024), None);
        assert_eq!(b.buffer_pool_bytes, DEFAULT_BUFFER_POOL_CAP_BYTES as usize);

        // Tiny 2 MiB container -> does not exceed 25% = 512 KiB
        let b = MemoryBudget::from_limits(Some(2 * 1024 * 1024), None);
        assert_eq!(b.buffer_pool_bytes, 512 * 1024);
    }
}
