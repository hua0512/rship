//! Deterministic seeded property-testing harness for `rship-crypto`.
//!
//! Honors:
//! - `PROPTEST_CASES`: explicit case count per property (default `256`, nightly `512`).
//! - `RSHIP_DST_SEEDS`: deterministic stress-sweep multiplier (default `1`, nightly `64`).
//! - `RSHIP_PROP_SEED`: replay a single `u64` seed (decimal or `0x`-prefixed hex).

use bytes::Bytes;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};

fn parse_env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
}

fn parse_replay_seed() -> Option<u64> {
    let raw = std::env::var("RSHIP_PROP_SEED").ok()?;
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

/// Resolve the number of seeded property cases to execute.
pub(crate) fn case_count(default_cases: usize) -> usize {
    let default_cases = default_cases.max(1);
    let proptest_cases = parse_env_usize("PROPTEST_CASES");
    let dst_seeds = parse_env_usize("RSHIP_DST_SEEDS");

    match (proptest_cases, dst_seeds) {
        (Some(cases), Some(seeds)) => cases.max(seeds),
        (Some(cases), None) => cases,
        (None, Some(seeds)) if seeds > 1 => default_cases.max(seeds.saturating_mul(8)),
        (None, _) => default_cases,
    }
}

/// SplitMix64 mixing function for independent, well-distributed per-case seeds.
#[inline]
pub(crate) fn mix_seed(base_seed: u64, case_idx: usize) -> u64 {
    let mut z = base_seed.wrapping_add((case_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Return `(case_idx, seed)` pairs for a seeded property test.
///
/// If `RSHIP_PROP_SEED` is set, returns only that seed for instant failure replay.
pub(crate) fn seeds_for(base_seed: u64, default_cases: usize) -> Vec<(usize, u64)> {
    if let Some(seed) = parse_replay_seed() {
        return vec![(0, seed)];
    }
    let count = case_count(default_cases);
    (0..count)
        .map(|idx| (idx, mix_seed(base_seed, idx)))
        .collect()
}

pub(crate) fn rng_for(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// RAII drop guard that prints the exact failing property and seed on panic.
pub(crate) struct SeedGuard {
    property: &'static str,
    case_idx: usize,
    total_cases: usize,
    seed: u64,
}

impl SeedGuard {
    pub(crate) fn new(
        property: &'static str,
        case_idx: usize,
        total_cases: usize,
        seed: u64,
    ) -> Self {
        Self {
            property,
            case_idx,
            total_cases,
            seed,
        }
    }
}

impl Drop for SeedGuard {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "PROPERTY FAILURE `{}` at case {}/{}: seed={:#018x} (replay with RSHIP_PROP_SEED={:#018x})",
                self.property,
                self.case_idx + 1,
                self.total_cases,
                self.seed,
                self.seed,
            );
        }
    }
}

/// Partition `data` into an arbitrary sequence of `Bytes` chunks exercising
/// empty chunks, tiny byte-wise splits, unaligned splits, and multi-block slabs.
pub(crate) fn random_split_chunks(data: &[u8], rng: &mut StdRng) -> Vec<Bytes> {
    if data.is_empty() {
        // Occasionally emit empty chunks even for 0-byte streams.
        let empties = rng.random_range(0usize..=2);
        return vec![Bytes::new(); empties];
    }

    let mode = rng.random_range(0u8..5);
    let mut out = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        // Occasionally interleave 0-byte chunks to ensure streaming parsers skip them cleanly.
        if rng.random_bool(0.10) {
            out.push(Bytes::new());
        }
        let remaining = data.len() - pos;
        let step = match mode {
            // Tiny fragments (1..=37 bytes) — stresses partial header/block assembly.
            0 => rng.random_range(1..=37),
            // Medium unaligned fragments (1..=16 KiB).
            1 => rng.random_range(1..=16_384),
            // Straddling 64 KiB chunk boundary (32 KiB..=140 KiB).
            2 => rng.random_range(32_768..=140_000),
            // Single contiguous chunk.
            3 => remaining,
            // Mixed exponential sizes (1 byte up to 131 KiB).
            _ => {
                let shift = rng.random_range(0u32..=17);
                let hi = (1usize << shift).max(1);
                rng.random_range(1..=hi)
            }
        }
        .min(remaining);
        out.push(Bytes::copy_from_slice(&data[pos..pos + step]));
        pos += step;
    }

    if rng.random_bool(0.15) {
        out.push(Bytes::new());
    }
    out
}
