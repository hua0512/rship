//! Checked-arithmetic protocol chunk geometry planner.
//!
//! Decouples HTTP request counts (protocol chunks: e.g. 128 MiB for GDrive,
//! tiered 16–512 MiB for S3) from in-flight RAM (256 KiB pooled I/O slices),
//! while rejecting impossible geometry BEFORE creating any remote session.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{Capabilities, ChunkAlignment, UploadTopology};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UploadPlan {
    /// Single HTTP request (GDrive `uploadType=multipart`, S3 `PutObject`, or 0-byte file).
    SingleShot { total_size: u64 },
    /// Multi-chunk / multipart resumable upload with validated geometry.
    Resumable {
        total_size: u64,
        chunk_size: u64,
        total_parts: u32,
        topology: UploadTopology,
    },
}

/// Compute a strictly valid upload plan using checked arithmetic.
///
/// Rejects impossible user overrides or files exceeding provider limits up front.
pub fn plan_upload(
    file_size: u64,
    caps: &Capabilities,
    user_chunk_override: Option<u64>,
) -> Result<UploadPlan> {
    if file_size == 0 || file_size <= caps.single_shot_max_bytes {
        return Ok(UploadPlan::SingleShot {
            total_size: file_size,
        });
    }

    match caps.chunk_alignment {
        ChunkAlignment::Arbitrary => {
            let chunk_size = user_chunk_override.unwrap_or(caps.default_chunk_size);
            if chunk_size == 0 {
                return Err(Error::invalid_geometry("chunk_size must be > 0"));
            }
            let parts = file_size.div_ceil(chunk_size);
            let total_parts = u32::try_from(parts).map_err(|_| {
                Error::invalid_geometry(format!("part count {parts} overflows u32"))
            })?;
            Ok(UploadPlan::Resumable {
                total_size: file_size,
                chunk_size,
                total_parts,
                topology: caps.upload_topology,
            })
        }

        ChunkAlignment::MultipleOf {
            align_bytes,
            max_chunk_bytes,
        } => {
            if align_bytes == 0 {
                return Err(Error::invalid_geometry("align_bytes must be > 0"));
            }
            let chunk_size = match user_chunk_override {
                Some(u) => {
                    if u == 0 || !u.is_multiple_of(align_bytes) {
                        return Err(Error::invalid_geometry(format!(
                            "chunk_size ({u}) must be a positive multiple of {align_bytes} bytes"
                        )));
                    }
                    if let Some(max_c) = max_chunk_bytes
                        && u > max_c
                    {
                        return Err(Error::invalid_geometry(format!(
                            "chunk_size ({u}) exceeds backend max_chunk_bytes ({max_c})"
                        )));
                    }
                    u
                }
                None => {
                    let mut c = caps.default_chunk_size;
                    if let Some(max_c) = max_chunk_bytes {
                        c = c.min(max_c);
                    }
                    // Align down to exact multiple (at least 1 alignment unit).
                    let aligned = (c / align_bytes) * align_bytes;
                    if aligned == 0 {
                        return Err(Error::invalid_geometry(
                            "default_chunk_size smaller than alignment",
                        ));
                    }
                    aligned
                }
            };
            let parts = file_size.div_ceil(chunk_size);
            let total_parts = u32::try_from(parts).map_err(|_| {
                Error::invalid_geometry(format!("part count {parts} overflows u32"))
            })?;
            Ok(UploadPlan::Resumable {
                total_size: file_size,
                chunk_size,
                total_parts,
                topology: caps.upload_topology,
            })
        }

        ChunkAlignment::MinSizeWithMaxParts {
            min_bytes,
            max_bytes,
            max_parts,
            max_object_bytes,
            ..
        } => {
            if max_parts == 0 || min_bytes == 0 || min_bytes > max_bytes {
                return Err(Error::invalid_geometry(
                    "invalid backend multipart constraints",
                ));
            }
            if file_size > max_object_bytes {
                return Err(Error::invalid_geometry(format!(
                    "file size ({file_size}) exceeds backend max_object_bytes ({max_object_bytes})"
                )));
            }

            let min_for_part_cap = file_size.div_ceil(u64::from(max_parts));
            let chunk_size = match user_chunk_override {
                Some(u) => {
                    if u < min_bytes || u > max_bytes {
                        return Err(Error::invalid_geometry(format!(
                            "chunk_size ({u}) outside backend part bounds [{min_bytes}, {max_bytes}]"
                        )));
                    }
                    if u < min_for_part_cap {
                        return Err(Error::invalid_geometry(format!(
                            "chunk_size ({u}) would exceed max_parts ({max_parts}) for file_size ({file_size}); minimum required is {min_for_part_cap}"
                        )));
                    }
                    u
                }
                None => {
                    // Tiered sizing to cut S3/R2 PUT request costs while costing 0 extra RAM.
                    let tiered = if file_size < GIB {
                        caps.default_chunk_size.max(16 * MIB)
                    } else if file_size < 32 * GIB {
                        caps.default_chunk_size.max(64 * MIB)
                    } else {
                        caps.default_chunk_size.max(128 * MIB)
                    };
                    let required = tiered.max(min_for_part_cap).max(min_bytes);
                    // Round up to 1 MiB boundary cleanly via checked math.
                    let aligned = required
                        .checked_add(MIB - 1)
                        .map(|x| (x / MIB) * MIB)
                        .unwrap_or(max_bytes)
                        .min(max_bytes);
                    if aligned < min_for_part_cap {
                        return Err(Error::invalid_geometry(format!(
                            "cannot fit file_size ({file_size}) into max_parts ({max_parts}) within max_bytes ({max_bytes})"
                        )));
                    }
                    aligned
                }
            };

            let parts = file_size.div_ceil(chunk_size);
            if parts > u64::from(max_parts) {
                return Err(Error::invalid_geometry(format!(
                    "computed part count ({parts}) exceeds max_parts ({max_parts})"
                )));
            }
            Ok(UploadPlan::Resumable {
                total_size: file_size,
                chunk_size,
                total_parts: parts as u32,
                topology: caps.upload_topology,
            })
        }
    }
}

/// Compute exact byte `(offset, len)` for 1-based `part_number` under locked
/// `chunk_size` and `total_size`.
pub fn part_byte_range(total_size: u64, chunk_size: u64, part_number: u32) -> Result<(u64, u64)> {
    if part_number == 0 || chunk_size == 0 {
        return Err(Error::invalid_geometry(
            "part_number and chunk_size must be > 0",
        ));
    }
    let idx = u64::from(part_number - 1);
    let offset = idx
        .checked_mul(chunk_size)
        .ok_or_else(|| Error::invalid_geometry("part offset overflow"))?;
    if offset >= total_size {
        return Err(Error::invalid_geometry(format!(
            "part {part_number} starts at {offset} >= total_size {total_size}"
        )));
    }
    let len = (total_size - offset).min(chunk_size);
    Ok((offset, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn gdrive_caps() -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: Duration::from_millis(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::Sequential,
            chunk_alignment: ChunkAlignment::MultipleOf {
                align_bytes: 256 * 1024,
                max_chunk_bytes: None,
            },
            single_shot_max_bytes: 5 * MIB,
            default_chunk_size: 128 * MIB,
            allows_duplicate_names: true,
            case_sensitive: true,
            supports_node_id: true,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: true,
            supports_server_side_copy: true,
            default_write_qps: Some(3),
        }
    }

    fn r2_caps() -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: false,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                min_bytes: 5 * MIB,
                max_bytes: 5 * GIB,
                max_parts: 10_000,
                max_object_bytes: 5 * 1024 * GIB,
                require_equal_non_final_parts: true,
            },
            single_shot_max_bytes: 16 * MIB,
            default_chunk_size: 16 * MIB,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: true,
            supports_ordered_utf8_list: true,
            supports_conditional_write: true,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }

    #[test]
    fn handles_zero_byte_and_single_shot_and_gdrive_10gib() {
        let g = gdrive_caps();
        assert_eq!(
            plan_upload(0, &g, None).unwrap(),
            UploadPlan::SingleShot { total_size: 0 }
        );
        assert_eq!(
            plan_upload(4 * MIB, &g, None).unwrap(),
            UploadPlan::SingleShot {
                total_size: 4 * MIB
            }
        );

        let ten_gib = 10 * GIB;
        assert_eq!(
            plan_upload(ten_gib, &g, None).unwrap(),
            UploadPlan::Resumable {
                total_size: ten_gib,
                chunk_size: 128 * MIB,
                total_parts: 80,
                topology: UploadTopology::Sequential,
            }
        );

        // Unaligned GDrive override must be rejected up front.
        assert!(plan_upload(ten_gib, &g, Some(1000)).is_err());
    }

    #[test]
    fn enforces_s3_and_r2_part_limits_and_rejects_impossible_overrides() {
        let r2 = r2_caps();
        // 5 TiB file auto-scales part size >= 512 MiB to fit in 10,000 parts.
        let five_tib = 5 * 1024 * GIB;
        match plan_upload(five_tib, &r2, None).unwrap() {
            UploadPlan::Resumable {
                chunk_size,
                total_parts,
                ..
            } => {
                assert!(total_parts <= 10_000);
                assert!(chunk_size >= 512 * MIB);
            }
            _ => panic!("expected resumable"),
        }

        // User forcing 8 MiB on 1 TiB exceeds 10,000 parts -> rejected before session init.
        assert!(plan_upload(1024 * GIB, &r2, Some(8 * MIB)).is_err());

        // File above R2's 5 TiB max_object_bytes -> rejected.
        assert!(plan_upload(five_tib + 1, &r2, None).is_err());
    }

    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        fn arbitrary_caps_strategy() -> impl Strategy<Value = Capabilities> {
            prop_oneof![
                // Arbitrary alignment
                (0u64..=(4 * MIB), 1u64..=(16 * MIB), prop::bool::ANY).prop_map(
                    |(single_shot, default_chunk, seq)| {
                        let mut c = gdrive_caps();
                        c.upload_topology = if seq {
                            UploadTopology::Sequential
                        } else {
                            UploadTopology::ParallelParts
                        };
                        c.chunk_alignment = ChunkAlignment::Arbitrary;
                        c.single_shot_max_bytes = single_shot;
                        c.default_chunk_size = default_chunk;
                        c
                    }
                ),
                // MultipleOf alignment (GDrive-like)
                (
                    prop::sample::select(vec![4 * 1024u64, 64 * 1024, 256 * 1024, MIB]),
                    1u64..=32,
                    prop::option::of(1u64..=64),
                    0u64..=(8 * MIB),
                )
                    .prop_map(|(align, mult, max_mult, single_shot)| {
                        let mut c = gdrive_caps();
                        c.chunk_alignment = ChunkAlignment::MultipleOf {
                            align_bytes: align,
                            max_chunk_bytes: max_mult.map(|m| m * align),
                        };
                        c.default_chunk_size = mult * align;
                        c.single_shot_max_bytes = single_shot;
                        c
                    }),
                // MinSizeWithMaxParts (S3/R2-like)
                (
                    prop::sample::select(vec![64 * 1024u64, MIB, 5 * MIB, 8 * MIB]),
                    prop::sample::select(vec![16 * MIB, 64 * MIB, 5 * GIB]),
                    prop::sample::select(vec![10u32, 100, 1_000, 10_000]),
                    0u64..=(16 * MIB),
                )
                    .prop_map(|(min_b, max_b, max_parts, single_shot)| {
                        let max_bytes = max_b.max(min_b);
                        let max_object_bytes = max_bytes
                            .saturating_mul(u64::from(max_parts))
                            .min(5 * 1024 * GIB);
                        let mut c = r2_caps();
                        c.chunk_alignment = ChunkAlignment::MinSizeWithMaxParts {
                            min_bytes: min_b,
                            max_bytes,
                            max_parts,
                            max_object_bytes,
                            require_equal_non_final_parts: true,
                        };
                        c.default_chunk_size = min_b;
                        c.single_shot_max_bytes = single_shot;
                        c
                    }),
            ]
        }

        proptest! {
            #[test]
            fn prop_plan_upload_geometry_and_alignment_invariants(
                caps in arbitrary_caps_strategy(),
                file_size in prop_oneof![
                    0u64..=(64 * MIB),
                    (64 * MIB)..=(6 * 1024 * GIB),
                ],
                override_choice in prop::option::of(0u64..=(256 * MIB)),
            ) {
                let res = plan_upload(file_size, &caps, override_choice);
                if file_size == 0 || file_size <= caps.single_shot_max_bytes {
                    prop_assert_eq!(res.unwrap(), UploadPlan::SingleShot { total_size: file_size });
                    return Ok(());
                }

                if let Ok(plan) = res {
                    match plan {
                        UploadPlan::SingleShot { total_size } => {
                            prop_assert_eq!(total_size, file_size);
                            prop_assert!(file_size == 0 || file_size <= caps.single_shot_max_bytes);
                        }
                        UploadPlan::Resumable {
                            total_size,
                            chunk_size,
                            total_parts,
                            topology,
                        } => {
                            prop_assert_eq!(total_size, file_size);
                            prop_assert_eq!(topology, caps.upload_topology);
                            prop_assert!(chunk_size > 0);
                            prop_assert!(total_parts >= 1);
                            prop_assert_eq!(u64::from(total_parts), file_size.div_ceil(chunk_size));

                            match caps.chunk_alignment {
                                ChunkAlignment::Arbitrary => {}
                                ChunkAlignment::MultipleOf { align_bytes, max_chunk_bytes } => {
                                    prop_assert_eq!(chunk_size % align_bytes, 0);
                                    if let Some(max_c) = max_chunk_bytes {
                                        prop_assert!(chunk_size <= max_c);
                                    }
                                }
                                ChunkAlignment::MinSizeWithMaxParts {
                                    min_bytes,
                                    max_bytes,
                                    max_parts,
                                    max_object_bytes,
                                    ..
                                } => {
                                    prop_assert!(file_size <= max_object_bytes);
                                    prop_assert!(chunk_size >= min_bytes);
                                    prop_assert!(chunk_size <= max_bytes);
                                    prop_assert!(total_parts <= max_parts);
                                }
                            }

                            // Verify first part, last part, out-of-bounds part, and full partition
                            // when part count is small enough for an exhaustive walk.
                            let (first_off, first_len) =
                                part_byte_range(total_size, chunk_size, 1).unwrap();
                            prop_assert_eq!(first_off, 0);
                            prop_assert!(first_len > 0 && first_len <= chunk_size);
                            let (last_off, last_len) =
                                part_byte_range(total_size, chunk_size, total_parts).unwrap();
                            prop_assert_eq!(last_off + last_len, total_size);
                            prop_assert!(last_len > 0 && last_len <= chunk_size);
                            prop_assert!(part_byte_range(total_size, chunk_size, 0).is_err());
                            if total_parts < u32::MAX {
                                prop_assert!(
                                    part_byte_range(total_size, chunk_size, total_parts + 1).is_err()
                                );
                            }
                        }
                    }
                }
            }

            #[test]
            fn prop_part_byte_range_exhaustively_partitions_zero_to_total_size(
                total_size in 1u64..=(20 * MIB),
                chunk_size in (16 * 1024u64)..=(2 * MIB),
            ) {
                let total_parts = total_size.div_ceil(chunk_size) as u32;
                let mut cursor = 0u64;
                for pn in 1..=total_parts {
                    let (off, len) = part_byte_range(total_size, chunk_size, pn).unwrap();
                    prop_assert_eq!(off, cursor, "gap or overlap at part {}", pn);
                    prop_assert!(len > 0 && len <= chunk_size);
                    if pn < total_parts {
                        prop_assert_eq!(len, chunk_size, "non-final part {} must be full chunk", pn);
                    }
                    cursor = off + len;
                }
                prop_assert_eq!(cursor, total_size);
                prop_assert!(part_byte_range(total_size, chunk_size, 0).is_err());
                prop_assert!(part_byte_range(total_size, chunk_size, total_parts + 1).is_err());
            }
        }
    }
}
