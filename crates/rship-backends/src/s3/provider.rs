//! S3-compatible provider capability matrix (`aws`, `r2`, `minio`, `oss`, `b2`, `generic`).
//!
//! Encodes exact provider limits and behavioral quirks (`PLAN.md` §3.6 &
//! `CONFORMANCE_TESTS.md` §4):
//! - Max object size (AWS 48.8 TiB vs Cloudflare R2 5 TiB vs B2 10 TB).
//! - Cloudflare R2's equal-non-final-part requirement.
//! - Conditional write support (`If-None-Match: *` / `If-Match`).
//! - Checksum header support (`CRC64NVME` enabled ONLY on AWS S3).

use rship_core::types::{Capabilities, ChunkAlignment, HashKind, UploadTopology};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;
pub const TIB: u64 = 1024 * GIB;

/// Supported S3-compatible provider profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S3Provider {
    #[default]
    Aws,
    R2,
    Minio,
    Oss,
    B2,
    Wasabi,
    DigitalOcean,
    Cos,
    Tigris,
    Scaleway,
    Hetzner,
    Generic,
}

impl S3Provider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aws => "aws",
            Self::R2 => "r2",
            Self::Minio => "minio",
            Self::Oss => "oss",
            Self::B2 => "b2",
            Self::Wasabi => "wasabi",
            Self::DigitalOcean => "digitalocean",
            Self::Cos => "cos",
            Self::Tigris => "tigris",
            Self::Scaleway => "scaleway",
            Self::Hetzner => "hetzner",
            Self::Generic => "generic",
        }
    }

    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "aws" | "amazon" | "s3" => Some(Self::Aws),
            "r2" | "cloudflare" | "cloudflare_r2" => Some(Self::R2),
            "minio" => Some(Self::Minio),
            "oss" | "alibaba" | "aliyun" => Some(Self::Oss),
            "b2" | "backblaze" | "backblaze_b2" => Some(Self::B2),
            "wasabi" => Some(Self::Wasabi),
            "digitalocean" | "do" | "spaces" | "digitaloceanspaces" => Some(Self::DigitalOcean),
            "cos" | "tencent" | "tencentcos" | "qcloud" => Some(Self::Cos),
            "tigris" => Some(Self::Tigris),
            "scaleway" | "scw" => Some(Self::Scaleway),
            "hetzner" => Some(Self::Hetzner),
            "generic" | "other" | "ceph" | "seaweedfs" | "garage" => Some(Self::Generic),
            _ => None,
        }
    }

    pub fn profile(self) -> ProviderProfile {
        match self {
            Self::Aws => ProviderProfile {
                // 10,000 * 5 GiB = 50,000 GiB (~48.8 TiB).
                max_object_bytes: 50_000 * GIB,
                default_force_path_style: false,
                supports_if_none_match: true,
                supports_if_match_write: true,
                supports_crc64nvme: true,
                supports_crc32c: true,
                supports_single_part_crc32c: true,
                hashes: vec![
                    HashKind::Crc64Nvme,
                    HashKind::Crc32c,
                    HashKind::Sha256,
                    HashKind::Md5,
                ],
                ..ProviderProfile::base(Self::Aws, "us-east-1")
            },
            Self::R2 => ProviderProfile {
                // Cloudflare R2 enforces 4.995 GiB max part / single upload, 4.995 TiB max object,
                // equal non-final parts, and COMPOSITE-only CRC32C (no single-part PutObject CRC32C).
                max_part_bytes: 5 * GIB - 5 * MIB,
                max_object_bytes: 5 * TIB - 5 * GIB,
                require_equal_non_final_parts: true,
                supports_if_none_match: true,
                supports_if_match_write: true,
                supports_crc32c: true,
                supports_single_part_crc32c: false,
                hashes: vec![HashKind::Crc32c, HashKind::Sha256, HashKind::Md5],
                ..ProviderProfile::base(Self::R2, "auto")
            },
            Self::Minio => ProviderProfile {
                supports_if_none_match: true,
                supports_if_match_write: true,
                supports_crc32c: true,
                supports_single_part_crc32c: true,
                hashes: vec![HashKind::Crc32c, HashKind::Sha256, HashKind::Md5],
                ..ProviderProfile::base(Self::Minio, "us-east-1")
            },
            Self::Oss => ProviderProfile {
                max_object_bytes: 50_000 * GIB,
                default_force_path_style: false,
                ..ProviderProfile::base(Self::Oss, "cn-hangzhou")
            },
            Self::B2 => ProviderProfile {
                max_object_bytes: 10 * TIB,
                hashes: vec![HashKind::Sha256, HashKind::Sha1, HashKind::Md5],
                ..ProviderProfile::base(Self::B2, "us-west-000")
            },
            Self::Wasabi => ProviderProfile {
                default_force_path_style: false,
                ..ProviderProfile::base(Self::Wasabi, "us-east-1")
            },
            Self::DigitalOcean => ProviderProfile {
                default_force_path_style: false,
                ..ProviderProfile::base(Self::DigitalOcean, "nyc3")
            },
            Self::Cos => ProviderProfile {
                max_object_bytes: 50_000 * GIB,
                default_force_path_style: false,
                ..ProviderProfile::base(Self::Cos, "ap-guangzhou")
            },
            Self::Tigris => ProviderProfile {
                default_force_path_style: false,
                supports_if_none_match: true,
                supports_if_match_write: true,
                supports_crc32c: true,
                supports_single_part_crc32c: true,
                hashes: vec![HashKind::Crc32c, HashKind::Sha256, HashKind::Md5],
                ..ProviderProfile::base(Self::Tigris, "auto")
            },
            Self::Scaleway => ProviderProfile {
                default_force_path_style: false,
                ..ProviderProfile::base(Self::Scaleway, "fr-par")
            },
            Self::Hetzner => ProviderProfile {
                default_force_path_style: false,
                ..ProviderProfile::base(Self::Hetzner, "fsn1")
            },
            Self::Generic => ProviderProfile::base(Self::Generic, "us-east-1"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProfile {
    pub provider: S3Provider,
    pub min_part_bytes: u64,
    pub max_part_bytes: u64,
    pub max_parts: u32,
    pub max_object_bytes: u64,
    pub require_equal_non_final_parts: bool,
    pub default_single_shot_max_bytes: u64,
    pub default_chunk_size: u64,
    pub default_force_path_style: bool,
    pub supports_if_none_match: bool,
    pub supports_if_match_write: bool,
    pub supports_crc64nvme: bool,
    pub supports_crc32c: bool,
    pub supports_single_part_crc32c: bool,
    pub hashes: Vec<HashKind>,
    pub default_region: &'static str,
}

impl ProviderProfile {
    fn base(provider: S3Provider, default_region: &'static str) -> Self {
        Self {
            provider,
            min_part_bytes: 5 * MIB,
            max_part_bytes: 5 * GIB,
            max_parts: 10_000,
            max_object_bytes: 5 * TIB,
            require_equal_non_final_parts: false,
            default_single_shot_max_bytes: 16 * MIB,
            default_chunk_size: 16 * MIB,
            default_force_path_style: true,
            supports_if_none_match: false,
            supports_if_match_write: false,
            supports_crc64nvme: false,
            supports_crc32c: false,
            supports_single_part_crc32c: false,
            hashes: vec![HashKind::Sha256, HashKind::Md5],
            default_region,
        }
    }
    pub fn to_capabilities(
        &self,
        single_shot_override: Option<u64>,
        chunk_override: Option<u64>,
        min_part_override: Option<u64>,
    ) -> Capabilities {
        let min_bytes = min_part_override.unwrap_or(self.min_part_bytes);
        Capabilities {
            hashes: self.hashes.clone(),
            mtime_granularity: Duration::from_secs(1),
            can_set_mtime: false,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                min_bytes,
                max_bytes: self.max_part_bytes,
                max_parts: self.max_parts,
                max_object_bytes: self.max_object_bytes,
                require_equal_non_final_parts: self.require_equal_non_final_parts,
            },
            single_shot_max_bytes: single_shot_override
                .unwrap_or(self.default_single_shot_max_bytes),
            default_chunk_size: chunk_override.unwrap_or(self.default_chunk_size),
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: true,
            supports_ordered_utf8_list: true,
            supports_conditional_write: self.supports_if_none_match,
            supports_change_feed: false,
            supports_server_side_copy: true,
            default_write_qps: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_matrix_encodes_aws_r2_minio_oss_b2_distinctly() {
        let aws = S3Provider::Aws.profile();
        assert_eq!(aws.max_object_bytes, 50_000 * GIB);
        assert!(aws.supports_crc64nvme);
        assert!(!aws.require_equal_non_final_parts);
        assert!(aws.supports_if_none_match);

        let r2 = S3Provider::R2.profile();
        assert_eq!(r2.max_part_bytes, 5 * GIB - 5 * MIB);
        assert_eq!(r2.max_object_bytes, 5 * TIB - 5 * GIB);
        assert!(!r2.supports_crc64nvme);
        assert!(r2.supports_crc32c);
        assert!(!r2.supports_single_part_crc32c);
        assert!(r2.require_equal_non_final_parts);
        assert!(r2.supports_if_none_match);

        let minio = S3Provider::Minio.profile();
        assert!(minio.default_force_path_style);
        assert!(!minio.supports_crc64nvme);
        assert!(minio.supports_single_part_crc32c);

        let oss = S3Provider::Oss.profile();
        assert_eq!(oss.default_region, "cn-hangzhou");
        assert!(!oss.default_force_path_style);
        assert!(!oss.supports_crc64nvme);

        let wasabi = S3Provider::Wasabi.profile();
        assert!(!wasabi.supports_if_none_match);
        assert!(!wasabi.supports_if_match_write);

        let b2 = S3Provider::B2.profile();
        assert_eq!(b2.max_object_bytes, 10 * TIB);
        assert!(!b2.supports_crc64nvme);
        assert!(b2.hashes.contains(&HashKind::Sha1));
    }
}
