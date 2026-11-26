//! Production-grade S3-compatible storage backend for `rship`.
//!
//! Covers AWS S3, Cloudflare R2, MinIO, Alibaba OSS, Backblaze B2, and generic
//! S3-compatible endpoints via an explicit provider capability matrix:
//! - Pure-Rust AWS Signature Version 4 (`AWS4-HMAC-SHA256`) with strict RFC 3986
//!   URI encoding (`TestMergeDeleteMarkersWithURLEncodedKeys`).
//! - Default `UNSIGNED-PAYLOAD` over HTTPS; automatic payload SHA-256 over plain
//!   HTTP or `strict_sigv4 = true` (no buggy `aws-chunked` trailers by default).
//! - Provider-scoped checksums (`CRC64NVME` only where supported, `CRC32C`, `SHA256`, `MD5`)
//!   without ever mistaking multipart ETags (`"...-N"`) for file MD5.
//! - Paginated `ListParts` resume verification against locked `planned_chunk_size`,
//!   HTTP `200 OK` `<Error>` XML inspection on `CompleteMultipartUpload`,
//!   `x-amz-meta-rship-op-id` ambiguous-commit reconciliation, `AbortMultipartUpload` GC,
//!   version-pinned `If-Match` `Range` downloads, and `rclone.conf` S3 import.

pub mod backend;
pub mod checksum;
pub mod config;
pub mod credentials;
pub mod error;
pub mod provider;
pub mod rclone_import;
pub mod sigv4;
pub mod xml;

pub use backend::{MultipartUploadInfo, S3Backend};
pub use checksum::{crc32c, crc32c_base64, crc64_nvme, crc64_nvme_base64, hash_seekable_sha256};
pub use config::{
    PayloadSigningMode, S3Config, S3Credentials, S3ServerSideEncryption, infer_content_type,
};
pub use credentials::{S3CredentialProvider, S3CredentialSource};
pub use error::{S3ErrorCode, classify_s3_error};
pub use provider::{ProviderProfile, S3Provider};
pub use rclone_import::{ImportedRcloneS3, RcloneS3ImportReport, parse_rclone_s3_conf};
pub use sigv4::{
    UNSIGNED_PAYLOAD, aws_uri_encode, aws_uri_encode_path, decode_s3_url_encoded_key, hmac_sha256,
    sha256_hex, sign_v4_request,
};
