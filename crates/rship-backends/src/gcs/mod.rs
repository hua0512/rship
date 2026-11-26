//! Google Cloud Storage (GCS) JSON API v1 [`rship_core::backend::StorageBackend`].
//!
//! Supports Service Account RS256 JWT (via shared [`crate::common::google_sa`]),
//! OAuth2 Desktop PKCE loopback, static bearer token, and anonymous public buckets;
//! strict `%2F` object-name URL encoding; streaming single-shot `uploadType=multipart`
//! and 256 KiB-aligned `uploadType=resumable` with `308 Resume Incomplete` recovery;
//! multi-step `rewriteTo` (`rewriteToken`) server-side copy; native `MD5` and `CRC32C`
//! metadata checksums; conditional `ifGenerationMatch=0` creates; and `rclone.conf`
//! (`type = google cloud storage`) import.

pub mod auth;
pub mod backend;
pub mod config;
pub mod rclone_import;

pub use auth::{
    FileGcsTokenStore, GcsAuthProvider, GcsOAuth2Auth, GcsPkceFlow, GcsToken, GcsTokenStore,
    ServiceAccountAuthProvider, ServiceAccountKey,
};
pub use backend::GcsBackend;
pub use config::{
    DEFAULT_GCS_API_URL, DEFAULT_GCS_AUTH_URL, DEFAULT_GCS_CHUNK_SIZE, DEFAULT_GCS_SCOPE,
    DEFAULT_GCS_SINGLE_SHOT_MAX, DEFAULT_GCS_TOKEN_URL, DEFAULT_GCS_UPLOAD_URL,
    GCS_CHUNK_ALIGN_BYTES, GcsConfig, gcs_encode_object_name, resolve_gcs_endpoint_urls,
    resolve_gcs_scope,
};
pub use rclone_import::{ImportedRcloneGcs, RcloneGcsImportReport, parse_rclone_gcs_conf};
