//! Full conformance and rclone-derived corner-case tests for [`AzureBlobBackend`]
//! against a strict in-process mock Azure Blob Storage (`2023-11-03`) server.
//!
//! Covers:
//! - Cryptographic SharedKey HMAC-SHA256 verification on EVERY request (returns 403 on mismatch!)
//! - Full `run_backend_conformance` matrix
//! - Parallel `Put Block` (`UploadTopology::ParallelParts`) + equal-length block ID validation
//!   + `Get Block List` uncommitted-block crash-resume + `Put Block List` commit
//! - `x-ms-copy-source` async `pending -> success` status polling server-side copy + `rename`
//! - SAS token authentication, XML special characters (`&`, `<`, `>`, Unicode), and `<NextMarker>` pagination

#[path = "../common/mod.rs"]
mod common;

mod audit_fixes;
mod body_stall;
mod conformance;
mod faults_and_checksums;
mod lost_response;
mod mock_server;
