//! Full conformance and rclone-derived corner-case tests for [`DropboxBackend`]
//! against a strict in-process mock Dropbox v2 API + Content server.
//!
//! Covers:
//! - Full `run_backend_conformance` matrix
//! - Strict ASCII-only `Dropbox-API-Arg` header validation with UTF-16 surrogate pairs (emoji & CJK)
//! - 4 MiB SHA-256 block-tree `content_hash` verification
//! - `409 incorrect_offset` crash-resume recovery across multi-chunk upload sessions
//! - `429 too_many_write_operations` automatic retry backoff
//! - Server-side `copy_v2`, in-place `move_v2` (`rename`), `delete_batch`, and `about()` quota

#[path = "../common/mod.rs"]
mod common;

mod conformance;
mod faults_and_checksums;
mod lost_response;
mod mock_server;
