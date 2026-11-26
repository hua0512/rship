//! Full conformance and rclone-derived corner-case tests for [`GcsBackend`]
//! against a strict in-process mock Google Cloud Storage JSON API v1 server.
//!
//! Covers:
//! - Full `run_backend_conformance` matrix
//! - Strict single-segment `%2F`/`%23`/`%3F`/`%2B`/`%25`/UTF-8 object encoding
//! - `md5Hash` (base64 -> hex) and `crc32c` (base64 -> hex) metadata checksums
//! - `ifGenerationMatch=0` conditional create precondition (412 Conflict)
//! - 256 KiB-aligned `uploadType=resumable` with `308 Resume Incomplete` (both missing `Range`
//!   and `Range: bytes=0-N`), `499` session abort, and `rship-op-id` reconciliation
//! - Multi-step `rewriteTo` server-side copy looping across `rewriteToken` until `done == true`

#[path = "../common/mod.rs"]
mod common;

mod conformance;
mod faults_and_checksums;
mod lost_response;
mod mock_server;
