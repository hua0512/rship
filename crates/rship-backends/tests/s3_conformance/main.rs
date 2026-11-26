//! End-to-end S3-compatible backend conformance & corner-case integration suite
//! driven against a faithful in-process mock S3 HTTP server with real SigV4 verification.

#[path = "../common/mod.rs"]
mod common;

mod audit_conformance;
mod body_stall;
mod checksums;
mod crud_and_listing;
mod faults;
mod mock_server;
mod multipart_and_copy;
mod multipart_checksums;
mod retry_quota;
