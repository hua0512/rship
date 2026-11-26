//! End-to-end Google Drive v3 conformance and corner-case integration suite
//! driven against a faithful in-process mock Google Drive v3 HTTP server.

#[path = "../common/mod.rs"]
mod common;

mod conformance;
mod faults_and_checksums;
mod mock_server;
mod tree_and_shortcuts;
