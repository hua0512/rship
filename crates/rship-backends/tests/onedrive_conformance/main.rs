//! Full conformance, 320 KiB resumable upload session crash-resume, async server-side
//! copy monitor polling, quota `about()`, and fault-injection tests against a mock
//! Microsoft Graph API server.

#[path = "../common/mod.rs"]
mod common;

mod conformance;
mod faults_and_checksums;
mod lost_response;
mod mock_server;
mod p0_p1_fixes;
