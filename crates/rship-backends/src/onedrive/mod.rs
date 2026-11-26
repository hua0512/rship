//! Production constant-memory Microsoft OneDrive (Personal, Business & SharePoint)
//! backend on Microsoft Graph API v1.0.
//!
//! - Uses `rship-transport` split Control Plane (HTTP/2) and Data Plane (HTTP/1.1).
//! - Desktop OAuth2 PKCE loopback (`127.0.0.1:0`) with single-flight `401` token refresh.
//! - Small files (`<= 4 MiB`): 1-request `PUT /content`.
//! - Large files (`> 4 MiB`): crash-resumable `createUploadSession` with strict
//!   **320 KiB** chunk alignment (up to `60 MiB` chunks) and `nextExpectedRanges` recovery.
//! - Zero-bandwidth server-side copy (`POST /items/{id}/copy` async monitor polling),
//!   HTTP `Range` downloads (`RemoteRangeReadable`), `sha256`/`sha1` checksums, streaming
//!   QuickXorHash upload/download verification, and quota `about`.

pub mod auth;
pub mod backend;
pub mod config;
pub mod quickxor;
pub mod rclone_import;

pub use auth::{
    FileOnedriveTokenStore, OnedriveAuthProvider, OnedriveOAuth2Auth, OnedrivePkceFlow,
    OnedriveToken, OnedriveTokenStore,
};
pub use backend::OnedriveBackend;
pub use config::{
    DEFAULT_GRAPH_API_URL, DEFAULT_ONEDRIVE_AUTH_URL, DEFAULT_ONEDRIVE_CHUNK_SIZE,
    DEFAULT_ONEDRIVE_SCOPE, DEFAULT_ONEDRIVE_SINGLE_SHOT_MAX, DEFAULT_ONEDRIVE_TOKEN_URL,
    MAX_ONEDRIVE_CHUNK_BYTES, ONEDRIVE_CHUNK_ALIGN_BYTES, OnedriveConfig, OnedriveDriveType,
    OnedriveRegion,
};
pub use rclone_import::{
    ImportedOnedriveRemote, RcloneOnedriveImportReport, parse_rclone_onedrive_conf,
    try_parse_rclone_onedrive_conf,
};
