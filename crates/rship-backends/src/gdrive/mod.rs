//! Production-grade Google Drive v3 storage backend for `rship`.
//!
//! Features & protocol invariants:
//! - OAuth2 Desktop PKCE loopback (`127.0.0.1:0`, no deprecated OOB) with
//!   user-owned `client_id`/`client_secret`, token persistence, single-flight
//!   `401` refresh preserving active `session_uri`, and headless export/import.
//! - Service Account `RS256` JWT authentication with Shared Drive
//!   (`supportsAllDrives=true&includeItemsFromAllDrives=true`) and Domain-Wide
//!   Delegation (`sub`).
//! - Zero-big-buffer streaming uploads:
//!   - `<= 5 MiB`: 1-request `uploadType=multipart` (`multipart/related`).
//!   - `> 5 MiB`: `uploadType=resumable` (default `256 MiB`, strict `256 KiB`
//!     alignment), pre-generated `fileId` (`files.generateIds`) for create
//!     reconciliation, `PATCH /upload/drive/v3/files/{fileId}` for overwrites.
//!   - Exact `308 Resume Incomplete` recovery (missing `Range` = `0`,
//!     `bytes=0-N` -> `N + 1`, `query_upload` always carries
//!     `?fields=...&supportsAllDrives=true`, `404`/`410` triggers reconciliation).
//! - Segmented per-path `mkdir` locking, strict `'`/`\` Drive query escaping,
//!   explicit `fields` masks, `trashed = false` filtering, Workspace native Docs
//!   skipping, Shortcut cycle detection, exact `403` `error.errors[].reason`
//!   classification, and `changes.list` ID-graph incremental sync.

pub mod auth;
pub mod backend;
pub mod changes;
pub mod config;
pub mod error;
pub mod query;
pub mod rclone_import;

pub use auth::{
    AuthExportBundle, AuthProvider, FileTokenStore, InMemoryTokenStore, OAuth2AuthProvider,
    OAuthToken, PkceFlow, PkceSession, ServiceAccountAuthProvider, ServiceAccountKey,
    StaticBearerAuth, TokenStore,
};
pub use backend::GdriveBackend;
pub use changes::{ChangesSyncReport, InMemoryGdriveStore};
pub use config::{GdriveConfig, resolve_gdrive_scope};
pub use error::{GdriveErrorReason, classify_gdrive_error};
pub use query::{
    FOLDER_MIME, SHORTCUT_MIME, escape_query_literal, is_exportable_workspace_doc,
    parse_content_range_308,
};
pub use rclone_import::{ImportedRcloneGdrive, RcloneImportReport, parse_rclone_conf};
