//! Dropbox v2 API [`rship_core::backend::StorageBackend`].
//!
//! Supports OAuth2 Desktop PKCE loopback (`token_access_type=offline`), streaming uploads
//! (`StrictBodyStream`), 4 MiB-aligned resumable upload sessions (`/files/upload_session/*`)
//! with `incorrect_offset` crash-resume recovery, ASCII-safe `Dropbox-API-Arg` UTF-16 escaping,
//! Dropbox 4 MiB SHA-256 block-tree `content_hash`, server-side copy (`/files/copy_v2`),
//! batch delete, in-place rename, storage quota (`about`), and `rclone.conf` import.

pub mod auth;
pub mod backend;
pub mod config;
pub mod hash;
pub mod rclone_import;

pub use auth::{
    DropboxAuthProvider, DropboxOAuth2Auth, DropboxPkceFlow, DropboxToken, DropboxTokenStore,
    FileDropboxTokenStore,
};
pub use backend::DropboxBackend;
pub use config::{
    DEFAULT_DROPBOX_API_URL, DEFAULT_DROPBOX_AUTH_URL, DEFAULT_DROPBOX_CHUNK_SIZE,
    DEFAULT_DROPBOX_CONTENT_URL, DEFAULT_DROPBOX_SINGLE_SHOT_MAX, DEFAULT_DROPBOX_TOKEN_URL,
    DROPBOX_CHUNK_ALIGN_BYTES, DropboxConfig, MAX_DROPBOX_CHUNK_BYTES,
};
pub use hash::{dropbox_content_hash, encode_dropbox_api_arg};
pub use rclone_import::{
    ImportedRcloneDropbox, RcloneDropboxImportReport, parse_rclone_dropbox_conf,
    try_parse_rclone_dropbox_conf,
};
