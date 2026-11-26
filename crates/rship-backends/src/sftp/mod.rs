//! SSH/SFTP storage backend (`russh` + `russh-sftp`).
//!
//! - Constant-memory streaming reads (`RemoteRangeReadable`) and offset writes.
//! - True cross-restart crash-resumable uploads via sibling `.rship.part.<op_id>`
//!   staging files, live remote size/offset checks (`query_upload`), mtime
//!   preservation, and atomic `posix-rename@openssh.com` publication.
//! - Supports `statvfs@openssh.com` quota reporting (`about`) and `rclone.conf` import.
//! - No content checksums: SFTP has no remote hash, so transfers are length-checked only
//!   (unverified end to end).

pub mod backend;
pub mod config;
pub mod rclone_import;

pub use backend::SftpBackend;
pub use config::{
    DEFAULT_SFTP_CHUNK_SIZE, DEFAULT_SFTP_SINGLE_SHOT_MAX, HostKeyPolicy, SftpAuth, SftpConfig,
};
pub use rclone_import::{
    ImportedSftpRemote, RcloneSftpImportReport, parse_rclone_sftp_conf, try_parse_rclone_sftp_conf,
};
