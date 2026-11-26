//! Cross-platform, constant-memory WebDAV storage backend supporting Nextcloud,
//! OwnCloud, Alist, Synology NAS, InfiniCloud, and standard RFC 4918 WebDAV servers.
//!
//! - Uses `rship-transport` split Control Plane (HTTP/2) and Data Plane (HTTP/1.1)
//!   so bulk uploads/downloads stream at constant memory without RAM buffering.
//! - Supports **Nextcloud / OwnCloud Chunked Upload v2** for crash-resumable
//!   uploads across restarts (`MKCOL` -> `PUT` numbered chunks -> `PROPFIND` recovery -> `MOVE .file`).
//! - Supports zero-bandwidth server-side `COPY`, HTTP `Range` (`RemoteRangeReadable`),
//!   and RFC 4331 `PROPFIND` storage quota reporting (`about`).

pub mod backend;
pub mod config;
pub mod rclone_import;
pub mod xml;

pub use backend::WebdavBackend;
pub use config::{WebdavAuth, WebdavChunkNaming, WebdavConfig, WebdavVendor};
pub use rclone_import::{
    ImportedWebdavRemote, RcloneWebdavImportReport, parse_rclone_webdav_conf,
    try_parse_rclone_webdav_conf,
};
