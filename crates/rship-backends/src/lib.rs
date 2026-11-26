//! Unified, feature-gated multi-cloud [`rship_core::backend::StorageBackend`]
//! implementations for `rship`.
//!
//! Each storage provider lives in its own feature-gated module so consumers and
//! minimal builds compile ONLY the dependencies required by enabled providers
//! (e.g. `sftp` is the only feature pulling `russh` / `russh-sftp`; `gdrive` and
//! `gcs` share `rsa` for Google Service Account JWT; `local` compiles with zero HTTP stack).

#[cfg(any(
    feature = "local",
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "sftp",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
#[doc(hidden)]
pub mod common;

#[cfg(feature = "local")]
pub mod local;

#[cfg(feature = "gdrive")]
pub mod gdrive;

#[cfg(feature = "s3")]
pub mod s3;

#[cfg(feature = "webdav")]
pub mod webdav;

#[cfg(feature = "onedrive")]
pub mod onedrive;

#[cfg(feature = "sftp")]
pub mod sftp;

#[cfg(feature = "dropbox")]
pub mod dropbox;

#[cfg(feature = "gcs")]
pub mod gcs;

#[cfg(feature = "azureblob")]
pub mod azureblob;
