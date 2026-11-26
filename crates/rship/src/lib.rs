//! # `rship` — Cross-Platform, Low-Memory Multi-Cloud Transfer & Sync SDK
//!
//! `rship` provides an ergonomic, production-hardened Rust SDK on top of the
//! modular `rship-*` workspace (`rship-core`, `rship-backends`, `rship-transport`,
//! `rship-state`, and `rship-crypto`).
//!
//! ## Quick Start
//!
//! Add `rship` with only the backends and features you need:
//!
//! ```toml
//! [dependencies]
//! # Default: lightweight local-only SDK (zero HTTP, zero SQLite, zero keyring):
//! rship = { git = "https://github.com/hua0512/rship" }
//!
//! # Production Google Drive + Local with durable SQLite crash-resumption:
//! rship = { git = "https://github.com/hua0512/rship", features = ["gdrive", "sqlite"] }
//! ```
//!
//! ## Example: Copy & Move Explicit Files with Push Events
//!
//! ```rust
//! # #[cfg(feature = "local")]
//! # #[tokio::main]
//! # async fn main() -> rship::Result<()> {
//! use rship::prelude::*;
//! use std::sync::{Arc, Mutex};
//!
//! let tmp = tempfile::tempdir().unwrap();
//! let src = tmp.path().join("src");
//! let dst = tmp.path().join("dst");
//! std::fs::create_dir_all(&src).unwrap();
//! std::fs::create_dir_all(&dst).unwrap();
//! std::fs::write(src.join("clip.mp4"), b"video-bytes").unwrap();
//! std::fs::write(src.join("live.flv"), b"still-recording").unwrap();
//!
//! let client = RshipClient::ephemeral()?;
//! let seen = Arc::new(Mutex::new(Vec::new()));
//! let seen_c = seen.clone();
//!
//! let report = client
//!     .move_files(src.as_path(), dst.as_path(), ["clip.mp4"])
//!     .on_event(move |ev| {
//!         if let TransferEvent::FileCompleted { result, .. } = ev {
//!             seen_c.lock().unwrap().push(result.path);
//!         }
//!     })
//!     .run()
//!     .await?;
//!
//! assert!(report.is_success());
//! assert_eq!(report.files_transferred, 1);
//! assert_eq!(report.sources_deleted, 1);
//! assert!(dst.join("clip.mp4").exists());
//! assert!(src.join("live.flv").exists()); // Untouched sibling file
//! assert_eq!(seen.lock().unwrap().as_slice(), &["clip.mp4"]);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "local"))]
//! # fn main() {}
//! ```
//!
//! ## Programmatic Remote Builders & Secret Redaction
//!
//! All `*RemoteConfig` structs are `#[non_exhaustive]`, expose fluent `with_*` builders,
//! redact inline secrets automatically in `Debug`, and convert directly into [`RemoteConfig`]:
//!
//! ```rust
//! use rship::prelude::*;
//!
//! let cfg = AppConfig::new()
//!     .with_remote(
//!         "r2",
//!         S3RemoteConfig::new("r2")
//!             .with_bucket("backups")
//!             .with_endpoint("https://example.r2.cloudflarestorage.com")
//!             .with_credentials("AKIA_PUBLIC", "super-secret"),
//!     )
//!     .with_remote(
//!         "vault",
//!         CryptRemoteConfig::new("r2:encrypted").with_password("passphrase"),
//!     );
//!
//! let debug_out = format!("{cfg:?}");
//! assert!(!debug_out.contains("super-secret"));
//! assert!(!debug_out.contains("passphrase"));
//! ```
//!
//! ## Architecture & Feature Flags
//!
//! - **Lazy runtime**: [`RshipClient`] initializes `HttpTransport` only for HTTP cloud remotes
//!   (local & SFTP paths pay zero TLS/HTTP startup cost) and opens SQLite `StateActor` lazily
//!   only on durable journal or delta-inventory operations.
//! - **`local`** — OS-native fast-copy local filesystem backend (zero HTTP deps).
//! - **`gdrive` / `s3` / `webdav` / `onedrive` / `dropbox` / `gcs` / `azureblob`** —
//!   feature-gated cloud backends sharing a split-plane HTTP transport (`http`).
//! - **`sftp`** — SSH/SFTP backend (`russh`, zero HTTP deps).
//! - **`crypt`** — seekable STREAM OAE2 (`XChaCha20-Poly1305`) encryption overlay.
//! - **`sqlite`** — WAL-mode crash-resumable `StateActor` & disk-backed `SqliteSyncIndex`.
//! - **`keyring`** — OS Keyring secret resolution (`keyring://rship/<slot>`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod config;
pub mod factory;
pub mod prelude;
pub mod secrets;

/// Re-export of the core zero-I/O engine, planner, filter, and trait contracts.
pub use rship_core as core;

/// Re-export of feature-gated storage backend implementations.
pub use rship_backends as backends;

/// Re-export of the split-plane HTTP transport, CUBIC rate limiter, and OAuth primitives.
#[cfg(feature = "http")]
pub use rship_transport as transport;

/// Re-export of the durable SQLite `StateActor`, `SqliteSyncIndex`, and `ProcessLock`.
#[cfg(feature = "sqlite")]
pub use rship_state as state;

/// Re-export of the STREAM OAE2 seekable encryption overlay.
#[cfg(feature = "crypt")]
pub use rship_crypto as crypto;

pub use client::{
    BisyncBuilder, ClientBuilder, ResolvedTarget, RshipClient, TransferBuilder, TransferTarget,
};
pub use config::{
    AppConfig, AppPaths, AzureblobRemoteConfig, CryptRemoteConfig, DefaultsConfig,
    DropboxRemoteConfig, GcsRemoteConfig, GdriveRemoteConfig, LocalRemoteConfig,
    OnedriveRemoteConfig, RemoteConfig, RuntimeOptions, S3RemoteConfig, SftpRemoteConfig,
    TransferOptions, TransferProfile, WebdavRemoteConfig,
};
pub use rship_core::{Error, ErrorCategory, ErrorKind, FsyncMode, Result, RetryClass};
