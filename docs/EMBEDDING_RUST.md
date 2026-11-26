# Production CLI & Rust SDK Embedding Guide (`rship`)

This guide shows how to replace `rclone` with `rship` in automated high-throughput upload pipelines (such as `rust-srec` on Docker hosts) using **either** the standalone CLI **or** the top-level **`rship`** Rust SDK crate.

---

## Option A: Production CLI Replacement (Headless / Docker)

### 1. One-Time Migration from `rclone.conf`

```bash
rship --config /app/config/rship.toml --state-dir /app/state \
  config import-rclone /app/config/rclone.conf
```

All Google Drive accounts (`gdrive2`..`gdrive6`), custom OAuth `client_id`/`client_secret`, Service Accounts, and tokens are imported with `0600` permissions into `/app/config/rship.toml` and `/app/state/tokens/<remote>.json`.

### 2. CLI Flag Mapping (`rclone` → `rship`)

| Operation | `rship` Command |
| :--- | :--- |
| **Idempotent `mkdir`** | `rship --config /app/config/rship.toml --state-dir /app/state --tpslimit 8 mkdir gdrive2:streamer/2026-11` |
| **Single-file `moveto`** | `rship --config ... --state-dir ... --drive-stop-on-upload-limit --tpslimit 8 moveto /rec/a.xml gdrive2:streamer/2026-11/a.xml --bwlimit 20M --chunk-size 128M --retries 1 --json --json-progress --stats 1s` |
| **Batch `--files-from` `move`** | `rship --config ... --state-dir ... --drive-stop-on-upload-limit --tpslimit 8 move /rec gdrive2:streamer/2026-11 --files-from /tmp/files.txt --no-traverse --bwlimit 20M --chunk-size 128M --retries 1 --json --json-progress --stats 1s` |

Key production guarantees:
- **Zero directory scan on `--files-from`**: `rship` directly `stat`s only the listed relative paths (skipping sibling in-progress `.flv` recordings and eliminating remote `files.list` / `changes.list` API calls).
- **Safe concurrent subprocesses**: Advisory `ProcessLock` is scoped per file (`moveto`), per `--files-from` batch, or per sub-prefix (and can be disabled via `--no-lock`). `StateActor` uses busy-timeout-first SQLite WAL initialization with non-blocking checkpoints, and `FileTokenStore` writes unique per-PID temp files with atomic replacement.
- **Fast-fail on 750 GiB/day quota**: `--drive-stop-on-upload-limit` converts `403 userRateLimitExceeded` on upload endpoints directly to permanent `QuotaExceeded` (exit `8`, `"error_kind": "quota_exceeded"`), while `403 rateLimitExceeded` QPS bursts still retry with CUBIC backoff.
- **Cross-restart 8.5 GiB+ resume**: Active resumable `session_uri` and `confirmed_offset` persist in `journal.db`; re-running the exact same `move`/`moveto` command automatically resumes via Google Drive `308` instead of restarting from byte 0.
- **Graceful `SIGTERM` & `SIGINT`**: Cancels in-flight transfers (including immediate wakeup from retry backoff), flushes SQLite WAL, preserves resumable sessions, exits `130`, and never deletes local source files before verified remote commit.
- **Structured telemetry**: `--json-progress --stats 1s` streams JSONL progress events (`event`, `phase`, `bytes_done`, `bytes_total`, `speed_bps`, `eta_secs`, `files_done`, `files_total`, `current_file`, `active_files`) to `stderr`, while `--json` writes one final summary JSON with per-file attribution (`"files": [...]`) to `stdout`.

---

## Option B: Ergonomic Rust SDK Embedding (`rship` Facade Crate — Recommended)

Embedding the top-level **`rship`** crate directly into your Tokio service eliminates subprocess spawning, JSON parsing, and cross-process locking while sharing a single `HttpTransport`, per-account `ScopedLimiter`, `dir_id_cache`, `mkdir_locks`, `BufferPool`, and WAL-mode `StateActor` across all upload workers.

### 1. Minimal `Cargo.toml` (Compile Only the Backends You Need)

```toml
[dependencies]
# Default: minimal local-only SDK (zero HTTP, zero SQLite, zero keyring):
rship = { git = "https://github.com/hua0512/rship" }

# Production Local + Google Drive + durable SQLite crash-resumption (no S3/SFTP/Azure/keyring):
rship = { git = "https://github.com/hua0512/rship", features = ["gdrive", "sqlite"] }
```

### 2. High-Level `RshipClient`: `rclone.conf` / `config.toml`, `move_files`, Push Events & Shutdown

```rust
use rship::prelude::*;

pub async fn run_pipeline() -> Result<()> {
    // Load existing rclone.conf (or .config_file("/app/config/rship.toml"))
    let client = RshipClient::builder()
        .rclone_conf("/app/config/rclone.conf")
        .state_dir("/app/state")
        .tps_limit(10.0)
        .gdrive_stop_on_upload_limit(true)
        .gdrive_low_level_retries(3)
        .build()?;

    let cancel = CancelFlag::new();

    // Direct-stat verified move over explicit [clip.jpg, clip.mp4] — never scans live .flv files!
    let report = client
        .move_files("/recordings", "gdrive2:streamer/2026-11", ["clip.jpg", "clip.mp4"])
        .bwlimit(20 * 1024 * 1024)
        .chunk_size(128 * 1024 * 1024)
        .retries(1)
        .cancel_on(cancel.clone())
        .on_event(|ev| match ev {
            TransferEvent::PhaseChanged { phase, .. } => tracing::info!(%phase, "phase"),
            TransferEvent::FileCompleted { result, .. } => tracing::info!(?result, "file done"),
            _ => {}
        })
        .run()
        .await?;

    assert!(report.is_success());

    // Exact single-file moveto for sidecar XML
    let xml_report = client
        .move_file("/recordings/clip.xml", "gdrive2:streamer/2026-11/clip.xml")
        .bwlimit(20 * 1024 * 1024)
        .retries(1)
        .run()
        .await?;
    assert!(xml_report.is_success());

    // Wait for any in-flight jobs, flush SQLite WAL, and join background actor thread
    client.shutdown().await?;
    Ok(())
}
```

### 3. Programmatic Remote Configuration & Lazy Resource Initialization

All declarative remote config types (`S3RemoteConfig`, `GdriveRemoteConfig`, `GcsRemoteConfig`, `AzureblobRemoteConfig`, `OnedriveRemoteConfig`, `DropboxRemoteConfig`, `WebdavRemoteConfig`, `SftpRemoteConfig`, `CryptRemoteConfig`) are `#[non_exhaustive]`, redact secrets automatically in `Debug`, and convert directly into `RemoteConfig` via `Into<RemoteConfig>`:

```rust
use rship::prelude::*;

pub async fn sync_encrypted_to_r2() -> Result<RunReport> {
    let client = RshipClient::builder()
        .ephemeral()
        .remote(
            "r2",
            S3RemoteConfig::new("r2")
                .with_bucket("media-archive")
                .with_endpoint("https://<account-id>.r2.cloudflarestorage.com")
                .with_credentials("AKIA...", "secret-key"),
        )
        .remote(
            "vault",
            CryptRemoteConfig::new("r2:encrypted")
                .with_password("strong-passphrase"),
        )
        .build()?;

    let report = client
        .sync("/var/backups", "vault:daily")
        .delete_mode(DeleteMode::After)
        .backup_dir("vault:deleted-archive")
        .bwlimit_schedule("08:00,20M 23:00,off".parse()?)
        .run()
        .await?;

    client.shutdown().await?;
    Ok(report)
}
```

Key `RshipClient` runtime guarantees:
- **Lazy `HttpTransport` & `StateActor`**: Local filesystem and SFTP targets never load TLS root certificates or initialize HTTP connection pools. Read-only operations (`stat`, `list`, `resolve_any`) never open `journal.db` or spawn the background SQLite thread — durable state opens lazily only on transfers, `bisync`, GDrive `changes.list`, or explicit `client.journal()` / `client.state_actor()` calls.
- **Unified directory-or-file resolution**: `client.resolve_any(target).await?` returns a `ResolvedTarget` (`backend`, `prefix`, `single_file`) for both local paths and cloud specs.
- **Forward-compatible public API**: Config structs, `RuntimeOptions`, `ResolvedTarget`, `RunReport`, `BisyncReport`, `TransferEvent`, `ErrorKind`, and `RetryClass` are all marked `#[non_exhaustive]` with fluent builder constructors.

### 4. Multi-Account 750 GiB/day Quota Failover (`FailoverPool`)

```rust
use rship::prelude::*;

pub async fn upload_with_account_failover(
    client: &RshipClient,
    local_dir: &str,
    remote_prefix: &str,
    files: &[&str],
    cancel: CancelFlag,
) -> Result<(String, RunReport)> {
    let pool = client.failover_pool(&["gdrive2", "gdrive3", "gdrive4", "gdrive5", "gdrive6"])?;
    let dst_rel = RelPath::parse(remote_prefix)?;

    pool.run_with_failover(
        DEFAULT_QUOTA_COOLDOWN,
        DEFAULT_THROTTLE_COOLDOWN,
        |acct_name, backend| {
            let client = client.clone();
            let dst = TransferTarget::backend(backend, dst_rel.clone());
            let files: Vec<String> = files.iter().map(|s| (*s).to_string()).collect();
            let cancel = cancel.clone();
            async move {
                let rep = client
                    .move_files(local_dir, dst, files)
                    .bwlimit(20 * 1024 * 1024)
                    .chunk_size(128 * 1024 * 1024)
                    .retries(1)
                    .cancel_on(cancel)
                    .run()
                    .await?;

                if rep
                    .file_results
                    .iter()
                    .any(|r| r.error_kind == Some(ErrorKind::QuotaExceeded))
                {
                    return Err(Error::quota_exceeded(format!(
                        "account `{acct_name}` reached daily upload quota"
                    )));
                }
                Ok(rep)
            }
        },
    )
    .await
}
```

### 5. Low-Level Crate Composition (Full Control)

All underlying crates remain accessible directly via `rship::core`, `rship::backends`, `rship::transport`, `rship::state`, and `rship::crypto` (or as standalone crates) whenever you need custom `StorageBackend`, `JournalStore`, `EventSink`, or deterministic `VirtualClock` / `ChaosBackend` testing.
