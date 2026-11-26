# Adding a New Storage Provider to `rship`

`rship` keeps its workspace permanently lean at **7 crates** (`rship`, `rship-core`, `rship-state`, `rship-transport`, `rship-crypto`, `rship-backends`, `rship-cli`) while shipping **10 built-in providers** (`local`, `gdrive`, `s3` with 12 presets, `dropbox`, `gcs`, `azureblob`, `onedrive`, `webdav`, `sftp`, `crypt`). Adding another storage provider does **not** require creating a new crate — add a feature-gated module inside `crates/rship-backends/src/<name>/`, wire its config/factory once in `crates/rship`, and register a thin `ProviderAdapter` in `crates/rship-cli`.

---

## Core Invariants Every Provider Must Uphold

1. **Low Memory Footprint (`<= 64 MiB` typical RSS via bounded streaming)**:
   - Never collect a full directory listing or arbitrarily large file payload into RAM.
   - Stream directory entries through a bounded `tokio::sync::mpsc::channel(256)` (`EntryStream`).
   - Stream uploads from `ByteStream` directly into the transport (`reqwest::Body::wrap_stream` on `transport.data_client()` or chunked socket writes), preserving `Bytes::from_owner(PooledSlice)` backpressure. (Small bounded fast paths like S3's `<= 4 MiB` strict-SigV4 buffer are fine when capped.)
   - Implement `open_read` returning `DataSource::RemoteRangeReadable` so cloud-to-cloud relays transfer directly between providers without local disk spill or RAM buffering.
2. **Cross-Restart Crash-Resumable Uploads**:
   - Declare exact geometry in `Capabilities` (`UploadTopology::Sequential` or `UploadTopology::ParallelParts`, `ChunkAlignment`, `single_shot_max_bytes`, `default_chunk_size`).
   - Implement `begin_upload` → `query_upload` → `upload_chunk` → `finish_upload` → `abort_upload` → `reconcile_operation`.
   - `query_upload` must inspect live remote progress (`SequentialOffset(n)` or `CompletedParts(parts)`) so resuming after `SIGKILL` retransmits at most one uncheckpointed chunk/part.
   - Never corrupt or overwrite an existing destination object when an upload stream hits early EOF or mid-stream error.
3. **Shared Reusable Infrastructure**:
   - Reuse `rship-transport::HttpTransport` (HTTP/2 Control Plane + `.http1_only()` Data Plane + `--proxy` + `--ca-cert` + `ProgressWatchdog` + CUBIC `ScopedLimiter`) for all HTTP/REST providers.
   - Reuse **`rship_transport::oauth`** (`PkceSession`, `OAuth2TokenManager`, `FileTokenStore`, `OAuthProvider`) for any OAuth2 cloud provider — zero duplicated PKCE loopback or single-flight `401` refresh logic.
   - Reuse **`rship_backends::common`** (`rx_to_entry_stream`, `StrictBodyStream`, `ExactDownloadStream`, `common::http`, `common::crc`, `common::google_sa`, and `common::xml`) to avoid protocol boilerplate.
   - Reuse **`rship_core::rclone_ini`** (`parse_rclone_ini`, `reveal_or_passthrough_rclone_secret`) for `rclone.conf` import with automatic AES-256-CTR obscured password decryption.
   - Reuse **`rship_core::state::DeltaInventoryStore`** if your provider supports incremental delta change feeds (e.g. Google Drive `changes.list`, OneDrive `/delta`).
   - Keep heavy protocol-specific dependencies optional under your feature in `crates/rship-backends/Cargo.toml` so minimal builds stay tiny and fast.

---

## 4-Step Recipe to Add Provider `foo`

### Step 1: Add Module `crates/rship-backends/src/foo/`
No new crate or workspace member is needed. Add your module inside `rship-backends`:

```text
crates/rship-backends/
├── Cargo.toml                  # Add feature `foo = [...]` (+ optional deps) and `[[test]]`
├── src/
│   ├── lib.rs                  # Add `#[cfg(feature = "foo")] pub mod foo;`
│   └── foo/
│       ├── mod.rs              # Re-export FooBackend, FooConfig, parse_rclone_foo_conf
│       ├── config.rs           # Typed config, defaults, chunk alignment constants
│       ├── auth.rs             # Optional thin wrapper over `rship_transport::oauth`
│       ├── backend.rs          # `impl StorageBackend for FooBackend` (or `backend/` dir)
│       └── rclone_import.rs    # Optional `rclone.conf` parser using `rship_core::rclone_ini`
└── tests/
    └── foo_conformance.rs      # `required-features = ["foo"]`
```

### Step 2: Implement `rship_core::backend::StorageBackend` & Run Conformance
Mandatory methods:
- Identity: `name`, `kind`, `endpoint_identity`, `capabilities`
- Namespace: `stat`, `list_stream`, `mkdir`, `delete`, `compute_hash`, `open_read`
- Uploads: `put_single_shot`, `begin_upload`, `query_upload`, `upload_chunk`, `finish_upload`, `abort_upload`, `reconcile_operation`

Optional high-value overrides (defaults work automatically):
- `delete_batch` (native bulk-delete API like S3 `DeleteObjects`)
- `can_server_side_copy_from` & `server_side_copy` (zero-bandwidth same-cloud copy/move)
- `about` (storage quota inquiry for `rship about`)
- `rename` (zero-bandwidth in-place rename for `rship dedupe --mode rename`)

In `crates/rship-backends/tests/foo_conformance.rs`, spin up an in-process mock/wire server and call:

```rust
rship_core::conformance::run_backend_conformance(Arc::new(backend), clock).await;
```

This single call verifies all 9 universal invariants (`0`-byte uploads, short EOF preserving existing objects, stream error preservation, shorter/longer overwrites, nested idempotent `mkdir`, `list` not-found/empty, idempotent `delete`, partial `Range` reads, and early stream drop leak freedom). Add 1–2 provider-specific tests (chunk alignment, crash-resume across restarts, rate-limit `429`, server-side copy).

Fast isolated test loop while developing:
```bash
cargo test -p rship-backends --no-default-features --features foo
```

### Step 3: Wire Type, Config & Factory Once in `rship-core` & `crates/rship` (Shared by SDK & CLI)
Because `rship-cli`'s `CliRuntime` wraps `RshipClient` directly, wiring your provider once in `rship-core` and `crates/rship` unlocks both embedded Rust SDK consumers and `rship-cli` simultaneously:

1. **`crates/rship-core/src/types.rs`**: Add `BackendKind::Foo` variant plus its `as_str()` and `parse()` arms.
2. **`crates/rship/Cargo.toml`**: Add feature `foo = ["rship-backends/foo", "http"]` (omit `"http"` for non-HTTP protocols like SFTP) and include `"foo"` in `all-backends`.
3. **`crates/rship/src/config.rs`**: Add `#[must_use] #[non_exhaustive] pub struct FooRemoteConfig` with `::new(...)` / fluent `with_*` builders, redacted `Debug`, `RemoteConfig::Foo(Box<FooRemoteConfig>)`, `RemoteConfig::foo(...)`, `From<FooRemoteConfig> for RemoteConfig`, and wire `kind()` + `visit_secrets` / `visit_secrets_mut` (the single source of truth powering redaction, inline-secret counting, keyring migration, and cleanup).
4. **`crates/rship/src/lib.rs` & `prelude.rs`**: Re-export `FooRemoteConfig`.
5. **`crates/rship/src/factory.rs`**: Wire `RemoteConfig::Foo` in `build_remote_backend`, `target_needs_transport` (if non-HTTP), and `import_rclone_conf` / `import_rclone_conf_in_memory` if supporting `rclone.conf`.

### Step 4: Register CLI Auth & Secret Lifecycle in `rship-cli`
1. **`crates/rship-cli/Cargo.toml`**: Add feature `backend-foo = ["rship/foo", "rship-backends/foo"]` and include it in `all-backends`.
2. **`crates/rship-cli/src/cli.rs`**: Add `FooAuthArgs` (`#[derive(Debug, Args)]`) and `AuthAction::Foo(FooAuthArgs)`.
3. **`crates/rship-cli/src/ops/config_ops.rs`**: Add display summary, provider description, ordering, and alias handling for `RemoteConfig::Foo`.
4. **`crates/rship-cli/src/providers/foo.rs`** + **`providers/mod.rs`**: Implement [`ProviderAdapter`](../crates/rship-cli/src/providers/mod.rs) (`kind`, `rclone_type`, optional `cleanup_secrets` for sidecar token files, `abort_gc_operation` via shared `abort_gc_for_remotes`, `export_bundle`, `import_bundle`) and `pub fn handle_auth(args: FooAuthArgs, ...)` (reusing `providers::oauth` helpers for OAuth2 PKCE providers), then register `&foo::FooAdapter` in `registered_providers()` and forward `AuthAction::Foo(args)` in `dispatch_provider_auth`.
   - Secret redaction, keyring migration, and keyring cleanup work **automatically** via `RemoteConfig::visit_secrets*`.
   - Backend instantiation and lazy transport/SQLite lifecycle route **automatically** through `CliRuntime` → `RshipClient`.
   - Once registered, `copy`, `copyto`, `sync`, `move`, `moveto`, `bisync`, `check`, `hashsum`, `dedupe`, `cat`, `rcat`, `about`, `size`, `tree`, `delete`, `purge`, `gc`, `config test|rm|show|import-rclone`, `auth export|import|keyring-migrate`, and `crypt` overlay remotes all work **automatically**.

Verify full workspace, minimal SDK, and isolated CLI feature builds:
```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p rship --no-default-features --features foo
cargo clippy -p rship-cli --no-default-features --features backend-local,backend-foo -- -D warnings
cargo test --workspace
```
