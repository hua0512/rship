# Contributing to `rship`

Thank you for contributing to **`rship`**! This guide covers local setup, toolchain/MSRV policy, developer tooling, testing, fuzzing, and live-cloud test configuration.

---

## 1. Prerequisites & Local Setup

- **Rust Toolchain (MSRV `1.100`)**: The repository pins Rust **`1.100.0`** (Edition `2024`) with `rustfmt` and `clippy` in [`rust-toolchain.toml`](rust-toolchain.toml). Running `cargo` in this repository automatically selects that toolchain via `rustup`.
- **Recommended developer tools** (optional, used by [`justfile`](justfile) and CI):
  ```bash
  cargo install --locked just cargo-nextest cargo-deny cargo-hack cargo-llvm-cov
  ```
  For fuzzing (requires nightly):
  ```bash
  rustup toolchain install nightly
  cargo install --locked cargo-fuzz
  ```

### MSRV Policy

`rship`'s Minimum Supported Rust Version is **Rust `1.100`** (`rust-version = "1.100"` in [`Cargo.toml`](Cargo.toml)). CI runs the **full workspace test suite** (not just `cargo check`) on Rust `1.100` in the `msrv-check` job. Avoid syntax or `std` APIs newer than `1.100` unless an MSRV bump is explicitly agreed upon.

---

## 2. Common Commands (`justfile`)

Run `just` with no arguments to see all recipes:

| Recipe | Command / Purpose |
| :--- | :--- |
| `just check` | `cargo check --workspace --all-targets --locked` |
| `just fmt` | Format all crates with `cargo fmt --all` |
| `just fmt-check` | Verify formatting (`cargo fmt --all -- --check`) |
| `just clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `just test` | Standard `cargo test --workspace --locked --no-fail-fast` |
| `just nextest` | Run `cargo nextest run --workspace --locked` + workspace doctests |
| `just doc` | Build library rustdoc with `RUSTDOCFLAGS="-D warnings"` (`--lib --no-deps --locked`) |
| `just msrv` | Run full workspace tests on Rust `1.100.0` |
| `just powerset` | `cargo hack --feature-powerset --depth 2 check --locked -p rship -p rship-backends` |
| `just deny` | Run `cargo deny check` (advisories, licenses, bans, sources) |
| `just cov` | Collect workspace LCOV coverage (`lcov.info`) via `cargo-llvm-cov nextest` |
| `just bench-scale` | Run 1M-row SQLite RSS check (`<= 64 MiB`) and S3/SQLite scale benchmarks |
| `just live-s3` | Run `s3_live_smoke` against a live S3/MinIO endpoint |
| `just fuzz-list` | List configured `cargo-fuzz` targets under `fuzz/` |
| `just ci` | Full local pre-push check (`fmt-check`, `clippy`, `doc`, `nextest`) |

---

## 3. Testing, Nextest & Supply-Chain Checks

### `cargo-nextest`

Configuration lives in [`.config/nextest.toml`](.config/nextest.toml):

- **`default` profile**: Clean per-test pass output, immediate + final failure summaries, and 30 s slow-timeout warnings.
- **`ci` profile**: `fail-fast = false`, exponential retries (`count = 2`) for transient socket/timing flakes, extended slow timeouts for acceptance benchmarks, and JUnit XML written to `target/nextest/ci/junit.xml`. DST, chaos and crash-sweep tests are never retried (`retries = 0`), so an interleaving failure fails CI instead of being reported as flaky.

> **Note:** `cargo-nextest` does not execute rustdoc doctests. Always run `cargo test --workspace --doc --locked` (or `just nextest`, which runs both).

### Deterministic Simulation Testing (DST) & Property Tests

`rship-core` and `rship-backends` include deterministic chaos/fault-injection suites and `proptest` suites. Nightly CI runs an expanded sweep using:

| Environment Variable | Default | Purpose |
| :--- | :--- | :--- |
| `RSHIP_DST_SEEDS` | `16` for the single-thread sweep; `8` for the pipelined/streaming-merge sweep and the multi-thread variants; `4` for the replay check | Number of deterministic PRNG fault-injection seeds executed in DST stress runs (nightly uses `64`) |
| `RSHIP_DST_SEED` | unset | Run exactly one seed. Single-thread DST tests replay a seed exactly (fault schedule, backoff jitter, virtual time). Multi-thread variants replay only the fault schedule; thread interleavings are not reproducible |
| `PROPTEST_CASES` | `256` | Number of generated `proptest` cases per property (nightly uses `512`) |

### `cargo-deny`

[`deny.toml`](deny.toml) enforces:

- **Advisories**: Fails on RustSec security vulnerabilities and unsound advisories; warns on yanked crates; checks workspace dependencies for unmaintained status.
- **Licenses**: Restricts dependencies to permissive OSI-approved licenses (`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unicode-3.0`, `Zlib`, `OpenSSL`, `CC0-1.0`, `CDLA-Permissive-2.0`), with a single narrow `MPL-2.0` exception for `option-ext` (transitive dependency of `directories`).
- **Bans**: Denies wildcard version requirements and warns on duplicate crate versions.
- **Sources**: Allows only `crates.io` (denies unknown registries and git dependencies).

Run locally with `just deny` or `cargo deny check`.

---

## 4. Fuzzing (`fuzz/`)

Protocol XML parsers, `rclone.conf` parsing/obscure codecs, and `rship-crypto` AEAD framing have dedicated libFuzzer targets under [`fuzz/`](fuzz/README.md). `fuzz/Cargo.toml` defines its own `[workspace]` so fuzzing dependencies never affect root `--locked` builds.

```bash
# List targets
just fuzz-list

# Run a target on Linux/macOS with nightly Rust
cargo +nightly fuzz run s3_xml --fuzz-dir fuzz -- -max_total_time=60
```

Available targets: `s3_xml`, `azure_xml`, `webdav_xml`, `rclone_ini`, and `crypt_decrypt`.

---

## 5. Live-Cloud Testing & Provider Verification Status

All default tests (`cargo test --workspace` / `just nextest`) run **100% offline** using local filesystems, in-process Axum HTTP fault-injection mocks, and an in-process `russh` SFTP server. Live cloud smoke tests are gated behind `#[ignore]` and explicit environment variables.

### Live S3 Smoke Test Environment Variables (`s3_live_smoke`)

Used by `crates/rship-backends/tests/s3_live_smoke.rs` (also executed in CI against a pinned `pgsty/silo` S3-compatible container):

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `RSHIP_LIVE_S3_ENDPOINT` | Yes | — | S3/MinIO endpoint URL (e.g. `http://127.0.0.1:9000` or Cloudflare R2 endpoint) |
| `RSHIP_LIVE_S3_BUCKET` | Yes | — | Target bucket name (test isolates writes under a timestamped `smoke-<ms>/` prefix and cleans up) |
| `RSHIP_LIVE_S3_ACCESS_KEY` | Yes | — | S3 access key ID |
| `RSHIP_LIVE_S3_SECRET_KEY` | Yes | — | S3 secret access key |
| `RSHIP_LIVE_S3_PROVIDER` | No | `minio` | Provider preset (`aws`, `r2`, `minio`, `oss`, `b2`, `wasabi`, `digitalocean`, `cos`, `tigris`, `scaleway`, `hetzner`, `generic`) |
| `RSHIP_LIVE_S3_REGION` | No | `us-east-1` | Signing region (e.g. `us-east-1`, `auto` for R2) |

Example against a local S3/MinIO server:

```bash
# Start a disposable local S3-compatible server
docker run -d --rm --name rship-silo -p 9000:9000 \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  pgsty/silo@sha256:c20d112390b9a9ce8c11b8af95ad35bcaa62f4759663c09c936cd8d2b511f329 server /data

# Create test bucket and run live smoke suite
AWS_ACCESS_KEY_ID=minioadmin AWS_SECRET_ACCESS_KEY=minioadmin \
  aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://rship-ci

RSHIP_LIVE_S3_ENDPOINT=http://127.0.0.1:9000 \
RSHIP_LIVE_S3_BUCKET=rship-ci \
RSHIP_LIVE_S3_ACCESS_KEY=minioadmin \
RSHIP_LIVE_S3_SECRET_KEY=minioadmin \
RSHIP_LIVE_S3_PROVIDER=minio \
just live-s3
```

### Provider Test Verification Matrix

We explicitly distinguish **mock-verified** providers from **automated live-tested** providers so contributors and users know the exact test coverage of each backend:

| Provider | Verification Status | Test Suite(s) |
| :--- | :--- | :--- |
| **Local FS** | **Live-tested in CI** (Linux, macOS, Windows) | `rship-backends` unit tests, `rship::sdk_api`, `rship-cli` integration & acceptance benchmarks |
| **S3-Compatible** | **Mock-verified + Live-tested in CI** (against pinned `pgsty/silo`) | `s3_conformance` (Axum fault-injection mock) + `s3_live_smoke` (real S3 server in CI) |
| **SSH / SFTP** | **In-process real-protocol tested in CI** (embedded `russh` server) | `sftp_conformance` |
| **Encrypted Vault (`crypt`)** | **Live-tested in CI** (bit-exact vs reference `chacha20poly1305` over local backend) | `rship-crypto` unit/integration tests + `crypt_decrypt` fuzz target |
| **Google Drive** | **Mock-verified in CI** *(live throughput/RSS manually benchmarked on real Drive; no automated live CI credentials)* | `gdrive_conformance` (Axum fault-injection mock) |
| **Dropbox** | **Mock-verified in CI** | `dropbox_conformance` (Axum fault-injection mock) |
| **Google Cloud Storage (GCS)** | **Mock-verified in CI** | `gcs_conformance` (Axum fault-injection mock) |
| **Azure Blob Storage** | **Mock-verified in CI** | `azureblob_conformance` (Axum fault-injection mock) |
| **OneDrive & SharePoint** | **Mock-verified in CI** | `onedrive_conformance` (Axum fault-injection mock) |
| **WebDAV** | **Mock-verified in CI** | `webdav_conformance` (Axum fault-injection mock) |

---

## 6. Architectural & Code Guidelines

Please keep these core invariants intact when opening a pull request (see [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/ADDING_A_PROVIDER.md`](docs/ADDING_A_PROVIDER.md) for full details):

1. **Memory ceiling (`<= 64 MiB` RSS)**: Never buffer whole files or full listings in RAM. Stream via `BufferPool` (`Bytes::from_owner(PooledSlice)`) and disk-backed `SqliteSyncIndex`.
2. **`unsafe` discipline**: 5 of 7 crates enforce `#![forbid(unsafe_code)]` (`rship-core`, `rship-state`, `rship-transport`, `rship-crypto`, `rship`). Any `unsafe` block in `rship-backends` or `rship-cli` must carry a clear `// SAFETY:` justification (`clippy::undocumented_unsafe_blocks`).
3. **Shared HTTP retry & secret hygiene**: Route HTTP backend requests through `rship_backends::common::http` retry/reconciliation helpers and mark bearer/auth headers sensitive (`HeaderValue::set_sensitive(true)`). Never log raw credentials.
4. **Feature isolation**: Preserve lean optional features so minimal builds (`rship` default local-only, `rship-backends --no-default-features --features sftp`, minimal CLI builds) compile cleanly with zero unnecessary dependencies.
5. **Pre-push verification**: Run `just ci` (and `just deny` / `just powerset` if you touched dependencies or feature flags) before submitting a PR.
