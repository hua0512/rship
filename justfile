# Developer task runner for rship (https://github.com/casey/just)

set windows-shell := ["pwsh", "-NoLogo", "-Command"]

# List available recipes
default:
    @just --list

# Fast type-check across all workspace targets
check:
    cargo check --workspace --all-targets --locked

# Format all workspace crates with rustfmt
fmt:
    cargo fmt --all

# Check rustfmt formatting without modifying files
fmt-check:
    cargo fmt --all -- --check

# Run Clippy with warnings denied across all targets
clippy:
    cargo clippy --workspace --all-targets --locked -- -D warnings

# Run all workspace tests via standard cargo test
test:
    cargo test --workspace --locked --no-fail-fast

# Run workspace tests via cargo-nextest plus rustdoc doctests
nextest:
    cargo nextest run --workspace --locked
    cargo test --workspace --doc --locked --no-fail-fast

# Build workspace library rustdoc with warnings denied
[unix]
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --lib --no-deps --locked

# Build workspace library rustdoc with warnings denied
[windows]
doc:
    $env:RUSTDOCFLAGS = "-D warnings"; cargo doc --workspace --lib --no-deps --locked

# Run full workspace tests on the MSRV toolchain (1.100.0)
msrv:
    cargo +1.100.0 test --workspace --locked --no-fail-fast

# Check feature powerset combinations (depth 2) on SDK and backends crates
powerset:
    cargo hack --feature-powerset --depth 2 check --locked -p rship -p rship-backends

# Audit advisories, licenses, bans, and sources with cargo-deny
deny:
    cargo deny check

# Collect workspace test coverage (LCOV) via cargo-llvm-cov + nextest
cov:
    cargo llvm-cov nextest --workspace --locked --lcov --output-path lcov.info

# Run 1M-row RSS acceptance check and S3/SQLite scale benchmarks (release)
bench-scale:
    cargo test --release -p rship-cli --test acceptance_benchmarks acceptance_sqlite_sync_index_1m_rows_rss_under_64mib -- --ignored --nocapture
    cargo test --release -p rship-backends --test scale_bench -- --ignored --nocapture

# Run live S3 smoke suite (requires RSHIP_LIVE_S3_* environment variables)
live-s3:
    cargo test -p rship-backends --no-default-features --features s3 --test s3_live_smoke -- --ignored --nocapture

# List available cargo-fuzz targets under fuzz/
fuzz-list:
    cargo +nightly fuzz list --fuzz-dir fuzz

# Full local pre-push CI verification (format, clippy, docs, nextest + doctests)
ci: fmt-check clippy doc nextest
