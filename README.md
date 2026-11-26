<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/logo-wordmark-light.svg" />
    <img alt="rship" src="assets/logo-wordmark-dark.svg" width="260" />
  </picture>
</p>

<p align="center">
  <strong>Move millions of files across 10 clouds — fast, crash-safe, and under 64 MiB of RAM.</strong>
</p>

<p align="center">
  <a href="https://hua0512.github.io/rship/"><img src="https://img.shields.io/badge/docs-rship-FF7A3D?style=flat-square&logo=gitbook&logoColor=white" alt="Documentation" /></a>
  <a href="https://github.com/hua0512/rship/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/hua0512/rship/ci.yml?branch=main&style=flat-square&label=CI" alt="CI Status" /></a>
  <img src="https://img.shields.io/badge/rust-1.100%2B-06B6D4?style=flat-square&logo=rust&logoColor=white" alt="Rust 1.100+" />
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-38BDF8?style=flat-square" alt="License" /></a>
</p>

<p align="center">
  <a href="https://hua0512.github.io/rship/"><strong>Explore the Docs »</strong></a><br />
  <a href="https://hua0512.github.io/rship/guide/getting-started">Quick Start</a> ·
  <a href="https://hua0512.github.io/rship/providers/">10 Providers</a> ·
  <a href="https://hua0512.github.io/rship/sdk/embedding">Rust SDK</a> ·
  <a href="https://hua0512.github.io/rship/benchmarks/">Benchmarks</a> ·
  <a href="https://hua0512.github.io/rship/privacy">Privacy Policy</a>
</p>

---

```text
$ rship copy ./photos gdrive:backups/photos --adaptive --bwlimit 20M

⠋ copy  ━━━━━━━━━━━━━━━━━━━──────  74.2%  13.6 GiB / 18.4 GiB  9.69 MiB/s ▃▅▆▇█▇  ETA 00:18
  3,124/4,218 files · 412 skip · buf 2.5M/16M (pk 4.0M) · Falcon S:6 L:4

  [L] photos/RAW_8842.dng                   ━━━━━━━━━━━━━───   84%   5.82 MiB/s
  [L] photos/archive_2026_backup.tar.zst    ━━━━━━━━━━──────   62%   3.45 MiB/s
  [S] photos/meta/exif_0412.json            ━━━━━━━━━━━━━━━━  100%  420.0 KiB/s
```

**`rship`** is a modern, local-first cloud transfer and sync engine written in Rust — built as a blazing-fast, tiny-memory alternative to `rclone` that won't OOM your VPS, drop your progress on a crash, or duplicate your files.

## Why `rship`?

- **Tiny, predictable memory (`<= 64 MiB` RSS)** — Every local NVMe, 1M-file SQLite diff, and live 1 Gbps Google Drive workload stays **strictly under 64 MiB RSS** out of the box (up to **6.8× less RAM** than `rclone`: `54.8 MiB` vs `374.5 MiB` on 4×64 MiB parallel Drive uploads, `31.6 MiB` on 4-stream downloads, and `25.2 MiB` on 1,000,000-file diffs).
- **Crash-proof resume, zero duplicates** — Hit `Ctrl+C`, lose Wi-Fi, or survive a sudden `SIGKILL`. Re-run `rship resume` and pick up bit-exact where you left off.
- **Drop-in `rclone.conf` migration** — Already have remotes configured? Import 8 cloud providers in one command, including obscured passwords.
- **Fast, zero-knowledge encryption** — Wrap any cloud in a seekable encrypted vault (`1,214 MiB/s` local throughput at `52.9 MiB` RSS — `4.07×` faster and `1.5×` less RAM than `rclone crypt`) and read byte ranges without downloading the whole file.
- **Safe sync & two-way `bisync`** — Never wipes your destination if a network glitch cuts a scan short, and keeps both copies on conflicts by default.
- **Self-contained single binary** — Bundled SQLite and hardware-accelerated crypto with an interactive terminal dashboard, plus a clean **Rust SDK** (`rship`) when you want to embed transfers directly in your app.

---

## Performance Highlights

Head-to-head release benchmarks (MD5 bit-exact verified, default tuned `mimalloc` build) on **1 Gbps Linux VPS** (live Google Drive vs `rclone v1.60.1-DEV`, Linux `wait4 ru_maxrss`) and **Windows 11 NVMe** (vs `rclone v1.76.0`, Win32 `PeakWorkingSetSize`) — see [full benchmarks](https://hua0512.github.io/rship/benchmarks/):

| Workload | `rship 0.1.0` | `rclone` | Highlight |
| :--- | :--- | :--- | :--- |
| **GDrive 128 MiB 4-Stream Download (1G)** | **Up to 77.1 MiB/s** · **31.6 MiB RAM** | 21.1 MiB/s · 55.6–59.6 MiB RAM | **Up to 3.66× faster · 1.8× less RAM** |
| **GDrive 4×64 MiB Parallel Upload (1G)** | **Up to 32.1 MiB/s** · **54.8 MiB RAM** | 28.9 MiB/s (`64M`) · 374.5 MiB RAM | **6.8× less RAM · strictly `< 64 MiB`** |
| **GDrive 128 MiB Single Upload (1G)** | **Up to 27.6 MiB/s** · **29.4 MiB RAM** | 17.9–23.2 MiB/s · 75.8–132.5 MiB RAM | **Up to 1.54× faster · 2.6–4.5× less RAM** |
| **GDrive 64 MiB Crypt Up / Down (1G)** | **11.2–12.1 / 13.0–26.2 MiB/s** · **47.1 / 45.5 MiB** | 7.6–8.3 / 9.5–13.4 MiB/s · 147.9 / 70.8 MiB | **1.35–1.95× faster · up to 3.1× less RAM** |
| **GDrive Warm Sync (`changes.list`, 1G)** | **285–304 ms** · **31.1 MiB RAM** | 1,239–1,305 ms · 52.7 MiB RAM | **4.1–4.6× faster · 1.7× less RAM** |
| **1 GiB Local Copy (NVMe)** | **905 ms** (`1,131 MiB/s`) · **17.5 MiB RAM** | 1,323 ms (`774 MiB/s`) · 64.7 MiB RAM | **1.46× faster · 3.7× less RAM** |
| **1 GiB Local Crypt Write (OAE2)** | **844 ms** (`1,214 MiB/s`) · **52.9 MiB RAM** | 3,436 ms (`298 MiB/s`) · 79.7 MiB RAM | **4.07× faster · 1.5× less RAM** |
| **5,000-File Warm Sync** | **27.6 ms** · **26.3 MiB RAM** | 132.0 ms · 65.8 MiB RAM | **4.78× faster · 2.5× less RAM** |
| **5,000-File Warm Bisync (`--transfers 16`)** | **42.5 ms** · **25.3 MiB RAM** | 206.9 ms · 58.9 MiB RAM | **4.87× faster · 2.3× less RAM** |
| **5,000-File Read-Only `ls -r` (Lazy Zero-DB)** | **23.7 ms** · **15.5 MiB RAM** | 103.4 ms · 51.1 MiB RAM | **4.36× faster · 3.3× less RAM** |
| **1,000,000-Row Sync Diff (Release)** | **1.55 s** · **25.2 MiB RAM** | — | **`~39%` of 64 MiB cap (`16.6 MiB` sys alloc)** |

<sub>`rship-cli` tunes `mimalloc` v3 at startup (`no_thp`, lazy arena commit, immediate cross-thread page reclaim, 20 ms arena purge) and bounds Tokio async workers (`2..=8`) so every workload stays under `64 MiB` RSS without sacrificing throughput. Build with `--no-default-features --features all-backends` to use the platform system allocator instead.</sub>

---

## 10 Backends Built In

| Backend | Highlights |
| :--- | :--- |
| **Local FS** | OS-native fast copy, atomic saves, parallel cloud downloads |
| **Google Drive** | OAuth2 PKCE, Service Accounts & Shared Drives, fast incremental sync, `dedupe` |
| **S3-Compatible (12 Presets)** | AWS S3, Cloudflare R2, MinIO, OSS, Backblaze B2, Wasabi, DO Spaces, COS, Tigris, Scaleway, Hetzner |
| **Dropbox** | OAuth2 PKCE, crash-resumable sessions, native block hashes, server-side copy |
| **Google Cloud Storage** | Service Accounts, OAuth2 PKCE, anonymous public buckets, `rewrite` copy |
| **Azure Blob Storage** | SharedKey, SAS URLs, Azurite emulator, parallel block resume |
| **OneDrive & SharePoint** | Microsoft Graph OAuth2 PKCE, resumable sessions, async server-side copy |
| **WebDAV** | Nextcloud, OwnCloud, Alist, Synology NAS, InfiniCloud, generic WebDAV |
| **SSH / SFTP** | Built on `russh` + `russh-sftp`, pooled sessions, offset crash-resume |
| **Encrypted Vault (`crypt`)** | Hardware-accelerated `XChaCha20-Poly1305` + encrypted filenames over any backend |

---

## Quick Start

### 1. Install

Install the latest release cleanly (verifies `SHA256SUMS.txt` automatically):

```bash
# macOS / Linux
curl -fsSL https://hua0512.github.io/rship/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://hua0512.github.io/rship/install.ps1 | iex
```

Or download a prebuilt archive directly from [GitHub Releases (Latest)](https://github.com/hua0512/rship/releases/latest) (includes `SHA256SUMS.txt`):

| Platform | Archive |
| :--- | :--- |
| **Linux (x86_64, glibc ≥ 2.28 / static musl)** | `rship-<VERSION>-x86_64-unknown-linux-gnu.tar.gz` / `x86_64-unknown-linux-musl.tar.gz` |
| **Linux (ARM64, glibc ≥ 2.28 / static musl)** | `rship-<VERSION>-aarch64-unknown-linux-gnu.tar.gz` / `aarch64-unknown-linux-musl.tar.gz` |
| **macOS (Apple Silicon / Intel)** | `rship-<VERSION>-aarch64-apple-darwin.tar.gz` / `x86_64-apple-darwin.tar.gz` |
| **Windows (x86_64)** | `rship-<VERSION>-x86_64-pc-windows-msvc.zip` |

Extract `rship` (or `rship.exe`) into a directory on your `PATH`, or see the [Installation Guide](https://hua0512.github.io/rship/guide/getting-started#installation) for manual release-download commands per OS.

### 2. Connect Your Clouds (or Import `rclone.conf`)

```bash
# Import existing rclone remotes in one shot (preview first with --dry-run)
rship config import-rclone

# Or connect a cloud directly
rship auth gdrive gdrive --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>
rship auth s3 r2 --provider r2 --bucket backups --region auto --endpoint <ENDPOINT>
rship auth crypt vault --target r2:encrypted-vault --password "strong-passphrase"

# Optional: lock secrets into your OS Keyring (Windows / macOS / Linux)
rship auth keyring-migrate
```

### 3. Transfer, Sync, Verify & Resume

```bash
# Fast copy with adaptive dual-lane concurrency and live TUI
rship copy ./photos gdrive:backups/photos --adaptive --bwlimit 20M

# Safe mirror sync with filter rules and delete cap
rship sync ./workspace r2:workspace --exclude '.git/' --max-delete 100

# Two-way sync that keeps both versions on conflict
rship bisync ./notes gdrive:notes

# Zero-bandwidth server-side copy inside the same cloud
rship copyto r2:backups/a.bin r2:backups/b.bin

# Stream stdin into an encrypted vault, or read any byte range back out
tar -cf - ./docs | rship rcat vault:backups/docs.tar
rship cat vault:backups/docs.tar --offset 0 --count 4096 | xxd

# Interrupted? Pick up right where you left off
rship status
rship resume <job-id>
```

### 4. Or Embed Directly in Rust

```rust
use rship::prelude::*;

let client = RshipClient::builder()
    .rclone_conf("/app/config/rclone.conf")
    .remote(
        "r2",
        S3RemoteConfig::new("r2")
            .with_bucket("backups")
            .with_endpoint("https://<account-id>.r2.cloudflarestorage.com")
            .with_credentials("AKIA...", "secret"),
    )
    .state_dir("/app/state")
    .build()?;

let report = client
    .move_files("/recordings", "gdrive:2026", ["clip.mp4"])
    .bwlimit(20 * 1024 * 1024)
    .run()
    .await?;

client.shutdown().await?;
```

---

## Documentation

- **[Public Documentation Site](https://hua0512.github.io/rship/)** — Guides, CLI reference, provider matrix, benchmarks, and SDK docs
- **[Rust SDK & Production Embedding](docs/EMBEDDING_RUST.md)** — Embedding `RshipClient`, `FailoverPool`, and headless `rclone` flag mapping
- **[Google Drive OAuth Setup](docs/GOOGLE_OAUTH_SETUP.md)** — 5-minute Desktop Client ID, Service Accounts, and verification checklist
- **[Architecture & Invariants](ARCHITECTURE.md)** — 7-crate workspace design, `BufferPool`, SQLite WAL journal, and split transport
- **[Adding a New Provider](docs/ADDING_A_PROVIDER.md)** — 4-step guide to adding a storage backend
- **[Privacy Policy](docs/PRIVACY_POLICY.md)** — Local-first, zero-telemetry disclosure

## License

Dual-licensed under **[MIT](LICENSE-MIT)** or **[Apache-2.0](LICENSE-APACHE)**.
