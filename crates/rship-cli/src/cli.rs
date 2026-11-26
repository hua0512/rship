use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

const HEADING_CONFIG: &str = "Profile & Config";
const HEADING_DIAGNOSTICS: &str = "Diagnostics";
const HEADING_NETWORK: &str = "Network & Rate Limits";
const HEADING_BACKEND: &str = "Backend Overrides";
const HEADING_PERF: &str = "Performance & Concurrency";
const HEADING_SAFETY: &str = "Sync & Safety";
const HEADING_FILTER: &str = "Filtering";
const HEADING_OUTPUT: &str = "Output";

const SHORT_HELP_TIP: &str = "Tip: pass --help to view all advanced/network options, or save defaults in config.toml ([defaults] / [profiles.<name>]).";
const LONG_HELP_TIP: &str = "Defaults & presets: configure [defaults] or [profiles.<name>] in config.toml and reuse them with -p/--profile <NAME> (inspect via `rship config profiles`).";

#[derive(Debug, Parser)]
#[command(
    name = "rship",
    version,
    about = "Fast, low-memory, crash-resumable multi-cloud transfer & sync engine",
    styles = crate::ui::clap_styles(),
    after_help = SHORT_HELP_TIP,
    after_long_help = LONG_HELP_TIP,
)]
pub struct Cli {
    /// Apply a named preset from `[profiles.<NAME>]` in `config.toml` (layers over `[defaults]`; CLI flags win)
    #[arg(
        short = 'p',
        long,
        global = true,
        env = "RSHIP_PROFILE",
        value_name = "NAME",
        help_heading = HEADING_CONFIG
    )]
    pub profile: Option<String>,

    /// Override config file path (default: platform user config dir / rship / config.toml)
    #[arg(long, global = true, env = "RSHIP_CONFIG", help_heading = HEADING_CONFIG)]
    pub config: Option<PathBuf>,

    /// Override state directory (default: platform user data dir / rship)
    #[arg(long, global = true, env = "RSHIP_STATE_DIR", help_heading = HEADING_CONFIG)]
    pub state_dir: Option<PathBuf>,

    /// Verbose logging (-v info, -vv debug, -vvv trace)
    #[arg(
        short,
        long,
        action = clap::ArgAction::Count,
        global = true,
        help_heading = HEADING_DIAGNOSTICS
    )]
    pub verbose: u8,

    /// Append diagnostic logs to a file instead of stderr (creates parent directories if needed)
    #[arg(
        long,
        global = true,
        env = "RSHIP_LOG_FILE",
        hide_short_help = true,
        help_heading = HEADING_DIAGNOSTICS
    )]
    pub log_file: Option<PathBuf>,

    /// Dump redacted HTTP wire diagnostics (`headers`) for cloud troubleshooting
    #[arg(
        long,
        global = true,
        env = "RSHIP_DUMP",
        hide_short_help = true,
        help_heading = HEADING_DIAGNOSTICS
    )]
    pub dump: Option<String>,

    /// Disable interactive prompts and fail fast when required arguments are omitted
    #[arg(
        long,
        global = true,
        env = "RSHIP_NON_INTERACTIVE",
        hide_short_help = true,
        help_heading = HEADING_DIAGNOSTICS
    )]
    pub non_interactive: bool,

    /// Explicit proxy URL (`http://`, `https://`, `socks5://`, `socks5h://`) for Control & Data Planes
    #[arg(
        long,
        global = true,
        env = "RSHIP_PROXY",
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub proxy: Option<String>,

    /// Optional custom PEM CA certificate bundle for corporate/proxy TLS roots
    #[arg(
        long,
        global = true,
        env = "RSHIP_CA_CERT",
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub ca_cert: Option<PathBuf>,

    /// Proactive global API requests-per-second ceiling across reads & writes (e.g. `8`, `4.5`; `0` = unlimited)
    #[arg(
        long,
        global = true,
        env = "RSHIP_TPSLIMIT",
        allow_hyphen_values = true,
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub tpslimit: Option<f64>,

    /// TCP/TLS connect timeout (e.g. `15s`, `30s`)
    #[arg(
        long,
        global = true,
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub connect_timeout: Option<String>,

    /// Data-plane byte-progress idle stall timeout (e.g. `30s`, `2m`)
    #[arg(
        long,
        global = true,
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub stall_timeout: Option<String>,

    /// Control-plane metadata/RPC timeout (e.g. `60s`, `2m`)
    #[arg(
        long,
        global = true,
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub control_timeout: Option<String>,

    /// Override per-HTTP-request low-level retry count on cloud backends (e.g. `3`, `6`)
    #[arg(
        long,
        global = true,
        env = "RSHIP_LOW_LEVEL_RETRIES",
        hide_short_help = true,
        help_heading = HEADING_NETWORK
    )]
    pub low_level_retries: Option<u32>,

    /// [Google Drive] Disable `changes.list` incremental inventory cache for this invocation (also configurable per remote via `use_changes_feed`)
    #[arg(
        long,
        global = true,
        hide_short_help = true,
        help_heading = HEADING_BACKEND
    )]
    pub no_changes_feed: bool,

    /// [Google Drive] Fail fast with QuotaExceeded on `403 userRateLimitExceeded` uploads (750 GiB/day cap; also configurable per remote via `stop_on_upload_limit`)
    #[arg(
        long,
        global = true,
        env = "RSHIP_DRIVE_STOP_ON_UPLOAD_LIMIT",
        hide_short_help = true,
        help_heading = HEADING_BACKEND
    )]
    pub drive_stop_on_upload_limit: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List objects at a local or remote target
    Ls {
        target: String,
        #[arg(short, long)]
        recursive: bool,
        #[arg(long)]
        json: bool,
    },
    /// Display a directory tree for a local or remote target
    Tree(TreeArgs),
    /// Show total file count and byte size under a local or remote target
    Size(SizeArgs),
    /// Show storage quota / disk capacity (`total`, `used`, `free`, `trashed`) for a local or remote target
    About {
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Read-only verification comparing files (size and common checksum) between source and destination
    Check(CheckArgs),
    /// Produce a checksum manifest (`md5`, `sha256`, `sha1`, `crc32c`) compatible with `sha256sum -c`
    Hashsum(HashsumArgs),
    /// Resolve duplicate sibling filenames (e.g. on Google Drive) safely by node ID
    Dedupe(DedupeArgs),
    /// Copy files (or a single file) from source to destination (never deletes destination files)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Copy(TransferArgs),
    /// Copy a single file from source to an explicit destination file path (supports rename & server-side copy)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Copyto(TransferArgs),
    /// Synchronize destination to match source (deletes extraneous destination files after transfers succeed)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Sync(TransferArgs),
    /// Move files (or a single file) from source to destination (deletes source ONLY after verified commit)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Move(MoveArgs),
    /// Move a single file from source to an explicit destination file path (supports rename & server-side copy)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Moveto(TransferArgs),
    /// Safe Three-Tree bidirectional sync between two targets (Unison / Dropbox Canopy model)
    #[command(after_help = SHORT_HELP_TIP, after_long_help = LONG_HELP_TIP)]
    Bisync(BisyncArgs),
    /// Delete files matching filters under target (preserves directories)
    Delete(DeleteArgs),
    /// Recursively delete all files and directories under target prefix
    Purge(PurgeArgs),
    /// Create a directory (and parent chain) on a local or remote target
    Mkdir { target: String },
    /// Stream a file (or byte range) from any local, cloud, or encrypted remote directly to stdout
    Cat(CatArgs),
    /// Stream stdin into a local, cloud, or encrypted remote file (spools to bounded temp file for retries/chunking)
    Rcat(RcatArgs),
    /// Generate shell completion script for bash, zsh, fish, powershell, or elvish
    Completions { shell: Shell },
    /// Show recent jobs and active/resumable operations in SQLite
    Status {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Resume a previously paused or failed job by ID (restores original persisted options)
    Resume {
        job_id: String,
        #[arg(long, help_heading = HEADING_PERF)]
        transfers: Option<usize>,
        #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
        max_buffer_mem: Option<String>,
        #[arg(long, help_heading = HEADING_PERF)]
        bwlimit: Option<String>,
        /// Emit structured newline-delimited JSON (JSONL) progress events to stderr
        #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
        json_progress: bool,
        /// Progress reporting interval for `--json-progress` (e.g. `1s`, `500ms`; default `1s`)
        #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
        stats: Option<String>,
        #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
        tui: bool,
        /// Output machine-readable JSON summary
        #[arg(long, help_heading = HEADING_OUTPUT)]
        json: bool,
    },
    /// Garbage-collect stale/aborted operations from the state journal or remote S3 multipart uploads
    Gc {
        /// Delete all stored active operations (aborts their remote/staging sessions)
        #[arg(long)]
        all: bool,
        /// Abort stale incomplete multipart uploads on a remote bucket/prefix (e.g. `r2:my-bucket` or `aws:bucket/prefix`)
        #[arg(long)]
        remote_multipart: Option<String>,
        /// Minimum age of incomplete remote multipart uploads to abort (e.g. `7d`, `24h`, `0s`; default: `7d`)
        #[arg(long, default_value = "7d")]
        older_than: String,
        /// Preview remote multipart GC without aborting anything
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Output machine-readable JSON summary
        #[arg(long)]
        json: bool,
    },
    /// Authorize cloud remotes interactively (or export/import credentials for headless servers)
    Auth {
        #[command(subcommand)]
        action: Option<AuthAction>,
    },
    /// Interactively manage, inspect, test, or import rship remote configurations
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthAction {
    /// Authorize a Google Drive remote using Desktop PKCE loopback (127.0.0.1) or Service Account
    Gdrive(GdriveAuthArgs),
    /// Authorize a Microsoft OneDrive / SharePoint remote via OAuth2 Desktop PKCE loopback
    Onedrive(OnedriveAuthArgs),
    /// Configure a WebDAV remote (Nextcloud, OwnCloud, Alist, Synology NAS, InfiniCloud, generic)
    Webdav(WebdavAuthArgs),
    /// Configure an SSH/SFTP remote (private key or password)
    Sftp(SftpAuthArgs),
    /// Migrate all inline secrets in `config.toml` into the OS Keyring (`keyring://rship/...`)
    KeyringMigrate,
    /// Configure an S3-compatible remote (AWS S3, Cloudflare R2, MinIO, OSS, B2, Wasabi, DO Spaces, Tencent COS, Tigris, Scaleway, Hetzner)
    S3(S3AuthArgs),
    /// Authorize a Dropbox remote via OAuth2 Desktop PKCE loopback (`token_access_type=offline`)
    Dropbox(DropboxAuthArgs),
    /// Configure a Google Cloud Storage (GCS) remote (Service Account JSON, OAuth2 PKCE, or anonymous)
    Gcs(GcsAuthArgs),
    /// Configure an Azure Blob Storage remote (SharedKey, SAS token/URL, anonymous, or Azurite emulator)
    Azureblob(AzureblobAuthArgs),
    /// Configure an encrypted STREAM OAE2 (`crypt`) overlay remote wrapping any backend
    Crypt(CryptAuthArgs),
    /// Configure a named local filesystem directory alias
    Local(LocalAuthArgs),
    /// Export a remote's credentials & token bundle for headless server import
    Export {
        /// Configured remote name to export
        remote: String,
        /// Emit formatted JSON instead of compact `rship-auth-v1:...` string
        #[arg(long)]
        json: bool,
        /// Write bundle to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Import an exported credential bundle on a headless machine
    Import {
        /// Path to an exported bundle file (reads stdin if both --input and --bundle are omitted)
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Inline `rship-auth-v1:...` or JSON bundle string
        #[arg(long)]
        bundle: Option<String>,
        /// Optional override for the imported remote name
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-local"), allow(dead_code))]
pub struct LocalAuthArgs {
    /// Logical remote name (e.g. `backups`, `nas-mount`)
    pub remote: Option<String>,
    /// Local root directory path on disk
    #[arg(long)]
    pub root: Option<PathBuf>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-gdrive"), allow(dead_code))]
pub struct GdriveAuthArgs {
    /// Logical remote name (e.g. `gdrive`, `work-drive`)
    pub remote: Option<String>,
    /// User-owned Google Cloud OAuth 2.0 Desktop client_id
    #[arg(long)]
    pub client_id: Option<String>,
    /// User-owned Google Cloud OAuth 2.0 Desktop client_secret
    #[arg(long)]
    pub client_secret: Option<String>,
    /// Google Drive OAuth scope or alias (`drive`, `drive.file`, `drive.readonly`, or full URL)
    #[arg(long)]
    pub scope: Option<String>,
    /// Optional Drive root folder ID (default: `root`)
    #[arg(long)]
    pub root_folder_id: Option<String>,
    /// Optional Shared Drive (`team_drive`) ID
    #[arg(long)]
    pub shared_drive_id: Option<String>,
    /// Use a Service Account JSON key file instead of interactive OAuth2 PKCE
    #[arg(long)]
    pub service_account_file: Option<PathBuf>,
    /// Domain-Wide Delegation user email (`sub`) when using a Service Account
    #[arg(long)]
    pub impersonate: Option<String>,
    /// Print the complete Google Cloud OAuth Client ID setup & verification checklist and exit
    #[arg(long)]
    pub guide: bool,
    /// Do not automatically open the system browser during OAuth2 login
    #[arg(long)]
    pub no_browser: bool,
    /// Headless/SSH mode: print the auth URL and paste the redirected callback URL manually
    #[arg(long)]
    pub manual: bool,
    /// Explicit loopback callback port (default: tries 53682, falls back to ephemeral port; 0 = ephemeral)
    #[arg(long)]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-onedrive"), allow(dead_code))]
pub struct OnedriveAuthArgs {
    /// Logical remote name (e.g. `onedrive`, `work-od`)
    pub remote: Option<String>,
    /// Azure App Registration (Entra ID) OAuth2 Application (client) ID
    #[arg(long)]
    pub client_id: Option<String>,
    /// Optional Azure OAuth2 client secret (omit for public Desktop PKCE app)
    #[arg(long)]
    pub client_secret: Option<String>,
    /// Optional Graph Drive ID (for SharePoint Document Libraries)
    #[arg(long)]
    pub drive_id: Option<String>,
    /// Optional OAuth scope override
    #[arg(long)]
    pub scope: Option<String>,
    /// Optional direct bearer token (non-interactive / testing)
    #[arg(long)]
    pub access_token: Option<String>,
    /// Do not automatically open the system browser during OAuth2 login
    #[arg(long)]
    pub no_browser: bool,
    /// Headless/SSH mode: print the auth URL and paste the redirected callback URL manually
    #[arg(long)]
    pub manual: bool,
    /// Explicit loopback callback port (default: tries 53682, falls back to ephemeral port; 0 = ephemeral)
    #[arg(long)]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-webdav"), allow(dead_code))]
pub struct WebdavAuthArgs {
    /// Logical remote name (e.g. `nextcloud`, `nas`)
    pub remote: Option<String>,
    /// Base WebDAV URL (e.g. `https://cloud.example.com/remote.php/dav/files/alice`)
    #[arg(long)]
    pub url: Option<String>,
    /// Vendor profile: nextcloud, owncloud, alist, synology, infinicloud, generic
    #[arg(long)]
    pub vendor: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub bearer_token: Option<String>,
    /// Optional explicit Nextcloud/OwnCloud chunked v2 upload root URL
    #[arg(long)]
    pub chunked_upload_root: Option<String>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-sftp"), allow(dead_code))]
pub struct SftpAuthArgs {
    /// Logical remote name (e.g. `vps`, `nas-ssh`)
    pub remote: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    #[arg(long)]
    pub user: Option<String>,
    /// Optional remote root directory
    #[arg(long)]
    pub root_path: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub key_passphrase: Option<String>,
    /// Host-key verification policy: `accept-new` (default), `strict`, or `insecure`
    #[arg(long)]
    pub host_key_policy: Option<String>,
    #[arg(long)]
    pub known_hosts: Option<PathBuf>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-s3"), allow(dead_code))]
pub struct S3AuthArgs {
    /// Logical remote name (e.g. `r2`, `aws-backups`, `minio`)
    pub remote: Option<String>,
    /// Provider profile: aws, r2, minio, oss, b2, wasabi, digitalocean, cos, tigris, scaleway, hetzner, generic
    #[arg(long)]
    pub provider: Option<String>,
    /// Default bucket name (optional; if omitted, pass `remote:bucket/path`)
    #[arg(long)]
    pub bucket: Option<String>,
    /// Optional default key prefix inside the bucket
    #[arg(long)]
    pub prefix: Option<String>,
    /// Region (e.g. us-east-1, auto, oss-cn-hangzhou)
    #[arg(long)]
    pub region: Option<String>,
    /// Custom S3 endpoint URL (required for R2/MinIO/custom endpoints)
    #[arg(long)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub access_key_id: Option<String>,
    #[arg(long)]
    pub secret_access_key: Option<String>,
    #[arg(long)]
    pub session_token: Option<String>,
    /// Resolve AWS credentials dynamically (env vars, ~/.aws/credentials, ECS, EC2 IMDSv2)
    #[arg(long)]
    pub env_auth: bool,
    /// Named AWS profile in ~/.aws/credentials / ~/.aws/config
    #[arg(long = "aws-profile")]
    pub aws_profile: Option<String>,
    /// Force path-style URLs (`endpoint/bucket/key`)
    #[arg(long)]
    pub force_path_style: Option<bool>,
    /// Always compute SHA-256 payload hashes even over HTTPS (alias for `--payload-signing sha256`)
    #[arg(long)]
    pub strict_sigv4: bool,
    /// SigV4 payload signing policy: `auto` (UNSIGNED-PAYLOAD on HTTPS, SHA-256 on HTTP), `unsigned`, or `sha256`
    #[arg(long)]
    pub payload_signing: Option<String>,
    /// Pin S3 range reads with `If-Match: <etag>` (disable for legacy Swift/S3 gateways with buggy SLO If-Match)
    #[arg(long)]
    pub pin_read_etag: Option<bool>,
    /// Send hardware upload checksum header (`CRC64NVME` on AWS / `CRC32C` on R2 & MinIO)
    #[arg(long)]
    pub send_upload_checksum: Option<bool>,
    #[arg(long)]
    pub storage_class: Option<String>,
    /// Server-Side Encryption mode: `AES256` (SSE-S3) or `aws:kms` (SSE-KMS)
    #[arg(long)]
    pub sse: Option<String>,
    /// Optional AWS KMS Key ID or ARN for `--sse aws:kms`
    #[arg(long)]
    pub kms_key_id: Option<String>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-dropbox"), allow(dead_code))]
pub struct DropboxAuthArgs {
    /// Logical remote name (e.g. `dropbox`, `work-dbx`)
    pub remote: Option<String>,
    /// Dropbox App Key (`client_id`)
    #[arg(long)]
    pub client_id: Option<String>,
    /// Optional Dropbox App Secret (omit for PKCE-only public apps)
    #[arg(long)]
    pub client_secret: Option<String>,
    /// Optional root folder path inside Dropbox (e.g. `/backups`)
    #[arg(long)]
    pub root_path: Option<String>,
    /// Optional direct access token (non-interactive / testing)
    #[arg(long)]
    pub access_token: Option<String>,
    /// Do not automatically open the system browser during OAuth2 login
    #[arg(long)]
    pub no_browser: bool,
    /// Headless/SSH mode: print the auth URL and paste the redirected callback URL manually
    #[arg(long)]
    pub manual: bool,
    /// Explicit loopback callback port (default: tries 53682, falls back to ephemeral port; 0 = ephemeral)
    #[arg(long)]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-gcs"), allow(dead_code))]
pub struct GcsAuthArgs {
    /// Logical remote name (e.g. `gcs`, `gcp-archive`)
    pub remote: Option<String>,
    /// Default GCS bucket name (optional; if omitted, pass `remote:bucket/path`)
    #[arg(long)]
    pub bucket: Option<String>,
    /// Optional default object prefix inside the bucket
    #[arg(long)]
    pub prefix: Option<String>,
    /// Optional Google Cloud project number
    #[arg(long)]
    pub project_number: Option<String>,
    /// Optional GCS storage class (`STANDARD`, `NEARLINE`, `COLDLINE`, `ARCHIVE`)
    #[arg(long)]
    pub storage_class: Option<String>,
    /// Service Account JSON key file (recommended for servers & CI)
    #[arg(long)]
    pub service_account_file: Option<PathBuf>,
    /// Optional impersonated principal (`sub`) for Domain-Wide Delegation
    #[arg(long)]
    pub impersonate: Option<String>,
    /// Google OAuth2 client_id (for interactive Desktop PKCE flow)
    #[arg(long)]
    pub client_id: Option<String>,
    /// Google OAuth2 client_secret
    #[arg(long)]
    pub client_secret: Option<String>,
    /// GCS OAuth scope alias (`full`, `read_write`, `read_only`, `cloud-platform`, or full URL)
    #[arg(long)]
    pub scope: Option<String>,
    /// Access public GCS buckets anonymously without credentials
    #[arg(long)]
    pub anonymous: bool,
    /// Optional custom GCS endpoint URL (e.g. `http://127.0.0.1:4443` for `fake-gcs-server`)
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Optional static bearer token (non-interactive / testing)
    #[arg(long)]
    pub access_token: Option<String>,
    /// Do not automatically open the system browser during OAuth2 login
    #[arg(long)]
    pub no_browser: bool,
    /// Headless/SSH mode: print the auth URL and paste the redirected callback URL manually
    #[arg(long)]
    pub manual: bool,
    /// Explicit loopback callback port (default: tries 53682, falls back to ephemeral port; 0 = ephemeral)
    #[arg(long)]
    pub callback_port: Option<u16>,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-azureblob"), allow(dead_code))]
pub struct AzureblobAuthArgs {
    /// Logical remote name (e.g. `azure`, `az-backups`)
    pub remote: Option<String>,
    /// Azure Storage Account name (optional when `--sas-url` or `--use-emulator` is provided)
    #[arg(long)]
    pub account: Option<String>,
    /// Default Azure container name (optional; if omitted, pass `remote:container/path`)
    #[arg(long)]
    pub container: Option<String>,
    /// Optional default blob prefix inside the container
    #[arg(long)]
    pub prefix: Option<String>,
    /// Base64 Storage Account Shared Key
    #[arg(long)]
    pub key: Option<String>,
    /// Azure SAS token (`?sv=...`) or full SAS URL (`https://acct.blob.core.windows.net?sv=...`)
    #[arg(long)]
    pub sas_url: Option<String>,
    /// Optional custom service endpoint (e.g. Azure China or Azurite `http://127.0.0.1:10000/devstoreaccount1`)
    #[arg(long)]
    pub endpoint: Option<String>,
    /// Optional Azure blob access tier (`Hot`, `Cool`, `Cold`, `Archive`)
    #[arg(long)]
    pub access_tier: Option<String>,
    /// Configure local Azurite storage emulator defaults (`devstoreaccount1`)
    #[arg(long)]
    pub use_emulator: bool,
    /// Access public Azure Blob containers anonymously
    #[arg(long)]
    pub anonymous: bool,
}

#[derive(Debug, Default, Args)]
#[cfg_attr(not(feature = "backend-crypt"), allow(dead_code))]
pub struct CryptAuthArgs {
    /// Logical encrypted remote name (e.g. `vault`)
    pub remote: Option<String>,
    /// Underlying target (`my-s3:bucket/enc`, `gdrive:vault`, or local path)
    #[arg(long)]
    pub target: Option<String>,
    /// Passphrase for Argon2id key derivation (or supply `--key-hex`)
    #[arg(long)]
    pub password: Option<String>,
    /// Raw 256-bit hex master key (64 hex chars)
    #[arg(long)]
    pub key_hex: Option<String>,
    /// Optional Argon2id salt string
    #[arg(long)]
    pub salt: Option<String>,
    /// Filename encryption mode: `standard` (default) or `off`
    #[arg(long)]
    pub filename_encryption: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// List configured remotes with provider type and secret storage status
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
    /// List `[defaults]` and named `[profiles.<name>]` presets configured in `config.toml`
    Profiles {
        #[arg(long)]
        json: bool,
    },
    /// Interactively add a new remote (guided provider wizard)
    #[command(alias = "add")]
    New {
        /// Optional provider kind (`s3`, `gdrive`, `onedrive`, `dropbox`, `gcs`, `azureblob`, `webdav`, `sftp`, `crypt`, `local`)
        provider: Option<String>,
        /// Optional logical remote name
        remote: Option<String>,
    },
    /// Interactively edit an existing configured remote
    Edit {
        /// Remote name to edit (prompts to select if omitted)
        remote: Option<String>,
    },
    /// Print resolved config & state paths
    Path,
    /// Show active configuration as TOML (secrets redacted by default)
    Show {
        /// Reveal raw secrets/passwords/tokens in output
        #[arg(long)]
        show_secrets: bool,
    },
    /// Import remotes (GDrive, S3, OneDrive, Dropbox, GCS, Azure Blob, WebDAV, SFTP) from an existing `rclone.conf`
    ImportRclone {
        /// Path to `rclone.conf` (auto-detects standard rclone locations if omitted)
        path: Option<PathBuf>,
        /// Overwrite existing remotes with the same name in `config.toml`
        #[arg(long)]
        overwrite: bool,
        /// Preview what would be imported without writing config or tokens
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Test connectivity, authentication, and latency against a configured remote
    Test {
        remote: String,
        #[arg(long)]
        json: bool,
    },
    /// Remove a configured remote and clean up its saved tokens & OS keyring entries
    Rm { remote: String },
}

/// Shared path, rule-file, size, and age filtering flags across transfer & inspection commands.
#[derive(Debug, Args, Clone, Default)]
pub struct FilterArgs {
    /// Glob patterns to exclude (repeatable, e.g. --exclude '.git/' --exclude '*.tmp')
    #[arg(long, help_heading = HEADING_FILTER)]
    pub exclude: Vec<String>,
    /// Glob patterns to include (repeatable)
    #[arg(long, help_heading = HEADING_FILTER)]
    pub include: Vec<String>,
    /// Read ordered `+ pattern` / `- pattern` filter rules from a file (first match wins)
    #[arg(long, help_heading = HEADING_FILTER)]
    pub filter_from: Vec<PathBuf>,
    /// Read exact relative file paths to include from a file (prunes unrelated directories)
    #[arg(long, help_heading = HEADING_FILTER)]
    pub files_from: Option<PathBuf>,
    /// Read exclude glob patterns from a file (one per line; `#`/`;` comments ignored)
    #[arg(long, hide_short_help = true, help_heading = HEADING_FILTER)]
    pub exclude_from: Vec<PathBuf>,
    /// Only include files >= this size (e.g. 1K, 10M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_FILTER)]
    pub min_size: Option<String>,
    /// Only include files <= this size (e.g. 100M, 2G)
    #[arg(long, hide_short_help = true, help_heading = HEADING_FILTER)]
    pub max_size: Option<String>,
    /// Only include files modified at least this long ago (e.g. 1h, 7d, 2w)
    #[arg(long, hide_short_help = true, help_heading = HEADING_FILTER)]
    pub min_age: Option<String>,
    /// Only include files modified no more than this long ago (e.g. 30m, 24h, 7d)
    #[arg(long, hide_short_help = true, help_heading = HEADING_FILTER)]
    pub max_age: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct TransferArgs {
    /// Source path (local path or `remote:path`)
    pub src: String,
    /// Destination path (local path or `remote:path`)
    pub dst: String,
    /// Concurrent file transfers (default: config `[defaults]` or `4`)
    #[arg(long, help_heading = HEADING_PERF)]
    pub transfers: Option<usize>,
    /// Enable Falcon dual-lane (`<= 1 MiB` vs `> 1 MiB`) online adaptive concurrency control
    #[arg(long, conflicts_with = "no_adaptive", help_heading = HEADING_PERF)]
    pub adaptive: bool,
    /// Disable Falcon adaptive concurrency even if enabled in `[defaults]` or `--profile`
    #[arg(
        long,
        conflicts_with = "adaptive",
        hide_short_help = true,
        help_heading = HEADING_PERF
    )]
    pub no_adaptive: bool,
    /// Sustained bandwidth limit or time-of-day timetable (e.g. `10M`, `500K`, `"08:00,10M 23:00,off"`, `off`)
    #[arg(long, help_heading = HEADING_PERF)]
    pub bwlimit: Option<String>,
    /// Concurrent parts per parallel-multipart upload (default: config `[defaults]` or `4`)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub part_concurrency: Option<usize>,
    /// Override protocol chunk size (e.g. 64M, 128M, 256K)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub chunk_size: Option<String>,
    /// Hard cap for engine-owned BufferPool (e.g. 8M, 16M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub max_buffer_mem: Option<String>,
    /// Per-file/session transfer retry limit (default: 5)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub retries: Option<u32>,
    /// Disable cloud server-side copy and force streaming relay through local host
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub no_server_side_copy: bool,
    /// Skip directory tree listing when `--files-from` is used (stat only listed paths)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub no_traverse: bool,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Simulate without mutating destination or state
    #[arg(short = 'n', long, help_heading = HEADING_SAFETY)]
    pub dry_run: bool,
    /// Compare files by checksum instead of size + mtime
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub checksum: bool,
    /// Abort sync if planned deletions exceed this count (`100`), percentage (`50%`), or `off`
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub max_delete: Option<String>,
    /// Archive overwritten or deleted destination files into this non-overlapping backup target
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub backup_dir: Option<String>,
    /// When extraneous destination files are deleted during `sync`: `after` (default), `during`, or `before`
    #[arg(
        long,
        value_name = "MODE",
        conflicts_with_all = ["delete_before", "delete_during", "delete_after"],
        help_heading = HEADING_SAFETY
    )]
    pub delete_mode: Option<String>,
    /// Alias for `--delete-mode before` (deletes extraneous destination files before transfers)
    #[arg(
        long,
        conflicts_with_all = ["delete_mode", "delete_during", "delete_after"],
        hide_short_help = true,
        help_heading = HEADING_SAFETY
    )]
    pub delete_before: bool,
    /// Alias for `--delete-mode during` (deletes extraneous destination files concurrently with transfers)
    #[arg(
        long,
        conflicts_with_all = ["delete_mode", "delete_before", "delete_after"],
        hide_short_help = true,
        help_heading = HEADING_SAFETY
    )]
    pub delete_during: bool,
    /// Alias for `--delete-mode after` (deletes extraneous destination files only after transfers succeed)
    #[arg(
        long,
        conflicts_with_all = ["delete_mode", "delete_before", "delete_during"],
        hide_short_help = true,
        help_heading = HEADING_SAFETY
    )]
    pub delete_after: bool,
    /// Follow local source symlinks and copy the pointed-to files/directories (detects symlink cycles)
    #[arg(short = 'L', long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub copy_links: bool,
    /// Local filesystem fsync durability mode: `always`, `batch` (default), or `never`
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub fsync: Option<String>,
    /// Freeze each source file into a private local snapshot before upload (protects actively mutated files)
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub strict_source: bool,
    /// Max per-file snapshot size allowed under `--strict-source` (default: 256M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub strict_source_max_size: Option<String>,
    /// Allow replacing a file with a directory (or vice versa)
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub force_type_replace: bool,
    /// Baseline persistence policy: `auto` (default, skip when mtime/hashes suffice), `all`, or `none`
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub baseline: Option<String>,
    /// Disable destination advisory process lock (for external orchestrators managing concurrency)
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub no_lock: bool,
    /// Output machine-readable JSON summary
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
    /// Show single-line live progress on stderr (TTY auto-enables TUI unless `--json`)
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub progress: bool,
    /// Force multi-task live terminal TUI dashboard on stderr (default on TTY unless `--json`)
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub tui: bool,
    /// Emit structured newline-delimited JSON (JSONL) progress events to stderr
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub json_progress: bool,
    /// Progress reporting interval for `--json-progress` (e.g. `1s`, `500ms`; default `1s`)
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub stats: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct MoveArgs {
    #[command(flatten)]
    pub transfer: TransferArgs,
    /// Prune empty source directories after all file moves succeed
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub delete_empty_src_dirs: bool,
}

#[derive(Debug, Args, Clone)]
pub struct DeleteArgs {
    /// Target path (local path or `remote:path`)
    pub target: String,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Abort if planned deletions exceed this threshold
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub max_delete: Option<u64>,
    /// Preview deletions without removing anything
    #[arg(short = 'n', long, help_heading = HEADING_SAFETY)]
    pub dry_run: bool,
    /// Output machine-readable JSON summary
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct SizeArgs {
    /// Target path (local path or `remote:path`)
    pub target: String,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Output machine-readable JSON summary
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct HashsumArgs {
    /// Checksum algorithm: `md5`, `sha256`, `sha1`, `crc32c`, `crc64nvme`
    pub hash: String,
    /// Target path (local path or `remote:path`)
    pub target: String,
    /// Concurrent hash computation workers
    #[arg(long, default_value_t = 8, help_heading = HEADING_PERF)]
    pub checkers: usize,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Output machine-readable JSON array
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct DedupeArgs {
    /// Target path (e.g. `gdrive:photos`)
    pub target: String,
    /// Resolution mode: `newest` (default), `oldest`, `largest`, `rename`, or `skip`
    #[arg(long, default_value = "newest")]
    pub mode: String,
    /// Preview actions without deleting or renaming any files
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Output machine-readable JSON report
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct PurgeArgs {
    /// Target directory/prefix to recursively delete
    pub target: String,
    /// Abort if planned deletions exceed this threshold
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub max_delete: Option<u64>,
    /// Preview purge without removing anything
    #[arg(short = 'n', long, help_heading = HEADING_SAFETY)]
    pub dry_run: bool,
    /// Output machine-readable JSON summary
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct CatArgs {
    /// Source file path (local path or `remote:path`)
    pub target: String,
    /// Byte offset to start reading from (zero-based; seekable on S3, GDrive, Local & Crypt!)
    #[arg(long, default_value_t = 0)]
    pub offset: u64,
    /// Maximum number of bytes to read (reads until EOF if omitted)
    #[arg(long)]
    pub count: Option<u64>,
    /// Hard cap for engine-owned BufferPool (e.g. 4M, 16M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub max_buffer_mem: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct RcatArgs {
    /// Destination file path (local path or `remote:path`)
    pub target: String,
    /// Max bytes allowed to spool from stdin into private temp file (default: 256M)
    #[arg(long, help_heading = HEADING_PERF)]
    pub max_spool: Option<String>,
    /// Override protocol chunk size for large uploads
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub chunk_size: Option<String>,
    /// Hard cap for engine-owned BufferPool (e.g. 4M, 16M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub max_buffer_mem: Option<String>,
}

#[derive(Debug, Args, Clone)]
pub struct BisyncArgs {
    /// Side A path (local path or `remote:path`)
    pub path_a: String,
    /// Side B path (local path or `remote:path`)
    pub path_b: String,
    /// Concurrent file transfers (default: config `[defaults]` or `4`)
    #[arg(long, help_heading = HEADING_PERF)]
    pub transfers: Option<usize>,
    /// Sustained bandwidth limit or time-of-day timetable (e.g. `10M`, `500K`, `"08:00,10M 23:00,off"`)
    #[arg(long, help_heading = HEADING_PERF)]
    pub bwlimit: Option<String>,
    /// Hard cap for engine-owned BufferPool (e.g. 8M, 16M)
    #[arg(long, hide_short_help = true, help_heading = HEADING_PERF)]
    pub max_buffer_mem: Option<String>,
    /// Simulate without mutating either side or persistent state
    #[arg(short = 'n', long, help_heading = HEADING_SAFETY)]
    pub dry_run: bool,
    /// Conflict resolution strategy: `keep-both` (default), `abort`, `prefer-a`, `prefer-b`
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub conflict_strategy: Option<String>,
    /// Allow merging two existing non-empty trees with no prior baseline
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub resync: bool,
    /// Abort deletions if planned deletes exceed this count (`100`), percentage (`50%`; default `50%`), or `off`
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub max_delete: Option<String>,
    /// Allow proceeding if one previously non-empty side suddenly appears empty (disables unmounted-drive guard)
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub force_empty_side: bool,
    /// Follow local symlinks when reading/listing both sides (detects symlink cycles; writes still block symlink escape)
    #[arg(short = 'L', long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub copy_links: bool,
    /// Local filesystem fsync durability mode: `always`, `batch` (default), or `never`
    #[arg(long, hide_short_help = true, help_heading = HEADING_SAFETY)]
    pub fsync: Option<String>,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Output machine-readable JSON summary
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
    /// Show single-line live progress on stderr (TTY auto-enables TUI unless `--json`)
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub progress: bool,
    /// Force multi-task live terminal TUI dashboard on stderr
    #[arg(long, hide_short_help = true, help_heading = HEADING_OUTPUT)]
    pub tui: bool,
}

#[derive(Debug, Args, Clone)]
pub struct CheckArgs {
    /// Source path (local path or `remote:path`)
    pub src: String,
    /// Destination path (local path or `remote:path`)
    pub dst: String,
    /// Concurrent checksum verification workers
    #[arg(long, default_value_t = 8, help_heading = HEADING_PERF)]
    pub checkers: usize,
    /// Compare file sizes only (skip checksum calculation)
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub size_only: bool,
    /// Only check that files in source exist and match in destination (ignore extra files in destination)
    #[arg(long, help_heading = HEADING_SAFETY)]
    pub one_way: bool,
    #[command(flatten)]
    pub filters: FilterArgs,
    /// Output machine-readable JSON report
    #[arg(long, help_heading = HEADING_OUTPUT)]
    pub json: bool,
}

#[derive(Debug, Args, Clone)]
pub struct TreeArgs {
    /// Target path (local path or `remote:path`)
    pub target: String,
    /// Maximum directory depth to descend (unlimited if omitted)
    #[arg(short = 'L', long)]
    pub max_depth: Option<usize>,
    /// Show directories only
    #[arg(short = 'd', long)]
    pub dirs_only: bool,
    /// Print human-readable file sizes
    #[arg(short = 's', long)]
    pub sizes: bool,
    #[command(flatten)]
    pub filters: FilterArgs,
}

/// Parse human byte sizes (`512`, `64K`, `16M`, `2G`, `64MiB`, `256KiB`).
pub fn parse_byte_size(input: &str) -> anyhow::Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(rship_core::Error::config("empty byte size").into());
    }
    let split_idx = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let num_str = &s[..split_idx];
    let unit = s[split_idx..].trim().to_ascii_lowercase();
    let num: u64 = num_str
        .parse()
        .map_err(|_| rship_core::Error::config(format!("invalid byte size `{input}`")))?;
    let mult: u64 = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024 * 1024 * 1024 * 1024,
        _ => {
            return Err(rship_core::Error::config(format!(
                "unknown size unit `{unit}` in `{input}`"
            ))
            .into());
        }
    };
    num.checked_mul(mult).ok_or_else(|| {
        rship_core::Error::config(format!("byte size `{input}` overflows u64")).into()
    })
}

/// Parse `--max-delete` accepting an integer deletion count (`100`), a percentage of
/// observed files (`50%`, `12.5%`), or `off` / `unlimited` to explicitly disable any
/// default or profile cap.
pub fn parse_max_delete(input: &str) -> anyhow::Result<(Option<u64>, Option<f64>)> {
    let s = input.trim();
    if s.is_empty() {
        return Err(rship_core::Error::config("--max-delete cannot be empty").into());
    }
    if s.eq_ignore_ascii_case("off") || s.eq_ignore_ascii_case("unlimited") {
        return Ok((None, None));
    }
    if let Some(pct_str) = s.strip_suffix('%') {
        let pct: f64 = pct_str.trim().parse().map_err(|_| {
            rship_core::Error::config(format!(
                "invalid --max-delete percentage `{input}` (expected e.g. `50%`)"
            ))
        })?;
        if !pct.is_finite() || !(0.0..=100.0).contains(&pct) {
            return Err(rship_core::Error::config(format!(
                "invalid --max-delete percentage `{input}` (must be between 0% and 100%)"
            ))
            .into());
        }
        Ok((None, Some(pct)))
    } else {
        let count: u64 = s.parse().map_err(|_| {
            rship_core::Error::config(format!(
                "invalid --max-delete `{input}` (expected integer count like `100`, percentage like `50%`, or `off`)"
            ))
        })?;
        Ok((Some(count), None))
    }
}

impl Command {
    /// Returns `true` when this subcommand invocation requested machine-readable `--json` output.
    pub fn wants_json(&self) -> bool {
        match self {
            Self::Ls { json, .. }
            | Self::About { json, .. }
            | Self::Status { json, .. }
            | Self::Resume { json, .. }
            | Self::Gc { json, .. } => *json,
            Self::Size(args) => args.json,
            Self::Check(args) => args.json,
            Self::Hashsum(args) => args.json,
            Self::Dedupe(args) => args.json,
            Self::Copy(args) | Self::Copyto(args) | Self::Sync(args) | Self::Moveto(args) => {
                args.json
            }
            Self::Move(args) => args.transfer.json,
            Self::Bisync(args) => args.json,
            Self::Delete(args) => args.json,
            Self::Purge(args) => args.json,
            Self::Config {
                action:
                    Some(
                        ConfigAction::List { json }
                        | ConfigAction::Profiles { json }
                        | ConfigAction::Test { json, .. },
                    ),
            } => *json,
            Self::Auth {
                action: Some(AuthAction::Export { json, .. }),
            } => *json,
            _ => false,
        }
    }

    /// Returns `true` when this subcommand invocation requested streaming `--json-progress` on stderr.
    pub fn wants_json_progress(&self) -> bool {
        match self {
            Self::Copy(args) | Self::Copyto(args) | Self::Sync(args) | Self::Moveto(args) => {
                args.json_progress
            }
            Self::Move(args) => args.transfer.json_progress,
            Self::Resume { json_progress, .. } => *json_progress,
            _ => false,
        }
    }

    /// Short canonical subcommand label included in structured JSON error envelopes.
    pub fn command_name(&self) -> &'static str {
        match self {
            Self::Ls { .. } => "ls",
            Self::Tree(_) => "tree",
            Self::Size(_) => "size",
            Self::About { .. } => "about",
            Self::Check(_) => "check",
            Self::Hashsum(_) => "hashsum",
            Self::Dedupe(_) => "dedupe",
            Self::Copy(_) => "copy",
            Self::Copyto(_) => "copyto",
            Self::Sync(_) => "sync",
            Self::Move(_) => "move",
            Self::Moveto(_) => "moveto",
            Self::Bisync(_) => "bisync",
            Self::Delete(_) => "delete",
            Self::Purge(_) => "purge",
            Self::Mkdir { .. } => "mkdir",
            Self::Cat(_) => "cat",
            Self::Rcat(_) => "rcat",
            Self::Completions { .. } => "completions",
            Self::Status { .. } => "status",
            Self::Resume { .. } => "resume",
            Self::Gc { .. } => "gc",
            Self::Auth { .. } => "auth",
            Self::Config { .. } => "config",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_command_definition_has_no_conflicts() {
        Cli::command().debug_assert();
    }

    #[test]
    fn short_help_hides_advanced_knobs_while_long_help_groups_them() {
        let mut cmd = Cli::command();
        cmd.build();
        let copy = cmd.find_subcommand_mut("copy").expect("copy subcommand");
        let short_help = copy.render_help().to_string();
        let long_help = copy.render_long_help().to_string();

        // Short help stays focused on everyday options and omits deep tuning/backend overrides.
        assert!(short_help.contains("--transfers"));
        assert!(short_help.contains("--adaptive"));
        assert!(short_help.contains("--dry-run"));
        assert!(short_help.contains("--delete-mode"));
        assert!(short_help.contains("--profile"));
        assert!(!short_help.contains("--drive-stop-on-upload-limit"));
        assert!(!short_help.contains("--strict-source-max-size"));
        assert!(!short_help.contains("--connect-timeout"));

        // Long help shows everything cleanly grouped under headings.
        assert!(long_help.contains("Performance & Concurrency:"));
        assert!(long_help.contains("Sync & Safety:"));
        assert!(long_help.contains("Filtering:"));
        assert!(long_help.contains("Network & Rate Limits:"));
        assert!(long_help.contains("Backend Overrides:"));
        assert!(long_help.contains("--drive-stop-on-upload-limit"));
        assert!(long_help.contains("--strict-source-max-size"));
    }

    #[test]
    fn parses_human_byte_sizes() {
        assert_eq!(parse_byte_size("256K").unwrap(), 256 * 1024);
        assert_eq!(parse_byte_size("128M").unwrap(), 128 * 1024 * 1024);
        assert_eq!(parse_byte_size("16MiB").unwrap(), 16 * 1024 * 1024);
        assert_eq!(parse_byte_size("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert!(parse_byte_size("12X").is_err());
    }

    #[test]
    fn parses_max_delete_count_and_percent() {
        assert_eq!(parse_max_delete("100").unwrap(), (Some(100), None));
        assert_eq!(parse_max_delete("0").unwrap(), (Some(0), None));
        assert_eq!(parse_max_delete("50%").unwrap(), (None, Some(50.0)));
        assert_eq!(parse_max_delete("12.5%").unwrap(), (None, Some(12.5)));
        assert_eq!(parse_max_delete("off").unwrap(), (None, None));
        assert_eq!(parse_max_delete("unlimited").unwrap(), (None, None));
        assert!(parse_max_delete("").is_err());
        assert!(parse_max_delete("-5%").is_err());
        assert!(parse_max_delete("101%").is_err());
        assert!(parse_max_delete("abc").is_err());
    }
}
