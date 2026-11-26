use directories::{BaseDirs, ProjectDirs};
use rship_core::{Error, Result};
use std::path::{Path, PathBuf};

use super::AppConfig;

/// Resolved filesystem layout for `config.toml`, SQLite state, locks, ephemeral sync DBs,
/// and OAuth/service-account token files.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AppPaths {
    /// Path to `config.toml`.
    pub config_file: PathBuf,
    /// Root directory for `state.db`, `locks/`, `runs/`, and `tokens/`.
    pub state_dir: PathBuf,
}

impl AppPaths {
    /// Construct an explicit [`AppPaths`] from a config file path and state directory.
    pub fn new(config_file: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_file: config_file.into(),
            state_dir: state_dir.into(),
        }
    }

    /// Resolve OS-standard config and data directories with optional explicit overrides.
    pub fn resolve(config_override: Option<PathBuf>, state_override: Option<PathBuf>) -> Self {
        let proj = ProjectDirs::from("dev", "rship", "rship");
        let config_file = config_override.unwrap_or_else(|| {
            proj.as_ref()
                .map(|p| p.config_dir().join("config.toml"))
                .unwrap_or_else(|| PathBuf::from(".rship/config.toml"))
        });
        let state_dir = state_override.unwrap_or_else(|| {
            proj.as_ref()
                .map(|p| p.data_local_dir().to_path_buf())
                .unwrap_or_else(|| PathBuf::from(".rship/state"))
        });
        Self {
            config_file,
            state_dir,
        }
    }

    /// Path to persistent WAL-mode SQLite `journal.db` (jobs, active resumable operations).
    pub fn journal_db_path(&self) -> PathBuf {
        self.state_dir.join("journal.db")
    }

    /// Directory holding lazily created per-pair `WITHOUT ROWID` baseline SQLite shards.
    pub fn baselines_dir(&self) -> PathBuf {
        self.state_dir.join("baselines")
    }

    /// Directory holding lazily created per-scope delta inventory SQLite shards.
    pub fn inventory_dir(&self) -> PathBuf {
        self.state_dir.join("inventory")
    }

    /// Directory holding cross-platform advisory process locks.
    pub fn locks_dir(&self) -> PathBuf {
        self.state_dir.join("locks")
    }

    /// Directory holding ephemeral per-run `run-<job_id>/sync.db` folders, SQLite sort
    /// scratch files, S3 upload spools, and `--strict-source` snapshots.
    pub fn ephemeral_dir(&self) -> PathBuf {
        self.state_dir.join("runs")
    }

    /// Dedicated disk-backed scratch directory exported via `SQLITE_TMPDIR` so SQLite
    /// external sorts never overflow small RAM-backed `/tmp` (`tmpfs`) mounts.
    pub fn sqlite_tmp_dir(&self) -> PathBuf {
        self.ephemeral_dir().join("sqlite-tmp")
    }

    /// Dedicated spool directory for S3 hashed uploads (avoids OS `/tmp` `tmpfs` exhaustion).
    pub fn s3_spool_dir(&self) -> PathBuf {
        self.ephemeral_dir().join("s3-spool")
    }

    /// Directory holding per-remote OAuth token and inline service-account files.
    pub fn tokens_dir(&self) -> PathBuf {
        self.state_dir.join("tokens")
    }

    /// OAuth token file path for a Google Drive remote.
    pub fn token_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.json"))
    }

    /// OAuth token file path for a OneDrive remote.
    pub fn onedrive_token_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.onedrive.json"))
    }

    /// OAuth token file path for a Dropbox remote.
    pub fn dropbox_token_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.dropbox.json"))
    }

    /// OAuth token file path for a Google Cloud Storage remote.
    pub fn gcs_token_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.gcs.json"))
    }

    /// Extracted Service Account key file path for a Google Cloud Storage remote.
    pub fn gcs_service_account_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.gcs.sa.json"))
    }

    /// Extracted Service Account key file path for a Google Drive remote.
    pub fn service_account_file_for(&self, remote: &str) -> PathBuf {
        self.tokens_dir().join(format!("{remote}.sa.json"))
    }
}

/// Write sensitive credential/bundle bytes to `path` with `0o600` permissions set at
/// file creation time on Unix (eliminating any `write` -> `chmod` TOCTOU window).
pub fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::io(format!("create directory `{}`", parent.display()), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| Error::io(format!("open `{}`", path.display()), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten permissions if the file already existed with a broader mode.
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    file.write_all(content)
        .map_err(|e| Error::io(format!("write `{}`", path.display()), e))?;
    file.sync_all()
        .map_err(|e| Error::io(format!("sync `{}`", path.display()), e))?;
    Ok(())
}

/// Load an [`AppConfig`] from a TOML file, returning [`AppConfig::default`] if the file does not exist.
pub fn load_config(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("failed to read config `{}`", path.display()), e))?;
    toml::from_str(&raw)
        .map_err(|e| Error::config(format!("failed to parse TOML `{}`: {e}", path.display())))
}

/// Atomically persist an [`AppConfig`] to `path` with `0o600` permissions on Unix.
pub fn save_config(path: &Path, cfg: &AppConfig) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::io(
                format!("failed to create config dir `{}`", parent.display()),
                e,
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let encoded = toml::to_string_pretty(cfg)
        .map_err(|e| Error::protocol(format!("failed to serialize config TOML: {e}")))?;

    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config.toml");
    let tmp = path.with_file_name(format!(".{file_name}.{pid}.{seq}.tmp"));

    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp).map_err(|e| {
            Error::io(
                format!("failed to create temp config `{}`", tmp.display()),
                e,
            )
        })?;
        file.write_all(encoded.as_bytes()).map_err(|e| {
            Error::io(
                format!("failed to write temp config `{}`", tmp.display()),
                e,
            )
        })?;
        file.sync_all()
            .map_err(|e| Error::io(format!("failed to sync temp config `{}`", tmp.display()), e))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    let mut last_err = None;
    for attempt in 0..8u32 {
        match std::fs::rename(&tmp, path) {
            Ok(()) => {
                last_err = None;
                break;
            }
            Err(e) if attempt < 7 && is_transient_config_fs_err(&e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(
                    10 * u64::from(attempt + 1),
                ));
            }
            Err(e) => {
                last_err = Some(e);
                break;
            }
        }
    }
    if let Some(e) = last_err {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::io(
            format!("failed to save config `{}`", path.display()),
            e,
        ));
    }
    Ok(())
}

fn is_transient_config_fs_err(e: &std::io::Error) -> bool {
    let kind_match = matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AlreadyExists
    );
    #[cfg(windows)]
    {
        kind_match || matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33))
    }
    #[cfg(not(windows))]
    {
        kind_match
    }
}

/// Locate the default `rclone.conf` file if no explicit path was supplied.
pub fn default_rclone_conf_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("RCLONE_CONFIG")
        && !env_path.trim().is_empty()
    {
        return Some(PathBuf::from(env_path));
    }
    let base = BaseDirs::new()?;
    let candidates = [
        base.config_dir().join("rclone").join("rclone.conf"),
        base.home_dir()
            .join(".config")
            .join("rclone")
            .join("rclone.conf"),
        base.home_dir().join(".rclone.conf"),
    ];
    candidates.into_iter().find(|p| p.exists())
}
