//! Durable OAuth2 token stores: atomic `0600` file persistence with cross-process
//! sibling `.lock` serialization, plus an in-memory store for tests.

use rship_core::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;

use super::{OAuthToken, StoredOAuthToken};

/// Durable token storage abstraction (file-backed in production, in-memory in tests).
pub trait TokenStore: Send + Sync {
    fn load(&self) -> Result<Option<OAuthToken>>;
    fn save(&self, token: &OAuthToken) -> Result<()>;

    /// Load a persisted token alongside its optional per-token proactive refresh margin.
    fn load_with_margin(&self) -> Result<Option<(OAuthToken, Option<i64>)>> {
        Ok(self.load()?.map(|tok| (tok, None)))
    }

    /// Persist a token alongside an optional per-token proactive refresh margin.
    fn save_with_margin(
        &self,
        token: &OAuthToken,
        _refresh_margin_secs: Option<i64>,
    ) -> Result<()> {
        self.save(token)
    }

    /// Acquire an optional cross-process exclusive lock serializing OAuth refresh
    /// operations against this store (implemented by [`FileTokenStore`]).
    fn lock_refresh(&self) -> Result<Option<Box<dyn Send>>> {
        Ok(None)
    }
}

/// File-backed atomic token store (`0700` parent directory and `0600` file on Unix)
/// with cross-process sibling `.lock` coordination via safe `std::fs::File::lock`.
#[derive(Debug, Clone)]
pub struct FileTokenStore {
    path: PathBuf,
}

impl FileTokenStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_path(&self) -> PathBuf {
        let mut os = self.path.as_os_str().to_os_string();
        os.push(".lock");
        PathBuf::from(os)
    }

    fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::io(format!("create token dir `{}`", parent.display()), e))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(())
    }

    fn read_raw_string(&self) -> Result<Option<String>> {
        let mut last_err = None;
        let mut raw = None;
        for attempt in 0..8u32 {
            match std::fs::read_to_string(&self.path) {
                Ok(s) => {
                    raw = Some(s);
                    last_err = None;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) if attempt < 7 && is_transient_fs_contention(&e) => {
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
        match raw {
            Some(s) => Ok(Some(s)),
            None => Err(Error::io(
                format!("read token file `{}`", self.path.display()),
                last_err.expect("error present when read failed"),
            )),
        }
    }

    fn write_atomic_bytes(&self, data: &[u8]) -> Result<()> {
        self.ensure_parent_dir()?;

        // Unique per-process/per-call temp filename so concurrent subprocesses refreshing
        // the same remote token never collide on a shared `.json.tmp` path.
        static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pid = std::process::id();
        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("token.json");
        let tmp = self
            .path
            .with_file_name(format!(".{file_name}.{pid}.{seq}.tmp"));

        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&tmp)
                .map_err(|e| Error::io(format!("create temp token `{}`", tmp.display()), e))?;
            f.write_all(data)
                .map_err(|e| Error::io(format!("write temp token `{}`", tmp.display()), e))?;
            f.sync_all()
                .map_err(|e| Error::io(format!("sync temp token `{}`", tmp.display()), e))?;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }

        // Atomic in-place replace without removing the existing file first (prevents
        // concurrent readers in other processes from ever observing ENOENT).
        let mut last_err = None;
        for attempt in 0..8u32 {
            match std::fs::rename(&tmp, &self.path) {
                Ok(()) => {
                    last_err = None;
                    break;
                }
                Err(e) if attempt < 7 && is_transient_fs_contention(&e) => {
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
                format!("commit token file `{}`", self.path.display()),
                e,
            ));
        }
        Ok(())
    }
}

struct FileLockGuard {
    file: std::fs::File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn is_transient_fs_contention(e: &std::io::Error) -> bool {
    if matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::AlreadyExists
    ) {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_ACCESS_DENIED (5), ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33)
        if matches!(e.raw_os_error(), Some(5) | Some(32) | Some(33)) {
            return true;
        }
    }
    false
}

impl TokenStore for FileTokenStore {
    fn load(&self) -> Result<Option<OAuthToken>> {
        let Some(raw) = self.read_raw_string()? else {
            return Ok(None);
        };
        let tok: OAuthToken = serde_json::from_str(&raw).map_err(|e| {
            Error::protocol(format!("parse token file `{}`: {e}", self.path.display()))
        })?;
        Ok(Some(tok))
    }

    fn save(&self, token: &OAuthToken) -> Result<()> {
        let data = serde_json::to_vec_pretty(token)
            .map_err(|e| Error::protocol(format!("encode token JSON: {e}")))?;
        self.write_atomic_bytes(&data)
    }

    fn load_with_margin(&self) -> Result<Option<(OAuthToken, Option<i64>)>> {
        let Some(raw) = self.read_raw_string()? else {
            return Ok(None);
        };
        let stored: StoredOAuthToken = serde_json::from_str(&raw).map_err(|e| {
            Error::protocol(format!("parse token file `{}`: {e}", self.path.display()))
        })?;
        Ok(Some((stored.token, stored.refresh_margin_secs)))
    }

    fn save_with_margin(&self, token: &OAuthToken, refresh_margin_secs: Option<i64>) -> Result<()> {
        let stored = StoredOAuthToken {
            token: token.clone(),
            refresh_margin_secs,
        };
        let data = serde_json::to_vec_pretty(&stored)
            .map_err(|e| Error::protocol(format!("encode token JSON: {e}")))?;
        self.write_atomic_bytes(&data)
    }

    fn lock_refresh(&self) -> Result<Option<Box<dyn Send>>> {
        self.ensure_parent_dir()?;
        let lock_path = self.lock_path();
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut last_err = None;
        let mut opened = None;
        for attempt in 0..8u32 {
            match opts.open(&lock_path) {
                Ok(f) => {
                    opened = Some(f);
                    last_err = None;
                    break;
                }
                Err(e) if attempt < 7 && is_transient_fs_contention(&e) => {
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
        let file = match opened {
            Some(f) => f,
            None => {
                return Err(Error::io(
                    format!("open token lock file `{}`", lock_path.display()),
                    last_err.expect("error present when open failed"),
                ));
            }
        };
        file.lock()
            .map_err(|e| Error::io(format!("lock token file `{}`", lock_path.display()), e))?;
        Ok(Some(Box::new(FileLockGuard { file })))
    }
}

/// In-memory token store for deterministic unit/integration tests.
#[derive(Debug, Default)]
pub struct InMemoryTokenStore {
    token: StdMutex<Option<(OAuthToken, Option<i64>)>>,
}

impl InMemoryTokenStore {
    pub fn new(initial: Option<OAuthToken>) -> Self {
        Self {
            token: StdMutex::new(initial.map(|tok| (tok, None))),
        }
    }
}

impl TokenStore for InMemoryTokenStore {
    fn load(&self) -> Result<Option<OAuthToken>> {
        Ok(self
            .token
            .lock()
            .expect("token mutex")
            .as_ref()
            .map(|(tok, _)| tok.clone()))
    }

    fn save(&self, token: &OAuthToken) -> Result<()> {
        *self.token.lock().expect("token mutex") = Some((token.clone(), None));
        Ok(())
    }

    fn load_with_margin(&self) -> Result<Option<(OAuthToken, Option<i64>)>> {
        Ok(self.token.lock().expect("token mutex").clone())
    }

    fn save_with_margin(&self, token: &OAuthToken, refresh_margin_secs: Option<i64>) -> Result<()> {
        *self.token.lock().expect("token mutex") = Some((token.clone(), refresh_margin_secs));
        Ok(())
    }
}
