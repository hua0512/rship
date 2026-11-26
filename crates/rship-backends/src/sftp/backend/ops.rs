//! SFTP metadata, concurrent directory listing, directory creation, deletion,
//! and `statvfs@openssh.com` quota reporting.

use rship_core::backend::{BackendPath, EntryStream, ListOptions};
use rship_core::path::RelPath;
use rship_core::types::{Entry, EntryKind, StorageQuota};
use rship_core::{Error, Result};
use russh_sftp::protocol::FileAttributes;
use std::borrow::Cow;
use std::collections::VecDeque;
use tokio::sync::mpsc;

use crate::common::lock_unpoisoned;

use super::pool::{MAX_LIST_CONCURRENCY, SftpOpError, is_sftp_not_found};
use super::{BAK_PREFIX, PART_PREFIX, SftpBackend};

pub(super) fn is_special_node(meta: &FileAttributes) -> bool {
    let type_bits = meta.permissions.unwrap_or(0) & 0xF000;
    type_bits != 0 && !meta.is_dir() && !meta.is_regular() && !meta.is_symlink()
}

pub(super) fn is_regular_file_attrs(meta: &FileAttributes) -> bool {
    meta.is_regular() || (meta.permissions.unwrap_or(0) & 0xF000) == 0
}

pub(super) fn attrs_to_entry(
    meta: &FileAttributes,
    raw_path: impl AsRef<str>,
    nfc_path: RelPath,
) -> Option<Entry> {
    if is_special_node(meta) {
        return None;
    }
    let kind = if meta.is_dir() {
        EntryKind::Directory
    } else if meta.is_symlink() {
        EntryKind::Symlink
    } else {
        EntryKind::File
    };
    let size = if kind == EntryKind::File {
        meta.size.unwrap_or(0)
    } else {
        0
    };
    let mtime_ns = meta
        .mtime
        .map(|s| i64::from(s) * 1_000_000_000)
        .unwrap_or(0);
    Some(Entry {
        node_id: None,
        parent_id: None,
        raw_path: rship_core::types::raw_path_override(&nfc_path, raw_path.as_ref()),
        nfc_path,
        kind,
        size,
        mtime_ns,
        ctime_ns: None,
        etag: None,
        checksum: None,
    })
}

impl SftpBackend {
    pub(super) async fn stat_impl(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let raw_rel = path.raw_path();
        let rpath = self.remote_path(raw_rel);
        self.with_sftp_retry("stat", |sftp| {
            let rpath = rpath.clone();
            async move {
                match sftp.symlink_metadata(&rpath).await {
                    Ok(meta) => Ok(attrs_to_entry(&meta, raw_rel, path.nfc_path.clone())),
                    Err(e) if is_sftp_not_found(&e) => Ok(None),
                    Err(e) => Err(SftpOpError::Sftp(e)),
                }
            }
        })
        .await
    }

    pub(super) async fn list_with_options_impl(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let (tx, rx) = mpsc::channel::<Result<Entry>>(256);
        let base_depth = prefix.segments().count();
        let effective_max_depth = options.effective_max_depth();
        if effective_max_depth == Some(0) {
            return Ok(crate::common::rx_to_entry_stream(rx));
        }

        let backend = self.clone();
        let start = prefix.clone();
        let pruner = options.dir_pruner().cloned();
        let io_timeout = self.inner.cfg.io_timeout;

        tokio::spawn(async move {
            let mut queue: VecDeque<(String, RelPath)> = VecDeque::new();
            queue.push_back((start.as_str().to_string(), start));

            type SftpDirResult = (
                String,
                RelPath,
                Result<Option<russh_sftp::client::fs::ReadDir>>,
            );
            let mut in_flight: tokio::task::JoinSet<SftpDirResult> = tokio::task::JoinSet::new();

            loop {
                if tx.is_closed() {
                    in_flight.abort_all();
                    return;
                }
                while in_flight.len() < MAX_LIST_CONCURRENCY {
                    let Some((dir_raw, dir_nfc)) = queue.pop_front() else {
                        break;
                    };
                    let b = backend.clone();
                    in_flight.spawn(async move {
                        let rpath = b.remote_path(&dir_raw);
                        let res = b
                            .with_sftp_retry("read_dir", |sftp| {
                                let rpath = rpath.clone();
                                async move {
                                    match tokio::time::timeout(io_timeout, sftp.read_dir(&rpath))
                                        .await
                                    {
                                        Ok(Ok(rd)) => Ok(Some(rd)),
                                        Ok(Err(e)) if is_sftp_not_found(&e) => Ok(None),
                                        Ok(Err(e)) => Err(SftpOpError::Sftp(e)),
                                        Err(_) => Err(SftpOpError::Core(Error::timeout(format!(
                                            "SFTP read_dir stalled for {io_timeout:?}"
                                        )))),
                                    }
                                }
                            })
                            .await;
                        (dir_raw, dir_nfc, res)
                    });
                }
                let Some(joined) = in_flight.join_next().await else {
                    break;
                };
                let (dir_raw, dir_nfc, res) = match joined {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx
                            .send(Err(Error::protocol(format!("SFTP list task failed: {e}"))))
                            .await;
                        in_flight.abort_all();
                        return;
                    }
                };
                let entries = match res {
                    Ok(Some(rd)) => rd,
                    Ok(None) => continue,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        in_flight.abort_all();
                        return;
                    }
                };
                for de in entries {
                    let name = de.file_name();
                    if name.is_empty()
                        || name == "."
                        || name == ".."
                        || name.contains(['/', '\0'])
                        || name.starts_with(PART_PREFIX)
                        || name.starts_with(BAK_PREFIX)
                    {
                        continue;
                    }
                    let meta = de.metadata();
                    let raw_rel = if dir_raw.is_empty() {
                        name.clone()
                    } else {
                        format!("{dir_raw}/{name}")
                    };
                    // Unix filenames may legitimately contain `\`; map `\` -> `\u{FF3C}` in the
                    // canonical `RelPath` segment while preserving the literal `\` in `raw_rel`.
                    let nfc_seg: Cow<'_, str> = if name.contains('\\') {
                        Cow::Owned(name.replace('\\', "\u{FF3C}"))
                    } else {
                        Cow::Borrowed(&name)
                    };
                    let Ok(nfc_rel) = dir_nfc.join(&nfc_seg) else {
                        continue;
                    };
                    let rel_depth = nfc_rel.segments().count().saturating_sub(base_depth);
                    if effective_max_depth.is_some_and(|limit| rel_depth > limit) {
                        continue;
                    }
                    let is_dir = meta.is_dir();
                    if is_dir && pruner.as_ref().is_some_and(|p| p(&nfc_rel)) {
                        continue;
                    }
                    let Some(entry) = attrs_to_entry(&meta, &raw_rel, nfc_rel.clone()) else {
                        continue;
                    };
                    if tx.send(Ok(entry)).await.is_err() {
                        in_flight.abort_all();
                        return;
                    }
                    if is_dir && effective_max_depth.is_none_or(|limit| rel_depth < limit) {
                        queue.push_back((raw_rel, nfc_rel));
                    }
                }
            }
        });

        Ok(crate::common::rx_to_entry_stream(rx))
    }

    pub(super) async fn mkdir_impl(&self, path: &RelPath) -> Result<()> {
        if path.is_root() {
            return Ok(());
        }
        if lock_unpoisoned(&self.inner.known_dirs).contains(path.as_str()) {
            return Ok(());
        }
        let _guard = self.inner.mkdir_lock.lock().await;
        if lock_unpoisoned(&self.inner.known_dirs).contains(path.as_str()) {
            return Ok(());
        }

        self.with_sftp_retry("mkdir", |sftp| async move {
            let mut acc = String::new();
            for seg in path.segments() {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(seg);
                if lock_unpoisoned(&self.inner.known_dirs).contains(&acc) {
                    continue;
                }
                let rpath = self.remote_path(&acc);
                match sftp.symlink_metadata(&rpath).await {
                    Ok(m) if m.is_dir() => {
                        lock_unpoisoned(&self.inner.known_dirs).insert(acc.clone());
                    }
                    Ok(_) => {
                        return Err(SftpOpError::Core(Error::conflict(format!(
                            "SFTP mkdir `{acc}` blocked by existing file"
                        ))));
                    }
                    Err(e) if is_sftp_not_found(&e) => {
                        if let Err(ce) = sftp.create_dir(&rpath).await
                            && !sftp
                                .symlink_metadata(&rpath)
                                .await
                                .is_ok_and(|m| m.is_dir())
                        {
                            return Err(SftpOpError::Sftp(ce));
                        }
                        lock_unpoisoned(&self.inner.known_dirs).insert(acc.clone());
                    }
                    Err(e) => return Err(SftpOpError::Sftp(e)),
                }
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn delete_impl(&self, path: &BackendPath) -> Result<()> {
        if path.nfc_path.is_root() {
            return Ok(());
        }
        let raw_rel = path.raw_path();
        let rpath = self.remote_path(raw_rel);
        self.with_sftp_retry("delete", |sftp| {
            let rpath = rpath.clone();
            async move {
                let meta = match sftp.symlink_metadata(&rpath).await {
                    Ok(m) => m,
                    Err(e) if is_sftp_not_found(&e) => return Ok(()),
                    Err(e) => return Err(SftpOpError::Sftp(e)),
                };
                let res = if meta.is_dir() {
                    sftp.remove_dir(&rpath).await
                } else {
                    sftp.remove_file(&rpath).await
                };
                match res {
                    Ok(()) => {
                        let mut dirs = lock_unpoisoned(&self.inner.known_dirs);
                        let target = path.nfc_path.as_str();
                        let prefix = format!("{target}/");
                        dirs.retain(|d| d != target && !d.starts_with(&prefix));
                        Ok(())
                    }
                    Err(e) if is_sftp_not_found(&e) => Ok(()),
                    Err(e) => Err(SftpOpError::Sftp(e)),
                }
            }
        })
        .await
    }

    pub(super) async fn about_impl(&self) -> Result<Option<StorageQuota>> {
        let rpath = self.remote_path("");
        let res = self
            .with_sftp_retry("about", |sftp| {
                let rpath = rpath.clone();
                async move {
                    match sftp.fs_info(&rpath).await {
                        Ok(Some(st)) => {
                            let unit = if st.fragment_size > 0 {
                                st.fragment_size
                            } else {
                                st.block_size
                            };
                            let total = st.blocks.saturating_mul(unit);
                            let free_avail = st.blocks_avail.saturating_mul(unit);
                            let free_total = st.blocks_free.saturating_mul(unit);
                            Ok(Some(StorageQuota {
                                total_bytes: Some(total),
                                used_bytes: Some(total.saturating_sub(free_total)),
                                free_bytes: Some(free_avail),
                                trashed_bytes: None,
                            }))
                        }
                        Ok(None) => Ok(None),
                        Err(e) => Err(SftpOpError::Sftp(e)),
                    }
                }
            })
            .await;
        Ok(res.unwrap_or(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs_with_mode(mode: u32, size: u64) -> FileAttributes {
        FileAttributes {
            size: Some(size),
            permissions: Some(mode),
            mtime: Some(1_700_000_000),
            ..Default::default()
        }
    }

    #[test]
    fn attrs_to_entry_skips_posix_special_nodes_and_preserves_regular_and_untyped() {
        let nfc = RelPath::parse("item").unwrap();
        for special_mode in [0o010644, 0o020644, 0o050644, 0o060644, 0o140755] {
            assert!(
                attrs_to_entry(&attrs_with_mode(special_mode, 0), "item", nfc.clone()).is_none(),
                "mode {special_mode:#o} must be skipped"
            );
        }
        let reg = attrs_to_entry(&attrs_with_mode(0o100644, 123), "item", nfc.clone()).unwrap();
        assert_eq!(reg.kind, EntryKind::File);
        assert_eq!(reg.size, 123);

        let untyped = FileAttributes {
            size: Some(99),
            permissions: None,
            mtime: Some(1_700_000_000),
            ..Default::default()
        };
        let untyped_entry = attrs_to_entry(&untyped, "item", nfc).unwrap();
        assert_eq!(untyped_entry.kind, EntryKind::File);
        assert_eq!(untyped_entry.size, 99);
    }
}
