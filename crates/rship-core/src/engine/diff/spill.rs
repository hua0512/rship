use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::BackendPath;
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::state::{RunScratchDir, SourceVersion};
use crate::types::{EntryKind, NodeId};

/// Default in-memory threshold for [`DeleteSpillLog`] (`~1.5 MiB` RAM; zero disk I/O for
/// 99.9% of syncs, transparently spilling to a binary log above `16,384` deletions).
pub const DELETE_SPILL_RAM_CAP: usize = 16_384;
/// Batch size used when flushing spilled [`DeleteSpillLog`] items via `spawn_blocking`.
const DELETE_SPILL_FLUSH_BATCH: usize = 1_024;

/// Record stored in [`DeleteSpillLog`].
#[derive(Debug, Clone)]
pub struct DeleteTarget {
    pub nfc_path: RelPath,
    pub backend_path: BackendPath,
    pub kind: EntryKind,
    /// Optional observed version tuple verified via re-stat before deletion (used by `bisync`).
    pub expected_version: Option<SourceVersion>,
}

/// Hybrid in-RAM -> disk spill log for Phase 3 `--delete-after` candidates.
///
/// Keeps up to `ram_cap` (default `16,384` items = ~1.5 MiB) strictly in RAM with zero disk
/// I/O, transparently spilling to a compact binary log inside `RunScratchDir` above `ram_cap`
/// so `--max-delete 10_000_000` or 40M-object syncs never spike memory.
pub struct DeleteSpillLog {
    ram_cap: usize,
    ram_items: Vec<DeleteTarget>,
    spill_writer: Option<BufWriter<File>>,
    spill_path: Option<PathBuf>,
    scratch_dir: Option<Arc<dyn RunScratchDir>>,
    total_count: u64,
}

impl DeleteSpillLog {
    pub fn new(scratch_dir: Option<Arc<dyn RunScratchDir>>) -> Self {
        Self::with_ram_cap(scratch_dir, DELETE_SPILL_RAM_CAP)
    }

    pub fn with_ram_cap(scratch_dir: Option<Arc<dyn RunScratchDir>>, ram_cap: usize) -> Self {
        Self {
            ram_cap,
            ram_items: Vec::new(),
            spill_writer: None,
            spill_path: None,
            scratch_dir,
            total_count: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.total_count
    }

    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    #[cfg(test)]
    pub(super) fn spill_path(&self) -> Option<&PathBuf> {
        self.spill_path.as_ref()
    }

    pub fn is_spilled(&self) -> bool {
        self.spill_path.is_some()
    }

    /// Synchronous [`Self::push_async`] for tests of logs without a scratch directory.
    #[cfg(test)]
    pub(crate) fn push(&mut self, item: DeleteTarget) -> Result<()> {
        self.total_count += 1;
        if self.spill_writer.is_none() && self.ram_items.len() < self.ram_cap {
            self.ram_items.push(item);
            return Ok(());
        }
        self.ensure_spill_writer()?;
        if !self.ram_items.is_empty() {
            let drained = std::mem::take(&mut self.ram_items);
            let w = self
                .spill_writer
                .as_mut()
                .expect("spill writer initialized");
            for old in drained {
                write_delete_record(w, &old)?;
            }
        }
        let w = self
            .spill_writer
            .as_mut()
            .expect("spill writer initialized");
        write_delete_record(w, &item)?;
        Ok(())
    }

    /// Async-safe push: keeps the `<= ram_cap` in-memory fast path
    /// zero-overhead (no `spawn_blocking` or disk I/O) and offloads spill-file creation and
    /// batched writes onto Tokio's blocking thread pool once spilled to disk.
    pub async fn push_async(&mut self, item: DeleteTarget) -> Result<()> {
        self.total_count += 1;
        if self.spill_writer.is_none() {
            if self.ram_items.len() < self.ram_cap {
                self.ram_items.push(item);
                return Ok(());
            }
            let mut batch = std::mem::take(&mut self.ram_items);
            batch.push(item);
            self.flush_batch_to_spill_async(batch).await
        } else {
            self.ram_items.push(item);
            if self.ram_items.len() >= DELETE_SPILL_FLUSH_BATCH {
                let batch = std::mem::take(&mut self.ram_items);
                self.flush_batch_to_spill_async(batch).await?;
            }
            Ok(())
        }
    }

    async fn flush_batch_to_spill_async(&mut self, batch: Vec<DeleteTarget>) -> Result<()> {
        let spill_dir = if self.spill_writer.is_none() {
            Some(spill_dir(self.scratch_dir.as_ref()).await?)
        } else {
            None
        };
        let existing_writer = self.spill_writer.take();
        let existing_path = self.spill_path.take();
        let (writer, path, write_res) = tokio::task::spawn_blocking(move || {
            let (mut writer, path) = match (existing_writer, existing_path, spill_dir) {
                (Some(w), Some(p), _) => (w, p),
                (_, _, dir) => match create_spill_writer(
                    dir.unwrap_or_else(|| std::env::temp_dir().join("rship-delete-spill")),
                ) {
                    Ok(created) => created,
                    Err(e) => return (None, None, Err(e)),
                },
            };
            for item in &batch {
                if let Err(e) = write_delete_record(&mut writer, item) {
                    return (Some(writer), Some(path), Err(e));
                }
            }
            (Some(writer), Some(path), Ok(()))
        })
        .await
        .map_err(|e| Error::protocol(format!("delete spill write join: {e}")))?;
        self.spill_writer = writer;
        self.spill_path = path;
        write_res
    }

    #[cfg(test)]
    fn ensure_spill_writer(&mut self) -> Result<()> {
        if self.spill_writer.is_some() {
            return Ok(());
        }
        assert!(
            self.scratch_dir.is_none(),
            "the synchronous push is only for logs without a scratch directory"
        );
        let (writer, path) = create_spill_writer(std::env::temp_dir().join("rship-delete-spill"))?;
        self.spill_writer = Some(writer);
        self.spill_path = Some(path);
        Ok(())
    }

    /// Consume this log and iterate over all recorded [`DeleteTarget`]s in chunks of `chunk_size`
    /// with strictly bounded RAM (`O(chunk_size)`).
    pub fn into_reader(mut self) -> Result<DeleteSpillReader> {
        if let Some(mut w) = self.spill_writer.take() {
            let tail = std::mem::take(&mut self.ram_items);
            for item in &tail {
                write_delete_record(&mut w, item)?;
            }
            w.flush()
                .map_err(|e| Error::io("flush delete spill log", e))?;
        }
        let path = self.spill_path.take();
        let ram = std::mem::take(&mut self.ram_items);
        let reader = match path {
            Some(ref p) => {
                let f = File::open(p).map_err(|e| {
                    Error::io(format!("open delete spill log `{}`", p.display()), e)
                })?;
                Some(BufReader::with_capacity(256 * 1024, f))
            }
            None => None,
        };
        Ok(DeleteSpillReader {
            ram: ram.into_iter(),
            reader,
            path,
        })
    }

    /// Async-safe variant of [`Self::into_reader`]: zero-overhead for in-memory logs, and
    /// offloads final flush + reopen onto `tokio::task::spawn_blocking` when spilled.
    pub async fn into_reader_async(mut self) -> Result<DeleteSpillReader> {
        if self.spill_writer.is_none() && self.spill_path.is_none() {
            let ram = std::mem::take(&mut self.ram_items);
            return Ok(DeleteSpillReader {
                ram: ram.into_iter(),
                reader: None,
                path: None,
            });
        }
        let writer = self.spill_writer.take();
        let path = self.spill_path.take();
        let tail = std::mem::take(&mut self.ram_items);
        let (reader, path) = tokio::task::spawn_blocking(move || {
            if let Some(mut w) = writer {
                for item in &tail {
                    if let Err(e) = write_delete_record(&mut w, item) {
                        drop(w);
                        if let Some(ref p) = path {
                            let _ = std::fs::remove_file(p);
                        }
                        return Err(e);
                    }
                }
                if let Err(e) = w.flush() {
                    drop(w);
                    if let Some(ref p) = path {
                        let _ = std::fs::remove_file(p);
                    }
                    return Err(Error::io("flush delete spill log", e));
                }
            }
            let reader = match path {
                Some(ref p) => {
                    let f = File::open(p).map_err(|e| {
                        Error::io(format!("open delete spill log `{}`", p.display()), e)
                    })?;
                    Some(BufReader::with_capacity(256 * 1024, f))
                }
                None => None,
            };
            Ok((reader, path))
        })
        .await
        .map_err(|e| Error::protocol(format!("delete spill open join: {e}")))??;
        Ok(DeleteSpillReader {
            ram: Vec::new().into_iter(),
            reader,
            path,
        })
    }
}

async fn spill_dir(scratch_dir: Option<&Arc<dyn RunScratchDir>>) -> Result<PathBuf> {
    Ok(match scratch_dir {
        Some(s) => s.ensure_subdir("delete-spill").await?,
        None => std::env::temp_dir().join("rship-delete-spill"),
    })
}

fn create_spill_writer(dir: PathBuf) -> Result<(BufWriter<File>, PathBuf)> {
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::io(format!("create delete spill dir `{}`", dir.display()), e))?;
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let path = dir.join(format!(
        "delete-{}-{}.log",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| Error::io(format!("create delete spill log `{}`", path.display()), e))?;
    Ok((BufWriter::with_capacity(256 * 1024, file), path))
}

impl Drop for DeleteSpillLog {
    fn drop(&mut self) {
        let writer = self.spill_writer.take();
        let path = self.spill_path.take();
        if let Some(p) = path {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn_blocking(move || {
                    drop(writer);
                    let _ = std::fs::remove_file(p);
                });
            } else {
                drop(writer);
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

pub struct DeleteSpillReader {
    ram: std::vec::IntoIter<DeleteTarget>,
    reader: Option<BufReader<File>>,
    path: Option<PathBuf>,
}

impl DeleteSpillReader {
    /// Read up to `max_items` delete targets into `out` (`Ok(0)` at EOF).
    pub fn next_chunk(&mut self, max_items: usize, out: &mut Vec<DeleteTarget>) -> Result<usize> {
        out.clear();
        if self.reader.is_none() {
            for item in self.ram.by_ref().take(max_items) {
                out.push(item);
            }
            return Ok(out.len());
        }
        let r = self.reader.as_mut().unwrap();
        while out.len() < max_items {
            match read_delete_record(r)? {
                Some(item) => out.push(item),
                None => break,
            }
        }
        Ok(out.len())
    }

    /// Async-safe variant of [`Self::next_chunk`]: zero-overhead for in-memory logs, and
    /// offloads spilled file reads onto `tokio::task::spawn_blocking`.
    pub async fn next_chunk_async(
        &mut self,
        max_items: usize,
        out: &mut Vec<DeleteTarget>,
    ) -> Result<usize> {
        out.clear();
        if self.reader.is_none() {
            for item in self.ram.by_ref().take(max_items) {
                out.push(item);
            }
            return Ok(out.len());
        }
        let mut r = self.reader.take().expect("reader verified Some");
        let (r, res) = tokio::task::spawn_blocking(move || {
            let mut items = Vec::with_capacity(max_items.min(4096));
            while items.len() < max_items {
                match read_delete_record(&mut r) {
                    Ok(Some(item)) => items.push(item),
                    Ok(None) => break,
                    Err(e) => return (r, Err(e)),
                }
            }
            (r, Ok(items))
        })
        .await
        .map_err(|e| Error::protocol(format!("delete spill read join: {e}")))?;
        self.reader = Some(r);
        let items = res?;
        let n = items.len();
        *out = items;
        Ok(n)
    }
}

impl Drop for DeleteSpillReader {
    fn drop(&mut self) {
        let reader = self.reader.take();
        let path = self.path.take();
        if let Some(p) = path {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn_blocking(move || {
                    drop(reader);
                    let _ = std::fs::remove_file(p);
                });
            } else {
                drop(reader);
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

fn write_delete_record(w: &mut BufWriter<File>, t: &DeleteTarget) -> Result<()> {
    let kind_b: u8 = match t.kind {
        EntryKind::File => 0,
        EntryKind::Directory => 1,
        EntryKind::Symlink => 2,
    };
    let nfc = t.nfc_path.as_str().as_bytes();
    let raw = t
        .backend_path
        .raw_path
        .as_deref()
        .map(str::as_bytes)
        .unwrap_or(&[]);
    let node = t
        .backend_path
        .node_id
        .as_ref()
        .map(|n| n.as_str().as_bytes())
        .unwrap_or(&[]);
    let ver_flags: u8 = match &t.expected_version {
        None => 0,
        Some(v) => {
            0x01 | (u8::from(v.node_id.is_some()) << 1)
                | (u8::from(v.ctime_ns.is_some()) << 2)
                | (u8::from(v.etag.is_some()) << 3)
        }
    };

    let mut hdr = [0u8; 14];
    hdr[0] = kind_b;
    hdr[1] = ver_flags;
    hdr[2..6].copy_from_slice(&(nfc.len() as u32).to_le_bytes());
    hdr[6..10].copy_from_slice(&(raw.len() as u32).to_le_bytes());
    hdr[10..14].copy_from_slice(&(node.len() as u32).to_le_bytes());
    w.write_all(&hdr)
        .and_then(|()| w.write_all(nfc))
        .and_then(|()| w.write_all(raw))
        .and_then(|()| w.write_all(node))
        .map_err(|e| Error::io("write delete spill record", e))?;

    if let Some(v) = &t.expected_version {
        let mut fixed = [0u8; 16];
        fixed[0..8].copy_from_slice(&v.size.to_le_bytes());
        fixed[8..16].copy_from_slice(&v.mtime_ns.to_le_bytes());
        w.write_all(&fixed)
            .map_err(|e| Error::io("write delete spill version header", e))?;
        if let Some(c) = v.ctime_ns {
            w.write_all(&c.to_le_bytes())
                .map_err(|e| Error::io("write delete spill version ctime", e))?;
        }
        if let Some(nid) = &v.node_id {
            let b = nid.as_str().as_bytes();
            w.write_all(&(b.len() as u32).to_le_bytes())
                .and_then(|()| w.write_all(b))
                .map_err(|e| Error::io("write delete spill version node_id", e))?;
        }
        if let Some(etag) = &v.etag {
            let b = etag.as_bytes();
            w.write_all(&(b.len() as u32).to_le_bytes())
                .and_then(|()| w.write_all(b))
                .map_err(|e| Error::io("write delete spill version etag", e))?;
        }
    }
    Ok(())
}

fn read_delete_record(r: &mut BufReader<File>) -> Result<Option<DeleteTarget>> {
    let mut first = [0u8; 1];
    match r.read(&mut first) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) => return Err(Error::io("read delete spill kind", e)),
    }
    let mut rest_hdr = [0u8; 13];
    r.read_exact(&mut rest_hdr)
        .map_err(|e| Error::io("read delete spill header", e))?;
    let kind = match first[0] {
        1 => EntryKind::Directory,
        2 => EntryKind::Symlink,
        _ => EntryKind::File,
    };
    let ver_flags = rest_hdr[0];
    let nfc_len = u32::from_le_bytes(rest_hdr[1..5].try_into().unwrap()) as usize;
    let raw_len = u32::from_le_bytes(rest_hdr[5..9].try_into().unwrap()) as usize;
    let node_len = u32::from_le_bytes(rest_hdr[9..13].try_into().unwrap()) as usize;

    let mut nfc_buf = vec![0u8; nfc_len];
    r.read_exact(&mut nfc_buf)
        .map_err(|e| Error::io("read delete spill nfc", e))?;
    let nfc_s = String::from_utf8(nfc_buf)
        .map_err(|e| Error::protocol(format!("corrupt delete spill nfc utf8: {e}")))?;

    let raw_override: Option<Box<str>> = if raw_len == 0 {
        None
    } else {
        let mut raw_buf = vec![0u8; raw_len];
        r.read_exact(&mut raw_buf)
            .map_err(|e| Error::io("read delete spill raw", e))?;
        Some(
            String::from_utf8(raw_buf)
                .map_err(|e| Error::protocol(format!("corrupt delete spill raw utf8: {e}")))?
                .into_boxed_str(),
        )
    };

    let node_id = if node_len == 0 {
        None
    } else {
        let mut node_buf = vec![0u8; node_len];
        r.read_exact(&mut node_buf)
            .map_err(|e| Error::io("read delete spill node_id", e))?;
        Some(NodeId(String::from_utf8(node_buf).map_err(|e| {
            Error::protocol(format!("corrupt delete spill node_id utf8: {e}"))
        })?))
    };

    let expected_version = if (ver_flags & 0x01) == 0 {
        None
    } else {
        let mut fixed = [0u8; 16];
        r.read_exact(&mut fixed)
            .map_err(|e| Error::io("read delete spill version header", e))?;
        let size = u64::from_le_bytes(fixed[0..8].try_into().unwrap());
        let mtime_ns = i64::from_le_bytes(fixed[8..16].try_into().unwrap());
        let ctime_ns = if (ver_flags & 0x04) != 0 {
            let mut cb = [0u8; 8];
            r.read_exact(&mut cb)
                .map_err(|e| Error::io("read delete spill version ctime", e))?;
            Some(i64::from_le_bytes(cb))
        } else {
            None
        };
        let ver_node_id = if (ver_flags & 0x02) != 0 {
            let mut lb = [0u8; 4];
            r.read_exact(&mut lb)
                .map_err(|e| Error::io("read delete spill version node_id len", e))?;
            let len = u32::from_le_bytes(lb) as usize;
            let mut nb = vec![0u8; len];
            r.read_exact(&mut nb)
                .map_err(|e| Error::io("read delete spill version node_id", e))?;
            Some(NodeId(String::from_utf8(nb).map_err(|e| {
                Error::protocol(format!("corrupt delete spill version node_id utf8: {e}"))
            })?))
        } else {
            None
        };
        let etag = if (ver_flags & 0x08) != 0 {
            let mut lb = [0u8; 4];
            r.read_exact(&mut lb)
                .map_err(|e| Error::io("read delete spill version etag len", e))?;
            let len = u32::from_le_bytes(lb) as usize;
            let mut eb = vec![0u8; len];
            r.read_exact(&mut eb)
                .map_err(|e| Error::io("read delete spill version etag", e))?;
            Some(String::from_utf8(eb).map_err(|e| {
                Error::protocol(format!("corrupt delete spill version etag utf8: {e}"))
            })?)
        } else {
            None
        };
        Some(SourceVersion {
            node_id: ver_node_id,
            size,
            mtime_ns,
            ctime_ns,
            etag,
        })
    };

    let nfc_path = RelPath::from_normalized_unchecked(nfc_s);
    let backend_path = BackendPath {
        raw_path: raw_override,
        nfc_path: nfc_path.clone(),
        node_id,
        kind: Some(kind),
    };
    Ok(Some(DeleteTarget {
        nfc_path,
        backend_path,
        kind,
        expected_version,
    }))
}
