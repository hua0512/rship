//! Three-tier data source model and bounded zero-copy range streaming.
//!
//! 1. `LocalSeekable`: stateless `read_at(offset, buf)` streaming arbitrarily
//!    large logical chunks (e.g. 128 MiB) via 256 KiB pooled slices.
//! 2. `RemoteRangeReadable`: version-pinned HTTP Range reader for zero-RAM
//!    cloud-to-cloud relays (`gdrive -> s3`, `s3 -> gdrive`).
//! 3. `SequentialStream`: non-seekable streams (e.g. stdin / pipes).

use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::buffer::{BufferPool, LARGE_STREAM_SLICE_BYTES, PooledSlice};
use crate::error::{Error, Result};
use crate::types::ByteRange;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

/// Stateless random-access byte source (e.g. local disk file via `pread` on Unix
/// or independent `File` handles on Windows).
#[async_trait]
pub trait SeekableSource: Send + Sync {
    fn total_len(&self) -> u64;

    /// Read up to `buf.len()` bytes starting at `offset`.
    /// Returning `Ok(0)` before `total_len()` is treated by callers as unexpected
    /// early EOF (source truncation / mutation).
    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Optional zero-extra-copy fast path: fill up to `want` bytes directly into
    /// an owned [`PooledSlice`] (avoids an intermediate `Vec<u8>` allocation and
    /// memcpy across `spawn_blocking` on local disk reads).
    async fn read_into_slice(
        &self,
        offset: u64,
        mut slice: PooledSlice,
        want: usize,
    ) -> Result<(PooledSlice, usize)> {
        let mut filled = 0usize;
        while filled < want {
            let n = self
                .read_at(offset + filled as u64, &mut slice.spare_mut()[filled..want])
                .await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        Ok((slice, filled))
    }
}

/// Version-pinned remote range source for cloud-to-cloud relays without disk spill.
#[async_trait]
pub trait RemoteRangeReadable: Send + Sync {
    fn total_len(&self) -> u64;
    async fn open_range(&self, range: ByteRange) -> Result<ByteStream>;
}

pub enum DataSource {
    LocalSeekable(Arc<dyn SeekableSource>),
    RemoteRangeReadable(Arc<dyn RemoteRangeReadable>),
    SequentialStream {
        total_len: Option<u64>,
        stream: ByteStream,
    },
}

/// Streams exact byte range `[start_offset, start_offset + len)` from a
/// `SeekableSource` using `BufferPool` slabs (`Bytes::from_owner`), enforcing:
/// - **Anti-deadlock lock ordering**: never blocks on `BufferPool::acquire*().await`
///   while holding a pooled buffer. For multi-MiB ranges with spare pool capacity,
///   coalesces reads into `1 MiB` recycled slabs and prefetches 1 chunk ahead via
///   non-blocking `try_acquire*` so disk `pread` overlaps with TLS & socket writes.
/// - **Early EOF detection**: if `read_at` returns `0` before `len` bytes are
///   produced, fails with `ErrorKind::SourceMutated` rather than silently
///   producing a short stream.
pub fn bounded_range_stream(
    source: Arc<dyn SeekableSource>,
    start_offset: u64,
    len: u64,
    pool: BufferPool,
) -> ByteStream {
    const PREFETCH_MIN_LEN: u64 = 2 * 1024 * 1024;
    const PREFETCH_MIN_POOL: usize = 4 * 1024 * 1024;

    if len >= PREFETCH_MIN_LEN && pool.max_bytes() >= PREFETCH_MIN_POOL {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(1);
        tokio::spawn(async move {
            let mut offset = start_offset;
            let mut remaining = len;
            while remaining > 0 {
                if tx.is_closed() {
                    return;
                }
                // Reserve channel slot FIRST when empty, or only prefetch non-blockingly when
                // the downstream consumer still holds the previous slot: guarantees we NEVER
                // await on `BufferPool` while holding an unconsumed `Bytes` in `tx`!
                let (permit, slice, want) = if let Ok(tx_permit) = tx.try_reserve() {
                    // Channel is completely empty -> safe to await on `pool`!
                    let (s, w) = match acquire_read_slice(&pool, remaining, true).await {
                        Ok(v) => v,
                        Err(e) => {
                            tx_permit.send(Err(e));
                            return;
                        }
                    };
                    (tx_permit, s, w)
                } else {
                    // Consumer is still transmitting the previous slab -> try non-blocking
                    // prefetch if spare pool permits exist; otherwise wait for channel drain first!
                    if let Some((s, w)) = try_acquire_read_slice(&pool, remaining) {
                        let Ok(tx_permit) = tx.reserve().await else {
                            return;
                        };
                        (tx_permit, s, w)
                    } else {
                        let Ok(tx_permit) = tx.reserve().await else {
                            return;
                        };
                        let (s, w) = match acquire_read_slice(&pool, remaining, true).await {
                            Ok(v) => v,
                            Err(e) => {
                                tx_permit.send(Err(e));
                                return;
                            }
                        };
                        (tx_permit, s, w)
                    }
                };

                match source.read_into_slice(offset, slice, want).await {
                    Ok((mut s, filled)) => {
                        if filled < want {
                            tx_permit_send(
                                permit,
                                Err(Error::source_mutated(format!(
                                    "unexpected early EOF at offset {} (expected {} more bytes)",
                                    offset + filled as u64,
                                    want - filled
                                ))),
                            );
                            return;
                        }
                        s.set_len(filled);
                        tx_permit_send(permit, Ok(s.into_bytes()));
                        offset += filled as u64;
                        remaining -= filled as u64;
                    }
                    Err(e) => {
                        tx_permit_send(permit, Err(e));
                        return;
                    }
                }
            }
        });

        let stream = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        return Box::pin(stream);
    }

    let stream = futures::stream::try_unfold(
        (source, start_offset, len, pool),
        |(src, offset, remaining, pool)| async move {
            if remaining == 0 {
                return Ok(None);
            }
            let (slice, want) = acquire_read_slice(&pool, remaining, false).await?;
            let (mut slice, filled) = src.read_into_slice(offset, slice, want).await?;
            if filled < want {
                return Err(Error::source_mutated(format!(
                    "unexpected early EOF at offset {} (expected {} more bytes)",
                    offset + filled as u64,
                    want - filled
                )));
            }
            slice.set_len(filled);
            let bytes = slice.into_bytes();
            Ok(Some((
                bytes,
                (src, offset + filled as u64, remaining - filled as u64, pool),
            )))
        },
    );
    Box::pin(stream)
}

#[inline]
fn tx_permit_send<T>(permit: tokio::sync::mpsc::Permit<'_, T>, val: T) {
    permit.send(val);
}

async fn acquire_read_slice(
    pool: &BufferPool,
    remaining: u64,
    allow_large: bool,
) -> Result<(PooledSlice, usize)> {
    if allow_large
        && remaining >= LARGE_STREAM_SLICE_BYTES as u64
        && let Some(large) = pool.try_acquire_large_slab()
    {
        return Ok((large, LARGE_STREAM_SLICE_BYTES));
    }
    let want = (remaining as usize).min(pool.slab_size());
    let slice = if want < pool.slab_size() {
        pool.acquire_exact(want).await?
    } else {
        pool.acquire_slab().await?
    };
    Ok((slice, want))
}

fn try_acquire_read_slice(pool: &BufferPool, remaining: u64) -> Option<(PooledSlice, usize)> {
    if remaining >= LARGE_STREAM_SLICE_BYTES as u64
        && let Some(large) = pool.try_acquire_large_slab()
    {
        return Some((large, LARGE_STREAM_SLICE_BYTES));
    }
    let want = (remaining as usize).min(pool.slab_size());
    let slice = if want < pool.slab_size() {
        pool.try_acquire_exact(want)?
    } else {
        pool.try_acquire_slab()?
    };
    Some((slice, want))
}

/// In-memory `SeekableSource` handy for tests and small payloads.
#[derive(Debug, Clone)]
pub struct MemorySource {
    data: Bytes,
}

impl MemorySource {
    pub fn new(data: impl Into<Bytes>) -> Self {
        Self { data: data.into() }
    }
}

#[async_trait]
impl SeekableSource for MemorySource {
    fn total_len(&self) -> u64 {
        self.data.len() as u64
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let start = usize::try_from(offset).unwrap_or(self.data.len());
        if start >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        Ok(n)
    }
}

/// Quota-bounded temporary disk spool implementing [`SeekableSource`].
///
/// Used by both:
/// - `--strict-source` (freezes an actively mutated source file into an immutable
///   private snapshot before upload), and
/// - `rship rcat` / `SequentialStream` (spools non-seekable `stdin` pipes to a
///   private temp file so retries and chunked/multipart uploads remain reliable).
///
/// The backing temp file is closed and deleted automatically on [`Drop`].
pub struct SpoolSeekableSource {
    path: PathBuf,
    file: Arc<Mutex<Option<File>>>,
    len: u64,
    cleaned: std::sync::atomic::AtomicBool,
}

/// Closes and unlinks a spool file when dropped.
///
/// Cleanup is handed to `spawn_blocking` as this guard, not as code inside the closure: if
/// the blocking pool never runs the closure (the runtime is shutting down, or the awaiting
/// task was cancelled), dropping the closure drops the guard, which then removes the file
/// synchronously on whatever thread dropped it.
struct RemoveOnDrop {
    file: Option<File>,
    path: PathBuf,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        // Close the handle before unlinking (required on Windows).
        drop(self.file.take());
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl RemoveOnDrop {
    /// Remove off the async threads when a runtime is available, else right here.
    fn spawn(self) -> Option<tokio::task::JoinHandle<()>> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => Some(handle.spawn_blocking(move || drop(self))),
            Err(_) => {
                drop(self);
                None
            }
        }
    }

    async fn run(self) {
        if let Some(h) = self.spawn() {
            let _ = h.await;
        }
    }
}

impl SpoolSeekableSource {
    /// Drain `stream` into a private file inside `spool_dir`, aborting and deleting
    /// the file immediately if the stream exceeds `max_bytes`.
    pub async fn from_stream(
        mut stream: ByteStream,
        spool_dir: &Path,
        max_bytes: u64,
    ) -> Result<Arc<Self>> {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let dir = spool_dir.to_path_buf();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = dir.join(format!("rship-spool-{pid}-{seq}.tmp"));

        let path_create = path.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(8);
        let writer_handle = tokio::task::spawn_blocking(move || -> Result<File> {
            std::fs::create_dir_all(&dir)
                .map_err(|e| Error::io(format!("create spool dir `{}`", dir.display()), e))?;
            let _ = std::fs::remove_file(&path_create);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path_create)
                .map_err(|e| {
                    Error::io(format!("create spool file `{}`", path_create.display()), e)
                })?;
            let mut writer = BufWriter::with_capacity(256 * 1024, file);
            while let Some(chunk) = rx.blocking_recv() {
                writer
                    .write_all(&chunk)
                    .map_err(|e| Error::io("write spool chunk", e))?;
            }
            writer
                .flush()
                .map_err(|e| Error::io("flush spool file", e))?;
            writer
                .into_inner()
                .map_err(|e| Error::io("finish spool file", e.into_error()))
        });

        let mut total_written = 0u64;
        let mut producer_err: Option<Error> = None;

        while let Some(item) = stream.next().await {
            let chunk = match item {
                Ok(b) => b,
                Err(e) => {
                    producer_err = Some(e);
                    break;
                }
            };
            if chunk.is_empty() {
                continue;
            }
            total_written = total_written.saturating_add(chunk.len() as u64);
            if total_written > max_bytes {
                producer_err = Some(Error::invalid_geometry(format!(
                    "spool quota exceeded ({total_written} > {max_bytes} bytes)"
                )));
                break;
            }
            if tx.send(chunk).await.is_err() {
                break;
            }
        }
        drop(tx);

        let writer_res = writer_handle
            .await
            .map_err(|e| Error::protocol(format!("spool writer join: {e}")))?;
        if let Some(e) = producer_err {
            RemoveOnDrop {
                file: writer_res.ok(),
                path,
            }
            .run()
            .await;
            return Err(e);
        }
        let write_file = match writer_res {
            Ok(f) => f,
            Err(e) => {
                RemoveOnDrop { file: None, path }.run().await;
                return Err(e);
            }
        };

        Ok(Arc::new(Self {
            path,
            file: Arc::new(Mutex::new(Some(write_file))),
            len: total_written,
            cleaned: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Close and unlink the backing spool file on Tokio's blocking pool, awaiting
    /// completion so callers observe deterministic cleanup without blocking async threads.
    pub async fn cleanup_async(&self) {
        if self.cleaned.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let file = self.file.lock().ok().and_then(|mut guard| guard.take());
        RemoveOnDrop {
            file,
            path: self.path.clone(),
        }
        .run()
        .await;
    }
}

impl Drop for SpoolSeekableSource {
    fn drop(&mut self) {
        if self.cleaned.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        let file = self.file.lock().ok().and_then(|mut guard| guard.take());
        let path = std::mem::take(&mut self.path);
        let _ = RemoveOnDrop { file, path }.spawn();
    }
}

#[async_trait]
impl SeekableSource for SpoolSeekableSource {
    fn total_len(&self) -> u64 {
        self.len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() || offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        let file = self.file.clone();
        let tmp = tokio::task::spawn_blocking(move || {
            let mut g = file.lock().expect("spool file mutex poisoned");
            let f = g
                .as_mut()
                .ok_or_else(|| Error::protocol("spool file already closed"))?;
            f.seek(SeekFrom::Start(offset))
                .map_err(|e| Error::io("seek spool file", e))?;
            let mut out = vec![0u8; want];
            let n = f
                .read(&mut out)
                .map_err(|e| Error::io("read spool file", e))?;
            out.truncate(n);
            Ok::<_, Error>(out)
        })
        .await
        .map_err(|e| Error::protocol(format!("spool read join: {e}")))??;
        buf[..tmp.len()].copy_from_slice(&tmp);
        Ok(tmp.len())
    }
}
