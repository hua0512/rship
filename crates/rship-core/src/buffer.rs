//! Byte-unit bounded `BufferPool` backed by `Bytes::from_owner(PooledSlice)`.
//!
//! Design invariants (validated against Carbon & GPT-6.2 reviews):
//! 1. **Permit lifetime matches consumer lifetime**: converting a `PooledSlice`
//!    into `bytes::Bytes` transfers ownership of its `OwnedSemaphorePermit` into
//!    the `Bytes` owner. Permits are ONLY returned when the last consumer (e.g.
//!    hyper/TLS socket writer or disk writer) drops the `Bytes`.
//! 2. **4 KiB-unit byte semaphore**: streaming reads rent recycled `256 KiB`
//!    slabs (64 units), whereas tiny single-shot files rent exact `ceil(n/4096)`
//!    units so 1 KiB files never waste 256 KiB slabs.
//! 3. **Anti-deadlock lock ordering**: a task holds at most ONE `PooledSlice` at
//!    a time and NEVER calls `BufferPool::acquire*().await` while holding one.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{Error, Result};
use crate::memory::{BUFFER_UNIT_BYTES, STREAM_SLICE_BYTES};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct BufferPoolStats {
    pub max_units: usize,
    pub in_use_units: usize,
    pub peak_units: usize,
    pub slab_allocations: usize,
    pub slab_recycles: usize,
}

impl BufferPoolStats {
    pub fn max_bytes(self) -> usize {
        self.max_units * BUFFER_UNIT_BYTES
    }

    pub fn in_use_bytes(self) -> usize {
        self.in_use_units * BUFFER_UNIT_BYTES
    }

    pub fn peak_bytes(self) -> usize {
        self.peak_units * BUFFER_UNIT_BYTES
    }
}

pub const LARGE_STREAM_SLICE_BYTES: usize = 1024 * 1024; // 1 MiB coalesced slab for multi-MiB streams

#[derive(Debug)]
struct PoolInner {
    max_units: usize,
    slab_size: usize,
    max_cached_slabs: usize,
    max_cached_large_slabs: usize,
    semaphore: Arc<Semaphore>,
    free_slabs: Mutex<Vec<Box<[u8]>>>,
    free_large_slabs: Mutex<Vec<Box<[u8]>>>,
    in_use_units: AtomicUsize,
    peak_units: AtomicUsize,
    slab_allocations: AtomicUsize,
    slab_recycles: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

impl BufferPool {
    /// Create a pool capped at `max_bytes` (rounded down to 4 KiB units) with
    /// recycled streaming slabs of `slab_size` bytes.
    pub fn new(max_bytes: usize, slab_size: usize) -> Result<Self> {
        if slab_size == 0 || !slab_size.is_multiple_of(BUFFER_UNIT_BYTES) {
            return Err(Error::invalid_geometry(format!(
                "slab_size ({slab_size}) must be a non-zero multiple of {BUFFER_UNIT_BYTES}"
            )));
        }
        let max_units = max_bytes / BUFFER_UNIT_BYTES;
        let slab_units = slab_size / BUFFER_UNIT_BYTES;
        if max_units < slab_units {
            return Err(Error::invalid_geometry(format!(
                "buffer pool max_bytes ({max_bytes}) must be >= slab_size ({slab_size})"
            )));
        }
        let max_cached_slabs = max_units / slab_units;
        let large_units = LARGE_STREAM_SLICE_BYTES / BUFFER_UNIT_BYTES;
        let max_cached_large_slabs = max_units / large_units;
        Ok(Self {
            inner: Arc::new(PoolInner {
                max_units,
                slab_size,
                max_cached_slabs,
                max_cached_large_slabs,
                semaphore: Arc::new(Semaphore::new(max_units)),
                free_slabs: Mutex::new(Vec::with_capacity(max_cached_slabs.min(64))),
                free_large_slabs: Mutex::new(Vec::with_capacity(max_cached_large_slabs.min(16))),
                in_use_units: AtomicUsize::new(0),
                peak_units: AtomicUsize::new(0),
                slab_allocations: AtomicUsize::new(0),
                slab_recycles: AtomicUsize::new(0),
            }),
        })
    }

    pub fn with_default_slab(max_bytes: usize) -> Result<Self> {
        Self::new(max_bytes, STREAM_SLICE_BYTES)
    }

    pub fn slab_size(&self) -> usize {
        self.inner.slab_size
    }

    pub fn max_bytes(&self) -> usize {
        self.inner.max_units * BUFFER_UNIT_BYTES
    }

    pub fn available_bytes(&self) -> usize {
        self.inner.semaphore.available_permits() * BUFFER_UNIT_BYTES
    }

    /// Non-blocking acquisition of a recycled `1 MiB` (`LARGE_STREAM_SLICE_BYTES`) slab when
    /// the pool has ample spare headroom (`>= 2 * LARGE_STREAM_SLICE_BYTES` free), avoiding
    /// any contention or deadlock under small/busy pools.
    pub fn try_acquire_large_slab(&self) -> Option<PooledSlice> {
        if self.inner.slab_size >= LARGE_STREAM_SLICE_BYTES {
            return self.try_acquire_slab();
        }
        let units = LARGE_STREAM_SLICE_BYTES / BUFFER_UNIT_BYTES;
        if self.inner.semaphore.available_permits() < units * 2 {
            return None;
        }
        let permit = self
            .inner
            .semaphore
            .clone()
            .try_acquire_many_owned(units as u32)
            .ok()?;
        let buf = {
            let mut guard = self
                .inner
                .free_large_slabs
                .lock()
                .expect("large pool mutex poisoned");
            if let Some(reused) = guard.pop() {
                self.inner.slab_recycles.fetch_add(1, Ordering::Relaxed);
                reused
            } else {
                self.inner.slab_allocations.fetch_add(1, Ordering::Relaxed);
                vec![0u8; LARGE_STREAM_SLICE_BYTES].into_boxed_slice()
            }
        };
        self.record_acquire(units);
        Some(PooledSlice {
            buf: Some(buf),
            len: 0,
            is_slab: true,
            units,
            _permit: permit,
            pool: Arc::downgrade(&self.inner),
        })
    }

    /// Non-blocking acquisition of one standard streaming slab (`slab_size` bytes),
    /// used by read-ahead prefetching so a task already holding a prefetched buffer
    /// NEVER blocks on `BufferPool::acquire*().await`.
    pub fn try_acquire_slab(&self) -> Option<PooledSlice> {
        let units = self.inner.slab_size / BUFFER_UNIT_BYTES;
        if self.inner.semaphore.available_permits() < units {
            return None;
        }
        let permit = self
            .inner
            .semaphore
            .clone()
            .try_acquire_many_owned(units as u32)
            .ok()?;
        let buf = {
            let mut guard = self.inner.free_slabs.lock().expect("pool mutex poisoned");
            if let Some(reused) = guard.pop() {
                self.inner.slab_recycles.fetch_add(1, Ordering::Relaxed);
                reused
            } else {
                self.inner.slab_allocations.fetch_add(1, Ordering::Relaxed);
                vec![0u8; self.inner.slab_size].into_boxed_slice()
            }
        };
        self.record_acquire(units);
        Some(PooledSlice {
            buf: Some(buf),
            len: 0,
            is_slab: true,
            units,
            _permit: permit,
            pool: Arc::downgrade(&self.inner),
        })
    }

    /// Non-blocking exact slice acquisition (`<= slab_size`) for read-ahead tails.
    pub fn try_acquire_exact(&self, size: usize) -> Option<PooledSlice> {
        if size == 0 {
            let permit = self
                .inner
                .semaphore
                .clone()
                .try_acquire_many_owned(0)
                .ok()?;
            return Some(PooledSlice {
                buf: Some(Box::new([])),
                len: 0,
                is_slab: false,
                units: 0,
                _permit: permit,
                pool: Arc::downgrade(&self.inner),
            });
        }
        if size == self.inner.slab_size {
            return self.try_acquire_slab();
        }
        let units = size.div_ceil(BUFFER_UNIT_BYTES);
        if self.inner.semaphore.available_permits() < units {
            return None;
        }
        let permit = self
            .inner
            .semaphore
            .clone()
            .try_acquire_many_owned(units as u32)
            .ok()?;
        self.record_acquire(units);
        Some(PooledSlice {
            buf: Some(vec![0u8; size].into_boxed_slice()),
            len: 0,
            is_slab: false,
            units,
            _permit: permit,
            pool: Arc::downgrade(&self.inner),
        })
    }

    /// Acquire one fixed streaming slab (`slab_size` bytes) with backpressure.
    pub async fn acquire_slab(&self) -> Result<PooledSlice> {
        let units = self.inner.slab_size / BUFFER_UNIT_BYTES;
        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_many_owned(units as u32)
            .await
            .map_err(|_| Error::cancelled("buffer pool closed"))?;

        let buf = {
            let mut guard = self.inner.free_slabs.lock().expect("pool mutex poisoned");
            if let Some(reused) = guard.pop() {
                self.inner.slab_recycles.fetch_add(1, Ordering::Relaxed);
                reused
            } else {
                self.inner.slab_allocations.fetch_add(1, Ordering::Relaxed);
                vec![0u8; self.inner.slab_size].into_boxed_slice()
            }
        };

        self.record_acquire(units);
        Ok(PooledSlice {
            buf: Some(buf),
            len: 0,
            is_slab: true,
            units,
            _permit: permit,
            pool: Arc::downgrade(&self.inner),
        })
    }

    /// Acquire a right-sized slice for small single-shot transfers (`<= slab_size`)
    /// so tiny files only consume `ceil(size / 4 KiB)` units.
    pub async fn acquire_exact(&self, size: usize) -> Result<PooledSlice> {
        if size == 0 {
            let permit = self
                .inner
                .semaphore
                .clone()
                .acquire_many_owned(0)
                .await
                .map_err(|_| Error::cancelled("buffer pool closed"))?;
            return Ok(PooledSlice {
                buf: Some(Box::new([])),
                len: 0,
                is_slab: false,
                units: 0,
                _permit: permit,
                pool: Arc::downgrade(&self.inner),
            });
        }
        if size == self.inner.slab_size {
            return self.acquire_slab().await;
        }
        let units = size.div_ceil(BUFFER_UNIT_BYTES);
        if units > self.inner.max_units {
            return Err(Error::invalid_geometry(format!(
                "requested exact buffer ({size} bytes = {units} units) exceeds pool cap ({} units)",
                self.inner.max_units
            )));
        }
        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_many_owned(units as u32)
            .await
            .map_err(|_| Error::cancelled("buffer pool closed"))?;

        self.record_acquire(units);
        Ok(PooledSlice {
            buf: Some(vec![0u8; size].into_boxed_slice()),
            len: 0,
            is_slab: false,
            units,
            _permit: permit,
            pool: Arc::downgrade(&self.inner),
        })
    }

    fn record_acquire(&self, units: usize) {
        let now = self.inner.in_use_units.fetch_add(units, Ordering::SeqCst) + units;
        self.inner.peak_units.fetch_max(now, Ordering::SeqCst);
    }

    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            max_units: self.inner.max_units,
            in_use_units: self.inner.in_use_units.load(Ordering::SeqCst),
            peak_units: self.inner.peak_units.load(Ordering::SeqCst),
            slab_allocations: self.inner.slab_allocations.load(Ordering::Relaxed),
            slab_recycles: self.inner.slab_recycles.load(Ordering::Relaxed),
        }
    }
}

/// Owned pooled buffer holding its semaphore permit until dropped.
///
/// Convert via [`PooledSlice::into_bytes`] to hand zero-copy `Bytes` to async
/// sinks while keeping backpressure active until the sink drops the `Bytes`.
pub struct PooledSlice {
    buf: Option<Box<[u8]>>,
    len: usize,
    is_slab: bool,
    units: usize,
    _permit: OwnedSemaphorePermit,
    pool: Weak<PoolInner>,
}

impl PooledSlice {
    pub fn capacity(&self) -> usize {
        self.buf.as_ref().map_or(0, |b| b.len())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mutable access to the entire backing allocation for reading into.
    pub fn spare_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut().expect("PooledSlice buffer already taken")
    }

    /// Set the initialized byte length (`<= capacity()`).
    pub fn set_len(&mut self, len: usize) {
        assert!(
            len <= self.capacity(),
            "PooledSlice len ({len}) > capacity ({})",
            self.capacity()
        );
        self.len = len;
    }

    /// Freeze into a zero-copy `bytes::Bytes` that owns this `PooledSlice`
    /// (and therefore keeps its semaphore permit held until all `Bytes` clones drop).
    pub fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }
}

impl AsRef<[u8]> for PooledSlice {
    fn as_ref(&self) -> &[u8] {
        match &self.buf {
            Some(b) => &b[..self.len],
            None => &[],
        }
    }
}

impl Drop for PooledSlice {
    fn drop(&mut self) {
        if let Some(inner) = self.pool.upgrade() {
            if self.units > 0 {
                inner.in_use_units.fetch_sub(self.units, Ordering::SeqCst);
            }
            if self.is_slab
                && let Some(buf) = self.buf.take()
            {
                if buf.len() == inner.slab_size {
                    if let Ok(mut guard) = inner.free_slabs.lock()
                        && guard.len() < inner.max_cached_slabs
                    {
                        guard.push(buf);
                    }
                } else if buf.len() == LARGE_STREAM_SLICE_BYTES
                    && let Ok(mut guard) = inner.free_large_slabs.lock()
                    && guard.len() < inner.max_cached_large_slabs
                {
                    guard.push(buf);
                }
            }
        }
        // `_permit` drops immediately after, releasing `self.units` permits.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bytes_from_owner_holds_permit_until_last_consumer_drops() {
        let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap(); // 2 slabs = 128 units

        let mut s1 = pool.acquire_slab().await.unwrap();
        s1.spare_mut()[..4].copy_from_slice(b"test");
        s1.set_len(4);
        let b1 = s1.into_bytes();
        let b1_clone = b1.clone();

        assert_eq!(&b1[..], b"test");
        assert_eq!(pool.stats().in_use_bytes(), 256 * 1024);

        // Dropping one clone must NOT release the permit!
        drop(b1);
        assert_eq!(pool.stats().in_use_bytes(), 256 * 1024);

        // Dropping the final clone releases the permit and recycles the slab.
        drop(b1_clone);
        assert_eq!(pool.stats().in_use_bytes(), 0);

        let s2 = pool.acquire_slab().await.unwrap();
        assert_eq!(pool.stats().slab_allocations, 1);
        assert_eq!(pool.stats().slab_recycles, 1);
        drop(s2);
    }

    #[tokio::test]
    async fn small_files_use_4kib_units_not_full_slabs() {
        let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
        let mut s = pool.acquire_exact(1024).await.unwrap(); // 1 KiB -> 1 unit (4 KiB)
        s.spare_mut()[..5].copy_from_slice(b"hello");
        s.set_len(5);
        assert_eq!(pool.stats().in_use_units, 1);
        assert_eq!(pool.stats().in_use_bytes(), 4096);
        let b = s.into_bytes();
        assert_eq!(&b[..], b"hello");
        drop(b);
        assert_eq!(pool.stats().in_use_units, 0);
    }

    #[tokio::test]
    async fn peak_watermark_never_exceeds_ceiling_under_concurrency() {
        let pool = BufferPool::new(1024 * 1024, 256 * 1024).unwrap(); // 4 slabs max
        let mut handles = Vec::new();
        for _ in 0..32 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..8 {
                    let mut slab = p.acquire_slab().await.unwrap();
                    slab.set_len(128);
                    let bytes = slab.into_bytes();
                    tokio::task::yield_now().await;
                    drop(bytes);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let st = pool.stats();
        assert_eq!(st.in_use_units, 0);
        assert!(st.peak_units <= st.max_units);
        assert!(st.slab_allocations <= 4);
    }
}
