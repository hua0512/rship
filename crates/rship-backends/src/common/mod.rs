//! Shared low-memory stream enforcement, hardware CRC checksums, streaming hashers,
//! HMAC-SHA256, Google Service Account JWT, HTTP helpers, and XML decoding reused across backends.

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
pub mod checksum;
#[cfg(any(feature = "local", feature = "s3", feature = "gcs"))]
pub mod crc;
#[cfg(any(feature = "s3", feature = "azureblob"))]
pub mod crypto;
#[cfg(any(feature = "gdrive", feature = "gcs"))]
pub mod google_sa;
#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
pub mod http;
#[cfg(any(
    feature = "local",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "sftp"
))]
pub mod reconcile;
#[cfg(any(feature = "s3", feature = "webdav", feature = "azureblob"))]
pub mod xml;

#[cfg(any(feature = "local", feature = "s3", feature = "gcs"))]
#[allow(unused_imports)]
pub(crate) use crc::crc64_nvme_update_table1;
#[cfg(any(feature = "local", feature = "s3", feature = "gcs"))]
pub use crc::{
    crc32c, crc32c_update, crc32c_update_slice8, crc64_nvme, crc64_nvme_update,
    crc64_nvme_update_slice8,
};

/// Acquire a `std::sync::Mutex`, recovering the inner value if a previous holder panicked.
#[inline]
pub fn lock_unpoisoned<T>(mutex: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone)]
struct SessionSlot<V> {
    value: V,
    touched_at: std::time::Instant,
    seq: u64,
}

/// Memory-bounded, TTL-expiring session map with O(1)-amortized LRU eviction.
#[derive(Debug)]
pub struct BoundedSessionMap<K, V> {
    entries: std::collections::HashMap<K, SessionSlot<V>>,
    order: std::collections::VecDeque<(K, u64)>,
    max_entries: usize,
    ttl: std::time::Duration,
    next_seq: u64,
}

impl<K, V> BoundedSessionMap<K, V>
where
    K: Eq + std::hash::Hash + Clone,
{
    pub fn new(max_entries: usize, ttl: std::time::Duration) -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
            max_entries: max_entries.max(1),
            ttl,
            next_seq: 1,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(4096, std::time::Duration::from_secs(6 * 3600))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1).max(1);
        seq
    }

    fn compact_order(&mut self) {
        if self.order.len() > self.max_entries.saturating_mul(2) {
            self.order
                .retain(|(k, seq)| self.entries.get(k).is_some_and(|s| s.seq == *seq));
        }
    }

    pub fn prune_expired_at(&mut self, now: std::time::Instant) {
        while let Some((k, seq)) = self.order.front() {
            let Some(slot) = self.entries.get(k) else {
                self.order.pop_front();
                continue;
            };
            if slot.seq != *seq {
                self.order.pop_front();
                continue;
            }
            if now.saturating_duration_since(slot.touched_at) >= self.ttl {
                let (expired_key, _) = self.order.pop_front().expect("front present");
                self.entries.remove(&expired_key);
            } else {
                break;
            }
        }
    }

    pub fn prune_expired(&mut self) {
        self.prune_expired_at(std::time::Instant::now());
    }

    pub fn insert_at(&mut self, key: K, value: V, now: std::time::Instant) -> Option<V> {
        self.prune_expired_at(now);
        let seq = self.alloc_seq();
        if let Some(existing) = self.entries.get_mut(&key) {
            let prev = std::mem::replace(&mut existing.value, value);
            existing.touched_at = now;
            existing.seq = seq;
            self.order.push_back((key, seq));
            self.compact_order();
            return Some(prev);
        }
        while self.entries.len() >= self.max_entries {
            let Some((evict_k, evict_seq)) = self.order.pop_front() else {
                break;
            };
            if self
                .entries
                .get(&evict_k)
                .is_some_and(|s| s.seq == evict_seq)
            {
                self.entries.remove(&evict_k);
            }
        }
        self.entries.insert(
            key.clone(),
            SessionSlot {
                value,
                touched_at: now,
                seq,
            },
        );
        self.order.push_back((key, seq));
        self.compact_order();
        None
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.insert_at(key, value, std::time::Instant::now())
    }

    pub fn get_mut_at(&mut self, key: &K, now: std::time::Instant) -> Option<&mut V> {
        if let Some(slot) = self.entries.get(key)
            && now.saturating_duration_since(slot.touched_at) >= self.ttl
        {
            self.entries.remove(key);
            return None;
        }
        let seq = self.alloc_seq();
        {
            let slot = self.entries.get_mut(key)?;
            slot.touched_at = now;
            slot.seq = seq;
        }
        self.order.push_back((key.clone(), seq));
        self.compact_order();
        self.entries.get_mut(key).map(|s| &mut s.value)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.get_mut_at(key, std::time::Instant::now())
    }

    /// Inspect a cached entry without refreshing its LRU position or checking TTL expiration.
    /// Callers requiring TTL enforcement should use [`Self::get_mut`] (or [`Self::get_mut_at`])
    /// or call [`Self::prune_expired`] first.
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.entries.get(key).map(|s| &s.value)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.entries.remove(key).map(|s| s.value)
    }
}

/// Convert a bounded `mpsc::Receiver<Result<Entry>>` into a boxed [`rship_core::backend::EntryStream`].
pub fn rx_to_entry_stream(
    rx: tokio::sync::mpsc::Receiver<rship_core::Result<rship_core::types::Entry>>,
) -> rship_core::backend::EntryStream {
    Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    }))
}

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
mod streams {
    use bytes::Bytes;
    use futures::Stream;
    use rship_core::source::ByteStream;
    use rship_core::{Error, Result};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::task::{Context, Poll};

    /// Enforces exact upload byte length on a streaming request body, capturing the
    /// root-cause [`Error`] (short EOF, length overflow, or source read error) into
    /// `captured_error` so HTTP clients do not mask it behind a generic send error.
    pub struct StrictBodyStream {
        label: &'static str,
        body: ByteStream,
        expected_len: u64,
        seen_len: u64,
        captured_error: Arc<StdMutex<Option<Error>>>,
        finished: bool,
    }

    impl StrictBodyStream {
        pub fn new(
            label: &'static str,
            body: ByteStream,
            expected_len: u64,
            captured_error: Arc<StdMutex<Option<Error>>>,
        ) -> Self {
            Self {
                label,
                body,
                expected_len,
                seen_len: 0,
                captured_error,
                finished: false,
            }
        }

        fn record_and_fail(&mut self, err: Error) -> Poll<Option<Result<Bytes>>> {
            self.finished = true;
            let msg = err.to_string();
            *super::lock_unpoisoned(&self.captured_error) = Some(err);
            Poll::Ready(Some(Err(Error::network(msg))))
        }
    }

    impl Stream for StrictBodyStream {
        type Item = Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.as_mut().get_mut();
            if this.finished {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.body).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    this.seen_len = this.seen_len.saturating_add(chunk.len() as u64);
                    if this.seen_len > this.expected_len {
                        let err = Error::source_mutated(format!(
                            "{} upload stream exceeded declared length ({} > {})",
                            this.label, this.seen_len, this.expected_len
                        ));
                        return this.record_and_fail(err);
                    }
                    Poll::Ready(Some(Ok(chunk)))
                }
                Poll::Ready(Some(Err(e))) => this.record_and_fail(e),
                Poll::Ready(None) => {
                    if this.seen_len != this.expected_len {
                        let err = Error::source_mutated(format!(
                            "short EOF during {} upload: received {} of {} bytes",
                            this.label, this.seen_len, this.expected_len
                        ));
                        return this.record_and_fail(err);
                    }
                    this.finished = true;
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }

    /// Enforces exact downloaded byte count on an HTTP `Range` stream, returning a
    /// retryable network error on premature truncation or protocol error on overflow.
    pub struct ExactDownloadStream<S> {
        label: &'static str,
        inner: S,
        expected: u64,
        seen: u64,
        done: bool,
    }

    impl<S> ExactDownloadStream<S> {
        pub fn new(label: &'static str, inner: S, expected: u64) -> Self {
            Self {
                label,
                inner,
                expected,
                seen: 0,
                done: false,
            }
        }
    }

    impl<S> Stream for ExactDownloadStream<S>
    where
        S: Stream<Item = Result<Bytes>> + Unpin,
    {
        type Item = Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.as_mut().get_mut();
            if this.done {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    this.seen = this.seen.saturating_add(chunk.len() as u64);
                    if this.seen > this.expected {
                        this.done = true;
                        return Poll::Ready(Some(Err(Error::protocol(format!(
                            "{} download returned more bytes ({}) than requested ({})",
                            this.label, this.seen, this.expected
                        )))));
                    }
                    Poll::Ready(Some(Ok(chunk)))
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    Poll::Ready(Some(Err(e)))
                }
                Poll::Ready(None) => {
                    this.done = true;
                    if this.seen != this.expected {
                        return Poll::Ready(Some(Err(Error::network(format!(
                            "truncated {} download stream: received {} of {} bytes",
                            this.label, this.seen, this.expected
                        )))));
                    }
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

#[cfg(any(feature = "s3", feature = "onedrive"))]
pub use checksum::Sha256Hasher;
#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "gcs",
    feature = "azureblob"
))]
pub use checksum::StreamingMd5;
#[cfg(any(feature = "s3", feature = "gcs"))]
pub use checksum::{Crc32cHasher, Crc64NvmeHasher};
#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
pub use checksum::{
    StreamingDigest, StreamingHashStream, VerifyingDownloadStream, checksum_mismatch_error,
};
#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "dropbox",
    feature = "gcs",
    feature = "azureblob"
))]
pub use streams::{ExactDownloadStream, StrictBodyStream};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant};

    #[test]
    fn lock_unpoisoned_recovers_after_panic() {
        let mutex = Arc::new(StdMutex::new(41u32));
        let m2 = Arc::clone(&mutex);
        let _ = std::thread::spawn(move || {
            let mut g = m2.lock().unwrap();
            *g = 42;
            panic!("intentional poison");
        })
        .join();
        assert!(mutex.is_poisoned());
        let guard = lock_unpoisoned(&mutex);
        assert_eq!(*guard, 42);
    }

    #[test]
    fn bounded_session_map_evicts_lru_on_capacity() {
        let t0 = Instant::now();
        let mut map = BoundedSessionMap::new(3, Duration::from_secs(60));
        assert_eq!(map.insert_at("k1", 1, t0), None);
        assert_eq!(map.insert_at("k2", 2, t0), None);
        assert_eq!(map.insert_at("k3", 3, t0), None);
        // Touch k1 so k2 becomes the least-recently-used key.
        *map.get_mut_at(&"k1", t0 + Duration::from_secs(1)).unwrap() = 10;
        // Insert k4 -> k2 must be evicted, k1/k3/k4 retained.
        assert_eq!(map.insert_at("k4", 4, t0 + Duration::from_secs(2)), None);
        assert_eq!(map.len(), 3);
        assert_eq!(map.peek(&"k2"), None);
        assert_eq!(map.peek(&"k1"), Some(&10));
        assert_eq!(map.peek(&"k3"), Some(&3));
        assert_eq!(map.peek(&"k4"), Some(&4));
    }

    #[test]
    fn bounded_session_map_expires_by_ttl_and_refreshes_on_get_mut() {
        let t0 = Instant::now();
        let mut map = BoundedSessionMap::new(4, Duration::from_secs(10));
        map.insert_at("a", 1, t0);
        map.insert_at("b", 2, t0);

        // Refresh "a" at t0 + 6s -> expires at t0 + 16s; "b" expires at t0 + 10s.
        assert_eq!(
            map.get_mut_at(&"a", t0 + Duration::from_secs(6)),
            Some(&mut 1)
        );

        // At t0 + 11s: "b" is expired, "a" is still alive.
        map.prune_expired_at(t0 + Duration::from_secs(11));
        assert_eq!(map.peek(&"b"), None);
        assert_eq!(map.peek(&"a"), Some(&1));

        // Accessing "a" past its refreshed TTL returns None and removes it.
        assert_eq!(map.get_mut_at(&"a", t0 + Duration::from_secs(16)), None);
        assert!(map.is_empty());
    }
}
