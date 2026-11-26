//! Byte-level idle stall watchdog and independent total-deadline enforcement.
//!
//! Covers ALL Data Plane stall vectors:
//! 1. **Upload source stall or TCP blackhole**: [`ProgressWatchdog::run`] races
//!    the HTTP send future against an idle timer that resets ONLY when `n > 0`
//!    bytes move through [`WatchedByteStream`]. Even if `hyper` stops polling
//!    the upload body because the TCP send buffer is full (dead peer), the
//!    watchdog fires on schedule.
//! 2. **Download body stall**: [`StallWatchdogStream`] wraps a response stream
//!    with an internal pinned sleep reset strictly on non-empty chunks (`len > 0`)
//!    plus an optional independent total deadline.
//!
//! # Known limitation: the tail of an upload body
//!
//! Byte progress is measured where the body is handed to hyper, not where it leaves the
//! host. Upload body EOF ([`ProgressHandle::mark_body_eof`]) is therefore signalled when the
//! last chunk is handed over, while up to hyper's write buffer plus the kernel socket send
//! buffer (often several MiB) may still be unsent. A TCP blackhole that starts during that
//! tail, or anywhere in a body small enough to fit in those buffers (such as a single-chunk
//! upload), is only detected by the post-EOF `finalize_timeout` (default 300 s), not by the
//! 30 s stall timeout.
//!
//! There is no sound fix at this layer. With a `Content-Length` body, hyper's HTTP/1.1
//! encoder stops polling the body once the declared length has been yielded, so there is no
//! later "past the end" poll to wait for. reqwest does not expose the connection's socket,
//! which would be needed to watch real progress (e.g. `TCP_INFO` unacked / not-sent bytes on
//! Linux). Keeping the short stall timer after EOF would instead misfire on legitimately slow
//! server-side finalization (Drive/OneDrive final fragments, Nextcloud assembly, SSE-KMS),
//! which is what the separate finalize timeout exists for.

use bytes::Bytes;
use futures::Stream;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::{Instant, Sleep};

/// Default timeout allowed after upload body EOF while waiting for server-side
/// assembly/finalization (e.g. Drive/OneDrive final fragment, Nextcloud assembly, SSE-KMS).
pub const DEFAULT_DATA_FINALIZE_TIMEOUT: Duration = Duration::from_secs(300);

/// Shared progress signal updated whenever `n > 0` payload bytes are transmitted
/// or received, plus a one-way body-EOF signal for post-upload finalize waits.
#[derive(Debug, Clone)]
pub struct ProgressHandle {
    bytes: Arc<AtomicU64>,
    body_eof: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl ProgressHandle {
    pub fn new() -> Self {
        Self {
            bytes: Arc::new(AtomicU64::new(0)),
            body_eof: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Record forward byte progress. Zero-byte ticks are deliberately ignored so
    /// empty frames cannot keep a stalled connection alive indefinitely.
    pub fn record_bytes(&self, count: usize) {
        if count > 0 {
            self.bytes.fetch_add(count as u64, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes.load(Ordering::Acquire)
    }

    /// Mark that the outbound upload body stream reached EOF (`Poll::Ready(None)`),
    /// transitioning [`ProgressWatchdog::run`] from `stall_timeout` to `finalize_timeout`.
    pub fn mark_body_eof(&self) {
        if !self.body_eof.swap(true, Ordering::AcqRel) {
            self.notify.notify_waiters();
        }
    }

    /// Returns `true` once the outbound upload body stream has reached EOF.
    pub fn is_body_eof(&self) -> bool {
        self.body_eof.load(Ordering::Acquire)
    }
}

impl Default for ProgressHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Independent byte-progress idle watchdog + post-body-EOF finalize timeout +
/// optional total transfer deadline.
#[derive(Debug, Clone)]
pub struct ProgressWatchdog {
    stall_timeout: Duration,
    finalize_timeout: Duration,
    total_timeout: Option<Duration>,
    progress: ProgressHandle,
}

impl ProgressWatchdog {
    pub fn new(stall_timeout: Duration, total_timeout: Option<Duration>) -> Self {
        Self {
            stall_timeout,
            finalize_timeout: stall_timeout.max(DEFAULT_DATA_FINALIZE_TIMEOUT),
            total_timeout,
            progress: ProgressHandle::new(),
        }
    }

    /// Override the post-body-EOF finalize timeout used while waiting for server
    /// upload assembly/finalization after the last request body chunk is sent.
    pub fn with_finalize_timeout(mut self, finalize_timeout: Duration) -> Self {
        self.finalize_timeout = finalize_timeout;
        self
    }

    pub fn finalize_timeout(&self) -> Duration {
        self.finalize_timeout
    }

    pub fn handle(&self) -> ProgressHandle {
        self.progress.clone()
    }

    /// Wrap an outbound `ByteStream` so every yielded non-empty chunk advances
    /// this watchdog's progress signal and stream EOF transitions to `finalize_timeout`.
    pub fn watch_upload_stream<S>(&self, inner: S) -> WatchedByteStream<S>
    where
        S: Stream<Item = Result<Bytes>> + Unpin,
    {
        WatchedByteStream {
            inner,
            progress: self.progress.clone(),
        }
    }

    /// Wrap an inbound byte stream with per-chunk byte-progress stall detection
    /// and optional overall deadline.
    pub fn watch_download_stream<S>(&self, inner: S) -> StallWatchdogStream<S>
    where
        S: Stream<Item = Result<Bytes>> + Unpin,
    {
        StallWatchdogStream::new(inner, self.stall_timeout, self.total_timeout)
    }

    /// Execute `fut` (e.g., an HTTP Data Plane `send()` call) while enforcing:
    /// - Failure with `ErrorKind::Timeout` (`RetryClass::Retryable`) if no byte
    ///   progress occurs for `stall_timeout` before upload body EOF.
    /// - Once [`ProgressHandle::mark_body_eof`] is signaled, switches once to
    ///   `finalize_timeout` (still bounded by `total_timeout`) while waiting for
    ///   server-side upload finalization.
    /// - Failure with `ErrorKind::Timeout` (`RetryClass::Retryable`) if
    ///   `total_timeout` elapses even while slowly trickling.
    pub async fn run<F, T>(&self, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        let start = Instant::now();
        let total_deadline = self.total_timeout.map(|d| start + d);
        let stall_timeout = self.stall_timeout;
        let finalize_timeout = self.finalize_timeout;
        let progress = self.progress.clone();

        tokio::pin!(fut);

        let mut last_seen = progress.total_bytes();
        let mut in_finalize = progress.is_body_eof();
        let active_sleep = tokio::time::sleep(if in_finalize {
            finalize_timeout
        } else {
            stall_timeout
        });
        tokio::pin!(active_sleep);

        loop {
            // Check overall ceiling first if configured.
            if let Some(deadline) = total_deadline
                && Instant::now() >= deadline
            {
                return Err(Error::new(
                    ErrorKind::Timeout,
                    RetryClass::Retryable,
                    format!(
                        "data-plane operation exceeded total timeout ({:?})",
                        self.total_timeout.unwrap_or_default()
                    ),
                ));
            }

            let notified = progress.notify.notified();
            tokio::pin!(notified);
            // Register the waiter BEFORE re-checking `total_bytes()` / `is_body_eof()`
            // so concurrent `notify_waiters()` calls cannot slip between the check and `select!`.
            notified.as_mut().enable();

            // Re-check after registering `notified` to avoid missed wakeups.
            if !in_finalize {
                if progress.is_body_eof() {
                    in_finalize = true;
                    last_seen = progress.total_bytes();
                    active_sleep
                        .as_mut()
                        .reset(Instant::now() + finalize_timeout);
                } else {
                    let current = progress.total_bytes();
                    if current != last_seen {
                        last_seen = current;
                        active_sleep.as_mut().reset(Instant::now() + stall_timeout);
                    }
                }
            }

            let total_fut = async {
                match total_deadline {
                    Some(dl) => tokio::time::sleep_until(dl).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                res = &mut fut => return res,
                _ = &mut notified => {
                    if !in_finalize {
                        if progress.is_body_eof() {
                            in_finalize = true;
                            last_seen = progress.total_bytes();
                            active_sleep.as_mut().reset(Instant::now() + finalize_timeout);
                        } else {
                            let now_bytes = progress.total_bytes();
                            if now_bytes != last_seen {
                                last_seen = now_bytes;
                                active_sleep.as_mut().reset(Instant::now() + stall_timeout);
                            }
                        }
                    }
                }
                _ = &mut active_sleep => {
                    if !in_finalize {
                        if progress.is_body_eof() {
                            in_finalize = true;
                            last_seen = progress.total_bytes();
                            active_sleep.as_mut().reset(Instant::now() + finalize_timeout);
                        } else {
                            let now_bytes = progress.total_bytes();
                            if now_bytes != last_seen {
                                last_seen = now_bytes;
                                active_sleep.as_mut().reset(Instant::now() + stall_timeout);
                            } else {
                                return Err(Error::new(
                                    ErrorKind::Timeout,
                                    RetryClass::Retryable,
                                    format!(
                                        "data-plane stream stalled for {stall_timeout:?} with no byte progress (at {last_seen} bytes)"
                                    ),
                                ));
                            }
                        }
                    } else {
                        return Err(Error::new(
                            ErrorKind::Timeout,
                            RetryClass::Retryable,
                            format!(
                                "data-plane upload finalize timed out after {finalize_timeout:?} following body EOF (at {last_seen} bytes)"
                            ),
                        ));
                    }
                }
                _ = total_fut => {
                    return Err(Error::new(
                        ErrorKind::Timeout,
                        RetryClass::Retryable,
                        format!(
                            "data-plane operation exceeded total timeout ({:?})",
                            self.total_timeout.unwrap()
                        ),
                    ));
                }
            }
        }
    }
}

/// Adapter around an upload `ByteStream` that notifies a [`ProgressHandle`] on
/// every non-empty `Bytes` chunk pulled by the HTTP client and signals body EOF
/// once the underlying stream terminates.
pub struct WatchedByteStream<S> {
    inner: S,
    progress: ProgressHandle,
}

impl<S> Stream for WatchedByteStream<S>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.progress.record_bytes(chunk.len());
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                this.progress.mark_body_eof();
                Poll::Ready(None)
            }
            other => other,
        }
    }
}

/// Stream wrapper enforcing a byte-progress idle stall timeout and optional total
/// deadline directly inside `Stream::poll_next` (ideal for download response streams).
pub struct StallWatchdogStream<S> {
    inner: S,
    stall_timeout: Duration,
    stall_sleep: Pin<Box<Sleep>>,
    total_timeout: Option<Duration>,
    total_sleep: Option<Pin<Box<Sleep>>>,
    bytes_seen: u64,
    terminated: bool,
}

impl<S> StallWatchdogStream<S> {
    pub fn new(inner: S, stall_timeout: Duration, total_timeout: Option<Duration>) -> Self {
        let now = Instant::now();
        Self {
            inner,
            stall_timeout,
            stall_sleep: Box::pin(tokio::time::sleep_until(now + stall_timeout)),
            total_timeout,
            total_sleep: total_timeout.map(|d| Box::pin(tokio::time::sleep_until(now + d))),
            bytes_seen: 0,
            terminated: false,
        }
    }
}

impl<S> Stream for StallWatchdogStream<S>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
{
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.terminated {
            return Poll::Ready(None);
        }

        // Enforce `total_timeout` on EVERY poll (not only when inner returns `Pending`)
        // so continuously-ready slow-drip streams cannot bypass the total deadline.
        if let Some(total) = this.total_sleep.as_mut()
            && total.as_mut().poll(cx).is_ready()
        {
            this.terminated = true;
            return Poll::Ready(Some(Err(Error::new(
                ErrorKind::Timeout,
                RetryClass::Retryable,
                format!(
                    "download stream exceeded total timeout ({:?})",
                    this.total_timeout.unwrap_or_default()
                ),
            ))));
        }

        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                if !chunk.is_empty() {
                    this.bytes_seen = this.bytes_seen.saturating_add(chunk.len() as u64);
                    this.stall_sleep
                        .as_mut()
                        .reset(Instant::now() + this.stall_timeout);
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.terminated = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.terminated = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.stall_sleep.as_mut().poll(cx).is_ready() {
                    this.terminated = true;
                    return Poll::Ready(Some(Err(Error::new(
                        ErrorKind::Timeout,
                        RetryClass::Retryable,
                        format!(
                            "download stream stalled for {:?} with no byte progress (at {} bytes)",
                            this.stall_timeout, this.bytes_seen
                        ),
                    ))));
                }
                Poll::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test(start_paused = true)]
    async fn download_watchdog_resets_on_bytes_and_fires_on_stall() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(4);
        let raw = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let mut watched = StallWatchdogStream::new(
            Box::pin(raw),
            Duration::from_secs(5),
            Some(Duration::from_secs(30)),
        );

        // Emit 3 chunks spaced 4s apart (< 5s stall timeout): must keep succeeding!
        let producer = tokio::spawn(async move {
            for i in 0..3u8 {
                tokio::time::sleep(Duration::from_secs(4)).await;
                tx.send(Ok(Bytes::from(vec![i; 16]))).await.unwrap();
            }
            // Send an empty chunk at +2s -> MUST NOT reset stall timer!
            tokio::time::sleep(Duration::from_secs(2)).await;
            tx.send(Ok(Bytes::new())).await.unwrap();
            // Now hang forever (drop sender only after 100s).
            tokio::time::sleep(Duration::from_secs(100)).await;
            drop(tx);
        });

        let mut received = 0usize;
        for _ in 0..3 {
            let chunk = watched.next().await.unwrap().unwrap();
            received += chunk.len();
        }
        assert_eq!(received, 48);

        // Next comes empty chunk (0 bytes, does NOT reset timer).
        let empty = watched.next().await.unwrap().unwrap();
        assert!(empty.is_empty());

        // 3 more seconds later (total 5s since last non-empty chunk), watchdog fires!
        let err = watched.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert_eq!(err.retry, RetryClass::Retryable);
        producer.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn upload_watchdog_catches_blackholed_send_and_enforces_total_timeout() {
        // Case 1: send future stops making progress (simulating full TCP buffer / dead peer).
        let wd = ProgressWatchdog::new(Duration::from_secs(3), Some(Duration::from_secs(20)));
        let handle = wd.handle();

        let err = wd
            .run(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                handle.record_bytes(1024);
                tokio::time::sleep(Duration::from_secs(2)).await;
                handle.record_bytes(1024);
                // Now hang forever with no byte progress:
                std::future::pending::<Result<()>>().await
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert!(err.message.contains("stalled"));

        // Case 2: steady trickle exceeds total_timeout even without stalling.
        let wd2 = ProgressWatchdog::new(Duration::from_secs(5), Some(Duration::from_secs(7)));
        let h2 = wd2.handle();
        let err2 = wd2
            .run(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    h2.record_bytes(1);
                }
                #[allow(unreachable_code)]
                Ok::<(), Error>(())
            })
            .await
            .unwrap_err();
        assert_eq!(err2.kind, ErrorKind::Timeout);
        assert!(err2.message.contains("total timeout"));
    }

    #[tokio::test(start_paused = true)]
    async fn download_watchdog_enforces_total_timeout_on_continuously_ready_stream() {
        let raw = futures::stream::repeat_with(|| Ok::<Bytes, Error>(Bytes::from_static(b"x")));
        let mut watched = StallWatchdogStream::new(
            Box::pin(raw),
            Duration::from_secs(10),
            Some(Duration::from_secs(5)),
        );
        // First poll succeeds before total timeout elapses.
        assert!(watched.next().await.unwrap().is_ok());
        // Advance past total timeout without the inner stream ever returning Poll::Pending.
        tokio::time::advance(Duration::from_secs(6)).await;
        let err = watched.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert!(err.message.contains("total timeout"));
    }

    #[tokio::test(start_paused = true)]
    async fn upload_watchdog_allows_slow_finalize_after_body_eof() {
        let wd = ProgressWatchdog::new(Duration::from_secs(5), Some(Duration::from_secs(600)));
        let raw = futures::stream::iter(vec![Ok::<Bytes, Error>(Bytes::from_static(b"payload"))]);
        let mut upload_stream = wd.watch_upload_stream(raw);

        let res = wd
            .run(async move {
                // Drain entire upload body to EOF.
                while let Some(chunk) = upload_stream.next().await {
                    chunk?;
                }
                // Simulate a slow server-side finalize (> 5s stall_timeout, < 300s finalize_timeout).
                tokio::time::sleep(Duration::from_secs(20)).await;
                Ok::<&'static str, Error>("finalized")
            })
            .await;
        assert_eq!(res.unwrap(), "finalized");
    }

    #[tokio::test(start_paused = true)]
    async fn upload_watchdog_times_out_hung_finalize_and_still_catches_mid_body_stalls() {
        // (b) Hung server finalize exceeding finalize_timeout fails with Timeout mentioning "finalize".
        let wd_fin = ProgressWatchdog::new(Duration::from_secs(5), Some(Duration::from_secs(600)))
            .with_finalize_timeout(Duration::from_secs(30));
        let raw = futures::stream::iter(vec![Ok::<Bytes, Error>(Bytes::from_static(b"done"))]);
        let mut upload_stream = wd_fin.watch_upload_stream(raw);
        let err = wd_fin
            .run(async move {
                while let Some(chunk) = upload_stream.next().await {
                    chunk?;
                }
                tokio::time::sleep(Duration::from_secs(120)).await;
                Ok::<(), Error>(())
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Timeout);
        assert_eq!(err.retry, RetryClass::Retryable);
        assert!(
            err.message.contains("finalize"),
            "expected finalize timeout error, got: {}",
            err.message
        );

        // (c) Mid-body stall BEFORE EOF still trips stall_timeout (not finalize_timeout).
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(2);
        let raw_mid = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|item| (item, rx))
        });
        let wd_mid = ProgressWatchdog::new(Duration::from_secs(5), Some(Duration::from_secs(600)))
            .with_finalize_timeout(Duration::from_secs(60));
        let mut watched_mid = wd_mid.watch_upload_stream(Box::pin(raw_mid));
        tx.send(Ok(Bytes::from_static(b"first-chunk")))
            .await
            .unwrap();
        let err_mid = wd_mid
            .run(async move {
                // Consume first chunk, then block waiting for next chunk (no EOF!).
                let first = watched_mid.next().await.unwrap()?;
                assert_eq!(first.len(), 11);
                let _keep_open = tx;
                let _ = watched_mid.next().await;
                Ok::<(), Error>(())
            })
            .await
            .unwrap_err();
        assert_eq!(err_mid.kind, ErrorKind::Timeout);
        assert_eq!(err_mid.retry, RetryClass::Retryable);
        assert!(
            err_mid.message.contains("stalled"),
            "expected pre-EOF stall error, got: {}",
            err_mid.message
        );

        // (d) total_timeout still bounds a long finalize_timeout.
        let wd_tot = ProgressWatchdog::new(Duration::from_secs(5), Some(Duration::from_secs(15)))
            .with_finalize_timeout(Duration::from_secs(300));
        let handle_tot = wd_tot.handle();
        let err_tot = wd_tot
            .run(async move {
                handle_tot.record_bytes(16);
                handle_tot.mark_body_eof();
                tokio::time::sleep(Duration::from_secs(100)).await;
                Ok::<(), Error>(())
            })
            .await
            .unwrap_err();
        assert_eq!(err_tot.kind, ErrorKind::Timeout);
        assert!(err_tot.message.contains("total timeout"));
    }
}
