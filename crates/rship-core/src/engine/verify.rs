//! End-to-end verification of chunked and ranged source reads (C3).
//!
//! Backends verify a *full* download against the object's advertised hash, but chunked
//! uploads read the source as byte ranges, which no backend can verify on its own. When
//! the source entry carries a full-object checksum, the engine hashes the bytes it streams
//! and checks the whole object before (or, at worst, while) committing it:
//!
//! - Sequential resumable uploads: a running SHA-256 or CRC-32C over the chunks of one
//!   session that started at offset 0. The last bytes of the final chunk are withheld
//!   until the digest matches, so a mismatch aborts the upload before the destination can
//!   commit it.
//! - Parallel multipart uploads: per-part CRC-32C values computed while streaming are
//!   combined in part order ([`crate::crc32c::crc32c_combine`]) and checked before
//!   `finish_upload`. Only CRC-32C is combinable; other hash kinds are not verified here.
//!
//! Not verified by this module (documented gaps):
//! - sessions resumed from an earlier process (chunks or parts sent before the restart
//!   were never hashed by this process), and sequential sessions whose chunk was re-sent
//!   from a server offset behind the bytes already hashed (verification is abandoned);
//! - sources without a full-object checksum (e.g. local files), multipart-composite
//!   checksums (`-N` suffix), and MD5/other non-combinable hashes on parallel uploads;
//! - single-shot uploads and `--strict-source` snapshots, which read the whole object in
//!   one request and rely on the source backend's full-download verification.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::Stream;
use sha2::{Digest, Sha256};

use crate::crc32c::{crc32c_combine, crc32c_hex, crc32c_update};
use crate::error::{Error, Result};
use crate::source::ByteStream;
use crate::types::{Checksum, Entry, HashKind};

/// Slot through which a verifying stream hands its integrity error to the protocol
/// machine (backends may wrap body-stream errors and lose the error kind).
pub(super) type FailureSlot = Arc<Mutex<Option<Error>>>;

pub(super) fn new_failure_slot() -> FailureSlot {
    Arc::new(Mutex::new(None))
}

pub(super) fn take_failure(slot: &FailureSlot) -> Option<Error> {
    slot.lock().ok().and_then(|mut g| g.take())
}

fn full_object_checksum(src: &Entry) -> Option<&Checksum> {
    src.checksum.as_ref().filter(|c| !c.hex.contains('-'))
}

enum Running {
    Crc32c(u32),
    Sha256(Box<Sha256>),
}

impl Running {
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Crc32c(c) => *c = crc32c_update(*c, data),
            Self::Sha256(h) => h.update(data),
        }
    }

    fn finish_hex(self) -> String {
        match self {
            Self::Crc32c(c) => crc32c_hex(c),
            Self::Sha256(h) => hex::encode(h.finalize()),
        }
    }
}

struct SeqState {
    /// `None` once verification had to be abandoned (bytes re-sent out of order).
    running: Option<Running>,
    /// Object offset up to which `running` has hashed.
    hashed_upto: u64,
}

/// Running whole-object digest across the sequential chunks of one upload session.
pub(super) struct SequentialVerifier {
    expected: Checksum,
    total: u64,
    state: Mutex<SeqState>,
}

impl SequentialVerifier {
    /// A verifier for a session that streams `src` from offset 0, if its checksum kind
    /// can be computed incrementally here.
    pub(super) fn for_entry(src: &Entry, total: u64) -> Option<Arc<Self>> {
        let expected = full_object_checksum(src)?.clone();
        let running = match expected.kind {
            HashKind::Crc32c => Running::Crc32c(0),
            HashKind::Sha256 => Running::Sha256(Box::new(Sha256::new())),
            _ => return None,
        };
        Some(Arc::new(Self {
            expected,
            total,
            state: Mutex::new(SeqState {
                running: Some(running),
                hashed_upto: 0,
            }),
        }))
    }

    /// Wrap the body of the chunk at `offset` (`len` bytes).
    pub(super) fn wrap(
        self: &Arc<Self>,
        offset: u64,
        len: u64,
        body: ByteStream,
        failure: FailureSlot,
    ) -> ByteStream {
        Box::pin(SeqVerifyStream {
            inner: body,
            verifier: self.clone(),
            offset,
            len,
            seen: 0,
            failure,
        })
    }

    /// Hash `chunk` at object offset `at`; returns `Err` with the integrity error when
    /// these are the object's final bytes and the digest does not match.
    fn feed(&self, at: u64, chunk: &[u8]) -> Result<()> {
        let mut st = self.state.lock().expect("sequential verifier mutex");
        if st.running.is_none() {
            return Ok(());
        }
        if st.hashed_upto != at {
            // Re-sent bytes (retry from a server offset): the running digest cannot be
            // rewound, so this session goes unverified.
            st.running = None;
            return Ok(());
        }
        if let Some(r) = st.running.as_mut() {
            r.update(chunk);
        }
        st.hashed_upto += chunk.len() as u64;
        if st.hashed_upto == self.total
            && let Some(r) = st.running.take()
        {
            let got = r.finish_hex();
            if !got.eq_ignore_ascii_case(&self.expected.hex) {
                return Err(Error::integrity(format!(
                    "source read checksum mismatch ({:?}): expected {}, streamed {got}",
                    self.expected.kind, self.expected.hex
                )));
            }
        }
        Ok(())
    }
}

struct SeqVerifyStream {
    inner: ByteStream,
    verifier: Arc<SequentialVerifier>,
    offset: u64,
    len: u64,
    seen: u64,
    failure: FailureSlot,
}

impl Stream for SeqVerifyStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let at = this.offset + this.seen;
                this.seen += chunk.len() as u64;
                debug_assert!(this.seen <= this.len);
                match this.verifier.feed(at, &chunk) {
                    // Withhold the object's last bytes: the destination never receives a
                    // complete body, so it cannot commit the corrupt object.
                    Err(e) => {
                        if let Ok(mut g) = this.failure.lock() {
                            *g = Some(Error::integrity(e.message.clone()));
                        }
                        Poll::Ready(Some(Err(e)))
                    }
                    Ok(()) => Poll::Ready(Some(Ok(chunk))),
                }
            }
            other => other,
        }
    }
}

/// Per-part CRC-32C values of one parallel multipart session.
pub(super) struct PartCrcs {
    expected: u32,
    expected_hex: String,
    parts: Mutex<HashMap<u32, (u32, u64)>>,
}

impl PartCrcs {
    /// Collector for `src` when it carries a full-object CRC-32C.
    pub(super) fn for_entry(src: &Entry) -> Option<Arc<Self>> {
        let ck = full_object_checksum(src).filter(|c| c.kind == HashKind::Crc32c)?;
        let expected = u32::from_str_radix(&ck.hex, 16).ok()?;
        Some(Arc::new(Self {
            expected,
            expected_hex: ck.hex.clone(),
            parts: Mutex::new(HashMap::new()),
        }))
    }

    /// Wrap one attempt at part `part_number` (`len` bytes).
    pub(super) fn wrap(
        self: &Arc<Self>,
        part_number: u32,
        len: u64,
        body: ByteStream,
    ) -> ByteStream {
        Box::pin(PartCrcStream {
            inner: body,
            sink: self.clone(),
            part_number,
            len,
            seen: 0,
            crc: 0,
        })
    }

    /// Check the combined CRC of parts `1..=total_parts`. Returns `Ok(())` when some part
    /// was not hashed by this process (unverifiable), and an integrity error on mismatch.
    pub(super) fn verify(&self, total_parts: u32) -> Result<()> {
        let parts = self.parts.lock().expect("part crc mutex");
        let mut acc = 0u32;
        for pn in 1..=total_parts {
            let Some(&(crc, len)) = parts.get(&pn) else {
                return Ok(());
            };
            acc = crc32c_combine(acc, crc, len);
        }
        if acc != self.expected {
            return Err(Error::integrity(format!(
                "source read checksum mismatch (Crc32c): expected {}, combined parts {}",
                self.expected_hex,
                crc32c_hex(acc)
            )));
        }
        Ok(())
    }
}

struct PartCrcStream {
    inner: ByteStream,
    sink: Arc<PartCrcs>,
    part_number: u32,
    len: u64,
    seen: u64,
    crc: u32,
}

impl Stream for PartCrcStream {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let res = this.inner.as_mut().poll_next(cx);
        if let Poll::Ready(Some(Ok(chunk))) = &res {
            this.crc = crc32c_update(this.crc, chunk);
            this.seen += chunk.len() as u64;
            if this.seen == this.len
                && let Ok(mut parts) = this.sink.parts.lock()
            {
                parts.insert(this.part_number, (this.crc, this.len));
            }
        }
        res
    }
}
