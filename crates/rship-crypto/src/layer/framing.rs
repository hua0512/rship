//! Stream encryption pipeline, ciphertext framing, and offset-geometry helpers for `CryptoBackend`.

use bytes::Bytes;
use futures::StreamExt;
use rship_core::path::RelPath;
use rship_core::source::ByteStream;
use rship_core::{Error, Result};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tokio::sync::Semaphore;

use crate::stream::{
    CIPHERTEXT_CHUNK_LEN, HEADER_LEN, PLAINTEXT_CHUNK_LEN, StreamEncryptor, StreamHeader,
    ciphertext_size,
};

/// Global cap on background pipelined AEAD encryptor channels (`6 × ~1.5 MiB = ~9 MiB` max
/// across the entire process). Additional concurrent encrypted streams beyond 6 fall back
/// seamlessly to inline zero-queue `StreamEncryptor` (`4 × 64 KiB = 256 KiB` coalesced frame),
/// keeping peak RSS strictly bounded even under `-t 16` or `-t 64`.
pub(super) const MAX_GLOBAL_ENCRYPT_PIPELINES: usize = 6;

pub(super) fn encrypt_pipeline_slots() -> &'static Arc<Semaphore> {
    static SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SLOTS.get_or_init(|| Arc::new(Semaphore::new(MAX_GLOBAL_ENCRYPT_PIPELINES)))
}

/// Coalesce OAE2 blocks (`512 KiB` pipelined / `256 KiB` inline) per output frame, and for
/// multi-MiB payloads acquire one of [`MAX_GLOBAL_ENCRYPT_PIPELINES`] slots to overlap
/// `ChaCha20-Poly1305` on a dedicated Tokio worker task (`channel(2)`) with TLS/socket I/O.
/// When all global pipeline slots are saturated (e.g. `-t 16` concurrent large uploads),
/// falls back cleanly to zero-queue inline encryption so memory stays strictly bounded.
pub(super) fn build_fast_encrypt_stream(
    body: ByteStream,
    data_key: [u8; 32],
    header: StreamHeader,
    start_chunk_idx: u64,
    expected_pt_len: u64,
    emit_header: bool,
    is_final_segment: bool,
) -> ByteStream {
    const PIPELINED_COALESCE_BLOCKS: usize = 8; // 512 KiB per yielded frame
    const INLINE_COALESCE_BLOCKS: usize = 4; // 256 KiB per yielded frame
    const PIPELINE_MIN_BYTES: u64 = 1024 * 1024; // >= 1 MiB

    if expected_pt_len < PIPELINE_MIN_BYTES {
        return Box::pin(StreamEncryptor::with_coalesced_blocks(
            body,
            &data_key,
            header,
            start_chunk_idx,
            expected_pt_len,
            emit_header,
            is_final_segment,
            INLINE_COALESCE_BLOCKS,
        ));
    }

    let Ok(permit) = encrypt_pipeline_slots().clone().try_acquire_owned() else {
        return Box::pin(StreamEncryptor::with_coalesced_blocks(
            body,
            &data_key,
            header,
            start_chunk_idx,
            expected_pt_len,
            emit_header,
            is_final_segment,
            INLINE_COALESCE_BLOCKS,
        ));
    };

    let mut enc = StreamEncryptor::with_coalesced_blocks(
        body,
        &data_key,
        header,
        start_chunk_idx,
        expected_pt_len,
        emit_header,
        is_final_segment,
        PIPELINED_COALESCE_BLOCKS,
    );
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes>>(2);
    // Keep `permit` inside the producer task so the bounded pipeline slot is held
    // until `StreamEncryptor` and its buffers are actually dropped; aborting the
    // producer on consumer drop prevents leaked background encryption tasks.
    let producer = AbortOnDrop(tokio::spawn(async move {
        let _permit = permit;
        while let Some(item) = enc.next().await {
            let is_err = item.is_err();
            if tx.send(item).await.is_err() || is_err {
                return;
            }
        }
    }));
    let s = futures::stream::unfold((rx, producer), |(mut rx, producer)| async move {
        rx.recv().await.map(|item| (item, (rx, producer)))
    });
    Box::pin(s)
}

/// Map a server-confirmed sequential ciphertext offset `ct_off` back to the exact
/// `(plaintext_block_offset, skip_leading_ct_bytes)` resume point.
pub(super) fn map_sequential_ct_offset(ct_off: u64, total_pt: u64) -> (u64, u64) {
    if ct_off == 0 {
        return (0, 0);
    }
    let ct_total = ciphertext_size(total_pt).unwrap_or(u64::MAX);
    if ct_off >= ct_total {
        return (total_pt, 0);
    }
    if ct_off < (HEADER_LEN + CIPHERTEXT_CHUNK_LEN) as u64 {
        return (0, ct_off);
    }
    let body = ct_off - HEADER_LEN as u64;
    let block_idx = body / (CIPHERTEXT_CHUNK_LEN as u64);
    let skip_in_block = body % (CIPHERTEXT_CHUNK_LEN as u64);
    let pt_off = block_idx
        .saturating_mul(PLAINTEXT_CHUNK_LEN as u64)
        .min(total_pt);
    (pt_off, skip_in_block)
}

/// Skip the first `skip_bytes` from `inner` (used when resuming mid-OAE2-block after a `308` query).
pub(super) fn skip_ciphertext_prefix(inner: ByteStream, skip_bytes: u64) -> ByteStream {
    if skip_bytes == 0 {
        return inner;
    }
    let s = futures::stream::try_unfold(
        (inner, skip_bytes),
        |(mut inner, mut rem_skip)| async move {
            while let Some(item) = inner.next().await {
                let b = item?;
                if b.is_empty() {
                    continue;
                }
                if rem_skip == 0 {
                    return Ok(Some((b, (inner, 0))));
                }
                if (b.len() as u64) <= rem_skip {
                    rem_skip -= b.len() as u64;
                    continue;
                }
                let sliced = b.slice((rem_skip as usize)..);
                return Ok(Some((sliced, (inner, 0))));
            }
            Ok(None)
        },
    );
    Box::pin(s)
}

pub(super) fn equal_ct_part_size(pt_chunk_size: u64) -> Result<u64> {
    if pt_chunk_size == 0 || !pt_chunk_size.is_multiple_of(PLAINTEXT_CHUNK_LEN as u64) {
        return Err(Error::invalid_geometry(format!(
            "crypto equal-part plaintext chunk ({pt_chunk_size}) must be a positive multiple of {PLAINTEXT_CHUNK_LEN}"
        )));
    }
    let blocks = pt_chunk_size / (PLAINTEXT_CHUNK_LEN as u64);
    blocks
        .checked_mul(CIPHERTEXT_CHUNK_LEN as u64)
        .ok_or_else(|| Error::invalid_geometry("equal_ct_part_size overflow"))
}

pub(super) fn split_ciphertext_stream(
    prefix: Vec<u8>,
    inner: ByteStream,
    take_len: u64,
    tail_out: Arc<StdMutex<Vec<u8>>>,
) -> ByteStream {
    let prefix_bytes = if prefix.is_empty() {
        None
    } else {
        Some(Bytes::from(prefix))
    };
    let s = futures::stream::try_unfold(
        (prefix_bytes, inner, 0u64, tail_out),
        move |(mut pref, mut inner, mut emitted, tail_out)| async move {
            loop {
                let next_chunk = if let Some(p) = pref.take() {
                    p
                } else {
                    match inner.next().await {
                        Some(Ok(b)) if b.is_empty() => continue,
                        Some(Ok(b)) => b,
                        Some(Err(e)) => return Err(e),
                        None => return Ok(None),
                    }
                };
                if emitted >= take_len {
                    super::lock_unpoisoned(&tail_out).extend_from_slice(&next_chunk);
                    continue;
                }
                let rem = (take_len - emitted) as usize;
                if next_chunk.len() <= rem {
                    emitted += next_chunk.len() as u64;
                    return Ok(Some((next_chunk, (pref, inner, emitted, tail_out))));
                }
                let head = next_chunk.slice(..rem);
                let tail = next_chunk.slice(rem..);
                emitted += rem as u64;
                super::lock_unpoisoned(&tail_out).extend_from_slice(&tail);
                return Ok(Some((head, (pref, inner, emitted, tail_out))));
            }
        },
    );
    Box::pin(s)
}

pub(super) fn ciphertext_offset_for_plaintext(pt_off: u64) -> Result<u64> {
    if pt_off == 0 {
        return Ok(0);
    }
    if !pt_off.is_multiple_of(PLAINTEXT_CHUNK_LEN as u64) {
        return Err(Error::invalid_geometry(format!(
            "crypto chunk offset ({pt_off}) must be a multiple of {PLAINTEXT_CHUNK_LEN}"
        )));
    }
    let idx = pt_off / (PLAINTEXT_CHUNK_LEN as u64);
    (HEADER_LEN as u64)
        .checked_add(
            idx.checked_mul(CIPHERTEXT_CHUNK_LEN as u64)
                .ok_or_else(|| Error::invalid_geometry("ct offset overflow"))?,
        )
        .ok_or_else(|| Error::invalid_geometry("ct offset overflow"))
}

pub(super) fn ciphertext_part_len(pt_off: u64, pt_len: u64, total_pt: u64) -> Result<u64> {
    let header_bytes = if pt_off == 0 { HEADER_LEN as u64 } else { 0 };
    if total_pt == 0 {
        return Ok(HEADER_LEN as u64 + 16);
    }
    let blocks = pt_len.div_ceil(PLAINTEXT_CHUNK_LEN as u64);
    let tags = blocks
        .checked_mul(16)
        .ok_or_else(|| Error::invalid_geometry("tag length overflow"))?;
    header_bytes
        .checked_add(pt_len)
        .and_then(|v| v.checked_add(tags))
        .ok_or_else(|| Error::invalid_geometry("ct part len overflow"))
}

pub(super) fn plaintext_offset_from_ciphertext(ct_off: u64, total_pt: u64) -> u64 {
    if ct_off <= HEADER_LEN as u64 {
        return 0;
    }
    let ct_total = ciphertext_size(total_pt).unwrap_or(u64::MAX);
    if ct_off >= ct_total {
        return total_pt;
    }
    let body = ct_off - HEADER_LEN as u64;
    let complete_blocks = body / (CIPHERTEXT_CHUNK_LEN as u64);
    complete_blocks
        .saturating_mul(PLAINTEXT_CHUNK_LEN as u64)
        .min(total_pt)
}

pub(super) fn strip_inner_prefix(inner_rel: &RelPath, prefix: &RelPath) -> Result<RelPath> {
    if prefix.is_root() {
        return Ok(inner_rel.clone());
    }
    if inner_rel == prefix {
        return Ok(RelPath::root());
    }
    let rest = inner_rel
        .as_str()
        .strip_prefix(prefix.as_str())
        .and_then(|s| s.strip_prefix('/'))
        .ok_or_else(|| {
            Error::protocol(format!(
                "inner entry `{inner_rel}` is outside crypt inner_prefix `{prefix}`"
            ))
        })?;
    RelPath::parse(rest)
}
