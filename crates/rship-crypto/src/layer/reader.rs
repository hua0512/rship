//! Zero-big-buffer, in-place seekable range decryptor implementing [`RemoteRangeReadable`].

use crate::keys::CryptoKeys;
use crate::stream::{
    CIPHERTEXT_CHUNK_LEN, HEADER_LEN, PLAINTEXT_CHUNK_LEN, StreamCipher, StreamHeader, TAG_LEN,
    decrypt_chunk, decrypt_chunk_in_place, total_chunks,
};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt;
use rship_core::backend::{BackendPath, StorageBackend};
use rship_core::buffer::BufferPool;
use rship_core::source::{ByteStream, DataSource, RemoteRangeReadable, bounded_range_stream};
use rship_core::types::{ByteRange, Entry};
use rship_core::{Error, Result};
use std::sync::Arc;
use tokio::sync::OnceCell;

pub(super) struct CryptoRangeReader {
    pub(super) inner: Arc<dyn StorageBackend>,
    pub(super) enc_path: BackendPath,
    pub(super) ct_entry: Option<Entry>,
    pub(super) ct_len: u64,
    pub(super) pt_len: u64,
    pub(super) keys: Arc<CryptoKeys>,
    pub(super) header: OnceCell<StreamHeader>,
    pub(super) pool: BufferPool,
}

impl CryptoRangeReader {
    async fn open_inner_range(&self, range: ByteRange) -> Result<DataSource> {
        match &self.ct_entry {
            Some(entry) => {
                self.inner
                    .open_read_entry(entry, &self.enc_path, Some(range))
                    .await
            }
            None => self.inner.open_read(&self.enc_path, Some(range)).await,
        }
    }

    async fn read_inner_exact(&self, range: ByteRange) -> Result<Vec<u8>> {
        let ds = self.open_inner_range(range).await?;
        let mut stream: ByteStream = match ds {
            DataSource::LocalSeekable(src) => {
                bounded_range_stream(src, range.offset, range.len, self.pool.clone())
            }
            DataSource::RemoteRangeReadable(r) => r.open_range(range).await?,
            DataSource::SequentialStream { stream, .. } => stream,
        };
        let mut out = Vec::with_capacity(range.len as usize);
        while let Some(item) = stream.next().await {
            let chunk = item?;
            out.extend_from_slice(&chunk);
            drop(chunk);
        }
        if out.len() as u64 != range.len {
            return Err(Error::network(format!(
                "short encrypted read: got {} of {} bytes",
                out.len(),
                range.len
            )));
        }
        Ok(out)
    }

    async fn load_header(&self) -> Result<StreamHeader> {
        self.header
            .get_or_try_init(|| async {
                let raw = self
                    .read_inner_exact(ByteRange {
                        offset: 0,
                        len: HEADER_LEN as u64,
                    })
                    .await?;
                StreamHeader::decode(&raw)
            })
            .await
            .copied()
    }
}

#[async_trait]
impl RemoteRangeReadable for CryptoRangeReader {
    fn total_len(&self) -> u64 {
        self.pt_len
    }

    async fn open_range(&self, range: ByteRange) -> Result<ByteStream> {
        let end_exclusive = range
            .end_exclusive()
            .ok_or_else(|| Error::invalid_geometry("crypto ByteRange overflow"))?;
        if end_exclusive > self.pt_len {
            return Err(Error::invalid_geometry(format!(
                "crypto read range [{}..{}) exceeds plaintext len {}",
                range.offset, end_exclusive, self.pt_len
            )));
        }

        let header = self.load_header().await?;

        // Even for a 0-byte plaintext file, authenticate the empty final AEAD block!
        if self.pt_len == 0 {
            let ct = self
                .read_inner_exact(ByteRange {
                    offset: HEADER_LEN as u64,
                    len: TAG_LEN as u64,
                })
                .await?;
            let pt = decrypt_chunk(&self.keys.data_key, &header, 0, true, &ct)?;
            if !pt.is_empty() {
                return Err(Error::protocol(
                    "expected empty plaintext for 0-byte encrypted file",
                ));
            }
            return Ok(Box::pin(futures::stream::empty()));
        }

        if range.len == 0 {
            return Ok(Box::pin(futures::stream::empty()));
        }

        let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
        let ct_chunk = CIPHERTEXT_CHUNK_LEN as u64;
        let first_chunk = range.offset / pt_chunk;
        let last_chunk = (end_exclusive - 1) / pt_chunk;
        let last_file_chunk = total_chunks(self.pt_len) - 1;

        let ct_start = (HEADER_LEN as u64) + first_chunk * ct_chunk;
        let ct_end = if last_chunk == last_file_chunk {
            self.ct_len
        } else {
            (HEADER_LEN as u64) + (last_chunk + 1) * ct_chunk
        };

        let ds = self
            .open_inner_range(ByteRange {
                offset: ct_start,
                len: ct_end - ct_start,
            })
            .await?;
        let ct_stream: ByteStream = match ds {
            DataSource::LocalSeekable(src) => {
                bounded_range_stream(src, ct_start, ct_end - ct_start, self.pool.clone())
            }
            DataSource::RemoteRangeReadable(r) => {
                r.open_range(ByteRange {
                    offset: ct_start,
                    len: ct_end - ct_start,
                })
                .await?
            }
            DataSource::SequentialStream { stream, .. } => stream,
        };

        let cipher = StreamCipher::new(&self.keys.data_key, &header);
        let pt_len = self.pt_len;
        let req_start = range.offset;
        let req_end = end_exclusive;
        let initial_cap = (ct_end - ct_start).min(CIPHERTEXT_CHUNK_LEN as u64) as usize;

        let dec_stream = futures::stream::try_unfold(
            (
                ct_stream,
                cipher,
                Bytes::new(),
                BytesMut::with_capacity(initial_cap),
                first_chunk,
                false,
            ),
            move |(mut stream, cipher, mut pending, mut block, mut chunk_idx, mut eof)| async move {
                loop {
                    if chunk_idx > last_chunk {
                        return Ok(None);
                    }
                    let is_last_file_chunk = chunk_idx == last_file_chunk;
                    let expected_ct_len = if is_last_file_chunk {
                        let rem = pt_len % pt_chunk;
                        let pt_block_len = if rem == 0 { pt_chunk } else { rem };
                        (pt_block_len + TAG_LEN as u64) as usize
                    } else {
                        CIPHERTEXT_CHUNK_LEN
                    };

                    if block.is_empty() {
                        block.reserve(expected_ct_len);
                    }
                    while block.len() < expected_ct_len {
                        if !pending.is_empty() {
                            let take = (expected_ct_len - block.len()).min(pending.len());
                            block.extend_from_slice(&pending[..take]);
                            pending.advance(take);
                            if pending.is_empty() {
                                // `Bytes::advance` to len 0 keeps the `PooledSlice` owner alive;
                                // reset to empty immediately so the `BufferPool` permit is
                                // returned before awaiting the next slab or yielding downstream.
                                pending = Bytes::new();
                            }
                            continue;
                        }
                        if eof {
                            break;
                        }
                        pending = Bytes::new();
                        match stream.next().await {
                            Some(Ok(b)) if !b.is_empty() => pending = b,
                            Some(Ok(_)) => {}
                            Some(Err(e)) => return Err(e),
                            None => eof = true,
                        }
                    }

                    if block.len() < expected_ct_len {
                        return Err(Error::protocol(format!(
                            "truncated encrypted stream at chunk {chunk_idx}: got {} of {expected_ct_len} ciphertext bytes",
                            block.len()
                        )));
                    }

                    decrypt_chunk_in_place(&cipher, chunk_idx, is_last_file_chunk, &mut block)?;
                    let pt_bytes = block.split().freeze();

                    let block_start = chunk_idx * pt_chunk;
                    let slice_start = req_start.saturating_sub(block_start) as usize;
                    let slice_end = (req_end - block_start).min(pt_bytes.len() as u64) as usize;
                    chunk_idx += 1;
                    if chunk_idx > last_chunk {
                        pending = Bytes::new();
                    }

                    if slice_start < slice_end {
                        let out = if slice_start == 0 && slice_end == pt_bytes.len() {
                            pt_bytes
                        } else {
                            pt_bytes.slice(slice_start..slice_end)
                        };
                        return Ok(Some((
                            out,
                            (stream, cipher, pending, block, chunk_idx, eof),
                        )));
                    }
                }
            },
        );

        Ok(Box::pin(dec_stream))
    }
}

/// Stream-decrypt a full encrypted object (`0..ct_len`) in ONE inner read request
/// (reading the 32-byte `StreamHeader` off the front of the stream inline while
/// preserving inner ETag version pinning via `open_read_entry`).
pub(super) async fn open_full_decrypt_stream(
    inner: &Arc<dyn StorageBackend>,
    ct_entry: &Entry,
    enc_path: &BackendPath,
    pt_len: u64,
    ct_len: u64,
    data_key: [u8; 32],
    pool: &BufferPool,
) -> Result<ByteStream> {
    let full_range = ByteRange {
        offset: 0,
        len: ct_len,
    };
    let ds = inner
        .open_read_entry(ct_entry, enc_path, Some(full_range))
        .await?;
    let ct_stream: ByteStream = match ds {
        DataSource::LocalSeekable(src) => bounded_range_stream(src, 0, ct_len, pool.clone()),
        DataSource::RemoteRangeReadable(r) => r.open_range(full_range).await?,
        DataSource::SequentialStream { stream, .. } => stream,
    };

    let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
    let last_file_chunk = if pt_len == 0 {
        0
    } else {
        total_chunks(pt_len) - 1
    };
    let initial_cap = ct_len.min(CIPHERTEXT_CHUNK_LEN as u64) as usize;

    struct FullDecState {
        stream: ByteStream,
        data_key: [u8; 32],
        cipher: Option<StreamCipher>,
        pending: Bytes,
        block: BytesMut,
        chunk_idx: u64,
        eof: bool,
        done: bool,
    }

    let state = FullDecState {
        stream: ct_stream,
        data_key,
        cipher: None,
        pending: Bytes::new(),
        block: BytesMut::with_capacity(initial_cap.max(HEADER_LEN)),
        chunk_idx: 0,
        eof: false,
        done: false,
    };

    let dec_stream = futures::stream::try_unfold(state, move |mut st| async move {
        if st.done {
            return Ok(None);
        }

        // Helper closure-style loop to fill `st.block` up to `need` bytes.
        async fn fill_exact(st: &mut FullDecState, need: usize) -> Result<bool> {
            if st.block.len() < need {
                st.block.reserve(need - st.block.len());
            }
            while st.block.len() < need {
                if !st.pending.is_empty() {
                    let take = (need - st.block.len()).min(st.pending.len());
                    st.block.extend_from_slice(&st.pending[..take]);
                    st.pending.advance(take);
                    if st.pending.is_empty() {
                        // `Bytes::advance` to len 0 keeps the `PooledSlice` owner alive;
                        // reset to empty immediately so the `BufferPool` permit is
                        // returned before awaiting the next slab or yielding downstream.
                        st.pending = Bytes::new();
                    }
                    continue;
                }
                if st.eof {
                    break;
                }
                st.pending = Bytes::new();
                match st.stream.next().await {
                    Some(Ok(b)) if !b.is_empty() => st.pending = b,
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(e),
                    None => st.eof = true,
                }
            }
            Ok(st.block.len() >= need)
        }

        if st.cipher.is_none() {
            if !fill_exact(&mut st, HEADER_LEN).await? {
                return Err(Error::protocol(format!(
                    "truncated encrypted header: got {} of {HEADER_LEN} bytes",
                    st.block.len()
                )));
            }
            let hdr_bytes = st.block.split_to(HEADER_LEN);
            let header = StreamHeader::decode(&hdr_bytes)?;
            let cipher = StreamCipher::new(&st.data_key, &header);

            if pt_len == 0 {
                if !fill_exact(&mut st, TAG_LEN).await? {
                    return Err(Error::protocol(format!(
                        "truncated 0-byte encrypted tag: got {} of {TAG_LEN} bytes",
                        st.block.len()
                    )));
                }
                let tag_bytes = st.block.split_to(TAG_LEN);
                let pt = decrypt_chunk(&st.data_key, &header, 0, true, &tag_bytes)?;
                if !pt.is_empty() {
                    return Err(Error::protocol(
                        "expected empty plaintext for 0-byte encrypted file",
                    ));
                }
                return Ok(None);
            }
            st.cipher = Some(cipher);
        }

        if st.chunk_idx > last_file_chunk {
            return Ok(None);
        }

        let is_last_file_chunk = st.chunk_idx == last_file_chunk;
        let expected_ct_len = if is_last_file_chunk {
            let rem = pt_len % pt_chunk;
            let pt_block_len = if rem == 0 { pt_chunk } else { rem };
            (pt_block_len + TAG_LEN as u64) as usize
        } else {
            CIPHERTEXT_CHUNK_LEN
        };

        if !fill_exact(&mut st, expected_ct_len).await? {
            return Err(Error::protocol(format!(
                "truncated encrypted stream at chunk {}: got {} of {expected_ct_len} ciphertext bytes",
                st.chunk_idx,
                st.block.len()
            )));
        }
        let mut chunk_buf = st.block.split_to(expected_ct_len);
        let cipher = st.cipher.as_ref().expect("cipher initialized above");
        decrypt_chunk_in_place(cipher, st.chunk_idx, is_last_file_chunk, &mut chunk_buf)?;
        st.chunk_idx += 1;
        if st.chunk_idx > last_file_chunk {
            st.done = true;
            st.pending = Bytes::new();
        }
        Ok(Some((chunk_buf.freeze(), st)))
    });

    Ok(Box::pin(dec_stream))
}
