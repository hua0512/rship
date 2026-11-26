//! STREAM OAE2 seekable 64 KiB AEAD block format & hardware-accelerated in-place stream cipher.
//!
//! Per RFC draft-irtf-cfrg-xchacha §2.3, `XChaCha20-Poly1305(data_key, nonce_prefix || tail8)`
//! is bit-for-bit identical to deriving a single 32-byte subkey via `HChaCha20(data_key, nonce_prefix)`
//! once per file and running hardware-accelerated (AVX2 / AVX-512 / NEON via `aws-lc-rs`)
//! IETF `ChaCha20-Poly1305(subkey, [0,0,0,0] || tail8)` for every 64 KiB block.

#[cfg(test)]
mod tests;

use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use bytes::{Buf, Bytes, BytesMut};
use futures::Stream;
use rand::Rng;
use rship_core::source::ByteStream;
use rship_core::{Error, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use zeroize::Zeroize;

pub const HEADER_MAGIC: [u8; 8] = *b"RSHIPCR1";
pub const FORMAT_VERSION: u8 = 1;
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;
pub const HEADER_LEN: usize = 32;
pub const PLAINTEXT_CHUNK_LEN: usize = 64 * 1024;
pub const TAG_LEN: usize = 16;
pub const CIPHERTEXT_CHUNK_LEN: usize = PLAINTEXT_CHUNK_LEN + TAG_LEN;

const HEADER_AAD_PREFIX: [u8; 12] = [
    b'R',
    b'S',
    b'H',
    b'I',
    b'P',
    b'C',
    b'R',
    b'1',
    FORMAT_VERSION,
    CIPHER_XCHACHA20_POLY1305,
    0,
    0,
];

/// 32-byte authenticated file header preceding encrypted 64 KiB AEAD chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    pub nonce_prefix: [u8; 16],
}

impl StreamHeader {
    pub fn generate_random() -> Self {
        let mut nonce_prefix = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_prefix);
        Self { nonce_prefix }
    }

    pub fn from_nonce_prefix(nonce_prefix: [u8; 16]) -> Self {
        Self { nonce_prefix }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..12].copy_from_slice(&HEADER_AAD_PREFIX);
        out[12..28].copy_from_slice(&self.nonce_prefix);
        out[28..32].copy_from_slice(&(PLAINTEXT_CHUNK_LEN as u32).to_le_bytes());
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            return Err(Error::protocol(format!(
                "encrypted header truncated ({} < {HEADER_LEN} bytes)",
                raw.len()
            )));
        }
        if raw[0..8] != HEADER_MAGIC {
            return Err(Error::protocol(
                "invalid encrypted file header magic (expected RSHIPCR1)",
            ));
        }
        if raw[8] != FORMAT_VERSION || raw[9] != CIPHER_XCHACHA20_POLY1305 {
            return Err(Error::protocol(format!(
                "unsupported encrypted file version={} cipher={}",
                raw[8], raw[9]
            )));
        }
        if raw[10] != 0 || raw[11] != 0 {
            return Err(Error::protocol(format!(
                "invalid encrypted file header reserved flags ({:#04x}, {:#04x})",
                raw[10], raw[11]
            )));
        }
        let chunk_sz = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]) as usize;
        if chunk_sz != PLAINTEXT_CHUNK_LEN {
            return Err(Error::protocol(format!(
                "unsupported encrypted chunk size {chunk_sz} (expected {PLAINTEXT_CHUNK_LEN})"
            )));
        }
        let mut nonce_prefix = [0u8; 16];
        nonce_prefix.copy_from_slice(&raw[12..28]);
        Ok(Self { nonce_prefix })
    }
}

/// Compute exact ciphertext byte length for a plaintext file of `pt_len` bytes.
///
/// A 0-byte plaintext file encrypts to `HEADER_LEN + TAG_LEN` (48 bytes): the
/// 32-byte header plus 1 authenticated empty final block (`is_last = true`).
pub fn ciphertext_size(pt_len: u64) -> Result<u64> {
    let hdr = HEADER_LEN as u64;
    let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
    let ct_chunk = CIPHERTEXT_CHUNK_LEN as u64;
    let tag = TAG_LEN as u64;

    if pt_len == 0 {
        return Ok(hdr + tag);
    }
    let full = pt_len / pt_chunk;
    let rem = pt_len % pt_chunk;
    let full_ct = full
        .checked_mul(ct_chunk)
        .ok_or_else(|| Error::invalid_geometry("ciphertext size overflow"))?;
    let tail_ct = if rem == 0 { 0 } else { rem + tag };
    hdr.checked_add(full_ct)
        .and_then(|v| v.checked_add(tail_ct))
        .ok_or_else(|| Error::invalid_geometry("ciphertext size overflow"))
}

/// Compute the maximum plaintext byte length whose encrypted STREAM OAE2 size
/// (`ciphertext_size(pt)`) does not exceed `max_ct_len`.
///
/// Returns `0` when `max_ct_len < HEADER_LEN + TAG_LEN` (48 bytes), since even a
/// 0-byte file encrypts to 48 bytes.
pub fn max_plaintext_for_ciphertext(max_ct_len: u64) -> u64 {
    let min_ct = (HEADER_LEN + TAG_LEN) as u64;
    if max_ct_len < min_ct {
        return 0;
    }
    let body = max_ct_len - (HEADER_LEN as u64);
    let ct_chunk = CIPHERTEXT_CHUNK_LEN as u64;
    let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
    let full = body / ct_chunk;
    let rem = body % ct_chunk;
    full * pt_chunk + rem.saturating_sub(TAG_LEN as u64)
}

/// Exact inverse of [`ciphertext_size`], rejecting truncated or tag-corrupted lengths.
pub fn plaintext_size(ct_len: u64) -> Result<u64> {
    let hdr = HEADER_LEN as u64;
    let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
    let ct_chunk = CIPHERTEXT_CHUNK_LEN as u64;
    let tag = TAG_LEN as u64;

    if ct_len < hdr + tag {
        return Err(Error::protocol(format!(
            "ciphertext length ({ct_len}) smaller than minimum authenticated size ({})",
            hdr + tag
        )));
    }
    let body = ct_len - hdr;
    if body == tag {
        return Ok(0);
    }
    let full = body / ct_chunk;
    let rem = body % ct_chunk;
    if rem == 0 {
        full.checked_mul(pt_chunk)
            .ok_or_else(|| Error::invalid_geometry("plaintext size overflow"))
    } else if rem <= tag {
        Err(Error::protocol(format!(
            "corrupted ciphertext length ({ct_len}): invalid trailing block size {rem}"
        )))
    } else {
        full.checked_mul(pt_chunk)
            .and_then(|v| v.checked_add(rem - tag))
            .ok_or_else(|| Error::invalid_geometry("plaintext size overflow"))
    }
}

/// Number of AEAD blocks for a plaintext file of `pt_len` bytes (always >= 1).
pub fn total_chunks(pt_len: u64) -> u64 {
    if pt_len == 0 {
        1
    } else {
        pt_len.div_ceil(PLAINTEXT_CHUNK_LEN as u64)
    }
}

#[inline]
fn chacha_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// RFC draft-irtf-cfrg-xchacha §2.2: derive the 32-byte IETF ChaCha20-Poly1305 subkey
/// from `(data_key, header.nonce_prefix)`. Computed once per file/stream.
pub(crate) fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        u32::from_le_bytes(nonce16[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce16[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce16[8..12].try_into().unwrap()),
        u32::from_le_bytes(nonce16[12..16].try_into().unwrap()),
    ];
    for _ in 0..10 {
        chacha_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut subkey = [0u8; 32];
    for (i, &word) in state[0..4].iter().chain(state[12..16].iter()).enumerate() {
        subkey[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
    }
    state.zeroize();
    subkey
}

/// Hardware-accelerated per-file STREAM OAE2 cipher bound to one `(data_key, StreamHeader)`.
///
/// Precomputes the `HChaCha20` subkey once and executes every 64 KiB block through
/// `aws-lc-rs` SIMD/assembly `ChaCha20-Poly1305`.
pub struct StreamCipher {
    key: LessSafeKey,
}

impl StreamCipher {
    pub fn new(data_key: &[u8; 32], header: &StreamHeader) -> Self {
        let mut subkey = hchacha20(data_key, &header.nonce_prefix);
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &subkey)
            .expect("32-byte HChaCha20 subkey always matches CHACHA20_POLY1305");
        subkey.zeroize();
        Self {
            key: LessSafeKey::new(unbound),
        }
    }
}

fn build_ietf_nonce_and_aad(chunk_idx: u64, is_last: bool) -> Result<(Nonce, [u8; 21])> {
    // 56-bit chunk counter (up to ~4.7 ZiB per file) leaves byte 23 exclusively for `last_flag`.
    if chunk_idx >= (1u64 << 56) {
        return Err(Error::invalid_geometry(
            "STREAM chunk_idx exceeds 56-bit limit",
        ));
    }
    let idx_le = chunk_idx.to_le_bytes();
    let mut nonce = [0u8; 12];
    // Bytes 0..4 are zero per RFC draft-irtf-cfrg-xchacha §2.3.
    nonce[4..11].copy_from_slice(&idx_le[0..7]);
    nonce[11] = if is_last { 0x01 } else { 0x00 };

    let mut aad = [0u8; 21];
    aad[0..12].copy_from_slice(&HEADER_AAD_PREFIX);
    aad[12..20].copy_from_slice(&idx_le);
    aad[20] = if is_last { 0x01 } else { 0x00 };
    Ok((Nonce::assume_unique_for_key(nonce), aad))
}

/// Encrypt one plaintext chunk (`<= 64 KiB`) strictly in place inside `buf`,
/// appending the 16-byte Poly1305 authentication tag without reallocating when
/// `buf` already has `TAG_LEN` spare bytes reserved.
pub fn encrypt_chunk_in_place(
    cipher: &StreamCipher,
    chunk_idx: u64,
    is_last: bool,
    buf: &mut BytesMut,
) -> Result<()> {
    if buf.len() > PLAINTEXT_CHUNK_LEN {
        return Err(Error::invalid_geometry(format!(
            "plaintext block ({}) exceeds 64 KiB limit",
            buf.len()
        )));
    }
    let (nonce, aad) = build_ietf_nonce_and_aad(chunk_idx, is_last)?;
    let tag = cipher
        .key
        .seal_in_place_separate_tag(nonce, Aad::from(&aad), buf.as_mut())
        .map_err(|_| Error::protocol("AEAD encryption failed"))?;
    buf.extend_from_slice(tag.as_ref());
    Ok(())
}

/// Decrypt and authenticate one ciphertext chunk (`<= 64 KiB + 16`) strictly in
/// place inside `buf`, truncating the trailing 16-byte tag upon success.
///
/// On authentication failure, `buf` is scrubbed with `zeroize` and cleared so
/// unauthenticated plaintext is never exposed to callers.
pub fn decrypt_chunk_in_place(
    cipher: &StreamCipher,
    chunk_idx: u64,
    is_last: bool,
    buf: &mut BytesMut,
) -> Result<()> {
    if buf.len() < TAG_LEN || buf.len() > CIPHERTEXT_CHUNK_LEN {
        return Err(Error::protocol(format!(
            "invalid ciphertext block length {}",
            buf.len()
        )));
    }
    let (nonce, aad) = build_ietf_nonce_and_aad(chunk_idx, is_last)?;
    let pt_len = buf.len() - TAG_LEN;

    if cipher
        .key
        .open_in_place(nonce, Aad::from(&aad), buf.as_mut())
        .is_err()
    {
        buf.as_mut().zeroize();
        buf.clear();
        return Err(Error::protocol(format!(
            "AEAD authentication failed at chunk {chunk_idx} (is_last={is_last}): data tampered, truncated, or wrong key"
        )));
    }
    buf.truncate(pt_len);
    Ok(())
}

/// Encrypt one plaintext chunk (`<= 64 KiB`) with STREAM OAE2 nonce & AAD binding.
pub fn encrypt_chunk(
    data_key: &[u8; 32],
    header: &StreamHeader,
    chunk_idx: u64,
    is_last: bool,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > PLAINTEXT_CHUNK_LEN {
        return Err(Error::invalid_geometry(format!(
            "plaintext block ({}) exceeds 64 KiB limit",
            plaintext.len()
        )));
    }
    let (nonce, aad) = build_ietf_nonce_and_aad(chunk_idx, is_last)?;
    let cipher = StreamCipher::new(data_key, header);
    let mut out = Vec::with_capacity(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = cipher
        .key
        .seal_in_place_separate_tag(nonce, Aad::from(&aad), out.as_mut_slice())
        .map_err(|_| Error::protocol("AEAD encryption failed"))?;
    out.extend_from_slice(tag.as_ref());
    Ok(out)
}

/// Decrypt and authenticate one ciphertext chunk (`<= 64 KiB + 16`), verifying
/// `(nonce_prefix, chunk_idx, is_last)` and header AAD.
pub fn decrypt_chunk(
    data_key: &[u8; 32],
    header: &StreamHeader,
    chunk_idx: u64,
    is_last: bool,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN || ciphertext.len() > CIPHERTEXT_CHUNK_LEN {
        return Err(Error::protocol(format!(
            "invalid ciphertext block length {}",
            ciphertext.len()
        )));
    }
    let (nonce, aad) = build_ietf_nonce_and_aad(chunk_idx, is_last)?;
    let cipher = StreamCipher::new(data_key, header);
    let pt_len = ciphertext.len() - TAG_LEN;
    let mut out = ciphertext.to_vec();
    if cipher
        .key
        .open_in_place(nonce, Aad::from(&aad), out.as_mut_slice())
        .is_err()
    {
        out.zeroize();
        return Err(Error::protocol(format!(
            "AEAD authentication failed at chunk {chunk_idx} (is_last={is_last}): data tampered, truncated, or wrong key"
        )));
    }
    out.truncate(pt_len);
    Ok(out)
}

/// Zero-big-buffer, in-place streaming STREAM OAE2 encryptor converting a
/// plaintext `ByteStream` of exact declared length `expected_pt_len` into
/// ciphertext blocks.
///
/// Key properties:
/// - Derives the `HChaCha20` subkey once per stream and executes every block via
///   `aws-lc-rs` SIMD/assembly `ChaCha20-Poly1305`.
/// - Holds incoming `Bytes` slices by reference (`pending`) and fills a single
///   `CIPHERTEXT_CHUNK_LEN` (`64 KiB + 16`) `BytesMut` block buffer.
/// - Encrypts each block strictly in place via [`encrypt_chunk_in_place`], freezes
///   zero-copy into `Bytes`, and reclaims the backing allocation automatically
///   once the downstream sink drops the previous `Bytes` chunk.
/// - Scrubs any staged plaintext bytes in `block` on `Drop`.
pub struct StreamEncryptor {
    inner: ByteStream,
    cipher: StreamCipher,
    header: StreamHeader,
    emit_header: bool,
    next_chunk_idx: u64,
    expected_pt_len: u64,
    seen_pt_len: u64,
    emitted_pt_len: u64,
    is_final_segment: bool,
    max_blocks: usize,
    pending: Bytes,
    block: BytesMut,
    out_frame: BytesMut,
    pending_empty_final: bool,
    done: bool,
}

impl StreamEncryptor {
    pub fn new(
        inner: ByteStream,
        data_key: &[u8; 32],
        header: StreamHeader,
        start_chunk_idx: u64,
        expected_pt_len: u64,
        emit_header: bool,
        is_final_segment: bool,
    ) -> Self {
        Self::with_coalesced_blocks(
            inner,
            data_key,
            header,
            start_chunk_idx,
            expected_pt_len,
            emit_header,
            is_final_segment,
            1,
        )
    }

    /// Create an in-place STREAM OAE2 encryptor that coalesces up to `max_blocks`
    /// (`max_blocks * 64 KiB` plaintext + tags, plus the 32-byte header on block 0)
    /// into a single contiguous `Bytes` frame per poll so HTTP/TLS writers avoid
    /// 64 KiB syscall/record fragmentation on multi-GiB uploads.
    #[allow(clippy::too_many_arguments)]
    pub fn with_coalesced_blocks(
        inner: ByteStream,
        data_key: &[u8; 32],
        header: StreamHeader,
        start_chunk_idx: u64,
        expected_pt_len: u64,
        emit_header: bool,
        is_final_segment: bool,
        max_blocks: usize,
    ) -> Self {
        let max_blocks = max_blocks.max(1);
        let initial_cap = if expected_pt_len == 0 {
            TAG_LEN
        } else {
            (expected_pt_len as usize).min(PLAINTEXT_CHUNK_LEN) + TAG_LEN
        };
        Self {
            inner,
            cipher: StreamCipher::new(data_key, &header),
            header,
            emit_header,
            next_chunk_idx: start_chunk_idx,
            expected_pt_len,
            seen_pt_len: 0,
            emitted_pt_len: 0,
            is_final_segment,
            max_blocks,
            pending: Bytes::new(),
            block: BytesMut::with_capacity(initial_cap),
            out_frame: BytesMut::new(),
            pending_empty_final: expected_pt_len == 0 && is_final_segment,
            done: false,
        }
    }

    fn seal_block(&mut self, is_last: bool) -> Result<Bytes> {
        let pt_len = self.block.len() as u64;
        let idx = self.next_chunk_idx;
        self.next_chunk_idx += 1;
        self.emitted_pt_len = self.emitted_pt_len.saturating_add(pt_len);
        encrypt_chunk_in_place(&self.cipher, idx, is_last, &mut self.block)?;
        Ok(self.block.split().freeze())
    }

    fn append_and_seal_pending_block(&mut self, is_last: bool) -> Result<()> {
        let idx = self.next_chunk_idx;
        self.next_chunk_idx += 1;
        self.emitted_pt_len = self
            .emitted_pt_len
            .saturating_add(PLAINTEXT_CHUNK_LEN as u64);
        let (nonce, aad) = build_ietf_nonce_and_aad(idx, is_last)?;
        let start = self.out_frame.len();
        self.out_frame
            .extend_from_slice(&self.pending[..PLAINTEXT_CHUNK_LEN]);
        self.pending.advance(PLAINTEXT_CHUNK_LEN);
        if self.pending.is_empty() {
            // Drop empty `Bytes` immediately so any `PooledSlice` owner releases
            // its `BufferPool` permit before polling the next input slab.
            self.pending = Bytes::new();
        }
        let tag = self
            .cipher
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut self.out_frame[start..])
            .map_err(|_| Error::protocol("AEAD encryption failed"))?;
        self.out_frame.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn append_and_seal_empty_final(&mut self) -> Result<()> {
        let idx = self.next_chunk_idx;
        self.next_chunk_idx += 1;
        let (nonce, aad) = build_ietf_nonce_and_aad(idx, true)?;
        let start = self.out_frame.len();
        let tag = self
            .cipher
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut self.out_frame[start..])
            .map_err(|_| Error::protocol("AEAD encryption failed"))?;
        self.out_frame.extend_from_slice(tag.as_ref());
        Ok(())
    }

    fn flush_partial_block_into_out(&mut self, is_last: bool) -> Result<()> {
        let idx = self.next_chunk_idx;
        self.next_chunk_idx += 1;
        self.emitted_pt_len = self.emitted_pt_len.saturating_add(self.block.len() as u64);
        let (nonce, aad) = build_ietf_nonce_and_aad(idx, is_last)?;
        let start = self.out_frame.len();
        self.out_frame.extend_from_slice(&self.block);
        self.block.as_mut().zeroize();
        self.block.clear();
        let tag = self
            .cipher
            .key
            .seal_in_place_separate_tag(nonce, Aad::from(&aad), &mut self.out_frame[start..])
            .map_err(|_| Error::protocol("AEAD encryption failed"))?;
        self.out_frame.extend_from_slice(tag.as_ref());
        Ok(())
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        self.block.as_mut().zeroize();
        self.out_frame.as_mut().zeroize();
    }
}

impl Stream for StreamEncryptor {
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.done {
            return Poll::Ready(None);
        }

        if this.max_blocks == 1 {
            if this.emit_header {
                this.emit_header = false;
                return Poll::Ready(Some(Ok(Bytes::copy_from_slice(&this.header.encode()))));
            }

            loop {
                if !this.pending.is_empty() {
                    if this.block.is_empty() {
                        let remaining_pt = this.expected_pt_len.saturating_sub(this.emitted_pt_len);
                        let target_pt = (remaining_pt as usize).min(PLAINTEXT_CHUNK_LEN);
                        this.block.reserve(target_pt + TAG_LEN);
                    }
                    let need = PLAINTEXT_CHUNK_LEN - this.block.len();
                    let take = need.min(this.pending.len());
                    this.block.extend_from_slice(&this.pending[..take]);
                    this.pending.advance(take);
                    if this.pending.is_empty() {
                        this.pending = Bytes::new();
                    }

                    if this.block.len() == PLAINTEXT_CHUNK_LEN {
                        let is_last = this.is_final_segment
                            && this.emitted_pt_len + (PLAINTEXT_CHUNK_LEN as u64)
                                == this.expected_pt_len;
                        return match this.seal_block(is_last) {
                            Ok(ct) => Poll::Ready(Some(Ok(ct))),
                            Err(e) => {
                                this.pending = Bytes::new();
                                this.done = true;
                                Poll::Ready(Some(Err(e)))
                            }
                        };
                    }
                    continue;
                }

                // Ensure no empty `Bytes` holding a `PooledSlice` permit stays alive
                // while polling `this.inner` for the next slab.
                this.pending = Bytes::new();
                match Pin::new(&mut this.inner).poll_next(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        this.seen_pt_len = this.seen_pt_len.saturating_add(chunk.len() as u64);
                        if this.seen_pt_len > this.expected_pt_len {
                            this.done = true;
                            return Poll::Ready(Some(Err(Error::source_mutated(format!(
                                "plaintext stream exceeded declared size ({} > {})",
                                this.seen_pt_len, this.expected_pt_len
                            )))));
                        }
                        this.pending = chunk;
                    }
                    Poll::Ready(Some(Err(e))) => {
                        this.done = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Ready(None) => {
                        if this.seen_pt_len != this.expected_pt_len {
                            this.done = true;
                            return Poll::Ready(Some(Err(Error::source_mutated(format!(
                                "short EOF during encrypted upload: received {} of {} plaintext bytes",
                                this.seen_pt_len, this.expected_pt_len
                            )))));
                        }
                        if !this.block.is_empty() {
                            this.done = true;
                            return match this.seal_block(this.is_final_segment) {
                                Ok(ct) => Poll::Ready(Some(Ok(ct))),
                                Err(e) => Poll::Ready(Some(Err(e))),
                            };
                        }
                        if this.pending_empty_final {
                            this.pending_empty_final = false;
                            this.done = true;
                            this.block.reserve(TAG_LEN);
                            return match this.seal_block(true) {
                                Ok(ct) => Poll::Ready(Some(Ok(ct))),
                                Err(e) => Poll::Ready(Some(Err(e))),
                            };
                        }
                        this.done = true;
                        return Poll::Ready(None);
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
        }

        // Coalesced multi-block fast path (`max_blocks > 1`):
        let mut blocks_in_frame = 0usize;
        if this.emit_header {
            let rem_blocks = this
                .expected_pt_len
                .saturating_sub(this.emitted_pt_len)
                .div_ceil(PLAINTEXT_CHUNK_LEN as u64)
                .max(1) as usize;
            let cap = HEADER_LEN + rem_blocks.min(this.max_blocks) * CIPHERTEXT_CHUNK_LEN;
            this.out_frame.reserve(cap);
            this.out_frame.extend_from_slice(&this.header.encode());
            this.emit_header = false;
        }

        loop {
            while !this.pending.is_empty() && blocks_in_frame < this.max_blocks {
                if this.block.is_empty() && this.pending.len() >= PLAINTEXT_CHUNK_LEN {
                    // Zero-staging-copy fast path: copy 64 KiB directly from `pending` into `out_frame` and seal in place!
                    if this.out_frame.is_empty() {
                        let rem_blocks = this
                            .expected_pt_len
                            .saturating_sub(this.emitted_pt_len)
                            .div_ceil(PLAINTEXT_CHUNK_LEN as u64)
                            as usize;
                        this.out_frame
                            .reserve(rem_blocks.min(this.max_blocks) * CIPHERTEXT_CHUNK_LEN);
                    } else {
                        this.out_frame.reserve(CIPHERTEXT_CHUNK_LEN);
                    }
                    let is_last = this.is_final_segment
                        && this.emitted_pt_len + (PLAINTEXT_CHUNK_LEN as u64)
                            == this.expected_pt_len;
                    if let Err(e) = this.append_and_seal_pending_block(is_last) {
                        this.pending = Bytes::new();
                        this.done = true;
                        return Poll::Ready(Some(Err(e)));
                    }
                    blocks_in_frame += 1;
                } else {
                    if this.block.is_empty() {
                        let remaining_pt = this.expected_pt_len.saturating_sub(this.emitted_pt_len);
                        let target_pt = (remaining_pt as usize).min(PLAINTEXT_CHUNK_LEN);
                        this.block.reserve(target_pt);
                    }
                    let need = PLAINTEXT_CHUNK_LEN - this.block.len();
                    let take = need.min(this.pending.len());
                    this.block.extend_from_slice(&this.pending[..take]);
                    this.pending.advance(take);
                    if this.pending.is_empty() {
                        this.pending = Bytes::new();
                    }

                    if this.block.len() == PLAINTEXT_CHUNK_LEN {
                        this.out_frame.reserve(CIPHERTEXT_CHUNK_LEN);
                        let is_last = this.is_final_segment
                            && this.emitted_pt_len + (PLAINTEXT_CHUNK_LEN as u64)
                                == this.expected_pt_len;
                        if let Err(e) = this.flush_partial_block_into_out(is_last) {
                            this.pending = Bytes::new();
                            this.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }
                        blocks_in_frame += 1;
                    }
                }
            }

            if blocks_in_frame >= this.max_blocks {
                return Poll::Ready(Some(Ok(this.out_frame.split().freeze())));
            }

            // Ensure no empty `Bytes` holding a `PooledSlice` permit stays alive
            // while polling `this.inner` for the next slab.
            this.pending = Bytes::new();
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        continue;
                    }
                    this.seen_pt_len = this.seen_pt_len.saturating_add(chunk.len() as u64);
                    if this.seen_pt_len > this.expected_pt_len {
                        this.done = true;
                        return Poll::Ready(Some(Err(Error::source_mutated(format!(
                            "plaintext stream exceeded declared size ({} > {})",
                            this.seen_pt_len, this.expected_pt_len
                        )))));
                    }
                    this.pending = chunk;
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    if this.seen_pt_len != this.expected_pt_len {
                        this.done = true;
                        return Poll::Ready(Some(Err(Error::source_mutated(format!(
                            "short EOF during encrypted upload: received {} of {} plaintext bytes",
                            this.seen_pt_len, this.expected_pt_len
                        )))));
                    }
                    if !this.block.is_empty() {
                        this.out_frame.reserve(this.block.len() + TAG_LEN);
                        if let Err(e) = this.flush_partial_block_into_out(this.is_final_segment) {
                            this.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }
                    } else if this.pending_empty_final {
                        this.pending_empty_final = false;
                        this.out_frame.reserve(TAG_LEN);
                        if let Err(e) = this.append_and_seal_empty_final() {
                            this.done = true;
                            return Poll::Ready(Some(Err(e)));
                        }
                    }
                    this.done = true;
                    if !this.out_frame.is_empty() {
                        return Poll::Ready(Some(Ok(this.out_frame.split().freeze())));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    if !this.out_frame.is_empty() {
                        return Poll::Ready(Some(Ok(this.out_frame.split().freeze())));
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
