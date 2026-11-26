//! Streaming upload/download checksum wrappers and incremental hashers
//! (hardware CRC-32C, hardware CRC-64/NVME, SHA-256 with pure-Rust FIPS 180-4 fallback,
//! and MD5 with pure-Rust RFC 1321 fallback).

use bytes::Bytes;
use futures::Stream;
use rship_core::{Error, Result};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

/// Build an [`Error::integrity`] representing an in-transit or server-side
/// upload/download checksum mismatch.
///
/// Integrity errors are never retried in place or reconciled into a committed result:
/// the engine discards the attempt and restarts the transfer from scratch.
pub fn checksum_mismatch_error(
    context: &str,
    algorithm: &str,
    expected: &str,
    actual: &str,
) -> Error {
    Error::integrity(format!(
        "{context} checksum mismatch ({algorithm}): expected {expected}, got {actual}"
    ))
}

/// Incremental, zero-buffer streaming digest accumulator used by [`StreamingHashStream`]
/// and [`VerifyingDownloadStream`].
pub trait StreamingDigest: Send + Unpin {
    type Output: Send + 'static;

    fn update(&mut self, chunk: &[u8]);
    fn finalize(self) -> Self::Output;
}

/// Zero-copy, zero-spool upload stream wrapper that feeds every `Ok(chunk)` yielded by
/// `inner` into a [`StreamingDigest`] and stores the finalized digest into `digest_slot`
/// as soon as `expected_len` bytes are observed (or at exact EOF).
///
/// Finalizing on `seen_len == expected_len` ensures HTTP/1.1 sized `Content-Length`
/// encoders (which stop polling once `expected_len` bytes are transmitted without polling
/// for a trailing `None`) still publish the finalized digest before the response arrives.
pub struct StreamingHashStream<S, H: StreamingDigest> {
    inner: S,
    hasher: Option<H>,
    expected_len: u64,
    seen_len: u64,
    digest_slot: Arc<StdMutex<Option<H::Output>>>,
}

impl<S, H: StreamingDigest> StreamingHashStream<S, H> {
    pub fn new(
        inner: S,
        hasher: H,
        expected_len: u64,
        digest_slot: Arc<StdMutex<Option<H::Output>>>,
    ) -> Self {
        let hasher = if expected_len == 0 {
            let digest = hasher.finalize();
            *super::lock_unpoisoned(&digest_slot) = Some(digest);
            None
        } else {
            Some(hasher)
        };
        Self {
            inner,
            hasher,
            expected_len,
            seen_len: 0,
            digest_slot,
        }
    }
}

impl<S, H> Stream for StreamingHashStream<S, H>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
    H: StreamingDigest,
{
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.seen_len = this.seen_len.saturating_add(chunk.len() as u64);
                if let Some(ref mut hasher) = this.hasher {
                    hasher.update(&chunk);
                    if this.seen_len >= this.expected_len {
                        let h = this.hasher.take().expect("hasher present");
                        if this.seen_len == this.expected_len {
                            *super::lock_unpoisoned(&this.digest_slot) = Some(h.finalize());
                        }
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.hasher = None;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                if let Some(h) = this.hasher.take()
                    && this.seen_len == this.expected_len
                {
                    *super::lock_unpoisoned(&this.digest_slot) = Some(h.finalize());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Zero-copy download verification stream wrapper that computes a running digest as
/// downloaded bytes stream to the caller and verifies it against `expected_hex` upon
/// reaching exact `expected_len` bytes (or EOF), returning a retryable
/// [`Error::network`] if bytes were corrupted in transit.
///
/// Callers MUST ONLY wrap full-object reads (`offset == 0 && len == total_len`) with a
/// full-object checksum, never sub-range slices.
pub struct VerifyingDownloadStream<S, H> {
    label: &'static str,
    algorithm: &'static str,
    inner: S,
    hasher: Option<H>,
    expected_len: u64,
    seen_len: u64,
    expected_hex: String,
    done: bool,
}

impl<S, H> VerifyingDownloadStream<S, H>
where
    H: StreamingDigest<Output = String>,
{
    pub fn new(
        label: &'static str,
        algorithm: &'static str,
        inner: S,
        hasher: H,
        expected_len: u64,
        expected_hex: impl Into<String>,
    ) -> Self {
        Self {
            label,
            algorithm,
            inner,
            hasher: Some(hasher),
            expected_len,
            seen_len: 0,
            expected_hex: expected_hex.into().to_ascii_lowercase(),
            done: false,
        }
    }
}

impl<S, H> Stream for VerifyingDownloadStream<S, H>
where
    S: Stream<Item = Result<Bytes>> + Unpin,
    H: StreamingDigest<Output = String>,
{
    type Item = Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.seen_len = this.seen_len.saturating_add(chunk.len() as u64);
                if let Some(ref mut hasher) = this.hasher {
                    hasher.update(&chunk);
                    if this.seen_len == this.expected_len {
                        let actual = this.hasher.take().expect("hasher present").finalize();
                        if !actual.eq_ignore_ascii_case(&this.expected_hex) {
                            this.done = true;
                            return Poll::Ready(Some(Err(checksum_mismatch_error(
                                &format!("{} download", this.label),
                                this.algorithm,
                                &this.expected_hex,
                                &actual,
                            ))));
                        }
                    }
                }
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                this.hasher = None;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.done = true;
                if let Some(h) = this.hasher.take()
                    && this.seen_len == this.expected_len
                {
                    let actual = h.finalize();
                    if !actual.eq_ignore_ascii_case(&this.expected_hex) {
                        return Poll::Ready(Some(Err(checksum_mismatch_error(
                            &format!("{} download", this.label),
                            this.algorithm,
                            &this.expected_hex,
                            &actual,
                        ))));
                    }
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Incremental hardware-accelerated CRC-32C (Castagnoli) streaming hasher.
#[cfg(any(feature = "s3", feature = "gcs"))]
pub struct Crc32cHasher {
    state: u32,
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl Default for Crc32cHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl Crc32cHasher {
    pub fn new() -> Self {
        Self { state: u32::MAX }
    }

    pub fn update_bytes(&mut self, data: &[u8]) {
        self.state = super::crc32c_update(self.state, data);
    }

    pub fn finalize_u32(self) -> u32 {
        !self.state
    }

    pub fn finalize_hex(self) -> String {
        format!("{:08x}", self.finalize_u32())
    }
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl StreamingDigest for Crc32cHasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

/// Incremental hardware-accelerated CRC-64/NVME streaming hasher.
#[cfg(any(feature = "s3", feature = "gcs"))]
pub struct Crc64NvmeHasher {
    state: u64,
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl Default for Crc64NvmeHasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl Crc64NvmeHasher {
    pub fn new() -> Self {
        Self { state: u64::MAX }
    }

    pub fn update_bytes(&mut self, data: &[u8]) {
        self.state = super::crc64_nvme_update(self.state, data);
    }

    pub fn finalize_u64(self) -> u64 {
        !self.state
    }

    pub fn finalize_hex(self) -> String {
        format!("{:016x}", self.finalize_u64())
    }
}

#[cfg(any(feature = "s3", feature = "gcs"))]
impl StreamingDigest for Crc64NvmeHasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "onedrive",
    feature = "gcs",
    feature = "azureblob"
))]
fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Pure-Rust FIPS 180-4 streaming SHA-256 implementation used when optional `sha2` crate
/// is not enabled by the active feature set (e.g. isolated `--features onedrive`).
#[cfg(any(
    test,
    all(
        feature = "onedrive",
        not(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        ))
    )
))]
#[derive(Clone)]
struct Fips180Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

#[cfg(any(
    test,
    all(
        feature = "onedrive",
        not(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        ))
    )
))]
impl Fips180Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a_2f98,
            0x7137_4491,
            0xb5c0_fbcf,
            0xe9b5_dba5,
            0x3956_c25b,
            0x59f1_11f1,
            0x923f_82a4,
            0xab1c_5ed5,
            0xd807_aa98,
            0x1283_5b01,
            0x2431_85be,
            0x550c_7dc3,
            0x72be_5d74,
            0x80de_b1fe,
            0x9bdc_06a7,
            0xc19b_f174,
            0xe49b_69c1,
            0xefbe_4786,
            0x0fc1_9dc6,
            0x240c_a1cc,
            0x2de9_2c6f,
            0x4a74_84aa,
            0x5cb0_a9dc,
            0x76f9_88da,
            0x983e_5152,
            0xa831_c66d,
            0xb003_27c8,
            0xbf59_7fc7,
            0xc6e0_0bf3,
            0xd5a7_9147,
            0x06ca_6351,
            0x1429_2967,
            0x27b7_0a85,
            0x2e1b_2138,
            0x4d2c_6dfc,
            0x5338_0d13,
            0x650a_7354,
            0x766a_0abb,
            0x81c2_c92e,
            0x9272_2c85,
            0xa2bf_e8a1,
            0xa81a_664b,
            0xc24b_8b70,
            0xc76c_51a3,
            0xd192_e819,
            0xd699_0624,
            0xf40e_3585,
            0x106a_a070,
            0x19a4_c116,
            0x1e37_6c08,
            0x2748_774c,
            0x34b0_bcb5,
            0x391c_0cb3,
            0x4ed8_aa4a,
            0x5b9c_ca4f,
            0x682e_6ff3,
            0x748f_82ee,
            0x78a5_636f,
            0x84c8_7814,
            0x8cc7_0208,
            0x90be_fffa,
            0xa450_6ceb,
            0xbef9_a3f7,
            0xc671_78f2,
        ];

        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let o = i * 4;
            *word = u32::from_be_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for block in blocks {
            Self::compress(&mut self.state, block);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::compress(&mut self.state, &self.buf);

        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Incremental SHA-256 streaming hasher returning 64-char lowercase hex.
#[cfg(any(feature = "s3", feature = "onedrive"))]
pub struct Sha256Hasher {
    #[cfg(any(
        feature = "local",
        feature = "gdrive",
        feature = "s3",
        feature = "dropbox",
        feature = "gcs",
        feature = "azureblob"
    ))]
    inner: sha2::Sha256,
    #[cfg(not(any(
        feature = "local",
        feature = "gdrive",
        feature = "s3",
        feature = "dropbox",
        feature = "gcs",
        feature = "azureblob"
    )))]
    inner: Fips180Sha256,
}

#[cfg(any(feature = "s3", feature = "onedrive"))]
impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "s3", feature = "onedrive"))]
impl Sha256Hasher {
    pub fn new() -> Self {
        #[cfg(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        ))]
        {
            use sha2::Digest as _;
            Self {
                inner: sha2::Sha256::new(),
            }
        }
        #[cfg(not(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        )))]
        {
            Self {
                inner: Fips180Sha256::new(),
            }
        }
    }

    pub fn update_bytes(&mut self, data: &[u8]) {
        #[cfg(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        ))]
        {
            use sha2::Digest as _;
            self.inner.update(data);
        }
        #[cfg(not(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        )))]
        {
            self.inner.update(data);
        }
    }

    pub fn finalize_bytes(self) -> [u8; 32] {
        #[cfg(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        ))]
        {
            use sha2::Digest as _;
            self.inner.finalize().into()
        }
        #[cfg(not(any(
            feature = "local",
            feature = "gdrive",
            feature = "s3",
            feature = "dropbox",
            feature = "gcs",
            feature = "azureblob"
        )))]
        {
            self.inner.finalize()
        }
    }

    pub fn finalize_hex(self) -> String {
        encode_hex_lower(&self.finalize_bytes())
    }
}

#[cfg(any(feature = "s3", feature = "onedrive"))]
impl StreamingDigest for Sha256Hasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

/// Pure-Rust RFC 1321 streaming MD5 implementation used when optional `md-5` crate is
/// not enabled by the active feature set (e.g. isolated `--features gdrive`, `--features gcs`,
/// `--features webdav`, or `--features azureblob`).
#[cfg(any(
    test,
    all(
        any(
            feature = "gdrive",
            feature = "webdav",
            feature = "gcs",
            feature = "azureblob"
        ),
        not(any(feature = "local", feature = "s3"))
    )
))]
#[derive(Clone)]
struct Rfc1321Md5 {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total_bytes: u64,
}

#[cfg(any(
    test,
    all(
        any(
            feature = "gdrive",
            feature = "webdav",
            feature = "gcs",
            feature = "azureblob"
        ),
        not(any(feature = "local", feature = "s3"))
    )
))]
impl Rfc1321Md5 {
    fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buf: [0u8; 64],
            buf_len: 0,
            total_bytes: 0,
        }
    }

    fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        const S: [u32; 64] = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20,
            5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
        ];
        const K: [u32; 64] = [
            0xd76a_a478,
            0xe8c7_b756,
            0x2420_70db,
            0xc1bd_ceee,
            0xf57c_0faf,
            0x4787_c62a,
            0xa830_4613,
            0xfd46_9501,
            0x6980_98d8,
            0x8b44_f7af,
            0xffff_5bb1,
            0x895c_d7be,
            0x6b90_1122,
            0xfd98_7193,
            0xa679_438e,
            0x49b4_0821,
            0xf61e_2562,
            0xc040_b340,
            0x265e_5a51,
            0xe9b6_c7aa,
            0xd62f_105d,
            0x0244_1453,
            0xd8a1_e681,
            0xe7d3_fbc8,
            0x21e1_cde6,
            0xc337_07d6,
            0xf4d5_0d87,
            0x455a_14ed,
            0xa9e3_e905,
            0xfcef_a3f8,
            0x676f_02d9,
            0x8d2a_4c8a,
            0xfffa_3942,
            0x8771_f681,
            0x6d9d_6122,
            0xfde5_380c,
            0xa4be_ea44,
            0x4bde_cfa9,
            0xf6bb_4b60,
            0xbebf_bc70,
            0x289b_7ec6,
            0xeaa1_27fa,
            0xd4ef_3085,
            0x0488_1d05,
            0xd9d4_d039,
            0xe6db_99e5,
            0x1fa2_7cf8,
            0xc4ac_5665,
            0xf429_2244,
            0x432a_ff97,
            0xab94_23a7,
            0xfc93_a039,
            0x655b_59c3,
            0x8f0c_cc92,
            0xffef_f47d,
            0x8584_5dd1,
            0x6fa8_7e4f,
            0xfe2c_e6e0,
            0xa301_4314,
            0x4e08_11a1,
            0xf753_7e82,
            0xbd3a_f235,
            0x2ad7_d2bb,
            0xeb86_d391,
        ];

        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let o = i * 4;
            *word = u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
        }

        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let tmp = d;
            d = c;
            c = b;
            let sum = a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(S[i]));
            a = tmp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                Self::compress(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for block in blocks {
            Self::compress(&mut self.state, block);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len();
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total_bytes.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_le_bytes());
        Self::compress(&mut self.state, &self.buf);

        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// Incremental streaming MD5 hasher returning 32-char lowercase hex.
#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "gcs",
    feature = "azureblob"
))]
pub struct StreamingMd5 {
    #[cfg(any(feature = "local", feature = "s3"))]
    inner: md5::Md5,
    #[cfg(not(any(feature = "local", feature = "s3")))]
    inner: Rfc1321Md5,
}

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "gcs",
    feature = "azureblob"
))]
impl Default for StreamingMd5 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "gcs",
    feature = "azureblob"
))]
impl StreamingMd5 {
    pub fn new() -> Self {
        #[cfg(any(feature = "local", feature = "s3"))]
        {
            use md5::Digest as _;
            Self {
                inner: md5::Md5::new(),
            }
        }
        #[cfg(not(any(feature = "local", feature = "s3")))]
        {
            Self {
                inner: Rfc1321Md5::new(),
            }
        }
    }

    pub fn update_bytes(&mut self, data: &[u8]) {
        #[cfg(any(feature = "local", feature = "s3"))]
        {
            use md5::Digest as _;
            self.inner.update(data);
        }
        #[cfg(not(any(feature = "local", feature = "s3")))]
        {
            self.inner.update(data);
        }
    }

    pub fn finalize_bytes(self) -> [u8; 16] {
        #[cfg(any(feature = "local", feature = "s3"))]
        {
            use md5::Digest as _;
            self.inner.finalize().into()
        }
        #[cfg(not(any(feature = "local", feature = "s3")))]
        {
            self.inner.finalize()
        }
    }

    pub fn finalize_hex(self) -> String {
        encode_hex_lower(&self.finalize_bytes())
    }
}

#[cfg(any(
    feature = "s3",
    feature = "gdrive",
    feature = "webdav",
    feature = "gcs",
    feature = "azureblob"
))]
impl StreamingDigest for StreamingMd5 {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use md5::{Digest as _, Md5};
    use sha2::Sha256;

    #[test]
    fn fips180_sha256_matches_standard_vectors_and_incremental_splits() {
        let vectors = [
            (
                b"" as &[u8],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (input, expected) in vectors {
            let mut h = Fips180Sha256::new();
            h.update(input);
            assert_eq!(hex::encode(h.finalize()), expected);
        }

        // Sweep lengths 0..=512 and odd chunk sizes against `sha2::Sha256`.
        let data: Vec<u8> = (0usize..=512)
            .map(|i| ((i * 59 + 13) & 0xFF) as u8)
            .collect();
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 256, 512] {
            let slice = &data[..len];
            let expected = hex::encode(Sha256::digest(slice));
            for step in [1usize, 7, 31, 64, 100] {
                let mut h = Fips180Sha256::new();
                for chunk in slice.chunks(step) {
                    h.update(chunk);
                }
                assert_eq!(
                    hex::encode(h.finalize()),
                    expected,
                    "SHA-256 mismatch at len={len}, step={step}"
                );
            }
        }
    }

    #[test]
    fn rfc1321_md5_matches_standard_vectors_and_incremental_splits() {
        let vectors = [
            (b"" as &[u8], "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
        ];
        for (input, expected) in vectors {
            let mut h = Rfc1321Md5::new();
            h.update(input);
            assert_eq!(hex::encode(h.finalize()), expected);
        }

        // Sweep lengths 0..=256 and odd chunk sizes against `md5::Md5`.
        let data: Vec<u8> = (0usize..=512)
            .map(|i| ((i * 73 + 19) & 0xFF) as u8)
            .collect();
        for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 256, 512] {
            let slice = &data[..len];
            let expected = hex::encode(Md5::digest(slice));
            for step in [1usize, 7, 31, 64, 100] {
                let mut h = Rfc1321Md5::new();
                for chunk in slice.chunks(step) {
                    h.update(chunk);
                }
                assert_eq!(
                    hex::encode(h.finalize()),
                    expected,
                    "MD5 mismatch at len={len}, step={step}"
                );
            }
        }
    }

    #[tokio::test]
    async fn streaming_hash_and_verifying_download_streams_work_end_to_end() {
        struct SumDigest(u64);
        impl StreamingDigest for SumDigest {
            type Output = String;
            fn update(&mut self, chunk: &[u8]) {
                for &b in chunk {
                    self.0 = self.0.wrapping_add(u64::from(b));
                }
            }
            fn finalize(self) -> String {
                format!("{:016x}", self.0)
            }
        }

        // Upload stream publishes digest immediately when `seen_len == expected_len`
        // (even before polling trailing `None`, matching HTTP/1.1 hyper behavior).
        let slot: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
        let inner = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"def")),
        ]);
        let mut s = StreamingHashStream::new(inner, SumDigest(0), 6, slot.clone());
        let c1 = s.next().await.unwrap().unwrap();
        assert_eq!(c1.as_ref(), b"abc");
        assert!(slot.lock().unwrap().is_none());
        let c2 = s.next().await.unwrap().unwrap();
        assert_eq!(c2.as_ref(), b"def");
        let expected_sum: u64 = b"abcdef".iter().map(|&b| u64::from(b)).sum();
        assert_eq!(
            slot.lock().unwrap().as_deref(),
            Some(format!("{expected_sum:016x}").as_str())
        );

        // Download verification passes on exact match and fails with a non-retryable
        // Integrity error on mismatch (never reconciled into success by the engine).
        let ok_inner = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"def")),
        ]);
        let mut ok_dl = VerifyingDownloadStream::new(
            "Test",
            "SUM",
            ok_inner,
            SumDigest(0),
            6,
            format!("{expected_sum:016x}"),
        );
        let mut got = Vec::new();
        while let Some(item) = ok_dl.next().await {
            got.extend_from_slice(&item.unwrap());
        }
        assert_eq!(got, b"abcdef");

        let bad_inner = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"deX")),
        ]);
        let mut bad_dl = VerifyingDownloadStream::new(
            "Test",
            "SUM",
            bad_inner,
            SumDigest(0),
            6,
            format!("{expected_sum:016x}"),
        );
        let _ = bad_dl.next().await.unwrap().unwrap();
        let err = bad_dl.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind, rship_core::ErrorKind::Integrity);
        assert!(err.is_integrity());
        assert!(!err.is_retryable());
        assert!(!err.is_throttled());
        assert!(err.message().contains("checksum mismatch"));
    }
}
