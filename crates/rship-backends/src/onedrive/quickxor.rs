//! Streaming Microsoft `QuickXorHash`, the content hash OneDrive Personal, OneDrive for
//! Business and SharePoint return in `file.hashes.quickXorHash`.
//!
//! Algorithm (<https://learn.microsoft.com/onedrive/developer/code-snippets/quickxorhash>):
//! byte `i` of the input is XORed into a 160-bit circular register at bit offset
//! `(i * 11) mod 160`, and the total input length (little-endian `u64`) is XORed into the
//! last 8 bytes of the 20-byte result. Graph reports the result base64-encoded.
//!
//! Because `gcd(11, 160) == 1`, byte `i` lands at the same offset as byte `i mod 160`. So the
//! hasher XORs input into a 160-byte accumulator (`acc[i mod 160] ^= byte`), which the
//! compiler vectorizes, and folds the accumulator into the 160-bit register only once, at
//! finalize. The state is plain data, so a clone resumes hashing exactly where it left off.

use crate::common::StreamingDigest;

/// Width of the QuickXorHash register in bits.
const WIDTH_BITS: usize = 160;
/// Bit shift between consecutive input bytes.
const SHIFT: usize = 11;
/// Size of the finalized hash in bytes.
pub const QUICKXOR_LEN: usize = WIDTH_BITS / 8;

/// Incremental QuickXorHash. Cloning snapshots the running state.
#[derive(Clone)]
pub struct QuickXorHasher {
    /// `acc[k]` is the XOR of every input byte at a position `i` with `i % 160 == k`.
    acc: [u8; WIDTH_BITS],
    len: u64,
}

impl Default for QuickXorHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for QuickXorHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuickXorHasher")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl QuickXorHasher {
    pub fn new() -> Self {
        Self {
            acc: [0; WIDTH_BITS],
            len: 0,
        }
    }

    /// Number of bytes hashed so far.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether no bytes have been hashed yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn update_bytes(&mut self, mut data: &[u8]) {
        // Position of the first new byte inside the 160-byte period.
        let start = (self.len % WIDTH_BITS as u64) as usize;
        self.len = self.len.wrapping_add(data.len() as u64);
        if start != 0 {
            let n = data.len().min(WIDTH_BITS - start);
            xor_into(&mut self.acc[start..start + n], &data[..n]);
            data = &data[n..];
        }
        let (blocks, rest) = data.as_chunks::<WIDTH_BITS>();
        for block in blocks {
            xor_into(&mut self.acc, block);
        }
        xor_into(&mut self.acc[..rest.len()], rest);
    }

    pub fn finalize_bytes(&self) -> [u8; QUICKXOR_LEN] {
        // One spare byte absorbs the carry of a byte placed at bit offset 153..=159; it wraps
        // around to bit 0 of the circular register.
        let mut out = [0u8; QUICKXOR_LEN + 1];
        for (i, &byte) in self.acc.iter().enumerate() {
            let bit = (i * SHIFT) % WIDTH_BITS;
            let shifted = u16::from(byte) << (bit % 8);
            out[bit / 8] ^= shifted as u8;
            out[bit / 8 + 1] ^= (shifted >> 8) as u8;
        }
        out[0] ^= out[QUICKXOR_LEN];
        let mut hash = [0u8; QUICKXOR_LEN];
        hash.copy_from_slice(&out[..QUICKXOR_LEN]);
        for (dst, len_byte) in hash[QUICKXOR_LEN - 8..]
            .iter_mut()
            .zip(self.len.to_le_bytes())
        {
            *dst ^= len_byte;
        }
        hash
    }

    /// Finalized hash as 40 lowercase hex characters.
    pub fn finalize_hex(&self) -> String {
        hex_lower(&self.finalize_bytes())
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_LOWER[(b >> 4) as usize] as char);
        s.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    s
}

/// Convert Graph's base64 `quickXorHash` into 40 lowercase hex characters, or `None` if the
/// value is not a valid 20-byte hash.
pub fn quickxor_base64_to_hex(b64: &str) -> Option<String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    (raw.len() == QUICKXOR_LEN).then(|| hex_lower(&raw))
}

/// [`StreamingDigest`] producing the finalized hash as lowercase hex.
impl StreamingDigest for QuickXorHasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

/// [`StreamingDigest`] that yields the running hasher itself, so the state after one upload
/// chunk can seed the next chunk of the same session.
pub struct QuickXorState(pub QuickXorHasher);

impl StreamingDigest for QuickXorState {
    type Output = QuickXorHasher;

    fn update(&mut self, chunk: &[u8]) {
        self.0.update_bytes(chunk);
    }

    fn finalize(self) -> QuickXorHasher {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;

    /// Bit-by-bit restatement of Microsoft's documented algorithm (each byte XORed into the
    /// circular 160-bit register at bit `(i * 11) mod 160`), kept independent from the
    /// production accumulator so the two cross-check each other.
    fn reference_quickxor(data: &[u8]) -> [u8; QUICKXOR_LEN] {
        let mut bits = [false; WIDTH_BITS];
        for (i, &byte) in data.iter().enumerate() {
            let base = (i * SHIFT) % WIDTH_BITS;
            for b in 0..8 {
                if byte & (1 << b) != 0 {
                    let pos = (base + b) % WIDTH_BITS;
                    bits[pos] = !bits[pos];
                }
            }
        }
        let mut out = [0u8; QUICKXOR_LEN];
        for (pos, &set) in bits.iter().enumerate() {
            if set {
                out[pos / 8] |= 1 << (pos % 8);
            }
        }
        for (dst, len_byte) in out[QUICKXOR_LEN - 8..]
            .iter_mut()
            .zip((data.len() as u64).to_le_bytes())
        {
            *dst ^= len_byte;
        }
        out
    }

    /// `(input length, base64 input, base64 QuickXorHash)` known-answer vectors, taken from
    /// rclone's `backend/onedrive/quickxorhash` test suite.
    const VECTORS: &[(usize, &str, &str)] = &[
        (0, "", "AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
        (1, "Sg==", "SgAAAAAAAAAAAAAAAQAAAAAAAAA="),
        (2, "tbQ=", "taAFAAAAAAAAAAAAAgAAAAAAAAA="),
        (3, "0pZP", "0rDEEwAAAAAAAAAAAwAAAAAAAAA="),
        (8, "/aNzzCFPS/A=", "/RjFHJgRgicsAR4ACAAAAAAAAAA="),
        (13, "vPgoDjOfO6fm71RxLw==", "vMAHChwwg0/s4BTmdQcV4vACAAA="),
        (
            16,
            "2fuxhBJXtpWFe8dOfdGeHw==",
            "O9tHLAghgSvYohKFyMMxnNCHaHg=",
        ),
        (
            19,
            "g8VtAh+2Kf4k0kY5tzji2i2zmA==",
            "wDNrgwHWAVukwB8kg4YRcnALHIg=",
        ),
        (
            20,
            "T6LYJIfDh81JrAK309H2JMJTXis=",
            "zBTHrspn3mEcohlJdIUAbjGNaNg=",
        ),
        (
            21,
            "DWAAX5/CIfrmErgZa8ot6ZraeSbu",
            "LR2Z0PjuRYGKQB/mhQAuMrAGZbQ=",
        ),
        (
            40,
            "YnF4smoy9hox2jBlJ3VUa4qyCRhOZbWcmFGIiszTT4zAdYHsqJazyg==",
            "arkIn+ELddmE8N34J9ydyFKW+9w=",
        ),
        (
            64,
            "Mb7EGva2rEE5fENDL85P+BsapHEEjv2/siVhKjvAQe02feExVOQSkfmuYzU/kTF1MaKjPmKF/w+cbvwfdWL8aQ==",
            "n1anP5NfvD4XDYWIeRPW3ZkPv1Y=",
        ),
        (
            111,
            "jyibxJSzO6ZiZ0O1qe3tG/bvIAYssvukh9suIT5wEy1JBINVgPiqdsTW0cOpP0aUfP7mgqLfADkzI/m/GgCuVhr8oFLrOCoTx1/psBOWwhltCbhUx51Icm9aH8tY4Z3ccU+6BKpYQkLCy0B/A9Zc",
            "hZfLIilSITC6N3e3tQ/iSgEzkto=",
        ),
        (
            128,
            "ikwCorI7PKWz17EI50jZCGbV9JU2E8bXVfxNMg5zdmqSZ2NlsQPp0kqYIPjzwTg1MBtfWPg53k0h0P2naJNEVgrqpoHTfV2b3pJ4m0zYPTJmUX4Bg/lOxcnCxAYKU29Y5F0U8Quz7ZXFBEweftXxJ7RS4r6N7BzJrPsLhY7hgck=",
            "imAoFvCWlDn4yVw3/oq1PDbbm6U=",
        ),
        (
            222,
            "PfxMcUd0vIW6VbHG/uj/Y0W6qEoKmyBD0nYebEKazKaKG+UaDqBEcmQjbfQeVnVLuodMoPp7P7TR1htX5n2VnkHh22xDyoJ8C/ZQKiSNqQfXvh83judf4RVr9exJCud8Uvgip6aVZTaPrJHVjQhMCp/dEnGvqg0oN5OVkM2qqAXvA0teKUDhgNM71sDBVBCGXxNOR2bpbD1iM4dnuT0ey4L+loXEHTL0fqMeUcEi2asgImnlNakwenDzz0x57aBwyq3AspCFGB1ncX4yYCr/OaCcS5OKi/00WH+wNQU3",
            "QX/YEpG0gDsmhEpCdWhsxDzsfVE=",
        ),
        (
            256,
            "qwGf2ESubE5jOUHHyc94ORczFYYbc2OmEzo+hBIyzJiNwAzC8PvJqtTzwkWkSslgHFGWQZR2BV5+uYTrYT7HVwRM40vqfj0dBgeDENyTenIOL1LHkjtDKoXEnQ0mXAHoJ8PjbNC93zi5TovVRXTNzfGEs5dpWVqxUzb5lc7dwkyvOluBw482mQ4xrzYyIY1t+//OrNi1ObGXuUw2jBQOFfJVj2Y6BOyYmfB1y36eBxi3zxeG5d5NYjm2GSh6e08QMAwu3zrINcqIzLOuNIiGXBtl7DjKt7b5wqi4oFiRpZsCyx2smhSrdrtK/CkdU6nDN+34vSR/M8rZpWQdBE7a8g==",
            "WYT9JY3JIo/pEBp+tIM6Gt2nyTM=",
        ),
        (
            333,
            "w0LGhqU1WXFbdavqDE4kAjEzWLGGzmTNikzqnsiXHx2KRReKVTxkv27u3UcEz9+lbMvYl4xFf2Z4aE1xRBBNd1Ke5C0zToSaYw5o4B/7X99nKK2/XaUX1byLow2aju2XJl2OpKpJg+tSJ2fmjIJTkfuYUz574dFX6/VXxSxwGH/xQEAKS5TCsBK3CwnuG1p5SAsQq3gGVozDWyjEBcWDMdy8/AIFrj/y03Lfc/RNRCQTAfZbnf2QwV7sluw4fH3XJr07UoD0YqN+7XZzidtrwqMY26fpLZnyZjnBEt1FAZWO7RnKG5asg8xRk9YaDdedXdQSJAOy6bWEWlABj+tVAigBxavaluUH8LOj+yfCFldJjNLdi90fVHkUD/m4Mr5OtmupNMXPwuG3EQlqWUVpQoYpUYKLsk7a5Mvg6UFkiH596y5IbJEVCI1Kb3D1",
            "e3+wo77iKcILiZegnzyUNcjCdoQ=",
        ),
    ];

    #[test]
    fn quickxor_matches_known_answer_vectors() {
        for &(len, input_b64, expected_b64) in VECTORS {
            let input = B64.decode(input_b64).unwrap();
            assert_eq!(input.len(), len, "vector input length");
            let expected = B64.decode(expected_b64).unwrap();
            let mut h = QuickXorHasher::new();
            h.update_bytes(&input);
            assert_eq!(
                h.finalize_bytes().as_slice(),
                expected.as_slice(),
                "len={len}"
            );
            assert_eq!(reference_quickxor(&input).as_slice(), expected.as_slice());
            assert_eq!(
                quickxor_base64_to_hex(expected_b64).as_deref(),
                Some(h.finalize_hex().as_str())
            );
        }
    }

    #[test]
    fn quickxor_incremental_splits_and_cloned_state_match_one_shot() {
        let data: Vec<u8> = (0..5_000usize)
            .map(|i| ((i * 73 + 19) % 256) as u8)
            .collect();
        for len in [
            0usize, 1, 159, 160, 161, 319, 320, 321, 1_759, 1_760, 1_761, 5_000,
        ] {
            let slice = &data[..len];
            let expected = reference_quickxor(slice);
            for step in [1usize, 7, 64, 159, 160, 161, 1_000] {
                let mut h = QuickXorHasher::new();
                for chunk in slice.chunks(step) {
                    h.update_bytes(chunk);
                }
                assert_eq!(h.finalize_bytes(), expected, "len={len} step={step}");
            }
            // Resuming from a cloned mid-stream snapshot yields the same hash.
            let mid = len / 3;
            let mut first = QuickXorHasher::new();
            first.update_bytes(&slice[..mid]);
            let mut resumed = first.clone();
            resumed.update_bytes(&slice[mid..]);
            assert_eq!(resumed.finalize_bytes(), expected, "resume len={len}");
            assert_eq!(resumed.len(), len as u64);
        }
    }

    #[test]
    fn quickxor_base64_to_hex_rejects_wrong_lengths() {
        assert_eq!(quickxor_base64_to_hex("AAAA"), None);
        assert_eq!(quickxor_base64_to_hex("not base64!"), None);
        assert_eq!(
            quickxor_base64_to_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Some("0".repeat(40))
        );
    }
}
