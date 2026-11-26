//! Dropbox `content_hash` (4 MiB SHA-256 block tree) and ASCII-safe `Dropbox-API-Arg`
//! JSON header encoding (rclone `jsonEncodeHeader` rule: escape all non-ASCII codepoints
//! `>= 0x7F` as `\uXXXX` / UTF-16 surrogate pairs).

use crate::common::StreamingDigest;
use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Incremental, O(1)-memory streaming Dropbox `content_hash` accumulator
/// (4 MiB SHA-256 block tree, zero block buffering).
pub struct DropboxContentHasher {
    overall: Sha256,
    block: Sha256,
    block_bytes: usize,
}

impl Default for DropboxContentHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl DropboxContentHasher {
    pub fn new() -> Self {
        Self {
            overall: Sha256::new(),
            block: Sha256::new(),
            block_bytes: 0,
        }
    }

    pub fn update_bytes(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let space = BLOCK_SIZE - self.block_bytes;
            let take = data.len().min(space);
            self.block.update(&data[..take]);
            self.block_bytes += take;
            data = &data[take..];
            if self.block_bytes == BLOCK_SIZE {
                let block_digest = self.block.finalize_reset();
                self.overall.update(block_digest);
                self.block_bytes = 0;
            }
        }
    }

    pub fn finalize_hex(mut self) -> String {
        if self.block_bytes > 0 {
            let block_digest = self.block.finalize();
            self.overall.update(block_digest);
        }
        hex::encode(self.overall.finalize())
    }
}

impl StreamingDigest for DropboxContentHasher {
    type Output = String;

    fn update(&mut self, chunk: &[u8]) {
        self.update_bytes(chunk);
    }

    fn finalize(self) -> String {
        self.finalize_hex()
    }
}

/// Compute the official Dropbox `content_hash` (64-char lowercase hex):
/// split into 4 MiB blocks, SHA-256 each block, concatenate the 32-byte digests,
/// and return the SHA-256 of the concatenation.
pub fn dropbox_content_hash(data: &[u8]) -> String {
    let mut hasher = DropboxContentHasher::new();
    hasher.update_bytes(data);
    hasher.finalize_hex()
}

/// Derive the exact Dropbox `content_hash` from a known flat SHA-256 hex digest when the
/// object fits in a single 4 MiB Dropbox block (`total_size <= 4 MiB`):
/// - For 0 bytes: `SHA256("")` (`e3b0c442...`) directly.
/// - For `1..=4 MiB`: `SHA256(raw_sha256_bytes)` (single-leaf block tree).
///
/// Returns `None` for files larger than 4 MiB or malformed SHA-256 hex.
pub fn dropbox_content_hash_from_single_block_sha256(
    sha256_hex: &str,
    total_size: u64,
) -> Option<String> {
    if total_size > BLOCK_SIZE as u64 {
        return None;
    }
    let raw = hex::decode(sha256_hex.trim()).ok()?;
    if raw.len() != 32 {
        return None;
    }
    if total_size == 0 {
        return Some(hex::encode(Sha256::digest([])));
    }
    Some(hex::encode(Sha256::digest(raw)))
}

/// Serialize a JSON value into an ASCII-safe HTTP header string for `Dropbox-API-Arg`.
///
/// Dropbox strictly rejects raw bytes `>= 0x7F` in the `Dropbox-API-Arg` header;
/// every character `>= 0x7F` is encoded as `\uXXXX` (or a UTF-16 surrogate pair for
/// supplementary codepoints like emoji), matching `rclone`'s Dropbox encoder.
pub fn encode_dropbox_api_arg(val: &serde_json::Value) -> String {
    let raw = serde_json::to_string(val).unwrap_or_else(|_| "{}".to_string());
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        let cp = ch as u32;
        if cp < 0x7F {
            out.push(ch);
        } else if cp <= 0xFFFF {
            out.push_str(&format!("\\u{cp:04x}"));
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_matches_empty_and_multi_block_vectors() {
        // Empty file: SHA256("")
        assert_eq!(
            dropbox_content_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Single block: SHA256(SHA256("hello"))
        let inner = Sha256::digest(b"hello");
        let expected = hex::encode(Sha256::digest(inner));
        assert_eq!(dropbox_content_hash(b"hello"), expected);

        // Two blocks (4 MiB + 1 byte): SHA256(SHA256(block0) || SHA256(block1))
        let mut two = vec![0x61u8; BLOCK_SIZE];
        two.push(0x62);
        let d0 = Sha256::digest(&two[..BLOCK_SIZE]);
        let d1 = Sha256::digest(&two[BLOCK_SIZE..]);
        let mut combined = Sha256::new();
        combined.update(d0);
        combined.update(d1);
        assert_eq!(dropbox_content_hash(&two), hex::encode(combined.finalize()));

        // Incremental streaming across odd chunk boundaries spanning the 4 MiB block edge.
        let mut inc = DropboxContentHasher::new();
        for piece in two.chunks(131_071) {
            inc.update_bytes(piece);
        }
        assert_eq!(inc.finalize_hex(), dropbox_content_hash(&two));

        // Exact 4 MiB single-block boundary matches both incremental and SHA256-derived hash.
        let exact_4m = &two[..BLOCK_SIZE];
        let sha_exact_4m = hex::encode(Sha256::digest(exact_4m));
        assert_eq!(
            dropbox_content_hash_from_single_block_sha256(&sha_exact_4m, BLOCK_SIZE as u64),
            Some(dropbox_content_hash(exact_4m))
        );
        // Empty input and > 4 MiB guard.
        let empty_sha = hex::encode(Sha256::digest([]));
        assert_eq!(
            dropbox_content_hash_from_single_block_sha256(&empty_sha, 0),
            Some(dropbox_content_hash(b""))
        );
        assert_eq!(
            dropbox_content_hash_from_single_block_sha256(&sha_exact_4m, BLOCK_SIZE as u64 + 1),
            None
        );
    }

    #[test]
    fn encodes_dropbox_api_arg_ascii_safely_with_surrogate_pairs() {
        let arg = encode_dropbox_api_arg(&serde_json::json!({
            "path": "/文档/rocket🚀.txt"
        }));
        assert!(arg.is_ascii(), "Dropbox-API-Arg must be pure ASCII: {arg}");
        assert!(arg.contains("\\u6587\\u6863"));
        assert!(arg.contains("\\ud83d\\ude80"));
        let decoded: serde_json::Value = serde_json::from_str(&arg).unwrap();
        assert_eq!(decoded["path"], "/文档/rocket🚀.txt");
    }
}
