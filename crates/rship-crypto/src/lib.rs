//! STREAM OAE2 seekable 64 KiB AEAD encryption layer for `rship`.
//!
//! Based on Hoang, Reyhanitabar, Rogaway & Vizár (ePrint 2015/189):
//! - Fixed 32-byte authenticated header + 64 KiB plaintext chunks encrypted with
//!   `XChaCha20-Poly1305`.
//! - Each block binds `(nonce_prefix, chunk_idx, last_flag)` into both nonce and
//!   associated data (AAD), cryptographically rejecting chunk reordering, block
//!   duplication, header tampering, and silent file truncation.
//! - **100% seekable & constant-memory**: random-access HTTP `Range` downloads
//!   fetch and decrypt only the needed 64 KiB ciphertext blocks; uploads stream
//!   one 64 KiB block at a time with in-place AEAD (`AeadInPlace`) and remain
//!   compatible with resumable & parallel multipart backends.
//! - Optional deterministic SIV-style encrypted filenames (`base32` lowercase,
//!   cross-OS & case-insensitive safe).

#![forbid(unsafe_code)]

pub mod filename;
pub mod keys;
pub mod layer;
#[cfg(test)]
pub(crate) mod prop_test;
pub mod stream;

pub use filename::{FilenameEncryption, decrypt_rel_path, encrypt_rel_path};
pub use keys::{CryptoKeys, MasterKey};
pub use layer::{CryptoBackend, CryptoConfig};
pub use stream::{
    CIPHERTEXT_CHUNK_LEN, HEADER_LEN, PLAINTEXT_CHUNK_LEN, StreamCipher, StreamHeader, TAG_LEN,
    ciphertext_size, decrypt_chunk, decrypt_chunk_in_place, encrypt_chunk, encrypt_chunk_in_place,
    max_plaintext_for_ciphertext, plaintext_size,
};
