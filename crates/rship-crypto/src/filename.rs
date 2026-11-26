//! Deterministic SIV-style per-segment encrypted filename codec (base32 lowercase,
//! 100% cross-OS / Windows case-insensitive / URL-safe).

use std::collections::HashMap;

use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use rship_core::path::RelPath;
use rship_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::Zeroize;

use crate::keys::CryptoKeys;
use crate::stream::{TAG_LEN, hchacha20};

pub(crate) const NAME_AAD: &[u8] = b"rship-fname-v1";
const SIV_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilenameEncryption {
    /// Leave paths unencrypted; encrypt file contents only.
    Off,
    /// Deterministically encrypt each path segment using SIV-XChaCha20-Poly1305 + base32.
    #[default]
    Standard,
}

/// Encrypt a single path segment deterministically using hardware-accelerated
/// `aws-lc-rs` ChaCha20-Poly1305 with `HChaCha20` subkey derivation (wire-identical
/// to `XChaCha20-Poly1305(name_enc_key, siv || [0; 8])`).
pub fn encrypt_segment(keys: &CryptoKeys, segment: &str) -> Result<String> {
    let siv = derive_siv(keys, segment.as_bytes());

    let mut raw = Vec::with_capacity(SIV_LEN + segment.len() + TAG_LEN);
    raw.extend_from_slice(&siv);
    raw.extend_from_slice(segment.as_bytes());

    let mut subkey = hchacha20(&keys.name_enc_key, &siv);
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &subkey)
        .expect("32-byte HChaCha20 subkey always matches CHACHA20_POLY1305");
    subkey.zeroize();
    let key = LessSafeKey::new(unbound);

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(NAME_AAD),
            &mut raw[SIV_LEN..],
        )
        .map_err(|_| Error::protocol("filename encryption failed"))?;
    raw.extend_from_slice(tag.as_ref());
    Ok(base32_lower_encode(&raw))
}

/// Decrypt a single base32-encoded encrypted path segment using in-place AEAD.
pub fn decrypt_segment(keys: &CryptoKeys, encoded: &str) -> Result<String> {
    let mut raw = base32_lower_decode(encoded)?;
    if raw.len() < SIV_LEN + TAG_LEN {
        return Err(Error::protocol(format!(
            "encrypted path segment `{encoded}` is too short"
        )));
    }
    let siv: [u8; SIV_LEN] = raw[0..SIV_LEN]
        .try_into()
        .expect("siv length already validated");

    let mut subkey = hchacha20(&keys.name_enc_key, &siv);
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &subkey)
        .expect("32-byte HChaCha20 subkey always matches CHACHA20_POLY1305");
    subkey.zeroize();
    let key = LessSafeKey::new(unbound);

    let pt_len = match key.open_in_place(
        Nonce::assume_unique_for_key([0u8; 12]),
        Aad::from(NAME_AAD),
        &mut raw[SIV_LEN..],
    ) {
        Ok(pt) => pt.len(),
        Err(_) => {
            raw.zeroize();
            return Err(Error::protocol(format!(
                "failed to decrypt path segment `{encoded}` (wrong key or non-encrypted item)"
            )));
        }
    };

    raw.copy_within(SIV_LEN..SIV_LEN + pt_len, 0);
    raw.truncate(pt_len);
    String::from_utf8(raw)
        .map_err(|e| Error::protocol(format!("decrypted filename is not valid UTF-8: {e}")))
}

pub fn encrypt_rel_path(
    keys: &CryptoKeys,
    mode: FilenameEncryption,
    path: &RelPath,
) -> Result<RelPath> {
    if mode == FilenameEncryption::Off || path.is_root() {
        return Ok(path.clone());
    }
    let mut joined = String::with_capacity(path.as_str().len() * 2 + 64);
    for seg in path.segments() {
        if !joined.is_empty() {
            joined.push('/');
        }
        let enc = encrypt_segment(keys, seg)?;
        joined.push_str(&enc);
    }
    // Every encrypted segment is strictly lowercase ASCII base32 (`[a-z2-7]{52,}`),
    // which is guaranteed NFC, traversal-safe, and free of slashes/NULs.
    Ok(RelPath::from_normalized_unchecked(joined))
}

fn validate_decrypted_segment(dec: &str) -> Result<()> {
    if dec.is_empty() || dec == "." || dec == ".." || dec.contains(['/', '\\', '\0']) {
        return Err(Error::invalid_path(format!(
            "invalid decrypted path segment `{dec}`"
        )));
    }
    Ok(())
}

pub fn decrypt_rel_path(
    keys: &CryptoKeys,
    mode: FilenameEncryption,
    path: &RelPath,
) -> Result<RelPath> {
    if mode == FilenameEncryption::Off || path.is_root() {
        return Ok(path.clone());
    }
    let mut joined = String::with_capacity(path.as_str().len());
    for seg in path.segments() {
        let dec = decrypt_segment(keys, seg)?;
        validate_decrypted_segment(&dec)?;
        if !joined.is_empty() {
            joined.push('/');
        }
        joined.push_str(&dec);
    }
    RelPath::parse(&joined)
}

/// Decrypt a relative path while memoizing repeated parent-directory segments
/// in `dir_cache` (bounded by `cache_limit`) to avoid re-decrypting shared
/// ancestor directories across large tree listings.
pub(crate) fn decrypt_rel_path_cached(
    keys: &CryptoKeys,
    mode: FilenameEncryption,
    path: &RelPath,
    is_dir: bool,
    dir_cache: &mut HashMap<String, String>,
    cache_limit: usize,
) -> Result<RelPath> {
    if mode == FilenameEncryption::Off || path.is_root() {
        return Ok(path.clone());
    }
    let mut joined = String::with_capacity(path.as_str().len());
    let mut iter = path.segments().peekable();
    while let Some(seg) = iter.next() {
        let cacheable = is_dir || iter.peek().is_some();
        if !joined.is_empty() {
            joined.push('/');
        }
        if cacheable {
            if let Some(cached) = dir_cache.get(seg) {
                joined.push_str(cached);
                continue;
            }
            let dec = decrypt_segment(keys, seg)?;
            validate_decrypted_segment(&dec)?;
            joined.push_str(&dec);
            if dir_cache.len() < cache_limit {
                dir_cache.insert(seg.to_owned(), dec);
            }
        } else {
            let dec = decrypt_segment(keys, seg)?;
            validate_decrypted_segment(&dec)?;
            joined.push_str(&dec);
        }
    }
    RelPath::parse(&joined)
}

fn derive_siv(keys: &CryptoKeys, segment: &[u8]) -> [u8; SIV_LEN] {
    // RFC 2104 HMAC-SHA256 truncated to 128-bit synthetic IV using precomputed
    // ipad/opad SHA-256 midstates stored on `CryptoKeys`.
    let mut inner = keys.name_mac_inner.clone();
    inner.update(segment);
    let inner_digest = inner.finalize();

    let mut outer = keys.name_mac_outer.clone();
    outer.update(inner_digest);
    let full = outer.finalize();
    let mut siv = [0u8; SIV_LEN];
    siv.copy_from_slice(&full[..SIV_LEN]);
    siv
}

const B32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

const B32_DECODE_LUT: [u8; 256] = {
    let mut lut = [0xFFu8; 256];
    let mut i = 0usize;
    while i < 26 {
        lut[b'a' as usize + i] = i as u8;
        lut[b'A' as usize + i] = i as u8;
        i += 1;
    }
    let mut j = 0usize;
    while j < 6 {
        lut[b'2' as usize + j] = (26 + j) as u8;
        j += 1;
    }
    lut
};

fn base32_lower_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() * 8).div_ceil(5));
    let (chunks, rem) = data.as_chunks::<5>();
    for c in chunks {
        let v = (u64::from(c[0]) << 32)
            | (u64::from(c[1]) << 24)
            | (u64::from(c[2]) << 16)
            | (u64::from(c[3]) << 8)
            | u64::from(c[4]);
        out.extend_from_slice(&[
            B32_ALPHABET[((v >> 35) & 0x1F) as usize],
            B32_ALPHABET[((v >> 30) & 0x1F) as usize],
            B32_ALPHABET[((v >> 25) & 0x1F) as usize],
            B32_ALPHABET[((v >> 20) & 0x1F) as usize],
            B32_ALPHABET[((v >> 15) & 0x1F) as usize],
            B32_ALPHABET[((v >> 10) & 0x1F) as usize],
            B32_ALPHABET[((v >> 5) & 0x1F) as usize],
            B32_ALPHABET[(v & 0x1F) as usize],
        ]);
    }
    if !rem.is_empty() {
        let mut acc = 0u64;
        let mut bits = 0u32;
        for &b in rem {
            acc = (acc << 8) | u64::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(B32_ALPHABET[((acc >> bits) & 0x1F) as usize]);
            }
        }
        if bits > 0 {
            out.push(B32_ALPHABET[((acc << (5 - bits)) & 0x1F) as usize]);
        }
    }
    String::from_utf8(out).expect("base32 alphabet is valid ASCII")
}

fn base32_lower_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() * 5) / 8);
    let (chunks, rem) = bytes.as_chunks::<8>();
    for c in chunks {
        let v0 = B32_DECODE_LUT[c[0] as usize];
        let v1 = B32_DECODE_LUT[c[1] as usize];
        let v2 = B32_DECODE_LUT[c[2] as usize];
        let v3 = B32_DECODE_LUT[c[3] as usize];
        let v4 = B32_DECODE_LUT[c[4] as usize];
        let v5 = B32_DECODE_LUT[c[5] as usize];
        let v6 = B32_DECODE_LUT[c[6] as usize];
        let v7 = B32_DECODE_LUT[c[7] as usize];
        if (v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7) & 0x80 != 0 {
            let bad = c
                .iter()
                .copied()
                .find(|&b| B32_DECODE_LUT[b as usize] == 0xFF)
                .unwrap();
            return Err(Error::protocol(format!(
                "invalid base32 char `{}` in encrypted filename",
                bad as char
            )));
        }
        let v = (u64::from(v0) << 35)
            | (u64::from(v1) << 30)
            | (u64::from(v2) << 25)
            | (u64::from(v3) << 20)
            | (u64::from(v4) << 15)
            | (u64::from(v5) << 10)
            | (u64::from(v6) << 5)
            | u64::from(v7);
        out.extend_from_slice(&[
            ((v >> 32) & 0xFF) as u8,
            ((v >> 24) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ]);
    }
    if !rem.is_empty() {
        if matches!(rem.len(), 1 | 3 | 6) {
            return Err(Error::protocol(format!(
                "invalid base32 length ({}) in encrypted filename",
                bytes.len()
            )));
        }
        let mut acc = 0u64;
        let mut bits = 0u32;
        for &b in rem {
            let val = B32_DECODE_LUT[b as usize];
            if val == 0xFF {
                return Err(Error::protocol(format!(
                    "invalid base32 char `{}` in encrypted filename",
                    b as char
                )));
            }
            acc = (acc << 5) | u64::from(val);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push(((acc >> bits) & 0xFF) as u8);
            }
        }
        if bits > 0 && (acc & ((1u64 << bits) - 1)) != 0 {
            return Err(Error::protocol(
                "non-canonical trailing base32 padding bits in encrypted filename",
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::MasterKey;

    #[test]
    fn deterministic_path_encryption_round_trips_unicode_and_is_case_safe() {
        let keys = MasterKey::from_bytes([7u8; 32]).derive_subkeys();
        let orig = RelPath::parse("2026/O'Reilly/中文报告 café.pdf").unwrap();
        let enc1 = encrypt_rel_path(&keys, FilenameEncryption::Standard, &orig).unwrap();
        let enc2 = encrypt_rel_path(&keys, FilenameEncryption::Standard, &orig).unwrap();
        assert_eq!(enc1, enc2);
        assert!(
            enc1.as_str()
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7' | b'/')),
            "encrypted path must only use lowercase base32 + `/`: {enc1}"
        );
        let dec = decrypt_rel_path(&keys, FilenameEncryption::Standard, &enc1).unwrap();
        assert_eq!(dec, orig);
    }

    #[test]
    fn aws_lc_filename_encryption_is_bit_exact_with_reference_xchacha20_poly1305() {
        use chacha20poly1305::aead::AeadInOut;
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

        let keys = MasterKey::from_bytes([0x5Au8; 32]).derive_subkeys();
        let ref_cipher = XChaCha20Poly1305::new((&keys.name_enc_key).into());

        // Test empty, ASCII, UTF-8, and every length 0..=40 to exercise all 5->8 base32 remainders.
        let mut samples: Vec<String> = vec![
            String::new(),
            "a".into(),
            "report.pdf".into(),
            "中文报告 café.pdf".into(),
        ];
        for len in 1..=40 {
            samples.push((0..len).map(|i| (b'a' + (i % 26) as u8) as char).collect());
        }

        for seg in &samples {
            let actual = encrypt_segment(&keys, seg).unwrap();

            // Reference XChaCha20-Poly1305 calculation.
            let siv = derive_siv(&keys, seg.as_bytes());
            let mut nonce = [0u8; 24];
            nonce[0..SIV_LEN].copy_from_slice(&siv);
            let mut raw = Vec::with_capacity(SIV_LEN + seg.len() + TAG_LEN);
            raw.extend_from_slice(&siv);
            raw.extend_from_slice(seg.as_bytes());
            let tag = ref_cipher
                .encrypt_inout_detached(
                    &XNonce::from(nonce),
                    NAME_AAD,
                    (&mut raw[SIV_LEN..]).into(),
                )
                .unwrap();
            raw.extend_from_slice(tag.as_slice());
            let expected = base32_lower_encode(&raw);

            assert_eq!(actual, expected, "wire mismatch for segment `{seg}`");
            // Case-insensitive base32 decoding check (uppercase variant must also decrypt).
            assert_eq!(decrypt_segment(&keys, &actual).unwrap(), *seg);
            assert_eq!(
                decrypt_segment(&keys, &actual.to_ascii_uppercase()).unwrap(),
                *seg
            );
        }

        // Verify directory-segment memoization matches uncached path decryption and stays bounded.
        let mut dir_cache = HashMap::new();
        for i in 0..8 {
            let orig = RelPath::parse(&format!("2026/O'Reilly/sub/file_{i}.bin")).unwrap();
            let enc = encrypt_rel_path(&keys, FilenameEncryption::Standard, &orig).unwrap();
            let dec = decrypt_rel_path_cached(
                &keys,
                FilenameEncryption::Standard,
                &enc,
                false,
                &mut dir_cache,
                16,
            )
            .unwrap();
            assert_eq!(dec, orig);
        }
        // Only the 3 parent directory segments should be cached, never the 8 unique leaf files.
        assert_eq!(dir_cache.len(), 3);
    }

    fn random_valid_segment(rng: &mut rand::rngs::StdRng, target_chars: usize) -> String {
        use rand::RngExt;

        // Precomposed NFC Unicode + printable ASCII + punctuation + spaces (no '/', '\\', '\0').
        const ASCII_ALNUM: &[char] = &[
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
            'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        ];
        const PUNCT_SPACE: &[char] = &[
            ' ', '.', '-', '_', '!', '@', '#', '$', '%', '^', '&', '(', ')', '[', ']', '{', '}',
            '+', '=', ',', ';', '\'', '~', '`',
        ];
        const UNICODE_NFC: &[char] = &[
            'é', 'ü', 'ñ', 'ç', 'ø', 'ß', 'Ł', 'α', 'Ω', 'Д', 'ж', '中', '文', '報', '告', '日',
            '本', '語', '한', '글', '🚀', '🔒', '🧪', '🦀',
        ];

        let style = rng.random_range(0u8..5);
        let mut s = String::with_capacity(target_chars * 2);
        for _ in 0..target_chars.max(1) {
            let ch = match style {
                0 => ASCII_ALNUM[rng.random_range(0..ASCII_ALNUM.len())],
                1 => {
                    if rng.random_bool(0.5) {
                        ASCII_ALNUM[rng.random_range(0..ASCII_ALNUM.len())]
                    } else {
                        PUNCT_SPACE[rng.random_range(0..PUNCT_SPACE.len())]
                    }
                }
                2 => UNICODE_NFC[rng.random_range(0..UNICODE_NFC.len())],
                3 => PUNCT_SPACE[rng.random_range(0..PUNCT_SPACE.len())],
                _ => match rng.random_range(0u8..3) {
                    0 => ASCII_ALNUM[rng.random_range(0..ASCII_ALNUM.len())],
                    1 => PUNCT_SPACE[rng.random_range(0..PUNCT_SPACE.len())],
                    _ => UNICODE_NFC[rng.random_range(0..UNICODE_NFC.len())],
                },
            };
            s.push(ch);
        }
        // Avoid traversal-reserved literal segments "." and "..".
        if s == "." || s == ".." {
            s.push('_');
        }
        s
    }

    #[test]
    fn prop_siv_filename_segment_bijection_determinism_and_domain_separation() {
        use crate::prop_test::{SeedGuard, rng_for, seeds_for};
        use chacha20poly1305::aead::AeadInOut;
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        use rand::{Rng, RngExt};

        const EDGE_LENGTHS: &[usize] = &[1, 2, 3, 4, 5, 6, 15, 16, 32, 64, 126, 127, 128, 199, 200];

        let seeds = seeds_for(0x5253_4849_464E_0001, 256);
        let total = seeds.len();
        for (case_idx, seed) in seeds {
            let _guard = SeedGuard::new(
                "siv_filename_segment_bijection_determinism_and_domain_separation",
                case_idx,
                total,
                seed,
            );
            let mut rng = rng_for(seed);

            let mut k1_raw = [0u8; 32];
            let mut k2_raw = [0u8; 32];
            rng.fill_bytes(&mut k1_raw);
            rng.fill_bytes(&mut k2_raw);
            if k2_raw == k1_raw {
                k2_raw[0] ^= 0x01;
            }
            let keys1 = MasterKey::from_bytes(k1_raw).derive_subkeys();
            let keys2 = MasterKey::from_bytes(k2_raw).derive_subkeys();

            let len = if case_idx < EDGE_LENGTHS.len() {
                EDGE_LENGTHS[case_idx]
            } else {
                rng.random_range(1usize..=200)
            };
            let seg = random_valid_segment(&mut rng, len);

            // 1. Deterministic encryption and canonical lowercase base32 output format.
            let enc1 = encrypt_segment(&keys1, &seg).unwrap();
            let enc2 = encrypt_segment(&keys1, &seg).unwrap();
            assert_eq!(
                enc1, enc2,
                "non-deterministic SIV encryption (seed={seed:#018x})"
            );
            assert!(
                enc1.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')),
                "encrypted segment must be lowercase base32: {enc1} (seed={seed:#018x})"
            );
            let expected_b32_len = ((SIV_LEN + seg.len() + TAG_LEN) * 8).div_ceil(5);
            assert_eq!(
                enc1.len(),
                expected_b32_len,
                "unexpected base32 length for seg byte len {} (seed={seed:#018x})",
                seg.len()
            );

            // 2. Exact bijection (lowercase, uppercase, and random mixed case).
            assert_eq!(
                decrypt_segment(&keys1, &enc1).unwrap(),
                seg,
                "decrypt_segment roundtrip failed (seed={seed:#018x})"
            );
            assert_eq!(
                decrypt_segment(&keys1, &enc1.to_ascii_uppercase()).unwrap(),
                seg,
                "uppercase decrypt_segment failed (seed={seed:#018x})"
            );
            let mixed_case: String = enc1
                .chars()
                .map(|c| {
                    if rng.random_bool(0.5) {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect();
            assert_eq!(
                decrypt_segment(&keys1, &mixed_case).unwrap(),
                seg,
                "mixed-case decrypt_segment failed (seed={seed:#018x})"
            );

            // 3. Domain separation: distinct keys yield distinct ciphertexts and reject cross-key decrypt.
            let enc_other_key = encrypt_segment(&keys2, &seg).unwrap();
            assert_ne!(
                enc1, enc_other_key,
                "distinct keys produced identical ciphertext (seed={seed:#018x})"
            );
            assert!(
                decrypt_segment(&keys2, &enc1).is_err(),
                "wrong key decrypted segment (seed={seed:#018x})"
            );

            // 4. Domain separation: distinct inputs yield distinct ciphertexts.
            let seg2 = match rng.random_range(0u8..3) {
                0 => format!("{seg}x"),
                1 => format!(" {seg}"),
                _ => {
                    let mut chars: Vec<char> = seg.chars().collect();
                    let pos = rng.random_range(0..chars.len());
                    chars[pos] = if chars[pos] == 'a' { 'b' } else { 'a' };
                    let mutated: String = chars.into_iter().collect();
                    if mutated == seg {
                        format!("{seg}_")
                    } else {
                        mutated
                    }
                }
            };
            assert_ne!(seg, seg2);
            let enc_other_input = encrypt_segment(&keys1, &seg2).unwrap();
            assert_ne!(
                enc1, enc_other_input,
                "distinct inputs `{seg}` vs `{seg2}` collided (seed={seed:#018x})"
            );

            // 5. Reference XChaCha20-Poly1305 parity check.
            let ref_cipher = XChaCha20Poly1305::new((&keys1.name_enc_key).into());
            let siv = derive_siv(&keys1, seg.as_bytes());
            let mut nonce = [0u8; 24];
            nonce[0..SIV_LEN].copy_from_slice(&siv);
            let mut raw = Vec::with_capacity(SIV_LEN + seg.len() + TAG_LEN);
            raw.extend_from_slice(&siv);
            raw.extend_from_slice(seg.as_bytes());
            let tag = ref_cipher
                .encrypt_inout_detached(
                    &XNonce::from(nonce),
                    NAME_AAD,
                    (&mut raw[SIV_LEN..]).into(),
                )
                .unwrap();
            raw.extend_from_slice(tag.as_slice());
            assert_eq!(
                enc1,
                base32_lower_encode(&raw),
                "reference XChaCha20Poly1305 mismatch (seed={seed:#018x})"
            );
        }
    }

    #[test]
    fn prop_siv_rel_path_bijection_and_cached_parity() {
        use crate::prop_test::{SeedGuard, rng_for, seeds_for};
        use rand::{Rng, RngExt};

        let seeds = seeds_for(0x5253_4849_464E_0002, 256);
        let total = seeds.len();
        for (case_idx, seed) in seeds {
            let _guard = SeedGuard::new(
                "siv_rel_path_bijection_and_cached_parity",
                case_idx,
                total,
                seed,
            );
            let mut rng = rng_for(seed);

            let mut key_raw = [0u8; 32];
            rng.fill_bytes(&mut key_raw);
            let keys = MasterKey::from_bytes(key_raw).derive_subkeys();

            let depth = rng.random_range(1usize..=6);
            let mut parts = Vec::with_capacity(depth);
            for _ in 0..depth {
                let len = rng.random_range(1usize..=48);
                parts.push(random_valid_segment(&mut rng, len));
            }
            let rel = RelPath::parse(&parts.join("/")).unwrap();

            // Standard mode: deterministic bijection + cached parity.
            let enc1 = encrypt_rel_path(&keys, FilenameEncryption::Standard, &rel).unwrap();
            let enc2 = encrypt_rel_path(&keys, FilenameEncryption::Standard, &rel).unwrap();
            assert_eq!(
                enc1, enc2,
                "non-deterministic RelPath encrypt (seed={seed:#018x})"
            );
            assert!(
                enc1.as_str()
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7' | b'/')),
                "invalid chars in encrypted RelPath `{enc1}` (seed={seed:#018x})"
            );

            let dec = decrypt_rel_path(&keys, FilenameEncryption::Standard, &enc1).unwrap();
            assert_eq!(dec, rel, "RelPath roundtrip mismatch (seed={seed:#018x})");

            let mut dir_cache = HashMap::new();
            let is_dir = rng.random_bool(0.5);
            let cache_limit = rng.random_range(0usize..=8);
            let dec_cached = decrypt_rel_path_cached(
                &keys,
                FilenameEncryption::Standard,
                &enc1,
                is_dir,
                &mut dir_cache,
                cache_limit,
            )
            .unwrap();
            assert_eq!(
                dec_cached, rel,
                "cached RelPath decrypt mismatch (seed={seed:#018x})"
            );
            assert!(
                dir_cache.len() <= cache_limit,
                "dir_cache exceeded limit {cache_limit} (seed={seed:#018x})"
            );
            // Second call exercises cache hits.
            let dec_cached_2 = decrypt_rel_path_cached(
                &keys,
                FilenameEncryption::Standard,
                &enc1,
                is_dir,
                &mut dir_cache,
                cache_limit,
            )
            .unwrap();
            assert_eq!(
                dec_cached_2, rel,
                "cached RelPath hit mismatch (seed={seed:#018x})"
            );

            // Off mode is identity.
            assert_eq!(
                encrypt_rel_path(&keys, FilenameEncryption::Off, &rel).unwrap(),
                rel
            );
            assert_eq!(
                decrypt_rel_path(&keys, FilenameEncryption::Off, &rel).unwrap(),
                rel
            );
        }
    }

    #[test]
    fn prop_siv_decrypt_rejects_corrupted_truncated_and_random_inputs() {
        use crate::prop_test::{SeedGuard, rng_for, seeds_for};
        use rand::{Rng, RngExt};

        const INVALID_CHARS: &[char] = &[
            '0', '1', '8', '9', '=', '/', '\\', '-', '_', ' ', '\0', '\n', 'é', '中', '🦀',
        ];

        let seeds = seeds_for(0x5253_4849_464E_0003, 256);
        let total = seeds.len();
        for (case_idx, seed) in seeds {
            let _guard = SeedGuard::new(
                "siv_decrypt_rejects_corrupted_truncated_and_random_inputs",
                case_idx,
                total,
                seed,
            );
            let mut rng = rng_for(seed);

            let mut key_raw = [0u8; 32];
            rng.fill_bytes(&mut key_raw);
            let keys = MasterKey::from_bytes(key_raw).derive_subkeys();

            let seg_len = rng.random_range(1usize..=160);
            let seg = random_valid_segment(&mut rng, seg_len);
            let enc = encrypt_segment(&keys, &seg).unwrap();

            // 1. Mutating any base32 character to a different base32 value (including first & last
            //    char, exercising canonical padding-bit validation) must be rejected.
            for pos in [0usize, enc.len() - 1, rng.random_range(0..enc.len())] {
                let mut bytes = enc.clone().into_bytes();
                let orig = bytes[pos];
                let orig_val = B32_DECODE_LUT[orig as usize];
                let delta = rng.random_range(1u8..32);
                let new_val = (orig_val + delta) % 32;
                bytes[pos] = B32_ALPHABET[new_val as usize];
                let mutated = String::from_utf8(bytes).unwrap();
                assert!(
                    decrypt_segment(&keys, &mutated).is_err(),
                    "mutated base32 at pos={pos}/{} was NOT rejected (seg_len={seg_len}, seed={seed:#018x})",
                    enc.len()
                );
            }

            // 2. Replacing a character with an invalid base32 ASCII or multi-byte UTF-8 char.
            let bad_ch = INVALID_CHARS[rng.random_range(0..INVALID_CHARS.len())];
            let inject_pos = rng.random_range(0..enc.len());
            let mut bad_str = String::with_capacity(enc.len() + 4);
            bad_str.push_str(&enc[..inject_pos]);
            bad_str.push(bad_ch);
            bad_str.push_str(&enc[inject_pos + 1..]);
            assert!(
                decrypt_segment(&keys, &bad_str).is_err(),
                "invalid char `{bad_ch:?}` at pos={inject_pos} was NOT rejected (seed={seed:#018x})"
            );

            // 3. Truncating valid ciphertext (1 char and arbitrary prefix).
            for cut in [0usize, enc.len() - 1, rng.random_range(0..enc.len())] {
                assert!(
                    decrypt_segment(&keys, &enc[..cut]).is_err(),
                    "truncated segment len={cut}/{} was NOT rejected (seed={seed:#018x})",
                    enc.len()
                );
            }

            // 4. Appending 1..=16 random base32 chars (including dangling 1-char suffix).
            for extra in [1usize, rng.random_range(1..=16)] {
                let mut extended = enc.clone();
                for _ in 0..extra {
                    extended.push(B32_ALPHABET[rng.random_range(0..32)] as char);
                }
                assert!(
                    decrypt_segment(&keys, &extended).is_err(),
                    "extended segment +{extra} chars was NOT rejected (seed={seed:#018x})"
                );
            }

            // 5. Pure random base32 strings across edge and random lengths must never panic and return Err.
            let rand_b32_len = match case_idx {
                0 => 0,
                1 => 1,
                2 => 51,
                3 => 52,
                4 => 53,
                5 => 56,
                _ => rng.random_range(0usize..=300),
            };
            let rand_b32: String = (0..rand_b32_len)
                .map(|_| B32_ALPHABET[rng.random_range(0..32)] as char)
                .collect();
            assert!(
                decrypt_segment(&keys, &rand_b32).is_err(),
                "random base32 len={rand_b32_len} unexpectedly decrypted (seed={seed:#018x})"
            );

            // 6. Arbitrary random UTF-8 strings must never panic and return Err.
            let arb_len = rng.random_range(0usize..=120);
            let mut arb = String::with_capacity(arb_len * 2);
            for _ in 0..arb_len {
                let cp = if rng.random_bool(0.5) {
                    rng.random_range(0u32..128)
                } else {
                    rng.random_range(0u32..=0x10_FFFF)
                };
                if let Some(ch) = char::from_u32(cp) {
                    arb.push(ch);
                }
            }
            assert!(
                decrypt_segment(&keys, &arb).is_err(),
                "arbitrary UTF-8 unexpectedly decrypted (seed={seed:#018x})"
            );
        }
    }
}
