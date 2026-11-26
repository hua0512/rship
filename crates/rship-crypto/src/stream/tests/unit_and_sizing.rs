use super::super::*;
use futures::StreamExt;

#[test]
fn ciphertext_and_plaintext_size_math_is_bijective_and_rejects_corrupt_lengths() {
    for pt in [
        0u64,
        1,
        15,
        16,
        65535,
        65536,
        65537,
        65536 * 2,
        65536 * 3 + 12345,
        10 * 1024 * 1024,
    ] {
        let ct = ciphertext_size(pt).unwrap();
        assert_eq!(
            plaintext_size(ct).unwrap(),
            pt,
            "round-trip failed for pt={pt}"
        );
    }
    assert!(plaintext_size(0).is_err());
    assert!(plaintext_size(47).is_err());
    assert!(plaintext_size(32 + 65552 + 10).is_err()); // partial tag
    assert!(plaintext_size(32 + 65552 + 16).is_err()); // empty trailing block after full block
}

#[test]
fn oae2_rejects_bit_flip_chunk_swap_and_truncation() {
    let key = [0x42u8; 32];
    let hdr = StreamHeader::generate_random();

    let c0 = encrypt_chunk(&key, &hdr, 0, false, b"chunk zero").unwrap();
    let c1 = encrypt_chunk(&key, &hdr, 1, true, b"chunk one").unwrap();

    assert_eq!(
        decrypt_chunk(&key, &hdr, 0, false, &c0).unwrap(),
        b"chunk zero"
    );
    assert_eq!(
        decrypt_chunk(&key, &hdr, 1, true, &c1).unwrap(),
        b"chunk one"
    );

    // 1. Single bit flip rejected!
    let mut flipped = c0.clone();
    flipped[3] ^= 0x01;
    assert!(decrypt_chunk(&key, &hdr, 0, false, &flipped).is_err());

    // 2. Chunk reordering (swapping chunk 0 and chunk 1) rejected!
    assert!(decrypt_chunk(&key, &hdr, 1, false, &c0).is_err());
    assert!(decrypt_chunk(&key, &hdr, 0, true, &c1).is_err());

    // 3. Silent truncation (claiming chunk 0 is the final chunk) rejected!
    assert!(decrypt_chunk(&key, &hdr, 0, true, &c0).is_err());
}

#[test]
fn in_place_aead_matches_wire_format_and_clears_buffer_on_tamper() {
    let key = [0x5Au8; 32];
    let hdr = StreamHeader::generate_random();
    let cipher = StreamCipher::new(&key, &hdr);

    for (idx, is_last, payload) in [
        (0u64, true, vec![]),
        (0u64, false, vec![0x11u8; PLAINTEXT_CHUNK_LEN]),
        (7u64, true, b"partial trailing block".to_vec()),
    ] {
        let expected_ct = encrypt_chunk(&key, &hdr, idx, is_last, &payload).unwrap();

        let mut buf = BytesMut::with_capacity(payload.len() + TAG_LEN);
        buf.extend_from_slice(&payload);
        let ptr_before = buf.as_ptr();
        encrypt_chunk_in_place(&cipher, idx, is_last, &mut buf).unwrap();
        assert_eq!(
            buf.as_ptr(),
            ptr_before,
            "in-place encrypt must not reallocate"
        );
        assert_eq!(&buf[..], &expected_ct[..]);

        decrypt_chunk_in_place(&cipher, idx, is_last, &mut buf).unwrap();
        assert_eq!(&buf[..], &payload[..]);

        // Tampered ciphertext must fail auth AND leave buffer empty/scrubbed.
        let mut bad = BytesMut::from(&expected_ct[..]);
        bad[0] ^= 0x80;
        assert!(decrypt_chunk_in_place(&cipher, idx, is_last, &mut bad).is_err());
        assert!(bad.is_empty());
    }
}

#[test]
fn aws_lc_hchacha20_matches_reference_xchacha20poly1305_bit_exact() {
    use chacha20poly1305::aead::AeadInOut;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

    let key = [0xC3u8; 32];
    let hdr = StreamHeader::from_nonce_prefix([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    let ref_cipher = XChaCha20Poly1305::new((&key).into());
    let fast_cipher = StreamCipher::new(&key, &hdr);

    for (idx, is_last, payload) in [
        (0u64, true, vec![]),
        (0u64, false, b"hello rship wire parity".to_vec()),
        (
            42u64,
            false,
            (0..PLAINTEXT_CHUNK_LEN).map(|i| (i * 17) as u8).collect(),
        ),
        (0x0001_2345_6789_ABCDu64, true, b"high chunk index".to_vec()),
    ] {
        let mut xnonce = [0u8; 24];
        xnonce[0..16].copy_from_slice(&hdr.nonce_prefix);
        let idx_le = idx.to_le_bytes();
        xnonce[16..23].copy_from_slice(&idx_le[0..7]);
        xnonce[23] = if is_last { 0x01 } else { 0x00 };

        let mut aad = [0u8; 21];
        aad[0..12].copy_from_slice(&HEADER_AAD_PREFIX);
        aad[12..20].copy_from_slice(&idx_le);
        aad[20] = if is_last { 0x01 } else { 0x00 };

        let mut ref_ct = payload.clone();
        let ref_tag = ref_cipher
            .encrypt_inout_detached(&XNonce::from(xnonce), &aad, ref_ct.as_mut_slice().into())
            .unwrap();
        ref_ct.extend_from_slice(ref_tag.as_slice());

        let mut fast_buf = BytesMut::with_capacity(payload.len() + TAG_LEN);
        fast_buf.extend_from_slice(&payload);
        encrypt_chunk_in_place(&fast_cipher, idx, is_last, &mut fast_buf).unwrap();

        assert_eq!(
            &fast_buf[..],
            &ref_ct[..],
            "aws-lc-rs + HChaCha20 must be bit-for-bit identical to XChaCha20Poly1305 for idx={idx}"
        );

        decrypt_chunk_in_place(&fast_cipher, idx, is_last, &mut fast_buf).unwrap();
        assert_eq!(&fast_buf[..], &payload[..]);
    }
}

#[tokio::test]
async fn stream_encryptor_reclaims_single_block_allocation_when_chunks_consumed() {
    let key = [0x99u8; 32];
    let hdr = StreamHeader::generate_random();
    // 8 × 64 KiB = 512 KiB fed as two 256 KiB slabs (matching BufferPool slabs).
    let slab1 = Bytes::from(vec![0xA5u8; 256 * 1024]);
    let slab2 = Bytes::from(vec![0x5Au8; 256 * 1024]);
    let input: ByteStream = Box::pin(futures::stream::iter(vec![Ok(slab1), Ok(slab2)]));

    let mut enc = StreamEncryptor::new(input, &key, hdr, 0, 512 * 1024, true, true);

    let first = enc.next().await.unwrap().unwrap();
    assert_eq!(&first[..], &hdr.encode()[..]);
    drop(first);

    let cipher = StreamCipher::new(&key, &hdr);
    let mut first_block_ptr: Option<*const u8> = None;
    let mut reclaimed_hits = 0usize;

    for idx in 0..8u64 {
        let ct = enc.next().await.unwrap().unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_CHUNK_LEN);
        match first_block_ptr {
            None => first_block_ptr = Some(ct.as_ptr()),
            Some(p) if ct.as_ptr() == p => reclaimed_hits += 1,
            _ => {}
        }
        let mut verify = BytesMut::from(&ct[..]);
        drop(ct); // Sink finished writing before next poll!
        decrypt_chunk_in_place(&cipher, idx, idx == 7, &mut verify).unwrap();
        let expected_byte = if idx < 4 { 0xA5u8 } else { 0x5Au8 };
        assert!(verify.iter().all(|&b| b == expected_byte));
    }
    assert!(enc.next().await.is_none());
    assert_eq!(
        reclaimed_hits, 7,
        "all 7 subsequent 64 KiB encrypted blocks must reclaim the exact same buffer without malloc"
    );
}

#[tokio::test]
async fn coalesced_stream_encryptor_matches_single_block_wire_bytes() {
    let key = [0x77u8; 32];
    let hdr = StreamHeader::generate_random();

    for total_len in [0usize, 1, 65_536, 65_537, 512 * 1024, 1_300_123] {
        let payload: Vec<u8> = (0..total_len).map(|i| ((i * 31 + 7) % 251) as u8).collect();
        // Feed in awkward unaligned 100 KiB chunks to exercise both direct-slice and partial-block paths!
        let chunks_ref: Vec<Result<Bytes>> = if payload.is_empty() {
            vec![]
        } else {
            payload
                .chunks(100 * 1024)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect()
        };
        let chunks_fast: Vec<Result<Bytes>> = if payload.is_empty() {
            vec![]
        } else {
            payload
                .chunks(100 * 1024)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect()
        };

        let mut ref_enc = StreamEncryptor::new(
            Box::pin(futures::stream::iter(chunks_ref)),
            &key,
            hdr,
            0,
            total_len as u64,
            true,
            true,
        );
        let mut fast_enc = StreamEncryptor::with_coalesced_blocks(
            Box::pin(futures::stream::iter(chunks_fast)),
            &key,
            hdr,
            0,
            total_len as u64,
            true,
            true,
            8,
        );

        let mut ref_out = Vec::new();
        while let Some(b) = ref_enc.next().await {
            ref_out.extend_from_slice(&b.unwrap());
        }
        let mut fast_out = Vec::new();
        let mut fast_frames = 0usize;
        while let Some(b) = fast_enc.next().await {
            fast_frames += 1;
            fast_out.extend_from_slice(&b.unwrap());
        }

        assert_eq!(fast_out, ref_out, "wire mismatch for total_len={total_len}");
        if total_len >= 512 * 1024 {
            assert!(
                fast_frames <= 4,
                "expected coalesced frames (got {fast_frames} for {total_len} bytes)"
            );
        }
    }
}

#[tokio::test]
async fn stream_encryptor_releases_empty_pooled_slabs_under_1slab_pool() {
    use rship_core::buffer::BufferPool;
    use rship_core::source::{MemorySource, SeekableSource, bounded_range_stream};
    use std::sync::Arc;
    use std::time::Duration;

    let key = [0x66u8; 32];
    let hdr = StreamHeader::generate_random();
    let payload: Vec<u8> = (0..700_137).map(|i| ((i * 31 + 19) % 251) as u8).collect();
    let src: Arc<dyn SeekableSource> = Arc::new(MemorySource::new(payload.clone()));

    // Test single-block (max_blocks=1), inline coalesced (4), and pipelined coalesced (8)
    // across both 64 KiB-aligned (256 KiB) and unaligned (100 KiB) 1-slab pools.
    for slab_size in [256 * 1024usize, 100 * 1024usize] {
        for max_blocks in [1usize, 4, 8] {
            let pool = BufferPool::new(slab_size, slab_size).unwrap();
            let input = bounded_range_stream(src.clone(), 0, payload.len() as u64, pool.clone());
            let mut enc = StreamEncryptor::with_coalesced_blocks(
                input,
                &key,
                hdr,
                0,
                payload.len() as u64,
                true,
                true,
                max_blocks,
            );
            let ct = tokio::time::timeout(Duration::from_secs(5), async {
                let mut out = Vec::new();
                while let Some(item) = enc.next().await {
                    out.extend_from_slice(&item?);
                }
                Ok::<_, Error>(out)
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "StreamEncryptor deadlocked under 1-slab pool (slab_size={slab_size}, max_blocks={max_blocks})"
                )
            })
            .unwrap();

            assert_eq!(
                ct.len() as u64,
                ciphertext_size(payload.len() as u64).unwrap()
            );
            assert_eq!(pool.available_bytes(), pool.max_bytes());
            assert_eq!(pool.stats().in_use_bytes(), 0);
        }
    }
}

#[test]
fn prop_size_bijection_monotonicity_and_overflow_safety() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use rand::RngExt;

    let pt_chunk = PLAINTEXT_CHUNK_LEN as u64;
    let hdr = HEADER_LEN as u64;
    let tag = TAG_LEN as u64;

    let check_valid_pt = |pt: u64, ctx: &str| {
        let ct = ciphertext_size(pt)
            .unwrap_or_else(|e| panic!("ciphertext_size({pt}) failed ({ctx}): {e}"));
        let expected_ct = hdr
            .checked_add(pt)
            .and_then(|v| v.checked_add(total_chunks(pt).checked_mul(tag)?))
            .expect("valid pt fits algebraic overhead formula");
        assert_eq!(
            ct, expected_ct,
            "overhead formula mismatch for pt={pt} ({ctx})"
        );
        assert_eq!(
            plaintext_size(ct)
                .unwrap_or_else(|e| panic!("plaintext_size({ct}) failed ({ctx}): {e}")),
            pt,
            "bijection failed for pt={pt}, ct={ct} ({ctx})"
        );
        if pt > 0 {
            let prev_ct = ciphertext_size(pt - 1).unwrap();
            assert!(
                prev_ct < ct,
                "strict monotonicity failed at pt={pt}: ct({})={prev_ct} >= ct({pt})={ct} ({ctx})",
                pt - 1
            );
        }
    };

    // 1. Exhaustive boundary values and neighborhoods around chunk multiples.
    let mut boundaries = vec![
        0u64,
        1,
        2,
        15,
        16,
        17,
        31,
        32,
        33,
        47,
        48,
        49,
        pt_chunk - 1,
        pt_chunk,
        pt_chunk + 1,
        2 * pt_chunk - 1,
        2 * pt_chunk,
        2 * pt_chunk + 1,
        3 * pt_chunk - 1,
        3 * pt_chunk,
        3 * pt_chunk + 1,
        1_000_000,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX / 4,
        u64::MAX / 2 - 1,
        u64::MAX / 2,
        u64::MAX / 2 + 1,
    ];
    for n in 0..=1024u64 {
        boundaries.push(n);
    }
    for k in 1..=15u64 {
        let center = k * pt_chunk;
        for delta in 0..=32u64 {
            boundaries.push(center - delta);
            boundaries.push(center + delta);
        }
    }
    for pt in boundaries {
        check_valid_pt(pt, "boundary");
    }

    // 2. Exact overflow boundary near u64::MAX (must never panic or wrap).
    let mut max_valid_ct = u64::MAX;
    while plaintext_size(max_valid_ct).is_err() {
        max_valid_ct -= 1;
    }
    let max_valid_pt = plaintext_size(max_valid_ct).unwrap();
    check_valid_pt(max_valid_pt, "max_valid_pt");
    assert!(
        ciphertext_size(max_valid_pt + 1).is_err(),
        "pt above u64 ciphertext limit must return Err"
    );
    for overflow_pt in [
        max_valid_pt + 1,
        max_valid_pt.saturating_add(pt_chunk),
        u64::MAX - pt_chunk,
        u64::MAX - 1,
        u64::MAX,
    ] {
        assert!(
            ciphertext_size(overflow_pt).is_err(),
            "overflow pt={overflow_pt} must return Err"
        );
        // total_chunks must also never overflow even at u64::MAX.
        assert!(total_chunks(overflow_pt) >= 1);
    }

    // 3. Seeded sweep over thousands of plaintext lengths spanning 0..=1_000_000 and large u64s.
    let seeds = seeds_for(0x5253_4849_535A_0001, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "size_bijection_monotonicity_and_overflow_safety",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);

        // 32 random lengths in 0..=1_000_000 per case (8,192 lengths at default 256 cases).
        let mut sampled: Vec<u64> = (0..32)
            .map(|_| rng.random_range(0u64..=1_000_000))
            .collect();
        // Plus 4 large lengths spanning up to u64::MAX / 2 and near max_valid_pt.
        sampled.push(rng.random_range(0u64..=(u64::MAX / 2)));
        sampled.push(rng.random_range((u64::MAX / 2)..=max_valid_pt));
        sampled.sort_unstable();
        sampled.dedup();

        let mut prev: Option<(u64, u64)> = None;
        for pt in sampled {
            check_valid_pt(pt, &format!("seed={seed:#018x}"));
            let ct = ciphertext_size(pt).unwrap();
            if let Some((prev_pt, prev_ct)) = prev {
                assert!(
                    prev_ct < ct,
                    "monotonicity violated: pt {prev_pt} < {pt} gave ct {prev_ct} >= {ct} (seed={seed:#018x})"
                );
            }
            prev = Some((pt, ct));
        }
    }
}

#[test]
fn prop_invalid_ciphertext_sizes_rejected_without_panic() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use rand::RngExt;

    let hdr = HEADER_LEN as u64;
    let ct_chunk = CIPHERTEXT_CHUNK_LEN as u64;
    let tag = TAG_LEN as u64;

    // Every length strictly below HEADER_LEN + TAG_LEN (48 bytes) is invalid.
    for short in 0..(hdr + tag) {
        assert!(
            plaintext_size(short).is_err(),
            "short ciphertext length {short} must return Err"
        );
    }
    assert_eq!(plaintext_size(hdr + tag).unwrap(), 0);

    let max_k = (u64::MAX - hdr) / ct_chunk;
    let check_k = |k: u64, ctx: &str| {
        let base = hdr + k * ct_chunk;
        // Exact multiple of full chunks (r == 0) is valid.
        let pt_exact = plaintext_size(base)
            .unwrap_or_else(|e| panic!("expected valid ct={base} for k={k} ({ctx}): {e}"));
        assert_eq!(
            ciphertext_size(pt_exact).unwrap(),
            base,
            "reverse bijection failed for k={k}, r=0 ({ctx})"
        );

        // Every trailing remainder r in 1..=TAG_LEN (partial tag OR empty trailing block) is invalid.
        for r in 1..=tag {
            if let Some(bad_ct) = base.checked_add(r) {
                assert!(
                    plaintext_size(bad_ct).is_err(),
                    "invalid ct={bad_ct} (k={k}, r={r}) must return Err ({ctx})"
                );
            }
        }

        // Valid trailing block boundaries (r == TAG_LEN + 1 and r == CIPHERTEXT_CHUNK_LEN - 1).
        for r in [tag + 1, ct_chunk - 1] {
            if let Some(valid_ct) = base.checked_add(r) {
                let pt = plaintext_size(valid_ct).unwrap_or_else(|e| {
                    panic!("expected valid ct={valid_ct} (k={k}, r={r}) ({ctx}): {e}")
                });
                assert_eq!(
                    ciphertext_size(pt).unwrap(),
                    valid_ct,
                    "reverse bijection failed for k={k}, r={r} ({ctx})"
                );
            }
        }
    };

    for k in [1u64, 2, 3, 4, 16, 1024, max_k - 1, max_k] {
        check_k(k, "boundary_k");
    }

    let seeds = seeds_for(0x5253_4849_535A_0002, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "invalid_ciphertext_sizes_rejected_without_panic",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);

        // Random small and huge chunk counts k.
        let k_small = rng.random_range(1u64..=10_000);
        let k_large = rng.random_range(1u64..=max_k);
        check_k(k_small, &format!("seed={seed:#018x}"));
        check_k(k_large, &format!("seed={seed:#018x}"));

        // Arbitrary u64 probes must never panic and satisfy reverse bijection whenever Ok.
        for _ in 0..32 {
            let ct: u64 = rng.random();
            if let Ok(pt) = plaintext_size(ct) {
                assert_eq!(
                    ciphertext_size(pt).unwrap(),
                    ct,
                    "reverse bijection failed for ct={ct}, pt={pt} (seed={seed:#018x})"
                );
            }
        }
    }
}

#[test]
fn max_plaintext_for_ciphertext_boundaries_and_tightness() {
    for limit in 0u64..=47 {
        assert_eq!(
            max_plaintext_for_ciphertext(limit),
            0,
            "limit={limit} < 48 cannot fit even a 0-byte encrypted file"
        );
    }

    assert_eq!(max_plaintext_for_ciphertext(48), 0);
    assert_eq!(max_plaintext_for_ciphertext(49), 1);
    assert_eq!(max_plaintext_for_ciphertext(65_536), 65_488);
    assert_eq!(max_plaintext_for_ciphertext(65_583), 65_535);
    assert_eq!(max_plaintext_for_ciphertext(65_584), 65_536);

    for limit in 65_585u64..=65_600 {
        assert_eq!(
            max_plaintext_for_ciphertext(limit),
            65_536,
            "limit={limit} lacks 16B tag + 1B plaintext for a second block"
        );
    }
    assert_eq!(max_plaintext_for_ciphertext(65_601), 65_537);
    assert_eq!(max_plaintext_for_ciphertext(4 * 1024 * 1024), 4_193_248);
    assert_eq!(max_plaintext_for_ciphertext(5 * 1024 * 1024), 5_241_568);
    assert_eq!(max_plaintext_for_ciphertext(16 * 1024 * 1024), 16_773_088);

    for limit in [
        48u64,
        49,
        65_536,
        65_583,
        65_584,
        65_600,
        65_601,
        4 * 1024 * 1024,
        5 * 1024 * 1024,
        16 * 1024 * 1024,
        u64::MAX,
    ] {
        let pt = max_plaintext_for_ciphertext(limit);
        let ct = ciphertext_size(pt).unwrap();
        assert!(
            ct <= limit,
            "ciphertext_size({pt})={ct} exceeded limit={limit}"
        );
        if let Some(next_pt) = pt.checked_add(1)
            && let Ok(next_ct) = ciphertext_size(next_pt)
        {
            assert!(
                next_ct > limit,
                "max_plaintext_for_ciphertext({limit})={pt} is not tight: ct({next_pt})={next_ct} <= {limit}"
            );
        }
    }
}
