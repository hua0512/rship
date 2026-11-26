use super::super::*;
use super::{decrypt_full_ciphertext, encrypt_chunks_to_vec, sample_stream_pt_len};
use futures::StreamExt;

#[tokio::test]
async fn prop_total_chunks_matches_stream_encryptor_emitted_blocks() {
    use crate::prop_test::{SeedGuard, random_split_chunks, rng_for, seeds_for};

    let seeds = seeds_for(0x5253_4849_535A_0003, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "total_chunks_matches_stream_encryptor_emitted_blocks",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_stream_pt_len(case_idx, &mut rng);

        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce_prefix);
        let hdr = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);
        let chunks = random_split_chunks(&plaintext, &mut rng);

        let input: ByteStream = Box::pin(futures::stream::iter(chunks.into_iter().map(Ok)));
        let mut enc = StreamEncryptor::new(input, &key, hdr, 0, pt_len as u64, true, true);

        let first = enc
            .next()
            .await
            .expect("header frame must be yielded")
            .unwrap();
        assert_eq!(
            &first[..],
            &hdr.encode()[..],
            "header mismatch (seed={seed:#018x})"
        );

        let expected_chunks = total_chunks(pt_len as u64);
        let cipher = StreamCipher::new(&key, &hdr);
        let mut block_count = 0u64;
        let mut total_ct_bytes = first.len() as u64;
        let mut recovered = Vec::with_capacity(pt_len);

        while let Some(item) = enc.next().await {
            let ct_block = item.unwrap();
            total_ct_bytes += ct_block.len() as u64;
            let is_last = block_count + 1 == expected_chunks;
            let mut buf = BytesMut::from(&ct_block[..]);
            decrypt_chunk_in_place(&cipher, block_count, is_last, &mut buf).unwrap_or_else(|e| {
                panic!(
                    "block {block_count}/{expected_chunks} failed decrypt (pt_len={pt_len}, seed={seed:#018x}): {e}"
                )
            });
            recovered.extend_from_slice(&buf);
            block_count += 1;
        }

        assert_eq!(
            block_count, expected_chunks,
            "emitted block count mismatch for pt_len={pt_len} (seed={seed:#018x})"
        );
        assert_eq!(
            total_ct_bytes,
            ciphertext_size(pt_len as u64).unwrap(),
            "emitted ciphertext size mismatch for pt_len={pt_len} (seed={seed:#018x})"
        );
        assert_eq!(
            recovered, plaintext,
            "decrypted payload mismatch for pt_len={pt_len} (seed={seed:#018x})"
        );
    }
}

#[tokio::test]
async fn prop_stream_encryptor_split_and_coalesce_invariance() {
    use crate::prop_test::{SeedGuard, random_split_chunks, rng_for, seeds_for};
    use rand::RngExt;

    let seeds = seeds_for(0x5253_4849_5354_0001, 256);
    let total = seeds.len();
    const COALESCE_CHOICES: &[usize] = &[1, 2, 3, 4, 8, 16];

    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "stream_encryptor_split_and_coalesce_invariance",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_stream_pt_len(case_idx, &mut rng);

        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce_prefix);
        let hdr = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);

        // Reference single-block encryption from one contiguous buffer.
        let ref_chunks = if plaintext.is_empty() {
            vec![]
        } else {
            vec![Bytes::copy_from_slice(&plaintext)]
        };
        let ct_ref = encrypt_chunks_to_vec(&key, hdr, pt_len as u64, ref_chunks, 1)
            .await
            .unwrap();
        assert_eq!(
            ct_ref.len() as u64,
            ciphertext_size(pt_len as u64).unwrap(),
            "ciphertext length mismatch for pt_len={pt_len} (seed={seed:#018x})"
        );

        // Arbitrary split pattern + random max_blocks coalescing must produce bit-exact ciphertext.
        let split_a = random_split_chunks(&plaintext, &mut rng);
        let max_blocks = COALESCE_CHOICES[rng.random_range(0..COALESCE_CHOICES.len())];
        let ct_split = encrypt_chunks_to_vec(&key, hdr, pt_len as u64, split_a, max_blocks)
            .await
            .unwrap();
        assert_eq!(
            ct_split, ct_ref,
            "split/coalesce wire mismatch (pt_len={pt_len}, max_blocks={max_blocks}, seed={seed:#018x})"
        );

        // Roundtrip decrypt must match original plaintext bit-for-bit.
        let decrypted = decrypt_full_ciphertext(&key, &ct_split).unwrap_or_else(|e| {
            panic!("full decrypt failed (pt_len={pt_len}, seed={seed:#018x}): {e}")
        });
        assert_eq!(
            decrypted, plaintext,
            "roundtrip plaintext mismatch (pt_len={pt_len}, seed={seed:#018x})"
        );
    }
}

#[test]
fn prop_chunk_parity_with_reference_xchacha20poly1305() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use chacha20poly1305::aead::AeadInOut;
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    use rand::RngExt;

    let seeds = seeds_for(0x5253_4849_5354_0002, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "chunk_parity_with_reference_xchacha20poly1305",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);

        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce_prefix);
        let hdr = StreamHeader::from_nonce_prefix(nonce_prefix);

        let chunk_idx = match case_idx {
            0 => 0u64,
            1 => 1u64,
            2 => (1u64 << 56) - 1,
            _ => rng.random::<u64>() & ((1u64 << 56) - 1),
        };
        let is_last = rng.random_bool(0.5);
        let pt_len = match case_idx {
            0 => 0usize,
            1 => 1,
            2 => PLAINTEXT_CHUNK_LEN,
            3 => PLAINTEXT_CHUNK_LEN - 1,
            _ => match rng.random_range(0u8..4) {
                0 => rng.random_range(0..=64),
                1 => PLAINTEXT_CHUNK_LEN,
                _ => rng.random_range(0..=PLAINTEXT_CHUNK_LEN),
            },
        };
        let mut pt = vec![0u8; pt_len];
        rng.fill_bytes(&mut pt);

        // Reference XChaCha20-Poly1305 wire bytes.
        let mut xnonce = [0u8; 24];
        xnonce[0..16].copy_from_slice(&nonce_prefix);
        let idx_le = chunk_idx.to_le_bytes();
        xnonce[16..23].copy_from_slice(&idx_le[0..7]);
        xnonce[23] = if is_last { 0x01 } else { 0x00 };

        let mut aad = [0u8; 21];
        aad[0..12].copy_from_slice(&HEADER_AAD_PREFIX);
        aad[12..20].copy_from_slice(&idx_le);
        aad[20] = if is_last { 0x01 } else { 0x00 };

        let ref_cipher = XChaCha20Poly1305::new((&key).into());
        let mut expected = pt.clone();
        let ref_tag = ref_cipher
            .encrypt_inout_detached(&XNonce::from(xnonce), &aad, expected.as_mut_slice().into())
            .unwrap();
        expected.extend_from_slice(ref_tag.as_slice());

        // Both allocating and in-place paths must match bit-for-bit.
        let ct_alloc = encrypt_chunk(&key, &hdr, chunk_idx, is_last, &pt).unwrap();
        assert_eq!(
            ct_alloc, expected,
            "encrypt_chunk mismatch (seed={seed:#018x})"
        );
        assert_eq!(
            decrypt_chunk(&key, &hdr, chunk_idx, is_last, &ct_alloc).unwrap(),
            pt,
            "decrypt_chunk mismatch (seed={seed:#018x})"
        );

        let cipher = StreamCipher::new(&key, &hdr);
        let mut buf = BytesMut::with_capacity(pt.len() + TAG_LEN);
        buf.extend_from_slice(&pt);
        encrypt_chunk_in_place(&cipher, chunk_idx, is_last, &mut buf).unwrap();
        assert_eq!(
            &buf[..],
            &expected[..],
            "encrypt_chunk_in_place mismatch (seed={seed:#018x})"
        );
        decrypt_chunk_in_place(&cipher, chunk_idx, is_last, &mut buf).unwrap();
        assert_eq!(
            &buf[..],
            &pt[..],
            "decrypt_chunk_in_place mismatch (seed={seed:#018x})"
        );

        // 56-bit chunk counter overflow must always return Err.
        let overflow_idx = (1u64 << 56) | (chunk_idx & 0xFFFF);
        assert!(
            encrypt_chunk(&key, &hdr, overflow_idx, is_last, &pt[..pt.len().min(16)]).is_err(),
            "56-bit counter overflow must fail (seed={seed:#018x})"
        );
    }
}

#[tokio::test]
async fn prop_tamper_single_bit_flip_always_rejected() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use rand::RngExt;

    // 1. Exhaustive single-bit flip across EVERY bit of 0-byte and 1-byte ciphertexts
    //    (covers all 256 bits of the 32-byte header including magic, version, cipher,
    //    reserved flags [10..12], nonce prefix [12..28], chunk size [28..32], body, and tag).
    {
        let key = [0xA5u8; 32];
        let hdr = StreamHeader::from_nonce_prefix([0x3Cu8; 16]);
        for pt in [&[][..], &[0x7Fu8][..]] {
            let chunks = if pt.is_empty() {
                vec![]
            } else {
                vec![Bytes::copy_from_slice(pt)]
            };
            let ct = encrypt_chunks_to_vec(&key, hdr, pt.len() as u64, chunks, 1)
                .await
                .unwrap();
            assert_eq!(decrypt_full_ciphertext(&key, &ct).unwrap(), pt);

            for byte_idx in 0..ct.len() {
                for bit in 0..8u8 {
                    let mut tampered = ct.clone();
                    tampered[byte_idx] ^= 1u8 << bit;
                    assert!(
                        decrypt_full_ciphertext(&key, &tampered).is_err(),
                        "single-bit flip accepted at pt_len={}, byte_idx={byte_idx}, bit={bit}",
                        pt.len()
                    );
                }
            }
        }
    }

    // 2. Seeded single-bit flips across 0-byte, 1-byte, single-block, and multi-block ciphertexts.
    let seeds = seeds_for(0x5253_4849_544D_0001, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "tamper_single_bit_flip_always_rejected",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_stream_pt_len(case_idx, &mut rng);

        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce_prefix);
        let hdr = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);
        let chunks = if plaintext.is_empty() {
            vec![]
        } else {
            vec![Bytes::copy_from_slice(&plaintext)]
        };
        let ct = encrypt_chunks_to_vec(&key, hdr, pt_len as u64, chunks, 4)
            .await
            .unwrap();

        // Target positions covering: header, nonce prefix, body (if non-empty),
        // non-final tag (if multi-block), final tag, and an arbitrary byte.
        let mut targets = vec![
            rng.random_range(0..HEADER_LEN),                  // any header byte
            rng.random_range(12..28),                         // nonce prefix byte
            rng.random_range(0..12), // magic / version / cipher / reserved flags
            rng.random_range(28..HEADER_LEN), // chunk size field
            rng.random_range((ct.len() - TAG_LEN)..ct.len()), // final Poly1305 tag
            rng.random_range(0..ct.len()), // arbitrary position
        ];
        if pt_len > 0 {
            // Random byte inside the ciphertext body (not header, not final tag).
            let body_pos = rng.random_range(HEADER_LEN..(ct.len() - TAG_LEN));
            targets.push(body_pos);
        }
        if pt_len > PLAINTEXT_CHUNK_LEN {
            // Tag of the first non-final chunk.
            let first_tag_start = HEADER_LEN + PLAINTEXT_CHUNK_LEN;
            targets.push(rng.random_range(first_tag_start..(first_tag_start + TAG_LEN)));
        }

        for pos in targets {
            let bit = rng.random_range(0u8..8);
            let mut tampered = ct.clone();
            tampered[pos] ^= 1u8 << bit;
            assert!(
                decrypt_full_ciphertext(&key, &tampered).is_err(),
                "bit flip was NOT rejected (pt_len={pt_len}, pos={pos}/{}, bit={bit}, seed={seed:#018x})",
                ct.len()
            );
        }

        // Flipping any bit in the decryption key must also fail authentication.
        let mut wrong_key = key;
        let key_bit = rng.random_range(0usize..256);
        wrong_key[key_bit / 8] ^= 1u8 << (key_bit % 8);
        assert!(
            decrypt_full_ciphertext(&wrong_key, &ct).is_err(),
            "wrong key was NOT rejected (pt_len={pt_len}, key_bit={key_bit}, seed={seed:#018x})"
        );
    }
}

#[tokio::test]
async fn prop_tamper_truncation_swap_and_append_rejected() {
    use crate::prop_test::{SeedGuard, rng_for, seeds_for};
    use rand::RngExt;

    // 1. Exhaustive truncation across every length 0..ct.len() for 0-byte and 1-byte files.
    {
        let key = [0x5Au8; 32];
        let hdr = StreamHeader::from_nonce_prefix([0xC3u8; 16]);
        for pt in [&[][..], &[0x42u8][..]] {
            let chunks = if pt.is_empty() {
                vec![]
            } else {
                vec![Bytes::copy_from_slice(pt)]
            };
            let ct = encrypt_chunks_to_vec(&key, hdr, pt.len() as u64, chunks, 1)
                .await
                .unwrap();
            for cut in 0..ct.len() {
                assert!(
                    decrypt_full_ciphertext(&key, &ct[..cut]).is_err(),
                    "truncation to {cut}/{} bytes accepted (pt_len={})",
                    ct.len(),
                    pt.len()
                );
            }
        }
    }

    // 2. Seeded truncation, chunk swapping/duplication, and trailing-byte append attacks.
    let seeds = seeds_for(0x5253_4849_544D_0002, 256);
    let total = seeds.len();
    for (case_idx, seed) in seeds {
        let _guard = SeedGuard::new(
            "tamper_truncation_swap_and_append_rejected",
            case_idx,
            total,
            seed,
        );
        let mut rng = rng_for(seed);
        let pt_len = sample_stream_pt_len(case_idx, &mut rng);

        let mut key = [0u8; 32];
        let mut nonce_prefix = [0u8; 16];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce_prefix);
        let hdr = StreamHeader::from_nonce_prefix(nonce_prefix);

        let mut plaintext = vec![0u8; pt_len];
        rng.fill_bytes(&mut plaintext);
        let chunks = if plaintext.is_empty() {
            vec![]
        } else {
            vec![Bytes::copy_from_slice(&plaintext)]
        };
        let ct = encrypt_chunks_to_vec(&key, hdr, pt_len as u64, chunks, 4)
            .await
            .unwrap();

        // (a) Truncating any random suffix 1..ct.len() (plus targeted boundaries).
        let mut trunc_suffixes = vec![
            1usize,
            TAG_LEN.min(ct.len() - 1),
            rng.random_range(1..ct.len()),
            rng.random_range(1..ct.len()),
            ct.len() - rng.random_range(0..HEADER_LEN), // mid-header truncation
        ];
        let n_chunks = total_chunks(pt_len as u64) as usize;
        if n_chunks >= 2 {
            // Drop exact final chunk so remaining length is valid for (n_chunks - 1) full chunks!
            // Only STREAM OAE2 `is_last` binding catches this silent truncation attack.
            let last_block_ct_len = ct.len() - (HEADER_LEN + (n_chunks - 1) * CIPHERTEXT_CHUNK_LEN);
            trunc_suffixes.push(last_block_ct_len);
        }
        for suffix in trunc_suffixes {
            let cut = ct.len() - suffix;
            assert!(
                decrypt_full_ciphertext(&key, &ct[..cut]).is_err(),
                "truncating suffix={suffix} (cut={cut}/{}) was NOT rejected (pt_len={pt_len}, seed={seed:#018x})",
                ct.len()
            );
        }

        // (b) Chunk swapping and duplication for multi-block ciphertexts.
        if n_chunks >= 2 {
            let mut block_slices: Vec<&[u8]> = Vec::with_capacity(n_chunks);
            let mut offset = HEADER_LEN;
            for idx in 0..n_chunks {
                let end = if idx + 1 == n_chunks {
                    ct.len()
                } else {
                    offset + CIPHERTEXT_CHUNK_LEN
                };
                block_slices.push(&ct[offset..end]);
                offset = end;
            }

            // Swap two distinct random chunks (rebuilding header + swapped blocks).
            let i = rng.random_range(0..n_chunks);
            let mut j = rng.random_range(0..(n_chunks - 1));
            if j >= i {
                j += 1;
            }
            let mut swapped_blocks = block_slices.clone();
            swapped_blocks.swap(i, j);
            let mut swapped_ct = Vec::with_capacity(ct.len());
            swapped_ct.extend_from_slice(&ct[..HEADER_LEN]);
            for blk in &swapped_blocks {
                swapped_ct.extend_from_slice(blk);
            }
            assert_eq!(swapped_ct.len(), ct.len());
            assert!(
                decrypt_full_ciphertext(&key, &swapped_ct).is_err(),
                "swapping chunks ({i}, {j}) of {n_chunks} was NOT rejected (pt_len={pt_len}, seed={seed:#018x})"
            );

            // If >= 2 full-size blocks exist, also test duplicating one full block into another.
            if n_chunks >= 3 || block_slices[n_chunks - 1].len() == CIPHERTEXT_CHUNK_LEN {
                let full_count = if block_slices[n_chunks - 1].len() == CIPHERTEXT_CHUNK_LEN {
                    n_chunks
                } else {
                    n_chunks - 1
                };
                let src_blk = rng.random_range(0..full_count);
                let mut dst_blk = rng.random_range(0..(full_count - 1));
                if dst_blk >= src_blk {
                    dst_blk += 1;
                }
                let mut dup_blocks = block_slices.clone();
                dup_blocks[dst_blk] = dup_blocks[src_blk];
                let mut dup_ct = Vec::with_capacity(ct.len());
                dup_ct.extend_from_slice(&ct[..HEADER_LEN]);
                for blk in &dup_blocks {
                    dup_ct.extend_from_slice(blk);
                }
                assert!(
                    decrypt_full_ciphertext(&key, &dup_ct).is_err(),
                    "duplicating chunk {src_blk} into {dst_blk} was NOT rejected (pt_len={pt_len}, seed={seed:#018x})"
                );
            }
        }

        // (c) Appending trailing bytes (1 byte, small random, medium random, full extra block).
        let mut append_lens = vec![
            1usize,
            rng.random_range(1..=TAG_LEN),
            rng.random_range((TAG_LEN + 1)..=512),
            CIPHERTEXT_CHUNK_LEN,
        ];
        for extra_len in append_lens.drain(..) {
            let mut appended = ct.clone();
            let start = appended.len();
            appended.resize(start + extra_len, 0);
            rng.fill_bytes(&mut appended[start..]);
            assert!(
                decrypt_full_ciphertext(&key, &appended).is_err(),
                "appending {extra_len} random trailing bytes was NOT rejected (pt_len={pt_len}, seed={seed:#018x})"
            );
        }
        // Also append a real authenticated chunk (duplicate of chunk 0) onto the end.
        if ct.len() >= HEADER_LEN + CIPHERTEXT_CHUNK_LEN {
            let mut appended = ct.clone();
            appended.extend_from_slice(&ct[HEADER_LEN..HEADER_LEN + CIPHERTEXT_CHUNK_LEN]);
            assert!(
                decrypt_full_ciphertext(&key, &appended).is_err(),
                "appending duplicate chunk 0 was NOT rejected (pt_len={pt_len}, seed={seed:#018x})"
            );
        }
    }
}
