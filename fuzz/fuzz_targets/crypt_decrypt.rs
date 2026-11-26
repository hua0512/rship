#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use rship_crypto::filename::decrypt_segment;
use rship_crypto::keys::MasterKey;
use rship_crypto::stream::{
    HEADER_LEN, PLAINTEXT_CHUNK_LEN, StreamCipher, StreamHeader, ciphertext_size, decrypt_chunk,
    decrypt_chunk_in_place, encrypt_chunk, plaintext_size, total_chunks,
};

fuzz_target!(|data: &[u8]| {
    // Fixed deterministic key material so fuzzing focuses on framing, AEAD auth,
    // and boundary checks without spending time in Argon2id KDF.
    let data_key = [0x42u8; 32];
    let keys = MasterKey::from_bytes(data_key).derive_subkeys();

    // 1. Fuzz header decoding on arbitrary bytes (must never panic).
    let decoded_header = StreamHeader::decode(data);
    if let Ok(hdr) = decoded_header {
        let reencoded = hdr.encode();
        assert_eq!(StreamHeader::decode(&reencoded).unwrap(), hdr);
    }

    // 2. Fuzz length arithmetic on arbitrary 64-bit values derived from input.
    if data.len() >= 8 {
        let n = u64::from_le_bytes(data[..8].try_into().unwrap());
        let _ = total_chunks(n);
        if let Ok(ct) = ciphertext_size(n) {
            assert_eq!(plaintext_size(ct).unwrap(), n);
        }
        let _ = plaintext_size(n);
    }

    // 3. Fuzz chunk decryption (both allocating and in-place paths) on arbitrary
    //    tampered bytes with arbitrary chunk_idx, is_last flag, and nonce prefix.
    let header = match decoded_header {
        Ok(h) => h,
        Err(_) => {
            let mut nonce_prefix = [0u8; 16];
            let take = data.len().min(16);
            nonce_prefix[..take].copy_from_slice(&data[..take]);
            StreamHeader::from_nonce_prefix(nonce_prefix)
        }
    };
    let cipher = StreamCipher::new(&data_key, &header);

    let (chunk_idx, is_last, body) = if data.len() > HEADER_LEN + 9 {
        let idx = u64::from_le_bytes(data[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap());
        let last = (data[HEADER_LEN + 8] & 1) != 0;
        (idx, last, &data[HEADER_LEN + 9..])
    } else if data.len() >= 9 {
        let idx = u64::from_le_bytes(data[..8].try_into().unwrap());
        let last = (data[8] & 1) != 0;
        (idx, last, &data[9..])
    } else {
        (0u64, true, data)
    };

    let _ = decrypt_chunk(&data_key, &header, chunk_idx, is_last, body);

    let mut in_place = BytesMut::from(body);
    if decrypt_chunk_in_place(&cipher, chunk_idx, is_last, &mut in_place).is_err() {
        // Failed AEAD verification must never leave unauthenticated bytes behind
        // when the length was valid for decryption.
        if body.len() >= rship_crypto::stream::TAG_LEN
            && body.len() <= rship_crypto::stream::CIPHERTEXT_CHUNK_LEN
            && chunk_idx < (1u64 << 56)
        {
            assert!(in_place.is_empty());
        }
    }

    // 4. Encrypt a bounded plaintext slice, flip one bit, and assert AEAD rejects it.
    let pt_slice = &body[..body.len().min(PLAINTEXT_CHUNK_LEN)];
    let safe_idx = chunk_idx & ((1u64 << 56) - 1);
    if let Ok(mut ct) = encrypt_chunk(&data_key, &header, safe_idx, is_last, pt_slice) {
        let flip_pos = (data.first().copied().unwrap_or(0) as usize) % ct.len();
        ct[flip_pos] ^= 0x01;
        assert!(
            decrypt_chunk(&data_key, &header, safe_idx, is_last, &ct).is_err(),
            "bit-flipped ciphertext must always fail Poly1305 authentication"
        );
    }

    // 5. Fuzz encrypted filename segment decoding on arbitrary UTF-8 strings.
    if let Ok(seg) = std::str::from_utf8(data) {
        let _ = decrypt_segment(&keys, seg);
    }
});
