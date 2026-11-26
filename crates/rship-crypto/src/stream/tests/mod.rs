mod stream_and_tamper;
mod unit_and_sizing;

use super::*;
use futures::StreamExt;

pub(super) fn decrypt_full_ciphertext(data_key: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>> {
    let pt_len = plaintext_size(ct.len() as u64)?;
    let header = StreamHeader::decode(&ct[..HEADER_LEN])?;
    let cipher = StreamCipher::new(data_key, &header);

    if pt_len == 0 {
        if ct.len() != HEADER_LEN + TAG_LEN {
            return Err(Error::protocol(format!(
                "unexpected 0-byte ciphertext length {}",
                ct.len()
            )));
        }
        let mut buf = BytesMut::from(&ct[HEADER_LEN..]);
        if let Err(e) = decrypt_chunk_in_place(&cipher, 0, true, &mut buf) {
            assert!(
                buf.is_empty(),
                "failed decrypt_chunk_in_place must scrub buffer"
            );
            return Err(e);
        }
        if !buf.is_empty() {
            return Err(Error::protocol("non-empty plaintext for 0-byte file"));
        }
        return Ok(Vec::new());
    }

    let chunks = total_chunks(pt_len);
    let mut out = Vec::with_capacity(pt_len as usize);
    let mut pos = HEADER_LEN;
    for chunk_idx in 0..chunks {
        let is_last = chunk_idx == chunks - 1;
        let expected_ct_len = if is_last {
            let rem = (pt_len % (PLAINTEXT_CHUNK_LEN as u64)) as usize;
            let pt_block_len = if rem == 0 { PLAINTEXT_CHUNK_LEN } else { rem };
            pt_block_len + TAG_LEN
        } else {
            CIPHERTEXT_CHUNK_LEN
        };
        if pos + expected_ct_len > ct.len() {
            return Err(Error::protocol("truncated ciphertext stream"));
        }
        let mut buf = BytesMut::from(&ct[pos..pos + expected_ct_len]);
        pos += expected_ct_len;
        if let Err(e) = decrypt_chunk_in_place(&cipher, chunk_idx, is_last, &mut buf) {
            assert!(
                buf.is_empty(),
                "failed decrypt_chunk_in_place must scrub buffer"
            );
            return Err(e);
        }
        out.extend_from_slice(&buf);
    }
    if pos != ct.len() || out.len() as u64 != pt_len {
        return Err(Error::protocol(
            "ciphertext/plaintext framing length mismatch",
        ));
    }
    Ok(out)
}

pub(super) async fn encrypt_chunks_to_vec(
    data_key: &[u8; 32],
    header: StreamHeader,
    pt_len: u64,
    chunks: Vec<Bytes>,
    max_blocks: usize,
) -> Result<Vec<u8>> {
    let input: ByteStream = Box::pin(futures::stream::iter(chunks.into_iter().map(Ok)));
    let mut enc = StreamEncryptor::with_coalesced_blocks(
        input, data_key, header, 0, pt_len, true, true, max_blocks,
    );
    let mut out = Vec::new();
    while let Some(item) = enc.next().await {
        out.extend_from_slice(&item?);
    }
    Ok(out)
}

pub(super) fn sample_stream_pt_len(case_idx: usize, rng: &mut rand::rngs::StdRng) -> usize {
    use rand::RngExt;
    const BOUNDARIES: &[usize] = &[
        0,
        1,
        2,
        15,
        16,
        17,
        65_535,
        65_536,
        65_537,
        2 * PLAINTEXT_CHUNK_LEN - 1,
        2 * PLAINTEXT_CHUNK_LEN,
        2 * PLAINTEXT_CHUNK_LEN + 1,
        3 * PLAINTEXT_CHUNK_LEN,
        200_000,
    ];
    if case_idx < BOUNDARIES.len() {
        return BOUNDARIES[case_idx];
    }
    match rng.random_range(0u8..6) {
        0 => rng.random_range(0..=64),
        1 => {
            let base = PLAINTEXT_CHUNK_LEN;
            rng.random_range((base - 64)..=(base + 64))
        }
        2 => {
            let base = 2 * PLAINTEXT_CHUNK_LEN;
            rng.random_range((base - 64)..=(base + 64))
        }
        3 => rng.random_range(1..=3) * PLAINTEXT_CHUNK_LEN,
        _ => rng.random_range(0..=200_000),
    }
}
