//! Hardware-portable pure-Rust CRC32C, CRC64-NVME, and constant-memory
//! 2-pass `SeekableSource` SHA-256 hashing for S3 integrity & strict SigV4.

pub use crate::common::{
    crc32c, crc32c_update, crc64_nvme, crc64_nvme_update, crc64_nvme_update_slice8,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use rship_core::buffer::BufferPool;
use rship_core::source::SeekableSource;
use rship_core::{Error, Result};
use sha2::{Digest, Sha256};

/// Compute S3 `x-amz-checksum-crc32c` header value (base64 of big-endian u32).
pub fn crc32c_base64(data: &[u8]) -> String {
    BASE64_STD.encode(crc32c(data).to_be_bytes())
}

/// Compute S3 `x-amz-checksum-crc64nvme` header value (base64 of big-endian u64).
pub fn crc64_nvme_base64(data: &[u8]) -> String {
    BASE64_STD.encode(crc64_nvme(data).to_be_bytes())
}

/// Compute lowercase hex SHA-256 over `[offset, offset + len)` of a `SeekableSource`
/// using a single `BufferPool` slab at a time (zero large RAM buffering, suitable for
/// 2-pass strict SigV4 over plain HTTP).
pub async fn hash_seekable_sha256(
    src: &dyn SeekableSource,
    offset: u64,
    len: u64,
    pool: &BufferPool,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut pos = offset;
    let mut remaining = len;

    while remaining > 0 {
        let want = (remaining as usize).min(pool.slab_size());
        let mut slice = if want < pool.slab_size() {
            pool.acquire_exact(want).await?
        } else {
            pool.acquire_slab().await?
        };
        let mut filled = 0usize;
        while filled < want {
            let n = src
                .read_at(pos + filled as u64, &mut slice.spare_mut()[filled..want])
                .await?;
            if n == 0 {
                return Err(Error::source_mutated(format!(
                    "early EOF while computing SHA-256 at offset {}",
                    pos + filled as u64
                )));
            }
            filled += n;
        }
        hasher.update(&slice.spare_mut()[..filled]);
        pos += filled as u64;
        remaining -= filled as u64;
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rship_core::source::MemorySource;

    #[test]
    fn crc32c_and_crc64_nvme_match_standard_check_vectors() {
        // Official standard check value for ASCII "123456789".
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(
            !crate::common::crc32c_update_slice8(u32::MAX, b"123456789"),
            0xE306_9283
        );
        // Verify hardware dispatch and slicing-by-8 agree across odd/unaligned chunk boundaries.
        let sample: Vec<u8> = (0..4099).map(|i| ((i * 37 + 11) & 0xFF) as u8).collect();
        for len in [0usize, 1, 3, 7, 8, 9, 15, 16, 31, 64, 513, 4099] {
            let hw = !crc32c_update(u32::MAX, &sample[..len]);
            let sw = !crate::common::crc32c_update_slice8(u32::MAX, &sample[..len]);
            assert_eq!(hw, sw, "CRC32C mismatch at len={len}");
        }
        let mut streamed = u32::MAX;
        for chunk in sample.chunks(137) {
            streamed = crc32c_update(streamed, chunk);
        }
        assert_eq!(!streamed, crc32c(&sample));
        assert_eq!(crc64_nvme(b"123456789"), 0xAE8B_1486_0A79_9888);
        assert_eq!(
            !crc64_nvme_update_slice8(u64::MAX, b"123456789"),
            0xAE8B_1486_0A79_9888
        );
        assert_eq!(
            crc64_nvme_base64(b"123456789"),
            BASE64_STD.encode(0xAE8B_1486_0A79_9888u64.to_be_bytes())
        );

        // Verify hardware PCLMULQDQ/PMULL dispatch, slicing-by-8, and 1-byte reference agree
        // across thresholds, odd lengths, unaligned slices, and incremental chunking.
        let big: Vec<u8> = (0usize..65_543)
            .map(|i| ((i.wrapping_mul(131) + 17) & 0xFF) as u8)
            .collect();
        for len in [
            0usize, 1, 7, 8, 15, 16, 63, 64, 127, 128, 129, 143, 144, 191, 192, 193, 255, 256, 513,
            1023, 4099, 65_537,
        ] {
            let ref1 = !crate::common::crc64_nvme_update_table1(u64::MAX, &big[..len]);
            let sw8 = !crc64_nvme_update_slice8(u64::MAX, &big[..len]);
            let hw = crc64_nvme(&big[..len]);
            assert_eq!(hw, ref1, "CRC64-NVME HW mismatch at len={len}");
            assert_eq!(sw8, ref1, "CRC64-NVME slice8 mismatch at len={len}");
        }
        for align in 1..8 {
            let slice = &big[align..align + 4099];
            assert_eq!(
                crc64_nvme(slice),
                !crate::common::crc64_nvme_update_table1(u64::MAX, slice),
                "CRC64-NVME unaligned mismatch at offset={align}"
            );
        }
        for step in [13usize, 137, 1009] {
            let mut acc = u64::MAX;
            for chunk in big.chunks(step) {
                acc = crc64_nvme_update(acc, chunk);
            }
            assert_eq!(
                !acc,
                !crate::common::crc64_nvme_update_table1(u64::MAX, &big),
                "CRC64-NVME streamed mismatch at step={step}"
            );
        }
    }

    #[tokio::test]
    async fn two_pass_seekable_sha256_holds_bounded_pool_and_matches_direct_hash() {
        let data: Vec<u8> = (0..700_000).map(|i| (i % 251) as u8).collect();
        let expected = hex::encode(Sha256::digest(&data[1000..650_000]));
        let src = MemorySource::new(Bytes::from(data));
        let pool = BufferPool::new(512 * 1024, 256 * 1024).unwrap();
        let actual = hash_seekable_sha256(&src, 1000, 649_000, &pool)
            .await
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(pool.stats().in_use_units, 0);
        assert!(pool.stats().peak_units <= pool.stats().max_units);
    }
}
