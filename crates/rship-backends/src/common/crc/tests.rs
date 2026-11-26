use super::*;

/// Independent bit-by-bit reflected CRC-32C (Castagnoli, poly `0x82F6_3B78`) reference.
/// Uses zero lookup tables and zero shared code with production implementations.
fn ref_crc32c_update_bit_by_bit(mut crc: u32, data: &[u8]) -> u32 {
    const POLY: u32 = 0x82F6_3B78;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn ref_crc32c(data: &[u8]) -> u32 {
    !ref_crc32c_update_bit_by_bit(u32::MAX, data)
}

/// Independent bit-by-bit reflected CRC-64/NVME (poly `0x9A6C_9329_AC4B_C9B5`) reference.
/// Uses zero lookup tables and zero shared code with production implementations.
fn ref_crc64_nvme_update_bit_by_bit(mut crc: u64, data: &[u8]) -> u64 {
    const POLY: u64 = 0x9A6C_9329_AC4B_C9B5;
    for &b in data {
        crc ^= u64::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn ref_crc64_nvme(data: &[u8]) -> u64 {
    !ref_crc64_nvme_update_bit_by_bit(u64::MAX, data)
}

/// Deterministic SplitMix64 PRNG so tests never depend on external crates or OS entropy.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let word = self.next_u64().to_le_bytes();
            let take = (len - out.len()).min(8);
            out.extend_from_slice(&word[..take]);
        }
        out
    }
}

fn assert_all_crc32c_impls(seed: u32, data: &[u8], ctx: &str) {
    let expected = ref_crc32c_update_bit_by_bit(seed, data);
    assert_eq!(
        crc32c_update(seed, data),
        expected,
        "crc32c_update mismatch ({ctx}, len={}, seed={seed:#010x})",
        data.len()
    );
    assert_eq!(
        crc32c_update_slice8(seed, data),
        expected,
        "crc32c_update_slice8 mismatch ({ctx}, len={}, seed={seed:#010x})",
        data.len()
    );
    if seed == u32::MAX {
        assert_eq!(
            crc32c(data),
            !expected,
            "crc32c one-shot mismatch ({ctx}, len={})",
            data.len()
        );
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.2") {
        // SAFETY: Runtime feature check confirmed SSE4.2 support.
        let got = unsafe { crc32c_update_sse42(seed, data) };
        assert_eq!(
            got,
            expected,
            "crc32c_update_sse42 mismatch ({ctx}, len={}, seed={seed:#010x})",
            data.len()
        );
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("crc") {
        // SAFETY: Runtime feature check confirmed ARMv8 CRC support.
        let got = unsafe { crc32c_update_aarch64(seed, data) };
        assert_eq!(
            got,
            expected,
            "crc32c_update_aarch64 mismatch ({ctx}, len={}, seed={seed:#010x})",
            data.len()
        );
    }
}

fn assert_all_crc64_nvme_impls(seed: u64, data: &[u8], ctx: &str) {
    let expected = ref_crc64_nvme_update_bit_by_bit(seed, data);
    assert_eq!(
        crc64_nvme_update(seed, data),
        expected,
        "crc64_nvme_update mismatch ({ctx}, len={}, seed={seed:#018x})",
        data.len()
    );
    assert_eq!(
        crc64_nvme_update_slice8(seed, data),
        expected,
        "crc64_nvme_update_slice8 mismatch ({ctx}, len={}, seed={seed:#018x})",
        data.len()
    );
    assert_eq!(
        crc64_nvme_update_table1(seed, data),
        expected,
        "crc64_nvme_update_table1 mismatch ({ctx}, len={}, seed={seed:#018x})",
        data.len()
    );
    if seed == u64::MAX {
        assert_eq!(
            crc64_nvme(data),
            !expected,
            "crc64_nvme one-shot mismatch ({ctx}, len={})",
            data.len()
        );
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("pclmulqdq")
        && std::arch::is_x86_feature_detected!("sse4.1")
    {
        // SAFETY: Runtime feature check confirmed SSE4.1 + PCLMULQDQ support.
        let got = unsafe { crc64_nvme_update_pclmulqdq(seed, data) };
        assert_eq!(
            got,
            expected,
            "crc64_nvme_update_pclmulqdq mismatch ({ctx}, len={}, seed={seed:#018x})",
            data.len()
        );
    }
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    ))]
    if std::arch::is_aarch64_feature_detected!("aes") {
        // SAFETY: Runtime feature check confirmed ARMv8 NEON + PMULL (`aes`) support.
        let got = unsafe { crc64_nvme_update_pmull(seed, data) };
        assert_eq!(
            got,
            expected,
            "crc64_nvme_update_pmull mismatch ({ctx}, len={}, seed={seed:#018x})",
            data.len()
        );
    }
}

#[test]
fn standard_check_values_and_known_vectors() {
    // Empty input check values.
    assert_eq!(ref_crc32c(b""), 0x0000_0000);
    assert_all_crc32c_impls(u32::MAX, b"", "empty");
    assert_eq!(ref_crc64_nvme(b""), 0x0000_0000_0000_0000);
    assert_all_crc64_nvme_impls(u64::MAX, b"", "empty");

    // Official standard check values for ASCII "123456789".
    assert_eq!(ref_crc32c(b"123456789"), 0xE306_9283);
    assert_all_crc32c_impls(u32::MAX, b"123456789", "check-123456789");

    assert_eq!(ref_crc64_nvme(b"123456789"), 0xAE8B_1486_0A79_9888);
    assert_all_crc64_nvme_impls(u64::MAX, b"123456789", "check-123456789");

    // RFC 3720 Section B.4 official CRC-32C test vectors.
    let zeros32 = [0x00u8; 32];
    assert_eq!(ref_crc32c(&zeros32), 0x8A91_36AA);
    assert_all_crc32c_impls(u32::MAX, &zeros32, "rfc3720-zeros32");

    let ones32 = [0xFFu8; 32];
    assert_eq!(ref_crc32c(&ones32), 0x62A8_AB43);
    assert_all_crc32c_impls(u32::MAX, &ones32, "rfc3720-ones32");

    let asc32: Vec<u8> = (0u8..32).collect();
    assert_eq!(ref_crc32c(&asc32), 0x46DD_794E);
    assert_all_crc32c_impls(u32::MAX, &asc32, "rfc3720-asc32");

    let desc32: Vec<u8> = (0u8..32).rev().collect();
    assert_eq!(ref_crc32c(&desc32), 0x113F_DB5C);
    assert_all_crc32c_impls(u32::MAX, &desc32, "rfc3720-desc32");

    let iscsi_pdu: [u8; 48] = [
        0x01, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00,
        0x00, 0x18, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    assert_eq!(ref_crc32c(&iscsi_pdu), 0xD996_3A56);
    assert_all_crc32c_impls(u32::MAX, &iscsi_pdu, "rfc3720-iscsi-pdu");

    // NVMe NVM Command Set Specification & AWS S3 CRC-64/NVME 4 KiB test vectors.
    let zeros4k = vec![0x00u8; 4096];
    assert_eq!(ref_crc64_nvme(&zeros4k), 0x6482_D367_EB22_B64E);
    assert_all_crc64_nvme_impls(u64::MAX, &zeros4k, "nvme-zeros4k");

    let ones4k = vec![0xFFu8; 4096];
    assert_eq!(ref_crc64_nvme(&ones4k), 0xC0DD_BA73_02EC_A3AC);
    assert_all_crc64_nvme_impls(u64::MAX, &ones4k, "nvme-ones4k");

    let asc4k: Vec<u8> = (0usize..4096).map(|i| (i & 0xFF) as u8).collect();
    assert_eq!(ref_crc64_nvme(&asc4k), 0x3E72_9F5F_6750_449C);
    assert_all_crc64_nvme_impls(u64::MAX, &asc4k, "nvme-asc4k");

    let desc4k: Vec<u8> = (0usize..4096).map(|i| (0xFF - (i & 0xFF)) as u8).collect();
    assert_eq!(ref_crc64_nvme(&desc4k), 0x9A2D_F64B_8E9E_517E);
    assert_all_crc64_nvme_impls(u64::MAX, &desc4k, "nvme-desc4k");
}

#[test]
fn all_lengths_0_to_512_match_bit_by_bit_reference() {
    let mut rng = SplitMix64::new(0x517C_C1B7_2722_0A95);
    let buf = rng.fill_bytes(512);
    for len in 0..=512 {
        assert_all_crc32c_impls(u32::MAX, &buf[..len], "len-sweep-0..=512");
        assert_all_crc64_nvme_impls(u64::MAX, &buf[..len], "len-sweep-0..=512");
    }
}

#[test]
fn large_boundary_lengths_match_bit_by_bit_reference() {
    let mut rng = SplitMix64::new(0xA076_1D64_78BD_642F);
    let buf = rng.fill_bytes(65_537);
    for len in [1023, 1024, 1025, 4095, 4096, 4097, 65_536, 65_537] {
        assert_all_crc32c_impls(u32::MAX, &buf[..len], "large-boundary");
        assert_all_crc64_nvme_impls(u64::MAX, &buf[..len], "large-boundary");
    }
}

#[test]
fn all_byte_misalignments_0_to_63_match_bit_by_bit_reference() {
    let mut rng = SplitMix64::new(0xE703_7ED1_A0B4_28DB);
    let max_len = 1025usize;
    let buf = rng.fill_bytes(64 + max_len);
    let lengths = [
        0usize, 1, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 513, 1025,
    ];
    for offset in 0..64 {
        for &len in &lengths {
            let slice = &buf[offset..offset + len];
            let ctx = format!("align-offset={offset}");
            assert_all_crc32c_impls(u32::MAX, slice, &ctx);
            assert_all_crc64_nvme_impls(u64::MAX, slice, &ctx);
        }
    }
}

#[test]
fn incremental_streaming_chunks_and_random_splits_match_single_shot() {
    let mut rng = SplitMix64::new(0x8EBC_6AF0_9C88_C6E3);
    let data = rng.fill_bytes(4099);

    let ref32 = ref_crc32c_update_bit_by_bit(u32::MAX, &data);
    let ref64 = ref_crc64_nvme_update_bit_by_bit(u64::MAX, &data);
    assert_eq!(!ref32, crc32c(&data));
    assert_eq!(!ref64, crc64_nvme(&data));

    // Fixed non-aligned chunk sizes across every implementation.
    for chunk_size in [1usize, 3, 7, 13, 64, 127, 257, 1000] {
        let mut c32_dispatch = u32::MAX;
        let mut c32_slice8 = u32::MAX;
        let mut c64_dispatch = u64::MAX;
        let mut c64_slice8 = u64::MAX;
        let mut c64_table1 = u64::MAX;

        #[cfg(target_arch = "x86_64")]
        let mut c32_sse42 = u32::MAX;
        #[cfg(target_arch = "x86_64")]
        let mut c64_pclmul = u64::MAX;
        #[cfg(target_arch = "aarch64")]
        let mut c32_aarch64 = u32::MAX;
        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        let mut c64_pmull = u64::MAX;

        for chunk in data.chunks(chunk_size) {
            c32_dispatch = crc32c_update(c32_dispatch, chunk);
            c32_slice8 = crc32c_update_slice8(c32_slice8, chunk);
            c64_dispatch = crc64_nvme_update(c64_dispatch, chunk);
            c64_slice8 = crc64_nvme_update_slice8(c64_slice8, chunk);
            c64_table1 = crc64_nvme_update_table1(c64_table1, chunk);

            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("sse4.2") {
                // SAFETY: Runtime feature check confirmed SSE4.2 support.
                c32_sse42 = unsafe { crc32c_update_sse42(c32_sse42, chunk) };
            }
            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                // SAFETY: Runtime feature check confirmed SSE4.1 + PCLMULQDQ support.
                c64_pclmul = unsafe { crc64_nvme_update_pclmulqdq(c64_pclmul, chunk) };
            }
            #[cfg(target_arch = "aarch64")]
            if std::arch::is_aarch64_feature_detected!("crc") {
                // SAFETY: Runtime feature check confirmed ARMv8 CRC support.
                c32_aarch64 = unsafe { crc32c_update_aarch64(c32_aarch64, chunk) };
            }
            #[cfg(all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_endian = "little"
            ))]
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: Runtime feature check confirmed ARMv8 NEON + PMULL (`aes`) support.
                c64_pmull = unsafe { crc64_nvme_update_pmull(c64_pmull, chunk) };
            }
        }

        assert_eq!(c32_dispatch, ref32, "crc32c_update chunk={chunk_size}");
        assert_eq!(c32_slice8, ref32, "crc32c_update_slice8 chunk={chunk_size}");
        assert_eq!(c64_dispatch, ref64, "crc64_nvme_update chunk={chunk_size}");
        assert_eq!(
            c64_slice8, ref64,
            "crc64_nvme_update_slice8 chunk={chunk_size}"
        );
        assert_eq!(
            c64_table1, ref64,
            "crc64_nvme_update_table1 chunk={chunk_size}"
        );

        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("sse4.2") {
            assert_eq!(c32_sse42, ref32, "crc32c_update_sse42 chunk={chunk_size}");
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
        {
            assert_eq!(
                c64_pclmul, ref64,
                "crc64_nvme_update_pclmulqdq chunk={chunk_size}"
            );
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("crc") {
            assert_eq!(
                c32_aarch64, ref32,
                "crc32c_update_aarch64 chunk={chunk_size}"
            );
        }
        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        if std::arch::is_aarch64_feature_detected!("aes") {
            assert_eq!(
                c64_pmull, ref64,
                "crc64_nvme_update_pmull chunk={chunk_size}"
            );
        }
    }

    // 100 seeded pseudo-random split iterations mixing 0-byte, short, unaligned,
    // and >128-byte SIMD chunks across varying sub-slices.
    for iter in 0..100 {
        let start = (rng.next_u64() as usize) % 64;
        let len = 128 + ((rng.next_u64() as usize) % (data.len() - 64 - 128));
        let slice = &data[start..start + len];
        let expected32 = ref_crc32c_update_bit_by_bit(u32::MAX, slice);
        let expected64 = ref_crc64_nvme_update_bit_by_bit(u64::MAX, slice);

        let mut c32_dispatch = u32::MAX;
        let mut c32_slice8 = u32::MAX;
        let mut c64_dispatch = u64::MAX;
        let mut c64_slice8 = u64::MAX;
        let mut c64_table1 = u64::MAX;
        #[cfg(target_arch = "x86_64")]
        let mut c32_sse42 = u32::MAX;
        #[cfg(target_arch = "x86_64")]
        let mut c64_pclmul = u64::MAX;
        #[cfg(target_arch = "aarch64")]
        let mut c32_aarch64 = u32::MAX;
        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        let mut c64_pmull = u64::MAX;

        let mut pos = 0usize;
        while pos < slice.len() {
            // Mix empty chunks, tiny tail sizes, and multi-block SIMD chunks.
            let step = match rng.next_u64() % 5 {
                0 => 0,
                1 => 1 + (rng.next_u64() as usize % 15),
                2 => 16 + (rng.next_u64() as usize % 112),
                3 => 128 + (rng.next_u64() as usize % 384),
                _ => 1 + (rng.next_u64() as usize % 64),
            };
            let end = (pos + step).min(slice.len());
            let chunk = &slice[pos..end];
            c32_dispatch = crc32c_update(c32_dispatch, chunk);
            c32_slice8 = crc32c_update_slice8(c32_slice8, chunk);
            c64_dispatch = crc64_nvme_update(c64_dispatch, chunk);
            c64_slice8 = crc64_nvme_update_slice8(c64_slice8, chunk);
            c64_table1 = crc64_nvme_update_table1(c64_table1, chunk);

            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("sse4.2") {
                // SAFETY: Runtime feature check confirmed SSE4.2 support.
                c32_sse42 = unsafe { crc32c_update_sse42(c32_sse42, chunk) };
            }
            #[cfg(target_arch = "x86_64")]
            if std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                // SAFETY: Runtime feature check confirmed SSE4.1 + PCLMULQDQ support.
                c64_pclmul = unsafe { crc64_nvme_update_pclmulqdq(c64_pclmul, chunk) };
            }
            #[cfg(target_arch = "aarch64")]
            if std::arch::is_aarch64_feature_detected!("crc") {
                // SAFETY: Runtime feature check confirmed ARMv8 CRC support.
                c32_aarch64 = unsafe { crc32c_update_aarch64(c32_aarch64, chunk) };
            }
            #[cfg(all(
                target_arch = "aarch64",
                target_feature = "neon",
                target_endian = "little"
            ))]
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: Runtime feature check confirmed ARMv8 NEON + PMULL (`aes`) support.
                c64_pmull = unsafe { crc64_nvme_update_pmull(c64_pmull, chunk) };
            }

            if step == 0 {
                // Ensure progress after verifying an empty-chunk no-op update.
                pos += 1;
                let single = &slice[pos - 1..pos];
                c32_dispatch = crc32c_update(c32_dispatch, single);
                c32_slice8 = crc32c_update_slice8(c32_slice8, single);
                c64_dispatch = crc64_nvme_update(c64_dispatch, single);
                c64_slice8 = crc64_nvme_update_slice8(c64_slice8, single);
                c64_table1 = crc64_nvme_update_table1(c64_table1, single);
                #[cfg(target_arch = "x86_64")]
                if std::arch::is_x86_feature_detected!("sse4.2") {
                    // SAFETY: Runtime feature check confirmed SSE4.2 support.
                    c32_sse42 = unsafe { crc32c_update_sse42(c32_sse42, single) };
                }
                #[cfg(target_arch = "x86_64")]
                if std::arch::is_x86_feature_detected!("pclmulqdq")
                    && std::arch::is_x86_feature_detected!("sse4.1")
                {
                    // SAFETY: Runtime feature check confirmed SSE4.1 + PCLMULQDQ support.
                    c64_pclmul = unsafe { crc64_nvme_update_pclmulqdq(c64_pclmul, single) };
                }
                #[cfg(target_arch = "aarch64")]
                if std::arch::is_aarch64_feature_detected!("crc") {
                    // SAFETY: Runtime feature check confirmed ARMv8 CRC support.
                    c32_aarch64 = unsafe { crc32c_update_aarch64(c32_aarch64, single) };
                }
                #[cfg(all(
                    target_arch = "aarch64",
                    target_feature = "neon",
                    target_endian = "little"
                ))]
                if std::arch::is_aarch64_feature_detected!("aes") {
                    // SAFETY: Runtime feature check confirmed ARMv8 NEON + PMULL (`aes`) support.
                    c64_pmull = unsafe { crc64_nvme_update_pmull(c64_pmull, single) };
                }
            } else {
                pos = end;
            }
        }

        assert_eq!(c32_dispatch, expected32, "random split iter={iter} c32");
        assert_eq!(
            c32_slice8, expected32,
            "random split iter={iter} c32_slice8"
        );
        assert_eq!(
            !c32_dispatch,
            crc32c(slice),
            "random split iter={iter} c32 1shot"
        );
        assert_eq!(c64_dispatch, expected64, "random split iter={iter} c64");
        assert_eq!(
            c64_slice8, expected64,
            "random split iter={iter} c64_slice8"
        );
        assert_eq!(
            c64_table1, expected64,
            "random split iter={iter} c64_table1"
        );
        assert_eq!(
            !c64_dispatch,
            crc64_nvme(slice),
            "random split iter={iter} c64 1shot"
        );
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("sse4.2") {
            assert_eq!(c32_sse42, expected32, "random split iter={iter} c32_sse42");
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("sse4.1")
        {
            assert_eq!(
                c64_pclmul, expected64,
                "random split iter={iter} c64_pclmul"
            );
        }
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("crc") {
            assert_eq!(
                c32_aarch64, expected32,
                "random split iter={iter} c32_aarch64"
            );
        }
        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        if std::arch::is_aarch64_feature_detected!("aes") {
            assert_eq!(c64_pmull, expected64, "random split iter={iter} c64_pmull");
        }
    }
}

#[test]
fn arbitrary_non_zero_initial_seeds_chain_identically() {
    let mut rng = SplitMix64::new(0xD6E8_FEB8_6659_FD93);
    let buf = rng.fill_bytes(1040);
    let lengths = [
        0usize, 1, 7, 8, 15, 16, 31, 63, 64, 65, 127, 128, 129, 192, 255, 256, 513, 1025,
    ];

    let seeds32 = [
        0x0000_0000u32,
        0x0000_0001,
        0x1234_5678,
        0x8000_0000,
        0xDEAD_BEEF,
        0xA5A5_5A5A,
        u32::MAX,
    ];
    let seeds64 = [
        0x0000_0000_0000_0000u64,
        0x0000_0000_0000_0001,
        0x0123_4567_89AB_CDEF,
        0x8000_0000_0000_0000,
        0xDEAD_BEEF_CAFE_BABE,
        0xA5A5_5A5A_F00D_FACE,
        u64::MAX,
    ];

    for &len in &lengths {
        let aligned = &buf[..len];
        let unaligned = &buf[7..7 + len];
        for &seed in &seeds32 {
            assert_all_crc32c_impls(seed, aligned, "seed32-aligned");
            assert_all_crc32c_impls(seed, unaligned, "seed32-unaligned");
        }
        for &seed in &seeds64 {
            assert_all_crc64_nvme_impls(seed, aligned, "seed64-aligned");
            assert_all_crc64_nvme_impls(seed, unaligned, "seed64-unaligned");
        }
    }
}

#[test]
fn direct_simd_crc64_handles_short_and_single_block_slices_safely() {
    // Regression test: direct calls to `crc64_nvme_update_pclmulqdq` /
    // `crc64_nvme_update_pmull` must remain memory-safe and exact for `< 64`
    // (table1 fallback) and `64..128` (zero iterations of the 64-byte fold loop).
    let mut rng = SplitMix64::new(0x94D0_49BB_1331_11EB);
    let buf = rng.fill_bytes(135);
    for len in 0..=130 {
        assert_all_crc64_nvme_impls(0x0123_4567_89AB_CDEF, &buf[3..3 + len], "short-simd");
    }
}
