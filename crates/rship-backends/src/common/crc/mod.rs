//! Hardware-accelerated reflected CRC-32C (Castagnoli) and CRC-64/NVME checksums
//! with portable Slicing-by-8 fallback.

use std::sync::OnceLock;

#[cfg(test)]
mod tests;

/// Reflected CRC-32C (Castagnoli) polynomial.
const CRC32C_POLY_REFLECTED: u32 = 0x82F6_3B78;

fn crc32c_tables() -> &'static [[u32; 256]; 8] {
    static TABLES: OnceLock<[[u32; 256]; 8]> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = [[0u32; 256]; 8];
        for (i, slot) in t[0].iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ CRC32C_POLY_REFLECTED;
                } else {
                    crc >>= 1;
                }
            }
            *slot = crc;
        }
        for k in 1..8 {
            for i in 0..256 {
                let prev = t[k - 1][i];
                t[k][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            }
        }
        t
    })
}

/// Portable Slicing-by-8 reflected CRC-32C implementation (8 bytes per iteration).
pub fn crc32c_update_slice8(mut crc: u32, data: &[u8]) -> u32 {
    let t = crc32c_tables();
    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        let lo = crc ^ u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let hi = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        crc = t[7][(lo & 0xFF) as usize]
            ^ t[6][((lo >> 8) & 0xFF) as usize]
            ^ t[5][((lo >> 16) & 0xFF) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xFF) as usize]
            ^ t[2][((hi >> 8) & 0xFF) as usize]
            ^ t[1][((hi >> 16) & 0xFF) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in remainder {
        crc = (crc >> 8) ^ t[0][((crc ^ u32::from(b)) & 0xFF) as usize];
    }
    crc
}

/// # Safety
///
/// Caller must ensure the current CPU supports `sse4.2` (e.g. via
/// `std::arch::is_x86_feature_detected!("sse4.2")`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_update_sse42(crc: u32, data: &[u8]) -> u32 {
    use core::arch::x86_64::{_mm_crc32_u8, _mm_crc32_u64};
    let mut c64 = u64::from(crc);
    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        c64 = _mm_crc32_u64(c64, u64::from_le_bytes(*chunk));
    }
    let mut c32 = c64 as u32;
    for &b in remainder {
        c32 = _mm_crc32_u8(c32, b);
    }
    c32
}

/// # Safety
///
/// Caller must ensure the current CPU supports ARMv8 CRC instructions (e.g. via
/// `std::arch::is_aarch64_feature_detected!("crc")`).
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn crc32c_update_aarch64(mut crc: u32, data: &[u8]) -> u32 {
    use core::arch::aarch64::{__crc32cb, __crc32cd};
    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        crc = __crc32cd(crc, u64::from_le_bytes(*chunk));
    }
    for &b in remainder {
        crc = __crc32cb(crc, b);
    }
    crc
}

/// Incrementally update a reflected CRC-32C accumulator (init with `u32::MAX`, finalize with `!crc`).
///
/// Automatically dispatches to hardware `SSE4.2` (`x86_64`) or `ARMv8 CRC` (`aarch64`)
/// instructions at runtime, falling back to portable Slicing-by-8.
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: Runtime feature check confirmed SSE4.2 support.
            return unsafe { crc32c_update_sse42(crc, data) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("crc") {
            // SAFETY: Runtime feature check confirmed ARMv8 CRC support.
            return unsafe { crc32c_update_aarch64(crc, data) };
        }
    }
    crc32c_update_slice8(crc, data)
}

/// Compute CRC-32C (Castagnoli) checksum.
pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(0xFFFF_FFFFu32, data)
}

/// Reflected CRC-64/NVME (NVMe NVM Command Set Spec / AWS S3 `CRC64NVME`) polynomial.
const CRC64_NVME_POLY_REFLECTED: u64 = 0x9A6C_9329_AC4B_C9B5;

/// Compute reflected GF(2) reduction constant `x^n mod P` for CRC-64/NVME at compile time.
const fn crc64_nvme_xn_mod_p(n: usize) -> u64 {
    let mut v = 1u64 << 63;
    let mut i = 0;
    while i < n {
        if v & 1 != 0 {
            v = (v >> 1) ^ CRC64_NVME_POLY_REFLECTED;
        } else {
            v >>= 1;
        }
        i += 1;
    }
    v
}

#[cfg(any(
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
const CRC64_K512_LO: u64 = crc64_nvme_xn_mod_p(512 + 64 - 1);
#[cfg(any(
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
const CRC64_K512_HI: u64 = crc64_nvme_xn_mod_p(512 - 1);
#[cfg(any(
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
const CRC64_K128_LO: u64 = crc64_nvme_xn_mod_p(128 + 64 - 1);
#[cfg(any(
    target_arch = "x86_64",
    all(
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
const CRC64_K128_HI: u64 = crc64_nvme_xn_mod_p(128 - 1);

fn crc64_nvme_table_1() -> &'static [u64; 256] {
    static TABLE: OnceLock<[u64; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u64; 256];
        for (i, slot) in t.iter_mut().enumerate() {
            let mut crc = i as u64;
            for _ in 0..8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ CRC64_NVME_POLY_REFLECTED;
                } else {
                    crc >>= 1;
                }
            }
            *slot = crc;
        }
        t
    })
}

fn crc64_nvme_tables_8() -> &'static [[u64; 256]; 8] {
    static TABLES: OnceLock<[[u64; 256]; 8]> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = [[0u64; 256]; 8];
        t[0] = *crc64_nvme_table_1();
        for k in 1..8 {
            for i in 0..256 {
                let prev = t[k - 1][i];
                t[k][i] = (prev >> 8) ^ t[0][(prev & 0xFF) as usize];
            }
        }
        t
    })
}

pub(crate) fn crc64_nvme_update_table1(mut crc: u64, data: &[u8]) -> u64 {
    let table = crc64_nvme_table_1();
    for &b in data {
        let idx = ((crc ^ u64::from(b)) & 0xFF) as usize;
        crc = (crc >> 8) ^ table[idx];
    }
    crc
}

/// Portable Slicing-by-8 reflected CRC-64/NVME implementation (8 bytes per iteration).
pub fn crc64_nvme_update_slice8(mut crc: u64, data: &[u8]) -> u64 {
    let t = crc64_nvme_tables_8();
    let (chunks, remainder) = data.as_chunks::<8>();
    for chunk in chunks {
        let v = crc ^ u64::from_le_bytes(*chunk);
        crc = t[7][(v & 0xFF) as usize]
            ^ t[6][((v >> 8) & 0xFF) as usize]
            ^ t[5][((v >> 16) & 0xFF) as usize]
            ^ t[4][((v >> 24) & 0xFF) as usize]
            ^ t[3][((v >> 32) & 0xFF) as usize]
            ^ t[2][((v >> 40) & 0xFF) as usize]
            ^ t[1][((v >> 48) & 0xFF) as usize]
            ^ t[0][(v >> 56) as usize];
    }
    for &b in remainder {
        crc = (crc >> 8) ^ t[0][((crc ^ u64::from(b)) & 0xFF) as usize];
    }
    crc
}

/// # Safety
///
/// Caller must ensure the current CPU supports `sse4.1` and `pclmulqdq`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1,pclmulqdq")]
#[inline]
unsafe fn fold_128_x86(
    a: core::arch::x86_64::__m128i,
    b: core::arch::x86_64::__m128i,
    k: core::arch::x86_64::__m128i,
) -> core::arch::x86_64::__m128i {
    use core::arch::x86_64::{_mm_clmulepi64_si128, _mm_xor_si128};
    let lo = _mm_clmulepi64_si128(a, k, 0x00);
    let hi = _mm_clmulepi64_si128(a, k, 0x11);
    _mm_xor_si128(_mm_xor_si128(lo, hi), b)
}

/// # Safety
///
/// Caller must ensure the current CPU supports `sse4.1` and `pclmulqdq` (e.g. via
/// `std::arch::is_x86_feature_detected!("sse4.1")` and
/// `std::arch::is_x86_feature_detected!("pclmulqdq")`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1,pclmulqdq")]
unsafe fn crc64_nvme_update_pclmulqdq(crc: u64, data: &[u8]) -> u64 {
    use core::arch::x86_64::{
        __m128i, _mm_cvtsi64_si128, _mm_loadu_si128, _mm_set_epi64x, _mm_storeu_si128,
        _mm_xor_si128,
    };
    if data.len() < 64 {
        return crc64_nvme_update_table1(crc, data);
    }
    let mut ptr = data.as_ptr();
    let mut rem = data.len();

    // SAFETY: Guard above ensures `rem >= 64`, so four 16-byte unaligned loads from `ptr..ptr+64` are in bounds.
    let (mut x0, mut x1, mut x2, mut x3) = unsafe {
        (
            _mm_loadu_si128(ptr.cast::<__m128i>()),
            _mm_loadu_si128(ptr.add(16).cast::<__m128i>()),
            _mm_loadu_si128(ptr.add(32).cast::<__m128i>()),
            _mm_loadu_si128(ptr.add(48).cast::<__m128i>()),
        )
    };
    x0 = _mm_xor_si128(x0, _mm_cvtsi64_si128(crc as i64));
    // SAFETY: `rem >= 64`, so advancing by 64 stays within `data` (at most one-past-the-end).
    ptr = unsafe { ptr.add(64) };
    rem -= 64;

    let k512 = _mm_set_epi64x(CRC64_K512_HI as i64, CRC64_K512_LO as i64);
    while rem >= 64 {
        // SAFETY: `rem >= 64` guarantees all four 16-byte unaligned loads and `ptr.add(64)` are in bounds.
        unsafe {
            x0 = fold_128_x86(x0, _mm_loadu_si128(ptr.cast::<__m128i>()), k512);
            x1 = fold_128_x86(x1, _mm_loadu_si128(ptr.add(16).cast::<__m128i>()), k512);
            x2 = fold_128_x86(x2, _mm_loadu_si128(ptr.add(32).cast::<__m128i>()), k512);
            x3 = fold_128_x86(x3, _mm_loadu_si128(ptr.add(48).cast::<__m128i>()), k512);
            ptr = ptr.add(64);
        }
        rem -= 64;
    }

    let k128 = _mm_set_epi64x(CRC64_K128_HI as i64, CRC64_K128_LO as i64);
    // SAFETY: Enclosing function enables SSE4.1 + PCLMULQDQ.
    let mut acc = unsafe {
        let a = fold_128_x86(x0, x1, k128);
        let a = fold_128_x86(a, x2, k128);
        fold_128_x86(a, x3, k128)
    };

    while rem >= 16 {
        // SAFETY: `rem >= 16` guarantees a 16-byte unaligned load and `ptr.add(16)` are in bounds.
        unsafe {
            acc = fold_128_x86(acc, _mm_loadu_si128(ptr.cast::<__m128i>()), k128);
            ptr = ptr.add(16);
        }
        rem -= 16;
    }

    let mut final16 = [0u8; 16];
    // SAFETY: `final16` is 16 bytes; `ptr..ptr+rem` is the untouched tail of `data`.
    let tail = unsafe {
        _mm_storeu_si128(final16.as_mut_ptr().cast::<__m128i>(), acc);
        core::slice::from_raw_parts(ptr, rem)
    };
    let c = crc64_nvme_update_table1(0, &final16);
    crc64_nvme_update_table1(c, tail)
}

/// # Safety
///
/// Caller must ensure the current CPU supports ARMv8 NEON and `aes` (`PMULL`) on little-endian `aarch64`.
#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
#[target_feature(enable = "aes")]
#[inline]
unsafe fn fold_128_aarch64(
    a: core::arch::aarch64::uint64x2_t,
    b: core::arch::aarch64::uint64x2_t,
    k: core::arch::aarch64::uint64x2_t,
) -> core::arch::aarch64::uint64x2_t {
    use core::arch::aarch64::{
        veorq_u64, vgetq_lane_u64, vmull_high_p64, vmull_p64, vreinterpretq_p64_u64,
        vreinterpretq_u64_p128,
    };
    let lo = vmull_p64(vgetq_lane_u64::<0>(a), vgetq_lane_u64::<0>(k));
    let hi = vmull_high_p64(vreinterpretq_p64_u64(a), vreinterpretq_p64_u64(k));
    veorq_u64(
        b,
        veorq_u64(vreinterpretq_u64_p128(lo), vreinterpretq_u64_p128(hi)),
    )
}

/// # Safety
///
/// Caller must ensure the current CPU supports ARMv8 NEON and `aes` (`PMULL`) on little-endian
/// `aarch64` (e.g. via `std::arch::is_aarch64_feature_detected!("aes")`).
#[cfg(all(
    target_arch = "aarch64",
    target_feature = "neon",
    target_endian = "little"
))]
#[target_feature(enable = "aes")]
unsafe fn crc64_nvme_update_pmull(crc: u64, data: &[u8]) -> u64 {
    use core::arch::aarch64::{
        vdupq_n_u64, veorq_u64, vld1q_u8, vld1q_u64, vreinterpretq_u8_u64, vreinterpretq_u64_u8,
        vsetq_lane_u64, vst1q_u8,
    };
    if data.len() < 64 {
        return crc64_nvme_update_table1(crc, data);
    }
    let mut ptr = data.as_ptr();
    let mut rem = data.len();

    // SAFETY: Guard above ensures `rem >= 64`, so four 16-byte loads from `ptr..ptr+64` are in bounds.
    let (mut x0, mut x1, mut x2, mut x3) = unsafe {
        (
            vreinterpretq_u64_u8(vld1q_u8(ptr)),
            vreinterpretq_u64_u8(vld1q_u8(ptr.add(16))),
            vreinterpretq_u64_u8(vld1q_u8(ptr.add(32))),
            vreinterpretq_u64_u8(vld1q_u8(ptr.add(48))),
        )
    };
    x0 = veorq_u64(x0, vsetq_lane_u64::<0>(crc, vdupq_n_u64(0)));
    // SAFETY: `rem >= 64`, so advancing by 64 stays within `data` (at most one-past-the-end).
    ptr = unsafe { ptr.add(64) };
    rem -= 64;

    let k512_arr = [CRC64_K512_LO, CRC64_K512_HI];
    // SAFETY: `k512_arr` holds 2 `u64` lanes.
    let k512 = unsafe { vld1q_u64(k512_arr.as_ptr()) };
    while rem >= 64 {
        // SAFETY: `rem >= 64` guarantees all four 16-byte loads and `ptr.add(64)` are in bounds.
        unsafe {
            x0 = fold_128_aarch64(x0, vreinterpretq_u64_u8(vld1q_u8(ptr)), k512);
            x1 = fold_128_aarch64(x1, vreinterpretq_u64_u8(vld1q_u8(ptr.add(16))), k512);
            x2 = fold_128_aarch64(x2, vreinterpretq_u64_u8(vld1q_u8(ptr.add(32))), k512);
            x3 = fold_128_aarch64(x3, vreinterpretq_u64_u8(vld1q_u8(ptr.add(48))), k512);
            ptr = ptr.add(64);
        }
        rem -= 64;
    }

    let k128_arr = [CRC64_K128_LO, CRC64_K128_HI];
    // SAFETY: `k128_arr` holds 2 `u64` lanes; enclosing function enables ARMv8 `aes` (`PMULL`).
    let (k128, mut acc) = unsafe {
        let k128 = vld1q_u64(k128_arr.as_ptr());
        let a = fold_128_aarch64(x0, x1, k128);
        let a = fold_128_aarch64(a, x2, k128);
        (k128, fold_128_aarch64(a, x3, k128))
    };

    while rem >= 16 {
        // SAFETY: `rem >= 16` guarantees a 16-byte load and `ptr.add(16)` are in bounds.
        unsafe {
            acc = fold_128_aarch64(acc, vreinterpretq_u64_u8(vld1q_u8(ptr)), k128);
            ptr = ptr.add(16);
        }
        rem -= 16;
    }

    let mut final16 = [0u8; 16];
    // SAFETY: `final16` is 16 bytes; `ptr..ptr+rem` is the untouched tail of `data`.
    let tail = unsafe {
        vst1q_u8(final16.as_mut_ptr(), vreinterpretq_u8_u64(acc));
        core::slice::from_raw_parts(ptr, rem)
    };
    let c = crc64_nvme_update_table1(0, &final16);
    crc64_nvme_update_table1(c, tail)
}

/// Incrementally update a reflected CRC-64/NVME accumulator (init with `u64::MAX`, finalize with `!crc`).
///
/// Automatically dispatches inputs `>= 128` bytes to hardware 128-bit `PCLMULQDQ` (`x86_64`)
/// or `ARMv8 PMULL` (`aarch64`) carry-less folding, falling back to portable Slicing-by-8.
pub fn crc64_nvme_update(crc: u64, data: &[u8]) -> u64 {
    if data.len() >= 128 {
        #[cfg(target_arch = "x86_64")]
        {
            if std::arch::is_x86_feature_detected!("pclmulqdq")
                && std::arch::is_x86_feature_detected!("sse4.1")
            {
                // SAFETY: Runtime feature check confirmed SSE4.1 + PCLMULQDQ.
                return unsafe { crc64_nvme_update_pclmulqdq(crc, data) };
            }
        }
        #[cfg(all(
            target_arch = "aarch64",
            target_feature = "neon",
            target_endian = "little"
        ))]
        {
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: Runtime feature check confirmed ARMv8 PMULL (`aes`).
                return unsafe { crc64_nvme_update_pmull(crc, data) };
            }
        }
        return crc64_nvme_update_slice8(crc, data);
    }
    crc64_nvme_update_table1(crc, data)
}

/// Compute CRC-64/NVME checksum (matches AWS S3 `CRC64NVME`).
pub fn crc64_nvme(data: &[u8]) -> u64 {
    !crc64_nvme_update(0xFFFF_FFFF_FFFF_FFFFu64, data)
}
