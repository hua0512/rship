//! Portable CRC-32C (Castagnoli) with slice-by-8 tables and `crc32c_combine`.
//!
//! `rship-core` forbids `unsafe`, so this is the software implementation; backends use
//! their hardware-accelerated CRC for wire checksums. The engine uses this one to verify
//! ranged/chunked source reads against a full-object CRC32C: each part's CRC is computed
//! while streaming and the parts are combined in order with [`crc32c_combine`].

const POLY: u32 = 0x82f6_3b78;

const fn make_tables() -> [[u32; 256]; 8] {
    let mut t = [[0u32; 256]; 8];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[0][i] = c;
        i += 1;
    }
    let mut i = 0;
    while i < 256 {
        let mut s = 1;
        while s < 8 {
            let prev = t[s - 1][i];
            t[s][i] = (prev >> 8) ^ t[0][(prev & 0xff) as usize];
            s += 1;
        }
        i += 1;
    }
    t
}

static TABLES: [[u32; 256]; 8] = make_tables();

/// Continue a CRC-32C over `data` (`crc` is a previous result, `0` to start).
pub fn crc32c_update(crc: u32, data: &[u8]) -> u32 {
    let t = &TABLES;
    let mut c = !crc;
    let (chunks, rest) = data.as_chunks::<8>();
    for b in chunks {
        let lo = c ^ u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let hi = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        c = t[7][(lo & 0xff) as usize]
            ^ t[6][((lo >> 8) & 0xff) as usize]
            ^ t[5][((lo >> 16) & 0xff) as usize]
            ^ t[4][(lo >> 24) as usize]
            ^ t[3][(hi & 0xff) as usize]
            ^ t[2][((hi >> 8) & 0xff) as usize]
            ^ t[1][((hi >> 16) & 0xff) as usize]
            ^ t[0][(hi >> 24) as usize];
    }
    for &b in rest {
        c = (c >> 8) ^ t[0][((c ^ u32::from(b)) & 0xff) as usize];
    }
    !c
}

/// CRC-32C of `data`.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(0, data)
}

fn gf2_times(mat: &[u32; 32], mut vec: u32) -> u32 {
    let mut sum = 0;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 != 0 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_square(square: &mut [u32; 32], mat: &[u32; 32]) {
    for n in 0..32 {
        square[n] = gf2_times(mat, mat[n]);
    }
}

/// CRC-32C of `A || B` given `crc32c(A)`, `crc32c(B)` and `len(B)` (zlib's
/// `crc32_combine`, adapted to the Castagnoli polynomial).
pub fn crc32c_combine(crc1: u32, crc2: u32, mut len2: u64) -> u32 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = [0u32; 32];
    let mut odd = [0u32; 32];
    // Operator for one zero bit.
    odd[0] = POLY;
    let mut row = 1u32;
    for item in odd.iter_mut().skip(1) {
        *item = row;
        row <<= 1;
    }
    gf2_square(&mut even, &odd); // two zero bits
    gf2_square(&mut odd, &even); // four zero bits
    let mut crc1 = crc1;
    loop {
        gf2_square(&mut even, &odd);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        gf2_square(&mut odd, &even);
        if len2 & 1 != 0 {
            crc1 = gf2_times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

/// Lowercase big-endian hex, the form backends store in [`crate::types::Checksum::hex`].
pub fn crc32c_hex(crc: u32) -> String {
    format!("{crc:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bitwise(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
        }
        !c
    }

    #[test]
    fn crc32c_matches_reference_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0, 1, 7, 8, 9, 63, 64, 1000, 10_000] {
            assert_eq!(crc32c(&data[..len]), bitwise(&data[..len]), "len {len}");
        }
        assert_eq!(
            crc32c_update(crc32c(&data[..333]), &data[333..]),
            crc32c(&data)
        );
    }

    #[test]
    fn crc32c_combine_equals_crc_of_concatenation() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 31 + 11) as u8).collect();
        for split in [0usize, 1, 5, 4096, 65_536, 100_001, 200_000] {
            let (a, b) = data.split_at(split);
            assert_eq!(
                crc32c_combine(crc32c(a), crc32c(b), b.len() as u64),
                crc32c(&data),
                "split {split}"
            );
        }
        // Many equal parts combined in order.
        let mut acc = 0u32;
        for part in data.chunks(64 * 1024) {
            acc = crc32c_combine(acc, crc32c(part), part.len() as u64);
        }
        assert_eq!(acc, crc32c(&data));
    }
}
