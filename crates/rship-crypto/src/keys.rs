//! Key derivation (Argon2id + domain-separated HKDF-SHA256) with `zeroize` memory scrubbing.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rship_core::{Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::filename::NAME_AAD;

const DEFAULT_SALT: &[u8] = b"rship-crypto-v1-default-salt";
const INFO_DATA_KEY: &[u8] = b"rship-stream-oae2-v1-data";
const INFO_NAME_ENC_KEY: &[u8] = b"rship-stream-oae2-v1-name-enc";
const INFO_NAME_MAC_KEY: &[u8] = b"rship-stream-oae2-v1-name-mac";

/// 256-bit master key zeroized on drop.
#[derive(Clone)]
pub struct MasterKey {
    bytes: [u8; 32],
}

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Generate a cryptographically random 256-bit master key using the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::Rng as _;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Encode this 256-bit master key as a lowercase 64-character hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let mut raw = hex::decode(hex_str.trim())
            .map_err(|e| Error::protocol(format!("invalid hex master key: {e}")))?;
        if raw.len() != 32 {
            let len = raw.len();
            raw.zeroize();
            return Err(Error::protocol(format!(
                "master key must be 32 bytes (64 hex chars), got {len} bytes",
            )));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        raw.zeroize();
        Ok(Self { bytes })
    }

    /// Derive a 256-bit master key from a user passphrase and salt via Argon2id.
    pub fn from_passphrase(passphrase: &str, salt: Option<&[u8]>) -> Result<Self> {
        if passphrase.is_empty() {
            return Err(Error::protocol("encryption passphrase cannot be empty"));
        }
        let salt_bytes = salt.filter(|s| s.len() >= 8).unwrap_or(DEFAULT_SALT);
        // OWASP-aligned memory-hard Argon2id parameters (19 MiB, 2 iterations, 1 lane).
        let params = Params::new(19 * 1024, 2, 1, Some(32))
            .map_err(|e| Error::protocol(format!("argon2 params: {e}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut out = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt_bytes, &mut out)
            .map_err(|e| Error::protocol(format!("argon2id key derivation failed: {e}")))?;
        Ok(Self { bytes: out })
    }

    pub fn derive_subkeys(&self) -> CryptoKeys {
        let hk = Hkdf::<Sha256>::new(None, &self.bytes);
        let mut data_key = [0u8; 32];
        let mut name_enc_key = [0u8; 32];
        let mut name_mac_key = [0u8; 32];
        hk.expand(INFO_DATA_KEY, &mut data_key)
            .expect("32-byte HKDF expand");
        hk.expand(INFO_NAME_ENC_KEY, &mut name_enc_key)
            .expect("32-byte HKDF expand");
        hk.expand(INFO_NAME_MAC_KEY, &mut name_mac_key)
            .expect("32-byte HKDF expand");
        // Precompute RFC 2104 HMAC-SHA256 inner/outer block midstates once so each
        // `encrypt_segment` clones the midstate instead of re-hashing 64-byte pads.
        const HMAC_BLOCK: usize = 64;
        let mut ipad = [0x36u8; HMAC_BLOCK];
        let mut opad = [0x5cu8; HMAC_BLOCK];
        for i in 0..32 {
            ipad[i] ^= name_mac_key[i];
            opad[i] ^= name_mac_key[i];
        }
        let mut name_mac_inner = Sha256::new();
        name_mac_inner.update(ipad);
        name_mac_inner.update(NAME_AAD);
        name_mac_inner.update([0u8]);
        let mut name_mac_outer = Sha256::new();
        name_mac_outer.update(opad);
        ipad.zeroize();
        opad.zeroize();
        CryptoKeys {
            data_key,
            name_enc_key,
            name_mac_key,
            name_mac_inner,
            name_mac_outer,
        }
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Domain-separated subkeys derived from [`MasterKey`].
#[derive(Clone)]
pub struct CryptoKeys {
    pub(crate) data_key: [u8; 32],
    pub(crate) name_enc_key: [u8; 32],
    pub(crate) name_mac_key: [u8; 32],
    pub(crate) name_mac_inner: Sha256,
    pub(crate) name_mac_outer: Sha256,
}

impl std::fmt::Debug for CryptoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CryptoKeys([REDACTED])")
    }
}

impl Drop for CryptoKeys {
    fn drop(&mut self) {
        self.data_key.zeroize();
        self.name_enc_key.zeroize();
        self.name_mac_key.zeroize();
        self.name_mac_inner = Sha256::new();
        self.name_mac_outer = Sha256::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_random_master_key_round_trips_hex() {
        let k1 = MasterKey::generate();
        let k2 = MasterKey::generate();
        let h1 = k1.to_hex();
        let h2 = k2.to_hex();
        assert_eq!(h1.len(), 64);
        assert_eq!(h2.len(), 64);
        assert_ne!(h1, h2);
        let parsed = MasterKey::from_hex(&h1).unwrap();
        assert_eq!(parsed.to_hex(), h1);
    }

    #[test]
    fn prop_master_key_hex_bijection_and_subkey_domain_separation() {
        use crate::prop_test::{SeedGuard, rng_for, seeds_for};
        use rand::{Rng, RngExt};

        let seeds = seeds_for(0x5253_4849_4B45_5901, 256);
        let total = seeds.len();
        for (case_idx, seed) in seeds {
            let _guard = SeedGuard::new(
                "master_key_hex_bijection_and_subkey_domain_separation",
                case_idx,
                total,
                seed,
            );
            let mut rng = rng_for(seed);

            let mut raw = [0u8; 32];
            rng.fill_bytes(&mut raw);
            let key = MasterKey::from_bytes(raw);

            // Debug formatting must never leak key material.
            let dbg_master = format!("{key:?}");
            assert!(dbg_master.contains("REDACTED"), "seed={seed:#018x}");

            // Hex roundtrip (lowercase, uppercase, surrounding whitespace).
            let hex_str = key.to_hex();
            assert_eq!(hex_str.len(), 64, "seed={seed:#018x}");
            assert_eq!(
                MasterKey::from_hex(&hex_str).unwrap().to_hex(),
                hex_str,
                "seed={seed:#018x}"
            );
            let padded_upper = format!("  {}\n", hex_str.to_ascii_uppercase());
            assert_eq!(
                MasterKey::from_hex(&padded_upper).unwrap().to_hex(),
                hex_str,
                "seed={seed:#018x}"
            );

            // Deterministic HKDF subkeys with pairwise domain separation.
            let sub1 = key.derive_subkeys();
            let sub2 = key.derive_subkeys();
            assert_eq!(sub1.data_key, sub2.data_key, "seed={seed:#018x}");
            assert_eq!(sub1.name_enc_key, sub2.name_enc_key, "seed={seed:#018x}");
            assert_eq!(sub1.name_mac_key, sub2.name_mac_key, "seed={seed:#018x}");
            assert_ne!(sub1.data_key, raw, "seed={seed:#018x}");
            assert_ne!(sub1.name_enc_key, raw, "seed={seed:#018x}");
            assert_ne!(sub1.name_mac_key, raw, "seed={seed:#018x}");
            assert_ne!(sub1.data_key, sub1.name_enc_key, "seed={seed:#018x}");
            assert_ne!(sub1.data_key, sub1.name_mac_key, "seed={seed:#018x}");
            assert_ne!(sub1.name_enc_key, sub1.name_mac_key, "seed={seed:#018x}");
            assert!(
                format!("{sub1:?}").contains("REDACTED"),
                "seed={seed:#018x}"
            );

            // Single-bit difference in master key changes all derived subkeys.
            let mut raw2 = raw;
            let bit_idx = rng.random_range(0usize..256);
            raw2[bit_idx / 8] ^= 1u8 << (bit_idx % 8);
            let sub_other = MasterKey::from_bytes(raw2).derive_subkeys();
            assert_ne!(sub1.data_key, sub_other.data_key, "seed={seed:#018x}");
            assert_ne!(
                sub1.name_enc_key, sub_other.name_enc_key,
                "seed={seed:#018x}"
            );
            assert_ne!(
                sub1.name_mac_key, sub_other.name_mac_key,
                "seed={seed:#018x}"
            );

            // Malformed hex (truncated, oversized, invalid char) must cleanly return Err.
            let cut = rng.random_range(0usize..64);
            assert!(
                MasterKey::from_hex(&hex_str[..cut]).is_err(),
                "seed={seed:#018x}"
            );
            let extra = format!("{hex_str}00");
            assert!(MasterKey::from_hex(&extra).is_err(), "seed={seed:#018x}");
            let mut bad_hex = hex_str.into_bytes();
            let pos = rng.random_range(0usize..64);
            bad_hex[pos] = b'z';
            assert!(
                MasterKey::from_hex(std::str::from_utf8(&bad_hex).unwrap()).is_err(),
                "seed={seed:#018x}"
            );
        }
    }
}
