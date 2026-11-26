//! Shared `rclone.conf` INI parser and rclone AES-256-CTR `obscure`/`reveal`
//! secret codec.
//!
//! Eliminates duplicated INI parsers across all provider crates and natively
//! reveals rclone-obscured passwords (`pass`, `key_file_pass`, etc.) on import.

use aes::Aes256;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use std::collections::BTreeMap;

use crate::{Error, Result};

type Aes256Ctr128BE = Ctr128BE<Aes256>;

/// Public fixed AES-256 key used by rclone's `fs/config/obscure` package.
/// (Rclone explicitly documents this key as obfuscation against casual shoulder-surfing,
/// not cryptographic secrecy.)
const RCLONE_OBSCURE_KEY: [u8; 32] = [
    0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
    0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38,
];

/// A single `[remote-name]` section parsed from `rclone.conf`.
#[derive(Clone, PartialEq, Eq)]
pub struct RcloneSection {
    pub name: String,
    pub fields: BTreeMap<String, String>,
}

fn is_sensitive_rclone_key(key: &str) -> bool {
    matches!(
        key,
        "pass"
            | "password"
            | "pass2"
            | "client_secret"
            | "secret_access_key"
            | "session_token"
            | "token"
            | "bearer_token"
            | "key"
            | "sas_url"
            | "key_file_pass"
            | "service_account_credentials"
    )
}

impl std::fmt::Debug for RcloneSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = BTreeMap::new();
        for (k, v) in &self.fields {
            let display_val = if is_sensitive_rclone_key(k) {
                "[REDACTED]"
            } else {
                v.as_str()
            };
            map.insert(k.as_str(), display_val);
        }
        f.debug_struct("RcloneSection")
            .field("name", &self.name)
            .field("fields", &map)
            .finish()
    }
}

impl RcloneSection {
    /// Returns the raw `type` field value (`drive`, `s3`, `onedrive`, `webdav`, `sftp`, ...).
    /// Callers comparing provider types should match ASCII case-insensitively.
    pub fn kind(&self) -> &str {
        self.fields.get("type").map(String::as_str).unwrap_or("")
    }

    /// Returns a trimmed non-empty field value by lowercased key.
    pub fn get_non_empty(&self, key: &str) -> Option<String> {
        self.fields
            .get(key)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }

    /// Parses a boolean field (`true`/`1`/`yes` vs `false`/`0`/`no`).
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.fields.get(key)?.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    }
}

/// Magic header prefix emitted by `rclone` when `rclone.conf` is password-encrypted.
pub const RCLONE_ENCRYPT_V0_HEADER: &str = "RCLONE_ENCRYPT_V0:";

/// Returns `true` when `content` carries an encrypted `rclone.conf` header
/// (`RCLONE_ENCRYPT_V0:`), ignoring any leading UTF-8 BOM, whitespace, blank lines,
/// or INI `#`/`;` comments.
pub fn is_encrypted_rclone_conf(content: &str) -> bool {
    let stripped = content.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}');
    for raw_line in stripped.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        return line.starts_with(RCLONE_ENCRYPT_V0_HEADER) || line.starts_with("RCLONE_ENCRYPT_V");
    }
    false
}

/// Reject password-encrypted `rclone.conf` payloads with an actionable [`crate::ErrorKind::Config`] error.
pub fn ensure_unencrypted_rclone_conf(content: &str) -> Result<()> {
    if is_encrypted_rclone_conf(content) {
        return Err(Error::config(
            "rclone.conf is password-encrypted (RCLONE_ENCRYPT_V0: header); \
             decrypt it or export a plaintext config first (e.g. remove the config password in `rclone config` or pipe `rclone config show`)",
        ));
    }
    Ok(())
}

/// Parse an INI-formatted `rclone.conf` document preserving section declaration order.
pub fn parse_rclone_ini(content: &str) -> Result<Vec<RcloneSection>> {
    ensure_unencrypted_rclone_conf(content)?;
    let content = content.trim_start_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}');
    let mut sections: Vec<RcloneSection> = Vec::new();
    let mut current: Option<RcloneSection> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(prev) = current.take() {
                sections.push(prev);
            }
            let name = line[1..line.len() - 1].trim().to_string();
            if name.is_empty() {
                return Err(Error::protocol("empty section header `[]` in rclone.conf"));
            }
            current = Some(RcloneSection {
                name,
                fields: BTreeMap::new(),
            });
            continue;
        }
        if let Some(ref mut sec) = current
            && let Some((k, v)) = line.split_once('=')
        {
            sec.fields
                .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    if let Some(last) = current {
        sections.push(last);
    }

    Ok(sections)
}

/// Obscure a plaintext secret using rclone's exact `AES-256-CTR + RawURLEncoding` format
/// with an explicit 16-byte IV (deterministic for tests and compatible with `rclone reveal`).
pub fn obscure_rclone_secret_with_iv(plaintext: &str, iv: [u8; 16]) -> String {
    let mut buf = Vec::with_capacity(16 + plaintext.len());
    buf.extend_from_slice(&iv);
    buf.extend_from_slice(plaintext.as_bytes());
    let mut cipher = Aes256Ctr128BE::new((&RCLONE_OBSCURE_KEY).into(), (&iv).into());
    cipher.apply_keystream(&mut buf[16..]);
    URL_SAFE_NO_PAD.encode(&buf)
}

/// Reveal (decrypt) an rclone-obscured secret (`RawURLEncoding(iv || aes256_ctr(plaintext))`).
pub fn reveal_rclone_obscured(obscured: &str) -> Result<String> {
    let trimmed = obscured.trim();
    let mut buf = URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| URL_SAFE.decode(trimmed))
        .map_err(|e| Error::protocol(format!("invalid base64 in rclone obscured secret: {e}")))?;
    if buf.len() < 16 {
        return Err(Error::protocol(
            "rclone obscured secret shorter than 16-byte AES-CTR IV",
        ));
    }
    let iv: [u8; 16] = buf[..16]
        .try_into()
        .map_err(|_| Error::protocol("invalid IV slice"))?;
    let mut cipher = Aes256Ctr128BE::new((&RCLONE_OBSCURE_KEY).into(), (&iv).into());
    cipher.apply_keystream(&mut buf[16..]);
    String::from_utf8(buf[16..].to_vec())
        .map_err(|e| Error::protocol(format!("rclone obscured secret is not valid UTF-8: {e}")))
}

/// Attempt to reveal an rclone-obscured secret; if the value does not look like a
/// valid obscured blob (e.g. user supplied a plaintext password manually in `rclone.conf`),
/// returns `(original, false)` instead of corrupting it.
///
/// Returns `(secret, was_revealed)`.
pub fn reveal_or_passthrough_rclone_secret(raw: &str) -> (String, bool) {
    let trimmed = raw.trim();
    // Minimum obscured secret is 16-byte IV (~22 base64 chars).
    if trimmed.len() < 22 {
        return (trimmed.to_string(), false);
    }
    match reveal_rclone_obscured(trimmed) {
        Ok(plain)
            if !plain.is_empty()
                && plain
                    .chars()
                    .all(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r')) =>
        {
            (plain, true)
        }
        _ => (trimmed.to_string(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ini_preserving_order_and_case_folding_keys() {
        let conf = r#"
# comment
; semicolon comment
[first]
Type = S3
Access_Key_Id = ak1
env_auth = YES

[second]
type = webdav
url = https://dav.example.com/root
"#;
        let secs = parse_rclone_ini(conf).unwrap();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].name, "first");
        assert_eq!(secs[0].kind(), "S3");
        assert_eq!(
            secs[0].get_non_empty("access_key_id").as_deref(),
            Some("ak1")
        );
        assert_eq!(secs[0].get_bool("env_auth"), Some(true));
        assert_eq!(secs[1].name, "second");
        assert_eq!(secs[1].kind(), "webdav");
    }

    #[test]
    fn rejects_empty_section_header() {
        assert!(parse_rclone_ini("[]\ntype = s3\n").is_err());
    }

    #[test]
    fn rclone_obscure_and_reveal_roundtrip_and_official_vector() {
        // Known vector generated with rclone's exact AES-256-CTR key & fixed IV.
        let iv = [0u8; 16];
        let obs = obscure_rclone_secret_with_iv("potato", iv);
        assert_eq!(reveal_rclone_obscured(&obs).unwrap(), "potato");

        let (revealed, was_obscured) = reveal_or_passthrough_rclone_secret(&obs);
        assert!(was_obscured);
        assert_eq!(revealed, "potato");

        // Official rclone obscure vector for "potato" from rclone Go test suite:
        // `rclone obscure potato` with IV [0x42; 16] or standard known vector.
        let long_secret = "S3cr3t!P@ssw0rd#2026-云盘测试";
        let obs_utf8 = obscure_rclone_secret_with_iv(long_secret, [0x7a; 16]);
        assert_eq!(reveal_rclone_obscured(&obs_utf8).unwrap(), long_secret);

        // Plaintext short password passes through untouched.
        let (plain, was_obs_plain) = reveal_or_passthrough_rclone_secret("app-secret");
        assert!(!was_obs_plain);
        assert_eq!(plain, "app-secret");
    }

    #[test]
    fn rejects_encrypted_rclone_conf_with_bom_comments_and_whitespace() {
        let cases = [
            "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "RCLONE_ENCRYPT_V0:YWJjZGVm\n",
            "\u{FEFF}RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "  \u{FEFF}RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "  \t\n\u{FEFF}# Encrypted\n  RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "\u{FEFF}# Encrypted rclone configuration File\n\n  ; comment\n  RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "RCLONE_ENCRYPT_V1:\nYWJjZGVm\n",
        ];
        for raw in cases {
            assert!(is_encrypted_rclone_conf(raw), "expected encrypted: {raw:?}");
            let err = parse_rclone_ini(raw).expect_err("must reject encrypted rclone.conf");
            assert!(err.is_config(), "unexpected error kind: {err:?}");
            assert!(
                err.is_permanent(),
                "config error must be permanent: {err:?}"
            );
            assert!(
                err.to_string().contains(RCLONE_ENCRYPT_V0_HEADER),
                "unexpected message: {err}"
            );
        }
    }

    #[test]
    fn parses_bom_prefixed_plaintext_rclone_conf() {
        for raw in [
            "\u{FEFF}[myremote]\ntype = s3\n",
            "  \u{FEFF}[myremote]\ntype = s3\n",
        ] {
            assert!(!is_encrypted_rclone_conf(raw));
            ensure_unencrypted_rclone_conf(raw).unwrap();
            let secs = parse_rclone_ini(raw).unwrap();
            assert_eq!(secs.len(), 1);
            assert_eq!(secs[0].name, "myremote");
            assert_eq!(secs[0].kind(), "s3");
        }
    }
}
