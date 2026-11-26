//! Azure Blob Storage configuration and blob-path URI encoding.

use std::time::Duration;

use crate::common::http::RetryPolicyConfig;

pub const AZURE_MIN_BLOCK_BYTES: u64 = 256 * 1024;
/// Azure Storage REST API (`2019-12-12` / `2023-11-03`) maximum single block size: 4,000 MiB.
pub const AZURE_MAX_BLOCK_BYTES: u64 = 4_000 * 1024 * 1024;
pub const AZURE_MAX_BLOCKS: u32 = 50_000;
/// Maximum block-blob object size (`50,000 * 4,000 MiB` ≈ 190.7 TiB).
pub const AZURE_MAX_OBJECT_BYTES: u64 = AZURE_MAX_BLOCK_BYTES * (AZURE_MAX_BLOCKS as u64);
pub const DEFAULT_AZURE_BLOCK_SIZE: u64 = 8 * 1024 * 1024;
pub const DEFAULT_AZURE_SINGLE_SHOT_MAX: u64 = 16 * 1024 * 1024;

/// Well-known Azurite local storage emulator credentials (public Microsoft dev key).
pub const AZURITE_ACCOUNT: &str = "devstoreaccount1";
pub const AZURITE_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
pub const AZURITE_ENDPOINT: &str = "http://127.0.0.1:10000/devstoreaccount1";

#[derive(Debug, Clone)]
pub struct AzureBlobConfig {
    pub remote_name: String,
    pub account: String,
    pub container: String,
    pub prefix: String,
    /// Optional custom service endpoint (e.g. `https://<acct>.blob.core.chinacloudapi.cn`,
    /// Azurite `http://127.0.0.1:10000/devstoreaccount1`, or mock test server URL).
    pub endpoint: Option<String>,
    /// Optional Azure access tier (`Hot`, `Cool`, `Cold`, `Archive`).
    pub access_tier: Option<String>,
    pub block_size: u64,
    pub single_shot_max_bytes: u64,
    /// Maximum number of control-plane retries after the initial request.
    pub max_retries: u32,
    /// Base delay for full-jitter exponential backoff on control-plane retries.
    pub base_retry_delay: Duration,
    /// Maximum delay ceiling applied to both exponential backoff and `Retry-After` hints.
    pub max_retry_delay: Duration,
}

impl AzureBlobConfig {
    pub fn new(
        remote_name: impl Into<String>,
        account: impl Into<String>,
        container: impl Into<String>,
    ) -> Self {
        let retry = RetryPolicyConfig::default();
        Self {
            remote_name: remote_name.into(),
            account: account.into(),
            container: container.into(),
            prefix: String::new(),
            endpoint: None,
            access_tier: None,
            block_size: DEFAULT_AZURE_BLOCK_SIZE,
            single_shot_max_bytes: DEFAULT_AZURE_SINGLE_SHOT_MAX,
            max_retries: retry.max_retries,
            base_retry_delay: retry.base_delay,
            max_retry_delay: retry.max_delay,
        }
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_retry_delays(mut self, base_delay: Duration, max_delay: Duration) -> Self {
        self.base_retry_delay = base_delay;
        self.max_retry_delay = max_delay;
        self
    }

    pub fn retry_policy(&self) -> RetryPolicyConfig {
        RetryPolicyConfig::new()
            .with_max_retries(self.max_retries)
            .with_delays(self.base_retry_delay, self.max_retry_delay)
    }

    pub fn effective_endpoint(&self) -> String {
        if let Some(ep) = &self.endpoint
            && !ep.trim().is_empty()
        {
            return ep.trim_end_matches('/').to_string();
        }
        format!("https://{}.blob.core.windows.net", self.account)
    }

    pub fn container_url(&self) -> String {
        format!(
            "{}/{}",
            self.effective_endpoint(),
            azure_encode_segment(&self.container)
        )
    }

    pub fn blob_url(&self, full_blob_name: &str) -> String {
        format!(
            "{}/{}",
            self.container_url(),
            azure_encode_blob_path(full_blob_name)
        )
    }

    pub fn normalized_prefix(&self) -> String {
        let trimmed = self.prefix.trim_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}/")
        }
    }

    pub fn full_key(&self, rel: &str) -> String {
        let p = self.normalized_prefix();
        let r = rel.trim_start_matches('/');
        if p.is_empty() {
            r.to_string()
        } else if r.is_empty() {
            p
        } else {
            format!("{p}{r}")
        }
    }

    pub(crate) fn dir_marker_key(&self, rel: &str) -> String {
        let fk = self.full_key(rel);
        let trimmed = fk.trim_end_matches('/');
        if trimmed.is_empty() {
            String::new()
        } else {
            format!("{trimmed}/")
        }
    }

    pub fn strip_prefix<'a>(&self, full: &'a str) -> Option<&'a str> {
        let p = self.normalized_prefix();
        if p.is_empty() {
            Some(full)
        } else {
            full.strip_prefix(&p)
        }
    }
}

/// Append `params` to `base` using strict RFC 3986 percent-encoding (`%20` for space,
/// `%2B` for `+`), never `application/x-www-form-urlencoded` (`+` for space).
pub(crate) fn append_rfc3986_query(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let mut out = String::with_capacity(base.len() + params.len() * 24);
    out.push_str(base);
    let mut first = !base.contains('?');
    for &(k, v) in params {
        out.push(if first { '?' } else { '&' });
        first = false;
        out.push_str(&crate::common::http::percent_encode_segment(k));
        out.push('=');
        out.push_str(&crate::common::http::percent_encode_segment(v));
    }
    out
}

/// Percent-decode `%XX` sequences strictly as UTF-8 bytes without turning `+` into space.
pub(crate) fn percent_decode_rfc3986(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Some(hi) = (bytes[i + 1] as char).to_digit(16)
            && let Some(lo) = (bytes[i + 2] as char).to_digit(16)
        {
            out.push(((hi << 4) | lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encode a single URI path segment per RFC 3986 (leaving `[A-Za-z0-9._~-]` unescaped).
pub fn azure_encode_segment(seg: &str) -> String {
    crate::common::http::percent_encode_segment(seg)
}

/// Percent-encode each `/`-delimited segment of an Azure Blob path, preserving `/` separators.
pub fn azure_encode_blob_path(path: &str) -> String {
    crate::common::http::percent_encode_path(path.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_azure_blob_paths_preserving_slashes() {
        assert_eq!(
            azure_encode_blob_path("dir/a + b #1?q=2/中文.txt"),
            "dir/a%20%2B%20b%20%231%3Fq%3D2/%E4%B8%AD%E6%96%87.txt"
        );
    }

    #[test]
    fn builds_default_and_custom_endpoints() {
        let cfg = AzureBlobConfig::new("az", "myacct", "data");
        assert_eq!(
            cfg.blob_url("a/b c.txt"),
            "https://myacct.blob.core.windows.net/data/a/b%20c.txt"
        );
        let mut azurite = AzureBlobConfig::new("local-az", AZURITE_ACCOUNT, "test");
        azurite.endpoint = Some(AZURITE_ENDPOINT.to_string());
        assert_eq!(
            azurite.container_url(),
            "http://127.0.0.1:10000/devstoreaccount1/test"
        );
    }

    #[test]
    fn block_and_object_limits_match_azure_2019_12_12_spec() {
        assert_eq!(AZURE_MAX_BLOCK_BYTES, 4_000 * 1024 * 1024);
        assert_eq!(
            AZURE_MAX_OBJECT_BYTES,
            AZURE_MAX_BLOCK_BYTES * u64::from(AZURE_MAX_BLOCKS)
        );
    }

    #[test]
    fn rfc3986_query_encoding_and_decoding_preserve_spaces_and_plus() {
        let url = append_rfc3986_query(
            "https://acct.blob.core.windows.net/cont",
            &[
                ("restype", "container"),
                ("comp", "list"),
                ("prefix", "my dir/a+b/"),
                ("blockid", "ab+cd/ef=="),
            ],
        );
        assert!(!url.contains('+'));
        assert!(url.contains("prefix=my%20dir%2Fa%2Bb%2F"));
        assert!(url.contains("blockid=ab%2Bcd%2Fef%3D%3D"));

        assert_eq!(percent_decode_rfc3986("a%20b+c%2Bd%09e"), "a b+c+d\te");
        assert_eq!(percent_decode_rfc3986("%E4%B8%AD%E6%96%87"), "中文");
    }

    #[test]
    fn dir_marker_key_normalizes_trailing_slash_with_and_without_prefix() {
        let mut cfg = AzureBlobConfig::new("az", "myacct", "data");
        assert_eq!(cfg.dir_marker_key("sub/dir/"), "sub/dir/");
        assert_eq!(cfg.dir_marker_key("sub/dir"), "sub/dir/");
        assert_eq!(cfg.dir_marker_key(""), "");
        cfg.prefix = "root/".to_string();
        assert_eq!(cfg.dir_marker_key("sub"), "root/sub/");
        assert_eq!(cfg.dir_marker_key(""), "root/");
    }
}
