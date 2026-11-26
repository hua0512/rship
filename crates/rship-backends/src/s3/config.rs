//! Configuration and credentials for [`crate::s3::S3Backend`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use url::{Host, Url};

use crate::s3::credentials::S3CredentialSource;
use crate::s3::provider::S3Provider;

/// Server-Side Encryption policy applied on `PutObject`, `CreateMultipartUpload`,
/// and `CopyObject` (plus `GetObject`/`HeadObject`/`UploadPart` for SSE-C).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum S3ServerSideEncryption {
    /// SSE-S3 (`x-amz-server-side-encryption: AES256`).
    Aes256,
    /// SSE-KMS (`x-amz-server-side-encryption: aws:kms` + optional KMS Key ARN/ID).
    AwsKms { key_id: Option<String> },
    /// SSE-C (`x-amz-server-side-encryption-customer-algorithm: AES256` + base64 256-bit key).
    SseC { customer_key_b64: String },
}

impl std::fmt::Debug for S3ServerSideEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes256 => f.write_str("Aes256"),
            Self::AwsKms { key_id } => f.debug_struct("AwsKms").field("key_id", key_id).finish(),
            Self::SseC { .. } => f
                .debug_struct("SseC")
                .field("customer_key_b64", &"[REDACTED]")
                .finish(),
        }
    }
}

impl S3ServerSideEncryption {
    pub fn as_header_value(&self) -> &'static str {
        match self {
            Self::Aes256 | Self::SseC { .. } => "AES256",
            Self::AwsKms { .. } => "aws:kms",
        }
    }

    pub fn sse_c_from_bytes(raw_key: &[u8]) -> rship_core::Result<Self> {
        if raw_key.len() != 32 {
            return Err(rship_core::Error::config(format!(
                "SSE-C requires a 32-byte (256-bit) AES key, got {} bytes",
                raw_key.len()
            )));
        }
        Ok(Self::SseC {
            customer_key_b64: BASE64_STD.encode(raw_key),
        })
    }

    pub fn sse_c_from_base64(key_b64: &str) -> rship_core::Result<Self> {
        let trimmed = key_b64.trim();
        let decoded = BASE64_STD
            .decode(trimmed)
            .map_err(|e| rship_core::Error::config(format!("invalid base64 SSE-C key: {e}")))?;
        Self::sse_c_from_bytes(&decoded)
    }

    pub fn parse(raw: &str, kms_key_id: Option<String>) -> Option<Self> {
        let key_id = kms_key_id.filter(|s| !s.trim().is_empty());
        match raw.trim().to_ascii_lowercase().as_str() {
            "aes256" | "sse-s3" | "s3" => Some(Self::Aes256),
            "aws:kms" | "kms" | "sse-kms" | "aws_kms" => Some(Self::AwsKms { key_id }),
            _ => None,
        }
    }
}

/// Infer standard RFC MIME `Content-Type` from a file path's extension so S3
/// static-website / CDN uploads preserve accurate browser and media types,
/// falling back to `application/octet-stream` for unknown or extensionless keys.
pub fn infer_content_type(path: &str) -> &'static str {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    let Some((_, ext)) = file_name.rsplit_once('.') else {
        return "application/octet-stream";
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" | "cjs" => "text/javascript; charset=utf-8",
        "json" | "jsonl" | "ndjson" => "application/json",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "txt" | "log" => "text/plain; charset=utf-8",
        "md" | "markdown" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "tsv" => "text/tab-separated-values; charset=utf-8",
        "yaml" | "yml" => "application/yaml",
        "toml" => "application/toml",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "bmp" => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "m4a" => "audio/mp4",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "zst" => "application/zstd",
        "7z" => "application/x-7z-compressed",
        "parquet" => "application/vnd.apache.parquet",
        _ => "application/octet-stream",
    }
}

/// Controls how `x-amz-content-sha256` is computed on `PutObject` and `UploadPart`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PayloadSigningMode {
    /// Default (`PLAN.md` §3.6): `UNSIGNED-PAYLOAD` over `https://`, automatic
    /// real SHA-256 over plain `http://` (zero `aws-chunked` trailers).
    #[default]
    Auto,
    /// Always compute and sign real SHA-256 payload digests (even over HTTPS).
    StrictSha256,
    /// Always use `UNSIGNED-PAYLOAD` (useful only for trusted local/private proxies).
    Unsigned,
}

impl PayloadSigningMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::StrictSha256 => "strict_sha256",
            Self::Unsigned => "unsigned",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "unsigned" | "unsigned_payload" | "unsigned-payload" => Some(Self::Unsigned),
            "strict" | "strict_sha256" | "strict-sha256" | "sha256" => Some(Self::StrictSha256),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field(
                "secret_access_key",
                &if self.secret_access_key.is_empty() {
                    "<empty>"
                } else {
                    "[REDACTED]"
                },
            )
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl S3Credentials {
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token: None,
        }
    }

    pub fn with_session_token(mut self, token: Option<String>) -> Self {
        self.session_token = token.filter(|s| !s.is_empty());
        self
    }

    /// Resolve credentials from standard AWS environment variables when `env_auth = true`.
    pub fn from_env() -> Option<Self> {
        let ak = std::env::var("AWS_ACCESS_KEY_ID")
            .ok()
            .filter(|s| !s.is_empty())?;
        let sk = std::env::var("AWS_SECRET_ACCESS_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let st = std::env::var("AWS_SESSION_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        Some(Self {
            access_key_id: ak,
            secret_access_key: sk,
            session_token: st,
        })
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct S3Config {
    pub remote_name: String,
    pub provider: S3Provider,
    /// Target bucket name.
    pub bucket: String,
    /// Optional key prefix within the bucket (normalized without leading/trailing `/`).
    pub prefix: String,
    pub region: String,
    /// Custom S3 endpoint URL (e.g. `https://<acct>.r2.cloudflarestorage.com`,
    /// `http://127.0.0.1:9000`, or `None` for standard AWS regional endpoint).
    pub endpoint: Option<String>,
    /// Override path-style (`https://endpoint/bucket/key`) vs virtual-hosted-style
    /// (`https://bucket.endpoint/key`). Defaults to provider profile setting.
    pub force_path_style: Option<bool>,
    pub credentials: S3Credentials,
    /// Optional dynamic credential source (`AwsChain` for env/profile/ECS/IMDSv2).
    /// When `None`, static [`Self::credentials`] are used with zero async overhead.
    pub credential_source: Option<S3CredentialSource>,
    pub payload_signing: PayloadSigningMode,
    /// Optional Server-Side Encryption policy (`SSE-S3` or `SSE-KMS`).
    pub server_side_encryption: Option<S3ServerSideEncryption>,
    /// Optional override for single-shot `PutObject` cutoff (defaults to 16 MiB).
    pub single_shot_max_bytes: Option<u64>,
    /// Optional override for multipart chunk size (defaults to 16 MiB).
    pub default_chunk_size: Option<u64>,
    /// Optional override for min part size (for testing multipart below 5 MiB).
    pub min_part_bytes_override: Option<u64>,
    /// Optional override for single-request `CopyObject` ceiling (defaults to 512 MiB,
    /// clamped by `profile.max_part_bytes`; objects larger than this automatically use
    /// multipart `UploadPartCopy`).
    pub max_single_copy_bytes: Option<u64>,
    /// Optional storage class header (`x-amz-storage-class`).
    pub storage_class: Option<String>,
    /// Send AWS-supported upload checksum headers (`CRC64NVME` on AWS, `CRC32C` on
    /// R2/MinIO/Tigris) on uploads when enabled (default: `true`).
    ///
    /// Known source checksums are sent directly without spooling; large `UNSIGNED-PAYLOAD`
    /// streaming uploads hash on-the-fly without disk spooling and verify server response
    /// checksums / ETags immediately on commit.
    pub send_upload_checksum: bool,
    /// Pin `GetObject` range reads with `If-Match: <etag>` (default: `true`).
    /// Disable (`false`) on legacy S3/Swift gateways that mis-evaluate `If-Match` on SLOs.
    pub pin_read_etag: bool,
    /// Optional directory for strict-SigV4 / upload-checksum disk spools (avoids Linux `/tmp` `tmpfs`).
    pub spool_dir: Option<PathBuf>,
    /// Max parallel lexicographical prefix workers for `list_stream` (`1` = serial).
    pub list_prefix_concurrency: usize,
    pub max_retries: u32,
    pub base_retry_delay: Duration,
    pub max_retry_delay: Duration,
}

impl S3Config {
    pub fn new(
        remote_name: impl Into<String>,
        provider: S3Provider,
        bucket: impl Into<String>,
        credentials: S3Credentials,
    ) -> Self {
        let prof = provider.profile();
        Self {
            remote_name: remote_name.into(),
            provider,
            bucket: bucket.into(),
            prefix: String::new(),
            region: prof.default_region.to_string(),
            endpoint: None,
            force_path_style: None,
            credentials,
            credential_source: None,
            payload_signing: PayloadSigningMode::Auto,
            server_side_encryption: None,
            single_shot_max_bytes: None,
            default_chunk_size: None,
            min_part_bytes_override: None,
            max_single_copy_bytes: None,
            storage_class: None,
            send_upload_checksum: true,
            pin_read_etag: true,
            spool_dir: None,
            list_prefix_concurrency: 1,
            max_retries: 6,
            base_retry_delay: Duration::from_millis(150),
            max_retry_delay: rship_core::engine::DEFAULT_MAX_RETRY_DELAY,
        }
    }

    /// Region identifier used in AWS SigV4 credential scopes.
    ///
    /// For Alibaba OSS, users sometimes configure `oss-cn-hangzhou` (the endpoint prefix)
    /// rather than `cn-hangzhou`; strip any leading `"oss-"` so SigV4 always signs with
    /// the bare region ID (`cn-hangzhou`).
    pub fn signing_region(&self) -> &str {
        if self.provider == S3Provider::Oss {
            let trimmed = self.region.trim();
            trimmed.strip_prefix("oss-").unwrap_or(trimmed)
        } else {
            &self.region
        }
    }

    /// Returns `true` when the configured SSE mode (`AwsKms` or `SseC`) produces ETags that
    /// are NOT plaintext MD5 digests of the object data.
    pub fn is_non_md5_sse(&self) -> bool {
        matches!(
            self.server_side_encryption,
            Some(S3ServerSideEncryption::AwsKms { .. } | S3ServerSideEncryption::SseC { .. })
        )
    }

    pub fn effective_endpoint(&self) -> String {
        if let Some(ep) = &self.endpoint
            && !ep.trim().is_empty()
        {
            return ep.trim().trim_end_matches('/').to_string();
        }
        match self.provider {
            S3Provider::Aws => format!("https://s3.{}.amazonaws.com", self.region),
            S3Provider::Oss => format!("https://s3.oss-{}.aliyuncs.com", self.signing_region()),
            S3Provider::B2 => format!("https://s3.{}.backblazeb2.com", self.region),
            S3Provider::Wasabi => format!("https://s3.{}.wasabisys.com", self.region),
            S3Provider::DigitalOcean => format!("https://{}.digitaloceanspaces.com", self.region),
            S3Provider::Cos => format!("https://cos.{}.myqcloud.com", self.region),
            S3Provider::Tigris => "https://fly.storage.tigris.dev".to_string(),
            S3Provider::Scaleway => format!("https://s3.{}.scw.cloud", self.region),
            S3Provider::Hetzner => format!("https://{}.your-objectstorage.com", self.region),
            _ => format!("https://s3.{}.amazonaws.com", self.region),
        }
    }

    pub fn use_path_style(&self) -> bool {
        if self.force_path_style == Some(true) {
            return true;
        }
        if self.bucket.contains('.') || is_ip_literal_endpoint(&self.effective_endpoint()) {
            return true;
        }
        self.force_path_style
            .unwrap_or_else(|| self.provider.profile().default_force_path_style)
    }

    pub fn is_https(&self) -> bool {
        self.effective_endpoint()
            .to_ascii_lowercase()
            .starts_with("https://")
    }

    /// Whether uploads should compute real SHA-256 payload digests instead of `UNSIGNED-PAYLOAD`.
    pub fn requires_payload_sha256(&self) -> bool {
        match self.payload_signing {
            PayloadSigningMode::Auto => !self.is_https(),
            PayloadSigningMode::StrictSha256 => true,
            PayloadSigningMode::Unsigned => false,
        }
    }

    pub fn normalized_prefix(&self) -> &str {
        self.prefix.trim_matches('/')
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn with_force_path_style(mut self, force: bool) -> Self {
        self.force_path_style = Some(force);
        self
    }

    pub fn with_payload_signing(mut self, mode: PayloadSigningMode) -> Self {
        self.payload_signing = mode;
        self
    }

    pub fn with_storage_class(mut self, class: impl Into<String>) -> Self {
        self.storage_class = Some(class.into());
        self
    }

    pub fn with_send_upload_checksum(mut self, enabled: bool) -> Self {
        self.send_upload_checksum = enabled;
        self
    }

    pub fn with_pin_read_etag(mut self, enabled: bool) -> Self {
        self.pin_read_etag = enabled;
        self
    }

    pub fn with_spool_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.spool_dir = Some(dir.into());
        self
    }

    pub fn with_list_prefix_concurrency(mut self, concurrency: usize) -> Self {
        self.list_prefix_concurrency = concurrency.max(1);
        self
    }

    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    pub fn with_credential_source(mut self, source: S3CredentialSource) -> Self {
        self.credential_source = Some(source);
        self
    }

    pub fn with_server_side_encryption(mut self, sse: S3ServerSideEncryption) -> Self {
        self.server_side_encryption = Some(sse);
        self
    }
}

fn is_ip_literal_endpoint(endpoint: &str) -> bool {
    Url::parse(endpoint)
        .ok()
        .and_then(|u| u.host().map(|h| matches!(h, Host::Ipv4(_) | Host::Ipv6(_))))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oss_endpoint_and_signing_region_normalize_oss_prefix() {
        let creds = S3Credentials::new("ak", "sk");
        let def = S3Config::new("oss", S3Provider::Oss, "bkt", creds.clone());
        assert_eq!(def.region, "cn-hangzhou");
        assert_eq!(def.signing_region(), "cn-hangzhou");
        assert_eq!(
            def.effective_endpoint(),
            "https://s3.oss-cn-hangzhou.aliyuncs.com"
        );
        assert!(!def.use_path_style());

        let legacy =
            S3Config::new("oss", S3Provider::Oss, "bkt", creds).with_region("oss-cn-beijing");
        assert_eq!(legacy.signing_region(), "cn-beijing");
        assert_eq!(
            legacy.effective_endpoint(),
            "https://s3.oss-cn-beijing.aliyuncs.com"
        );
    }

    #[test]
    fn path_style_auto_fallback_handles_dotted_buckets_and_ip_literals() {
        let creds = S3Credentials::new("ak", "sk");
        let dotted = S3Config::new("aws", S3Provider::Aws, "my.dot.bucket", creds.clone())
            .with_force_path_style(false);
        assert!(dotted.use_path_style());

        let ipv4 = S3Config::new("aws", S3Provider::Aws, "plainbkt", creds.clone())
            .with_endpoint("http://127.0.0.1:9000")
            .with_force_path_style(false);
        assert!(ipv4.use_path_style());

        let ipv6 = S3Config::new("aws", S3Provider::Aws, "plainbkt", creds.clone())
            .with_endpoint("http://[::1]:9000")
            .with_force_path_style(false);
        assert!(ipv6.use_path_style());

        let normal = S3Config::new("aws", S3Provider::Aws, "plain-bkt", creds);
        assert!(!normal.use_path_style());
    }

    #[test]
    fn sse_c_validates_key_length_and_redacts_debug() {
        assert!(S3ServerSideEncryption::sse_c_from_bytes(&[1u8; 16]).is_err());
        let sse_c = S3ServerSideEncryption::sse_c_from_bytes(&[0x42u8; 32]).unwrap();
        let dbg = format!("{sse_c:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("QkJC"));
    }
}
