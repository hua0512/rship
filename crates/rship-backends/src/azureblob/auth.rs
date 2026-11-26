//! Azure Blob Storage authentication:
//! - SharedKey HMAC-SHA256 request signing (REST API `2023-11-03`)
//! - SAS token / SAS URL query injection
//! - Anonymous public container access

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use rship_core::{Error, Result};
use std::collections::BTreeMap;

use crate::common::crypto::hmac_sha256;

pub const AZURE_API_VERSION: &str = "2023-11-03";

#[derive(Clone)]
pub enum AzureAuth {
    /// Storage Account Shared Key (Base64-encoded 512-bit key).
    SharedKey { account: String, key_bytes: Vec<u8> },
    /// Shared Access Signature query string (without leading `?`, e.g. `sv=2023-11-03&...&sig=...`).
    SasToken(String),
    /// Public anonymous container access.
    Anonymous,
}

impl std::fmt::Debug for AzureAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SharedKey { account, .. } => f
                .debug_struct("SharedKey")
                .field("account", account)
                .field("key_bytes", &"[REDACTED]")
                .finish(),
            Self::SasToken(_) => f.debug_tuple("SasToken").field(&"[REDACTED]").finish(),
            Self::Anonymous => f.write_str("Anonymous"),
        }
    }
}

impl AzureAuth {
    pub fn shared_key(account: impl Into<String>, base64_key: &str) -> Result<Self> {
        let account = account.into();
        if account.trim().is_empty() {
            return Err(Error::protocol(
                "Azure SharedKey requires a non-empty account name",
            ));
        }
        let key_bytes = B64.decode(base64_key.trim()).map_err(|e| {
            Error::protocol(format!("invalid Base64 Azure storage account key: {e}"))
        })?;
        if key_bytes.is_empty() {
            return Err(Error::protocol(
                "Azure storage account key must not be empty",
            ));
        }
        Ok(Self::SharedKey { account, key_bytes })
    }

    pub fn sas_token(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        let query = match trimmed.split_once('?') {
            Some((_, q)) => q,
            None if trimmed.contains("://") => {
                return Err(Error::protocol(
                    "Azure SAS URL is missing '?' query parameters",
                ));
            }
            None => trimmed,
        }
        .trim_start_matches(['?', '&']);
        if query.is_empty() {
            return Err(Error::protocol("Azure SAS token/URL is empty"));
        }
        Ok(Self::SasToken(query.to_string()))
    }

    pub fn principal(&self, fallback_account: &str) -> String {
        match self {
            Self::SharedKey { account, .. } => format!("sharedkey:{account}"),
            Self::SasToken(_) => format!("sas:{fallback_account}"),
            Self::Anonymous => format!("anonymous:{fallback_account}"),
        }
    }

    /// Attach SAS query parameters to `url` if using `AzureAuth::SasToken`.
    pub fn apply_url(&self, raw_url: &str) -> String {
        match self {
            Self::SasToken(sas) => {
                let cleaned = sas.trim().trim_start_matches(['?', '&']);
                if cleaned.is_empty() {
                    return raw_url.to_string();
                }
                if raw_url.contains('?') {
                    format!("{raw_url}&{cleaned}")
                } else {
                    format!("{raw_url}?{cleaned}")
                }
            }
            _ => raw_url.to_string(),
        }
    }

    /// Populate `x-ms-version`, `x-ms-date`, and (for SharedKey) `Authorization: SharedKey ...`.
    pub fn sign_headers(
        &self,
        method: &Method,
        full_url: &str,
        headers: &mut HeaderMap,
        now: rship_core::time::Timestamp,
    ) -> Result<()> {
        if !headers.contains_key("x-ms-version") {
            headers.insert(
                HeaderName::from_static("x-ms-version"),
                HeaderValue::from_static(AZURE_API_VERSION),
            );
        }
        if !headers.contains_key("x-ms-date") {
            let date_str = rship_core::time::format_http_date(now.as_second());
            headers.insert(
                HeaderName::from_static("x-ms-date"),
                HeaderValue::from_str(&date_str)
                    .map_err(|e| Error::protocol(format!("invalid x-ms-date header: {e}")))?,
            );
        }

        if let Self::SharedKey { account, key_bytes } = self {
            let auth_header =
                sign_shared_key_request(method, full_url, headers, account, key_bytes)?;
            headers.insert(
                http::header::AUTHORIZATION,
                crate::common::http::sensitive_header_value(
                    &auth_header,
                    "Azure Authorization header",
                )?,
            );
        }
        Ok(())
    }
}

/// Build the `CanonicalizedHeaders` block for Azure SharedKey signing:
/// sorted lowercase `x-ms-*` headers formatted as `name:value\n`.
pub fn canonicalize_headers(headers: &HeaderMap) -> String {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, val) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if !lower.starts_with("x-ms-") {
            continue;
        }
        let collapsed = val
            .to_str()
            .unwrap_or("")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        grouped.entry(lower).or_default().push(collapsed);
    }
    let mut out = String::new();
    for (k, vals) in grouped {
        out.push_str(&k);
        out.push(':');
        out.push_str(&vals.join(","));
        out.push('\n');
    }
    out
}

/// Build the `CanonicalizedResource` block for Azure SharedKey signing:
/// `/{account}{raw_uri_path}` followed by `\n{lower_param}:{sorted_comma_values}`.
///
/// Per the Azure Storage SharedKey specification:
/// - Virtual-host endpoints (`https://{account}.blob.core.windows.net/c/b`) have URI path `/c/b`,
///   yielding `/{account}/c/b`.
/// - Path-style / Azurite endpoints (`http://127.0.0.1:10000/{account}/c/b`) include `/{account}`
///   in the wire HTTP URI path, so `CanonicalizedResource` MUST include the account prefix twice
///   (`/{account}/{account}/c/b`).
pub fn canonicalize_resource(account: &str, full_url: &str) -> Result<String> {
    let parsed = url::Url::parse(full_url)
        .map_err(|e| Error::protocol(format!("parse Azure URL `{full_url}`: {e}")))?;
    let path = parsed.path();
    let mut out = format!("/{account}{path}");

    let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(raw_q) = parsed.query() {
        for pair in raw_q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let dk = crate::azureblob::config::percent_decode_rfc3986(k).to_ascii_lowercase();
            let dv = crate::azureblob::config::percent_decode_rfc3986(v);
            params.entry(dk).or_default().push(dv);
        }
    }
    for (k, mut vals) in params {
        vals.sort();
        out.push('\n');
        out.push_str(&k);
        out.push(':');
        out.push_str(&vals.join(","));
    }
    Ok(out)
}

/// Returns `true` when `sas` is scoped to a single container (`sr=c`) or blob (`sr=b`)
/// rather than an Account SAS (`srt=...`), which cannot be used to read a different source
/// container in `x-ms-copy-source`.
pub(crate) fn sas_is_resource_scoped(sas: &str) -> bool {
    let query = sas
        .trim()
        .split_once('?')
        .map_or(sas.trim(), |(_, q)| q)
        .trim_start_matches(['?', '&']);
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let dk = crate::azureblob::config::percent_decode_rfc3986(k);
        if dk.eq_ignore_ascii_case("sr") {
            let dv = crate::azureblob::config::percent_decode_rfc3986(v);
            if matches!(dv.trim().to_ascii_lowercase().as_str(), "c" | "b") {
                return true;
            }
        }
    }
    false
}

fn header_str(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Compute Azure Storage `Authorization: SharedKey {account}:{signature}` header value.
pub fn sign_shared_key_request(
    method: &Method,
    full_url: &str,
    headers: &HeaderMap,
    account: &str,
    key_bytes: &[u8],
) -> Result<String> {
    let content_encoding = header_str(headers, "content-encoding");
    let content_language = header_str(headers, "content-language");
    // Azure SharedKey spec (2015-02-21+): Content-Length MUST be empty string when 0 or omitted!
    let raw_cl = header_str(headers, "content-length");
    let content_length = if raw_cl.is_empty() || raw_cl == "0" {
        String::new()
    } else {
        raw_cl
    };
    let content_md5 = header_str(headers, "content-md5");
    let content_type = header_str(headers, "content-type");
    // When `x-ms-date` is present, the `Date` line in StringToSign MUST be empty.
    let date = if headers.contains_key("x-ms-date") {
        String::new()
    } else {
        header_str(headers, "date")
    };
    let if_modified_since = header_str(headers, "if-modified-since");
    let if_match = header_str(headers, "if-match");
    let if_none_match = header_str(headers, "if-none-match");
    let if_unmodified_since = header_str(headers, "if-unmodified-since");
    let range = header_str(headers, "range");

    let canon_headers = canonicalize_headers(headers);
    let canon_resource = canonicalize_resource(account, full_url)?;

    let string_to_sign = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
        method.as_str(),
        content_encoding,
        content_language,
        content_length,
        content_md5,
        content_type,
        date,
        if_modified_since,
        if_match,
        if_none_match,
        if_unmodified_since,
        range,
        canon_headers,
        canon_resource
    );

    let mac = hmac_sha256(key_bytes, string_to_sign.as_bytes());
    let sig_b64 = B64.encode(mac);
    Ok(format!("SharedKey {account}:{sig_b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_key_signs_deterministically_with_zero_content_length_omitted() {
        let key_b64 = B64.encode([0x42u8; 32]);
        let auth = AzureAuth::shared_key("myaccount", &key_b64).unwrap();
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("0"));
        h.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("BlockBlob"),
        );
        let ts = rship_core::time::Timestamp::from_second(1_795_572_000).unwrap(); // 2026-11-25T02:00:00Z
        let url = "https://myaccount.blob.core.windows.net/mycontainer/dir/file.txt?comp=block&blockid=YmxvY2sx";
        auth.sign_headers(&Method::PUT, url, &mut h, ts).unwrap();

        let auth_val = h.get(http::header::AUTHORIZATION).unwrap();
        assert!(
            auth_val.is_sensitive(),
            "SharedKey Authorization header must be marked sensitive"
        );
        let got = auth_val.to_str().unwrap().to_string();
        assert!(got.starts_with("SharedKey myaccount:"));
        // Golden RFC 1123 `x-ms-date` and the signature computed over it.
        assert_eq!(
            h.get("x-ms-date").unwrap().to_str().unwrap(),
            "Wed, 25 Nov 2026 02:00:00 GMT"
        );
        assert_eq!(
            got,
            "SharedKey myaccount:2uD+whYAUOxlLJxVgGd5ISHkIHR/Gr1MD7HRPdapVnM="
        );
        assert!(
            !format!("{auth_val:?}").contains("SharedKey"),
            "Debug formatting must hide sensitive SharedKey Authorization header"
        );

        // Recomputing with omitted Content-Length must produce the EXACT same signature.
        let mut h2 = HeaderMap::new();
        h2.insert(
            HeaderName::from_static("x-ms-blob-type"),
            HeaderValue::from_static("BlockBlob"),
        );
        auth.sign_headers(&Method::PUT, url, &mut h2, ts).unwrap();
        assert_eq!(
            got,
            h2.get(http::header::AUTHORIZATION)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn canonicalizes_virtual_host_and_azurite_path_style_resources() {
        let vh = canonicalize_resource(
            "myacct",
            "https://myacct.blob.core.windows.net/data/a%20b.txt?restype=container&comp=list",
        )
        .unwrap();
        assert_eq!(vh, "/myacct/data/a%20b.txt\ncomp:list\nrestype:container");

        let az = canonicalize_resource(
            "devstoreaccount1",
            "http://127.0.0.1:10000/devstoreaccount1/data/a.txt?comp=blocklist",
        )
        .unwrap();
        assert_eq!(
            az,
            "/devstoreaccount1/devstoreaccount1/data/a.txt\ncomp:blocklist"
        );
    }

    #[test]
    fn canonicalize_resource_decodes_rfc3986_without_turning_plus_into_space() {
        let res = canonicalize_resource(
            "myacct",
            "https://myacct.blob.core.windows.net/data?restype=container&comp=list&prefix=my%20dir%2Fa%2Bb%2F&blockid=ab+cd%2B1%3D",
        )
        .unwrap();
        assert_eq!(
            res,
            "/myacct/data\nblockid:ab+cd+1=\ncomp:list\nprefix:my dir/a+b/\nrestype:container"
        );
    }

    #[test]
    fn sas_token_normalizes_leading_delimiters_and_detects_resource_scope() {
        let a1 = AzureAuth::sas_token("?sv=2023-11-03&sr=c&sig=abc").unwrap();
        let a2 = AzureAuth::sas_token(
            "https://acct.blob.core.windows.net/c?&sv=2023-11-03&sr=b&sig=abc",
        )
        .unwrap();
        let a3 = AzureAuth::SasToken("?&sv=2023-11-03&srt=co&sig=abc".to_string());

        assert_eq!(
            a1.apply_url("https://acct.blob.core.windows.net/c"),
            "https://acct.blob.core.windows.net/c?sv=2023-11-03&sr=c&sig=abc"
        );
        assert_eq!(
            a2.apply_url("https://acct.blob.core.windows.net/c?comp=list"),
            "https://acct.blob.core.windows.net/c?comp=list&sv=2023-11-03&sr=b&sig=abc"
        );
        assert_eq!(
            a3.apply_url("https://acct.blob.core.windows.net/c"),
            "https://acct.blob.core.windows.net/c?sv=2023-11-03&srt=co&sig=abc"
        );

        assert!(sas_is_resource_scoped("sv=2023-11-03&sr=c&sig=abc"));
        assert!(sas_is_resource_scoped("?sv=2023-11-03&sr=b&sig=abc"));
        assert!(!sas_is_resource_scoped("sv=2023-11-03&ss=b&srt=co&sig=abc"));
    }

    #[test]
    fn sas_token_rejects_url_without_query_separator() {
        for bad in [
            "https://acct.blob.core.windows.net/cont",
            "http://127.0.0.1:10000/devstoreaccount1/cont",
            "https://acct.blob.core.windows.net/cont?",
            "   ",
        ] {
            let err = AzureAuth::sas_token(bad).unwrap_err();
            assert_eq!(err.kind, rship_core::ErrorKind::Protocol, "input={bad}");
        }
    }
}
