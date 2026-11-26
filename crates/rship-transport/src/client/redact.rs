//! URL/header secret redaction and `--dump headers` diagnostic formatting.

use http::HeaderMap;
use reqwest::Response;
use std::time::Duration;

/// Scrub embedded `user:pass@` credentials AND sensitive query parameters (AWS presigned
/// signatures/session tokens, Azure SAS `sig`/`se`/`sp`, GCS `X-Goog-Signature`, OAuth
/// `access_token`/`refresh_token`/`client_secret`/`code`) from a URL before logging.
pub fn redact_url_for_dump(url: &str) -> String {
    let scrubbed = redact_url_credentials(url);
    let Some((base, query_and_frag)) = scrubbed.split_once('?') else {
        return scrubbed;
    };
    let (query, frag) = match query_and_frag.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (query_and_frag, None),
    };
    let mut out = String::with_capacity(scrubbed.len());
    out.push_str(base);
    out.push('?');
    redact_kv_pairs(query, &mut out);
    if let Some(f) = frag {
        out.push('#');
        if f.contains('=') {
            redact_kv_pairs(f, &mut out);
        } else {
            out.push_str(f);
        }
    }
    out
}

fn redact_kv_pairs(input: &str, out: &mut String) {
    let mut rest = input;
    while !rest.is_empty() {
        let (pair, sep) = match rest.find(['&', ';']) {
            Some(idx) => {
                let sep_ch = rest.as_bytes()[idx] as char;
                let p = &rest[..idx];
                rest = &rest[idx + 1..];
                (p, Some(sep_ch))
            }
            None => {
                let p = rest;
                rest = "";
                (p, None)
            }
        };
        if let Some((k, v)) = pair.split_once('=') {
            let decoded_k = percent_decode_param_key(k);
            if is_sensitive_query_param(&decoded_k) {
                out.push_str(k);
                out.push_str("=***REDACTED***");
            } else {
                out.push_str(k);
                out.push('=');
                out.push_str(v);
            }
        } else {
            out.push_str(pair);
        }
        if let Some(ch) = sep {
            out.push(ch);
        }
    }
}

fn percent_decode_param_key(raw: &str) -> std::borrow::Cow<'_, str> {
    if !raw.contains('%') && !raw.contains('+') {
        return std::borrow::Cow::Borrowed(raw);
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    std::borrow::Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn is_sensitive_query_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "sig"
            | "signature"
            | "x-amz-signature"
            | "x-amz-security-token"
            | "x-amz-credential"
            | "x-goog-signature"
            | "x-goog-credential"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "client_secret"
            | "code"
            | "code_verifier"
            | "auth"
            | "tempauth"
            | "upload_id"
            | "token"
            | "key"
            | "apikey"
            | "api_key"
            | "password"
            | "passwd"
            | "secret"
            | "skoid"
            | "sktid"
            | "sks"
            | "skt"
            | "ske"
    ) || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("signature")
        || lower.contains("password")
        || lower.contains("credential")
        || lower.contains("auth")
}

/// Format an HTTP `HeaderMap` for `--dump headers` with all authorization credentials,
/// tokens, cookies, encryption keys, and secret headers strictly scrubbed.
pub fn format_redacted_headers(headers: &HeaderMap) -> String {
    let mut out = String::new();
    for (name, val) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        let display_val = redact_header_value(&lower, val.to_str().unwrap_or("<non-utf8>"));
        out.push_str("  ");
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(&display_val);
        out.push('\n');
    }
    out
}

fn redact_header_value(lower_name: &str, raw_val: &str) -> String {
    if lower_name == "authorization" || lower_name == "proxy-authorization" {
        if let Some((scheme, _)) = raw_val.split_once(' ')
            && !scheme.is_empty()
            && scheme.len() <= 24
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return format!("{scheme} ***REDACTED***");
        }
        return "***REDACTED***".to_string();
    }
    if lower_name == "cookie"
        || lower_name == "set-cookie"
        || lower_name == "x-amz-security-token"
        || lower_name == "x-aws-ec2-metadata-token"
        || lower_name == "x-api-key"
        || lower_name == "x-goog-api-key"
        || lower_name == "api-key"
        || lower_name == "x-auth-token"
        || lower_name == "x-ms-copy-source-authorization"
        || lower_name == "x-goog-encryption-key"
        || lower_name == "x-ms-encryption-key"
        || lower_name.contains("cookie")
        || lower_name.contains("token")
        || lower_name.contains("secret")
        || lower_name.contains("password")
        || lower_name.contains("signature")
        || lower_name.contains("authorization")
        || lower_name.contains("credential")
        || lower_name.contains("customer-key")
        || lower_name.contains("encryption-key")
    {
        return "***REDACTED***".to_string();
    }
    if lower_name == "location"
        || lower_name == "content-location"
        || lower_name == "destination"
        || lower_name == "x-amz-copy-source"
        || lower_name == "x-ms-copy-source"
        || lower_name == "x-amz-website-redirect-location"
        || lower_name == "x-goog-upload-url"
        || lower_name == "referer"
    {
        return redact_url_for_dump(raw_val);
    }
    raw_val.to_string()
}

pub(super) fn dump_http_request(context: &str, req: &reqwest::Request) {
    let safe_url = redact_url_for_dump(req.url().as_str());
    let hdrs = format_redacted_headers(req.headers());
    tracing::info!(
        target: "rship::http_dump",
        ">>> HTTP REQUEST [{context}] {} {safe_url}\n{hdrs}",
        req.method()
    );
}

pub(super) fn dump_http_response(context: &str, resp: &Response, elapsed: Duration) {
    let hdrs = format_redacted_headers(resp.headers());
    tracing::info!(
        target: "rship::http_dump",
        "<<< HTTP RESPONSE [{context}] {:?} {} ({}ms)\n{hdrs}",
        resp.version(),
        resp.status(),
        elapsed.as_millis()
    );
}

/// Fail-closed credential scrubber for a standalone URL candidate (such as `--proxy`),
/// scrubbing everything between `://` and the final `@` even when raw unencoded `#`, `?`,
/// `/`, whitespace, quotes, or `)` characters appear inside the username or password.
pub(super) fn redact_single_url_credentials(url: &str) -> String {
    let Some(scheme_pos) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = scheme_pos + 3;
    let tail = &url[after_scheme..];
    let line_end = tail.find(['\n', '\r']).unwrap_or(tail.len());
    let span = &tail[..line_end];
    if let Some(at_idx) = span.rfind('@') {
        let mut out = String::with_capacity(url.len());
        out.push_str(&url[..after_scheme]);
        out.push_str("***@");
        out.push_str(&tail[at_idx + 1..]);
        out
    } else {
        redact_url_for_dump(url)
    }
}

fn looks_like_domain_with_port(auth: &str) -> bool {
    let Some((host, port)) = auth.rsplit_once(':') else {
        return false;
    };
    if host.is_empty() || !host.contains('.') && host != "localhost" {
        return false;
    }
    port.parse::<u16>().is_ok()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}

fn after_at_has_host_port(after_at: &str) -> bool {
    let host_end = after_at
        .find(['/', '?', '#', ' ', '\t', '\n', '\r', '\'', '"', ')', '`'])
        .unwrap_or(after_at.len());
    let candidate = &after_at[..host_end];
    candidate
        .rsplit_once(':')
        .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok())
}

/// Scrub embedded `user:pass@` credentials from any URL(s) appearing in proxy
/// configuration errors or HTTP client error strings so secrets never leak to logs,
/// including malformed URLs whose raw password contains unencoded `#`, `?`, `/`,
/// whitespace, quotes, or `)`.
pub fn redact_url_credentials(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_pos) = rest.find("://") {
        let after_scheme = scheme_pos + 3;
        out.push_str(&rest[..after_scheme]);
        let tail = &rest[after_scheme..];
        let line_end = tail.find(['\n', '\r']).unwrap_or(tail.len());
        let next_scheme = tail[..line_end].find("://");
        let span_end = next_scheme.unwrap_or(line_end);
        let span = &tail[..span_end];
        let std_auth_end = span
            .find(['/', '?', '#', ' ', '\t', '\'', '"', ')', '`'])
            .unwrap_or(span.len());

        if let Some(last_at) = span.rfind('@') {
            let in_std_auth = last_at < std_auth_end;
            let no_slash_before_at = !span[..last_at].contains('/');
            let std_prefix = &span[..std_auth_end];
            let has_userinfo_colon = std_prefix.contains(':')
                && (!looks_like_domain_with_port(std_prefix)
                    || after_at_has_host_port(&span[last_at + 1..]));

            if in_std_auth || no_slash_before_at || has_userinfo_colon {
                out.push_str("***@");
                rest = &tail[last_at + 1..];
                continue;
            }
        }
        out.push_str(&tail[..std_auth_end]);
        rest = &tail[std_auth_end..];
    }
    out.push_str(rest);
    out
}

/// Scrub both embedded `user:pass@` credentials and sensitive query/fragment parameters
/// from every URL appearing inside arbitrary error or diagnostic text.
pub fn redact_urls_in_text(input: &str) -> String {
    let cred_scrubbed = redact_url_credentials(input);
    let mut out = String::with_capacity(cred_scrubbed.len());
    let mut rest = cred_scrubbed.as_str();
    while let Some(scheme_pos) = rest.find("://") {
        let mut scheme_start = scheme_pos;
        let bytes = rest.as_bytes();
        while scheme_start > 0 {
            let b = bytes[scheme_start - 1];
            if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
                scheme_start -= 1;
            } else {
                break;
            }
        }
        out.push_str(&rest[..scheme_start]);
        let after_scheme = scheme_pos + 3;
        let tail = &rest[after_scheme..];
        let rel_end = tail
            .find([' ', '\t', '\n', '\r', '\'', '"', ')', '>', '`', ']'])
            .unwrap_or(tail.len());
        let url_end = after_scheme + rel_end;
        out.push_str(&redact_url_for_dump(&rest[scheme_start..url_end]));
        rest = &rest[url_end..];
    }
    out.push_str(rest);
    out
}
