//! Parse WebDAV (`type = webdav`) remotes from an existing `rclone.conf`,
//! automatically revealing rclone-obscured (`AES-256-CTR`) passwords.

use rship_core::Result;
use rship_core::rclone_ini::{parse_rclone_ini, reveal_or_passthrough_rclone_secret};

use crate::webdav::config::WebdavVendor;

#[derive(Clone, PartialEq, Eq)]
pub struct ImportedWebdavRemote {
    pub name: String,
    pub url: String,
    pub vendor: WebdavVendor,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub bearer_token: Option<String>,
    pub bearer_token_command: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for ImportedWebdavRemote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(k, _)| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_struct("ImportedWebdavRemote")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("vendor", &self.vendor)
            .field("user", &self.user)
            .field("pass", &self.pass.as_ref().map(|_| "[REDACTED]"))
            .field(
                "bearer_token",
                &self.bearer_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "bearer_token_command",
                &self.bearer_token_command.as_ref().map(|_| "[REDACTED]"),
            )
            .field("headers", &redacted_headers)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct RcloneWebdavImportReport {
    pub remotes: Vec<ImportedWebdavRemote>,
    pub warnings: Vec<String>,
}

/// Parse comma-separated `k1,v1,k2,v2` rclone `headers` field (supporting CSV double quotes).
fn parse_rclone_headers(raw: &str) -> (Vec<(String, String)>, Option<String>) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FieldState {
        Start,
        InQuotes,
        AfterQuotes,
        Unquoted,
    }

    if raw.trim().is_empty() {
        return (Vec::new(), None);
    }

    let mut fields: Vec<(String, bool)> = Vec::new();
    let mut cur = String::new();
    let mut state = FieldState::Start;
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        match state {
            FieldState::Start => {
                if c == '"' {
                    state = FieldState::InQuotes;
                } else if c == ',' {
                    fields.push((String::new(), false));
                } else if !c.is_whitespace() {
                    cur.push(c);
                    state = FieldState::Unquoted;
                }
            }
            FieldState::InQuotes => {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        cur.push('"');
                    } else {
                        state = FieldState::AfterQuotes;
                    }
                } else {
                    cur.push(c);
                }
            }
            FieldState::AfterQuotes => {
                if c == ',' {
                    fields.push((std::mem::take(&mut cur), true));
                    state = FieldState::Start;
                } else if !c.is_whitespace() {
                    return (
                        Vec::new(),
                        Some(
                            "unexpected character after closing quote in `headers` field"
                                .to_string(),
                        ),
                    );
                }
            }
            FieldState::Unquoted => {
                if c == ',' {
                    let token = std::mem::take(&mut cur).trim_end().to_string();
                    fields.push((token, false));
                    state = FieldState::Start;
                } else {
                    cur.push(c);
                }
            }
        }
    }

    match state {
        FieldState::InQuotes => {
            return (
                Vec::new(),
                Some("unclosed quote in `headers` field".to_string()),
            );
        }
        FieldState::AfterQuotes => fields.push((cur, true)),
        FieldState::Start => fields.push((String::new(), false)),
        FieldState::Unquoted => fields.push((cur.trim_end().to_string(), false)),
    }

    let mut pairs = Vec::with_capacity(fields.len() / 2);
    let mut warnings: Vec<String> = Vec::new();
    for chunk in fields.chunks(2) {
        if chunk.len() < 2 {
            warnings.push(format!(
                "trailing unpaired token `{}` in `headers` ignored",
                chunk[0].0.trim()
            ));
            break;
        }
        let k = chunk[0].0.trim();
        let v = if chunk[1].1 {
            chunk[1].0.as_str()
        } else {
            chunk[1].0.trim()
        };
        if k.is_empty() {
            warnings.push("empty header name in `headers` ignored".to_string());
            continue;
        }
        pairs.push((k.to_string(), v.to_string()));
    }
    let warn = (!warnings.is_empty()).then(|| warnings.join("; "));
    (pairs, warn)
}

/// Parse WebDAV (`type = webdav`) remotes from an `rclone.conf` document, propagating
/// structural / encryption errors (`RCLONE_ENCRYPT_V0:`) as `Err(ErrorKind::Config)`.
pub fn try_parse_rclone_webdav_conf(raw: &str) -> Result<RcloneWebdavImportReport> {
    let mut report = RcloneWebdavImportReport::default();
    let sections = parse_rclone_ini(raw)?;

    for sec in sections {
        if !sec.kind().eq_ignore_ascii_case("webdav") {
            continue;
        }
        let name = sec.name.clone();
        let Some(url) = sec.get_non_empty("url") else {
            report
                .warnings
                .push(format!("webdav remote `{name}` missing `url`; skipped"));
            continue;
        };
        let vendor = match sec.get_non_empty("vendor") {
            Some(raw_vendor) => match WebdavVendor::parse(&raw_vendor) {
                Some(v) => v,
                None => {
                    report.warnings.push(format!(
                        "webdav remote `{name}` specifies unsupported vendor `{raw_vendor}`; \
                         falling back to `generic` (vendor-specific auth/chunking may not work)"
                    ));
                    WebdavVendor::Generic
                }
            },
            None => WebdavVendor::Generic,
        };
        let user = sec.get_non_empty("user");
        let pass = sec
            .get_non_empty("pass")
            .map(|raw| reveal_or_passthrough_rclone_secret(&raw).0);
        let bearer_token = sec.get_non_empty("bearer_token");
        let bearer_token_command = sec.get_non_empty("bearer_token_command");
        if bearer_token_command.is_some() && bearer_token.is_none() {
            report.warnings.push(format!(
                "webdav remote `{name}` specifies `bearer_token_command` which is not executed \
                 automatically; supply a static `bearer_token` or refresh credentials externally"
            ));
        }
        let headers = match sec.get_non_empty("headers") {
            Some(raw_headers) => {
                let (parsed, maybe_warn) = parse_rclone_headers(&raw_headers);
                if let Some(w) = maybe_warn {
                    report.warnings.push(format!("webdav remote `{name}`: {w}"));
                }
                parsed
            }
            None => Vec::new(),
        };
        report.remotes.push(ImportedWebdavRemote {
            name,
            url,
            vendor,
            user,
            pass,
            bearer_token,
            bearer_token_command,
            headers,
        });
    }
    Ok(report)
}

/// Backwards-compatible infallible wrapper around [`try_parse_rclone_webdav_conf`].
pub fn parse_rclone_webdav_conf(text: &str) -> RcloneWebdavImportReport {
    match try_parse_rclone_webdav_conf(text) {
        Ok(report) => report,
        Err(e) => RcloneWebdavImportReport {
            remotes: Vec::new(),
            warnings: vec![format!("parse rclone.conf: {e}")],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::rclone_ini::obscure_rclone_secret_with_iv;

    #[test]
    fn imports_webdav_sections_and_reveals_rclone_obscured_passwords() {
        let obscured = obscure_rclone_secret_with_iv("my-nextcloud-app-pass", [0x11; 16]);
        let conf = format!(
            r#"
[nc]
type = webdav
url = https://cloud.example.com/remote.php/dav/files/alice
vendor = nextcloud
user = alice
pass = {obscured}

[alist]
type = webdav
url = http://127.0.0.1:5244/dav
vendor = other
bearer_token = tok-123
"#
        );
        let rep = parse_rclone_webdav_conf(&conf);
        assert!(rep.warnings.is_empty());
        assert_eq!(rep.remotes.len(), 2);
        let nc = rep.remotes.iter().find(|r| r.name == "nc").unwrap();
        assert_eq!(nc.vendor, WebdavVendor::Nextcloud);
        assert_eq!(nc.user.as_deref(), Some("alice"));
        assert_eq!(nc.pass.as_deref(), Some("my-nextcloud-app-pass"));
        let al = rep.remotes.iter().find(|r| r.name == "alist").unwrap();
        assert_eq!(al.bearer_token.as_deref(), Some("tok-123"));
    }

    #[test]
    fn try_parse_rejects_encrypted_rclone_conf_and_wrapper_warns() {
        let encrypted = "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n";
        let err = try_parse_rclone_webdav_conf(encrypted)
            .expect_err("encrypted rclone.conf must fail with ErrorKind::Config");
        assert!(err.is_config(), "got: {err:?}");

        let wrapped = parse_rclone_webdav_conf(encrypted);
        assert!(wrapped.remotes.is_empty());
        assert_eq!(wrapped.warnings.len(), 1);
    }

    #[test]
    fn warns_on_unsupported_vendor_and_imports_redacted_headers_and_bearer_command() {
        let conf = r#"
[sp]
type = webdav
url = https://sp.example.com/dav
vendor = sharepoint
bearer_token_command = /usr/local/bin/get-token --secret-flag
headers = X-Custom,secret-hdr-val,"Cookie","sid=supersecret"
"#;
        let rep = try_parse_rclone_webdav_conf(conf).unwrap();
        assert_eq!(rep.remotes.len(), 1);
        let sp = &rep.remotes[0];
        assert_eq!(sp.vendor, WebdavVendor::Generic);
        assert_eq!(
            sp.bearer_token_command.as_deref(),
            Some("/usr/local/bin/get-token --secret-flag")
        );
        assert_eq!(
            sp.headers,
            vec![
                ("X-Custom".to_string(), "secret-hdr-val".to_string()),
                ("Cookie".to_string(), "sid=supersecret".to_string()),
            ]
        );
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("unsupported vendor `sharepoint`")),
            "warnings: {:?}",
            rep.warnings
        );
        assert!(
            rep.warnings
                .iter()
                .any(|w| w.contains("bearer_token_command")),
            "warnings: {:?}",
            rep.warnings
        );

        let dbg = format!("{sp:?}");
        assert!(!dbg.contains("secret-hdr-val"));
        assert!(!dbg.contains("sid=supersecret"));
        assert!(!dbg.contains("/usr/local/bin/get-token"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn parse_rclone_headers_handles_spaces_around_quotes_escapes_and_edge_cases() {
        // Challenger Probe 6b: space after comma before opening quote.
        let (pairs, warn) = parse_rclone_headers(r#"X-One, "val,with,comma", X-Two, plain"#);
        assert_eq!(warn, None);
        assert_eq!(
            pairs,
            vec![
                ("X-One".to_string(), "val,with,comma".to_string()),
                ("X-Two".to_string(), "plain".to_string()),
            ]
        );

        // Whitespace outside quotes trimmed; whitespace inside quotes preserved.
        let (pairs, warn) = parse_rclone_headers(r#"  "X-A"  ,  "  keep  " , X-B ,  trim me   "#);
        assert_eq!(warn, None);
        assert_eq!(
            pairs,
            vec![
                ("X-A".to_string(), "  keep  ".to_string()),
                ("X-B".to_string(), "trim me".to_string()),
            ]
        );

        // Escaped double quotes `""` and empty quoted value `""`.
        let (pairs, warn) = parse_rclone_headers(r#"X-Q, "say ""hello"", world", X-Empty, """#);
        assert_eq!(warn, None);
        assert_eq!(
            pairs,
            vec![
                ("X-Q".to_string(), r#"say "hello", world"#.to_string()),
                ("X-Empty".to_string(), "".to_string()),
            ]
        );

        // Empty header names skipped with warning while keeping valid pairs.
        let (pairs, warn) = parse_rclone_headers(r#", v1, "", v2, X-Ok, ok-val"#);
        assert!(
            warn.as_deref()
                .is_some_and(|w| w.contains("empty header name"))
        );
        assert_eq!(pairs, vec![("X-Ok".to_string(), "ok-val".to_string())]);

        // Odd trailing token keeps valid pairs and warns.
        let (pairs, warn) = parse_rclone_headers("X-One, v1, X-Orphan");
        assert!(
            warn.as_deref()
                .is_some_and(|w| w.contains("trailing unpaired token `X-Orphan`"))
        );
        assert_eq!(pairs, vec![("X-One".to_string(), "v1".to_string())]);

        // Unclosed quote and trailing junk after closing quote fail with warning.
        let (pairs, warn) = parse_rclone_headers(r#"X-One, "unclosed"#);
        assert!(pairs.is_empty());
        assert!(
            warn.as_deref()
                .is_some_and(|w| w.contains("unclosed quote"))
        );

        let (pairs, warn) = parse_rclone_headers(r#""X-One"bad, v1"#);
        assert!(pairs.is_empty());
        assert!(
            warn.as_deref()
                .is_some_and(|w| w.contains("unexpected character after closing quote"))
        );

        // Empty / whitespace-only returns empty with no warning.
        assert_eq!(parse_rclone_headers(""), (Vec::new(), None));
        assert_eq!(parse_rclone_headers("   \t  "), (Vec::new(), None));
    }
}
