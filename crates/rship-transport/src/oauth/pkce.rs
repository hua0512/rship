//! Interactive Desktop OAuth 2.0 PKCE S256 loopback (`127.0.0.1`) callback session.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use rship_core::clock::Clock;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

use crate::HttpTransport;

use super::{OAuthToken, TokenEndpointResponse, default_bearer};

/// Well-known default loopback OAuth callback port tried first by interactive CLI auth
/// (falls back cleanly to an ephemeral OS port `0` if already in use).
pub const DEFAULT_OAUTH_CALLBACK_PORT: u16 = 53682;

/// Parameters to start an interactive Desktop OAuth2 PKCE S256 loopback flow.
#[derive(Clone)]
pub struct PkceConfig {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub auth_endpoint: String,
    pub token_endpoint: String,
    pub scope: String,
    /// Optional provider-specific authorization query parameters
    /// (e.g. Google requires `("access_type", "offline")` & `("prompt", "consent")`).
    pub extra_auth_params: Vec<(String, String)>,
    /// Optional `scope` parameter included in the token-exchange POST form.
    pub include_scope_in_token_exchange: bool,
    /// Redirect path on `127.0.0.1:<port>` (e.g. `"/callback"` or `""`).
    pub callback_path: String,
    /// Human-readable title displayed in the browser callback success page.
    pub success_title: String,
    /// Preferred loopback port (`None` or `Some(0)` binds an ephemeral port directly).
    pub preferred_port: Option<u16>,
    /// When `true` and `preferred_port` is non-zero, fail instead of falling back to an ephemeral port.
    pub strict_port: bool,
}

impl std::fmt::Debug for PkceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkceConfig")
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("auth_endpoint", &self.auth_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("scope", &self.scope)
            .field("preferred_port", &self.preferred_port)
            .field("strict_port", &self.strict_port)
            .finish()
    }
}

/// Active Desktop PKCE loopback session bound to `127.0.0.1:<port>`.
pub struct PkceSession {
    pub auth_url: String,
    pub redirect_uri: String,
    pub state: String,
    port: u16,
    callback_path: String,
    code_verifier: String,
    listener: TcpListener,
    client_id: String,
    client_secret: Option<String>,
    token_url: String,
    scope: String,
    include_scope_in_token_exchange: bool,
    success_title: String,
}

impl PkceSession {
    /// Bind a loopback listener (`127.0.0.1:<preferred_port>` or ephemeral `127.0.0.1:0`),
    /// generate PKCE S256 challenge + CSRF `state`, and build the browser authorization URL.
    pub async fn start(cfg: PkceConfig) -> Result<Self> {
        let listener = match cfg.preferred_port.filter(|&p| p != 0) {
            Some(port) => match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(l) => l,
                Err(e) if !cfg.strict_port => {
                    let _ = e;
                    TcpListener::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| Error::io("bind loopback OAuth callback listener", e))?
                }
                Err(e) => {
                    return Err(Error::io(
                        format!("bind OAuth loopback callback port 127.0.0.1:{port}"),
                        e,
                    ));
                }
            },
            None => TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| Error::io("bind loopback OAuth callback listener", e))?,
        };
        let port = listener
            .local_addr()
            .map_err(|e| Error::io("read loopback listener addr", e))?
            .port();
        let redirect_uri = format!("http://127.0.0.1:{port}{}", cfg.callback_path);

        let mut verifier_raw = [0u8; 48];
        let mut state_raw = [0u8; 24];
        rand::rng().fill_bytes(&mut verifier_raw);
        rand::rng().fill_bytes(&mut state_raw);
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_raw);
        let state = URL_SAFE_NO_PAD.encode(state_raw);

        let challenge_digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(challenge_digest);

        let mut url = Url::parse(&cfg.auth_endpoint).map_err(|e| {
            Error::protocol(format!(
                "invalid OAuth auth_url `{}`: {e}",
                cfg.auth_endpoint
            ))
        })?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(Error::protocol(format!(
                "unsupported OAuth auth_url scheme `{}` (expected http or https)",
                url.scheme()
            )));
        }
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("client_id", &cfg.client_id)
                .append_pair("redirect_uri", &redirect_uri)
                .append_pair("response_type", "code");
            let scope = cfg.scope.trim();
            if !scope.is_empty() {
                pairs.append_pair("scope", scope);
            }
            pairs
                .append_pair("code_challenge", &code_challenge)
                .append_pair("code_challenge_method", "S256")
                .append_pair("state", &state);
            for (k, v) in &cfg.extra_auth_params {
                pairs.append_pair(k, v);
            }
        }

        Ok(Self {
            auth_url: url.into(),
            redirect_uri,
            state,
            port,
            callback_path: cfg.callback_path,
            code_verifier,
            listener,
            client_id: cfg.client_id,
            client_secret: cfg.client_secret,
            token_url: cfg.token_endpoint,
            scope: cfg.scope,
            include_scope_in_token_exchange: cfg.include_scope_in_token_exchange,
            success_title: cfg.success_title,
        })
    }

    /// Bound local loopback TCP port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Parse and validate a pasted redirect URL (or raw query string) for headless/SSH OAuth flows.
    ///
    /// Verifies CSRF `state` and extracts the authorization `code`.
    pub fn parse_callback_url(&self, raw: &str) -> Result<String> {
        let trimmed = raw.trim();
        let parsed = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            Url::parse(trimmed)
                .map_err(|e| Error::protocol(format!("invalid callback URL: {e}")))?
        } else if trimmed.starts_with('/') || trimmed.starts_with('?') {
            Url::parse(&format!("http://127.0.0.1{trimmed}"))
                .map_err(|e| Error::protocol(format!("invalid callback query: {e}")))?
        } else if trimmed.contains("code=") || trimmed.contains("error=") {
            Url::parse(&format!("http://127.0.0.1/?{trimmed}"))
                .map_err(|e| Error::protocol(format!("invalid callback query: {e}")))?
        } else {
            return Err(Error::protocol(
                "paste the full redirected URL from your browser address bar (e.g. `http://127.0.0.1:.../callback?code=...&state=...`)",
            ));
        };

        let mut code: Option<String> = None;
        let mut returned_state: Option<String> = None;
        let mut oauth_error: Option<String> = None;
        let mut oauth_error_desc: Option<String> = None;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => returned_state = Some(v.into_owned()),
                "error" => oauth_error = Some(v.into_owned()),
                "error_description" => oauth_error_desc = Some(v.into_owned()),
                _ => {}
            }
        }

        if returned_state.as_deref() != Some(self.state.as_str()) {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                "OAuth2 callback CSRF `state` mismatch — make sure you copied the URL from this login session",
            ));
        }
        if let Some(err) = oauth_error {
            let detail = oauth_error_desc
                .filter(|d| !d.trim().is_empty())
                .map(|d| format!(" ({d})"))
                .unwrap_or_default();
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!("OAuth2 authorization denied: {err}{detail}"),
            ));
        }
        code.filter(|c| !c.is_empty())
            .ok_or_else(|| Error::protocol("OAuth2 callback URL missing `code` query parameter"))
    }

    /// Exchange an already-validated authorization `code` + PKCE `code_verifier` for an [`OAuthToken`].
    pub async fn exchange_code(
        self,
        code: &str,
        transport: &HttpTransport,
        clock: &Arc<dyn Clock>,
    ) -> Result<OAuthToken> {
        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("code_verifier", self.code_verifier.as_str()),
        ];
        if let Some(sec) = self.client_secret.as_deref().filter(|s| !s.is_empty()) {
            form.push(("client_secret", sec));
        }
        let scope = self.scope.trim();
        if self.include_scope_in_token_exchange && !scope.is_empty() {
            form.push(("scope", scope));
        }

        let req = transport.control_client().post(&self.token_url).form(&form);
        let resp = transport
            .send_control_request("exchange OAuth2 PKCE code", req)
            .await?;
        let status = resp.status();
        let body = transport.read_control_body(resp).await?;
        if !status.is_success() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!(
                    "OAuth2 code exchange failed (HTTP {}): {}",
                    status.as_u16(),
                    String::from_utf8_lossy(&body).trim()
                ),
            ));
        }

        let parsed: TokenEndpointResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse OAuth2 token response: {e}")))?;
        let now = clock.now_unix_secs();
        let ttl = parsed.expires_in.max(1);
        Ok(OAuthToken {
            access_token: parsed.access_token,
            refresh_token: parsed.refresh_token,
            token_type: parsed.token_type.unwrap_or_else(default_bearer),
            expires_at_unix_secs: now + ttl,
            scope: parsed.scope,
        })
    }

    /// Validate a manually pasted redirect URL and exchange its authorization code for an [`OAuthToken`].
    pub async fn exchange_callback_url(
        self,
        callback_url: &str,
        transport: &HttpTransport,
        clock: &Arc<dyn Clock>,
    ) -> Result<OAuthToken> {
        let code = self.parse_callback_url(callback_url)?;
        self.exchange_code(&code, transport, clock).await
    }

    /// Wait for the browser redirect on loopback, verify CSRF `state`, and exchange
    /// the authorization code + PKCE `code_verifier` for an [`OAuthToken`].
    pub async fn wait_and_exchange(
        self,
        transport: &HttpTransport,
        clock: &Arc<dyn Clock>,
    ) -> Result<OAuthToken> {
        let code = self.receive_callback_code().await?;
        self.exchange_code(&code, transport, clock).await
    }

    async fn receive_callback_code(&self) -> Result<String> {
        let expected_path = if self.callback_path.is_empty() {
            "/"
        } else {
            self.callback_path.as_str()
        };
        loop {
            let (mut stream, _) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::io("accept OAuth2 loopback callback", e))?;

            let mut buf = vec![0u8; 16 * 1024];
            // Guard against idle speculative browser preconnect sockets blocking subsequent callbacks.
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => continue,
            };

            let req_str = String::from_utf8_lossy(&buf[..n]);
            let first_line = req_str.lines().next().unwrap_or("");
            let target = first_line.split_whitespace().nth(1).unwrap_or("");
            if !target.starts_with('/') {
                let _ = write_loopback_http(&mut stream, 400, "<h1>Bad Request</h1>").await;
                continue;
            }
            let Ok(parsed) = Url::parse(&format!("http://127.0.0.1{target}")) else {
                let _ = write_loopback_http(&mut stream, 400, "<h1>Bad Request</h1>").await;
                continue;
            };

            // Ignore incidental browser fetches such as `/favicon.ico` (even with query params).
            if parsed.path() != expected_path {
                let _ = write_loopback_http(&mut stream, 404, "Not Found").await;
                continue;
            }

            let mut code: Option<String> = None;
            let mut returned_state: Option<String> = None;
            let mut oauth_error: Option<String> = None;
            let mut oauth_error_desc: Option<String> = None;

            for (k, v) in parsed.query_pairs() {
                match k.as_ref() {
                    "code" => code = Some(v.into_owned()),
                    "state" => returned_state = Some(v.into_owned()),
                    "error" => oauth_error = Some(v.into_owned()),
                    "error_description" => oauth_error_desc = Some(v.into_owned()),
                    _ => {}
                }
            }

            // Always verify CSRF `state` BEFORE acting on `error` so an unauthenticated probe
            // against the predictable loopback port cannot cancel an active login or reflect HTML.
            if returned_state.as_deref() != Some(self.state.as_str()) {
                let _ = write_loopback_http(&mut stream, 400, "<h1>Invalid OAuth state</h1>").await;
                continue;
            }

            if let Some(err) = oauth_error {
                let escaped_err = html_escape(&err);
                let escaped_desc = oauth_error_desc
                    .as_deref()
                    .filter(|d| !d.trim().is_empty())
                    .map(|d| format!("<p>{}</p>", html_escape(d)))
                    .unwrap_or_default();
                let _ = write_loopback_http(
                    &mut stream,
                    400,
                    &format!("<h1>OAuth authorization failed: {escaped_err}</h1>{escaped_desc}"),
                )
                .await;
                let detail = oauth_error_desc
                    .filter(|d| !d.trim().is_empty())
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default();
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!("OAuth2 authorization denied: {err}{detail}"),
                ));
            }

            let Some(code) = code.filter(|c| !c.is_empty()) else {
                let _ = write_loopback_http(
                    &mut stream,
                    400,
                    "<h1>Missing OAuth authorization code</h1>",
                )
                .await;
                return Err(Error::protocol(
                    "OAuth2 loopback callback missing `code` query parameter",
                ));
            };

            let _ = write_loopback_http(
                &mut stream,
                200,
                &format!(
                    "<h1>{}</h1><p>Authorization complete. You may close this browser tab.</p>",
                    html_escape(&self.success_title)
                ),
            )
            .await;
            return Ok(code);
        }
    }
}

fn html_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

async fn write_loopback_http(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    html: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.flush().await
}
