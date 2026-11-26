//! Shared Google Service Account RS256 JWT token exchange reused by Google Drive and GCS.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::StatusCode;
use rsa::PrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rship_core::clock::Clock;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::oauth::{OAuthProvider, OAuthToken};
use rship_transport::{HttpTransport, LimiterScope, ScopedLimiter, parse_retry_after};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use super::http::{Idempotency, PolicyDecision, RetryPolicyConfig, execute_with_policy};

const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

#[derive(Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default = "default_expires_in")]
    expires_in: i64,
}

fn default_expires_in() -> i64 {
    3600
}

fn default_sa_token_uri() -> String {
    GOOGLE_TOKEN_URL.to_string()
}

/// Google Cloud Service Account JSON key file structure.
#[derive(Clone, Serialize, Deserialize)]
pub struct ServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    #[serde(default)]
    pub private_key_id: Option<String>,
    #[serde(default = "default_sa_token_uri")]
    pub token_uri: String,
    #[serde(default)]
    pub project_id: Option<String>,
}

impl std::fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key", &"[REDACTED]")
            .field("private_key_id", &self.private_key_id)
            .field("token_uri", &self.token_uri)
            .field("project_id", &self.project_id)
            .finish()
    }
}

impl ServiceAccountKey {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::io(format!("read service account key `{}`", path.display()), e))?;
        Self::from_json_str(&raw)
    }

    pub fn from_json_str(raw: &str) -> Result<Self> {
        serde_json::from_str(raw)
            .map_err(|e| Error::protocol(format!("parse service account JSON key: {e}")))
    }
}

/// Service Account `RS256` JWT token provider supporting Shared Drives, GCS, and
/// Domain-Wide Delegation (`sub`).
pub struct ServiceAccountAuthProvider {
    principal: String,
    key: ServiceAccountKey,
    signing_key: SigningKey<Sha256>,
    scope: String,
    impersonate_sub: Option<String>,
    token_url_override: Option<String>,
    transport: HttpTransport,
    clock: Arc<dyn Clock>,
    limiter: ScopedLimiter,
    retry_cfg: RetryPolicyConfig,
    cached: Mutex<Option<OAuthToken>>,
}

impl ServiceAccountAuthProvider {
    pub fn new(
        key: ServiceAccountKey,
        scope: impl Into<String>,
        impersonate_sub: Option<String>,
        token_url_override: Option<String>,
        transport: HttpTransport,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let rsa_key = PrivateKey::from_pkcs8_pem(&key.private_key)
            .or_else(|_| PrivateKey::from_pkcs1_pem(&key.private_key))
            .map_err(|e| Error::protocol(format!("decode service account RSA private key: {e}")))?;
        let signing_key = SigningKey::<Sha256>::new(rsa_key);
        let principal = match &impersonate_sub {
            Some(sub) => format!("{}->{}", key.client_email, sub),
            None => key.client_email.clone(),
        };
        let limiter = ScopedLimiter::new(
            LimiterScope::control("google-sa", &principal),
            transport.config().default_rate_limit.clone(),
            clock.clone(),
        );
        let retry_cfg = RetryPolicyConfig::new()
            .with_max_retries(4)
            .with_delays(Duration::from_millis(200), Duration::from_secs(30));
        Ok(Self {
            principal,
            key,
            signing_key,
            scope: scope.into(),
            impersonate_sub,
            token_url_override,
            transport,
            clock,
            limiter,
            retry_cfg,
            cached: Mutex::new(None),
        })
    }

    /// Override the bounded retry policy used when exchanging service-account JWTs.
    pub fn with_retry_policy(mut self, cfg: RetryPolicyConfig) -> Self {
        self.retry_cfg = cfg;
        self
    }

    /// Mint a signed `RS256` JWT assertion (`header.claims.signature`).
    pub fn sign_jwt_assertion(&self, now_unix_secs: i64) -> Result<String> {
        let aud = self
            .token_url_override
            .as_deref()
            .unwrap_or(&self.key.token_uri);

        let header = match &self.key.private_key_id {
            Some(kid) if !kid.is_empty() => serde_json::json!({
                "alg": "RS256",
                "typ": "JWT",
                "kid": kid,
            }),
            _ => serde_json::json!({
                "alg": "RS256",
                "typ": "JWT",
            }),
        };

        let mut claims = serde_json::json!({
            "iss": self.key.client_email,
            "scope": self.scope,
            "aud": aud,
            "iat": now_unix_secs,
            "exp": now_unix_secs + 3600,
        });
        if let Some(sub) = &self.impersonate_sub
            && !sub.is_empty()
        {
            claims["sub"] = serde_json::Value::String(sub.clone());
        }

        let header_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&header)
                .map_err(|e| Error::protocol(format!("encode JWT header: {e}")))?,
        );
        let claims_b64 = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&claims)
                .map_err(|e| Error::protocol(format!("encode JWT claims: {e}")))?,
        );
        let signing_input = format!("{header_b64}.{claims_b64}");
        let sig = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        Ok(format!("{signing_input}.{sig_b64}"))
    }

    async fn exchange_locked(&self, guard: &mut Option<OAuthToken>) -> Result<String> {
        let token_url = self
            .token_url_override
            .as_deref()
            .unwrap_or(&self.key.token_uri);

        let parsed: TokenEndpointResponse = execute_with_policy(
            &self.transport,
            &self.limiter,
            "exchange service account JWT",
            &self.retry_cfg,
            Idempotency::Idempotent,
            || async {
                let now = self.clock.now_unix_secs();
                let assertion = self.sign_jwt_assertion(now)?;
                let form = [
                    ("grant_type", JWT_GRANT_TYPE),
                    ("assertion", assertion.as_str()),
                ];
                Ok(self.transport.control_client().post(token_url).form(&form))
            },
            |resp| {
                if resp.status.is_success() {
                    return match serde_json::from_slice::<TokenEndpointResponse>(&resp.body) {
                        Ok(parsed) => PolicyDecision::Ok(parsed),
                        Err(e) => PolicyDecision::Fail(Error::protocol(format!(
                            "parse service account token response: {e}"
                        ))),
                    };
                }
                let msg = format!(
                    "service account JWT exchange failed (HTTP {}): {}",
                    resp.status.as_u16(),
                    String::from_utf8_lossy(&resp.body).trim()
                );
                let retry_after = parse_retry_after(&resp.headers);
                if resp.status == StatusCode::TOO_MANY_REQUESTS {
                    PolicyDecision::Retry(Error::rate_limited(msg, retry_after))
                } else if resp.status == StatusCode::REQUEST_TIMEOUT {
                    let mut err = Error::timeout(msg);
                    if let Some(ra) = retry_after {
                        err = err.with_retry_after(ra);
                    }
                    PolicyDecision::Retry(err)
                } else if resp.status.is_server_error() {
                    let retry = if resp.status == StatusCode::SERVICE_UNAVAILABLE {
                        RetryClass::Throttled
                    } else {
                        RetryClass::Retryable
                    };
                    let mut err = Error::new(ErrorKind::Network, retry, msg);
                    if let Some(ra) = retry_after {
                        err = err.with_retry_after(ra);
                    }
                    PolicyDecision::Retry(err)
                } else {
                    PolicyDecision::Fail(Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        msg,
                    ))
                }
            },
        )
        .await?;

        let now = self.clock.now_unix_secs();
        let tok = OAuthToken {
            access_token: parsed.access_token.clone(),
            refresh_token: None,
            token_type: parsed.token_type.unwrap_or_else(|| "Bearer".to_string()),
            expires_at_unix_secs: now + parsed.expires_in.max(60),
            scope: Some(self.scope.clone()),
        };
        *guard = Some(tok);
        Ok(parsed.access_token)
    }
}

#[async_trait]
impl OAuthProvider for ServiceAccountAuthProvider {
    fn principal(&self) -> &str {
        &self.principal
    }

    async fn access_token(&self) -> Result<String> {
        let mut guard = self.cached.lock().await;
        let now = self.clock.now_unix_secs();
        if let Some(tok) = guard.as_ref()
            && tok.is_valid_at(now)
        {
            return Ok(tok.access_token.clone());
        }
        self.exchange_locked(&mut guard).await
    }

    async fn force_refresh(&self, rejected_token: &str) -> Result<String> {
        let mut guard = self.cached.lock().await;
        let now = self.clock.now_unix_secs();
        if let Some(tok) = guard.as_ref()
            && tok.access_token != rejected_token
            && tok.is_valid_at(now)
        {
            return Ok(tok.access_token.clone());
        }
        self.exchange_locked(&mut guard).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use rsa::pkcs8::EncodePrivateKey;
    use rship_core::clock::VirtualClock;
    use rship_transport::TransportConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn test_sa_key(token_uri: String) -> ServiceAccountKey {
        let mut rng = rand::rng();
        let private_key = PrivateKey::new(&mut rng, 2048).unwrap();
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();
        ServiceAccountKey {
            client_email: "sa@test-project.iam.gserviceaccount.com".into(),
            private_key: pem,
            private_key_id: Some("kid-1".into()),
            token_uri,
            project_id: Some("test-project".into()),
        }
    }

    #[tokio::test]
    async fn exchange_retries_on_429_with_retry_after_and_503_then_succeeds() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let app = Router::new().route(
            "/token",
            post(move || {
                let calls_c = calls_c.clone();
                async move {
                    let n = calls_c.fetch_add(1, Ordering::SeqCst) + 1;
                    match n {
                        1 => (
                            StatusCode::TOO_MANY_REQUESTS,
                            [(http::header::RETRY_AFTER, "3")],
                            "rate limited",
                        )
                            .into_response(),
                        2 => (StatusCode::SERVICE_UNAVAILABLE, "unavailable").into_response(),
                        _ => (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "access_token": "ya29.sa-recovered",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                            })),
                        )
                            .into_response(),
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let t0 = clock.now_unix_nanos();
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let provider = ServiceAccountAuthProvider::new(
            test_sa_key(format!("http://{addr}/token")),
            "https://www.googleapis.com/auth/devstorage.read_write",
            None,
            None,
            transport,
            clock.clone(),
        )
        .unwrap();

        let tok = provider.access_token().await.unwrap();
        assert_eq!(tok, "ya29.sa-recovered");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(
            clock.now_unix_nanos() - t0 >= 3_000_000_000,
            "Retry-After: 3 must advance virtual clock by >= 3s"
        );
        // Cached token is served on subsequent call without another HTTP request.
        assert_eq!(provider.access_token().await.unwrap(), "ya29.sa-recovered");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn exchange_fails_immediately_on_400_invalid_grant_without_retry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let app = Router::new().route(
            "/token",
            post(move || {
                let calls_c = calls_c.clone();
                async move {
                    calls_c.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({ "error": "invalid_grant" })),
                    )
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let provider = ServiceAccountAuthProvider::new(
            test_sa_key(format!("http://{addr}/token")),
            "https://www.googleapis.com/auth/drive",
            None,
            None,
            transport,
            clock,
        )
        .unwrap();

        let err = provider.access_token().await.unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(err.kind, ErrorKind::PermissionDenied);
        assert_eq!(err.retry_class(), RetryClass::Permanent);
    }

    #[tokio::test]
    async fn exchange_marks_retries_exhausted_after_max_retries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_c = calls.clone();
        let app = Router::new().route(
            "/token",
            post(move || {
                let calls_c = calls_c.clone();
                async move {
                    calls_c.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::SERVICE_UNAVAILABLE, "still down")
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let clock = Arc::new(VirtualClock::new_instant_sleep(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let provider = ServiceAccountAuthProvider::new(
            test_sa_key(format!("http://{addr}/token")),
            "https://www.googleapis.com/auth/drive",
            None,
            None,
            transport,
            clock,
        )
        .unwrap()
        .with_retry_policy(
            RetryPolicyConfig::new()
                .with_max_retries(2)
                .with_delays(Duration::from_millis(5), Duration::from_millis(20)),
        );

        let err = provider.access_token().await.unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(err.retries_exhausted());
        assert!(!err.is_retryable());
    }
}
