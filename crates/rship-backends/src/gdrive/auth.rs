//! Google Drive authentication built on shared `rship_transport::oauth`:
//! 1. OAuth2 Desktop PKCE loopback (`127.0.0.1:0`, NO deprecated OOB) with
//!    user-owned `client_id` / `client_secret`, token persistence, single-flight
//!    `401` refresh, and headless export/import bundles.
//! 2. Service Account `RS256` JWT exchange supporting Shared Drives and
//!    Domain-Wide Delegation (`sub`).

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rship_core::clock::Clock;
use rship_core::{Error, Result};
use rship_transport::HttpTransport;
use rship_transport::oauth::{OAuth2RefreshConfig, OAuth2TokenManager, PkceConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use crate::common::google_sa::{ServiceAccountAuthProvider, ServiceAccountKey};
pub use rship_transport::oauth::{
    FileTokenStore, InMemoryTokenStore, OAuthProvider as AuthProvider, OAuthToken, PkceSession,
    StaticBearerAuth, TokenStore,
};

/// OAuth2 Desktop PKCE token provider using user-supplied `client_id` & `client_secret`.
pub struct OAuth2AuthProvider(OAuth2TokenManager);

impl OAuth2AuthProvider {
    pub fn new(
        principal: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        token_url: impl Into<String>,
        transport: HttpTransport,
        store: Arc<dyn TokenStore>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        let mgr = OAuth2TokenManager::new(
            OAuth2RefreshConfig {
                principal: principal.into(),
                client_id: client_id.into(),
                client_secret: Some(client_secret.into()),
                token_url: token_url.into(),
                refresh_scope: None,
                missing_refresh_hint: "run `rship auth gdrive <remote>` to authorize".to_string(),
                refresh_error_hint: Some(
                    "hint: if your Google Cloud OAuth consent screen is in 'Testing' mode, refresh tokens expire after 7 days — switch to 'In Production'".to_string(),
                ),
            },
            transport,
            store,
            clock,
        )?;
        Ok(Self(mgr))
    }
}

#[async_trait]
impl AuthProvider for OAuth2AuthProvider {
    fn principal(&self) -> &str {
        self.0.principal()
    }

    async fn access_token(&self) -> Result<String> {
        self.0.access_token().await
    }

    async fn force_refresh(&self, rejected_token: &str) -> Result<String> {
        self.0.force_refresh(rejected_token).await
    }
}

/// Interactive Desktop OAuth2 PKCE flow using an ephemeral `127.0.0.1:0` loopback
/// listener (Google retired OOB `urn:ietf:wg:oauth:2.0:oob`).
pub struct PkceFlow;

impl PkceFlow {
    /// Start a Google Drive PKCE loopback session bound to `127.0.0.1:0`.
    pub async fn start(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: &str,
        auth_endpoint: &str,
        token_endpoint: &str,
    ) -> Result<PkceSession> {
        Self::start_with_port(
            client_id,
            client_secret,
            scope,
            auth_endpoint,
            token_endpoint,
            None,
            false,
        )
        .await
    }

    /// Start a Google Drive PKCE loopback session with an optional preferred callback port.
    pub async fn start_with_port(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: &str,
        auth_endpoint: &str,
        token_endpoint: &str,
        preferred_port: Option<u16>,
        strict_port: bool,
    ) -> Result<PkceSession> {
        PkceSession::start(PkceConfig {
            client_id: client_id.into(),
            client_secret: Some(client_secret.into()),
            auth_endpoint: auth_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            scope: scope.to_string(),
            extra_auth_params: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
            include_scope_in_token_exchange: false,
            callback_path: "/callback".to_string(),
            success_title: "rship Google Drive authorization complete".to_string(),
            preferred_port,
            strict_port,
        })
        .await
    }
}

/// Portable credential bundle for headless servers (`rship auth export` / `rship auth import`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthExportBundle {
    pub version: u32,
    pub remote_name: String,
    pub remote_type: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub root_folder_id: Option<String>,
    #[serde(default)]
    pub shared_drive_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub token: Option<OAuthToken>,
    #[serde(default)]
    pub service_account_json: Option<String>,
    #[serde(default)]
    pub impersonate: Option<String>,
}

impl std::fmt::Debug for AuthExportBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthExportBundle")
            .field("version", &self.version)
            .field("remote_name", &self.remote_name)
            .field("remote_type", &self.remote_type)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("root_folder_id", &self.root_folder_id)
            .field("shared_drive_id", &self.shared_drive_id)
            .field("scope", &self.scope)
            .field("token", &self.token)
            .field(
                "service_account_json",
                &self.service_account_json.as_ref().map(|_| "[REDACTED]"),
            )
            .field("impersonate", &self.impersonate)
            .finish()
    }
}

impl AuthExportBundle {
    pub fn encode_compact(&self) -> Result<String> {
        let json = serde_json::to_vec(self)
            .map_err(|e| Error::protocol(format!("encode auth export bundle: {e}")))?;
        Ok(format!("rship-auth-v1:{}", URL_SAFE_NO_PAD.encode(json)))
    }

    pub fn decode(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if let Some(b64) = trimmed.strip_prefix("rship-auth-v1:") {
            let bytes = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| Error::protocol(format!("decode auth bundle base64: {e}")))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| Error::protocol(format!("parse auth bundle JSON: {e}")))
        } else {
            serde_json::from_str(trimmed)
                .map_err(|e| Error::protocol(format!("parse auth bundle JSON: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Form, Json, Router};
    use rsa::PrivateKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::signature::Verifier;
    use rship_core::clock::VirtualClock;
    use rship_transport::TransportConfig;
    use sha2::Sha256;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    #[tokio::test]
    async fn pkce_loopback_flow_verifies_state_and_exchanges_code_verifier() {
        let captured = Arc::new(StdMutex::new(HashMap::<String, String>::new()));
        let cap_c = captured.clone();

        let app = Router::new().route(
            "/token",
            post(move |Form(params): Form<HashMap<String, String>>| {
                let cap = cap_c.clone();
                async move {
                    *cap.lock().unwrap() = params;
                    Json(serde_json::json!({
                        "access_token": "ya29.pkce-access",
                        "refresh_token": "1//pkce-refresh",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let session = PkceFlow::start(
            "my-client-id",
            "my-client-secret",
            crate::gdrive::config::DEFAULT_SCOPE,
            "https://accounts.google.com/o/oauth2/v2/auth",
            &format!("http://{addr}/token"),
        )
        .await
        .unwrap();

        assert!(session.auth_url.contains("code_challenge_method=S256"));
        assert!(session.redirect_uri.starts_with("http://127.0.0.1:"));

        let callback_url = format!(
            "{}?code=auth-code-123&state={}",
            session.redirect_uri, session.state
        );
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));

        let transport_c = transport.clone();
        let exchange_task =
            tokio::spawn(async move { session.wait_and_exchange(&transport_c, &clock).await });

        let resp = transport
            .control_client()
            .get(&callback_url)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());

        let token = exchange_task.await.unwrap().unwrap();
        assert_eq!(token.access_token, "ya29.pkce-access");
        assert_eq!(token.refresh_token.as_deref(), Some("1//pkce-refresh"));
        assert_eq!(token.expires_at_unix_secs, 1_700_003_600);

        let params = captured.lock().unwrap();
        assert_eq!(
            params.get("code").map(String::as_str),
            Some("auth-code-123")
        );
        assert_eq!(
            params.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert!(params.get("code_verifier").is_some_and(|v| v.len() >= 43));
    }

    #[tokio::test]
    async fn oauth2_single_flight_force_refresh_deduplicates_concurrent_401s() {
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let rc = refresh_calls.clone();

        let app = Router::new().route(
            "/token",
            post(move || {
                let rc = rc.clone();
                async move {
                    let n = rc.fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    Json(serde_json::json!({
                        "access_token": format!("ya29.fresh-{n}"),
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let store = Arc::new(InMemoryTokenStore::new(Some(OAuthToken {
            access_token: "ya29.stale".into(),
            refresh_token: Some("1//keep-me".into()),
            token_type: "Bearer".into(),
            expires_at_unix_secs: 1_700_003_600,
            scope: None,
        })));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let provider = Arc::new(
            OAuth2AuthProvider::new(
                "alice@example.com",
                "cid",
                "csec",
                format!("http://{addr}/token"),
                transport,
                store.clone(),
                clock,
            )
            .unwrap(),
        );

        let (r1, r2, r3) = tokio::join!(
            provider.force_refresh("ya29.stale"),
            provider.force_refresh("ya29.stale"),
            provider.force_refresh("ya29.stale"),
        );
        assert_eq!(r1.unwrap(), "ya29.fresh-1");
        assert_eq!(r2.unwrap(), "ya29.fresh-1");
        assert_eq!(r3.unwrap(), "ya29.fresh-1");
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);

        let persisted = store.load().unwrap().unwrap();
        assert_eq!(persisted.refresh_token.as_deref(), Some("1//keep-me"));
    }

    #[tokio::test]
    async fn service_account_rs256_jwt_with_dwd_sub_verifies_and_exchanges() {
        let mut rng = rand::rng();
        let private_key = PrivateKey::new(&mut rng, 2048).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(private_key.to_public_key());
        let pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap()
            .to_string();

        let captured_jwt = Arc::new(StdMutex::new(String::new()));
        let cj = captured_jwt.clone();

        let app = Router::new().route(
            "/token",
            post(move |Form(params): Form<HashMap<String, String>>| {
                let cj = cj.clone();
                async move {
                    assert_eq!(
                        params.get("grant_type").map(String::as_str),
                        Some(JWT_GRANT_TYPE)
                    );
                    *cj.lock().unwrap() = params.get("assertion").cloned().unwrap_or_default();
                    Json(serde_json::json!({
                        "access_token": "ya29.sa-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    }))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let sa_key = ServiceAccountKey {
            client_email: "bot@proj.iam.gserviceaccount.com".into(),
            private_key: pem,
            private_key_id: Some("kid-42".into()),
            token_uri: format!("http://{addr}/token"),
            project_id: Some("proj".into()),
        };
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let provider = ServiceAccountAuthProvider::new(
            sa_key,
            crate::gdrive::config::DEFAULT_SCOPE,
            Some("admin@corp.example".into()),
            None,
            transport,
            clock,
        )
        .unwrap();

        let tok = provider.access_token().await.unwrap();
        assert_eq!(tok, "ya29.sa-token");

        let jwt = captured_jwt.lock().unwrap().clone();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let sig = Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("RS256 signature must verify");

        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], "kid-42");
        assert_eq!(claims["iss"], "bot@proj.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], "admin@corp.example");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_003_600);
    }

    #[test]
    fn auth_export_bundle_round_trips_compact_and_json() {
        let bundle = AuthExportBundle {
            version: 1,
            remote_name: "mygd".into(),
            remote_type: "gdrive".into(),
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            root_folder_id: Some("root".into()),
            shared_drive_id: Some("0A-shared".into()),
            scope: Some(crate::gdrive::config::DEFAULT_SCOPE.into()),
            token: Some(OAuthToken {
                access_token: "acc".into(),
                refresh_token: Some("ref".into()),
                token_type: "Bearer".into(),
                expires_at_unix_secs: 1_800_000_000,
                scope: None,
            }),
            service_account_json: None,
            impersonate: None,
        };
        let encoded = bundle.encode_compact().unwrap();
        assert!(encoded.starts_with("rship-auth-v1:"));
        assert_eq!(AuthExportBundle::decode(&encoded).unwrap(), bundle);

        let raw_json = serde_json::to_string_pretty(&bundle).unwrap();
        assert_eq!(AuthExportBundle::decode(&raw_json).unwrap(), bundle);
    }

    #[tokio::test]
    async fn pkce_preferred_port_fallback_favicon_ignore_and_manual_url_exchange() {
        let app = Router::new().route(
            "/token",
            post(|| async {
                Json(serde_json::json!({
                    "access_token": "ya29.manual-access",
                    "refresh_token": "1//manual-refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }))
            }),
        );
        let token_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token_addr = token_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(token_listener, app).await;
        });

        // 1. Occupy a port to verify both non-strict fallback AND strict_port failure.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let busy_port = occupied.local_addr().unwrap().port();

        let strict_err = PkceFlow::start_with_port(
            "cid",
            "csec",
            crate::gdrive::config::DEFAULT_SCOPE,
            "https://accounts.google.com/o/oauth2/v2/auth",
            &format!("http://{token_addr}/token"),
            Some(busy_port),
            true,
        )
        .await;
        assert!(
            strict_err.is_err(),
            "strict_port must fail when port is busy"
        );

        let fallback_session = PkceFlow::start_with_port(
            "cid",
            "csec",
            crate::gdrive::config::DEFAULT_SCOPE,
            "https://accounts.google.com/o/oauth2/v2/auth",
            &format!("http://{token_addr}/token"),
            Some(busy_port),
            false,
        )
        .await
        .unwrap();
        assert_ne!(fallback_session.port(), busy_port);

        // 2. Loopback listener ignores `/favicon.ico?v=1` (404), ignores mismatched-state XSS probe
        //    without aborting or reflecting raw HTML, and still accepts the real callback!
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let clock: Arc<dyn Clock> = Arc::new(VirtualClock::new(1_700_000_000));
        let favicon_url = format!(
            "http://127.0.0.1:{}/favicon.ico?v=1",
            fallback_session.port()
        );
        let xss_probe_url = format!(
            "{}?error=%3Cscript%3Ealert(1)%3C/script%3E&state=bogus-state",
            fallback_session.redirect_uri
        );
        let cb_url = format!(
            "{}?code=ok-after-favicon&state={}",
            fallback_session.redirect_uri, fallback_session.state
        );
        let t_bg = transport.clone();
        let c_bg = clock.clone();
        let wait_task =
            tokio::spawn(async move { fallback_session.wait_and_exchange(&t_bg, &c_bg).await });

        let fav_resp = transport
            .control_client()
            .get(&favicon_url)
            .send()
            .await
            .unwrap();
        assert_eq!(fav_resp.status().as_u16(), 404);

        let xss_resp = transport
            .control_client()
            .get(&xss_probe_url)
            .send()
            .await
            .unwrap();
        assert_eq!(xss_resp.status().as_u16(), 400);
        let xss_body = xss_resp.text().await.unwrap();
        assert!(
            !xss_body.contains("<script>"),
            "unencoded HTML leaked: {xss_body}"
        );

        let cb_resp = transport
            .control_client()
            .get(&cb_url)
            .send()
            .await
            .unwrap();
        assert!(cb_resp.status().is_success());
        let tok1 = wait_task.await.unwrap().unwrap();
        assert_eq!(tok1.access_token, "ya29.manual-access");

        // 2b. Non-http(s) auth_endpoint scheme must be rejected.
        let bad_scheme = PkceFlow::start(
            "cid",
            "csec",
            crate::gdrive::config::DEFAULT_SCOPE,
            "file:///etc/passwd",
            &format!("http://{token_addr}/token"),
        )
        .await;
        assert!(bad_scheme.is_err());

        // 3. Manual paste URL validation (including error_description) & token exchange.
        let manual_session = PkceFlow::start(
            "cid",
            "csec",
            crate::gdrive::config::DEFAULT_SCOPE,
            "https://accounts.google.com/o/oauth2/v2/auth",
            &format!("http://{token_addr}/token"),
        )
        .await
        .unwrap();
        assert!(
            manual_session
                .parse_callback_url("http://127.0.0.1:9999/callback?code=abc&state=wrong")
                .is_err()
        );
        let denied_err = manual_session
            .parse_callback_url(&format!(
                "error=access_denied&error_description=User+cancelled+consent&state={}",
                manual_session.state
            ))
            .unwrap_err();
        assert!(
            denied_err.to_string().contains("User cancelled consent"),
            "expected error_description preserved, got: {denied_err}"
        );
        let pasted = format!(
            "{}?code=manual-code-77&state={}",
            manual_session.redirect_uri, manual_session.state
        );
        let tok2 = manual_session
            .exchange_callback_url(&pasted, &transport, &clock)
            .await
            .unwrap();
        assert_eq!(tok2.access_token, "ya29.manual-access");
        assert_eq!(tok2.refresh_token.as_deref(), Some("1//manual-refresh"));
    }
}
