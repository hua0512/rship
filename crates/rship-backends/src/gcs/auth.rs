//! Google Cloud Storage authentication providers:
//! - Service Account RS256 JWT (via shared [`crate::common::google_sa`])
//! - OAuth2 Desktop PKCE loopback (`access_type=offline`, `prompt=consent`)
//! - Static bearer token

use async_trait::async_trait;
use rship_core::Result;
use rship_core::clock::SystemClock;
use rship_transport::HttpTransport;
use rship_transport::oauth::{OAuth2RefreshConfig, OAuth2TokenManager, PkceConfig, PkceSession};
use std::sync::Arc;

pub use crate::common::google_sa::{ServiceAccountAuthProvider, ServiceAccountKey};
pub use rship_transport::oauth::{
    FileTokenStore as FileGcsTokenStore, OAuthProvider as GcsAuthProvider, OAuthToken as GcsToken,
    TokenStore as GcsTokenStore,
};

pub struct GcsOAuth2Auth(OAuth2TokenManager);

impl GcsOAuth2Auth {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        token_url: impl Into<String>,
        principal: impl Into<String>,
        transport: HttpTransport,
        store: Arc<dyn GcsTokenStore>,
    ) -> Result<Self> {
        let mgr = OAuth2TokenManager::new(
            OAuth2RefreshConfig {
                principal: principal.into(),
                client_id: client_id.into(),
                client_secret,
                token_url: token_url.into(),
                refresh_scope: None,
                missing_refresh_hint: "re-run `rship auth gcs <remote>`".to_string(),
                refresh_error_hint: Some(
                    "if using an external Google OAuth app in Testing mode, publish it or use a Service Account JSON key"
                        .to_string(),
                ),
            },
            transport,
            store,
            SystemClock::shared(),
        )?;
        Ok(Self(mgr))
    }
}

#[async_trait]
impl GcsAuthProvider for GcsOAuth2Auth {
    fn principal(&self) -> &str {
        self.0.principal()
    }

    async fn access_token(&self) -> Result<String> {
        self.0.access_token().await
    }

    async fn force_refresh(&self, failed_token: &str) -> Result<String> {
        self.0.force_refresh(failed_token).await
    }
}

pub struct GcsPkceFlow {
    pub authorize_url: String,
    pub redirect_uri: String,
    session: PkceSession,
}

impl GcsPkceFlow {
    pub async fn start(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<Self> {
        Self::start_with_port(
            client_id,
            client_secret,
            auth_url,
            token_url,
            scope,
            None,
            false,
        )
        .await
    }

    pub async fn start_with_port(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
        preferred_port: Option<u16>,
        strict_port: bool,
    ) -> Result<Self> {
        let session = PkceSession::start(PkceConfig {
            client_id: client_id.into(),
            client_secret,
            auth_endpoint: auth_url.into(),
            token_endpoint: token_url.into(),
            scope: scope.into(),
            extra_auth_params: vec![
                ("access_type".into(), "offline".into()),
                ("prompt".into(), "consent".into()),
            ],
            include_scope_in_token_exchange: false,
            callback_path: "/callback".to_string(),
            success_title: "rship Google Cloud Storage authorization complete".to_string(),
            preferred_port,
            strict_port,
        })
        .await?;
        let authorize_url = session.auth_url.clone();
        let redirect_uri = session.redirect_uri.clone();
        Ok(Self {
            authorize_url,
            redirect_uri,
            session,
        })
    }

    pub fn into_session(self) -> PkceSession {
        self.session
    }

    pub async fn complete(self, transport: &HttpTransport) -> Result<GcsToken> {
        self.session
            .wait_and_exchange(transport, &SystemClock::shared())
            .await
    }
}
