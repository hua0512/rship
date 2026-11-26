//! Microsoft Identity Platform OAuth2 Desktop PKCE loopback (`127.0.0.1:0`) and
//! single-flight `401` token refresh built on shared `rship_transport::oauth`.

use async_trait::async_trait;
use rship_core::Result;
use rship_core::clock::SystemClock;
use rship_transport::HttpTransport;
use rship_transport::oauth::{OAuth2RefreshConfig, OAuth2TokenManager, PkceConfig, PkceSession};
use std::sync::Arc;

pub use rship_transport::oauth::{
    FileTokenStore as FileOnedriveTokenStore, OAuthProvider as OnedriveAuthProvider,
    OAuthToken as OnedriveToken, TokenStore as OnedriveTokenStore,
};

/// Microsoft Entra ID OAuth2 refresh manager delegating to `rship_transport::oauth`.
pub struct OnedriveOAuth2Auth(OAuth2TokenManager);

impl OnedriveOAuth2Auth {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        token_url: impl Into<String>,
        scope: impl Into<String>,
        principal: impl Into<String>,
        transport: HttpTransport,
        store: Arc<dyn OnedriveTokenStore>,
    ) -> Result<Self> {
        let raw_scope = scope.into();
        let trimmed = raw_scope.trim();
        let refresh_scope = (!trimmed.is_empty()).then(|| trimmed.to_string());
        let mgr = OAuth2TokenManager::new(
            OAuth2RefreshConfig {
                principal: principal.into(),
                client_id: client_id.into(),
                client_secret,
                token_url: token_url.into(),
                refresh_scope,
                missing_refresh_hint: "re-run `rship auth onedrive <remote>`".to_string(),
                refresh_error_hint: None,
            },
            transport,
            store,
            SystemClock::shared(),
        )?;
        Ok(Self(mgr))
    }
}

#[async_trait]
impl OnedriveAuthProvider for OnedriveOAuth2Auth {
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

/// Interactive Desktop PKCE S256 loopback authorization flow for OneDrive / SharePoint.
pub struct OnedrivePkceFlow {
    pub authorize_url: String,
    pub redirect_uri: String,
    session: PkceSession,
}

impl OnedrivePkceFlow {
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
            extra_auth_params: Vec::new(),
            include_scope_in_token_exchange: true,
            callback_path: String::new(),
            success_title: "rship OneDrive authorization complete".to_string(),
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

    pub async fn complete(self, transport: &HttpTransport) -> Result<OnedriveToken> {
        self.session
            .wait_and_exchange(transport, &SystemClock::shared())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_transport::TransportConfig;
    use rship_transport::oauth::InMemoryTokenStore;

    #[test]
    fn empty_refresh_scope_is_omitted_and_non_empty_does_not_inject_user_read() {
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let store = Arc::new(InMemoryTokenStore::new(None));
        let auth_empty = OnedriveOAuth2Auth::new(
            "cid",
            None,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "   ",
            "alice@example.com",
            transport.clone(),
            store.clone(),
        )
        .unwrap();
        assert_eq!(auth_empty.principal(), "alice@example.com");

        let auth_scoped = OnedriveOAuth2Auth::new(
            "cid",
            None,
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            crate::onedrive::config::DEFAULT_ONEDRIVE_SCOPE,
            "alice@example.com",
            transport,
            store,
        )
        .unwrap();
        assert_eq!(auth_scoped.principal(), "alice@example.com");
    }
}
