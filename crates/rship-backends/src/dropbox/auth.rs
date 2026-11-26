//! Dropbox OAuth2 Desktop PKCE loopback (`token_access_type=offline`) and single-flight
//! `401` refresh built on shared `rship_transport::oauth`.

use async_trait::async_trait;
use rship_core::Result;
use rship_core::clock::SystemClock;
use rship_transport::HttpTransport;
use rship_transport::oauth::{OAuth2RefreshConfig, OAuth2TokenManager, PkceConfig, PkceSession};
use std::sync::Arc;

pub use rship_transport::oauth::{
    FileTokenStore as FileDropboxTokenStore, OAuthProvider as DropboxAuthProvider,
    OAuthToken as DropboxToken, TokenStore as DropboxTokenStore,
};

pub struct DropboxOAuth2Auth(OAuth2TokenManager);

impl DropboxOAuth2Auth {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        token_url: impl Into<String>,
        principal: impl Into<String>,
        transport: HttpTransport,
        store: Arc<dyn DropboxTokenStore>,
    ) -> Result<Self> {
        let mgr = OAuth2TokenManager::new(
            OAuth2RefreshConfig {
                principal: principal.into(),
                client_id: client_id.into(),
                client_secret,
                token_url: token_url.into(),
                refresh_scope: None,
                missing_refresh_hint: "re-run `rship auth dropbox <remote>`".to_string(),
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
impl DropboxAuthProvider for DropboxOAuth2Auth {
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

pub struct DropboxPkceFlow {
    pub authorize_url: String,
    pub redirect_uri: String,
    session: PkceSession,
}

impl DropboxPkceFlow {
    pub async fn start(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> Result<Self> {
        Self::start_with_port(client_id, client_secret, auth_url, token_url, None, false).await
    }

    pub async fn start_with_port(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        preferred_port: Option<u16>,
        strict_port: bool,
    ) -> Result<Self> {
        let session = PkceSession::start(PkceConfig {
            client_id: client_id.into(),
            client_secret,
            auth_endpoint: auth_url.into(),
            token_endpoint: token_url.into(),
            scope: String::new(),
            extra_auth_params: vec![("token_access_type".into(), "offline".into())],
            include_scope_in_token_exchange: false,
            callback_path: "/callback".to_string(),
            success_title: "rship Dropbox authorization complete".to_string(),
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

    pub async fn complete(self, transport: &HttpTransport) -> Result<DropboxToken> {
        self.session
            .wait_and_exchange(transport, &SystemClock::shared())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pkce_authorize_url_omits_empty_scope_and_sets_offline_s256() {
        let flow = DropboxPkceFlow::start(
            "dbx-app-key",
            None,
            "https://www.dropbox.com/oauth2/authorize",
            "https://api.dropboxapi.com/oauth2/token",
        )
        .await
        .expect("start DropboxPkceFlow");
        let query = flow
            .authorize_url
            .split_once('?')
            .map(|(_, q)| q)
            .unwrap_or("");
        let params: Vec<(&str, &str)> = query
            .split('&')
            .filter(|p| !p.is_empty())
            .map(|p| p.split_once('=').unwrap_or((p, "")))
            .collect();
        assert!(
            !params.iter().any(|(k, _)| *k == "scope"),
            "Dropbox authorize_url must omit empty scope parameter: {}",
            flow.authorize_url
        );
        assert!(
            params
                .iter()
                .any(|(k, v)| *k == "token_access_type" && *v == "offline"),
            "missing token_access_type=offline: {}",
            flow.authorize_url
        );
        assert!(
            params
                .iter()
                .any(|(k, v)| *k == "code_challenge_method" && *v == "S256"),
            "missing code_challenge_method=S256: {}",
            flow.authorize_url
        );
        drop(flow);
    }
}
