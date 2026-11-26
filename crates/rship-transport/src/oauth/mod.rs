//! Shared OAuth 2.0 Desktop PKCE loopback (`127.0.0.1:0`), atomic `0600` token
//! persistence, and single-flight `401` refresh manager shared across all OAuth2
//! cloud backends (Google Drive, Microsoft OneDrive, future Dropbox/Box/etc.).

mod pkce;
mod store;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use rship_core::clock::Clock;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::{HttpTransport, LimiterScope, parse_retry_after};

pub use pkce::{DEFAULT_OAUTH_CALLBACK_PORT, PkceConfig, PkceSession};
pub use store::{FileTokenStore, InMemoryTokenStore, TokenStore};

/// Proactive refresh window before token expiry (seconds).
pub const PROACTIVE_REFRESH_MARGIN_SECS: i64 = 60;

fn default_bearer() -> String {
    "Bearer".to_string()
}

fn deserialize_null_bearer<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_else(default_bearer))
}

fn deserialize_null_i64<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(deserializer)?.unwrap_or(0))
}

/// Normalized OAuth 2.0 bearer token persisted on disk or held in memory.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthToken {
    pub access_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(
        default = "default_bearer",
        deserialize_with = "deserialize_null_bearer"
    )]
    pub token_type: String,
    #[serde(
        default,
        alias = "expires_at_unix",
        deserialize_with = "deserialize_null_i64"
    )]
    pub expires_at_unix_secs: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthToken")
            .field(
                "access_token",
                &if self.access_token.is_empty() {
                    "<empty>"
                } else {
                    "[REDACTED]"
                },
            )
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .field("scope", &self.scope)
            .finish()
    }
}

impl OAuthToken {
    /// Compute the proactive refresh margin for a token minted with `ttl_secs`
    /// (`expires_in`). Clamps `ttl / 2` to `[0, PROACTIVE_REFRESH_MARGIN_SECS]` so
    /// short-lived tokens (e.g. `expires_in = 30` or `60`) do not refresh on every call.
    pub fn effective_refresh_margin_for_ttl(ttl_secs: i64) -> i64 {
        (ttl_secs.max(1) / 2).clamp(0, PROACTIVE_REFRESH_MARGIN_SECS)
    }

    /// Returns `true` when `access_token` is non-empty and still has more than
    /// `refresh_margin_secs` (clamped to `[0, PROACTIVE_REFRESH_MARGIN_SECS]`)
    /// remaining before expiry.
    pub fn is_valid_at_with_margin(&self, now_unix_secs: i64, refresh_margin_secs: i64) -> bool {
        let margin = refresh_margin_secs.clamp(0, PROACTIVE_REFRESH_MARGIN_SECS);
        !self.access_token.is_empty()
            && self.expires_at_unix_secs > now_unix_secs.saturating_add(margin)
    }

    /// Returns `true` when `access_token` is non-empty and still has more than
    /// `PROACTIVE_REFRESH_MARGIN_SECS` remaining before expiry.
    pub fn is_valid_at(&self, now_unix_secs: i64) -> bool {
        self.is_valid_at_with_margin(now_unix_secs, PROACTIVE_REFRESH_MARGIN_SECS)
    }

    /// Inverse convenience check used by callers checking expiration.
    pub fn is_expired_at(&self, now_unix_secs: i64) -> bool {
        !self.is_valid_at(now_unix_secs)
    }
}

/// On-disk JSON representation preserving backward compatibility with legacy
/// `OAuthToken` files while persisting optional per-token proactive refresh margins.
#[derive(Clone, Serialize, Deserialize)]
struct StoredOAuthToken {
    #[serde(flatten)]
    token: OAuthToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh_margin_secs: Option<i64>,
}

/// Provider-agnostic OAuth bearer token provider with single-flight `401` refresh.
#[async_trait]
pub trait OAuthProvider: Send + Sync {
    /// Stable principal identifier used for rate-limiter & delta-inventory scoping.
    fn principal(&self) -> &str;

    /// Obtain a valid Bearer access token (proactively refreshing if close to expiry).
    async fn access_token(&self) -> Result<String>;

    /// Force a single-flight token refresh after an HTTP `401 Unauthorized` response.
    /// If another concurrent request already refreshed `rejected_token`, returns the
    /// newly cached token without triggering a redundant token endpoint call.
    async fn force_refresh(&self, rejected_token: &str) -> Result<String>;
}

/// Static bearer token provider for tests or ephemeral tokens.
///
/// Parameter order is `(principal, token)`: `principal` identifies the account
/// for rate-limiter and delta-inventory scoping, while `token` is the raw bearer secret.
#[derive(Clone)]
pub struct StaticBearerAuth {
    principal: String,
    token: String,
}

impl std::fmt::Debug for StaticBearerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticBearerAuth")
            .field("principal", &self.principal)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl StaticBearerAuth {
    /// Construct a static bearer auth provider from `(principal, token)`.
    ///
    /// Pass the account/user identifier first (`principal`) and the bearer secret
    /// second (`token`).
    pub fn new(principal: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            token: token.into(),
        }
    }
}

#[async_trait]
impl OAuthProvider for StaticBearerAuth {
    fn principal(&self) -> &str {
        &self.principal
    }

    async fn access_token(&self) -> Result<String> {
        Ok(self.token.clone())
    }

    async fn force_refresh(&self, _rejected_token: &str) -> Result<String> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            RetryClass::Permanent,
            "static bearer token rejected (401) and no refresh credentials are configured",
        ))
    }
}

#[derive(Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default = "default_expires_in")]
    expires_in: i64,
    #[serde(default)]
    scope: Option<String>,
}

fn default_expires_in() -> i64 {
    3600
}

/// Configuration for [`OAuth2TokenManager`].
#[derive(Clone)]
pub struct OAuth2RefreshConfig {
    pub principal: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub token_url: String,
    /// Optional `scope` sent on `refresh_token` grant (required by Microsoft Graph,
    /// omitted by Google OAuth2).
    pub refresh_scope: Option<String>,
    /// Human-readable guidance when no `refresh_token` is persisted.
    pub missing_refresh_hint: String,
    /// Optional extra hint appended to HTTP refresh errors (e.g. Google Testing 7-day note).
    pub refresh_error_hint: Option<String>,
}

impl std::fmt::Debug for OAuth2RefreshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2RefreshConfig")
            .field("principal", &self.principal)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("token_url", &self.token_url)
            .field("refresh_scope", &self.refresh_scope)
            .finish()
    }
}

#[derive(Clone)]
struct CachedToken {
    token: OAuthToken,
    refresh_margin_secs: Option<i64>,
    /// `true` while this token was minted by a refresh but could not be written to the
    /// [`TokenStore`]. The in-memory copy is then authoritative: IdPs such as Microsoft
    /// rotate refresh tokens, so the persisted record holds an already-revoked one.
    unpersisted: bool,
}

impl CachedToken {
    fn effective_refresh_margin_secs(&self) -> i64 {
        self.refresh_margin_secs
            .unwrap_or(PROACTIVE_REFRESH_MARGIN_SECS)
            .clamp(0, PROACTIVE_REFRESH_MARGIN_SECS)
    }

    fn is_valid_at(&self, now_unix_secs: i64) -> bool {
        self.token
            .is_valid_at_with_margin(now_unix_secs, self.effective_refresh_margin_secs())
    }
}

enum CachedState {
    Unloaded,
    Loaded(Option<CachedToken>),
}

struct RefreshLockGuard(Option<Box<dyn Send>>);

impl RefreshLockGuard {
    /// Release any underlying OS file lock on the blocking threadpool so async
    /// worker threads are never stalled by file unlock/close syscalls.
    async fn release(mut self) {
        if let Some(lock) = self.0.take() {
            let _ = tokio::task::spawn_blocking(move || drop(lock)).await;
        }
    }
}

/// Single-flight OAuth2 refresh manager usable by any OAuth2 cloud provider.
pub struct OAuth2TokenManager {
    cfg: OAuth2RefreshConfig,
    transport: HttpTransport,
    store: Arc<dyn TokenStore>,
    clock: Arc<dyn Clock>,
    cached: Mutex<CachedState>,
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl OAuth2TokenManager {
    pub fn new(
        cfg: OAuth2RefreshConfig,
        transport: HttpTransport,
        store: Arc<dyn TokenStore>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        Ok(Self {
            cfg,
            transport,
            store,
            clock,
            cached: Mutex::new(CachedState::Unloaded),
            max_retries: 4,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(30),
        })
    }

    /// Override the bounded retry policy used on transient OAuth2 token endpoint errors
    /// (`429`, `408`, `5xx`, and retryable transport/timeout errors).
    pub fn with_retry_config(
        mut self,
        max_retries: u32,
        base_delay: Duration,
        max_delay: Duration,
    ) -> Self {
        self.max_retries = max_retries;
        self.base_delay = base_delay;
        self.max_delay = max_delay;
        self
    }

    async fn load_store(&self) -> Result<Option<CachedToken>> {
        let store = Arc::clone(&self.store);
        let loaded = tokio::task::spawn_blocking(move || store.load_with_margin())
            .await
            .map_err(|e| Error::protocol(format!("OAuth2 token store load task failed: {e}")))??;
        Ok(loaded.map(|(token, refresh_margin_secs)| CachedToken {
            token,
            refresh_margin_secs,
            unpersisted: false,
        }))
    }

    async fn save_store(&self, token: OAuthToken, refresh_margin_secs: Option<i64>) -> Result<()> {
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.save_with_margin(&token, refresh_margin_secs))
            .await
            .map_err(|e| Error::protocol(format!("OAuth2 token store save task failed: {e}")))?
    }

    async fn lock_store_refresh(&self) -> Result<RefreshLockGuard> {
        let store = Arc::clone(&self.store);
        let lock = tokio::task::spawn_blocking(move || store.lock_refresh())
            .await
            .map_err(|e| Error::protocol(format!("OAuth2 token store lock task failed: {e}")))??;
        Ok(RefreshLockGuard(lock))
    }

    async fn refresh_locked(
        &self,
        guard: &mut CachedState,
        rejected_token: Option<&str>,
    ) -> Result<String> {
        let lock_guard = self.lock_store_refresh().await?;
        let res = self.refresh_with_store_lock(guard, rejected_token).await;
        lock_guard.release().await;
        res
    }

    async fn refresh_with_store_lock(
        &self,
        guard: &mut CachedState,
        rejected_token: Option<&str>,
    ) -> Result<String> {
        // A previous refresh could not persist its (possibly rotated) token: retry the save
        // first. While it still fails, keep using the in-memory token and do NOT adopt the
        // stale persisted record, whose refresh_token the IdP may already have revoked.
        let mut memory_is_authoritative = false;
        if let CachedState::Loaded(Some(cached)) = &mut *guard
            && cached.unpersisted
        {
            match self
                .save_store(cached.token.clone(), cached.refresh_margin_secs)
                .await
            {
                Ok(()) => cached.unpersisted = false,
                Err(e) => {
                    tracing::warn!(
                        principal = %self.cfg.principal,
                        "OAuth2 token store still unwritable; keeping rotated token in memory: {e}"
                    );
                    memory_is_authoritative = true;
                }
            }
        }

        // Re-read the backing store under the cross-process lock: if another
        // process/instance already refreshed (and potentially rotated the
        // refresh_token), adopt that valid token and skip the HTTP refresh.
        if !memory_is_authoritative && let Some(fresh) = self.load_store().await? {
            let now = self.clock.now_unix_secs();
            let not_rejected =
                rejected_token.is_none_or(|rejected| fresh.token.access_token != rejected);
            if not_rejected && fresh.is_valid_at(now) {
                let access = fresh.token.access_token.clone();
                *guard = CachedState::Loaded(Some(fresh));
                return Ok(access);
            }
            // Adopt the freshest persisted record even when expired/rejected so we
            // use any rotated `refresh_token` written by a peer.
            *guard = CachedState::Loaded(Some(fresh));
        }

        let current = match guard {
            CachedState::Loaded(opt) => opt.as_ref(),
            CachedState::Unloaded => None,
        };
        let refresh_token = current
            .and_then(|c| c.token.refresh_token.clone())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!(
                        "no OAuth refresh_token available; {}",
                        self.cfg.missing_refresh_hint
                    ),
                )
            })?;
        let prev_scope = current.and_then(|c| c.token.scope.clone());

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("client_id", self.cfg.client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ];
        if let Some(sec) = self.cfg.client_secret.as_deref().filter(|s| !s.is_empty()) {
            form.push(("client_secret", sec));
        }
        if let Some(scope) = self
            .cfg
            .refresh_scope
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            form.push(("scope", scope));
        }

        let limiter = self
            .transport
            .control_limiter_for(LimiterScope::new("oauth2", &self.cfg.principal));
        let hint_suffix = self
            .cfg
            .refresh_error_hint
            .as_deref()
            .map(|h| format!(" ({h})"))
            .unwrap_or_default();

        let mut attempt: u32 = 0;
        let mut had_timeout = false;
        let body = loop {
            limiter.acquire_send_permit().await;
            let req = self
                .transport
                .control_client()
                .post(&self.cfg.token_url)
                .form(&form);

            let step_err = match self
                .transport
                .send_control_request("refresh OAuth2 token", req)
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    match self.transport.read_control_body(resp).await {
                        Ok(body) if status.is_success() => {
                            limiter.record_success(attempt > 0, had_timeout);
                            break body;
                        }
                        Ok(body) => {
                            let msg = String::from_utf8_lossy(&body);
                            let err_msg = format!(
                                "OAuth2 token refresh failed (HTTP {}): {}{hint_suffix}",
                                status.as_u16(),
                                msg.trim()
                            );
                            let retry_after = parse_retry_after(&headers);
                            if status.as_u16() == 429 {
                                Error::rate_limited(err_msg, retry_after)
                            } else if status.as_u16() == 408 {
                                let mut err = Error::timeout(err_msg);
                                if let Some(ra) = retry_after {
                                    err = err.with_retry_after(ra);
                                }
                                err
                            } else if status.is_server_error() {
                                let retry = if status.as_u16() == 503 {
                                    RetryClass::Throttled
                                } else {
                                    RetryClass::Retryable
                                };
                                let mut err = Error::new(ErrorKind::Network, retry, err_msg);
                                if let Some(ra) = retry_after {
                                    err = err.with_retry_after(ra);
                                }
                                err
                            } else {
                                return Err(Error::new(
                                    ErrorKind::PermissionDenied,
                                    RetryClass::Permanent,
                                    err_msg,
                                ));
                            }
                        }
                        Err(e) => e,
                    }
                }
                Err(e) => e,
            };

            if !step_err.is_retryable() {
                return Err(step_err);
            }
            let is_timeout = step_err.kind == ErrorKind::Timeout;
            had_timeout |= is_timeout;
            if step_err.is_throttled() {
                limiter.record_throttle();
            }
            if attempt < self.max_retries && limiter.try_acquire_retry_quota(is_timeout) {
                attempt += 1;
                let delay = limiter.backoff_delay(
                    attempt,
                    self.base_delay,
                    self.max_delay,
                    step_err.retry_after,
                );
                if !delay.is_zero() {
                    self.clock.sleep(delay).await;
                }
                continue;
            }
            return Err(step_err.with_retries_exhausted());
        };

        let parsed: TokenEndpointResponse = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse OAuth2 refresh response: {e}")))?;

        let now = self.clock.now_unix_secs();
        let ttl = parsed.expires_in.max(1);
        let margin = OAuthToken::effective_refresh_margin_for_ttl(ttl);
        let updated = OAuthToken {
            access_token: parsed.access_token.clone(),
            // Most IdPs omit refresh_token on refresh responses — preserve existing one!
            refresh_token: parsed.refresh_token.or(Some(refresh_token)),
            token_type: parsed.token_type.unwrap_or_else(default_bearer),
            expires_at_unix_secs: now + ttl,
            scope: parsed.scope.or(prev_scope),
        };
        // Update memory FIRST: the IdP may have rotated (and revoked) the old refresh token,
        // so losing `updated` on a failed save would strand the credential.
        *guard = CachedState::Loaded(Some(CachedToken {
            token: updated.clone(),
            refresh_margin_secs: Some(margin),
            unpersisted: true,
        }));
        match self.save_store(updated, Some(margin)).await {
            Ok(()) => {
                if let CachedState::Loaded(Some(cached)) = &mut *guard {
                    cached.unpersisted = false;
                }
            }
            Err(e) => {
                // The access token is valid; keep serving it and retry persistence on the
                // next refresh. Surface the failure so the user can fix the token store.
                tracing::warn!(
                    principal = %self.cfg.principal,
                    "OAuth2 token refreshed but persisting it failed (will retry on next refresh): {e}"
                );
            }
        }
        Ok(parsed.access_token)
    }
}

#[async_trait]
impl OAuthProvider for OAuth2TokenManager {
    fn principal(&self) -> &str {
        &self.cfg.principal
    }

    async fn access_token(&self) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if matches!(*guard, CachedState::Unloaded) {
            let initial = self.load_store().await?;
            *guard = CachedState::Loaded(initial);
        }
        let now = self.clock.now_unix_secs();
        if let CachedState::Loaded(Some(tok)) = &*guard
            && tok.is_valid_at(now)
        {
            return Ok(tok.token.access_token.clone());
        }
        self.refresh_locked(&mut guard, None).await
    }

    async fn force_refresh(&self, rejected_token: &str) -> Result<String> {
        let mut guard = self.cached.lock().await;
        if matches!(*guard, CachedState::Unloaded) {
            let initial = self.load_store().await?;
            *guard = CachedState::Loaded(initial);
        }
        let now = self.clock.now_unix_secs();
        if let CachedState::Loaded(Some(tok)) = &*guard
            && tok.token.access_token != rejected_token
            && tok.is_valid_at(now)
        {
            return Ok(tok.token.access_token.clone());
        }
        self.refresh_locked(&mut guard, Some(rejected_token)).await
    }
}
