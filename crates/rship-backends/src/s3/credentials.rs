//! Dynamic AWS / S3 credential provider chain (static, env vars, shared
//! `~/.aws/credentials` & `~/.aws/config` profiles, STS `AssumeRole` /
//! `AssumeRoleWithWebIdentity` IRSA, AWS SSO / IAM Identity Center, ECS /
//! EKS Pod Identity container credentials, and EC2 IMDSv2) with single-flight
//! caching, pre-expiry refresh, and `ExpiredToken` forced-refresh recovery —
//! zero heavy AWS SDK dependencies.

use http::{HeaderMap, Method};
use rship_core::clock::Clock;
use rship_core::{Error, ErrorKind, Result, RetryClass};
use rship_transport::HttpTransport;
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use url::{Host, Url};

use crate::common::http::sensitive_header_value;
use crate::s3::config::S3Credentials;
use crate::s3::error::classify_s3_error;
use crate::s3::sigv4::{aws_uri_encode, sha256_hex, sign_v4_service_request};
use crate::s3::xml::parse_sts_credentials_xml;

/// Refresh temporary STS/ECS/IMDS credentials 5 minutes before expiry.
const REFRESH_MARGIN_SECS: i64 = 300;
/// Minimum interval between forced refreshes so repeated IAM `HEAD 403 AccessDenied`
/// responses never stampede ECS/IMDSv2 metadata endpoints.
const FORCE_REFRESH_COOLDOWN_SECS: i64 = 5;
/// Short timeout for local EC2 IMDSv2 / ECS metadata endpoints so non-AWS hosts fail fast.
const METADATA_TIMEOUT: Duration = Duration::from_secs(2);
const STS_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";
const DEFAULT_ECS_ENDPOINT: &str = "http://169.254.170.2";
const MAX_PROFILE_CHAIN_DEPTH: usize = 8;

/// Abstraction over environment lookups so unit tests can exercise env-driven
/// credential flows (IRSA, EKS Pod Identity, `AWS_ENDPOINT_URL_STS`, etc.)
/// without mutating global process environment variables in parallel tests.
trait EnvLookup: Send + Sync {
    fn get_var(&self, key: &str) -> Option<String>;

    fn get_non_empty(&self, key: &str) -> Option<String> {
        self.get_var(key).filter(|s| !s.trim().is_empty())
    }
}

struct StdEnv;

impl EnvLookup for StdEnv {
    fn get_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

#[cfg(test)]
struct MockEnv(HashMap<String, String>);

#[cfg(test)]
impl EnvLookup for MockEnv {
    fn get_var(&self, key: &str) -> Option<String> {
        self.0.get(key).cloned()
    }
}

/// Source strategy used by [`S3CredentialProvider`] to obtain SigV4 credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum S3CredentialSource {
    /// Fixed static key pair (plus optional STS session token).
    Static(S3Credentials),
    /// Standard AWS default credential resolution chain:
    /// - If `profile` is explicitly set: `~/.aws/credentials` / `~/.aws/config` profile first,
    ///   then env vars, ECS container metadata, and EC2 IMDSv2.
    /// - If `profile` is `None`: env vars (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`) first,
    ///   then shared profile (`AWS_PROFILE` / `AWS_DEFAULT_PROFILE` / `"default"`), then ECS
    ///   container credentials, then EC2 IMDSv2.
    AwsChain {
        profile: Option<String>,
        credentials_file: Option<PathBuf>,
        config_file: Option<PathBuf>,
        ecs_endpoint: Option<String>,
        imds_endpoint: Option<String>,
    },
}

impl S3CredentialSource {
    pub fn aws_chain(profile: Option<String>) -> Self {
        Self::AwsChain {
            profile: profile.filter(|s| !s.trim().is_empty()),
            credentials_file: None,
            config_file: None,
            ecs_endpoint: None,
            imds_endpoint: None,
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedCreds {
    creds: S3Credentials,
    expires_at_unix_secs: Option<i64>,
}

#[derive(Debug, Default)]
struct CredCache {
    resolved: Option<ResolvedCreds>,
    last_forced_refresh_unix_secs: Option<i64>,
}

/// Thread-safe, single-flight caching credential provider for [`crate::s3::S3Backend`].
pub struct S3CredentialProvider {
    source: S3CredentialSource,
    transport: HttpTransport,
    clock: Arc<dyn Clock>,
    cache: Mutex<CredCache>,
    sts_endpoint: Option<String>,
    sso_cache_dir: Option<PathBuf>,
    sso_endpoint: Option<String>,
}

impl S3CredentialProvider {
    pub fn new(
        source: S3CredentialSource,
        transport: HttpTransport,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            source,
            transport,
            clock,
            cache: Mutex::new(CredCache::default()),
            sts_endpoint: None,
            sso_cache_dir: None,
            sso_endpoint: None,
        }
    }

    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let ep = endpoint.into();
        if !ep.trim().is_empty() {
            self.sts_endpoint = Some(ep);
        }
        self
    }

    pub fn with_sso_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.sso_cache_dir = Some(dir.into());
        self
    }

    pub fn with_sso_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        let ep = endpoint.into();
        if !ep.trim().is_empty() {
            self.sso_endpoint = Some(ep);
        }
        self
    }

    pub fn is_dynamic(&self) -> bool {
        !matches!(self.source, S3CredentialSource::Static(_))
    }

    /// Return a short stable identity fragment for rate-limiter scoping without triggering I/O.
    pub fn scope_label(&self) -> String {
        match &self.source {
            S3CredentialSource::Static(c) => c.access_key_id.clone(),
            S3CredentialSource::AwsChain { profile, .. } => {
                format!("aws-chain:{}", profile.as_deref().unwrap_or("default"))
            }
        }
    }

    /// Fetch valid SigV4 credentials, refreshing automatically before expiry under a
    /// single-flight lock so concurrent workers never stampede ECS/IMDS endpoints.
    pub async fn credentials(&self) -> Result<S3Credentials> {
        if let S3CredentialSource::Static(ref creds) = self.source {
            return Ok(creds.clone());
        }

        let now = self.clock.now_unix_secs();
        let mut guard = self.cache.lock().await;
        if let Some(ref cached) = guard.resolved
            && is_fresh(cached, now)
        {
            return Ok(cached.creds.clone());
        }

        let resolved = self.resolve_chain().await?;
        let creds = resolved.creds.clone();
        guard.resolved = Some(resolved);
        Ok(creds)
    }

    /// Force a credential refresh after S3 reports `ExpiredToken` / `InvalidToken`.
    ///
    /// Returns `Ok(None)` for static credentials, when within the forced-refresh cooldown
    /// window, or when the underlying provider returns the exact same credentials that just
    /// failed (preventing futile retries and IMDSv2 stampedes on IAM `HEAD 403 AccessDenied`).
    pub async fn force_refresh(
        &self,
        failed_access_key: &str,
        failed_session_token: Option<&str>,
    ) -> Result<Option<S3Credentials>> {
        if matches!(self.source, S3CredentialSource::Static(_)) {
            return Ok(None);
        }

        let now = self.clock.now_unix_secs();
        let mut guard = self.cache.lock().await;
        if let Some(ref cached) = guard.resolved
            && is_fresh(cached, now)
            && (cached.creds.access_key_id != failed_access_key
                || cached.creds.session_token.as_deref() != failed_session_token)
        {
            return Ok(Some(cached.creds.clone()));
        }
        if let Some(last) = guard.last_forced_refresh_unix_secs
            && now.saturating_sub(last) < FORCE_REFRESH_COOLDOWN_SECS
        {
            return Ok(None);
        }

        guard.last_forced_refresh_unix_secs = Some(now);
        let resolved = self.resolve_chain().await?;
        let changed = resolved.creds.access_key_id != failed_access_key
            || resolved.creds.session_token.as_deref() != failed_session_token;
        let creds = resolved.creds.clone();
        guard.resolved = Some(resolved);
        if changed { Ok(Some(creds)) } else { Ok(None) }
    }

    async fn resolve_chain(&self) -> Result<ResolvedCreds> {
        self.resolve_chain_with_env(&StdEnv).await
    }

    async fn resolve_chain_with_env(&self, env: &dyn EnvLookup) -> Result<ResolvedCreds> {
        let S3CredentialSource::AwsChain {
            profile,
            credentials_file,
            config_file,
            ecs_endpoint,
            imds_endpoint,
        } = &self.source
        else {
            unreachable!("static source returned early");
        };

        let explicit_profile = profile.as_deref().filter(|s| !s.trim().is_empty());

        // 1. If an explicit profile was configured on the remote, ONLY resolve that named
        //    profile — never silently fall back to ambient env vars or EC2 IMDSv2 for a
        //    different AWS account.
        if let Some(prof) = explicit_profile {
            let aws_files =
                load_aws_ini_files(credentials_file.as_deref(), config_file.as_deref(), env)
                    .await?;
            let mut visited = Vec::new();
            if let Some(resolved) = self
                .resolve_profile_chain(prof, &aws_files, env, &mut visited)
                .await?
            {
                return Ok(resolved);
            }
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!(
                    "AWS profile `{prof}` was not found or has no usable credentials in ~/.aws/credentials or ~/.aws/config"
                ),
            ));
        }

        // 2. Standard environment variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).
        if let Some(creds) = env_static_credentials(env) {
            return Ok(ResolvedCreds {
                creds,
                expires_at_unix_secs: None,
            });
        }

        // 3. Ambient shared profile (`AWS_PROFILE` / `AWS_DEFAULT_PROFILE` / `"default"`).
        let explicit_env_prof = env
            .get_non_empty("AWS_PROFILE")
            .or_else(|| env.get_non_empty("AWS_DEFAULT_PROFILE"));
        let env_prof = explicit_env_prof.as_deref().unwrap_or("default");
        let aws_files =
            load_aws_ini_files(credentials_file.as_deref(), config_file.as_deref(), env).await?;
        let mut visited = Vec::new();
        if let Some(resolved) = self
            .resolve_profile_chain(env_prof, &aws_files, env, &mut visited)
            .await?
        {
            return Ok(resolved);
        }

        // 4. IRSA / Web Identity Token from environment (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`).
        if let Some(resolved) = self.try_env_web_identity(env).await? {
            return Ok(resolved);
        }

        // 5. ECS / EKS Pod Identity container credentials.
        if let Some(resolved) = self
            .try_ecs_credentials_with_env(ecs_endpoint.as_deref(), env)
            .await?
        {
            return Ok(resolved);
        }

        // 6. EC2 Instance Metadata Service v2 (IMDSv2) unless explicitly disabled.
        let imds_disabled = env
            .get_var("AWS_EC2_METADATA_DISABLED")
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");
        if !imds_disabled && let Some(resolved) = self.try_imds_v2(imds_endpoint.as_deref()).await?
        {
            return Ok(resolved);
        }

        Err(Error::new(
            ErrorKind::PermissionDenied,
            RetryClass::Permanent,
            "unable to resolve AWS credentials via environment variables, ~/.aws/credentials, ~/.aws/config, web identity (IRSA), ECS/EKS Pod Identity metadata, or EC2 IMDSv2",
        ))
    }

    fn resolve_profile_chain<'a>(
        &'a self,
        profile: &'a str,
        files: &'a AwsIniFiles,
        env: &'a dyn EnvLookup,
        visited: &'a mut Vec<String>,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ResolvedCreds>>> + Send + 'a>> {
        Box::pin(async move {
            if visited.iter().any(|p| p == profile) {
                return Err(Error::config(format!(
                    "cycle detected in AWS profile `source_profile` chain involving `{profile}`"
                )));
            }
            if visited.len() >= MAX_PROFILE_CHAIN_DEPTH {
                return Err(Error::config(format!(
                    "AWS profile `source_profile` chain exceeded max depth ({MAX_PROFILE_CHAIN_DEPTH}) at `{profile}`"
                )));
            }
            visited.push(profile.to_string());

            let res = self
                .resolve_profile_inner(profile, files, env, visited)
                .await;
            visited.pop();
            res
        })
    }

    async fn resolve_profile_inner(
        &self,
        profile: &str,
        files: &AwsIniFiles,
        env: &dyn EnvLookup,
        visited: &mut Vec<String>,
    ) -> Result<Option<ResolvedCreds>> {
        let Some(fields) = files.profiles.get(profile) else {
            return Ok(None);
        };

        // 1. Static keys in profile.
        if let (Some(ak), Some(sk)) = (
            fields.get("aws_access_key_id").filter(|s| !s.is_empty()),
            fields
                .get("aws_secret_access_key")
                .filter(|s| !s.is_empty()),
        ) {
            let st = fields
                .get("aws_session_token")
                .filter(|s| !s.is_empty())
                .cloned();
            return Ok(Some(ResolvedCreds {
                creds: S3Credentials::new(ak.clone(), sk.clone()).with_session_token(st),
                expires_at_unix_secs: None,
            }));
        }

        let profile_region = fields
            .get("region")
            .filter(|s| !s.trim().is_empty())
            .cloned()
            .or_else(|| env.get_non_empty("AWS_REGION"))
            .or_else(|| env.get_non_empty("AWS_DEFAULT_REGION"));

        // 2. Role ARN: either Web Identity (`web_identity_token_file`) or STS `AssumeRole`.
        if let Some(role_arn) = fields.get("role_arn").filter(|s| !s.trim().is_empty()) {
            let session_name = fields
                .get("role_session_name")
                .filter(|s| !s.trim().is_empty())
                .cloned()
                .or_else(|| env.get_non_empty("AWS_ROLE_SESSION_NAME"))
                .unwrap_or_else(|| "rship-s3-session".to_string());

            if let Some(token_file) = fields
                .get("web_identity_token_file")
                .filter(|s| !s.trim().is_empty())
            {
                return self
                    .assume_role_with_web_identity(
                        role_arn.trim(),
                        token_file.trim(),
                        &session_name,
                        profile_region.as_deref(),
                        env,
                    )
                    .await
                    .map(Some);
            }

            let source_profile = fields
                .get("source_profile")
                .filter(|s| !s.trim().is_empty());
            let credential_source = fields
                .get("credential_source")
                .filter(|s| !s.trim().is_empty());
            if source_profile.is_some() && credential_source.is_some() {
                return Err(Error::config(format!(
                    "AWS profile `{profile}` specifies both `source_profile` and `credential_source`"
                )));
            }

            let source_creds = if let Some(src_prof) = source_profile {
                let Some(resolved) = self
                    .resolve_profile_chain(src_prof.trim(), files, env, visited)
                    .await?
                else {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        format!(
                            "AWS profile `{profile}` references missing `source_profile = {src_prof}`"
                        ),
                    ));
                };
                resolved.creds
            } else if let Some(cs) = credential_source {
                self.resolve_credential_source(cs.trim(), env).await?
            } else {
                return Err(Error::config(format!(
                    "AWS profile `{profile}` specifies `role_arn` without `source_profile`, `credential_source`, or `web_identity_token_file`"
                )));
            };

            let external_id = fields
                .get("external_id")
                .filter(|s| !s.trim().is_empty())
                .map(String::as_str);

            return self
                .assume_role_with_sts(
                    role_arn.trim(),
                    &session_name,
                    external_id,
                    &source_creds,
                    profile_region.as_deref(),
                    env,
                )
                .await
                .map(Some);
        }

        // 3. AWS SSO / IAM Identity Center (`sso_account_id` + `sso_role_name`).
        if let (Some(account_id), Some(role_name)) = (
            fields
                .get("sso_account_id")
                .filter(|s| !s.trim().is_empty()),
            fields.get("sso_role_name").filter(|s| !s.trim().is_empty()),
        ) {
            let sso_session_name = fields
                .get("sso_session")
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string());
            let session_fields = sso_session_name
                .as_deref()
                .and_then(|name| files.sso_sessions.get(name));

            let start_url = session_fields
                .and_then(|m| m.get("sso_start_url"))
                .or_else(|| fields.get("sso_start_url"))
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .ok_or_else(|| {
                    Error::config(format!(
                        "AWS SSO profile `{profile}` is missing `sso_start_url`"
                    ))
                })?;

            let sso_region = session_fields
                .and_then(|m| m.get("sso_region"))
                .or_else(|| fields.get("sso_region"))
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .ok_or_else(|| {
                    Error::config(format!(
                        "AWS SSO profile `{profile}` is missing `sso_region`"
                    ))
                })?;

            return self
                .resolve_sso_credentials(
                    sso_session_name.as_deref(),
                    &start_url,
                    &sso_region,
                    account_id.trim(),
                    role_name.trim(),
                    env,
                )
                .await
                .map(Some);
        }

        Ok(None)
    }

    async fn resolve_credential_source(
        &self,
        credential_source: &str,
        env: &dyn EnvLookup,
    ) -> Result<S3Credentials> {
        let S3CredentialSource::AwsChain {
            ecs_endpoint,
            imds_endpoint,
            ..
        } = &self.source
        else {
            unreachable!();
        };
        match credential_source {
            "Environment" => env_static_credentials(env).ok_or_else(|| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    "AWS credential_source=Environment requested, but AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are not set",
                )
            }),
            "EcsContainer" => self
                .try_ecs_credentials_with_env(ecs_endpoint.as_deref(), env)
                .await?
                .map(|r| r.creds)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        "AWS credential_source=EcsContainer requested, but ECS/EKS container credentials are unavailable",
                    )
                }),
            "Ec2InstanceMetadata" => self
                .try_imds_v2(imds_endpoint.as_deref())
                .await?
                .map(|r| r.creds)
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        "AWS credential_source=Ec2InstanceMetadata requested, but IMDSv2 credentials are unavailable",
                    )
                }),
            other => Err(Error::config(format!(
                "unsupported AWS profile `credential_source = {other}` (expected Environment, EcsContainer, or Ec2InstanceMetadata)"
            ))),
        }
    }

    async fn try_env_web_identity(&self, env: &dyn EnvLookup) -> Result<Option<ResolvedCreds>> {
        let Some(token_file) = env.get_non_empty("AWS_WEB_IDENTITY_TOKEN_FILE") else {
            return Ok(None);
        };
        let Some(role_arn) = env.get_non_empty("AWS_ROLE_ARN") else {
            return Ok(None);
        };
        let session_name = env
            .get_non_empty("AWS_ROLE_SESSION_NAME")
            .unwrap_or_else(|| "rship-s3-session".to_string());
        let region = env
            .get_non_empty("AWS_REGION")
            .or_else(|| env.get_non_empty("AWS_DEFAULT_REGION"));
        self.assume_role_with_web_identity(
            role_arn.trim(),
            token_file.trim(),
            &session_name,
            region.as_deref(),
            env,
        )
        .await
        .map(Some)
    }

    fn effective_sts_endpoint(&self, region: Option<&str>, env: &dyn EnvLookup) -> String {
        if let Some(ref ep) = self.sts_endpoint {
            return ep.trim_end_matches('/').to_string();
        }
        if let Some(ep) = env.get_non_empty("AWS_ENDPOINT_URL_STS") {
            return ep.trim().trim_end_matches('/').to_string();
        }
        if let Some(ep) = env.get_non_empty("AWS_ENDPOINT_URL") {
            return ep.trim().trim_end_matches('/').to_string();
        }
        match region.map(str::trim).filter(|r| !r.is_empty()) {
            Some(r) => format!("https://sts.{r}.amazonaws.com"),
            None => "https://sts.amazonaws.com".to_string(),
        }
    }

    async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        token_file: &str,
        session_name: &str,
        region: Option<&str>,
        env: &dyn EnvLookup,
    ) -> Result<ResolvedCreds> {
        let raw_token = tokio::fs::read_to_string(token_file).await.map_err(|e| {
            Error::io(
                format!("read AWS web identity token file `{token_file}`"),
                e,
            )
        })?;
        let token = raw_token.trim();
        if token.is_empty() {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!("AWS web identity token file `{token_file}` is empty"),
            ));
        }

        let sts_base = self.effective_sts_endpoint(region, env);
        let url = format!("{sts_base}/");
        let form = format!(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn={}&RoleSessionName={}&WebIdentityToken={}",
            aws_uri_encode(role_arn),
            aws_uri_encode(session_name),
            aws_uri_encode(token),
        );

        let req = self
            .transport
            .control_client()
            .post(&url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form)
            .timeout(STS_TIMEOUT);
        let resp = self
            .transport
            .send_control_request("STS AssumeRoleWithWebIdentity", req)
            .await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = self.transport.read_control_body(resp).await?;
        if !status.is_success() {
            return Err(classify_s3_error(
                "STS AssumeRoleWithWebIdentity",
                status,
                &headers,
                &body,
                false,
            ));
        }
        let (ak, sk, st, exp) = parse_sts_credentials_xml(&body)?;
        Ok(ResolvedCreds {
            creds: S3Credentials::new(ak, sk).with_session_token(st),
            expires_at_unix_secs: exp,
        })
    }

    async fn assume_role_with_sts(
        &self,
        role_arn: &str,
        session_name: &str,
        external_id: Option<&str>,
        source_creds: &S3Credentials,
        region: Option<&str>,
        env: &dyn EnvLookup,
    ) -> Result<ResolvedCreds> {
        let sts_base = self.effective_sts_endpoint(region, env);
        let parsed = Url::parse(&sts_base)
            .map_err(|e| Error::config(format!("invalid STS endpoint `{sts_base}`: {e}")))?;
        let scheme = parsed.scheme();
        let base_host = parsed
            .host_str()
            .ok_or_else(|| Error::config(format!("STS endpoint `{sts_base}` missing host")))?;
        let port_suffix = match (scheme, parsed.port()) {
            ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
            (_, Some(p)) => format!(":{p}"),
        };
        let host_header = format!("{base_host}{port_suffix}");
        let ep_path = parsed.path().trim_end_matches('/');
        let canonical_uri = if ep_path.is_empty() {
            "/".to_string()
        } else {
            ep_path.to_string()
        };
        let url = format!("{scheme}://{host_header}{canonical_uri}");

        let mut form = format!(
            "Action=AssumeRole&Version=2011-06-15&RoleArn={}&RoleSessionName={}",
            aws_uri_encode(role_arn),
            aws_uri_encode(session_name),
        );
        if let Some(ext) = external_id {
            form.push_str("&ExternalId=");
            form.push_str(&aws_uri_encode(ext));
        }

        let signing_region = region
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .unwrap_or("us-east-1");
        let payload_sha = sha256_hex(form.as_bytes());
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        sign_v4_service_request(
            &Method::POST,
            &canonical_uri,
            &[],
            &host_header,
            &mut headers,
            &payload_sha,
            source_creds,
            signing_region,
            "sts",
            self.clock.now_unix_secs(),
        )?;

        let req = self
            .transport
            .control_client()
            .post(&url)
            .headers(headers)
            .body(form)
            .timeout(STS_TIMEOUT);
        let resp = self
            .transport
            .send_control_request("STS AssumeRole", req)
            .await?;
        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let body = self.transport.read_control_body(resp).await?;
        if !status.is_success() {
            return Err(classify_s3_error(
                "STS AssumeRole",
                status,
                &resp_headers,
                &body,
                false,
            ));
        }
        let (ak, sk, st, exp) = parse_sts_credentials_xml(&body)?;
        Ok(ResolvedCreds {
            creds: S3Credentials::new(ak, sk).with_session_token(st),
            expires_at_unix_secs: exp,
        })
    }

    async fn resolve_sso_credentials(
        &self,
        sso_session_name: Option<&str>,
        start_url: &str,
        sso_region: &str,
        account_id: &str,
        role_name: &str,
        env: &dyn EnvLookup,
    ) -> Result<ResolvedCreds> {
        let cache_dir = self
            .sso_cache_dir
            .clone()
            .or_else(|| default_aws_dir_with_env(env).map(|d| d.join("sso").join("cache")))
            .ok_or_else(|| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    "unable to locate ~/.aws/sso/cache directory (HOME/USERPROFILE not set)",
                )
            })?;

        let now = self.clock.now_unix_secs();
        let access_token =
            load_sso_access_token(&cache_dir, sso_session_name, start_url, now).await?;

        let sso_base = self
            .sso_endpoint
            .as_deref()
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("https://portal.sso.{sso_region}.amazonaws.com"));
        let url = format!(
            "{sso_base}/federation/credentials?account_id={}&role_name={}",
            aws_uri_encode(account_id),
            aws_uri_encode(role_name),
        );

        let req = self
            .transport
            .control_client()
            .get(&url)
            .header(
                "x-amz-sso_bearer_token",
                sensitive_header_value(&access_token, "AWS SSO bearer token")?,
            )
            .timeout(STS_TIMEOUT);
        let resp = self
            .transport
            .send_control_request("AWS SSO getRoleCredentials", req)
            .await?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = self.transport.read_control_body(resp).await?;
        if !status.is_success() {
            return Err(classify_s3_error(
                "AWS SSO getRoleCredentials",
                status,
                &headers,
                &body,
                false,
            ));
        }

        #[derive(Deserialize)]
        struct SsoRoleCredsWrapper {
            #[serde(rename = "roleCredentials")]
            role_credentials: SsoRoleCreds,
        }
        #[derive(Deserialize)]
        struct SsoRoleCreds {
            #[serde(rename = "accessKeyId")]
            access_key_id: String,
            #[serde(rename = "secretAccessKey")]
            secret_access_key: String,
            #[serde(rename = "sessionToken", default)]
            session_token: Option<String>,
            #[serde(default)]
            expiration: Option<i64>,
        }

        let parsed: SsoRoleCredsWrapper = serde_json::from_slice(&body)
            .map_err(|e| Error::protocol(format!("parse AWS SSO roleCredentials JSON: {e}")))?;
        let rc = parsed.role_credentials;
        if rc.access_key_id.is_empty() || rc.secret_access_key.is_empty() {
            return Err(Error::protocol(
                "AWS SSO roleCredentials missing accessKeyId or secretAccessKey",
            ));
        }
        let expires_at_unix_secs = rc.expiration.map(|ms| ms.div_euclid(1000));
        Ok(ResolvedCreds {
            creds: S3Credentials::new(rc.access_key_id, rc.secret_access_key)
                .with_session_token(rc.session_token),
            expires_at_unix_secs,
        })
    }

    async fn try_ecs_credentials_with_env(
        &self,
        base_override: Option<&str>,
        env: &dyn EnvLookup,
    ) -> Result<Option<ResolvedCreds>> {
        let url = if let Some(rel) = env.get_non_empty("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            let base = base_override
                .unwrap_or(DEFAULT_ECS_ENDPOINT)
                .trim_end_matches('/');
            if rel.starts_with('/') {
                format!("{base}{rel}")
            } else {
                format!("{base}/{rel}")
            }
        } else if let Some(full) = env.get_non_empty("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            validate_container_creds_full_uri(&full)?;
            full
        } else if let Some(base) = base_override
            && !base.trim().is_empty()
        {
            // Explicit test override endpoint with direct JSON response.
            base.to_string()
        } else {
            return Ok(None);
        };

        let mut req = self
            .transport
            .control_client()
            .get(&url)
            .timeout(METADATA_TIMEOUT);
        if let Some(tok) = env
            .get_var("AWS_CONTAINER_AUTHORIZATION_TOKEN")
            .filter(|t| !t.is_empty())
        {
            req = req.header(
                http::header::AUTHORIZATION,
                sensitive_header_value(&tok, "ECS Authorization")?,
            );
        } else if let Some(tok_file) = env.get_non_empty("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            let raw_tok = tokio::fs::read_to_string(tok_file.trim())
                .await
                .map_err(|e| {
                    Error::io(
                        format!(
                            "read EKS Pod Identity authorization token file `{}`",
                            tok_file.trim()
                        ),
                        e,
                    )
                })?;
            let tok = raw_tok.trim();
            if tok.is_empty() {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!(
                        "EKS Pod Identity authorization token file `{}` is empty",
                        tok_file.trim()
                    ),
                ));
            }
            req = req.header(
                http::header::AUTHORIZATION,
                sensitive_header_value(tok, "EKS Pod Identity Authorization")?,
            );
        }
        let Ok(resp) = self
            .transport
            .send_control_request("ECS credentials", req)
            .await
        else {
            return Ok(None);
        };
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body = self.transport.read_control_body(resp).await?;
        parse_metadata_creds_json(&body).map(Some)
    }

    async fn try_imds_v2(&self, base_override: Option<&str>) -> Result<Option<ResolvedCreds>> {
        let base = base_override
            .unwrap_or(DEFAULT_IMDS_ENDPOINT)
            .trim_end_matches('/');

        // Step 1: Acquire IMDSv2 session token via PUT /latest/api/token.
        let token_url = format!("{base}/latest/api/token");
        let tok_req = self
            .transport
            .control_client()
            .put(&token_url)
            .header("x-aws-ec2-metadata-token-ttl-seconds", "21600")
            .timeout(METADATA_TIMEOUT);
        let Ok(tok_resp) = self
            .transport
            .send_control_request("IMDSv2 token", tok_req)
            .await
        else {
            return Ok(None);
        };
        if !tok_resp.status().is_success() {
            return Ok(None);
        }
        let token_bytes = self.transport.read_control_body(tok_resp).await?;
        let token = String::from_utf8_lossy(&token_bytes).trim().to_string();
        if token.is_empty() {
            return Ok(None);
        }

        let token_header = sensitive_header_value(&token, "IMDSv2 metadata token")?;

        // Step 2: Discover attached IAM instance profile role name.
        let roles_url = format!("{base}/latest/meta-data/iam/security-credentials/");
        let roles_req = self
            .transport
            .control_client()
            .get(&roles_url)
            .header("x-aws-ec2-metadata-token", token_header.clone())
            .timeout(METADATA_TIMEOUT);
        let Ok(roles_resp) = self
            .transport
            .send_control_request("IMDSv2 role", roles_req)
            .await
        else {
            return Ok(None);
        };
        if !roles_resp.status().is_success() {
            return Ok(None);
        }
        let roles_bytes = self.transport.read_control_body(roles_resp).await?;
        let role_name = String::from_utf8_lossy(&roles_bytes)
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(str::to_string);
        let Some(role_name) = role_name else {
            return Ok(None);
        };

        // Step 3: Fetch temporary STS credentials for that role.
        let creds_url = format!("{base}/latest/meta-data/iam/security-credentials/{role_name}");
        let creds_req = self
            .transport
            .control_client()
            .get(&creds_url)
            .header("x-aws-ec2-metadata-token", token_header)
            .timeout(METADATA_TIMEOUT);
        let Ok(creds_resp) = self
            .transport
            .send_control_request("IMDSv2 credentials", creds_req)
            .await
        else {
            return Ok(None);
        };
        if !creds_resp.status().is_success() {
            return Ok(None);
        }
        let body = self.transport.read_control_body(creds_resp).await?;
        parse_metadata_creds_json(&body).map(Some)
    }
}

fn is_fresh(cached: &ResolvedCreds, now_unix_secs: i64) -> bool {
    match cached.expires_at_unix_secs {
        Some(exp) => now_unix_secs.saturating_add(REFRESH_MARGIN_SECS) < exp,
        None => true,
    }
}

#[derive(Debug, Deserialize)]
struct MetadataCredsPayload {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "Token", default)]
    token: Option<String>,
    #[serde(rename = "Expiration", default)]
    expiration: Option<String>,
}

fn parse_metadata_creds_json(body: &[u8]) -> Result<ResolvedCreds> {
    let payload: MetadataCredsPayload = serde_json::from_slice(body)
        .map_err(|e| Error::protocol(format!("parse AWS metadata credentials JSON: {e}")))?;
    if payload.access_key_id.is_empty() || payload.secret_access_key.is_empty() {
        return Err(Error::protocol(
            "AWS metadata credentials JSON missing AccessKeyId or SecretAccessKey",
        ));
    }
    let expires_at_unix_secs = payload
        .expiration
        .as_deref()
        .and_then(rship_core::time::parse_rfc3339_to_secs);
    Ok(ResolvedCreds {
        creds: S3Credentials::new(payload.access_key_id, payload.secret_access_key)
            .with_session_token(payload.token),
        expires_at_unix_secs,
    })
}

fn env_static_credentials(env: &dyn EnvLookup) -> Option<S3Credentials> {
    let ak = env.get_var("AWS_ACCESS_KEY_ID").filter(|s| !s.is_empty())?;
    let sk = env
        .get_var("AWS_SECRET_ACCESS_KEY")
        .filter(|s| !s.is_empty())?;
    let st = env.get_var("AWS_SESSION_TOKEN").filter(|s| !s.is_empty());
    Some(S3Credentials::new(ak, sk).with_session_token(st))
}

fn validate_container_creds_full_uri(raw: &str) -> Result<()> {
    let parsed = Url::parse(raw).map_err(|e| {
        Error::config(format!(
            "invalid AWS_CONTAINER_CREDENTIALS_FULL_URI `{raw}`: {e}"
        ))
    })?;
    let scheme = parsed.scheme();
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http") {
        let allowed = match parsed.host() {
            Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(ip)) => {
                ip.is_loopback()
                    || ip == std::net::Ipv4Addr::new(169, 254, 170, 2)
                    || ip == std::net::Ipv4Addr::new(169, 254, 170, 23)
            }
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        };
        if allowed {
            return Ok(());
        }
    }
    Err(Error::config(format!(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI `{raw}` must use https:// or a loopback / ECS link-local http:// endpoint"
    )))
}

#[derive(Default)]
struct AwsIniFiles {
    profiles: HashMap<String, HashMap<String, String>>,
    sso_sessions: HashMap<String, HashMap<String, String>>,
}

async fn load_aws_ini_files(
    credentials_override: Option<&Path>,
    config_override: Option<&Path>,
    env: &dyn EnvLookup,
) -> Result<AwsIniFiles> {
    let mut out = AwsIniFiles::default();

    let cfg_path = config_override
        .map(Path::to_path_buf)
        .or_else(|| env.get_non_empty("AWS_CONFIG_FILE").map(PathBuf::from))
        .or_else(|| default_aws_dir_with_env(env).map(|d| d.join("config")));

    if let Some(ref p) = cfg_path
        && let Some(text) = read_optional_ini_file(p).await?
    {
        parse_aws_ini_into(&text, true, &mut out);
    }

    // `~/.aws/credentials` overrides overlapping keys from `~/.aws/config` (standard AWS SDK rule).
    let cred_path = credentials_override
        .map(Path::to_path_buf)
        .or_else(|| {
            env.get_non_empty("AWS_SHARED_CREDENTIALS_FILE")
                .map(PathBuf::from)
        })
        .or_else(|| default_aws_dir_with_env(env).map(|d| d.join("credentials")));

    if let Some(ref p) = cred_path
        && let Some(text) = read_optional_ini_file(p).await?
    {
        parse_aws_ini_into(&text, false, &mut out);
    }

    Ok(out)
}

async fn read_optional_ini_file(path: &Path) -> Result<Option<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(
            format!("read AWS credentials file `{}`", path.display()),
            e,
        )),
    }
}

fn parse_aws_ini_into(text: &str, is_config_file: bool, out: &mut AwsIniFiles) {
    enum SectionTarget {
        Profile(String),
        SsoSession(String),
    }

    let mut current: Option<SectionTarget> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[')
            && let Some(name) = rest.strip_suffix(']')
        {
            let trimmed = name.trim();
            current = if is_config_file && let Some(sess) = trimmed.strip_prefix("sso-session ") {
                Some(SectionTarget::SsoSession(sess.trim().to_string()))
            } else if is_config_file {
                let key = trimmed
                    .strip_prefix("profile ")
                    .map(str::trim)
                    .unwrap_or(trimmed);
                Some(SectionTarget::Profile(key.to_string()))
            } else {
                Some(SectionTarget::Profile(trimmed.to_string()))
            };
            continue;
        }
        if let Some(ref target) = current
            && let Some((k, v)) = line.split_once('=')
        {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match target {
                SectionTarget::Profile(p) => {
                    out.profiles.entry(p.clone()).or_default().insert(key, val);
                }
                SectionTarget::SsoSession(s) => {
                    out.sso_sessions
                        .entry(s.clone())
                        .or_default()
                        .insert(key, val);
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct SsoCacheEntry {
    #[serde(rename = "accessToken", default)]
    access_token: Option<String>,
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<String>,
    #[serde(rename = "startUrl", default)]
    start_url: Option<String>,
}

async fn load_sso_access_token(
    cache_dir: &Path,
    sso_session_name: Option<&str>,
    start_url: &str,
    now_unix_secs: i64,
) -> Result<String> {
    let mut candidate_files: Vec<PathBuf> = Vec::new();
    if let Some(sess) = sso_session_name {
        candidate_files.push(cache_dir.join(format!("{}.json", sha1_hex(sess.as_bytes()))));
    }
    candidate_files.push(cache_dir.join(format!("{}.json", sha1_hex(start_url.as_bytes()))));

    for path in &candidate_files {
        if let Ok(raw) = tokio::fs::read_to_string(path).await
            && let Some(tok) = extract_valid_sso_token(&raw, None, now_unix_secs)
        {
            return Ok(tok);
        }
    }

    // Fallback: scan `*.json` in `sso/cache` matching `startUrl`.
    if let Ok(mut rd) = tokio::fs::read_dir(cache_dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json")
                && let Ok(raw) = tokio::fs::read_to_string(&p).await
                && let Some(tok) = extract_valid_sso_token(&raw, Some(start_url), now_unix_secs)
            {
                return Ok(tok);
            }
        }
    }

    Err(Error::new(
        ErrorKind::PermissionDenied,
        RetryClass::Permanent,
        format!(
            "AWS SSO access token missing or expired in `{}` (run `aws sso login`)",
            cache_dir.display()
        ),
    ))
}

fn extract_valid_sso_token(
    raw_json: &str,
    required_start_url: Option<&str>,
    now_unix_secs: i64,
) -> Option<String> {
    let entry: SsoCacheEntry = serde_json::from_str(raw_json).ok()?;
    if let Some(req_url) = required_start_url
        && entry.start_url.as_deref() != Some(req_url)
    {
        return None;
    }
    let token = entry.access_token.filter(|t| !t.trim().is_empty())?;
    if let Some(exp_str) = entry.expires_at.as_deref() {
        let exp = rship_core::time::parse_rfc3339_to_secs(exp_str)?;
        if exp <= now_unix_secs {
            return None;
        }
    }
    Some(token)
}

/// Pure-Rust RFC 3174 / FIPS 180-4 SHA-1 hex digest (used exclusively for AWS SSO
/// cache filenames `~/.aws/sso/cache/<sha1>.json`, avoiding extra crate dependencies).
fn sha1_hex(data: &[u8]) -> String {
    let mut h0: u32 = 0x6745_2301;
    let mut h1: u32 = 0xEFCD_AB89;
    let mut h2: u32 = 0x98BA_DCFE;
    let mut h3: u32 = 0x1032_5476;
    let mut h4: u32 = 0xC3D2_E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity((data.len() + 9 + 63) & !63);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let (blocks, _) = msg.as_chunks::<64>();
    for block in blocks {
        let mut w = [0u32; 80];
        let (words, _) = block.as_chunks::<4>();
        for (i, chunk) in words.iter().enumerate() {
            w[i] = u32::from_be_bytes(*chunk);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
                _ => (b ^ c ^ d, 0xCA62_C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    format!("{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}")
}

/// Load credentials for `profile` from `~/.aws/credentials` (falling back to `~/.aws/config`).
pub async fn load_shared_aws_profile(
    profile: &str,
    credentials_override: Option<&Path>,
    config_override: Option<&Path>,
) -> Result<Option<S3Credentials>> {
    let cred_path = credentials_override
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("AWS_SHARED_CREDENTIALS_FILE")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| default_aws_dir().map(|d| d.join("credentials")));

    if let Some(ref p) = cred_path
        && let Some(c) = parse_aws_ini_credentials(p, profile, false).await?
    {
        return Ok(Some(c));
    }

    let cfg_path = config_override
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var_os("AWS_CONFIG_FILE")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        })
        .or_else(|| default_aws_dir().map(|d| d.join("config")));

    if let Some(ref p) = cfg_path
        && let Some(c) = parse_aws_ini_credentials(p, profile, true).await?
    {
        return Ok(Some(c));
    }

    Ok(None)
}

fn default_aws_dir() -> Option<PathBuf> {
    default_aws_dir_with_env(&StdEnv)
}

fn default_aws_dir_with_env(env: &dyn EnvLookup) -> Option<PathBuf> {
    env.get_non_empty("HOME")
        .or_else(|| env.get_non_empty("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".aws"))
}

async fn parse_aws_ini_credentials(
    path: &Path,
    profile: &str,
    is_config_file: bool,
) -> Result<Option<S3Credentials>> {
    let text = match tokio::fs::read_to_string(path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::io(
                format!("read AWS credentials file `{}`", path.display()),
                e,
            ));
        }
    };
    Ok(parse_aws_ini_text(&text, profile, is_config_file))
}

/// Pure INI parser for AWS `~/.aws/credentials` and `~/.aws/config` profile sections.
pub fn parse_aws_ini_text(
    text: &str,
    profile: &str,
    is_config_file: bool,
) -> Option<S3Credentials> {
    let mut files = AwsIniFiles::default();
    parse_aws_ini_into(text, is_config_file, &mut files);
    let map = files.profiles.get(profile)?;
    let ak = map.get("aws_access_key_id").filter(|s| !s.is_empty())?;
    let sk = map.get("aws_secret_access_key").filter(|s| !s.is_empty())?;
    let st = map
        .get("aws_session_token")
        .filter(|s| !s.is_empty())
        .cloned();
    Some(S3Credentials::new(ak.clone(), sk.clone()).with_session_token(st))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, put};
    use rship_core::clock::VirtualClock;
    use rship_transport::TransportConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn parses_aws_credentials_and_config_profiles() {
        let creds_ini = r#"
            # comment
            [default]
            aws_access_key_id = AKIA_DEFAULT
            aws_secret_access_key = SECRET_DEFAULT

            [prod]
            aws_access_key_id = AKIA_PROD
            aws_secret_access_key = SECRET_PROD
            aws_session_token = TOK_PROD
        "#;
        let def = parse_aws_ini_text(creds_ini, "default", false).unwrap();
        assert_eq!(def.access_key_id, "AKIA_DEFAULT");
        assert_eq!(def.secret_access_key, "SECRET_DEFAULT");
        assert_eq!(def.session_token, None);

        let prod = parse_aws_ini_text(creds_ini, "prod", false).unwrap();
        assert_eq!(prod.access_key_id, "AKIA_PROD");
        assert_eq!(prod.session_token.as_deref(), Some("TOK_PROD"));
        assert!(parse_aws_ini_text(creds_ini, "missing", false).is_none());

        let cfg_ini = r#"
            [profile staging]
            region = us-west-2
            aws_access_key_id = AKIA_STAGE
            aws_secret_access_key = SECRET_STAGE
        "#;
        let stage = parse_aws_ini_text(cfg_ini, "staging", true).unwrap();
        assert_eq!(stage.access_key_id, "AKIA_STAGE");
        assert_eq!(stage.secret_access_key, "SECRET_STAGE");
    }

    #[tokio::test]
    async fn imdsv2_provider_fetches_caches_and_refreshes_before_expiry() {
        #[derive(Clone)]
        struct ImdsMock {
            cred_calls: Arc<AtomicUsize>,
        }

        let mock = ImdsMock {
            cred_calls: Arc::new(AtomicUsize::new(0)),
        };

        let app = Router::new()
            .route(
                "/latest/api/token",
                put(|headers: HeaderMap| async move {
                    assert!(headers.contains_key("x-aws-ec2-metadata-token-ttl-seconds"));
                    (StatusCode::OK, "imds-v2-token-abc")
                }),
            )
            .route(
                "/latest/meta-data/iam/security-credentials/",
                get(|headers: HeaderMap| async move {
                    assert_eq!(
                        headers
                            .get("x-aws-ec2-metadata-token")
                            .and_then(|v| v.to_str().ok()),
                        Some("imds-v2-token-abc")
                    );
                    (StatusCode::OK, "rship-worker-role\n")
                }),
            )
            .route(
                "/latest/meta-data/iam/security-credentials/rship-worker-role",
                get(
                    |State(st): State<ImdsMock>, headers: HeaderMap| async move {
                        assert_eq!(
                            headers
                                .get("x-aws-ec2-metadata-token")
                                .and_then(|v| v.to_str().ok()),
                            Some("imds-v2-token-abc")
                        );
                        let n = st.cred_calls.fetch_add(1, Ordering::SeqCst) + 1;
                        // First call expires at 1_700_003_600 (1h after clock start 1_700_000_000).
                        let exp = if n == 1 {
                            "2023-11-14T23:13:20Z"
                        } else {
                            "2023-11-15T00:13:20Z"
                        };
                        let body = serde_json::json!({
                            "AccessKeyId": format!("ASIA_IMDS_{n}"),
                            "SecretAccessKey": format!("SECRET_{n}"),
                            "Token": format!("SESSION_{n}"),
                            "Expiration": exp,
                        });
                        (StatusCode::OK, axum::Json(body)).into_response()
                    },
                ),
            )
            .with_state(mock.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let tmp = tempfile::TempDir::new().unwrap();
        let missing = tmp.path().join("nonexistent");
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();

        // Explicit nonexistent profile MUST fail with PermissionDenied instead of falling
        // through to ambient env vars or EC2 IMDSv2 for a different AWS account.
        let explicit_missing = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("nonexistent-prod".into()),
                credentials_file: Some(missing.clone()),
                config_file: Some(missing.clone()),
                ecs_endpoint: None,
                imds_endpoint: Some(format!("http://{addr}")),
            },
            transport.clone(),
            clock.clone(),
        );
        let prof_err = explicit_missing.credentials().await.unwrap_err();
        assert_eq!(prof_err.kind, ErrorKind::PermissionDenied);
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 0);

        let provider = Arc::new(S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: None,
                credentials_file: Some(missing.clone()),
                config_file: Some(missing),
                ecs_endpoint: None,
                imds_endpoint: Some(format!("http://{addr}")),
            },
            transport,
            clock.clone(),
        ));

        // Only verify IMDSv2 path when ambient AWS env vars are not set in the runner environment.
        if S3Credentials::from_env().is_some() {
            return;
        }

        // 1. Concurrent callers must coalesce onto a single IMDSv2 fetch.
        let (c1, c2) = tokio::join!(provider.credentials(), provider.credentials());
        let c1 = c1.unwrap();
        let c2 = c2.unwrap();
        assert_eq!(c1.access_key_id, "ASIA_IMDS_1");
        assert_eq!(c2.access_key_id, "ASIA_IMDS_1");
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 1);

        // 2. Advance clock within the 5-minute pre-expiry margin -> automatic refresh!
        clock.advance(Duration::from_secs(3400));
        let c3 = provider.credentials().await.unwrap();
        assert_eq!(c3.access_key_id, "ASIA_IMDS_2");
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 2);

        // 3. `force_refresh` with stale key `ASIA_IMDS_1` returns already-refreshed `ASIA_IMDS_2`
        // without hitting IMDS again!
        let c4 = provider
            .force_refresh("ASIA_IMDS_1", Some("SESSION_1"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(c4.access_key_id, "ASIA_IMDS_2");
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 2);

        // 4. `force_refresh` with current key `ASIA_IMDS_2` triggers a real fresh fetch!
        let c5 = provider
            .force_refresh("ASIA_IMDS_2", Some("SESSION_2"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(c5.access_key_id, "ASIA_IMDS_3");
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 3);

        // 5. Immediate repeat `force_refresh` inside the 5s cooldown returns `Ok(None)` without
        // hammering IMDSv2 (prevents stampede on IAM `HEAD 403 AccessDenied`).
        let cooldown = provider
            .force_refresh("ASIA_IMDS_3", Some("SESSION_3"))
            .await
            .unwrap();
        assert!(cooldown.is_none());
        assert_eq!(mock.cred_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn sha1_hex_matches_rfc3174_vectors() {
        assert_eq!(sha1_hex(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[tokio::test]
    async fn eks_pod_identity_reads_and_rotates_token_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let tok_file = tmp.path().join("eks-token");
        std::fs::write(&tok_file, "eks-jwt-v1\n").unwrap();

        let seen_auth = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_c = seen_auth.clone();
        let app = Router::new().route(
            "/v1/credentials",
            get(move |headers: HeaderMap| {
                let seen = seen_c.clone();
                async move {
                    let auth = headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    seen.lock().unwrap().push(auth);
                    let body = serde_json::json!({
                        "AccessKeyId": "ASIA_EKS_1",
                        "SecretAccessKey": "SECRET_EKS_1",
                        "Token": "TOK_EKS_1",
                        "Expiration": "2023-11-15T00:00:00Z"
                    });
                    (StatusCode::OK, axum::Json(body))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let missing = tmp.path().join("missing");
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();
        let provider = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: None,
                credentials_file: Some(missing.clone()),
                config_file: Some(missing),
                ecs_endpoint: None,
                imds_endpoint: Some("http://127.0.0.1:1".into()),
            },
            transport,
            clock,
        );

        let mut env_map = HashMap::new();
        env_map.insert(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
            format!("http://{addr}/v1/credentials"),
        );
        env_map.insert(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE".into(),
            tok_file.to_string_lossy().into_owned(),
        );
        let env = MockEnv(env_map);

        let r1 = provider.resolve_chain_with_env(&env).await.unwrap();
        assert_eq!(r1.creds.access_key_id, "ASIA_EKS_1");

        // Rotate token file on disk and resolve again -> must read fresh token!
        std::fs::write(&tok_file, "eks-jwt-v2").unwrap();
        let r2 = provider.resolve_chain_with_env(&env).await.unwrap();
        assert_eq!(r2.creds.access_key_id, "ASIA_EKS_1");
        assert_eq!(
            *seen_auth.lock().unwrap(),
            vec!["eks-jwt-v1".to_string(), "eks-jwt-v2".to_string()]
        );
    }

    #[tokio::test]
    async fn irsa_web_identity_and_assume_role_with_sts_and_cycle_guard() {
        use axum::routing::post;

        let tmp = tempfile::TempDir::new().unwrap();
        let oidc_file = tmp.path().join("oidc-token");
        std::fs::write(&oidc_file, "oidc.jwt.payload\n").unwrap();

        let captured_sts = Arc::new(std::sync::Mutex::new(Vec::<(String, String, String)>::new()));
        let cap_c = captured_sts.clone();
        let app = Router::new().route(
            "/",
            post(move |headers: HeaderMap, body: String| {
                let cap = cap_c.clone();
                async move {
                    let auth = headers
                        .get(http::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    cap.lock().unwrap().push((
                        body.clone(),
                        auth.clone(),
                        headers
                            .get("x-amz-date")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string(),
                    ));
                    if body.contains("Action=AssumeRoleWithWebIdentity") {
                        assert!(body.contains("WebIdentityToken=oidc.jwt.payload"));
                        let xml = r#"<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>ASIA_IRSA</AccessKeyId><SecretAccessKey>SEC_IRSA</SecretAccessKey><SessionToken>TOK_IRSA</SessionToken><Expiration>2023-11-15T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"#;
                        (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
                    } else if body.contains("Action=AssumeRole") {
                        assert!(
                            auth.contains("/us-west-2/sts/aws4_request"),
                            "STS AssumeRole must sign with service=sts: {auth}"
                        );
                        assert!(body.contains("ExternalId=ext-123"));
                        let xml = r#"<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA_ASSUMED</AccessKeyId><SecretAccessKey>SEC_ASSUMED</SecretAccessKey><SessionToken>TOK_ASSUMED</SessionToken><Expiration>2023-11-15T01:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"#;
                        (StatusCode::OK, [("content-type", "application/xml")], xml).into_response()
                    } else {
                        (StatusCode::BAD_REQUEST, "unexpected action").into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let missing = tmp.path().join("missing");
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();

        // 1. Ambient IRSA via env vars.
        let irsa_provider = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: None,
                credentials_file: Some(missing.clone()),
                config_file: Some(missing.clone()),
                ecs_endpoint: None,
                imds_endpoint: Some("http://127.0.0.1:1".into()),
            },
            transport.clone(),
            clock.clone(),
        )
        .with_sts_endpoint(format!("http://{addr}"));
        let mut irsa_env = HashMap::new();
        irsa_env.insert("AWS_ROLE_ARN".into(), "arn:aws:iam::123:role/irsa".into());
        irsa_env.insert(
            "AWS_WEB_IDENTITY_TOKEN_FILE".into(),
            oidc_file.to_string_lossy().into_owned(),
        );
        irsa_env.insert("AWS_ROLE_SESSION_NAME".into(), "pod-session".into());
        let irsa_res = irsa_provider
            .resolve_chain_with_env(&MockEnv(irsa_env))
            .await
            .unwrap();
        assert_eq!(irsa_res.creds.access_key_id, "ASIA_IRSA");
        assert_eq!(irsa_res.creds.session_token.as_deref(), Some("TOK_IRSA"));

        // 2. Profile `role_arn` + `source_profile` + `external_id` + cycle/conflict checks.
        let creds_path = tmp.path().join("credentials");
        let cfg_path = tmp.path().join("config");
        std::fs::write(
            &creds_path,
            "[base]\naws_access_key_id = AKIA_BASE\naws_secret_access_key = SEC_BASE\n",
        )
        .unwrap();
        std::fs::write(
            &cfg_path,
            r#"
[profile assume-prod]
region = us-west-2
role_arn = arn:aws:iam::999:role/prod
source_profile = base
external_id = ext-123

[profile cycle-a]
role_arn = arn:aws:iam::999:role/a
source_profile = cycle-b

[profile cycle-b]
role_arn = arn:aws:iam::999:role/b
source_profile = cycle-a

[profile conflict]
role_arn = arn:aws:iam::999:role/c
source_profile = base
credential_source = Environment
"#,
        )
        .unwrap();

        let assume_provider = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("assume-prod".into()),
                credentials_file: Some(creds_path.clone()),
                config_file: Some(cfg_path.clone()),
                ecs_endpoint: None,
                imds_endpoint: None,
            },
            transport.clone(),
            clock.clone(),
        )
        .with_sts_endpoint(format!("http://{addr}"));
        let assumed = assume_provider
            .resolve_chain_with_env(&MockEnv(HashMap::new()))
            .await
            .unwrap();
        assert_eq!(assumed.creds.access_key_id, "ASIA_ASSUMED");

        let cycle_provider = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("cycle-a".into()),
                credentials_file: Some(creds_path.clone()),
                config_file: Some(cfg_path.clone()),
                ecs_endpoint: None,
                imds_endpoint: None,
            },
            transport.clone(),
            clock.clone(),
        )
        .with_sts_endpoint(format!("http://{addr}"));
        let cycle_err = cycle_provider
            .resolve_chain_with_env(&MockEnv(HashMap::new()))
            .await
            .unwrap_err();
        assert_eq!(cycle_err.kind, ErrorKind::Config);

        let conflict_provider = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("conflict".into()),
                credentials_file: Some(creds_path),
                config_file: Some(cfg_path),
                ecs_endpoint: None,
                imds_endpoint: None,
            },
            transport,
            clock,
        );
        let conflict_err = conflict_provider
            .resolve_chain_with_env(&MockEnv(HashMap::new()))
            .await
            .unwrap_err();
        assert_eq!(conflict_err.kind, ErrorKind::Config);
    }

    #[tokio::test]
    async fn sso_modern_session_and_legacy_profile_exchange_epoch_ms_expiration() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cache_dir = tmp.path().join("sso_cache");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let sess_hash = sha1_hex(b"corp-sso");
        std::fs::write(
            cache_dir.join(format!("{sess_hash}.json")),
            serde_json::json!({
                "startUrl": "https://corp.awsapps.com/start",
                "region": "us-east-1",
                "accessToken": "sso-bearer-modern",
                "expiresAt": "2023-11-15T01:00:00Z"
            })
            .to_string(),
        )
        .unwrap();

        let legacy_hash = sha1_hex(b"https://legacy.awsapps.com/start");
        std::fs::write(
            cache_dir.join(format!("{legacy_hash}.json")),
            serde_json::json!({
                "startUrl": "https://legacy.awsapps.com/start",
                "region": "eu-west-1",
                "accessToken": "sso-bearer-legacy",
                "expiresAt": "2023-11-15T01:00:00Z"
            })
            .to_string(),
        )
        .unwrap();

        let cfg_path = tmp.path().join("config");
        std::fs::write(
            &cfg_path,
            r#"
[sso-session corp-sso]
sso_start_url = https://corp.awsapps.com/start
sso_region = us-east-1

[profile modern-dev]
sso_session = corp-sso
sso_account_id = 111122223333
sso_role_name = PowerUser

[profile legacy-dev]
sso_start_url = https://legacy.awsapps.com/start
sso_region = eu-west-1
sso_account_id = 444455556666
sso_role_name = ReadOnly
"#,
        )
        .unwrap();

        let app = Router::new().route(
            "/federation/credentials",
            get(|headers: HeaderMap, uri: axum::http::Uri| async move {
                let tok = headers
                    .get("x-amz-sso_bearer_token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let q = uri.query().unwrap_or("");
                let ak = if tok == "sso-bearer-modern" && q.contains("account_id=111122223333") {
                    "ASIA_SSO_MODERN"
                } else if tok == "sso-bearer-legacy" && q.contains("account_id=444455556666") {
                    "ASIA_SSO_LEGACY"
                } else {
                    return (StatusCode::UNAUTHORIZED, "bad sso token").into_response();
                };
                // 1_700_003_600_000 ms == 1_700_003_600 secs
                let body = serde_json::json!({
                    "roleCredentials": {
                        "accessKeyId": ak,
                        "secretAccessKey": "SEC_SSO",
                        "sessionToken": "TOK_SSO",
                        "expiration": 1_700_003_600_000i64
                    }
                });
                (StatusCode::OK, axum::Json(body)).into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let missing = tmp.path().join("missing");
        let clock = Arc::new(VirtualClock::new(1_700_000_000));
        let transport = HttpTransport::new(TransportConfig::default()).unwrap();

        let modern = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("modern-dev".into()),
                credentials_file: Some(missing.clone()),
                config_file: Some(cfg_path.clone()),
                ecs_endpoint: None,
                imds_endpoint: None,
            },
            transport.clone(),
            clock.clone(),
        )
        .with_sso_cache_dir(&cache_dir)
        .with_sso_endpoint(format!("http://{addr}"));
        let res_modern = modern.credentials().await.unwrap();
        assert_eq!(res_modern.access_key_id, "ASIA_SSO_MODERN");
        // Verify epoch-ms converted to 1_700_003_600 secs -> advancing 3400s enters 300s refresh margin!
        clock.advance(Duration::from_secs(3400));
        assert!(!is_fresh(
            modern.cache.lock().await.resolved.as_ref().unwrap(),
            clock.now_unix_secs()
        ));

        let legacy = S3CredentialProvider::new(
            S3CredentialSource::AwsChain {
                profile: Some("legacy-dev".into()),
                credentials_file: Some(missing),
                config_file: Some(cfg_path),
                ecs_endpoint: None,
                imds_endpoint: None,
            },
            transport,
            clock,
        )
        .with_sso_cache_dir(&cache_dir)
        .with_sso_endpoint(format!("http://{addr}"));
        let res_legacy = legacy.credentials().await.unwrap();
        assert_eq!(res_legacy.access_key_id, "ASIA_SSO_LEGACY");
    }
}
