//! Shared OAuth2 Desktop PKCE interactive credential prompts, loopback/manual callback
//! completion, static bearer token / Google Service Account wizards, and Google Drive BYO OAuth guide.

#![cfg_attr(not(feature = "all-backends"), allow(dead_code, unused_imports))]

use anyhow::{Context, Result};
use rship::secrets::{
    resolve_opt_secret, resolve_secret, resolve_stored_and_runtime_secret_with, store_secret,
};
use rship_transport::HttpTransport;
use rship_transport::oauth::{OAuthToken, PkceSession, TokenStore};
use std::future::Future;
use std::path::{Path, PathBuf};

use crate::errors::{cancelled_err, config_err};
use crate::prompt::{self, SecretOutcome, SelectItem};

use super::wizard::PromptWizard;
use super::{apply_secret_outcome, merge_flag_secret};

/// Prompt metadata for [`resolve_oauth_client_creds`], shared by all OAuth2 PKCE providers.
pub(super) struct OAuthClientPrompt<'a> {
    pub provider_label: &'a str,
    pub client_id_prompt: &'a str,
    pub client_id_hint: Option<&'a str>,
    pub missing_client_id_err: &'a str,
    pub client_secret_prompt: &'a str,
    pub client_secret_hint: Option<&'a str>,
    pub secret_required: bool,
}

pub(super) struct ResolvedOAuthClientCreds {
    pub client_id: String,
    pub stored_secret: Option<String>,
    pub runtime_secret: Option<String>,
    pub secret_changed: bool,
    pub did_prompt: bool,
}

/// Resolve OAuth2 `client_id` and `client_secret` across CLI flags, interactive wizard prompts,
/// and existing stored (or `keyring://`-backed) values with in-place keyring rotation.
#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_oauth_client_creds(
    arg_client_id: Option<String>,
    arg_client_secret: Option<String>,
    existing_client_id: Option<&str>,
    existing_client_secret: Option<&str>,
    full_wizard: bool,
    interactive: bool,
    spec: &OAuthClientPrompt<'_>,
) -> Result<ResolvedOAuthClientCreds> {
    let mut did_prompt = false;
    let mut secret_changed = false;

    let existing_cid = existing_client_id.filter(|s| !s.trim().is_empty());
    let existing_csec = existing_client_secret.filter(|s| !s.trim().is_empty());

    let client_id = if let Some(cid) = arg_client_id.filter(|s| !s.trim().is_empty()) {
        cid
    } else if full_wizard || (interactive && existing_cid.is_none()) {
        did_prompt = true;
        prompt::text_required(spec.client_id_prompt, existing_cid, spec.client_id_hint)?
    } else if let Some(prev) = existing_cid {
        prev.to_string()
    } else {
        return Err(config_err(spec.missing_client_id_err));
    };

    let (stored_secret, runtime_secret) = if arg_client_secret.is_some() {
        secret_changed = true;
        match resolve_stored_and_runtime_secret_with(
            arg_client_secret,
            existing_csec,
            resolve_secret,
            store_secret,
        )? {
            Some((s, r)) => (Some(s), Some(r)),
            None if spec.secret_required => {
                return Err(config_err("client_secret cannot be empty"));
            }
            None => (None, None),
        }
    } else if full_wizard || (spec.secret_required && interactive && existing_csec.is_none()) {
        did_prompt = true;
        let has_existing_sec = existing_csec.is_some();
        let outcome = prompt::password(
            spec.client_secret_prompt,
            has_existing_sec,
            spec.secret_required,
            spec.client_secret_hint,
        )?;
        match outcome {
            SecretOutcome::KeepExisting => match existing_csec {
                Some(prev) => (Some(prev.to_string()), Some(resolve_secret(prev)?)),
                None if spec.secret_required => {
                    return Err(config_err(format!(
                        "client_secret is required for {} OAuth2 PKCE",
                        spec.provider_label
                    )));
                }
                None => (None, None),
            },
            SecretOutcome::Empty => {
                if spec.secret_required {
                    return Err(config_err(format!(
                        "client_secret is required for {} OAuth2 PKCE",
                        spec.provider_label
                    )));
                }
                secret_changed = has_existing_sec;
                let _ = apply_secret_outcome(SecretOutcome::Empty, existing_csec)?;
                (None, None)
            }
            SecretOutcome::Value(new_val) => {
                secret_changed = true;
                let stored = apply_secret_outcome(SecretOutcome::Value(new_val), existing_csec)?;
                let runtime = resolve_opt_secret(stored.as_deref())?;
                (stored, runtime)
            }
        }
    } else {
        match resolve_stored_and_runtime_secret_with(
            None,
            existing_csec,
            resolve_secret,
            store_secret,
        )? {
            Some((s, r)) => (Some(s), Some(r)),
            None if spec.secret_required => {
                return Err(config_err(format!(
                    "missing `--client-secret` for {} OAuth2 PKCE (run interactively in a terminal or pass `--client-secret`)",
                    spec.provider_label
                )));
            }
            None => (None, None),
        }
    };

    Ok(ResolvedOAuthClientCreds {
        client_id,
        stored_secret,
        runtime_secret,
        secret_changed,
        did_prompt,
    })
}

/// Shared static bearer token prompt/flag resolution (`StaticBearerAuth` providers: GCS, OneDrive, Dropbox).
pub(super) fn resolve_static_bearer_token(
    wiz: &mut PromptWizard<'_, '_>,
    flag_token: Option<String>,
    existing_token: Option<&str>,
    prompt_label: &str,
) -> Result<Option<String>> {
    if flag_token.is_some() {
        merge_flag_secret(flag_token, existing_token)
    } else if wiz.full_wizard {
        wiz.prompt_secret(prompt_label, existing_token, true, None)
    } else {
        Ok(existing_token.map(str::to_string))
    }
}

/// Shared Google Service Account JSON file resolution & validation (`gdrive`, `gcs`).
#[cfg(any(feature = "backend-gdrive", feature = "backend-gcs"))]
pub(super) fn resolve_service_account_key(
    wiz: &mut PromptWizard<'_, '_>,
    flag_path: Option<PathBuf>,
    existing_path: Option<&PathBuf>,
    missing_err: &str,
) -> Result<(
    PathBuf,
    rship_backends::common::google_sa::ServiceAccountKey,
)> {
    use rship_backends::common::google_sa::ServiceAccountKey;

    if let Some(p) = flag_path {
        let expanded = prompt::expand_tilde_path(p);
        let key = ServiceAccountKey::from_file(&expanded)
            .with_context(|| format!("invalid service account file `{}`", expanded.display()))?;
        Ok((expanded, key))
    } else if wiz.full_wizard || (wiz.ctx.interactive && existing_path.is_none()) {
        wiz.did_prompt = true;
        let def_sa = existing_path.map(|p| p.display().to_string());
        loop {
            let raw = prompt::text_required(
                "Path to Service Account JSON key file",
                def_sa.as_deref(),
                Some("Download from GCP Console → IAM & Admin → Service Accounts → Keys"),
            )?;
            let expanded = prompt::expand_tilde(&raw);
            match ServiceAccountKey::from_file(&expanded) {
                Ok(key) => return Ok((expanded, key)),
                Err(e) => prompt::validation_err(&format!(
                    "invalid service account file `{}`: {e}",
                    expanded.display()
                )),
            }
        }
    } else if let Some(prev) = existing_path {
        let key = ServiceAccountKey::from_file(prev)
            .with_context(|| format!("invalid service account file `{}`", prev.display()))?;
        Ok((prev.clone(), key))
    } else {
        Err(config_err(missing_err))
    }
}

/// Validate that a Google Service Account key parses cleanly for RS256 JWT signing (`gdrive`, `gcs`).
#[cfg(any(feature = "backend-gdrive", feature = "backend-gcs"))]
pub(super) fn validate_service_account_key(
    key: rship_backends::common::google_sa::ServiceAccountKey,
    scope: String,
    impersonate: Option<String>,
    token_url: Option<String>,
    transport: HttpTransport,
) -> Result<()> {
    let _ = rship_backends::common::google_sa::ServiceAccountAuthProvider::new(
        key,
        scope,
        impersonate,
        token_url,
        transport,
        rship_core::clock::SystemClock::shared(),
    )
    .context("failed to load service account RSA private key")?;
    Ok(())
}

/// Options for [`run_oauth_pkce_wizard`].
pub(super) struct OAuthPkceRunOpts<'a> {
    pub display_name: &'a str,
    pub confirm_label: &'a str,
    pub creds_changed: bool,
    pub explicit_oauth: bool,
    pub no_browser: bool,
    pub manual: bool,
}

/// Shared OAuth2 PKCE re-auth prompt, browser/manual flow execution, and token persistence.
pub(super) async fn run_oauth_pkce_wizard<S, F, Fut>(
    opts: OAuthPkceRunOpts<'_>,
    wiz: &mut PromptWizard<'_, '_>,
    store: &S,
    start_session: F,
) -> Result<bool>
where
    S: TokenStore,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<PkceSession>>,
{
    let has_saved_token = store.load()?.is_some();
    let need_browser_login = if !has_saved_token || opts.creds_changed || opts.explicit_oauth {
        true
    } else if wiz.full_wizard {
        prompt::confirm(
            &format!(
                "Re-authorize {} OAuth2 token in browser?",
                opts.confirm_label
            ),
            false,
        )?
    } else {
        false
    };

    if need_browser_login {
        let session = start_session().await?;
        let transport = wiz.ctx.transport()?.clone();
        let tok = complete_pkce_session(
            opts.display_name,
            &wiz.remote,
            session,
            &transport,
            wiz.ctx.interactive,
            opts.no_browser,
            opts.manual,
        )
        .await?;
        store.save(&tok)?;
        wiz.did_prompt = wiz.did_prompt || wiz.ctx.interactive;
    }

    Ok(need_browser_login)
}

pub(super) fn print_oauth_save_summary(
    provider_label: &str,
    remote: &str,
    reauthorized: bool,
    token_path: &Path,
    config_path: &Path,
) {
    if reauthorized {
        println!(
            "authorized {provider_label} remote `{remote}`! Token saved to {}",
            token_path.display()
        );
    } else {
        println!(
            "updated {provider_label} remote `{remote}` in {}",
            config_path.display()
        );
    }
}

/// Resolve OAuth loopback port preferences from an optional `--callback-port` CLI flag.
pub(super) fn resolve_oauth_port(explicit_port: Option<u16>) -> (Option<u16>, bool) {
    match explicit_port {
        Some(0) => (None, false),
        Some(p) => (Some(p), true),
        None => (
            Some(rship_transport::oauth::DEFAULT_OAUTH_CALLBACK_PORT),
            false,
        ),
    }
}

/// Complete an OAuth2 Desktop PKCE session with automatic browser launch, SSH detection,
/// manual redirect-URL paste fallback, and clean Ctrl+C cancellation.
pub(super) async fn complete_pkce_session(
    provider_label: &str,
    remote: &str,
    session: PkceSession,
    transport: &HttpTransport,
    interactive: bool,
    no_browser: bool,
    manual: bool,
) -> Result<OAuthToken> {
    use rship_core::clock::SystemClock;

    if !interactive {
        if manual {
            return Err(config_err(
                "`--manual` OAuth2 callback paste requires an interactive terminal (run in a TTY, or use `rship auth export` / `rship auth import` on headless servers)",
            ));
        }
        return Err(config_err(format!(
            "OAuth2 PKCE browser login for {provider_label} `{remote}` requires an interactive terminal (use a Service Account, `--access-token`, or `rship auth export`/`import` in non-interactive scripts)"
        )));
    }

    let use_manual = if manual {
        true
    } else if prompt::is_ssh_session() {
        let items = [
            SelectItem::new("Paste redirect URL manually").with_desc(
                "Recommended over SSH — open link on any device, then paste the redirected URL",
            ),
            SelectItem::new(format!(
                "Automatic loopback on 127.0.0.1:{}",
                session.port()
            ))
            .with_desc(format!(
                "Requires browser on this host or `ssh -L {}:127.0.0.1:{}`",
                session.port(),
                session.port()
            )),
        ];
        prompt::select("OAuth2 callback method (SSH session detected)", &items, 0)? == 0
    } else {
        false
    };

    if use_manual {
        eprintln!();
        prompt::note(&format!(
            "1. Open this URL in any browser to authorize {provider_label} `{remote}`:"
        ));
        eprintln!("\n  {}\n", session.auth_url);
        prompt::note(&format!(
            "2. After approving access, your browser will redirect to `{}` (the page may fail to load — that is expected).",
            session.redirect_uri
        ));
        prompt::note("3. Copy the full URL from your browser's address bar and paste it below.");
        eprintln!();

        loop {
            let pasted = prompt::text_required("Redirected callback URL", None, None)?;
            match session.parse_callback_url(&pasted) {
                Ok(code) => {
                    prompt::note("Exchanging authorization code for OAuth2 tokens...");
                    return Ok(session
                        .exchange_code(&code, transport, &SystemClock::shared())
                        .await?);
                }
                Err(e) => {
                    prompt::validation_err(&e.to_string());
                }
            }
        }
    }

    let auto_open = !no_browser
        && !std::env::var("RSHIP_FORCE_INTERACTIVE")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true"))
            .unwrap_or(false);

    eprintln!();
    if auto_open && prompt::open_browser(&session.auth_url) {
        prompt::ok(&format!(
            "Opened your browser to authorize {provider_label} `{remote}`"
        ));
        prompt::note("If the browser did not open, copy this URL manually:");
    } else {
        prompt::note(&format!(
            "Open this URL in your browser to authorize {provider_label} `{remote}`:"
        ));
    }
    eprintln!("\n  {}\n", session.auth_url);
    prompt::note(&format!(
        "Waiting for OAuth2 loopback callback on {} (Ctrl+C to cancel; pass `--manual` for headless/SSH)...",
        session.redirect_uri
    ));

    let clock = SystemClock::shared();
    tokio::select! {
        res = session.wait_and_exchange(transport, &clock) => Ok(res?),
        _ = tokio::signal::ctrl_c() => Err(cancelled_err("OAuth2 authorization cancelled by user")),
    }
}

pub fn print_gdrive_oauth_guide(remote: &str) {
    println!(
        r#"=== Google Cloud OAuth 2.0 Client ID Setup Guide for `rship` ===

Why Bring Your Own Client ID (BYO)?
  - Google classifies `drive` / `drive.readonly` as Restricted Scopes (public shared IDs
    require annual CASA Tier 2 audits). Your own GCP project needs ZERO audit!
  - Full step-by-step & public verification checklist: `docs/GOOGLE_OAUTH_SETUP.md`
  - Ready-to-host Privacy Policy template:             `docs/PRIVACY_POLICY.md`

5-Minute Setup Steps:
  1. Open https://console.cloud.google.com/ -> Create/select a project.
  2. APIs & Services -> Library -> search "Google Drive API" -> Enable.
  3. Google Auth Platform -> Overview -> Get Started:
       - Audience: "Internal" (Workspace, no expiry) or "External" (personal Gmail).
       - Data Access -> Add Scope:
           * Full access: `https://www.googleapis.com/auth/drive`         (--scope drive)
           * App-only:    `https://www.googleapis.com/auth/drive.file`    (--scope drive.file, Non-Sensitive!)
           * Read-only:   `https://www.googleapis.com/auth/drive.readonly`(--scope drive.readonly)
       - Audience -> Add your email under "Test users" (or click "Publish app" so
         refresh tokens don't expire every 7 days!).
  4. Clients -> Create Client -> Application type: **Desktop app**
     (Desktop app automatically enables `http://127.0.0.1:<port>/callback` PKCE loopback!).
  5. Authorize `rship`:
       rship auth gdrive {remote}
     (or pass flags non-interactively: `--client-id <ID> --client-secret <SECRET>`)
  6. Optional: store secrets in your OS Keyring & verify connectivity:
       rship auth keyring-migrate
       rship config test {remote}
       rship about {remote}:
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{AuthContext, test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn resolve_oauth_port_handles_ephemeral_explicit_and_default() {
        assert_eq!(resolve_oauth_port(Some(0)), (None, false));
        assert_eq!(resolve_oauth_port(Some(12345)), (Some(12345), true));
        assert_eq!(
            resolve_oauth_port(None),
            (
                Some(rship_transport::oauth::DEFAULT_OAUTH_CALLBACK_PORT),
                false
            )
        );
    }

    #[test]
    fn resolve_static_bearer_token_preserves_or_updates_non_interactively() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);
        let mut wiz = PromptWizard::begin(
            Some("od-test".to_string()),
            "onedrive",
            "onedrive",
            true,
            &mut ctx,
        )
        .unwrap();

        assert_eq!(
            resolve_static_bearer_token(&mut wiz, None, Some("existing-tok"), "Token").unwrap(),
            Some("existing-tok".to_string())
        );
        assert_eq!(
            resolve_static_bearer_token(
                &mut wiz,
                Some("new-tok".to_string()),
                Some("existing-tok"),
                "Token"
            )
            .unwrap(),
            Some("new-tok".to_string())
        );
    }
}
