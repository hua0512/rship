//! Remote configuration management, interactive config wizard, diagnostics, removal,
//! and OS Keyring migration operations.

use anyhow::Result;
use futures::StreamExt;
use rship_core::progress::format_human_bytes;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use crate::errors::config_err;
use crate::ops::{CliRuntime, TransportOverrides};
use crate::prompt::{self, SelectItem};
use crate::providers::{
    AuthContext, cleanup_remote_secrets, import_rclone_all, migrate_config_secrets,
    registered_providers, run_provider_wizard,
};
use crate::ui::Style;
use rship::config::{
    AppConfig, AppPaths, RemoteConfig, default_rclone_conf_path, redact_config, save_config,
};
use rship::secrets::is_keyring_ref;

/// Outcome of the post-save interactive keyring & connectivity check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostSaveAction {
    Done,
    RetryEdit,
}

fn str_is_inline_secret(s: &str) -> bool {
    !s.trim().is_empty() && !is_keyring_ref(s)
}

fn opt_is_inline_secret(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(str_is_inline_secret)
}

fn opt_is_keyring_secret(v: &Option<String>) -> bool {
    v.as_deref().is_some_and(is_keyring_ref)
}

/// Returns the number of inline (plaintext, non-keyring) secret fields on `rcfg`.
pub fn count_remote_inline_secrets(rcfg: &RemoteConfig) -> usize {
    let mut count = 0usize;
    rcfg.visit_secrets(|_, field| {
        if opt_is_inline_secret(field) {
            count += 1;
        }
    });
    if let RemoteConfig::Webdav(w) = rcfg {
        count += w
            .headers
            .iter()
            .filter(|(_, val)| str_is_inline_secret(val))
            .count();
    }
    count
}

/// Returns total count of inline plaintext secret fields across all configured remotes.
pub fn count_config_inline_secrets(cfg: &AppConfig) -> usize {
    cfg.remotes.values().map(count_remote_inline_secrets).sum()
}

fn secret_storage_badge(rcfg: &RemoteConfig) -> &'static str {
    let fallback = match rcfg {
        RemoteConfig::Local(_) => return "local",
        RemoteConfig::Gdrive(g) => {
            if g.service_account_file.is_some() {
                "service-account"
            } else {
                "oauth/none"
            }
        }
        RemoteConfig::S3(s) => {
            if s.env_auth == Some(true) {
                "env"
            } else {
                "none"
            }
        }
        RemoteConfig::Onedrive(_) | RemoteConfig::Dropbox(_) => "oauth/none",
        RemoteConfig::Webdav(_) | RemoteConfig::Crypt(_) => "none",
        RemoteConfig::Sftp(s) => {
            if s.key_file.is_some() {
                "ssh-key"
            } else {
                "none"
            }
        }
        RemoteConfig::Gcs(g) => {
            if g.anonymous == Some(true) {
                "anonymous"
            } else if g.service_account_file.is_some() {
                "service-account"
            } else {
                "oauth/none"
            }
        }
        RemoteConfig::Azureblob(a) if a.anonymous == Some(true) => "anonymous",
        _ => "none",
    };
    let mut has_inline = false;
    let mut has_keyring = false;
    rcfg.visit_secrets(|_, field| {
        if opt_is_inline_secret(field) {
            has_inline = true;
        }
        if opt_is_keyring_secret(field) {
            has_keyring = true;
        }
    });
    if let RemoteConfig::Webdav(w) = rcfg {
        for (_, val) in &w.headers {
            if str_is_inline_secret(val) {
                has_inline = true;
            }
            if is_keyring_ref(val) {
                has_keyring = true;
            }
        }
    }
    match (has_inline, has_keyring) {
        (true, true) => "mixed",
        (true, false) => "inline",
        (false, true) => "keyring",
        (false, false) => fallback,
    }
}

/// Concise human-readable description of a configured remote (never leaks secrets).
pub fn remote_summary(rcfg: &RemoteConfig) -> String {
    match rcfg {
        RemoteConfig::Local(l) => match l
            .encoding
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(enc) => format!("root={} · encoding={enc}", l.root.display()),
            None => format!("root={}", l.root.display()),
        },
        RemoteConfig::Gdrive(g) => {
            let mode = if g.service_account_file.is_some() {
                "Service Account"
            } else if g.access_token.is_some() {
                "Static token"
            } else {
                "OAuth2 PKCE"
            };
            let mut parts = vec![mode.to_string()];
            if let Some(sd) = &g.shared_drive_id {
                parts.push(format!("shared_drive={sd}"));
            } else if let Some(rf) = &g.root_folder_id {
                parts.push(format!("root={rf}"));
            }
            parts.join(" · ")
        }
        RemoteConfig::S3(s) => {
            let mut parts = vec![s.provider.clone()];
            if let Some(b) = &s.bucket {
                parts.push(format!("bucket={b}"));
            }
            if let Some(r) = &s.region {
                parts.push(r.clone());
            }
            if let Some(ep) = &s.endpoint {
                parts.push(ep.clone());
            }
            parts.join(" · ")
        }
        RemoteConfig::Onedrive(o) => {
            let mode = if o.access_token.is_some() {
                "Static token"
            } else {
                "OAuth2 PKCE"
            };
            match &o.drive_id {
                Some(id) => format!("{mode} · drive={id}"),
                None => mode.to_string(),
            }
        }
        RemoteConfig::Webdav(w) => {
            let vendor = w.vendor.as_deref().unwrap_or("generic");
            format!("{vendor} · {}", w.url)
        }
        RemoteConfig::Sftp(s) => {
            let port = s.port.unwrap_or(22);
            let mut base = format!("{}@{}:{port}", s.user, s.host);
            if let Some(rp) = &s.root_path {
                base.push_str(&format!(" ({rp})"));
            }
            base
        }
        RemoteConfig::Dropbox(d) => {
            let mode = if d.access_token.is_some() {
                "Static token"
            } else {
                "OAuth2 PKCE"
            };
            match &d.root_path {
                Some(p) => format!("{mode} · root={p}"),
                None => mode.to_string(),
            }
        }
        RemoteConfig::Gcs(g) => {
            let mode = if g.anonymous == Some(true) {
                "Anonymous"
            } else if g.service_account_file.is_some() {
                "Service Account"
            } else if g.access_token.is_some() {
                "Static token"
            } else {
                "OAuth2 PKCE"
            };
            let mut parts = vec![mode.to_string()];
            if let Some(b) = &g.bucket {
                parts.push(format!("bucket={b}"));
            }
            parts.join(" · ")
        }
        RemoteConfig::Azureblob(a) => {
            let mut parts = Vec::new();
            if let Some(acct) = &a.account {
                parts.push(format!("account={acct}"));
            } else if a.sas_url.is_some() {
                parts.push("SAS".to_string());
            } else if a.anonymous == Some(true) {
                parts.push("Anonymous".to_string());
            }
            if let Some(c) = &a.container {
                parts.push(format!("container={c}"));
            }
            if parts.is_empty() {
                "azureblob".to_string()
            } else {
                parts.join(" · ")
            }
        }
        RemoteConfig::Crypt(c) => {
            let mode = c.filename_encryption.as_deref().unwrap_or("standard");
            format!("→ {} (names={mode})", c.remote)
        }
        _ => rcfg.kind_str().to_string(),
    }
}

fn provider_description(kind: &str) -> &'static str {
    match kind {
        "s3" => "S3-compatible (AWS, Cloudflare R2, MinIO, OSS, B2, Wasabi, ...)",
        "gdrive" => "Google Drive (OAuth2 PKCE or Service Account)",
        "onedrive" => "Microsoft OneDrive & SharePoint (Graph OAuth2 PKCE)",
        "dropbox" => "Dropbox (OAuth2 PKCE with offline refresh)",
        "gcs" => "Google Cloud Storage (Service Account, OAuth2, or Anonymous)",
        "azureblob" => "Azure Blob Storage (SharedKey, SAS URL, or Azurite)",
        "webdav" => "WebDAV (Nextcloud, OwnCloud, Alist, Synology, InfiniCloud)",
        "sftp" => "SSH / SFTP (private key or password)",
        "crypt" => "Encrypted Vault (STREAM OAE2 wrapper over any remote)",
        "local" => "Local filesystem directory alias",
        _ => "Storage provider",
    }
}

/// Preferred display order when offering providers in interactive menus.
const PROVIDER_ORDER: &[&str] = &[
    "s3",
    "gdrive",
    "onedrive",
    "dropbox",
    "gcs",
    "azureblob",
    "webdav",
    "sftp",
    "crypt",
    "local",
];

fn ordered_enabled_providers() -> Vec<&'static str> {
    let enabled: Vec<&'static str> = registered_providers()
        .into_iter()
        .map(|p| p.kind())
        .collect();
    let mut out = Vec::with_capacity(enabled.len());
    for &p in PROVIDER_ORDER {
        if enabled.contains(&p) {
            out.push(p);
        }
    }
    for p in enabled {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

pub fn execute_config_list(json: bool, app_cfg: &AppConfig) -> Result<ExitCode> {
    if json {
        let rows: Vec<serde_json::Value> = app_cfg
            .remotes
            .iter()
            .map(|(name, cfg)| {
                serde_json::json!({
                    "name": name,
                    "kind": cfg.kind_str(),
                    "summary": remote_summary(cfg),
                    "secrets": secret_storage_badge(cfg),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(ExitCode::SUCCESS);
    }

    let st = Style::stdout();
    println!(
        "{} {}",
        st.bold("Configured remotes"),
        st.dim(&format!("({})", app_cfg.remotes.len()))
    );
    if app_cfg.remotes.is_empty() {
        println!(
            "  {}",
            st.dim(
                "No remotes configured yet. Run `rship config new` or `rship config import-rclone`."
            )
        );
        return Ok(ExitCode::SUCCESS);
    }

    let max_name = app_cfg
        .remotes
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(8)
        .clamp(8, 24);
    for (name, cfg) in &app_cfg.remotes {
        let badge = secret_storage_badge(cfg);
        let badge_styled = match badge {
            "keyring" | "ssh-key" | "env" | "service-account" => st.ok(&format!("[{badge}]")),
            "inline" | "mixed" => st.warn(&format!("[{badge}]")),
            _ => st.dim(&format!("[{badge}]")),
        };
        println!(
            "  {:<width$}  {:<10}  {}  {}",
            st.bold(name),
            st.accent(cfg.kind_str()),
            remote_summary(cfg),
            badge_styled,
            width = max_name,
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn execute_config_profiles(json: bool, app_cfg: &AppConfig) -> Result<ExitCode> {
    let redacted = redact_config(app_cfg);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "defaults": redacted.defaults,
                "profiles": redacted.profiles,
            }))?
        );
        return Ok(ExitCode::SUCCESS);
    }

    let st = Style::stdout();
    let defaults_summary = redacted.defaults.to_profile().summary();
    println!("{}  {}", st.bold("Defaults"), st.dim(&defaults_summary));
    println!(
        "\n{} {}",
        st.bold("Named profiles"),
        st.dim(&format!("({})", redacted.profiles.len()))
    );
    if redacted.profiles.is_empty() {
        println!(
            "  {}",
            st.dim("No profiles configured. Add `[profiles.<name>]` in config.toml and use `-p <name>`.")
        );
        return Ok(ExitCode::SUCCESS);
    }

    let max_name = redacted
        .profiles
        .keys()
        .map(String::len)
        .max()
        .unwrap_or(8)
        .clamp(8, 24);
    for (name, prof) in &redacted.profiles {
        println!(
            "  {:<width$}  {}",
            st.accent_bold(name),
            prof.summary(),
            width = max_name,
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// Interactive post-save close-out: test connectivity with instant edit-on-failure loop.
///
/// Note: OS Keyring migration is performed *in memory* prior to saving `config.toml` inside
/// `providers::persist_remote` so plaintext secrets are never written to disk first.
pub async fn post_save_interactive(
    remote_name: &str,
    ctx: &mut AuthContext<'_>,
) -> Result<PostSaveAction> {
    if prompt::confirm(&format!("Test connection to `{remote_name}` now?"), true)? {
        let mut rt = CliRuntime::new(
            ctx.paths,
            ctx.app_cfg,
            ctx.app_cfg.defaults.to_profile(),
            ctx.t_opts,
            false,
            ctx.runtime_options.clone(),
        )?;
        let test_res = execute_config_test(remote_name, false, &mut rt).await;
        let _ = rt.shutdown().await;
        if let Err(e) = test_res {
            crate::ui::print_error(&e);
            if prompt::confirm(
                &format!("Edit `{remote_name}` settings to fix the issue?"),
                true,
            )? {
                return Ok(PostSaveAction::RetryEdit);
            }
        }
    }

    Ok(PostSaveAction::Done)
}

pub async fn execute_config_new(
    provider_opt: Option<&str>,
    remote_opt: Option<&str>,
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
    t_opts: &TransportOverrides,
    interactive: bool,
) -> Result<ExitCode> {
    let enabled = ordered_enabled_providers();
    let chosen_kind = match provider_opt {
        Some(raw) => {
            let lower = raw.trim().to_ascii_lowercase();
            let canonical = match lower.as_str() {
                "drive" | "google-drive" | "google_drive" => "gdrive",
                "azure" | "azure-blob" => "azureblob",
                "ssh" => "sftp",
                "dav" => "webdav",
                "crypto" | "vault" => "crypt",
                other => other,
            };
            if !enabled.contains(&canonical) {
                return Err(config_err(format!(
                    "unknown or disabled provider `{raw}` (available: {})",
                    enabled.join(", ")
                )));
            }
            canonical.to_string()
        }
        None => {
            if !interactive {
                return Err(config_err(format!(
                    "missing provider (usage: `rship config new <PROVIDER> [REMOTE]`, available: {})",
                    enabled.join(", ")
                )));
            }
            prompt::section(
                "Add a new remote",
                Some("Select a cloud or storage provider to configure interactively"),
            );
            let items: Vec<SelectItem> = enabled
                .iter()
                .map(|k| SelectItem::new(*k).with_desc(provider_description(k)))
                .collect();
            let idx = prompt::select("Storage provider", &items, 0)?;
            enabled[idx].to_string()
        }
    };

    let mut ctx = AuthContext::new(paths, app_cfg, t_opts, interactive)
        .with_force_wizard(true)
        .with_confirm_overwrite(true);
    run_provider_wizard(&chosen_kind, remote_opt, &mut ctx).await
}

pub async fn execute_config_edit(
    remote_opt: Option<&str>,
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
    t_opts: &TransportOverrides,
    interactive: bool,
) -> Result<ExitCode> {
    if app_cfg.remotes.is_empty() {
        return Err(config_err(
            "no remotes configured yet (run `rship config new` or `rship config import-rclone`)",
        ));
    }
    let remote_name = match remote_opt {
        Some(r) => r.to_string(),
        None => {
            if !interactive {
                return Err(config_err(
                    "missing remote name (usage: `rship config edit <REMOTE>`)",
                ));
            }
            let names: Vec<String> = app_cfg.remotes.keys().cloned().collect();
            let items: Vec<SelectItem> = names
                .iter()
                .map(|n| {
                    let cfg = &app_cfg.remotes[n];
                    SelectItem::new(n).with_desc(format!(
                        "{} · {}",
                        cfg.kind_str(),
                        remote_summary(cfg)
                    ))
                })
                .collect();
            let idx = prompt::select("Select remote to edit", &items, 0)?;
            names[idx].clone()
        }
    };

    let Some(existing) = app_cfg.remotes.get(&remote_name) else {
        return Err(config_err(format!(
            "remote `{remote_name}` does not exist in {}",
            paths.config_file.display()
        )));
    };
    let kind = existing.kind_str().to_string();
    if !interactive {
        return Err(config_err(format!(
            "`rship config edit` requires an interactive terminal (use `rship auth {kind} {remote_name} ...` with explicit flags in scripts)"
        )));
    }

    let mut ctx = AuthContext::new(paths, app_cfg, t_opts, true).with_force_wizard(true);
    run_provider_wizard(&kind, Some(&remote_name), &mut ctx).await
}

/// Interactive top-level `rship config` remote manager loop.
pub async fn execute_config_interactive(
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
    t_opts: &TransportOverrides,
    interactive: bool,
) -> Result<ExitCode> {
    if !interactive {
        let code = execute_config_list(false, app_cfg)?;
        let st = Style::stderr();
        eprintln!(
            "\n{}",
            st.dim("Run `rship config --help` for subcommands, or run `rship config` in an interactive terminal.")
        );
        return Ok(code);
    }

    prompt::section(
        "rship remote configuration",
        Some(&format!("Config: {}", paths.config_file.display())),
    );

    loop {
        let _ = execute_config_list(false, app_cfg)?;
        eprintln!();

        #[derive(Clone, Copy)]
        enum MenuAction {
            New,
            Edit,
            Test,
            Remove,
            ImportRclone,
            KeyringMigrate,
            Show,
            Quit,
        }

        let has_remotes = !app_cfg.remotes.is_empty();
        let inline_secrets = count_config_inline_secrets(app_cfg);

        let mut actions = Vec::new();
        let mut items = Vec::new();

        actions.push(MenuAction::New);
        items.push(SelectItem::new("Add a new remote").with_desc(
            "Guided setup for S3, GDrive, OneDrive, Dropbox, GCS, Azure, WebDAV, SFTP, Crypt",
        ));

        if has_remotes {
            actions.push(MenuAction::Edit);
            items.push(
                SelectItem::new("Edit an existing remote")
                    .with_desc("Modify settings or re-authenticate"),
            );

            actions.push(MenuAction::Test);
            items.push(
                SelectItem::new("Test a remote connection")
                    .with_desc("Verify credentials, latency, and storage quota"),
            );

            actions.push(MenuAction::Remove);
            items.push(
                SelectItem::new("Remove a remote")
                    .with_desc("Delete from config and clean up tokens / keyring"),
            );
        }

        actions.push(MenuAction::ImportRclone);
        items.push(
            SelectItem::new("Import from rclone.conf")
                .with_desc("Migrate existing rclone remotes into rship"),
        );

        if inline_secrets > 0 {
            actions.push(MenuAction::KeyringMigrate);
            items.push(
                SelectItem::new("Migrate inline secrets to OS Keyring").with_desc(format!(
                    "{inline_secrets} inline secret(s) currently in config.toml"
                )),
            );
        }

        if has_remotes {
            actions.push(MenuAction::Show);
            items.push(
                SelectItem::new("Show config TOML (redacted)")
                    .with_desc("Inspect active config.toml with secrets masked"),
            );
        }

        actions.push(MenuAction::Quit);
        items.push(SelectItem::new("Quit"));

        let choice = match prompt::select("What would you like to do?", &items, 0) {
            Ok(idx) => actions[idx],
            Err(_) => break,
        };

        match choice {
            MenuAction::New => {
                if let Err(e) = execute_config_new(None, None, paths, app_cfg, t_opts, true).await {
                    crate::ui::print_error(&e);
                }
            }
            MenuAction::Edit => {
                if let Err(e) = execute_config_edit(None, paths, app_cfg, t_opts, true).await {
                    crate::ui::print_error(&e);
                }
            }
            MenuAction::Test => {
                let names: Vec<String> = app_cfg.remotes.keys().cloned().collect();
                let ritems: Vec<SelectItem> = names
                    .iter()
                    .map(|n| {
                        let cfg = &app_cfg.remotes[n];
                        SelectItem::new(n).with_desc(format!(
                            "{} · {}",
                            cfg.kind_str(),
                            remote_summary(cfg)
                        ))
                    })
                    .collect();
                if let Ok(idx) = prompt::select("Select remote to test", &ritems, 0) {
                    let target = &names[idx];
                    let mut rt = CliRuntime::new(
                        paths,
                        app_cfg,
                        app_cfg.defaults.to_profile(),
                        t_opts,
                        false,
                        rship::RuntimeOptions::default(),
                    )?;
                    let res = execute_config_test(target, false, &mut rt).await;
                    let _ = rt.shutdown().await;
                    if let Err(e) = res {
                        crate::ui::print_error(&e);
                    }
                }
            }
            MenuAction::Remove => {
                let names: Vec<String> = app_cfg.remotes.keys().cloned().collect();
                let ritems: Vec<SelectItem> = names
                    .iter()
                    .map(|n| {
                        let cfg = &app_cfg.remotes[n];
                        SelectItem::new(n).with_desc(format!(
                            "{} · {}",
                            cfg.kind_str(),
                            remote_summary(cfg)
                        ))
                    })
                    .collect();
                if let Ok(idx) = prompt::select("Select remote to remove", &ritems, 0) {
                    let target = names[idx].clone();
                    if prompt::confirm(
                        &format!("Permanently remove remote `{target}` and its saved tokens?"),
                        false,
                    )
                    .unwrap_or(false)
                        && let Err(e) = execute_config_rm(&target, paths, app_cfg)
                    {
                        crate::ui::print_error(&e);
                    }
                }
            }
            MenuAction::ImportRclone => {
                let detected = default_rclone_conf_path();
                let default_str = detected.as_ref().map(|p| p.display().to_string());
                if let Ok(Some(path_str)) = prompt::text(
                    "Path to rclone.conf",
                    default_str.as_deref(),
                    Some("Leave empty to use auto-detected path if shown"),
                    true,
                ) {
                    let conf_path: PathBuf = prompt::expand_tilde(&path_str);
                    let overwrite = prompt::confirm(
                        "Overwrite existing rship remotes with the same name?",
                        false,
                    )
                    .unwrap_or(false);
                    if let Err(e) =
                        import_rclone_all(Some(conf_path.clone()), overwrite, true, paths, app_cfg)
                    {
                        crate::ui::print_error(&e);
                    } else if prompt::confirm("Proceed with importing these remotes?", true)
                        .unwrap_or(false)
                        && let Err(e) =
                            import_rclone_all(Some(conf_path), overwrite, false, paths, app_cfg)
                    {
                        crate::ui::print_error(&e);
                    }
                }
            }
            MenuAction::KeyringMigrate => {
                if let Err(e) = handle_auth_keyring_migrate(paths, app_cfg) {
                    crate::ui::print_error(&e);
                }
            }
            MenuAction::Show => {
                let display_cfg = redact_config(app_cfg);
                if let Ok(s) = toml::to_string_pretty(&display_cfg) {
                    println!("\n{s}");
                }
            }
            MenuAction::Quit => break,
        }
        eprintln!();
    }

    Ok(ExitCode::SUCCESS)
}

pub async fn execute_config_test(
    remote: &str,
    json: bool,
    rt: &mut CliRuntime<'_>,
) -> Result<ExitCode> {
    let (remote_name, sub_part, spec) = match remote.split_once(':') {
        Some((r, rest)) => (r, rest, remote.to_string()),
        None => (remote, "", format!("{remote}:")),
    };
    let Some(rcfg) = rt.app_cfg.remotes.get(remote_name) else {
        return Err(
            rship_core::Error::config(format!("remote `{remote_name}` is not configured")).into(),
        );
    };
    let kind = rcfg.kind_str();
    let started = Instant::now();

    let service_ep = if sub_part.is_empty() {
        rt.client().probe_bucketless_remote(remote_name).await?
    } else {
        None
    };

    let (endpoint, quota) = if let Some(ep) = service_ep {
        (ep, None)
    } else {
        let (backend, prefix) = rt.resolve_backend(&spec, None)?;
        let mut ls = backend.list_stream(&prefix, false).await?;
        if let Some(Err(e)) = ls.next().await {
            return Err(e.into());
        }
        let quota = backend.about().await.ok().flatten();
        (backend.endpoint_identity(), quota)
    };
    let latency_ms = started.elapsed().as_millis() as u64;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "remote": remote_name,
                "kind": kind,
                "endpoint": endpoint,
                "ok": true,
                "latency_ms": latency_ms,
                "quota": quota,
            }))?
        );
    } else {
        let st = Style::stdout();
        println!(
            "{} {}  {}  {}  {}",
            st.sym_ok(),
            st.bold(remote_name),
            st.accent(kind),
            st.dim(&format!("{latency_ms} ms")),
            st.dim(&endpoint),
        );
        if let Some(q) = quota
            && let (Some(u), Some(t)) = (q.used_bytes, q.total_bytes)
        {
            let ratio = if t > 0 { u as f64 / t as f64 } else { 0.0 };
            println!(
                "  {} {:>5.1}%  {} {} {}",
                st.quota_bar(ratio, 20),
                ratio * 100.0,
                st.bold(&format_human_bytes(u)),
                st.dim("/"),
                st.dim(&format_human_bytes(t)),
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

pub fn execute_config_rm(
    remote: &str,
    paths: &AppPaths,
    app_cfg: &mut AppConfig,
) -> Result<ExitCode> {
    let Some(removed) = app_cfg.remotes.remove(remote) else {
        return Err(rship_core::Error::config(format!(
            "remote `{remote}` does not exist in {}",
            paths.config_file.display()
        ))
        .into());
    };
    cleanup_remote_secrets(remote, &removed, paths);
    save_config(&paths.config_file, app_cfg)?;
    let st = Style::stdout();
    println!(
        "{} removed remote {} {} {}",
        st.sym_ok(),
        st.bold(remote),
        st.dim(&format!("({})", removed.kind_str())),
        st.dim(&format!("from {}", paths.config_file.display()))
    );
    Ok(ExitCode::SUCCESS)
}

pub fn handle_auth_keyring_migrate(paths: &AppPaths, app_cfg: &mut AppConfig) -> Result<ExitCode> {
    let migrated = migrate_config_secrets(app_cfg)?;
    if migrated > 0 {
        save_config(&paths.config_file, app_cfg)?;
    }
    let st = Style::stdout();
    println!(
        "{} migrated {} secret(s) into OS keyring {}",
        st.sym_ok(),
        st.bold(&migrated.to_string()),
        st.dim(&format!("({})", paths.config_file.display()))
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship::config::WebdavRemoteConfig;
    use tempfile::TempDir;

    #[test]
    fn webdav_headers_count_and_storage_badge_cover_inline_keyring_mixed_and_empty() {
        let _tmp = TempDir::new().unwrap();

        let inline_only: RemoteConfig = WebdavRemoteConfig::new("https://dav.example.com")
            .with_header("X-Api-Key", "super-secret-header-token")
            .into();
        assert_eq!(count_remote_inline_secrets(&inline_only), 1);
        assert_eq!(secret_storage_badge(&inline_only), "inline");

        let keyring_only: RemoteConfig = WebdavRemoteConfig::new("https://dav.example.com")
            .with_header("X-Api-Key", "keyring://rship/dav.header.0.X-Api-Key")
            .into();
        assert_eq!(count_remote_inline_secrets(&keyring_only), 0);
        assert_eq!(secret_storage_badge(&keyring_only), "keyring");

        let mixed_keyring_pw_inline_hdr: RemoteConfig =
            WebdavRemoteConfig::new("https://dav.example.com")
                .with_password("keyring://rship/dav.password")
                .with_header("X-Api-Key", "inline-plaintext-secret")
                .into();
        assert_eq!(count_remote_inline_secrets(&mixed_keyring_pw_inline_hdr), 1);
        assert_eq!(secret_storage_badge(&mixed_keyring_pw_inline_hdr), "mixed");

        let mixed_inline_pw_keyring_hdr: RemoteConfig =
            WebdavRemoteConfig::new("https://dav.example.com")
                .with_password("plaintext-pw")
                .with_header("X-Api-Key", "keyring://rship/dav.header.0.X-Api-Key")
                .into();
        assert_eq!(count_remote_inline_secrets(&mixed_inline_pw_keyring_hdr), 1);
        assert_eq!(secret_storage_badge(&mixed_inline_pw_keyring_hdr), "mixed");

        let empty_hdr_only: RemoteConfig = WebdavRemoteConfig::new("https://dav.example.com")
            .with_header("X-Empty", "   ")
            .into();
        assert_eq!(count_remote_inline_secrets(&empty_hdr_only), 0);
        assert_eq!(secret_storage_badge(&empty_hdr_only), "none");

        let app_cfg = AppConfig::new()
            .with_remote("dav_inline", inline_only)
            .with_remote("dav_keyring", keyring_only)
            .with_remote("dav_mixed", mixed_keyring_pw_inline_hdr);
        assert_eq!(count_config_inline_secrets(&app_cfg), 2);
    }
}
