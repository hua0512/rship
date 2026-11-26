//! Zero-knowledge STREAM OAE2 encryption overlay [`ProviderAdapter`] and interactive
//! `rship auth crypt` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;
use rship_crypto::MasterKey;

use crate::cli::CryptAuthArgs;
use crate::errors::config_err;
use crate::ops::config_ops::remote_summary;
use crate::prompt::{self, SecretOutcome, SelectItem};
use rship::config::{AppPaths, CryptRemoteConfig, RemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    apply_secret_outcome, clear_secret_opt, merge_flag_secret,
};

pub struct CryptAdapter;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FilenameEncMode {
    Standard,
    Off,
}

impl FilenameEncMode {
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "standard" | "std" => Some(Self::Standard),
            "off" | "none" => Some(Self::Off),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Off => "off",
        }
    }
}

const FILENAME_ENC_ITEMS: &[(FilenameEncMode, &str, &str)] = &[
    (
        FilenameEncMode::Standard,
        "standard",
        "Recommended — encrypt both file contents and file/folder names",
    ),
    (
        FilenameEncMode::Off,
        "off",
        "Encrypt file contents only, keep plaintext filenames",
    ),
];

pub(super) fn handle_auth(args: CryptAuthArgs, ctx: &mut AuthContext<'_>) -> Result<AuthOutcome> {
    let any_config_flag = args.target.is_some()
        || args.password.is_some()
        || args.key_hex.is_some()
        || args.salt.is_some()
        || args.filename_encryption.is_some();

    let mut wiz = PromptWizard::begin(args.remote, "vault", "crypt", any_config_flag, ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Crypt(c)) => Some((**c).clone()),
        _ => None,
    };

    wiz.section(
        &format!("Configure encrypted vault `{}`", wiz.remote),
        existing.is_some(),
        "Editing existing encrypted vault — press Enter to keep current values",
        "Wrap any configured remote or local directory with zero-knowledge XChaCha20-Poly1305 encryption",
    );

    // 1. Underlying target (`remote:path` or local path)
    let existing_target = existing
        .as_ref()
        .map(|c| c.remote.as_str())
        .filter(|t| !t.is_empty());
    let target = if let Some(t) = args.target {
        t
    } else if wiz.full_wizard || (wiz.ctx.interactive && existing_target.is_none()) {
        wiz.did_prompt = true;
        let candidates: Vec<(String, String)> = wiz
            .ctx
            .app_cfg
            .remotes
            .iter()
            .filter(|(name, _)| *name != &wiz.remote)
            .map(|(name, cfg)| {
                (
                    name.clone(),
                    format!("{} · {}", cfg.kind_str(), remote_summary(cfg)),
                )
            })
            .collect();

        if !candidates.is_empty() && existing_target.is_none() {
            let mut items: Vec<SelectItem> = candidates
                .iter()
                .map(|(n, desc)| SelectItem::new(format!("{n}:")).with_desc(desc))
                .collect();
            let custom_idx = items.len();
            items.push(
                SelectItem::new("Custom target or local directory")
                    .with_desc("Enter any `remote:subpath` or local filesystem path"),
            );
            let idx = prompt::select("Underlying storage remote to encrypt", &items, 0)?;
            if idx < custom_idx {
                let base_remote = &candidates[idx].0;
                let subpath = prompt::text(
                    &format!("Subpath inside `{base_remote}:`"),
                    Some("vault"),
                    Some("Encrypted files will be stored under this prefix (leave empty for root)"),
                    false,
                )?;
                match subpath {
                    Some(p) => format!("{base_remote}:{}", p.trim_start_matches('/')),
                    None => format!("{base_remote}:"),
                }
            } else {
                prompt::text_required(
                    "Underlying target (`remote:subpath` or local path)",
                    None,
                    Some("Examples: my-r2:encrypted-vault, gdrive:vault, ~/vault"),
                )?
            }
        } else {
            prompt::text_required(
                "Underlying target (`remote:subpath` or local path)",
                existing_target,
                Some("Examples: my-r2:encrypted-vault, gdrive:vault, ~/vault"),
            )?
        }
    } else if let Some(prev) = existing_target {
        prev.to_string()
    } else {
        return Err(config_err(format!(
            "missing `--target <REMOTE:PATH|DIR>` for crypt remote `{}` (run interactively in a terminal or pass `--target`)",
            wiz.remote
        )));
    };

    // 2. Encryption key (Argon2id passphrase or 256-bit hex MasterKey)
    if let Some(ref hk) = args.key_hex {
        let _ = MasterKey::from_hex(hk)?;
    }
    if let Some(ref s) = args.salt
        && s.len() < 8
    {
        return Err(config_err(format!(
            "Argon2id `--salt` must be at least 8 bytes (got {} bytes; shorter salts are ignored by Argon2id)",
            s.len()
        )));
    }

    let mut password = merge_flag_secret(
        args.password.clone(),
        existing.as_ref().and_then(|c| c.password.as_deref()),
    )?;
    let mut key_hex = merge_flag_secret(
        args.key_hex.clone(),
        existing.as_ref().and_then(|c| c.key_hex.as_deref()),
    )?;
    let mut salt = args
        .salt
        .clone()
        .or_else(|| existing.as_ref().and_then(|c| c.salt.clone()));

    let has_key_material = password.as_deref().is_some_and(|s| !s.is_empty())
        || key_hex.as_deref().is_some_and(|s| !s.is_empty());

    if wiz.full_wizard || (wiz.ctx.interactive && !has_key_material) {
        wiz.did_prompt = true;
        let def_mode = if key_hex.is_some() && password.is_none() {
            2
        } else {
            0
        };
        let key_items = [
            SelectItem::new("Passphrase (Argon2id key derivation)")
                .with_desc("Recommended — enter & confirm a memorable passphrase"),
            SelectItem::new("Generate random 256-bit master key")
                .with_desc("Maximum entropy (64-char hex key generated by OS CSPRNG)"),
            SelectItem::new("Enter existing 64-character hex master key")
                .with_desc("Reuse a previously generated 256-bit hex key"),
        ];
        match prompt::select("Vault encryption key", &key_items, def_mode)? {
            0 => {
                key_hex = clear_secret_opt(key_hex.as_deref());
                let has_pw = password.as_deref().is_some_and(|s| !s.is_empty());
                let pw_out = prompt::password_confirmed(
                    "Vault passphrase",
                    "Confirm vault passphrase",
                    has_pw,
                    true,
                    Some("Store a backup copy safely — forgotten passphrases cannot be recovered!"),
                )?;
                password = apply_secret_outcome(pw_out, password.as_deref())?;
                if args.salt.is_none() {
                    if prompt::confirm("Set a custom Argon2id salt (optional)?", salt.is_some())? {
                        salt = prompt::text_validated(
                            "Argon2id salt",
                            salt.as_deref(),
                            Some("Must be at least 8 bytes"),
                            false,
                            |v| {
                                if v.len() >= 8 {
                                    Ok(())
                                } else {
                                    Err(format!(
                                        "salt must be at least 8 bytes (got {} bytes)",
                                        v.len()
                                    ))
                                }
                            },
                        )?;
                    } else {
                        salt = None;
                    }
                }
            }
            1 => {
                password = clear_secret_opt(password.as_deref());
                salt = None;
                let generated = MasterKey::generate();
                let hex_key = generated.to_hex();
                prompt::warn(
                    "Generated a new 256-bit master key. Save a backup copy — losing it permanently locks your vault!",
                );
                prompt::note(&format!("Master key (hex): {hex_key}"));
                key_hex = apply_secret_outcome(SecretOutcome::Value(hex_key), key_hex.as_deref())?;
            }
            _ => {
                password = clear_secret_opt(password.as_deref());
                salt = None;
                let has_hk = key_hex.as_deref().is_some_and(|s| !s.is_empty());
                loop {
                    let hk_out =
                        prompt::password("64-character hex master key", has_hk, true, None)?;
                    match &hk_out {
                        SecretOutcome::Value(v) => {
                            if let Err(e) = MasterKey::from_hex(v) {
                                prompt::validation_err(&e.to_string());
                                continue;
                            }
                        }
                        SecretOutcome::KeepExisting | SecretOutcome::Empty => {}
                    }
                    key_hex = apply_secret_outcome(hk_out, key_hex.as_deref())?;
                    break;
                }
            }
        }
    } else if !has_key_material {
        return Err(config_err(
            "either `--password` or `--key-hex` is required for `rship auth crypt` (run interactively in a terminal or pass flags)",
        ));
    } else if args.key_hex.is_some() && args.password.is_none() {
        password = clear_secret_opt(password.as_deref());
    } else if args.password.is_some() && args.key_hex.is_none() {
        key_hex = clear_secret_opt(key_hex.as_deref());
    }

    // 3. Filename encryption mode
    let cur_mode = existing
        .as_ref()
        .and_then(|c| c.filename_encryption.as_deref())
        .and_then(FilenameEncMode::parse)
        .unwrap_or(FilenameEncMode::Standard);
    let mode = wiz
        .select_flag_or_menu(
            "Filename encryption mode",
            args.filename_encryption.as_deref(),
            FilenameEncMode::parse,
            |other| {
                config_err(format!(
                    "invalid --filename-encryption `{other}` (expected `standard` or `off`)"
                ))
            },
            FILENAME_ENC_ITEMS,
            cur_mode,
            cur_mode,
        )?
        .as_str()
        .to_string();

    let mut ccfg = CryptRemoteConfig::new(target.clone()).with_filename_encryption(mode.clone());
    ccfg.password = password;
    ccfg.key_hex = key_hex;
    ccfg.salt = salt;

    let msg = format!(
        "configured STREAM OAE2 crypt remote `{}` -> `{target}` (filename_encryption={mode}) in {}",
        wiz.remote,
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(ccfg.into(), &msg)
}

#[async_trait]
impl ProviderAdapter for CryptAdapter {
    fn kind(&self) -> &'static str {
        "crypt"
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Crypt(_)).then(RelPath::root)
        })
        .await;
    }

    fn export_bundle(
        &self,
        remote: &str,
        cfg: &RemoteConfig,
        _paths: &AppPaths,
        as_json: bool,
    ) -> Result<String> {
        let RemoteConfig::Crypt(ccfg) = cfg else {
            bail!("internal mismatch: expected Crypt remote config");
        };
        let mut resolved = (**ccfg).clone();
        resolved.password = resolve_opt_secret(resolved.password.as_deref())?;
        resolved.key_hex = resolve_opt_secret(resolved.key_hex.as_deref())?;
        PortableBundle::export_config(remote, "crypt", &resolved, as_json)
    }

    fn import_bundle(
        &self,
        _remote_name: &str,
        bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let ccfg: CryptRemoteConfig = bundle.deserialize_config("crypt")?;
        Ok(RemoteConfig::Crypt(Box::new(ccfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn handle_auth_accepts_std_alias_for_filename_encryption() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        handle_auth(
            CryptAuthArgs {
                remote: Some("vault".to_string()),
                target: Some(tmp.path().to_string_lossy().into_owned()),
                password: Some("strong-pw".to_string()),
                filename_encryption: Some("std".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();

        let RemoteConfig::Crypt(saved) = cfg.remotes.get("vault").unwrap() else {
            panic!("expected Crypt");
        };
        assert_eq!(saved.filename_encryption.as_deref(), Some("standard"));
    }
}
