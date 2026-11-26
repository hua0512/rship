//! SSH/SFTP [`ProviderAdapter`] and interactive `rship auth sftp` handler.

use anyhow::{Result, bail};
use async_trait::async_trait;
use rship_backends::sftp::HostKeyPolicy;
use rship_core::path::RelPath;
use rship_core::state::OperationRecord;
use std::path::PathBuf;

use crate::cli::SftpAuthArgs;
use crate::errors::config_err;
use crate::prompt::{self, SelectItem};
use rship::config::{AppPaths, RemoteConfig, SftpRemoteConfig};
use rship::secrets::resolve_opt_secret;

use super::wizard::PromptWizard;
use super::{
    AuthContext, AuthOutcome, BuildContext, PortableBundle, ProviderAdapter, abort_gc_for_remotes,
    clear_secret_opt, merge_flag_secret,
};

pub struct SftpAdapter;

const HOST_KEY_POLICIES: &[(HostKeyPolicy, &str, &str)] = &[
    (
        HostKeyPolicy::AcceptNew,
        "accept-new",
        "Recommended — trust first connection and record host key in known_hosts",
    ),
    (
        HostKeyPolicy::Strict,
        "strict",
        "Require an existing matching entry in known_hosts",
    ),
    (
        HostKeyPolicy::Insecure,
        "insecure",
        "Skip host-key verification (dev/ephemeral servers only)",
    ),
];

pub(super) fn handle_auth(args: SftpAuthArgs, ctx: &mut AuthContext<'_>) -> Result<AuthOutcome> {
    let any_config_flag = args.host.is_some()
        || args.port.is_some()
        || args.user.is_some()
        || args.root_path.is_some()
        || args.password.is_some()
        || args.key_file.is_some()
        || args.key_passphrase.is_some()
        || args.host_key_policy.is_some()
        || args.known_hosts.is_some();

    let mut wiz = PromptWizard::begin(args.remote, "sftp", "sftp", any_config_flag, ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Sftp(s)) => Some((**s).clone()),
        _ => None,
    };

    wiz.section(
        &format!("Configure SFTP remote `{}`", wiz.remote),
        existing.is_some(),
        "Editing existing remote — press Enter to keep current values",
        "Configure SSH/SFTP host, credentials, and host-key verification",
    );

    // 1. Host
    let existing_host = existing
        .as_ref()
        .map(|s| s.host.as_str())
        .filter(|h| !h.is_empty());
    let host = wiz.required_text(
        "SSH hostname or IP address",
        args.host,
        existing_host,
        Some("Example: vps.example.com or 192.168.1.20"),
        &format!(
            "missing `--host <HOST>` for SFTP remote `{}` (run interactively in a terminal or pass `--host`)",
            wiz.remote
        ),
    )?;

    // 2. Port
    let port = if let Some(p) = args.port {
        p
    } else if wiz.full_wizard {
        let def_port = existing.as_ref().and_then(|s| s.port).unwrap_or(22);
        let port_str =
            prompt::text_validated_required("SSH port", Some(&def_port.to_string()), None, |v| {
                match v.parse::<u16>() {
                    Ok(p) if p > 0 => Ok(()),
                    _ => Err("port must be an integer between 1 and 65535".to_string()),
                }
            })?;
        wiz.did_prompt = true;
        port_str.parse::<u16>()?
    } else {
        existing.as_ref().and_then(|s| s.port).unwrap_or(22)
    };

    // 3. Username
    let existing_user = existing
        .as_ref()
        .map(|s| s.user.as_str())
        .filter(|u| !u.is_empty());
    let os_user = prompt::current_username();
    let user = if let Some(u) = args.user {
        u
    } else if wiz.full_wizard || (wiz.ctx.interactive && existing_user.is_none()) {
        wiz.did_prompt = true;
        let def_user = existing_user.or(os_user.as_deref());
        prompt::text_required("SSH username", def_user, None)?
    } else if let Some(prev) = existing_user {
        prev.to_string()
    } else {
        return Err(config_err(format!(
            "missing `--user <USER>` for SFTP remote `{}` (run interactively in a terminal or pass `--user`)",
            wiz.remote
        )));
    };

    // 4. Authentication (SSH private key with ~/.ssh auto-discovery, password, or inline PEM)
    let mut key_file = args
        .key_file
        .clone()
        .map(prompt::expand_tilde_path)
        .or_else(|| existing.as_ref().and_then(|s| s.key_file.clone()));
    let mut key_pem = existing.as_ref().and_then(|s| s.key_pem.clone());
    let mut password = merge_flag_secret(
        args.password.clone(),
        existing.as_ref().and_then(|s| s.password.as_deref()),
    )?;
    let mut key_passphrase = merge_flag_secret(
        args.key_passphrase.clone(),
        existing.as_ref().and_then(|s| s.key_passphrase.as_deref()),
    )?;

    let has_auth = key_file.is_some()
        || key_pem.as_deref().is_some_and(|s| !s.is_empty())
        || password.as_deref().is_some_and(|s| !s.is_empty());

    if wiz.full_wizard || (wiz.ctx.interactive && !has_auth) {
        wiz.did_prompt = true;
        let discovered = prompt::discover_ssh_keys();
        let mut items: Vec<SelectItem> = Vec::new();
        let mut key_choices: Vec<Option<PathBuf>> = Vec::new();

        for kp in &discovered {
            let label = format!("SSH private key: {}", kp.display());
            let desc = if prompt::ssh_key_looks_encrypted(kp) {
                "encrypted — passphrase will be prompted"
            } else {
                "auto-detected in ~/.ssh"
            };
            items.push(SelectItem::new(label).with_desc(desc));
            key_choices.push(Some(kp.clone()));
        }
        let custom_key_idx = items.len();
        items.push(
            SelectItem::new("Custom SSH private key path")
                .with_desc("Specify a private key file (ed25519, RSA, ECDSA)"),
        );
        key_choices.push(None);

        let password_idx = items.len();
        items.push(
            SelectItem::new("Password authentication")
                .with_desc("Hidden password input (can be stored in OS Keyring)"),
        );

        let pem_idx = items.len();
        items.push(
            SelectItem::new("Inline SSH private key (PEM)")
                .with_desc("Paste PEM private key directly (stored in config or OS Keyring)"),
        );

        let default_idx = if let Some(ref cur_kf) = key_file {
            discovered
                .iter()
                .position(|k| k == cur_kf)
                .unwrap_or(custom_key_idx)
        } else if password.is_some() {
            password_idx
        } else if key_pem.is_some() {
            pem_idx
        } else {
            0
        };

        let chosen = prompt::select("SSH authentication method", &items, default_idx)?;
        if chosen == password_idx {
            key_file = None;
            key_pem = clear_secret_opt(key_pem.as_deref());
            key_passphrase = clear_secret_opt(key_passphrase.as_deref());
            password = wiz.prompt_secret("SSH password", password.as_deref(), true, None)?;
        } else if chosen == pem_idx {
            key_file = None;
            password = clear_secret_opt(password.as_deref());
            key_pem = wiz.prompt_secret(
                "SSH private key (PEM)",
                key_pem.as_deref(),
                true,
                Some("Paste PEM block or single-line `\\n`-escaped PEM key"),
            )?;
            key_passphrase = wiz.prompt_secret(
                "SSH key passphrase",
                key_passphrase.as_deref(),
                false,
                Some("Optional — leave empty if key is unencrypted"),
            )?;
        } else {
            password = clear_secret_opt(password.as_deref());
            key_pem = clear_secret_opt(key_pem.as_deref());
            let chosen_path = if chosen == custom_key_idx {
                let def_k = key_file.as_ref().map(|p| p.display().to_string());
                let raw = prompt::text_validated_required(
                    "Path to SSH private key file",
                    def_k.as_deref(),
                    Some("Example: ~/.ssh/id_ed25519"),
                    |v| {
                        let p = prompt::expand_tilde(v);
                        if p.is_file() {
                            Ok(())
                        } else {
                            Err(format!("key file `{}` does not exist", p.display()))
                        }
                    },
                )?;
                prompt::expand_tilde(&raw)
            } else {
                key_choices[chosen]
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("missing selected SSH key path"))?
            };

            let looks_enc = prompt::ssh_key_looks_encrypted(&chosen_path);
            let same_key = existing
                .as_ref()
                .and_then(|s| s.key_file.as_ref())
                .is_some_and(|prev| prev == &chosen_path);
            let has_pp = same_key && key_passphrase.as_deref().is_some_and(|s| !s.is_empty());
            if !same_key {
                key_passphrase = clear_secret_opt(key_passphrase.as_deref());
            }
            if looks_enc || has_pp {
                let pp_hint = if looks_enc {
                    Some("This private key appears to be passphrase-protected")
                } else {
                    Some("Enter `-` to clear the saved passphrase if this key is unencrypted")
                };
                key_passphrase = wiz.prompt_secret(
                    "SSH key passphrase",
                    key_passphrase.as_deref(),
                    false,
                    pp_hint,
                )?;
            } else {
                key_passphrase = clear_secret_opt(key_passphrase.as_deref());
            }
            key_file = Some(chosen_path);
        }
    } else if !has_auth {
        return Err(config_err(
            "either `--key-file` or `--password` is required for `rship auth sftp` (run interactively in a terminal or pass flags)",
        ));
    } else {
        // Explicit CLI mode switch cleanup
        if args.key_file.is_some() && args.password.is_none() {
            password = clear_secret_opt(password.as_deref());
            key_pem = clear_secret_opt(key_pem.as_deref());
        } else if args.password.is_some() && args.key_file.is_none() {
            key_file = None;
            key_pem = clear_secret_opt(key_pem.as_deref());
            key_passphrase = clear_secret_opt(key_passphrase.as_deref());
        }
    }

    // 5. Remote root path
    let root_path = wiz.optional_text(
        "Remote root directory",
        args.root_path,
        existing.as_ref().and_then(|s| s.root_path.clone()),
        Some("Optional starting path on server, e.g. /data/backups (leave empty for login home)"),
    )?;

    // 6. Host key policy
    let cur_pol = existing
        .as_ref()
        .and_then(|s| s.host_key_policy.as_deref())
        .and_then(HostKeyPolicy::parse)
        .unwrap_or(HostKeyPolicy::AcceptNew);
    let pol = wiz.select_flag_or_menu(
        "SSH host-key verification policy",
        args.host_key_policy.as_deref(),
        HostKeyPolicy::parse,
        |raw| {
            anyhow::anyhow!("invalid --host-key-policy `{raw}` (accept-new, strict, insecure)")
        },
        HOST_KEY_POLICIES,
        cur_pol,
        cur_pol,
    )?;

    let known_hosts_path = args
        .known_hosts
        .map(prompt::expand_tilde_path)
        .or_else(|| existing.and_then(|s| s.known_hosts_path));

    let mut scfg = SftpRemoteConfig::new(host.clone(), user.clone())
        .with_port(port)
        .with_host_key_policy(pol.as_str());
    scfg.root_path = root_path;
    scfg.password = password;
    scfg.key_file = key_file;
    scfg.key_pem = key_pem;
    scfg.key_passphrase = key_passphrase;
    scfg.known_hosts_path = known_hosts_path;

    let msg = format!(
        "configured SFTP remote `{}` ({user}@{host}:{port}) in {}",
        wiz.remote,
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(scfg.into(), &msg)
}

#[async_trait]
impl ProviderAdapter for SftpAdapter {
    fn kind(&self) -> &'static str {
        "sftp"
    }

    fn rclone_type(&self) -> Option<&'static str> {
        Some("sftp")
    }

    async fn abort_gc_operation(&self, ctx: &BuildContext<'_>, op: &OperationRecord) {
        abort_gc_for_remotes(ctx, op, |rcfg| {
            matches!(rcfg, RemoteConfig::Sftp(_)).then(RelPath::root)
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
        let RemoteConfig::Sftp(scfg) = cfg else {
            bail!("internal mismatch: expected Sftp remote config");
        };
        let mut resolved = (**scfg).clone();
        resolved.password = resolve_opt_secret(resolved.password.as_deref())?;
        resolved.key_pem = resolve_opt_secret(resolved.key_pem.as_deref())?;
        resolved.key_passphrase = resolve_opt_secret(resolved.key_passphrase.as_deref())?;
        PortableBundle::export_config(remote, "sftp", &resolved, as_json)
    }

    fn import_bundle(
        &self,
        _remote_name: &str,
        bundle: &PortableBundle,
        _paths: &AppPaths,
    ) -> Result<RemoteConfig> {
        let scfg: SftpRemoteConfig = bundle.deserialize_config("sftp")?;
        Ok(RemoteConfig::Sftp(Box::new(scfg)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use tempfile::TempDir;

    #[test]
    fn handle_auth_preserves_key_pem_on_metadata_edit_and_clears_on_password_switch() {
        let tmp = TempDir::new().unwrap();
        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "ssh1".to_string(),
            SftpRemoteConfig::new("10.0.0.1", "alice")
                .with_key_pem("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
                .with_known_hosts_path(tmp.path().join("kh"))
                .into(),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        // Metadata-only update must preserve key_pem & known_hosts_path.
        handle_auth(
            SftpAuthArgs {
                remote: Some("ssh1".to_string()),
                root_path: Some("/srv/data".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Sftp(saved) = ctx.app_cfg.remotes.get("ssh1").unwrap() else {
            panic!("expected Sftp");
        };
        assert_eq!(saved.root_path.as_deref(), Some("/srv/data"));
        assert!(saved.key_pem.is_some());
        assert_eq!(saved.known_hosts_path, Some(tmp.path().join("kh")));

        // Export & import bundle round-trips key_pem & known_hosts_path.
        let encoded = SftpAdapter
            .export_bundle(
                "ssh1",
                ctx.app_cfg.remotes.get("ssh1").unwrap(),
                &paths,
                false,
            )
            .unwrap();
        let decoded = PortableBundle::decode(&encoded).unwrap();
        let RemoteConfig::Sftp(imported) =
            SftpAdapter.import_bundle("ssh1", &decoded, &paths).unwrap()
        else {
            panic!("expected Sftp");
        };
        assert_eq!(
            imported.key_pem.as_deref(),
            Some("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
        );

        // Switching to password clears key_pem.
        handle_auth(
            SftpAuthArgs {
                remote: Some("ssh1".to_string()),
                password: Some("new-pw".to_string()),
                ..Default::default()
            },
            &mut ctx,
        )
        .unwrap();
        let RemoteConfig::Sftp(switched) = cfg.remotes.get("ssh1").unwrap() else {
            panic!("expected Sftp");
        };
        assert_eq!(switched.password.as_deref(), Some("new-pw"));
        assert!(switched.key_pem.is_none());
    }
}
