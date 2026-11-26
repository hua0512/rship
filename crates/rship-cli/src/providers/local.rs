//! Local filesystem [`ProviderAdapter`] and `rship auth local` handler.

use anyhow::{Context, Result};
use async_trait::async_trait;
use rship_backends::local::{LocalBackend, to_os_path};
use rship_core::backend::StorageBackend;
use rship_core::state::OperationRecord;
use std::path::{Path, PathBuf};

use crate::cli::LocalAuthArgs;
use crate::errors::config_err;
use crate::prompt;
use rship::config::{LocalRemoteConfig, RemoteConfig};

use super::wizard::PromptWizard;
use super::{AuthContext, AuthOutcome, BuildContext, ProviderAdapter};

pub struct LocalAdapter;

pub(super) fn handle_auth(args: LocalAuthArgs, ctx: &mut AuthContext<'_>) -> Result<AuthOutcome> {
    let mut wiz = PromptWizard::begin(args.remote, "local", "local", args.root.is_some(), ctx)?;

    let existing = match wiz.ctx.app_cfg.remotes.get(&wiz.remote) {
        Some(RemoteConfig::Local(l)) => Some((**l).clone()),
        _ => None,
    };
    let existing_root = existing.as_ref().map(|l| l.root.clone());
    let existing_encoding = existing.and_then(|l| l.encoding);

    let root = if let Some(p) = args.root {
        prompt::expand_tilde_path(p)
    } else if wiz.full_wizard || (wiz.ctx.interactive && existing_root.is_none()) {
        wiz.section(
            &format!("Configure local remote `{}`", wiz.remote),
            existing_root.is_some(),
            "Editing existing local remote — press Enter to keep current directory",
            "Expose a local directory on disk as a named remote",
        );
        let def_str = existing_root.as_ref().map(|p| p.display().to_string());
        let chosen = wiz.required_text(
            "Local root directory path",
            None,
            def_str.as_deref(),
            Some("Directory on disk exposed as `remote:` (e.g. ~/backups or /mnt/data)"),
            "missing `--root <DIR>` for local remote",
        )?;
        let expanded = prompt::expand_tilde(&chosen);
        if !expanded.exists()
            && prompt::confirm(
                &format!(
                    "Directory `{}` does not exist yet — create it now?",
                    expanded.display()
                ),
                true,
            )?
        {
            std::fs::create_dir_all(&expanded)
                .with_context(|| format!("failed to create directory `{}`", expanded.display()))?;
        }
        expanded
    } else if let Some(prev) = existing_root {
        prev
    } else {
        return Err(config_err(format!(
            "missing `--root <DIR>` for local remote `{}` (run interactively in a terminal or pass `--root`)",
            wiz.remote
        )));
    };

    let mut lcfg = LocalRemoteConfig::new(root.clone());
    lcfg.encoding = existing_encoding;
    let msg = format!(
        "configured local remote `{}` (root={}) in {}",
        wiz.remote,
        root.display(),
        wiz.ctx.paths.config_file.display()
    );
    wiz.finish(lcfg.into(), &msg)
}

#[async_trait]
impl ProviderAdapter for LocalAdapter {
    fn kind(&self) -> &'static str {
        "local"
    }

    async fn abort_gc_operation(&self, _ctx: &BuildContext<'_>, op: &OperationRecord) {
        if let Some(tok) = op.session_token.clone() {
            let _ = tokio::task::spawn_blocking(move || {
                let part_path = to_os_path(Path::new(&tok));
                let mut manifest_os = part_path.as_os_str().to_os_string();
                manifest_os.push(".parts");
                let manifest_path = PathBuf::from(manifest_os);
                let _ = std::fs::remove_file(&part_path);
                let _ = std::fs::remove_file(&manifest_path);
            })
            .await;
        } else if let Some(root_str) = op.dst_endpoint.strip_prefix("local://") {
            let root_owned = root_str.to_string();
            if let Ok(Ok(lb)) =
                tokio::task::spawn_blocking(move || LocalBackend::new("gc-local", root_owned))
                    .await
            {
                let _ = lb.abort_upload(op).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::config_ops::remote_summary;
    use crate::providers::{test_paths, test_transport_overrides};
    use rship::config::AppConfig;
    use rship_core::path::RelPath;
    use rship_core::state::{DstPrecondition, OperationState, SourceVersion};
    use tempfile::TempDir;

    fn sample_op(
        op_id: &str,
        dst_endpoint: String,
        dst_nfc_path: &str,
        session_token: Option<String>,
    ) -> OperationRecord {
        OperationRecord {
            op_id: op_id.to_string(),
            session_key: format!("sess-{op_id}"),
            job_id: "job-1".to_string(),
            src_endpoint: "local://src".to_string(),
            dst_endpoint,
            src_raw_path: dst_nfc_path.to_string(),
            dst_raw_path: dst_nfc_path.to_string(),
            dst_nfc_path: RelPath::parse(dst_nfc_path).unwrap(),
            src_version: SourceVersion {
                node_id: None,
                size: 1024,
                mtime_ns: 0,
                ctime_ns: None,
                etag: None,
            },
            dst_precondition: DstPrecondition::Any,
            existing_dst_node_id: None,
            remote_op_id: None,
            backend_kind: "local".to_string(),
            session_token,
            backend_meta: String::new(),
            planned_chunk_size: 512,
            confirmed_offset: 0,
            state: OperationState::Aborted,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn abort_gc_operation_removes_part_and_parts_manifest_via_spawn_blocking() {
        let tmp = TempDir::new().unwrap();
        let part_path = tmp.path().join("archive.tar.gz.rship.part.op1");
        let mut manifest_os = part_path.as_os_str().to_os_string();
        manifest_os.push(".parts");
        let manifest_path = PathBuf::from(manifest_os);

        std::fs::write(&part_path, b"partial-bytes").unwrap();
        std::fs::write(&manifest_path, b"manifest").unwrap();

        let paths = test_paths(tmp.path());
        let cfg = AppConfig::default();
        let rt_opts = rship::RuntimeOptions::default();
        let ctx = BuildContext {
            app_cfg: &cfg,
            paths: &paths,
            transport: None,
            inventory: None,
            allow_changes_feed: false,
            runtime_options: &rt_opts,
        };
        let op = sample_op(
            "op1",
            format!("local://{}", tmp.path().display()),
            "archive.tar.gz",
            Some(part_path.to_string_lossy().into_owned()),
        );

        LocalAdapter.abort_gc_operation(&ctx, &op).await;

        assert!(!part_path.exists(), "part file must be deleted");
        assert!(!manifest_path.exists(), ".parts manifest must be deleted");
    }

    #[tokio::test]
    async fn abort_gc_operation_fallback_local_endpoint_cleans_part_and_manifest() {
        let tmp = TempDir::new().unwrap();
        let part_path = tmp.path().join(".rship.part.op-fallback");
        let mut manifest_os = part_path.as_os_str().to_os_string();
        manifest_os.push(".parts");
        let manifest_path = PathBuf::from(manifest_os);

        std::fs::write(&part_path, b"partial").unwrap();
        std::fs::write(&manifest_path, b"manifest").unwrap();

        let paths = test_paths(tmp.path());
        let cfg = AppConfig::default();
        let rt_opts = rship::RuntimeOptions::default();
        let ctx = BuildContext {
            app_cfg: &cfg,
            paths: &paths,
            transport: None,
            inventory: None,
            allow_changes_feed: false,
            runtime_options: &rt_opts,
        };
        let op = sample_op(
            "op-fallback",
            format!("local://{}", tmp.path().display()),
            "dest.bin",
            None,
        );

        LocalAdapter.abort_gc_operation(&ctx, &op).await;

        assert!(!part_path.exists(), "fallback part file must be deleted");
        assert!(
            !manifest_path.exists(),
            "fallback .parts manifest must be deleted"
        );
    }

    #[test]
    fn handle_auth_local_creates_and_preserves_encoding() {
        let tmp = TempDir::new().unwrap();
        let dir1 = tmp.path().join("d1");
        let dir2 = tmp.path().join("d2");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();

        let paths = test_paths(tmp.path());
        let mut cfg = AppConfig::default();
        cfg.remotes.insert(
            "loc".to_string(),
            RemoteConfig::Local(Box::new(
                LocalRemoteConfig::new(&dir1).with_encoding("windows_safe"),
            )),
        );
        let t_opts = test_transport_overrides();
        let mut ctx = AuthContext::new(&paths, &mut cfg, &t_opts, false);

        let out = handle_auth(
            LocalAuthArgs {
                remote: Some("loc".to_string()),
                root: Some(dir2.clone()),
            },
            &mut ctx,
        )
        .unwrap();
        assert_eq!(out.remote, "loc");
        assert!(!out.did_prompt);

        let RemoteConfig::Local(saved) = cfg.remotes.get("loc").unwrap() else {
            panic!("expected Local remote");
        };
        assert_eq!(saved.root, dir2);
        assert_eq!(saved.encoding.as_deref(), Some("windows_safe"));
        let summary = remote_summary(cfg.remotes.get("loc").unwrap());
        assert!(summary.contains("encoding=windows_safe"), "{summary}");
    }
}
