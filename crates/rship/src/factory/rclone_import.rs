use rship_core::Result;
use rship_core::path::is_valid_remote_name;
use std::collections::HashSet;
#[cfg(any(feature = "gdrive", feature = "gcs"))]
use std::path::Path;

use crate::config::{AppConfig, AppPaths, RemoteConfig};

use super::InMemoryCredentials;

/// Summary produced by [`import_rclone_conf`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RcloneImportSummary {
    /// Names and descriptions of imported remotes (`(remote_name, summary)`).
    pub imported: Vec<(String, String)>,
    /// Names of remotes skipped because they already existed and `overwrite == false`.
    pub skipped_existing: Vec<String>,
    /// Non-fatal warnings encountered while parsing `rclone.conf`.
    pub warnings: Vec<String>,
}

#[cfg(any(feature = "gdrive", feature = "gcs"))]
fn write_private_file(path: &Path, content: &str) -> Result<()> {
    crate::config::write_private_file(path, content.as_bytes())
}

#[allow(dead_code)]
enum CredentialTarget<'a> {
    PersistToDisk(&'a AppPaths),
    InMemory(&'a mut InMemoryCredentials),
    DryRun,
}

/// Import supported remotes from raw `rclone.conf` INI text into `app_cfg`, persisting
/// sidecar OAuth token and inline service-account files under `paths` unless `dry_run` is set.
pub fn import_rclone_conf(
    app_cfg: &mut AppConfig,
    raw: &str,
    paths: &AppPaths,
    overwrite: bool,
    dry_run: bool,
) -> Result<RcloneImportSummary> {
    let target = if dry_run {
        CredentialTarget::DryRun
    } else {
        CredentialTarget::PersistToDisk(paths)
    };
    import_rclone_conf_inner(app_cfg, raw, overwrite, target)
}

/// Import supported remotes from raw `rclone.conf` INI text strictly in memory without
/// writing any OAuth token or service-account sidecar files to disk.
pub(crate) fn import_rclone_conf_in_memory(
    app_cfg: &mut AppConfig,
    raw: &str,
    overwrite: bool,
    creds: &mut InMemoryCredentials,
) -> Result<RcloneImportSummary> {
    import_rclone_conf_inner(app_cfg, raw, overwrite, CredentialTarget::InMemory(creds))
}

#[allow(unused_mut, unused_variables)]
fn import_rclone_conf_inner(
    app_cfg: &mut AppConfig,
    raw: &str,
    overwrite: bool,
    mut target: CredentialTarget<'_>,
) -> Result<RcloneImportSummary> {
    rship_core::rclone_ini::ensure_unencrypted_rclone_conf(raw)?;
    let mut summary = RcloneImportSummary::default();
    let existing_names: HashSet<String> = app_cfg.remotes.keys().cloned().collect();
    let mut candidates: Vec<(String, RemoteConfig, String)> = Vec::new();
    let dry_run = matches!(target, CredentialTarget::DryRun);

    #[cfg(feature = "gdrive")]
    {
        use rship_backends::gdrive::{FileTokenStore, TokenStore, parse_rclone_conf};
        let rep = parse_rclone_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for gd in rep.gdrive_remotes {
            let mut sa_file = gd.service_account_file.clone();
            if is_valid_remote_name(&gd.name) && (!existing_names.contains(&gd.name) || overwrite) {
                match &mut target {
                    CredentialTarget::PersistToDisk(paths) => {
                        if let Some(tok) = &gd.token {
                            FileTokenStore::new(paths.token_file_for(&gd.name)).save(tok)?;
                        }
                        if sa_file.is_none()
                            && let Some(inline_sa) = &gd.service_account_credentials
                        {
                            let sa_path = paths.service_account_file_for(&gd.name);
                            write_private_file(&sa_path, inline_sa)?;
                            sa_file = Some(sa_path);
                        }
                    }
                    CredentialTarget::InMemory(creds) => {
                        if let Some(tok) = &gd.token {
                            creds.tokens.insert(gd.name.clone(), tok.clone());
                        }
                        if sa_file.is_none()
                            && let Some(inline_sa) = &gd.service_account_credentials
                        {
                            creds
                                .service_accounts
                                .insert(gd.name.clone(), inline_sa.clone());
                        }
                    }
                    CredentialTarget::DryRun => {}
                }
            }
            let desc = format!(
                "gdrive remote `{}` (token={}, service_account={})",
                gd.name,
                gd.token.is_some(),
                gd.service_account_file.is_some() || gd.service_account_credentials.is_some()
            );
            let cfg = crate::config::GdriveRemoteConfig {
                client_id: gd.client_id,
                client_secret: gd.client_secret,
                root_folder_id: gd.root_folder_id,
                shared_drive_id: gd.shared_drive_id,
                scope: Some(gd.scope),
                service_account_file: sa_file,
                impersonate: gd.impersonate,
                use_trash: Some(gd.use_trash.unwrap_or(true)),
                shared_with_me: gd.shared_with_me.then_some(true),
                trashed_only: gd.trashed_only.then_some(true),
                stop_on_upload_limit: gd.stop_on_upload_limit,
                ..Default::default()
            };
            candidates.push((gd.name, RemoteConfig::Gdrive(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "s3")]
    {
        let rep = rship_backends::s3::parse_rclone_s3_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for s3 in rep.s3_remotes {
            let desc = format!(
                "s3 remote `{}` (provider={})",
                s3.name,
                s3.provider.as_str()
            );
            let cfg = crate::config::S3RemoteConfig {
                provider: s3.provider.as_str().to_string(),
                region: s3.region,
                endpoint: s3.endpoint,
                access_key_id: s3.access_key_id,
                secret_access_key: s3.secret_access_key,
                session_token: s3.session_token,
                env_auth: s3.env_auth.then_some(true),
                profile: s3.profile,
                force_path_style: s3.force_path_style,
                storage_class: s3.storage_class,
                sse: s3.server_side_encryption,
                kms_key_id: s3.kms_key_id,
                send_upload_checksum: s3.disable_checksum.map(|disabled| !disabled),
                ..Default::default()
            };
            candidates.push((s3.name, RemoteConfig::S3(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "onedrive")]
    {
        use rship_backends::onedrive::{
            FileOnedriveTokenStore, OnedriveTokenStore, try_parse_rclone_onedrive_conf,
        };
        let rep = try_parse_rclone_onedrive_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for od in rep.remotes {
            if is_valid_remote_name(&od.name)
                && (!existing_names.contains(&od.name) || overwrite)
                && let Some(tok) = &od.token
            {
                match &mut target {
                    CredentialTarget::PersistToDisk(paths) => {
                        FileOnedriveTokenStore::new(paths.onedrive_token_file_for(&od.name))
                            .save(tok)?;
                    }
                    CredentialTarget::InMemory(creds) => {
                        creds.tokens.insert(od.name.clone(), tok.clone());
                    }
                    CredentialTarget::DryRun => {}
                }
            }
            let desc = format!(
                "onedrive remote `{}` (token={})",
                od.name,
                od.token.is_some()
            );
            let cfg = crate::config::OnedriveRemoteConfig {
                client_id: od.client_id,
                client_secret: od.client_secret,
                drive_id: od.drive_id,
                region: od.region,
                drive_type: od.drive_type,
                chunk_size: od.chunk_size,
                scope: od.scope,
                ..Default::default()
            };
            candidates.push((od.name, RemoteConfig::Onedrive(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "webdav")]
    {
        let rep = rship_backends::webdav::try_parse_rclone_webdav_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for dav in rep.remotes {
            let desc = format!(
                "webdav remote `{}` (vendor={})",
                dav.name,
                dav.vendor.as_str()
            );
            let cfg = crate::config::WebdavRemoteConfig {
                url: dav.url,
                vendor: Some(dav.vendor.as_str().to_string()),
                username: dav.user,
                password: dav.pass,
                bearer_token: dav.bearer_token,
                bearer_token_command: dav.bearer_token_command,
                headers: dav.headers,
                chunked_upload_root: None,
                ..Default::default()
            };
            candidates.push((dav.name, RemoteConfig::Webdav(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "sftp")]
    {
        let rep = rship_backends::sftp::try_parse_rclone_sftp_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for sf in rep.remotes {
            let desc = format!(
                "sftp remote `{}` ({}@{}:{})",
                sf.name, sf.user, sf.host, sf.port
            );
            let cfg = crate::config::SftpRemoteConfig {
                host: sf.host,
                port: Some(sf.port),
                user: sf.user,
                password: sf.pass,
                key_file: sf.key_file,
                key_pem: sf.key_pem,
                key_passphrase: sf.key_file_pass,
                known_hosts_path: sf.known_hosts_file,
                ..Default::default()
            };
            candidates.push((sf.name, RemoteConfig::Sftp(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "dropbox")]
    {
        use rship_backends::dropbox::{
            DropboxTokenStore, FileDropboxTokenStore, try_parse_rclone_dropbox_conf,
        };
        let rep = try_parse_rclone_dropbox_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for dbx in rep.remotes {
            if is_valid_remote_name(&dbx.name)
                && (!existing_names.contains(&dbx.name) || overwrite)
                && let Some(tok) = &dbx.token
            {
                match &mut target {
                    CredentialTarget::PersistToDisk(paths) => {
                        FileDropboxTokenStore::new(paths.dropbox_token_file_for(&dbx.name))
                            .save(tok)?;
                    }
                    CredentialTarget::InMemory(creds) => {
                        creds.tokens.insert(dbx.name.clone(), tok.clone());
                    }
                    CredentialTarget::DryRun => {}
                }
            }
            let desc = format!(
                "dropbox remote `{}` (token={})",
                dbx.name,
                dbx.token.is_some()
            );
            let cfg = crate::config::DropboxRemoteConfig {
                client_id: dbx.client_id,
                client_secret: dbx.client_secret,
                root_namespace: dbx.root_namespace,
                impersonate: dbx.impersonate,
                shared_folders: dbx.shared_folders.then_some(true),
                ..Default::default()
            };
            candidates.push((dbx.name, RemoteConfig::Dropbox(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "gcs")]
    {
        use rship_backends::gcs::{FileGcsTokenStore, GcsTokenStore, parse_rclone_gcs_conf};
        let rep = parse_rclone_gcs_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for gcs in rep.remotes {
            let mut sa_file = gcs.service_account_file.clone();
            if is_valid_remote_name(&gcs.name) && (!existing_names.contains(&gcs.name) || overwrite)
            {
                match &mut target {
                    CredentialTarget::PersistToDisk(paths) => {
                        if let Some(tok) = &gcs.token {
                            FileGcsTokenStore::new(paths.gcs_token_file_for(&gcs.name))
                                .save(tok)?;
                        }
                        if sa_file.is_none()
                            && let Some(inline_sa) = &gcs.service_account_credentials
                        {
                            let sa_path = paths.gcs_service_account_file_for(&gcs.name);
                            write_private_file(&sa_path, inline_sa)?;
                            sa_file = Some(sa_path);
                        }
                    }
                    CredentialTarget::InMemory(creds) => {
                        if let Some(tok) = &gcs.token {
                            creds.tokens.insert(gcs.name.clone(), tok.clone());
                        }
                        if sa_file.is_none()
                            && let Some(inline_sa) = &gcs.service_account_credentials
                        {
                            creds
                                .service_accounts
                                .insert(gcs.name.clone(), inline_sa.clone());
                        }
                    }
                    CredentialTarget::DryRun => {}
                }
            }
            let desc = format!("gcs remote `{}`", gcs.name);
            let cfg = crate::config::GcsRemoteConfig {
                project_number: gcs.project_number,
                user_project: gcs.user_project,
                storage_class: gcs.storage_class,
                client_id: gcs.client_id,
                client_secret: gcs.client_secret,
                scope: gcs.scope,
                service_account_file: sa_file,
                env_auth: gcs.env_auth.then_some(true),
                anonymous: gcs.anonymous.then_some(true),
                endpoint: gcs.endpoint,
                auth_url: gcs.auth_url,
                token_url: gcs.token_url,
                ..Default::default()
            };
            candidates.push((gcs.name, RemoteConfig::Gcs(Box::new(cfg)), desc));
        }
    }

    #[cfg(feature = "azureblob")]
    {
        let rep = rship_backends::azureblob::parse_rclone_azureblob_conf(raw)?;
        summary.warnings.extend(rep.warnings);
        for az in rep.remotes {
            let desc = format!("azureblob remote `{}`", az.name);
            let cfg = crate::config::AzureblobRemoteConfig {
                account: az.account,
                container: az.container,
                key: az.key,
                sas_url: az.sas_url,
                endpoint: az.endpoint,
                access_tier: az.access_tier,
                anonymous: az.anonymous.then_some(true),
                ..Default::default()
            };
            candidates.push((az.name, RemoteConfig::Azureblob(Box::new(cfg)), desc));
        }
    }

    for (name, rcfg, desc) in candidates {
        if !is_valid_remote_name(&name) {
            summary.warnings.push(format!(
                "skipping remote `{name}`: invalid remote name (must be >= 2 chars, [A-Za-z0-9_-])"
            ));
            continue;
        }
        if app_cfg.remotes.contains_key(&name) && !overwrite {
            summary.skipped_existing.push(name);
            continue;
        }
        if !dry_run {
            app_cfg.remotes.insert(name.clone(), rcfg);
        }
        summary.imported.push((name, desc));
    }

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::ErrorKind;

    #[test]
    fn rejects_encrypted_rclone_conf_with_bom_and_comments_under_all_feature_sets() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        for raw in [
            "RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
            "\u{FEFF}# Encrypted rclone config\n\n  RCLONE_ENCRYPT_V0:\nYWJjZGVm\n",
        ] {
            let mut cfg = AppConfig::new();
            let err = import_rclone_conf(&mut cfg, raw, &paths, true, false)
                .expect_err("encrypted rclone.conf must fail");
            assert_eq!(err.kind, ErrorKind::Config);
            assert!(err.to_string().contains("RCLONE_ENCRYPT_V0:"));

            let mut mem_creds = InMemoryCredentials::default();
            let err_mem = import_rclone_conf_in_memory(&mut cfg, raw, true, &mut mem_creds)
                .expect_err("in-memory import must reject encrypted rclone.conf");
            assert_eq!(err_mem.kind, ErrorKind::Config);
        }
    }

    #[cfg(any(
        feature = "onedrive",
        feature = "dropbox",
        feature = "webdav",
        feature = "sftp"
    ))]
    #[test]
    fn try_parse_importers_propagate_ini_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let mut cfg = AppConfig::new();
        let err = import_rclone_conf(&mut cfg, "[]\ntype = onedrive\n", &paths, true, false)
            .expect_err("empty section header must fail");
        assert!(matches!(err.kind, ErrorKind::Protocol | ErrorKind::Config));
    }

    #[cfg(feature = "s3")]
    #[test]
    fn imports_s3_sse_kms_profile_and_disable_checksum() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[s3_kms]
type = s3
provider = AWS
region = us-east-1
profile = prod-prof
server_side_encryption = aws:kms
sse_kms_key_id = arn:aws:kms:us-east-1:123:key/abc
disable_checksum = true

[s3_ck]
type = s3
provider = AWS
access_key_id = ak
secret_access_key = sk
disable_checksum = false
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("s3_kms") {
            Some(RemoteConfig::S3(s)) => {
                assert_eq!(s.profile.as_deref(), Some("prod-prof"));
                assert_eq!(s.sse.as_deref(), Some("aws:kms"));
                assert_eq!(
                    s.kms_key_id.as_deref(),
                    Some("arn:aws:kms:us-east-1:123:key/abc")
                );
                assert_eq!(s.send_upload_checksum, Some(false));
            }
            other => panic!("expected S3, got {other:?}"),
        }
        match cfg.remotes.get("s3_ck") {
            Some(RemoteConfig::S3(s)) => {
                assert_eq!(s.send_upload_checksum, Some(true));
            }
            other => panic!("expected S3, got {other:?}"),
        }
    }

    #[cfg(feature = "gcs")]
    #[test]
    fn imports_gcs_endpoint_urls_scope_user_project_and_env_auth() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[gcs_custom]
type = google cloud storage
endpoint = http://127.0.0.1:4443
auth_url = https://auth.example.test/auth
token_url = https://token.example.test/token
scope = read_only
user_project = billing-proj
env_auth = true
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("gcs_custom") {
            Some(RemoteConfig::Gcs(g)) => {
                assert_eq!(g.endpoint.as_deref(), Some("http://127.0.0.1:4443"));
                assert_eq!(
                    g.auth_url.as_deref(),
                    Some("https://auth.example.test/auth")
                );
                assert_eq!(
                    g.token_url.as_deref(),
                    Some("https://token.example.test/token")
                );
                assert_eq!(
                    g.scope.as_deref(),
                    Some("https://www.googleapis.com/auth/devstorage.read_only")
                );
                assert_eq!(g.user_project.as_deref(), Some("billing-proj"));
                assert_eq!(g.env_auth, Some(true));
            }
            other => panic!("expected Gcs, got {other:?}"),
        }
    }

    #[cfg(feature = "azureblob")]
    #[test]
    fn imports_azureblob_container_and_anonymous() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[az_pub]
type = azureblob
account = pubacct
container = pubcont
anonymous = true

[az_sas]
type = azureblob
sas_url = http://127.0.0.1:10000/devstoreaccount1/mycont?sv=2023-11-03&sig=abc
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("az_pub") {
            Some(RemoteConfig::Azureblob(a)) => {
                assert_eq!(a.container.as_deref(), Some("pubcont"));
                assert_eq!(a.anonymous, Some(true));
            }
            other => panic!("expected Azureblob, got {other:?}"),
        }
        match cfg.remotes.get("az_sas") {
            Some(RemoteConfig::Azureblob(a)) => {
                assert_eq!(a.account.as_deref(), Some("devstoreaccount1"));
                assert_eq!(a.container.as_deref(), Some("mycont"));
                assert_eq!(
                    a.endpoint.as_deref(),
                    Some("http://127.0.0.1:10000/devstoreaccount1")
                );
                assert_eq!(a.anonymous, None);
            }
            other => panic!("expected Azureblob, got {other:?}"),
        }
    }

    #[cfg(feature = "gdrive")]
    #[test]
    fn imports_gdrive_use_trash_default_true_and_filters() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[gd_def]
type = drive
client_id = cid

[gd_perm]
type = drive
client_id = cid
use_trash = false
shared_with_me = true
trashed_only = true
stop_on_upload_limit = true
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("gd_def") {
            Some(RemoteConfig::Gdrive(g)) => {
                assert_eq!(g.use_trash, Some(true));
                assert_eq!(g.shared_with_me, None);
                assert_eq!(g.trashed_only, None);
                assert_eq!(g.stop_on_upload_limit, None);
            }
            other => panic!("expected Gdrive, got {other:?}"),
        }
        match cfg.remotes.get("gd_perm") {
            Some(RemoteConfig::Gdrive(g)) => {
                assert_eq!(g.use_trash, Some(false));
                assert_eq!(g.shared_with_me, Some(true));
                assert_eq!(g.trashed_only, Some(true));
                assert_eq!(g.stop_on_upload_limit, Some(true));
            }
            other => panic!("expected Gdrive, got {other:?}"),
        }
    }

    #[cfg(feature = "onedrive")]
    #[test]
    fn imports_onedrive_region_drive_type_chunk_size_and_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[od_cn]
type = onedrive
client_id = cid
region = cn
drive_type = business
chunk_size = 5Mi
scope = Files.Read.All offline_access
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("od_cn") {
            Some(RemoteConfig::Onedrive(o)) => {
                assert_eq!(o.region.as_deref(), Some("cn"));
                assert_eq!(o.drive_type.as_deref(), Some("business"));
                assert_eq!(o.chunk_size, Some(5 * 1024 * 1024));
                assert_eq!(o.scope.as_deref(), Some("Files.Read.All offline_access"));
            }
            other => panic!("expected Onedrive, got {other:?}"),
        }
    }

    #[cfg(feature = "dropbox")]
    #[test]
    fn imports_dropbox_root_namespace_impersonate_and_shared_folders() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[dbx_team]
type = dropbox
client_id = cid
root_namespace = 123456
impersonate = dbmid:team_user
shared_folders = true
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("dbx_team") {
            Some(RemoteConfig::Dropbox(d)) => {
                assert_eq!(d.root_namespace.as_deref(), Some("123456"));
                assert_eq!(d.impersonate.as_deref(), Some("dbmid:team_user"));
                assert_eq!(d.shared_folders, Some(true));
            }
            other => panic!("expected Dropbox, got {other:?}"),
        }
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn imports_webdav_headers_and_bearer_token_command() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[dav_hdrs]
type = webdav
url = https://dav.example.com/root
vendor = nextcloud
headers = X-Custom,"a, b",X-Two,val2
bearer_token_command = /usr/local/bin/get-token --scope dav
"#;
        let mut cfg = AppConfig::new();
        let summary = import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();
        assert!(
            summary
                .warnings
                .iter()
                .any(|w| w.contains("bearer_token_command"))
        );

        match cfg.remotes.get("dav_hdrs") {
            Some(RemoteConfig::Webdav(w)) => {
                assert_eq!(
                    w.headers,
                    vec![
                        ("X-Custom".to_string(), "a, b".to_string()),
                        ("X-Two".to_string(), "val2".to_string()),
                    ]
                );
                assert_eq!(
                    w.bearer_token_command.as_deref(),
                    Some("/usr/local/bin/get-token --scope dav")
                );
            }
            other => panic!("expected Webdav, got {other:?}"),
        }
    }

    #[cfg(feature = "sftp")]
    #[test]
    fn imports_sftp_key_pem_and_known_hosts_path() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(tmp.path().join("config.toml"), tmp.path().join("state"));
        let raw = r#"
[sf_pem]
type = sftp
host = 10.0.0.1
user = deploy
known_hosts_file = /etc/ssh/ssh_known_hosts
key_pem = -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----
"#;
        let mut cfg = AppConfig::new();
        import_rclone_conf(&mut cfg, raw, &paths, true, false).unwrap();

        match cfg.remotes.get("sf_pem") {
            Some(RemoteConfig::Sftp(s)) => {
                assert_eq!(
                    s.known_hosts_path.as_deref(),
                    Some(Path::new("/etc/ssh/ssh_known_hosts"))
                );
                assert_eq!(
                    s.key_pem.as_deref(),
                    Some(
                        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
                    )
                );
            }
            other => panic!("expected Sftp, got {other:?}"),
        }
    }
}
