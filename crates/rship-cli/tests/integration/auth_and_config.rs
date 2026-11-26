use crate::rship_bin;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_rclone_import_and_auth_export_import_headless_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let rclone_conf = tmp.path().join("rclone.conf");

    std::fs::write(
        &rclone_conf,
        r#"
[work-gd]
type = drive
client_id = 123456.apps.googleusercontent.com
client_secret = GOCSPX-mysecret
scope = drive
root_folder_id = 1RootFolderABC
team_drive = 0ASharedDriveXYZ
token = {"access_token":"ya29.imported","token_type":"Bearer","refresh_token":"1//ref-imported","expiry":"2027-01-01T00:00:00Z"}

[my-r2]
type = s3
provider = Cloudflare
access_key_id = r2-ak
secret_access_key = r2-sk
region = auto
endpoint = https://acct.r2.cloudflarestorage.com

[ignored-ftp]
type = ftp
"#,
    )
    .unwrap();

    // 1. Import from rclone.conf (imports BOTH drive and s3 remotes!)
    let out_imp = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "config",
            "import-rclone",
            rclone_conf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out_imp.status.success(),
        "import-rclone failed: {}",
        String::from_utf8_lossy(&out_imp.stderr)
    );
    let stdout = String::from_utf8_lossy(&out_imp.stdout);
    assert!(stdout.contains("imported gdrive remote `work-gd`"));
    assert!(stdout.contains("imported s3 remote `my-r2` (provider=r2"));
    assert!(stdout.contains("skipped unsupported remote `ignored-ftp`"));
    assert!(state_dir.join("tokens/work-gd.json").exists());

    // 2. Verify `config show` renders BOTH `[remotes.work-gd]` and `[remotes.my-r2]`
    let out_show = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "config",
            "show",
        ])
        .output()
        .unwrap();
    assert!(out_show.status.success());
    let toml_out = String::from_utf8_lossy(&out_show.stdout);
    assert!(toml_out.contains("type = \"gdrive\""));
    assert!(toml_out.contains("123456.apps.googleusercontent.com"));
    assert!(toml_out.contains("0ASharedDriveXYZ"));
    assert!(toml_out.contains("type = \"s3\""));
    assert!(toml_out.contains("provider = \"r2\""));
    assert!(toml_out.contains("https://acct.r2.cloudflarestorage.com"));

    // 2b. Verify `rship auth s3` creates an AWS remote cleanly
    let out_s3 = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "s3",
            "aws-prod",
            "--provider",
            "aws",
            "--bucket",
            "my-backups",
            "--region",
            "us-west-2",
            "--env-auth",
        ])
        .output()
        .unwrap();
    assert!(
        out_s3.status.success(),
        "auth s3 failed: {}",
        String::from_utf8_lossy(&out_s3.stderr)
    );
    let saved_toml = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(saved_toml.contains("[remotes.aws-prod]"));
    assert!(saved_toml.contains("bucket = \"my-backups\""));

    // 3. Export bundle for headless server and import into a clean second environment
    let out_exp = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "export",
            "work-gd",
        ])
        .output()
        .unwrap();
    assert!(
        out_exp.status.success(),
        "auth export failed: {}",
        String::from_utf8_lossy(&out_exp.stderr)
    );
    let bundle = String::from_utf8(out_exp.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(bundle.starts_with("rship-auth-v1:"));

    let cfg_headless = tmp.path().join("headless/config.toml");
    let state_headless = tmp.path().join("headless/state");
    let out_himp = Command::new(rship_bin())
        .args([
            "--config",
            cfg_headless.to_str().unwrap(),
            "--state-dir",
            state_headless.to_str().unwrap(),
            "auth",
            "import",
            "--bundle",
            &bundle,
            "--name",
            "headless-gd",
        ])
        .output()
        .unwrap();
    assert!(
        out_himp.status.success(),
        "auth import failed: {}",
        String::from_utf8_lossy(&out_himp.stderr)
    );
    assert!(state_headless.join("tokens/headless-gd.json").exists());
    let imported_cfg = std::fs::read_to_string(&cfg_headless).unwrap();
    assert!(imported_cfg.contains("[remotes.headless-gd]"));
    assert!(imported_cfg.contains("type = \"gdrive\""));
}

#[test]
fn cli_about_hashsum_config_test_rm_multi_provider_auth_rclone_import_and_gdrive_guide() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("alpha.txt"), b"hello world").unwrap();
    std::fs::write(data_dir.join("beta.bin"), b"0123456789").unwrap();

    // 1. `rship about` on local filesystem returns real disk quota!
    let about_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "about",
            data_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        about_out.status.success(),
        "about failed: {}",
        String::from_utf8_lossy(&about_out.stderr)
    );
    let about_json: serde_json::Value = serde_json::from_slice(&about_out.stdout).unwrap();
    assert!(about_json["total_bytes"].as_u64().unwrap_or(0) > 0);
    assert!(about_json["free_bytes"].as_u64().is_some());

    // 2. `rship hashsum sha256` computes concurrent hashes compatible with `sha256sum`.
    let hash_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "hashsum",
            "sha256",
            data_dir.to_str().unwrap(),
            "--checkers",
            "4",
        ])
        .output()
        .unwrap();
    assert!(
        hash_out.status.success(),
        "hashsum failed: {}",
        String::from_utf8_lossy(&hash_out.stderr)
    );
    let hash_txt = String::from_utf8(hash_out.stdout).unwrap();
    assert!(
        hash_txt.contains(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9  alpha.txt"
        ),
        "unexpected sha256 output:\n{hash_txt}"
    );
    assert!(hash_txt.contains("beta.bin"));

    // 3. `rship auth gdrive mygd --guide` prints full Google Cloud OAuth Client ID checklist.
    let guide_out = Command::new(rship_bin())
        .args(["auth", "gdrive", "mygd", "--guide"])
        .output()
        .unwrap();
    assert!(guide_out.status.success());
    let guide_txt = String::from_utf8(guide_out.stdout).unwrap();
    assert!(guide_txt.contains("Desktop app"));
    assert!(guide_txt.contains("docs/GOOGLE_OAUTH_SETUP.md"));

    // 4. Configure WebDAV, SFTP, OneDrive remotes + `config show` redaction + `config rm`!
    let dav_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "auth",
            "webdav",
            "my-nc",
            "--url",
            "https://cloud.example.com/remote.php/dav/files/alice",
            "--vendor",
            "nextcloud",
            "--username",
            "alice",
            "--password",
            "DAV_SECRET_123",
        ])
        .output()
        .unwrap();
    assert!(dav_out.status.success());

    let sftp_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "auth",
            "sftp",
            "my-vps",
            "--host",
            "10.0.0.5",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--password",
            "SSH_SECRET_456",
        ])
        .output()
        .unwrap();
    assert!(sftp_out.status.success());

    let od_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "auth",
            "onedrive",
            "my-od",
            "--access-token",
            "OD_TOKEN_789",
        ])
        .output()
        .unwrap();
    assert!(od_out.status.success());

    let show = Command::new(rship_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "config", "show"])
        .output()
        .unwrap();
    assert!(show.status.success());
    let shown = String::from_utf8(show.stdout).unwrap();
    assert!(!shown.contains("DAV_SECRET_123"));
    assert!(!shown.contains("SSH_SECRET_456"));
    assert!(!shown.contains("OD_TOKEN_789"));
    assert!(shown.contains("***REDACTED***"));

    // 5. `config test` on a local alias + `config rm` cleanup!
    let mut cfg_content = std::fs::read_to_string(&cfg_path).unwrap();
    cfg_content.push_str(&format!(
        "\n[remotes.local-alias]\ntype = \"local\"\nroot = {:?}\n",
        data_dir.to_string_lossy()
    ));
    std::fs::write(&cfg_path, cfg_content).unwrap();

    let test_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "config",
            "test",
            "local-alias",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        test_out.status.success(),
        "config test failed: {}",
        String::from_utf8_lossy(&test_out.stderr)
    );
    let test_json: serde_json::Value = serde_json::from_slice(&test_out.stdout).unwrap();
    assert_eq!(test_json["ok"], true);
    assert_eq!(test_json["kind"], "local");

    let rm_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "config",
            "rm",
            "my-vps",
        ])
        .output()
        .unwrap();
    assert!(rm_out.status.success());
    assert!(
        !std::fs::read_to_string(&cfg_path)
            .unwrap()
            .contains("my-vps")
    );

    // 6. Multi-provider `rclone.conf` import covering `webdav`, `sftp`, `onedrive`!
    let rclone_conf = tmp.path().join("rclone.conf");
    std::fs::write(
        &rclone_conf,
        r#"
[rc-dav]
type = webdav
url = https://dav.example.com/files
vendor = nextcloud
user = bob
pass = secret

[rc-sftp]
type = sftp
host = 192.168.1.10
port = 22
user = ops
pass = sshpw

[rc-od]
type = onedrive
client_id = cid-od
drive_id = drv-123
"#,
    )
    .unwrap();

    let imp = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "config",
            "import-rclone",
            rclone_conf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        imp.status.success(),
        "multi-provider rclone import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );
    let cfg_final = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_final.contains("[remotes.rc-dav]"));
    assert!(cfg_final.contains("[remotes.rc-sftp]"));
    assert!(cfg_final.contains("[remotes.rc-od]"));
}

#[test]
fn cli_auth_export_import_redact_and_rclone_import_for_dropbox_gcs_azureblob_and_s3_presets() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");

    // 1. Configure Dropbox, GCS (anonymous + static token), Azure Blob (SharedKey + Azurite),
    //    and newly added S3 presets (Wasabi, Tigris, Tencent COS).
    let commands: &[&[&str]] = &[
        &[
            "auth",
            "dropbox",
            "my-dbx",
            "--access-token",
            "DBX_SECRET_TOKEN_111",
            "--root-path",
            "/backups",
        ],
        &[
            "auth",
            "gcs",
            "my-gcs",
            "--bucket",
            "prod-gcs",
            "--access-token",
            "GCS_SECRET_TOKEN_222",
            "--storage-class",
            "NEARLINE",
        ],
        &[
            "auth",
            "gcs",
            "pub-gcs",
            "--bucket",
            "public-dataset",
            "--anonymous",
        ],
        &[
            "auth",
            "azureblob",
            "my-az",
            "--account",
            "myprodacct",
            "--container",
            "archive",
            "--key",
            "AZ_SECRET_KEY_333",
            "--access-tier",
            "Cool",
        ],
        &[
            "auth",
            "azureblob",
            "az-emu",
            "--use-emulator",
            "--container",
            "dev",
        ],
        &[
            "auth",
            "s3",
            "my-wasabi",
            "--provider",
            "wasabi",
            "--bucket",
            "w-bkt",
            "--region",
            "us-east-1",
            "--access-key-id",
            "ak-w",
            "--secret-access-key",
            "WASABI_SECRET_444",
        ],
        &[
            "auth",
            "s3",
            "my-tigris",
            "--provider",
            "tigris",
            "--bucket",
            "t-bkt",
            "--access-key-id",
            "ak-t",
            "--secret-access-key",
            "TIGRIS_SECRET_555",
        ],
        &[
            "auth",
            "s3",
            "my-cos",
            "--provider",
            "cos",
            "--bucket",
            "c-bkt",
            "--region",
            "ap-shanghai",
            "--access-key-id",
            "ak-c",
            "--secret-access-key",
            "COS_SECRET_666",
        ],
    ];

    for args in commands {
        let out = Command::new(rship_bin())
            .args([
                "--config",
                cfg_path.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
            ])
            .args(*args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "command `{args:?}` failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // 2. Verify `config show` redacts every single secret across all new providers!
    let show = Command::new(rship_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "config", "show"])
        .output()
        .unwrap();
    assert!(show.status.success());
    let shown = String::from_utf8(show.stdout).unwrap();
    for secret in [
        "DBX_SECRET_TOKEN_111",
        "GCS_SECRET_TOKEN_222",
        "AZ_SECRET_KEY_333",
        "WASABI_SECRET_444",
        "TIGRIS_SECRET_555",
        "COS_SECRET_666",
    ] {
        assert!(
            !shown.contains(secret),
            "secret `{secret}` leaked in `config show`!"
        );
    }
    assert!(shown.contains("***REDACTED***"));

    // 3. Verify `auth export` -> `auth import` portable bundle roundtrip for Dropbox, GCS, AzureBlob!
    let cfg2 = tmp.path().join("cfg2.toml");
    let state2 = tmp.path().join("state2");
    for (src_name, dst_name) in [
        ("my-dbx", "dbx-imported"),
        ("my-gcs", "gcs-imported"),
        ("my-az", "az-imported"),
    ] {
        let exp = Command::new(rship_bin())
            .args([
                "--config",
                cfg_path.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
                "auth",
                "export",
                src_name,
            ])
            .output()
            .unwrap();
        assert!(
            exp.status.success(),
            "export `{src_name}` failed: {}",
            String::from_utf8_lossy(&exp.stderr)
        );
        let bundle = String::from_utf8(exp.stdout).unwrap().trim().to_string();
        assert!(bundle.starts_with("rship-remote-v1:"));

        let imp = Command::new(rship_bin())
            .args([
                "--config",
                cfg2.to_str().unwrap(),
                "--state-dir",
                state2.to_str().unwrap(),
                "auth",
                "import",
                "--bundle",
                &bundle,
                "--name",
                dst_name,
            ])
            .output()
            .unwrap();
        assert!(
            imp.status.success(),
            "import `{dst_name}` failed: {}",
            String::from_utf8_lossy(&imp.stderr)
        );
    }
    let cfg2_txt = std::fs::read_to_string(&cfg2).unwrap();
    assert!(cfg2_txt.contains("[remotes.dbx-imported]"));
    assert!(cfg2_txt.contains("[remotes.gcs-imported]"));
    assert!(cfg2_txt.contains("[remotes.az-imported]"));

    // 4. Multi-provider `rclone.conf` import covering Dropbox, GCS, AzureBlob, Wasabi, DO Spaces, Hetzner!
    let rclone_conf = tmp.path().join("rclone_all.conf");
    std::fs::write(
        &rclone_conf,
        r#"
[rc-dbx]
type = dropbox
client_id = dbx-app-key
token = {"access_token":"sl.tok","token_type":"bearer","refresh_token":"ref-dbx","expiry":"2026-12-01T00:00:00Z"}

[rc-gcs]
type = google cloud storage
project_number = 987654321
anonymous = true

[rc-az]
type = azureblob
account = rcazacct
key = dGVzdGtleQ==
access_tier = Hot

[rc-wasabi]
type = s3
provider = Wasabi
access_key_id = wak
secret_access_key = wsk
region = eu-central-1

[rc-do]
type = s3
provider = DigitalOcean
access_key_id = doak
secret_access_key = dosk
region = nyc3

[rc-hetzner]
type = s3
provider = Hetzner
access_key_id = hak
secret_access_key = hsk
region = fsn1
"#,
    )
    .unwrap();

    let imp = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "config",
            "import-rclone",
            rclone_conf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        imp.status.success(),
        "rclone import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );
    let final_cfg = std::fs::read_to_string(&cfg_path).unwrap();
    for name in [
        "rc-dbx",
        "rc-gcs",
        "rc-az",
        "rc-wasabi",
        "rc-do",
        "rc-hetzner",
    ] {
        assert!(
            final_cfg.contains(&format!("[remotes.{name}]")),
            "expected `[remotes.{name}]` in imported config:\n{final_cfg}"
        );
    }
    assert!(
        state_dir.join("tokens/rc-dbx.dropbox.json").exists(),
        "expected imported Dropbox token sidecar file"
    );
}

#[cfg(feature = "all-backends")]
#[test]
fn cli_interactive_auth_wizards_config_manager_and_non_interactive_fail_fast() {
    use std::io::Write;
    use std::process::Stdio;

    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let local_root = tmp.path().join("local_root");
    std::fs::create_dir_all(&local_root).unwrap();

    let run_interactive = |args: &[&str], stdin_script: &str| {
        let mut child = Command::new(rship_bin())
            .env("RSHIP_FORCE_INTERACTIVE", "1")
            .args([
                "--config",
                cfg_path.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_script.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    // 1. Non-interactive fail-fast when required arguments are omitted or OAuth requires a browser
    for bad_args in [
        &["auth"][..],
        &["auth", "s3", "empty-s3"][..],
        &["auth", "webdav", "empty-dav"][..],
        &[
            "auth",
            "webdav",
            "no-pw-dav",
            "--url",
            "https://dav.example.com",
            "--username",
            "alice",
        ][..],
        &["auth", "sftp", "empty-ssh"][..],
        &["auth", "crypt", "empty-vault"][..],
        &[
            "auth",
            "crypt",
            "bad-salt",
            "--target",
            local_root.to_str().unwrap(),
            "--password",
            "pw",
            "--salt",
            "short",
        ][..],
        &["auth", "azureblob", "empty-az"][..],
        &["auth", "azureblob", "no-key-az", "--account", "myacct"][..],
        &["auth", "azureblob", "no-acct-anon", "--anonymous"][..],
        &["auth", "gcs", "empty-gcs"][..],
        &[
            "auth",
            "gdrive",
            "ni-gd",
            "--client-id",
            "cid",
            "--client-secret",
            "sec",
        ][..],
        &[
            "auth",
            "gdrive",
            "ni-gd-man",
            "--client-id",
            "cid",
            "--client-secret",
            "sec",
            "--manual",
        ][..],
        &["auth", "onedrive", "ni-od", "--client-id", "cid"][..],
        &["auth", "dropbox", "ni-dbx", "--client-id", "cid"][..],
    ] {
        let out = Command::new(rship_bin())
            .args([
                "--non-interactive",
                "--config",
                cfg_path.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
            ])
            .args(bad_args)
            .output()
            .unwrap();
        assert!(
            !out.status.success(),
            "expected non-interactive `{bad_args:?}` to fail fast"
        );
    }

    // 2. Interactive `rship auth s3` (no remote name, no flags!) -> Cloudflare R2 preset!
    // Prompts:
    //   Remote name -> my-r2
    //   Provider preset -> 2 (Cloudflare R2)
    //   Auth method -> 1 (Static keys)
    //   Access Key ID -> r2-ak-123
    //   Secret Access Key -> r2-sk-secret
    //   Region -> (Enter -> default "auto")
    //   Custom endpoint -> bad-url (inline error!), then https://acct.r2.cloudflarestorage.com
    //   Default bucket -> backups
    //   Advanced options? -> n
    //   Store in OS Keyring? -> n (deterministic in CI)
    //   Test connection now? -> n
    let s3_out = run_interactive(
        &["auth", "s3"],
        "my-r2\n2\n1\nr2-ak-123\nr2-sk-secret\n\nbad-url\nhttps://acct.r2.cloudflarestorage.com\nbackups\nn\nn\nn\n",
    );
    assert!(
        s3_out.status.success(),
        "interactive s3 failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&s3_out.stdout),
        String::from_utf8_lossy(&s3_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.my-r2]"), "{cfg_txt}");
    assert!(cfg_txt.contains("provider = \"r2\""), "{cfg_txt}");
    assert!(cfg_txt.contains("region = \"auto\""), "{cfg_txt}");
    assert!(
        cfg_txt.contains("endpoint = \"https://acct.r2.cloudflarestorage.com\""),
        "{cfg_txt}"
    );
    assert!(
        cfg_txt.contains("access_key_id = \"r2-ak-123\""),
        "{cfg_txt}"
    );
    assert!(
        cfg_txt.contains("secret_access_key = \"r2-sk-secret\""),
        "{cfg_txt}"
    );
    assert!(cfg_txt.contains("bucket = \"backups\""), "{cfg_txt}");

    // 2b. Re-running `rship auth s3 my-r2 --bucket archive` non-interactively MUST preserve
    //     existing endpoint, region, and credentials instead of wiping them!
    let s3_merge = Command::new(rship_bin())
        .args([
            "--non-interactive",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "s3",
            "my-r2",
            "--bucket",
            "archive",
        ])
        .output()
        .unwrap();
    assert!(
        s3_merge.status.success(),
        "s3 merge update failed: {}",
        String::from_utf8_lossy(&s3_merge.stderr)
    );
    let cfg_after_merge = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_after_merge.contains("bucket = \"archive\""));
    assert!(cfg_after_merge.contains("provider = \"r2\""));
    assert!(cfg_after_merge.contains("secret_access_key = \"r2-sk-secret\""));
    assert!(cfg_after_merge.contains("https://acct.r2.cloudflarestorage.com"));

    // 3. Interactive `rship auth webdav my-nc` -> Nextcloud + Basic Auth
    // Prompts: vendor=1(Nextcloud), url=https://cloud.example.com/remote.php/dav/files/alice,
    //          auth=1(Basic), user=alice, pass=app-pass, chunked?=n, keyring?=n, test?=n
    let dav_out = run_interactive(
        &["auth", "webdav", "my-nc"],
        "1\nhttps://cloud.example.com/remote.php/dav/files/alice\n1\nalice\napp-pass\nn\nn\nn\n",
    );
    assert!(
        dav_out.status.success(),
        "interactive webdav failed:\n{}",
        String::from_utf8_lossy(&dav_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.my-nc]"));
    assert!(cfg_txt.contains("vendor = \"nextcloud\""));
    assert!(cfg_txt.contains("username = \"alice\""));

    // 4. Interactive `rship auth azureblob my-emu` -> Azurite emulator (choice 3)
    // Prompts: mode=3(Azurite), container=dev, advanced?=n, keyring?=n, test?=n
    let az_out = run_interactive(&["auth", "azureblob", "my-emu"], "3\ndev\nn\nn\nn\n");
    assert!(
        az_out.status.success(),
        "interactive azureblob failed:\n{}",
        String::from_utf8_lossy(&az_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.my-emu]"));
    assert!(cfg_txt.contains("account = \"devstoreaccount1\""));
    assert!(cfg_txt.contains("container = \"dev\""));

    // 5. Interactive `rship auth gcs pub-gcs` -> Anonymous (choice 3)
    // Prompts: mode=3(Anonymous), bucket=open-data, advanced?=n, test?=n (no secrets -> no keyring prompt!)
    let gcs_out = run_interactive(&["auth", "gcs", "pub-gcs"], "3\nopen-data\nn\nn\n");
    assert!(
        gcs_out.status.success(),
        "interactive gcs failed:\n{}",
        String::from_utf8_lossy(&gcs_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.pub-gcs]"));
    assert!(cfg_txt.contains("anonymous = true"));
    assert!(cfg_txt.contains("bucket = \"open-data\""));

    // 6. Interactive `rship config new local my-local` + immediate live connectivity test (`y`)!
    // Prompts: root=<local_root>, test?=y (no inline secrets -> no keyring prompt!)
    let local_script = format!("{}\ny\n", local_root.display());
    let loc_out = run_interactive(&["config", "new", "local", "my-local"], &local_script);
    assert!(
        loc_out.status.success(),
        "interactive local failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&loc_out.stdout),
        String::from_utf8_lossy(&loc_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&loc_out.stdout).contains("my-local"),
        "expected connectivity test output on stdout"
    );

    // 7. Interactive `rship auth crypt my-vault` -> selects `my-local:` from existing remotes,
    //    sets subpath `enc`, tests passphrase mismatch re-prompt + matching confirmation,
    //    skips salt, selects standard filename encryption, declines keyring, runs live test (`y`)!
    // Existing remotes (BTreeMap alphabetical): my-emu(1), my-local(2), my-nc(3), my-r2(4), pub-gcs(5)
    let crypt_out = run_interactive(
        &["auth", "crypt", "my-vault"],
        "2\nenc\n1\nfirst-pass\nwrong-confirm\nstrong-passphrase\nstrong-passphrase\nn\n1\nn\ny\n",
    );
    assert!(
        crypt_out.status.success(),
        "interactive crypt failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&crypt_out.stdout),
        String::from_utf8_lossy(&crypt_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.my-vault]"));
    assert!(cfg_txt.contains("remote = \"my-local:enc\""));
    assert!(cfg_txt.contains("password = \"strong-passphrase\""));

    // 8. Interactive `rship auth crypt rand-vault --target <dir>` with generated 256-bit random key!
    // Prompts: key mode=2(Generate random 256-bit key), keyring?=n, test?=y
    // Wait: since --target was passed, only key material is prompted (not full_wizard)!
    let rand_dir = tmp.path().join("rand_vault");
    std::fs::create_dir_all(&rand_dir).unwrap();
    let rand_out = run_interactive(
        &[
            "auth",
            "crypt",
            "rand-vault",
            "--target",
            rand_dir.to_str().unwrap(),
        ],
        "2\nn\ny\n",
    );
    assert!(
        rand_out.status.success(),
        "interactive random-key crypt failed:\n{}",
        String::from_utf8_lossy(&rand_out.stderr)
    );
    let cfg_txt = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_txt.contains("[remotes.rand-vault]"));
    assert!(cfg_txt.contains("key_hex = \""));

    // 9. `rship config list --json` returns structured inventory of all configured remotes!
    let list_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "config",
            "list",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_json: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let arr = list_json.as_array().unwrap();
    assert_eq!(arr.len(), 7, "expected 7 configured remotes: {list_json}");

    // 10. Interactive `rship config edit my-r2` keeps existing secret & changes bucket -> `edited-bkt`!
    // Prompts: provider=(Enter keep r2), auth=1(Static), ak=(Enter keep), sk=(Enter keep existing),
    //          region=(Enter keep auto), endpoint=(Enter keep), bucket=edited-bkt,
    //          advanced?=n, keyring?=n, test?=n
    let edit_out = run_interactive(
        &["config", "edit", "my-r2"],
        "\n1\n\n\n\n\nedited-bkt\nn\nn\nn\n",
    );
    assert!(
        edit_out.status.success(),
        "interactive config edit failed:\n{}",
        String::from_utf8_lossy(&edit_out.stderr)
    );
    let cfg_edited = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_edited.contains("bucket = \"edited-bkt\""));
    assert!(cfg_edited.contains("secret_access_key = \"r2-sk-secret\""));

    // 11. Interactive `rship config` menu: pick Test(3) -> my-local(2) -> Quit(8)!
    // Menu options when remotes + inline secrets exist:
    //   1: Add, 2: Edit, 3: Test, 4: Remove, 5: Import rclone, 6: Keyring migrate, 7: Show, 8: Quit
    // Remotes alphabetical: my-emu(1), my-local(2), my-nc(3), my-r2(4), my-vault(5), pub-gcs(6), rand-vault(7)
    let menu_out = run_interactive(&["config"], "3\n2\n8\n");
    assert!(
        menu_out.status.success(),
        "interactive config menu failed:\nSTDOUT:\n{}\nSTDERR:\n{}",
        String::from_utf8_lossy(&menu_out.stdout),
        String::from_utf8_lossy(&menu_out.stderr)
    );
    assert!(String::from_utf8_lossy(&menu_out.stdout).contains("my-local"));

    // 12. Auth-mode switching clears superseded credentials so `factory.rs` honors the new mode!
    // 12a. S3 static keys -> `--env-auth` clears `access_key_id` & `secret_access_key`
    let s3_env_switch = Command::new(rship_bin())
        .args([
            "--non-interactive",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "s3",
            "my-r2",
            "--env-auth",
        ])
        .output()
        .unwrap();
    assert!(s3_env_switch.status.success());
    let cfg_s3_env = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_s3_env.contains("env_auth = true"));
    assert!(!cfg_s3_env.contains("r2-ak-123"));
    assert!(!cfg_s3_env.contains("r2-sk-secret"));

    // 12b. Pre-seed an OAuth OneDrive remote + token file, switch to Static Token,
    //      verify `client_id` & sidecar token file are cleared, then update `--drive-id` non-interactively!
    std::fs::create_dir_all(state_dir.join("tokens")).unwrap();
    let od_tok_file = state_dir.join("tokens/switch-od.onedrive.json");
    std::fs::write(
        &od_tok_file,
        r#"{"access_token":"old","refresh_token":"ref","token_type":"Bearer","expires_at_unix_secs":1999999999}"#,
    )
    .unwrap();
    {
        let mut raw = std::fs::read_to_string(&cfg_path).unwrap();
        raw.push_str(
            "\n[remotes.switch-od]\ntype = \"onedrive\"\nclient_id = \"old-od-cid\"\nclient_secret = \"old-od-sec\"\n",
        );
        std::fs::write(&cfg_path, raw).unwrap();
    }
    let od_switch = Command::new(rship_bin())
        .args([
            "--non-interactive",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "onedrive",
            "switch-od",
            "--access-token",
            "NEW_STATIC_OD_TOK",
        ])
        .output()
        .unwrap();
    assert!(
        od_switch.status.success(),
        "onedrive switch failed: {}",
        String::from_utf8_lossy(&od_switch.stderr)
    );
    assert!(
        !od_tok_file.exists(),
        "stale OneDrive OAuth token file must be cleaned up when switching to static token"
    );
    let cfg_od = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(!cfg_od.contains("old-od-cid"));
    assert!(!cfg_od.contains("old-od-sec"));
    assert!(cfg_od.contains("NEW_STATIC_OD_TOK"));

    // Non-interactive metadata-only update (`--drive-id`) on static-token OneDrive must succeed!
    let od_meta = Command::new(rship_bin())
        .args([
            "--non-interactive",
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "onedrive",
            "switch-od",
            "--drive-id",
            "b!Drive999",
        ])
        .output()
        .unwrap();
    assert!(
        od_meta.status.success(),
        "onedrive metadata update failed: {}",
        String::from_utf8_lossy(&od_meta.stderr)
    );
    let cfg_od2 = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(cfg_od2.contains("drive_id = \"b!Drive999\""));
    assert!(cfg_od2.contains("NEW_STATIC_OD_TOK"));

    // 13. Password leading/trailing whitespace preservation + clearing optional field with `-`!
    let space_dir = tmp.path().join("space_vault");
    std::fs::create_dir_all(&space_dir).unwrap();
    let space_out = run_interactive(
        &[
            "auth",
            "crypt",
            "space-vault",
            "--target",
            space_dir.to_str().unwrap(),
        ],
        "1\n  padded secret  \n  padded secret  \nn\nn\nn\n",
    );
    assert!(
        space_out.status.success(),
        "whitespace password crypt failed:\n{}",
        String::from_utf8_lossy(&space_out.stderr)
    );
    let cfg_space = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        cfg_space.contains("password = \"  padded secret  \""),
        "leading/trailing spaces in password must be preserved:\n{cfg_space}"
    );

    // Clear `bucket` on `my-r2` with `-` in `rship config edit my-r2`
    let clear_bkt = run_interactive(&["config", "edit", "my-r2"], "\n2\n\n\n-\nn\nn\n");
    assert!(
        clear_bkt.status.success(),
        "clearing bucket with `-` failed:\n{}",
        String::from_utf8_lossy(&clear_bkt.stderr)
    );
    let cfg_cleared = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(
        !cfg_cleared.contains("edited-bkt"),
        "expected bucket cleared with `-`:\n{cfg_cleared}"
    );

    // 14. `rship config new` refuses to silently overwrite an existing remote when user answers `n`!
    let no_overwrite = run_interactive(&["config", "new", "local", "my-local"], "n\n");
    assert!(
        !no_overwrite.status.success(),
        "config new must abort when user declines overwriting existing remote"
    );
}
