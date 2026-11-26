mod auth_and_config;
mod combinations_and_scenarios;
mod mock_http;
mod provider_wire_and_fs;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

pub(crate) fn rship_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rship")
}

pub(crate) struct CliHarness {
    pub(crate) tmp: TempDir,
    pub(crate) cfg_path: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) home_dir: PathBuf,
}

impl CliHarness {
    pub(crate) fn new() -> Self {
        let tmp = TempDir::new().expect("create tempdir");
        let cfg_path = tmp.path().join("config.toml");
        let state_dir = tmp.path().join("state");
        let home_dir = tmp.path().join("home");
        std::fs::create_dir_all(&state_dir).expect("create state_dir");
        std::fs::create_dir_all(&home_dir).expect("create home_dir");
        Self {
            tmp,
            cfg_path,
            state_dir,
            home_dir,
        }
    }

    pub(crate) fn path(&self) -> &Path {
        self.tmp.path()
    }

    pub(crate) fn cmd(&self) -> Command {
        let mut cmd = Command::new(rship_bin());
        cmd.args([
            "--config",
            self.cfg_path.to_str().expect("utf8 cfg_path"),
            "--state-dir",
            self.state_dir.to_str().expect("utf8 state_dir"),
        ]);
        cmd.env_remove("RSHIP_CONFIG")
            .env_remove("RSHIP_STATE_DIR")
            .env_remove("RSHIP_CRYPT_PASSWORD")
            .env_remove("RCLONE_CONFIG")
            .env_remove("RSHIP_FORCE_INTERACTIVE")
            .env_remove("RSHIP_NON_INTERACTIVE")
            .env_remove("GOOGLE_APPLICATION_CREDENTIALS")
            .env_remove("AWS_ACCESS_KEY_ID")
            .env_remove("AWS_SECRET_ACCESS_KEY")
            .env_remove("AWS_SESSION_TOKEN")
            .env_remove("AWS_PROFILE")
            .env_remove("AZURE_STORAGE_ACCOUNT")
            .env_remove("AZURE_STORAGE_KEY")
            .env_remove("AZURE_STORAGE_SAS_TOKEN")
            .env("HOME", &self.home_dir)
            .env("USERPROFILE", &self.home_dir);
        cmd
    }

    pub(crate) fn run_non_interactive(&self, args: &[&str]) -> Output {
        let mut cmd = self.cmd();
        cmd.arg("--non-interactive").args(args);
        cmd.output().expect("spawn rship non-interactive")
    }

    pub(crate) fn run_interactive(&self, args: &[&str], stdin_script: &str) -> Output {
        let mut child = self
            .cmd()
            .env("RSHIP_FORCE_INTERACTIVE", "1")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rship interactive");
        {
            let stdin = child.stdin.as_mut().expect("stdin piped");
            stdin
                .write_all(stdin_script.as_bytes())
                .expect("write stdin script");
        }
        child.wait_with_output().expect("wait interactive child")
    }

    pub(crate) fn run_with_stdin(&self, args: &[&str], stdin_bytes: &[u8]) -> Output {
        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rship with stdin");
        {
            let stdin = child.stdin.as_mut().expect("stdin piped");
            stdin.write_all(stdin_bytes).expect("write stdin bytes");
        }
        child.wait_with_output().expect("wait child")
    }

    pub(crate) fn write_config(&self, content: &str) {
        std::fs::write(&self.cfg_path, content).expect("write config.toml");
    }

    pub(crate) fn append_config(&self, content: &str) {
        let mut existing = std::fs::read_to_string(&self.cfg_path).unwrap_or_default();
        if !existing.is_empty() && !existing.ends_with('\n') {
            existing.push('\n');
        }
        existing.push_str(content);
        std::fs::write(&self.cfg_path, existing).expect("append config.toml");
    }

    pub(crate) fn read_config(&self) -> String {
        std::fs::read_to_string(&self.cfg_path).unwrap_or_default()
    }

    pub(crate) fn parse_config_toml(&self) -> toml::Value {
        let raw = self.read_config();
        toml::from_str(&raw).unwrap_or_else(|e| panic!("invalid config.toml ({e}):\n{raw}"))
    }

    pub(crate) fn parse_json_stdout(out: &Output) -> serde_json::Value {
        let stdout = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "expected JSON on stdout ({e}):\nSTDOUT:\n{stdout}\nSTDERR:\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        })
    }

    pub(crate) fn assert_ok(out: &Output, label: &str) {
        assert!(
            out.status.success(),
            "{label} failed (code={:?}):\nSTDOUT:\n{}\nSTDERR:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

pub(crate) fn s3_toml(name: &str, port: u16, provider: &str, sse_kms: bool) -> String {
    let mut s = format!(
        "[remotes.{name}]\ntype = \"s3\"\nprovider = \"{provider}\"\nbucket = \"test-bucket\"\nregion = \"us-east-1\"\nendpoint = \"http://127.0.0.1:{port}\"\naccess_key_id = \"AKIA_TEST\"\nsecret_access_key = \"SECRET_TEST\"\nforce_path_style = true\n"
    );
    if sse_kms {
        s.push_str("sse = \"aws:kms\"\nkms_key_id = \"alias/test-key\"\n");
    }
    s
}

pub(crate) fn gcs_toml(name: &str, port: u16) -> String {
    format!(
        "[remotes.{name}]\ntype = \"gcs\"\nbucket = \"test-bucket\"\napi_base_url = \"http://127.0.0.1:{port}/storage/v1\"\nupload_base_url = \"http://127.0.0.1:{port}/upload/storage/v1\"\ntoken_url = \"http://127.0.0.1:{port}/oauth2/token\"\naccess_token = \"gcs-test-token\"\n"
    )
}

pub(crate) fn azure_toml(name: &str, port: u16) -> String {
    format!(
        "[remotes.{name}]\ntype = \"azureblob\"\naccount = \"rshiptestacct\"\ncontainer = \"test-container\"\nendpoint = \"http://127.0.0.1:{port}\"\nsas_url = \"sv=2023-11-03&ss=b&srt=co&sp=rwdlac&sig=valid-mock-sas\"\n"
    )
}

pub(crate) fn gdrive_toml(name: &str, port: u16, use_trash: Option<bool>) -> String {
    let mut s = format!(
        "[remotes.{name}]\ntype = \"gdrive\"\napi_base_url = \"http://127.0.0.1:{port}/drive/v3\"\nupload_base_url = \"http://127.0.0.1:{port}/upload/drive/v3\"\ntoken_url = \"http://127.0.0.1:{port}/oauth2/token\"\nuse_changes_feed = false\naccess_token = \"gd-test-token\"\n"
    );
    if let Some(ut) = use_trash {
        s.push_str(&format!("use_trash = {ut}\n"));
    }
    s
}

pub(crate) fn onedrive_toml(name: &str, port: u16) -> String {
    format!(
        "[remotes.{name}]\ntype = \"onedrive\"\napi_base_url = \"http://127.0.0.1:{port}/v1.0\"\ntoken_url = \"http://127.0.0.1:{port}/oauth2/v2.0/token\"\naccess_token = \"od-test-token\"\n"
    )
}

pub(crate) fn dropbox_toml(name: &str, port: u16) -> String {
    format!(
        "[remotes.{name}]\ntype = \"dropbox\"\napi_base_url = \"http://127.0.0.1:{port}/2\"\ncontent_base_url = \"http://127.0.0.1:{port}/2\"\ntoken_url = \"http://127.0.0.1:{port}/oauth2/token\"\naccess_token = \"dbx-test-token\"\n"
    )
}

pub(crate) fn webdav_toml(name: &str, port: u16, vendor: &str) -> String {
    format!(
        "[remotes.{name}]\ntype = \"webdav\"\nurl = \"http://127.0.0.1:{port}/remote.php/dav/files/alice\"\nvendor = \"{vendor}\"\nusername = \"alice\"\npassword = \"secret\"\nchunked_upload_root = \"http://127.0.0.1:{port}/remote.php/dav/uploads/alice\"\n"
    )
}

pub(crate) fn crypt_toml(name: &str, inner_target: &str) -> String {
    format!(
        "[remotes.{name}]\ntype = \"crypt\"\nremote = \"{inner_target}\"\nkey_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n"
    )
}
