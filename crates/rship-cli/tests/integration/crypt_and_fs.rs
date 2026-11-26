use crate::rship_bin;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_crypt_stream_oae2_bisync_and_bwlimit_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");

    // 1. Configure STREAM OAE2 `crypt` remote wrapping a local vault directory!
    let vault_dir = tmp.path().join("vault_raw");
    let plain_src = tmp.path().join("plain_src");
    let restored = tmp.path().join("restored");
    std::fs::create_dir_all(&vault_dir).unwrap();
    std::fs::create_dir_all(plain_src.join("docs")).unwrap();
    std::fs::create_dir_all(&restored).unwrap();
    let secret_payload: Vec<u8> = (0..150_000).map(|i| (i % 251) as u8).collect();
    std::fs::write(plain_src.join("docs/confidential.bin"), &secret_payload).unwrap();

    let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let out_crypt = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "crypt",
            "vault",
            "--target",
            vault_dir.to_str().unwrap(),
            "--key-hex",
            key_hex,
        ])
        .output()
        .unwrap();
    assert!(
        out_crypt.status.success(),
        "auth crypt failed: {}",
        String::from_utf8_lossy(&out_crypt.stderr)
    );

    // Copy plaintext -> `vault:` with `--bwlimit 5M`
    let out_enc = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            plain_src.to_str().unwrap(),
            "vault:",
            "--bwlimit",
            "5M",
        ])
        .output()
        .unwrap();
    assert!(
        out_enc.status.success(),
        "copy to crypt failed: {}",
        String::from_utf8_lossy(&out_enc.stderr)
    );
    // Raw directory MUST NOT contain plaintext filename!
    assert!(!vault_dir.join("docs/confidential.bin").exists());

    // `rship ls vault: -r` must list decrypted name & exact plaintext size (150000)!
    let out_ls = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "ls",
            "vault:",
            "-r",
        ])
        .output()
        .unwrap();
    assert!(out_ls.status.success());
    let ls_out = String::from_utf8_lossy(&out_ls.stdout);
    assert!(ls_out.contains("docs/confidential.bin"), "got: {ls_out}");
    assert!(ls_out.contains("150000"), "got: {ls_out}");

    // Copy `vault:` -> `restored` and verify bit-exact decryption!
    let out_dec = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            "vault:",
            restored.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out_dec.status.success(),
        "copy from crypt failed: {}",
        String::from_utf8_lossy(&out_dec.stderr)
    );
    assert_eq!(
        std::fs::read(restored.join("docs/confidential.bin")).unwrap(),
        secret_payload
    );

    // 2. Three-Tree `rship bisync` end-to-end (bidirectional propagation + keep-both conflict)!
    let dir_a = tmp.path().join("side_a");
    let dir_b = tmp.path().join("side_b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::write(dir_a.join("notes.txt"), b"v1").unwrap();
    std::fs::write(dir_b.join("from_b.txt"), b"hello-b").unwrap();

    let bs1 = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "bisync",
            dir_a.to_str().unwrap(),
            dir_b.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        bs1.status.success(),
        "bisync 1 failed: {}",
        String::from_utf8_lossy(&bs1.stderr)
    );
    assert_eq!(std::fs::read(dir_b.join("notes.txt")).unwrap(), b"v1");
    assert_eq!(std::fs::read(dir_a.join("from_b.txt")).unwrap(), b"hello-b");

    // Concurrent edit on BOTH sides!
    std::thread::sleep(std::time::Duration::from_millis(50));
    std::fs::write(dir_a.join("notes.txt"), b"edit-on-a").unwrap();
    std::fs::write(dir_b.join("notes.txt"), b"edit-on-b-different").unwrap();

    let bs2 = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "bisync",
            dir_a.to_str().unwrap(),
            dir_b.to_str().unwrap(),
            "--conflict-strategy",
            "keep-both",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        bs2.status.success(),
        "bisync 2 failed: {}",
        String::from_utf8_lossy(&bs2.stderr)
    );
    let bs2_json: serde_json::Value = serde_json::from_slice(&bs2.stdout).unwrap();
    assert_eq!(bs2_json["conflicts_resolved"], 1);
    assert_eq!(
        std::fs::read(dir_a.join("notes.txt")).unwrap(),
        b"edit-on-a"
    );
    assert_eq!(
        std::fs::read(dir_b.join("notes.txt")).unwrap(),
        b"edit-on-a"
    );
    let conflict_files: Vec<_> = std::fs::read_dir(&dir_a)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".conflict-"))
        .collect();
    assert_eq!(conflict_files.len(), 1);
    assert_eq!(
        std::fs::read(conflict_files[0].path()).unwrap(),
        b"edit-on-b-different"
    );
}

#[test]
fn cli_move_delete_purge_mkdir_cat_rcat_auth_export_and_completions() {
    use std::io::Write;
    use std::process::Stdio;

    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let vault_dir = tmp.path().join("vault_raw");
    std::fs::create_dir_all(&vault_dir).unwrap();

    // 1. Setup S3 + Crypt remotes and test universal `auth export` / `auth import`!
    let s3_setup = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "s3",
            "my-r2",
            "--provider",
            "r2",
            "--bucket",
            "prod-bkt",
            "--region",
            "auto",
            "--endpoint",
            "https://acct.r2.cloudflarestorage.com",
            "--access-key-id",
            "ak-demo",
            "--secret-access-key",
            "sk-demo",
        ])
        .output()
        .unwrap();
    assert!(s3_setup.status.success());

    let key_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let crypt_setup = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "crypt",
            "vault",
            "--target",
            vault_dir.to_str().unwrap(),
            "--key-hex",
            key_hex,
        ])
        .output()
        .unwrap();
    assert!(crypt_setup.status.success());

    let exp_s3 = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "export",
            "my-r2",
        ])
        .output()
        .unwrap();
    assert!(exp_s3.status.success());
    let s3_bundle = String::from_utf8(exp_s3.stdout).unwrap().trim().to_string();
    assert!(s3_bundle.starts_with("rship-remote-v1:"));

    let exp_crypt = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "export",
            "vault",
        ])
        .output()
        .unwrap();
    assert!(exp_crypt.status.success());
    let crypt_bundle = String::from_utf8(exp_crypt.stdout)
        .unwrap()
        .trim()
        .to_string();
    assert!(crypt_bundle.starts_with("rship-remote-v1:"));

    let cfg2 = tmp.path().join("cfg2.toml");
    let state2 = tmp.path().join("state2");
    for (bundle, name) in [(&s3_bundle, "r2-copy"), (&crypt_bundle, "vault-copy")] {
        let imp = Command::new(rship_bin())
            .args([
                "--config",
                cfg2.to_str().unwrap(),
                "--state-dir",
                state2.to_str().unwrap(),
                "auth",
                "import",
                "--bundle",
                bundle,
                "--name",
                name,
            ])
            .output()
            .unwrap();
        assert!(
            imp.status.success(),
            "import `{name}` failed: {}",
            String::from_utf8_lossy(&imp.stderr)
        );
    }
    let cfg2_txt = std::fs::read_to_string(&cfg2).unwrap();
    assert!(cfg2_txt.contains("[remotes.r2-copy]"));
    assert!(cfg2_txt.contains("[remotes.vault-copy]"));

    // 2. `rship mkdir` + `rship rcat` (stdin -> encrypted `vault:`) + `rship cat --offset --count`!
    let mk = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "mkdir",
            "vault:pipes",
        ])
        .output()
        .unwrap();
    assert!(mk.status.success());

    let mut rcat_child = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "rcat",
            "vault:pipes/stream.txt",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    rcat_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"0123456789ABCDEF-secret-stream!")
        .unwrap();
    let rcat_out = rcat_child.wait_with_output().unwrap();
    assert!(
        rcat_out.status.success(),
        "rcat failed: {}",
        String::from_utf8_lossy(&rcat_out.stderr)
    );

    let cat_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "cat",
            "vault:pipes/stream.txt",
            "--offset",
            "10",
            "--count",
            "6",
        ])
        .output()
        .unwrap();
    assert!(
        cat_out.status.success(),
        "cat failed: {}",
        String::from_utf8_lossy(&cat_out.stderr)
    );
    assert_eq!(cat_out.stdout, b"ABCDEF");

    // 3. `rship move` with `--strict-source` and `--delete-empty-src-dirs`!
    let mv_src = tmp.path().join("mv_src");
    let mv_dst = tmp.path().join("mv_dst");
    std::fs::create_dir_all(mv_src.join("nested")).unwrap();
    std::fs::create_dir_all(&mv_dst).unwrap();
    std::fs::write(mv_src.join("nested/data.txt"), b"moved-payload").unwrap();

    let mv_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "move",
            mv_src.to_str().unwrap(),
            mv_dst.to_str().unwrap(),
            "--strict-source",
            "--delete-empty-src-dirs",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        mv_out.status.success(),
        "move failed: {}",
        String::from_utf8_lossy(&mv_out.stderr)
    );
    let mv_json: serde_json::Value = serde_json::from_slice(&mv_out.stdout).unwrap();
    assert_eq!(mv_json["files_transferred"], 1);
    assert_eq!(mv_json["sources_deleted"], 1);
    assert_eq!(
        std::fs::read(mv_dst.join("nested/data.txt")).unwrap(),
        b"moved-payload"
    );
    assert!(!mv_src.join("nested/data.txt").exists());
    assert!(
        !mv_src.join("nested").exists(),
        "empty source dir must be pruned"
    );

    // 4. `rship delete` (filtered) + `rship purge`!
    std::fs::write(mv_dst.join("nested/keep.log"), b"keep").unwrap();
    std::fs::write(mv_dst.join("nested/drop.tmp"), b"drop").unwrap();
    let del_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "delete",
            mv_dst.to_str().unwrap(),
            "--include",
            "*.tmp",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(del_out.status.success());
    assert!(!mv_dst.join("nested/drop.tmp").exists());
    assert!(mv_dst.join("nested/keep.log").exists());

    let purge_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "purge",
            mv_dst.join("nested").to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(purge_out.status.success());
    assert!(!mv_dst.join("nested/keep.log").exists());

    // 5. `rship completions` generates valid shell completion scripts!
    for shell in ["bash", "powershell"] {
        let comp = Command::new(rship_bin())
            .args(["completions", shell])
            .output()
            .unwrap();
        assert!(comp.status.success());
        let script = String::from_utf8_lossy(&comp.stdout);
        assert!(
            script.contains("rship"),
            "completion for {shell} missing command name"
        );
    }
}

#[test]
fn cli_dogfood_regressions_single_file_ops_crypt_subprefix_and_bisync_resync() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");

    // 1. Configure a local remote + a `crypt` remote targeting a SUB-PREFIX (`local-raw:nested/vault`)!
    let raw_root = tmp.path().join("raw_root");
    std::fs::create_dir_all(&raw_root).unwrap();
    std::fs::write(
        &cfg_path,
        format!(
            "[remotes.local-raw]\ntype = \"local\"\nroot = {:?}\n",
            raw_root.to_string_lossy()
        ),
    )
    .unwrap();

    let auth_crypt = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "crypt",
            "subvault",
            "--target",
            "local-raw:nested/vault",
            "--key-hex",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ])
        .output()
        .unwrap();
    assert!(auth_crypt.status.success());

    let sample = tmp.path().join("hello world.txt");
    std::fs::write(&sample, b"123456789").unwrap();

    let cp_vault = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copyto",
            sample.to_str().unwrap(),
            "subvault:docs/item.txt",
        ])
        .output()
        .unwrap();
    assert!(cp_vault.status.success());

    // Ciphertexts MUST live inside `raw_root/nested/vault/`, NOT encrypted at `raw_root`!
    assert!(
        raw_root.join("nested/vault").is_dir(),
        "expected plaintext sub-prefix `nested/vault` on inner backend"
    );
    let root_entries: Vec<_> = std::fs::read_dir(&raw_root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(root_entries, vec!["nested".to_string()]);

    // `ls subvault: -r` must display `docs/item.txt` (without `nested/vault/` prefix!).
    let ls_vault = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "ls",
            "subvault:",
            "-r",
        ])
        .output()
        .unwrap();
    assert!(ls_vault.status.success());
    let ls_vault_txt = String::from_utf8_lossy(&ls_vault.stdout);
    assert!(
        ls_vault_txt.contains("docs/item.txt"),
        "got: {ls_vault_txt}"
    );
    assert!(
        !ls_vault_txt.contains("nested/vault"),
        "got: {ls_vault_txt}"
    );

    // 2. Single-file `ls`, `size`, `tree`, `hashsum` (crc32c & sha256), `check`, and `delete`!
    let ls_one = Command::new(rship_bin())
        .args(["ls", sample.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(ls_one.status.success());
    assert!(String::from_utf8_lossy(&ls_one.stdout).contains("hello world.txt"));

    for target in [sample.to_str().unwrap(), "subvault:docs/item.txt"] {
        let sz = Command::new(rship_bin())
            .args([
                "--config",
                cfg_path.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
                "size",
                target,
                "--json",
            ])
            .output()
            .unwrap();
        assert!(sz.status.success());
        let sz_json: serde_json::Value = serde_json::from_slice(&sz.stdout).unwrap();
        assert_eq!(sz_json["count"], 1, "target={target}");
        assert_eq!(sz_json["bytes"], 9, "target={target}");
    }

    let tree_one = Command::new(rship_bin())
        .args(["tree", sample.to_str().unwrap(), "-s"])
        .output()
        .unwrap();
    assert!(tree_one.status.success());
    assert!(String::from_utf8_lossy(&tree_one.stdout).contains("0 directories, 1 files (9 B)"));

    let crc_one = Command::new(rship_bin())
        .args(["hashsum", "crc32c", sample.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(crc_one.status.success());
    assert_eq!(
        String::from_utf8_lossy(&crc_one.stdout).trim(),
        "e3069283  hello world.txt"
    );

    let sample_same = tmp.path().join("copy_same.txt");
    let sample_diff = tmp.path().join("copy_diff.txt");
    std::fs::write(&sample_same, b"123456789").unwrap();
    std::fs::write(&sample_diff, b"123456780").unwrap();

    let chk_same = Command::new(rship_bin())
        .args([
            "check",
            sample.to_str().unwrap(),
            sample_same.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(chk_same.status.success());
    let chk_same_json: serde_json::Value = serde_json::from_slice(&chk_same.stdout).unwrap();
    assert_eq!(chk_same_json["matched"], 1);
    assert_eq!(chk_same_json["differences"], 0);

    let chk_diff = Command::new(rship_bin())
        .args([
            "check",
            sample.to_str().unwrap(),
            sample_diff.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !chk_diff.status.success(),
        "mismatched single files must fail check"
    );
    let chk_diff_json: serde_json::Value = serde_json::from_slice(&chk_diff.stdout).unwrap();
    assert_eq!(chk_diff_json["differences"], 1);

    let del_single = Command::new(rship_bin())
        .args(["delete", sample_diff.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(del_single.status.success());
    assert!(
        !sample_diff.exists(),
        "single-file delete must remove target file"
    );

    // 3. `bisync --resync` merges union instead of deleting from stale baseline!
    let ba = tmp.path().join("bs_a");
    let bb = tmp.path().join("bs_b");
    std::fs::create_dir_all(&ba).unwrap();
    std::fs::create_dir_all(&bb).unwrap();
    std::fs::write(ba.join("keep.txt"), b"v1").unwrap();

    assert!(
        Command::new(rship_bin())
            .args([
                "--state-dir",
                state_dir.to_str().unwrap(),
                "bisync",
                ba.to_str().unwrap(),
                bb.to_str().unwrap(),
            ])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(bb.join("keep.txt").exists());

    // Delete `keep.txt` on Side A, then run `--resync`: must restore from Side B -> Side A!
    std::fs::remove_file(ba.join("keep.txt")).unwrap();
    let resync_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "bisync",
            ba.to_str().unwrap(),
            bb.to_str().unwrap(),
            "--resync",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(resync_out.status.success());
    let resync_json: serde_json::Value = serde_json::from_slice(&resync_out.stdout).unwrap();
    assert_eq!(resync_json["deleted_on_b"], 0);
    assert_eq!(resync_json["copied_b_to_a"], 1);
    assert_eq!(std::fs::read(ba.join("keep.txt")).unwrap(), b"v1");
}
