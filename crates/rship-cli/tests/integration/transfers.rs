use crate::rship_bin;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn cli_copy_sync_status_and_exclude_filters_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(src.join("keep")).unwrap();
    std::fs::create_dir_all(src.join("ignored_dir")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("keep/a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("keep/skip.tmp"), b"temp").unwrap();
    std::fs::write(src.join("ignored_dir/b.txt"), b"secret").unwrap();
    std::fs::write(dst.join("extra.txt"), b"delete-me").unwrap();

    // 1. Copy with --exclude (must NOT delete extra.txt and must skip excluded paths).
    let out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--exclude",
            "ignored_dir/",
            "--exclude",
            "*.tmp",
            "--max-buffer-mem",
            "2M",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "copy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(dst.join("keep/a.txt")).unwrap(), b"alpha");
    assert!(!dst.join("keep/skip.tmp").exists());
    assert!(!dst.join("ignored_dir/b.txt").exists());
    assert!(dst.join("extra.txt").exists(), "copy must not delete");

    // 2. Sync with --max-delete 0 trips the circuit breaker and preserves extra.txt!
    let out_cb = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--exclude",
            "ignored_dir/",
            "--exclude",
            "*.tmp",
            "--max-delete",
            "0",
        ])
        .output()
        .unwrap();
    assert!(!out_cb.status.success());
    assert!(
        dst.join("extra.txt").exists(),
        "circuit breaker must protect extra.txt"
    );

    // 3. Normal sync deletes extra.txt cleanly.
    let out_sync = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--exclude",
            "ignored_dir/",
            "--exclude",
            "*.tmp",
        ])
        .output()
        .unwrap();
    assert!(
        out_sync.status.success(),
        "sync failed: {}",
        String::from_utf8_lossy(&out_sync.stderr)
    );
    assert!(!dst.join("extra.txt").exists());

    // 4. Status command lists the completed jobs.
    let out_status = Command::new(rship_bin())
        .args(["--state-dir", state.to_str().unwrap(), "status", "--json"])
        .output()
        .unwrap();
    assert!(out_status.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out_status.stdout).unwrap();
    assert!(json["jobs"].as_array().unwrap().len() >= 3);
}

#[test]
fn cli_check_tree_and_adaptive_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(src.join("alpha/nested")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("alpha/nested/a.bin"), vec![0x41u8; 4096]).unwrap();
    std::fs::write(src.join("alpha/b.txt"), b"hello-world").unwrap();

    // 1. Copy with `--adaptive` Falcon dual-lane concurrency enabled.
    let copy_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--adaptive",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        copy_out.status.success(),
        "adaptive copy failed: {}",
        String::from_utf8_lossy(&copy_out.stderr)
    );
    let copy_json: serde_json::Value = serde_json::from_slice(&copy_out.stdout).unwrap();
    assert_eq!(copy_json["files_transferred"], 2);
    assert!(copy_json["final_small_concurrency"].as_u64().unwrap() >= 1);
    assert!(copy_json["final_large_concurrency"].as_u64().unwrap() >= 1);

    // 2. `rship tree -s` renders the directory hierarchy with sizes.
    let tree_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "tree",
            dst.to_str().unwrap(),
            "-s",
        ])
        .output()
        .unwrap();
    assert!(
        tree_out.status.success(),
        "tree failed: {}",
        String::from_utf8_lossy(&tree_out.stderr)
    );
    let tree_txt = String::from_utf8_lossy(&tree_out.stdout);
    assert!(tree_txt.contains("alpha/"), "got: {tree_txt}");
    assert!(tree_txt.contains("nested/"), "got: {tree_txt}");
    assert!(tree_txt.contains("a.bin"), "got: {tree_txt}");
    assert!(
        tree_txt.contains("2 directories, 2 files"),
        "got: {tree_txt}"
    );

    // 3. `rship check` succeeds when both trees match bit-for-bit.
    let chk_ok = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "check",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        chk_ok.status.success(),
        "check expected clean match: {}",
        String::from_utf8_lossy(&chk_ok.stderr)
    );
    let chk_ok_json: serde_json::Value = serde_json::from_slice(&chk_ok.stdout).unwrap();
    assert_eq!(chk_ok_json["matched"], 2);
    assert_eq!(chk_ok_json["differences"], 0);

    // 4. Same-length single-byte tamper + extra dst file detected by `rship check`.
    std::fs::write(dst.join("alpha/b.txt"), b"hello-worlX").unwrap();
    std::fs::write(dst.join("extra.txt"), b"extra").unwrap();

    let chk_bad = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "check",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        !chk_bad.status.success(),
        "check must fail on tamper + extra"
    );
    let chk_bad_json: serde_json::Value = serde_json::from_slice(&chk_bad.stdout).unwrap();
    assert_eq!(chk_bad_json["hash_mismatch"].as_array().unwrap().len(), 1);
    assert_eq!(chk_bad_json["missing_on_src"].as_array().unwrap().len(), 1);

    // 5. `--one-way --size-only` ignores same-length hash diff & extra dst files.
    let chk_ow = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "check",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--one-way",
            "--size-only",
        ])
        .output()
        .unwrap();
    assert!(chk_ow.status.success());
}

#[test]
fn cli_subprocess_kill_at_journal_boundary_and_resume_converges_bit_exact() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    // 4 × 512 KiB files paced at 128 KiB/s (~16 seconds total) so even on slow CI runners
    // we deterministically observe an active `.rship.part.*` staging file AND committed
    // SQLite WAL job + operation rows before hard-killing the subprocess.
    let mut expected = Vec::new();
    for i in 0..4u8 {
        let data: Vec<u8> = (0..(512 * 1024))
            .map(|k| ((k + usize::from(i) * 17) % 251) as u8)
            .collect();
        let name = format!("chunk_{i}.bin");
        std::fs::write(src.join(&name), &data).unwrap();
        expected.push((name, data));
    }

    let mut child = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--transfers",
            "1",
            "--chunk-size",
            "256K",
            "--bwlimit",
            "128K",
        ])
        .spawn()
        .unwrap();

    // Deterministically poll for BOTH an active `.rship.part.*` staging file on disk
    // (with written bytes or a prior completed file) AND durable job + active operation
    // rows visible in SQLite WAL via `rship status --json` — zero fixed post-detect sleeps.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut saw_in_flight = false;
    while std::time::Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("copy subprocess exited prematurely ({status}) before kill boundary");
        }

        let mut has_part_file = false;
        let mut has_nonempty_part = false;
        let mut has_completed_file = false;
        if let Ok(entries) = std::fs::read_dir(&dst) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains(".rship.part.") {
                    has_part_file = true;
                    if entry.metadata().is_ok_and(|m| m.len() > 0) {
                        has_nonempty_part = true;
                    }
                } else if name.starts_with("chunk_") {
                    has_completed_file = true;
                }
            }
        }

        if has_part_file
            && (has_nonempty_part || has_completed_file)
            && state.join("journal.db").exists()
        {
            // Verify durable job + active operation rows are actually committed in SQLite WAL.
            let probe = Command::new(rship_bin())
                .args(["--state-dir", state.to_str().unwrap(), "status", "--json"])
                .output()
                .unwrap();
            if probe.status.success()
                && let Ok(val) = serde_json::from_slice::<serde_json::Value>(&probe.stdout)
                && val["jobs"].as_array().is_some_and(|j| !j.is_empty())
                && val["active_operations"]
                    .as_array()
                    .is_some_and(|ops| !ops.is_empty())
            {
                saw_in_flight = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    // Hard-kill the subprocess (SIGKILL / TerminateProcess) mid-transfer!
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        saw_in_flight,
        "expected subprocess to reach durable WAL + staging boundary within 30s before kill"
    );

    // Inspect durable WAL journal via `rship status --json` to extract the interrupted job_id.
    let status_out = Command::new(rship_bin())
        .args(["--state-dir", state.to_str().unwrap(), "status", "--json"])
        .output()
        .unwrap();
    assert!(
        status_out.status.success(),
        "status after kill failed: {}",
        String::from_utf8_lossy(&status_out.stderr)
    );
    let status_json: serde_json::Value = serde_json::from_slice(&status_out.stdout).unwrap();
    let jobs = status_json["jobs"].as_array().unwrap();
    assert!(
        !jobs.is_empty(),
        "expected interrupted job recorded in SQLite WAL"
    );
    let job_id = jobs[0]["job_id"].as_str().unwrap().to_string();

    // Resume the killed job at full speed (`--bwlimit off` overrides persisted 128K pacing)
    // and verify 100% bit-exact convergence!
    let res_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "resume",
            &job_id,
            "--bwlimit",
            "off",
        ])
        .output()
        .unwrap();
    assert!(
        res_out.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&res_out.stderr)
    );

    for (name, data) in &expected {
        assert_eq!(
            std::fs::read(dst.join(name)).unwrap(),
            *data,
            "file `{name}` diverged after kill + resume"
        );
    }

    // No `.rship.part.*` leftovers and no active operations remaining!
    let leftover_parts: Vec<_> = std::fs::read_dir(&dst)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".rship.part."))
        .collect();
    assert!(
        leftover_parts.is_empty(),
        "leftover part files: {leftover_parts:?}"
    );

    let post_status = Command::new(rship_bin())
        .args(["--state-dir", state.to_str().unwrap(), "status", "--json"])
        .output()
        .unwrap();
    let post_json: serde_json::Value = serde_json::from_slice(&post_status.stdout).unwrap();
    assert!(
        post_json["active_operations"]
            .as_array()
            .unwrap()
            .is_empty(),
        "expected all active operations retired after resume: {}",
        post_json["active_operations"]
    );
}

#[test]
fn cli_single_file_copyto_moveto_filters_resume_options_size_and_config_redaction() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");

    // 1. Config redaction by default vs `--show-secrets`.
    let s3_setup = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "auth",
            "s3",
            "prod-s3",
            "--provider",
            "aws",
            "--bucket",
            "bkt",
            "--access-key-id",
            "AKIA_VISIBLE",
            "--secret-access-key",
            "SUPER_SECRET_VALUE_999",
        ])
        .output()
        .unwrap();
    assert!(s3_setup.status.success());

    let show_redacted = Command::new(rship_bin())
        .args(["--config", cfg_path.to_str().unwrap(), "config", "show"])
        .output()
        .unwrap();
    assert!(show_redacted.status.success());
    let redacted_txt = String::from_utf8(show_redacted.stdout).unwrap();
    assert!(redacted_txt.contains("AKIA_VISIBLE"));
    assert!(redacted_txt.contains("***REDACTED***"));
    assert!(!redacted_txt.contains("SUPER_SECRET_VALUE_999"));

    let show_raw = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "config",
            "show",
            "--show-secrets",
        ])
        .output()
        .unwrap();
    assert!(show_raw.status.success());
    let raw_txt = String::from_utf8(show_raw.stdout).unwrap();
    assert!(raw_txt.contains("SUPER_SECRET_VALUE_999"));

    // 2. Single-file `copy`, `copyto`, and `moveto` (including rename & encrypted remote).
    let vault_raw = tmp.path().join("vault_raw");
    std::fs::create_dir_all(&vault_raw).unwrap();
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
            vault_raw.to_str().unwrap(),
            "--key-hex",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ])
        .output()
        .unwrap();
    assert!(crypt_setup.status.success());

    let one_file = tmp.path().join("report.txt");
    std::fs::write(&one_file, b"single-file-payload").unwrap();
    let dst_dir = tmp.path().join("single_dst");

    // Auto-detected local single-file copy -> directory.
    let cp_single = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            one_file.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        cp_single.status.success(),
        "single-file copy failed: {}",
        String::from_utf8_lossy(&cp_single.stderr)
    );
    assert_eq!(
        std::fs::read(dst_dir.join("report.txt")).unwrap(),
        b"single-file-payload"
    );

    // `copyto` local file -> renamed file inside encrypted `vault:`.
    let copyto = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copyto",
            one_file.to_str().unwrap(),
            "vault:docs/renamed.txt",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        copyto.status.success(),
        "copyto failed: {}",
        String::from_utf8_lossy(&copyto.stderr)
    );

    // Auto-detected remote single-file copy from `vault:docs/renamed.txt` -> local dir!
    let from_remote_dir = tmp.path().join("from_remote");
    let cp_remote = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            "vault:docs/renamed.txt",
            from_remote_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        cp_remote.status.success(),
        "remote single-file copy failed: {}",
        String::from_utf8_lossy(&cp_remote.stderr)
    );
    assert_eq!(
        std::fs::read(from_remote_dir.join("renamed.txt")).unwrap(),
        b"single-file-payload"
    );

    // `moveto` renames file and removes original source.
    let moved_dst = tmp.path().join("moved/final.txt");
    let moveto = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "moveto",
            one_file.to_str().unwrap(),
            moved_dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        moveto.status.success(),
        "moveto failed: {}",
        String::from_utf8_lossy(&moveto.stderr)
    );
    assert!(!one_file.exists(), "moveto must delete source after commit");
    assert_eq!(std::fs::read(&moved_dst).unwrap(), b"single-file-payload");

    // 3. Advanced filters (`--filter-from`, `--min-size`, `--max-size`, `--files-from`),
    //    `rship size --json`, concurrent `check --checkers 4`, and `resume` option persistence!
    let fsrc = tmp.path().join("filter_src");
    let fdst = tmp.path().join("filter_dst");
    std::fs::create_dir_all(fsrc.join("keep")).unwrap();
    std::fs::create_dir_all(fsrc.join("drop")).unwrap();
    std::fs::write(fsrc.join("keep/ok.txt"), vec![b'A'; 200]).unwrap();
    std::fs::write(fsrc.join("keep/tiny.txt"), vec![b'B'; 10]).unwrap();
    std::fs::write(fsrc.join("keep/huge.txt"), vec![b'C'; 2000]).unwrap();
    std::fs::write(fsrc.join("keep/ignored.log"), vec![b'D'; 200]).unwrap();
    std::fs::write(fsrc.join("drop/nope.txt"), vec![b'E'; 200]).unwrap();

    let rules_file = tmp.path().join("rules.txt");
    std::fs::write(
        &rules_file,
        "# sample filter rules\n- drop/\n+ *.txt\n- *\n",
    )
    .unwrap();

    let cp_filt = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            fsrc.to_str().unwrap(),
            fdst.to_str().unwrap(),
            "--filter-from",
            rules_file.to_str().unwrap(),
            "--min-size",
            "100",
            "--max-size",
            "1000",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        cp_filt.status.success(),
        "filtered copy failed: {}",
        String::from_utf8_lossy(&cp_filt.stderr)
    );
    let cp_json: serde_json::Value = serde_json::from_slice(&cp_filt.stdout).unwrap();
    let job_id = cp_json["job_id"].as_str().unwrap().to_string();
    assert_eq!(cp_json["files_transferred"], 1);
    assert!(fdst.join("keep/ok.txt").exists());
    assert!(!fdst.join("keep/tiny.txt").exists());
    assert!(!fdst.join("keep/huge.txt").exists());
    assert!(!fdst.join("keep/ignored.log").exists());
    assert!(!fdst.join("drop/nope.txt").exists());

    // Delete `rules.txt`, add a second matching file & a non-matching file, then `rship resume <job_id>`:
    // persisted `options_json` MUST still enforce the exact original filters!
    std::fs::remove_file(&rules_file).unwrap();
    std::fs::write(fsrc.join("keep/ok2.txt"), vec![b'F'; 300]).unwrap();
    std::fs::write(fsrc.join("keep/blocked2.log"), vec![b'G'; 300]).unwrap();

    let resumed = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "resume",
            &job_id,
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "resume with persisted filters failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(fdst.join("keep/ok2.txt").exists());
    assert!(
        !fdst.join("keep/blocked2.log").exists(),
        "resume must honor persisted --filter-from rules"
    );
    assert!(
        !fdst.join("keep/tiny.txt").exists(),
        "resume must honor persisted --min-size"
    );

    // `rship size --json` with `--files-from` + `rship check --checkers 4`.
    let files_list = tmp.path().join("files.txt");
    std::fs::write(&files_list, "keep/ok.txt\nkeep/ok2.txt\n").unwrap();
    let sz_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "size",
            fdst.to_str().unwrap(),
            "--files-from",
            files_list.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(sz_out.status.success());
    let sz_json: serde_json::Value = serde_json::from_slice(&sz_out.stdout).unwrap();
    assert_eq!(sz_json["count"], 2);
    assert_eq!(sz_json["bytes"], 500);

    let chk_out = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "check",
            fsrc.to_str().unwrap(),
            fdst.to_str().unwrap(),
            "--files-from",
            files_list.to_str().unwrap(),
            "--checkers",
            "4",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        chk_out.status.success(),
        "concurrent check failed: {}",
        String::from_utf8_lossy(&chk_out.stderr)
    );
    let chk_json: serde_json::Value = serde_json::from_slice(&chk_out.stdout).unwrap();
    assert_eq!(chk_json["matched"], 2);
    assert_eq!(chk_json["differences"], 0);
}

#[test]
fn cli_fsync_modes_max_delete_percent_high_delete_warning_and_missing_root() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("config.toml");
    let state = tmp.path().join("state");
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("keep.txt"), b"keep").unwrap();

    // 1. `--fsync=always`, `--fsync=batch`, `--fsync=never` all succeed; invalid mode fails.
    for mode in ["always", "batch", "never"] {
        let out = Command::new(rship_bin())
            .args([
                "--config",
                cfg.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
                "copy",
                src.to_str().unwrap(),
                dst.to_str().unwrap(),
                "--fsync",
                mode,
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "copy --fsync={mode} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let bad_fsync = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--fsync",
            "bogus",
        ])
        .output()
        .unwrap();
    assert!(!bad_fsync.status.success());

    // 2. `--max-delete 50%` trips circuit breaker when >50% of dst files would be deleted.
    for i in 0..4 {
        std::fs::write(dst.join(format!("extra_{i}.txt")), b"extra").unwrap();
    }
    let blocked = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--max-delete",
            "50%",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!blocked.status.success());
    let blocked_json: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked_json["items_deleted"], 0);
    assert!(dst.join("extra_0.txt").exists());

    // 3. Without `--max-delete`, deleting >50% succeeds and prints `high_delete_warning`
    //    on stderr (human mode) and in `--json`.
    let warn_human = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(warn_human.status.success());
    let warn_stderr = String::from_utf8_lossy(&warn_human.stderr);
    assert!(
        warn_stderr.contains("50%") || warn_stderr.to_ascii_lowercase().contains("warning"),
        "expected high_delete_warning on stderr, got: {warn_stderr}"
    );

    let warn_json_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(warn_json_out.status.success());
    let warn_json: serde_json::Value = serde_json::from_slice(&warn_json_out.stdout).unwrap();
    assert_eq!(warn_json["items_deleted"], 4);
    assert!(
        warn_json["high_delete_warning"].is_string(),
        "expected high_delete_warning in JSON output: {warn_json}"
    );

    // 4. D3-local via CLI: syncing from a missing local root fails with exit code 3 (NotFound)
    //    and preserves every existing destination file!
    let missing_src = tmp.path().join("definitely_missing_mount");
    let missing_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            missing_src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        missing_out.status.code(),
        Some(3),
        "missing local root must exit with code 3 (NotFound); stdout={} stderr={}",
        String::from_utf8_lossy(&missing_out.stdout),
        String::from_utf8_lossy(&missing_out.stderr)
    );
    assert!(
        dst.join("keep.txt").exists(),
        "missing local source root must NEVER wipe destination"
    );
}

#[test]
fn cli_defaults_named_profiles_precedence_and_help_tiers_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let cfg = tmp.path().join("config.toml");
    let state = tmp.path().join("state");
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("keep.txt"), b"hello").unwrap();
    std::fs::write(src.join("scratch.tmp"), b"ignored-by-default").unwrap();
    std::fs::write(src.join("debug.log"), b"ignored-by-profile").unwrap();
    std::fs::write(dst.join("extra.txt"), b"protected-by-max-delete").unwrap();

    std::fs::write(
        &cfg,
        r#"
[defaults]
transfers = 6
part_concurrency = 4
adaptive = true
max_buffer_mem = "2M"
exclude = ["*.tmp"]
proxy = "http://alice:topsecret@proxy.internal:8080"

[profiles.safe_backup]
max_delete = "0"
delete_mode = "before"
exclude = ["*.log"]
"#,
    )
    .unwrap();

    // 1. `[defaults]` applies to `copy` automatically: `adaptive = true` populates
    //    `final_small_concurrency`, `max_buffer_mem = "2M"` caps pool, and `*.tmp` is excluded.
    let copy_def = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        copy_def.status.success(),
        "default copy failed: stdout={} stderr={}",
        String::from_utf8_lossy(&copy_def.stdout),
        String::from_utf8_lossy(&copy_def.stderr)
    );
    let copy_json: serde_json::Value = serde_json::from_slice(&copy_def.stdout).unwrap();
    assert_eq!(copy_json["files_transferred"], 2); // keep.txt + debug.log (scratch.tmp excluded)
    assert_eq!(copy_json["buffer_pool_cap_bytes"], 2 * 1024 * 1024);
    assert!(
        copy_json["final_small_concurrency"].is_number(),
        "defaults.adaptive=true must activate Falcon adaptive concurrency: {copy_json}"
    );
    assert!(dst.join("keep.txt").exists());
    assert!(dst.join("debug.log").exists());
    assert!(!dst.join("scratch.tmp").exists());

    // 2. Explicit `--no-adaptive` overrides `defaults.adaptive = true`.
    let no_adapt = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--no-adaptive",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(no_adapt.status.success());
    let no_adapt_json: serde_json::Value = serde_json::from_slice(&no_adapt.stdout).unwrap();
    assert!(
        no_adapt_json["final_small_concurrency"].is_null(),
        "--no-adaptive must disable defaults.adaptive=true: {no_adapt_json}"
    );

    // 3. `-p safe_backup` layers profile excludes (`*.log`) onto defaults (`*.tmp`),
    //    applies consistently to `size`, and trips `max_delete = "0"` on `sync`.
    let size_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "-p",
            "safe_backup",
            "size",
            src.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(size_out.status.success());
    let size_json: serde_json::Value = serde_json::from_slice(&size_out.stdout).unwrap();
    assert_eq!(size_json["count"], 1); // only keep.txt survives *.tmp + *.log

    let sync_blocked = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            "-p",
            "safe_backup",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(sync_blocked.status.code(), Some(2));
    assert!(
        dst.join("extra.txt").exists(),
        "profile max_delete=0 must protect extra.txt"
    );

    // 4. Explicit CLI `--max-delete off --delete-mode after` overrides profile `max_delete = "0"`.
    let sync_override = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "sync",
            "-p",
            "safe_backup",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--max-delete",
            "off",
            "--delete-mode",
            "after",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        sync_override.status.success(),
        "sync override failed: stdout={} stderr={}",
        String::from_utf8_lossy(&sync_override.stdout),
        String::from_utf8_lossy(&sync_override.stderr)
    );
    assert!(!dst.join("extra.txt").exists());

    // 5. Unknown profile fails fast with exit code 7 (`config`) and lists available names.
    let bad_prof = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "--profile",
            "nonexistent",
            "size",
            src.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_prof.status.code(), Some(7));
    let bad_prof_text = String::from_utf8_lossy(&bad_prof.stdout);
    assert!(bad_prof_text.contains("safe_backup"));

    // 6. `config profiles` & `config profiles --json` inspect presets and scrub proxy secrets.
    let prof_list = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "config",
            "profiles",
        ])
        .output()
        .unwrap();
    assert!(prof_list.status.success());
    let prof_stdout = String::from_utf8_lossy(&prof_list.stdout);
    assert!(prof_stdout.contains("safe_backup"));
    assert!(prof_stdout.contains("***REDACTED***@proxy.internal:8080"));
    assert!(!prof_stdout.contains("topsecret"));

    let prof_json_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "--state-dir",
            state.to_str().unwrap(),
            "config",
            "profiles",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(prof_json_out.status.success());
    let prof_json: serde_json::Value = serde_json::from_slice(&prof_json_out.stdout).unwrap();
    assert_eq!(prof_json["defaults"]["transfers"], 6);
    assert_eq!(prof_json["profiles"]["safe_backup"]["max_delete"], "0");
    assert!(!prof_json.to_string().contains("topsecret"));

    // 7. Short `-h` stays concise while `--help` exposes grouped advanced/network/backend options.
    let short_h = Command::new(rship_bin())
        .args(["copy", "-h"])
        .output()
        .unwrap();
    assert!(short_h.status.success());
    let short_txt = String::from_utf8_lossy(&short_h.stdout);
    assert!(short_txt.contains("--profile"));
    assert!(short_txt.contains("--delete-mode"));
    assert!(!short_txt.contains("--drive-stop-on-upload-limit"));

    let long_h = Command::new(rship_bin())
        .args(["copy", "--help"])
        .output()
        .unwrap();
    assert!(long_h.status.success());
    let long_txt = String::from_utf8_lossy(&long_h.stdout);
    assert!(long_txt.contains("Performance & Concurrency:"));
    assert!(long_txt.contains("Network & Rate Limits:"));
    assert!(long_txt.contains("Backend Overrides:"));
    assert!(long_txt.contains("--drive-stop-on-upload-limit"));
}
