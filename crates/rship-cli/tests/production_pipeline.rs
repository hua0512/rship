//! Production orchestrator integration tests (`rust-srec`-style multi-task pipelines):
//! - `--files-from` direct-stat (`--no-traverse`) ignoring sibling live `.flv` files
//! - Concurrent `moveto` + `move --files-from` subprocesses on the same destination root
//! - Real-time JSONL progress streaming (`--json-progress --stats 100ms`) + per-file JSON summary
//! - Multi-thread atomic `FileTokenStore::save` safety
//! - In-process Rust crate embedding via `TransferEngine::run_file_list`

use rship_backends::local::LocalBackend;
use rship_core::backend::StorageBackend;
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, FileTransferStatus, TransferEngine};
use rship_core::path::RelPath;
use rship_core::progress::{TransferPhase, TransferProgress};
use rship_core::state::JobMode;
use rship_state::{ProcessLock, StateActor};
use rship_transport::oauth::{FileTokenStore, OAuthToken, TokenStore};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

fn rship_bin() -> &'static str {
    env!("CARGO_BIN_EXE_rship")
}

#[test]
fn cli_files_from_concurrent_subprocesses_and_jsonl_progress() {
    let tmp = TempDir::new().unwrap();
    let cfg_file = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let src_dir = tmp.path().join("recordings");
    let dst_dir = tmp.path().join("remote_mirror");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Populate recording dir: batch [clip.jpg, clip.mp4], single [clip.xml], and live [live.flv].
    std::fs::write(src_dir.join("clip.jpg"), vec![0xABu8; 32 * 1024]).unwrap();
    std::fs::write(src_dir.join("clip.mp4"), vec![0xCDu8; 512 * 1024]).unwrap();
    std::fs::write(src_dir.join("clip.xml"), b"<danmaku>hello</danmaku>").unwrap();
    std::fs::write(src_dir.join("live.flv"), b"actively recording stream").unwrap();

    let list_file = tmp.path().join("files_from.txt");
    std::fs::write(&list_file, "clip.jpg\nclip.mp4\n").unwrap();

    // Spawn BOTH subprocesses concurrently targeting the SAME destination root:
    // 1) `move --files-from` for [clip.jpg, clip.mp4]
    // 2) `moveto` for single file clip.xml
    let batch_cmd = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--drive-stop-on-upload-limit",
            "--tpslimit",
            "100",
            "move",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--files-from",
            list_file.to_str().unwrap(),
            "--no-traverse",
            "--retries",
            "1",
            "--json",
            "--json-progress",
            "--stats",
            "100ms",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let single_cmd = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "moveto",
            src_dir.join("clip.xml").to_str().unwrap(),
            dst_dir.join("clip.xml").to_str().unwrap(),
            "--retries",
            "1",
            "--json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let batch_out = batch_cmd.wait_with_output().unwrap();
    let single_out = single_cmd.wait_with_output().unwrap();

    assert!(
        batch_out.status.success(),
        "batch move failed: stdout={} stderr={}",
        String::from_utf8_lossy(&batch_out.stdout),
        String::from_utf8_lossy(&batch_out.stderr)
    );
    assert!(
        single_out.status.success(),
        "single moveto failed: stdout={} stderr={}",
        String::from_utf8_lossy(&single_out.stdout),
        String::from_utf8_lossy(&single_out.stderr)
    );

    // Verify stdout summary JSON contains exact per-file attribution.
    let summary: serde_json::Value = serde_json::from_slice(&batch_out.stdout).unwrap();
    assert_eq!(summary["files_transferred"], 2);
    assert_eq!(summary["sources_deleted"], 2);
    assert_eq!(summary["errors"].as_array().unwrap().len(), 0);
    let files = summary["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert!(
        files
            .iter()
            .all(|f| f["status"] == "transferred" && f["source_deleted"] == true)
    );

    // Verify stderr emitted valid JSONL progress event(s) with phase & counters.
    let stderr_text = String::from_utf8_lossy(&batch_out.stderr);
    let progress_events: Vec<serde_json::Value> = stderr_text
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str(l).expect("valid JSONL progress line"))
        .collect();
    assert!(
        !progress_events.is_empty(),
        "expected >= 1 JSONL progress event on stderr, got: {stderr_text}"
    );
    let last_ev = progress_events.last().unwrap();
    assert_eq!(last_ev["event"], "progress");
    assert!(last_ev["phase"].is_string());
    assert!(last_ev["bytes_done"].is_u64());
    assert!(last_ev["files_total"].is_u64());

    // Verify moved files exist at dst, sources were deleted, and live.flv stayed untouched!
    assert!(dst_dir.join("clip.jpg").exists());
    assert!(dst_dir.join("clip.mp4").exists());
    assert!(dst_dir.join("clip.xml").exists());
    assert!(!src_dir.join("clip.jpg").exists());
    assert!(!src_dir.join("clip.mp4").exists());
    assert!(!src_dir.join("clip.xml").exists());
    assert!(src_dir.join("live.flv").exists());
    assert!(!dst_dir.join("live.flv").exists());

    // Simulate partial-success retry: re-run exact same `--files-from` after `.jpg` was
    // already deleted and only a newly re-created `clip.mp4` remains.
    std::fs::write(src_dir.join("clip.mp4"), vec![0xEFu8; 64 * 1024]).unwrap();
    let retry_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "move",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--files-from",
            list_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(retry_out.status.success());
    let retry_json: serde_json::Value = serde_json::from_slice(&retry_out.stdout).unwrap();
    assert_eq!(retry_json["files_transferred"], 1);
    assert_eq!(retry_json["sources_deleted"], 1);
    assert!(!src_dir.join("clip.mp4").exists());
    assert_eq!(
        std::fs::read(dst_dir.join("clip.mp4")).unwrap().len(),
        64 * 1024
    );
}

#[tokio::test]
async fn embedded_run_file_list_moves_exact_files_without_sync_index() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(src_dir.join("2026-11")).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    std::fs::write(src_dir.join("2026-11/seg1.jpg"), b"thumb-bytes").unwrap();
    std::fs::write(src_dir.join("2026-11/seg1.mp4"), vec![7u8; 128 * 1024]).unwrap();
    std::fs::write(src_dir.join("2026-11/recording.flv"), b"live-flv").unwrap();

    let src: Arc<dyn StorageBackend> = Arc::new(LocalBackend::new("local-src", &src_dir).unwrap());
    let dst: Arc<dyn StorageBackend> = Arc::new(LocalBackend::new("local-dst", &dst_dir).unwrap());
    let journal = Arc::new(StateActor::open(&state_dir).unwrap());
    let pool = BufferPool::new(4 * 1024 * 1024, 256 * 1024).unwrap();
    let progress = TransferProgress::new();
    let engine = TransferEngine::new(
        src,
        dst,
        journal,
        pool,
        SystemClock::shared(),
        CancelFlag::new(),
    )
    .with_progress(progress.clone());

    let cfg = EngineConfig::new("embed-1", JobMode::Move, "src", "dst");
    let list = vec![
        RelPath::parse("2026-11/seg1.jpg").unwrap(),
        RelPath::parse("2026-11/seg1.mp4").unwrap(),
        // Already deleted on prior attempt -> skipped cleanly.
        RelPath::parse("2026-11/already_moved.txt").unwrap(),
    ];

    let rep = engine.run_file_list(&cfg, &list).await.unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files_transferred, 2);
    assert_eq!(rep.sources_deleted, 2);
    assert_eq!(rep.file_results.len(), 2);
    assert!(
        rep.file_results
            .iter()
            .all(|r| r.status == FileTransferStatus::Transferred && r.source_deleted)
    );
    assert_eq!(progress.phase(), TransferPhase::Completed);

    assert!(dst_dir.join("2026-11/seg1.jpg").exists());
    assert!(dst_dir.join("2026-11/seg1.mp4").exists());
    assert!(!src_dir.join("2026-11/seg1.jpg").exists());
    assert!(!src_dir.join("2026-11/seg1.mp4").exists());
    assert!(src_dir.join("2026-11/recording.flv").exists());
    assert!(!dst_dir.join("2026-11/recording.flv").exists());
}

#[test]
fn file_token_store_concurrent_saves_remain_valid_json() {
    let tmp = TempDir::new().unwrap();
    let tok_path = tmp.path().join("gdrive2.json");
    let store = Arc::new(FileTokenStore::new(&tok_path));

    let handles: Vec<_> = (0..12)
        .map(|i| {
            let s = store.clone();
            std::thread::spawn(move || {
                for j in 0..8 {
                    let tok = OAuthToken {
                        access_token: format!("ya29.tok-{i}-{j}"),
                        refresh_token: Some("1//keep-refresh".into()),
                        token_type: "Bearer".into(),
                        expires_at_unix_secs: 1_800_000_000 + i * 100 + j,
                        scope: None,
                    };
                    s.save(&tok).unwrap();
                    let loaded = s.load().unwrap().expect("token must exist");
                    assert_eq!(loaded.refresh_token.as_deref(), Some("1//keep-refresh"));
                }
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
    let final_tok = store.load().unwrap().unwrap();
    assert!(final_tok.access_token.starts_with("ya29.tok-"));
}

#[test]
fn cli_planning_skips_appear_in_json_files_and_progress_totals() {
    let tmp = TempDir::new().unwrap();
    let cfg_file = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Seed 8 files and copy them first so mtime + size match identically at dst.
    for i in 0..8 {
        std::fs::write(
            src_dir.join(format!("skip_{i}.txt")),
            format!("existing-payload-{i}"),
        )
        .unwrap();
    }
    let seed = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(seed.status.success());

    // Add 2 new files -> 10 total examined (8 planning skips + 2 planned transfers).
    std::fs::write(src_dir.join("new_0.txt"), b"fresh-file-0").unwrap();
    std::fs::write(src_dir.join("new_1.txt"), b"fresh-file-1").unwrap();

    let copy_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
            "--json-progress",
            "--stats",
            "100ms",
        ])
        .output()
        .unwrap();
    assert!(
        copy_out.status.success(),
        "copy failed: stdout={} stderr={}",
        String::from_utf8_lossy(&copy_out.stdout),
        String::from_utf8_lossy(&copy_out.stderr)
    );

    let copy_json: serde_json::Value = serde_json::from_slice(&copy_out.stdout).unwrap();
    assert_eq!(copy_json["ok"], true);
    assert_eq!(copy_json["exit_code"], 0);
    assert!(copy_json["error_category"].is_null());
    assert_eq!(copy_json["files_transferred"], 2);
    assert_eq!(copy_json["files_skipped"], 8);
    let files = copy_json["files"].as_array().unwrap();
    assert_eq!(
        files.len(),
        10,
        "planning-skipped files must appear in --json files"
    );
    assert_eq!(
        files
            .iter()
            .filter(|f| f["status"] == "skipped" && f["source_deleted"] == false)
            .count(),
        8
    );
    assert_eq!(
        files
            .iter()
            .filter(|f| f["status"] == "transferred" && f["source_deleted"] == false)
            .count(),
        2
    );

    let stderr_text = String::from_utf8_lossy(&copy_out.stderr);
    let progress_events: Vec<serde_json::Value> = stderr_text
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("valid JSONL"))
        .filter(|v| v["event"] == "progress")
        .collect();
    assert!(
        !progress_events.is_empty(),
        "expected progress JSONL on stderr"
    );
    let last_prog = progress_events.last().unwrap();
    assert_eq!(last_prog["files_total"], 10);
    assert_eq!(last_prog["files_planned"], 2);
    assert_eq!(last_prog["files_done"], 2);
    assert_eq!(last_prog["files_skipped"], 8);
    assert_eq!(last_prog["errors"], 0);

    // Now `move` the same directory: all 10 files are planning-skipped and sources deleted!
    let move_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "move",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(move_out.status.success());
    let move_json: serde_json::Value = serde_json::from_slice(&move_out.stdout).unwrap();
    assert_eq!(move_json["files_transferred"], 0);
    assert_eq!(move_json["files_skipped"], 10);
    assert_eq!(move_json["sources_deleted"], 10);
    let move_files = move_json["files"].as_array().unwrap();
    assert_eq!(move_files.len(), 10);
    assert!(
        move_files
            .iter()
            .all(|f| f["status"] == "skipped" && f["source_deleted"] == true)
    );
    assert!(!src_dir.join("new_0.txt").exists());

    // Single-file `moveto` planning skip must also emit a `skipped` entry with `source_deleted: true`.
    let single_src = tmp.path().join("single_src.txt");
    let single_dst = tmp.path().join("single_dst.txt");
    std::fs::write(&single_src, b"same-single-content").unwrap();
    let seed_single = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copyto",
            single_src.to_str().unwrap(),
            single_dst.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(seed_single.status.success());
    let moveto_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "moveto",
            single_src.to_str().unwrap(),
            single_dst.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(moveto_out.status.success());
    let moveto_json: serde_json::Value = serde_json::from_slice(&moveto_out.stdout).unwrap();
    assert_eq!(moveto_json["files_skipped"], 1);
    assert_eq!(moveto_json["sources_deleted"], 1);
    let mf = moveto_json["files"].as_array().unwrap();
    assert_eq!(mf.len(), 1);
    assert_eq!(mf[0]["status"], "skipped");
    assert_eq!(mf[0]["source_deleted"], true);
    assert!(!single_src.exists());
}

#[test]
fn cli_fatal_json_errors_distinct_exit_codes_and_tpslimit_zero() {
    let tmp = TempDir::new().unwrap();
    let cfg_file = tmp.path().join("config.toml");
    let state_dir = tmp.path().join("state");
    let src_dir = tmp.path().join("src");
    let dst_dir = tmp.path().join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();
    std::fs::write(src_dir.join("ok.txt"), b"hello").unwrap();

    // 1. Unconfigured remote -> exit 7 (`config`), valid JSON on stdout, JSONL error on stderr.
    let uncfg = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            "ghost_remote:bucket",
            dst_dir.to_str().unwrap(),
            "--json",
            "--json-progress",
        ])
        .output()
        .unwrap();
    assert_eq!(uncfg.status.code(), Some(7));
    let uncfg_json: serde_json::Value = serde_json::from_slice(&uncfg.stdout).unwrap();
    assert_eq!(uncfg_json["ok"], false);
    assert_eq!(uncfg_json["fatal"], true);
    assert_eq!(uncfg_json["error_category"], "config");
    assert_eq!(uncfg_json["exit_code"], 7);
    assert_eq!(uncfg_json["error_details"][0]["category"], "config");
    let uncfg_stderr = String::from_utf8_lossy(&uncfg.stderr);
    let err_line: serde_json::Value = uncfg_stderr
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str(l).unwrap())
        .find(|v: &serde_json::Value| v["event"] == "error")
        .expect("expected fatal JSONL error event on stderr");
    assert_eq!(err_line["fatal"], true);
    assert_eq!(err_line["error_category"], "config");

    // 2. Invalid `--proxy` -> exit 7 (`config`) + structured JSON.
    let bad_proxy = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--proxy",
            "://not-a-valid-url",
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_proxy.status.code(), Some(7));
    let proxy_json: serde_json::Value = serde_json::from_slice(&bad_proxy.stdout).unwrap();
    assert_eq!(proxy_json["error_category"], "config");
    assert_eq!(proxy_json["exit_code"], 7);

    // 3. Negative `--tpslimit` (both `--tpslimit=-1` and space-separated `--tpslimit -1`) -> exit 7.
    for tps_args in [vec!["--tpslimit=-1"], vec!["--tpslimit", "-1"]] {
        let mut cmd = Command::new(rship_bin());
        cmd.args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ]);
        cmd.args(&tps_args);
        cmd.args([
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ]);
        let neg_tps = cmd.output().unwrap();
        assert_eq!(neg_tps.status.code(), Some(7), "args={tps_args:?}");
        let neg_tps_json: serde_json::Value = serde_json::from_slice(&neg_tps.stdout).unwrap();
        assert_eq!(neg_tps_json["error_category"], "config");
    }

    // 3b. Missing `--ca-cert` -> exit 7 (`config`) eagerly even on local copy, with detail message.
    let bad_ca = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--ca-cert",
            tmp.path().join("no_such_ca.pem").to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_ca.status.code(), Some(7));
    let bad_ca_json: serde_json::Value = serde_json::from_slice(&bad_ca.stdout).unwrap();
    assert_eq!(bad_ca_json["error_category"], "config");
    assert!(
        bad_ca_json["error_details"][0]["message"]
            .as_str()
            .unwrap()
            .contains("no_such_ca.pem")
    );

    // 3c. Clap parse error under `--json` -> exit 7 (`config`) + valid JSON on stdout.
    let bad_flag = Command::new(rship_bin())
        .args([
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--definitely-not-a-real-flag",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_flag.status.code(), Some(7));
    let bad_flag_json: serde_json::Value = serde_json::from_slice(&bad_flag.stdout).unwrap();
    assert_eq!(bad_flag_json["ok"], false);
    assert_eq!(bad_flag_json["fatal"], true);
    assert_eq!(bad_flag_json["error_category"], "config");

    // 3d. `resume` unknown job with `--json` -> exit 3 (`not_found`), `delete --max-delete 0` -> exit 2 (`conflict`).
    let missing_job = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "resume",
            "job-missing-123",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_job.status.code(), Some(3));
    let missing_job_json: serde_json::Value = serde_json::from_slice(&missing_job.stdout).unwrap();
    assert_eq!(missing_job_json["error_category"], "not_found");

    let max_del = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "delete",
            src_dir.to_str().unwrap(),
            "--max-delete",
            "0",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(max_del.status.code(), Some(2));
    let max_del_json: serde_json::Value = serde_json::from_slice(&max_del.stdout).unwrap();
    assert_eq!(max_del_json["error_category"], "conflict");

    // 4. `--tpslimit 0` is treated as unlimited and succeeds!
    let zero_tps = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--tpslimit",
            "0",
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        zero_tps.status.success(),
        "--tpslimit 0 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&zero_tps.stdout),
        String::from_utf8_lossy(&zero_tps.stderr)
    );
    let zero_tps_json: serde_json::Value = serde_json::from_slice(&zero_tps.stdout).unwrap();
    assert_eq!(zero_tps_json["ok"], true);
    assert_eq!(zero_tps_json["files_transferred"], 1);

    // 5. Missing source file in `moveto` -> exit 3 (`not_found`), structured JSON, and
    //    no misleading `errors: 0` trailing progress line under `--json-progress`.
    let missing = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "moveto",
            src_dir.join("does_not_exist.mp4").to_str().unwrap(),
            dst_dir.join("out.mp4").to_str().unwrap(),
            "--json",
            "--json-progress",
        ])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(3));
    let missing_json: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(missing_json["ok"], false);
    assert_eq!(missing_json["fatal"], true);
    assert_eq!(missing_json["error_category"], "not_found");
    assert_eq!(missing_json["error_kind"], "not_found");
    assert_eq!(missing_json["exit_code"], 3);
    let missing_stderr = String::from_utf8_lossy(&missing.stderr);
    let missing_events: Vec<serde_json::Value> = missing_stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("strict JSONL stderr"))
        .collect();
    assert_eq!(missing_events.last().unwrap()["event"], "error");
    assert_eq!(missing_events.last().unwrap()["fatal"], true);
    // A periodic tick may legitimately precede the error on a slow runner; what must never
    // happen is a progress record (e.g. the final "stop" tick) after the fatal error.
    let first_error = missing_events
        .iter()
        .position(|v| v["event"] == "error")
        .expect("fatal error event");
    assert!(
        !missing_events[first_error..]
            .iter()
            .any(|v| v["event"] == "progress"),
        "must not emit misleading trailing progress tick on fatal error: {missing_events:?}"
    );

    // 6. Held destination ProcessLock -> exit 9 (`lock_busy`) + structured JSON.
    let dst_backend = LocalBackend::new("dst", &dst_dir).unwrap();
    let lock_scope = format!("{}::prefix::", dst_backend.endpoint_identity());
    let _held = ProcessLock::try_acquire(&state_dir.join("locks"), &lock_scope).unwrap();
    let busy = Command::new(rship_bin())
        .args([
            "--config",
            cfg_file.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            dst_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(busy.status.code(), Some(9));
    let busy_json: serde_json::Value = serde_json::from_slice(&busy.stdout).unwrap();
    assert_eq!(busy_json["ok"], false);
    assert_eq!(busy_json["fatal"], true);
    assert_eq!(busy_json["error_category"], "lock_busy");
    assert_eq!(busy_json["error_kind"], "lock_busy");
    assert_eq!(busy_json["exit_code"], 9);
}

#[cfg(feature = "backend-s3")]
fn spawn_mock_s3(
    put_status: &'static str,
    put_extra_headers: &'static str,
    put_body: &'static str,
) -> (u16, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();

    let handle = std::thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                    let mut buf = [0u8; 8192];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let first_line = req.lines().next().unwrap_or("");
                    let (status, extra_headers, body) = if first_line.starts_with("HEAD ") {
                        ("404 Not Found", "", "")
                    } else if first_line.starts_with("GET ") {
                        (
                            "200 OK",
                            "Content-Type: application/xml\r\n",
                            r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>testb</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>"#,
                        )
                    } else {
                        (put_status, put_extra_headers, put_body)
                    };
                    let resp = format!(
                        "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (port, stop, handle)
}

#[cfg(feature = "backend-s3")]
#[test]
fn cli_streams_per_file_error_jsonl_and_returns_auth_and_rate_limit_exit_codes() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    let src_dir = tmp.path().join("src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src_dir.join("b.txt"), b"beta").unwrap();

    // Case A: HTTP 403 AccessDenied on per-file PUT -> exit 4 (`auth`) + streamed JSONL errors.
    let (port_auth, stop_auth, handle_auth) = spawn_mock_s3(
        "403 Forbidden",
        "Content-Type: application/xml\r\n",
        "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
    );
    let cfg_auth = tmp.path().join("config_auth.toml");
    std::fs::write(
        &cfg_auth,
        format!(
            "[remotes.mocks3]\ntype = \"s3\"\nendpoint = \"http://127.0.0.1:{port_auth}\"\nregion = \"us-east-1\"\nbucket = \"testb\"\naccess_key_id = \"ak\"\nsecret_access_key = \"sk\"\nforce_path_style = true\n"
        ),
    )
    .unwrap();

    let auth_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_auth.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            "mocks3:",
            "--retries",
            "0",
            "--json",
            "--json-progress",
            "--stats",
            "100ms",
        ])
        .output()
        .unwrap();
    stop_auth.store(true, Ordering::Relaxed);
    let _ = handle_auth.join();

    assert_eq!(
        auth_out.status.code(),
        Some(4),
        "expected exit 4 (auth): stdout={} stderr={}",
        String::from_utf8_lossy(&auth_out.stdout),
        String::from_utf8_lossy(&auth_out.stderr)
    );
    let auth_json: serde_json::Value = serde_json::from_slice(&auth_out.stdout).unwrap();
    assert_eq!(auth_json["ok"], false);
    assert_eq!(auth_json["exit_code"], 4);
    assert_eq!(auth_json["error_category"], "auth");
    assert_eq!(auth_json["error_details"].as_array().unwrap().len(), 2);
    assert!(
        auth_json["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["status"] == "failed" && f["error_category"] == "auth")
    );

    let auth_err_events: Vec<serde_json::Value> = String::from_utf8_lossy(&auth_out.stderr)
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("valid JSONL"))
        .filter(|v| v["event"] == "error")
        .collect();
    assert_eq!(
        auth_err_events.len(),
        2,
        "expected 2 streamed per-file error JSONL events, got: {auth_err_events:?}"
    );
    assert!(auth_err_events.iter().all(|ev| ev["fatal"] == false
        && ev["error_category"] == "auth"
        && ev["path"].is_string()));

    // Case B: HTTP 429 Too Many Requests with Retry-After -> exit 6 (`rate_limited`).
    let (port_rl, stop_rl, handle_rl) = spawn_mock_s3(
        "429 Too Many Requests",
        "Content-Type: application/xml\r\nRetry-After: 2\r\n",
        "<Error><Code>SlowDown</Code><Message>Please reduce your request rate.</Message></Error>",
    );
    let cfg_rl = tmp.path().join("config_rl.toml");
    std::fs::write(
        &cfg_rl,
        format!(
            "[remotes.mocks3]\ntype = \"s3\"\nendpoint = \"http://127.0.0.1:{port_rl}\"\nregion = \"us-east-1\"\nbucket = \"testb\"\naccess_key_id = \"ak\"\nsecret_access_key = \"sk\"\nforce_path_style = true\n"
        ),
    )
    .unwrap();

    let rl_out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_rl.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copyto",
            src_dir.join("a.txt").to_str().unwrap(),
            "mocks3:a.txt",
            "--retries",
            "0",
            "--json",
            "--json-progress",
        ])
        .output()
        .unwrap();
    stop_rl.store(true, Ordering::Relaxed);
    let _ = handle_rl.join();

    assert_eq!(
        rl_out.status.code(),
        Some(6),
        "expected exit 6 (rate_limited): stdout={} stderr={}",
        String::from_utf8_lossy(&rl_out.stdout),
        String::from_utf8_lossy(&rl_out.stderr)
    );
    let rl_json: serde_json::Value = serde_json::from_slice(&rl_out.stdout).unwrap();
    assert_eq!(rl_json["ok"], false);
    assert_eq!(rl_json["exit_code"], 6);
    assert_eq!(rl_json["error_category"], "rate_limited");
    assert_eq!(rl_json["error_details"][0]["category"], "rate_limited");
    assert_eq!(rl_json["error_details"][0]["retry_after_ms"], 2000);

    let rl_err_events: Vec<serde_json::Value> = String::from_utf8_lossy(&rl_out.stderr)
        .lines()
        .filter(|l| l.trim_start().starts_with('{'))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("valid JSONL"))
        .filter(|v| v["event"] == "error")
        .collect();
    assert_eq!(rl_err_events.len(), 1);
    assert_eq!(rl_err_events[0]["error_category"], "rate_limited");
    assert_eq!(rl_err_events[0]["retry_after_ms"], 2000);
    assert_eq!(rl_err_events[0]["path"], "a.txt");

    // Case C: `--json-progress` WITHOUT `--json`, with ambient `RUST_LOG=info`, must keep
    // `stderr` 100% pure JSONL (no human `✗` summary lines and no tracing `WARN`/`INFO` noise).
    let (port_pure, stop_pure, handle_pure) = spawn_mock_s3(
        "403 Forbidden",
        "Content-Type: application/xml\r\n",
        "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
    );
    let cfg_pure = tmp.path().join("config_pure.toml");
    std::fs::write(
        &cfg_pure,
        format!(
            "[remotes.mocks3]\ntype = \"s3\"\nendpoint = \"http://127.0.0.1:{port_pure}\"\nregion = \"us-east-1\"\nbucket = \"testb\"\naccess_key_id = \"ak\"\nsecret_access_key = \"sk\"\nforce_path_style = true\n"
        ),
    )
    .unwrap();

    let pure_out = Command::new(rship_bin())
        .env("RUST_LOG", "info")
        .args([
            "--config",
            cfg_pure.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            "mocks3:",
            "--retries",
            "0",
            "--json-progress",
            "--stats",
            "100ms",
        ])
        .output()
        .unwrap();
    stop_pure.store(true, Ordering::Relaxed);
    let _ = handle_pure.join();

    assert_eq!(pure_out.status.code(), Some(4));
    let pure_stderr = String::from_utf8_lossy(&pure_out.stderr);
    let non_empty_lines: Vec<&str> = pure_stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(!non_empty_lines.is_empty());
    let mut err_count = 0usize;
    for line in &non_empty_lines {
        let parsed: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("non-JSONL line on --json-progress stderr: `{line}` ({e})"));
        if parsed["event"] == "error" {
            err_count += 1;
        }
    }
    assert_eq!(err_count, 2);
}

#[cfg(feature = "backend-s3")]
#[test]
fn cli_dump_headers_and_log_file_redact_secrets_and_protect_jsonl() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src");
    let state_dir = tmp.path().join("state");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("hello.txt"), b"hello-wire").unwrap();

    // 1. Invalid `--dump` value must fail fast with EXIT_CONFIG (7).
    let bad_dump = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dump",
            "bodies",
            "config",
            "path",
        ])
        .output()
        .unwrap();
    assert_eq!(
        bad_dump.status.code(),
        Some(7),
        "expected EXIT_CONFIG (7) for invalid --dump: stderr={}",
        String::from_utf8_lossy(&bad_dump.stderr)
    );

    // 2. `--dump headers` + `--json-progress` WITHOUT `--log-file` must fail fast with EXIT_CONFIG (7)
    //    so wire logs can never corrupt JSONL stderr streams.
    let conflict = Command::new(rship_bin())
        .args([
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dump",
            "headers",
            "copy",
            src_dir.to_str().unwrap(),
            tmp.path().join("dst").to_str().unwrap(),
            "--json-progress",
        ])
        .output()
        .unwrap();
    assert_eq!(
        conflict.status.code(),
        Some(7),
        "expected EXIT_CONFIG (7) for --dump headers + --json-progress without --log-file: stderr={}",
        String::from_utf8_lossy(&conflict.stderr)
    );

    // 3. `--dump headers` + `--log-file <nested>/wire.log` + `--json-progress` against mock S3:
    //    - creates parent dirs and writes redacted HTTP request/response headers to wire.log
    //    - redacts SigV4 Authorization + session token while keeping auth scheme & non-secret headers
    //    - keeps stderr 100% pure valid JSONL!
    let (port, stop, handle) = spawn_mock_s3(
        "403 Forbidden",
        "Content-Type: application/xml\r\nx-amz-request-id: REQ-DUMP-123\r\n",
        "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>",
    );
    let cfg_path = tmp.path().join("dump_s3.toml");
    std::fs::write(
        &cfg_path,
        format!(
            "[remotes.dumps3]\ntype = \"s3\"\nendpoint = \"http://127.0.0.1:{port}\"\nregion = \"us-east-1\"\nbucket = \"testb\"\naccess_key_id = \"AKIA_DUMP_TEST\"\nsecret_access_key = \"SUPER_SECRET_KEY_XYZ\"\nsession_token = \"SESSION_TOKEN_SECRET_ABC\"\nforce_path_style = true\n"
        ),
    )
    .unwrap();
    let log_file = tmp.path().join("logs").join("wire.log");

    let out = Command::new(rship_bin())
        .args([
            "--config",
            cfg_path.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dump",
            "headers",
            "--log-file",
            log_file.to_str().unwrap(),
            "copy",
            src_dir.to_str().unwrap(),
            "dumps3:",
            "--retries",
            "0",
            "--json-progress",
            "--stats",
            "100ms",
        ])
        .output()
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    let _ = handle.join();

    assert_eq!(
        out.status.code(),
        Some(4),
        "expected auth exit code 4: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify stderr stayed 100% pure JSONL.
    let stderr_str = String::from_utf8_lossy(&out.stderr);
    for line in stderr_str.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("non-JSONL line on stderr with --log-file: `{line}` ({e})"));
    }

    // Verify wire.log contains redacted headers and zero raw secrets.
    let log_contents = std::fs::read_to_string(&log_file).expect("wire.log created");
    assert!(
        log_contents.contains(">>> HTTP REQUEST"),
        "missing request dump in wire.log:\n{log_contents}"
    );
    assert!(
        log_contents.contains("<<< HTTP RESPONSE"),
        "missing response dump in wire.log:\n{log_contents}"
    );
    assert!(
        log_contents.contains("authorization: AWS4-HMAC-SHA256 ***REDACTED***"),
        "missing redacted Authorization header in wire.log:\n{log_contents}"
    );
    assert!(
        log_contents.contains("x-amz-security-token: ***REDACTED***"),
        "missing redacted session token header in wire.log:\n{log_contents}"
    );
    assert!(
        log_contents.contains("x-amz-request-id: REQ-DUMP-123"),
        "missing diagnostic response header in wire.log:\n{log_contents}"
    );
    assert!(
        !log_contents.contains("SUPER_SECRET_KEY_XYZ"),
        "LEAKED secret_access_key in wire.log!"
    );
    assert!(
        !log_contents.contains("SESSION_TOKEN_SECRET_ABC"),
        "LEAKED session_token in wire.log!"
    );
    assert!(
        !log_contents.contains("Signature="),
        "LEAKED SigV4 Signature in wire.log!"
    );
    assert!(
        !log_contents.contains("AKIA_DUMP_TEST"),
        "LEAKED access_key_id inside Authorization header in wire.log!"
    );
    assert!(
        !log_contents.contains("\x1b["),
        "unexpected ANSI escape codes in --log-file output!"
    );
}
