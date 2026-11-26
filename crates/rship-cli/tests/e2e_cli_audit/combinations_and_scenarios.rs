use crate::mock_http::{
    FaultAction, MockResponse, md5_hex, sha256_hex, start_gdrive_mock, start_onedrive_mock,
    start_s3_mock, start_webdav_mock,
};
use crate::{CliHarness, onedrive_toml, s3_toml, webdav_toml};

// ===========================================================================
// Tier 3: Pairwise Combinatorial CLI Workflows (6 cases)
// ===========================================================================

#[test]
fn tier3_crypt_local_nfd_check_json() {
    let h = CliHarness::new();
    let raw_dir = h.path().join("raw_crypt");
    let src_dir = h.path().join("src_nfd");
    std::fs::create_dir_all(&raw_dir).unwrap();
    std::fs::create_dir_all(src_dir.join("nested")).unwrap();

    // Seed NFD filename (`e\u{0301}`) when filesystem allows it (or NFC equivalent).
    let fname = "cafe\u{0301}.txt";
    std::fs::write(src_dir.join(fname), b"espresso-nfd").unwrap();
    std::fs::write(src_dir.join("nested/bean.txt"), b"arabica").unwrap();

    h.write_config(&format!(
        "[remotes.rawloc]\ntype = \"local\"\nroot = {:?}\n\n\
         [remotes.vault]\ntype = \"crypt\"\nremote = \"rawloc:vault\"\nkey_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        raw_dir
    ));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["sync", src_dir.to_str().unwrap(), "vault:", "--json"]),
        "sync local->crypt",
    );
    let chk = h.run_non_interactive(&[
        "check",
        src_dir.to_str().unwrap(),
        "vault:",
        "--one-way",
        "--size-only",
        "--json",
    ]);
    CliHarness::assert_ok(&chk, "check crypt");
    let cj = CliHarness::parse_json_stdout(&chk);
    assert_eq!(cj["ok"], true);
    assert_eq!(cj["matched"], 2);

    let ls = h.run_non_interactive(&["ls", "-r", "vault:", "--json"]);
    CliHarness::assert_ok(&ls, "ls -r crypt");
    let arr = CliHarness::parse_json_stdout(&ls);
    assert_eq!(
        arr.as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "file")
            .count(),
        2
    );
}

#[test]
fn tier3_s3_sse_kms_dump_headers_json_progress() {
    let h = CliHarness::new();
    let (srv, st) = start_s3_mock("test-bucket");
    st.lock().unwrap().sse_kms_mode = true;
    h.write_config(&s3_toml("s3kms", srv.port(), "aws", true));

    let src = h.path().join("kms_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("secret.bin"), b"kms-sensitive-payload").unwrap();
    let wire_log = h.path().join("wire.log");

    let cp = h.run_non_interactive(&[
        "--dump",
        "headers",
        "--log-file",
        wire_log.to_str().unwrap(),
        "copy",
        src.to_str().unwrap(),
        "s3kms:",
        "--json",
        "--json-progress",
        "--stats",
        "20ms",
    ]);
    CliHarness::assert_ok(&cp, "copy s3 sse-kms");

    let log_txt = std::fs::read_to_string(&wire_log).unwrap();
    assert!(log_txt.contains("x-amz-server-side-encryption: aws:kms"));
    assert!(!log_txt.contains("SECRET_TEST"));

    let chk = h.run_non_interactive(&["check", src.to_str().unwrap(), "s3kms:", "--json"]);
    let cj = CliHarness::parse_json_stdout(&chk);
    assert_eq!(cj["counts"]["hash_mismatch"], 0);
    assert_eq!(cj["differences"], 0);
    assert!(chk.status.success());
}

#[test]
fn tier3_gdrive_rclone_import_use_trash_dedupe() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        let mut g = st.lock().unwrap();
        g.seed_file(
            "d1",
            "report.pdf",
            "root",
            b"older".to_vec(),
            "2026-11-20T00:00:00Z",
        );
        g.seed_file(
            "d2",
            "report.pdf",
            "root",
            b"newer".to_vec(),
            "2026-11-24T00:00:00Z",
        );
    }

    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[gd]
type = drive
client_id = cid
client_secret = csec
token = {"access_token":"gd-tok","token_type":"Bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone gdrive",
    );
    let mut cfg = h.parse_config_toml();
    {
        let tbl = cfg["remotes"]["gd"].as_table_mut().unwrap();
        tbl.insert(
            "api_base_url".into(),
            format!("{}/drive/v3", srv.base_url()).into(),
        );
        tbl.insert(
            "upload_base_url".into(),
            format!("{}/upload/drive/v3", srv.base_url()).into(),
        );
        tbl.insert(
            "token_url".into(),
            format!("{}/oauth2/token", srv.base_url()).into(),
        );
        tbl.insert("use_changes_feed".into(), false.into());
    }
    h.write_config(&toml::to_string_pretty(&cfg).unwrap());

    let dedupe_out = h.run_non_interactive(&["dedupe", "gd:", "--mode", "newest", "--json"]);
    CliHarness::assert_ok(&dedupe_out, "dedupe newest");
    assert_eq!(CliHarness::parse_json_stdout(&dedupe_out)["deleted"], 1);
    assert!(
        srv.requests().iter().any(|r| {
            r.method == "PATCH"
                && r.path == "/drive/v3/files/d1"
                && String::from_utf8_lossy(&r.body).contains("\"trashed\":true")
        }),
        "rclone-imported gdrive without explicit use_trash MUST trash older duplicate via PATCH"
    );

    let about_out = h.run_non_interactive(&["about", "gd:", "--json"]);
    CliHarness::assert_ok(&about_out, "about gd");
}

#[test]
fn tier3_bisync_filters_and_max_delete_conflict() {
    let h = CliHarness::new();
    let a = h.path().join("side_a");
    let b = h.path().join("side_b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    for i in 0..4 {
        std::fs::write(a.join(format!("keep_{i}.txt")), format!("v1-{i}")).unwrap();
    }
    std::fs::write(a.join("ignored.tmp"), b"temp-ignored").unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "bisync",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--resync",
            "--exclude",
            "*.tmp",
            "--json",
        ]),
        "bisync resync",
    );
    assert!(!b.join("ignored.tmp").exists());

    // Delete 2 of 4 files on A (50%) -> --max-delete 20% must trip EXIT_CONFLICT (2)
    std::fs::remove_file(a.join("keep_0.txt")).unwrap();
    std::fs::remove_file(a.join("keep_1.txt")).unwrap();
    let trip = h.run_non_interactive(&[
        "bisync",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--exclude",
        "*.tmp",
        "--max-delete",
        "20%",
        "--json",
    ]);
    assert_eq!(trip.status.code(), Some(2));
    assert!(b.join("keep_0.txt").is_file() && b.join("keep_1.txt").is_file());

    // Conflict + --conflict-strategy prefer-b (with --max-delete 100% to permit the 2/4 deletions)
    std::fs::write(a.join("keep_2.txt"), b"edit-a").unwrap();
    std::fs::write(b.join("keep_2.txt"), b"edit-b-longer").unwrap();
    let rec = h.run_non_interactive(&[
        "bisync",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--exclude",
        "*.tmp",
        "--conflict-strategy",
        "prefer-b",
        "--max-delete",
        "100%",
        "--json",
    ]);
    CliHarness::assert_ok(&rec, "bisync prefer-b");
    assert_eq!(
        std::fs::read(a.join("keep_2.txt")).unwrap(),
        b"edit-b-longer"
    );
}

#[test]
fn tier3_rcat_cat_hashsum_webdav() {
    let h = CliHarness::new();
    let (srv, _) = start_webdav_mock();
    h.write_config(&webdav_toml("davmock", srv.port(), "nextcloud"));

    // > 10 MiB piped to rcat with --chunk-size 5M -> Nextcloud Chunked v2 (MKCOL + PUT chunks + MOVE .file)
    let payload: Vec<u8> = (0..(10 * 1024 * 1024 + 512))
        .map(|i| (i % 251) as u8)
        .collect();
    let rcat = h.run_with_stdin(
        &["rcat", "davmock:streamed.bin", "--chunk-size", "5M"],
        &payload,
    );
    CliHarness::assert_ok(&rcat, "rcat >10MiB webdav");
    assert!(srv.requests().iter().any(|r| r.method == "MKCOL"));
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.method == "MOVE" && r.path.ends_with("/.file"))
    );

    let cat = h.run_non_interactive(&[
        "cat",
        "davmock:streamed.bin",
        "--offset",
        "100",
        "--count",
        "32",
    ]);
    CliHarness::assert_ok(&cat, "cat webdav");
    assert_eq!(cat.stdout, &payload[100..132]);

    let restored = h.path().join("webdav_restored.bin");
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            "davmock:streamed.bin",
            restored.to_str().unwrap(),
            "--json",
        ]),
        "copyto webdav->local",
    );
    let hs = h.run_non_interactive(&["hashsum", "md5", restored.to_str().unwrap(), "--json"]);
    CliHarness::assert_ok(&hs, "hashsum md5 restored");
    let hj = CliHarness::parse_json_stdout(&hs);
    assert_eq!(hj[0]["hash"], md5_hex(&payload));
}

#[test]
fn tier3_s3_r2_single_part_checksum_and_copyto() {
    let h = CliHarness::new();
    let (srv, st) = start_s3_mock("test-bucket");
    st.lock()
        .unwrap()
        .seed_incomplete_upload("old.bin", "uid-r2-1", "2020-01-01T00:00:00.000Z");
    h.write_config(&s3_toml("r2mock", srv.port(), "r2", false));

    let src = h.path().join("r2_small.bin");
    std::fs::write(&src, vec![0x42u8; 64 * 1024]).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src.to_str().unwrap(),
            "r2mock:r2_small.bin",
            "--json",
        ]),
        "r2 copyto",
    );

    // Audit §III.1 #3: R2 single-part PutObject MUST NOT send `x-amz-checksum-crc32c`.
    let puts: Vec<_> = srv
        .requests()
        .into_iter()
        .filter(|r| r.method == "PUT" && r.path == "/test-bucket/r2_small.bin")
        .collect();
    assert_eq!(puts.len(), 1);
    assert!(
        puts[0].header("x-amz-checksum-crc32c").is_none(),
        "Cloudflare R2 single-part PutObject must NOT send unsupported x-amz-checksum-crc32c!"
    );

    let gc = h.run_non_interactive(&["gc", "--remote-multipart", "r2mock:", "--dry-run", "--json"]);
    CliHarness::assert_ok(&gc, "r2 gc dry-run");
    assert_eq!(CliHarness::parse_json_stdout(&gc)["matched"], 1);
}

// ===========================================================================
// Tier 4: Multi-Step Real-World CLI Application Scenarios (5 cases)
// ===========================================================================

#[test]
fn tier4_scenario_rclone_import_sync_check_move_gc_s3_crypt() {
    let h = CliHarness::new();
    let (srv, _) = start_s3_mock("test-bucket");

    let rclone_conf = h.path().join("rclone.conf");
    std::fs::write(
        &rclone_conf,
        format!(
            "[s3raw]\ntype = s3\nprovider = AWS\naccess_key_id = AKIA_TEST\nsecret_access_key = SECRET_TEST\nregion = us-east-1\nendpoint = {}\nforce_path_style = true\n\n\
             [vault]\ntype = crypt\nremote = s3raw:test-bucket/enc\npassword = rclone-pw\n",
            srv.base_url()
        ),
    )
    .unwrap();

    // Note: `rship` supports `rclone` `crypt` remotes via `rclone_import` OR `auth crypt`.
    // Import S3 from rclone.conf, then wire crypt over `s3raw:test-bucket/enc` if crypt wasn't imported by rclone_import.
    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", rclone_conf.to_str().unwrap()]),
        "import-rclone s3+crypt",
    );
    if !h.read_config().contains("[remotes.vault]") {
        CliHarness::assert_ok(
            &h.run_non_interactive(&[
                "auth",
                "crypt",
                "vault",
                "--target",
                "s3raw:test-bucket/enc",
                "--key-hex",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ]),
            "auth crypt over s3raw",
        );
    }

    let local_tree = h.path().join("local_tree");
    std::fs::create_dir_all(local_tree.join("2026/media")).unwrap();
    std::fs::write(local_tree.join("2026/readme.txt"), b"project-notes").unwrap();
    std::fs::write(
        local_tree.join("2026/media/clip.bin"),
        vec![0x9Au8; 128 * 1024],
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["sync", local_tree.to_str().unwrap(), "vault:live", "--json"]),
        "sync local->crypt(s3)",
    );
    let chk = h.run_non_interactive(&[
        "check",
        local_tree.to_str().unwrap(),
        "vault:live",
        "--one-way",
        "--size-only",
        "--json",
    ]);
    CliHarness::assert_ok(&chk, "check vault:live");
    assert_eq!(CliHarness::parse_json_stdout(&chk)["matched"], 2);

    CliHarness::assert_ok(
        &h.run_non_interactive(&["move", "vault:live", "vault:archive", "--json"]),
        "move vault:live -> vault:archive",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "check",
            local_tree.to_str().unwrap(),
            "vault:archive",
            "--one-way",
            "--size-only",
            "--json",
        ]),
        "check vault:archive",
    );

    let st_out = h.run_non_interactive(&["status", "--json"]);
    CliHarness::assert_ok(&st_out, "status --json");
    assert!(
        !CliHarness::parse_json_stdout(&st_out)["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let gc_out = h.run_non_interactive(&["gc", "--json"]);
    CliHarness::assert_ok(&gc_out, "gc --json");
    assert_eq!(CliHarness::parse_json_stdout(&gc_out)["ok"], true);
}

#[test]
fn tier4_scenario_gdrive_oauth_retry_interrupt_resume() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    st.lock().unwrap().expected_token = Some("gd-fresh-tok-1".to_string());

    std::fs::create_dir_all(h.state_dir.join("tokens")).unwrap();
    std::fs::write(
        h.state_dir.join("tokens/gd_oauth.json"),
        r#"{"access_token":"expired","refresh_token":"ref-1","token_type":"Bearer","expires_at_unix_secs":1}"#,
    )
    .unwrap();
    h.write_config(&format!(
        "[remotes.gd_oauth]\ntype = \"gdrive\"\nclient_id = \"gd-cid\"\nclient_secret = \"gd-sec\"\napi_base_url = \"{base}/drive/v3\"\nupload_base_url = \"{base}/upload/drive/v3\"\ntoken_url = \"{base}/oauth2/token\"\nuse_changes_feed = false\n",
        base = srv.base_url()
    ));

    // > 5 MiB triggers resumable upload session.
    let src_dir = h.path().join("gd_src");
    std::fs::create_dir_all(&src_dir).unwrap();
    let big_data: Vec<u8> = (0..(5 * 1024 * 1024 + 512 * 1024))
        .map(|i| (i % 199) as u8)
        .collect();
    std::fs::write(src_dir.join("video.bin"), &big_data).unwrap();

    // Inject 503 on `/oauth2/token` (recovered by token retry) and 503 on `/upload/session/`
    // with `--retries 0` to record a resumable job in `journal.db`.
    srv.push_fault(
        Some("POST"),
        "/oauth2/token",
        FaultAction::Status(MockResponse::new(503, b"token down".to_vec())),
    );
    srv.push_fault(
        Some("PUT"),
        "/upload/session/",
        FaultAction::Status(MockResponse::new(503, b"chunk stall".to_vec())),
    );

    let fail_out = h.run_non_interactive(&[
        "copy",
        src_dir.to_str().unwrap(),
        "gd_oauth:",
        "--chunk-size",
        "1M",
        "--retries",
        "0",
        "--json",
    ]);
    assert!(
        !fail_out.status.success(),
        "expected initial transfer failure on injected 503"
    );

    let status_out = h.run_non_interactive(&["status", "--json"]);
    CliHarness::assert_ok(&status_out, "status after interrupted job");
    let sj = CliHarness::parse_json_stdout(&status_out);
    let job_id = sj["jobs"][0]["job_id"]
        .as_str()
        .expect("persisted job_id in status")
        .to_string();

    // Inject 429 on `/oauth2/token` during `resume` too.
    srv.push_fault(
        Some("POST"),
        "/oauth2/token",
        FaultAction::Status(
            MockResponse::new(429, b"slow down".to_vec()).with_header("Retry-After", "0"),
        ),
    );
    let resume_out = h.run_non_interactive(&["resume", &job_id, "--json", "--json-progress"]);
    CliHarness::assert_ok(&resume_out, "resume gdrive job");
    assert_eq!(CliHarness::parse_json_stdout(&resume_out)["ok"], true);

    CliHarness::assert_ok(
        &h.run_non_interactive(&["check", src_dir.to_str().unwrap(), "gd_oauth:", "--json"]),
        "check resumed gdrive",
    );
}

#[test]
fn tier4_scenario_webdav_nextcloud_chunked_and_207_move_safety() {
    let h = CliHarness::new();
    let (srv, st) = start_webdav_mock();
    h.write_config(&webdav_toml("davmock", srv.port(), "nextcloud"));

    let src = h.path().join("big_nc.bin");
    let payload: Vec<u8> = (0..(10 * 1024 * 1024 + 2048))
        .map(|i| (i % 233) as u8)
        .collect();
    std::fs::write(&src, &payload).unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src.to_str().unwrap(),
            "davmock:big_nc.bin",
            "--chunk-size",
            "5M",
            "--json",
        ]),
        "webdav chunked copyto",
    );
    assert!(srv.requests().iter().any(|r| r.method == "MKCOL"));
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.method == "MOVE" && r.path.ends_with("/.file"))
    );

    // Inject 207 Multi-Status failure on COPY/MOVE -> must fail and preserve source!
    srv.clear_requests();
    st.lock().unwrap().move_207_failure = Some((
        "/remote.php/dav/files/alice/archived_nc.bin".to_string(),
        "HTTP/1.1 403 Forbidden".to_string(),
    ));
    let mv_fail = h.run_non_interactive(&[
        "moveto",
        "davmock:big_nc.bin",
        "davmock:archived_nc.bin",
        "--json",
    ]);
    assert!(!mv_fail.status.success(), "207 failure must abort moveto");
    let mv_reqs = srv.requests();
    assert!(
        mv_reqs.iter().any(|r| r.method == "COPY"),
        "expected COPY request during moveto: {mv_reqs:?}"
    );
    assert!(
        !mv_reqs.iter().any(|r| r.method == "DELETE"),
        "DELETE must not be sent after 207 COPY failure: {mv_reqs:?}"
    );
    {
        let guard = st.lock().unwrap();
        assert!(
            guard
                .files
                .contains_key("/remote.php/dav/files/alice/big_nc.bin")
        );
        assert!(
            !guard
                .files
                .contains_key("/remote.php/dav/files/alice/archived_nc.bin")
        );
    }

    // Clear fault, re-run moveto, verify byte slice via `cat`!
    st.lock().unwrap().move_207_failure = None;
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "moveto",
            "davmock:big_nc.bin",
            "davmock:archived_nc.bin",
            "--json",
        ]),
        "webdav moveto after clearing 207 fault",
    );
    let cat_out = h.run_non_interactive(&[
        "cat",
        "davmock:archived_nc.bin",
        "--offset",
        "5000",
        "--count",
        "64",
    ]);
    CliHarness::assert_ok(&cat_out, "cat archived_nc.bin");
    assert_eq!(cat_out.stdout, &payload[5000..5064]);

    // Also verify Nextcloud chunked upload assembly (`MOVE /.file`) handles 207 Multi-Status safely!
    srv.push_fault(
        Some("MOVE"),
        "/.file",
        FaultAction::Status(MockResponse::xml(
            207,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>/remote.php/dav/files/alice/fail_nc.bin</d:href><d:status>HTTP/1.1 403 Forbidden</d:status></d:response></d:multistatus>",
        )),
    );
    let chunk_fail = h.run_non_interactive(&[
        "copyto",
        src.to_str().unwrap(),
        "davmock:fail_nc.bin",
        "--chunk-size",
        "5M",
        "--json",
    ]);
    assert!(
        !chunk_fail.status.success(),
        "207 Multi-Status on Nextcloud chunked assembly MOVE /.file must fail copyto"
    );
    assert!(
        !st.lock()
            .unwrap()
            .files
            .contains_key("/remote.php/dav/files/alice/fail_nc.bin"),
        "fail_nc.bin must not be committed when MOVE /.file returns 207"
    );
}

#[test]
fn tier4_scenario_bisync_resync_concurrent_conflict_and_max_delete() {
    let h = CliHarness::new();
    let a = h.path().join("tree_a");
    let b = h.path().join("tree_b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("shared.txt"), b"v1").unwrap();
    std::fs::write(a.join("del_1.txt"), b"d1").unwrap();
    std::fs::write(a.join("del_2.txt"), b"d2").unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "bisync",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--resync",
            "--json",
        ]),
        "bisync resync",
    );

    // Concurrent edits (distinct sizes from baseline "v1") + 2 deletions on A -> --max-delete 1 trips EXIT_CONFLICT (2)
    std::fs::write(a.join("shared.txt"), b"edit-from-a-v1").unwrap();
    std::fs::write(b.join("shared.txt"), b"edit-from-b-v2-longer").unwrap();
    std::fs::remove_file(a.join("del_1.txt")).unwrap();
    std::fs::remove_file(a.join("del_2.txt")).unwrap();

    let trip = h.run_non_interactive(&[
        "bisync",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--max-delete",
        "1",
        "--json",
    ]);
    assert_eq!(trip.status.code(), Some(2));
    assert!(b.join("del_1.txt").is_file() && b.join("del_2.txt").is_file());

    // Re-run with --conflict-strategy keep-both and --max-delete 100%
    let ok = h.run_non_interactive(&[
        "bisync",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        "--conflict-strategy",
        "keep-both",
        "--max-delete",
        "100%",
        "--json",
    ]);
    CliHarness::assert_ok(&ok, "bisync keep-both");
    let has_conflict_copy = std::fs::read_dir(&a)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("conflict"));
    assert!(has_conflict_copy, "expected .conflict-* preserved file");

    let chk = h.run_non_interactive(&["check", a.to_str().unwrap(), b.to_str().unwrap(), "--json"]);
    CliHarness::assert_ok(&chk, "check converged after bisync");
}

#[test]
fn tier4_scenario_dedupe_and_diagnostics_pipeline() {
    let h = CliHarness::new();
    let (gd_srv, gd_st) = start_gdrive_mock();
    let (od_srv, _) = start_onedrive_mock();
    {
        let mut g = gd_st.lock().unwrap();
        g.seed_file(
            "g1",
            "notes.txt",
            "root",
            b"v1".to_vec(),
            "2026-11-20T00:00:00Z",
        );
        g.seed_file(
            "g2",
            "notes.txt",
            "root",
            b"v2".to_vec(),
            "2026-11-24T00:00:00Z",
        );
    }

    h.write_config(&format!(
        "[remotes.gdmock]\ntype = \"gdrive\"\napi_base_url = \"{gd}/drive/v3\"\nupload_base_url = \"{gd}/upload/drive/v3\"\ntoken_url = \"{gd}/oauth2/token\"\nuse_changes_feed = false\naccess_token = \"SUPER_SECRET_GD_TOKEN\"\n\n{}",
        onedrive_toml("odmock", od_srv.port()),
        gd = gd_srv.base_url()
    ));

    let wire_log = h.path().join("diag_wire.log");
    let dd = h.run_non_interactive(&[
        "--dump",
        "headers",
        "--log-file",
        wire_log.to_str().unwrap(),
        "dedupe",
        "gdmock:",
        "--mode",
        "rename",
        "--json",
    ]);
    CliHarness::assert_ok(&dd, "dedupe rename");
    assert_eq!(CliHarness::parse_json_stdout(&dd)["renamed"], 1);

    let ls = h.run_non_interactive(&["ls", "gdmock:", "--json"]);
    CliHarness::assert_ok(&ls, "ls gdmock after dedupe");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls).as_array().unwrap().len(),
        2
    );

    let data = b"0123diagnostics-binary-stream".to_vec();
    CliHarness::assert_ok(
        &h.run_with_stdin(&["rcat", "odmock:stream.bin"], &data),
        "rcat odmock",
    );
    let cat =
        h.run_non_interactive(&["cat", "odmock:stream.bin", "--offset", "4", "--count", "11"]);
    CliHarness::assert_ok(&cat, "cat odmock");
    assert_eq!(cat.stdout, b"diagnostics");

    let hs = h.run_non_interactive(&["hashsum", "sha256", "odmock:", "--json"]);
    CliHarness::assert_ok(&hs, "hashsum sha256 odmock");
    assert_eq!(
        CliHarness::parse_json_stdout(&hs)[0]["hash"],
        sha256_hex(&data)
    );

    let log_txt = std::fs::read_to_string(&wire_log).unwrap();
    assert!(!log_txt.contains("SUPER_SECRET_GD_TOKEN"));
    assert!(log_txt.contains("***REDACTED***"));
}
