use crate::mock_http::{
    FaultAction, MockResponse, pct_decode, start_azure_mock, start_dropbox_mock, start_gcs_mock,
    start_gdrive_mock, start_onedrive_mock, start_s3_mock, start_webdav_mock,
};
use crate::{
    CliHarness, azure_toml, crypt_toml, dropbox_toml, gcs_toml, gdrive_toml, onedrive_toml,
    s3_toml, webdav_toml,
};
use std::collections::BTreeMap;

// ===========================================================================
// Tier 1: Baseline-Green CLI Operations Across Local, Crypt, and HTTP Mocks
// ===========================================================================

#[test]
fn tier1_local_ls_tree_size_about_mkdir_cat_rcat_hashsum() {
    let h = CliHarness::new();
    let root = h.path().join("local_ops");
    std::fs::create_dir_all(&root).unwrap();

    // mkdir
    let sub = root.join("nested/sub");
    CliHarness::assert_ok(
        &h.run_non_interactive(&["mkdir", sub.to_str().unwrap()]),
        "mkdir",
    );
    assert!(sub.is_dir());

    // rcat (stdin -> file) + cat --offset --count
    let file_a = sub.join("alpha.bin");
    CliHarness::assert_ok(
        &h.run_with_stdin(&["rcat", file_a.to_str().unwrap()], b"0123456789abcdef"),
        "rcat",
    );
    assert_eq!(std::fs::read(&file_a).unwrap(), b"0123456789abcdef");

    let cat_out = h.run_non_interactive(&[
        "cat",
        file_a.to_str().unwrap(),
        "--offset",
        "4",
        "--count",
        "6",
    ]);
    CliHarness::assert_ok(&cat_out, "cat --offset --count");
    assert_eq!(cat_out.stdout, b"456789");

    // ls, ls -r, ls --json
    let ls_out = h.run_non_interactive(&["ls", "-r", "--json", root.to_str().unwrap()]);
    CliHarness::assert_ok(&ls_out, "ls -r --json");
    let entries = CliHarness::parse_json_stdout(&ls_out);
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["nfc_path"] == "nested/sub/alpha.bin")
    );

    // tree -L 1 -d -s
    let tree_out = h.run_non_interactive(&["tree", root.to_str().unwrap(), "-L", "1", "-d", "-s"]);
    CliHarness::assert_ok(&tree_out, "tree -L 1");
    let tree_txt = String::from_utf8_lossy(&tree_out.stdout);
    assert!(tree_txt.contains("nested/"));
    assert!(!tree_txt.contains("alpha.bin"));

    // size --json & about --json
    let size_out = h.run_non_interactive(&["size", root.to_str().unwrap(), "--json"]);
    CliHarness::assert_ok(&size_out, "size --json");
    let sj = CliHarness::parse_json_stdout(&size_out);
    assert_eq!(sj["count"], 1);
    assert_eq!(sj["bytes"], 16);

    let about_out = h.run_non_interactive(&["about", root.to_str().unwrap(), "--json"]);
    CliHarness::assert_ok(&about_out, "about --json");
    let aj = CliHarness::parse_json_stdout(&about_out);
    assert!(aj["total_bytes"].as_u64().unwrap_or(0) > 0);

    // hashsum sha256 --json, md5, crc32c
    let hs_out = h.run_non_interactive(&["hashsum", "sha256", root.to_str().unwrap(), "--json"]);
    CliHarness::assert_ok(&hs_out, "hashsum sha256 --json");
    let hj = CliHarness::parse_json_stdout(&hs_out);
    assert_eq!(hj.as_array().unwrap().len(), 1);
    assert_eq!(hj[0]["hash_kind"], "sha256");
    CliHarness::assert_ok(
        &h.run_non_interactive(&["hashsum", "md5", root.to_str().unwrap()]),
        "hashsum md5",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["hashsum", "crc32c", root.to_str().unwrap()]),
        "hashsum crc32c",
    );
}

#[test]
fn tier1_local_copy_copyto_sync_move_moveto_delete_purge() {
    let h = CliHarness::new();
    let src = h.path().join("src");
    let dst = h.path().join("dst");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("a.txt"), b"aaa").unwrap();
    std::fs::write(src.join("sub/b.log"), b"bbb").unwrap();
    std::fs::write(dst.join("extra.txt"), b"keep-on-copy").unwrap();

    // copy preserves extra.txt
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ]),
        "copy",
    );
    assert!(dst.join("a.txt").is_file());
    assert!(dst.join("sub/b.log").is_file());
    assert!(dst.join("extra.txt").is_file());

    // sync deletes extra.txt
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "sync",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
            "--json",
        ]),
        "sync",
    );
    assert!(!dst.join("extra.txt").exists());

    // copyto & moveto
    let single_src = h.path().join("single.txt");
    let single_copy = h.path().join("single_copy.txt");
    let single_moved = h.path().join("single_moved.txt");
    std::fs::write(&single_src, b"single-bytes").unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            single_src.to_str().unwrap(),
            single_copy.to_str().unwrap(),
        ]),
        "copyto",
    );
    assert!(single_src.is_file() && single_copy.is_file());
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "moveto",
            single_copy.to_str().unwrap(),
            single_moved.to_str().unwrap(),
        ]),
        "moveto",
    );
    assert!(!single_copy.exists() && single_moved.is_file());

    // delete --include *.log
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "delete",
            dst.to_str().unwrap(),
            "--include",
            "*.log",
            "--json",
        ]),
        "delete --include",
    );
    assert!(!dst.join("sub/b.log").exists());
    assert!(dst.join("a.txt").is_file());

    // move --delete-empty-src-dirs
    let mv_dst = h.path().join("mv_dst");
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "move",
            src.to_str().unwrap(),
            mv_dst.to_str().unwrap(),
            "--delete-empty-src-dirs",
            "--json",
        ]),
        "move --delete-empty-src-dirs",
    );
    assert!(mv_dst.join("a.txt").is_file());
    assert!(!src.join("a.txt").exists());
    assert!(!src.join("sub").exists());

    // purge
    CliHarness::assert_ok(
        &h.run_non_interactive(&["purge", mv_dst.to_str().unwrap(), "--json"]),
        "purge",
    );
    assert!(!mv_dst.join("a.txt").exists());
}

#[test]
fn tier1_local_check_bisync_status_gc() {
    let h = CliHarness::new();
    let dir_a = h.path().join("side_a");
    let dir_b = h.path().join("side_b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();
    std::fs::write(dir_a.join("shared.txt"), b"from-a").unwrap();
    std::fs::write(dir_b.join("from_b.txt"), b"from-b").unwrap();

    // bisync --resync
    let bs1 = h.run_non_interactive(&[
        "bisync",
        dir_a.to_str().unwrap(),
        dir_b.to_str().unwrap(),
        "--resync",
        "--json",
    ]);
    CliHarness::assert_ok(&bs1, "bisync --resync");
    assert!(dir_a.join("from_b.txt").is_file());
    assert!(dir_b.join("shared.txt").is_file());

    // check --json
    let chk = h.run_non_interactive(&[
        "check",
        dir_a.to_str().unwrap(),
        dir_b.to_str().unwrap(),
        "--json",
    ]);
    CliHarness::assert_ok(&chk, "check --json");
    let cj = CliHarness::parse_json_stdout(&chk);
    assert_eq!(cj["ok"], true);
    assert_eq!(cj["differences"], 0);
    assert_eq!(cj["matched"], 2);

    // incremental bisync
    std::fs::write(dir_a.join("inc.txt"), b"inc").unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "bisync",
            dir_a.to_str().unwrap(),
            dir_b.to_str().unwrap(),
            "--json",
        ]),
        "bisync incremental",
    );
    assert!(dir_b.join("inc.txt").is_file());

    // status --json & gc --json
    let st_out = h.run_non_interactive(&["status", "--json"]);
    CliHarness::assert_ok(&st_out, "status --json");
    let sj = CliHarness::parse_json_stdout(&st_out);
    assert!(sj["jobs"].is_array());

    let gc_out = h.run_non_interactive(&["gc", "--json"]);
    CliHarness::assert_ok(&gc_out, "gc --json");
    assert_eq!(CliHarness::parse_json_stdout(&gc_out)["ok"], true);
}

#[test]
fn tier1_crypt_over_local_roundtrip_ops() {
    let h = CliHarness::new();
    let raw_vault = h.path().join("raw_vault");
    let plain_src = h.path().join("plain_src");
    std::fs::create_dir_all(&raw_vault).unwrap();
    std::fs::create_dir_all(&plain_src).unwrap();
    std::fs::write(plain_src.join("secret.txt"), b"top-secret-contents-12345").unwrap();

    h.write_config(&format!(
        "[remotes.rawloc]\ntype = \"local\"\nroot = {:?}\n\n{}",
        raw_vault,
        crypt_toml("vault", "rawloc:")
    ));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["mkdir", "vault:folder"]),
        "crypt mkdir",
    );
    CliHarness::assert_ok(
        &h.run_with_stdin(&["rcat", "vault:folder/piped.txt"], b"piped-crypt-data"),
        "crypt rcat",
    );
    let cat_out = h.run_non_interactive(&[
        "cat",
        "vault:folder/piped.txt",
        "--offset",
        "6",
        "--count",
        "5",
    ]);
    CliHarness::assert_ok(&cat_out, "crypt cat");
    assert_eq!(cat_out.stdout, b"crypt");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["copy", plain_src.to_str().unwrap(), "vault:", "--json"]),
        "copy to crypt",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "check",
            plain_src.to_str().unwrap(),
            "vault:",
            "--one-way",
            "--json",
        ]),
        "check crypt",
    );

    let ls_out = h.run_non_interactive(&["ls", "-r", "--json", "vault:"]);
    CliHarness::assert_ok(&ls_out, "crypt ls");
    let entries = CliHarness::parse_json_stdout(&ls_out);
    assert_eq!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["kind"] == "file")
            .count(),
        2
    );

    // Ensure disk contents are NOT plaintext.
    for entry in std::fs::read_dir(&raw_vault).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            let bytes = std::fs::read(&p).unwrap();
            assert!(!bytes.windows(10).any(|w| w == b"top-secret"));
        }
    }

    let sz = h.run_non_interactive(&["size", "vault:", "--json"]);
    CliHarness::assert_ok(&sz, "crypt size");
    assert_eq!(CliHarness::parse_json_stdout(&sz)["count"], 2);

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "vault:secret.txt", "--json"]),
        "crypt delete",
    );
}

#[test]
fn tier1_s3_mock_cli_crud_copy_sync_gc_multipart() {
    let h = CliHarness::new();
    let (srv, st) = start_s3_mock("test-bucket");
    {
        st.lock().unwrap().seed_incomplete_upload(
            "stale/part.bin",
            "stale-uid-1",
            "2020-01-01T00:00:00.000Z",
        );
    }
    h.write_config(&s3_toml("s3mock", srv.port(), "aws", false));

    let src = h.path().join("s3_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("small.txt"), b"hello-s3-world").unwrap();
    // > 16 MiB triggers multipart upload with --chunk-size 5M
    let big = vec![0x5Au8; 17 * 1024 * 1024];
    std::fs::write(src.join("big.bin"), &big).unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            "s3mock:",
            "--chunk-size",
            "5M",
            "--json",
        ]),
        "s3 copy",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.raw_target.contains("uploadId="))
    );

    let ls_out = h.run_non_interactive(&["ls", "s3mock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "s3 ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        2
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["check", src.to_str().unwrap(), "s3mock:", "--json"]),
        "s3 check",
    );

    let cat_out =
        h.run_non_interactive(&["cat", "s3mock:small.txt", "--offset", "6", "--count", "2"]);
    CliHarness::assert_ok(&cat_out, "s3 cat");
    assert_eq!(cat_out.stdout, b"s3");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "s3mock:small.txt", "--json"]),
        "s3 delete",
    );

    let gc_out = h.run_non_interactive(&[
        "gc",
        "--remote-multipart",
        "s3mock:",
        "--older-than",
        "0s",
        "--json",
    ]);
    CliHarness::assert_ok(&gc_out, "s3 gc --remote-multipart");
    let gcj = CliHarness::parse_json_stdout(&gc_out);
    assert_eq!(gcj["aborted"], 1);
    assert_eq!(st.lock().unwrap().aborted_uploads.len(), 1);
}

#[test]
fn tier1_gcs_mock_cli_copy_ls_check_delete() {
    let h = CliHarness::new();
    let (srv, _) = start_gcs_mock("test-bucket");
    h.write_config(&gcs_toml("gcsmock", srv.port()));

    let src = h.path().join("gcs_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("small.txt"), b"gcs-small-data").unwrap();
    // > 8 MiB triggers GCS resumable upload
    std::fs::write(
        src.join("resumable.bin"),
        vec![0x33u8; 8 * 1024 * 1024 + 512],
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            "gcsmock:",
            "--chunk-size",
            "1M",
            "--json",
        ]),
        "gcs copy",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.raw_target.contains("uploadType=resumable"))
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.raw_target.contains("uploadType=multipart"))
    );

    let ls_out = h.run_non_interactive(&["ls", "gcsmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "gcs ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        2
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["check", src.to_str().unwrap(), "gcsmock:", "--json"]),
        "gcs check",
    );

    let cat_out = h.run_non_interactive(&["cat", "gcsmock:small.txt"]);
    CliHarness::assert_ok(&cat_out, "gcs cat");
    assert_eq!(cat_out.stdout, b"gcs-small-data");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gcsmock:small.txt", "--json"]),
        "gcs delete",
    );
}

#[test]
fn tier1_azureblob_mock_cli_copy_ls_check_delete() {
    let h = CliHarness::new();
    let (srv, _) = start_azure_mock("test-container");
    h.write_config(&azure_toml("azmock", srv.port()));

    let src = h.path().join("az_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("small.txt"), b"azure-small-data").unwrap();
    // > 16 MiB triggers PutBlock + PutBlockList
    std::fs::write(
        src.join("blocks.bin"),
        vec![0x77u8; 16 * 1024 * 1024 + 1024],
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            "azmock:",
            "--chunk-size",
            "8M",
            "--json",
        ]),
        "azure copy",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.raw_target.contains("comp=blocklist"))
    );

    let ls_out = h.run_non_interactive(&["ls", "azmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "azure ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        2
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["check", src.to_str().unwrap(), "azmock:", "--json"]),
        "azure check",
    );

    let cat_out = h.run_non_interactive(&["cat", "azmock:small.txt"]);
    CliHarness::assert_ok(&cat_out, "azure cat");
    assert_eq!(cat_out.stdout, b"azure-small-data");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "azmock:small.txt", "--json"]),
        "azure delete",
    );
}

#[test]
fn tier1_gdrive_mock_cli_copy_ls_about_dedupe_delete() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        let mut g = st.lock().unwrap();
        g.seed_file(
            "dup-1",
            "dup.txt",
            "root",
            b"old".to_vec(),
            "2026-11-20T00:00:00Z",
        );
        g.seed_file(
            "dup-2",
            "dup.txt",
            "root",
            b"new".to_vec(),
            "2026-11-24T00:00:00Z",
        );
    }
    h.write_config(&gdrive_toml("gdmock", srv.port(), Some(false)));

    let about_out = h.run_non_interactive(&["about", "gdmock:", "--json"]);
    CliHarness::assert_ok(&about_out, "gdrive about");
    assert_eq!(
        CliHarness::parse_json_stdout(&about_out)["total_bytes"],
        10_737_418_240u64
    );

    let dedupe_skip = h.run_non_interactive(&["dedupe", "gdmock:", "--mode", "skip", "--json"]);
    CliHarness::assert_ok(&dedupe_skip, "gdrive dedupe skip");
    assert_eq!(
        CliHarness::parse_json_stdout(&dedupe_skip)["duplicate_groups"],
        1
    );

    let dedupe_ren = h.run_non_interactive(&["dedupe", "gdmock:", "--mode", "rename", "--json"]);
    CliHarness::assert_ok(&dedupe_ren, "gdrive dedupe rename");
    assert_eq!(CliHarness::parse_json_stdout(&dedupe_ren)["renamed"], 1);

    let src_file = h.path().join("up.txt");
    std::fs::write(&src_file, b"drive-upload").unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src_file.to_str().unwrap(),
            "gdmock:up.txt",
            "--json",
        ]),
        "gdrive copyto",
    );

    let ls_out = h.run_non_interactive(&["ls", "gdmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "gdrive ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        3
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gdmock:up.txt", "--json"]),
        "gdrive delete",
    );
}

#[test]
fn tier1_onedrive_mock_cli_copy_ls_about_delete() {
    let h = CliHarness::new();
    let (srv, _) = start_onedrive_mock();
    h.write_config(&onedrive_toml("odmock", srv.port()));

    let about_out = h.run_non_interactive(&["about", "odmock:", "--json"]);
    CliHarness::assert_ok(&about_out, "onedrive about");
    assert_eq!(
        CliHarness::parse_json_stdout(&about_out)["total_bytes"],
        100_000_000u64
    );

    let src = h.path().join("od_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("small.txt"), b"onedrive-small").unwrap();
    // > 4 MiB triggers createUploadSession; 3200 KiB = 10 * 320 KiB alignment
    std::fs::write(src.join("big.bin"), vec![0x44u8; 4 * 1024 * 1024 + 1024]).unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            "odmock:",
            "--chunk-size",
            "3200K",
            "--json",
        ]),
        "onedrive copy",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.path.contains("createUploadSession"))
    );

    let ls_out = h.run_non_interactive(&["ls", "odmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "onedrive ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let cat_out = h.run_non_interactive(&["cat", "odmock:small.txt"]);
    CliHarness::assert_ok(&cat_out, "onedrive cat");
    assert_eq!(cat_out.stdout, b"onedrive-small");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "odmock:small.txt", "--json"]),
        "onedrive delete",
    );
}

#[test]
fn tier1_dropbox_mock_cli_copy_ls_about_move_delete() {
    let h = CliHarness::new();
    let (srv, _) = start_dropbox_mock();
    h.write_config(&dropbox_toml("dbxmock", srv.port()));

    let about_out = h.run_non_interactive(&["about", "dbxmock:", "--json"]);
    CliHarness::assert_ok(&about_out, "dropbox about");
    assert_eq!(
        CliHarness::parse_json_stdout(&about_out)["total_bytes"],
        2_000_000_000u64
    );

    let src = h.path().join("dbx_src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"dropbox-hello").unwrap();
    std::fs::write(src.join("big.bin"), vec![0x22u8; 4 * 1024 * 1024 + 512]).unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copy",
            src.to_str().unwrap(),
            "dbxmock:",
            "--chunk-size",
            "4M",
            "--json",
        ]),
        "dropbox copy",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.path == "/2/files/upload_session/finish")
    );

    let ls_out = h.run_non_interactive(&["ls", "dbxmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "dropbox ls");
    assert_eq!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .len(),
        2
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["moveto", "dbxmock:a.txt", "dbxmock:b.txt", "--json"]),
        "dropbox moveto",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "dbxmock:b.txt", "--json"]),
        "dropbox delete",
    );
}

#[test]
fn tier1_webdav_mock_cli_copy_ls_about_mkdir_delete() {
    let h = CliHarness::new();
    let (srv, _) = start_webdav_mock();
    h.write_config(&webdav_toml("davmock", srv.port(), "nextcloud"));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["mkdir", "davmock:docs"]),
        "webdav mkdir",
    );
    let src_file = h.path().join("note.txt");
    std::fs::write(&src_file, b"webdav-payload").unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src_file.to_str().unwrap(),
            "davmock:docs/note.txt",
            "--json",
        ]),
        "webdav copyto",
    );

    let about_out = h.run_non_interactive(&["about", "davmock:", "--json"]);
    CliHarness::assert_ok(&about_out, "webdav about");
    assert_eq!(
        CliHarness::parse_json_stdout(&about_out)["total_bytes"],
        10_000_000u64
    );

    let ls_out = h.run_non_interactive(&["ls", "-r", "davmock:", "--json"]);
    CliHarness::assert_ok(&ls_out, "webdav ls");
    assert!(
        CliHarness::parse_json_stdout(&ls_out)
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["nfc_path"] == "docs/note.txt")
    );

    let cat_out = h.run_non_interactive(&["cat", "davmock:docs/note.txt"]);
    CliHarness::assert_ok(&cat_out, "webdav cat");
    assert_eq!(cat_out.stdout, b"webdav-payload");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "davmock:docs/note.txt", "--json"]),
        "webdav delete",
    );
}

// ===========================================================================
// Tier 2: P0 / P1 / R2 Wire & Filesystem Acceptance Probes
// ===========================================================================

#[test]
fn tier2_tree_max_depth_zero_returns_empty() {
    let h = CliHarness::new();
    let root = h.path().join("tree_root");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();
    std::fs::write(root.join("sub/file.txt"), b"nested").unwrap();

    let (dav_srv, dav_st) = start_webdav_mock();
    {
        let mut g = dav_st.lock().unwrap();
        g.seed_file("top.txt", b"top".to_vec());
        g.seed_file("sub/file.txt", b"nested".to_vec());
    }
    h.write_config(&webdav_toml("davmock", dav_srv.port(), "nextcloud"));

    for target in [root.to_str().unwrap(), "davmock:"] {
        let out = h.run_non_interactive(&["tree", target, "-L", "0"]);
        CliHarness::assert_ok(&out, &format!("tree -L 0 on {target}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("0 directories, 0 files"),
            "tree -L 0 on `{target}` MUST return 0 directories, 0 files; got:\n{stdout}"
        );
        assert!(
            !stdout.contains("top.txt"),
            "tree -L 0 leaked child file on `{target}`:\n{stdout}"
        );
        assert!(
            !stdout.contains("sub"),
            "tree -L 0 leaked child dir on `{target}`:\n{stdout}"
        );
    }
}

#[test]
fn tier2_nfd_paths_in_ls_sync_move() {
    let h = CliHarness::new();
    let (dav_srv, dav_st) = start_webdav_mock();
    // Seed NFD directory `cafe\u{0301}` ("café" decomposed) on WebDAV mock.
    let nfd_dir = "cafe\u{0301}";
    {
        dav_st
            .lock()
            .unwrap()
            .seed_file(&format!("{nfd_dir}/sub/note.txt"), b"nfd-bytes".to_vec());
    }
    h.write_config(&webdav_toml("davmock", dav_srv.port(), "nextcloud"));

    // 1. Recursive `ls -r` must NOT drop `sub/note.txt` under NFD parent!
    let ls_out = h.run_non_interactive(&["ls", "-r", "--json", "davmock:"]);
    CliHarness::assert_ok(&ls_out, "nfd ls -r");
    let entries = CliHarness::parse_json_stdout(&ls_out);
    assert!(
        entries
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "file" && e["nfc_path"] == "café/sub/note.txt"),
        "recursive ls dropped NFD subtree! entries={entries}"
    );

    // 2a. `sync` from WebDAV to local must read `cafe\u{0301}/sub/note.txt` cleanly via listed `raw_path`.
    let local_dst = h.path().join("nfd_sync_dst");
    std::fs::create_dir_all(&local_dst).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&["sync", "davmock:", local_dst.to_str().unwrap(), "--json"]),
        "nfd sync davmock -> local",
    );
    let synced_note = [
        local_dst.join(format!("{nfd_dir}/sub/note.txt")),
        local_dst.join("café/sub/note.txt"),
    ]
    .into_iter()
    .find(|p| p.is_file())
    .unwrap_or_else(|| panic!("synced NFD file missing under {}", local_dst.display()));
    assert_eq!(std::fs::read(&synced_note).unwrap(), b"nfd-bytes");

    // 2b. Seed two NFC-colliding names under the NFD parent and run `dedupe --mode rename`:
    // `dedupe` invokes `WebdavBackend::rename` using the listed `raw_path`, which must preserve
    // the exact NFD parent directory in the `MOVE` `Destination` header and stored path!
    {
        let mut g = dav_st.lock().unwrap();
        g.seed_file(
            &format!("{nfd_dir}/sub/dupe\u{0301}.txt"),
            b"nfd-dup-1".to_vec(),
        );
        g.seed_file(
            &format!("{nfd_dir}/sub/dup\u{00e9}.txt"),
            b"nfc-dup-2".to_vec(),
        );
    }
    let dedupe_out = h.run_non_interactive(&["dedupe", "davmock:", "--mode", "rename", "--json"]);
    CliHarness::assert_ok(&dedupe_out, "nfd dedupe rename");
    let dj = CliHarness::parse_json_stdout(&dedupe_out);
    assert_eq!(dj["ok"], true);
    assert_eq!(
        dj["renamed"], 1,
        "expected 1 NFC-colliding duplicate renamed: {dj}"
    );

    let expected_nfd_dst = format!("/remote.php/dav/files/alice/{nfd_dir}/sub/dupé-1.txt");
    let has_nfd_move = dav_srv.requests().iter().any(|r| {
        r.method == "MOVE"
            && r.header("destination")
                .is_some_and(|d| pct_decode(d).ends_with(&expected_nfd_dst))
    });
    assert!(
        has_nfd_move,
        "WebDAV rename MOVE Destination did not preserve exact NFD parent directory `{expected_nfd_dst}`: {:?}",
        dav_srv.requests()
    );
    let has_nfd_file = dav_st.lock().unwrap().files.contains_key(&expected_nfd_dst);
    assert!(
        has_nfd_file,
        "WebDAV rename under NFD parent did not store file at `{expected_nfd_dst}`"
    );
}

#[test]
fn tier2_check_json_exit_1_on_mismatch_and_s3_sse_kms_etag() {
    let h = CliHarness::new();
    let src = h.path().join("chk_src");
    let dst = h.path().join("chk_dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();

    std::fs::write(src.join("hash_diff.txt"), b"abcd").unwrap();
    std::fs::write(dst.join("hash_diff.txt"), b"wxyz").unwrap();
    std::fs::write(src.join("size_diff.txt"), b"12345").unwrap();
    std::fs::write(dst.join("size_diff.txt"), b"123").unwrap();
    std::fs::write(src.join("only_src.txt"), b"only").unwrap();

    // Part A: local mismatch -> exit 1 (`EXIT_ERROR`), ok=false, counts exact
    let chk = h.run_non_interactive(&[
        "check",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(chk.status.code(), Some(1), "check mismatch must exit 1");
    let cj = CliHarness::parse_json_stdout(&chk);
    assert_eq!(cj["ok"], false);
    assert_eq!(cj["exit_code"], 1);
    assert_eq!(cj["differences"], 3);
    assert_eq!(cj["counts"]["hash_mismatch"], 1);
    assert_eq!(cj["counts"]["size_mismatch"], 1);
    assert_eq!(cj["counts"]["missing_on_dst"], 1);

    // Part B: S3 SSE-KMS ETag is NOT MD5 -> `check` must NOT fail with false hash_mismatch!
    let (s3_srv, s3_st) = start_s3_mock("test-bucket");
    let payload = b"kms-encrypted-object-bytes".to_vec();
    {
        let mut g = s3_st.lock().unwrap();
        g.sse_kms_mode = true;
        g.seed_object("secret.bin", payload.clone());
    }
    let kms_src = h.path().join("kms_src");
    std::fs::create_dir_all(&kms_src).unwrap();
    std::fs::write(kms_src.join("secret.bin"), &payload).unwrap();
    h.write_config(&s3_toml("s3kms", s3_srv.port(), "aws", true));

    let kms_chk = h.run_non_interactive(&["check", kms_src.to_str().unwrap(), "s3kms:", "--json"]);
    let kcj = CliHarness::parse_json_stdout(&kms_chk);
    assert_eq!(
        kcj["counts"]["hash_mismatch"], 0,
        "SSE-KMS non-MD5 ETag must NOT trigger false hash_mismatch: {kcj}"
    );
    assert_eq!(
        kcj["differences"], 0,
        "expected 0 differences on SSE-KMS check: {kcj}"
    );
    assert!(kms_chk.status.success());
}

#[test]
fn tier2_max_delete_circuit_breaker_exit_conflict_2() {
    let h = CliHarness::new();
    let src = h.path().join("md_src");
    let dst = h.path().join("md_dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::write(src.join("keep.txt"), b"keep").unwrap();
    std::fs::write(dst.join("keep.txt"), b"keep").unwrap();
    std::fs::write(dst.join("victim.txt"), b"must-not-be-deleted").unwrap();

    // 1. sync --max-delete 0
    let sync_out = h.run_non_interactive(&[
        "sync",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
        "--max-delete",
        "0",
        "--json",
    ]);
    assert_eq!(sync_out.status.code(), Some(2));
    let sj = CliHarness::parse_json_stdout(&sync_out);
    assert_eq!(sj["ok"], false);
    assert_eq!(sj["exit_code"], 2);
    assert_eq!(sj["error_category"], "conflict");
    assert!(dst.join("victim.txt").is_file());

    // 2. delete --max-delete 0
    let del_out = h.run_non_interactive(&[
        "delete",
        dst.to_str().unwrap(),
        "--max-delete",
        "0",
        "--json",
    ]);
    assert_eq!(del_out.status.code(), Some(2));
    assert!(dst.join("victim.txt").is_file());

    // 3. purge --max-delete 0
    let purge_out = h.run_non_interactive(&[
        "purge",
        dst.to_str().unwrap(),
        "--max-delete",
        "0",
        "--json",
    ]);
    assert_eq!(purge_out.status.code(), Some(2));
    assert!(dst.join("victim.txt").is_file());

    // 4. bisync --resync then delete on A -> bisync --max-delete 0
    let bs_a = h.path().join("bs_a");
    let bs_b = h.path().join("bs_b");
    std::fs::create_dir_all(&bs_a).unwrap();
    std::fs::create_dir_all(&bs_b).unwrap();
    std::fs::write(bs_a.join("f1.txt"), b"one").unwrap();
    std::fs::write(bs_a.join("f2.txt"), b"two").unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "bisync",
            bs_a.to_str().unwrap(),
            bs_b.to_str().unwrap(),
            "--resync",
            "--json",
        ]),
        "bisync seed",
    );
    std::fs::remove_file(bs_a.join("f2.txt")).unwrap();
    let bs_trip = h.run_non_interactive(&[
        "bisync",
        bs_a.to_str().unwrap(),
        bs_b.to_str().unwrap(),
        "--max-delete",
        "0",
        "--json",
    ]);
    assert_eq!(bs_trip.status.code(), Some(2));
    assert!(bs_b.join("f2.txt").is_file());
}

#[test]
fn tier2_json_and_json_progress_and_dump_headers_log_file() {
    let h = CliHarness::new();
    let (srv, _) = start_s3_mock("test-bucket");
    h.write_config(&s3_toml("s3mock", srv.port(), "aws", false));

    let src = h.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"payload-a").unwrap();
    std::fs::write(src.join("b.txt"), b"payload-b").unwrap();

    // --dump headers --json-progress WITHOUT --log-file must fail fast with EXIT_CONFIG (7)
    let no_log = h.run_non_interactive(&[
        "--dump",
        "headers",
        "copy",
        src.to_str().unwrap(),
        "s3mock:",
        "--json-progress",
    ]);
    assert_eq!(no_log.status.code(), Some(7));

    // With --log-file, stdout is clean JSON, stderr is strict JSONL, and wire.log redacts secrets.
    let wire_log = h.path().join("logs/wire.log");
    let out = h.run_non_interactive(&[
        "--dump",
        "headers",
        "--log-file",
        wire_log.to_str().unwrap(),
        "copy",
        src.to_str().unwrap(),
        "s3mock:",
        "--json",
        "--json-progress",
        "--stats",
        "20ms",
    ]);
    CliHarness::assert_ok(&out, "copy with dump headers + json-progress");
    let summary = CliHarness::parse_json_stdout(&out);
    assert_eq!(summary["ok"], true);
    assert_eq!(summary["files_transferred"], 2);

    let stderr = String::from_utf8_lossy(&out.stderr);
    let events: Vec<serde_json::Value> = stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("strict JSONL stderr line"))
        .collect();
    assert!(events.iter().any(|ev| ev["event"] == "progress"));

    let log_txt = std::fs::read_to_string(&wire_log).unwrap();
    assert!(log_txt.contains(">>> HTTP REQUEST"));
    assert!(log_txt.contains("<<< HTTP RESPONSE"));
    assert!(!log_txt.contains("SECRET_TEST"));
    assert!(log_txt.contains("***REDACTED***"));
}

#[test]
fn tier2_oauth_503_429_retry_via_cli() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        let mut g = st.lock().unwrap();
        g.expected_token = Some("gd-fresh-tok-1".to_string());
        g.seed_file(
            "f1",
            "hello.txt",
            "root",
            b"oauth-ok".to_vec(),
            "2026-11-24T12:00:00Z",
        );
    }
    // Inject transient 503 then 429 on `/oauth2/token` before 200.
    srv.push_fault(
        Some("POST"),
        "/oauth2/token",
        FaultAction::Status(MockResponse::new(503, b"service unavailable".to_vec())),
    );
    srv.push_fault(
        Some("POST"),
        "/oauth2/token",
        FaultAction::Status(
            MockResponse::new(429, b"rate limited".to_vec()).with_header("Retry-After", "0"),
        ),
    );

    // Seed expired OAuth token sidecar `tokens/gd_oauth.json`.
    std::fs::create_dir_all(h.state_dir.join("tokens")).unwrap();
    std::fs::write(
        h.state_dir.join("tokens/gd_oauth.json"),
        r#"{"access_token":"expired-tok","refresh_token":"ref-tok-1","token_type":"Bearer","expires_at_unix_secs":1}"#,
    )
    .unwrap();
    h.write_config(&format!(
        "[remotes.gd_oauth]\ntype = \"gdrive\"\nclient_id = \"gd-cid\"\nclient_secret = \"gd-sec\"\napi_base_url = \"{base}/drive/v3\"\nupload_base_url = \"{base}/upload/drive/v3\"\ntoken_url = \"{base}/oauth2/token\"\nuse_changes_feed = false\n",
        base = srv.base_url()
    ));

    let out = h.run_non_interactive(&["ls", "gd_oauth:", "--json"]);
    CliHarness::assert_ok(&out, "gdrive OAuth 503/429 token retry");
    let token_hits = srv
        .requests()
        .iter()
        .filter(|r| r.method == "POST" && r.path == "/oauth2/token")
        .count();
    assert!(
        token_hits >= 3,
        "expected >= 3 POST /oauth2/token attempts (503, 429, 200), got {token_hits}"
    );
}

#[test]
fn tier2_gdrive_use_trash_default_true_patches_trashed() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        st.lock().unwrap().seed_file(
            "f-default-trash",
            "sample.txt",
            "root",
            b"trash-me".to_vec(),
            "2026-11-24T12:00:00Z",
        );
    }
    // Omit `use_trash` in TOML!
    h.write_config(&gdrive_toml("gdmock", srv.port(), None));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gdmock:sample.txt", "--json"]),
        "gdrive delete with omitted use_trash",
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "PATCH"
                && r.path == "/drive/v3/files/f-default-trash"
                && String::from_utf8_lossy(&r.body).contains("\"trashed\":true")
        }),
        "omitted use_trash MUST send PATCH {{\"trashed\":true}}, requests: {reqs:?}"
    );
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/drive/v3/files/f-default-trash"),
        "omitted use_trash MUST NOT send permanent DELETE"
    );
}

#[test]
fn tier2_gdrive_shortcut_delete_isolation() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        let mut g = st.lock().unwrap();
        g.seed_file(
            "tgt-1",
            "outside_secret.txt",
            "outside-folder",
            b"precious-target-data".to_vec(),
            "2026-11-24T12:00:00Z",
        );
        g.seed_shortcut(
            "sc-1",
            "link.txt",
            "root",
            "tgt-1",
            "application/octet-stream",
        );
    }
    h.write_config(&gdrive_toml("gdmock", srv.port(), Some(false)));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gdmock:link.txt", "--json"]),
        "delete gdrive shortcut",
    );
    let reqs = srv.requests();
    assert!(
        !reqs.iter().any(|r| {
            (r.method == "DELETE" || r.method == "PATCH") && r.path == "/drive/v3/files/tgt-1"
        }),
        "deleting a shortcut MUST NOT delete or trash the target `tgt-1`: {reqs:?}"
    );
    let guard = st.lock().unwrap();
    assert!(
        !guard.files.contains_key("sc-1"),
        "shortcut `sc-1` must be deleted"
    );
    assert!(
        guard.files.contains_key("tgt-1"),
        "target file `tgt-1` was destroyed when deleting shortcut `sc-1`!"
    );
}

#[test]
fn tier2_webdav_207_multistatus_failure_on_move_preserves_source() {
    let h = CliHarness::new();
    let (srv, st) = start_webdav_mock();
    {
        let mut g = st.lock().unwrap();
        g.seed_file("a.txt", b"must-survive-207".to_vec());
        g.move_207_failure = Some((
            "/remote.php/dav/files/alice/b.txt".to_string(),
            "HTTP/1.1 403 Forbidden".to_string(),
        ));
    }
    h.write_config(&webdav_toml("davmock", srv.port(), "nextcloud"));

    let out = h.run_non_interactive(&["moveto", "davmock:a.txt", "davmock:b.txt", "--json"]);
    assert!(
        !out.status.success(),
        "207 Multi-Status containing 403 Forbidden MUST fail `moveto`! stdout={}",
        String::from_utf8_lossy(&out.stdout)
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| r.method == "COPY"),
        "expected `COPY` request to hit WebDAV mock before 207 failure: {reqs:?}"
    );
    assert!(
        !reqs.iter().any(|r| r.method == "DELETE"),
        "source `DELETE` must NOT be attempted after `COPY` returned 207 Multi-Status: {reqs:?}"
    );
    let guard = st.lock().unwrap();
    assert!(
        guard
            .files
            .contains_key("/remote.php/dav/files/alice/a.txt"),
        "source `a.txt` was lost despite 207 Multi-Status COPY failure!"
    );
    assert!(
        !guard
            .files
            .contains_key("/remote.php/dav/files/alice/b.txt"),
        "destination `b.txt` must not be created after 207 Multi-Status failure!"
    );
}

#[test]
fn tier2_crypt_over_local_gt_64mib_and_onedrive_4mib_overwrite() {
    let h = CliHarness::new();
    let raw_vault = h.path().join("raw_vault");
    std::fs::create_dir_all(&raw_vault).unwrap();
    let (od_srv, _) = start_onedrive_mock();

    h.write_config(&format!(
        "[remotes.rawloc]\ntype = \"local\"\nroot = {:?}\n\n{}\n{}\n{}",
        raw_vault,
        crypt_toml("vault_loc", "rawloc:"),
        onedrive_toml("odmock", od_srv.port()),
        crypt_toml("vault_od", "odmock:")
    ));

    // Part A: `crypt` over `local` > 64 MiB overwrite (`DstPrecondition::Existing` ciphertext size bug)
    let big_src = h.path().join("big65.bin");
    let data1 = vec![0x11u8; 65 * 1024 * 1024];
    std::fs::write(&big_src, &data1).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            big_src.to_str().unwrap(),
            "vault_loc:big.bin",
            "--json",
        ]),
        "crypt >64MiB initial upload",
    );

    let mut data2 = vec![0x22u8; 65 * 1024 * 1024];
    data2[1234] = 0x99;
    std::fs::write(&big_src, &data2).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            big_src.to_str().unwrap(),
            "vault_loc:big.bin",
            "--json",
        ]),
        "crypt >64MiB overwrite (DstPrecondition::Existing)",
    );

    let restored = h.path().join("restored65.bin");
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            "vault_loc:big.bin",
            restored.to_str().unwrap(),
            "--json",
        ]),
        "crypt >64MiB readback",
    );
    assert_eq!(std::fs::read(&restored).unwrap(), data2);

    // Part B: `crypt` over OneDrive exact 4 MiB plaintext MUST use chunked `createUploadSession`
    // because OAE2 header + tags push ciphertext > 4 MiB!
    let exact_4m = h.path().join("exact4m.bin");
    std::fs::write(&exact_4m, vec![0x33u8; 4 * 1024 * 1024]).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            exact_4m.to_str().unwrap(),
            "vault_od:exact4m.bin",
            "--json",
        ]),
        "crypt over onedrive 4MiB",
    );
    let reqs = od_srv.requests();
    assert!(
        reqs.iter().any(|r| r.path.contains("createUploadSession")),
        "4 MiB plaintext under crypt over OneDrive MUST use chunked createUploadSession (not single-shot PUT), reqs: {reqs:?}"
    );
}

#[test]
fn tier2_local_symlink_escape_rejection_and_readonly_source_non_pollution() {
    let h = CliHarness::new();
    let root = h.path().join("sandbox_root");
    let outside = h.path().join("outside_secret");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside-secret").unwrap();

    let link_path = root.join("escape");
    let link_created = {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &link_path).is_ok()
        }
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(&outside, &link_path).is_ok() {
                true
            } else {
                // Fall back to NTFS junction (no elevated privilege required on Windows).
                std::process::Command::new("cmd")
                    .args([
                        "/C",
                        "mklink",
                        "/J",
                        link_path.to_str().unwrap(),
                        outside.to_str().unwrap(),
                    ])
                    .output()
                    .is_ok_and(|o| o.status.success())
            }
        }
    };
    assert!(
        link_created,
        "test fixture must create directory symlink/junction"
    );

    let local_in = h.path().join("payload.txt");
    std::fs::write(&local_in, b"escape-attempt").unwrap();
    h.write_config(&format!(
        "[remotes.sandbox]\ntype = \"local\"\nroot = {:?}\n",
        root
    ));

    let cp_out = h.run_non_interactive(&[
        "copyto",
        local_in.to_str().unwrap(),
        "sandbox:escape/pwn.txt",
        "--json",
    ]);
    assert!(
        !cp_out.status.success(),
        "copyto through symlink escape MUST fail, stdout={}",
        String::from_utf8_lossy(&cp_out.stdout)
    );
    assert!(
        !outside.join("pwn.txt").exists(),
        "symlink escape wrote file outside local root!"
    );

    let cat_out = h.run_non_interactive(&["cat", "sandbox:escape/secret.txt"]);
    assert!(
        !cat_out.status.success(),
        "cat through symlink escape MUST fail"
    );

    // Source directory non-pollution across ALL platforms (read-only chmod on Unix)
    {
        let ro_src = h.path().join("ro_src");
        let ro_dst = h.path().join("ro_dst");
        std::fs::create_dir_all(&ro_src).unwrap();
        std::fs::create_dir_all(&ro_dst).unwrap();
        std::fs::write(ro_src.join("data.txt"), b"ro-data").unwrap();
        let before_mtime = std::fs::metadata(&ro_src).unwrap().modified().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ro_src, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        let res = h.run_non_interactive(&[
            "copy",
            ro_src.to_str().unwrap(),
            ro_dst.to_str().unwrap(),
            "--json",
        ]);
        let after_mtime = std::fs::metadata(&ro_src).unwrap().modified().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ro_src, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        CliHarness::assert_ok(&res, "copy from source dir");
        assert_eq!(
            before_mtime, after_mtime,
            "probe_case_sensitivity must NOT modify/pollute source directory mtime!"
        );
        let remnants: Vec<_> = std::fs::read_dir(&ro_src)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".rship-case-probe-")
            })
            .collect();
        assert!(
            remnants.is_empty(),
            "probe_case_sensitivity left probe remnants in source dir: {remnants:?}"
        );
    }
}

#[test]
fn tier2_gcs_azure_rclone_mtime_dual_read_and_write() {
    let h = CliHarness::new();
    let (gcs_srv, gcs_st) = start_gcs_mock("test-bucket");
    let (az_srv, az_st) = start_azure_mock("test-container");

    // Seed legacy & rclone-style mtime metadata on GCS and Azure.
    {
        let mut g = gcs_st.lock().unwrap();
        let mut leg = BTreeMap::new();
        leg.insert(
            "rship-mtime-ns".to_string(),
            "1700000001123456789".to_string(),
        );
        g.seed_object("legacy.txt", b"leg".to_vec(), leg);

        let mut rcl = BTreeMap::new();
        rcl.insert(
            "goog-reserved-file-mtime".to_string(),
            "1700000005.500000000".to_string(),
        );
        g.seed_object("rclone.txt", b"rcl".to_vec(), rcl);
    }
    {
        let mut a = az_st.lock().unwrap();
        let mut leg = BTreeMap::new();
        leg.insert(
            "rship_mtime_ns".to_string(),
            "1700000002123456789".to_string(),
        );
        a.seed_blob("legacy.txt", b"leg".to_vec(), leg);

        let mut rcl = BTreeMap::new();
        rcl.insert("mtime".to_string(), "1700000006.250000000".to_string());
        a.seed_blob("rclone.txt", b"rcl".to_vec(), rcl);
    }

    h.write_config(&format!(
        "{}\n{}",
        gcs_toml("gcsmock", gcs_srv.port()),
        azure_toml("azmock", az_srv.port())
    ));

    let up = h.path().join("up.txt");
    std::fs::write(&up, b"mtime-upload").unwrap();

    // GCS write + dual read
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            up.to_str().unwrap(),
            "gcsmock:uploaded.txt",
            "--json",
        ]),
        "gcs mtime upload",
    );
    {
        let g = gcs_st.lock().unwrap();
        let obj = g.objects.get("uploaded.txt").unwrap();
        assert!(
            obj.metadata.contains_key("goog-reserved-file-mtime"),
            "GCS upload must write rclone `goog-reserved-file-mtime` metadata, got: {:?}",
            obj.metadata
        );
    }
    let gcs_ls = h.run_non_interactive(&["ls", "gcsmock:", "--json"]);
    CliHarness::assert_ok(&gcs_ls, "gcs ls mtime");
    let gcs_entries = CliHarness::parse_json_stdout(&gcs_ls);
    let gcs_arr = gcs_entries.as_array().unwrap();
    assert_eq!(
        gcs_arr
            .iter()
            .find(|e| e["nfc_path"] == "legacy.txt")
            .unwrap()["mtime_ns"],
        1_700_000_001_123_456_789i64
    );
    assert_eq!(
        gcs_arr
            .iter()
            .find(|e| e["nfc_path"] == "rclone.txt")
            .unwrap()["mtime_ns"],
        1_700_000_005_500_000_000i64
    );

    // Azure write + dual read
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            up.to_str().unwrap(),
            "azmock:uploaded.txt",
            "--json",
        ]),
        "azure mtime upload",
    );
    {
        let a = az_st.lock().unwrap();
        let blob = a.blobs.get("uploaded.txt").unwrap();
        assert!(
            blob.metadata.contains_key("mtime"),
            "Azure upload must write rclone `x-ms-meta-mtime` header, got: {:?}",
            blob.metadata
        );
    }
    let az_ls = h.run_non_interactive(&["ls", "azmock:", "--json"]);
    CliHarness::assert_ok(&az_ls, "azure ls mtime");
    let az_entries = CliHarness::parse_json_stdout(&az_ls);
    let az_arr = az_entries.as_array().unwrap();
    assert_eq!(
        az_arr
            .iter()
            .find(|e| e["nfc_path"] == "legacy.txt")
            .unwrap()["mtime_ns"],
        1_700_000_002_123_456_789i64
    );
    assert_eq!(
        az_arr
            .iter()
            .find(|e| e["nfc_path"] == "rclone.txt")
            .unwrap()["mtime_ns"],
        1_700_000_006_250_000_000i64
    );
}

#[test]
fn tier2_azure_percent20_encoding_and_async_copy_status_on_move() {
    let h = CliHarness::new();
    let (srv, st) = start_azure_mock("test-container");
    {
        let mut a = st.lock().unwrap();
        a.seed_blob(
            "dir with space/item.txt",
            b"spaced".to_vec(),
            BTreeMap::new(),
        );
        a.seed_blob("src.txt", b"async-copy-src".to_vec(), BTreeMap::new());
        a.copy_status_override = Some("failed".to_string());
    }
    h.write_config(&azure_toml("azmock", srv.port()));

    // 1. `ls "azmock:dir with space"` must encode spaces as `%20`, NEVER `+`.
    CliHarness::assert_ok(
        &h.run_non_interactive(&["ls", "azmock:dir with space", "--json"]),
        "azure ls space prefix",
    );
    let list_reqs: Vec<_> = srv
        .requests()
        .into_iter()
        .filter(|r| {
            r.raw_query
                .as_deref()
                .is_some_and(|q| q.contains("comp=list"))
        })
        .collect();
    assert!(
        list_reqs.iter().any(|r| {
            r.raw_query.as_deref().is_some_and(|q| {
                q.contains("prefix=dir%20with%20space") && !q.contains("dir+with+space")
            })
        }),
        "Azure prefix query MUST use `%20` instead of `+`: {list_reqs:?}"
    );

    // 2. When CopyBlob returns `x-ms-copy-status: failed` (even with 202), `move` MUST NOT delete source.
    let mv = h.run_non_interactive(&["moveto", "azmock:src.txt", "azmock:dst.txt", "--json"]);
    assert!(
        !mv.status.success(),
        "Azure failed async CopyBlob must fail `moveto`"
    );
    assert!(
        st.lock().unwrap().blobs.contains_key("src.txt"),
        "source `src.txt` must be preserved when Azure CopyBlob fails"
    );
}

#[test]
fn tier2_onedrive_download_url_range_and_416_resume() {
    let h = CliHarness::new();
    let (srv, st) = start_onedrive_mock();
    {
        st.lock()
            .unwrap()
            .seed_file("big.bin", b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_vec());
    }
    h.write_config(&onedrive_toml("odmock", srv.port()));

    // Part A: Range read should use `@microsoft.graph.downloadUrl` (`/download/{id}`) WITHOUT Authorization header.
    let cat_out =
        h.run_non_interactive(&["cat", "odmock:big.bin", "--offset", "10", "--count", "16"]);
    CliHarness::assert_ok(&cat_out, "onedrive cat range");
    assert_eq!(cat_out.stdout, b"ABCDEFGHIJKLMNOP");
    let dl_reqs: Vec<_> = srv
        .requests()
        .into_iter()
        .filter(|r| r.path.starts_with("/download/"))
        .collect();
    assert!(
        !dl_reqs.is_empty(),
        "expected OneDrive Range read to hit pre-authenticated @microsoft.graph.downloadUrl `/download/...`, got: {:?}",
        srv.requests()
    );
    assert!(
        dl_reqs.iter().all(|r| r.header("authorization").is_none()),
        "pre-authenticated downloadUrl MUST NOT send Authorization header: {dl_reqs:?}"
    );

    // Part B: Inject 416 fragmentOverlap on upload chunk PUT -> must resume via `GET /upload/{sid}` and succeed.
    let up_file = h.path().join("up5m.bin");
    std::fs::write(&up_file, vec![0x55u8; 4 * 1024 * 1024 + 1024]).unwrap();
    srv.push_fault(
        Some("PUT"),
        "/upload/",
        FaultAction::Status(MockResponse::json(
            416,
            &serde_json::json!({ "error": { "code": "fragmentOverlap" } }),
        )),
    );
    let up_out = h.run_non_interactive(&[
        "copyto",
        up_file.to_str().unwrap(),
        "odmock:up5m.bin",
        "--chunk-size",
        "3200K",
        "--json",
    ]);
    CliHarness::assert_ok(&up_out, "onedrive 416 fragmentOverlap recovery");
}

#[test]
fn tier2_webdav_nextcloud_chunked_v2_headers_and_numeric_chunks() {
    let h = CliHarness::new();
    let (dav_srv, dav_st) = start_webdav_mock();
    h.write_config(&webdav_toml("davmock", dav_srv.port(), "nextcloud"));

    // 10.5 MiB with 1 MiB chunks -> 11 chunks (>= 10) exercising Nextcloud Chunking v2
    // `Destination` headers on MKCOL/chunk PUT/MOVE, `OC-Total-Length`, and `1..=11` numeric names.
    let total_len = 10 * 1024 * 1024 + 512;
    let payload: Vec<u8> = (0..total_len).map(|i| (i % 251) as u8).collect();
    let src = h.path().join("nc_v2.bin");
    std::fs::write(&src, &payload).unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src.to_str().unwrap(),
            "davmock:nc_v2.bin",
            "--chunk-size",
            "1M",
            "--json",
        ]),
        "nextcloud chunked v2 copyto",
    );

    let reqs = dav_srv.requests();
    let expected_dst = "/remote.php/dav/files/alice/nc_v2.bin";
    let expected_total = total_len.to_string();

    let mkcols: Vec<_> = reqs
        .iter()
        .filter(|r| r.method == "MKCOL" && r.path.starts_with("/remote.php/dav/uploads/alice/"))
        .collect();
    assert!(
        !mkcols.is_empty(),
        "expected MKCOL under uploads root: {reqs:?}"
    );
    assert!(
        mkcols.iter().all(|r| {
            r.header("destination")
                .is_some_and(|d| pct_decode(d).ends_with(expected_dst))
        }),
        "Nextcloud Chunking v2 MKCOL must include Destination header: {mkcols:?}"
    );

    let chunk_puts: Vec<_> = reqs
        .iter()
        .filter(|r| r.method == "PUT" && r.path.starts_with("/remote.php/dav/uploads/alice/"))
        .collect();
    assert_eq!(
        chunk_puts.len(),
        11,
        "expected 11 chunk PUTs: {chunk_puts:?}"
    );
    let chunk_names: Vec<&str> = chunk_puts
        .iter()
        .map(|r| {
            r.path
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("")
        })
        .collect();
    let expected_names: Vec<String> = (1..=11).map(|i| i.to_string()).collect();
    assert_eq!(
        chunk_names,
        expected_names
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "Nextcloud Chunking v2 chunks must be named `1..=11`"
    );
    assert!(
        chunk_puts.iter().all(|r| {
            r.header("destination")
                .is_some_and(|d| pct_decode(d).ends_with(expected_dst))
                && r.header("oc-total-length") == Some(expected_total.as_str())
        }),
        "Nextcloud Chunking v2 chunk PUTs must include Destination & OC-Total-Length: {chunk_puts:?}"
    );

    let move_req = reqs
        .iter()
        .find(|r| r.method == "MOVE" && r.path.ends_with("/.file"))
        .expect("expected MOVE /.file");
    assert!(
        move_req
            .header("destination")
            .is_some_and(|d| pct_decode(d).ends_with(expected_dst))
            && move_req.header("oc-total-length") == Some(expected_total.as_str()),
        "MOVE /.file must include Destination & OC-Total-Length: {move_req:?}"
    );

    let stored = dav_st
        .lock()
        .unwrap()
        .files
        .get(expected_dst)
        .cloned()
        .expect("assembled file missing in WebDAV mock");
    assert_eq!(
        stored, payload,
        "assembled payload corrupted (check numeric 1..=11 chunk ordering)"
    );
}
