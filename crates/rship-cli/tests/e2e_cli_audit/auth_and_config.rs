use crate::CliHarness;
use crate::mock_http::{
    MockHttpServer, MockResponse, start_dropbox_mock, start_gdrive_mock, start_webdav_mock,
};
use std::io::{BufRead, BufReader, Write};
use std::process::Stdio;

// Throwaway 2048-bit RSA PKCS#8 private key generated strictly for local unit/E2E SA JSON tests.
const TEST_ONLY_RSA_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDmCGt+/C78UGk0\n\
yeovLQgL8+WSNGb5Z8LQGlZskqYY1utPb/oJmjrZGezy+NCq3aoHnZJskgWip7eB\n\
w975E8d91fr8Y9EU895ZRamGOeiWtv2LWjgi3BCTHykSay661LQnV2jhgTd78gxZ\n\
wGONyX8tvHbri2ppSY4pyWq9bbR6XqiWjU/0IEC9Ldgfilx+i2sWJSWF6+pRiqER\n\
e9InRz/G6LIzaCHqmYDeFNxbeE2AzToE5RNOxBKTP2bzHWYTe7ttrIU/pBhgJnu2\n\
giRNGFUuvp1IJ2Pofl8tEJ1QUbO7O/M+70vcZ1zh4Pux8NC67hhjzuWwx2VTzogd\n\
GrjV2k/tAgMBAAECggEBAM6rp/DaIFi+4hb0hjvGaKFciti1zgKsL8KKtzUq+KH+\n\
jkG7qFjyQYcGnPWbiNbK+tWGw6RZ+UgvCVdEJNOB6szq8GnMQHBjvlRUmz+mTYsD\n\
c369GwxuzVFxQJR0yfI/4nAqP2fDkZcBXAlTKd6ct2/fELUFeCCKXni6pvT0WJ9L\n\
MhynYupx5maG6SG4Z81YeGyI4FJlr4W1Im1K8YwPhgdch/Q4VFJh6+KW2MoVk0IN\n\
jh9sSPm+AqK15DIa++yMxnJGbP1pFd52i29E0UJ6q19Hl6re9+OVqrV9YZUjmmek\n\
g78F2s/PbMwrGlontgtrITFJ7Qj6vytC6HVy5r3QfF0CgYEA/PV8v8oFJY2GhUQ6\n\
dgNy7I+xaVHCKOAsozf86g4KRP6EjBXoct8rMS62kV2uGCuFIM3UqSGqWcusKmbv\n\
Xw+5Gx476a29FjGTXqJH6/5q7G9gfiUDkHlYUZGAWr/fhCGULAE+QPvGT/0in4jO\n\
zD68ubWgu3LczhpoQ30bNLDUDl8CgYEA6Mxf9ZXRYczsak9gm0C1YkYDQ4fclVii\n\
YHakxH6s4JjFrj6TQmQniHXJsZ2y2KvNftbswu5akR7gLvX7R8JT8O9PxtOQ71LG\n\
zw4YkyKLLPUcQfyhD0LdR3m/Dfeb04tP//R/t8w3IvA7FOrTMSCVv4L/eRxJlqVb\n\
sg+K37WjbTMCgYEApNkCTCZGRlu9n5mAE6pZuapG7qC2TFcTH+b7rjgqHx5SmMwq\n\
KLog9rM/jOok62FpJ6CbhwEGd/BQKW3dbvDbK73/Q2DSyeTS6igNgNDTM3O9yVcr\n\
xHofwUB2Ci3iZsRPQIIq5MRvT29iod7RDa+Q4+FmduH63WG+MsUT9rmJ6DcCgYB2\n\
yNGt3eQYoxd+p0ID9eCXZGIF8yz6h19TGTa5jGlpsIotfoBlP/VsC63+kxjOtdsE\n\
/WWRkU1k/vwk+h5dXyq1pWZvbURm2TXYMLkZWmbpaaghg2YrA1MlRVnXJqC8MDmB\n\
wJ/qiKkZirqa0bcxOg8uyQjSIzzpQTaohIW34FajQQKBgD19q6viXt20LVgHlEaT\n\
/MWYAO8E6VBjJLkPab2qbYRBNAWNhPU1Nuk3AVg7IpnXf+jU/SzjPB4lDsBheNCO\n\
sbNZFrHlGXqAs4m6vauY7dLLO3Xe9gHs5pDr5DMD+Me51RU7UknqWcXLGj4iCjt6\n\
l8vTzo35m1efRYleCkqZ2kuP\n\
-----END PRIVATE KEY-----\n";

fn write_test_sa_json(path: &std::path::Path, client_email: &str) {
    let payload = serde_json::json!({
        "type": "service_account",
        "project_id": "rship-test-proj",
        "private_key_id": "test-kid-1",
        "private_key": TEST_ONLY_RSA_PKCS8_PEM,
        "client_email": client_email,
        "token_uri": "https://oauth2.googleapis.com/token"
    });
    std::fs::write(path, serde_json::to_vec_pretty(&payload).unwrap()).unwrap();
}

// ===========================================================================
// Tier 1: Baseline-Green Auth & Config Contracts
// ===========================================================================

#[test]
fn tier1_auth_all_10_providers_non_interactive_flags() {
    let h = CliHarness::new();
    let local_root = h.path().join("local_root");
    let vault_dir = h.path().join("vault_raw");
    let sa_path = h.path().join("sa.json");
    let kh_path = h.path().join("known_hosts");
    std::fs::create_dir_all(&local_root).unwrap();
    std::fs::create_dir_all(&vault_dir).unwrap();
    write_test_sa_json(&sa_path, "svc@rship-test.iam.gserviceaccount.com");
    std::fs::write(&kh_path, "").unwrap();

    let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // 1. local
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "local",
            "my-local",
            "--root",
            local_root.to_str().unwrap(),
        ]),
        "auth local",
    );
    // 2. crypt (passphrase + key-hex)
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "crypt",
            "my-vault",
            "--target",
            "my-local:vault",
            "--password",
            "pw-secret",
            "--salt",
            "12345678",
            "--filename-encryption",
            "standard",
        ]),
        "auth crypt password",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "crypt",
            "my-vault-hex",
            "--target",
            vault_dir.to_str().unwrap(),
            "--key-hex",
            hex_key,
            "--filename-encryption",
            "off",
        ]),
        "auth crypt key-hex",
    );
    // 3. s3 (static + env_auth)
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "s3",
            "my-r2",
            "--provider",
            "r2",
            "--bucket",
            "bkt",
            "--region",
            "auto",
            "--endpoint",
            "http://127.0.0.1:9000",
            "--access-key-id",
            "ak-r2",
            "--secret-access-key",
            "sk-r2-secret",
            "--sse",
            "aws:kms",
            "--kms-key-id",
            "alias/k",
            "--send-upload-checksum",
            "false",
            "--pin-read-etag",
            "false",
            "--payload-signing",
            "sha256",
            "--force-path-style",
            "true",
        ]),
        "auth s3 r2",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "s3",
            "my-aws",
            "--provider",
            "aws",
            "--env-auth",
            "--aws-profile",
            "prod",
        ]),
        "auth s3 aws env-auth",
    );
    // 4. gcs (token + anonymous + SA)
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "gcs",
            "my-gcs-tok",
            "--bucket",
            "b1",
            "--access-token",
            "gcs-tok-secret",
            "--storage-class",
            "NEARLINE",
            "--endpoint",
            "http://127.0.0.1:4443",
        ]),
        "auth gcs token",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "gcs", "my-gcs-pub", "--bucket", "b2", "--anonymous"]),
        "auth gcs anon",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "gcs",
            "my-gcs-sa",
            "--service-account-file",
            sa_path.to_str().unwrap(),
            "--impersonate",
            "user@corp.test",
            "--scope",
            "read_write",
        ]),
        "auth gcs sa",
    );
    // 5. azureblob (SharedKey + SAS + emulator + anon)
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "azureblob",
            "my-az-sk",
            "--account",
            "acct",
            "--container",
            "c",
            "--key",
            "dGVzdGtleQ==",
            "--access-tier",
            "Cool",
        ]),
        "auth azure sharedkey",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "azureblob",
            "my-az-sas",
            "--sas-url",
            "https://myacct.blob.core.windows.net?sv=2023-11-03&sig=abc",
        ]),
        "auth azure sas",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "azureblob",
            "my-az-emu",
            "--use-emulator",
            "--container",
            "dev",
        ]),
        "auth azure emu",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "azureblob",
            "my-az-anon",
            "--anonymous",
            "--account",
            "pubacct",
            "--container",
            "pub",
        ]),
        "auth azure anon",
    );
    // 6. gdrive (--guide + SA)
    let guide_out = h.run_non_interactive(&["auth", "gdrive", "my-gd", "--guide"]);
    CliHarness::assert_ok(&guide_out, "auth gdrive guide");
    assert!(String::from_utf8_lossy(&guide_out.stdout).contains("Desktop app"));
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "gdrive",
            "my-gd-sa",
            "--service-account-file",
            sa_path.to_str().unwrap(),
            "--shared-drive-id",
            "0ADrive",
            "--scope",
            "drive.readonly",
        ]),
        "auth gdrive sa",
    );
    // 7. onedrive
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "onedrive",
            "my-od",
            "--access-token",
            "od-tok-secret",
            "--drive-id",
            "b!123",
        ]),
        "auth onedrive",
    );
    // 8. dropbox
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "dropbox",
            "my-dbx",
            "--access-token",
            "dbx-tok-secret",
            "--root-path",
            "/backups",
        ]),
        "auth dropbox",
    );
    // 9. webdav (basic + bearer)
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "webdav",
            "my-nc",
            "--url",
            "https://nc.example/remote.php/dav/files/alice",
            "--vendor",
            "nextcloud",
            "--username",
            "alice",
            "--password",
            "dav-pw-secret",
            "--chunked-upload-root",
            "https://nc.example/remote.php/dav/uploads/alice",
        ]),
        "auth webdav basic",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "webdav",
            "my-alist",
            "--url",
            "http://127.0.0.1:5244/dav",
            "--vendor",
            "alist",
            "--bearer-token",
            "bt-secret",
        ]),
        "auth webdav bearer",
    );
    // 10. sftp
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "sftp",
            "my-sftp",
            "--host",
            "10.0.0.5",
            "--port",
            "2222",
            "--user",
            "deploy",
            "--root-path",
            "/data",
            "--password",
            "sftp-pw-secret",
            "--host-key-policy",
            "strict",
            "--known-hosts",
            kh_path.to_str().unwrap(),
        ]),
        "auth sftp",
    );

    let list_out = h.run_non_interactive(&["config", "list", "--json"]);
    CliHarness::assert_ok(&list_out, "config list --json");
    let arr = CliHarness::parse_json_stdout(&list_out);
    assert_eq!(arr.as_array().unwrap().len(), 18);

    let show_redacted = h.run_non_interactive(&["config", "show"]);
    CliHarness::assert_ok(&show_redacted, "config show");
    let redacted_txt = String::from_utf8_lossy(&show_redacted.stdout);
    for secret in [
        "pw-secret",
        hex_key,
        "sk-r2-secret",
        "gcs-tok-secret",
        "dGVzdGtleQ==",
        "od-tok-secret",
        "dbx-tok-secret",
        "dav-pw-secret",
        "bt-secret",
        "sftp-pw-secret",
    ] {
        assert!(
            !redacted_txt.contains(secret),
            "secret leaked in `config show`: {secret}"
        );
    }
    assert!(redacted_txt.contains("***REDACTED***"));

    let show_plain = h.run_non_interactive(&["config", "show", "--show-secrets"]);
    CliHarness::assert_ok(&show_plain, "config show --show-secrets");
    let plain_txt = String::from_utf8_lossy(&show_plain.stdout);
    assert!(plain_txt.contains("sk-r2-secret"));
    assert!(plain_txt.contains("sftp-pw-secret"));
}

#[test]
fn tier1_auth_non_interactive_fail_fast_matrix() {
    let h = CliHarness::new();
    let cases: Vec<Vec<&str>> = vec![
        vec!["auth", "local"],
        vec!["auth", "local", "a", "--root", "."],
        vec!["auth", "local", "bad:name", "--root", "."],
        vec!["auth", "local", "loc1"],
        vec!["auth", "crypt", "cr1"],
        vec!["auth", "crypt", "cr1", "--target", "/tmp/v"],
        vec![
            "auth",
            "crypt",
            "cr1",
            "--target",
            "/tmp/v",
            "--password",
            "p",
            "--salt",
            "short",
        ],
        vec!["auth", "s3", "s3a"],
        vec![
            "auth",
            "s3",
            "s3a",
            "--provider",
            "r2",
            "--access-key-id",
            "ak",
            "--secret-access-key",
            "sk",
        ],
        vec![
            "auth",
            "s3",
            "s3a",
            "--provider",
            "aws",
            "--env-auth",
            "--sse",
            "AES256",
            "--kms-key-id",
            "k",
        ],
        vec!["auth", "gcs", "g1"],
        vec!["auth", "gcs", "g1", "--client-id", "cid"],
        vec!["auth", "azureblob", "az1"],
        vec!["auth", "azureblob", "az1", "--account", "acct"],
        vec!["auth", "azureblob", "az1", "--anonymous"],
        vec![
            "auth",
            "gdrive",
            "gd1",
            "--client-id",
            "cid",
            "--client-secret",
            "sec",
        ],
        vec![
            "auth",
            "gdrive",
            "gd1",
            "--client-id",
            "cid",
            "--client-secret",
            "sec",
            "--manual",
        ],
        vec!["auth", "onedrive", "od1"],
        vec!["auth", "onedrive", "od1", "--client-id", "cid"],
        vec!["auth", "dropbox", "dbx1"],
        vec!["auth", "dropbox", "dbx1", "--client-id", "cid"],
        vec!["auth", "webdav", "dav1"],
        vec![
            "auth",
            "webdav",
            "dav1",
            "--url",
            "https://dav.example",
            "--username",
            "u",
        ],
        vec!["auth", "sftp", "sf1", "--host", "10.0.0.1", "--user", "u"],
        vec!["config", "edit", "missing"],
    ];
    for args in cases {
        let out = h.run_non_interactive(&args);
        assert_eq!(
            out.status.code(),
            Some(7),
            "expected EXIT_CONFIG (7) for `{args:?}`, got {:?}\nstderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // `auth export` on `local` must fail with EXIT_CONFIG (7)
    let dir = h.path().join("loc_exp");
    std::fs::create_dir_all(&dir).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "local", "loc-exp", "--root", dir.to_str().unwrap()]),
        "auth local",
    );
    let exp_out = h.run_non_interactive(&["auth", "export", "loc-exp"]);
    assert_eq!(exp_out.status.code(), Some(7));
}

#[test]
fn tier1_auth_mode_switching_and_secret_preservation() {
    let h = CliHarness::new();

    // S3 update preserves secret, then --env-auth clears static keys.
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "s3",
            "s3x",
            "--provider",
            "r2",
            "--endpoint",
            "http://127.0.0.1:9000",
            "--bucket",
            "b1",
            "--access-key-id",
            "ak1",
            "--secret-access-key",
            "sk1",
        ]),
        "s3 init",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "s3", "s3x", "--bucket", "b2"]),
        "s3 bucket update",
    );
    let cfg = h.read_config();
    assert!(cfg.contains("bucket = \"b2\""));
    assert!(cfg.contains("secret_access_key = \"sk1\""));

    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "s3", "s3x", "--env-auth"]),
        "s3 env-auth switch",
    );
    let cfg = h.read_config();
    assert!(cfg.contains("env_auth = true"));
    assert!(!cfg.contains("ak1"));
    assert!(!cfg.contains("sk1"));

    // OneDrive OAuth -> static token deletes sidecar token file & clears client_id.
    std::fs::create_dir_all(h.state_dir.join("tokens")).unwrap();
    let od_tok = h.state_dir.join("tokens/odx.onedrive.json");
    std::fs::write(
        &od_tok,
        r#"{"access_token":"old","refresh_token":"ref","token_type":"Bearer","expires_at_unix_secs":1999999999}"#,
    )
    .unwrap();
    h.append_config(
        "[remotes.odx]\ntype = \"onedrive\"\nclient_id = \"cid\"\nclient_secret = \"csec\"\n",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "onedrive", "odx", "--access-token", "new-od-tok"]),
        "onedrive static switch",
    );
    assert!(!od_tok.exists(), "stale token sidecar must be removed");
    let cfg = h.read_config();
    assert!(!cfg.contains("client_id"));
    assert!(cfg.contains("new-od-tok"));
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "onedrive", "odx", "--drive-id", "drv-9"]),
        "onedrive drive-id merge",
    );
    let cfg = h.read_config();
    assert!(cfg.contains("drive_id = \"drv-9\""));
    assert!(cfg.contains("new-od-tok"));

    // Crypt password -> key_hex -> password.
    let vdir = h.path().join("vdir");
    std::fs::create_dir_all(&vdir).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "crypt",
            "crx",
            "--target",
            vdir.to_str().unwrap(),
            "--password",
            "pw1",
        ]),
        "crypt pw",
    );
    let hex_k = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "crypt", "crx", "--key-hex", hex_k]),
        "crypt key-hex switch",
    );
    let cfg = h.read_config();
    assert!(cfg.contains(hex_k));
    assert!(!cfg.contains("pw1"));
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "crypt", "crx", "--password", "pw2"]),
        "crypt pw switch back",
    );
    let cfg = h.read_config();
    assert!(cfg.contains("pw2"));
    assert!(!cfg.contains(hex_k));
}

#[test]
fn tier1_auth_interactive_wizards_and_manual_pkce() {
    let h = CliHarness::new();
    let local_dir = h.path().join("missing_local_dir");

    // 1. Interactive local (creates missing dir)
    let out = h.run_interactive(
        &["auth", "local", "my-loc"],
        &format!("{}\ny\nn\n", local_dir.display()),
    );
    CliHarness::assert_ok(&out, "interactive local");
    assert!(local_dir.is_dir());

    // 2. Interactive s3 (R2 preset=2, static=1, ak, sk, region=Enter, invalid ep retry -> valid ep, bkt, adv=n, keyring=n, test=n)
    let out = h.run_interactive(
        &["auth", "s3", "my-r2"],
        "2\n1\nr2-ak\nr2-sk\n\nftp://bad\nhttp://127.0.0.1:9000\nmy-bkt\nn\nn\nn\n",
    );
    CliHarness::assert_ok(&out, "interactive s3");

    // 3. Interactive gcs (Anonymous=3, bucket, adv=n, test=n)
    CliHarness::assert_ok(
        &h.run_interactive(&["auth", "gcs", "my-gcs"], "3\npub-bkt\nn\nn\n"),
        "interactive gcs",
    );

    // 4. Interactive azureblob (Azurite=3, container, adv=n, keyring=n, test=n)
    CliHarness::assert_ok(
        &h.run_interactive(&["auth", "azureblob", "my-az"], "3\ndev\nn\nn\nn\n"),
        "interactive azureblob",
    );

    // 5. Interactive webdav (Nextcloud=1, url, Basic=1, user, pass, chunked?=n, keyring?=n, test?=n)
    CliHarness::assert_ok(
        &h.run_interactive(
            &["auth", "webdav", "my-dav"],
            "1\nhttps://dav.example/remote.php/dav/files/alice\n1\nalice\npw\nn\nn\nn\n",
        ),
        "interactive webdav",
    );

    // 6. Interactive sftp (host, port=Enter(22), user, auth=Password(1 since no ~/.ssh keys in fake home), pw, root=Enter, policy=1(accept-new), keyring=n, test=n)
    CliHarness::assert_ok(
        &h.run_interactive(
            &["auth", "sftp", "my-sftp"],
            "10.0.0.9\n\nalice\n2\nssh-pw\n\n1\nn\nn\n",
        ),
        "interactive sftp",
    );

    // 7. Interactive crypt (BTreeMap order: my-az=1, my-dav=2, my-gcs=3, my-loc=4, my-r2=5, my-sftp=6)
    // Pick my-loc(4), subpath="enc", key=1(passphrase), mismatch then padded "  pw  ", salt=n, filename=1(standard), keyring=n, test=y
    let out = h.run_interactive(
        &["auth", "crypt", "my-vault"],
        "4\nenc\n1\naaa\nbbb\n  pw  \n  pw  \nn\n1\nn\ny\n",
    );
    CliHarness::assert_ok(&out, "interactive crypt");
    assert!(h.read_config().contains("password = \"  pw  \""));

    // 8. Interactive config edit & config new overwrite decline
    CliHarness::assert_ok(
        &h.run_interactive(&["config", "edit", "my-r2"], "\n1\n\n\n\n\n-\nn\nn\nn\n"),
        "interactive config edit clear bucket",
    );
    assert!(!h.read_config().contains("my-bkt"));
    let decline = h.run_interactive(&["config", "new", "local", "my-loc"], "n\n");
    assert!(!decline.status.success());

    // 9. Interactive --manual PKCE against MockHttpServer `/oauth2/token`
    let pkce_srv = MockHttpServer::start(|req| {
        if req.path == "/oauth2/token" && req.method == "POST" {
            MockResponse::json(
                200,
                &serde_json::json!({
                    "access_token": "manual-pkce-access-tok",
                    "refresh_token": "manual-pkce-refresh-tok",
                    "token_type": "bearer",
                    "expires_in": 3600
                }),
            )
        } else {
            MockResponse::empty(404)
        }
    });
    h.append_config(&format!(
        "[remotes.dbx-pkce]\ntype = \"dropbox\"\ntoken_url = \"{}/oauth2/token\"\n",
        pkce_srv.base_url()
    ));
    let mut child = h
        .cmd()
        .env("RSHIP_FORCE_INTERACTIVE", "1")
        .args([
            "auth",
            "dropbox",
            "dbx-pkce",
            "--client-id",
            "dbx-cid",
            "--manual",
            "--callback-port",
            "0",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn manual pkce");
    let mut stdin = child.stdin.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut auth_line = None;
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line.contains("state=") {
            auth_line = Some(line.trim().to_string());
            break;
        }
        line.clear();
    }
    let url_str = auth_line.expect("auth url with state= printed on stderr");
    let state_val = url_str
        .split("state=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let redirect_uri = url_str
        .split("redirect_uri=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap()
        .replace("%3A", ":")
        .replace("%2F", "/");
    let cb = format!("{redirect_uri}?code=mock-auth-code&state={state_val}\n");
    stdin.write_all(cb.as_bytes()).unwrap();
    // Answer "Test connection now?" = n (or keyring? = n if secret present; dbx-pkce has no client_secret -> only test prompt!)
    stdin.write_all(b"n\nn\n").unwrap();
    drop(stdin);
    let pkce_out = child.wait_with_output().unwrap();
    assert!(
        pkce_out.status.success(),
        "manual PKCE failed: stdout={} stderr={}",
        String::from_utf8_lossy(&pkce_out.stdout),
        String::from_utf8_lossy(&pkce_out.stderr)
    );
    assert!(h.state_dir.join("tokens/dbx-pkce.dropbox.json").is_file());
    assert!(
        pkce_srv
            .requests()
            .iter()
            .any(|r| r.path == "/oauth2/token" && r.method == "POST")
    );
}

#[test]
fn tier1_auth_export_import_all_supported_formats() {
    let h = CliHarness::new();
    let sa_path = h.path().join("sa.json");
    write_test_sa_json(&sa_path, "svc@rship-test.iam.gserviceaccount.com");
    let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "s3",
            "r_s3",
            "--provider",
            "aws",
            "--access-key-id",
            "ak",
            "--secret-access-key",
            "sk",
        ]),
        "s3",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "gcs",
            "r_gcs",
            "--service-account-file",
            sa_path.to_str().unwrap(),
        ]),
        "gcs",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "azureblob",
            "r_az",
            "--use-emulator",
            "--container",
            "c",
        ]),
        "azure",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "gdrive",
            "r_gd",
            "--service-account-file",
            sa_path.to_str().unwrap(),
            "--shared-drive-id",
            "0AD",
        ]),
        "gdrive",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "onedrive", "r_od", "--access-token", "od-t"]),
        "onedrive",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "dropbox", "r_dbx", "--access-token", "dbx-t"]),
        "dropbox",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "webdav",
            "r_dav",
            "--url",
            "https://dav.example/dav",
            "--username",
            "u",
            "--password",
            "p",
        ]),
        "webdav",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "sftp",
            "r_sftp",
            "--host",
            "10.0.0.1",
            "--user",
            "u",
            "--password",
            "p",
        ]),
        "sftp",
    );
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "auth",
            "crypt",
            "r_crypt",
            "--target",
            "/tmp/v",
            "--key-hex",
            hex_key,
        ]),
        "crypt",
    );

    let h2 = CliHarness::new();
    for (idx, name) in [
        "r_s3", "r_gcs", "r_az", "r_gd", "r_od", "r_dbx", "r_dav", "r_sftp", "r_crypt",
    ]
    .iter()
    .enumerate()
    {
        let new_name = format!("imp_{name}");
        if idx % 3 == 0 {
            let file_out = h.path().join(format!("{name}.bundle.json"));
            CliHarness::assert_ok(
                &h.run_non_interactive(&[
                    "auth",
                    "export",
                    name,
                    "--json",
                    "-o",
                    file_out.to_str().unwrap(),
                ]),
                "export -o --json",
            );
            CliHarness::assert_ok(
                &h2.run_non_interactive(&[
                    "auth",
                    "import",
                    "-i",
                    file_out.to_str().unwrap(),
                    "--name",
                    &new_name,
                ]),
                "import -i",
            );
        } else if idx % 3 == 1 {
            let exp = h.run_non_interactive(&["auth", "export", name]);
            CliHarness::assert_ok(&exp, "export compact");
            let bundle = String::from_utf8(exp.stdout).unwrap().trim().to_string();
            CliHarness::assert_ok(
                &h2.run_non_interactive(&[
                    "auth", "import", "--bundle", &bundle, "--name", &new_name,
                ]),
                "import --bundle",
            );
        } else {
            let exp = h.run_non_interactive(&["auth", "export", name]);
            CliHarness::assert_ok(&exp, "export for stdin");
            CliHarness::assert_ok(
                &h2.run_with_stdin(&["auth", "import", "--name", &new_name], &exp.stdout),
                "import stdin",
            );
        }
    }

    let list2 = h2.run_non_interactive(&["config", "list", "--json"]);
    CliHarness::assert_ok(&list2, "h2 config list");
    assert_eq!(
        CliHarness::parse_json_stdout(&list2)
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert!(h2.state_dir.join("tokens/imp_r_gd.sa.json").is_file());
    assert!(h2.state_dir.join("tokens/imp_r_gcs.gcs.sa.json").is_file());
}

#[test]
fn tier1_crypt_password_env_and_wrapping_local_and_http() {
    let h = CliHarness::new();
    let enc_dir = h.path().join("enc");
    let src_file = h.path().join("plain.txt");
    std::fs::create_dir_all(&enc_dir).unwrap();
    std::fs::write(&src_file, b"env-crypt-payload").unwrap();

    let (dav_srv, _) = start_webdav_mock();
    h.write_config(&format!(
        "[remotes.loc]\ntype = \"local\"\nroot = {:?}\n\n\
         [remotes.vault_env]\ntype = \"crypt\"\nremote = \"loc:sub\"\n\n\
         [remotes.dav]\ntype = \"webdav\"\nurl = \"{}/remote.php/dav/files/alice\"\nvendor = \"nextcloud\"\nusername = \"alice\"\npassword = \"secret\"\n\n\
         [remotes.vault_dav]\ntype = \"crypt\"\nremote = \"dav:enc\"\nkey_hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\n",
        enc_dir,
        dav_srv.base_url()
    ));

    // Missing RSHIP_CRYPT_PASSWORD -> EXIT_AUTH (4)
    let no_pw = h.run_non_interactive(&["ls", "vault_env:"]);
    assert_eq!(no_pw.status.code(), Some(4));

    // With RSHIP_CRYPT_PASSWORD -> succeeds
    let out = h
        .cmd()
        .env("RSHIP_CRYPT_PASSWORD", "secret-pass")
        .args([
            "copyto",
            src_file.to_str().unwrap(),
            "vault_env:note.txt",
            "--json",
        ])
        .output()
        .unwrap();
    CliHarness::assert_ok(&out, "crypt copyto with RSHIP_CRYPT_PASSWORD");

    let cat = h
        .cmd()
        .env("RSHIP_CRYPT_PASSWORD", "secret-pass")
        .args(["cat", "vault_env:note.txt"])
        .output()
        .unwrap();
    CliHarness::assert_ok(&cat, "crypt cat");
    assert_eq!(cat.stdout, b"env-crypt-payload");

    // Crypt wrapping HTTP WebDAV mock
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            src_file.to_str().unwrap(),
            "vault_dav:doc.txt",
            "--json",
        ]),
        "crypt over webdav copyto",
    );
    let ls_dav = h.run_non_interactive(&["ls", "vault_dav:", "--json"]);
    CliHarness::assert_ok(&ls_dav, "crypt over webdav ls");
    let entries = CliHarness::parse_json_stdout(&ls_dav);
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["nfc_path"], "doc.txt");
}

#[test]
fn tier1_config_subcommands_and_rclone_import_baseline() {
    let h = CliHarness::new();

    // config path + empty config list
    let p_out = h.run_non_interactive(&["config", "path"]);
    CliHarness::assert_ok(&p_out, "config path");
    assert!(String::from_utf8_lossy(&p_out.stdout).contains("config_file:"));
    let empty_list = h.run_non_interactive(&["config", "list", "--json"]);
    CliHarness::assert_ok(&empty_list, "config list empty");
    assert_eq!(
        CliHarness::parse_json_stdout(&empty_list)
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // rclone.conf via RCLONE_CONFIG env var + --dry-run + obscured password + gdrive client_id warning + unsupported skip
    let rclone_conf = h.path().join("rclone.conf");
    // rclone obscured "secret" -> generated via rclone obscure ("yQ..."? wait: use plaintext or valid rclone obscured? Let's test `config import-rclone` with `--dry-run` + real import + `gdrive` warning!)
    std::fs::write(
        &rclone_conf,
        r#"
[gd_nocid]
type = drive
token = {"access_token":"tok1","token_type":"Bearer","refresh_token":"ref1","expiry":"2027-01-01T00:00:00Z"}

[ftp_skip]
type = ftp
host = ftp.example.com
"#,
    )
    .unwrap();

    let dry_out = h
        .cmd()
        .env("RCLONE_CONFIG", &rclone_conf)
        .args(["config", "import-rclone", "--dry-run"])
        .output()
        .unwrap();
    CliHarness::assert_ok(&dry_out, "import-rclone --dry-run");
    let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
    let dry_stderr = String::from_utf8_lossy(&dry_out.stderr);
    assert!(dry_stdout.contains("would import"));
    assert!(dry_stdout.contains("skipped unsupported remote `ftp_skip`"));
    assert!(dry_stderr.contains("warning:") && dry_stderr.contains("client_id"));
    assert!(!h.cfg_path.exists(), "dry-run must not write config.toml");

    // Real import via RCLONE_CONFIG env
    let imp_out = h
        .cmd()
        .env("RCLONE_CONFIG", &rclone_conf)
        .args(["config", "import-rclone"])
        .output()
        .unwrap();
    CliHarness::assert_ok(&imp_out, "import-rclone real");
    assert!(h.state_dir.join("tokens/gd_nocid.json").is_file());

    // Skip existing without --overwrite, replace with --overwrite
    let skip_out = h
        .cmd()
        .env("RCLONE_CONFIG", &rclone_conf)
        .args(["config", "import-rclone"])
        .output()
        .unwrap();
    CliHarness::assert_ok(&skip_out, "import-rclone skip existing");
    assert!(String::from_utf8_lossy(&skip_out.stdout).contains("existing_skipped=1"));

    let ov_out = h
        .cmd()
        .env("RCLONE_CONFIG", &rclone_conf)
        .args(["config", "import-rclone", "--overwrite"])
        .output()
        .unwrap();
    CliHarness::assert_ok(&ov_out, "import-rclone overwrite");
    assert!(String::from_utf8_lossy(&ov_out.stdout).contains("imported=1 existing_skipped=0"));

    // config test on local remote + config rm cleanup + config rm missing -> EXIT_CONFIG (7)
    let loc_dir = h.path().join("loc_test");
    std::fs::create_dir_all(&loc_dir).unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&["auth", "local", "loc1", "--root", loc_dir.to_str().unwrap()]),
        "auth local",
    );
    let test_out = h.run_non_interactive(&["config", "test", "loc1", "--json"]);
    CliHarness::assert_ok(&test_out, "config test local");
    let tj = CliHarness::parse_json_stdout(&test_out);
    assert_eq!(tj["ok"], true);
    assert_eq!(tj["kind"], "local");

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "rm", "gd_nocid"]),
        "config rm",
    );
    assert!(!h.state_dir.join("tokens/gd_nocid.json").exists());
    let rm_missing = h.run_non_interactive(&["config", "rm", "no_such_remote"]);
    assert_eq!(rm_missing.status.code(), Some(7));
}

// ===========================================================================
// Tier 2: P0 / P1 / R2 Config & `rclone_import` Probes
// ===========================================================================

#[test]
fn tier2_config_import_rclone_rejects_encrypted_rclone_conf() {
    let h = CliHarness::new();
    let enc_conf = h.path().join("encrypted_rclone.conf");
    std::fs::write(
        &enc_conf,
        "# Encrypted rclone configuration File\n\nRCLONE_ENCRYPT_V0:\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
    )
    .unwrap();

    let out = h.run_non_interactive(&["config", "import-rclone", enc_conf.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(7),
        "encrypted rclone.conf MUST fail with EXIT_CONFIG (7), got {:?}, stdout={}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("encrypt") || stderr.contains("decrypt") || stderr.contains("plaintext"),
        "expected clear encrypted-config error message, got: {stderr}"
    );
    assert!(!h.cfg_path.exists(), "must not create config.toml on error");
}

#[test]
fn tier2_config_import_rclone_warns_missing_client_id_for_all_oauth_providers() {
    let h = CliHarness::new();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[gd]
type = drive
token = {"access_token":"t1","token_type":"Bearer","refresh_token":"r1","expiry":"2027-01-01T00:00:00Z"}

[gcs_oauth]
type = google cloud storage
token = {"access_token":"t2","token_type":"Bearer","refresh_token":"r2","expiry":"2027-01-01T00:00:00Z"}

[od]
type = onedrive
drive_id = b!123
token = {"access_token":"t3","token_type":"Bearer","refresh_token":"r3","expiry":"2027-01-01T00:00:00Z"}

[dbx]
type = dropbox
token = {"access_token":"t4","token_type":"Bearer","refresh_token":"r4","expiry":"2027-01-01T00:00:00Z"}
"#,
    )
    .unwrap();

    let out = h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]);
    CliHarness::assert_ok(&out, "import-rclone missing client_id");
    let stderr = String::from_utf8_lossy(&out.stderr);
    for remote in ["gd", "gcs_oauth", "od", "dbx"] {
        assert!(
            stderr
                .lines()
                .any(|l| l.contains("warning:") && l.contains(remote) && l.contains("client_id")),
            "expected missing client_id warning for `{remote}` on stderr, got:\n{stderr}"
        );
    }
}

#[test]
fn tier2_config_import_rclone_gdrive_use_trash_default_true_and_wire_trash() {
    let h = CliHarness::new();
    let (srv, st) = start_gdrive_mock();
    {
        let mut g = st.lock().unwrap();
        g.seed_file(
            "f-trash",
            "sample.txt",
            "root",
            b"hello".to_vec(),
            "2026-11-24T12:00:00Z",
        );
        g.seed_file(
            "f-perm",
            "perm.txt",
            "root",
            b"bye".to_vec(),
            "2026-11-24T12:00:00Z",
        );
    }

    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[gd_default]
type = drive
client_id = cid
client_secret = csec
token = {"access_token":"gd-tok","token_type":"Bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}

[gd_perm]
type = drive
client_id = cid
client_secret = csec
use_trash = false
token = {"access_token":"gd-tok","token_type":"Bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone gdrive",
    );

    // Point imported remotes at mock server without specifying `use_trash` on `gd_default`.
    let mut cfg: toml::Value = h.parse_config_toml();
    for name in ["gd_default", "gd_perm"] {
        let tbl = cfg["remotes"][name].as_table_mut().unwrap();
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

    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gd_default:sample.txt", "--json"]),
        "delete gd_default:sample.txt",
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "PATCH"
                && r.path == "/drive/v3/files/f-trash"
                && String::from_utf8_lossy(&r.body).contains("\"trashed\":true")
        }),
        "omitted use_trash MUST default to true and send PATCH trashed=true, requests: {reqs:?}"
    );
    assert!(
        !reqs
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/drive/v3/files/f-trash"),
        "omitted use_trash must NOT permanently DELETE"
    );

    srv.clear_requests();
    CliHarness::assert_ok(
        &h.run_non_interactive(&["delete", "gd_perm:perm.txt", "--json"]),
        "delete gd_perm:perm.txt",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.method == "DELETE" && r.path == "/drive/v3/files/f-perm"),
        "explicit use_trash = false must still send DELETE"
    );
}

#[test]
fn tier2_config_import_rclone_expands_tilde_paths() {
    let h = CliHarness::new();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[gcs_t]
type = google cloud storage
service_account_file = ~/keys/gcs.json

[gd_t]
type = drive
service_account_file = ~/keys/gd.json

[sftp_t]
type = sftp
host = example.com
user = deploy
key_file = ~/.ssh/id_ed25519
known_hosts_file = ~/.ssh/known_hosts
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone tilde",
    );
    let cfg = h.parse_config_toml();
    let home_str = h.home_dir.to_string_lossy();

    for (remote, field) in [
        ("gcs_t", "service_account_file"),
        ("gd_t", "service_account_file"),
        ("sftp_t", "key_file"),
        ("sftp_t", "known_hosts_path"),
    ] {
        let val = cfg["remotes"][remote]
            .get(field)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("missing `{field}` on `{remote}`:\n{}", h.read_config()));
        assert!(
            !val.starts_with('~') && val.contains(&*home_str),
            "expected expanded `{field}` under `{home_str}`, got `{val}`"
        );
    }
}

#[test]
fn tier2_config_import_rclone_sftp_os_user_default_and_known_hosts_key_pem() {
    let h = CliHarness::new();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[sf_no_user]
type = sftp
host = sftp.example.com
key_file = /tmp/id_ed25519
known_hosts_file = /tmp/custom_known_hosts
key_pem = -----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----
"#,
    )
    .unwrap();

    let out = h
        .cmd()
        .env("USER", "alice_os")
        .env("USERNAME", "alice_os")
        .args([
            "--non-interactive",
            "config",
            "import-rclone",
            conf.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    CliHarness::assert_ok(&out, "import-rclone sftp");

    let cfg = h.parse_config_toml();
    let sf = &cfg["remotes"]["sf_no_user"];
    assert_eq!(
        sf["user"].as_str(),
        Some("alice_os"),
        "missing SFTP user must default to OS user, not `root`: {}",
        h.read_config()
    );
    assert_eq!(
        sf["known_hosts_path"].as_str(),
        Some("/tmp/custom_known_hosts")
    );
    assert!(
        sf.get("key_pem")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains("OPENSSH PRIVATE KEY")),
        "expected `key_pem` imported into config.toml: {}",
        h.read_config()
    );
}

#[test]
fn tier2_config_import_rclone_s3_sse_kms_profile_disable_checksum() {
    let h = CliHarness::new();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[s3enc]
type = s3
provider = AWS
profile = corp-prod
server_side_encryption = aws:kms
sse_kms_key_id = arn:aws:kms:us-east-1:123456:key/abc
disable_checksum = true
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone s3",
    );
    let cfg = h.parse_config_toml();
    let s3 = &cfg["remotes"]["s3enc"];
    assert_eq!(s3["profile"].as_str(), Some("corp-prod"));
    assert_eq!(s3["sse"].as_str(), Some("aws:kms"));
    assert_eq!(
        s3["kms_key_id"].as_str(),
        Some("arn:aws:kms:us-east-1:123456:key/abc")
    );
    assert_eq!(s3["send_upload_checksum"].as_bool(), Some(false));
}

#[test]
fn tier2_config_import_rclone_gcs_endpoints_env_auth_user_project_and_scope_alias() {
    let h = CliHarness::new();
    let (srv, _) = crate::mock_http::start_gcs_mock("test-bucket");
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        format!(
            "[gcs_env]\ntype = google cloud storage\nenv_auth = true\n\n\
             [gcs_custom]\ntype = google cloud storage\nendpoint = {base}\nauth_url = {base}/auth\ntoken_url = {base}/oauth2/token\nuser_project = my-billing-proj\nscope = read_only\nclient_id = cid\nclient_secret = csec\ntoken = {{\"access_token\":\"gcs-tok\",\"token_type\":\"Bearer\",\"refresh_token\":\"ref\",\"expiry\":\"2099-01-01T00:00:00Z\"}}\n",
            base = srv.base_url()
        ),
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone gcs",
    );

    let cfg = h.parse_config_toml();
    let gcs_env = &cfg["remotes"]["gcs_env"];
    assert_eq!(gcs_env["env_auth"].as_bool(), Some(true));

    let gcs_custom = &cfg["remotes"]["gcs_custom"];
    let has_imported_endpoint = gcs_custom
        .get("endpoint")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.starts_with(&srv.base_url()))
        || gcs_custom
            .get("api_base_url")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.starts_with(&srv.base_url()));
    assert!(
        has_imported_endpoint,
        "imported GCS `endpoint` must populate `endpoint` or `api_base_url` with `{}`: {gcs_custom:?}",
        srv.base_url()
    );
    assert_eq!(gcs_custom["user_project"].as_str(), Some("my-billing-proj"));
    assert_eq!(
        gcs_custom["scope"].as_str(),
        Some("https://www.googleapis.com/auth/devstorage.read_only")
    );

    CliHarness::assert_ok(
        &h.run_non_interactive(&["ls", "gcs_custom:test-bucket", "--json"]),
        "ls gcs_custom",
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| {
            r.path == "/storage/v1/b/test-bucket/o"
                && r.query.get("userProject").map(String::as_str) == Some("my-billing-proj")
        }),
        "expected `/storage/v1/b/test-bucket/o` with `userProject=my-billing-proj` on GCS wire request: {reqs:?}"
    );

    let probe_src = h.path().join("probe.txt");
    std::fs::write(&probe_src, b"gcs-endpoint-probe").unwrap();
    CliHarness::assert_ok(
        &h.run_non_interactive(&[
            "copyto",
            probe_src.to_str().unwrap(),
            "gcs_custom:test-bucket/probe.txt",
            "--json",
        ]),
        "copyto gcs_custom",
    );
    let reqs_after_copy = srv.requests();
    assert!(
        reqs_after_copy
            .iter()
            .any(|r| r.method == "POST" && r.path == "/upload/storage/v1/b/test-bucket/o"),
        "expected `POST /upload/storage/v1/b/test-bucket/o` on GCS upload from imported endpoint: {reqs_after_copy:?}"
    );
}

#[test]
fn tier2_config_import_rclone_onedrive_region_drive_type_chunk_size_and_scope() {
    let h = CliHarness::new();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[od_cn]
type = onedrive
region = cn
drive_type = business
chunk_size = 10M
client_id = cid
token = {"access_token":"od-tok","token_type":"Bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone onedrive cn",
    );
    let cfg = h.parse_config_toml();
    let od = &cfg["remotes"]["od_cn"];
    assert_eq!(od["region"].as_str(), Some("cn"));
    assert_eq!(od["drive_type"].as_str(), Some("business"));
    assert!(
        od.get("chunk_size").is_some(),
        "expected chunk_size imported"
    );
    if let Some(scope) = od.get("scope").and_then(|v| v.as_str()) {
        assert!(
            !scope.contains("User.Read"),
            "must not inject User.Read scope: {scope}"
        );
    }
}

#[test]
fn tier2_config_import_rclone_dropbox_team_headers_and_pkce_empty_scope() {
    let h = CliHarness::new();
    let (srv, _) = start_dropbox_mock();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        r#"
[dbx_team]
type = dropbox
root_namespace = ns-42
impersonate = dbmid:AAD123
shared_folders = true
client_id = cid
token = {"access_token":"dbx-tok","token_type":"Bearer","refresh_token":"ref","expiry":"2099-01-01T00:00:00Z"}
"#,
    )
    .unwrap();

    CliHarness::assert_ok(
        &h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]),
        "import-rclone dropbox team",
    );
    let mut cfg = h.parse_config_toml();
    {
        let tbl = cfg["remotes"]["dbx_team"].as_table_mut().unwrap();
        tbl.insert(
            "api_base_url".into(),
            format!("{}/2", srv.base_url()).into(),
        );
        tbl.insert(
            "content_base_url".into(),
            format!("{}/2", srv.base_url()).into(),
        );
        tbl.insert(
            "token_url".into(),
            format!("{}/oauth2/token", srv.base_url()).into(),
        );
    }
    h.write_config(&toml::to_string_pretty(&cfg).unwrap());

    CliHarness::assert_ok(
        &h.run_non_interactive(&["ls", "dbx_team:", "--json"]),
        "ls dbx_team",
    );
    let reqs = srv.requests();
    assert!(
        reqs.iter().any(|r| {
            r.header("dropbox-api-path-root")
                .is_some_and(|v| v.contains("ns-42"))
                && r.header("dropbox-api-select-user") == Some("dbmid:AAD123")
        }),
        "expected Dropbox team headers on wire request: {reqs:?}"
    );

    // Verify PKCE authorize URL omits empty `scope=` parameter.
    let mut child = h
        .cmd()
        .args([
            "auth",
            "dropbox",
            "dbx_pkce_check",
            "--client-id",
            "cid",
            "--manual",
            "--callback-port",
            "0",
        ])
        .env("RSHIP_FORCE_INTERACTIVE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut reader = BufReader::new(stderr);
    let mut line = String::new();
    let mut auth_url = None;
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line.contains("https://www.dropbox.com/oauth2/authorize") {
            auth_url = Some(line.trim().to_string());
            break;
        }
        line.clear();
    }
    let _ = child.kill();
    let _ = child.wait();
    let auth_url = auth_url.expect("expected Dropbox authorize URL on stderr");
    assert!(
        !auth_url.contains("scope="),
        "Dropbox PKCE URL must omit empty `scope=`: {auth_url}"
    );
}

#[test]
fn tier2_config_import_rclone_webdav_strict_vendor_and_headers() {
    let h = CliHarness::new();
    let (srv, _) = start_webdav_mock();
    let conf = h.path().join("rclone.conf");
    std::fs::write(
        &conf,
        format!(
            "[bad_dav]\ntype = webdav\nurl = https://dav.test\nvendor = unsupported_vendor_xyz\n\n\
             [hdr_dav]\ntype = webdav\nurl = {}/remote.php/dav/files/alice\nvendor = nextcloud\nuser = alice\npass = \nheaders = X-Custom,abc\n",
            srv.base_url()
        ),
    )
    .unwrap();

    let out = h.run_non_interactive(&["config", "import-rclone", conf.to_str().unwrap()]);
    let cfg_txt = h.read_config();
    let stderr_txt = String::from_utf8_lossy(&out.stderr);
    // `bad_dav` must NOT silently fall back to `vendor = "generic"` without a warning:
    // either import fails/skips `bad_dav`, OR stderr emits an explicit unsupported-vendor warning.
    if out.status.success() {
        let cfg = h.parse_config_toml();
        if cfg.get("remotes").and_then(|r| r.get("bad_dav")).is_some() {
            assert!(
                stderr_txt.contains("bad_dav")
                    && (stderr_txt.contains("unsupported_vendor_xyz")
                        || stderr_txt.contains("vendor")),
                "unsupported webdav vendor must not be silently imported as generic without stderr warning:\nstderr={stderr_txt}\ncfg={cfg_txt}"
            );
        }
    }

    // Also test `hdr_dav` alone to verify `headers` are imported and sent on PROPFIND.
    let h2 = CliHarness::new();
    let conf2 = h2.path().join("rclone2.conf");
    std::fs::write(
        &conf2,
        format!(
            "[hdr_dav]\ntype = webdav\nurl = {}/remote.php/dav/files/alice\nvendor = nextcloud\nuser = alice\nheaders = X-Custom,abc\n",
            srv.base_url()
        ),
    )
    .unwrap();
    CliHarness::assert_ok(
        &h2.run_non_interactive(&["config", "import-rclone", conf2.to_str().unwrap()]),
        "import-rclone hdr_dav",
    );
    CliHarness::assert_ok(
        &h2.run_non_interactive(&["ls", "hdr_dav:", "--json"]),
        "ls hdr_dav",
    );
    assert!(
        srv.requests()
            .iter()
            .any(|r| r.method == "PROPFIND" && r.header("x-custom") == Some("abc")),
        "expected custom WebDAV header `X-Custom: abc` on PROPFIND"
    );
}
