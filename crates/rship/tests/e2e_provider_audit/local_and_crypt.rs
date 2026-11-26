#![cfg(feature = "local")]

use futures::StreamExt;
use rship::backends::local::LocalBackend;
use rship::core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship::core::buffer::BufferPool;
use rship::core::encoding::EncodingMode;
use rship::core::path::{RelPath, TargetPath};
use rship::core::rclone_ini::{
    obscure_rclone_secret_with_iv, parse_rclone_ini, reveal_or_passthrough_rclone_secret,
    reveal_rclone_obscured,
};
use rship::core::source::{ByteStream, DataSource, MemorySource, bounded_range_stream};
use rship::core::state::{DstPrecondition, OperationRecord, OperationState, SourceVersion};
use rship::core::types::{
    ByteRange, Capabilities, Checksum, Entry, EntryKind, FsyncMode, HashKind,
};
use rship::prelude::*;
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tempfile::TempDir;

fn make_byte_stream(data: Vec<u8>) -> ByteStream {
    let len = data.len() as u64;
    if len == 0 {
        return Box::pin(futures::stream::empty());
    }
    let pool = BufferPool::new(2 * 1024 * 1024, 64 * 1024).unwrap();
    let src = Arc::new(MemorySource::new(data));
    bounded_range_stream(src, 0, len, pool)
}

async fn collect_entries(mut stream: EntryStream) -> Result<Vec<Entry>> {
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item?);
    }
    Ok(out)
}

async fn read_all_from_source(src: DataSource) -> Result<Vec<u8>> {
    match src {
        DataSource::LocalSeekable(seekable) => {
            let total = seekable.total_len() as usize;
            let mut out = vec![0u8; total];
            let mut off = 0usize;
            while off < total {
                let n = seekable.read_at(off as u64, &mut out[off..]).await?;
                if n == 0 {
                    break;
                }
                off += n;
            }
            out.truncate(off);
            Ok(out)
        }
        DataSource::RemoteRangeReadable(r) => {
            let total = r.total_len();
            let mut stream = r
                .open_range(ByteRange {
                    offset: 0,
                    len: total,
                })
                .await?;
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
        DataSource::SequentialStream { mut stream, .. } => {
            let mut out = Vec::new();
            while let Some(chunk) = stream.next().await {
                out.extend_from_slice(&chunk?);
            }
            Ok(out)
        }
    }
}

fn make_op_record(
    backend_kind: &str,
    init: &UploadInit,
    session_token: Option<String>,
    backend_meta: String,
    remote_op_id: Option<String>,
) -> OperationRecord {
    OperationRecord {
        op_id: init.op_id.clone(),
        session_key: format!("sess-{}", init.op_id),
        job_id: "job-test".to_string(),
        src_endpoint: "local://src".to_string(),
        dst_endpoint: format!("{backend_kind}://dst"),
        src_raw_path: init.dst_path.as_str().to_string(),
        dst_raw_path: init.dst_path.as_str().to_string(),
        dst_nfc_path: init.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: init.src_etag.clone(),
        },
        dst_precondition: init.precondition.clone(),
        existing_dst_node_id: init.existing_node_id.clone(),
        remote_op_id,
        backend_kind: backend_kind.to_string(),
        session_token,
        backend_meta,
        planned_chunk_size: init.planned_chunk_size,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1_700_000_000,
        updated_at: 1_700_000_000,
        expires_at: None,
    }
}

fn simple_upload_init(
    op_id: &str,
    dst: &str,
    total_size: u64,
    mtime_ns: i64,
    precondition: DstPrecondition,
) -> UploadInit {
    UploadInit {
        op_id: op_id.to_string(),
        dst_path: RelPath::parse(dst).unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size,
        src_mtime_ns: mtime_ns,
        planned_chunk_size: 64 * 1024,
        checksums: Vec::new(),
        precondition,
        src_etag: None,
    }
}

// ============================================================================
// Area #1: `rship-core` (Tier 1 >= 5, Tier 2 >= 5)
// ============================================================================

#[tokio::test]
async fn tier1_core_list_options_shallow_and_recursive() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("tree");
    std::fs::create_dir_all(root.join("sub/deep")).unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();
    std::fs::write(root.join("sub/mid.txt"), b"mid").unwrap();
    std::fs::write(root.join("sub/deep/leaf.txt"), b"leaf").unwrap();

    let client = RshipClient::ephemeral().unwrap();

    let shallow_entries = collect_entries(
        client
            .list(root.as_path(), &ListOptions::shallow())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let shallow_paths: BTreeSet<String> = shallow_entries
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert!(shallow_paths.contains("top.txt"));
    assert!(shallow_paths.contains("sub"));
    assert!(!shallow_paths.contains("sub/mid.txt"));
    assert!(!shallow_paths.contains("sub/deep/leaf.txt"));

    let rec_entries = collect_entries(
        client
            .list(root.as_path(), &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let rec_paths: BTreeSet<String> = rec_entries
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert!(rec_paths.contains("top.txt"));
    assert!(rec_paths.contains("sub"));
    assert!(rec_paths.contains("sub/mid.txt"));
    assert!(rec_paths.contains("sub/deep"));
    assert!(rec_paths.contains("sub/deep/leaf.txt"));
}

#[tokio::test]
async fn tier1_core_list_options_dir_pruner() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir_all(root.join(".git/objects")).unwrap();
    std::fs::create_dir_all(root.join("src/skip")).unwrap();
    std::fs::write(root.join(".git/HEAD"), b"ref").unwrap();
    std::fs::write(root.join(".git/objects/abc"), b"obj").unwrap();
    std::fs::write(root.join("src/main.rs"), b"fn main(){}").unwrap();
    std::fs::write(root.join("src/skip/ignored.txt"), b"skip").unwrap();

    let backend = LocalBackend::new("repo", &root).unwrap();
    let opts = ListOptions::recursive()
        .with_dir_pruner(|p| p.as_str() == ".git" || p.file_name() == Some("skip"));
    let entries = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &opts)
            .await
            .unwrap(),
    )
    .await
    .unwrap();

    let paths: BTreeSet<String> = entries
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert!(paths.contains("src"));
    assert!(paths.contains("src/main.rs"));
    assert!(!paths.iter().any(|p| p.starts_with(".git")));
    assert!(!paths.iter().any(|p| p.starts_with("src/skip")));
}

#[test]
fn tier1_core_rclone_ini_valid_and_obscure_roundtrip() {
    let secret = "p@ss:w0rd!#utf8-\u{00e9}\u{4e2d}\u{6587}";
    let obscured = obscure_rclone_secret_with_iv(secret, [0x42; 16]);
    let revealed = reveal_rclone_obscured(&obscured).unwrap();
    assert_eq!(revealed, secret);

    let (dec_ok, was_obscured) = reveal_or_passthrough_rclone_secret(&obscured);
    assert!(was_obscured);
    assert_eq!(dec_ok, secret);

    let (plain_pass, was_obs_plain) = reveal_or_passthrough_rclone_secret("short-plain");
    assert!(!was_obs_plain);
    assert_eq!(plain_pass, "short-plain");

    let ini = format!(
        "# header comment\n\
         ; semicolon comment\n\
         [FirstRemote]\n\
         TYPE = S3\n\
         Env_Auth = YES\n\
         Disable_Checksum = 0\n\
         Secret_Access_Key = {obscured}\n\n\
         [SecondRemote]\n\
         type = webdav\n\
         flag = no\n"
    );
    let sections = parse_rclone_ini(&ini).unwrap();
    assert_eq!(sections.len(), 2);
    assert_eq!(sections[0].name, "FirstRemote");
    assert_eq!(sections[0].kind(), "S3");
    assert_eq!(sections[0].get_bool("env_auth"), Some(true));
    assert_eq!(sections[0].get_bool("disable_checksum"), Some(false));
    assert_eq!(
        sections[0].get_non_empty("secret_access_key").as_deref(),
        Some(obscured.as_str())
    );
    assert_eq!(sections[1].name, "SecondRemote");
    assert_eq!(sections[1].get_bool("flag"), Some(false));
}

#[test]
fn tier1_core_relpath_normalization_and_traversal_reject() {
    assert!(RelPath::parse("").unwrap().is_root());
    assert!(RelPath::parse("/").unwrap().is_root());
    assert!(RelPath::parse("///\\").unwrap().is_root());

    let norm = RelPath::parse("/a//b\\c/").unwrap();
    assert_eq!(norm.as_str(), "a/b/c");

    // NFD "cafe\u{0301}" normalizes to NFC "caf\u{00e9}".
    let nfc = RelPath::parse("dir/cafe\u{0301}.txt").unwrap();
    assert_eq!(nfc.as_str(), "dir/caf\u{00e9}.txt");

    for bad in [".", "..", "a/./b", "a/../b", "../etc/passwd", "a/bad\0name"] {
        let err = RelPath::parse(bad).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidPath, "input: {bad}");
    }
}

#[test]
fn tier1_core_target_path_windows_unix_remote_disambiguation() {
    for local in [
        r"C:\foo\bar",
        "C:/foo/bar",
        "C:rel",
        r"\\server\share\dir",
        r"\\?\C:\long\path",
        "/var/data",
        "./rel/path",
        "../parent",
    ] {
        let parsed = TargetPath::parse(local).unwrap();
        assert!(
            matches!(parsed, TargetPath::Local(_)),
            "expected Local for `{local}`, got {parsed:?}"
        );
    }

    let remote = TargetPath::parse("my-remote_1:sub/cafe\u{0301}.txt").unwrap();
    match remote {
        TargetPath::Remote { remote, path } => {
            assert_eq!(remote, "my-remote_1");
            assert_eq!(path.as_str(), "sub/caf\u{00e9}.txt");
        }
        other => panic!("expected Remote, got {other:?}"),
    }

    assert!(TargetPath::parse("").is_err());
    assert!(TargetPath::parse("a\0b").is_err());
}

#[test]
fn tier2_core_rclone_ini_rejects_rclone_encrypt_v0() {
    for raw in [
        "RCLONE_ENCRYPT_V0:\nYWJjZGVmZ2g=\n",
        "\u{FEFF}RCLONE_ENCRYPT_V0:\nYWJj\n",
        "# encrypted config\n\n  RCLONE_ENCRYPT_V0:\nYWJj\n",
    ] {
        let err = parse_rclone_ini(raw).expect_err("encrypted rclone.conf must be rejected");
        assert!(
            err.is_config(),
            "expected Config error for `{raw:?}`, got {:?}",
            err.kind()
        );
        assert!(err.is_permanent());
    }
}

#[tokio::test]
async fn tier2_core_list_options_max_depth_zero_returns_zero_children() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("depth_zero");
    std::fs::create_dir_all(root.join("sub/nested")).unwrap();
    std::fs::write(root.join("top.txt"), b"top").unwrap();
    std::fs::write(root.join("sub/child.txt"), b"child").unwrap();
    std::fs::write(root.join("sub/nested/deep.txt"), b"deep").unwrap();

    let backend = LocalBackend::new("loc", &root).unwrap();
    let opts = ListOptions::new().with_max_depth(0);

    let root_entries = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &opts)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        root_entries.is_empty(),
        "with_max_depth(0) from root must return 0 children, got: {:?}",
        root_entries
            .iter()
            .map(|e| e.nfc_path.as_str())
            .collect::<Vec<_>>()
    );

    let sub_entries = collect_entries(
        backend
            .list_with_options(&RelPath::parse("sub").unwrap(), &opts)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        sub_entries.is_empty(),
        "with_max_depth(0) from sub prefix must return 0 children, got: {:?}",
        sub_entries
            .iter()
            .map(|e| e.nfc_path.as_str())
            .collect::<Vec<_>>()
    );

    let client = RshipClient::ephemeral().unwrap();
    let client_entries = collect_entries(client.list(root.as_path(), &opts).await.unwrap())
        .await
        .unwrap();
    assert!(
        client_entries.is_empty(),
        "RshipClient::list with_max_depth(0) must return 0 children"
    );
}

#[tokio::test]
async fn tier2_core_list_options_max_depth_zero_custom_backend_and_sub_prefix() {
    struct MockTreeBackend {
        entries: Vec<Entry>,
    }

    impl StorageBackend for MockTreeBackend {
        fn name(&self) -> &str {
            "mock"
        }
        fn kind(&self) -> &'static str {
            "mock"
        }
        fn endpoint_identity(&self) -> String {
            "mock://tree".to_string()
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::default()
        }
        fn stat<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _path: &'life1 BackendPath,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Entry>>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(None) })
        }
        fn list_stream<'life0, 'life1, 'async_trait>(
            &'life0 self,
            prefix: &'life1 RelPath,
            _recursive: bool,
        ) -> Pin<Box<dyn Future<Output = Result<EntryStream>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            let mut items = Vec::new();
            for e in &self.entries {
                if prefix.is_root()
                    || (e.nfc_path != *prefix && e.nfc_path.strip_prefix(prefix).is_some())
                {
                    items.push(Ok(e.clone()));
                }
            }
            Box::pin(async move {
                let st: EntryStream = Box::pin(futures::stream::iter(items));
                Ok(st)
            })
        }
        fn mkdir<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _path: &'life1 RelPath,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(()) })
        }
        fn delete<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _path: &'life1 BackendPath,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(()) })
        }
        fn compute_hash<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _path: &'life1 BackendPath,
            _kind: HashKind,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Checksum>>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(None) })
        }
        fn open_read<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _path: &'life1 BackendPath,
            _range: Option<ByteRange>,
        ) -> Pin<Box<dyn Future<Output = Result<DataSource>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(Error::unsupported("open_read")) })
        }
        fn put_single_shot<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _init: &'life1 UploadInit,
            _body: ByteStream,
        ) -> Pin<Box<dyn Future<Output = Result<Entry>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(Error::unsupported("put_single_shot")) })
        }
        fn begin_upload<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _init: &'life1 UploadInit,
        ) -> Pin<Box<dyn Future<Output = Result<UploadSessionInit>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(Error::unsupported("begin_upload")) })
        }
        fn query_upload<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _op: &'life1 OperationRecord,
        ) -> Pin<Box<dyn Future<Output = Result<UploadProgress>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(UploadProgress::Expired) })
        }
        fn upload_chunk<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _op: &'life1 OperationRecord,
            _chunk: ChunkUpload,
        ) -> Pin<Box<dyn Future<Output = Result<ChunkAck>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(Error::unsupported("upload_chunk")) })
        }
        fn finish_upload<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            _op: &'life1 OperationRecord,
            _parts: &'life2 [CompletedPart],
        ) -> Pin<Box<dyn Future<Output = Result<Entry>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Err(Error::unsupported("finish_upload")) })
        }
        fn abort_upload<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _op: &'life1 OperationRecord,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(()) })
        }
        fn reconcile_operation<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _op: &'life1 OperationRecord,
        ) -> Pin<Box<dyn Future<Output = Result<ReconcileOutcome>> + Send + 'async_trait>>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            Box::pin(async { Ok(ReconcileOutcome::NotCommitted) })
        }
    }

    let backend = MockTreeBackend {
        entries: vec![
            Entry::file(RelPath::parse("top.txt").unwrap(), 1, 1),
            Entry::dir(RelPath::parse("sub").unwrap(), 1),
            Entry::file(RelPath::parse("sub/a.txt").unwrap(), 2, 1),
            Entry::dir(RelPath::parse("sub/nested").unwrap(), 1),
            Entry::file(RelPath::parse("sub/nested/b.txt").unwrap(), 3, 1),
        ],
    };

    let d0 = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &ListOptions::new().with_max_depth(0))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(d0.is_empty());

    let d0_rec = collect_entries(
        backend
            .list_with_options(
                &RelPath::root(),
                &ListOptions::new().with_recursive(true).with_max_depth(0),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(d0_rec.is_empty());

    let d0_sub = collect_entries(
        backend
            .list_with_options(
                &RelPath::parse("sub").unwrap(),
                &ListOptions::new().with_max_depth(0),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(d0_sub.is_empty());

    let d2 = collect_entries(
        backend
            .list_with_options(&RelPath::root(), &ListOptions::shallow().with_max_depth(2))
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let names: BTreeSet<String> = d2.iter().map(|e| e.nfc_path.as_str().to_string()).collect();
    assert!(names.contains("top.txt"));
    assert!(names.contains("sub"));
    assert!(names.contains("sub/a.txt"));
    assert!(names.contains("sub/nested"));
    assert!(!names.contains("sub/nested/b.txt"));
}

#[test]
fn tier2_core_rclone_ini_rejects_empty_section_and_malformed_obscure() {
    assert!(parse_rclone_ini("[]\ntype = s3\n").is_err());

    assert!(reveal_rclone_obscured("not_valid_base64!!").is_err());
    // Too short (< 16-byte IV).
    assert!(reveal_rclone_obscured("AAAA").is_err());

    let (out, was_obscured) = reveal_or_passthrough_rclone_secret("plain-secret-value");
    assert!(!was_obscured);
    assert_eq!(out, "plain-secret-value");
}

#[test]
fn tier2_core_relpath_nfd_entry_raw_path_and_join_prefixed() {
    let nfc = RelPath::parse("d/cafe\u{0301}.txt").unwrap();
    assert_eq!(nfc.as_str(), "d/caf\u{00e9}.txt");

    let nfd_entry = Entry::file(nfc.clone(), 42, 100).with_raw_path("d/cafe\u{0301}.txt");
    let bp = BackendPath::from_entry(&nfd_entry);
    assert_eq!(bp.nfc_path.as_str(), "d/caf\u{00e9}.txt");
    assert_eq!(bp.raw_path(), "d/cafe\u{0301}.txt");

    let nfc_only = Entry::file(nfc.clone(), 42, 100).with_raw_path("d/caf\u{00e9}.txt");
    assert_eq!(nfc_only.raw_path, None);

    let prefix = RelPath::parse("root/sub").unwrap();
    let child_nfc = RelPath::parse("cafe\u{0301}.txt").unwrap();
    let joined =
        BackendPath::join_prefixed(&prefix, "cafe\u{0301}.txt", &child_nfc, None, None).unwrap();
    assert_eq!(joined.nfc_path.as_str(), "root/sub/caf\u{00e9}.txt");
    assert_eq!(joined.raw_path(), "root/sub/cafe\u{0301}.txt");
}

// ============================================================================
// Area #4: `rship-crypto` (`crypt`) (Tier 1 >= 5, Tier 2 >= 5)
// ============================================================================

#[cfg(feature = "crypt")]
mod crypt_tests {
    use super::*;
    use rship::config::CryptRemoteConfig;
    use rship::crypto::{
        CryptoBackend, CryptoConfig, FilenameEncryption, MasterKey, ciphertext_size,
    };
    use std::path::Path;

    fn test_keys() -> rship::crypto::CryptoKeys {
        MasterKey::from_bytes([0x5a; 32]).derive_subkeys()
    }

    fn collect_files_recursive(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return out;
        };
        for item in rd.flatten() {
            let p = item.path();
            if p.is_dir() {
                out.extend(collect_files_recursive(&p));
            } else if p.is_file() {
                out.push(p);
            }
        }
        out
    }

    #[tokio::test]
    async fn tier1_crypt_single_shot_and_chunked_roundtrip_over_local() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let vault = tmp.path().join("vault");
        let restore = tmp.path().join("restore");
        std::fs::create_dir_all(src.join("nested")).unwrap();
        std::fs::create_dir_all(&vault).unwrap();
        std::fs::create_dir_all(&restore).unwrap();

        let p_empty = Vec::<u8>::new();
        let p_small = vec![0x33u8; 1024];
        let p_large: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 251) as u8).collect();
        std::fs::write(src.join("empty.bin"), &p_empty).unwrap();
        std::fs::write(src.join("small.txt"), &p_small).unwrap();
        std::fs::write(src.join("nested/large.bin"), &p_large).unwrap();

        let inner = Arc::new(
            LocalBackend::new("vault_inner", &vault)
                .unwrap()
                .with_chunking(64 * 1024, 64 * 1024),
        );
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("crypt_v"), test_keys()).unwrap();

        let client = RshipClient::builder()
            .ephemeral()
            .register_backend("crypt_v", crypt)
            .build()
            .unwrap();

        let rep = client.sync(src.as_path(), "crypt_v:").run().await.unwrap();
        assert!(rep.is_success(), "{:?}", rep.errors);
        assert_eq!(rep.files_transferred, 3);

        // Verify ciphertext sizes on disk and absence of plaintext large payload.
        let disk_files = collect_files_recursive(&vault);
        assert_eq!(disk_files.len(), 3);
        let disk_sizes: BTreeSet<u64> = disk_files
            .iter()
            .map(|p| std::fs::metadata(p).unwrap().len())
            .collect();
        assert!(disk_sizes.contains(&ciphertext_size(0).unwrap()));
        assert!(disk_sizes.contains(&ciphertext_size(1024).unwrap()));
        assert!(disk_sizes.contains(&ciphertext_size(200 * 1024).unwrap()));

        let rep_back = client
            .sync("crypt_v:", restore.as_path())
            .run()
            .await
            .unwrap();
        assert!(rep_back.is_success(), "{:?}", rep_back.errors);
        assert_eq!(std::fs::read(restore.join("empty.bin")).unwrap(), p_empty);
        assert_eq!(std::fs::read(restore.join("small.txt")).unwrap(), p_small);
        assert_eq!(
            std::fs::read(restore.join("nested/large.bin")).unwrap(),
            p_large
        );
    }

    #[tokio::test]
    async fn tier1_crypt_filename_encryption_standard_vs_off() {
        let tmp = TempDir::new().unwrap();
        let vault_std = tmp.path().join("vault_std");
        let vault_off = tmp.path().join("vault_off");
        std::fs::create_dir_all(&vault_std).unwrap();
        std::fs::create_dir_all(&vault_off).unwrap();

        let payload = b"secret-doc-contents".to_vec();
        let rel = RelPath::parse("docs/report.pdf").unwrap();

        let std_crypt = CryptoBackend::new(
            Arc::new(LocalBackend::new("v1", &vault_std).unwrap()),
            CryptoConfig::new("c_std"),
            test_keys(),
        )
        .unwrap();
        std_crypt
            .put_single_shot(
                &simple_upload_init(
                    "op1",
                    rel.as_str(),
                    payload.len() as u64,
                    1_700_000_000_000_000_000,
                    DstPrecondition::Any,
                ),
                make_byte_stream(payload.clone()),
            )
            .await
            .unwrap();
        assert!(!vault_std.join("docs/report.pdf").exists());
        let std_list =
            collect_entries(std_crypt.list_stream(&RelPath::root(), true).await.unwrap())
                .await
                .unwrap();
        assert!(std_list.iter().any(|e| e.nfc_path == rel));
        assert!(
            std_crypt
                .stat(&BackendPath::from_rel(rel.clone()))
                .await
                .unwrap()
                .is_some()
        );

        let mut off_cfg = CryptoConfig::new("c_off");
        off_cfg.filename_encryption = FilenameEncryption::Off;
        let off_crypt = CryptoBackend::new(
            Arc::new(LocalBackend::new("v2", &vault_off).unwrap()),
            off_cfg,
            test_keys(),
        )
        .unwrap();
        off_crypt
            .put_single_shot(
                &simple_upload_init(
                    "op2",
                    rel.as_str(),
                    payload.len() as u64,
                    1_700_000_000_000_000_000,
                    DstPrecondition::Any,
                ),
                make_byte_stream(payload.clone()),
            )
            .await
            .unwrap();
        assert!(vault_off.join("docs/report.pdf").exists());
        assert_ne!(
            std::fs::read(vault_off.join("docs/report.pdf")).unwrap(),
            payload
        );
        let decrypted = read_all_from_source(
            off_crypt
                .open_read(&BackendPath::from_rel(rel), None)
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(decrypted, payload);
    }

    #[tokio::test]
    async fn tier1_crypt_inner_prefix_scoping_via_client_and_config() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let vault_root = tmp.path().join("vault_root");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&vault_root).unwrap();
        std::fs::write(vault_root.join("outside.txt"), b"keep-me").unwrap();
        std::fs::write(src.join("inside.txt"), b"secret-inside").unwrap();

        let client = RshipClient::builder()
            .ephemeral()
            .remote("base", RemoteConfig::local(&vault_root))
            .remote(
                "vault",
                CryptRemoteConfig::new("base:sub/dir").with_password("passphrase-1"),
            )
            .build()
            .unwrap();

        let rep = client.sync(src.as_path(), "vault:").run().await.unwrap();
        assert!(rep.is_success(), "{:?}", rep.errors);
        assert!(vault_root.join("outside.txt").exists());
        assert!(vault_root.join("sub/dir").is_dir());
        assert_eq!(
            collect_files_recursive(&vault_root.join("sub/dir")).len(),
            1
        );

        let listed = collect_entries(
            client
                .list("vault:", &ListOptions::recursive())
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].nfc_path.as_str(), "inside.txt");
    }

    #[tokio::test]
    async fn tier1_crypt_range_read_and_rename_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();

        let payload: Vec<u8> = (0..(200 * 1024)).map(|i| ((i * 13) % 251) as u8).collect();
        let inner = Arc::new(LocalBackend::new("v", &vault).unwrap());
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("c"), test_keys()).unwrap();

        crypt
            .put_single_shot(
                &simple_upload_init(
                    "op-rng",
                    "dir/old.bin",
                    payload.len() as u64,
                    1_700_000_000_000_000_000,
                    DstPrecondition::Any,
                ),
                make_byte_stream(payload.clone()),
            )
            .await
            .unwrap();

        let ds = crypt
            .open_read(
                &BackendPath::from_rel(RelPath::parse("dir/old.bin").unwrap()),
                None,
            )
            .await
            .unwrap();
        let slice = match ds {
            DataSource::RemoteRangeReadable(r) => {
                let mut st = r
                    .open_range(ByteRange {
                        offset: 70_000,
                        len: 10_000,
                    })
                    .await
                    .unwrap();
                let mut out = Vec::new();
                while let Some(chunk) = st.next().await {
                    out.extend_from_slice(&chunk.unwrap());
                }
                out
            }
            other => {
                let all = read_all_from_source(other).await.unwrap();
                all[70_000..80_000].to_vec()
            }
        };
        assert_eq!(slice, payload[70_000..80_000]);

        let renamed = crypt
            .rename(
                &BackendPath::from_rel(RelPath::parse("dir/old.bin").unwrap()),
                "new.bin",
            )
            .await
            .unwrap();
        assert_eq!(renamed.nfc_path.as_str(), "dir/new.bin");
        assert!(
            crypt
                .stat(&BackendPath::from_rel(
                    RelPath::parse("dir/old.bin").unwrap()
                ))
                .await
                .unwrap()
                .is_none()
        );
        let new_bytes = read_all_from_source(
            crypt
                .open_read(
                    &BackendPath::from_rel(RelPath::parse("dir/new.bin").unwrap()),
                    None,
                )
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(new_bytes, payload);
    }

    #[tokio::test]
    async fn tier1_crypt_tampered_ciphertext_rejected_by_aead() {
        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();

        let payload = vec![0x41u8; 10 * 1024];
        let inner = Arc::new(LocalBackend::new("v", &vault).unwrap());
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("c"), test_keys()).unwrap();

        let rel = RelPath::parse("auth.bin").unwrap();
        crypt
            .put_single_shot(
                &simple_upload_init(
                    "op-auth",
                    rel.as_str(),
                    payload.len() as u64,
                    1_700_000_000_000_000_000,
                    DstPrecondition::Any,
                ),
                make_byte_stream(payload),
            )
            .await
            .unwrap();

        let files = collect_files_recursive(&vault);
        assert_eq!(files.len(), 1);
        let mut ct = std::fs::read(&files[0]).unwrap();
        let idx = ct.len() - 5;
        ct[idx] ^= 0xff;
        std::fs::write(&files[0], ct).unwrap();

        let ds = crypt
            .open_read(&BackendPath::from_rel(rel), None)
            .await
            .unwrap();
        let err = read_all_from_source(ds)
            .await
            .expect_err("tampered ciphertext must fail AEAD authentication");
        assert!(!err.to_string().is_empty(), "expected non-empty AEAD error");
    }

    async fn upload_chunked_through_crypt(
        crypt: &CryptoBackend,
        op_id: &str,
        dst: &str,
        payload: Vec<u8>,
        mtime_ns: i64,
        precondition: DstPrecondition,
    ) -> Result<Entry> {
        let total = payload.len() as u64;
        let init = simple_upload_init(op_id, dst, total, mtime_ns, precondition);
        let sess = crypt.begin_upload(&init).await?;
        let op = make_op_record(
            "crypt",
            &init,
            Some(sess.session_token),
            sess.backend_meta,
            sess.remote_op_id,
        );
        let chunk_sz = 64 * 1024usize;
        let mut parts = Vec::new();
        let mut off = 0usize;
        let mut part_no = 1u32;
        while off < payload.len() {
            let end = (off + chunk_sz).min(payload.len());
            let slice = payload[off..end].to_vec();
            let len = slice.len() as u64;
            let ack = crypt
                .upload_chunk(
                    &op,
                    ChunkUpload::new(part_no, off as u64, len, total, make_byte_stream(slice)),
                )
                .await?;
            parts.push(CompletedPart {
                part_number: part_no,
                offset: off as u64,
                length: len,
                etag: ack.etag.unwrap_or_default(),
                checksum: ack.checksum,
            });
            off = end;
            part_no += 1;
        }
        crypt.finish_upload(&op, &parts).await
    }

    #[tokio::test]
    async fn tier2_crypt_existing_precondition_overwrite_over_single_shot_max() {
        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();

        let inner = Arc::new(
            LocalBackend::new("vault", &vault)
                .unwrap()
                .with_chunking(64 * 1024, 64 * 1024),
        );
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("crypt"), test_keys()).unwrap();

        let v1 = vec![0x11u8; 128 * 1024];
        let e1 = upload_chunked_through_crypt(
            &crypt,
            "op-v1",
            "big.bin",
            v1,
            1_700_000_001_000_000_000,
            DstPrecondition::Absent,
        )
        .await
        .unwrap();
        assert_eq!(e1.size, 128 * 1024);

        let v2: Vec<u8> = (0..(192 * 1024)).map(|i| (i % 241) as u8).collect();
        let e2 = upload_chunked_through_crypt(
            &crypt,
            "op-v2",
            "big.bin",
            v2.clone(),
            1_700_000_002_000_000_000,
            DstPrecondition::Existing {
                node_id: e1.node_id.clone(),
                etag: e1.etag.clone(),
                mtime_ns: e1.mtime_ns,
                size: e1.size,
            },
        )
        .await
        .expect("DstPrecondition::Existing overwrite over single_shot_max_bytes must succeed");
        assert_eq!(e2.size, 192 * 1024);

        let read_back = read_all_from_source(
            crypt
                .open_read(
                    &BackendPath::from_rel(RelPath::parse("big.bin").unwrap()),
                    None,
                )
                .await
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(read_back, v2);
    }

    #[tokio::test]
    async fn tier2_crypt_existing_precondition_tampered_inner_ciphertext_fails() {
        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();

        let inner = Arc::new(
            LocalBackend::new("vault", &vault)
                .unwrap()
                .with_chunking(64 * 1024, 64 * 1024),
        );
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("crypt"), test_keys()).unwrap();

        let v1 = vec![0x22u8; 128 * 1024];
        let e1 = upload_chunked_through_crypt(
            &crypt,
            "op-t1",
            "tamper.bin",
            v1,
            1_700_000_001_000_000_000,
            DstPrecondition::Absent,
        )
        .await
        .unwrap();

        // Replace inner ciphertext on disk with EXACTLY `e1.size` bytes (plaintext len 131_072,
        // NOT ciphertext_size(131_072) = 131_136) while preserving mtime so unfixed code
        // falsely passes the precondition and fixed code detects ciphertext mismatch!
        let files = collect_files_recursive(&vault);
        assert_eq!(files.len(), 1);
        let orig_mtime = std::fs::metadata(&files[0]).unwrap().modified().unwrap();
        let mut fake = std::fs::read(&files[0]).unwrap();
        fake.truncate(e1.size as usize);
        std::fs::write(&files[0], &fake).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&files[0])
            .unwrap()
            .set_modified(orig_mtime)
            .unwrap();

        let v2 = vec![0x33u8; 192 * 1024];
        let err = upload_chunked_through_crypt(
            &crypt,
            "op-t2",
            "tamper.bin",
            v2,
            1_700_000_002_000_000_000,
            DstPrecondition::Existing {
                node_id: e1.node_id.clone(),
                etag: e1.etag.clone(),
                mtime_ns: e1.mtime_ns,
                size: e1.size,
            },
        )
        .await
        .expect_err("tampered inner ciphertext size must fail precondition");
        assert_eq!(err.kind(), ErrorKind::PreconditionFailed);
    }

    #[test]
    fn tier2_crypt_single_shot_max_bytes_accounts_for_oae2_overhead() {
        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();

        let inner_limit = 4 * 1024 * 1024u64;
        let inner = Arc::new(
            LocalBackend::new("vault", &vault)
                .unwrap()
                .with_chunking(inner_limit, 1024 * 1024),
        );
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("crypt"), test_keys()).unwrap();

        let pt_limit = crypt.capabilities().single_shot_max_bytes;
        assert!(
            pt_limit < inner_limit,
            "crypt single_shot_max_bytes ({pt_limit}) must be strictly less than inner limit ({inner_limit}) to leave room for OAE2 header+tags"
        );
        let ct_at_limit = ciphertext_size(pt_limit).unwrap();
        assert!(
            ct_at_limit <= inner_limit,
            "ciphertext_size({pt_limit}) = {ct_at_limit} exceeds inner single_shot_max_bytes {inner_limit}"
        );
    }

    #[cfg(feature = "onedrive")]
    #[tokio::test]
    async fn tier2_crypt_onedrive_4mib_plaintext_routes_chunked_session() {
        use crate::mock_http::{MockAction, MockHttpServer, MockResponse};
        use rship::config::OnedriveRemoteConfig;
        use std::sync::Mutex;

        let tmp = TempDir::new().unwrap();
        let src_file = tmp.path().join("four_mib.bin");
        let payload = vec![0x7au8; 4 * 1024 * 1024];
        std::fs::write(&src_file, &payload).unwrap();

        let uploaded_len = Arc::new(Mutex::new(0u64));
        let uploaded_len_c = uploaded_len.clone();
        let srv_url_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
        let srv_url_c = srv_url_slot.clone();

        let srv = MockHttpServer::start_with_handler(move |req| {
            let p = req.path.as_str();
            if req.method == "GET" && p.starts_with("/me/drive/root:/") && !p.ends_with("/children")
            {
                return MockAction::Respond(MockResponse::empty(404));
            }
            if req.method == "PUT" && p.ends_with(":/content") {
                if req.body.len() > 4 * 1024 * 1024 {
                    return MockAction::Respond(MockResponse::text(
                        413,
                        "Payload Too Large (> 4 MiB simple upload limit)",
                    ));
                }
                return MockAction::Respond(MockResponse::json(
                    201,
                    &serde_json::json!({
                        "id": "od-simple-1",
                        "name": "enc",
                        "size": req.body.len(),
                        "eTag": "\"e1\""
                    }),
                ));
            }
            if req.method == "POST" && p.ends_with(":/createUploadSession") {
                let base = srv_url_c.lock().unwrap().clone();
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({
                        "uploadUrl": format!("{base}/upload_session/1"),
                        "expirationDateTime": "2099-01-01T00:00:00Z"
                    }),
                ));
            }
            if req.method == "PUT" && p == "/upload_session/1" {
                let mut total_acc = uploaded_len_c.lock().unwrap();
                *total_acc += req.body.len() as u64;
                if let Some(cr) = req.header("content-range")
                    && let Some((_, total_s)) = cr.split_once('/')
                    && let Ok(total) = total_s.trim().parse::<u64>()
                    && *total_acc >= total
                {
                    return MockAction::Respond(MockResponse::json(
                        201,
                        &serde_json::json!({
                            "id": "od-sess-1",
                            "name": "enc",
                            "size": total,
                            "eTag": "\"e-sess\""
                        }),
                    ));
                }
                return MockAction::Respond(MockResponse::json(
                    202,
                    &serde_json::json!({
                        "nextExpectedRanges": [format!("{}-", *total_acc)]
                    }),
                ));
            }
            if req.method == "GET" && p.ends_with("/children") {
                return MockAction::Respond(MockResponse::json(
                    200,
                    &serde_json::json!({ "value": [] }),
                ));
            }
            MockAction::Respond(MockResponse::empty(404))
        })
        .await;
        *srv_url_slot.lock().unwrap() = srv.base_url();

        let client = RshipClient::builder()
            .ephemeral()
            .remote(
                "od",
                OnedriveRemoteConfig::new()
                    .with_api_base_url(srv.base_url())
                    .with_access_token("test-od-token"),
            )
            .remote(
                "crypt_od",
                CryptRemoteConfig::new("od:").with_key_hex("5a".repeat(32)),
            )
            .build()
            .unwrap();

        let rep = client
            .copy_file(src_file.as_path(), "crypt_od:four_mib.bin")
            .run()
            .await
            .expect("4 MiB plaintext through crypt->onedrive must route via createUploadSession, not 413 single-shot PUT");
        assert!(rep.is_success(), "{:?}", rep.errors);

        let reqs = srv.requests();
        assert!(
            reqs.iter()
                .any(|r| r.method == "POST" && r.path.ends_with(":/createUploadSession")),
            "expected POST createUploadSession"
        );
        assert!(
            !reqs
                .iter()
                .any(|r| r.method == "PUT" && r.path.ends_with(":/content")),
            "4 MiB plaintext must not attempt single-shot PUT /content"
        );
    }

    #[tokio::test]
    async fn tier2_crypt_delete_batch_and_key_passphrase_derivation() {
        let k1 = MasterKey::from_passphrase("correct horse battery", Some(b"rship-salt")).unwrap();
        let k2 = MasterKey::from_passphrase("correct horse battery", Some(b"rship-salt")).unwrap();
        assert_eq!(k1.to_hex(), k2.to_hex());
        assert!(MasterKey::from_hex("deadbeef").is_err());

        let tmp = TempDir::new().unwrap();
        let vault = tmp.path().join("vault");
        std::fs::create_dir_all(&vault).unwrap();
        let inner = Arc::new(LocalBackend::new("v", &vault).unwrap());
        let crypt = CryptoBackend::new(inner, CryptoConfig::new("c"), k1.derive_subkeys()).unwrap();

        for name in ["a.txt", "b.txt"] {
            crypt
                .put_single_shot(
                    &simple_upload_init(
                        name,
                        name,
                        3,
                        1_700_000_000_000_000_000,
                        DstPrecondition::Any,
                    ),
                    make_byte_stream(b"abc".to_vec()),
                )
                .await
                .unwrap();
        }
        let batch_res = crypt
            .delete_batch(&[
                BackendPath::from_rel(RelPath::parse("a.txt").unwrap()),
                BackendPath::from_rel(RelPath::parse("b.txt").unwrap()),
                BackendPath::from_rel(RelPath::parse("missing.txt").unwrap()),
            ])
            .await
            .unwrap();
        assert!(
            batch_res.is_empty(),
            "expected no delete failures: {batch_res:?}"
        );
        assert!(
            crypt
                .stat(&BackendPath::from_rel(RelPath::parse("a.txt").unwrap()))
                .await
                .unwrap()
                .is_none()
        );
    }
}

// ============================================================================
// Area #13: `local` (Tier 1 >= 5, Tier 2 >= 5)
// ============================================================================

#[tokio::test]
async fn tier1_local_client_copy_sync_move_delete_rename_mkdir_stat_about() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    let mov = tmp.path().join("mov");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    std::fs::create_dir_all(&mov).unwrap();

    std::fs::write(src.join("alpha.txt"), b"alpha-body").unwrap();
    std::fs::write(dst.join("stale.txt"), b"stale").unwrap();

    let client = RshipClient::ephemeral().unwrap();

    // mkdir & stat
    client.mkdir(src.join("sub").as_path()).await.unwrap();
    let dir_stat = client
        .stat(src.join("sub").as_path())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dir_stat.kind, EntryKind::Directory);

    // sync mirrors src -> dst and removes stale.txt
    let sync_rep = client
        .sync(src.as_path(), dst.as_path())
        .run()
        .await
        .unwrap();
    assert!(sync_rep.is_success());
    assert!(dst.join("alpha.txt").exists());
    assert!(!dst.join("stale.txt").exists());

    // open_read full and ranged (LocalSeekable supports random-access read_at)
    let full = read_all_from_source(
        client
            .open_read(dst.join("alpha.txt").as_path(), None)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(full, b"alpha-body");
    let ds_ranged = client
        .open_read(
            dst.join("alpha.txt").as_path(),
            Some(ByteRange { offset: 6, len: 4 }),
        )
        .await
        .unwrap();
    let ranged = match ds_ranged {
        DataSource::LocalSeekable(seekable) => {
            let mut buf = vec![0u8; 4];
            let n = seekable.read_at(6, &mut buf).await.unwrap();
            buf.truncate(n);
            buf
        }
        other => read_all_from_source(other).await.unwrap(),
    };
    assert_eq!(ranged, b"body");

    // rename & delete
    client
        .rename(dst.join("alpha.txt").as_path(), "beta.txt")
        .await
        .unwrap();
    assert!(dst.join("beta.txt").exists());
    assert!(!dst.join("alpha.txt").exists());

    // move_path moves dst -> mov
    let mov_rep = client
        .move_path(dst.as_path(), mov.as_path())
        .run()
        .await
        .unwrap();
    assert!(mov_rep.is_success());
    assert!(mov.join("beta.txt").exists());
    assert!(!dst.join("beta.txt").exists());

    client.delete(mov.join("beta.txt").as_path()).await.unwrap();
    assert!(!mov.join("beta.txt").exists());

    // about returns quota
    let quota = client.about(src.as_path()).await.unwrap();
    assert!(quota.is_some());
}

#[tokio::test]
async fn tier1_local_resumable_chunked_upload_and_query_progress() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let backend = LocalBackend::new("loc", &root)
        .unwrap()
        .with_chunking(64 * 1024, 64 * 1024);

    let payload: Vec<u8> = (0..(128 * 1024)).map(|i| (i % 251) as u8).collect();
    let init = simple_upload_init(
        "op-chunk-ok",
        "chunked.bin",
        payload.len() as u64,
        1_700_000_000_000_000_000,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op_record(
        "local",
        &init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );

    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                payload.len() as u64,
                make_byte_stream(payload[..64 * 1024].to_vec()),
            ),
        )
        .await
        .unwrap();
    let ack2 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                64 * 1024,
                64 * 1024,
                payload.len() as u64,
                make_byte_stream(payload[64 * 1024..].to_vec()),
            ),
        )
        .await
        .unwrap();

    match backend.query_upload(&op).await.unwrap() {
        UploadProgress::CompletedParts(parts) => {
            assert_eq!(parts.len(), 2);
            assert!(parts.iter().all(|p| p.etag.starts_with("crc32c:")));
        }
        other => panic!("expected CompletedParts, got {other:?}"),
    }

    let entry = backend
        .finish_upload(
            &op,
            &[
                CompletedPart {
                    part_number: 1,
                    offset: 0,
                    length: 64 * 1024,
                    etag: ack1.etag.unwrap_or_default(),
                    checksum: ack1.checksum,
                },
                CompletedPart {
                    part_number: 2,
                    offset: 64 * 1024,
                    length: 64 * 1024,
                    etag: ack2.etag.unwrap_or_default(),
                    checksum: ack2.checksum,
                },
            ],
        )
        .await
        .unwrap();
    assert_eq!(entry.size, payload.len() as u64);
    assert_eq!(std::fs::read(root.join("chunked.bin")).unwrap(), payload);

    // Abort cleans staging files.
    let init_ab = simple_upload_init(
        "op-abort",
        "aborted.bin",
        128 * 1024,
        1_700_000_000_000_000_000,
        DstPrecondition::Absent,
    );
    let sess_ab = backend.begin_upload(&init_ab).await.unwrap();
    let op_ab = make_op_record(
        "local",
        &init_ab,
        Some(sess_ab.session_token),
        sess_ab.backend_meta,
        sess_ab.remote_op_id,
    );
    backend.abort_upload(&op_ab).await.unwrap();
    let leftovers: Vec<_> = std::fs::read_dir(&root)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains(".rship.part."))
        .collect();
    assert!(leftovers.is_empty());
}

#[tokio::test]
async fn tier1_local_dst_precondition_absent_and_existing_guards() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();
    let backend = LocalBackend::new("loc", &root).unwrap();

    let e1 = backend
        .put_single_shot(
            &simple_upload_init(
                "op1",
                "guard.txt",
                5,
                1_700_000_000_000_000_000,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"hello".to_vec()),
        )
        .await
        .unwrap();

    let err_abs = backend
        .put_single_shot(
            &simple_upload_init(
                "op2",
                "guard.txt",
                5,
                1_700_000_000_000_000_000,
                DstPrecondition::Absent,
            ),
            make_byte_stream(b"world".to_vec()),
        )
        .await
        .unwrap_err();
    assert_eq!(err_abs.kind(), ErrorKind::PreconditionFailed);

    let err_sz = backend
        .put_single_shot(
            &simple_upload_init(
                "op3",
                "guard.txt",
                6,
                1_700_000_000_000_000_000,
                DstPrecondition::Existing {
                    node_id: e1.node_id.clone(),
                    etag: e1.etag.clone(),
                    mtime_ns: e1.mtime_ns,
                    size: 999,
                },
            ),
            make_byte_stream(b"world!".to_vec()),
        )
        .await
        .unwrap_err();
    assert_eq!(err_sz.kind(), ErrorKind::PreconditionFailed);

    let e2 = backend
        .put_single_shot(
            &simple_upload_init(
                "op4",
                "guard.txt",
                6,
                1_700_000_001_000_000_000,
                DstPrecondition::Existing {
                    node_id: e1.node_id,
                    etag: e1.etag,
                    mtime_ns: e1.mtime_ns,
                    size: e1.size,
                },
            ),
            make_byte_stream(b"world!".to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(e2.size, 6);
    assert_eq!(std::fs::read(root.join("guard.txt")).unwrap(), b"world!");
}

#[tokio::test]
async fn tier1_local_compute_hash_all_supported_algorithms() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("hash");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("data.txt"), b"hello world").unwrap();

    let backend = LocalBackend::new("hash", &root).unwrap();
    let bp = BackendPath::from_rel(RelPath::parse("data.txt").unwrap());

    let sha = backend
        .compute_hash(&bp, HashKind::Sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        sha.hex,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    let md5 = backend
        .compute_hash(&bp, HashKind::Md5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(md5.hex, "5eb63bbbe01eeed093cb22bb8f5acdc3");
    assert!(
        backend
            .compute_hash(&bp, HashKind::Crc32c)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        backend
            .compute_hash(&bp, HashKind::Crc64Nvme)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        backend
            .compute_hash(&bp, HashKind::Blake3)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn tier1_local_fsync_modes_always_batch_never_and_flush() {
    let tmp = TempDir::new().unwrap();
    let d_always = tmp.path().join("always");
    let d_batch = tmp.path().join("batch");
    let d_never = tmp.path().join("never");
    std::fs::create_dir_all(&d_always).unwrap();
    std::fs::create_dir_all(&d_batch).unwrap();
    std::fs::create_dir_all(&d_never).unwrap();

    let b_always = LocalBackend::new("a", &d_always)
        .unwrap()
        .with_fsync_mode(FsyncMode::Always);
    assert!(!b_always.defers_durable_writes());
    b_always
        .put_single_shot(
            &simple_upload_init("fa", "f.txt", 3, 100, DstPrecondition::Any),
            make_byte_stream(b"abc".to_vec()),
        )
        .await
        .unwrap();
    assert!(b_always.fsync_count() > 0);

    let b_batch = LocalBackend::new("b", &d_batch)
        .unwrap()
        .with_fsync_mode(FsyncMode::Batch);
    assert!(b_batch.defers_durable_writes());
    b_batch
        .put_single_shot(
            &simple_upload_init("fb", "f.txt", 3, 100, DstPrecondition::Any),
            make_byte_stream(b"abc".to_vec()),
        )
        .await
        .unwrap();
    b_batch.flush_durable_writes().await.unwrap();
    assert!(b_batch.batch_flush_count() >= 1);

    let b_never = LocalBackend::new("n", &d_never)
        .unwrap()
        .with_fsync_mode(FsyncMode::Never);
    assert!(!b_never.defers_durable_writes());
    b_never
        .put_single_shot(
            &simple_upload_init("fn", "f.txt", 3, 100, DstPrecondition::Any),
            make_byte_stream(b"abc".to_vec()),
        )
        .await
        .unwrap();
    assert_eq!(b_never.fsync_count(), 0);
}

#[tokio::test]
async fn tier2_local_finish_upload_rejects_incomplete_parts_no_sparse_commit() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let backend = LocalBackend::new("loc", &root)
        .unwrap()
        .with_chunking(64 * 1024, 64 * 1024);

    let init = simple_upload_init(
        "op-sparse",
        "incomplete.bin",
        128 * 1024,
        1_700_000_000_000_000_000,
        DstPrecondition::Absent,
    );
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = make_op_record(
        "local",
        &init,
        Some(sess.session_token),
        sess.backend_meta,
        sess.remote_op_id,
    );

    // Upload ONLY part 1 (64 KiB) and skip part 2 [64 KiB..128 KiB).
    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                128 * 1024,
                make_byte_stream(vec![0xabu8; 64 * 1024]),
            ),
        )
        .await
        .unwrap();
    let p1 = CompletedPart {
        part_number: 1,
        offset: 0,
        length: 64 * 1024,
        etag: ack1.etag.unwrap_or_default(),
        checksum: ack1.checksum,
    };

    assert!(
        backend
            .finish_upload(&op, std::slice::from_ref(&p1))
            .await
            .is_err(),
        "finish_upload with incomplete parts must fail instead of committing sparse zero-filled file"
    );
    assert!(
        !root.join("incomplete.bin").exists(),
        "incomplete upload must not commit final file"
    );

    // Even if caller passes forged CompletedPart #2, missing .parts entry must reject commit.
    let forged_p2 = CompletedPart {
        part_number: 2,
        offset: 64 * 1024,
        length: 64 * 1024,
        etag: String::new(),
        checksum: None,
    };
    assert!(
        backend.finish_upload(&op, &[p1, forged_p2]).await.is_err(),
        "finish_upload with unuploaded part in .parts must fail"
    );
    assert!(!root.join("incomplete.bin").exists());
}

#[tokio::test]
async fn tier2_local_probe_case_sensitivity_non_polluting_on_source_dir() {
    let tmp = TempDir::new().unwrap();
    let src_dir = tmp.path().join("src_dir");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(src_dir.join("Sample.txt"), b"hi").unwrap();

    std::thread::sleep(std::time::Duration::from_millis(60));
    let before_mtime = std::fs::metadata(&src_dir).unwrap().modified().unwrap();

    let backend = LocalBackend::new("ro", &src_dir).unwrap();
    let after_mtime = std::fs::metadata(&src_dir).unwrap().modified().unwrap();
    assert_eq!(
        after_mtime, before_mtime,
        "LocalBackend::new must not create/delete probe files that mutate source dir mtime"
    );
    let expected_case_sensitive = !src_dir.join("sample.txt").exists();
    assert_eq!(
        backend.capabilities().case_sensitive,
        expected_case_sensitive,
        "LocalBackend::capabilities().case_sensitive must match actual filesystem behavior"
    );

    // Concurrent LocalBackend::new calls in the same process must not race on probe files.
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let dir = src_dir.clone();
            std::thread::spawn(move || {
                LocalBackend::new(format!("conc_{i}"), &dir)
                    .unwrap()
                    .capabilities()
                    .case_sensitive
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected_case_sensitive);
    }

    let names: Vec<String> = std::fs::read_dir(&src_dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["Sample.txt".to_string()]);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let ro_dir = tmp.path().join("ro_dir");
        std::fs::create_dir_all(&ro_dir).unwrap();
        std::fs::write(ro_dir.join("Sample.txt"), b"hi").unwrap();
        std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let res = LocalBackend::new("ro_unix", &ro_dir);
        let _ = std::fs::set_permissions(&ro_dir, std::fs::Permissions::from_mode(0o755));
        let ro_backend =
            res.expect("LocalBackend::new on 0555 read-only dir must succeed without writing");
        assert_eq!(
            ro_backend.capabilities().case_sensitive,
            !ro_dir.join("sample.txt").exists(),
            "read-only dir LocalBackend must still report accurate case_sensitive"
        );
    }
}

#[tokio::test]
async fn tier2_local_symlink_escape_rejection_and_ancestor_loop_above_root() {
    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    let root = outside.join("root");
    std::fs::create_dir_all(outside.join("sub")).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(outside.join("secret.txt"), b"top-secret").unwrap();
    std::fs::write(outside.join("sub/secret2.txt"), b"top-secret-2").unwrap();

    let esc_path = root.join("esc");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, &esc_path).unwrap();
    }
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &esc_path.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }

    let backend = LocalBackend::new("safe", &root)
        .unwrap()
        .with_follow_symlinks(false);

    let stat_res = backend
        .stat(&BackendPath::from_rel(
            RelPath::parse("esc/secret.txt").unwrap(),
        ))
        .await;
    assert!(
        stat_res.is_err(),
        "stat through symlink/junction escape must fail, got: {stat_res:?}"
    );

    let list_res = backend
        .list_with_options(
            &RelPath::parse("esc/sub").unwrap(),
            &ListOptions::recursive(),
        )
        .await;
    if let Ok(stream) = list_res {
        let items = collect_entries(stream).await;
        assert!(
            items.is_err() || items.as_ref().is_ok_and(|v| v.is_empty()),
            "list_with_options through symlink/junction escape must not return outside entries: {items:?}"
        );
    }

    #[cfg(unix)]
    {
        // Ancestor loop pointing above root (`outside/root/up -> ..`).
        std::os::unix::fs::symlink("..", root.join("up")).unwrap();
        let follow_backend = LocalBackend::new("follow", &root)
            .unwrap()
            .with_follow_symlinks(true);
        // A symlink to an ancestor of the root is a cycle: the walker reports it as a
        // per-entry error and never descends through it (see
        // `local::tests::walk_and_symlinks`), so collect tolerantly and assert on the
        // entries that were actually yielded rather than treating the error as fatal.
        let items: Vec<Result<Entry>> = follow_backend
            .list_stream(&RelPath::root(), true)
            .await
            .unwrap()
            .collect()
            .await;
        let leaked: Vec<_> = items
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .filter(|e| e.nfc_path.as_str().contains("secret.txt"))
            .map(|e| e.nfc_path.as_str().to_string())
            .collect();
        assert!(
            leaked.is_empty(),
            "ancestor loop above root must not leak outside entries: {leaked:?}"
        );
        assert!(
            items.iter().any(|r| r
                .as_ref()
                .err()
                .is_some_and(|e| e.to_string().contains("symlink cycle"))),
            "ancestor loop must be reported as a symlink-cycle error: {items:?}"
        );
    }
}

#[tokio::test]
async fn tier2_local_windows_safe_bidirectional_roundtrip_sync_ls_check() {
    let tmp = TempDir::new().unwrap();
    let d1 = tmp.path().join("ws1");
    let d2 = tmp.path().join("ws2");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();

    // Pre-seed WindowsSafe-encoded filenames directly on disk (valid on both Windows and Unix).
    std::fs::write(d1.join("^43ON"), b"con-body").unwrap();
    std::fs::write(d1.join("a^3Ab"), b"colon-body").unwrap();
    std::fs::write(d1.join("foo^20"), b"space-body").unwrap();
    std::fs::write(d1.join("^43ON.txt"), b"con-txt").unwrap();

    let ws1 = LocalBackend::new("ws1", &d1)
        .unwrap()
        .with_encoding(EncodingMode::WindowsSafe);
    let ws2 = LocalBackend::new("ws2", &d2)
        .unwrap()
        .with_encoding(EncodingMode::WindowsSafe);

    ws1.put_single_shot(
        &simple_upload_init(
            "op-q",
            "q?mark.txt",
            5,
            1_700_000_000_000_000_000,
            DstPrecondition::Any,
        ),
        make_byte_stream(b"quest".to_vec()),
    )
    .await
    .unwrap();

    let listed = collect_entries(ws1.list_stream(&RelPath::root(), true).await.unwrap())
        .await
        .unwrap();
    let logical_names: BTreeSet<String> = listed
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    for expected in ["CON", "a:b", "foo ", "CON.txt", "q?mark.txt"] {
        assert!(
            logical_names.contains(expected),
            "WindowsSafe listing missing decoded `{expected}`; got {logical_names:?}"
        );
    }

    for (logical, body) in [
        ("CON", b"con-body".as_slice()),
        ("a:b", b"colon-body".as_slice()),
        ("foo ", b"space-body".as_slice()),
        ("q?mark.txt", b"quest".as_slice()),
    ] {
        let bp = BackendPath::from_rel(RelPath::parse(logical).unwrap());
        assert!(
            ws1.stat(&bp).await.unwrap().is_some(),
            "stat({logical}) must resolve decoded logical name"
        );
        let got = read_all_from_source(ws1.open_read(&bp, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(got, body);
    }

    let client = RshipClient::builder()
        .ephemeral()
        .register_backend("ws1", ws1)
        .register_backend("ws2", ws2)
        .build()
        .unwrap();
    let rep1 = client.sync("ws1:", "ws2:").run().await.unwrap();
    assert!(rep1.is_success(), "{:?}", rep1.errors);
    assert_eq!(rep1.files_transferred, 5);

    let rep2 = client.sync("ws1:", "ws2:").run().await.unwrap();
    assert!(rep2.is_success(), "{:?}", rep2.errors);
    assert_eq!(rep2.files_transferred, 0);
    assert_eq!(rep2.items_deleted, 0);

    // Parity check equivalence (`rship check` via public SDK APIs; RshipClient has no `.check()`):
    // 1. Verify `ws2:` listing, `stat`, `open_read`, and SHA-256 parity against `ws1:`.
    let ws2_listed = collect_entries(
        client
            .list("ws2:", &ListOptions::recursive())
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let ws2_names: BTreeSet<String> = ws2_listed
        .iter()
        .map(|e| e.nfc_path.as_str().to_string())
        .collect();
    assert_eq!(ws2_names, logical_names);

    let (ws1_b, _) = client.resolve("ws1:").unwrap();
    let (ws2_b, _) = client.resolve("ws2:").unwrap();
    for (logical, body) in [
        ("CON", b"con-body".as_slice()),
        ("a:b", b"colon-body".as_slice()),
        ("foo ", b"space-body".as_slice()),
        ("CON.txt", b"con-txt".as_slice()),
        ("q?mark.txt", b"quest".as_slice()),
    ] {
        let target = format!("ws2:{logical}");
        let st = client
            .stat(&target)
            .await
            .unwrap()
            .expect("ws2 stat must exist");
        assert_eq!(st.size, body.len() as u64);
        let got = read_all_from_source(client.open_read(&target, None).await.unwrap())
            .await
            .unwrap();
        assert_eq!(got, body);

        let bp = BackendPath::from_rel(RelPath::parse(logical).unwrap());
        let h1 = ws1_b
            .compute_hash(&bp, HashKind::Sha256)
            .await
            .unwrap()
            .unwrap();
        let h2 = ws2_b
            .compute_hash(&bp, HashKind::Sha256)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(h1, h2, "SHA-256 mismatch on ws2 for `{logical}`");
    }

    // 2. Checksum-mode sync (non-dry-run) must verify all 5 files and transfer 0.
    let rep_chk = client
        .sync("ws1:", "ws2:")
        .checksum(true)
        .run()
        .await
        .unwrap();
    assert!(rep_chk.is_success(), "{:?}", rep_chk.errors);
    assert_eq!(rep_chk.files_transferred, 0);
    assert_eq!(rep_chk.files_skipped, 5);
    assert_eq!(rep_chk.items_deleted, 0);

    #[cfg(unix)]
    {
        let raw_dir = tmp.path().join("raw_unix");
        let ws3_dir = tmp.path().join("ws3");
        std::fs::create_dir_all(&raw_dir).unwrap();
        std::fs::create_dir_all(&ws3_dir).unwrap();
        std::fs::write(raw_dir.join("CON"), b"1").unwrap();
        std::fs::write(raw_dir.join("a:b"), b"2").unwrap();
        std::fs::write(raw_dir.join("foo "), b"3").unwrap();

        let ws3 = LocalBackend::new("ws3", &ws3_dir)
            .unwrap()
            .with_encoding(EncodingMode::WindowsSafe);
        let c2 = RshipClient::builder()
            .ephemeral()
            .register_backend("ws3", ws3)
            .build()
            .unwrap();
        let r1 = c2.sync(raw_dir.as_path(), "ws3:").run().await.unwrap();
        assert!(r1.is_success(), "{:?}", r1.errors);
        assert_eq!(r1.files_transferred, 3);
        let r2 = c2.sync(raw_dir.as_path(), "ws3:").run().await.unwrap();
        assert_eq!(r2.files_transferred, 0);
        assert_eq!(r2.items_deleted, 0);
    }
}

#[tokio::test]
async fn tier2_local_nfd_parent_dir_rename_and_prefix_traversal() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("nfd");
    let nfd_sub = root.join("cafe\u{0301}").join("sub");
    std::fs::create_dir_all(&nfd_sub).unwrap();
    std::fs::write(nfd_sub.join("old.txt"), b"nfd-payload").unwrap();

    let backend = LocalBackend::new("nfd", &root).unwrap();

    let prefix_listed = collect_entries(
        backend
            .list_with_options(
                &RelPath::parse("caf\u{00e9}").unwrap(),
                &ListOptions::recursive(),
            )
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        prefix_listed
            .iter()
            .any(|e| e.nfc_path.as_str() == "caf\u{00e9}/sub/old.txt"),
        "NFC prefix list must traverse NFD dir on disk, got: {:?}",
        prefix_listed
            .iter()
            .map(|e| e.nfc_path.as_str())
            .collect::<Vec<_>>()
    );

    let all = collect_entries(backend.list_stream(&RelPath::root(), true).await.unwrap())
        .await
        .unwrap();
    let old_entry = all
        .into_iter()
        .find(|e| e.nfc_path.as_str() == "caf\u{00e9}/sub/old.txt")
        .expect("old.txt must be listed");
    let renamed = backend
        .rename(&BackendPath::from_entry(&old_entry), "new.txt")
        .await
        .expect("rename inside NFD parent dir must succeed");
    assert_eq!(renamed.nfc_path.as_str(), "caf\u{00e9}/sub/new.txt");
    assert!(nfd_sub.join("new.txt").exists());
    assert!(!nfd_sub.join("old.txt").exists());
}

#[cfg(windows)]
#[test]
fn tier2_local_windows_to_os_path_unc_and_dotdot_normalization() {
    use rship::backends::local::to_os_path;
    use std::path::Path;

    let tail = "a".repeat(250);
    let unc_fwd = format!("//server/share/{tail}");
    let out_fwd = to_os_path(Path::new(&unc_fwd))
        .to_string_lossy()
        .into_owned();
    assert!(
        out_fwd.starts_with(r"\\?\UNC\server\share\"),
        "expected \\\\?\\UNC\\server\\share\\ prefix, got: {out_fwd}"
    );
    assert!(
        !out_fwd.contains('/'),
        "unexpected forward slash in {out_fwd}"
    );

    let unc_mix = format!(r"\\server/share/{tail}");
    let out_mix = to_os_path(Path::new(&unc_mix))
        .to_string_lossy()
        .into_owned();
    assert!(
        out_mix.starts_with(r"\\?\UNC\server\share\"),
        "expected \\\\?\\UNC\\server\\share\\ prefix, got: {out_mix}"
    );
    assert!(
        !out_mix.contains('/'),
        "unexpected forward slash in {out_mix}"
    );

    let dotdot = format!(r"C:\work\sub\..\dst\{tail}");
    let out_dotdot = to_os_path(Path::new(&dotdot))
        .to_string_lossy()
        .into_owned();
    assert!(
        out_dotdot.starts_with(r"\\?\C:\work\dst\"),
        "expected normalized \\\\?\\C:\\work\\dst\\ prefix, got: {out_dotdot}"
    );
    assert!(
        !out_dotdot.contains(r"\..\"),
        "unexpected .. segment under \\\\?\\ prefix: {out_dotdot}"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn tier2_local_windows_non_surrogate_reparse_point_allowed_vs_junction_rejected() {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_DEDUP: u32 = 0x8000_0013; // bit 29 == 0 (IsReparseTagNameSurrogate == false)

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn DeviceIoControl(
            h_device: *mut std::ffi::c_void,
            dw_io_control_code: u32,
            lp_in_buffer: *const u8,
            n_in_buffer_size: u32,
            lp_out_buffer: *mut u8,
            n_out_buffer_size: u32,
            lp_bytes_returned: *mut u32,
            lp_overlapped: *mut std::ffi::c_void,
        ) -> i32;
    }

    let tmp = TempDir::new().unwrap();
    let outside = tmp.path().join("outside");
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(outside.join("secret.txt"), b"outside-secret").unwrap();

    // 1. Non-surrogate reparse point regular file (unprivileged FSCTL_SET_REPARSE_POINT).
    let dedup_file = root.join("dedup.txt");
    let payload = b"non-surrogate-reparse-bytes";
    std::fs::write(&dedup_file, payload).unwrap();
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&dedup_file)
            .unwrap();
        // REPARSE_DATA_BUFFER: Tag(u32) + DataLength(u16=4) + Reserved(u16=0) + 4-byte dummy data
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&IO_REPARSE_TAG_DEDUP.to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes());
        let mut returned = 0u32;
        // SAFETY: `f.as_raw_handle()` is a valid open file handle and `buf` is a 12-byte
        // `REPARSE_DATA_BUFFER` valid for the duration of `DeviceIoControl`.
        let ok = unsafe {
            DeviceIoControl(
                f.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buf.as_ptr(),
                buf.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            ok,
            0,
            "FSCTL_SET_REPARSE_POINT(IO_REPARSE_TAG_DEDUP) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let meta = std::fs::symlink_metadata(&dedup_file).unwrap();
    assert_ne!(meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT, 0);
    assert!(!meta.file_type().is_symlink());

    // 2. Surrogate reparse point (NTFS directory junction -> IO_REPARSE_TAG_MOUNT_POINT).
    let junc = root.join("junc");
    let status = std::process::Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &junc.to_string_lossy(),
            &outside.to_string_lossy(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J failed");

    let backend = LocalBackend::new("win_reparse", &root)
        .unwrap()
        .with_follow_symlinks(false);

    // Non-surrogate reparse file MUST be readable and hashable on M4 (fails on baseline af414db).
    let bp = BackendPath::from_rel(RelPath::parse("dedup.txt").unwrap());
    let read_bytes = read_all_from_source(backend.open_read(&bp, None).await.unwrap())
        .await
        .expect("non-surrogate reparse point file must be readable");
    assert_eq!(read_bytes, payload);
    assert!(
        backend
            .compute_hash(&bp, HashKind::Sha256)
            .await
            .unwrap()
            .is_some(),
        "non-surrogate reparse point file must be hashable"
    );

    // Surrogate junction MUST still be rejected.
    let junc_bp = BackendPath::from_rel(RelPath::parse("junc/secret.txt").unwrap());
    assert!(
        backend.open_read(&junc_bp, None).await.is_err(),
        "surrogate junction reparse point must be rejected when follow_symlinks=false"
    );
}
