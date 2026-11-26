//! End-to-end wire-protocol SFTP conformance & cross-restart crash-resume suite
//! running against a real in-process `russh` SSH + `russh-sftp` server over TCP!

use bytes::Bytes;
use futures::StreamExt;
use rand::SeedableRng;
use rship_backends::sftp::{HostKeyPolicy, SftpAuth, SftpBackend, SftpConfig};
use rship_core::backend::{BackendPath, ChunkUpload, StorageBackend, UploadInit, UploadProgress};
use rship_core::clock::SystemClock;
use rship_core::conformance::run_backend_conformance;
use rship_core::path::RelPath;
use rship_core::state::{
    DstPrecondition, OperationRecord, OperationState, SourceVersion, compute_session_key,
};
use russh::keys::ssh_key::Certificate;
use russh::keys::ssh_key::certificate::{Builder as CertBuilder, CertType};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{
    Auth, ChannelOpenHandle, Msg, Response, Server as _, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId, MethodKind, MethodSet};
use russh_sftp::protocol::{
    Attrs, Data, File as SftpDirFile, FileAttributes, Handle, Name, OpenFlags, SftpHandle,
    SftpString, Status, StatusCode, Version,
};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

#[derive(Clone)]
struct TestSshServer {
    root: PathBuf,
}

impl russh::server::Server for TestSshServer {
    type Handler = TestSshConn;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        TestSshConn {
            root: self.root.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct TestSshConn {
    root: PathBuf,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for TestSshConn {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == "tester" && password == "sftp-pass" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            let channel = self.channels.lock().await.remove(&channel_id).unwrap();
            let handler = LocalBackedSftpServer::new(self.root.clone());
            session.channel_success(channel_id)?;
            tokio::spawn(async move {
                russh_sftp::server::run(channel.into_stream(), handler).await;
            });
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

enum OpenItem {
    File(fs::File),
    Dir {
        entries: Vec<SftpDirFile>,
        sent: bool,
    },
}

struct LocalBackedSftpServer {
    root: PathBuf,
    next_handle: u64,
    handles: HashMap<String, OpenItem>,
}

impl LocalBackedSftpServer {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            next_handle: 1,
            handles: HashMap::new(),
        }
    }

    fn resolve(&self, raw: &str) -> PathBuf {
        let trimmed = raw.trim().trim_start_matches('/');
        if trimmed.is_empty() || trimmed == "." {
            return self.root.clone();
        }
        let mut out = self.root.clone();
        for seg in trimmed.split('/').filter(|s| !s.is_empty() && *s != ".") {
            out.push(seg);
        }
        out
    }

    fn alloc_handle(&mut self) -> String {
        let h = format!("h-{}", self.next_handle);
        self.next_handle += 1;
        h
    }
}

fn fs_meta_to_attrs(meta: &fs::Metadata) -> FileAttributes {
    let perms = if meta.is_dir() { 0o040755 } else { 0o100644 };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32);
    FileAttributes {
        size: Some(if meta.is_dir() { 0 } else { meta.len() }),
        permissions: Some(perms),
        mtime,
        atime: mtime,
        ..Default::default()
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".into(),
        language_tag: "en-US".into(),
    }
}

fn map_io(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

impl russh_sftp::server::Handler for LocalBackedSftpServer {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn open(
        &mut self,
        id: u32,
        filename: SftpString,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let p = self.resolve(filename.to_string().as_str());
        let mut opts = OpenOptions::new();
        opts.read(pflags.contains(OpenFlags::READ) || !pflags.contains(OpenFlags::WRITE));
        opts.write(pflags.contains(OpenFlags::WRITE));
        opts.create(pflags.contains(OpenFlags::CREATE));
        opts.truncate(pflags.contains(OpenFlags::TRUNCATE));
        let f = opts.open(&p).map_err(map_io)?;
        let hid = self.alloc_handle();
        self.handles.insert(hid.clone(), OpenItem::File(f));
        Ok(Handle {
            id,
            handle: SftpHandle::from(hid),
        })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        self.handles.remove(&key);
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(OpenItem::File(f)) = self.handles.get_mut(&key) else {
            return Err(StatusCode::BadMessage);
        };
        f.seek(SeekFrom::Start(offset)).map_err(map_io)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).map_err(map_io)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(OpenItem::File(f)) = self.handles.get_mut(&key) else {
            return Err(StatusCode::BadMessage);
        };
        f.seek(SeekFrom::Start(offset)).map_err(map_io)?;
        f.write_all(&data).map_err(map_io)?;
        Ok(ok_status(id))
    }

    async fn lstat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        let meta = fs::symlink_metadata(&p).map_err(map_io)?;
        Ok(Attrs {
            id,
            attrs: fs_meta_to_attrs(&meta),
        })
    }

    async fn stat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        let meta = fs::metadata(&p).map_err(map_io)?;
        Ok(Attrs {
            id,
            attrs: fs_meta_to_attrs(&meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: SftpHandle) -> Result<Attrs, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(OpenItem::File(f)) = self.handles.get(&key) else {
            return Err(StatusCode::BadMessage);
        };
        let meta = f.metadata().map_err(map_io)?;
        Ok(Attrs {
            id,
            attrs: fs_meta_to_attrs(&meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: SftpString,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        if let Some(mt) = attrs.mtime
            && let Ok(f) = OpenOptions::new().write(true).open(&p)
        {
            let _ = f.set_modified(UNIX_EPOCH + Duration::from_secs(u64::from(mt)));
        }
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: SftpString) -> Result<Handle, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        let rd = fs::read_dir(&p).map_err(map_io)?;
        let mut entries = Vec::new();
        for item in rd.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if let Ok(meta) = item.metadata() {
                entries.push(SftpDirFile::new(name, fs_meta_to_attrs(&meta)));
            }
        }
        let hid = self.alloc_handle();
        self.handles.insert(
            hid.clone(),
            OpenItem::Dir {
                entries,
                sent: false,
            },
        );
        Ok(Handle {
            id,
            handle: SftpHandle::from(hid),
        })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(OpenItem::Dir { entries, sent }) = self.handles.get_mut(&key) else {
            return Err(StatusCode::BadMessage);
        };
        if *sent || entries.is_empty() {
            return Err(StatusCode::Eof);
        }
        *sent = true;
        Ok(Name {
            id,
            files: std::mem::take(entries),
        })
    }

    async fn remove(&mut self, id: u32, filename: SftpString) -> Result<Status, Self::Error> {
        let p = self.resolve(filename.to_string().as_str());
        fs::remove_file(&p).map_err(map_io)?;
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: SftpString,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        fs::create_dir(&p).map_err(map_io)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: SftpString) -> Result<Status, Self::Error> {
        let p = self.resolve(path.to_string().as_str());
        fs::remove_dir(&p).map_err(map_io)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: SftpString,
        newpath: SftpString,
    ) -> Result<Status, Self::Error> {
        let o = self.resolve(oldpath.to_string().as_str());
        let n = self.resolve(newpath.to_string().as_str());
        if n.exists() {
            let _ = fs::remove_file(&n);
        }
        fs::rename(&o, &n).map_err(map_io)?;
        Ok(ok_status(id))
    }

    async fn realpath(&mut self, id: u32, path: SftpString) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![SftpDirFile::dummy(path)],
        })
    }
}

async fn start_test_sftp_server(root: &Path) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host_key = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[42u8; 32])),
        "rship-test-host",
    )
    .unwrap();
    let config = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let mut server = TestSshServer {
        root: root.to_path_buf(),
    };
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

fn make_sftp_backend(port: u16) -> SftpBackend {
    let mut cfg = SftpConfig::new(
        "test-sftp",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.single_shot_max_bytes = 32 * 1024;
    cfg.default_chunk_size = 64 * 1024;
    SftpBackend::new(cfg).unwrap()
}

#[tokio::test]
async fn sftp_passes_full_conformance_and_resumes_across_restarted_connection() {
    let tmp = TempDir::new().unwrap();
    let port = start_test_sftp_server(tmp.path()).await;

    let backend1 = Arc::new(make_sftp_backend(port));
    run_backend_conformance(backend1.clone(), SystemClock::shared()).await;

    // Test cross-restart crash-resume: upload chunk 1 via `backend1`, drop `backend1`,
    // connect brand-new `backend2`, query live remote `.rship.part.*`, upload chunk 2 & commit!
    let payload: Vec<u8> = (0..(150 * 1024)).map(|i| ((i * 37) % 251) as u8).collect();
    let dst_rel = RelPath::parse("resumed/big-sftp.bin").unwrap();
    let init = UploadInit {
        op_id: "op-sftp-crash-1".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend1.begin_upload(&init).await.unwrap();
    let mut op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: compute_session_key("local", "big", &backend1.endpoint_identity(), &dst_rel),
        job_id: "j-sftp".into(),
        src_endpoint: "local".into(),
        dst_endpoint: backend1.endpoint_identity(),
        src_raw_path: "big".into(),
        dst_raw_path: dst_rel.as_str().into(),
        dst_nfc_path: dst_rel.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: payload.len() as u64,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "sftp".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 1,
        updated_at: 1,
        expires_at: None,
    };

    let c1 = payload[..64 * 1024].to_vec();
    let ack1 = backend1
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                c1.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c1)) })),
            ),
        )
        .await
        .unwrap();
    op.confirmed_offset = ack1.next_offset.unwrap();
    drop(backend1);

    // Brand-new SFTP client after simulated process restart!
    let backend2 = make_sftp_backend(port);
    assert_eq!(
        backend2.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(64 * 1024)
    );

    let c2 = payload[64 * 1024..].to_vec();
    backend2
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                64 * 1024,
                c2.len() as u64,
                payload.len() as u64,
                Box::pin(futures::stream::once(async move { Ok(Bytes::from(c2)) })),
            ),
        )
        .await
        .unwrap();
    backend2.finish_upload(&op, &[]).await.unwrap();

    // Stream back via RemoteRangeReadable and verify bit-exact match!
    let ds = backend2
        .open_read(&BackendPath::from_rel(dst_rel), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut s = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    let mut got = Vec::new();
    while let Some(chunk) = s.next().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, payload);
}

#[tokio::test]
async fn sftp_pipelined_multi_mib_fragmented_upload_and_range_download_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let port = start_test_sftp_server(tmp.path()).await;

    let mut cfg = SftpConfig::new(
        "test-sftp-pipe",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.single_shot_max_bytes = 4 * 1024 * 1024;
    cfg.default_chunk_size = 2 * 1024 * 1024;
    let backend = SftpBackend::new(cfg).unwrap();

    // Feed 2.5 MiB as fragmented 12 KiB slices to exercise WRITE_COALESCE_BYTES + 32-deep pipeline.
    let total_len = 2_560 * 1024usize;
    let payload: Vec<u8> = (0..total_len)
        .map(|i| ((i * 73 + 19) % 251) as u8)
        .collect();
    let slices: Vec<rship_core::Result<Bytes>> = payload
        .chunks(12 * 1024)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();

    let rel = RelPath::parse("pipelined/blob_2_5m.bin").unwrap();
    let init = UploadInit {
        op_id: "op-sftp-pipe-1".into(),
        dst_path: rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: total_len as u64,
        src_mtime_ns: 1_710_000_000_000_000_000,
        planned_chunk_size: total_len as u64,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let uploaded = backend
        .put_single_shot(&init, Box::pin(futures::stream::iter(slices)))
        .await
        .unwrap();
    assert_eq!(uploaded.size, total_len as u64);

    // Full pipelined download via 256 KiB slices + mid-file sub-range verification.
    let ds = backend
        .open_read(&BackendPath::from_rel(rel), None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };

    let mut full_stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: total_len as u64,
        })
        .await
        .unwrap();
    let mut got_full = Vec::with_capacity(total_len);
    while let Some(c) = full_stream.next().await {
        got_full.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got_full, payload);

    let sub_off = 1_000_003usize;
    let sub_len = 300_017usize;
    let mut sub_stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: sub_off as u64,
            len: sub_len as u64,
        })
        .await
        .unwrap();
    let mut got_sub = Vec::with_capacity(sub_len);
    while let Some(c) = sub_stream.next().await {
        got_sub.extend_from_slice(&c.unwrap());
    }
    assert_eq!(got_sub, &payload[sub_off..sub_off + sub_len]);
}

/// `reconcile_operation` must never accept an older file just because it has the source's
/// size: with the staging part gone, an unchanged size and mtime from the planner's pre-op
/// file cannot be told apart from a commit, so the engine must transfer again.
#[tokio::test]
async fn sftp_reconcile_never_accepts_an_older_same_size_file() {
    use rship_core::backend::ReconcileOutcome;
    use rship_core::state::{OperationRecord, OperationState, SourceVersion};
    let tmp = TempDir::new().unwrap();
    let port = start_test_sftp_server(tmp.path()).await;
    let backend = make_sftp_backend(port);
    let mtime_secs = 1_700_000_000u64;
    fs::write(tmp.path().join("old.bin"), b"old-sftp-content").unwrap();
    OpenOptions::new()
        .write(true)
        .open(tmp.path().join("old.bin"))
        .unwrap()
        .set_modified(UNIX_EPOCH + Duration::from_secs(mtime_secs))
        .unwrap();
    let rel = RelPath::parse("old.bin").unwrap();
    let old = backend
        .stat(&BackendPath::from_rel(rel.clone()))
        .await
        .unwrap()
        .unwrap();
    let mut op = OperationRecord {
        op_id: "op-sftp-reconcile".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "old.bin".into(),
        dst_raw_path: "old.bin".into(),
        dst_nfc_path: rel,
        src_version: SourceVersion {
            node_id: None,
            size: old.size,
            mtime_ns: old.mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Existing {
            node_id: None,
            etag: None,
            mtime_ns: old.mtime_ns,
            size: old.size,
        },
        existing_dst_node_id: None,
        remote_op_id: None,
        backend_kind: "sftp".into(),
        session_token: None,
        backend_meta: String::new(),
        planned_chunk_size: old.size,
        confirmed_offset: 0,
        state: OperationState::Completing,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    let outcome = backend.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::NotCommitted),
        "indistinguishable pre-op file must not be accepted: {outcome:?}"
    );

    // The pre-op file had other attributes; the file now has the source size and mtime.
    op.dst_precondition = DstPrecondition::Existing {
        node_id: None,
        etag: None,
        mtime_ns: old.mtime_ns - 3_600_000_000_000,
        size: old.size,
    };
    let outcome = backend.reconcile_operation(&op).await.unwrap();
    assert!(
        matches!(outcome, ReconcileOutcome::Committed(_)),
        "{outcome:?}"
    );
}

// ============================================================================
// Virtual SFTP filesystem + configurable SSH fault-injection server
// (runs deterministically on Windows and Unix!)
// ============================================================================

#[derive(Clone)]
enum VirtualNode {
    File {
        data: Vec<u8>,
        mtime: u32,
        mode: u32,
    },
    Dir {
        mtime: u32,
    },
    Special {
        mode: u32,
        mtime: u32,
    },
}

impl VirtualNode {
    fn to_attrs(&self) -> FileAttributes {
        match self {
            Self::File { data, mtime, mode } => FileAttributes {
                size: Some(data.len() as u64),
                permissions: Some(*mode),
                mtime: Some(*mtime),
                atime: Some(*mtime),
                ..Default::default()
            },
            Self::Dir { mtime } => FileAttributes {
                size: Some(0),
                permissions: Some(0o040755),
                mtime: Some(*mtime),
                atime: Some(*mtime),
                ..Default::default()
            },
            Self::Special { mode, mtime } => FileAttributes {
                size: Some(0),
                permissions: Some(*mode),
                mtime: Some(*mtime),
                atime: Some(*mtime),
                ..Default::default()
            },
        }
    }
}

#[derive(Default)]
struct VirtualFsState {
    /// Canonical absolute virtual paths: `"/"`, `"/dir"`, `"/dir/file.txt"`.
    nodes: BTreeMap<String, VirtualNode>,
    /// Optional paths recorded for `opendir`/`lstat`/`open` assertions.
    requested_paths: Vec<String>,
    /// Paths passed to `open()`.
    opened_paths: Vec<String>,
    /// Fault injections & telemetry.
    max_write_len_seen: u32,
    fail_setstat: bool,
    posix_rename_unsupported: bool,
    rename_rejects_existing: bool,
    drop_after_writes: Option<usize>,
    delete_on_write_number: Option<usize>,
    writes_seen: usize,
    drop_after_reads: Option<usize>,
    reads_seen: usize,
    drop_next_lstat_paths: HashSet<String>,
}

impl VirtualFsState {
    fn new_rooted() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            "/".into(),
            VirtualNode::Dir {
                mtime: 1_700_000_000,
            },
        );
        Self {
            nodes,
            ..Default::default()
        }
    }

    fn normalize(&self, raw: &str) -> String {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed == "." || trimmed == "/" {
            return "/".to_string();
        }
        let mut out = String::new();
        for seg in trimmed.split('/').filter(|s| !s.is_empty() && *s != ".") {
            out.push('/');
            out.push_str(seg);
        }
        if out.is_empty() { "/".to_string() } else { out }
    }

    fn parent_of(abs: &str) -> Option<&str> {
        if abs == "/" {
            return None;
        }
        match abs.rsplit_once('/') {
            Some(("", _)) => Some("/"),
            Some((p, _)) => Some(p),
            None => None,
        }
    }

    fn seed_dir(&mut self, abs_path: &str) {
        let norm = self.normalize(abs_path);
        self.nodes.insert(
            norm,
            VirtualNode::Dir {
                mtime: 1_700_000_000,
            },
        );
    }

    fn seed_file(&mut self, abs_path: &str, data: &[u8], mtime: u32) {
        let norm = self.normalize(abs_path);
        self.nodes.insert(
            norm,
            VirtualNode::File {
                data: data.to_vec(),
                mtime,
                mode: 0o100644,
            },
        );
    }

    fn seed_special(&mut self, abs_path: &str, mode: u32) {
        let norm = self.normalize(abs_path);
        self.nodes.insert(
            norm,
            VirtualNode::Special {
                mode,
                mtime: 1_700_000_000,
            },
        );
    }
}

#[derive(Clone, Default)]
struct VirtualSftpOpts {
    require_kb_interactive: bool,
    accepted_pubkeys: Vec<PublicKey>,
    certificates: Vec<Certificate>,
    auth_delay: Duration,
    subsystem_delay: Duration,
    close_session_after_first_cmd_on_conn: Arc<AtomicBool>,
    disconnect_conn1_on_second_subsystem: bool,
    deny_all_sftp_subsystems: bool,
    deny_conn1_second_subsystem: bool,
    ssh_connections_accepted: Arc<AtomicUsize>,
    active_ssh_connections: Arc<AtomicUsize>,
    max_concurrent_ssh_seen: Arc<AtomicUsize>,
}

#[derive(Clone)]
struct VirtualSshServer {
    fs: Arc<StdMutex<VirtualFsState>>,
    opts: VirtualSftpOpts,
}

impl russh::server::Server for VirtualSshServer {
    type Handler = VirtualSshConn;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        let total = self
            .opts
            .ssh_connections_accepted
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        let cur = self
            .opts
            .active_ssh_connections
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        self.opts
            .max_concurrent_ssh_seen
            .fetch_max(cur, Ordering::SeqCst);
        VirtualSshConn {
            fs: Arc::clone(&self.fs),
            opts: self.opts.clone(),
            conn_index: total,
            kb_stage: 0,
            subsystem_requests_on_conn: 0,
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct VirtualSshConn {
    fs: Arc<StdMutex<VirtualFsState>>,
    opts: VirtualSftpOpts,
    conn_index: usize,
    kb_stage: u8,
    subsystem_requests_on_conn: usize,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl Drop for VirtualSshConn {
    fn drop(&mut self) {
        self.opts
            .active_ssh_connections
            .fetch_sub(1, Ordering::SeqCst);
    }
}

impl russh::server::Handler for VirtualSshConn {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if !self.opts.auth_delay.is_zero() {
            tokio::time::sleep(self.opts.auth_delay).await;
        }
        if self.opts.require_kb_interactive {
            let methods: &[MethodKind] = &[MethodKind::KeyboardInteractive];
            return Ok(Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(methods)),
                partial_success: false,
            });
        }
        if user == "tester" && password == "sftp-pass" {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        if !self.opts.require_kb_interactive || user != "tester" {
            return Ok(Auth::reject());
        }
        match (self.kb_stage, response) {
            (0, None) => {
                // First send empty 0-prompt InfoRequest to verify multi-round handling.
                self.kb_stage = 1;
                Ok(Auth::Partial {
                    name: Cow::Borrowed("banner"),
                    instructions: Cow::Borrowed(""),
                    prompts: Cow::Borrowed(&[]),
                })
            }
            (1, Some(mut resp)) => {
                if resp.next().is_some() {
                    return Ok(Auth::reject());
                }
                self.kb_stage = 2;
                static PROMPTS: [(Cow<'static, str>, bool); 1] =
                    [(Cow::Borrowed("Password: "), false)];
                Ok(Auth::Partial {
                    name: Cow::Borrowed("auth"),
                    instructions: Cow::Borrowed("Enter password"),
                    prompts: Cow::Borrowed(&PROMPTS),
                })
            }
            (2, Some(mut resp)) => {
                let first = resp.next();
                if first.as_deref() == Some(b"sftp-pass") && resp.next().is_none() {
                    Ok(Auth::Accept)
                } else {
                    Ok(Auth::reject())
                }
            }
            _ => Ok(Auth::reject()),
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user == "tester"
            && self
                .opts
                .accepted_pubkeys
                .iter()
                .any(|k| k.key_data() == key.public_key.key_data())
        {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.opts.subsystem_delay.is_zero() {
            tokio::time::sleep(self.opts.subsystem_delay).await;
        }
        if name == "sftp" {
            self.subsystem_requests_on_conn += 1;
            if self.opts.deny_all_sftp_subsystems
                || (self.conn_index == 1
                    && self.opts.deny_conn1_second_subsystem
                    && self.subsystem_requests_on_conn == 2)
            {
                let _ = self.channels.lock().await.remove(&channel_id);
                session.channel_failure(channel_id)?;
                return Ok(());
            }
            if self.conn_index == 1
                && self.opts.disconnect_conn1_on_second_subsystem
                && self.subsystem_requests_on_conn == 2
            {
                let _ = self.channels.lock().await.remove(&channel_id);
                let _ = session.disconnect(
                    russh::Disconnect::ByApplication,
                    "simulated multiplexed subsystem disconnect",
                    "",
                );
                return Ok(());
            }
            let channel = self.channels.lock().await.remove(&channel_id).unwrap();
            let close_handle = if self.conn_index == 1
                && self
                    .opts
                    .close_session_after_first_cmd_on_conn
                    .load(Ordering::SeqCst)
            {
                Some(session.handle())
            } else {
                None
            };
            let handler = VirtualSftpHandler {
                fs: Arc::clone(&self.fs),
                next_handle: 1,
                handles: HashMap::new(),
                channel_id,
                session_handle: close_handle,
            };
            session.channel_success(channel_id)?;
            tokio::spawn(async move {
                russh_sftp::server::run(channel.into_stream(), handler).await;
            });
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

enum VirtualHandle {
    File {
        path: String,
    },
    Dir {
        entries: Vec<SftpDirFile>,
        sent: bool,
    },
}

struct VirtualSftpHandler {
    fs: Arc<StdMutex<VirtualFsState>>,
    next_handle: u64,
    handles: HashMap<String, VirtualHandle>,
    channel_id: ChannelId,
    session_handle: Option<russh::server::Handle>,
}

impl VirtualSftpHandler {
    fn alloc(&mut self) -> String {
        let h = format!("vh-{}", self.next_handle);
        self.next_handle += 1;
        h
    }

    async fn kill_conn_if_armed(&self) {
        if let Some(h) = &self.session_handle {
            let _ = h.close(self.channel_id).await;
        }
    }
}

impl russh_sftp::server::Handler for VirtualSftpHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut v = Version::new();
        let fs = self.fs.lock().unwrap();
        if !fs.posix_rename_unsupported {
            v.extensions
                .insert("posix-rename@openssh.com".into(), "1".into());
        }
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: SftpString,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let raw = filename.to_string();
        let mut fs = self.fs.lock().unwrap();
        fs.requested_paths.push(raw.clone());
        let abs = fs.normalize(&raw);
        fs.opened_paths.push(abs.clone());
        match fs.nodes.get_mut(&abs) {
            Some(VirtualNode::File { data, .. }) => {
                if pflags.contains(OpenFlags::TRUNCATE) {
                    data.clear();
                }
            }
            Some(VirtualNode::Dir { .. }) | Some(VirtualNode::Special { .. }) => {
                return Err(StatusCode::Failure);
            }
            None => {
                if !pflags.contains(OpenFlags::CREATE) {
                    return Err(StatusCode::NoSuchFile);
                }
                let parent = VirtualFsState::parent_of(&abs).unwrap_or("/");
                if !matches!(fs.nodes.get(parent), Some(VirtualNode::Dir { .. })) {
                    return Err(StatusCode::NoSuchFile);
                }
                fs.nodes.insert(
                    abs.clone(),
                    VirtualNode::File {
                        data: Vec::new(),
                        mtime: 1_700_000_000,
                        mode: 0o100644,
                    },
                );
            }
        }
        drop(fs);
        let hid = self.alloc();
        self.handles
            .insert(hid.clone(), VirtualHandle::File { path: abs });
        Ok(Handle {
            id,
            handle: SftpHandle::from(hid),
        })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        self.handles.remove(&key);
        Ok(ok_status(id))
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(VirtualHandle::File { path }) = self.handles.get(&key) else {
            return Err(StatusCode::BadMessage);
        };
        let should_drop = {
            let mut fs = self.fs.lock().unwrap();
            fs.reads_seen += 1;
            fs.drop_after_reads == Some(fs.reads_seen)
        };
        if should_drop {
            self.kill_conn_if_armed().await;
            return Err(StatusCode::ConnectionLost);
        }
        let fs = self.fs.lock().unwrap();
        let Some(VirtualNode::File { data, .. }) = fs.nodes.get(path) else {
            return Err(StatusCode::NoSuchFile);
        };
        let off = offset as usize;
        if off >= data.len() {
            return Err(StatusCode::Eof);
        }
        let end = (off + len as usize).min(data.len());
        Ok(Data {
            id,
            data: data[off..end].to_vec(),
        })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        chunk: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(VirtualHandle::File { path }) = self.handles.get(&key) else {
            return Err(StatusCode::BadMessage);
        };
        let should_drop = {
            let mut fs = self.fs.lock().unwrap();
            fs.max_write_len_seen = fs.max_write_len_seen.max(chunk.len() as u32);
            fs.writes_seen += 1;
            if fs.delete_on_write_number == Some(fs.writes_seen) {
                fs.nodes.remove(path);
            }
            fs.drop_after_writes == Some(fs.writes_seen)
        };
        if should_drop {
            self.kill_conn_if_armed().await;
            return Err(StatusCode::ConnectionLost);
        }
        let mut fs = self.fs.lock().unwrap();
        let Some(VirtualNode::File { data, .. }) = fs.nodes.get_mut(path) else {
            return Err(StatusCode::NoSuchFile);
        };
        let off = offset as usize;
        let needed = off + chunk.len();
        if data.len() < needed {
            data.resize(needed, 0);
        }
        data[off..needed].copy_from_slice(&chunk);
        Ok(ok_status(id))
    }

    async fn lstat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        let raw = path.to_string();
        let (abs, drop_now) = {
            let mut fs = self.fs.lock().unwrap();
            fs.requested_paths.push(raw.clone());
            let abs = fs.normalize(&raw);
            let drop_now = fs.drop_next_lstat_paths.remove(&abs);
            (abs, drop_now)
        };
        if drop_now {
            self.kill_conn_if_armed().await;
            return Err(StatusCode::ConnectionLost);
        }
        let fs = self.fs.lock().unwrap();
        let node = fs.nodes.get(&abs).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: node.to_attrs(),
        })
    }

    async fn stat(&mut self, id: u32, path: SftpString) -> Result<Attrs, Self::Error> {
        self.lstat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: SftpHandle) -> Result<Attrs, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(VirtualHandle::File { path }) = self.handles.get(&key) else {
            return Err(StatusCode::BadMessage);
        };
        let fs = self.fs.lock().unwrap();
        let node = fs.nodes.get(path).ok_or(StatusCode::NoSuchFile)?;
        Ok(Attrs {
            id,
            attrs: node.to_attrs(),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: SftpString,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let raw = path.to_string();
        let mut fs = self.fs.lock().unwrap();
        if fs.fail_setstat {
            return Err(StatusCode::Failure);
        }
        let abs = fs.normalize(&raw);
        let node = fs.nodes.get_mut(&abs).ok_or(StatusCode::NoSuchFile)?;
        if let Some(mt) = attrs.mtime {
            match node {
                VirtualNode::File { mtime, .. }
                | VirtualNode::Dir { mtime }
                | VirtualNode::Special { mtime, .. } => *mtime = mt,
            }
        }
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: SftpString) -> Result<Handle, Self::Error> {
        let raw = path.to_string();
        let mut fs = self.fs.lock().unwrap();
        fs.requested_paths.push(raw.clone());
        let abs = fs.normalize(&raw);
        if !matches!(fs.nodes.get(&abs), Some(VirtualNode::Dir { .. })) {
            return Err(StatusCode::NoSuchFile);
        }
        let mut entries = Vec::new();
        for (p, node) in &fs.nodes {
            if VirtualFsState::parent_of(p) == Some(abs.as_str()) {
                let name = p.rsplit('/').next().unwrap_or("").to_string();
                entries.push(SftpDirFile::new(name, node.to_attrs()));
            }
        }
        drop(fs);
        let hid = self.alloc();
        self.handles.insert(
            hid.clone(),
            VirtualHandle::Dir {
                entries,
                sent: false,
            },
        );
        Ok(Handle {
            id,
            handle: SftpHandle::from(hid),
        })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        let key = String::from_utf8_lossy(handle.as_bytes()).into_owned();
        let Some(VirtualHandle::Dir { entries, sent }) = self.handles.get_mut(&key) else {
            return Err(StatusCode::BadMessage);
        };
        if *sent || entries.is_empty() {
            return Err(StatusCode::Eof);
        }
        *sent = true;
        Ok(Name {
            id,
            files: std::mem::take(entries),
        })
    }

    async fn remove(&mut self, id: u32, filename: SftpString) -> Result<Status, Self::Error> {
        let raw = filename.to_string();
        let mut fs = self.fs.lock().unwrap();
        let abs = fs.normalize(&raw);
        match fs.nodes.get(&abs) {
            Some(VirtualNode::Dir { .. }) => Err(StatusCode::Failure),
            Some(_) => {
                fs.nodes.remove(&abs);
                Ok(ok_status(id))
            }
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: SftpString,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let raw = path.to_string();
        let mut fs = self.fs.lock().unwrap();
        let abs = fs.normalize(&raw);
        if fs.nodes.contains_key(&abs) {
            return Err(StatusCode::Failure);
        }
        fs.nodes.insert(
            abs,
            VirtualNode::Dir {
                mtime: 1_700_000_000,
            },
        );
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: SftpString) -> Result<Status, Self::Error> {
        let raw = path.to_string();
        let mut fs = self.fs.lock().unwrap();
        let abs = fs.normalize(&raw);
        match fs.nodes.get(&abs) {
            Some(VirtualNode::Dir { .. }) => {
                fs.nodes.remove(&abs);
                Ok(ok_status(id))
            }
            Some(_) => Err(StatusCode::Failure),
            None => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: SftpString,
        newpath: SftpString,
    ) -> Result<Status, Self::Error> {
        let o_raw = oldpath.to_string();
        let n_raw = newpath.to_string();
        let mut fs = self.fs.lock().unwrap();
        let o = fs.normalize(&o_raw);
        let n = fs.normalize(&n_raw);
        if fs.rename_rejects_existing && fs.nodes.contains_key(&n) {
            return Err(StatusCode::Failure);
        }
        let node = fs.nodes.remove(&o).ok_or(StatusCode::NoSuchFile)?;
        fs.nodes.insert(n, node);
        Ok(ok_status(id))
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Packet, Self::Error> {
        if request == "posix-rename@openssh.com" {
            let mut fs = self.fs.lock().unwrap();
            if fs.posix_rename_unsupported {
                return Err(StatusCode::OpUnsupported);
            }
            let mut cur = data.as_slice();
            fn read_str(buf: &mut &[u8]) -> Option<String> {
                if buf.len() < 4 {
                    return None;
                }
                let len = u32::from_be_bytes(buf[..4].try_into().ok()?) as usize;
                *buf = &buf[4..];
                if buf.len() < len {
                    return None;
                }
                let s = String::from_utf8(buf[..len].to_vec()).ok()?;
                *buf = &buf[len..];
                Some(s)
            }
            let old_s = read_str(&mut cur).ok_or(StatusCode::BadMessage)?;
            let new_s = read_str(&mut cur).ok_or(StatusCode::BadMessage)?;
            let o = fs.normalize(&old_s);
            let n = fs.normalize(&new_s);
            let node = fs.nodes.remove(&o).ok_or(StatusCode::NoSuchFile)?;
            fs.nodes.insert(n, node);
            return Ok(russh_sftp::protocol::Packet::Status(ok_status(id)));
        }
        Err(StatusCode::OpUnsupported)
    }

    async fn realpath(&mut self, id: u32, path: SftpString) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![SftpDirFile::dummy(path)],
        })
    }
}

async fn start_virtual_sftp_server(
    fs: Arc<StdMutex<VirtualFsState>>,
    host_keys: Vec<PrivateKey>,
    opts: VirtualSftpOpts,
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = russh::server::Config {
        auth_rejection_time: Duration::from_millis(5),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: host_keys,
        certificates: opts.certificates.clone(),
        ..Default::default()
    };
    cfg.methods = MethodSet::from(
        &[
            MethodKind::Password,
            MethodKind::PublicKey,
            MethodKind::KeyboardInteractive,
        ][..],
    );
    let config = Arc::new(cfg);
    let mut server = VirtualSshServer { fs, opts };
    tokio::spawn(async move {
        let _ = server.run_on_socket(config, &listener).await;
    });
    port
}

fn ed25519_host_key(seed: u8) -> PrivateKey {
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])),
        "test-host",
    )
    .unwrap()
}

#[tokio::test]
async fn sftp_accept_new_persists_known_hosts_and_blocks_cross_algo_mitm() {
    let tmp = TempDir::new().unwrap();
    let kh_path = tmp.path().join(".ssh").join("known_hosts");

    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let key1 = ed25519_host_key(1);
    let port1 =
        start_virtual_sftp_server(Arc::clone(&fs), vec![key1], VirtualSftpOpts::default()).await;

    let mut cfg1 = SftpConfig::new(
        "tofu",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg1.port = port1;
    cfg1.host_key_policy = HostKeyPolicy::AcceptNew;
    cfg1.known_hosts_path = Some(kh_path.clone());
    let b1 = SftpBackend::new(cfg1).unwrap();
    // First connect learns and persists key1.
    assert!(
        b1.stat(&BackendPath::from_rel(RelPath::parse("missing").unwrap()))
            .await
            .unwrap()
            .is_none()
    );
    assert!(kh_path.exists());

    // Strict connect on same port succeeds.
    let mut cfg_strict = SftpConfig::new(
        "strict",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_strict.port = port1;
    cfg_strict.host_key_policy = HostKeyPolicy::Strict;
    cfg_strict.known_hosts_path = Some(kh_path.clone());
    assert!(
        SftpBackend::new(cfg_strict)
            .unwrap()
            .stat(&BackendPath::from_rel(RelPath::parse("missing").unwrap()))
            .await
            .unwrap()
            .is_none()
    );

    // Now start a MITM server on a different port, rewrite known_hosts port token to simulate
    // same host:port key replacement with BOTH another Ed25519 key AND a different algorithm (ECDSA).
    let mitm_ed = ed25519_host_key(2);
    let port_mitm_ed =
        start_virtual_sftp_server(Arc::clone(&fs), vec![mitm_ed], VirtualSftpOpts::default()).await;
    let kh_content = fs::read_to_string(&kh_path).unwrap();
    let rewritten = kh_content.replace(&format!(":{port1}"), &format!(":{port_mitm_ed}"));
    fs::write(&kh_path, &rewritten).unwrap();

    let mut cfg_mitm_ed = SftpConfig::new(
        "mitm-ed",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_mitm_ed.port = port_mitm_ed;
    cfg_mitm_ed.host_key_policy = HostKeyPolicy::AcceptNew;
    cfg_mitm_ed.known_hosts_path = Some(kh_path.clone());
    let err_ed = SftpBackend::new(cfg_mitm_ed)
        .unwrap()
        .stat(&BackendPath::from_rel(RelPath::parse("x").unwrap()))
        .await
        .unwrap_err();
    assert!(err_ed.is_permanent(), "MITM must be permanent: {err_ed:?}");
    assert!(
        !err_ed.is_retryable(),
        "MITM must NEVER be retryable: {err_ed:?}"
    );

    // Cross-algorithm MITM: server presents ECDSA P-256 while known_hosts has Ed25519.
    let mut rng = rand::rngs::StdRng::seed_from_u64(101);
    let mitm_ecdsa = PrivateKey::random(
        &mut rng,
        Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let port_mitm_ecdsa = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![mitm_ecdsa],
        VirtualSftpOpts::default(),
    )
    .await;
    let rewritten2 = kh_content.replace(&format!(":{port1}"), &format!(":{port_mitm_ecdsa}"));
    fs::write(&kh_path, &rewritten2).unwrap();

    let mut cfg_mitm_ecdsa = SftpConfig::new(
        "mitm-ecdsa",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_mitm_ecdsa.port = port_mitm_ecdsa;
    cfg_mitm_ecdsa.host_key_policy = HostKeyPolicy::AcceptNew;
    cfg_mitm_ecdsa.known_hosts_path = Some(kh_path.clone());
    let err_ecdsa = SftpBackend::new(cfg_mitm_ecdsa)
        .unwrap()
        .stat(&BackendPath::from_rel(RelPath::parse("x").unwrap()))
        .await
        .unwrap_err();
    assert!(
        err_ecdsa.is_permanent() && !err_ecdsa.is_retryable(),
        "cross-algo MITM must be permanent and non-retryable: {err_ecdsa:?}"
    );

    // Fail-closed on malformed known_hosts even under AcceptNew.
    fs::write(&kh_path, "@badmarker 127.0.0.1 ssh-ed25519 AAAA\n").unwrap();
    let mut cfg_bad_kh = SftpConfig::new(
        "bad-kh",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_bad_kh.port = port1;
    cfg_bad_kh.host_key_policy = HostKeyPolicy::AcceptNew;
    cfg_bad_kh.known_hosts_path = Some(kh_path);
    let err_kh = SftpBackend::new(cfg_bad_kh)
        .unwrap()
        .stat(&BackendPath::from_rel(RelPath::parse("x").unwrap()))
        .await
        .unwrap_err();
    assert!(err_kh.is_config() && err_kh.is_permanent() && !err_kh.is_retryable());
}

#[tokio::test]
async fn sftp_root_slash_preserves_leading_slash_and_distinct_endpoint_identity() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.seed_dir("/etc");
        g.seed_file("/etc/hosts", b"127.0.0.1 localhost\n", 1_700_000_000);
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(3)],
        VirtualSftpOpts::default(),
    )
    .await;

    let make = |root: &str| {
        let mut cfg = SftpConfig::new(
            "root-slash",
            "127.0.0.1",
            "tester",
            SftpAuth::Password("sftp-pass".into()),
        );
        cfg.port = port;
        cfg.host_key_policy = HostKeyPolicy::Insecure;
        cfg.root_path = root.to_string();
        SftpBackend::new(cfg).unwrap()
    };

    let b_slash = make("/");
    let b_home = make("");
    let b_data_abs = make("/data");
    let b_data_rel = make("data");
    let ids: HashSet<_> = [&b_slash, &b_home, &b_data_abs, &b_data_rel]
        .into_iter()
        .map(|b| b.endpoint_identity())
        .collect();
    assert_eq!(ids.len(), 4);

    let mut stream = b_slash.list_stream(&RelPath::root(), true).await.unwrap();
    let mut names = Vec::new();
    while let Some(item) = stream.next().await {
        names.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert!(names.contains(&"etc".to_string()));
    assert!(names.contains(&"etc/hosts".to_string()));

    let recorded = fs.lock().unwrap().requested_paths.clone();
    assert!(
        recorded.contains(&"/".to_string()),
        "expected `/` opendir request, got: {recorded:?}"
    );
    assert!(
        recorded.contains(&"/etc".to_string()),
        "expected `/etc` opendir request, got: {recorded:?}"
    );
    assert!(!recorded.contains(&".".to_string()));
}

#[tokio::test]
async fn sftp_list_preserves_nfd_subtrees_unix_backslash_and_max_depth_zero() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let nfd_dir = "cafe\u{0301}";
    let nfd_file = "cafe\u{0301}/re\u{0301}sume\u{0301}.txt";
    let bs_file = "dir\\sub/file\\name.txt";
    {
        let mut g = fs.lock().unwrap();
        g.seed_dir(&format!("/{nfd_dir}"));
        g.seed_file(&format!("/{nfd_file}"), b"nfd-payload", 1_700_000_000);
        g.seed_dir("/dir\\sub");
        g.seed_file(&format!("/{bs_file}"), b"backslash-payload", 1_700_000_000);
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(4)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "nfd-bs",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    // `with_max_depth(0)` must yield 0 entries!
    let mut s0 = backend
        .list_with_options(
            &RelPath::root(),
            &rship_core::backend::ListOptions::new().with_max_depth(0),
        )
        .await
        .unwrap();
    assert!(
        s0.next().await.is_none(),
        "max_depth(0) must return empty stream"
    );

    // `with_max_depth(1)` yields top-level dir\sub (depth 1, NOT split by `\` into depth 2)
    let mut s1 = backend
        .list_with_options(
            &RelPath::root(),
            &rship_core::backend::ListOptions::new().with_max_depth(1),
        )
        .await
        .unwrap();
    let mut depth1_entries = Vec::new();
    while let Some(e) = s1.next().await {
        depth1_entries.push(e.unwrap());
    }
    assert_eq!(
        depth1_entries.len(),
        2,
        "expected 2 top-level dirs: {depth1_entries:?}"
    );

    // Recursive listing preserves NFD subtree and `\` in raw_path while escaping `\` in RelPath.
    let mut s_all = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut all = Vec::new();
    while let Some(e) = s_all.next().await {
        all.push(e.unwrap());
    }
    let nfd_entry = all
        .iter()
        .find(|e| e.raw_path.as_deref() == Some(nfd_file))
        .expect("NFD file inside NFD dir must be listed with raw NFD path");
    let bs_entry = all
        .iter()
        .find(|e| e.raw_path.as_deref() == Some(bs_file))
        .expect("backslash file must be listed with literal `\\` raw_path");
    assert_eq!(
        bs_entry.nfc_path.as_str(),
        "dir\u{FF3C}sub/file\u{FF3C}name.txt"
    );

    // Round-trip read both via entry's BackendPath.
    for (entry, expected) in [
        (nfd_entry, b"nfd-payload".as_slice()),
        (bs_entry, b"backslash-payload".as_slice()),
    ] {
        let bp = BackendPath::new(
            entry.raw_path.as_deref().unwrap_or(entry.nfc_path.as_str()),
            entry.nfc_path.clone(),
            None,
        );
        let st = backend.stat(&bp).await.unwrap().unwrap();
        assert_eq!(st.size, expected.len() as u64);
        let data_bytes = match backend.open_read(&bp, None).await.unwrap() {
            rship_core::source::DataSource::RemoteRangeReadable(rr) => {
                let mut rs = rr
                    .open_range(rship_core::types::ByteRange {
                        offset: 0,
                        len: expected.len() as u64,
                    })
                    .await
                    .unwrap();
                let mut out = Vec::new();
                while let Some(c) = rs.next().await {
                    out.extend_from_slice(&c.unwrap());
                }
                out
            }
            _ => panic!("expected RemoteRangeReadable"),
        };
        assert_eq!(data_bytes, expected);
    }
}

#[tokio::test]
async fn sftp_skips_and_refuses_posix_special_nodes_without_opening() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.seed_special("/pipe", 0o010644); // FIFO
        g.seed_special("/sock", 0o140755); // Socket
        g.seed_special("/tty", 0o020644); // Char device
        g.seed_special("/sda", 0o060644); // Block device
        g.seed_file("/regular.txt", b"ok", 1_700_000_000);
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(5)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "special",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    // `list_stream` yields ONLY regular.txt
    let mut s = backend.list_stream(&RelPath::root(), true).await.unwrap();
    let mut listed = Vec::new();
    while let Some(item) = s.next().await {
        listed.push(item.unwrap().nfc_path.as_str().to_string());
    }
    assert_eq!(listed, vec!["regular.txt"]);

    // `stat` on FIFO returns None; `open_read` returns NotFound
    let pipe_bp = BackendPath::from_rel(RelPath::parse("pipe").unwrap());
    assert!(backend.stat(&pipe_bp).await.unwrap().is_none());
    let err = backend
        .open_read(&pipe_bp, None)
        .await
        .err()
        .expect("expected NotFound");
    assert!(err.is_not_found());

    // Even with a forged `EntryKind::File`, `open_range` checks `lstat` before `SSH_FXP_OPEN`!
    let forged = rship_core::types::Entry {
        node_id: None,
        parent_id: None,
        raw_path: None,
        nfc_path: RelPath::parse("pipe").unwrap(),
        kind: rship_core::types::EntryKind::File,
        size: 10,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    };
    let ds = backend
        .open_read_entry(&forged, &pipe_bp, None)
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let open_err = rr
        .open_range(rship_core::types::ByteRange { offset: 0, len: 10 })
        .await
        .err()
        .expect("expected InvalidPath");
    assert_eq!(open_err.kind(), rship_core::ErrorKind::InvalidPath);
    assert!(
        !fs.lock()
            .unwrap()
            .opened_paths
            .contains(&"/pipe".to_string()),
        "SSH_FXP_OPEN must NEVER be called on a POSIX FIFO"
    );
}

#[tokio::test]
async fn sftp_write_packets_respect_32_kib_limit_and_enforces_dst_precondition() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.seed_file("/existing.bin", b"old-data", 1_700_000_123);
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(6)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "precond",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    cfg.single_shot_max_bytes = 512 * 1024;
    let backend = SftpBackend::new(cfg).unwrap();

    // 1. Upload 128 KiB single-shot and assert server saw write packets <= 32 KiB.
    let big = vec![0xABu8; 128 * 1024];
    let init_big = UploadInit {
        op_id: "op-32k".into(),
        dst_path: RelPath::parse("big.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: big.len() as u64,
        src_mtime_ns: 1_700_000_500_000_000_000,
        planned_chunk_size: 128 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    backend
        .put_single_shot(
            &init_big,
            Box::pin(futures::stream::once(async move { Ok(Bytes::from(big)) })),
        )
        .await
        .unwrap();
    let max_write = fs.lock().unwrap().max_write_len_seen;
    assert!(
        max_write > 0 && max_write <= 32_768,
        "max_write={max_write}"
    );

    // 2. DstPrecondition::Absent when target exists -> PreconditionFailed & no .rship.part.* left.
    let init_absent = UploadInit {
        op_id: "op-absent".into(),
        dst_path: RelPath::parse("existing.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 3,
        src_mtime_ns: 1_700_000_500_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Absent,
        src_etag: None,
    };
    let err_abs = backend
        .put_single_shot(
            &init_absent,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"new"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(err_abs.kind(), rship_core::ErrorKind::PreconditionFailed);
    let err_begin = backend.begin_upload(&init_absent).await.unwrap_err();
    assert_eq!(err_begin.kind(), rship_core::ErrorKind::PreconditionFailed);

    // 3. DstPrecondition::Existing wrong mtime -> PreconditionFailed & cleans up .rship.part.* on finish_upload.
    let init_ok = UploadInit {
        op_id: "op-existing-race".into(),
        dst_path: RelPath::parse("existing.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 3,
        src_mtime_ns: 1_700_000_999_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Existing {
            node_id: None,
            etag: None,
            mtime_ns: 1_700_000_123_000_000_000,
            size: 8,
        },
        src_etag: None,
    };
    let sess = backend.begin_upload(&init_ok).await.unwrap();
    let op = OperationRecord {
        op_id: init_ok.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "existing.bin".into(),
        dst_raw_path: "existing.bin".into(),
        dst_nfc_path: init_ok.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: 3,
            mtime_ns: init_ok.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Existing {
            node_id: None,
            etag: None,
            mtime_ns: 1_700_000_000_000_000_000, // stale precondition!
            size: 8,
        },
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "sftp".into(),
        session_token: Some(sess.session_token.clone()),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                3,
                3,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"xyz"))
                })),
            ),
        )
        .await
        .unwrap();
    let finish_err = backend.finish_upload(&op, &[]).await.unwrap_err();
    assert_eq!(finish_err.kind(), rship_core::ErrorKind::PreconditionFailed);
    assert!(
        !fs.lock()
            .unwrap()
            .nodes
            .keys()
            .any(|k| k.contains(".rship.part.")),
        "staging file must be cleaned up on precondition failure"
    );
}

#[tokio::test]
async fn sftp_query_upload_ignores_sparse_remote_len_and_begin_truncates() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        // Simulate a 1 MiB sparse staging file left by out-of-order pipelined writes
        // before durable checkpoint advanced past offset 0.
        g.seed_file(
            "/.rship.part.op-sparse.target.bin",
            &vec![0u8; 1024 * 1024],
            1_700_000_000,
        );
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(7)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "sparse",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    let op = OperationRecord {
        op_id: "op-sparse".into(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "target.bin".into(),
        dst_raw_path: "target.bin".into(),
        dst_nfc_path: RelPath::parse("target.bin").unwrap(),
        src_version: SourceVersion {
            node_id: None,
            size: 2 * 1024 * 1024,
            mtime_ns: 1_700_000_000_000_000_000,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: Some("op-sparse".into()),
        backend_kind: "sftp".into(),
        session_token: Some("/.rship.part.op-sparse.target.bin".into()),
        backend_meta: "/target.bin".into(),
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    assert_eq!(
        backend.query_upload(&op).await.unwrap(),
        UploadProgress::SequentialOffset(0)
    );

    // begin_upload must truncate any stale staging file to 0 bytes.
    let init = UploadInit {
        op_id: "op-sparse".into(),
        dst_path: RelPath::parse("target.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 10,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    backend.begin_upload(&init).await.unwrap();
    let VirtualNode::File { data, .. } = fs
        .lock()
        .unwrap()
        .nodes
        .get("/.rship.part.op-sparse.target.bin")
        .unwrap()
        .clone()
    else {
        panic!("expected file");
    };
    assert_eq!(data.len(), 0);
}

#[tokio::test]
async fn sftp_propagates_setstat_errors_and_guards_backup_dir_overwrite() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.fail_setstat = true;
        g.posix_rename_unsupported = true;
        g.rename_rejects_existing = true;
    }
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(8)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "setstat-backup",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    // 1. `setstat` failure must propagate (not succeed silently).
    let init = UploadInit {
        op_id: "op-setstat".into(),
        dst_path: RelPath::parse("f.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_123_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let err = backend
        .put_single_shot(
            &init,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"hello"))
            })),
        )
        .await
        .unwrap_err();
    assert!(!err.is_retryable());
    assert!(!fs.lock().unwrap().nodes.contains_key("/f.txt"));

    // 2. Re-enable setstat; test backup fallback over existing regular file (succeeds, 0 orphans)
    // and over existing directory (returns Conflict, dir intact, 0 orphans).
    {
        let mut g = fs.lock().unwrap();
        g.fail_setstat = false;
        g.seed_file("/overwrite.txt", b"old", 1_700_000_000);
        g.seed_dir("/existing_dir");
    }
    let init_ov = UploadInit {
        op_id: "op-ov".into(),
        dst_path: RelPath::parse("overwrite.txt").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 3,
        src_mtime_ns: 1_700_000_200_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    backend
        .put_single_shot(
            &init_ov,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"new"))
            })),
        )
        .await
        .unwrap();
    {
        let g = fs.lock().unwrap();
        let VirtualNode::File { data, .. } = g.nodes.get("/overwrite.txt").unwrap() else {
            panic!("expected file");
        };
        assert_eq!(data, b"new");
        assert!(!g.nodes.keys().any(|k| k.contains(".rship.bak.")));
    }

    let init_dir = UploadInit {
        op_id: "op-dir".into(),
        dst_path: RelPath::parse("existing_dir").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 3,
        src_mtime_ns: 1_700_000_200_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let dir_err = backend
        .put_single_shot(
            &init_dir,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from_static(b"bad"))
            })),
        )
        .await
        .unwrap_err();
    assert_eq!(dir_err.kind(), rship_core::ErrorKind::Conflict);
    let g = fs.lock().unwrap();
    assert!(matches!(
        g.nodes.get("/existing_dir"),
        Some(VirtualNode::Dir { .. })
    ));
    assert!(
        !g.nodes
            .keys()
            .any(|k| k.contains(".rship.bak.") || k.contains(".rship.part."))
    );
}

#[tokio::test]
async fn sftp_mid_transfer_disconnect_is_retryable_and_finish_retries_stale() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.seed_file("/read_target.bin", &vec![0x5Au8; 512 * 1024], 1_700_000_000);
        g.drop_after_reads = Some(1);
    }
    let opts = VirtualSftpOpts {
        close_session_after_first_cmd_on_conn: Arc::new(AtomicBool::new(true)),
        ..Default::default()
    };
    let port = start_virtual_sftp_server(Arc::clone(&fs), vec![ed25519_host_key(9)], opts).await;

    let mut cfg = SftpConfig::new(
        "disconnect",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    // 1. Mid-transfer read disconnect must be Retryable.
    let ds = backend
        .open_read(
            &BackendPath::from_rel(RelPath::parse("read_target.bin").unwrap()),
            None,
        )
        .await
        .unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut rs = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: 512 * 1024,
        })
        .await
        .unwrap();
    let read_err = rs.next().await.unwrap().unwrap_err();
    assert!(
        read_err.is_retryable(),
        "mid-read SSH disconnect must be retryable, got: {read_err:?}"
    );
    drop(rs);

    // 2. Mid-transfer write disconnect must be Retryable.
    {
        let mut g = fs.lock().unwrap();
        g.drop_after_reads = None;
        g.drop_after_writes = Some(1);
    }
    let init_w = UploadInit {
        op_id: "op-w-drop".into(),
        dst_path: RelPath::parse("wdrop.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 4096,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let write_err = backend
        .put_single_shot(
            &init_w,
            Box::pin(futures::stream::once(async {
                Ok(Bytes::from(vec![0x11u8; 4096]))
            })),
        )
        .await
        .unwrap_err();
    assert!(
        write_err.is_retryable(),
        "mid-write SSH disconnect must be retryable, got: {write_err:?}"
    );

    // 3. `finish_upload` stale connection retry (Phase 2 stat after publish drops idle/reused conn).
    {
        let mut g = fs.lock().unwrap();
        g.drop_after_writes = None;
    }
    let init_f = UploadInit {
        op_id: "op-fin-retry".into(),
        dst_path: RelPath::parse("fin.bin").unwrap(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 5,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init_f).await.unwrap();
    let op = OperationRecord {
        op_id: init_f.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "fin.bin".into(),
        dst_raw_path: "fin.bin".into(),
        dst_nfc_path: init_f.dst_path.clone(),
        src_version: SourceVersion {
            node_id: None,
            size: 5,
            mtime_ns: init_f.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "sftp".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };
    backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                5,
                5,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"12345"))
                })),
            ),
        )
        .await
        .unwrap();
    // Arm drop on Phase 2 lstat("/fin.bin") — finish_upload must retry Phase 2 without
    // re-running Phase 1 publish (where `.rship.part.*` is already gone!).
    fs.lock()
        .unwrap()
        .drop_next_lstat_paths
        .insert("/fin.bin".into());
    let committed = backend.finish_upload(&op, &[]).await.unwrap();
    assert_eq!(committed.size, 5);
}

#[tokio::test]
async fn sftp_keyboard_interactive_key_pem_and_connect_timeout() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    fs.lock()
        .unwrap()
        .seed_file("/hello.txt", b"hi", 1_700_000_000);

    // 1. keyboard-interactive fallback when password is rejected.
    let kb_port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(10)],
        VirtualSftpOpts {
            require_kb_interactive: true,
            ..Default::default()
        },
    )
    .await;
    let mut cfg_kb = SftpConfig::new(
        "kb",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_kb.port = kb_port;
    cfg_kb.host_key_policy = HostKeyPolicy::Insecure;
    cfg_kb.root_path = "/".into();
    let b_kb = SftpBackend::new(cfg_kb).unwrap();
    assert_eq!(
        b_kb.stat(&BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()))
            .await
            .unwrap()
            .unwrap()
            .size,
        2
    );

    // 2. SftpAuth::KeyPem (passphrase-encrypted OpenSSH PEM)
    let client_priv = PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&[55u8; 32])),
        "client",
    )
    .unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(202);
    let enc_priv = client_priv.encrypt(&mut rng, "pem-secret").unwrap();
    let pem_str = enc_priv
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .unwrap()
        .to_string();

    let pem_port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(11)],
        VirtualSftpOpts {
            accepted_pubkeys: vec![client_priv.public_key().clone()],
            ..Default::default()
        },
    )
    .await;
    let mut cfg_pem = SftpConfig::new(
        "pem",
        "127.0.0.1",
        "tester",
        SftpAuth::KeyPem {
            pem: pem_str,
            passphrase: Some("pem-secret".into()),
        },
    );
    cfg_pem.port = pem_port;
    cfg_pem.host_key_policy = HostKeyPolicy::Insecure;
    cfg_pem.root_path = "/".into();
    let b_pem = SftpBackend::new(cfg_pem).unwrap();
    assert_eq!(
        b_pem
            .stat(&BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()))
            .await
            .unwrap()
            .unwrap()
            .size,
        2
    );

    // Also verify lazy KeyPem decoding: stub PEM must pass SftpBackend::new!
    let stub_cfg = SftpConfig::new(
        "stub-pem",
        "127.0.0.1",
        "tester",
        SftpAuth::KeyPem {
            pem: "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            passphrase: None,
        },
    );
    assert!(SftpBackend::new(stub_cfg).is_ok());

    // 3. `connect_timeout` must cover stalled auth / SFTP subsystem open (not just TCP connect).
    let slow_port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(12)],
        VirtualSftpOpts {
            subsystem_delay: Duration::from_millis(400),
            ..Default::default()
        },
    )
    .await;
    let mut cfg_slow = SftpConfig::new(
        "slow",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_slow.port = slow_port;
    cfg_slow.host_key_policy = HostKeyPolicy::Insecure;
    cfg_slow.connect_timeout = Duration::from_millis(120);
    let err_slow = SftpBackend::new(cfg_slow)
        .unwrap()
        .stat(&BackendPath::from_rel(RelPath::parse("hello.txt").unwrap()))
        .await
        .unwrap_err();
    assert_eq!(err_slow.kind(), rship_core::ErrorKind::Timeout);
}

#[tokio::test]
async fn sftp_pool_multiplexing_avoids_deadlock_with_held_read_streams() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    {
        let mut g = fs.lock().unwrap();
        g.seed_file("/r.bin", &vec![0x77u8; 64 * 1024], 1_700_000_000);
    }
    let opts = VirtualSftpOpts::default();
    let max_ssh_seen = Arc::clone(&opts.max_concurrent_ssh_seen);
    let port = start_virtual_sftp_server(Arc::clone(&fs), vec![ed25519_host_key(13)], opts).await;

    let mut cfg = SftpConfig::new(
        "mux",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = Arc::new(SftpBackend::new(cfg).unwrap());

    // Hold 8 concurrent `open_range` read streams open simultaneously on the same backend,
    // then run `stat`, `list_stream`, and `put_single_shot` concurrently — must NOT deadlock!
    let bp = BackendPath::from_rel(RelPath::parse("r.bin").unwrap());
    let mut held_streams = Vec::new();
    for _ in 0..8 {
        let ds = backend.open_read(&bp, None).await.unwrap();
        let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
            panic!("expected RemoteRangeReadable");
        };
        let st = rr
            .open_range(rship_core::types::ByteRange {
                offset: 0,
                len: 64 * 1024,
            })
            .await
            .unwrap();
        held_streams.push(st);
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        assert!(backend.stat(&bp).await.unwrap().is_some());
        let mut ls = backend.list_stream(&RelPath::root(), false).await.unwrap();
        assert!(ls.next().await.is_some());
        let init = UploadInit {
            op_id: "op-mux-w".into(),
            dst_path: RelPath::parse("w.bin").unwrap(),
            existing_node_id: None,
            pregenerated_id: None,
            total_size: 4,
            src_mtime_ns: 1_700_000_000_000_000_000,
            planned_chunk_size: 64 * 1024,
            checksums: vec![],
            precondition: DstPrecondition::Any,
            src_etag: None,
        };
        backend
            .put_single_shot(
                &init,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from_static(b"test"))
                })),
            )
            .await
            .unwrap();
    })
    .await
    .expect("concurrent ops with 8 held read streams must not deadlock");

    // 8+ concurrent channels multiplexed over <= 4 SSH connections (significantly fewer than 1:1).
    assert!(
        max_ssh_seen.load(Ordering::SeqCst) <= 4,
        "expected multiplexed SSH connections <= 4, saw {}",
        max_ssh_seen.load(Ordering::SeqCst)
    );
    drop(held_streams);
}

#[tokio::test]
async fn sftp_upload_chunk_missing_part_fails_with_session_expired_without_zero_fill() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(14)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "chunk-missing-part",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    let dst_rel = RelPath::parse("sparse_corrupt.bin").unwrap();
    let init = UploadInit {
        op_id: "op-del-part".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 128 * 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "sparse_corrupt.bin".into(),
        dst_raw_path: "sparse_corrupt.bin".into(),
        dst_nfc_path: dst_rel,
        src_version: SourceVersion {
            node_id: None,
            size: 128 * 1024,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "sftp".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Chunk 1 succeeds at offset 0.
    let ack1 = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                128 * 1024,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0xAAu8; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ack1.next_offset, Some(64 * 1024));

    // External actor deletes `.rship.part.*`.
    fs.lock()
        .unwrap()
        .nodes
        .retain(|k, _| !k.contains(".rship.part."));

    // Chunk 2 at offset 65536 MUST fail with SessionExpired (never recreate a sparse zero-filled file).
    let err = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                2,
                64 * 1024,
                64 * 1024,
                128 * 1024,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0xBBu8; 64 * 1024]))
                })),
            ),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.kind(),
        rship_core::ErrorKind::SessionExpired,
        "missing staging file on upload_chunk must return SessionExpired, got: {err:?}"
    );
    let g = fs.lock().unwrap();
    assert!(
        !g.nodes.keys().any(|k| k.contains(".rship.part.")),
        "upload_chunk must never recreate missing .rship.part.* staging file"
    );
    assert!(!g.nodes.contains_key("/sparse_corrupt.bin"));
}

#[tokio::test]
async fn sftp_cert_authority_negotiates_over_wire_and_rejects_invalid_certs() {
    let tmp = TempDir::new().unwrap();
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    fs.lock()
        .unwrap()
        .seed_file("/cert_ok.txt", b"verified", 1_700_000_000);

    let ca_priv = ed25519_host_key(31);
    let untrusted_ca_priv = ed25519_host_key(32);
    let host_priv = ed25519_host_key(33);
    let now = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = rand::rngs::StdRng::seed_from_u64(303);

    let sign_host_cert = |rng: &mut rand::rngs::StdRng,
                          valid_after: u64,
                          valid_before: u64,
                          principal: &str,
                          signer: &PrivateKey| {
        let mut b = CertBuilder::new_with_random_nonce(
            rng,
            host_priv.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();
        b.cert_type(CertType::Host).unwrap();
        b.valid_principal(principal).unwrap();
        b.sign(signer).unwrap()
    };

    let valid_cert = sign_host_cert(&mut rng, now - 60, now + 3600, "127.0.0.1", &ca_priv);
    let expired_cert = sign_host_cert(&mut rng, now - 3600, now - 60, "127.0.0.1", &ca_priv);
    let wrong_principal_cert =
        sign_host_cert(&mut rng, now - 60, now + 3600, "wrong.host.test", &ca_priv);
    let forged_cert = sign_host_cert(
        &mut rng,
        now - 60,
        now + 3600,
        "127.0.0.1",
        &untrusted_ca_priv,
    );

    let ca_pub_openssh = PublicKey::new(ca_priv.public_key().key_data().clone(), "")
        .to_openssh()
        .unwrap();

    // 1. Valid host cert over real russh wire with @cert-authority in known_hosts (Strict & AcceptNew).
    let port_valid = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![host_priv.clone()],
        VirtualSftpOpts {
            certificates: vec![valid_cert],
            ..Default::default()
        },
    )
    .await;
    let kh_valid = tmp.path().join("kh_cert_valid");
    std::fs::write(
        &kh_valid,
        format!("@cert-authority [127.0.0.1]:{port_valid} {ca_pub_openssh}\n"),
    )
    .unwrap();

    for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
        let mut cfg = SftpConfig::new(
            "cert-valid",
            "127.0.0.1",
            "tester",
            SftpAuth::Password("sftp-pass".into()),
        );
        cfg.port = port_valid;
        cfg.host_key_policy = policy;
        cfg.known_hosts_path = Some(kh_valid.clone());
        cfg.root_path = "/".into();
        let entry = SftpBackend::new(cfg)
            .unwrap()
            .stat(&BackendPath::from_rel(
                RelPath::parse("cert_ok.txt").unwrap(),
            ))
            .await
            .unwrap()
            .expect("cert_ok.txt should exist");
        assert_eq!(entry.size, 8);
    }

    // 2. Expired, wrong-principal, and forged-CA certs MUST fail with permanent ErrorKind::Protocol.
    for (label, bad_cert) in [
        ("expired", expired_cert),
        ("wrong-principal", wrong_principal_cert),
        ("forged-ca", forged_cert),
    ] {
        let port_bad = start_virtual_sftp_server(
            Arc::clone(&fs),
            vec![host_priv.clone()],
            VirtualSftpOpts {
                certificates: vec![bad_cert],
                ..Default::default()
            },
        )
        .await;
        let kh_bad = tmp.path().join(format!("kh_{label}"));
        std::fs::write(
            &kh_bad,
            format!("@cert-authority [127.0.0.1]:{port_bad} {ca_pub_openssh}\n"),
        )
        .unwrap();

        let mut cfg = SftpConfig::new(
            label,
            "127.0.0.1",
            "tester",
            SftpAuth::Password("sftp-pass".into()),
        );
        cfg.port = port_bad;
        cfg.host_key_policy = HostKeyPolicy::Strict;
        cfg.known_hosts_path = Some(kh_bad);
        cfg.root_path = "/".into();
        let err = SftpBackend::new(cfg)
            .unwrap()
            .stat(&BackendPath::from_rel(
                RelPath::parse("cert_ok.txt").unwrap(),
            ))
            .await
            .unwrap_err();
        assert_eq!(
            err.kind(),
            rship_core::ErrorKind::Protocol,
            "{label} cert must fail with Protocol, got: {err:?}"
        );
        assert!(
            err.is_permanent() && !err.is_retryable(),
            "{label} cert must be permanent & non-retryable: {err:?}"
        );
    }

    // 3. Bare-key server (no certificates) still negotiates cleanly under AcceptNew & Strict.
    let port_bare =
        start_virtual_sftp_server(Arc::clone(&fs), vec![host_priv], VirtualSftpOpts::default())
            .await;
    let kh_bare = tmp.path().join("kh_bare");
    let mut cfg_bare_accept = SftpConfig::new(
        "bare-accept",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_bare_accept.port = port_bare;
    cfg_bare_accept.host_key_policy = HostKeyPolicy::AcceptNew;
    cfg_bare_accept.known_hosts_path = Some(kh_bare.clone());
    cfg_bare_accept.root_path = "/".into();
    assert!(
        SftpBackend::new(cfg_bare_accept)
            .unwrap()
            .stat(&BackendPath::from_rel(
                RelPath::parse("cert_ok.txt").unwrap()
            ))
            .await
            .unwrap()
            .is_some()
    );
    let mut cfg_bare_strict = SftpConfig::new(
        "bare-strict",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_bare_strict.port = port_bare;
    cfg_bare_strict.host_key_policy = HostKeyPolicy::Strict;
    cfg_bare_strict.known_hosts_path = Some(kh_bare);
    cfg_bare_strict.root_path = "/".into();
    assert!(
        SftpBackend::new(cfg_bare_strict)
            .unwrap()
            .stat(&BackendPath::from_rel(
                RelPath::parse("cert_ok.txt").unwrap()
            ))
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn sftp_multiplexed_subsystem_disconnect_falls_back_to_fresh_ssh_conn() {
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    fs.lock()
        .unwrap()
        .seed_file("/mux_drop.bin", &vec![0x42u8; 32 * 1024], 1_700_000_000);

    let opts = VirtualSftpOpts {
        disconnect_conn1_on_second_subsystem: true,
        ..Default::default()
    };
    let ssh_accepted = Arc::clone(&opts.ssh_connections_accepted);
    let port = start_virtual_sftp_server(Arc::clone(&fs), vec![ed25519_host_key(15)], opts).await;

    let mut cfg = SftpConfig::new(
        "mux-sub-drop",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    // Hold channel 1 open on SharedSshHandle #1 via open_read -> open_range.
    let bp = BackendPath::from_rel(RelPath::parse("mux_drop.bin").unwrap());
    let ds = backend.open_read(&bp, None).await.unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let held_stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: 32 * 1024,
        })
        .await
        .unwrap();
    assert_eq!(ssh_accepted.load(Ordering::SeqCst), 1);

    // Concurrent `stat` reserves channel 2 on SharedSshHandle #1; server disconnects on
    // 2nd `subsystem_request("sftp")`. Pool must mark handle #1 unusable, fall back to
    // `connect_fresh`, open SSH connection #2, and succeed!
    let st = backend
        .stat(&bp)
        .await
        .expect("stat must transparently fall back to fresh SSH connection")
        .expect("mux_drop.bin should exist");
    assert_eq!(st.size, 32 * 1024);
    assert_eq!(ssh_accepted.load(Ordering::SeqCst), 2);
    drop(held_stream);
}

#[tokio::test]
async fn sftp_subsystem_channel_failure_fails_fast_on_fresh_conn_and_falls_back_on_mux() {
    // C5: Fresh-conn `subsystem_request("sftp")` returning `channel_failure` must fail fast
    // (well under `connect_timeout = 10s`) with permanent `ErrorKind::Protocol`.
    let fs_deny = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let opts_deny = VirtualSftpOpts {
        deny_all_sftp_subsystems: true,
        ..Default::default()
    };
    let port_deny =
        start_virtual_sftp_server(Arc::clone(&fs_deny), vec![ed25519_host_key(16)], opts_deny)
            .await;

    let mut cfg_deny = SftpConfig::new(
        "fresh-sub-deny",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_deny.port = port_deny;
    cfg_deny.host_key_policy = HostKeyPolicy::Insecure;
    cfg_deny.root_path = "/".into();
    cfg_deny.connect_timeout = Duration::from_secs(10);
    let backend_deny = SftpBackend::new(cfg_deny).unwrap();

    let bp = BackendPath::from_rel(RelPath::parse("any.txt").unwrap());
    let started = std::time::Instant::now();
    let err = backend_deny
        .stat(&bp)
        .await
        .expect_err("subsystem channel_failure on fresh conn must fail");
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "subsystem channel_failure must fail fast (< 2s with 10s connect_timeout), took {elapsed:?}"
    );
    assert_eq!(
        err.kind(),
        rship_core::ErrorKind::Protocol,
        "subsystem denial must map to Protocol, got: {err:?}"
    );
    assert!(
        !err.is_retryable() && err.is_permanent(),
        "subsystem denial must be permanent & non-retryable, got: {err:?}"
    );

    // C6: Mux channel-2 `subsystem_request("sftp")` returning `channel_failure` while channel 1
    // (`open_read`) stays open on SSH conn 1 must transparently fall back to SSH conn 2 and succeed.
    let fs_mux = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let payload = vec![0x5Au8; 32 * 1024];
    fs_mux
        .lock()
        .unwrap()
        .seed_file("/mux_deny.bin", &payload, 1_700_000_000);

    let opts_mux = VirtualSftpOpts {
        deny_conn1_second_subsystem: true,
        ..Default::default()
    };
    let ssh_accepted = Arc::clone(&opts_mux.ssh_connections_accepted);
    let port_mux =
        start_virtual_sftp_server(Arc::clone(&fs_mux), vec![ed25519_host_key(17)], opts_mux).await;

    let mut cfg_mux = SftpConfig::new(
        "mux-sub-deny",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg_mux.port = port_mux;
    cfg_mux.host_key_policy = HostKeyPolicy::Insecure;
    cfg_mux.root_path = "/".into();
    cfg_mux.connect_timeout = Duration::from_secs(10);
    let backend_mux = SftpBackend::new(cfg_mux).unwrap();

    let mux_bp = BackendPath::from_rel(RelPath::parse("mux_deny.bin").unwrap());
    let ds = backend_mux.open_read(&mux_bp, None).await.unwrap();
    let rship_core::source::DataSource::RemoteRangeReadable(rr) = ds else {
        panic!("expected RemoteRangeReadable");
    };
    let mut held_stream = rr
        .open_range(rship_core::types::ByteRange {
            offset: 0,
            len: payload.len() as u64,
        })
        .await
        .unwrap();
    assert_eq!(ssh_accepted.load(Ordering::SeqCst), 1);

    let mux_started = std::time::Instant::now();
    let st = backend_mux
        .stat(&mux_bp)
        .await
        .expect("mux channel_failure must fall back to SSH conn 2")
        .expect("mux_deny.bin should exist");
    let mux_elapsed = mux_started.elapsed();
    assert!(
        mux_elapsed < Duration::from_secs(2),
        "mux channel_failure fallback must be fast (< 2s with 10s connect_timeout), took {mux_elapsed:?}"
    );
    assert_eq!(st.size, payload.len() as u64);
    assert_eq!(ssh_accepted.load(Ordering::SeqCst), 2);

    // Channel 1 stream on SSH conn 1 must still complete cleanly.
    let mut got = Vec::new();
    while let Some(chunk) = held_stream.next().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, payload);
}

#[tokio::test]
async fn sftp_upload_chunk_mid_write_nosuchfile_returns_session_expired() {
    // A3: Server deletes `.rship.part.*` and returns `StatusCode::NoSuchFile` on `SSH_FXP_WRITE`
    // during `upload_chunk`; `upload_chunk` must return `ErrorKind::SessionExpired` (not `Io`).
    let fs = Arc::new(StdMutex::new(VirtualFsState::new_rooted()));
    let port = start_virtual_sftp_server(
        Arc::clone(&fs),
        vec![ed25519_host_key(18)],
        VirtualSftpOpts::default(),
    )
    .await;

    let mut cfg = SftpConfig::new(
        "mid-write-nosuchfile",
        "127.0.0.1",
        "tester",
        SftpAuth::Password("sftp-pass".into()),
    );
    cfg.port = port;
    cfg.host_key_policy = HostKeyPolicy::Insecure;
    cfg.root_path = "/".into();
    let backend = SftpBackend::new(cfg).unwrap();

    let dst_rel = RelPath::parse("mid_write_gone.bin").unwrap();
    let init = UploadInit {
        op_id: "op-mid-write-del".into(),
        dst_path: dst_rel.clone(),
        existing_node_id: None,
        pregenerated_id: None,
        total_size: 128 * 1024,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 64 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    let sess = backend.begin_upload(&init).await.unwrap();
    let op = OperationRecord {
        op_id: init.op_id.clone(),
        session_key: "sk".into(),
        job_id: "j".into(),
        src_endpoint: "src".into(),
        dst_endpoint: backend.endpoint_identity(),
        src_raw_path: "mid_write_gone.bin".into(),
        dst_raw_path: "mid_write_gone.bin".into(),
        dst_nfc_path: dst_rel,
        src_version: SourceVersion {
            node_id: None,
            size: 128 * 1024,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: None,
        },
        dst_precondition: DstPrecondition::Any,
        existing_dst_node_id: None,
        remote_op_id: sess.remote_op_id,
        backend_kind: "sftp".into(),
        session_token: Some(sess.session_token),
        backend_meta: sess.backend_meta,
        planned_chunk_size: 64 * 1024,
        confirmed_offset: 0,
        state: OperationState::Active,
        created_at: 0,
        updated_at: 0,
        expires_at: None,
    };

    // Delete the staging file on the 2nd SSH_FXP_WRITE packet (mid-chunk) so `open` succeeds
    // and `SSH_FXP_WRITE` returns `StatusCode::NoSuchFile`.
    fs.lock().unwrap().delete_on_write_number = Some(2);

    let err = backend
        .upload_chunk(
            &op,
            ChunkUpload::new(
                1,
                0,
                64 * 1024,
                128 * 1024,
                Box::pin(futures::stream::once(async {
                    Ok(Bytes::from(vec![0xCCu8; 64 * 1024]))
                })),
            ),
        )
        .await
        .expect_err("mid-write NoSuchFile on .rship.part.* must fail");
    assert_eq!(
        err.kind(),
        rship_core::ErrorKind::SessionExpired,
        "mid-write StatusCode::NoSuchFile must map to SessionExpired, got: {err:?}"
    );
}
