//! Quantitative acceptance & Peak RSS memory ceiling verification suite (`PLAN.md` §1.1):
//! 1. Healthy GDrive 10 GiB upload data-plane request count (`<= 81` requests: 1 init + 80 × 128 MiB)
//!    & small-file fast-path (`1` request).
//! 2. Isolated-subprocess GiB-scale (`>= 1 GiB` default, overridable via `RSHIP_MEM_TEST_MIB`)
//!    constant-memory generator -> verifying sink streaming transfer under an `8 MiB` `BufferPool`
//!    (`transfers = 8`, `part_concurrency = 4`), verifying 100% byte-pattern integrity, zero
//!    leaked permits, and true cross-platform Peak RSS (`VmHWM` / `ru_maxrss` / `PeakWorkingSetSize`).
//! 3. Isolated-subprocess 16 concurrent local transfers strict `BufferPool` hard cap & Peak RSS.
//! 4. Isolated-subprocess disk-backed `SqliteSyncIndex` (`PRAGMA mmap_size = 0`, post-load
//!    non-unique indexes, keyset pagination) under 100k rows (and `#[ignore]` 1M-row nightly test)
//!    verifying Peak RSS <= 64 MiB.

#[cfg(any(feature = "mimalloc", target_env = "musl"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(any(feature = "mimalloc", target_env = "musl"), any(unix, windows)))]
mod mimalloc_early {
    use std::ffi::{c_int, c_long};

    // SAFETY: `mimalloc` is linked as `#[global_allocator]` for this integration test binary.
    // Ordinals are verified against mimalloc v3 and guarded by `mi_version() / 10_000 == 3`.
    unsafe extern "C" {
        fn mi_version() -> c_int;
        fn mi_option_set_default(option: c_int, value: c_long);
    }

    extern "C" fn init_mimalloc_early() {
        // SAFETY: Read-only version query, safe before CRT/runtime init.
        let ver = unsafe { mi_version() };
        if ver / 10_000 != 3 {
            return;
        }
        // SAFETY: Single-threaded process startup; `mi_option_set_default` writes only
        // static option defaults without allocating or touching CRT state.
        unsafe {
            mi_option_set_default(4, 0); // arena_eager_commit
            mi_option_set_default(5, 1); // purge_decommits
            mi_option_set_default(15, 10); // purge_delay
            mi_option_set_default(24, 2); // arena_purge_mult
            mi_option_set_default(35, 1); // page_reclaim_on_free
            mi_option_set_default(43, 0); // allow_thp
        }
    }

    #[used]
    #[cfg_attr(
        all(unix, not(target_vendor = "apple")),
        unsafe(link_section = ".init_array.00101")
    )]
    #[cfg_attr(
        target_vendor = "apple",
        unsafe(link_section = "__DATA,__mod_init_func")
    )]
    #[cfg_attr(windows, unsafe(link_section = ".CRT$XCU"))]
    static INIT_MIMALLOC: extern "C" fn() = init_mimalloc_early;
}

use async_trait::async_trait;
use futures::StreamExt;
use rship_backends::local::LocalBackend;
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::buffer::{BufferPool, PooledSlice};
use rship_core::chunking::{UploadPlan, plan_upload};
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource, SeekableSource};
use rship_core::state::{JobMode, OperationRecord, SyncDiffIndex};
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, UploadTopology,
};
use rship_core::{Error, Result};
use rship_state::{SqliteSyncIndex, StateActor};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const SUBPROCESS_ENV: &str = "RSHIP_MEM_SUBPROCESS";
const SUBPROCESS_MARKER: &str = "RSHIP_MEM_SUBPROCESS_OK";
const GEN_MTIME_NS: i64 = 1_700_000_000_000_000_000;

/// Read true process Peak RSS (high-water mark) in bytes across Linux, macOS, and Windows.
///
/// - **Linux**: parses `VmHWM:` (KiB -> `* 1024`) from `/proc/self/status`, falling back to
///   `libc::getrusage(RUSAGE_SELF).ru_maxrss * 1024` (never hardcodes a 4 KiB page size).
/// - **macOS**: `libc::getrusage(RUSAGE_SELF).ru_maxrss` (reported directly in bytes).
/// - **Windows**: `GetProcessMemoryInfo` -> `PROCESS_MEMORY_COUNTERS.PeakWorkingSetSize` (bytes).
fn peak_process_rss_bytes() -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            PageFaultCount: 0,
            PeakWorkingSetSize: 0,
            WorkingSetSize: 0,
            QuotaPeakPagedPoolUsage: 0,
            QuotaPagedPoolUsage: 0,
            QuotaPeakNonPagedPoolUsage: 0,
            QuotaNonPagedPoolUsage: 0,
            PagefileUsage: 0,
            PeakPagefileUsage: 0,
        };
        // SAFETY: Valid pseudo-handle from `GetCurrentProcess()` and properly initialized,
        // sized `PROCESS_MEMORY_COUNTERS` output struct.
        let ok = unsafe {
            GetProcessMemoryInfo(GetCurrentProcess(), &mut counters as *mut _, counters.cb)
        };
        if ok != 0 {
            Some(counters.PeakWorkingSetSize as u64)
        } else {
            None
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:")
                    && let Some(kib_str) = rest.split_whitespace().next()
                    && let Ok(kib) = kib_str.parse::<u64>()
                {
                    return Some(kib.saturating_mul(1024));
                }
            }
        }
        // SAFETY: `libc::rusage` is a plain C struct safe to zero-initialize;
        // `getrusage(RUSAGE_SELF, ...)` writes into our valid stack buffer.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `RUSAGE_SELF` is valid and `&mut usage` points to writable `libc::rusage`.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 && usage.ru_maxrss >= 0 {
            Some((usage.ru_maxrss as u64).saturating_mul(1024))
        } else {
            None
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `libc::rusage` is a plain C struct safe to zero-initialize.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `RUSAGE_SELF` is valid and `&mut usage` points to writable `libc::rusage`.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 && usage.ru_maxrss >= 0 {
            // macOS reports `ru_maxrss` directly in bytes.
            Some(usage.ru_maxrss as u64)
        } else {
            None
        }
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        // SAFETY: `libc::rusage` is a plain C struct safe to zero-initialize.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `RUSAGE_SELF` is valid and `&mut usage` points to writable `libc::rusage`.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 && usage.ru_maxrss >= 0 {
            Some((usage.ru_maxrss as u64).saturating_mul(1024))
        } else {
            None
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        None
    }
}

fn is_isolated_subprocess() -> bool {
    std::env::var_os(SUBPROCESS_ENV).is_some()
}

/// Re-execute a single test inside a clean, isolated child process so parallel tests
/// cannot pollute Peak RSS measurements (`VmHWM` / `ru_maxrss` / `PeakWorkingSetSize`).
fn run_in_isolated_subprocess(test_name: &str, ignored: bool) {
    let exe = std::env::current_exe().expect("locate current test executable");
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1");
    if ignored {
        cmd.arg("--ignored");
    }
    cmd.env(SUBPROCESS_ENV, "1");

    let out = cmd.output().expect("spawn isolated peak-RSS subprocess");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "isolated subprocess `{test_name}` failed (status={:?}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status.code()
    );
    assert!(
        stderr.contains(SUBPROCESS_MARKER) || stdout.contains(SUBPROCESS_MARKER),
        "isolated subprocess `{test_name}` exited 0 without executing inner benchmark!\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
    for line in stderr.lines().filter(|l| l.starts_with("[benchmark]")) {
        eprintln!("{line}");
    }
}

/// Build a bounded multi-threaded Tokio runtime matching `rship` CLI (`src/main.rs`).
fn build_lean_runtime() -> tokio::runtime::Runtime {
    let worker_threads = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 8);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .max_blocking_threads(16)
        .thread_keep_alive(Duration::from_secs(2))
        .build()
        .expect("build multi-thread Tokio runtime")
}

fn allocator_label() -> &'static str {
    if cfg!(any(feature = "mimalloc", target_env = "musl")) {
        "mimalloc"
    } else {
        "system"
    }
}

// ---------------------------------------------------------------------------
// Zero-disk, constant-memory deterministic GiB generator & verifying sink
// ---------------------------------------------------------------------------

#[inline(always)]
fn pattern_word(file_id: u64, aligned_byte_offset: u64) -> u64 {
    let x = aligned_byte_offset
        .wrapping_add(file_id.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^ (x >> 31)
}

#[inline(always)]
fn pattern_byte(file_id: u64, byte_offset: u64) -> u8 {
    let word = pattern_word(file_id, byte_offset & !7);
    word.to_le_bytes()[(byte_offset & 7) as usize]
}

fn fill_pattern(file_id: u64, start_offset: u64, mut buf: &mut [u8]) {
    let mut off = start_offset;
    let misalign = (off & 7) as usize;
    if misalign != 0 {
        let prefix = (8 - misalign).min(buf.len());
        for b in &mut buf[..prefix] {
            *b = pattern_byte(file_id, off);
            off += 1;
        }
        buf = &mut buf[prefix..];
    }

    let (chunks, remainder) = buf.as_chunks_mut::<8>();
    for chunk in chunks {
        *chunk = pattern_word(file_id, off).to_le_bytes();
        off += 8;
    }
    for b in remainder {
        *b = pattern_byte(file_id, off);
        off += 1;
    }
}

fn verify_pattern(file_id: u64, start_offset: u64, mut buf: &[u8]) -> std::result::Result<(), u64> {
    let mut off = start_offset;
    let misalign = (off & 7) as usize;
    if misalign != 0 {
        let prefix = (8 - misalign).min(buf.len());
        for &actual in &buf[..prefix] {
            if actual != pattern_byte(file_id, off) {
                return Err(off);
            }
            off += 1;
        }
        buf = &buf[prefix..];
    }

    let (chunks, remainder) = buf.as_chunks::<8>();
    for chunk in chunks {
        let expected = pattern_word(file_id, off).to_le_bytes();
        if *chunk != expected {
            for (i, (&a, &e)) in chunk.iter().zip(expected.iter()).enumerate() {
                if a != e {
                    return Err(off + i as u64);
                }
            }
        }
        off += 8;
    }
    for &actual in remainder {
        if actual != pattern_byte(file_id, off) {
            return Err(off);
        }
        off += 1;
    }
    Ok(())
}

fn parse_gen_file_id(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("gen_")?.strip_suffix(".bin")?;
    rest.parse::<u64>().ok()
}

/// Zero-allocation deterministic `SeekableSource` filling `PooledSlice` in place.
struct GeneratorSource {
    file_id: u64,
    total_len: u64,
}

#[async_trait]
impl SeekableSource for GeneratorSource {
    fn total_len(&self) -> u64 {
        self.total_len
    }

    async fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.total_len || buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min((self.total_len - offset) as usize);
        fill_pattern(self.file_id, offset, &mut buf[..n]);
        Ok(n)
    }

    async fn read_into_slice(
        &self,
        offset: u64,
        mut slice: PooledSlice,
        want: usize,
    ) -> Result<(PooledSlice, usize)> {
        if offset >= self.total_len || want == 0 {
            return Ok((slice, 0));
        }
        let available = (self.total_len - offset) as usize;
        let n = want.min(slice.capacity()).min(available);
        fill_pattern(self.file_id, offset, &mut slice.spare_mut()[..n]);
        Ok((slice, n))
    }
}

struct GeneratorBackend {
    num_files: usize,
    file_size: u64,
}

impl GeneratorBackend {
    fn new(num_files: usize, file_size: u64) -> Self {
        Self {
            num_files,
            file_size,
        }
    }

    fn make_entry(&self, file_id: usize) -> Entry {
        let rel = RelPath::parse(&format!("gen_{file_id:02}.bin")).unwrap();
        Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: rel,
            kind: EntryKind::File,
            size: self.file_size,
            mtime_ns: GEN_MTIME_NS,
            ctime_ns: None,
            etag: Some(format!("gen-etag-{file_id:02}")),
            checksum: None,
        }
    }
}

#[async_trait]
impl StorageBackend for GeneratorBackend {
    fn name(&self) -> &str {
        "gen-src"
    }

    fn kind(&self) -> &'static str {
        "memory"
    }

    fn endpoint_identity(&self) -> String {
        "generator://mem-gate".to_string()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: Duration::from_millis(1),
            can_set_mtime: false,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: MIB,
            default_chunk_size: 8 * MIB,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: true,
            supports_atomic_single_read: true,
            supports_version_pinned_read: true,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let Some(id) = parse_gen_file_id(path.nfc_path.as_str()) else {
            return Ok(None);
        };
        if (id as usize) < self.num_files {
            Ok(Some(self.make_entry(id as usize)))
        } else {
            Ok(None)
        }
    }

    async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
        let num_files = self.num_files;
        let file_size = self.file_size;
        let stream = futures::stream::iter((0..num_files).map(move |i| {
            let rel = RelPath::parse(&format!("gen_{i:02}.bin")).unwrap();
            Ok(Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: rel,
                kind: EntryKind::File,
                size: file_size,
                mtime_ns: GEN_MTIME_NS,
                ctime_ns: None,
                etag: Some(format!("gen-etag-{i:02}")),
                checksum: None,
            })
        }));
        Ok(Box::pin(stream))
    }

    async fn mkdir(&self, _path: &RelPath) -> Result<()> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn delete(&self, _path: &BackendPath) -> Result<()> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
    }

    async fn open_read(&self, path: &BackendPath, _range: Option<ByteRange>) -> Result<DataSource> {
        let id = parse_gen_file_id(path.nfc_path.as_str())
            .filter(|&id| (id as usize) < self.num_files)
            .ok_or_else(|| {
                Error::not_found(format!("unknown generator file `{}`", path.nfc_path))
            })?;
        Ok(DataSource::LocalSeekable(Arc::new(GeneratorSource {
            file_id: id,
            total_len: self.file_size,
        })))
    }

    async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn begin_upload(&self, _init: &UploadInit) -> Result<UploadSessionInit> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn upload_chunk(&self, _op: &OperationRecord, _chunk: ChunkUpload) -> Result<ChunkAck> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn finish_upload(
        &self,
        _op: &OperationRecord,
        _parts: &[CompletedPart],
    ) -> Result<Entry> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
        Err(Error::unsupported("read-only generator backend"))
    }

    async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
        Err(Error::unsupported("read-only generator backend"))
    }
}

struct SinkSession {
    dst_path: RelPath,
    file_id: u64,
    total_size: u64,
    mtime_ns: i64,
    parts: HashMap<u32, (u64, u64)>,
}

/// Constant-memory verifying sink (`UploadTopology::ParallelParts`): verifies every
/// received byte against the deterministic generator pattern on the fly and drops
/// pooled `Bytes` slabs immediately without retaining payload data.
struct VerifyingSinkBackend {
    next_session_id: AtomicU64,
    verified_bytes: AtomicU64,
    mismatch_count: AtomicU64,
    sessions: Mutex<HashMap<String, SinkSession>>,
    committed: Mutex<HashMap<String, Entry>>,
}

impl VerifyingSinkBackend {
    fn new() -> Self {
        Self {
            next_session_id: AtomicU64::new(1),
            verified_bytes: AtomicU64::new(0),
            mismatch_count: AtomicU64::new(0),
            sessions: Mutex::new(HashMap::new()),
            committed: Mutex::new(HashMap::new()),
        }
    }

    fn verified_bytes(&self) -> u64 {
        self.verified_bytes.load(Ordering::Acquire)
    }

    fn mismatch_count(&self) -> u64 {
        self.mismatch_count.load(Ordering::Acquire)
    }

    fn committed_count(&self) -> usize {
        self.committed.lock().unwrap().len()
    }
}

#[async_trait]
impl StorageBackend for VerifyingSinkBackend {
    fn name(&self) -> &str {
        "verify-sink"
    }

    fn kind(&self) -> &'static str {
        "memory"
    }

    fn endpoint_identity(&self) -> String {
        "verify-sink://mem-gate".to_string()
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hashes: vec![],
            mtime_granularity: Duration::from_millis(1),
            can_set_mtime: true,
            upload_topology: UploadTopology::ParallelParts,
            chunk_alignment: ChunkAlignment::Arbitrary,
            single_shot_max_bytes: MIB,
            default_chunk_size: 8 * MIB,
            allows_duplicate_names: false,
            case_sensitive: true,
            supports_node_id: false,
            supports_range_read: false,
            supports_atomic_single_read: false,
            supports_version_pinned_read: false,
            supports_ordered_utf8_list: false,
            supports_conditional_write: false,
            supports_change_feed: false,
            supports_server_side_copy: false,
            default_write_qps: None,
        }
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let guard = self.committed.lock().unwrap();
        Ok(guard.get(path.nfc_path.as_str()).cloned())
    }

    async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
        let entries: Vec<Result<Entry>> = self
            .committed
            .lock()
            .unwrap()
            .values()
            .cloned()
            .map(Ok)
            .collect();
        Ok(Box::pin(futures::stream::iter(entries)))
    }

    async fn mkdir(&self, _path: &RelPath) -> Result<()> {
        Ok(())
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        self.committed
            .lock()
            .unwrap()
            .remove(path.nfc_path.as_str());
        Ok(())
    }

    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
    }

    async fn open_read(
        &self,
        _path: &BackendPath,
        _range: Option<ByteRange>,
    ) -> Result<DataSource> {
        Err(Error::unsupported("write-only verifying sink backend"))
    }

    async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
        let file_id = parse_gen_file_id(init.dst_path.as_str())
            .ok_or_else(|| Error::protocol(format!("unexpected path `{}`", init.dst_path)))?;
        let mut off = 0u64;
        while let Some(item) = body.next().await {
            let bytes = item?;
            if let Err(bad_off) = verify_pattern(file_id, off, &bytes) {
                self.mismatch_count.fetch_add(1, Ordering::AcqRel);
                return Err(Error::protocol(format!(
                    "byte mismatch on `{}` at offset {bad_off}",
                    init.dst_path
                )));
            }
            off += bytes.len() as u64;
        }
        if off != init.total_size {
            return Err(Error::protocol(format!(
                "short single-shot body on `{}`: got {off}, expected {}",
                init.dst_path, init.total_size
            )));
        }
        self.verified_bytes.fetch_add(off, Ordering::AcqRel);
        let entry = Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: init.dst_path.clone(),
            kind: EntryKind::File,
            size: init.total_size,
            mtime_ns: init.src_mtime_ns,
            ctime_ns: None,
            etag: Some(format!("sink-ss-{file_id:02}")),
            checksum: None,
        };
        self.committed
            .lock()
            .unwrap()
            .insert(init.dst_path.as_str().to_string(), entry.clone());
        Ok(entry)
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let file_id = parse_gen_file_id(init.dst_path.as_str())
            .ok_or_else(|| Error::protocol(format!("unexpected path `{}`", init.dst_path)))?;
        let seq = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let token = format!("sink-sess-{seq}");
        self.sessions.lock().unwrap().insert(
            token.clone(),
            SinkSession {
                dst_path: init.dst_path.clone(),
                file_id,
                total_size: init.total_size,
                mtime_ns: init.src_mtime_ns,
                parts: HashMap::new(),
            },
        );
        Ok(UploadSessionInit {
            session_token: token,
            backend_meta: String::new(),
            remote_op_id: None,
            expires_at_unix_secs: None,
        })
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let Some(token) = op.session_token.as_deref() else {
            return Ok(UploadProgress::Expired);
        };
        let guard = self.sessions.lock().unwrap();
        let Some(sess) = guard.get(token) else {
            return Ok(UploadProgress::Expired);
        };
        let parts = sess
            .parts
            .iter()
            .map(|(&pn, &(offset, length))| CompletedPart {
                part_number: pn,
                offset,
                length,
                etag: format!("part-{pn}"),
                checksum: None,
            })
            .collect();
        Ok(UploadProgress::CompletedParts(parts))
    }

    async fn upload_chunk(&self, op: &OperationRecord, mut chunk: ChunkUpload) -> Result<ChunkAck> {
        let token = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("missing session_token on upload_chunk"))?;
        let file_id = {
            let guard = self.sessions.lock().unwrap();
            guard
                .get(token)
                .ok_or_else(|| Error::session_expired(format!("unknown session `{token}`")))?
                .file_id
        };

        let mut cur_offset = chunk.offset;
        let mut received = 0u64;
        while let Some(item) = chunk.body.next().await {
            let bytes = item?;
            if let Err(bad_off) = verify_pattern(file_id, cur_offset, &bytes) {
                self.mismatch_count.fetch_add(1, Ordering::AcqRel);
                return Err(Error::protocol(format!(
                    "byte mismatch on `{}` part {} at offset {bad_off}",
                    op.dst_nfc_path, chunk.part_number
                )));
            }
            let n = bytes.len() as u64;
            cur_offset += n;
            received += n;
            // `bytes` drops here, immediately returning its `BufferPool` permit & slab!
        }

        if received != chunk.len {
            return Err(Error::protocol(format!(
                "short chunk on `{}` part {}: got {received}, expected {}",
                op.dst_nfc_path, chunk.part_number, chunk.len
            )));
        }

        self.verified_bytes.fetch_add(received, Ordering::AcqRel);
        self.sessions
            .lock()
            .unwrap()
            .get_mut(token)
            .ok_or_else(|| Error::session_expired(format!("session `{token}` vanished")))?
            .parts
            .insert(chunk.part_number, (chunk.offset, chunk.len));

        Ok(ChunkAck {
            next_offset: None,
            etag: Some(format!("part-{}", chunk.part_number)),
            completed: None,
            checksum: None,
        })
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        let token = op
            .session_token
            .as_deref()
            .ok_or_else(|| Error::protocol("missing session_token on finish_upload"))?;
        let sess = self
            .sessions
            .lock()
            .unwrap()
            .remove(token)
            .ok_or_else(|| Error::session_expired(format!("unknown session `{token}`")))?;

        let mut ranges: Vec<(u64, u64)> = Vec::with_capacity(parts.len());
        for p in parts {
            let Some(&(off, len)) = sess.parts.get(&p.part_number) else {
                return Err(Error::protocol(format!(
                    "finish_upload referenced unverified part {} on `{}`",
                    p.part_number, sess.dst_path
                )));
            };
            if off != p.offset || len != p.length {
                return Err(Error::protocol(format!(
                    "part {} range mismatch on `{}`",
                    p.part_number, sess.dst_path
                )));
            }
            ranges.push((off, len));
        }
        ranges.sort_unstable_by_key(|&(off, _)| off);
        let mut cursor = 0u64;
        for (off, len) in ranges {
            if off != cursor {
                return Err(Error::protocol(format!(
                    "non-contiguous parts on `{}`: gap/overlap at {cursor} vs {off}",
                    sess.dst_path
                )));
            }
            cursor += len;
        }
        if cursor != sess.total_size {
            return Err(Error::protocol(format!(
                "incomplete upload on `{}`: {cursor} != {}",
                sess.dst_path, sess.total_size
            )));
        }

        let entry = Entry {
            node_id: None,
            parent_id: None,
            raw_path: None,
            nfc_path: sess.dst_path.clone(),
            kind: EntryKind::File,
            size: sess.total_size,
            mtime_ns: sess.mtime_ns,
            ctime_ns: None,
            etag: Some(format!("sink-mp-{:02}", sess.file_id)),
            checksum: None,
        };
        self.committed
            .lock()
            .unwrap()
            .insert(sess.dst_path.as_str().to_string(), entry.clone());
        Ok(entry)
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        if let Some(token) = op.session_token.as_deref() {
            self.sessions.lock().unwrap().remove(token);
        }
        Ok(())
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        let guard = self.committed.lock().unwrap();
        if let Some(entry) = guard.get(op.dst_nfc_path.as_str()) {
            Ok(ReconcileOutcome::Committed(entry.clone()))
        } else {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }
}

// ---------------------------------------------------------------------------
// Acceptance Tests
// ---------------------------------------------------------------------------

#[test]
fn acceptance_gdrive_10gib_plan_meets_81_request_target_and_small_fast_path() {
    let gdrive_caps = Capabilities {
        hashes: vec![],
        mtime_granularity: Duration::from_millis(1),
        can_set_mtime: true,
        upload_topology: UploadTopology::Sequential,
        chunk_alignment: ChunkAlignment::MultipleOf {
            align_bytes: 256 * 1024,
            max_chunk_bytes: None,
        },
        single_shot_max_bytes: 5 * MIB,
        default_chunk_size: 128 * MIB,
        allows_duplicate_names: true,
        case_sensitive: true,
        supports_node_id: true,
        supports_range_read: true,
        supports_atomic_single_read: true,
        supports_version_pinned_read: false,
        supports_ordered_utf8_list: false,
        supports_conditional_write: false,
        supports_change_feed: true,
        supports_server_side_copy: true,
        default_write_qps: Some(3),
    };

    // 10 GiB upload: 1 session init + 80 × 128 MiB PUTs = 81 data requests (<= 81 target!).
    match plan_upload(10 * GIB, &gdrive_caps, None).unwrap() {
        UploadPlan::Resumable {
            chunk_size,
            total_parts,
            ..
        } => {
            assert_eq!(chunk_size, 128 * MIB);
            assert_eq!(total_parts, 80);
            let total_data_requests = 1 + total_parts;
            assert!(total_data_requests <= 81);
        }
        other => panic!("expected Resumable plan, got {other:?}"),
    }

    // Small file <= 5 MiB: 1 single-shot request!
    assert_eq!(
        plan_upload(5 * MIB, &gdrive_caps, None).unwrap(),
        UploadPlan::SingleShot {
            total_size: 5 * MIB
        }
    );
}

/// Isolated-subprocess GiB-scale peak-memory gate: streams >= 1 GiB (default 1024 MiB,
/// 16 × 64 MiB files; overridable via `RSHIP_MEM_TEST_MIB` for multi-GiB nightly sweeps)
/// from a zero-disk deterministic `GeneratorBackend` into a constant-memory
/// `VerifyingSinkBackend` under an `8 MiB` `BufferPool` (`transfers = 8`,
/// `part_concurrency = 4`), asserting 100% byte-pattern integrity, zero leaked permits,
/// and true OS Peak RSS (`VmHWM` / `ru_maxrss` / `PeakWorkingSetSize`) well below 1 GiB.
#[test]
fn acceptance_gib_streaming_transfer_isolated_subprocess_peak_rss() {
    if !is_isolated_subprocess() {
        run_in_isolated_subprocess(
            "acceptance_gib_streaming_transfer_isolated_subprocess_peak_rss",
            false,
        );
        return;
    }

    const DEFAULT_TOTAL_MIB: u64 = 1024;
    const NUM_FILES: usize = 16;

    let total_mib = std::env::var("RSHIP_MEM_TEST_MIB")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|&v| v >= NUM_FILES as u64)
        .unwrap_or(DEFAULT_TOTAL_MIB);
    let file_size = (total_mib * MIB) / (NUM_FILES as u64);
    let total_bytes = file_size * (NUM_FILES as u64);

    let rt = build_lean_runtime();
    rt.block_on(async move {
        let tmp = TempDir::new().unwrap();
        let src = Arc::new(GeneratorBackend::new(NUM_FILES, file_size));
        let sink = Arc::new(VerifyingSinkBackend::new());
        let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
        let pool = BufferPool::new(8 * 1024 * 1024, 256 * 1024).unwrap();
        let engine = TransferEngine::new(
            src,
            sink.clone(),
            actor,
            pool.clone(),
            SystemClock::shared(),
            CancelFlag::new(),
        );

        let index = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "gib-mem-gate").unwrap());
        let mut cfg = EngineConfig::new("bench-gib", JobMode::Copy, "gen-src", "verify-sink");
        cfg.transfers = 8;
        cfg.part_concurrency = 4;

        let report = engine.run(&cfg, index).await.unwrap();
        assert!(report.errors.is_empty(), "transfer errors: {:?}", report.errors);
        assert_eq!(report.files_transferred, NUM_FILES as u64);
        assert_eq!(report.bytes_transferred, total_bytes);
        assert_eq!(sink.verified_bytes(), total_bytes);
        assert_eq!(sink.mismatch_count(), 0);
        assert_eq!(sink.committed_count(), NUM_FILES);

        let stats = pool.stats();
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "buffer pool leaked permits: available={} max={}",
            pool.available_bytes(),
            pool.max_bytes()
        );
        assert_eq!(stats.in_use_units, 0, "zero leaked buffer units");
        assert!(
            stats.peak_units <= stats.max_units,
            "pool exceeded hard cap: peak={} > cap={}",
            stats.peak_bytes(),
            stats.max_bytes()
        );

        let peak_rss = peak_process_rss_bytes()
            .expect("peak RSS measurement must be supported on Linux, macOS, and Windows");
        let ceiling_bytes: u64 = 64 * MIB;
        eprintln!(
            "[benchmark] gib_streaming_memory_gate bytes={} mib={:.1} files={} pool_peak={:.2} MiB pool_cap={:.2} MiB alloc={} peak_rss={:.2} MiB ceiling={:.1} MiB",
            total_bytes,
            (total_bytes as f64) / (MIB as f64),
            NUM_FILES,
            (stats.peak_bytes() as f64) / (MIB as f64),
            (stats.max_bytes() as f64) / (MIB as f64),
            allocator_label(),
            (peak_rss as f64) / (MIB as f64),
            (ceiling_bytes as f64) / (MIB as f64),
        );
        assert!(
            peak_rss <= ceiling_bytes,
            "GiB streaming subprocess Peak RSS ({:.2} MiB) exceeded {} MiB ceiling after streaming {:.1} MiB",
            (peak_rss as f64) / (MIB as f64),
            ceiling_bytes / MIB,
            (total_bytes as f64) / (MIB as f64),
        );
        eprintln!("{SUBPROCESS_MARKER}");
    });
}

#[test]
fn acceptance_16_concurrent_transfers_strict_buffer_cap_and_rss_under_64mib() {
    if !is_isolated_subprocess() {
        run_in_isolated_subprocess(
            "acceptance_16_concurrent_transfers_strict_buffer_cap_and_rss_under_64mib",
            false,
        );
        return;
    }

    let rt = build_lean_runtime();
    rt.block_on(async move {
        let tmp = TempDir::new().unwrap();
        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();

        // Create 16 files × 512 KiB = 8 MiB total, transferred concurrently under a strict 2 MiB BufferPool!
        let chunk_pattern: Vec<u8> = (0..(512 * 1024)).map(|i| (i % 251) as u8).collect();
        for i in 0..16 {
            std::fs::write(src_dir.join(format!("blob_{i:02}.bin")), &chunk_pattern).unwrap();
        }
        drop(chunk_pattern);

        let src = Arc::new(LocalBackend::new("src", &src_dir).unwrap());
        let dst = Arc::new(LocalBackend::new("dst", &dst_dir).unwrap());
        let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
        let pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024).unwrap();
        let engine = TransferEngine::new(
            src,
            dst,
            actor,
            pool.clone(),
            SystemClock::shared(),
            CancelFlag::new(),
        );

        let index = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "bench16").unwrap());
        let mut cfg = EngineConfig::new("bench-16", JobMode::Copy, "src", "dst");
        cfg.transfers = 16;

        let report = engine.run(&cfg, index).await.unwrap();
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.files_transferred, 16);

        let stats = pool.stats();
        assert_eq!(
            pool.available_bytes(),
            pool.max_bytes(),
            "zero leaked permits"
        );
        assert_eq!(stats.in_use_units, 0, "zero leaked units");
        assert!(
            stats.peak_units <= stats.max_units,
            "pool exceeded hard ceiling: peak={} > cap={}",
            stats.peak_bytes(),
            stats.max_bytes()
        );

        let peak_rss = peak_process_rss_bytes()
            .expect("peak RSS measurement must be supported on Linux, macOS, and Windows");
        eprintln!(
            "[benchmark] concurrent_16_local pool_peak={:.2} MiB alloc={} peak_rss={:.2} MiB",
            (stats.peak_bytes() as f64) / (MIB as f64),
            allocator_label(),
            (peak_rss as f64) / (MIB as f64),
        );
        assert!(
            peak_rss <= 64 * MIB,
            "measured Peak RSS ({:.2} MiB) exceeded 64 MiB ceiling",
            (peak_rss as f64) / (MIB as f64)
        );
        eprintln!("{SUBPROCESS_MARKER}");
    });
}

#[test]
fn acceptance_sqlite_sync_index_100k_rows_stays_under_64mib_rss() {
    if !is_isolated_subprocess() {
        run_in_isolated_subprocess(
            "acceptance_sqlite_sync_index_100k_rows_stays_under_64mib_rss",
            false,
        );
        return;
    }

    let rt = build_lean_runtime();
    rt.block_on(run_sqlite_scale_check(50_000));
    eprintln!("{SUBPROCESS_MARKER}");
}

/// Full 1,000,000-entry (500k src + 500k dst) SQLite `SyncIndex` Peak RSS verification.
/// Run explicitly with: `cargo test -p rship-cli --test acceptance_benchmarks -- --ignored`
#[test]
#[ignore]
fn acceptance_sqlite_sync_index_1m_rows_rss_under_64mib() {
    if !is_isolated_subprocess() {
        run_in_isolated_subprocess("acceptance_sqlite_sync_index_1m_rows_rss_under_64mib", true);
        return;
    }

    let rt = build_lean_runtime();
    rt.block_on(run_sqlite_scale_check(500_000));
    eprintln!("{SUBPROCESS_MARKER}");
}

async fn run_sqlite_scale_check(rows_per_side: usize) {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp(tmp.path(), "scale").unwrap();

    const BATCH: usize = 5000;
    for start in (0..rows_per_side).step_by(BATCH) {
        let end = (start + BATCH).min(rows_per_side);
        let mut src_batch = Vec::with_capacity(end - start);
        let mut dst_batch = Vec::with_capacity(end - start);
        for i in start..end {
            let p = format!("bucket_{:02}/dir_{:03}/file_{:07}.dat", i % 32, i % 512, i);
            let rel = RelPath::parse(&p).unwrap();
            let e = Entry {
                node_id: None,
                parent_id: None,
                raw_path: None,
                nfc_path: rel,
                kind: EntryKind::File,
                size: 4096,
                mtime_ns: 1_700_000_000_000_000_000,
                ctime_ns: None,
                etag: None,
                checksum: None,
            };
            src_batch.push(e.clone());
            dst_batch.push(e);
        }
        idx.insert_src_batch(src_batch).await.unwrap();
        idx.insert_dst_batch(dst_batch).await.unwrap();
    }

    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    assert!(conflicts.is_empty());

    // Stream full source keyset pagination verifying every row is visited cleanly.
    let mut after_id = 0i64;
    let mut visited = 0usize;
    loop {
        let page = idx.next_src_page(after_id, 512).await.unwrap();
        if page.is_empty() {
            break;
        }
        after_id = page.last().unwrap().row_id;
        visited += page.len();
    }
    assert_eq!(visited, rows_per_side);

    let peak_rss = peak_process_rss_bytes()
        .expect("peak RSS measurement must be supported on Linux, macOS, and Windows");
    eprintln!(
        "[benchmark] sqlite_sync_index rows={} alloc={} peak_rss={:.2} MiB",
        rows_per_side * 2,
        allocator_label(),
        (peak_rss as f64) / (MIB as f64)
    );
    assert!(
        peak_rss <= 64 * MIB,
        "SQLite SyncIndex ({} total rows) Peak RSS {:.2} MiB exceeded 64 MiB ceiling",
        rows_per_side * 2,
        (peak_rss as f64) / (MIB as f64)
    );
}
