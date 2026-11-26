//! Quantitative BEFORE/AFTER benchmark suite for 40M-scale S3 migrations:
//! 1. Ephemeral `SqliteSyncIndex` (100k src + 100k dst = 200k S3 rows, unordered)
//! 2. Durable `StateActor` (50k single-part S3 transfer commits)
//! 3. End-to-end S3 -> S3 migration (500 single-part files, Pass 1 + Pass 2 re-run)

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use md5::{Digest as _, Md5};
use rship_backends::s3::{PayloadSigningMode, S3Backend, S3Config, S3Credentials, S3Provider};
use rship_core::buffer::BufferPool;
use rship_core::clock::SystemClock;
use rship_core::engine::{CancelFlag, EngineConfig, TransferEngine};
use rship_core::path::RelPath;
use rship_core::state::{
    BaselineRecord, JobMode, JobRecord, JobStatus, JournalStore, SyncDiffIndex, compute_pair_key,
};
use rship_core::types::{Checksum, Entry, EntryKind, HashKind};
use rship_state::{SqliteSyncIndex, StateActor};
use rship_transport::{HttpTransport, TransportConfig};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::TempDir;
use tokio::net::TcpListener;

fn process_memory_bytes() -> (u64, u64) {
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
        // SAFETY: Valid current process handle and initialized struct size.
        let ok = unsafe {
            GetProcessMemoryInfo(GetCurrentProcess(), &mut counters as *mut _, counters.cb)
        };
        if ok != 0 {
            return (
                counters.WorkingSetSize as u64,
                counters.PeakWorkingSetSize as u64,
            );
        }
    }
    (0, 0)
}

fn dir_size_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                total += dir_size_bytes(&p);
            } else if let Ok(m) = std::fs::File::open(&p).and_then(|f| f.metadata()) {
                total += m.len();
            } else if let Ok(m) = entry.metadata() {
                total += m.len();
            }
        }
    }
    total
}

fn make_s3_entry(idx: usize) -> Entry {
    // Realistic ~72-byte S3 key with hex prefix + UUID-like filename + single-part MD5 ETag.
    let key = format!(
        "tenant-{:02}/shards/{:02x}/{:02x}/object-{:08x}-{:08x}.bin",
        idx % 16,
        (idx * 37) % 256,
        (idx * 91) % 256,
        idx,
        idx.wrapping_mul(2654435761)
    );
    let md5_hex = format!(
        "{:016x}{:016x}",
        idx as u64,
        (idx as u64).wrapping_mul(0x9e3779b97f4a7c15)
    );
    let etag = format!("\"{md5_hex}\"");
    let rel = RelPath::parse(&key).unwrap();
    Entry {
        node_id: None,
        parent_id: None,
        raw_path: None,
        nfc_path: rel,
        kind: EntryKind::File,
        size: 153_600, // 150 KiB avg
        mtime_ns: 1_716_000_000_000_000_000 + (idx as i64) * 1_000_000_000,
        ctime_ns: None,
        etag: Some(etag),
        checksum: Some(Checksum {
            kind: HashKind::Md5,
            hex: md5_hex,
        }),
    }
}

#[tokio::test]
#[ignore]
async fn bench_sync_index_200k_rows() {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp(tmp.path(), "bench200k").unwrap();

    const ROWS_PER_SIDE: usize = 100_000;
    const BATCH: usize = 2000;

    let t0 = Instant::now();
    // Insert src in forward order, dst in scrambled order (simulating unordered / prefix-split listing).
    for start in (0..ROWS_PER_SIDE).step_by(BATCH) {
        let end = (start + BATCH).min(ROWS_PER_SIDE);
        let mut src_batch = Vec::with_capacity(end - start);
        let mut dst_batch = Vec::with_capacity(end - start);
        for i in start..end {
            src_batch.push(make_s3_entry(i));
            // 95% matching + 5% dst-only orphans, inserted in scrambled order.
            let scrambled = (i * 7919) % ROWS_PER_SIDE;
            let dst_id = if scrambled.is_multiple_of(20) {
                ROWS_PER_SIDE + scrambled
            } else {
                scrambled
            };
            dst_batch.push(make_s3_entry(dst_id));
        }
        idx.insert_src_batch(src_batch).await.unwrap();
        idx.insert_dst_batch(dst_batch).await.unwrap();
    }
    let ingest_ms = t0.elapsed().as_millis();

    let t1 = Instant::now();
    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    let finalize_ms = t1.elapsed().as_millis();
    assert!(conflicts.is_empty());

    let db_bytes = idx.db_size_bytes().max(dir_size_bytes(tmp.path()));

    let t2 = Instant::now();
    let mut after_id = 0i64;
    let mut src_seen = 0usize;
    let mut matched = 0usize;
    loop {
        let page = idx.next_src_page(after_id, 512).await.unwrap();
        if page.is_empty() {
            break;
        }
        after_id = page.last().unwrap().row_id;
        for row in &page {
            if row.dst.is_some() {
                matched += 1;
            }
        }
        src_seen += page.len();
    }
    let mut dst_after_id = 0i64;
    let mut dst_only_seen = 0usize;
    loop {
        let page = idx.next_dst_only_page(dst_after_id, 512).await.unwrap();
        if page.is_empty() {
            break;
        }
        dst_after_id = page.last().unwrap().row_id;
        dst_only_seen += page.len();
    }
    let diff_ms = t2.elapsed().as_millis();
    let (rss, peak_rss) = process_memory_bytes();

    assert_eq!(src_seen, ROWS_PER_SIDE);
    assert_eq!(matched, 95_000);
    assert_eq!(dst_only_seen, 5_000);

    let total_rows = (ROWS_PER_SIDE * 2) as u64;
    println!(
        "BENCH_SYNC_INDEX rows={total_rows} db_bytes={db_bytes} bytes_per_row={:.1} ingest_ms={ingest_ms} finalize_ms={finalize_ms} diff_ms={diff_ms} rss_mib={:.2} peak_rss_mib={:.2}",
        db_bytes as f64 / total_rows as f64,
        rss as f64 / (1024.0 * 1024.0),
        peak_rss as f64 / (1024.0 * 1024.0),
    );
}

#[tokio::test]
#[ignore]
async fn bench_baseline_store_50k_commits() {
    let tmp = TempDir::new().unwrap();
    let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
    let pair_key = compute_pair_key("s3://swift.internal/std", "s3://s3.internal/std");

    let job = JobRecord {
        job_id: "bench-job".into(),
        mode: JobMode::Copy,
        src_spec: "swift:std".into(),
        dst_spec: "s3:std".into(),
        status: JobStatus::Running,
        files_total: 50_000,
        files_done: 0,
        bytes_total: 50_000 * 153_600,
        bytes_done: 0,
        created_at: 1_716_000_000,
        updated_at: 1_716_000_000,
        options_json: None,
        resume_cursor: None,
    };
    actor.upsert_job(&job).await.unwrap();

    const N: usize = 50_000;
    let t0 = Instant::now();
    let mut handles = Vec::new();
    let conc = 16usize;
    let per_worker = N / conc;
    for w in 0..conc {
        let actor = actor.clone();
        let pk = pair_key.clone();
        handles.push(tokio::spawn(async move {
            let start = w * per_worker;
            let end = start + per_worker;
            for i in start..end {
                let e = make_s3_entry(i);
                let base = BaselineRecord {
                    pair_key: pk.clone(),
                    nfc_path: e.nfc_path,
                    kind: EntryKind::File,
                    src_node_id: None,
                    dst_node_id: None,
                    size: e.size,
                    src_mtime_ns: e.mtime_ns,
                    dst_mtime_ns: e.mtime_ns + 1_000_000_000,
                    dst_etag: e.etag,
                    hash_kind: e.checksum.as_ref().map(|c| c.kind),
                    hash_hex: e.checksum.map(|c| c.hex),
                    updated_at: 1_716_000_001,
                };
                actor
                    .commit_verified_transfer(None, Some(&base), "bench-job", e.size)
                    .await
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    actor.flush().await.unwrap();
    let elapsed_ms = t0.elapsed().as_millis();
    let live_state_bytes = dir_size_bytes(tmp.path());
    let (rss, peak_rss) = process_memory_bytes();
    actor.shutdown().await.unwrap();
    let state_bytes = dir_size_bytes(tmp.path());

    println!(
        "BENCH_BASELINE_50K rows={N} state_bytes={state_bytes} live_state_bytes={live_state_bytes} bytes_per_row={:.1} elapsed_ms={elapsed_ms} rss_mib={:.2} peak_rss_mib={:.2}",
        state_bytes as f64 / N as f64,
        rss as f64 / (1024.0 * 1024.0),
        peak_rss as f64 / (1024.0 * 1024.0),
    );
}

#[derive(Default)]
struct BenchS3Counters {
    list: AtomicUsize,
    get: AtomicUsize,
    head: AtomicUsize,
    put: AtomicUsize,
}

type BenchObject = (Vec<u8>, String, String);

struct BenchS3Store {
    bucket: String,
    objects: Mutex<BTreeMap<String, BenchObject>>,
    counters: BenchS3Counters,
}

async fn bench_s3_handler(
    State(st): State<Arc<BenchS3Store>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().trim_start_matches('/');
    let query = uri.query().unwrap_or("");
    let prefix_bucket = format!("{}/", st.bucket);
    let key = path.strip_prefix(&prefix_bucket).unwrap_or("");

    if method == Method::GET && query.contains("list-type=2") {
        st.counters.list.fetch_add(1, Ordering::Relaxed);
        let mut start_token: Option<String> = None;
        let mut start_after: Option<String> = None;
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "continuation-token" {
                    start_token = Some(percent_decode(v));
                } else if k == "start-after" {
                    start_after = Some(percent_decode(v));
                }
            }
        }
        let lower_bound = start_token.as_deref().or(start_after.as_deref());
        let guard = st.objects.lock().unwrap();
        let all: Vec<(&String, &BenchObject)> = guard
            .iter()
            .filter(|(k, _)| lower_bound.is_none_or(|t| k.as_str() > t))
            .take(1001)
            .collect();
        let is_truncated = all.len() > 1000;
        let page = &all[..all.len().min(1000)];
        let next_tok = if is_truncated {
            page.last().map(|(k, _)| (*k).clone())
        } else {
            None
        };
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><IsTruncated>",
        );
        xml.push_str(if is_truncated { "true" } else { "false" });
        xml.push_str("</IsTruncated>");
        if let Some(tok) = next_tok {
            xml.push_str("<NextContinuationToken>");
            xml.push_str(&tok);
            xml.push_str("</NextContinuationToken>");
        }
        for (k, (data, etag, lm)) in page {
            xml.push_str("<Contents><Key>");
            xml.push_str(k);
            xml.push_str("</Key><LastModified>");
            xml.push_str(lm);
            xml.push_str("</LastModified><ETag>");
            xml.push_str(etag);
            xml.push_str("</ETag><Size>");
            xml.push_str(&data.len().to_string());
            xml.push_str("</Size></Contents>");
        }
        xml.push_str("</ListBucketResult>");
        return (StatusCode::OK, [("content-type", "application/xml")], xml).into_response();
    }

    if method == Method::HEAD {
        st.counters.head.fetch_add(1, Ordering::Relaxed);
        let guard = st.objects.lock().unwrap();
        if let Some((data, etag, _)) = guard.get(key) {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-length", data.len().to_string())
                .header("etag", etag.as_str())
                .header("last-modified", "Thu, 23 May 2024 19:48:40 GMT")
                .body(Body::empty())
                .unwrap();
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    if method == Method::GET {
        st.counters.get.fetch_add(1, Ordering::Relaxed);
        let guard = st.objects.lock().unwrap();
        if let Some((data, etag, _)) = guard.get(key) {
            if let Some(im) = headers
                .get(http::header::IF_MATCH)
                .and_then(|v| v.to_str().ok())
                && im != etag
            {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            return Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header("content-length", data.len().to_string())
                .header("etag", etag.as_str())
                .body(Body::from(data.clone()))
                .unwrap();
        }
        return StatusCode::NOT_FOUND.into_response();
    }

    if method == Method::PUT {
        st.counters.put.fetch_add(1, Ordering::Relaxed);
        let md5_hex = hex::encode(Md5::digest(&body));
        let etag = format!("\"{md5_hex}\"");
        st.objects.lock().unwrap().insert(
            key.to_string(),
            (body.to_vec(), etag.clone(), "2024-05-23T19:48:41Z".into()),
        );
        return Response::builder()
            .status(StatusCode::OK)
            .header("etag", etag)
            .header("date", "Thu, 23 May 2024 19:48:41 GMT")
            .body(Body::empty())
            .unwrap();
    }

    StatusCode::METHOD_NOT_ALLOWED.into_response()
}

async fn start_bench_s3(bucket: &str) -> (String, Arc<BenchS3Store>) {
    let store = Arc::new(BenchS3Store {
        bucket: bucket.into(),
        objects: Mutex::new(BTreeMap::new()),
        counters: BenchS3Counters::default(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let app = Router::new()
        .fallback(bench_s3_handler)
        .with_state(store.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, store)
}

#[tokio::test]
#[ignore]
async fn bench_s3_to_s3_500_files_e2e() {
    let (src_addr, src_store) = start_bench_s3("swift-std").await;
    let (dst_addr, dst_store) = start_bench_s3("s3-std").await;

    const FILES: usize = 500;
    {
        let mut g = src_store.objects.lock().unwrap();
        for i in 0..FILES {
            let key = format!("shard-{:02}/obj-{:06}.bin", i % 16, i);
            let mut data = vec![(i % 251) as u8; 8192];
            data[0] = (i & 0xff) as u8;
            data[1] = ((i >> 8) & 0xff) as u8;
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            g.insert(key, (data, etag, "2024-05-23T19:48:40Z".into()));
        }
    }

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let creds = S3Credentials::new("AK", "SK");
    let mut src_cfg = S3Config::new("swift", S3Provider::Generic, "swift-std", creds.clone());
    src_cfg.endpoint = Some(format!("http://{src_addr}"));
    src_cfg.force_path_style = Some(true);
    src_cfg.payload_signing = PayloadSigningMode::Unsigned;

    let mut dst_cfg = S3Config::new("s3dst", S3Provider::Generic, "s3-std", creds);
    dst_cfg.endpoint = Some(format!("http://{dst_addr}"));
    dst_cfg.force_path_style = Some(true);
    dst_cfg.payload_signing = PayloadSigningMode::Unsigned;

    let src = Arc::new(S3Backend::new(src_cfg, transport.clone(), None).unwrap());
    let dst = Arc::new(S3Backend::new(dst_cfg, transport, None).unwrap());

    let tmp = TempDir::new().unwrap();
    let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
    let pool = BufferPool::with_default_slab(16 * 1024 * 1024).unwrap();
    let engine = TransferEngine::new(
        src,
        dst,
        actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    // Pass 1: fresh copy of 500 files
    let mut cfg1 = EngineConfig::new("pass1", JobMode::Copy, "swift:swift-std", "s3dst:s3-std");
    cfg1.transfers = 16;
    let idx1 = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "pass1").unwrap());
    let t1 = Instant::now();
    let r1 = engine.run(&cfg1, idx1).await.unwrap();
    let pass1_ms = t1.elapsed().as_millis();
    assert!(r1.errors.is_empty(), "{:?}", r1.errors);
    assert_eq!(r1.files_transferred, FILES as u64);
    actor.flush().await.unwrap();

    let state_bytes_after_p1 = dir_size_bytes(tmp.path());
    let p1_src_list = src_store.counters.list.swap(0, Ordering::Relaxed);
    let p1_src_get = src_store.counters.get.swap(0, Ordering::Relaxed);
    let p1_src_head = src_store.counters.head.swap(0, Ordering::Relaxed);
    let p1_dst_list = dst_store.counters.list.swap(0, Ordering::Relaxed);
    let p1_dst_put = dst_store.counters.put.swap(0, Ordering::Relaxed);
    let p1_dst_head = dst_store.counters.head.swap(0, Ordering::Relaxed);

    // Pass 2: incremental catch-up copy (all 500 should skip!)
    let mut cfg2 = EngineConfig::new("pass2", JobMode::Copy, "swift:swift-std", "s3dst:s3-std");
    cfg2.transfers = 16;
    let idx2 = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "pass2").unwrap());
    let t2 = Instant::now();
    let r2 = engine.run(&cfg2, idx2).await.unwrap();
    let pass2_ms = t2.elapsed().as_millis();
    assert!(r2.errors.is_empty(), "{:?}", r2.errors);
    assert_eq!(r2.files_transferred, 0);
    assert_eq!(r2.files_skipped, FILES as u64);
    actor.flush().await.unwrap();

    let p2_src_head = src_store.counters.head.load(Ordering::Relaxed);
    let p2_dst_head = dst_store.counters.head.load(Ordering::Relaxed);
    let p2_dst_put = dst_store.counters.put.load(Ordering::Relaxed);
    let (rss, peak_rss) = process_memory_bytes();
    actor.shutdown().await.unwrap();

    println!(
        "BENCH_S3_E2E files={FILES} pass1_ms={pass1_ms} pass2_ms={pass2_ms} state_bytes={state_bytes_after_p1} p1_src_list={p1_src_list} p1_src_get={p1_src_get} p1_src_head={p1_src_head} p1_dst_list={p1_dst_list} p1_dst_put={p1_dst_put} p1_dst_head={p1_dst_head} p2_src_head={p2_src_head} p2_dst_head={p2_dst_head} p2_dst_put={p2_dst_put} pool_peak_kib={} rss_mib={:.2} peak_rss_mib={:.2}",
        pool.stats().peak_bytes() / 1024,
        rss as f64 / (1024.0 * 1024.0),
        peak_rss as f64 / (1024.0 * 1024.0),
    );
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

#[tokio::test]
#[ignore]
async fn bench_sync_index_1k_small_hybrid() {
    let tmp = TempDir::new().unwrap();
    let idx = SqliteSyncIndex::open_temp(tmp.path(), "bench1k").unwrap();

    const ROWS_PER_SIDE: usize = 500;
    let t0 = Instant::now();
    let src_batch: Vec<Entry> = (0..ROWS_PER_SIDE).map(make_s3_entry).collect();
    let dst_batch: Vec<Entry> = (0..ROWS_PER_SIDE)
        .map(|i| {
            let s = (i * 37) % ROWS_PER_SIDE;
            if s.is_multiple_of(20) {
                make_s3_entry(ROWS_PER_SIDE + s)
            } else {
                make_s3_entry(s)
            }
        })
        .collect();
    idx.insert_src_batch(src_batch).await.unwrap();
    idx.insert_dst_batch(dst_batch).await.unwrap();
    let ingest_us = t0.elapsed().as_micros();

    let t1 = Instant::now();
    let conflicts = idx.finalize_and_detect_conflicts(true).await.unwrap();
    let finalize_us = t1.elapsed().as_micros();
    assert!(conflicts.is_empty());

    let db_bytes = idx.db_size_bytes().max(dir_size_bytes(tmp.path()));
    let t2 = Instant::now();
    let mut after_id = 0i64;
    let mut seen = 0usize;
    loop {
        let p = idx.next_src_page(after_id, 512).await.unwrap();
        if p.is_empty() {
            break;
        }
        after_id = p.last().unwrap().row_id;
        seen += p.len();
    }
    let mut d_after = 0i64;
    let mut d_only = 0usize;
    loop {
        let p = idx.next_dst_only_page(d_after, 512).await.unwrap();
        if p.is_empty() {
            break;
        }
        d_after = p.last().unwrap().row_id;
        d_only += p.len();
    }
    let diff_us = t2.elapsed().as_micros();
    let (rss, peak_rss) = process_memory_bytes();
    assert_eq!(seen, ROWS_PER_SIDE);
    assert_eq!(d_only, 25);

    println!(
        "BENCH_SMALL_HYBRID_1K rows=1000 db_bytes={db_bytes} ingest_us={ingest_us} finalize_us={finalize_us} diff_us={diff_us} rss_mib={:.2} peak_rss_mib={:.2}",
        rss as f64 / (1024.0 * 1024.0),
        peak_rss as f64 / (1024.0 * 1024.0),
    );
}

#[tokio::test]
#[ignore]
async fn bench_s3_to_s3_2500_files_gear2_e2e() {
    let (src_addr, src_store) = start_bench_s3("swift-g2").await;
    let (dst_addr, dst_store) = start_bench_s3("s3-g2").await;

    const FILES: usize = 2_500;
    {
        let mut g = src_store.objects.lock().unwrap();
        for i in 0..FILES {
            let key = format!("shard-{:02}/obj-{:06}.bin", i % 16, i);
            let mut data = vec![(i % 251) as u8; 4096];
            data[0] = (i & 0xff) as u8;
            data[1] = ((i >> 8) & 0xff) as u8;
            let etag = format!("\"{}\"", hex::encode(Md5::digest(&data)));
            g.insert(key, (data, etag, "2024-05-23T19:48:40Z".into()));
        }
    }

    let transport = HttpTransport::new(TransportConfig::default()).unwrap();
    let creds = S3Credentials::new("AK", "SK");
    let mut src_cfg = S3Config::new("swift", S3Provider::Generic, "swift-g2", creds.clone());
    src_cfg.endpoint = Some(format!("http://{src_addr}"));
    src_cfg.force_path_style = Some(true);
    src_cfg.payload_signing = PayloadSigningMode::Unsigned;

    let mut dst_cfg = S3Config::new("s3dst", S3Provider::Generic, "s3-g2", creds);
    dst_cfg.endpoint = Some(format!("http://{dst_addr}"));
    dst_cfg.force_path_style = Some(true);
    dst_cfg.payload_signing = PayloadSigningMode::Unsigned;

    let src = Arc::new(S3Backend::new(src_cfg, transport.clone(), None).unwrap());
    let dst = Arc::new(S3Backend::new(dst_cfg, transport, None).unwrap());

    let tmp = TempDir::new().unwrap();
    let scratch_root = tmp.path().join("scratch");
    let actor = Arc::new(StateActor::open(tmp.path()).unwrap());
    let pool = BufferPool::with_default_slab(16 * 1024 * 1024).unwrap();
    let engine = TransferEngine::new(
        src,
        dst,
        actor.clone(),
        pool.clone(),
        SystemClock::shared(),
        CancelFlag::new(),
    );

    let mut cfg1 = EngineConfig::new("g2-p1", JobMode::Copy, "swift:swift-g2", "s3dst:s3-g2");
    cfg1.transfers = 32;
    cfg1.scratch_dir = Some(Arc::new(rship_state::LazyRunDir::new(
        scratch_root.clone(),
        "g2-p1",
    )));
    let idx1 = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "g2-p1").unwrap());
    let t1 = Instant::now();
    let r1 = engine.run(&cfg1, idx1).await.unwrap();
    let pass1_ms = t1.elapsed().as_millis();
    assert!(r1.errors.is_empty(), "{:?}", r1.errors);
    assert_eq!(r1.files_transferred, FILES as u64);
    actor.flush().await.unwrap();

    let state_bytes = dir_size_bytes(tmp.path());
    let scratch_bytes = dir_size_bytes(&scratch_root);
    let p1_src_list = src_store.counters.list.swap(0, Ordering::Relaxed);
    let p1_src_head = src_store.counters.head.swap(0, Ordering::Relaxed);
    let p1_dst_list = dst_store.counters.list.swap(0, Ordering::Relaxed);

    let mut cfg2 = EngineConfig::new("g2-p2", JobMode::Copy, "swift:swift-g2", "s3dst:s3-g2");
    cfg2.transfers = 32;
    let idx2 = Arc::new(SqliteSyncIndex::open_temp(tmp.path(), "g2-p2").unwrap());
    let t2 = Instant::now();
    let r2 = engine.run(&cfg2, idx2).await.unwrap();
    let pass2_ms = t2.elapsed().as_millis();
    assert!(r2.errors.is_empty(), "{:?}", r2.errors);
    assert_eq!(r2.files_transferred, 0);
    assert_eq!(r2.files_skipped, FILES as u64);
    let p2_src_list = src_store.counters.list.load(Ordering::Relaxed);
    let p2_dst_list = dst_store.counters.list.load(Ordering::Relaxed);
    let p2_src_head = src_store.counters.head.load(Ordering::Relaxed);
    let (rss, peak_rss) = process_memory_bytes();
    actor.shutdown().await.unwrap();

    println!(
        "BENCH_S3_GEAR2_2500 files={FILES} pass1_ms={pass1_ms} pass2_ms={pass2_ms} state_bytes={state_bytes} scratch_bytes={scratch_bytes} p1_src_list={p1_src_list} p1_dst_list={p1_dst_list} p1_src_head={p1_src_head} p2_src_list={p2_src_list} p2_dst_list={p2_dst_list} p2_src_head={p2_src_head} pool_peak_kib={} rss_mib={:.2} peak_rss_mib={:.2}",
        pool.stats().peak_bytes() / 1024,
        rss as f64 / (1024.0 * 1024.0),
        peak_rss as f64 / (1024.0 * 1024.0),
    );
}
