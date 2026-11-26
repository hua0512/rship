use super::*;
use crate::error::Error;
use crate::state::SourceVersion;
use crate::types::NodeId;
use std::collections::BTreeSet;

#[test]
fn cmp_merge_key_matches_wire_trailing_slash_order_exactly() {
    let items = [
        ("a", false),
        ("a-", false),
        ("a-b", false),
        ("a-b", true),
        ("a.txt", false),
        ("a", true),
        ("a/0", false),
        ("a/a", false),
        ("a/a", true),
        ("a/a-b", false),
        ("a/z", false),
        ("a0", false),
        ("b", false),
    ];
    for &(ap, ad) in &items {
        for &(bp, bd) in &items {
            let aw = if ad { format!("{ap}/") } else { ap.to_string() };
            let bw = if bd { format!("{bp}/") } else { bp.to_string() };
            assert_eq!(
                cmp_merge_key(ap, ad, bp, bd),
                aw.as_bytes().cmp(bw.as_bytes()),
                "mismatch for ({ap:?}, {ad}) vs ({bp:?}, {bd})"
            );
        }
    }
}

#[test]
fn utf8_midpoint_key_is_strictly_bounded_for_skewed_and_flat_keys() {
    for (lo, hi) in [
        ("0000", Some("ffff")),
        ("uploads/2026/04/a", Some("uploads/2026/04/z")),
        ("uploads/2026/04/a1", Some("uploads/2026/04/b0")),
        ("a", Some("a/z")),
        ("0000", None),
        ("uploads/2026/a001", None),
        ("z-flat-00999.bin", None),
        ("中文/文件001.bin", None),
    ] {
        let mid = utf8_midpoint_key(lo, hi).unwrap_or_else(|| panic!("no mid for {lo:?}..{hi:?}"));
        assert!(mid.as_str() > lo, "mid `{mid}` <= lo `{lo}`");
        if let Some(u) = hi {
            assert!(mid.as_str() < u, "mid `{mid}` >= hi `{u}`");
        }
    }
}

#[test]
fn safe_watermark_never_advances_past_inflight_or_failed_keys() {
    let w = SafeWatermarkTracker::new();
    w.mark_dispatched("k1".into());
    w.mark_dispatched("k2".into());
    w.mark_dispatched("k3".into());
    // Out-of-order completion of k3 must NOT advance watermark past k1!
    w.mark_completed("k3", true);
    assert_eq!(w.current_watermark(), None);
    // k1 completes -> watermark advances to k1 (still blocked by k2)
    w.mark_completed("k1", true);
    assert_eq!(w.current_watermark().as_deref(), Some("k1"));
    // k2 fails -> future completions must NOT advance past k2!
    w.mark_completed("k2", false);
    w.mark_dispatched("k4".into());
    w.mark_completed("k4", true);
    assert_eq!(w.current_watermark().as_deref(), Some("k1"));
}

#[test]
fn delete_spill_log_stays_in_ram_below_cap_and_roundtrips_spilled_binary() {
    for cap in [100usize, 3usize] {
        let mut log = DeleteSpillLog::with_ram_cap(None, cap);
        for i in 0..10 {
            let p = RelPath::parse(&format!("dir/file-{i:02}.bin")).unwrap();
            let bp = BackendPath::from_rel(p.clone()).with_kind(Some(EntryKind::File));
            log.push(DeleteTarget {
                nfc_path: p,
                backend_path: bp,
                kind: EntryKind::File,
                expected_version: (i % 2 == 0).then(|| SourceVersion {
                    node_id: Some(NodeId(format!("n-{i}"))),
                    size: i as u64 * 10,
                    mtime_ns: 1_700_000_000_000_000_000 + i as i64,
                    ctime_ns: Some(1_700_000_000_000_000_000 + i as i64),
                    etag: Some(format!("\"e-{i}\"")),
                }),
            })
            .unwrap();
        }
        assert_eq!(log.len(), 10);
        assert_eq!(log.is_spilled(), cap < 10);

        let mut reader = log.into_reader().unwrap();
        let mut got = Vec::new();
        let mut chunk = Vec::new();
        while reader.next_chunk(4, &mut chunk).unwrap() > 0 {
            got.append(&mut chunk);
        }
        assert_eq!(got.len(), 10);
        assert_eq!(got[0].nfc_path.as_str(), "dir/file-00.bin");
        assert_eq!(
            got[0]
                .expected_version
                .as_ref()
                .and_then(|v| v.etag.as_deref()),
            Some("\"e-0\"")
        );
        assert!(got[1].expected_version.is_none());
        assert_eq!(got[9].nfc_path.as_str(), "dir/file-09.bin");
    }
}

#[tokio::test]
async fn delete_spill_log_async_methods_roundtrip_ram_and_spilled_batches() {
    for (cap, total) in [(100usize, 10usize), (3usize, 10usize), (4usize, 2_500usize)] {
        let mut log = DeleteSpillLog::with_ram_cap(None, cap);
        for i in 0..total {
            let p = RelPath::parse(&format!("dir/file-{i:05}.bin")).unwrap();
            let bp = BackendPath::from_rel(p.clone()).with_kind(Some(EntryKind::File));
            log.push_async(DeleteTarget {
                nfc_path: p,
                backend_path: bp,
                kind: EntryKind::File,
                expected_version: (i % 2 == 0).then(|| SourceVersion {
                    node_id: Some(NodeId(format!("n-{i}"))),
                    size: i as u64 * 10,
                    mtime_ns: 1_700_000_000_000_000_000 + i as i64,
                    ctime_ns: Some(1_700_000_000_000_000_000 + i as i64),
                    etag: Some(format!("\"e-{i}\"")),
                }),
            })
            .await
            .unwrap();
        }
        assert_eq!(log.len(), total as u64);
        assert_eq!(log.is_spilled(), cap < total);

        let spill_path = log.spill_path().cloned();
        let mut reader = log.into_reader_async().await.unwrap();
        let mut got = Vec::with_capacity(total);
        let mut chunk = Vec::new();
        while reader.next_chunk_async(333, &mut chunk).await.unwrap() > 0 {
            got.append(&mut chunk);
        }
        assert_eq!(got.len(), total);
        assert_eq!(got[0].nfc_path.as_str(), "dir/file-00000.bin");
        assert_eq!(
            got[total - 1].nfc_path.as_str(),
            format!("dir/file-{:05}.bin", total - 1)
        );
        drop(reader);
        if let Some(p) = spill_path {
            // `Drop` unlinks asynchronously on Tokio's blocking pool.
            for _ in 0..50 {
                if !p.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            assert!(
                !p.exists(),
                "spilled log `{}` should be removed on drop",
                p.display()
            );
        }
    }
}

#[test]
fn pruned_dir_prefix_uses_raw_nfd_wire_bytes_and_sentinel_clears_emoji() {
    // P0-1: macOS NFD key "cafe\u{0301}/img_0001.jpg" pruned via NFC rule "café/".
    // Raw wire prefix MUST be "cafe\u{0301}/" (0x65 0xCC 0x81 0x2F), NEVER NFC "caf\u{00e9}/"
    // (0xC3 0xA9 0x2F), so jumping never leaps over unrelated live keys "caff/..." .. "cafz/...".
    let raw = "cafe\u{0301}/img_0001.jpg";
    let nfc = RelPath::parse(raw).unwrap();
    assert_eq!(nfc.as_str(), "caf\u{00e9}/img_0001.jpg");
    let entry = Entry {
        node_id: None,
        parent_id: None,
        raw_path: crate::types::raw_path_override(&nfc, raw),
        nfc_path: nfc,
        kind: EntryKind::File,
        size: 10,
        mtime_ns: 0,
        ctime_ns: None,
        etag: None,
        checksum: None,
    };
    let pruner: DirPruner = Arc::new(|dir: &RelPath| dir.as_str() == "caf\u{00e9}");
    let prefix = find_pruned_dir_prefix(&entry, &pruner).expect("must match pruned NFD dir");
    assert_eq!(prefix, "cafe\u{0301}/");
    assert!(entry_wire_key(&entry).starts_with(&prefix));

    let jump = format!("{prefix}{DIR_JUMP_SENTINEL}");
    assert!(
        jump.as_str() < "caff/live.jpg",
        "jump `{jump}` must stay strictly below `caff/live.jpg`"
    );
    // 4-byte UTF-8 emoji filenames inside the pruned directory must sort strictly below the sentinel.
    let emoji_child = format!("{prefix}\u{1F680}_rocket.txt");
    assert!(
        emoji_child.as_str() < jump.as_str(),
        "DIR_JUMP_SENTINEL must sort after 4-byte UTF-8 emoji keys"
    );
}

#[test]
fn safe_watermark_respects_buffered_floor_and_drains_out_of_order_completions() {
    // P0-2: out-of-order completions drain contiguously once earlier in-flight keys finish,
    // and `buffered_floor` prevents advancing past deferred NFD/pending source wire keys.
    let w = SafeWatermarkTracker::new();
    w.set_buffered_floor(Some("cafe\u{0301}.txt".into()));
    w.mark_dispatched("a.txt".into());
    w.mark_dispatched("cafg.txt".into());
    w.mark_completed("cafg.txt", true);
    assert_eq!(w.current_watermark(), None, "blocked by in-flight a.txt");

    w.mark_completed("a.txt", true);
    // `a.txt` < `cafe\u{0301}.txt`, so watermark advances to `a.txt`, NOT `cafg.txt`!
    assert_eq!(w.current_watermark().as_deref(), Some("a.txt"));

    // Once the deferred NFD wire key drains past `cafg.txt`, watermark advances to `cafg.txt`.
    w.set_buffered_floor(Some("z.txt".into()));
    assert_eq!(w.current_watermark().as_deref(), Some("cafg.txt"));

    // If `buffered_floor` drops below `safe_completed`, `current_watermark()` clamps cleanly.
    w.set_buffered_floor(Some("b.txt".into()));
    assert_eq!(w.current_watermark(), None);
}

#[test]
fn flat_prefix_unbounded_midpoint_skips_constant_prefix() {
    // P2-3: flat bucket with 23-byte constant prefix should NOT bisect byte 0 ('t' -> 'w').
    let first = "tenant_prod_2026_shard_00000001.parquet";
    let lower = "tenant_prod_2026_shard_00001000.parquet";
    let lcp = first
        .bytes()
        .zip(lower.bytes())
        .take_while(|(a, b)| a == b)
        .count()
        .saturating_sub(4);
    let mid = utf8_midpoint_key_with_anchor(lower, None, lcp).expect("must compute midpoint");
    assert!(mid.as_str() > lower);
    assert!(
        mid.starts_with("tenant_prod_2026_sh"),
        "midpoint `{mid}` should stay inside the shared flat prefix instead of probing `w`"
    );
}

mod prop_tests {
    use super::*;
    use crate::backend::{
        ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome, UploadInit,
        UploadProgress, UploadSessionInit,
    };
    use crate::source::{ByteStream, DataSource};
    use crate::state::OperationRecord;
    use crate::types::{ByteRange, Capabilities, Checksum, HashKind};
    use async_trait::async_trait;
    use proptest::prelude::*;

    struct PagedOrderedBackend {
        name: String,
        entries: Vec<Entry>,
        page_cap: usize,
        concurrency: usize,
    }

    impl PagedOrderedBackend {
        fn new(name: &str, mut entries: Vec<Entry>, page_cap: usize, concurrency: usize) -> Self {
            entries.sort_by_key(entry_wire_key);
            Self {
                name: name.to_string(),
                entries,
                page_cap: page_cap.max(1),
                concurrency: concurrency.max(1),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for PagedOrderedBackend {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> &'static str {
            "prop-ordered"
        }
        fn endpoint_identity(&self) -> String {
            format!("prop://{}", self.name)
        }
        fn capabilities(&self) -> Capabilities {
            crate::chaos::ChaosBackend::parallel_s3_like(&self.name, 64 * 1024)
                .with_caps(|c| c.supports_ordered_utf8_list = true)
                .capabilities()
        }
        fn ordered_list_concurrency(&self) -> usize {
            self.concurrency
        }
        async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
            Ok(self
                .entries
                .iter()
                .find(|e| e.nfc_path == path.nfc_path)
                .cloned())
        }
        async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
            let items: Vec<Result<Entry>> = self.entries.iter().cloned().map(Ok).collect();
            Ok(Box::pin(futures::stream::iter(items)))
        }
        async fn list_ordered_page(
            &self,
            _prefix: &RelPath,
            start_after: Option<&str>,
            continuation: Option<&str>,
            max_keys: u32,
        ) -> Result<OrderedListPage> {
            let after = continuation.or(start_after);
            let mut matched: Vec<Entry> = self
                .entries
                .iter()
                .filter(|e| after.is_none_or(|a| entry_wire_key(e).as_str() > a))
                .cloned()
                .collect();
            let limit = (max_keys as usize).min(self.page_cap).max(1);
            let is_truncated = matched.len() > limit;
            if is_truncated {
                matched.truncate(limit);
            }
            let last_wire_key = matched.last().map(entry_wire_key);
            let next_cursor = if is_truncated {
                last_wire_key.clone()
            } else {
                None
            };
            Ok(OrderedListPage {
                entries: matched,
                is_truncated,
                next_cursor,
                last_wire_key,
                supports_start_after: true,
            })
        }
        async fn mkdir(&self, _path: &RelPath) -> Result<()> {
            Ok(())
        }
        async fn delete(&self, _path: &BackendPath) -> Result<()> {
            Ok(())
        }
        async fn compute_hash(
            &self,
            _path: &BackendPath,
            _kind: HashKind,
        ) -> Result<Option<Checksum>> {
            Ok(None)
        }
        async fn open_read(
            &self,
            _path: &BackendPath,
            _range: Option<ByteRange>,
        ) -> Result<DataSource> {
            Err(Error::unsupported("unused"))
        }
        async fn put_single_shot(&self, _init: &UploadInit, _body: ByteStream) -> Result<Entry> {
            Err(Error::unsupported("unused"))
        }
        async fn begin_upload(&self, _init: &UploadInit) -> Result<UploadSessionInit> {
            Err(Error::unsupported("unused"))
        }
        async fn query_upload(&self, _op: &OperationRecord) -> Result<UploadProgress> {
            Err(Error::unsupported("unused"))
        }
        async fn upload_chunk(
            &self,
            _op: &OperationRecord,
            _chunk: ChunkUpload,
        ) -> Result<ChunkAck> {
            Err(Error::unsupported("unused"))
        }
        async fn finish_upload(
            &self,
            _op: &OperationRecord,
            _parts: &[CompletedPart],
        ) -> Result<Entry> {
            Err(Error::unsupported("unused"))
        }
        async fn abort_upload(&self, _op: &OperationRecord) -> Result<()> {
            Ok(())
        }
        async fn reconcile_operation(&self, _op: &OperationRecord) -> Result<ReconcileOutcome> {
            Ok(ReconcileOutcome::NotCommitted)
        }
    }

    fn merge_key_strategy() -> impl Strategy<Value = String> {
        // Includes tricky wire-order characters (`-`, `.`, digits, nested `/`, NFD accent).
        let seg = prop::sample::select(vec![
            "a",
            "a-",
            "a-b",
            "a.txt",
            "a0",
            "app",
            "b",
            "c",
            "cafe\u{0301}",
            "d",
            "m",
            "z",
        ]);
        prop::collection::vec(seg, 1..=3).prop_map(|v| v.join("/"))
    }

    fn entry_map_strategy() -> impl Strategy<Value = BTreeMap<RelPath, Entry>> {
        prop::collection::vec(
            (
                merge_key_strategy(),
                prop::bool::ANY,
                0u64..10_000,
                1i64..1000,
            ),
            0..=24,
        )
        .prop_map(|rows| {
            let mut map = BTreeMap::new();
            for (raw, is_dir, size, mtime) in rows {
                let nfc = RelPath::parse(&raw).unwrap();
                map.entry(nfc.clone()).or_insert_with(|| Entry {
                    node_id: None,
                    parent_id: None,
                    raw_path: crate::types::raw_path_override(&nfc, &raw),
                    nfc_path: nfc,
                    kind: if is_dir {
                        EntryKind::Directory
                    } else {
                        EntryKind::File
                    },
                    size: if is_dir { 0 } else { size },
                    mtime_ns: mtime * 1_000_000_000,
                    ctime_ns: None,
                    etag: None,
                    checksum: None,
                });
            }
            map
        })
    }

    #[derive(Debug, Clone)]
    enum WatermarkOp {
        Dispatch(String),
        CompleteOk(String),
        CompleteFail(String),
        Skip(String),
        SetFloor(Option<String>),
    }

    fn key_pool_strategy() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09", "k10", "k11", "k12",
        ])
        .prop_map(str::to_string)
    }

    fn watermark_op_strategy() -> impl Strategy<Value = WatermarkOp> {
        prop_oneof![
            4 => key_pool_strategy().prop_map(WatermarkOp::Dispatch),
            4 => key_pool_strategy().prop_map(WatermarkOp::CompleteOk),
            1 => key_pool_strategy().prop_map(WatermarkOp::CompleteFail),
            2 => key_pool_strategy().prop_map(WatermarkOp::Skip),
            2 => prop::option::of(key_pool_strategy()).prop_map(WatermarkOp::SetFloor),
        ]
    }

    proptest! {
        #[test]
        fn prop_streaming_merge_diff_matches_btreemap_reference(
            src_map in entry_map_strategy(),
            dst_map in entry_map_strategy(),
            page_cap in 1usize..=6,
            concurrency in 1usize..=4,
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            let src_entries: Vec<Entry> = src_map.values().cloned().collect();
            let dst_entries: Vec<Entry> = dst_map.values().cloned().collect();

            let (got_src_only, got_dst_only, got_both, conflicts) = rt.block_on(async {
                let src_b: Arc<dyn StorageBackend> = Arc::new(PagedOrderedBackend::new(
                    "src",
                    src_entries,
                    page_cap,
                    concurrency,
                ));
                let dst_b: Arc<dyn StorageBackend> = Arc::new(PagedOrderedBackend::new(
                    "dst",
                    dst_entries,
                    page_cap,
                    concurrency,
                ));
                let mut diff = StreamingMergeDiffSource::start(
                    src_b,
                    RelPath::root(),
                    dst_b,
                    RelPath::root(),
                    None,
                    None,
                    None,
                    CancelFlag::new(),
                )
                .await
                .unwrap();

                let mut so = BTreeMap::new();
                let mut do_ = BTreeMap::new();
                let mut bo = BTreeMap::new();
                let mut confs = Vec::new();
                while let Some(item) = diff.next_item().await {
                    match item {
                        DiffItem::SrcOnly(e) => {
                            assert!(so.insert(e.nfc_path.clone(), e.size).is_none());
                        }
                        DiffItem::DstOnly(e) => {
                            assert!(do_.insert(e.nfc_path.clone(), e.size).is_none());
                        }
                        DiffItem::Both { src, dst } => {
                            assert_eq!(src.nfc_path, dst.nfc_path);
                            assert!(bo.insert(src.nfc_path.clone(), (src.size, dst.size)).is_none());
                        }
                        DiffItem::Conflict(c) => confs.push(c),
                    }
                }
                assert!(diff.drain_errors().is_empty());
                (so, do_, bo, confs)
            });

            prop_assert!(conflicts.is_empty(), "unexpected conflicts: {:?}", conflicts);

            // Reference BTreeMap set-difference.
            let mut ref_src_only = BTreeMap::new();
            let mut ref_dst_only = BTreeMap::new();
            let mut ref_both = BTreeMap::new();
            for (k, s) in &src_map {
                if let Some(d) = dst_map.get(k) {
                    ref_both.insert(k.clone(), (s.size, d.size));
                } else {
                    ref_src_only.insert(k.clone(), s.size);
                }
            }
            for (k, d) in &dst_map {
                if !src_map.contains_key(k) {
                    ref_dst_only.insert(k.clone(), d.size);
                }
            }

            prop_assert_eq!(got_src_only, ref_src_only);
            prop_assert_eq!(got_dst_only, ref_dst_only);
            prop_assert_eq!(got_both, ref_both);
        }

        #[test]
        fn prop_safe_watermark_never_advances_past_inflight_failed_or_buffered_keys(
            ops in prop::collection::vec(watermark_op_strategy(), 1..=60),
        ) {
            let tracker = SafeWatermarkTracker::new();
            let mut in_flight: BTreeSet<String> = BTreeSet::new();
            let mut failed: BTreeSet<String> = BTreeSet::new();
            let mut succeeded: BTreeSet<String> = BTreeSet::new();
            let mut buffered_floor: Option<String> = None;

            for op in ops {
                match op {
                    WatermarkOp::Dispatch(k) => {
                        in_flight.insert(k.clone());
                        tracker.mark_dispatched(k);
                    }
                    WatermarkOp::CompleteOk(k) => {
                        in_flight.remove(&k);
                        succeeded.insert(k.clone());
                        tracker.mark_completed(&k, true);
                    }
                    WatermarkOp::CompleteFail(k) => {
                        in_flight.remove(&k);
                        failed.insert(k.clone());
                        tracker.mark_completed(&k, false);
                    }
                    WatermarkOp::Skip(k) => {
                        in_flight.remove(&k);
                        succeeded.insert(k.clone());
                        tracker.mark_skipped(&k);
                    }
                    WatermarkOp::SetFloor(floor) => {
                        buffered_floor = floor.clone();
                        tracker.set_buffered_floor(floor);
                    }
                }

                if let Some(wm) = tracker.current_watermark() {
                    prop_assert!(
                        succeeded.contains(&wm),
                        "watermark `{wm}` was never completed successfully"
                    );
                    for inf in &in_flight {
                        prop_assert!(
                            wm.as_str() < inf.as_str(),
                            "watermark `{wm}` advanced to/past in-flight key `{inf}`"
                        );
                    }
                    for f in &failed {
                        prop_assert!(
                            wm.as_str() < f.as_str(),
                            "watermark `{wm}` advanced to/past failed key `{f}`"
                        );
                    }
                    if let Some(ref bf) = buffered_floor {
                        prop_assert!(
                            wm.as_str() < bf.as_str(),
                            "watermark `{wm}` advanced to/past buffered floor `{bf}`"
                        );
                    }
                }
            }
        }
    }
}
