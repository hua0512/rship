//! The pipelined unordered path defers non-ASCII / NFD source names until listing EOF for
//! NFC collision detection. The deferred set must not be held in an unbounded `Vec`: it is
//! routed through the run's `SyncDiffIndex` (which spills to disk on large trees) in
//! bounded batches.

use super::super::*;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::state::{ConflictKind, DiffRow, JobMode, SyncConflict, SyncDiffIndex};
use crate::types::Entry;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// [`SyncDiffIndex`] wrapper recording how many source entries were handed to it and the
/// largest single batch (the producer's in-memory deferred buffer bound).
#[derive(Default)]
struct CountingIndex {
    inner: InMemorySyncIndex,
    src_entries: AtomicUsize,
    max_src_batch: AtomicUsize,
}

#[async_trait]
impl SyncDiffIndex for CountingIndex {
    async fn insert_src_batch(&self, entries: Vec<Entry>) -> crate::error::Result<()> {
        self.src_entries.fetch_add(entries.len(), Ordering::SeqCst);
        self.max_src_batch
            .fetch_max(entries.len(), Ordering::SeqCst);
        self.inner.insert_src_batch(entries).await
    }
    async fn insert_dst_batch(&self, entries: Vec<Entry>) -> crate::error::Result<()> {
        self.inner.insert_dst_batch(entries).await
    }
    async fn finalize_and_detect_conflicts(
        &self,
        dst_case_sensitive: bool,
    ) -> crate::error::Result<Vec<SyncConflict>> {
        self.inner
            .finalize_and_detect_conflicts(dst_case_sensitive)
            .await
    }
    async fn list_conflicts(&self) -> crate::error::Result<Vec<SyncConflict>> {
        self.inner.list_conflicts().await
    }
    async fn next_src_page(
        &self,
        after_id: i64,
        limit: usize,
    ) -> crate::error::Result<Vec<DiffRow>> {
        self.inner.next_src_page(after_id, limit).await
    }
    async fn next_dst_only_page(
        &self,
        after_id: i64,
        limit: usize,
    ) -> crate::error::Result<Vec<DiffRow>> {
        self.inner.next_dst_only_page(after_id, limit).await
    }
}

#[tokio::test]
async fn pipelined_non_ascii_names_are_deferred_through_the_bounded_index() {
    const CJK_FILES: usize = 5_000;
    // `parallel_s3_like` forbids duplicate names and is case-sensitive, so `run` takes the
    // pipelined unordered path.
    let src = Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024));
    let dst = Arc::new(ChaosBackend::parallel_s3_like("dst", 64 * 1024));
    let mtime = 1_700_000_000_000_000_000i64;
    for i in 0..CJK_FILES {
        src.insert_file(
            &format!("文档/文件{i:05}.txt"),
            vec![(i % 251) as u8; 8],
            mtime,
        );
    }
    for i in 0..50 {
        src.insert_file(&format!("ascii/{i}.txt"), vec![1; 8], mtime);
    }
    // NFC (U+00E9) and NFD (e + U+0301) spellings collide after normalization.
    src.insert_file("caf\u{e9}.txt", b"nfc".to_vec(), mtime);
    src.insert_file("cafe\u{301}.txt", b"nfd".to_vec(), mtime);

    let index = Arc::new(CountingIndex::default());
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(1024 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
        CancelFlag::new(),
    );
    let cfg = EngineConfig::new("pipelined-cjk", JobMode::Copy, "src:", "dst:")
        .with_transfers(4)
        .with_allow_server_side_copy(false);
    let rep = engine.run(&cfg, index.clone()).await.unwrap();

    assert!(rep.errors.is_empty(), "errors: {:?}", rep.errors);
    assert!(
        rep.conflicts
            .iter()
            .any(|c| c.kind == ConflictKind::UnicodeNfcCollision),
        "NFC/NFD collision must still be detected: {:?}",
        rep.conflicts
    );
    assert_eq!(rep.files_transferred as usize, CJK_FILES + 50);
    assert_eq!(dst.file_count(), CJK_FILES + 50);

    // Every deferred entry went to the index, in batches no larger than the bounded
    // producer-side buffer.
    let deferred = index.src_entries.load(Ordering::SeqCst);
    assert!(
        deferred >= CJK_FILES + 2,
        "non-ASCII entries must be deferred through the SyncDiffIndex (got {deferred})"
    );
    let max_batch = index.max_src_batch.load(Ordering::SeqCst);
    assert!(
        max_batch <= 2_000 + 128,
        "deferred entries must be flushed in bounded batches (largest batch {max_batch})"
    );
}
