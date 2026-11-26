//! C3: chunked uploads read the source as byte ranges, which no backend can verify on
//! its own. The engine verifies the streamed bytes against the source's full-object
//! checksum before the destination commits the object.

use super::super::*;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, RunReport, TransferEngine};
use crate::error::ErrorKind;
use crate::state::JobMode;
use crate::types::ChunkAlignment;
use std::sync::Arc;
use std::time::Duration;

const MTIME: i64 = 1_700_000_000_000_000_000;
const SIZE: usize = 200 * 1024;

fn payload() -> Vec<u8> {
    (0..SIZE).map(|i| ((i * 13 + 5) % 251) as u8).collect()
}

/// Sequential destination that exposes no content hash (so the engine's post-commit
/// checksum comparison cannot help).
fn seq_dst() -> ChaosBackend {
    ChaosBackend::sequential_gdrive_like("dst", 64 * 1024)
        .with_caps(|c| {
            c.chunk_alignment = ChunkAlignment::MultipleOf {
                align_bytes: 64 * 1024,
                max_chunk_bytes: None,
            };
            c.default_chunk_size = 64 * 1024;
            c.single_shot_max_bytes = 16 * 1024;
        })
        .without_listing_checksums()
}

fn s3_dst() -> ChaosBackend {
    ChaosBackend::parallel_s3_like("dst", 64 * 1024).without_listing_checksums()
}

async fn run(
    src: &Arc<ChaosBackend>,
    dst: &Arc<ChaosBackend>,
    mode: JobMode,
    chunk: Option<u64>,
) -> RunReport {
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        Arc::new(InMemoryJournal::default()),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
        CancelFlag::new(),
    );
    let mut cfg = EngineConfig::new("ranged-verify", mode, "src:", "dst:")
        .with_transfers(1)
        .with_part_concurrency(2)
        .with_allow_server_side_copy(false)
        .with_max_retries(3)
        .with_base_retry_delay(Duration::from_millis(1));
    cfg.chunk_size_override = chunk;
    engine
        .run(&cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap()
}

#[tokio::test]
async fn sequential_chunked_upload_detects_corrupt_ranged_read_before_commit() {
    let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
    let dst = Arc::new(seq_dst());
    src.insert_file("video.bin", payload(), MTIME);
    src.set_faults(FaultSchedule {
        corrupt_reads_remaining: 1,
        ..Default::default()
    });

    let rep = run(&src, &dst, JobMode::Copy, None).await;
    assert!(rep.is_success(), "{:?}", rep.error_details);
    assert_eq!(
        dst.get_file_bytes("video.bin").as_deref(),
        Some(payload().as_slice()),
        "corrupt ranged source read must not be committed"
    );
    assert_eq!(
        dst.begin_upload_calls(),
        2,
        "one aborted session, one fresh retry"
    );
    assert_eq!(dst.active_session_count(), 0);
}

#[tokio::test]
async fn parallel_multipart_combines_part_crc32c_and_rejects_corrupt_read_before_finish() {
    let src = Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).with_crc32c_checksums());
    let dst = Arc::new(s3_dst());
    src.insert_file("disk.img", payload(), MTIME);
    src.set_faults(FaultSchedule {
        corrupt_reads_remaining: 1,
        ..Default::default()
    });

    let rep = run(&src, &dst, JobMode::Copy, Some(64 * 1024)).await;
    assert!(rep.is_success(), "{:?}", rep.error_details);
    assert_eq!(
        dst.get_file_bytes("disk.img").as_deref(),
        Some(payload().as_slice())
    );
    assert_eq!(
        dst.finish_upload_calls(),
        1,
        "the session with the corrupt part must never be completed"
    );
    assert_eq!(dst.active_session_count(), 0);
}

#[tokio::test]
async fn persistent_corrupt_ranged_reads_fail_move_without_commit_or_source_delete() {
    for (label, crc, parallel) in [("sequential", false, false), ("parallel", true, true)] {
        let src = ChaosBackend::parallel_s3_like("src", 64 * 1024);
        let src = Arc::new(if crc {
            src.with_crc32c_checksums()
        } else {
            src
        });
        let dst = Arc::new(if parallel { s3_dst() } else { seq_dst() });
        src.insert_file("only-copy.bin", payload(), MTIME);
        src.set_faults(FaultSchedule {
            corrupt_reads_remaining: u32::MAX,
            ..Default::default()
        });

        let rep = run(&src, &dst, JobMode::Move, parallel.then_some(64 * 1024)).await;
        assert!(
            rep.error_details
                .iter()
                .any(|e| e.kind == ErrorKind::Integrity),
            "{label}: {:?}",
            rep.error_details
        );
        assert!(dst.get_file_bytes("only-copy.bin").is_none(), "{label}");
        assert_eq!(
            src.get_file_bytes("only-copy.bin").as_deref(),
            Some(payload().as_slice()),
            "{label}: the source must survive"
        );
        assert_eq!(dst.active_session_count(), 0, "{label}");
    }
}
