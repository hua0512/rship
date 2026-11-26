//! Data-integrity failures (checksum mismatches) must never be reconciled into a
//! committed transfer, must never produce a baseline or delete a moved source, and must
//! trigger a bounded number of fresh retries that discard any corrupt object we created.

use super::super::*;
use crate::backend::StorageBackend;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, RunReport, TransferEngine};
use crate::error::ErrorKind;
use crate::path::RelPath;
use crate::state::{BaselineMode, JobMode, JournalStore};
use crate::types::ChunkAlignment;
use std::sync::Arc;
use std::time::Duration;

const MTIME: i64 = 1_700_000_000_000_000_000;

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

fn gdrive_dst() -> ChaosBackend {
    ChaosBackend::sequential_gdrive_like("dst", 64 * 1024).with_caps(|c| {
        c.chunk_alignment = ChunkAlignment::MultipleOf {
            align_bytes: 64 * 1024,
            max_chunk_bytes: None,
        };
        c.default_chunk_size = 64 * 1024;
        c.single_shot_max_bytes = 16 * 1024;
    })
}

async fn run_once(
    src: &Arc<ChaosBackend>,
    dst: &Arc<ChaosBackend>,
    journal: &Arc<InMemoryJournal>,
    cfg: &EngineConfig,
) -> RunReport {
    let engine = TransferEngine::new(
        src.clone(),
        dst.clone(),
        journal.clone(),
        BufferPool::new(512 * 1024, 64 * 1024).unwrap(),
        Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
        CancelFlag::new(),
    );
    engine
        .run(cfg, Arc::new(InMemorySyncIndex::default()))
        .await
        .unwrap()
}

fn move_cfg(job: &str) -> EngineConfig {
    EngineConfig::new(job, JobMode::Move, "src:", "dst:")
        .with_transfers(1)
        .with_allow_server_side_copy(false)
        .with_max_retries(3)
        .with_base_retry_delay(Duration::from_millis(1))
}

fn has_integrity_error(rep: &RunReport) -> bool {
    rep.error_details
        .iter()
        .any(|e| e.kind == ErrorKind::Integrity)
}

/// Local (checksum-less) source -> GDrive-like single-shot `move` where the backend detects
/// a streaming checksum mismatch after the corrupt object was committed: the corrupt object
/// carries our op id, so reconcile would say `Committed`. It must not be accepted.
#[tokio::test]
async fn integrity_backend_mismatch_on_move_is_never_reconciled_and_source_survives() {
    let src =
        Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).without_listing_checksums());
    let dst = Arc::new(gdrive_dst());
    let data = payload(8 * 1024);
    src.insert_file("photo.jpg", data.clone(), MTIME);
    dst.set_faults(FaultSchedule {
        corrupt_commit_remaining: u32::MAX,
        corrupt_commit_reports_mismatch: true,
        ..Default::default()
    });
    let journal = Arc::new(InMemoryJournal::default());

    let rep = run_once(&src, &dst, &journal, &move_cfg("integrity-move")).await;

    assert!(
        has_integrity_error(&rep),
        "a persistent checksum mismatch must surface as an Integrity error: {:?}",
        rep.error_details
    );
    assert_eq!(
        rep.sources_deleted, 0,
        "move must never delete a source after a mismatch"
    );
    assert_eq!(
        src.get_file_bytes("photo.jpg").as_deref(),
        Some(data.as_slice()),
        "the only good copy must survive"
    );
    assert!(
        dst.get_file_bytes("photo.jpg").is_none(),
        "the corrupt object we created must be deleted on final failure"
    );
    // Bounded fresh retries: 1 initial attempt + min(max_retries, 2) retries.
    assert_eq!(dst.put_single_shot_calls(), 3);
    assert!(journal.list_active_operations().await.unwrap().is_empty());
}

/// A single transient corruption is retried from scratch and converges bit-exact.
#[tokio::test]
async fn integrity_transient_backend_mismatch_retries_fresh_and_converges() {
    let src =
        Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).without_listing_checksums());
    let dst = Arc::new(gdrive_dst());
    let data = payload(8 * 1024);
    src.insert_file("doc.txt", data.clone(), MTIME);
    dst.set_faults(FaultSchedule {
        corrupt_commit_remaining: 1,
        corrupt_commit_reports_mismatch: true,
        ..Default::default()
    });
    let journal = Arc::new(InMemoryJournal::default());

    let rep = run_once(&src, &dst, &journal, &move_cfg("integrity-transient")).await;

    assert!(rep.is_success(), "errors: {:?}", rep.error_details);
    assert_eq!(
        dst.get_file_bytes("doc.txt").as_deref(),
        Some(data.as_slice()),
        "destination must hold the re-uploaded good bytes, not the reconciled corrupt object"
    );
    assert_eq!(dst.file_count(), 1, "the retry must not leave a duplicate");
    assert_eq!(rep.sources_deleted, 1);
    assert!(src.get_file_bytes("doc.txt").is_none());
    assert!(journal.list_active_operations().await.unwrap().is_empty());
}

/// Engine-level end-to-end check (source and destination both expose SHA-256): a silently
/// corrupted commit is detected by `verify_committed_checksum`, the bad object is discarded,
/// and the transfer is retried fresh on every upload topology.
#[tokio::test]
async fn integrity_engine_level_mismatch_discards_bad_object_and_retries_on_all_topologies() {
    for (label, size, parallel) in [
        ("single-shot", 8 * 1024, false),
        ("sequential", 200 * 1024, false),
        ("parallel", 200 * 1024, true),
    ] {
        let src = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        let dst = Arc::new(if parallel {
            ChaosBackend::parallel_s3_like("dst", 64 * 1024)
        } else {
            gdrive_dst()
        });
        let data = payload(size);
        src.insert_file("blob.bin", data.clone(), MTIME);
        dst.set_faults(FaultSchedule {
            corrupt_commit_remaining: 1,
            corrupt_commit_reports_mismatch: false,
            ..Default::default()
        });
        let journal = Arc::new(InMemoryJournal::default());
        let mut cfg = EngineConfig::new(format!("e2e-{label}"), JobMode::Sync, "src:", "dst:")
            .with_transfers(1)
            .with_part_concurrency(1)
            .with_allow_server_side_copy(false)
            .with_baseline_mode(BaselineMode::All)
            .with_max_retries(3)
            .with_base_retry_delay(Duration::from_millis(1));
        if parallel {
            cfg.chunk_size_override = Some(64 * 1024);
        }

        let rep = run_once(&src, &dst, &journal, &cfg).await;
        assert!(rep.is_success(), "{label}: errors: {:?}", rep.error_details);
        assert_eq!(
            dst.get_file_bytes("blob.bin").as_deref(),
            Some(data.as_slice()),
            "{label}: destination must converge bit-exact after a fresh retry"
        );
        assert_eq!(dst.file_count(), 1, "{label}: no duplicate objects");
        assert_eq!(dst.active_session_count(), 0, "{label}: sessions leaked");
        assert!(journal.list_active_operations().await.unwrap().is_empty());

        // Persistent corruption: the error is reported, no baseline is written, and the
        // corrupt object we created is removed.
        let src2 = Arc::new(ChaosBackend::sequential_gdrive_like("src", 64 * 1024));
        let dst2 = Arc::new(if parallel {
            ChaosBackend::parallel_s3_like("dst", 64 * 1024)
        } else {
            gdrive_dst()
        });
        src2.insert_file("blob.bin", data.clone(), MTIME);
        dst2.set_faults(FaultSchedule {
            corrupt_commit_remaining: u32::MAX,
            corrupt_commit_reports_mismatch: false,
            ..Default::default()
        });
        let journal2 = Arc::new(InMemoryJournal::default());
        let rep2 = run_once(&src2, &dst2, &journal2, &cfg).await;
        assert!(
            has_integrity_error(&rep2),
            "{label}: expected an Integrity error, got {:?}",
            rep2.error_details
        );
        assert!(
            dst2.get_file_bytes("blob.bin").is_none(),
            "{label}: corrupt object must be deleted"
        );
        let pk = crate::engine::make_prefixed_pair_key(
            &src2.endpoint_identity(),
            &RelPath::root(),
            &dst2.endpoint_identity(),
            &RelPath::root(),
        );
        assert!(
            journal2
                .get_baseline(&pk, &RelPath::parse("blob.bin").unwrap())
                .await
                .unwrap()
                .is_none(),
            "{label}: no baseline may be written for a corrupt transfer"
        );
        assert!(journal2.list_active_operations().await.unwrap().is_empty());
    }
}

/// A pre-existing destination version is never deleted by integrity cleanup.
#[tokio::test]
async fn integrity_cleanup_leaves_pre_existing_destination_version_alone() {
    let src =
        Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).without_listing_checksums());
    let dst = Arc::new(gdrive_dst());
    src.insert_file("notes.txt", payload(4 * 1024), MTIME);
    dst.insert_file(
        "notes.txt",
        b"older version".to_vec(),
        MTIME - 10_000_000_000,
    );
    dst.set_faults(FaultSchedule {
        corrupt_commit_remaining: u32::MAX,
        corrupt_commit_reports_mismatch: true,
        ..Default::default()
    });
    let journal = Arc::new(InMemoryJournal::default());
    let cfg = EngineConfig::new("integrity-existing", JobMode::Copy, "src:", "dst:")
        .with_transfers(1)
        .with_allow_server_side_copy(false)
        .with_max_retries(3)
        .with_base_retry_delay(Duration::from_millis(1));

    let rep = run_once(&src, &dst, &journal, &cfg).await;
    assert!(has_integrity_error(&rep), "{:?}", rep.error_details);
    assert_eq!(
        dst.file_count(),
        1,
        "the destination path that existed before the run must not be deleted"
    );
    // The corrupt upload replaced the old version and stays in place, so only the
    // integrity marker remains in the journal.
    let ops = journal.list_active_operations().await.unwrap();
    assert_eq!(ops.len(), 1, "{ops:?}");
    assert_eq!(integrity_markers(&ops), 1);
}

fn integrity_markers(ops: &[crate::state::OperationRecord]) -> usize {
    ops.iter()
        .filter(|o| o.state == crate::state::OperationState::IntegrityFailed)
        .count()
}

/// A corrupt destination object that could not be removed (its delete failed, or the
/// corrupt upload replaced a pre-existing version) has the source's size and mtime, so a
/// later run would plan a skip and `move` would delete the only good copy. The persisted
/// integrity marker turns that skip into a fresh transfer.
#[tokio::test]
async fn move_after_integrity_failure_with_corrupt_object_left_re_transfers_and_keeps_source() {
    for case in ["delete-failed", "pre-existing-version"] {
        let src =
            Arc::new(ChaosBackend::parallel_s3_like("src", 64 * 1024).without_listing_checksums());
        let dst = Arc::new(gdrive_dst());
        let data = payload(8 * 1024);
        src.insert_file("photo.jpg", data.clone(), MTIME);
        let mut faults = FaultSchedule {
            corrupt_commit_remaining: u32::MAX,
            corrupt_commit_reports_mismatch: true,
            ..Default::default()
        };
        if case == "delete-failed" {
            faults.fail_delete_paths.insert("photo.jpg".to_string());
        } else {
            dst.insert_file(
                "photo.jpg",
                b"older version".to_vec(),
                MTIME - 10_000_000_000,
            );
        }
        dst.set_faults(faults.clone());
        let journal = Arc::new(InMemoryJournal::default());
        let cfg = move_cfg(&format!("integrity-left-{case}"));

        // Run 1: persistent corruption; the corrupt object stays on the destination.
        let rep1 = run_once(&src, &dst, &journal, &cfg).await;
        assert!(
            has_integrity_error(&rep1),
            "{case}: {:?}",
            rep1.error_details
        );
        let left = dst
            .get_file_bytes("photo.jpg")
            .expect("corrupt object left in place");
        assert_ne!(left, data, "{case}");
        assert_eq!(
            left.len(),
            data.len(),
            "{case}: corrupt object matches source size"
        );
        assert_eq!(
            integrity_markers(&journal.list_active_operations().await.unwrap()),
            1,
            "{case}: an integrity marker must be persisted"
        );

        // Run 2: still corrupting. The planner must not skip (size and mtime match) and
        // must not delete the source.
        let rep2 = run_once(&src, &dst, &journal, &cfg).await;
        assert!(
            has_integrity_error(&rep2),
            "{case}: {:?}",
            rep2.error_details
        );
        assert_eq!(rep2.sources_deleted, 0, "{case}");
        assert_eq!(
            src.get_file_bytes("photo.jpg").as_deref(),
            Some(data.as_slice()),
            "{case}: the only good copy must survive"
        );

        // Run 3: healthy destination. The file is re-transferred, then moved.
        faults.corrupt_commit_remaining = 0;
        dst.set_faults(faults);
        let before = dst.put_single_shot_calls();
        let rep3 = run_once(&src, &dst, &journal, &cfg).await;
        assert!(rep3.is_success(), "{case}: {:?}", rep3.error_details);
        assert_eq!(
            rep3.files_transferred, 1,
            "{case}: must re-transfer, not skip"
        );
        assert!(dst.put_single_shot_calls() > before, "{case}");
        assert_eq!(
            dst.get_file_bytes("photo.jpg").as_deref(),
            Some(data.as_slice()),
            "{case}"
        );
        assert!(src.get_file_bytes("photo.jpg").is_none(), "{case}: moved");
        assert!(
            journal.list_active_operations().await.unwrap().is_empty(),
            "{case}: a verified transfer clears the marker"
        );
    }
}
