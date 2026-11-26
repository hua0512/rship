//! Dead transfer workers (panics) must never let `sync --delete-after` delete anything:
//! a panicked worker is a reported error, and a producer that can no longer dispatch work
//! means the source was not fully observed.

use super::super::*;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, DeleteMode, EngineConfig, TransferEngine};
use crate::state::JobMode;
use std::sync::Arc;

const MTIME: i64 = 1_700_000_000_000_000_000;

fn ordered(b: ChaosBackend) -> ChaosBackend {
    b.with_caps(|c| c.supports_ordered_utf8_list = true)
}

#[tokio::test]
async fn sync_delete_after_deletes_nothing_when_transfer_workers_panic() {
    // (label, source, destination): pipelined unordered (no duplicate names on source),
    // indexed (source allows duplicate names), and streaming merge (both sides ordered).
    let cases: [(&str, ChaosBackend, ChaosBackend); 3] = [
        (
            "pipelined",
            ChaosBackend::parallel_s3_like("src", 64 * 1024),
            ChaosBackend::parallel_s3_like("dst", 64 * 1024),
        ),
        (
            "indexed",
            ChaosBackend::sequential_gdrive_like("src", 64 * 1024),
            ChaosBackend::parallel_s3_like("dst", 64 * 1024),
        ),
        (
            "streaming",
            ordered(ChaosBackend::parallel_s3_like("src", 64 * 1024)),
            ordered(ChaosBackend::parallel_s3_like("dst", 64 * 1024)),
        ),
    ];
    for (label, src, dst) in cases {
        let src = Arc::new(src);
        let dst = Arc::new(dst);
        // Far more source files than one pipelined batch (128) or the work queue (256).
        for i in 0..600 {
            src.insert_file(&format!("f/{i:04}.bin"), vec![i as u8; 64], MTIME);
        }
        for i in 0..5 {
            dst.insert_file(&format!("extra/{i}.bin"), vec![0xEE; 16], MTIME);
        }
        dst.set_faults(FaultSchedule {
            panic_on_upload: true,
            ..Default::default()
        });

        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            Arc::new(InMemoryJournal::default()),
            BufferPool::new(256 * 1024, 64 * 1024).unwrap(),
            Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
            CancelFlag::new(),
        );
        let cfg = EngineConfig::new(format!("panic-{label}"), JobMode::Sync, "src:", "dst:")
            .with_transfers(2)
            .with_delete(true)
            .with_delete_mode(DeleteMode::After)
            .with_allow_server_side_copy(false)
            .with_max_retries(0);
        let rep = engine
            .run(&cfg, Arc::new(InMemorySyncIndex::default()))
            .await
            .unwrap();

        assert_eq!(rep.items_deleted, 0, "{label}: deleted after worker panics");
        for i in 0..5 {
            assert!(
                dst.get_file_bytes(&format!("extra/{i}.bin")).is_some(),
                "{label}: extra/{i}.bin was deleted although transfers never ran"
            );
        }
        assert!(
            !rep.errors.is_empty(),
            "{label}: panicked workers must be reported as errors"
        );
        assert!(!rep.is_success(), "{label}: run must not report success");
        if label != "indexed" {
            assert!(
                !rep.src_observation_complete,
                "{label}: a closed producer means the source was not fully observed"
            );
        }
    }
}
