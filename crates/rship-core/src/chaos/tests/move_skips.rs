//! Planned `move` skips (verify-before-delete of sources already present on the
//! destination) must not run inline in the producer: slow source deletes must not stall
//! listing or the dispatch of later transfers.

use super::super::*;
use crate::buffer::BufferPool;
use crate::clock::VirtualClock;
use crate::engine::{CancelFlag, EngineConfig, TransferEngine};
use crate::state::JobMode;
use std::sync::Arc;
use std::time::Duration;

const MTIME: i64 = 1_700_000_000_000_000_000;

fn ordered(b: ChaosBackend) -> ChaosBackend {
    b.with_caps(|c| c.supports_ordered_utf8_list = true)
}

#[tokio::test]
async fn move_skip_deletes_do_not_block_listing_or_later_transfers() {
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
        // 600 files already on the destination (planned skips -> verify + delete source),
        // listed before one file that still needs a transfer.
        for i in 0..600 {
            let data = vec![(i % 251) as u8; 32];
            src.insert_file(&format!("a/{i:04}.bin"), data.clone(), MTIME);
            dst.insert_file(&format!("a/{i:04}.bin"), data, MTIME);
        }
        src.insert_file("z/late.bin", b"needs transfer".to_vec(), MTIME);

        // Source deletes block until the late transfer has reached the destination.
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        src.set_delete_gate(Some(gate.clone()));
        let watcher = {
            let dst = dst.clone();
            let gate = gate.clone();
            tokio::spawn(async move {
                while dst.get_file_bytes("z/late.bin").is_none() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                gate.add_permits(64);
            })
        };

        let engine = TransferEngine::new(
            src.clone(),
            dst.clone(),
            Arc::new(InMemoryJournal::default()),
            BufferPool::new(256 * 1024, 64 * 1024).unwrap(),
            Arc::new(VirtualClock::new_instant_sleep(1_700_000_100)),
            CancelFlag::new(),
        );
        let cfg = EngineConfig::new(format!("skips-{label}"), JobMode::Move, "src:", "dst:")
            .with_transfers(4)
            .with_allow_server_side_copy(false);
        let rep = tokio::time::timeout(
            Duration::from_secs(20),
            engine.run(&cfg, Arc::new(InMemorySyncIndex::default())),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("{label}: producer stalled behind blocked move-skip source deletes")
        })
        .unwrap();
        watcher.abort();

        assert!(rep.is_success(), "{label}: errors {:?}", rep.errors);
        assert_eq!(rep.files_transferred, 1, "{label}");
        assert_eq!(rep.files_skipped, 600, "{label}");
        assert_eq!(rep.sources_deleted, 601, "{label}");
        assert_eq!(src.file_count(), 0, "{label}: every source must be moved");
        assert_eq!(dst.file_count(), 601, "{label}");
    }
}
