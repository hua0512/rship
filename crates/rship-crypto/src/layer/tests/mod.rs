mod conformance_and_reads;
mod durability_hooks;
mod multipart_backends;
mod prop;
mod tight_pool;

use super::*;
use std::sync::OnceLock;

pub(super) fn pipeline_slot_test_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

pub(super) fn assert_pool_clean(pool: &BufferPool) {
    assert_eq!(
        pool.available_bytes(),
        pool.max_bytes(),
        "buffer pool leaked permits: available={} max={} stats={:?}",
        pool.available_bytes(),
        pool.max_bytes(),
        pool.stats()
    );
    assert_eq!(
        pool.stats().in_use_bytes(),
        0,
        "buffer pool still reports in-use bytes: {:?}",
        pool.stats()
    );
}

pub(super) async fn drain_byte_stream(mut stream: ByteStream) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

pub(super) async fn upload_test_blob_via_bounded_stream(
    crypto: &CryptoBackend,
    name: &str,
    payload: &[u8],
    pool: &BufferPool,
) -> Result<Entry> {
    use rship_core::source::{MemorySource, SeekableSource, bounded_range_stream};

    let rel = RelPath::parse(name)?;
    let src: Arc<dyn SeekableSource> = Arc::new(MemorySource::new(payload.to_vec()));
    let body = bounded_range_stream(src, 0, payload.len() as u64, pool.clone());
    let init = UploadInit {
        op_id: format!("op-{name}"),
        dst_path: rel,
        existing_node_id: None,
        pregenerated_id: None,
        total_size: payload.len() as u64,
        src_mtime_ns: 1_700_000_000_000_000_000,
        planned_chunk_size: 256 * 1024,
        checksums: vec![],
        precondition: DstPrecondition::Any,
        src_etag: None,
    };
    crypto.put_single_shot(&init, body).await
}
