//! Transparent `CryptoBackend` implementing [`StorageBackend`] over any inner
//! backend (Local, Google Drive, S3) with STREAM OAE2 seekable 64 KiB AEAD.

mod framing;
mod reader;
#[cfg(test)]
mod tests;

use async_trait::async_trait;
use bytes::Bytes;
#[cfg(test)]
use framing::{MAX_GLOBAL_ENCRYPT_PIPELINES, encrypt_pipeline_slots};
use framing::{
    build_fast_encrypt_stream, ciphertext_offset_for_plaintext, ciphertext_part_len,
    equal_ct_part_size, map_sequential_ct_offset, plaintext_offset_from_ciphertext,
    skip_ciphertext_prefix, split_ciphertext_stream, strip_inner_prefix,
};
use futures::StreamExt;
use reader::CryptoRangeReader;
use rship_core::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ListOptions, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use rship_core::buffer::BufferPool;
use rship_core::path::RelPath;
use rship_core::source::{ByteStream, DataSource};
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, NodeId,
    UploadTopology,
};
use rship_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::OnceCell;

use crate::filename::{FilenameEncryption, decrypt_rel_path, encrypt_rel_path};
use crate::keys::CryptoKeys;
use crate::stream::{
    CIPHERTEXT_CHUNK_LEN, HEADER_LEN, PLAINTEXT_CHUNK_LEN, StreamHeader, ciphertext_size,
    max_plaintext_for_ciphertext, plaintext_size,
};

#[inline]
pub(super) fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn map_precondition_to_ciphertext(pre: &DstPrecondition) -> Result<DstPrecondition> {
    Ok(match pre {
        DstPrecondition::Existing {
            node_id,
            etag,
            mtime_ns,
            size,
        } => DstPrecondition::Existing {
            node_id: node_id.clone(),
            etag: etag.clone(),
            mtime_ns: *mtime_ns,
            size: ciphertext_size(*size)?,
        },
        other => other.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct CryptoConfig {
    pub remote_name: String,
    pub filename_encryption: FilenameEncryption,
    /// Unencrypted sub-prefix on the inner backend (e.g. `vault` when wrapping `gdrive:vault`),
    /// keeping ciphertexts scoped under that directory/prefix instead of encrypting the prefix
    /// segments at the inner backend's root.
    pub inner_prefix: RelPath,
}

impl CryptoConfig {
    pub fn new(remote_name: impl Into<String>) -> Self {
        Self {
            remote_name: remote_name.into(),
            filename_encryption: FilenameEncryption::Standard,
            inner_prefix: RelPath::root(),
        }
    }

    pub fn with_inner_prefix(mut self, prefix: RelPath) -> Self {
        self.inner_prefix = prefix;
        self
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CryptoSessionMeta {
    nonce_prefix_hex: String,
    plaintext_total_size: u64,
    plaintext_chunk_size: u64,
    inner_meta: String,
    inner_dst_path: String,
    #[serde(default)]
    equal_non_final_parts: bool,
    #[serde(default)]
    seq_align_bytes: Option<u64>,
}

#[derive(Default)]
struct EqualPartsCarry {
    /// Rolling 32-byte (`HEADER_LEN`) ciphertext tail carried into the next equal-sized part.
    carry: Vec<u8>,
    completed_parts: Vec<CompletedPart>,
}

#[derive(Default)]
struct SeqAlignState {
    /// Rolling `< align_bytes` (e.g. `< 256 KiB` on GDrive) ciphertext carry across chunks.
    carry: Vec<u8>,
    /// Exact ciphertext offset confirmed on the inner sequential upload session.
    inner_offset: u64,
    /// Leading ciphertext bytes to skip on the first resumed chunk after `query_upload`.
    skip_leading_ct: u64,
}

const MAX_ABORTED_OPS: usize = 4096;

#[derive(Default)]
struct AbortedOps {
    order: VecDeque<String>,
    set: HashSet<String>,
}

impl AbortedOps {
    fn mark_aborted(&mut self, op_id: &str) {
        if self.set.insert(op_id.to_string()) {
            self.order.push_back(op_id.to_string());
            while self.order.len() > MAX_ABORTED_OPS {
                if let Some(old) = self.order.pop_front() {
                    self.set.remove(&old);
                }
            }
        }
    }

    fn contains(&self, op_id: &str) -> bool {
        self.set.contains(op_id)
    }

    fn clear(&mut self, op_id: &str) {
        if self.set.remove(op_id) {
            self.order.retain(|id| id != op_id);
        }
    }
}

/// Transparent STREAM OAE2 encryption wrapper around any [`StorageBackend`].
#[derive(Clone)]
pub struct CryptoBackend {
    inner: Arc<dyn StorageBackend>,
    cfg: Arc<CryptoConfig>,
    keys: Arc<CryptoKeys>,
    read_pool: BufferPool,
    equal_parts_state: Arc<StdMutex<HashMap<String, EqualPartsCarry>>>,
    seq_align_state: Arc<StdMutex<HashMap<String, SeqAlignState>>>,
    aborted_ops: Arc<StdMutex<AbortedOps>>,
}

impl CryptoBackend {
    pub fn new(
        inner: Arc<dyn StorageBackend>,
        cfg: CryptoConfig,
        keys: CryptoKeys,
    ) -> Result<Self> {
        let read_pool = BufferPool::new(2 * 1024 * 1024, 256 * 1024)?;
        Ok(Self {
            inner,
            cfg: Arc::new(cfg),
            keys: Arc::new(keys),
            read_pool,
            equal_parts_state: Arc::new(StdMutex::new(HashMap::new())),
            seq_align_state: Arc::new(StdMutex::new(HashMap::new())),
            aborted_ops: Arc::new(StdMutex::new(AbortedOps::default())),
        })
    }

    fn is_aborted(&self, op_id: &str) -> bool {
        lock_unpoisoned(&self.aborted_ops).contains(op_id)
    }

    async fn inner_upload_chunk_checked(
        &self,
        op_id: &str,
        inner_op: &OperationRecord,
        chunk: ChunkUpload,
    ) -> Result<ChunkAck> {
        let res = self.inner.upload_chunk(inner_op, chunk).await;
        if self.is_aborted(op_id) {
            return Err(Error::session_expired("upload session aborted"));
        }
        res
    }

    /// Share the caller's global [`BufferPool`] so encrypted range reads participate in
    /// the unified process memory budget instead of holding an isolated extra pool.
    pub fn with_buffer_pool(mut self, pool: BufferPool) -> Self {
        self.read_pool = pool;
        self
    }

    fn inner_requires_equal_parts(&self) -> bool {
        matches!(
            self.inner.capabilities().chunk_alignment,
            ChunkAlignment::MinSizeWithMaxParts {
                require_equal_non_final_parts: true,
                ..
            }
        )
    }

    fn inner_sequential_align(&self) -> Option<u64> {
        let caps = self.inner.capabilities();
        if caps.upload_topology != UploadTopology::Sequential {
            return None;
        }
        match caps.chunk_alignment {
            ChunkAlignment::MultipleOf { align_bytes, .. } if align_bytes > 1 => Some(align_bytes),
            _ => None,
        }
    }

    pub fn inner_backend(&self) -> &Arc<dyn StorageBackend> {
        &self.inner
    }

    fn to_inner_rel(&self, pt_rel: &RelPath) -> Result<RelPath> {
        let enc = encrypt_rel_path(&self.keys, self.cfg.filename_encryption, pt_rel)?;
        Ok(self.cfg.inner_prefix.join_path(&enc))
    }

    fn encrypt_backend_path(&self, path: &BackendPath) -> Result<BackendPath> {
        let enc_nfc = self.to_inner_rel(&path.nfc_path)?;
        Ok(BackendPath::from_rel(enc_nfc).with_node_id(path.node_id.clone()))
    }

    /// Inner-backend view of an [`UploadInit`]: encrypted destination path, ciphertext sizes
    /// and a precondition whose `Existing.size` is the ciphertext size the inner backend sees.
    fn inner_upload_init(&self, init: &UploadInit, planned_chunk_size: u64) -> Result<UploadInit> {
        Ok(UploadInit {
            op_id: init.op_id.clone(),
            dst_path: self.to_inner_rel(&init.dst_path)?,
            existing_node_id: init.existing_node_id.clone(),
            pregenerated_id: init.pregenerated_id.clone(),
            total_size: ciphertext_size(init.total_size)?,
            src_mtime_ns: init.src_mtime_ns,
            planned_chunk_size,
            checksums: vec![],
            precondition: map_precondition_to_ciphertext(&init.precondition)?,
            src_etag: None,
        })
    }

    fn decrypt_entry(&self, mut entry: Entry) -> Result<Entry> {
        let stripped = strip_inner_prefix(&entry.nfc_path, &self.cfg.inner_prefix)?;
        let dec_nfc = decrypt_rel_path(&self.keys, self.cfg.filename_encryption, &stripped)?;
        entry.raw_path = None;
        entry.nfc_path = dec_nfc;
        if entry.kind == EntryKind::File {
            entry.size = plaintext_size(entry.size)?;
            // Underlying ciphertext hash is NOT the plaintext hash!
            entry.checksum = None;
        }
        Ok(entry)
    }

    fn map_op_common(
        &self,
        op: &OperationRecord,
        inner_dst: RelPath,
        pt_total: u64,
    ) -> Result<OperationRecord> {
        let ct_total = ciphertext_size(pt_total)?;
        let mut inner_op = op.clone();
        inner_op.dst_raw_path = inner_dst.as_str().to_string();
        inner_op.dst_nfc_path = inner_dst;
        inner_op.src_version.size = ct_total;
        inner_op.backend_kind = self.inner.kind().to_string();
        inner_op.dst_precondition = map_precondition_to_ciphertext(&op.dst_precondition)?;
        if op.confirmed_offset > 0 {
            inner_op.confirmed_offset = if op.confirmed_offset >= pt_total {
                ct_total
            } else {
                let aligned = (op.confirmed_offset / (PLAINTEXT_CHUNK_LEN as u64))
                    * (PLAINTEXT_CHUNK_LEN as u64);
                ciphertext_offset_for_plaintext(aligned)?
            };
        }
        Ok(inner_op)
    }

    /// Map any journaled operation to the inner backend, including single-shot and
    /// server-side-copy operations that never opened an upload session and therefore carry
    /// no [`CryptoSessionMeta`] (empty `backend_meta`).
    fn map_any_op_to_inner(&self, op: &OperationRecord) -> Result<OperationRecord> {
        if !op.backend_meta.is_empty() {
            return Ok(self.map_op_to_inner(op)?.0);
        }
        let inner_dst = self.to_inner_rel(&op.dst_nfc_path)?;
        self.map_op_common(op, inner_dst, op.src_version.size)
    }

    fn map_op_to_inner(
        &self,
        op: &OperationRecord,
    ) -> Result<(OperationRecord, CryptoSessionMeta)> {
        let meta: CryptoSessionMeta = serde_json::from_str(&op.backend_meta)
            .map_err(|e| Error::protocol(format!("decode CryptoBackend session metadata: {e}")))?;
        let inner_dst = RelPath::parse(&meta.inner_dst_path)?;
        let mut inner_op = self.map_op_common(op, inner_dst, meta.plaintext_total_size)?;
        inner_op.backend_meta = meta.inner_meta.clone();
        inner_op.planned_chunk_size = if meta.equal_non_final_parts {
            equal_ct_part_size(meta.plaintext_chunk_size)?
        } else if let Some(align) = meta.seq_align_bytes {
            let raw = ciphertext_part_len(
                0,
                meta.plaintext_chunk_size.min(meta.plaintext_total_size),
                meta.plaintext_total_size,
            )?;
            ((raw / align).max(1)) * align
        } else {
            ciphertext_part_len(
                0,
                meta.plaintext_chunk_size.min(meta.plaintext_total_size),
                meta.plaintext_total_size,
            )?
        };
        Ok((inner_op, meta))
    }
}

#[async_trait]
impl StorageBackend for CryptoBackend {
    fn name(&self) -> &str {
        &self.cfg.remote_name
    }

    fn kind(&self) -> &'static str {
        "crypt"
    }

    fn endpoint_identity(&self) -> String {
        if self.cfg.inner_prefix.is_root() {
            format!(
                "crypto://{}?inner={}&names={:?}",
                self.cfg.remote_name,
                self.inner.endpoint_identity(),
                self.cfg.filename_encryption
            )
        } else {
            format!(
                "crypto://{}?inner={}/{}&names={:?}",
                self.cfg.remote_name,
                self.inner.endpoint_identity(),
                self.cfg.inner_prefix,
                self.cfg.filename_encryption
            )
        }
    }

    fn capabilities(&self) -> Capabilities {
        let mut caps = self.inner.capabilities();
        let mut force_sequential = false;
        caps.hashes = vec![];
        caps.supports_server_side_copy = false;
        caps.supports_range_read = true;
        // Encrypted object keys do not preserve decrypted RelPath order.
        caps.supports_ordered_utf8_list = false;
        let align = PLAINTEXT_CHUNK_LEN as u64;
        caps.default_chunk_size = (caps.default_chunk_size / align).max(1) * align;
        caps.single_shot_max_bytes = max_plaintext_for_ciphertext(caps.single_shot_max_bytes);
        caps.chunk_alignment = match caps.chunk_alignment {
            ChunkAlignment::Arbitrary => ChunkAlignment::MultipleOf {
                align_bytes: align,
                max_chunk_bytes: None,
            },
            ChunkAlignment::MultipleOf {
                align_bytes: inner_align,
                max_chunk_bytes,
            } => {
                let adjusted_max = max_chunk_bytes.map(|max_c| {
                    let safe_ct = max_c.saturating_sub(inner_align.saturating_mul(2));
                    let safe_pt = (safe_ct.saturating_mul(PLAINTEXT_CHUNK_LEN as u64))
                        / (CIPHERTEXT_CHUNK_LEN as u64);
                    ((safe_pt / align).max(1)) * align
                });
                if let Some(adj) = adjusted_max {
                    caps.default_chunk_size = caps.default_chunk_size.min(adj);
                }
                ChunkAlignment::MultipleOf {
                    align_bytes: align,
                    max_chunk_bytes: adjusted_max,
                }
            }
            ChunkAlignment::MinSizeWithMaxParts {
                min_bytes,
                max_bytes,
                max_parts,
                max_object_bytes,
                require_equal_non_final_parts,
            } => {
                let aligned_min = min_bytes.div_ceil(align) * align;
                let adjusted_max = if require_equal_non_final_parts {
                    force_sequential = true;
                    (max_bytes / (CIPHERTEXT_CHUNK_LEN as u64)) * align
                } else {
                    (max_plaintext_for_ciphertext(max_bytes) / align) * align
                };
                if adjusted_max >= aligned_min {
                    caps.default_chunk_size = caps.default_chunk_size.min(adjusted_max);
                }
                ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: aligned_min,
                    max_bytes: adjusted_max,
                    max_parts: if require_equal_non_final_parts {
                        max_parts.saturating_sub(1).max(1)
                    } else {
                        max_parts
                    },
                    max_object_bytes: max_plaintext_for_ciphertext(max_object_bytes),
                    require_equal_non_final_parts,
                }
            }
            _ => ChunkAlignment::MultipleOf {
                align_bytes: align,
                max_chunk_bytes: None,
            },
        };
        if force_sequential {
            caps.upload_topology = UploadTopology::Sequential;
        }
        caps
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let enc_path = self.encrypt_backend_path(path)?;
        let Some(entry) = self.inner.stat(&enc_path).await? else {
            return Ok(None);
        };
        Ok(Some(self.decrypt_entry(entry)?))
    }

    async fn list_stream(&self, prefix: &RelPath, recursive: bool) -> Result<EntryStream> {
        self.list_with_options(prefix, &ListOptions::new().with_recursive(recursive))
            .await
    }

    async fn list_with_options(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        let enc_prefix = self.to_inner_rel(prefix)?;
        let pass_pruner_down = self.cfg.filename_encryption == FilenameEncryption::Off
            && self.cfg.inner_prefix.is_root();
        let inner_opts = if pass_pruner_down {
            options.clone()
        } else {
            let mut o = ListOptions::new().with_recursive(options.recursive);
            if let Some(d) = options.max_depth {
                o = o.with_max_depth(d);
            }
            o
        };
        let inner_stream = self
            .inner
            .list_with_options(&enc_prefix, &inner_opts)
            .await?;
        let keys = self.keys.clone();
        let mode = self.cfg.filename_encryption;
        let inner_prefix = self.cfg.inner_prefix.clone();
        let post_pruner = if !pass_pruner_down {
            options.dir_pruner().cloned()
        } else {
            None
        };

        let mut dir_cache: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        const DIR_DECRYPT_CACHE_LIMIT: usize = 4096;

        let mapped = inner_stream.filter_map(move |item| {
            let out = match item {
                Err(e) => Some(Err(e)),
                Ok(mut entry) => {
                    let stripped = match strip_inner_prefix(&entry.nfc_path, &inner_prefix) {
                        Ok(s) => s,
                        Err(e) => return std::future::ready(Some(Err(e))),
                    };
                    if stripped.is_root() {
                        return std::future::ready(None);
                    }
                    match crate::filename::decrypt_rel_path_cached(
                        &keys,
                        mode,
                        &stripped,
                        entry.kind == EntryKind::Directory,
                        &mut dir_cache,
                        DIR_DECRYPT_CACHE_LIMIT,
                    ) {
                        Err(e) => Some(Err(e)),
                        Ok(dec_nfc) => {
                            if let Some(ref p) = post_pruner {
                                if entry.kind == EntryKind::Directory && p(&dec_nfc) {
                                    return std::future::ready(None);
                                }
                                let mut anc = dec_nfc.parent();
                                while let Some(dir) = anc {
                                    if dir.is_root() {
                                        break;
                                    }
                                    if p(&dir) {
                                        return std::future::ready(None);
                                    }
                                    anc = dir.parent();
                                }
                            }
                            entry.raw_path = None;
                            entry.nfc_path = dec_nfc;
                            if entry.kind == EntryKind::File {
                                match plaintext_size(entry.size) {
                                    Ok(sz) => {
                                        entry.size = sz;
                                        entry.checksum = None;
                                    }
                                    Err(e) => return std::future::ready(Some(Err(e))),
                                }
                            }
                            Some(Ok(entry))
                        }
                    }
                }
            };
            std::future::ready(out)
        });
        Ok(Box::pin(mapped))
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        let enc = self.to_inner_rel(path)?;
        self.inner.mkdir(&enc).await
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        let enc = self.encrypt_backend_path(path)?;
        self.inner.delete(&enc).await
    }

    async fn delete_batch(&self, paths: &[BackendPath]) -> Result<Vec<(BackendPath, Error)>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut enc_paths = Vec::with_capacity(paths.len());
        let mut map = std::collections::HashMap::with_capacity(paths.len());
        for bp in paths {
            let enc = self.encrypt_backend_path(bp)?;
            map.insert(enc.nfc_path.as_str().to_string(), bp.clone());
            enc_paths.push(enc);
        }
        let inner_failures = self.inner.delete_batch(&enc_paths).await?;
        let mapped = inner_failures
            .into_iter()
            .map(|(enc_bp, err)| {
                let orig = map.get(enc_bp.nfc_path.as_str()).cloned().unwrap_or(enc_bp);
                (orig, err)
            })
            .collect();
        Ok(mapped)
    }

    async fn compute_hash(&self, _path: &BackendPath, _kind: HashKind) -> Result<Option<Checksum>> {
        Ok(None)
    }

    async fn open_read(&self, path: &BackendPath, _range: Option<ByteRange>) -> Result<DataSource> {
        let enc_path = self.encrypt_backend_path(path)?;
        let Some(ct_entry) = self.inner.stat(&enc_path).await? else {
            return Err(Error::not_found(format!(
                "encrypted object `{}` not found",
                path.nfc_path
            )));
        };
        if ct_entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let pt_len = plaintext_size(ct_entry.size)?;

        Ok(DataSource::RemoteRangeReadable(Arc::new(
            CryptoRangeReader {
                inner: self.inner.clone(),
                enc_path,
                ct_len: ct_entry.size,
                ct_entry: Some(ct_entry),
                pt_len,
                keys: self.keys.clone(),
                header: OnceCell::new(),
                pool: self.read_pool.clone(),
            },
        )))
    }

    async fn open_read_entry(
        &self,
        entry: &Entry,
        path: &BackendPath,
        range: Option<ByteRange>,
    ) -> Result<DataSource> {
        if entry.kind != EntryKind::File {
            return Err(Error::invalid_path(format!(
                "cannot open directory `{}` for reading",
                path.nfc_path
            )));
        }
        let mut enc_path = self.encrypt_backend_path(path)?;
        if enc_path.node_id.is_none() {
            enc_path.node_id = entry.node_id.clone();
        }
        let ct_len = ciphertext_size(entry.size)?;
        let ct_entry = Entry {
            node_id: enc_path.node_id.clone(),
            parent_id: entry.parent_id.clone(),
            raw_path: enc_path.raw_path.clone(),
            nfc_path: enc_path.nfc_path.clone(),
            kind: EntryKind::File,
            size: ct_len,
            mtime_ns: entry.mtime_ns,
            ctime_ns: entry.ctime_ns,
            etag: entry.etag.clone(),
            checksum: None,
        };

        // Full-object read (single-shot transfers & full `cat`): fetch header + all
        // ciphertext chunks in ONE inner request while preserving ETag version pinning.
        if let Some(r) = range
            && r.offset == 0
            && r.len == entry.size
        {
            let stream = reader::open_full_decrypt_stream(
                &self.inner,
                &ct_entry,
                &enc_path,
                entry.size,
                ct_len,
                self.keys.data_key,
                &self.read_pool,
            )
            .await?;
            return Ok(DataSource::SequentialStream {
                stream,
                total_len: Some(entry.size),
            });
        }

        Ok(DataSource::RemoteRangeReadable(Arc::new(
            CryptoRangeReader {
                inner: self.inner.clone(),
                enc_path,
                ct_entry: Some(ct_entry),
                ct_len,
                pt_len: entry.size,
                keys: self.keys.clone(),
                header: OnceCell::new(),
                pool: self.read_pool.clone(),
            },
        )))
    }

    async fn put_single_shot(&self, init: &UploadInit, body: ByteStream) -> Result<Entry> {
        let header = StreamHeader::generate_random();
        let ct_size = ciphertext_size(init.total_size)?;
        let inner_init = self.inner_upload_init(init, ct_size.max(1))?;

        let enc_stream = build_fast_encrypt_stream(
            body,
            self.keys.data_key,
            header,
            0,
            init.total_size,
            true,
            true,
        );
        let entry = self.inner.put_single_shot(&inner_init, enc_stream).await?;
        self.decrypt_entry(entry)
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        if init.total_size > 0
            && !init
                .planned_chunk_size
                .is_multiple_of(PLAINTEXT_CHUNK_LEN as u64)
        {
            return Err(Error::invalid_geometry(format!(
                "crypto planned_chunk_size ({}) must be a multiple of {PLAINTEXT_CHUNK_LEN}",
                init.planned_chunk_size
            )));
        }
        let enc_dst = self.to_inner_rel(&init.dst_path)?;
        let header = StreamHeader::generate_random();
        let equal_non_final_parts = self.inner_requires_equal_parts();
        let seq_align_bytes = if equal_non_final_parts {
            None
        } else {
            self.inner_sequential_align()
        };
        let ct_planned_chunk = if equal_non_final_parts {
            equal_ct_part_size(init.planned_chunk_size)?
        } else if let Some(align) = seq_align_bytes {
            let raw = ciphertext_part_len(
                0,
                init.planned_chunk_size.min(init.total_size),
                init.total_size,
            )?;
            ((raw / align).max(1)) * align
        } else {
            ciphertext_part_len(
                0,
                init.planned_chunk_size.min(init.total_size),
                init.total_size,
            )?
        };

        let inner_init = self.inner_upload_init(init, ct_planned_chunk)?;

        let opened = self.inner.begin_upload(&inner_init).await?;
        {
            let mut aborted = lock_unpoisoned(&self.aborted_ops);
            aborted.clear(&init.op_id);
            if equal_non_final_parts {
                lock_unpoisoned(&self.equal_parts_state)
                    .insert(init.op_id.clone(), EqualPartsCarry::default());
            }
            if seq_align_bytes.is_some() {
                lock_unpoisoned(&self.seq_align_state)
                    .insert(init.op_id.clone(), SeqAlignState::default());
            }
        }
        let meta = CryptoSessionMeta {
            nonce_prefix_hex: hex::encode(header.nonce_prefix),
            plaintext_total_size: init.total_size,
            plaintext_chunk_size: init.planned_chunk_size,
            inner_meta: opened.backend_meta,
            inner_dst_path: enc_dst.as_str().to_string(),
            equal_non_final_parts,
            seq_align_bytes,
        };
        let backend_meta = serde_json::to_string(&meta)
            .map_err(|e| Error::protocol(format!("encode crypto session meta: {e}")))?;

        Ok(UploadSessionInit {
            session_token: opened.session_token,
            backend_meta,
            remote_op_id: opened.remote_op_id,
            expires_at_unix_secs: opened.expires_at_unix_secs,
        })
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let (inner_op, meta) = self.map_op_to_inner(op)?;
        if self.is_aborted(&op.op_id) {
            return Ok(UploadProgress::Expired);
        }
        if meta.equal_non_final_parts {
            let has_state = lock_unpoisoned(&self.equal_parts_state).contains_key(&op.op_id);
            if !has_state {
                let _ = self.inner.abort_upload(&inner_op).await;
                return Ok(UploadProgress::Expired);
            }
            let aligned = if op.confirmed_offset >= meta.plaintext_total_size {
                meta.plaintext_total_size
            } else {
                (op.confirmed_offset / (PLAINTEXT_CHUNK_LEN as u64)) * (PLAINTEXT_CHUNK_LEN as u64)
            };
            return Ok(UploadProgress::SequentialOffset(aligned));
        }
        match self.inner.query_upload(&inner_op).await? {
            UploadProgress::SequentialOffset(ct_off) => {
                if meta.seq_align_bytes.is_some() {
                    let (pt_off, skip_ct) =
                        map_sequential_ct_offset(ct_off, meta.plaintext_total_size);
                    {
                        let aborted = lock_unpoisoned(&self.aborted_ops);
                        if aborted.contains(&op.op_id) {
                            return Ok(UploadProgress::Expired);
                        }
                        lock_unpoisoned(&self.seq_align_state).insert(
                            op.op_id.clone(),
                            SeqAlignState {
                                carry: Vec::new(),
                                inner_offset: ct_off,
                                skip_leading_ct: skip_ct,
                            },
                        );
                    }
                    return Ok(UploadProgress::SequentialOffset(pt_off));
                }
                if self.is_aborted(&op.op_id) {
                    return Ok(UploadProgress::Expired);
                }
                Ok(UploadProgress::SequentialOffset(
                    plaintext_offset_from_ciphertext(ct_off, meta.plaintext_total_size),
                ))
            }
            UploadProgress::CompletedParts(parts) => {
                let mapped = parts
                    .into_iter()
                    .map(|mut p| {
                        let pt_off = u64::from(p.part_number.saturating_sub(1))
                            .saturating_mul(meta.plaintext_chunk_size);
                        let pt_len = meta
                            .plaintext_total_size
                            .saturating_sub(pt_off)
                            .min(meta.plaintext_chunk_size);
                        p.offset = pt_off;
                        p.length = pt_len;
                        p
                    })
                    .collect();
                Ok(UploadProgress::CompletedParts(mapped))
            }
            UploadProgress::AlreadyCompleted(entry) => {
                lock_unpoisoned(&self.seq_align_state).remove(&op.op_id);
                Ok(UploadProgress::AlreadyCompleted(self.decrypt_entry(entry)?))
            }
            UploadProgress::Expired => {
                lock_unpoisoned(&self.seq_align_state).remove(&op.op_id);
                Ok(UploadProgress::Expired)
            }
            other => Ok(other),
        }
    }

    async fn upload_chunk(&self, op: &OperationRecord, chunk: ChunkUpload) -> Result<ChunkAck> {
        let (inner_op, meta) = self.map_op_to_inner(op)?;
        if self.is_aborted(&op.op_id) {
            return Err(Error::session_expired("upload session aborted"));
        }
        if chunk.offset > 0 && !chunk.offset.is_multiple_of(PLAINTEXT_CHUNK_LEN as u64) {
            return Err(Error::invalid_geometry(format!(
                "crypto upload_chunk offset ({}) must be a multiple of {PLAINTEXT_CHUNK_LEN}",
                chunk.offset
            )));
        }
        let end_pt = chunk
            .offset
            .checked_add(chunk.len)
            .ok_or_else(|| Error::invalid_geometry("chunk offset + len overflow"))?;
        let is_final = end_pt == chunk.total_size;
        if !is_final && !chunk.len.is_multiple_of(PLAINTEXT_CHUNK_LEN as u64) {
            return Err(Error::invalid_geometry(format!(
                "non-final crypto chunk length ({}) must be a multiple of {PLAINTEXT_CHUNK_LEN}",
                chunk.len
            )));
        }

        let raw_prefix = hex::decode(&meta.nonce_prefix_hex)
            .map_err(|e| Error::protocol(format!("decode nonce_prefix: {e}")))?;
        let mut nonce_prefix = [0u8; 16];
        if raw_prefix.len() != 16 {
            return Err(Error::protocol("invalid nonce_prefix length"));
        }
        nonce_prefix.copy_from_slice(&raw_prefix);
        let header = StreamHeader::from_nonce_prefix(nonce_prefix);

        let ct_offset = ciphertext_offset_for_plaintext(chunk.offset)?;
        let ct_len = ciphertext_part_len(chunk.offset, chunk.len, chunk.total_size)?;
        let ct_total = ciphertext_size(chunk.total_size)?;
        let start_chunk_idx = chunk.offset / (PLAINTEXT_CHUNK_LEN as u64);
        let emit_header = chunk.offset == 0;

        let enc_stream = build_fast_encrypt_stream(
            chunk.body,
            self.keys.data_key,
            header,
            start_chunk_idx,
            chunk.len,
            emit_header,
            is_final,
        );

        if let Some(align) = meta.seq_align_bytes {
            let (prev_carry, inner_offset, skip_leading_ct) = {
                let aborted = lock_unpoisoned(&self.aborted_ops);
                if aborted.contains(&op.op_id) {
                    return Err(Error::session_expired("upload session aborted"));
                }
                let mut states = lock_unpoisoned(&self.seq_align_state);
                let st = states.entry(op.op_id.clone()).or_default();
                (st.carry.clone(), st.inner_offset, st.skip_leading_ct)
            };
            let ct_after_skip = ct_len
                .checked_sub(skip_leading_ct)
                .ok_or_else(|| Error::protocol("skip_leading_ct exceeds chunk ciphertext len"))?;
            let enc_trimmed = skip_ciphertext_prefix(enc_stream, skip_leading_ct);
            let avail = (prev_carry.len() as u64)
                .checked_add(ct_after_skip)
                .ok_or_else(|| Error::invalid_geometry("seq-align avail overflow"))?;

            if is_final {
                let tail_buf = Arc::new(StdMutex::new(Vec::new()));
                let part_stream = split_ciphertext_stream(prev_carry, enc_trimmed, avail, tail_buf);
                let ack = self
                    .inner_upload_chunk_checked(
                        &op.op_id,
                        &inner_op,
                        ChunkUpload::new(
                            chunk.part_number,
                            inner_offset,
                            avail,
                            ct_total,
                            part_stream,
                        ),
                    )
                    .await?;
                {
                    let aborted = lock_unpoisoned(&self.aborted_ops);
                    lock_unpoisoned(&self.seq_align_state).remove(&op.op_id);
                    if aborted.contains(&op.op_id) {
                        return Err(Error::session_expired("upload session aborted"));
                    }
                }
                let completed = match ack.completed {
                    Some(e) => Some(self.decrypt_entry(e)?),
                    None => None,
                };
                return Ok(ChunkAck {
                    next_offset: Some(chunk.total_size),
                    etag: ack.etag,
                    completed,
                    checksum: ack.checksum,
                });
            }

            if avail < align {
                let mut carry = prev_carry;
                let mut s = enc_trimmed;
                while let Some(item) = s.next().await {
                    if self.is_aborted(&op.op_id) {
                        return Err(Error::session_expired("upload session aborted"));
                    }
                    carry.extend_from_slice(&item?);
                }
                {
                    let aborted = lock_unpoisoned(&self.aborted_ops);
                    if aborted.contains(&op.op_id) {
                        return Err(Error::session_expired("upload session aborted"));
                    }
                    let mut states = lock_unpoisoned(&self.seq_align_state);
                    let st = states.get_mut(&op.op_id).ok_or_else(|| {
                        Error::session_expired(
                            "seq-align upload session state removed while in flight",
                        )
                    })?;
                    st.carry = carry;
                    st.inner_offset = inner_offset;
                    st.skip_leading_ct = 0;
                }
                return Ok(ChunkAck {
                    next_offset: Some(chunk.offset + chunk.len),
                    etag: None,
                    completed: None,
                    checksum: None,
                });
            }

            let emit_len = (avail / align) * align;
            let expected_tail = (avail - emit_len) as usize;
            let tail_buf = Arc::new(StdMutex::new(Vec::with_capacity(expected_tail)));
            let part_stream =
                split_ciphertext_stream(prev_carry, enc_trimmed, emit_len, tail_buf.clone());

            let ack = self
                .inner_upload_chunk_checked(
                    &op.op_id,
                    &inner_op,
                    ChunkUpload::new(
                        chunk.part_number,
                        inner_offset,
                        emit_len,
                        ct_total,
                        part_stream,
                    ),
                )
                .await?;
            let tail = std::mem::take(&mut *lock_unpoisoned(&tail_buf));
            if tail.len() != expected_tail {
                return Err(Error::protocol(format!(
                    "seq-align carry mismatch: got {} bytes, expected {expected_tail}",
                    tail.len()
                )));
            }

            let expected_next_ct = inner_offset + emit_len;
            let server_next_ct = ack.next_offset.unwrap_or(expected_next_ct);
            if server_next_ct != expected_next_ct {
                let (pt_off, skip_ct) = map_sequential_ct_offset(server_next_ct, chunk.total_size);
                {
                    let aborted = lock_unpoisoned(&self.aborted_ops);
                    if aborted.contains(&op.op_id) {
                        return Err(Error::session_expired("upload session aborted"));
                    }
                    let mut states = lock_unpoisoned(&self.seq_align_state);
                    let st = states.get_mut(&op.op_id).ok_or_else(|| {
                        Error::session_expired(
                            "seq-align upload session state removed while in flight",
                        )
                    })?;
                    *st = SeqAlignState {
                        carry: Vec::new(),
                        inner_offset: server_next_ct,
                        skip_leading_ct: skip_ct,
                    };
                }
                return Ok(ChunkAck {
                    next_offset: Some(pt_off),
                    etag: ack.etag,
                    completed: None,
                    checksum: ack.checksum,
                });
            }

            {
                let aborted = lock_unpoisoned(&self.aborted_ops);
                if aborted.contains(&op.op_id) {
                    return Err(Error::session_expired("upload session aborted"));
                }
                let mut states = lock_unpoisoned(&self.seq_align_state);
                let st = states.get_mut(&op.op_id).ok_or_else(|| {
                    Error::session_expired("seq-align upload session state removed while in flight")
                })?;
                *st = SeqAlignState {
                    carry: tail,
                    inner_offset: expected_next_ct,
                    skip_leading_ct: 0,
                };
            }
            return Ok(ChunkAck {
                next_offset: Some(chunk.offset + chunk.len),
                etag: ack.etag,
                completed: None,
                checksum: ack.checksum,
            });
        }

        if meta.equal_non_final_parts {
            let ct_part_size = equal_ct_part_size(meta.plaintext_chunk_size)?;
            let prev_carry = {
                let aborted = lock_unpoisoned(&self.aborted_ops);
                if aborted.contains(&op.op_id) {
                    return Err(Error::session_expired("upload session aborted"));
                }
                let states = lock_unpoisoned(&self.equal_parts_state);
                let st = states.get(&op.op_id).ok_or_else(|| {
                    Error::session_expired("missing equal-parts carry state; restarting")
                })?;
                if chunk.offset == 0 {
                    Vec::new()
                } else if st.carry.len() == HEADER_LEN {
                    st.carry.clone()
                } else {
                    return Err(Error::session_expired(
                        "missing 32-byte equal-parts carry; restarting",
                    ));
                }
            };
            let total_emit = (prev_carry.len() as u64)
                .checked_add(ct_len)
                .ok_or_else(|| Error::invalid_geometry("equal-part emit len overflow"))?;
            let part_offset = u64::from(chunk.part_number.saturating_sub(1))
                .checked_mul(ct_part_size)
                .ok_or_else(|| Error::invalid_geometry("equal-part offset overflow"))?;

            if !is_final || total_emit > ct_part_size {
                let tail_buf = Arc::new(StdMutex::new(Vec::with_capacity(HEADER_LEN)));
                let part_stream =
                    split_ciphertext_stream(prev_carry, enc_stream, ct_part_size, tail_buf.clone());
                let ack = self
                    .inner_upload_chunk_checked(
                        &op.op_id,
                        &inner_op,
                        ChunkUpload::new(
                            chunk.part_number,
                            part_offset,
                            ct_part_size,
                            ct_total,
                            part_stream,
                        ),
                    )
                    .await?;
                let etag = ack.etag.ok_or_else(|| {
                    Error::protocol(format!(
                        "inner equal-part upload missing ETag for part {}",
                        chunk.part_number
                    ))
                })?;
                let tail = std::mem::take(&mut *lock_unpoisoned(&tail_buf));
                let expected_tail = (total_emit - ct_part_size) as usize;
                if tail.len() != expected_tail {
                    return Err(Error::protocol(format!(
                        "equal-part carry mismatch: got {} bytes, expected {expected_tail}",
                        tail.len()
                    )));
                }

                let mut new_parts = vec![CompletedPart {
                    part_number: chunk.part_number,
                    offset: part_offset,
                    length: ct_part_size,
                    etag,
                    checksum: ack.checksum,
                }];

                let next_carry = if is_final {
                    let tail_len = tail.len() as u64;
                    let tail_pn = chunk.part_number + 1;
                    let tail_offset = part_offset + ct_part_size;
                    let tail_stream: ByteStream =
                        Box::pin(futures::stream::once(async move { Ok(Bytes::from(tail)) }));
                    let tail_ack = self
                        .inner_upload_chunk_checked(
                            &op.op_id,
                            &inner_op,
                            ChunkUpload::new(tail_pn, tail_offset, tail_len, ct_total, tail_stream),
                        )
                        .await?;
                    let tail_etag = tail_ack.etag.ok_or_else(|| {
                        Error::protocol(format!(
                            "inner equal-part upload missing ETag for final tail part {tail_pn}"
                        ))
                    })?;
                    new_parts.push(CompletedPart {
                        part_number: tail_pn,
                        offset: tail_offset,
                        length: tail_len,
                        etag: tail_etag,
                        checksum: tail_ack.checksum,
                    });
                    Vec::new()
                } else {
                    tail
                };

                {
                    let aborted = lock_unpoisoned(&self.aborted_ops);
                    if aborted.contains(&op.op_id) {
                        return Err(Error::session_expired("upload session aborted"));
                    }
                    let mut states = lock_unpoisoned(&self.equal_parts_state);
                    let st = states.get_mut(&op.op_id).ok_or_else(|| {
                        Error::session_expired(
                            "equal-parts upload session state removed while in flight",
                        )
                    })?;
                    st.carry = next_carry;
                    for np in new_parts {
                        if let Some(existing) = st
                            .completed_parts
                            .iter_mut()
                            .find(|p| p.part_number == np.part_number)
                        {
                            *existing = np;
                        } else {
                            st.completed_parts.push(np);
                        }
                    }
                }
            } else {
                let tail_buf = Arc::new(StdMutex::new(Vec::new()));
                let part_stream =
                    split_ciphertext_stream(prev_carry, enc_stream, total_emit, tail_buf);
                let ack = self
                    .inner_upload_chunk_checked(
                        &op.op_id,
                        &inner_op,
                        ChunkUpload::new(
                            chunk.part_number,
                            part_offset,
                            total_emit,
                            ct_total,
                            part_stream,
                        ),
                    )
                    .await?;
                let etag = ack.etag.ok_or_else(|| {
                    Error::protocol(format!(
                        "inner equal-part upload missing ETag for final part {}",
                        chunk.part_number
                    ))
                })?;
                let cp = CompletedPart {
                    part_number: chunk.part_number,
                    offset: part_offset,
                    length: total_emit,
                    etag,
                    checksum: ack.checksum,
                };
                let aborted = lock_unpoisoned(&self.aborted_ops);
                if aborted.contains(&op.op_id) {
                    return Err(Error::session_expired("upload session aborted"));
                }
                let mut states = lock_unpoisoned(&self.equal_parts_state);
                let st = states.get_mut(&op.op_id).ok_or_else(|| {
                    Error::session_expired(
                        "equal-parts upload session state removed while in flight",
                    )
                })?;
                st.carry.clear();
                if let Some(existing) = st
                    .completed_parts
                    .iter_mut()
                    .find(|p| p.part_number == cp.part_number)
                {
                    *existing = cp;
                } else {
                    st.completed_parts.push(cp);
                }
            }

            return Ok(ChunkAck {
                next_offset: Some(chunk.offset + chunk.len),
                etag: None,
                completed: None,
                checksum: None,
            });
        }

        let ack = self
            .inner_upload_chunk_checked(
                &op.op_id,
                &inner_op,
                ChunkUpload::new(chunk.part_number, ct_offset, ct_len, ct_total, enc_stream),
            )
            .await?;

        let completed = match ack.completed {
            Some(e) => Some(self.decrypt_entry(e)?),
            None => None,
        };
        let next_offset = ack
            .next_offset
            .map(|ct_off| plaintext_offset_from_ciphertext(ct_off, chunk.total_size));

        Ok(ChunkAck {
            next_offset,
            etag: ack.etag,
            completed,
            checksum: ack.checksum,
        })
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        let (inner_op, meta) = self.map_op_to_inner(op)?;
        if self.is_aborted(&op.op_id) {
            return Err(Error::session_expired("upload session aborted"));
        }
        let mapped_parts: Vec<CompletedPart> = if meta.equal_non_final_parts {
            let mut completed_parts = {
                let states = lock_unpoisoned(&self.equal_parts_state);
                let st = states.get(&op.op_id).ok_or_else(|| {
                    Error::session_expired("missing equal-parts manifest during finish_upload")
                })?;
                st.completed_parts.clone()
            };
            completed_parts.sort_by_key(|p| p.part_number);
            completed_parts
        } else {
            parts
                .iter()
                .map(|p| {
                    let ct_off = ciphertext_offset_for_plaintext(p.offset).unwrap_or(0);
                    let ct_len = ciphertext_part_len(p.offset, p.length, meta.plaintext_total_size)
                        .unwrap_or(p.length);
                    CompletedPart {
                        part_number: p.part_number,
                        offset: ct_off,
                        length: ct_len,
                        etag: p.etag.clone(),
                        checksum: p.checksum.clone(),
                    }
                })
                .collect()
        };
        let entry = self.inner.finish_upload(&inner_op, &mapped_parts).await?;
        {
            let mut aborted = lock_unpoisoned(&self.aborted_ops);
            aborted.clear(&op.op_id);
            lock_unpoisoned(&self.equal_parts_state).remove(&op.op_id);
            lock_unpoisoned(&self.seq_align_state).remove(&op.op_id);
        }
        self.decrypt_entry(entry)
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        {
            let mut aborted = lock_unpoisoned(&self.aborted_ops);
            aborted.mark_aborted(&op.op_id);
            lock_unpoisoned(&self.equal_parts_state).remove(&op.op_id);
            lock_unpoisoned(&self.seq_align_state).remove(&op.op_id);
        }
        let inner_op = self.map_any_op_to_inner(op)?;
        self.inner.abort_upload(&inner_op).await
    }

    async fn prepare_operation_id(&self, init: &UploadInit) -> Result<Option<NodeId>> {
        // The ID is for the encrypted inner object; geometry fields are irrelevant here.
        let inner_init = self.inner_upload_init(init, init.planned_chunk_size)?;
        self.inner.prepare_operation_id(&inner_init).await
    }

    fn defers_durable_writes(&self) -> bool {
        self.inner.defers_durable_writes()
    }

    fn retry_quota(&self) -> Option<Arc<dyn rship_core::engine::RetryQuota>> {
        self.inner.retry_quota()
    }

    async fn flush_durable_writes(&self) -> Result<()> {
        self.inner.flush_durable_writes().await
    }

    async fn sync_durable_file(&self, path: &BackendPath) -> Result<()> {
        let enc = self.encrypt_backend_path(path)?;
        self.inner.sync_durable_file(&enc).await
    }

    async fn about(&self) -> Result<Option<rship_core::types::StorageQuota>> {
        self.inner.about().await
    }

    async fn list_incomplete_uploads(
        &self,
        prefix: &RelPath,
    ) -> Result<Vec<rship_core::backend::IncompleteUpload>> {
        let inner_prefix = self.to_inner_rel(prefix)?;
        self.inner.list_incomplete_uploads(&inner_prefix).await
    }

    async fn abort_incomplete_upload(
        &self,
        upload: &rship_core::backend::IncompleteUpload,
    ) -> Result<()> {
        self.inner.abort_incomplete_upload(upload).await
    }

    async fn rename(&self, path: &BackendPath, new_name: &str) -> Result<Entry> {
        if new_name.is_empty() || new_name.contains('/') || new_name.contains('\\') {
            return Err(Error::invalid_path(format!(
                "invalid rename target name `{new_name}`"
            )));
        }
        let enc_path = self.encrypt_backend_path(path)?;
        let enc_new_rel = encrypt_rel_path(
            &self.keys,
            self.cfg.filename_encryption,
            &RelPath::parse(new_name)?,
        )?;
        let entry = self.inner.rename(&enc_path, enc_new_rel.as_str()).await?;
        self.decrypt_entry(entry)
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        let inner_op = self.map_any_op_to_inner(op)?;
        match self.inner.reconcile_operation(&inner_op).await? {
            ReconcileOutcome::Committed(e) => {
                Ok(ReconcileOutcome::Committed(self.decrypt_entry(e)?))
            }
            ReconcileOutcome::NotCommitted => Ok(ReconcileOutcome::NotCommitted),
            ReconcileOutcome::Ambiguous(m) => Ok(ReconcileOutcome::Ambiguous(m)),
            other => Ok(other),
        }
    }
}
