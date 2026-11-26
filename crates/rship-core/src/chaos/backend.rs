use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::faults::{ChaosOp, InjectedFault, chaos_checksum_mismatch};
use super::{FailpointCoordinator, FaultSchedule};
use crate::backend::{
    BackendPath, ChunkAck, ChunkUpload, CompletedPart, EntryStream, ReconcileOutcome,
    StorageBackend, UploadInit, UploadProgress, UploadSessionInit,
};
use crate::error::{Error, Result};
use crate::path::RelPath;
use crate::source::{ByteStream, DataSource, MemorySource};
use crate::state::OperationRecord;
use crate::types::{
    ByteRange, Capabilities, Checksum, ChunkAlignment, Entry, EntryKind, HashKind, NodeId,
    UploadTopology,
};

#[derive(Debug, Clone)]
struct StoredItem {
    entry: Entry,
    data: Vec<u8>,
    op_id: Option<String>,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    dst_path: RelPath,
    op_id: String,
    src_mtime_ns: i64,
    total_size: u64,
    buf: Vec<u8>,
    parts: BTreeMap<u32, (u64, Vec<u8>, String)>,
}

#[derive(Debug)]
struct ChaosInner {
    items: Vec<StoredItem>,
    sessions: HashMap<String, ActiveSession>,
    faults: FaultSchedule,
    failpoints: Option<FailpointCoordinator>,
    read_counts: HashMap<String, u32>,
    next_id: u64,
    upload_requests: u64,
    put_single_shot_calls: u64,
    begin_upload_calls: u64,
    upload_chunk_calls: u64,
    finish_upload_calls: u64,
    bytes_uploaded: u64,
}

/// `(gated destination path, semaphore)` for [`ChaosBackend::set_put_gate`].
type PutGate = (String, Arc<tokio::sync::Semaphore>);

#[derive(Debug, Clone)]
pub struct ChaosBackend {
    name: String,
    caps: Capabilities,
    inner: Arc<Mutex<ChaosInner>>,
    hide_checksums: bool,
    crc32c_checksums: bool,
    delete_gate: Arc<Mutex<Option<Arc<tokio::sync::Semaphore>>>>,
    put_gate: Arc<Mutex<Option<PutGate>>>,
    retry_quota: Arc<Mutex<Option<Arc<dyn crate::engine::RetryQuota>>>>,
}

impl ChaosBackend {
    pub fn new(name: impl Into<String>, caps: Capabilities) -> Self {
        Self {
            name: name.into(),
            caps,
            inner: Arc::new(Mutex::new(ChaosInner {
                items: Vec::new(),
                sessions: HashMap::new(),
                faults: FaultSchedule::default(),
                failpoints: None,
                read_counts: HashMap::new(),
                next_id: 1,
                upload_requests: 0,
                put_single_shot_calls: 0,
                begin_upload_calls: 0,
                upload_chunk_calls: 0,
                finish_upload_calls: 0,
                bytes_uploaded: 0,
            })),
            hide_checksums: false,
            crc32c_checksums: false,
            delete_gate: Arc::new(Mutex::new(None)),
            put_gate: Arc::new(Mutex::new(None)),
            retry_quota: Arc::new(Mutex::new(None)),
        }
    }

    /// Strip content checksums from every entry this backend returns (listing, `stat`,
    /// and committed uploads), like a local filesystem or WebDAV server that exposes only
    /// size and mtime.
    pub fn without_listing_checksums(mut self) -> Self {
        self.hide_checksums = true;
        self
    }

    /// Advertise a full-object CRC-32C (instead of SHA-256) on files inserted with
    /// [`Self::insert_file`], like GCS composite objects or S3 full-object CRC32C.
    pub fn with_crc32c_checksums(mut self) -> Self {
        self.crc32c_checksums = true;
        self
    }

    /// Make every `delete` wait for one permit of `gate` (a permit is returned after each
    /// delete). `None` removes the gate.
    pub fn set_delete_gate(&self, gate: Option<Arc<tokio::sync::Semaphore>>) {
        *self.delete_gate.lock().unwrap() = gate;
    }

    /// Make `put_single_shot` of `path` wait for one permit of `gate` before committing.
    pub fn set_put_gate(&self, gate: Option<(String, Arc<tokio::sync::Semaphore>)>) {
        *self.put_gate.lock().unwrap() = gate;
    }

    /// Expose `quota` through [`StorageBackend::retry_quota`] (a per-remote shared budget).
    pub fn set_retry_quota(&self, quota: Option<Arc<dyn crate::engine::RetryQuota>>) {
        *self.retry_quota.lock().unwrap() = quota;
    }

    fn present(&self, mut entry: Entry) -> Entry {
        if self.hide_checksums {
            entry.checksum = None;
        }
        entry
    }

    pub fn sequential_gdrive_like(name: impl Into<String>, chunk_size: u64) -> Self {
        Self::new(
            name,
            Capabilities {
                hashes: vec![HashKind::Sha256],
                mtime_granularity: Duration::from_millis(1),
                can_set_mtime: true,
                upload_topology: UploadTopology::Sequential,
                chunk_alignment: ChunkAlignment::MultipleOf {
                    align_bytes: 256 * 1024,
                    max_chunk_bytes: None,
                },
                single_shot_max_bytes: 16 * 1024,
                default_chunk_size: chunk_size,
                allows_duplicate_names: true,
                case_sensitive: true,
                supports_node_id: true,
                supports_range_read: true,
                supports_atomic_single_read: false,
                supports_version_pinned_read: false,
                supports_ordered_utf8_list: false,
                supports_conditional_write: false,
                supports_change_feed: true,
                supports_server_side_copy: true,
                default_write_qps: None,
            },
        )
    }

    pub fn parallel_s3_like(name: impl Into<String>, part_size: u64) -> Self {
        Self::new(
            name,
            Capabilities {
                hashes: vec![HashKind::Sha256],
                mtime_granularity: Duration::from_secs(1),
                can_set_mtime: false,
                upload_topology: UploadTopology::ParallelParts,
                chunk_alignment: ChunkAlignment::MinSizeWithMaxParts {
                    min_bytes: part_size,
                    max_bytes: 5 * 1024 * 1024 * 1024,
                    max_parts: 10_000,
                    max_object_bytes: 5 * 1024 * 1024 * 1024 * 1024,
                    require_equal_non_final_parts: true,
                },
                single_shot_max_bytes: 16 * 1024,
                default_chunk_size: part_size,
                allows_duplicate_names: false,
                case_sensitive: true,
                supports_node_id: false,
                supports_range_read: true,
                supports_atomic_single_read: true,
                supports_version_pinned_read: true,
                supports_ordered_utf8_list: false,
                supports_conditional_write: true,
                supports_change_feed: false,
                supports_server_side_copy: true,
                default_write_qps: None,
            },
        )
    }

    pub fn set_faults(&self, faults: FaultSchedule) {
        self.inner.lock().unwrap().faults = faults;
    }

    pub fn set_failpoints(&self, failpoints: Option<FailpointCoordinator>) {
        self.inner.lock().unwrap().failpoints = failpoints;
    }

    pub fn with_caps(mut self, f: impl FnOnce(&mut Capabilities)) -> Self {
        f(&mut self.caps);
        self
    }

    pub fn upload_request_count(&self) -> u64 {
        self.inner.lock().unwrap().upload_requests
    }

    pub fn put_single_shot_calls(&self) -> u64 {
        self.inner.lock().unwrap().put_single_shot_calls
    }

    pub fn begin_upload_calls(&self) -> u64 {
        self.inner.lock().unwrap().begin_upload_calls
    }

    pub fn upload_chunk_calls(&self) -> u64 {
        self.inner.lock().unwrap().upload_chunk_calls
    }

    pub fn finish_upload_calls(&self) -> u64 {
        self.inner.lock().unwrap().finish_upload_calls
    }

    pub fn bytes_uploaded(&self) -> u64 {
        self.inner.lock().unwrap().bytes_uploaded
    }

    /// Randomized faults injected so far by this backend's seeded [`FaultSchedule`].
    pub fn random_faults_injected(&self) -> u32 {
        self.inner.lock().unwrap().faults.random_faults_injected()
    }

    pub fn reset_upload_metrics(&self) {
        let mut g = self.inner.lock().unwrap();
        g.upload_requests = 0;
        g.put_single_shot_calls = 0;
        g.begin_upload_calls = 0;
        g.upload_chunk_calls = 0;
        g.finish_upload_calls = 0;
        g.bytes_uploaded = 0;
    }

    pub fn active_session_count(&self) -> usize {
        self.inner.lock().unwrap().sessions.len()
    }

    pub fn all_files(&self) -> BTreeMap<String, Vec<u8>> {
        let g = self.inner.lock().unwrap();
        g.items
            .iter()
            .filter(|i| i.entry.kind == EntryKind::File)
            .map(|i| (i.entry.nfc_path.as_str().to_string(), i.data.clone()))
            .collect()
    }

    pub fn insert_file(&self, raw_path: &str, data: Vec<u8>, mtime_ns: i64) {
        let mut g = self.inner.lock().unwrap();
        let id = g.next_id;
        g.next_id += 1;
        let hash = sha256_hex(&data);
        let nfc_path = RelPath::parse(raw_path).unwrap();
        let entry = Entry {
            node_id: Some(NodeId(format!("n-{id}"))),
            parent_id: None,
            raw_path: crate::types::raw_path_override(&nfc_path, raw_path),
            nfc_path,
            kind: EntryKind::File,
            size: data.len() as u64,
            mtime_ns,
            ctime_ns: Some(mtime_ns),
            etag: Some(format!("\"{}\"", &hash[..16])),
            checksum: Some(if self.crc32c_checksums {
                Checksum {
                    kind: HashKind::Crc32c,
                    hex: crate::crc32c::crc32c_hex(crate::crc32c::crc32c(&data)),
                }
            } else {
                Checksum {
                    kind: HashKind::Sha256,
                    hex: hash,
                }
            }),
        };
        g.items.push(StoredItem {
            entry,
            data,
            op_id: None,
        });
    }

    pub fn get_file_bytes(&self, nfc_path: &str) -> Option<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        g.items
            .iter()
            .find(|i| i.entry.nfc_path.as_str() == nfc_path && i.entry.kind == EntryKind::File)
            .map(|i| i.data.clone())
    }

    pub fn file_count(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .items
            .iter()
            .filter(|i| i.entry.kind == EntryKind::File)
            .count()
    }
}

#[async_trait]
impl StorageBackend for ChaosBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "chaos"
    }

    fn endpoint_identity(&self) -> String {
        format!("chaos://{}", self.name)
    }

    fn capabilities(&self) -> Capabilities {
        self.caps.clone()
    }

    fn retry_quota(&self) -> Option<Arc<dyn crate::engine::RetryQuota>> {
        self.retry_quota.lock().unwrap().clone()
    }

    async fn stat(&self, path: &BackendPath) -> Result<Option<Entry>> {
        let mut g = self.inner.lock().unwrap();
        if let Some(fault) = g.faults.next_fault(ChaosOp::Stat) {
            return Err(fault.into_error());
        }
        Ok(g.items
            .iter()
            .find(|i| {
                path.node_id
                    .as_ref()
                    .is_some_and(|nid| i.entry.node_id.as_ref() == Some(nid))
                    || i.entry.raw_path() == path.raw_path()
                    || i.entry.nfc_path == path.nfc_path
            })
            .map(|i| self.present(i.entry.clone())))
    }

    async fn list_stream(&self, _prefix: &RelPath, _recursive: bool) -> Result<EntryStream> {
        let (mut items, inject_err, random_err) = {
            let mut g = self.inner.lock().unwrap();
            let list: Vec<Entry> = g
                .items
                .iter()
                .map(|i| self.present(i.entry.clone()))
                .collect();
            let rnd = g.faults.next_fault(ChaosOp::List);
            (list, g.faults.inject_list_error, rnd)
        };
        if self.caps.supports_ordered_utf8_list {
            items.sort_by(|a, b| a.nfc_path.as_str().cmp(b.nfc_path.as_str()));
        }
        let mut results: Vec<Result<Entry>> = items.into_iter().map(Ok).collect();
        if let Some(fault) = random_err {
            let keep = results.len() / 2;
            results.truncate(keep);
            results.push(Err(fault.into_error()));
        } else if inject_err {
            results.push(Err(Error::network("injected partial listing error")));
        }
        Ok(Box::pin(futures::stream::iter(results)))
    }

    async fn list_ordered_page(
        &self,
        prefix: &RelPath,
        start_after: Option<&str>,
        continuation: Option<&str>,
        max_keys: u32,
    ) -> Result<crate::backend::OrderedListPage> {
        if !self.caps.supports_ordered_utf8_list {
            return Err(Error::unsupported(
                "backend `chaos` does not support ordered UTF-8 range listing",
            ));
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(fault) = g.faults.next_fault(ChaosOp::List) {
            return Err(fault.into_error());
        }
        if g.faults.inject_list_error {
            return Err(Error::network("injected ordered listing error"));
        }
        let after = continuation.or(start_after);
        let pfx = prefix.as_str();
        let mut items: Vec<Entry> = g
            .items
            .iter()
            .filter(|i| {
                let s = i.entry.nfc_path.as_str();
                let under_prefix = pfx.is_empty()
                    || s == pfx
                    || s.strip_prefix(pfx).is_some_and(|r| r.starts_with('/'));
                under_prefix && after.is_none_or(|a| s > a)
            })
            .map(|i| self.present(i.entry.clone()))
            .collect();
        items.sort_by(|a, b| a.nfc_path.as_str().cmp(b.nfc_path.as_str()));
        let limit = (max_keys as usize).max(1);
        let is_truncated = items.len() > limit;
        if is_truncated {
            items.truncate(limit);
        }
        let last_wire_key = items.last().map(|e| e.nfc_path.as_str().to_string());
        let next_cursor = if is_truncated {
            last_wire_key.clone()
        } else {
            None
        };
        Ok(crate::backend::OrderedListPage {
            entries: items,
            is_truncated,
            next_cursor,
            last_wire_key,
            supports_start_after: true,
        })
    }

    async fn mkdir(&self, path: &RelPath) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if let Some(ref fp) = g.failpoints {
            fp.check_not_crashed()?;
        }
        if g.items
            .iter()
            .any(|i| i.entry.nfc_path == *path && i.entry.kind == EntryKind::Directory)
        {
            return Ok(());
        }
        let id = g.next_id;
        g.next_id += 1;
        g.items.push(StoredItem {
            entry: Entry {
                node_id: Some(NodeId(format!("d-{id}"))),
                parent_id: None,
                raw_path: None,
                nfc_path: path.clone(),
                kind: EntryKind::Directory,
                size: 0,
                mtime_ns: 0,
                ctime_ns: None,
                etag: None,
                checksum: None,
            },
            data: Vec::new(),
            op_id: None,
        });
        Ok(())
    }

    async fn delete(&self, path: &BackendPath) -> Result<()> {
        let gate = self.delete_gate.lock().unwrap().clone();
        let _permit = match gate {
            Some(sem) => Some(
                sem.acquire_owned()
                    .await
                    .map_err(|_| Error::cancelled("delete gate closed"))?,
            ),
            None => None,
        };
        let mut g = self.inner.lock().unwrap();
        let fp = g.failpoints.clone();
        if let Some(ref c) = fp {
            c.check_not_crashed()?;
        }
        if let Some(fault) = g.faults.next_fault(ChaosOp::Delete) {
            return Err(fault.into_error());
        }
        if g.faults.fail_delete_paths.contains(path.nfc_path.as_str()) {
            return Err(Error::permission_denied(format!(
                "injected delete failure for `{}`",
                path.nfc_path
            )));
        }
        if let Some(ref c) = fp {
            c.hit("remote:delete:before")?;
        }
        g.items
            .retain(|i| i.entry.raw_path() != path.raw_path() && i.entry.nfc_path != path.nfc_path);
        if let Some(ref c) = fp {
            c.hit("remote:delete:after")?;
        }
        Ok(())
    }

    async fn compute_hash(&self, path: &BackendPath, kind: HashKind) -> Result<Option<Checksum>> {
        if kind != HashKind::Sha256 {
            return Ok(None);
        }
        let g = self.inner.lock().unwrap();
        Ok(g.items
            .iter()
            .find(|i| i.entry.raw_path() == path.raw_path() || i.entry.nfc_path == path.nfc_path)
            .map(|i| Checksum {
                kind: HashKind::Sha256,
                hex: sha256_hex(&i.data),
            }))
    }

    async fn open_read(&self, path: &BackendPath, range: Option<ByteRange>) -> Result<DataSource> {
        let mut g = self.inner.lock().unwrap();
        let count = {
            let c = g
                .read_counts
                .entry(path.raw_path().to_string())
                .or_insert(0);
            *c += 1;
            *c
        };

        // Optional live middle-byte mutation fault injection!
        if let Some((target_raw, trigger_at)) = g.faults.mutate_source_after_reads.clone()
            && target_raw == path.raw_path()
            && count == trigger_at
            && let Some(item) = g
                .items
                .iter_mut()
                .find(|i| i.entry.raw_path() == path.raw_path())
            && !item.data.is_empty()
        {
            let mid = item.data.len() / 2;
            item.data[mid] ^= 0xFF;
            item.entry.ctime_ns = Some(item.entry.ctime_ns.unwrap_or(0) + 1);
            item.entry.checksum = Some(Checksum {
                kind: HashKind::Sha256,
                hex: sha256_hex(&item.data),
            });
        }

        let mut data = g
            .items
            .iter()
            .find(|i| i.entry.raw_path() == path.raw_path() || i.entry.nfc_path == path.nfc_path)
            .ok_or_else(|| Error::not_found(format!("missing `{}`", path.raw_path())))?
            .data
            .clone();
        if g.faults.corrupt_reads_remaining > 0 && !data.is_empty() {
            // Bytes delivered by this read differ from the stored object (and from its
            // advertised checksum), e.g. corruption on a ranged GET.
            g.faults.corrupt_reads_remaining -= 1;
            let mid = match range {
                Some(r) if r.len > 0 => (r.offset + r.len / 2) as usize,
                _ => data.len() / 2,
            };
            if let Some(b) = data.get_mut(mid) {
                *b ^= 0x33;
            }
        }
        Ok(DataSource::LocalSeekable(Arc::new(MemorySource::new(
            Bytes::from(data),
        ))))
    }

    async fn put_single_shot(&self, init: &UploadInit, mut body: ByteStream) -> Result<Entry> {
        let gate = self
            .put_gate
            .lock()
            .unwrap()
            .clone()
            .filter(|(path, _)| path == init.dst_path.as_str());
        if let Some((_, sem)) = gate {
            let _permit = sem
                .acquire_owned()
                .await
                .map_err(|_| Error::cancelled("put gate closed"))?;
        }
        {
            let g = self.inner.lock().unwrap();
            if let Some(ref fp) = g.failpoints {
                fp.check_not_crashed()?;
            }
            if g.faults.fail_put_paths.contains(init.dst_path.as_str()) {
                return Err(Error::permission_denied(format!(
                    "injected permanent put failure for `{}`",
                    init.dst_path
                )));
            }
            if g.faults.panic_on_upload {
                drop(g);
                panic!("injected backend panic in put_single_shot");
            }
        }
        let mut data = Vec::with_capacity(init.total_size as usize);
        while let Some(chunk) = body.next().await {
            data.extend_from_slice(&chunk?);
        }
        if data.len() as u64 != init.total_size {
            return Err(Error::source_mutated(format!(
                "short EOF on put_single_shot: expected {}, got {}",
                init.total_size,
                data.len()
            )));
        }
        let mut g = self.inner.lock().unwrap();
        let fp = g.failpoints.clone();
        if let Some(ref c) = fp {
            c.check_not_crashed()?;
        }
        g.upload_requests += 1;
        g.put_single_shot_calls += 1;
        g.bytes_uploaded += data.len() as u64;
        let rnd_fault = g.faults.next_fault(ChaosOp::PutSingleShot);
        if let Some(ref f) = rnd_fault
            && !matches!(f, InjectedFault::LostCommitResponse)
        {
            return Err(f.clone().into_error());
        }
        if g.faults
            .fail_put_transient_paths
            .contains(init.dst_path.as_str())
        {
            return Err(Error::network(format!(
                "503 injected transient put failure for `{}`",
                init.dst_path
            )));
        }
        if let Some(ref c) = fp {
            c.hit("remote:put_single_shot:before")?;
        }
        let (data, mismatch) = maybe_corrupt(&mut g, data);
        let entry = commit_into_store(&mut g, &init.dst_path, &init.op_id, init.src_mtime_ns, data);
        let entry = self.present(entry);
        if mismatch {
            return Err(chaos_checksum_mismatch("put_single_shot"));
        }
        if let Some(ref c) = fp {
            c.hit("remote:put_single_shot:after")?;
        }
        if let Some(InjectedFault::LostCommitResponse) = rnd_fault {
            return Err(InjectedFault::LostCommitResponse.into_error());
        }
        if g.faults.drop_final_commit_response_remaining > 0 {
            g.faults.drop_final_commit_response_remaining -= 1;
            return Err(Error::network(
                "injected lost response after single-shot commit",
            ));
        }
        Ok(entry)
    }

    async fn begin_upload(&self, init: &UploadInit) -> Result<UploadSessionInit> {
        let mut g = self.inner.lock().unwrap();
        let fp = g.failpoints.clone();
        if let Some(ref c) = fp {
            c.check_not_crashed()?;
        }
        if let Some(fault) = g.faults.next_fault(ChaosOp::BeginUpload) {
            return Err(fault.into_error());
        }
        if g.faults.panic_on_upload {
            drop(g);
            panic!("injected backend panic in begin_upload");
        }
        if let Some(ref c) = fp {
            c.hit("remote:begin_upload:before")?;
        }
        g.upload_requests += 1;
        g.begin_upload_calls += 1;
        let id = g.next_id;
        g.next_id += 1;
        let token = format!("sess-{id}");
        g.sessions.insert(
            token.clone(),
            ActiveSession {
                dst_path: init.dst_path.clone(),
                op_id: init.op_id.clone(),
                src_mtime_ns: init.src_mtime_ns,
                total_size: init.total_size,
                buf: Vec::new(),
                parts: BTreeMap::new(),
            },
        );
        if let Some(ref c) = fp {
            c.hit("remote:begin_upload:after")?;
        }
        Ok(UploadSessionInit {
            session_token: token,
            backend_meta: "{}".into(),
            remote_op_id: Some(init.op_id.clone()),
            expires_at_unix_secs: None,
        })
    }

    async fn query_upload(&self, op: &OperationRecord) -> Result<UploadProgress> {
        let mut g = self.inner.lock().unwrap();
        let Some(token) = &op.session_token else {
            return Ok(UploadProgress::Expired);
        };
        if let Some(fault) = g.faults.next_fault(ChaosOp::QueryUpload) {
            match fault {
                InjectedFault::SessionExpired => {
                    g.sessions.remove(token);
                    return Ok(UploadProgress::Expired);
                }
                other => return Err(other.into_error()),
            }
        }
        if g.faults.expire_session_remaining > 0 {
            g.faults.expire_session_remaining -= 1;
            g.sessions.remove(token);
            return Ok(UploadProgress::Expired);
        }
        let Some(sess) = g.sessions.get(token) else {
            return Ok(UploadProgress::Expired);
        };
        match self.caps.upload_topology {
            UploadTopology::Sequential => {
                Ok(UploadProgress::SequentialOffset(sess.buf.len() as u64))
            }
            UploadTopology::ParallelParts => {
                let parts = sess
                    .parts
                    .iter()
                    .map(|(&pn, (off, bytes, etag))| CompletedPart {
                        part_number: pn,
                        offset: *off,
                        length: bytes.len() as u64,
                        etag: etag.clone(),
                        checksum: None,
                    })
                    .collect();
                Ok(UploadProgress::CompletedParts(parts))
            }
        }
    }

    async fn upload_chunk(&self, op: &OperationRecord, mut chunk: ChunkUpload) -> Result<ChunkAck> {
        {
            let g = self.inner.lock().unwrap();
            if let Some(ref fp) = g.failpoints {
                fp.check_not_crashed()?;
            }
        }
        let mut payload = Vec::with_capacity(chunk.len as usize);
        while let Some(slice) = chunk.body.next().await {
            payload.extend_from_slice(&slice?);
        }

        let mut g = self.inner.lock().unwrap();
        let fp = g.failpoints.clone();
        if let Some(ref c) = fp {
            c.check_not_crashed()?;
        }
        g.upload_requests += 1;
        g.upload_chunk_calls += 1;
        g.bytes_uploaded += payload.len() as u64;

        if g.faults.fail_chunk_rate_limit_remaining > 0 {
            g.faults.fail_chunk_rate_limit_remaining -= 1;
            return Err(Error::rate_limited(
                "injected 429",
                Some(Duration::from_millis(1)),
            ));
        }

        let token = op
            .session_token
            .as_ref()
            .ok_or_else(|| Error::session_expired("missing session token"))?;

        if g.faults.expire_session_remaining > 0 {
            g.faults.expire_session_remaining -= 1;
            g.sessions.remove(token);
            return Err(Error::session_expired("injected session expiry"));
        }

        let rnd_fault = g.faults.next_fault(ChaosOp::UploadChunk);
        let mut rnd_partial_drop = false;
        if let Some(fault) = rnd_fault {
            match fault {
                InjectedFault::SessionExpired => {
                    g.sessions.remove(token);
                    return Err(fault.into_error());
                }
                InjectedFault::PartialChunkDrop => {
                    if self.caps.upload_topology == UploadTopology::Sequential {
                        rnd_partial_drop = true;
                    } else {
                        return Err(fault.into_error());
                    }
                }
                other => return Err(other.into_error()),
            }
        }

        if let Some(ref c) = fp {
            c.hit("remote:upload_chunk:before")?;
        }

        match self.caps.upload_topology {
            UploadTopology::Sequential => {
                let drop_partial = if rnd_partial_drop {
                    true
                } else if g.faults.drop_after_partial_chunk_remaining > 0 {
                    g.faults.drop_after_partial_chunk_remaining -= 1;
                    true
                } else {
                    false
                };

                let sess = g
                    .sessions
                    .get_mut(token)
                    .ok_or_else(|| Error::session_expired("session gone"))?;
                if chunk.offset != sess.buf.len() as u64 {
                    return Err(Error::protocol(format!(
                        "sequential offset mismatch: got {}, expected {}",
                        chunk.offset,
                        sess.buf.len()
                    )));
                }
                if drop_partial && payload.len() >= 2 {
                    // Persist half of the chunk (simulating Drive 308 partial persist) then drop socket!
                    let half = payload.len() / 2;
                    sess.buf.extend_from_slice(&payload[..half]);
                    return Err(Error::network("injected mid-chunk socket drop"));
                }
                sess.buf.extend_from_slice(&payload);
                let new_off = sess.buf.len() as u64;
                if new_off == sess.total_size {
                    let sess = g.sessions.remove(token).unwrap();
                    let (buf, mismatch) = maybe_corrupt(&mut g, sess.buf);
                    let entry = commit_into_store(
                        &mut g,
                        &sess.dst_path,
                        &sess.op_id,
                        sess.src_mtime_ns,
                        buf,
                    );
                    let entry = self.present(entry);
                    if mismatch {
                        return Err(chaos_checksum_mismatch("final sequential chunk"));
                    }
                    if let Some(ref c) = fp {
                        c.hit("remote:upload_chunk:after")?;
                    }
                    if matches!(
                        g.faults.next_fault(ChaosOp::FinishUpload),
                        Some(InjectedFault::LostCommitResponse)
                    ) {
                        return Err(InjectedFault::LostCommitResponse.into_error());
                    }
                    if g.faults.drop_final_commit_response_remaining > 0 {
                        g.faults.drop_final_commit_response_remaining -= 1;
                        return Err(Error::network(
                            "injected lost response after final sequential PUT",
                        ));
                    }
                    Ok(ChunkAck {
                        next_offset: Some(new_off),
                        etag: None,
                        completed: Some(entry),
                        checksum: None,
                    })
                } else {
                    if let Some(ref c) = fp {
                        c.hit("remote:upload_chunk:after")?;
                    }
                    Ok(ChunkAck {
                        next_offset: Some(new_off),
                        etag: None,
                        completed: None,
                        checksum: None,
                    })
                }
            }
            UploadTopology::ParallelParts => {
                let etag = format!("\"{}\"", &sha256_hex(&payload)[..16]);
                let sess = g
                    .sessions
                    .get_mut(token)
                    .ok_or_else(|| Error::session_expired("session gone"))?;
                sess.parts
                    .insert(chunk.part_number, (chunk.offset, payload, etag.clone()));
                if let Some(ref c) = fp {
                    c.hit("remote:upload_chunk:after")?;
                }
                Ok(ChunkAck {
                    next_offset: None,
                    etag: Some(etag),
                    completed: None,
                    checksum: None,
                })
            }
        }
    }

    async fn finish_upload(&self, op: &OperationRecord, parts: &[CompletedPart]) -> Result<Entry> {
        let mut g = self.inner.lock().unwrap();
        let fp = g.failpoints.clone();
        if let Some(ref c) = fp {
            c.check_not_crashed()?;
        }
        let rnd_fault = g.faults.next_fault(ChaosOp::FinishUpload);
        if let Some(ref f) = rnd_fault
            && !matches!(f, InjectedFault::LostCommitResponse)
        {
            return Err(f.clone().into_error());
        }
        if let Some(ref c) = fp {
            c.hit("remote:finish_upload:before")?;
        }
        let token = op
            .session_token
            .as_ref()
            .ok_or_else(|| Error::session_expired("missing session token"))?;
        let sess = g
            .sessions
            .remove(token)
            .ok_or_else(|| Error::session_expired("NoSuchUpload"))?;
        g.finish_upload_calls += 1;
        let mut assembled = Vec::with_capacity(sess.total_size as usize);
        for p in parts {
            let (_, bytes, etag) = sess
                .parts
                .get(&p.part_number)
                .ok_or_else(|| Error::protocol(format!("missing part {}", p.part_number)))?;
            if etag != &p.etag {
                return Err(Error::protocol("ETag mismatch on finish_upload"));
            }
            assembled.extend_from_slice(bytes);
        }
        let (assembled, mismatch) = maybe_corrupt(&mut g, assembled);
        let entry = commit_into_store(
            &mut g,
            &sess.dst_path,
            &sess.op_id,
            sess.src_mtime_ns,
            assembled,
        );
        let entry = self.present(entry);
        if mismatch {
            return Err(chaos_checksum_mismatch("finish_upload"));
        }
        if let Some(ref c) = fp {
            c.hit("remote:finish_upload:after")?;
        }
        if let Some(InjectedFault::LostCommitResponse) = rnd_fault {
            return Err(InjectedFault::LostCommitResponse.into_error());
        }
        if g.faults.drop_final_commit_response_remaining > 0 {
            g.faults.drop_final_commit_response_remaining -= 1;
            return Err(Error::network(
                "injected lost response after CompleteMultipartUpload",
            ));
        }
        Ok(entry)
    }

    async fn abort_upload(&self, op: &OperationRecord) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if let Some(ref fp) = g.failpoints {
            fp.check_not_crashed()?;
        }
        if let Some(tok) = &op.session_token {
            g.sessions.remove(tok);
        }
        Ok(())
    }

    async fn reconcile_operation(&self, op: &OperationRecord) -> Result<ReconcileOutcome> {
        let mut g = self.inner.lock().unwrap();
        if let Some(fault) = g.faults.next_fault(ChaosOp::ReconcileOperation) {
            return Err(fault.into_error());
        }
        if let Some(item) = g
            .items
            .iter()
            .find(|i| i.op_id.as_deref() == Some(op.op_id.as_str()))
        {
            return Ok(ReconcileOutcome::Committed(
                self.present(item.entry.clone()),
            ));
        }
        Ok(ReconcileOutcome::NotCommitted)
    }
}

/// Apply a pending [`FaultSchedule::corrupt_commit_remaining`] fault: flip one byte of
/// `data` and report whether the backend should surface a checksum mismatch.
fn maybe_corrupt(g: &mut ChaosInner, mut data: Vec<u8>) -> (Vec<u8>, bool) {
    if g.faults.corrupt_commit_remaining == 0 || data.is_empty() {
        return (data, false);
    }
    g.faults.corrupt_commit_remaining -= 1;
    let mid = data.len() / 2;
    data[mid] ^= 0x5A;
    (data, g.faults.corrupt_commit_reports_mismatch)
}

fn commit_into_store(
    g: &mut ChaosInner,
    dst_path: &RelPath,
    op_id: &str,
    mtime_ns: i64,
    data: Vec<u8>,
) -> Entry {
    g.items
        .retain(|i| i.entry.nfc_path != *dst_path || i.entry.kind != EntryKind::File);
    let id = g.next_id;
    g.next_id += 1;
    let hash = sha256_hex(&data);
    let entry = Entry {
        node_id: Some(NodeId(format!("n-{id}"))),
        parent_id: None,
        raw_path: None,
        nfc_path: dst_path.clone(),
        kind: EntryKind::File,
        size: data.len() as u64,
        mtime_ns,
        ctime_ns: Some(mtime_ns),
        etag: Some(format!("\"{}\"", &hash[..16])),
        checksum: Some(Checksum {
            kind: HashKind::Sha256,
            hex: hash,
        }),
    };
    g.items.push(StoredItem {
        entry: entry.clone(),
        data,
        op_id: Some(op_id.to_string()),
    });
    entry
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
