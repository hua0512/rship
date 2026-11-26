//! Parallel bounded-concurrency local directory walker with symlink-cycle detection,
//! directory pruning, depth limiting, and batched `EntryStream` delivery.

use super::fs_util::{
    decode_local_rel_path, ensure_no_symlink_escape, metadata_to_entry, path_to_slash_utf8,
    strip_root_prefix, to_os_path,
};
use super::{LocalBackend, PART_FILE_PREFIX};
use rship_core::backend::{EntryStream, ListOptions};
use rship_core::path::RelPath;
use rship_core::types::Entry;
use rship_core::{Error, Result};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use tokio::sync::mpsc;

impl LocalBackend {
    pub(super) async fn list_with_options_impl(
        &self,
        prefix: &RelPath,
        options: &ListOptions,
    ) -> Result<EntryStream> {
        const WALK_BATCH_SIZE: usize = 64;
        const WALK_CHANNEL_CAP: usize = 16;

        let start = if prefix.is_root() {
            self.resolve_new(prefix)
        } else {
            self.resolve_write_path(prefix, true).await?
        };
        let root = self.root.clone();
        let root_os = to_os_path(&root);
        let encoding = self.encoding;
        let effective_max_depth = options.effective_max_depth();
        let pruner = options.dir_pruner().cloned();
        let follow_symlinks = self.follow_symlinks;
        let start_is_root = start == root
            || strip_root_prefix(&start, &root).is_some_and(|r| r.as_os_str().is_empty());

        // D3-local: verify the local root exists before streaming. A missing/unmounted
        // root MUST fail with `ErrorKind::NotFound` rather than returning an empty tree.
        let start_check = start.clone();
        let root_check = root_os.clone();
        let start_is_dir = tokio::task::spawn_blocking(move || -> Result<bool> {
            if !follow_symlinks && !start_is_root {
                ensure_no_symlink_escape(&root_check, &start_check)?;
            }
            let start_meta = if follow_symlinks || start_is_root {
                std::fs::metadata(&start_check)
            } else {
                std::fs::symlink_metadata(&start_check)
            };
            match start_meta {
                Ok(m) => Ok(m.is_dir()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if start_is_root {
                        Err(Error::not_found(format!(
                            "local root `{}` does not exist",
                            start_check.display()
                        )))
                    } else {
                        match std::fs::metadata(&root_check) {
                            Err(re) if re.kind() == std::io::ErrorKind::NotFound => {
                                Err(Error::not_found(format!(
                                    "local root `{}` does not exist",
                                    root_check.display()
                                )))
                            }
                            Err(re) => Err(Error::io(
                                format!("stat local root `{}`", root_check.display()),
                                re,
                            )),
                            Ok(_) => Ok(false),
                        }
                    }
                }
                Err(e) => Err(Error::io(format!("walk `{}`", start_check.display()), e)),
            }
        })
        .await
        .map_err(|e| Error::protocol(format!("list_with_options stat join: {e}")))??;

        if !start_is_dir || effective_max_depth == Some(0) {
            return Ok(Box::pin(futures::stream::empty()));
        }

        let (tx, rx) = mpsc::channel::<Vec<Result<Entry>>>(WALK_CHANNEL_CAP);

        tokio::task::spawn_blocking(move || {
            // Lazily track canonicalized symlink directory targets only along branches
            // that actually traversed a directory symlink (zero `canonicalize` syscalls and
            // zero `Vec` clones for ordinary directories!).
            let empty_symlink_targets: Arc<Vec<PathBuf>> = Arc::new(Vec::new());
            let root_canon = std::fs::canonicalize(&root_os).ok();
            let start_canon = std::fs::canonicalize(&start).ok();

            struct DirJob {
                dir: PathBuf,
                depth: usize,
                symlink_targets: Arc<Vec<PathBuf>>,
            }

            struct WalkShared {
                queue: VecDeque<DirJob>,
                active: usize,
                cancelled: bool,
            }

            let max_workers = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
                .clamp(2, 8);
            let bfs_threshold = max_workers * 4;

            let flush_batch =
                |batch: &mut Vec<Result<Entry>>, tx: &mpsc::Sender<Vec<Result<Entry>>>| -> bool {
                    if batch.is_empty() {
                        return true;
                    }
                    let send = std::mem::replace(batch, Vec::with_capacity(WALK_BATCH_SIZE));
                    tx.blocking_send(send).is_ok()
                };

            let push_item = |item: Result<Entry>, batch: &mut Vec<Result<Entry>>| -> bool {
                batch.push(item);
                batch.len() < WALK_BATCH_SIZE || flush_batch(batch, &tx)
            };

            let is_ancestor_cycle = |job: &DirJob, canon: &Path| -> bool {
                if job
                    .symlink_targets
                    .iter()
                    .any(|t| t == canon || t.starts_with(canon))
                {
                    return true;
                }
                if root_canon.as_ref().is_some_and(|rc| rc.starts_with(canon)) {
                    return true;
                }
                if start_canon.as_ref().is_some_and(|sc| sc.starts_with(canon)) {
                    return true;
                }
                for anc in job.dir.ancestors() {
                    let Some(rel_anc) = strip_root_prefix(anc, &root) else {
                        break;
                    };
                    if let Ok(anc_canon) = std::fs::canonicalize(to_os_path(anc))
                        && anc_canon == canon
                    {
                        return true;
                    }
                    if rel_anc.as_os_str().is_empty() {
                        break;
                    }
                }
                false
            };

            let scan_one_dir = |job: DirJob,
                                batch: &mut Vec<Result<Entry>>,
                                subdirs: &mut Vec<DirJob>|
             -> bool {
                let rd = match std::fs::read_dir(&job.dir) {
                    Ok(rd) => rd,
                    Err(e) => {
                        return push_item(
                            Err(Error::io(format!("walk `{}`", job.dir.display()), e)),
                            batch,
                        );
                    }
                };
                let child_depth = job.depth + 1;
                let can_descend = effective_max_depth.is_none_or(|limit| child_depth < limit);

                for dent_res in rd {
                    if tx.is_closed() {
                        return false;
                    }
                    let dent = match dent_res {
                        Ok(d) => d,
                        Err(e) => {
                            if !push_item(
                                Err(Error::io(format!("walk `{}`", job.dir.display()), e)),
                                batch,
                            ) {
                                return false;
                            }
                            continue;
                        }
                    };
                    if let Some(name) = dent.file_name().to_str()
                        && name.starts_with(PART_FILE_PREFIX)
                    {
                        continue;
                    }
                    let p = dent.path();
                    let ft = match dent.file_type() {
                        Ok(ft) => ft,
                        Err(e) => {
                            if !push_item(
                                Err(Error::io(format!("file_type `{}`", p.display()), e)),
                                batch,
                            ) {
                                return false;
                            }
                            continue;
                        }
                    };
                    // Skip Unix FIFOs, sockets, block/char devices cleanly.
                    if !ft.is_file() && !ft.is_dir() && !ft.is_symlink() {
                        continue;
                    }

                    let (meta, is_dir, cycle_checked_canon) = if follow_symlinks && ft.is_symlink()
                    {
                        match std::fs::metadata(&p) {
                            Ok(m) => {
                                if !m.is_file() && !m.is_dir() {
                                    continue;
                                }
                                if m.is_dir() {
                                    match std::fs::canonicalize(&p) {
                                        Ok(canon) => {
                                            if is_ancestor_cycle(&job, &canon) {
                                                if !push_item(
                                                    Err(Error::invalid_path(format!(
                                                        "symlink cycle detected at `{}` -> `{}`",
                                                        p.display(),
                                                        canon.display()
                                                    ))),
                                                    batch,
                                                ) {
                                                    return false;
                                                }
                                                continue;
                                            }
                                            (m, true, Some(canon))
                                        }
                                        Err(e) => {
                                            if !push_item(
                                                Err(Error::io(
                                                    format!(
                                                        "canonicalize symlink `{}`",
                                                        p.display()
                                                    ),
                                                    e,
                                                )),
                                                batch,
                                            ) {
                                                return false;
                                            }
                                            continue;
                                        }
                                    }
                                } else {
                                    (m, false, None)
                                }
                            }
                            Err(e) => {
                                if !push_item(
                                    Err(Error::io(format!("follow symlink `{}`", p.display()), e)),
                                    batch,
                                ) {
                                    return false;
                                }
                                continue;
                            }
                        }
                    } else {
                        let m = match dent.metadata() {
                            Ok(m) => m,
                            Err(e) => {
                                if !push_item(
                                    Err(Error::io(format!("metadata `{}`", p.display()), e)),
                                    batch,
                                ) {
                                    return false;
                                }
                                continue;
                            }
                        };
                        (m, ft.is_dir(), None)
                    };

                    let Some(rel_os) = strip_root_prefix(&p, &root) else {
                        if !push_item(
                            Err(Error::invalid_path(format!(
                                "walked entry `{}` outside backend root `{}`",
                                p.display(),
                                root.display()
                            ))),
                            batch,
                        ) {
                            return false;
                        }
                        continue;
                    };
                    let Some(disk_rel) = path_to_slash_utf8(&rel_os) else {
                        if !push_item(
                            Err(Error::invalid_path(format!(
                                "non-UTF-8 path `{}`",
                                p.display()
                            ))),
                            batch,
                        ) {
                            return false;
                        }
                        continue;
                    };
                    let decoded_raw = match decode_local_rel_path(encoding, &disk_rel) {
                        Ok(d) => d,
                        Err(e) => {
                            if !push_item(Err(e), batch) {
                                return false;
                            }
                            continue;
                        }
                    };
                    let nfc_path = match RelPath::parse(&decoded_raw) {
                        Ok(rp) => rp,
                        Err(e) => {
                            if !push_item(Err(e), batch) {
                                return false;
                            }
                            continue;
                        }
                    };

                    if is_dir && pruner.as_ref().is_some_and(|pr| pr(&nfc_path)) {
                        continue;
                    }

                    let raw_override =
                        rship_core::types::raw_path_override(&nfc_path, &decoded_raw);
                    if let Some(entry) = metadata_to_entry(&meta, raw_override, nfc_path)
                        && !push_item(Ok(entry), batch)
                    {
                        return false;
                    }

                    if is_dir && can_descend {
                        let next_targets = if let Some(canon) = cycle_checked_canon {
                            let mut next = (*job.symlink_targets).clone();
                            next.push(canon);
                            Arc::new(next)
                        } else {
                            job.symlink_targets.clone()
                        };
                        subdirs.push(DirJob {
                            dir: p,
                            depth: child_depth,
                            symlink_targets: next_targets,
                        });
                    }
                }
                true
            };

            // Fast single-thread scan first: flat or single-branch trees pay ZERO extra
            // OS thread-spawn overhead; as soon as >= 2 subdirectories queue up, fan out
            // across `max_workers` bounded scoped threads.
            let mut batch = Vec::with_capacity(WALK_BATCH_SIZE);
            let mut pending = Vec::new();
            let ok = scan_one_dir(
                DirJob {
                    dir: start,
                    depth: 0,
                    symlink_targets: empty_symlink_targets,
                },
                &mut batch,
                &mut pending,
            );
            if !ok {
                return;
            }
            while pending.len() <= 1 {
                let Some(job) = pending.pop() else {
                    let _ = flush_batch(&mut batch, &tx);
                    return;
                };
                if !scan_one_dir(job, &mut batch, &mut pending) {
                    return;
                }
            }
            if !flush_batch(&mut batch, &tx) {
                return;
            }

            // Fan-out bounded parallel directory walk across `2..=8` scoped OS threads.
            let worker_count = max_workers;
            let shared = (
                StdMutex::new(WalkShared {
                    queue: pending.into(),
                    active: 0,
                    cancelled: false,
                }),
                Condvar::new(),
            );

            let worker_loop = || {
                let mut local_batch = Vec::with_capacity(WALK_BATCH_SIZE);
                let mut local_subdirs = Vec::new();
                loop {
                    let job = {
                        let (lock, cvar) = &shared;
                        let mut st = crate::common::lock_unpoisoned(lock);
                        loop {
                            if st.cancelled || tx.is_closed() {
                                st.cancelled = true;
                                cvar.notify_all();
                                return;
                            }
                            let next = if st.queue.len() <= bfs_threshold {
                                st.queue.pop_front()
                            } else {
                                st.queue.pop_back()
                            };
                            if let Some(j) = next {
                                st.active += 1;
                                break j;
                            }
                            if st.active == 0 {
                                cvar.notify_all();
                                let _ = flush_batch(&mut local_batch, &tx);
                                return;
                            }
                            st = cvar.wait(st).unwrap_or_else(|e| e.into_inner());
                        }
                    };

                    local_subdirs.clear();
                    let keep_going = scan_one_dir(job, &mut local_batch, &mut local_subdirs);

                    let (lock, cvar) = &shared;
                    let mut st = crate::common::lock_unpoisoned(lock);
                    st.active -= 1;
                    if !keep_going {
                        st.cancelled = true;
                        cvar.notify_all();
                        return;
                    }
                    if !local_subdirs.is_empty() {
                        st.queue.extend(local_subdirs.drain(..));
                        cvar.notify_all();
                    } else if st.active == 0 && st.queue.is_empty() {
                        cvar.notify_all();
                    }
                }
            };

            std::thread::scope(|s| {
                for _ in 1..worker_count {
                    s.spawn(worker_loop);
                }
                worker_loop();
            });
        });

        let stream = futures::stream::unfold(
            (rx, Vec::<Result<Entry>>::new().into_iter()),
            |(mut rx, mut cur)| async move {
                loop {
                    if let Some(item) = cur.next() {
                        return Some((item, (rx, cur)));
                    }
                    let next_batch = rx.recv().await?;
                    cur = next_batch.into_iter();
                }
            },
        );
        Ok(Box::pin(stream))
    }
}
