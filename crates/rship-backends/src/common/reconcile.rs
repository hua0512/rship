//! Shared proof rules for `reconcile_operation` on backends that cannot tag an object with
//! the operation id (OneDrive, Dropbox, WebDAV, SFTP, local).
//!
//! An object found at an operation's destination is accepted as that operation's result
//! ([`ReconcileOutcome::Committed`]) only when it is proven, never because its size alone
//! matches. Accepting an older same-size file would let `move` delete the only good source.
//!
//! When the object cannot be attributed to the operation, the verdict is
//! [`ReconcileOutcome::NotCommitted`], not `Ambiguous`: the engine then transfers the file
//! again, which is always safe (the source is kept and the destination is overwritten with
//! verified content), whereas `Ambiguous` would block the path on every later run.

use rship_core::backend::ReconcileOutcome;
use rship_core::state::{DstPrecondition, OperationRecord};
use rship_core::types::Entry;
use serde::{Deserialize, Serialize};

/// What occupied the destination before the operation wrote anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PreOpState {
    /// Nothing was at the destination.
    Absent,
    /// An object was there. `identity` is the provider's version identity (eTag, rev,
    /// inode, ...) when it has one; `size`/`mtime_ns` are its attributes.
    Existing {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<String>,
        size: u64,
        mtime_ns: i64,
    },
    /// Not recorded.
    Unknown,
}

impl PreOpState {
    /// Snapshot of `entry` (or of its absence) taken before the operation writes.
    pub fn snapshot(entry: Option<&Entry>, identity: impl Fn(&Entry) -> Option<String>) -> Self {
        match entry {
            None => Self::Absent,
            Some(e) => Self::Existing {
                identity: identity(e),
                size: e.size,
                mtime_ns: e.mtime_ns,
            },
        }
    }

    /// Pre-op state implied by the planner's `dst_precondition`. `identity` picks the
    /// field holding the provider's version identity (`etag` or `node_id`).
    pub fn from_precondition(
        pre: &DstPrecondition,
        identity: impl Fn(&Option<rship_core::types::NodeId>, &Option<String>) -> Option<String>,
    ) -> Self {
        match pre {
            DstPrecondition::Absent => Self::Absent,
            DstPrecondition::Existing {
                node_id,
                etag,
                mtime_ns,
                size,
            } => Self::Existing {
                identity: identity(node_id, etag),
                size: *size,
                mtime_ns: *mtime_ns,
            },
            // `Any`, and any precondition added later, records nothing usable.
            _ => Self::Unknown,
        }
    }
}

/// Judge whether `current` (the object now at the destination) is `op`'s result.
///
/// - Size must equal the source size, and when the provider stores the mtime the operation
///   set (`mtime_tolerance_ns`), that mtime must match the source mtime. Otherwise the
///   operation did not commit: [`ReconcileOutcome::NotCommitted`].
/// - The object must also differ from what was there before the operation:
///   - pre-op absent: anything there now was created after planning;
///   - pre-op version identity known: it must have changed (unchanged means
///     `NotCommitted`);
///   - no identity, but our mtime is stored and the pre-op object differed from the
///     source in size or mtime: it changed into the source's size and mtime;
///   - otherwise the object cannot be attributed to the operation:
///     [`ReconcileOutcome::NotCommitted`], so the engine re-transfers.
pub fn judge_reconciled_object(
    op: &OperationRecord,
    current: Entry,
    current_identity: Option<&str>,
    pre: &PreOpState,
    mtime_tolerance_ns: Option<i64>,
    what: &str,
) -> ReconcileOutcome {
    let src = &op.src_version;
    if current.size != src.size {
        return ReconcileOutcome::NotCommitted;
    }
    let mtime_close = |a: i64, b: i64, tol: i64| (a - b).abs() <= tol;
    if let Some(tol) = mtime_tolerance_ns
        && !mtime_close(current.mtime_ns, src.mtime_ns, tol)
    {
        return ReconcileOutcome::NotCommitted;
    }
    match pre {
        PreOpState::Absent => ReconcileOutcome::Committed(current),
        PreOpState::Existing {
            identity: Some(pre_id),
            ..
        } if current_identity.is_some() => {
            if current_identity == Some(pre_id.as_str()) {
                ReconcileOutcome::NotCommitted
            } else {
                ReconcileOutcome::Committed(current)
            }
        }
        PreOpState::Existing { size, mtime_ns, .. } => match mtime_tolerance_ns {
            Some(tol) if *size != src.size || !mtime_close(*mtime_ns, src.mtime_ns, tol) => {
                ReconcileOutcome::Committed(current)
            }
            _ => {
                tracing::debug!(
                    op_id = %op.op_id,
                    "{what}: object matches the source but cannot be told apart from the \
                     pre-operation version; treating as not committed"
                );
                ReconcileOutcome::NotCommitted
            }
        },
        PreOpState::Unknown => {
            tracing::debug!(
                op_id = %op.op_id,
                "{what}: no pre-operation version recorded; treating as not committed"
            );
            ReconcileOutcome::NotCommitted
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rship_core::path::RelPath;
    use rship_core::state::{OperationState, SourceVersion};

    fn op(pre: DstPrecondition) -> OperationRecord {
        let p = RelPath::parse("a.bin").unwrap();
        OperationRecord {
            op_id: "op-1".into(),
            session_key: "sk".into(),
            job_id: "j".into(),
            src_endpoint: "s".into(),
            dst_endpoint: "d".into(),
            src_raw_path: "a.bin".into(),
            dst_raw_path: "a.bin".into(),
            dst_nfc_path: p,
            src_version: SourceVersion {
                node_id: None,
                size: 10,
                mtime_ns: 5_000_000_000,
                ctime_ns: None,
                etag: None,
            },
            dst_precondition: pre,
            existing_dst_node_id: None,
            remote_op_id: None,
            backend_kind: "x".into(),
            session_token: None,
            backend_meta: String::new(),
            planned_chunk_size: 10,
            confirmed_offset: 0,
            state: OperationState::Completing,
            created_at: 0,
            updated_at: 0,
            expires_at: None,
        }
    }

    fn entry(size: u64, mtime_ns: i64) -> Entry {
        Entry::file(RelPath::parse("a.bin").unwrap(), size, mtime_ns)
    }

    fn committed(o: &ReconcileOutcome) -> bool {
        matches!(o, ReconcileOutcome::Committed(_))
    }

    #[test]
    fn size_match_alone_never_proves_a_commit() {
        let o = op(DstPrecondition::Any);
        // Same size, no stored mtime, no pre-op record.
        let r = judge_reconciled_object(&o, entry(10, 1), None, &PreOpState::Unknown, None, "t");
        assert!(matches!(r, ReconcileOutcome::NotCommitted));
        // Same size, unchanged version identity.
        let pre = PreOpState::Existing {
            identity: Some("v1".into()),
            size: 10,
            mtime_ns: 1,
        };
        let r = judge_reconciled_object(&o, entry(10, 1), Some("v1"), &pre, None, "t");
        assert!(matches!(r, ReconcileOutcome::NotCommitted));
        // Same size and same (unchanged) attributes, no identity: indistinguishable.
        let pre = PreOpState::Existing {
            identity: None,
            size: 10,
            mtime_ns: 5_000_000_000,
        };
        let r = judge_reconciled_object(
            &o,
            entry(10, 5_000_000_000),
            None,
            &pre,
            Some(1_000_000_000),
            "t",
        );
        assert!(matches!(r, ReconcileOutcome::NotCommitted));
    }

    #[test]
    fn proven_commits_are_accepted_and_mismatches_rejected() {
        let o = op(DstPrecondition::Absent);
        let tol = Some(1_000_000_000);
        assert!(committed(&judge_reconciled_object(
            &o,
            entry(10, 5_000_000_000),
            None,
            &PreOpState::Absent,
            tol,
            "t"
        )));
        // Wrong mtime or size: not ours.
        let r = judge_reconciled_object(&o, entry(10, 1), None, &PreOpState::Absent, tol, "t");
        assert!(matches!(r, ReconcileOutcome::NotCommitted));
        let r = judge_reconciled_object(
            &o,
            entry(9, 5_000_000_000),
            None,
            &PreOpState::Absent,
            tol,
            "t",
        );
        assert!(matches!(r, ReconcileOutcome::NotCommitted));
        // Version changed.
        let pre = PreOpState::Existing {
            identity: Some("v1".into()),
            size: 10,
            mtime_ns: 1,
        };
        assert!(committed(&judge_reconciled_object(
            &o,
            entry(10, 5_000_000_000),
            Some("v2"),
            &pre,
            tol,
            "t"
        )));
        // No identity, but the stored mtime moved from the old value to the source's.
        let pre = PreOpState::Existing {
            identity: None,
            size: 10,
            mtime_ns: 1,
        };
        assert!(committed(&judge_reconciled_object(
            &o,
            entry(10, 5_000_000_000),
            None,
            &pre,
            tol,
            "t"
        )));
    }

    #[cfg(any(feature = "onedrive", feature = "dropbox", feature = "webdav"))]
    #[test]
    fn pre_op_state_round_trips_through_json() {
        for s in [
            PreOpState::Absent,
            PreOpState::Unknown,
            PreOpState::Existing {
                identity: Some("\"e\"".into()),
                size: 3,
                mtime_ns: -4,
            },
        ] {
            let j = serde_json::to_string(&s).unwrap();
            assert_eq!(serde_json::from_str::<PreOpState>(&j).unwrap(), s);
        }
    }
}
