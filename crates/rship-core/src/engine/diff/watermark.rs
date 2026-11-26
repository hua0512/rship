use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

const MAX_WATERMARK_COMPLETED_AHEAD: usize = 8_192;

/// Safe `StartAfter` resume watermark tracker for out-of-order concurrent worker pools.
///
/// Tracks all staged/in-flight keys, out-of-order completions (`completed_ahead`), the
/// earliest failed key (if any), and the minimum un-emitted buffered source wire key
/// (`buffered_floor`). The safe resume cursor NEVER advances past any buffered, staged,
/// in-flight, or failed key, guaranteeing zero skipped files across arbitrary worker
/// reordering, NFD deferrals, and crashes.
#[derive(Clone, Default)]
pub struct SafeWatermarkTracker {
    inner: Arc<Mutex<WatermarkState>>,
}

#[derive(Default)]
struct WatermarkState {
    in_flight: BTreeSet<String>,
    /// Bounded out-of-order completed keys awaiting drain once earlier `in_flight` keys finish.
    completed_ahead: BTreeSet<String>,
    /// Optional exclusive ceiling from un-emitted buffered `src` keys (e.g. NFD deferred).
    buffered_floor: Option<String>,
    /// Last key completed strictly BEFORE `in_flight.first()`, `first_failed`, and `buffered_floor`.
    safe_completed: Option<String>,
    /// Earliest key that failed in this run — watermark is frozen strictly before it.
    first_failed: Option<String>,
}

impl WatermarkState {
    fn drain_safe(&mut self) {
        while let Some(first) = self.completed_ahead.first() {
            if self.in_flight.first().is_some_and(|inf| first >= inf) {
                break;
            }
            if self
                .first_failed
                .as_deref()
                .is_some_and(|f| first.as_str() >= f)
            {
                break;
            }
            if self
                .buffered_floor
                .as_deref()
                .is_some_and(|bf| first.as_str() >= bf)
            {
                break;
            }
            let k = self.completed_ahead.pop_first().unwrap();
            if self
                .safe_completed
                .as_deref()
                .is_none_or(|cur| k.as_str() > cur)
            {
                self.safe_completed = Some(k);
            }
        }
        // Keep `completed_ahead` strictly O(1) even if one multi-hour file stalls `in_flight`
        // while millions of tiny files finish ahead: dropping the largest tail keys is always
        // safe (at worst a rare crash re-checks a tiny suffix on resume).
        while self.completed_ahead.len() > MAX_WATERMARK_COMPLETED_AHEAD {
            let _ = self.completed_ahead.pop_last();
        }
    }
}

impl SafeWatermarkTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_buffered_floor(&self, min_buffered_wire: Option<String>) {
        if let Ok(mut g) = self.inner.lock() {
            g.buffered_floor = min_buffered_wire;
            g.drain_safe();
        }
    }

    pub fn mark_dispatched(&self, wire_key: String) {
        if let Ok(mut g) = self.inner.lock() {
            g.in_flight.insert(wire_key);
        }
    }

    pub fn mark_completed(&self, wire_key: &str, succeeded: bool) {
        if let Ok(mut g) = self.inner.lock() {
            g.in_flight.remove(wire_key);
            if !succeeded {
                let replace = g.first_failed.as_deref().is_none_or(|f| wire_key < f);
                if replace {
                    g.first_failed = Some(wire_key.to_string());
                }
                g.completed_ahead.retain(|k| k.as_str() < wire_key);
                return;
            }
            if g.first_failed.as_deref().is_none_or(|f| wire_key < f) {
                g.completed_ahead.insert(wire_key.to_string());
            }
            g.drain_safe();
        }
    }

    /// Record a key that was skipped (already up-to-date or filtered) without entering the worker pool.
    pub fn mark_skipped(&self, wire_key: &str) {
        self.mark_completed(wire_key, true);
    }

    pub fn current_watermark(&self) -> Option<String> {
        let mut g = self.inner.lock().ok()?;
        g.drain_safe();
        let safe = g.safe_completed.as_ref()?;
        if g.in_flight.first().is_some_and(|inf| safe >= inf) {
            return None;
        }
        if g.first_failed
            .as_deref()
            .is_some_and(|f| safe.as_str() >= f)
        {
            return None;
        }
        if g.buffered_floor
            .as_deref()
            .is_some_and(|bf| safe.as_str() >= bf)
        {
            return None;
        }
        Some(safe.clone())
    }
}
