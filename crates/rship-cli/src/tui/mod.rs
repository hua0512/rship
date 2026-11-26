//! Zero-flicker, borderless multi-task live terminal TUI for `rship`.
//!
//! Design inspired by `uv`, `cargo`, and `docker buildx`:
//! - **Borderless & responsive**: adapts dynamically to live terminal width and height
//!   (no right-hand vertical border that CJK paths or narrow split panes can break),
//!   expanding paths and progress bars smoothly on wide terminals while never wrapping
//!   on narrow panes.
//! - **CJK / wide-char accurate**: computes real East Asian & BMP emoji display-column
//!   widths so columns and progress bars align cleanly even for CJK/emoji filenames.
//! - **Phase-aware & alive**: renders an animated braille spinner during scan/plan/mkdir/finalize
//!   phases and a rolling windowed throughput sparkline (`▁▂▃▄▅▆▇█`) during active transfers.
//! - **Zero-flicker synchronized updates**: wraps frames in DEC Mode 2026 synchronized output
//!   (`\x1b[?2026h`…`\x1b[?2026l`) with reflow-aware cursor-up redraws, per-line `\x1b[2K`,
//!   and race-free cursor hide/restore across `stop()`, `Drop`, and forced `Ctrl+C`.

mod render;

#[cfg(test)]
pub use render::render_dashboard_lines;
pub use render::{RenderContext, SparklineHistory, render_dashboard_lines_ctx, str_display_width};

use render::{
    ABS_MIN_WIDTH, DEFAULT_TERM_HEIGHT, DEFAULT_TERM_WIDTH, MAX_TERM_WIDTH, SPARKLINE_LEN,
    reflowed_row_count, strip_ansi,
};
use rship_core::buffer::BufferPool;
use rship_core::engine::FileTransferStatus;
use rship_core::progress::{
    EventSink, ProgressSnapshot, TransferEvent, TransferProgress, format_progress_line,
};
use rship_core::{ErrorCategory, ErrorKind, RetryClass};
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_ACTIVE_SLOTS: usize = 8;

/// Global reference count of active TUI dashboards that have hidden the terminal cursor,
/// enabling forced-exit signal handlers (second Ctrl+C) to immediately restore `\x1b[?25h`.
static HIDDEN_CURSOR_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Best-effort immediate cursor restore for forced-exit signal handlers.
pub fn restore_cursor_if_hidden() {
    if HIDDEN_CURSOR_COUNT.swap(0, Ordering::AcqRel) > 0 {
        let _ = write!(io::stderr(), "\x1b[?25h");
        let _ = io::stderr().flush();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveDisplayMode {
    Off,
    SingleLine,
    MultiTaskTui,
    JsonLines { interval: Duration },
}

#[derive(Debug, Default)]
struct TerminalRenderState {
    stopped: bool,
    cursor_hidden: bool,
    prev_line_widths: Vec<usize>,
}

pub struct LiveDashboardHandle {
    mode: LiveDisplayMode,
    done_tx: tokio::sync::watch::Sender<Option<bool>>,
    render_state: Arc<Mutex<TerminalRenderState>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl LiveDashboardHandle {
    pub fn spawn(
        mode: LiveDisplayMode,
        title: impl Into<String>,
        progress: Arc<TransferProgress>,
        pool: BufferPool,
    ) -> Option<Self> {
        if mode == LiveDisplayMode::Off {
            return None;
        }
        let title = title.into();
        let st_err = crate::ui::Style::stderr();
        let use_color = st_err.has_color();
        let is_tty = st_err.is_tty() && crate::ui::stderr_supports_ansi();
        let render_state = Arc::new(Mutex::new(TerminalRenderState::default()));
        let render_state_task = render_state.clone();
        let (done_tx, mut done_rx) = tokio::sync::watch::channel::<Option<bool>>(None);

        let join = tokio::spawn(async move {
            let interval = match mode {
                LiveDisplayMode::MultiTaskTui => Duration::from_millis(120),
                LiveDisplayMode::SingleLine => Duration::from_millis(200),
                LiveDisplayMode::JsonLines { interval } => interval.max(Duration::from_millis(100)),
                LiveDisplayMode::Off => return,
            };
            // `tokio::time::interval` fires its first tick immediately. For JSON lines that
            // would emit a zero-progress `observing` record before the job has done anything,
            // racing any fast fatal error, so machine consumers first hear from us one
            // interval in. Interactive modes keep the immediate first frame.
            let first_tick = match mode {
                LiveDisplayMode::JsonLines { .. } => tokio::time::Instant::now() + interval,
                _ => tokio::time::Instant::now(),
            };
            let mut tick_timer = tokio::time::interval_at(first_tick, interval);
            let mut tick_idx = 0usize;
            let mut spark = SparklineHistory::new(SPARKLINE_LEN);
            let mut prev_bytes: u64 = 0;
            let mut prev_sample_at = Instant::now();

            loop {
                tokio::select! {
                    _ = tick_timer.tick() => {
                        let snap = progress.snapshot(Some(&pool));
                        match mode {
                            LiveDisplayMode::SingleLine => {
                                let mut guard = render_state_task
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                if guard.stopped {
                                    break;
                                }
                                let line = format_progress_line(&snap);
                                let styled = if use_color {
                                    format!("\x1b[36m●\x1b[0m {line}")
                                } else {
                                    line.clone()
                                };
                                let _ = write!(io::stderr(), "\r\x1b[2K{styled}");
                                let _ = io::stderr().flush();
                                guard.prev_line_widths = vec![str_display_width(&line)];
                            }
                            LiveDisplayMode::MultiTaskTui => {
                                // Compute true windowed delta throughput roughly every ~0.48s
                                // so stalls and bursts immediately appear in the 6-bar sparkline.
                                if tick_idx.is_multiple_of(4) {
                                    let now = Instant::now();
                                    let dt = now.duration_since(prev_sample_at).as_secs_f64();
                                    if dt >= 0.05 && (snap.bytes_done > 0 || prev_bytes > 0) {
                                        let delta = snap.bytes_done.saturating_sub(prev_bytes);
                                        spark.push(delta as f64 / dt);
                                        prev_bytes = snap.bytes_done;
                                        prev_sample_at = now;
                                    }
                                }
                                let spark_str = if use_color { spark.render() } else { String::new() };
                                let (width, height) = detect_terminal_size();
                                let viewport_slots = height.saturating_sub(4).min(MAX_ACTIVE_SLOTS);
                                let ctx = RenderContext {
                                    width,
                                    tick: tick_idx,
                                    color: use_color,
                                    max_slots: viewport_slots,
                                    sparkline: &spark_str,
                                };
                                let rendered = render_dashboard_lines_ctx(&title, &snap, &ctx);
                                let line_widths: Vec<usize> = rendered
                                    .iter()
                                    .map(|l| str_display_width(&strip_ansi(l)))
                                    .collect();

                                let mut guard = render_state_task
                                    .lock()
                                    .unwrap_or_else(|e| e.into_inner());
                                if guard.stopped {
                                    break;
                                }
                                if is_tty && use_color && !guard.cursor_hidden {
                                    let _ = write!(io::stderr(), "\x1b[?25l");
                                    guard.cursor_hidden = true;
                                    HIDDEN_CURSOR_COUNT.fetch_add(1, Ordering::AcqRel);
                                }
                                let prev_rows =
                                    reflowed_row_count(&guard.prev_line_widths, width);
                                draw_frame(&rendered, prev_rows, is_tty && use_color);
                                guard.prev_line_widths = line_widths;
                                tick_idx = tick_idx.wrapping_add(1);
                            }
                            LiveDisplayMode::JsonLines { .. } => {
                                let json_line = format_progress_jsonl(&title, &snap);
                                crate::errors::write_jsonl_stderr(&json_line);
                            }
                            LiveDisplayMode::Off => break,
                        }
                    }
                    _ = done_rx.changed() => {
                        if let Some(emit_final) = *done_rx.borrow() {
                            if emit_final && matches!(mode, LiveDisplayMode::JsonLines { .. }) {
                                let snap = progress.snapshot(Some(&pool));
                                let json_line = format_progress_jsonl(&title, &snap);
                                crate::errors::write_jsonl_stderr(&json_line);
                            }
                            break;
                        }
                    }
                }
            }
        });

        Some(Self {
            mode,
            done_tx,
            render_state,
            join: Some(join),
        })
    }

    fn cleanup_terminal(&self) {
        let mut guard = self.render_state.lock().unwrap_or_else(|e| e.into_inner());
        guard.stopped = true;
        let restore_cursor = if guard.cursor_hidden {
            guard.cursor_hidden = false;
            HIDDEN_CURSOR_COUNT.fetch_sub(1, Ordering::AcqRel);
            true
        } else {
            false
        };
        let prev_widths = std::mem::take(&mut guard.prev_line_widths);
        match self.mode {
            LiveDisplayMode::SingleLine => {
                if !prev_widths.is_empty() {
                    let _ = write!(io::stderr(), "\r\x1b[2K");
                    let _ = io::stderr().flush();
                }
            }
            LiveDisplayMode::MultiTaskTui => {
                let (width, _) = detect_terminal_size();
                let prev_rows = reflowed_row_count(&prev_widths, width);
                clear_frame(prev_rows, restore_cursor);
            }
            LiveDisplayMode::JsonLines { .. } | LiveDisplayMode::Off => {
                if restore_cursor {
                    let _ = write!(io::stderr(), "\x1b[?25h");
                    let _ = io::stderr().flush();
                }
            }
        }
    }

    pub async fn stop(mut self, emit_final_jsonl: bool) {
        let _ = self.done_tx.send(Some(emit_final_jsonl));
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
        self.cleanup_terminal();
    }
}

impl Drop for LiveDashboardHandle {
    fn drop(&mut self) {
        let _ = self.done_tx.send(Some(false));
        if let Some(j) = self.join.take() {
            j.abort();
        }
        self.cleanup_terminal();
    }
}

/// Detect stderr terminal `(cols, rows)` without ever clamping real narrow panes upward.
pub fn detect_terminal_size() -> (usize, usize) {
    let (raw_cols, raw_rows) = query_os_stderr_size().unwrap_or_else(|| {
        let cols = std::env::var("COLUMNS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TERM_WIDTH);
        let rows = std::env::var("LINES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_TERM_HEIGHT);
        (cols, rows)
    });
    (
        raw_cols.clamp(ABS_MIN_WIDTH, MAX_TERM_WIDTH),
        raw_rows.max(4),
    )
}

#[cfg(windows)]
fn query_os_stderr_size() -> Option<(usize, usize)> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        CONSOLE_SCREEN_BUFFER_INFO, GetConsoleScreenBufferInfo, GetStdHandle, STD_ERROR_HANDLE,
    };

    // SAFETY: Standard Win32 console buffer query into a valid zeroed stack struct.
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) != 0 {
            let cols = isize::from(info.srWindow.Right) - isize::from(info.srWindow.Left) + 1;
            let rows = isize::from(info.srWindow.Bottom) - isize::from(info.srWindow.Top) + 1;
            if cols > 0 && rows > 0 {
                return Some((cols as usize, rows as usize));
            }
        }
    }
    None
}

#[cfg(unix)]
fn query_os_stderr_size() -> Option<(usize, usize)> {
    // SAFETY: `TIOCGWINSZ` writes into stack-allocated `libc::winsize` for `STDERR_FILENO`.
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(libc::STDERR_FILENO, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            let rows = if ws.ws_row > 0 {
                ws.ws_row as usize
            } else {
                DEFAULT_TERM_HEIGHT
            };
            return Some((ws.ws_col as usize, rows));
        }
    }
    None
}

#[cfg(not(any(windows, unix)))]
fn query_os_stderr_size() -> Option<(usize, usize)> {
    None
}

/// Format one structured newline-delimited JSON (JSONL) progress event for machine
/// consumers (`--json-progress --stats 1s`).
pub fn format_progress_jsonl(title: &str, snap: &ProgressSnapshot) -> String {
    let ts_unix_ms = rship_core::time::now_unix_ms();
    let current_file = snap.active_items.first().map(|i| i.path.as_str());
    let (pool_in_use, pool_peak, pool_cap) = match snap.pool {
        Some(p) => (
            Some(p.in_use_bytes() as u64),
            Some(p.peak_bytes() as u64),
            Some(p.max_bytes() as u64),
        ),
        None => (None, None, None),
    };
    serde_json::json!({
        "event": "progress",
        "ts_unix_ms": ts_unix_ms,
        "mode": title.to_ascii_lowercase(),
        "phase": snap.phase.as_str(),
        "bytes_done": snap.bytes_done,
        "bytes_total": snap.bytes_total,
        "speed_bps": snap.throughput_bps.round() as u64,
        "eta_secs": snap.eta_secs,
        "files_done": snap.files_done,
        "files_total": snap.files_total,
        "files_planned": snap.files_planned,
        "files_skipped": snap.files_skipped,
        "sources_deleted": snap.sources_deleted,
        "dirs_created": snap.dirs_created,
        "active_transfers": snap.active_transfers,
        "errors": snap.errors,
        "elapsed_secs": (snap.elapsed_secs * 1000.0).round() / 1000.0,
        "current_file": current_file,
        "active_files": snap.active_items,
        "buffer_pool_in_use_bytes": pool_in_use,
        "buffer_pool_peak_bytes": pool_peak,
        "buffer_pool_cap_bytes": pool_cap,
    })
    .to_string()
}

/// Real-time [`EventSink`] emitting `"event": "error"` JSONL lines onto `stderr` as
/// individual file or operational errors occur under `--json-progress`.
pub struct JsonErrorEventSink {
    mode: String,
}

impl JsonErrorEventSink {
    pub fn new(mode: impl Into<String>) -> Arc<Self> {
        Arc::new(Self { mode: mode.into() })
    }
}

impl EventSink for JsonErrorEventSink {
    fn on_event(&self, event: TransferEvent) {
        match event {
            TransferEvent::FileCompleted { job_id, result, .. }
                if result.status == FileTransferStatus::Failed =>
            {
                let kind = result.error_kind.unwrap_or(ErrorKind::Protocol);
                let retry = result.retry_class.unwrap_or(RetryClass::Permanent);
                let category = result
                    .error_category
                    .unwrap_or_else(|| ErrorCategory::from_kind_and_retry(kind, retry));
                let message = result.error.as_deref().unwrap_or("transfer failed");
                let line = crate::errors::format_error_jsonl(
                    &self.mode,
                    Some(&job_id),
                    Some(&result.path),
                    kind,
                    category,
                    retry,
                    result.retry_after_ms,
                    message,
                    false,
                );
                crate::errors::write_jsonl_stderr(&line);
            }
            TransferEvent::ErrorOccurred { job_id, error, .. } => {
                let line = crate::errors::format_error_jsonl(
                    &self.mode,
                    Some(&job_id),
                    error.path.as_deref(),
                    error.kind,
                    error.category,
                    error.retry_class,
                    error.retry_after_ms,
                    &error.message,
                    false,
                );
                crate::errors::write_jsonl_stderr(&line);
            }
            _ => {}
        }
    }
}

fn draw_frame(lines: &[String], prev_rows: usize, sync_mode: bool) {
    let mut buf = String::with_capacity(lines.len() * 128 + 32);
    if sync_mode {
        buf.push_str("\x1b[?2026h");
    }
    if prev_rows > 0 {
        buf.push_str(&format!("\x1b[{prev_rows}A\r"));
    }
    for line in lines {
        buf.push_str("\x1b[2K");
        buf.push_str(line);
        buf.push('\n');
    }
    if prev_rows > lines.len() {
        buf.push_str("\x1b[J");
    }
    if sync_mode {
        buf.push_str("\x1b[?2026l");
    }
    let _ = io::stderr().write_all(buf.as_bytes());
    let _ = io::stderr().flush();
}

fn clear_frame(prev_rows: usize, restore_cursor: bool) {
    let mut buf = String::with_capacity(32);
    if prev_rows > 0 {
        buf.push_str(&format!("\x1b[{prev_rows}A\r\x1b[J"));
    }
    if restore_cursor {
        buf.push_str("\x1b[?25h");
    }
    if !buf.is_empty() {
        let _ = io::stderr().write_all(buf.as_bytes());
        let _ = io::stderr().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::render::{char_display_width, truncate_middle_cols};
    use super::*;
    use rship_core::buffer::BufferPoolStats;
    use rship_core::progress::{ActiveTransferSnapshot, TransferPhase};

    #[test]
    fn renders_borderless_multi_task_dashboard_with_cjk_alignment_falcon_and_overflow() {
        let mut pool_stats = BufferPoolStats::default();
        pool_stats.max_units = 4096;
        pool_stats.in_use_units = 512;
        pool_stats.peak_units = 1024;
        pool_stats.slab_allocations = 16;
        pool_stats.slab_recycles = 40;

        let mut item1 = ActiveTransferSnapshot::default();
        item1.id = 1;
        item1.path = "very/deeply/nested/中文目录/archive_2026_backup.tar.zst".into();
        item1.lane_tag = "L";
        item1.total_bytes = 20 * 1024 * 1024;
        item1.done_bytes = 10 * 1024 * 1024;
        item1.elapsed_secs = 2.0;
        item1.speed_bps = 5.0 * 1024.0 * 1024.0;

        let mut item2 = ActiveTransferSnapshot::default();
        item2.id = 2;
        item2.path = "中文备份/notes.md".into();
        item2.lane_tag = "S";
        item2.total_bytes = 4096;
        item2.done_bytes = 4096;
        item2.elapsed_secs = 0.1;
        item2.speed_bps = 40960.0;

        let mut item3 = ActiveTransferSnapshot::default();
        item3.id = 3;
        item3.path = "media/video.mp4".into();
        item3.lane_tag = "L";
        item3.total_bytes = 1000;
        item3.done_bytes = 250;
        item3.elapsed_secs = 1.0;
        item3.speed_bps = 250.0;

        let mut snap = ProgressSnapshot::default();
        snap.phase = TransferPhase::Transferring;
        snap.files_total = 4218;
        snap.files_planned = 4216;
        snap.files_done = 3124;
        snap.files_skipped = 2;
        snap.server_side_copies = 3;
        snap.sources_deleted = 1;
        snap.dirs_created = 2;
        snap.bytes_total = 100 * 1024 * 1024;
        snap.bytes_done = 50 * 1024 * 1024;
        snap.active_transfers = 4;
        snap.elapsed_secs = 10.0;
        snap.throughput_bps = 5.0 * 1024.0 * 1024.0;
        snap.eta_secs = Some(10);
        snap.pool = Some(pool_stats);
        snap.small_lane_concurrency = Some(6);
        snap.large_lane_concurrency = Some(4);
        snap.active_items = vec![item1, item2, item3];

        let lines = render_dashboard_lines("COPY", &snap, 2);
        let joined = lines.join("\n");
        assert!(joined.contains("copy"));
        assert!(joined.contains("50.0%"));
        assert!(joined.contains("3,124/4,218 files"));
        assert!(joined.contains("3 ssc"));
        assert!(joined.contains("Falcon S:6 L:4"));
        assert!(joined.contains("中文备份/notes.md"));
        assert!(joined.contains("+1 more active transfer(s)"));
        assert!(!joined.contains('╭'), "style 1 must be borderless");

        let mut spark = SparklineHistory::default();
        for v in [1.0, 2.0, 4.0, 5.0, 4.5, 5.0, 0.0, 3.0] {
            spark.push(v * 1024.0 * 1024.0);
        }
        let spark_str = spark.render();
        assert_eq!(spark_str.chars().count(), SPARKLINE_LEN);

        // Verify styled lines never exceed terminal width across 40..=96 cols (including 48..=50 & Finalizing @ 80!)
        for &w in &[36usize, 40, 48, 49, 50, 52, 72, 80, 96] {
            for &phase in &[TransferPhase::Transferring, TransferPhase::Finalizing] {
                let mut s = snap.clone();
                s.phase = phase;
                if phase == TransferPhase::Finalizing {
                    s.eta_secs = None;
                }
                for color in [true, false] {
                    let ctx = RenderContext {
                        width: w,
                        tick: 3,
                        color,
                        max_slots: 2,
                        sparkline: &spark_str,
                    };
                    let out = render_dashboard_lines_ctx("COPY", &s, &ctx);
                    for line in &out {
                        let plain = strip_ansi(line);
                        assert!(
                            str_display_width(&plain) <= w,
                            "width={w} phase={phase:?} color={color} exceeded ({}): {plain}",
                            str_display_width(&plain)
                        );
                    }
                    if phase == TransferPhase::Finalizing && w >= 60 {
                        assert!(strip_ansi(&out[0]).contains("Finalizing…"));
                    }
                }
            }
        }

        // Verify CJK slot rows align identically at normal widths.
        let ctx96 = RenderContext {
            width: 96,
            tick: 3,
            color: true,
            max_slots: 2,
            sparkline: &spark_str,
        };
        let styled = render_dashboard_lines_ctx("COPY", &snap, &ctx96);
        let slot0_w = str_display_width(&strip_ansi(&styled[3]));
        let slot1_w = str_display_width(&strip_ansi(&styled[4]));
        assert_eq!(slot0_w, slot1_w, "CJK slot rows must align identically");

        // Pre-transfer phase respects narrow panes in BOTH color and plain modes.
        let mut scan_snap = ProgressSnapshot::default();
        scan_snap.phase = TransferPhase::CreatingDirs;
        scan_snap.dirs_created = 120;
        scan_snap.elapsed_secs = 12.0;
        for &w in &[32usize, 48, 60, 96] {
            for color in [true, false] {
                let ctx = RenderContext {
                    width: w,
                    tick: 2,
                    color,
                    max_slots: 4,
                    sparkline: "",
                };
                let scan_lines = render_dashboard_lines_ctx("BISYNC", &scan_snap, &ctx);
                assert_eq!(scan_lines.len(), 1);
                let plain = strip_ansi(&scan_lines[0]);
                assert!(
                    str_display_width(&plain) <= w,
                    "pre-transfer width={w} color={color} exceeded ({}): {plain}",
                    str_display_width(&plain)
                );
            }
        }

        // Reflow row count accounts for terminal shrink.
        assert_eq!(reflowed_row_count(&[95, 80, 0, 95], 70), 7);

        // JSONL schema remains unchanged.
        let jsonl = format_progress_jsonl("MOVE", &snap);
        let parsed: serde_json::Value = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(parsed["event"], "progress");
        assert_eq!(parsed["mode"], "move");
        assert_eq!(parsed["phase"], "transferring");
        assert_eq!(parsed["bytes_done"], 50 * 1024 * 1024);
        assert_eq!(parsed["bytes_total"], 100 * 1024 * 1024);
        assert_eq!(parsed["files_done"], 3124);
        assert_eq!(parsed["files_total"], 4218);
        assert_eq!(parsed["files_planned"], 4216);
        assert_eq!(parsed["files_skipped"], 2);
        assert_eq!(parsed["eta_secs"], 10);
        assert_eq!(
            parsed["current_file"],
            "very/deeply/nested/中文目录/archive_2026_backup.tar.zst"
        );
    }

    #[test]
    fn cjk_emoji_combining_width_and_middle_truncation_are_sound() {
        assert_eq!(str_display_width("中文目录"), 8);
        assert_eq!(str_display_width("abc中文"), 7);
        assert_eq!(char_display_width('\u{3099}'), 0); // Katakana combining dakuten
        assert_eq!(char_display_width('\u{1F3FD}'), 0); // Emoji skin-tone modifier
        assert_eq!(char_display_width('✅'), 2); // BMP wide emoji
        assert_eq!(str_display_width("👋🏽"), 2);

        let truncated = truncate_middle_cols("very/deeply/nested/中文目录/archive_2026.tar", 20);
        assert!(str_display_width(&truncated) <= 20);
        assert!(truncated.contains('…'));

        // Combining acute accent after 'e' must never be orphaned right after '…'.
        let nfd = "aaaaaaaaaa/bbbbbbbb/e\u{0301}tail.txt";
        let mid = truncate_middle_cols(nfd, 16);
        assert!(str_display_width(&mid) <= 16);
        let after_ellipsis = mid.split('…').nth(1).unwrap_or("");
        if let Some(first) = after_ellipsis.chars().next() {
            assert!(
                char_display_width(first) > 0,
                "orphaned combining mark after ellipsis: {mid:?}"
            );
        }
    }
}
