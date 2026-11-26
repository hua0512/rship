//! Pure, stateless TUI frame renderer and zero-dependency Unicode column-width layout engine.

use rship_core::progress::{
    ActiveTransferSnapshot, ProgressSnapshot, TransferPhase, format_human_bytes,
};
use std::collections::VecDeque;

pub(super) const DEFAULT_TERM_WIDTH: usize = 92;
pub(super) const DEFAULT_TERM_HEIGHT: usize = 24;
pub(super) const ABS_MIN_WIDTH: usize = 20;
pub(super) const MAX_TERM_WIDTH: usize = 132;
pub(super) const SPARKLINE_LEN: usize = 6;

const SPINNER_UNICODE: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: [&str; 4] = ["-", "\\", "|", "/"];
const SPARK_BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Rolling speed-history buffer powering the compact windowed throughput sparkline.
#[derive(Debug, Clone)]
pub struct SparklineHistory {
    samples: VecDeque<f64>,
    capacity: usize,
}

impl Default for SparklineHistory {
    fn default() -> Self {
        Self::new(SPARKLINE_LEN)
    }
}

impl SparklineHistory {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            samples: VecDeque::with_capacity(cap),
            capacity: cap,
        }
    }

    pub fn push(&mut self, bps: f64) {
        let cap = self.capacity.max(1);
        while self.samples.len() >= cap {
            self.samples.pop_front();
        }
        self.samples.push_back(bps.max(0.0));
    }

    /// Render a compact Unicode sparkline (empty until at least 2 samples arrive with any > 0).
    pub fn render(&self) -> String {
        if self.samples.len() < 2 {
            return String::new();
        }
        let max = self.samples.iter().copied().fold(0.0_f64, f64::max);
        if max <= 0.0 {
            return String::new();
        }
        self.samples
            .iter()
            .map(|&v| {
                let norm = (v / max).clamp(0.0, 1.0);
                let idx = ((norm * (SPARK_BLOCKS.len() - 1) as f64).round() as usize)
                    .min(SPARK_BLOCKS.len() - 1);
                SPARK_BLOCKS[idx]
            })
            .collect()
    }
}

/// Rendering context for deterministic, pure frame rendering.
#[derive(Debug, Clone)]
pub struct RenderContext<'a> {
    pub width: usize,
    pub tick: usize,
    pub color: bool,
    pub max_slots: usize,
    pub sparkline: &'a str,
}

/// Compute total physical rows occupied by previously printed lines after terminal reflow.
pub(super) fn reflowed_row_count(line_widths: &[usize], current_cols: usize) -> usize {
    let cols = current_cols.max(1);
    line_widths.iter().map(|&w| w.max(1).div_ceil(cols)).sum()
}

/// Pure, deterministic plain TUI frame renderer (used by unit tests).
#[cfg(test)]
pub fn render_dashboard_lines(
    title: &str,
    snap: &ProgressSnapshot,
    max_slots: usize,
) -> Vec<String> {
    let ctx = RenderContext {
        width: DEFAULT_TERM_WIDTH,
        tick: 0,
        color: false,
        max_slots,
        sparkline: "",
    };
    render_dashboard_lines_ctx(title, snap, &ctx)
}

/// Borderless, responsive, color-aware TUI frame renderer (`uv` / `cargo` aesthetic).
pub fn render_dashboard_lines_ctx(
    title: &str,
    snap: &ProgressSnapshot,
    ctx: &RenderContext<'_>,
) -> Vec<String> {
    let width = ctx.width.clamp(ABS_MIN_WIDTH, MAX_TERM_WIDTH);
    let color = ctx.color;
    let verb = title.to_ascii_lowercase();
    let spinner = if color {
        SPINNER_UNICODE[ctx.tick % SPINNER_UNICODE.len()]
    } else {
        SPINNER_ASCII[ctx.tick % SPINNER_ASCII.len()]
    };

    let dim = |s: &str| -> String {
        if color {
            format!("\x1b[2m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let bold = |s: &str| -> String {
        if color {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let cyan_bold = |s: &str| -> String {
        if color {
            format!("\x1b[1;36m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let green_bold = |s: &str| -> String {
        if color {
            format!("\x1b[1;32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let sky = |s: &str| -> String {
        if color {
            format!("\x1b[36m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };

    let mut lines = Vec::new();
    let elapsed = format_duration(snap.elapsed_secs as u64);

    // Phase-aware early view before planned totals arrive.
    let pre_transfer = matches!(
        snap.phase,
        TransferPhase::Preparing | TransferPhase::Observing | TransferPhase::CreatingDirs
    ) && snap.bytes_total == 0
        && snap.files_total == 0
        && snap.active_items.is_empty();

    if pre_transfer {
        let phase_msg = match snap.phase {
            TransferPhase::Preparing => "Preparing transfer session…",
            TransferPhase::Observing => "Scanning source & destination…",
            TransferPhase::CreatingDirs => "Creating destination directories…",
            _ => "Working…",
        };
        let extra = if snap.dirs_created > 0 {
            format!(" ({} dirs)", snap.dirs_created)
        } else {
            String::new()
        };
        let msg_full = format!("{phase_msg}{extra}");
        let prefix_w = 2 + str_display_width(&verb) + 2;
        let suffix_w = 2 + str_display_width(&elapsed);
        let msg_budget = width.saturating_sub(prefix_w + suffix_w);
        if msg_budget < 6 {
            let compact = truncate_right_cols(&format!("{spinner} {verb} {elapsed}"), width);
            lines.push(if color { bold(&compact) } else { compact });
        } else {
            let clipped_msg = truncate_right_cols(&msg_full, msg_budget);
            let line = if color {
                format!(
                    "{} {}  {}  {}",
                    cyan_bold(spinner),
                    bold(&verb),
                    sky(&clipped_msg),
                    dim(&elapsed),
                )
            } else {
                format!("{spinner} {verb}  {clipped_msg}  {elapsed}")
            };
            lines.push(line);
        }
        return lines;
    }

    // 1. Primary headline: spinner + verb + total bar + pct + bytes + speed + sparkline + tail
    let ratio = if snap.bytes_total > 0 {
        (snap.bytes_done as f64 / snap.bytes_total as f64).clamp(0.0, 1.0)
    } else if snap.files_planned > 0 {
        (snap.files_done as f64 / snap.files_planned as f64).clamp(0.0, 1.0)
    } else if snap.files_total > 0 {
        ((snap.files_done + snap.files_skipped) as f64 / snap.files_total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let pct = if !snap.totals_discovered {
        "  ... ".to_string()
    } else {
        format!("{:5.1}%", ratio * 100.0)
    };
    let total_suffix = if snap.totals_discovered { "" } else { "+" };
    let bytes_summary = format!(
        "{} / {}{total_suffix}",
        format_human_bytes(snap.bytes_done),
        format_human_bytes(snap.bytes_total)
    );
    let speed = format!("{}/s", format_human_bytes(snap.throughput_bps as u64));
    let tail_plain = if snap.phase == TransferPhase::Finalizing {
        "Finalizing…".to_string()
    } else {
        snap.eta_secs
            .map(|s| format!("ETA {}", format_duration(s)))
            .unwrap_or_else(|| elapsed.clone())
    };

    let show_spark = color && !ctx.sparkline.is_empty() && width >= 86;
    let spark_vis = if show_spark {
        1 + str_display_width(ctx.sparkline)
    } else {
        0
    };

    // Measure exact tail_plain (including "Finalizing…") BEFORE sizing the progress bar!
    let fixed_head_cols = 2 // spinner + space
        + str_display_width(&verb)
        + 2 // gap
        + if color { 0 } else { 2 } // optional brackets in plain mode
        + 2 + str_display_width(&pct)
        + 2 + str_display_width(&bytes_summary)
        + 2 + str_display_width(&speed)
        + spark_vis
        + 2 + str_display_width(&tail_plain);

    if width < fixed_head_cols + 10 {
        // Narrow pane fallback: omit full bar + bytes summary and guarantee <= width.
        let compact_plain = format!("{spinner} {verb} {pct} {speed} {tail_plain}");
        if str_display_width(&compact_plain) <= width {
            let line = if color {
                format!(
                    "{} {} {} {} {}",
                    cyan_bold(spinner),
                    bold(&verb),
                    bold(&pct),
                    green_bold(&speed),
                    dim(&tail_plain),
                )
            } else {
                compact_plain
            };
            lines.push(line);
        } else {
            let minimal = truncate_right_cols(&format!("{spinner} {verb} {pct} {speed}"), width);
            lines.push(if color { bold(&minimal) } else { minimal });
        }
    } else {
        let bar_w = width.saturating_sub(fixed_head_cols).clamp(10, 26);
        if color {
            let bar = render_bar(ratio, bar_w, true);
            let spark_part = if show_spark {
                format!(" {}", sky(ctx.sparkline))
            } else {
                String::new()
            };
            lines.push(format!(
                "{} {}  {}  {}  {}  {}{spark_part}  {}",
                cyan_bold(spinner),
                bold(&verb),
                bar,
                bold(&pct),
                dim(&bytes_summary),
                green_bold(&speed),
                dim(&tail_plain),
            ));
        } else {
            let bar = render_bar(ratio, bar_w, false);
            let plain =
                format!("{spinner} {verb}  [{bar}]  {pct}  {bytes_summary}  {speed}  {tail_plain}");
            lines.push(truncate_right_cols(&plain, width));
        }
    }

    // 2. Indented compact telemetry sub-row: files, skips, ssc, moves, errors, BufferPool, Falcon
    let mut meta_parts: Vec<String> = Vec::with_capacity(7);
    meta_parts.push(format!(
        "{}/{}{total_suffix} files",
        format_count(snap.files_done),
        format_count(snap.files_total)
    ));
    if snap.files_skipped > 0 {
        meta_parts.push(format!("{} skip", format_count(snap.files_skipped)));
    }
    if snap.server_side_copies > 0 {
        meta_parts.push(format!("{} ssc", snap.server_side_copies));
    }
    if snap.sources_deleted > 0 {
        meta_parts.push(format!("{} mv", snap.sources_deleted));
    }
    if snap.errors > 0 {
        meta_parts.push(format!("{} err", snap.errors));
    }
    if let Some(p) = snap.pool {
        meta_parts.push(format!(
            "buf {}/{} (pk {})",
            format_compact_bytes(p.in_use_bytes() as u64),
            format_compact_bytes(p.max_bytes() as u64),
            format_compact_bytes(p.peak_bytes() as u64),
        ));
    }
    if let (Some(sc), Some(lc)) = (snap.small_lane_concurrency, snap.large_lane_concurrency) {
        meta_parts.push(format!("Falcon S:{sc} L:{lc}"));
    }

    let sub_plain = format!("  {}", meta_parts.join(" · "));
    let sub_clipped = truncate_right_cols(&sub_plain, width);
    if color {
        let colored_sub = if snap.errors > 0 {
            let err_tok = format!("{} err", snap.errors);
            sub_clipped.replace(
                &err_tok,
                &format!("\x1b[0m\x1b[1;31m{err_tok}\x1b[0m\x1b[2m"),
            )
        } else {
            sub_clipped
        };
        lines.push(dim(&colored_sub));
    } else {
        lines.push(sub_clipped);
    }

    // 3. Per-file active slots (borderless, dynamically sized path + bar columns)
    if !snap.active_items.is_empty() && ctx.max_slots > 0 {
        lines.push(String::new());
        for item in snap.active_items.iter().take(ctx.max_slots) {
            lines.push(format_active_slot_row(item, width, color));
        }
        if snap.active_items.len() > ctx.max_slots {
            let extra = snap.active_items.len() - ctx.max_slots;
            let more = truncate_right_cols(&format!("  … +{extra} more active transfer(s)"), width);
            lines.push(if color { dim(&more) } else { more });
        }
    }

    lines
}

fn format_active_slot_row(item: &ActiveTransferSnapshot, width: usize, color: bool) -> String {
    let ratio = if item.total_bytes > 0 {
        (item.done_bytes as f64 / item.total_bytes as f64).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let tag = if item.lane_tag.is_empty() {
        " · ".to_string()
    } else {
        format!("[{}]", item.lane_tag)
    };
    let pct = format!("{:3.0}%", ratio * 100.0);
    let speed = format!("{:>11}/s", format_human_bytes(item.speed_bps as u64));

    let bar_w: usize = if width >= 96 {
        18
    } else if width >= 74 {
        14
    } else {
        10
    };

    // Full layout: "  "(2) + tag(3) + " "(1) + path(path_w) + "  "(2) + bar + " "(1) + pct(4) + " "(1) + speed(13)
    let fixed_cols = 2 + 3 + 1 + 2 + bar_w + if color { 0 } else { 2 } + 1 + 4 + 1 + 13;

    // Narrow pane fallback: drop per-slot bar (and speed if ultra-narrow) so row strictly fits `<= width`.
    if width < fixed_cols + 8 {
        let compact_fixed = 2 + 3 + 1 + 2 + 4; // "  [L] <path>  100%"
        let path_w = width.saturating_sub(compact_fixed).max(4);
        let path_trunc = truncate_middle_cols(&item.path, path_w);
        let path_padded = pad_right_cols(&path_trunc, path_w);
        if !color {
            return truncate_right_cols(&format!("  {tag} {path_padded}  {pct}"), width);
        }
        let styled_tag = style_lane_tag(item.lane_tag);
        let styled_pct = style_pct(&pct, ratio);
        return format!("  {styled_tag} {path_padded}  {styled_pct}");
    }

    let path_w = width.saturating_sub(fixed_cols).clamp(8, 54);
    let path_trunc = truncate_middle_cols(&item.path, path_w);
    let path_padded = pad_right_cols(&path_trunc, path_w);

    if !color {
        let bar = render_bar(ratio, bar_w, false);
        let row = format!("  {tag} {path_padded}  [{bar}] {pct} {speed}");
        return truncate_right_cols(&row, width);
    }

    let styled_tag = style_lane_tag(item.lane_tag);
    let styled_bar = render_bar(ratio, bar_w, true);
    let styled_pct = style_pct(&pct, ratio);
    format!("  {styled_tag} {path_padded}  {styled_bar} {styled_pct} \x1b[2m{speed}\x1b[0m")
}

fn style_lane_tag(lane_tag: &str) -> &'static str {
    match lane_tag {
        "S" => "\x1b[36m[S]\x1b[0m",
        "L" => "\x1b[35m[L]\x1b[0m",
        _ => "\x1b[2m · \x1b[0m",
    }
}

fn style_pct(pct: &str, ratio: f64) -> String {
    if ratio >= 0.999 {
        format!("\x1b[1;32m{pct}\x1b[0m")
    } else {
        format!("\x1b[1m{pct}\x1b[0m")
    }
}

fn render_bar(ratio: f64, width: usize, color: bool) -> String {
    let clamped = ratio.clamp(0.0, 1.0);
    let filled = ((clamped * width as f64).round() as usize).min(width);
    let empty = width - filled;
    if color {
        let fill_code = if clamped >= 0.999 { "1;32" } else { "1;36" };
        format!(
            "\x1b[{fill_code}m{}\x1b[0m\x1b[2m{}\x1b[0m",
            "━".repeat(filled),
            "─".repeat(empty)
        )
    } else {
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{:02}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{:02}:{:02}", secs / 60, secs % 60)
    }
}

fn format_compact_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let b = bytes as f64;
    if b >= GIB {
        format!("{:.1}G", b / GIB)
    } else if b >= MIB {
        let m = b / MIB;
        if (m - m.round()).abs() < 0.05 && m >= 10.0 {
            format!("{:.0}M", m)
        } else {
            format!("{m:.1}M")
        }
    } else if b >= KIB {
        format!("{:.0}K", b / KIB)
    } else {
        format!("{bytes}B")
    }
}

fn format_count(n: u64) -> String {
    let s = n.to_string();
    if s.len() <= 3 {
        return s;
    }
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        let rem = s.len() - i;
        if i > 0 && rem.is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Strip ANSI CSI SGR escape sequences so we can measure physical column width accurately.
pub(super) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for inner in chars.by_ref() {
                if inner.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Terminal column display width for a single Unicode scalar (zero-dependency East Asian + emoji width).
pub fn char_display_width(c: char) -> usize {
    let cp = c as u32;
    if c.is_control()
        || matches!(
            cp,
            0x00AD
                | 0x0300..=0x036F
                | 0x1AB0..=0x1AFF
                | 0x1DC0..=0x1DFF
                | 0x200B..=0x200F
                | 0x20D0..=0x20FF
                | 0x3099..=0x309A
                | 0xFE00..=0xFE0F
                | 0xFE20..=0xFE2F
                | 0xFEFF
                | 0x1F3FB..=0x1F3FF
                | 0xE0100..=0xE01EF
        )
    {
        return 0;
    }
    if matches!(
        cp,
        0x1100..=0x115F
            | 0x231A..=0x231B
            | 0x2329..=0x232A
            | 0x23E9..=0x23F3
            | 0x23F8..=0x23FA
            | 0x25FD..=0x25FE
            | 0x2614..=0x2615
            | 0x2648..=0x2653
            | 0x267F
            | 0x2693
            | 0x26A1
            | 0x26AA..=0x26AB
            | 0x26BD..=0x26BE
            | 0x26C4..=0x26C5
            | 0x26CE
            | 0x26D4
            | 0x26EA
            | 0x26F2..=0x26F3
            | 0x26F5
            | 0x26FA
            | 0x26FD
            | 0x2705
            | 0x270A..=0x270B
            | 0x2728
            | 0x274C
            | 0x274E
            | 0x2753..=0x2755
            | 0x2757
            | 0x2795..=0x2797
            | 0x27B0
            | 0x27BF
            | 0x2B1B..=0x2B1C
            | 0x2B50
            | 0x2B55
            | 0x2E80..=0x303E
            | 0x3040..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD
    ) {
        return 2;
    }
    1
}

/// Total display column width of a plain (non-ANSI) string.
pub fn str_display_width(s: &str) -> usize {
    s.chars().map(char_display_width).sum()
}

fn truncate_right_cols(s: &str, max_cols: usize) -> String {
    if str_display_width(s) <= max_cols {
        return s.to_string();
    }
    if max_cols == 0 {
        return String::new();
    }
    if max_cols == 1 {
        return "…".to_string();
    }
    let budget = max_cols - 1;
    let mut out = String::new();
    let mut used = 0usize;
    for ch in s.chars() {
        let w = char_display_width(ch);
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

pub(super) fn truncate_middle_cols(s: &str, max_cols: usize) -> String {
    if str_display_width(s) <= max_cols {
        return s.to_string();
    }
    if max_cols <= 3 {
        return truncate_right_cols(s, max_cols);
    }
    let left_budget = (max_cols - 1) / 2;
    let right_budget = max_cols - 1 - left_budget;

    let mut left = String::new();
    let mut left_used = 0usize;
    for ch in s.chars() {
        let w = char_display_width(ch);
        if left_used + w > left_budget {
            break;
        }
        left.push(ch);
        left_used += w;
    }

    let mut right_rev: Vec<char> = Vec::new();
    let mut right_used = 0usize;
    for ch in s.chars().rev() {
        let w = char_display_width(ch);
        if right_used + w > right_budget {
            break;
        }
        right_rev.push(ch);
        right_used += w;
    }
    right_rev.reverse();
    // Strip orphaned leading zero-width combining marks so `'…'` is never combined with them.
    let first_non_zw = right_rev
        .iter()
        .position(|&c| char_display_width(c) > 0)
        .unwrap_or(right_rev.len());
    let right: String = right_rev[first_non_zw..].iter().collect();
    format!("{left}…{right}")
}

fn pad_right_cols(s: &str, target_cols: usize) -> String {
    let w = str_display_width(s);
    if w >= target_cols {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(target_cols - w))
    }
}
