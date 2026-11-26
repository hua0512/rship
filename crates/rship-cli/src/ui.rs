//! Restrained, top-tier terminal styling and formatting primitives for `rship`.
//!
//! Design principles (inspired by `uv`, `cargo`, `gh`, `eza`, and `ripgrep`):
//! - Zero extra crate dependencies: uses standard ANSI 16-color palette that adapts cleanly
//!   to both dark and light terminal themes.
//! - Strictly honors `NO_COLOR`, `CLICOLOR_FORCE`, `TERM=dumb`, and `IsTerminal`:
//!   piped output, `--json`, `cat`, and `hashsum` stdout never emit stray escape sequences.
//! - High signal-to-noise: semantic icons (`✓`, `▲`, `✗`), subtle dim metadata, crisp
//!   proportional bars, and structured causal error chains with actionable hints.

use clap::builder::styling::{AnsiColor, Effects, Styles};
use rship_core::progress::format_human_bytes;
use std::io::IsTerminal;
#[cfg(windows)]
use std::sync::OnceLock;
use std::time::Duration;

#[cfg(windows)]
static WINDOWS_VT_STATE: OnceLock<(bool, bool)> = OnceLock::new();

#[cfg(windows)]
fn enable_windows_vt_on_handle(std_handle: u32) -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{
        ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle, SetConsoleMode,
    };
    // SAFETY: Standard Win32 console handle/mode query and update using a valid stack `u32`.
    unsafe {
        let handle = GetStdHandle(std_handle);
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true;
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}

/// Initialize terminal capabilities (enables Windows Virtual Terminal processing on
/// legacy `conhost.exe` consoles so ANSI colors & CSI cursor redraws never print raw escapes).
pub fn init_terminal() {
    #[cfg(windows)]
    {
        let _ = WINDOWS_VT_STATE.get_or_init(|| {
            use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, STD_OUTPUT_HANDLE};
            let out_ok = if std::io::stdout().is_terminal() {
                enable_windows_vt_on_handle(STD_OUTPUT_HANDLE)
            } else {
                false
            };
            let err_ok = if std::io::stderr().is_terminal() {
                enable_windows_vt_on_handle(STD_ERROR_HANDLE)
            } else {
                false
            };
            (out_ok, err_ok)
        });
    }
}

fn is_dumb_term() -> bool {
    std::env::var("TERM")
        .map(|t| t.eq_ignore_ascii_case("dumb"))
        .unwrap_or(false)
}

/// Returns `true` when `stderr` is an interactive terminal supporting ANSI CSI cursor controls.
pub fn stderr_supports_ansi() -> bool {
    std::io::stderr().is_terminal() && !is_dumb_term() && stderr_vt_ok()
}

#[cfg(windows)]
fn stdout_vt_ok() -> bool {
    init_terminal();
    WINDOWS_VT_STATE.get().is_some_and(|&(out_ok, _)| out_ok)
}

#[cfg(not(windows))]
fn stdout_vt_ok() -> bool {
    true
}

#[cfg(windows)]
fn stderr_vt_ok() -> bool {
    init_terminal();
    WINDOWS_VT_STATE.get().is_some_and(|&(_, err_ok)| err_ok)
}

#[cfg(not(windows))]
fn stderr_vt_ok() -> bool {
    true
}

/// Styled `clap` v4 help palette (`uv` / `cargo` aesthetic).
pub fn clap_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default() | Effects::BOLD)
        .usage(AnsiColor::Green.on_default() | Effects::BOLD)
        .literal(AnsiColor::Cyan.on_default() | Effects::BOLD)
        .placeholder(AnsiColor::Cyan.on_default())
        .valid(AnsiColor::Yellow.on_default())
        .invalid(AnsiColor::Red.on_default() | Effects::BOLD)
        .error(AnsiColor::Red.on_default() | Effects::BOLD)
}

/// Determine whether ANSI colors should be emitted for a stream whose TTY status is `is_tty`.
pub fn should_color(is_tty: bool) -> bool {
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0" && !v.is_empty()) {
        return true;
    }
    if std::env::var("TERM")
        .map(|t| t.eq_ignore_ascii_case("dumb"))
        .unwrap_or(false)
    {
        return false;
    }
    is_tty
}

/// Lightweight, Copy semantic ANSI styler bound to either `stdout` or `stderr`.
#[derive(Debug, Clone, Copy)]
pub struct Style {
    color: bool,
    tty: bool,
}

impl Style {
    pub fn stdout() -> Self {
        let tty = std::io::stdout().is_terminal();
        Self {
            color: should_color(tty) && (!tty || stdout_vt_ok()),
            tty,
        }
    }

    pub fn stderr() -> Self {
        let tty = std::io::stderr().is_terminal();
        Self {
            color: should_color(tty) && (!tty || stderr_vt_ok()),
            tty,
        }
    }

    #[cfg(test)]
    pub const fn new(color: bool) -> Self {
        Self { color, tty: color }
    }

    pub const fn is_tty(self) -> bool {
        self.tty
    }

    pub const fn has_color(self) -> bool {
        self.color
    }

    fn wrap(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(self, s: &str) -> String {
        self.wrap("1", s)
    }

    pub fn dim(self, s: &str) -> String {
        self.wrap("2", s)
    }

    pub fn accent(self, s: &str) -> String {
        self.wrap("36", s)
    }

    pub fn accent_bold(self, s: &str) -> String {
        self.wrap("1;36", s)
    }

    pub fn ok(self, s: &str) -> String {
        self.wrap("32", s)
    }

    pub fn ok_bold(self, s: &str) -> String {
        self.wrap("1;32", s)
    }

    pub fn warn(self, s: &str) -> String {
        self.wrap("33", s)
    }

    pub fn warn_bold(self, s: &str) -> String {
        self.wrap("1;33", s)
    }

    pub fn err(self, s: &str) -> String {
        self.wrap("31", s)
    }

    pub fn err_bold(self, s: &str) -> String {
        self.wrap("1;31", s)
    }

    pub fn sym_ok(self) -> String {
        self.ok_bold("✓")
    }

    pub fn sym_warn(self) -> String {
        self.warn_bold("▲")
    }

    pub fn sym_err(self) -> String {
        self.err_bold("✗")
    }

    pub fn sym_dot(self) -> String {
        self.dim("·")
    }

    pub fn sym_arrow(self) -> String {
        self.dim("→")
    }

    /// Render a compact proportional progress/quota bar (`━━━━━━━━──────────── 40.0%`),
    /// shifting from green/cyan -> amber (>=80%) -> red (>=92%).
    pub fn quota_bar(self, ratio: f64, width: usize) -> String {
        let clamped = ratio.clamp(0.0, 1.0);
        let filled = ((clamped * width as f64).round() as usize).min(width);
        let empty = width.saturating_sub(filled);
        let fill_str = "━".repeat(filled);
        let empty_str = "─".repeat(empty);
        let colored_fill = if clamped >= 0.92 {
            self.err_bold(&fill_str)
        } else if clamped >= 0.80 {
            self.warn_bold(&fill_str)
        } else {
            self.accent_bold(&fill_str)
        };
        format!("{colored_fill}{}", self.dim(&empty_str))
    }

    /// Render a concise semantic badge for job/operation status strings.
    pub fn status_badge(self, status: &str) -> String {
        let lower = status.to_ascii_lowercase();
        if lower.contains("completed") && !lower.contains("error") && !lower.contains("conflict") {
            self.ok(status)
        } else if lower.contains("failed") || lower.contains("error") {
            self.err(status)
        } else if lower.contains("running")
            || lower.contains("active")
            || lower.contains("completing")
        {
            self.accent(status)
        } else if lower.contains("paused")
            || lower.contains("interrupt")
            || lower.contains("conflict")
            || lower.contains("cancel")
        {
            self.warn(status)
        } else {
            self.dim(status)
        }
    }
}

/// Format elapsed wall-clock time concisely (`18 ms`, `1.42 s`, `2m 14s`, `1h 05m`).
pub fn format_duration_human(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.2} s", d.as_secs_f64())
    } else {
        let secs = d.as_secs();
        if secs < 3600 {
            format!("{}m {:02}s", secs / 60, secs % 60)
        } else {
            format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
        }
    }
}

/// Format average transfer throughput (`42.8 MiB/s`), returning `None` for zero bytes/time.
pub fn format_rate(bytes: u64, elapsed: Duration) -> Option<String> {
    let secs = elapsed.as_secs_f64();
    if bytes == 0 || secs <= 0.0005 {
        return None;
    }
    let bps = (bytes as f64 / secs) as u64;
    Some(format!("{}/s", format_human_bytes(bps)))
}

/// Render a structured, readable error report with causal chain and optional hint onto `stderr`.
pub fn print_error(err: &anyhow::Error) {
    let st = Style::stderr();
    let chain: Vec<String> = err.chain().map(ToString::to_string).collect();
    let headline = chain.first().map(String::as_str).unwrap_or("unknown error");
    eprintln!("{} {} {}", st.sym_err(), st.err_bold("error:"), headline);

    if chain.len() > 1 {
        let causes = &chain[1..];
        for (idx, cause) in causes.iter().enumerate() {
            let connector = if idx + 1 == causes.len() {
                "└─"
            } else {
                "├─"
            };
            eprintln!("  {} {}", st.dim(connector), cause);
        }
    }

    if let Some(hint) = infer_error_hint(&chain.join(" | ")) {
        eprintln!("  {} {}", st.accent_bold("hint:"), hint);
    }
}

pub fn infer_error_hint(full_msg: &str) -> Option<&'static str> {
    let lower = full_msg.to_ascii_lowercase();
    if lower.contains("invalid_grant") || lower.contains("refresh token") {
        Some(
            "OAuth session expired or revoked — re-authenticate with `rship auth <provider> <remote>`.",
        )
    } else if lower.contains("storagequotaexceeded") {
        Some(
            "Google Service Accounts have 0 GB personal quota — pass `--shared-drive-id` or `--impersonate`.",
        )
    } else if lower.contains("is locked by another") || lower.contains("process lock") {
        Some(
            "Another `rship` job is actively writing to this destination; wait for it to finish or inspect `rship status`.",
        )
    } else if lower.contains("max-delete") || lower.contains("circuit breaker") {
        Some("Increase or omit `--max-delete` after verifying planned deletions with `--dry-run`.")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_durations_rates_and_quota_bars_cleanly() {
        assert_eq!(format_duration_human(Duration::from_millis(42)), "42 ms");
        assert_eq!(format_duration_human(Duration::from_millis(1500)), "1.50 s");
        assert_eq!(format_duration_human(Duration::from_secs(134)), "2m 14s");
        assert_eq!(format_duration_human(Duration::from_secs(3900)), "1h 05m");

        let plain = Style::new(false);
        assert_eq!(plain.quota_bar(0.5, 10), "━━━━━─────");
        assert!(!plain.quota_bar(0.5, 10).contains('\x1b'));

        let colored = Style::new(true);
        assert!(colored.quota_bar(0.95, 10).contains("\x1b[1;31m"));
        assert!(colored.sym_ok().contains('✓'));
        assert!(format_rate(10 * 1024 * 1024, Duration::from_secs(2)).is_some());
    }
}
