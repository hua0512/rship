//! Zero-dependency interactive terminal prompt primitives for `rship`.
//!
//! Design principles (consistent with `ui.rs`):
//! - Zero extra crate dependencies: isolates platform raw-key / echo-free input FFI
//!   (`windows-sys` on Windows, `libc` termios on Unix) in [`platform`], with graceful
//!   numbered-line fallback on dumb terminals, mintty/Git Bash, or piped stdin
//!   (`RSHIP_FORCE_INTERACTIVE=1`).
//! - All interactive chrome renders to `stderr`, keeping `stdout` clean for final output/pipes.
//! - RAII guards always restore terminal/console modes, autowrap, and cursor visibility even on
//!   Ctrl+C or early returns.

#![cfg_attr(not(feature = "all-backends"), allow(dead_code))]

mod platform;

use anyhow::Result;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use crate::errors::{cancelled_err, config_err};
use crate::ui::Style;
use platform::{RawModeGuard, read_raw_key, read_secret_key};

/// Outcome of a hidden secret/password prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretOutcome {
    /// User pressed Enter when an existing secret is already configured (keep existing).
    KeepExisting,
    /// User entered a new non-empty secret value.
    Value(String),
    /// User left an optional secret blank or explicitly cleared it with `-`.
    Empty,
}

/// One selectable option in [`select`].
#[derive(Debug, Clone)]
pub struct SelectItem {
    pub label: String,
    pub description: Option<String>,
}

impl SelectItem {
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            description: None,
        }
    }

    pub fn with_desc(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Returns `true` when interactive prompts should be shown.
///
/// Honors `--non-interactive` and `RSHIP_NON_INTERACTIVE=1`, allows deterministic line-mode
/// testing via `RSHIP_FORCE_INTERACTIVE=1`, and otherwise checks `stdin` + `stderr` TTY status.
pub fn is_interactive(non_interactive_flag: bool) -> bool {
    if non_interactive_flag || env_truthy("RSHIP_NON_INTERACTIVE") {
        return false;
    }
    if env_truthy("RSHIP_FORCE_INTERACTIVE") {
        return true;
    }
    io::stdin().is_terminal() && io::stderr().is_terminal()
}

/// Returns `true` when running inside an SSH session (suggests manual/paste OAuth flow).
pub fn is_ssh_session() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
}

fn raw_tty_available() -> bool {
    !env_truthy("RSHIP_FORCE_INTERACTIVE")
        && io::stdin().is_terminal()
        && io::stderr().is_terminal()
        && crate::ui::stderr_supports_ansi()
}

/// Print a styled section banner for an interactive setup flow.
pub fn section(title: &str, subtitle: Option<&str>) {
    let st = Style::stderr();
    eprintln!();
    eprintln!("{} {}", st.accent_bold("◆"), st.bold(title));
    if let Some(sub) = subtitle {
        eprintln!("  {}", st.dim(sub));
    }
}

/// Print a dim informational note.
pub fn note(msg: &str) {
    let st = Style::stderr();
    eprintln!("  {}", st.dim(msg));
}

/// Print an accented tip/hint line.
pub fn tip(msg: &str) {
    let st = Style::stderr();
    eprintln!("  {} {}", st.accent("ℹ"), st.dim(msg));
}

/// Print an inline warning line.
pub fn warn(msg: &str) {
    let st = Style::stderr();
    eprintln!("  {} {}", st.sym_warn(), st.warn(msg));
}

/// Print an inline success line.
pub fn ok(msg: &str) {
    let st = Style::stderr();
    eprintln!("{} {msg}", st.sym_ok());
}

/// Print an inline validation error.
pub fn validation_err(msg: &str) {
    let st = Style::stderr();
    eprintln!("  {} {}", st.sym_err(), st.err(msg));
}

fn read_line_trimmed() -> Result<String> {
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Err(cancelled_err("cancelled (end of input)"));
    }
    Ok(line.trim().to_string())
}

fn read_line_raw_eol() -> Result<String> {
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Err(cancelled_err("cancelled (end of input)"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Prompt for a single line of text with optional default value, hint, and requirement check.
///
/// For optional fields with an existing default, entering `"-"` clears the value and returns `None`.
pub fn text(
    prompt: &str,
    default: Option<&str>,
    hint: Option<&str>,
    required: bool,
) -> Result<Option<String>> {
    text_validated(prompt, default, hint, required, |_| Ok(()))
}

/// Prompt for a required non-empty line of text, returning the validated string directly
/// without requiring callers to unwrap an `Option`.
pub fn text_required(prompt: &str, default: Option<&str>, hint: Option<&str>) -> Result<String> {
    text_validated_required(prompt, default, hint, |_| Ok(()))
}

/// Prompt for a required, validated line of text, looping on invalid entries.
pub fn text_validated_required<F>(
    prompt: &str,
    default: Option<&str>,
    hint: Option<&str>,
    validate: F,
) -> Result<String>
where
    F: FnMut(&str) -> std::result::Result<(), String>,
{
    text_validated(prompt, default, hint, true, validate)?
        .ok_or_else(|| anyhow::anyhow!("missing required input for `{prompt}`"))
}

/// Prompt for a validated line of text, looping on invalid entries instead of aborting.
pub fn text_validated<F>(
    prompt: &str,
    default: Option<&str>,
    hint: Option<&str>,
    required: bool,
    mut validate: F,
) -> Result<Option<String>>
where
    F: FnMut(&str) -> std::result::Result<(), String>,
{
    let st = Style::stderr();
    let default_clean = default.map(str::trim).filter(|s| !s.is_empty());
    if let Some(h) = hint {
        eprintln!("  {}", st.dim(h));
    }
    loop {
        if let Some(d) = default_clean {
            let suffix = if !required {
                format!("[{d}] (Enter=keep, -=clear)")
            } else {
                format!("[{d}]")
            };
            eprint!(
                "{} {} {}: ",
                st.accent_bold("?"),
                st.bold(prompt),
                st.dim(&suffix)
            );
        } else if !required {
            eprint!(
                "{} {} {}: ",
                st.accent_bold("?"),
                st.bold(prompt),
                st.dim("(optional)")
            );
        } else {
            eprint!("{} {}: ", st.accent_bold("?"), st.bold(prompt));
        }
        io::stderr().flush()?;

        let raw = read_line_trimmed()?;
        if raw.is_empty() {
            if let Some(d) = default_clean {
                match validate(d) {
                    Ok(()) => return Ok(Some(d.to_string())),
                    Err(msg) => {
                        validation_err(&msg);
                        continue;
                    }
                }
            }
            if required {
                validation_err("this field is required");
                continue;
            }
            return Ok(None);
        }
        if !required && default_clean.is_some() && raw == "-" {
            return Ok(None);
        }
        match validate(&raw) {
            Ok(()) => return Ok(Some(raw)),
            Err(msg) => validation_err(&msg),
        }
    }
}

/// Prompt for a yes/no confirmation.
pub fn confirm(prompt: &str, default_yes: bool) -> Result<bool> {
    let st = Style::stderr();
    let indicator = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        eprint!(
            "{} {} {}: ",
            st.accent_bold("?"),
            st.bold(prompt),
            st.dim(indicator)
        );
        io::stderr().flush()?;
        let raw = read_line_trimmed()?;
        if raw.is_empty() {
            return Ok(default_yes);
        }
        match raw.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => validation_err("please answer `y` or `n`"),
        }
    }
}

/// Prompt for a secret/password without terminal echo on interactive TTYs.
///
/// Preserves leading/trailing spaces (only strips `\r`/`\n`). When `!required && has_existing`,
/// entering `-` clears the stored secret and returns [`SecretOutcome::Empty`].
pub fn password(
    prompt: &str,
    has_existing: bool,
    required: bool,
    hint: Option<&str>,
) -> Result<SecretOutcome> {
    let st = Style::stderr();
    if let Some(h) = hint {
        eprintln!("  {}", st.dim(h));
    }
    let can_hide = can_hide_secret_input();
    if !can_hide && !env_truthy("RSHIP_FORCE_INTERACTIVE") && io::stdin().is_terminal() {
        warn("terminal emulator does not support hidden input; typed characters may be visible");
    }
    loop {
        let vis = if can_hide { "hidden" } else { "input" };
        let meta = if has_existing && !required {
            format!("({vis}, Enter=keep existing, -=clear)")
        } else if has_existing {
            format!("({vis}, Enter=keep existing)")
        } else if !required {
            format!("({vis}, optional)")
        } else {
            format!("({vis})")
        };
        eprint!(
            "{} {} {}: ",
            st.accent_bold("?"),
            st.bold(prompt),
            st.dim(&meta)
        );
        io::stderr().flush()?;

        let val = read_secret_line()?;
        if val.is_empty() {
            if has_existing {
                return Ok(SecretOutcome::KeepExisting);
            }
            if required {
                validation_err("this secret is required");
                continue;
            }
            return Ok(SecretOutcome::Empty);
        }
        if !required && has_existing && val == "-" {
            return Ok(SecretOutcome::Empty);
        }
        return Ok(SecretOutcome::Value(val));
    }
}

/// Prompt for a new secret twice to prevent typos (e.g. encryption passphrases).
pub fn password_confirmed(
    prompt: &str,
    confirm_prompt: &str,
    has_existing: bool,
    required: bool,
    hint: Option<&str>,
) -> Result<SecretOutcome> {
    loop {
        match password(prompt, has_existing, required, hint)? {
            SecretOutcome::Value(first) => match password(confirm_prompt, false, true, None)? {
                SecretOutcome::Value(second) if second == first => {
                    return Ok(SecretOutcome::Value(first));
                }
                _ => {
                    validation_err("entries did not match — please try again");
                }
            },
            other => return Ok(other),
        }
    }
}

/// Interactive single-choice selection menu.
///
/// Uses arrow keys (`↑`/`↓`, `j`/`k`, `Enter`, `Esc`/`Ctrl+C`) on raw-capable TTYs and
/// automatically falls back to numbered selection on non-raw terminals or scripted stdin.
pub fn select(prompt: &str, items: &[SelectItem], default_idx: usize) -> Result<usize> {
    if items.is_empty() {
        return Err(config_err("cannot select from empty list"));
    }
    let default_idx = default_idx.min(items.len() - 1);
    if raw_tty_available() {
        match select_raw(prompt, items, default_idx) {
            Ok(idx) => return Ok(idx),
            Err(RawSelectError::Cancelled) => return Err(cancelled_err("cancelled by user")),
            Err(RawSelectError::Unsupported) => {
                // Fall through cleanly to numbered line selection (e.g. mintty / legacy pipe).
            }
            Err(RawSelectError::Io(e)) => return Err(e.into()),
        }
    }
    select_line_fallback(prompt, items, default_idx)
}

fn select_line_fallback(prompt: &str, items: &[SelectItem], default_idx: usize) -> Result<usize> {
    let st = Style::stderr();
    eprintln!("{} {}", st.accent_bold("?"), st.bold(prompt));
    for (idx, item) in items.iter().enumerate() {
        let num = idx + 1;
        let marker = if idx == default_idx {
            st.accent_bold("❯")
        } else {
            " ".to_string()
        };
        let label = if idx == default_idx {
            st.bold(&item.label)
        } else {
            item.label.clone()
        };
        if let Some(desc) = &item.description {
            eprintln!("  {marker} {:>2}) {}  {}", num, label, st.dim(desc));
        } else {
            eprintln!("  {marker} {:>2}) {}", num, label);
        }
    }
    loop {
        eprint!(
            "  {} ",
            st.dim(&format!(
                "Select [1-{}, default {}]:",
                items.len(),
                default_idx + 1
            ))
        );
        io::stderr().flush()?;
        let raw = read_line_trimmed()?;
        if raw.is_empty() {
            return Ok(default_idx);
        }
        if let Ok(num) = raw.parse::<usize>()
            && (1..=items.len()).contains(&num)
        {
            return Ok(num - 1);
        }
        let lower = raw.to_ascii_lowercase();
        if let Some(pos) = items
            .iter()
            .position(|it| it.label.to_ascii_lowercase() == lower)
        {
            return Ok(pos);
        }
        validation_err(&format!(
            "enter a number between 1 and {} (or press Enter for {})",
            items.len(),
            default_idx + 1
        ));
    }
}

enum RawKey {
    Up,
    Down,
    Home,
    End,
    Enter,
    Cancel,
    Other,
}

enum SecretKey {
    Char(char),
    Backspace,
    ClearLine,
    Enter,
    Cancel,
    Ignore,
}

enum RawSelectError {
    Unsupported,
    Cancelled,
    Io(io::Error),
}

fn select_raw(
    prompt: &str,
    items: &[SelectItem],
    default_idx: usize,
) -> std::result::Result<usize, RawSelectError> {
    let _raw_guard = RawModeGuard::enter().ok_or(RawSelectError::Unsupported)?;
    let _nowrap_guard = NoWrapGuard::enter();
    let _cursor_guard = HideCursorGuard::hide();
    let st = Style::stderr();
    let mut selected = default_idx;
    let max_visible = items.len().min(12);
    let mut scroll_top = if selected >= max_visible {
        selected + 1 - max_visible
    } else {
        0
    };

    let mut rendered_lines: usize = 0;

    let render = |selected: usize, scroll_top: usize, prev_lines: &mut usize| -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        if *prev_lines > 0 {
            write!(stderr, "\x1b[{}A", *prev_lines)?;
        }
        let mut count = 0usize;
        writeln!(
            stderr,
            "\r\x1b[2K{} {} {}",
            st.accent_bold("?"),
            st.bold(prompt),
            st.dim("(↑/↓ move, Enter select, Esc cancel)")
        )?;
        count += 1;

        let end = (scroll_top + max_visible).min(items.len());
        if scroll_top > 0 {
            writeln!(stderr, "\r\x1b[2K  {}", st.dim("↑ more above"))?;
            count += 1;
        }
        for (idx, item) in items[scroll_top..end].iter().enumerate() {
            let abs_idx = scroll_top + idx;
            let is_sel = abs_idx == selected;
            let pointer = if is_sel {
                st.accent_bold("❯")
            } else {
                " ".to_string()
            };
            let label = if is_sel {
                st.accent_bold(&item.label)
            } else {
                item.label.clone()
            };
            if let Some(desc) = &item.description {
                writeln!(stderr, "\r\x1b[2K  {pointer} {label}  {}", st.dim(desc))?;
            } else {
                writeln!(stderr, "\r\x1b[2K  {pointer} {label}")?;
            }
            count += 1;
        }
        if end < items.len() {
            writeln!(stderr, "\r\x1b[2K  {}", st.dim("↓ more below"))?;
            count += 1;
        }
        if *prev_lines > count {
            let extra = *prev_lines - count;
            for _ in 0..extra {
                writeln!(stderr, "\r\x1b[2K")?;
            }
            write!(stderr, "\x1b[{extra}A")?;
        }
        stderr.flush()?;
        *prev_lines = count;
        Ok(())
    };

    let clear_menu = |prev_lines: usize| -> io::Result<()> {
        let mut stderr = io::stderr().lock();
        if prev_lines > 0 {
            write!(stderr, "\x1b[{prev_lines}A")?;
            for _ in 0..prev_lines {
                writeln!(stderr, "\r\x1b[2K")?;
            }
            write!(stderr, "\x1b[{prev_lines}A")?;
        }
        stderr.flush()
    };

    render(selected, scroll_top, &mut rendered_lines).map_err(RawSelectError::Io)?;

    loop {
        let key = read_raw_key().map_err(RawSelectError::Io)?;
        match key {
            RawKey::Up => {
                selected = if selected == 0 {
                    items.len() - 1
                } else {
                    selected - 1
                };
            }
            RawKey::Down => {
                selected = (selected + 1) % items.len();
            }
            RawKey::Home => selected = 0,
            RawKey::End => selected = items.len() - 1,
            RawKey::Enter => {
                clear_menu(rendered_lines).map_err(RawSelectError::Io)?;
                drop(_cursor_guard);
                drop(_nowrap_guard);
                drop(_raw_guard);
                eprintln!(
                    "{} {} {} {}",
                    st.sym_ok(),
                    st.bold(prompt),
                    st.sym_dot(),
                    st.accent(&items[selected].label)
                );
                return Ok(selected);
            }
            RawKey::Cancel => {
                clear_menu(rendered_lines).map_err(RawSelectError::Io)?;
                return Err(RawSelectError::Cancelled);
            }
            RawKey::Other => continue,
        }
        if selected < scroll_top {
            scroll_top = selected;
        } else if selected >= scroll_top + max_visible {
            scroll_top = selected + 1 - max_visible;
        }
        render(selected, scroll_top, &mut rendered_lines).map_err(RawSelectError::Io)?;
    }
}

struct HideCursorGuard;

impl HideCursorGuard {
    fn hide() -> Self {
        let _ = write!(io::stderr(), "\x1b[?25l");
        let _ = io::stderr().flush();
        Self
    }
}

impl Drop for HideCursorGuard {
    fn drop(&mut self) {
        let _ = write!(io::stderr(), "\x1b[?25h");
        let _ = io::stderr().flush();
    }
}

/// Disables terminal line autowrap (`DECAWM`) during menu redraws so long lines never
/// wrap onto extra physical rows and corrupt cursor-up rewind offsets.
struct NoWrapGuard;

impl NoWrapGuard {
    fn enter() -> Self {
        let _ = write!(io::stderr(), "\x1b[?7l");
        let _ = io::stderr().flush();
        Self
    }
}

impl Drop for NoWrapGuard {
    fn drop(&mut self) {
        let _ = write!(io::stderr(), "\x1b[?7h");
        let _ = io::stderr().flush();
    }
}

fn can_hide_secret_input() -> bool {
    if env_truthy("RSHIP_FORCE_INTERACTIVE") || !io::stdin().is_terminal() {
        return true;
    }
    platform::can_enter_raw_mode()
}

/// Read a secret line without echoing characters to the terminal.
///
/// Uses raw character-by-character reading (with `ISIG` / `ENABLE_PROCESSED_INPUT` disabled)
/// so pressing `Ctrl+C` cleanly unwinds `RawModeGuard` and NEVER leaves the parent shell
/// with echo permanently turned off. Preserves leading/trailing whitespace.
fn read_secret_line() -> Result<String> {
    if !env_truthy("RSHIP_FORCE_INTERACTIVE")
        && io::stdin().is_terminal()
        && let Some(_raw) = RawModeGuard::enter()
    {
        let mut buf = String::new();
        loop {
            match read_secret_key()? {
                SecretKey::Char(c) => buf.push(c),
                SecretKey::Backspace => {
                    buf.pop();
                }
                SecretKey::ClearLine => buf.clear(),
                SecretKey::Enter => {
                    drop(_raw);
                    eprintln!();
                    return Ok(buf);
                }
                SecretKey::Cancel => {
                    drop(_raw);
                    eprintln!();
                    return Err(cancelled_err("cancelled by user"));
                }
                SecretKey::Ignore => {}
            }
        }
    }
    read_line_raw_eol()
}

/// Expand leading `~/` or `~\` to the current user's home directory.
pub fn expand_tilde(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed
        .strip_prefix("~/")
        .or_else(|| trimmed.strip_prefix("~\\"))
        && let Some(home) = home_dir()
    {
        return home.join(rest);
    }
    if trimmed == "~"
        && let Some(home) = home_dir()
    {
        return home;
    }
    PathBuf::from(trimmed)
}

/// Losslessly expand a `PathBuf` only if it starts with `~`, preserving arbitrary non-UTF-8
/// Unix paths and whitespace on non-tilde paths.
pub fn expand_tilde_path(path: PathBuf) -> PathBuf {
    if let Some(s) = path.to_str() {
        if s == "~" {
            if let Some(home) = home_dir() {
                return home;
            }
        } else if let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\"))
            && let Some(home) = home_dir()
        {
            return home.join(rest);
        }
    }
    path
}

/// Best-effort current OS home directory.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Best-effort current OS username (used as default SSH username).
pub fn current_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Discover common SSH private key files under `~/.ssh/`.
pub fn discover_ssh_keys() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let ssh_dir = home.join(".ssh");
    let candidates = [
        "id_ed25519",
        "id_ecdsa",
        "id_rsa",
        "id_ed25519_sk",
        "id_ecdsa_sk",
    ];
    candidates
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|p| p.is_file())
        .collect()
}

/// Best-effort heuristic checking whether an SSH private key file is encrypted with a passphrase.
///
/// Reads at most 2048 bytes and parses the `openssh-key-v1\0` cipher/kdf header safely even for
/// large 4096-bit RSA OpenSSH private keys.
pub fn ssh_key_looks_encrypted(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut bytes = Vec::with_capacity(2048);
    if file.take(2048).read_to_end(&mut bytes).is_err() {
        return false;
    }
    let text = String::from_utf8_lossy(&bytes);
    // Legacy PEM encrypted keys include `ENCRYPTED` header (RFC 1421 / PKCS#8).
    if text.contains("ENCRYPTED") {
        return true;
    }
    // Modern OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`) wire format:
    //   "openssh-key-v1\0" || string ciphername || string kdfname || ...
    // Each string is u32 big-endian length followed by bytes.
    if text.contains("BEGIN OPENSSH PRIVATE KEY") {
        let b64: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .take(256)
            .collect();
        let aligned_len = b64.len() & !3;
        if aligned_len < 24 {
            return false;
        }
        use base64::Engine as _;
        let Ok(decoded) = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(b64[..aligned_len].trim_end_matches('='))
        else {
            return false;
        };
        const MAGIC: &[u8] = b"openssh-key-v1\0";
        let Some(rest) = decoded.strip_prefix(MAGIC) else {
            return false;
        };
        if let Some((cipher, after_cipher)) = read_ssh_string(rest) {
            if cipher != b"none" {
                return true;
            }
            if let Some((kdf, _)) = read_ssh_string(after_cipher) {
                return kdf != b"none";
            }
        }
    }
    false
}

fn read_ssh_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let body = buf.get(4..4 + len)?;
    let rest = buf.get(4 + len..)?;
    Some((body, rest))
}

/// Validate that `url` is a safe `http://` or `https://` URL before passing to OS browser launchers.
fn is_safe_browser_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && !trimmed.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// Attempt to open `url` in the user's default system browser without blocking.
///
/// Only permits `https://` and `http://` URLs. Returns `true` if a launcher process was spawned.
pub fn open_browser(url: &str) -> bool {
    use std::process::{Command, Stdio};

    if !is_safe_browser_url(url) {
        return false;
    }

    #[cfg(target_os = "windows")]
    {
        // Pass URL via environment variable so `&`, `?`, `=`, `%`, quotes in OAuth URLs
        // can never be misinterpreted by cmd.exe or PowerShell parsing.
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                "Start-Process -FilePath $env:RSHIP_OPEN_URL",
            ])
            .env("RSHIP_OPEN_URL", url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .args(["--", url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let has_gui = std::env::var_os("DISPLAY").is_some_and(|v| !v.is_empty())
            || std::env::var_os("WAYLAND_DISPLAY").is_some_and(|v| !v.is_empty());
        if !has_gui {
            return false;
        }
        Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = url;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_tilde_prefix_cleanly() {
        let expanded = expand_tilde("~/test.json");
        if let Some(home) = home_dir() {
            assert_eq!(expanded, home.join("test.json"));
            assert_eq!(expand_tilde("~"), home);
            assert_eq!(
                expand_tilde_path(PathBuf::from("~/nested/key")),
                home.join("nested/key")
            );
        }
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
        assert_eq!(
            expand_tilde_path(PathBuf::from("  /preserve/spaces  ")),
            PathBuf::from("  /preserve/spaces  ")
        );
    }

    #[test]
    fn rejects_non_http_schemes_in_browser_launcher_check() {
        assert!(is_safe_browser_url(
            "https://accounts.google.com/o/oauth2/v2/auth?x=1&y=2"
        ));
        assert!(is_safe_browser_url("http://127.0.0.1:53682/callback"));
        assert!(!is_safe_browser_url("file:///etc/passwd"));
        assert!(!is_safe_browser_url("ms-settings:privacy"));
        assert!(!is_safe_browser_url("calc.exe"));
        assert!(!is_safe_browser_url("https://example.com/a b"));
    }

    #[test]
    fn detects_encrypted_ssh_keys_including_large_rsa4096_openssh_format() {
        use base64::Engine as _;

        let tmp = tempfile::TempDir::new().unwrap();
        let pem_enc = tmp.path().join("id_pem_enc");
        std::fs::write(
            &pem_enc,
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n",
        )
        .unwrap();
        assert!(ssh_key_looks_encrypted(&pem_enc));

        let build_openssh_key = |cipher: &[u8], kdf: &[u8], pad_bytes: usize| -> String {
            let mut wire = Vec::new();
            wire.extend_from_slice(b"openssh-key-v1\0");
            wire.extend_from_slice(&(cipher.len() as u32).to_be_bytes());
            wire.extend_from_slice(cipher);
            wire.extend_from_slice(&(kdf.len() as u32).to_be_bytes());
            wire.extend_from_slice(kdf);
            wire.resize(wire.len() + pad_bytes, 0x5Au8);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&wire);
            let mut out = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\r\n");
            for chunk in encoded.as_bytes().chunks(70) {
                out.push_str(std::str::from_utf8(chunk).unwrap());
                out.push_str("\r\n");
            }
            out.push_str("-----END OPENSSH PRIVATE KEY-----\r\n");
            out
        };

        // Simulate a >3.3 KiB RSA-4096 encrypted OpenSSH key (truncated past 2048 bytes!)
        let rsa4096_enc = tmp.path().join("id_rsa4096_enc");
        std::fs::write(
            &rsa4096_enc,
            build_openssh_key(b"aes256-ctr", b"bcrypt", 3400),
        )
        .unwrap();
        assert!(ssh_key_looks_encrypted(&rsa4096_enc));

        // Unencrypted OpenSSH key
        let rsa4096_plain = tmp.path().join("id_rsa4096_plain");
        std::fs::write(&rsa4096_plain, build_openssh_key(b"none", b"none", 3400)).unwrap();
        assert!(!ssh_key_looks_encrypted(&rsa4096_plain));
    }
}
