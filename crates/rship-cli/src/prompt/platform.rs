//! Platform-specific console / termios raw-key & hidden-input FFI primitives.

use super::{RawKey, SecretKey};
use std::io;

#[cfg(windows)]
mod imp {
    use super::{RawKey, SecretKey};
    use std::io;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, GetConsoleMode, GetStdHandle,
        INPUT_RECORD, KEY_EVENT, ReadConsoleInputW, STD_INPUT_HANDLE, SetConsoleMode,
    };

    const VK_BACK: u16 = 0x08;
    const VK_RETURN: u16 = 0x0D;
    const VK_ESCAPE: u16 = 0x1B;
    const VK_END: u16 = 0x23;
    const VK_HOME: u16 = 0x24;
    const VK_UP: u16 = 0x26;
    const VK_DOWN: u16 = 0x28;
    const VK_C: u16 = 0x43;
    const CTRL_MASK: u32 = 0x000C; // RIGHT_CTRL_PRESSED (0x0004) | LEFT_CTRL_PRESSED (0x0008)

    fn stdin_handle() -> Option<HANDLE> {
        // SAFETY: `GetStdHandle` takes a standard Win32 handle selector constant.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                None
            } else {
                Some(h)
            }
        }
    }

    pub(super) fn can_enter_raw_mode() -> bool {
        let Some(handle) = stdin_handle() else {
            return false;
        };
        let mut mode: u32 = 0;
        // SAFETY: `handle` is a validated console handle and `mode` is writable stack storage.
        unsafe { GetConsoleMode(handle, &mut mode) != 0 }
    }

    pub struct RawModeGuard {
        handle: HANDLE,
        orig_mode: u32,
    }

    impl RawModeGuard {
        pub fn enter() -> Option<Self> {
            let handle = stdin_handle()?;
            let mut orig_mode: u32 = 0;
            // SAFETY: `handle` is a validated console handle and `orig_mode` is stack storage.
            unsafe {
                if GetConsoleMode(handle, &mut orig_mode) == 0 {
                    return None;
                }
                let new_mode =
                    orig_mode & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
                if SetConsoleMode(handle, new_mode) == 0 {
                    return None;
                }
            }
            Some(Self { handle, orig_mode })
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            // SAFETY: Restores the saved console mode on the validated stdin console handle.
            unsafe {
                let _ = SetConsoleMode(self.handle, self.orig_mode);
            }
        }
    }

    fn is_ctrl_c(vk: u16, ch: u16, ctrl_state: u32) -> bool {
        ch == 0x0003 || (vk == VK_C && (ctrl_state & CTRL_MASK) != 0)
    }

    pub(super) fn read_raw_key() -> io::Result<RawKey> {
        let Some(handle) = stdin_handle() else {
            return Err(io::Error::other("invalid console input handle"));
        };
        loop {
            // SAFETY: `INPUT_RECORD` is a plain C repr struct valid when all-zero initialized.
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read: u32 = 0;
            // SAFETY: `handle` is a valid console handle; `record` and `read` are writable locals.
            let ok = unsafe { ReadConsoleInputW(handle, &mut record, 1, &mut read) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if read == 0 || record.EventType != KEY_EVENT as u16 {
                continue;
            }
            // SAFETY: `record.EventType == KEY_EVENT` guarantees `Event.KeyEvent` is active.
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown == 0 {
                continue;
            }
            // SAFETY: `ReadConsoleInputW` populates the UTF-16 `UnicodeChar` union field.
            let ch = unsafe { key.uChar.UnicodeChar };
            if is_ctrl_c(key.wVirtualKeyCode, ch, key.dwControlKeyState) {
                return Ok(RawKey::Cancel);
            }
            match key.wVirtualKeyCode {
                VK_UP => return Ok(RawKey::Up),
                VK_DOWN => return Ok(RawKey::Down),
                VK_HOME => return Ok(RawKey::Home),
                VK_END => return Ok(RawKey::End),
                VK_RETURN => return Ok(RawKey::Enter),
                VK_ESCAPE => return Ok(RawKey::Cancel),
                _ => match ch {
                    0x006B => return Ok(RawKey::Up),   // 'k'
                    0x006A => return Ok(RawKey::Down), // 'j'
                    0x0067 => return Ok(RawKey::Home), // 'g'
                    0x0047 => return Ok(RawKey::End),  // 'G'
                    0x000D | 0x000A => return Ok(RawKey::Enter),
                    _ => return Ok(RawKey::Other),
                },
            }
        }
    }

    pub(super) fn read_secret_key() -> io::Result<SecretKey> {
        let Some(handle) = stdin_handle() else {
            return Err(io::Error::other("invalid console input handle"));
        };
        let mut high_surrogate: Option<u16> = None;
        loop {
            // SAFETY: `INPUT_RECORD` is a plain C repr struct valid when all-zero initialized.
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read: u32 = 0;
            // SAFETY: `handle` is a valid console handle; `record` and `read` are writable locals.
            let ok = unsafe { ReadConsoleInputW(handle, &mut record, 1, &mut read) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            if read == 0 || record.EventType != KEY_EVENT as u16 {
                continue;
            }
            // SAFETY: `record.EventType == KEY_EVENT` guarantees `Event.KeyEvent` is active.
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown == 0 {
                continue;
            }
            // SAFETY: `ReadConsoleInputW` populates the UTF-16 `UnicodeChar` union field.
            let ch = unsafe { key.uChar.UnicodeChar };
            if is_ctrl_c(key.wVirtualKeyCode, ch, key.dwControlKeyState) {
                return Ok(SecretKey::Cancel);
            }
            match key.wVirtualKeyCode {
                VK_RETURN => return Ok(SecretKey::Enter),
                VK_BACK => return Ok(SecretKey::Backspace),
                _ => {}
            }
            match ch {
                0x0000 => continue,
                0x000D | 0x000A => return Ok(SecretKey::Enter),
                0x0008 | 0x007F => return Ok(SecretKey::Backspace),
                0x0015 => return Ok(SecretKey::ClearLine), // Ctrl+U
                0x0004 => return Ok(SecretKey::Cancel),    // Ctrl+D
                0xD800..=0xDBFF => {
                    high_surrogate = Some(ch);
                    continue;
                }
                0xDC00..=0xDFFF => {
                    if let Some(hi) = high_surrogate.take()
                        && let Some(Ok(c)) = char::decode_utf16([hi, ch]).next()
                    {
                        return Ok(SecretKey::Char(c));
                    }
                    continue;
                }
                u if u >= 0x0020 => {
                    high_surrogate = None;
                    if let Some(c) = char::from_u32(u32::from(u)) {
                        return Ok(SecretKey::Char(c));
                    }
                }
                _ => return Ok(SecretKey::Ignore),
            }
        }
    }
}

#[cfg(unix)]
mod imp {
    use super::{RawKey, SecretKey};
    use std::io;

    pub(super) fn can_enter_raw_mode() -> bool {
        // SAFETY: `tcgetattr` initializes stack-allocated `libc::termios` for `STDIN_FILENO`.
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            libc::tcgetattr(libc::STDIN_FILENO, &mut orig) == 0
        }
    }

    pub struct RawModeGuard {
        orig: libc::termios,
    }

    impl RawModeGuard {
        pub fn enter() -> Option<Self> {
            // SAFETY: Queries and updates `STDIN_FILENO` termios using valid stack structs.
            unsafe {
                let mut orig: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                    return None;
                }
                let mut next = orig;
                next.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
                next.c_cc[libc::VMIN] = 1;
                next.c_cc[libc::VTIME] = 0;
                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &next) != 0 {
                    return None;
                }
                Some(Self { orig })
            }
        }
    }

    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            // SAFETY: Restores previously queried `libc::termios` attributes on `STDIN_FILENO`.
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.orig);
            }
        }
    }

    /// Read a single byte directly from kernel `STDIN_FILENO` (bypassing `io::Stdin`'s
    /// user-space `BufReader` so `libc::poll` always observes unread escape sequence bytes).
    fn read_fd_byte() -> io::Result<Option<u8>> {
        let mut b = 0u8;
        loop {
            // SAFETY: Reads at most 1 byte into valid stack local `b` from `STDIN_FILENO`.
            let n = unsafe {
                libc::read(
                    libc::STDIN_FILENO,
                    (&mut b as *mut u8).cast::<libc::c_void>(),
                    1,
                )
            };
            if n == 1 {
                return Ok(Some(b));
            }
            if n == 0 {
                return Ok(None);
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    fn poll_stdin_ms(timeout_ms: i32) -> bool {
        loop {
            let mut pfd = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` points to 1 valid `libc::pollfd` entry for the duration of `poll`.
            let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if rc < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return false;
            }
            return rc > 0 && (pfd.revents & libc::POLLIN) != 0;
        }
    }

    fn drain_csi_final() -> io::Result<Option<u8>> {
        // Consume CSI parameter/intermediate bytes (`0x20..=0x3F`) until the final byte (`0x40..=0x7E`).
        for _ in 0..16 {
            if !poll_stdin_ms(25) {
                return Ok(None);
            }
            let Some(b) = read_fd_byte()? else {
                return Ok(None);
            };
            if (0x40..=0x7E).contains(&b) {
                return Ok(Some(b));
            }
        }
        Ok(None)
    }

    pub(super) fn read_raw_key() -> io::Result<RawKey> {
        let Some(first) = read_fd_byte()? else {
            return Ok(RawKey::Cancel);
        };
        match first {
            0x03 => Ok(RawKey::Cancel), // Ctrl+C
            b'\r' | b'\n' => Ok(RawKey::Enter),
            b'k' => Ok(RawKey::Up),
            b'j' => Ok(RawKey::Down),
            b'g' => Ok(RawKey::Home),
            b'G' => Ok(RawKey::End),
            0x1b => {
                if !poll_stdin_ms(25) {
                    return Ok(RawKey::Cancel);
                }
                let Some(lead) = read_fd_byte()? else {
                    return Ok(RawKey::Cancel);
                };
                if lead == b'[' {
                    match drain_csi_final()? {
                        Some(b'A') => Ok(RawKey::Up),
                        Some(b'B') => Ok(RawKey::Down),
                        Some(b'H') => Ok(RawKey::Home),
                        Some(b'F') => Ok(RawKey::End),
                        _ => Ok(RawKey::Other),
                    }
                } else if lead == b'O' {
                    if !poll_stdin_ms(25) {
                        return Ok(RawKey::Other);
                    }
                    match read_fd_byte()? {
                        Some(b'A') => Ok(RawKey::Up),
                        Some(b'B') => Ok(RawKey::Down),
                        Some(b'H') => Ok(RawKey::Home),
                        Some(b'F') => Ok(RawKey::End),
                        _ => Ok(RawKey::Other),
                    }
                } else {
                    Ok(RawKey::Other)
                }
            }
            _ => Ok(RawKey::Other),
        }
    }

    pub(super) fn read_secret_key() -> io::Result<SecretKey> {
        let Some(first) = read_fd_byte()? else {
            return Ok(SecretKey::Cancel);
        };
        match first {
            0x03 | 0x04 => Ok(SecretKey::Cancel), // Ctrl+C / Ctrl+D
            b'\r' | b'\n' => Ok(SecretKey::Enter),
            0x7F | 0x08 => Ok(SecretKey::Backspace),
            0x15 => Ok(SecretKey::ClearLine), // Ctrl+U
            0x1b => {
                // Consume any trailing escape sequence bytes (e.g. arrow keys) cleanly.
                if poll_stdin_ms(25)
                    && let Some(lead) = read_fd_byte()?
                    && lead == b'['
                {
                    let _ = drain_csi_final();
                }
                Ok(SecretKey::Ignore)
            }
            b if b < 0x20 => Ok(SecretKey::Ignore),
            b if b < 0x80 => Ok(SecretKey::Char(b as char)),
            lead => {
                // Reassemble multi-byte UTF-8 sequence directly from STDIN_FILENO.
                let expected = if lead & 0xE0 == 0xC0 {
                    2
                } else if lead & 0xF0 == 0xE0 {
                    3
                } else if lead & 0xF8 == 0xF0 {
                    4
                } else {
                    return Ok(SecretKey::Ignore);
                };
                let mut utf8 = [0u8; 4];
                utf8[0] = lead;
                for slot in &mut utf8[1..expected] {
                    let Some(next) = read_fd_byte()? else {
                        return Ok(SecretKey::Ignore);
                    };
                    *slot = next;
                }
                if let Ok(s) = std::str::from_utf8(&utf8[..expected])
                    && let Some(c) = s.chars().next()
                {
                    return Ok(SecretKey::Char(c));
                }
                Ok(SecretKey::Ignore)
            }
        }
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    use super::{RawKey, SecretKey};
    use std::io;

    pub(super) fn can_enter_raw_mode() -> bool {
        false
    }

    pub struct RawModeGuard;
    impl RawModeGuard {
        pub fn enter() -> Option<Self> {
            None
        }
    }

    pub(super) fn read_raw_key() -> io::Result<RawKey> {
        Ok(RawKey::Cancel)
    }

    pub(super) fn read_secret_key() -> io::Result<SecretKey> {
        Ok(SecretKey::Cancel)
    }
}

pub(super) use imp::RawModeGuard;

pub(super) fn can_enter_raw_mode() -> bool {
    imp::can_enter_raw_mode()
}

pub(super) fn read_raw_key() -> io::Result<RawKey> {
    imp::read_raw_key()
}

pub(super) fn read_secret_key() -> io::Result<SecretKey> {
    imp::read_secret_key()
}
