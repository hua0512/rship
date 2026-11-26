//! Bijective, cross-OS filename encoding for Windows-safe and cloud-safe storage.
//!
//! Unlike naive replacement (which breaks bijectivity when source names already
//! contain replacement characters like `？`), this codec escapes the escape
//! marker itself (`^`) using hex escapes `^XX` (uppercase) or `^uXXXX` so every
//! valid UTF-8 filename round-trips 100% losslessly.

use crate::error::{Error, Result};

const ESC: char = '^';

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncodingMode {
    /// Leave valid segments untouched (POSIX / cloud keys).
    #[default]
    Identity,
    /// Bijective Windows-safe segment encoding (handles `<>:"/\|?*`, control
    /// chars, trailing `.` / space, Windows reserved device names including
    /// extensions like `CON.txt`, and escapes literal `^`).
    WindowsSafe,
}

impl EncodingMode {
    pub fn encode_segment(self, seg: &str) -> String {
        match self {
            Self::Identity => seg.to_string(),
            Self::WindowsSafe => encode_windows_segment(seg),
        }
    }

    pub fn decode_segment(self, seg: &str) -> Result<String> {
        match self {
            Self::Identity => Ok(seg.to_string()),
            Self::WindowsSafe => decode_windows_segment(seg),
        }
    }
}

/// Returns true if `seg` would be illegal or mangled by Win32 filesystems
/// (even under `\\?\` verbatim mode, creating raw reserved names or trailing
/// dots makes files undeletable in Windows Explorer).
pub fn is_windows_reserved_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg);
    let upper = stem.to_ascii_uppercase();
    WINDOWS_RESERVED.contains(&upper.as_str())
}

fn needs_char_escape(c: char) -> bool {
    matches!(
        c,
        ESC | '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | '\x00'..='\x1f' | '\x7f'
    )
}

fn push_escaped(out: &mut String, c: char) {
    let code = c as u32;
    if code <= 0xFF {
        out.push(ESC);
        out.push_str(&format!("{code:02X}"));
    } else {
        out.push(ESC);
        out.push('u');
        out.push_str(&format!("{code:04X}"));
    }
}

pub fn encode_windows_segment(seg: &str) -> String {
    if seg.is_empty() {
        return String::new();
    }

    let chars: Vec<char> = seg.chars().collect();
    let last_idx = chars.len() - 1;
    let reserved = is_windows_reserved_name(seg);

    let mut out = String::with_capacity(seg.len() + 8);
    for (idx, &c) in chars.iter().enumerate() {
        let is_trailing_dot_or_space = idx == last_idx && (c == '.' || c == ' ');
        let is_reserved_first = reserved && idx == 0;
        if needs_char_escape(c) || is_trailing_dot_or_space || is_reserved_first {
            push_escaped(&mut out, c);
        } else {
            out.push(c);
        }
    }
    out
}

pub fn decode_windows_segment(seg: &str) -> Result<String> {
    let mut out = String::with_capacity(seg.len());
    let mut chars = seg.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ESC {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('u') => {
                chars.next();
                let hex_str: String = chars.by_ref().take(4).collect();
                if hex_str.len() != 4 {
                    return Err(Error::invalid_path(format!(
                        "truncated unicode escape in `{seg}`"
                    )));
                }
                let code = u32::from_str_radix(&hex_str, 16)
                    .map_err(|_| Error::invalid_path(format!("bad hex escape in `{seg}`")))?;
                let decoded = char::from_u32(code)
                    .ok_or_else(|| Error::invalid_path(format!("bad codepoint in `{seg}`")))?;
                out.push(decoded);
            }
            Some(_) => {
                let hex_str: String = chars.by_ref().take(2).collect();
                if hex_str.len() != 2 {
                    return Err(Error::invalid_path(format!(
                        "truncated byte escape in `{seg}`"
                    )));
                }
                let code = u32::from_str_radix(&hex_str, 16)
                    .map_err(|_| Error::invalid_path(format!("bad hex escape in `{seg}`")))?;
                let decoded = char::from_u32(code)
                    .ok_or_else(|| Error::invalid_path(format!("bad codepoint in `{seg}`")))?;
                out.push(decoded);
            }
            None => {
                return Err(Error::invalid_path(format!(
                    "dangling escape marker in `{seg}`"
                )));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn encodes_windows_edge_cases_bijectively() {
        let cases = [
            "normal.txt",
            "what?file:name*.log",
            "literal^5E^3F^marker",
            "CON",
            "con.txt",
            "NUL.tar.gz",
            "trailing.",
            "trailing ",
            "a\tb\nc",
            "中文？全角.txt",
        ];

        for orig in cases {
            let enc = encode_windows_segment(orig);
            assert!(!is_windows_reserved_name(&enc), "still reserved: {enc}");
            assert!(!enc.ends_with('.'), "trailing dot: {enc}");
            assert!(!enc.ends_with(' '), "trailing space: {enc}");
            for bad in ['<', '>', ':', '"', '/', '\\', '|', '?', '*'] {
                assert!(!enc.contains(bad), "contains `{bad}`: {enc}");
            }
            let dec = decode_windows_segment(&enc).unwrap();
            assert_eq!(dec, orig, "roundtrip failed for {orig:?} -> {enc:?}");
        }

        // Distinct inputs that look similar must NOT collide.
        assert_ne!(
            encode_windows_segment("foo?"),
            encode_windows_segment("foo^3F")
        );
    }

    proptest! {
        #[test]
        fn windows_codec_is_bijective(s in "[^/\\\\\\x00]{1,64}") {
            let enc = encode_windows_segment(&s);
            let dec = decode_windows_segment(&enc).unwrap();
            prop_assert_eq!(dec, s);
            prop_assert!(!is_windows_reserved_name(&enc));
            prop_assert!(!enc.ends_with('.'));
            prop_assert!(!enc.ends_with(' '));
        }
    }
}
