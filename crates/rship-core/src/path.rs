use serde::{Deserialize, Serialize};
use std::borrow::{Borrow, Cow};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use unicode_normalization::{IsNormalized, UnicodeNormalization, is_nfc_quick};

use crate::error::{Error, Result};

/// Canonical, traversal-safe, NFC-normalized relative path using `/` separators.
///
/// Empty string represents the root of a backend target.
///
/// NOTE: Always pair `RelPath` with `Entry::raw_path` when addressing existing
/// items on backends that preserve raw NFD bytes (Linux ext4, S3 keys).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct RelPath(String);

impl RelPath {
    pub fn root() -> Self {
        Self(String::new())
    }

    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parse and normalize a slash- or backslash-separated relative path to UTF-8 NFC.
    /// Rejects `.`, `..`, NUL bytes, and empty interior segments.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim_matches(['/', '\\']);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        let bytes = trimmed.as_bytes();
        if bytes.contains(&0) {
            return Err(Error::invalid_path("path contains NUL byte"));
        }

        // Fast path: check if `trimmed` already uses single `/` separators, contains no
        // `.` or `..` segments, and is already ASCII or UTF-8 NFC.
        let mut clean_separators = true;
        let mut all_ascii = true;
        let mut seg_start = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            if b >= 0x80 {
                all_ascii = false;
            }
            if b == b'\\' {
                clean_separators = false;
            }
            if b == b'/' || b == b'\\' {
                let seg = &bytes[seg_start..i];
                if seg.is_empty() {
                    clean_separators = false;
                } else if seg == b"." || seg == b".." {
                    return Err(Error::invalid_path(format!(
                        "path traversal segment `{}` is forbidden in `{input}`",
                        &trimmed[seg_start..i]
                    )));
                }
                seg_start = i + 1;
            }
        }
        let tail_seg = &bytes[seg_start..];
        if tail_seg == b"." || tail_seg == b".." {
            return Err(Error::invalid_path(format!(
                "path traversal segment `{}` is forbidden in `{input}`",
                &trimmed[seg_start..]
            )));
        }

        if clean_separators && (all_ascii || is_nfc_quick(trimmed.chars()) == IsNormalized::Yes) {
            return Ok(Self(trimmed.to_owned()));
        }

        // Slow path: normalize backslashes, collapse duplicate slashes, and NFC-normalize
        // into a single pre-sized String without per-segment Vec/String allocations.
        let mut out = String::with_capacity(trimmed.len());
        for seg in trimmed.split(['/', '\\']) {
            if seg.is_empty() {
                continue;
            }
            if seg == "." || seg == ".." {
                return Err(Error::invalid_path(format!(
                    "path traversal segment `{seg}` is forbidden in `{input}`"
                )));
            }
            if !out.is_empty() {
                out.push('/');
            }
            if seg.is_ascii() || is_nfc_quick(seg.chars()) == IsNormalized::Yes {
                out.push_str(seg);
            } else {
                out.extend(seg.nfc());
            }
        }
        Ok(Self(out))
    }

    /// Zero-allocation fast-path variant of [`Self::parse`] for owned strings: reuses
    /// `input`'s heap buffer directly when already canonical UTF-8 NFC without leading/trailing
    /// slashes, backslashes, duplicate slashes, or `.`/`..` segments.
    pub fn parse_owned(input: String) -> Result<Self> {
        let bytes = input.as_bytes();
        if bytes.is_empty() {
            return Ok(Self::root());
        }
        if !matches!(bytes[0], b'/' | b'\\')
            && !matches!(bytes[bytes.len() - 1], b'/' | b'\\')
            && !bytes.contains(&0)
        {
            let mut clean = true;
            let mut all_ascii = true;
            let mut seg_start = 0usize;
            for (i, &b) in bytes.iter().enumerate() {
                if b >= 0x80 {
                    all_ascii = false;
                }
                if b == b'\\' {
                    clean = false;
                    break;
                }
                if b == b'/' {
                    let seg = &bytes[seg_start..i];
                    if seg.is_empty() {
                        clean = false;
                        break;
                    }
                    if seg == b"." || seg == b".." {
                        return Err(Error::invalid_path(format!(
                            "path traversal segment `{}` is forbidden in `{input}`",
                            &input[seg_start..i]
                        )));
                    }
                    seg_start = i + 1;
                }
            }
            if clean {
                let tail = &bytes[seg_start..];
                if tail == b"." || tail == b".." {
                    return Err(Error::invalid_path(format!(
                        "path traversal segment `{}` is forbidden in `{input}`",
                        &input[seg_start..]
                    )));
                }
                if all_ascii || is_nfc_quick(input.chars()) == IsNormalized::Yes {
                    return Ok(Self(input));
                }
            }
        }
        Self::parse(&input)
    }

    /// Construct directly from a string already known to be canonical NFC without `.`/`..`
    /// or leading/trailing slashes (e.g., persisted SQLite journal/index columns).
    #[inline]
    pub fn from_normalized_unchecked(normalized: String) -> Self {
        debug_assert!(
            normalized.is_empty()
                || (!normalized.starts_with('/')
                    && !normalized.ends_with('/')
                    && !normalized.contains('\\')
                    && !normalized.contains('\0')),
            "invalid pre-normalized RelPath: {normalized:?}"
        );
        Self(normalized)
    }

    /// Construct from already-validated segments (each NFC-normalized and checked).
    pub fn join(&self, segment: &str) -> Result<Self> {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains(['/', '\\', '\0'])
        {
            return Err(Error::invalid_path(format!(
                "invalid path segment `{segment}`"
            )));
        }
        let already_nfc = segment.is_ascii() || is_nfc_quick(segment.chars()) == IsNormalized::Yes;
        if self.0.is_empty() {
            if already_nfc {
                Ok(Self(segment.to_owned()))
            } else {
                Ok(Self(segment.nfc().collect()))
            }
        } else {
            let mut out = String::with_capacity(self.0.len() + 1 + segment.len());
            out.push_str(&self.0);
            out.push('/');
            if already_nfc {
                out.push_str(segment);
            } else {
                out.extend(segment.nfc());
            }
            Ok(Self(out))
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.rsplit_once('/') {
            Some((p, _)) => Some(Self(p.to_string())),
            None => Some(Self::root()),
        }
    }

    pub fn file_name(&self) -> Option<&str> {
        if self.0.is_empty() {
            return None;
        }
        match self.0.rsplit_once('/') {
            Some((_, name)) => Some(name),
            None => Some(&self.0),
        }
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|s| !s.is_empty())
    }

    /// Join two already-validated relative paths cleanly without re-parsing.
    pub fn join_path(&self, other: &Self) -> Self {
        if self.0.is_empty() {
            other.clone()
        } else if other.0.is_empty() {
            self.clone()
        } else {
            Self(format!("{}/{}", self.0, other.0))
        }
    }

    /// Strip a leading directory `prefix` from this relative path, returning the
    /// remainder (or [`RelPath::root`] when `self == prefix`), or `None` if `self`
    /// is not under `prefix`.
    pub fn strip_prefix(&self, prefix: &Self) -> Option<Self> {
        if prefix.0.is_empty() {
            return Some(self.clone());
        }
        if self.0 == prefix.0 {
            return Some(Self::root());
        }
        let rest = self.0.strip_prefix(&prefix.0)?.strip_prefix('/')?;
        Some(Self::from_normalized_unchecked(rest.to_string()))
    }

    /// Case-folded key used for pre-flight case-insensitive collision detection,
    /// borrowing `&str` without allocating when already lowercase ASCII.
    pub fn fold_key_cow(&self) -> Cow<'_, str> {
        let mut has_upper = false;
        let mut has_non_ascii = false;
        for &b in self.0.as_bytes() {
            if b >= 0x80 {
                has_non_ascii = true;
                break;
            }
            if b.is_ascii_uppercase() {
                has_upper = true;
            }
        }
        if has_non_ascii {
            Cow::Owned(self.0.to_lowercase())
        } else if has_upper {
            Cow::Owned(self.0.to_ascii_lowercase())
        } else {
            Cow::Borrowed(&self.0)
        }
    }

    /// Case-folded key used for pre-flight case-insensitive collision detection.
    pub fn fold_key(&self) -> String {
        self.fold_key_cow().into_owned()
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RelPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for RelPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl FromStr for RelPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for RelPath {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Self::parse(value)
    }
}

impl TryFrom<String> for RelPath {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse_owned(value)
    }
}

impl From<RelPath> for String {
    fn from(p: RelPath) -> Self {
        p.0
    }
}

/// Parsed CLI target specification: either a local filesystem path or `remote:path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetPath {
    Local(PathBuf),
    Remote { remote: String, path: RelPath },
}

impl TargetPath {
    /// Parse an rclone-style path specification with unambiguous Windows support:
    /// - `/foo`, `\foo`, `./foo`, `../foo`, `.\foo`, `..\foo` -> `Local`
    /// - `\\server\share\...`, `\\?\C:\...`, `\\.\...` -> `Local`
    /// - `C:\foo`, `C:/foo`, `C:foo`, `C:` (1-letter drive prefix) -> `Local`
    /// - `<remote>:<path>` where `<remote>` has len >= 2 and chars `[A-Za-z0-9_-]` -> `Remote`
    /// - Everything else -> `Local`
    pub fn parse(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::invalid_path("target path cannot be empty"));
        }
        if input.contains('\0') {
            return Err(Error::invalid_path("target path contains NUL byte"));
        }

        // Explicit local prefixes: Unix abs, Windows UNC/verbatim, relative ./ or ../
        if input.starts_with('/')
            || input.starts_with('\\')
            || input.starts_with("./")
            || input.starts_with("../")
            || input.starts_with(".\\")
            || input.starts_with("..\\")
            || input == "."
            || input == ".."
        {
            return Ok(Self::Local(PathBuf::from(input)));
        }

        // Windows drive letter (absolute `C:\foo`, `C:/foo`, or drive-relative `C:foo` / `C:`).
        let bytes = input.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Ok(Self::Local(PathBuf::from(input)));
        }

        // Check `remote:path` where remote name is >= 2 chars `[A-Za-z0-9_-]`.
        if let Some((prefix, rest)) = input.split_once(':')
            && is_valid_remote_name(prefix)
        {
            let rel = RelPath::parse(rest)?;
            return Ok(Self::Remote {
                remote: prefix.to_string(),
                path: rel,
            });
        }

        Ok(Self::Local(PathBuf::from(input)))
    }
}

impl FromStr for TargetPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl fmt::Display for TargetPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(p) => write!(f, "{}", p.display()),
            Self::Remote { remote, path } => write!(f, "{remote}:{path}"),
        }
    }
}

pub fn is_valid_remote_name(name: &str) -> bool {
    name.len() >= 2
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows_and_unix_and_remote_paths() {
        assert!(matches!(
            TargetPath::parse(r"C:\Users\alice\data").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse("D:/backup/2026").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse("C:relative.txt").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse(r"\\server\share\dir").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse(r"\\?\C:\very\long\path").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse("/var/data/file").unwrap(),
            TargetPath::Local(_)
        ));
        assert!(matches!(
            TargetPath::parse("./local_dir").unwrap(),
            TargetPath::Local(_)
        ));

        match TargetPath::parse("gdrive:backups/2026/file.bin").unwrap() {
            TargetPath::Remote { remote, path } => {
                assert_eq!(remote, "gdrive");
                assert_eq!(path.as_str(), "backups/2026/file.bin");
            }
            _ => panic!("expected remote"),
        }

        match TargetPath::parse("my-s3:").unwrap() {
            TargetPath::Remote { remote, path } => {
                assert_eq!(remote, "my-s3");
                assert!(path.is_root());
            }
            _ => panic!("expected remote root"),
        }
    }

    #[test]
    fn relpath_normalizes_nfc_and_blocks_traversal() {
        // NFD "cafe\u{0301}" -> NFC "caf\u{00e9}"
        let p = RelPath::parse("dir/cafe\u{0301}.txt").unwrap();
        assert_eq!(p.as_str(), "dir/caf\u{00e9}.txt");

        assert!(RelPath::parse("../secret").is_err());
        assert!(RelPath::parse("a/../b").is_err());
        assert!(RelPath::parse("a/./b").is_err());
    }

    #[test]
    fn relpath_parse_owned_and_fold_key_cow_fast_paths() {
        // Canonical ASCII moves owned String cleanly; non-canonical inputs normalize identically.
        let owned = String::from("assets/2026/photo.jpg");
        let ptr = owned.as_ptr();
        let rp = RelPath::parse_owned(owned).unwrap();
        assert_eq!(rp.as_str(), "assets/2026/photo.jpg");
        assert_eq!(
            rp.as_str().as_ptr(),
            ptr,
            "canonical NFC String should be moved without realloc"
        );

        let nfd = RelPath::parse_owned(String::from("dir/cafe\u{0301}.txt")).unwrap();
        assert_eq!(nfd.as_str(), "dir/caf\u{00e9}.txt");
        let trimmed = RelPath::parse_owned(String::from("/a//b/")).unwrap();
        assert_eq!(trimmed.as_str(), "a/b");
        assert!(RelPath::parse_owned(String::from("a/../b")).is_err());

        // fold_key_cow borrows lowercase ASCII without allocating, owns uppercase/Unicode.
        assert!(matches!(
            rp.fold_key_cow(),
            Cow::Borrowed("assets/2026/photo.jpg")
        ));
        let upper = RelPath::parse("Assets/Report.PDF").unwrap();
        assert!(matches!(upper.fold_key_cow(), Cow::Owned(ref s) if s == "assets/report.pdf"));
        let uni = RelPath::parse("CAF\u{00c9}/File.txt").unwrap();
        assert!(matches!(uni.fold_key_cow(), Cow::Owned(ref s) if s == "caf\u{00e9}/file.txt"));
        assert_eq!(uni.fold_key(), "caf\u{00e9}/file.txt");
    }

    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        fn safe_segment_strategy() -> impl Strategy<Value = String> {
            // Mix ASCII, punctuation, Unicode NFC/NFD combining sequences (e.g. e + combining acute).
            let alphabet = vec![
                "a",
                "b",
                "Z",
                "0",
                "_",
                "-",
                ".",
                "e\u{0301}",
                "\u{00e9}",
                "a\u{0308}",
                "中文",
                "\u{1F680}",
            ];
            prop::collection::vec(prop::sample::select(alphabet), 1..=6)
                .prop_map(|parts| parts.concat())
                .prop_filter("reject traversal dots", |s| {
                    !s.is_empty() && s != "." && s != ".."
                })
        }

        fn valid_segments_strategy() -> impl Strategy<Value = Vec<String>> {
            prop::collection::vec(safe_segment_strategy(), 0..=5)
        }

        proptest! {
            #[test]
            fn prop_relpath_parse_and_parse_owned_agree_and_normalize_nfc(
                segs in valid_segments_strategy(),
                leading in prop::sample::select(vec!["", "/", "//", "\\", "/\\"]),
                trailing in prop::sample::select(vec!["", "/", "//", "\\"]),
                sep in prop::sample::select(vec!["/", "//", "\\", "/\\"]),
            ) {
                let raw = format!("{leading}{}{trailing}", segs.join(sep));
                let parsed = RelPath::parse(&raw).unwrap();
                let owned = RelPath::parse_owned(raw.clone()).unwrap();
                prop_assert_eq!(&parsed, &owned);

                // Canonical invariants: strictly NFC, no leading/trailing slashes, no backslashes,
                // no NUL bytes, no empty interior segments, no `.` or `..` segments.
                let s = parsed.as_str();
                prop_assert_eq!(s.nfc().collect::<String>(), s);
                prop_assert!(!s.starts_with('/'));
                prop_assert!(!s.ends_with('/'));
                prop_assert!(!s.contains('\\'));
                prop_assert!(!s.contains('\0'));
                prop_assert!(!s.contains("//"));
                for seg in parsed.segments() {
                    prop_assert!(!seg.is_empty());
                    prop_assert_ne!(seg, ".");
                    prop_assert_ne!(seg, "..");
                }

                // Idempotence and NFD equivalence.
                prop_assert_eq!(RelPath::parse(s).unwrap(), parsed.clone());
                let nfd: String = s.nfd().collect();
                prop_assert_eq!(RelPath::parse(&nfd).unwrap(), parsed);
            }

            #[test]
            fn prop_relpath_join_parent_and_strip_prefix_invariants(
                base_segs in valid_segments_strategy(),
                leaf in safe_segment_strategy(),
            ) {
                let base = RelPath::parse(&base_segs.join("/")).unwrap();
                let joined = base.join(&leaf).unwrap();
                let expected_leaf_nfc: String = leaf.nfc().collect();

                prop_assert_eq!(joined.parent(), Some(base.clone()));
                prop_assert_eq!(joined.file_name(), Some(expected_leaf_nfc.as_str()));
                prop_assert_eq!(
                    joined.strip_prefix(&base),
                    Some(RelPath::parse(&expected_leaf_nfc).unwrap())
                );
                prop_assert_eq!(
                    base.join_path(&RelPath::parse(&leaf).unwrap()),
                    joined.clone()
                );

                // Walking `.parent()` terminates at root in exactly `segments().count()` steps.
                let mut cur = joined;
                let mut steps = 0usize;
                let expected_depth = cur.segments().count();
                while let Some(p) = cur.parent() {
                    steps += 1;
                    cur = p;
                }
                prop_assert!(cur.is_root());
                prop_assert_eq!(steps, expected_depth);
            }

            #[test]
            fn prop_relpath_rejects_traversal_nul_and_invalid_join_segments(
                prefix in valid_segments_strategy(),
                suffix in valid_segments_strategy(),
                bad_seg in prop::sample::select(vec![".", ".."]),
                sep in prop::sample::select(vec!["/", "\\"]),
            ) {
                let mut parts = prefix.clone();
                parts.push(bad_seg.to_string());
                parts.extend(suffix.clone());
                let bad_traversal = parts.join(sep);
                prop_assert!(RelPath::parse(&bad_traversal).is_err());
                prop_assert!(RelPath::parse_owned(bad_traversal).is_err());

                // NUL byte anywhere is always rejected.
                let with_nul = format!("{}\0{}", prefix.join("/"), suffix.join("/"));
                prop_assert!(RelPath::parse(&with_nul).is_err());
                prop_assert!(RelPath::parse_owned(with_nul).is_err());

                // `RelPath::join` strictly rejects empty, `.`, `..`, leading `/`, `\`, and `\0`.
                let base = RelPath::parse(&prefix.join("/")).unwrap();
                prop_assert!(base.join("").is_err());
                prop_assert!(base.join(".").is_err());
                prop_assert!(base.join("..").is_err());
                prop_assert!(base.join("/abs").is_err());
                prop_assert!(base.join("a/b").is_err());
                prop_assert!(base.join("a\\b").is_err());
                prop_assert!(base.join("a\0b").is_err());
            }
        }
    }
}
