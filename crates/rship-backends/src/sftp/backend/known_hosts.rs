//! Strict OpenSSH `known_hosts` parser, certificate/CA & HMAC-SHA1 hashed-host
//! verifier, cross-algorithm MITM guard, and atomic TOFU persistence.

use aws_lc_rs::hmac;
use russh::keys::PublicKeyOrCertificate;
use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::{Certificate, Fingerprint, HashAlg, PublicKey};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::common::lock_unpoisoned;
use crate::sftp::config::HostKeyPolicy;

/// Process-wide lock serializing TOFU `AcceptNew` read-check-write updates to `known_hosts`.
static KNOWN_HOSTS_WRITE_LOCK: StdMutex<()> = StdMutex::new(());
static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub(super) enum KnownHostsError {
    Mismatch(String),
    Revoked(String),
    Unknown(String),
    Invalid(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryMarker {
    None,
    Revoked,
    CertAuthority,
}

#[derive(Debug, Clone)]
struct KnownHostsEntry {
    line_no: usize,
    marker: EntryMarker,
    host_patterns: String,
    pubkey: PublicKey,
}

struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p);
        }
    }
}

fn resolve_known_hosts_path(explicit: Option<&Path>) -> Result<PathBuf, KnownHostsError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let home = ["HOME", "USERPROFILE"].into_iter().find_map(|var| {
        std::env::var_os(var)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    match home {
        Some(h) => Ok(h.join(".ssh").join("known_hosts")),
        None => Err(KnownHostsError::Invalid(
            "cannot resolve default `known_hosts` path: neither `HOME` nor `USERPROFILE` is set"
                .to_string(),
        )),
    }
}

fn read_known_hosts_file(
    path: &Path,
) -> Result<Option<(String, Vec<KnownHostsEntry>)>, KnownHostsError> {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let entries = parse_known_hosts(path, &raw)?;
            Ok(Some((raw, entries)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KnownHostsError::Invalid(format!(
            "cannot read known_hosts `{}`: {e}",
            path.display()
        ))),
    }
}

fn parse_known_hosts(path: &Path, content: &str) -> Result<Vec<KnownHostsEntry>, KnownHostsError> {
    let mut entries = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let first = tokens.next().ok_or_else(|| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: empty entry",
                path.display()
            ))
        })?;
        let (marker, host_patterns) = if first.starts_with('@') {
            let marker = match first {
                "@revoked" => EntryMarker::Revoked,
                "@cert-authority" => EntryMarker::CertAuthority,
                other => {
                    return Err(KnownHostsError::Invalid(format!(
                        "malformed known_hosts `{}` at line {line_no}: unknown marker `{other}`",
                        path.display()
                    )));
                }
            };
            let hosts = tokens.next().ok_or_else(|| {
                KnownHostsError::Invalid(format!(
                    "malformed known_hosts `{}` at line {line_no}: missing host pattern",
                    path.display()
                ))
            })?;
            (marker, hosts)
        } else {
            (EntryMarker::None, first)
        };

        let key_type = tokens.next().ok_or_else(|| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: missing key type",
                path.display()
            ))
        })?;
        let key_b64 = tokens.next().ok_or_else(|| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: missing key data",
                path.display()
            ))
        })?;
        let openssh_str = format!("{key_type} {key_b64}");
        let pubkey = PublicKey::from_openssh(&openssh_str).map_err(|e| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid public key `{key_type}`: {e}",
                path.display()
            ))
        })?;
        entries.push(KnownHostsEntry {
            line_no,
            marker,
            host_patterns: host_patterns.to_string(),
            pubkey,
        });
    }
    Ok(entries)
}

fn host_port_token(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

fn decode_base64_std(input: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let (chunks, _) = bytes.as_chunks::<4>();
    for (i, chunk) in chunks.iter().enumerate() {
        let is_last = (i + 1) * 4 == bytes.len();
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        if chunk[2] == b'=' {
            if !is_last || chunk[3] != b'=' {
                return None;
            }
            out.push((a << 2) | (b >> 4));
        } else {
            let c = val(chunk[2])?;
            if chunk[3] == b'=' {
                if !is_last {
                    return None;
                }
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            } else {
                let d = val(chunk[3])?;
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
        }
    }
    Some(out)
}

fn glob_match_ci(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi].eq_ignore_ascii_case(&t[ti])) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn match_single_host_pattern(host: &str, port: u16, pat: &str) -> bool {
    if let Some(rest) = pat.strip_prefix('[')
        && let Some((host_pat, port_str)) = rest.split_once("]:")
    {
        return port_str.parse::<u16>() == Ok(port) && glob_match_ci(host_pat, host);
    }
    port == 22 && glob_match_ci(pat, host)
}

fn match_host_patterns(
    path: &Path,
    line_no: usize,
    host: &str,
    port: u16,
    pattern_list: &str,
) -> Result<bool, KnownHostsError> {
    if pattern_list.starts_with("|1|") {
        if pattern_list.contains([',', '!']) {
            return Err(KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid hashed host pattern",
                path.display()
            )));
        }
        let mut parts = pattern_list.split('|');
        let p0 = parts.next();
        let p1 = parts.next();
        let salt_b64 = parts.next();
        let hash_b64 = parts.next();
        if p0 != Some("") || p1 != Some("1") || parts.next().is_some() {
            return Err(KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid `|1|` hashed host syntax",
                path.display()
            )));
        }
        let salt = salt_b64.and_then(decode_base64_std).ok_or_else(|| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid base64 salt in hashed host",
                path.display()
            ))
        })?;
        let hash = hash_b64.and_then(decode_base64_std).ok_or_else(|| {
            KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid base64 hash in hashed host",
                path.display()
            ))
        })?;
        if hash.len() != 20 {
            return Err(KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: unexpected HMAC-SHA1 hash length {}",
                path.display(),
                hash.len()
            )));
        }
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &salt);
        let tok = host_port_token(host, port);
        if hmac::verify(&key, tok.as_bytes(), &hash).is_ok() {
            return Ok(true);
        }
        let lower_tok = host_port_token(&host.to_ascii_lowercase(), port);
        if lower_tok != tok && hmac::verify(&key, lower_tok.as_bytes(), &hash).is_ok() {
            return Ok(true);
        }
        return Ok(false);
    }

    let mut matched = false;
    for seg in pattern_list.split(',') {
        if seg.is_empty() || seg.starts_with("|1|") {
            return Err(KnownHostsError::Invalid(format!(
                "malformed known_hosts `{}` at line {line_no}: invalid host pattern list",
                path.display()
            )));
        }
        if let Some(neg) = seg.strip_prefix('!') {
            if match_single_host_pattern(host, port, neg) {
                return Ok(false);
            }
        } else if match_single_host_pattern(host, port, seg) {
            matched = true;
        }
    }
    Ok(matched)
}

enum EvalOutcome {
    Trusted,
    NeedsLearn(PublicKey),
}

fn evaluate_entries(
    path: &Path,
    host: &str,
    port: u16,
    policy: HostKeyPolicy,
    server_key: &PublicKeyOrCertificate,
    entries: &[KnownHostsEntry],
) -> Result<EvalOutcome, KnownHostsError> {
    let target = host_port_token(host, port);
    let presented_plain = match server_key {
        PublicKeyOrCertificate::PublicKey { key, .. } => Some(key),
        PublicKeyOrCertificate::Certificate(_) => None,
    };

    // Step 1: @revoked takes absolute precedence over every other rule and policy (except Insecure).
    for entry in entries.iter().filter(|e| e.marker == EntryMarker::Revoked) {
        if !match_host_patterns(path, entry.line_no, host, port, &entry.host_patterns)? {
            continue;
        }
        let revoked_hit = match server_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                entry.pubkey.key_data() == key.key_data()
            }
            PublicKeyOrCertificate::Certificate(cert) => {
                entry.pubkey.key_data() == cert.public_key()
                    || entry.pubkey.key_data() == cert.signature_key()
            }
        };
        if revoked_hit {
            return Err(KnownHostsError::Revoked(format!(
                "SSH host key for `{target}` is marked @revoked in `{}` (line {})",
                path.display(),
                entry.line_no
            )));
        }
    }

    // Step 2: Host certificate verification via @cert-authority.
    if let PublicKeyOrCertificate::Certificate(cert) = server_key {
        return verify_host_certificate(path, host, port, policy, cert, entries);
    }

    let presented = presented_plain.expect("checked Certificate branch above");

    // Step 3: Regular host key entries (cross-algorithm MITM check!).
    let mut matching_host_entries = Vec::new();
    for entry in entries.iter().filter(|e| e.marker == EntryMarker::None) {
        if match_host_patterns(path, entry.line_no, host, port, &entry.host_patterns)? {
            matching_host_entries.push(entry);
        }
    }

    if matching_host_entries
        .iter()
        .any(|e| e.pubkey.key_data() == presented.key_data())
    {
        return Ok(EvalOutcome::Trusted);
    }

    if let Some(first_conflict) = matching_host_entries.first() {
        return Err(KnownHostsError::Mismatch(format!(
            "SSH host key verification FAILED for `{target}` (possible MITM): \
             presented {} ({}) does not match known_hosts `{}` line {} ({} / {})",
            presented.algorithm(),
            presented.fingerprint(HashAlg::Sha256),
            path.display(),
            first_conflict.line_no,
            first_conflict.pubkey.algorithm(),
            first_conflict.pubkey.fingerprint(HashAlg::Sha256),
        )));
    }

    match policy {
        HostKeyPolicy::Strict => Err(KnownHostsError::Unknown(format!(
            "SSH host `{target}` ({}) not found in known_hosts `{}` (strict policy)",
            presented.fingerprint(HashAlg::Sha256),
            path.display()
        ))),
        HostKeyPolicy::AcceptNew => Ok(EvalOutcome::NeedsLearn(presented.clone())),
        HostKeyPolicy::Insecure => Ok(EvalOutcome::Trusted),
    }
}

fn verify_host_certificate(
    path: &Path,
    host: &str,
    port: u16,
    policy: HostKeyPolicy,
    cert: &Certificate,
    entries: &[KnownHostsEntry],
) -> Result<EvalOutcome, KnownHostsError> {
    let target = host_port_token(host, port);
    if cert.cert_type() != CertType::Host {
        return Err(KnownHostsError::Mismatch(format!(
            "SSH server presented non-host certificate for `{target}`"
        )));
    }
    if !cert.critical_options().is_empty() {
        return Err(KnownHostsError::Mismatch(format!(
            "SSH host certificate for `{target}` contains unsupported critical options"
        )));
    }

    let mut ca_fingerprints: Vec<Fingerprint> = Vec::new();
    for entry in entries
        .iter()
        .filter(|e| e.marker == EntryMarker::CertAuthority)
    {
        if match_host_patterns(path, entry.line_no, host, port, &entry.host_patterns)? {
            ca_fingerprints.push(entry.pubkey.fingerprint(HashAlg::Sha256));
        }
    }

    let principal_ok = cert.valid_principals().is_empty()
        || cert
            .valid_principals()
            .iter()
            .any(|p| p.eq_ignore_ascii_case(host));

    if !ca_fingerprints.is_empty() && principal_ok && cert.validate(&ca_fingerprints).is_ok() {
        return Ok(EvalOutcome::Trusted);
    }

    // Also inspect plain host entries so an existing host key mismatch isn't hidden,
    // or if CA validation failed explicitly reject as Mismatch.
    if !ca_fingerprints.is_empty() {
        return Err(KnownHostsError::Mismatch(format!(
            "SSH host certificate validation failed for `{target}` against @cert-authority in `{}`",
            path.display()
        )));
    }

    let inner_key = PublicKey::new(cert.public_key().clone(), "");
    let mut conflict_line = None;
    for entry in entries.iter().filter(|e| e.marker == EntryMarker::None) {
        if match_host_patterns(path, entry.line_no, host, port, &entry.host_patterns)? {
            if entry.pubkey.key_data() == inner_key.key_data() {
                return Ok(EvalOutcome::Trusted);
            }
            conflict_line.get_or_insert(entry.line_no);
        }
    }

    if let Some(line_no) = conflict_line {
        return Err(KnownHostsError::Mismatch(format!(
            "SSH host certificate inner key for `{target}` conflicts with known_hosts `{}` line {line_no}",
            path.display()
        )));
    }

    match policy {
        HostKeyPolicy::Strict | HostKeyPolicy::AcceptNew => Err(KnownHostsError::Unknown(format!(
            "SSH host `{target}` presented unverified host certificate (no matching @cert-authority in `{}`)",
            path.display()
        ))),
        HostKeyPolicy::Insecure => Ok(EvalOutcome::Trusted),
    }
}

fn persist_known_host_atomic(
    path: &Path,
    host: &str,
    port: u16,
    policy: HostKeyPolicy,
    server_key: &PublicKeyOrCertificate,
    new_key: &PublicKey,
) -> Result<(), KnownHostsError> {
    let _guard = lock_unpoisoned(&KNOWN_HOSTS_WRITE_LOCK);

    // Re-read & re-check under lock to close concurrent TOFU race conditions.
    let existing_raw = match read_known_hosts_file(path)? {
        Some((raw, entries)) => {
            match evaluate_entries(path, host, port, policy, server_key, &entries)? {
                EvalOutcome::Trusted => return Ok(()),
                EvalOutcome::NeedsLearn(_) => raw,
            }
        }
        None => String::new(),
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let parent_existed = parent.exists();
        fs::create_dir_all(parent).map_err(|e| {
            KnownHostsError::Invalid(format!(
                "create known_hosts parent `{}`: {e}",
                parent.display()
            ))
        })?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
        #[cfg(not(unix))]
        let _ = parent_existed;
    }

    let clean_key = PublicKey::new(new_key.key_data().clone(), "");
    let openssh_key = clean_key.to_openssh().map_err(|e| {
        KnownHostsError::Invalid(format!("encode SSH host public key for known_hosts: {e}"))
    })?;
    let entry_line = format!("{} {}\n", host_port_token(host, port), openssh_key.trim());

    let mut content = existing_raw;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&entry_line);

    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("known_hosts");
    let tmp_name = format!(".{file_name}.tmp.{pid}.{seq}");
    let tmp_path = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(tmp_name),
        _ => PathBuf::from(tmp_name),
    };

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp_path).map_err(|e| {
        KnownHostsError::Invalid(format!(
            "create temporary known_hosts `{}`: {e}",
            tmp_path.display()
        ))
    })?;
    let mut guard = TempFileGuard::new(tmp_path.clone());

    f.write_all(content.as_bytes()).map_err(|e| {
        KnownHostsError::Invalid(format!(
            "write temporary known_hosts `{}`: {e}",
            tmp_path.display()
        ))
    })?;
    f.flush().map_err(|e| {
        KnownHostsError::Invalid(format!(
            "flush temporary known_hosts `{}`: {e}",
            tmp_path.display()
        ))
    })?;
    f.sync_all().map_err(|e| {
        KnownHostsError::Invalid(format!(
            "sync temporary known_hosts `{}`: {e}",
            tmp_path.display()
        ))
    })?;
    drop(f);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).map_err(|e| {
            KnownHostsError::Invalid(format!(
                "chmod 0600 temporary known_hosts `{}`: {e}",
                tmp_path.display()
            ))
        })?;
    }

    fs::rename(&tmp_path, path).map_err(|e| {
        KnownHostsError::Invalid(format!(
            "persist known_hosts `{}` -> `{}`: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    guard.disarm();
    Ok(())
}

pub(super) fn verify_and_maybe_learn(
    host: &str,
    port: u16,
    policy: HostKeyPolicy,
    explicit_path: Option<&Path>,
    server_key: &PublicKeyOrCertificate,
) -> Result<(), KnownHostsError> {
    if policy == HostKeyPolicy::Insecure {
        return Ok(());
    }
    let path = resolve_known_hosts_path(explicit_path)?;
    let entries = match read_known_hosts_file(&path)? {
        Some((_, entries)) => entries,
        None => Vec::new(),
    };

    match evaluate_entries(&path, host, port, policy, server_key, &entries)? {
        EvalOutcome::Trusted => Ok(()),
        EvalOutcome::NeedsLearn(new_key) => {
            persist_known_host_atomic(&path, host, port, policy, server_key, &new_key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::certificate::{Builder as CertBuilder, CertType};
    use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
    use std::sync::Arc;
    use tempfile::TempDir;

    fn ed25519_pub(seed: u8) -> PublicKey {
        PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[seed; 32])),
            "test-comment",
        )
        .unwrap()
        .public_key()
        .clone()
    }

    fn ecdsa_pub() -> PublicKey {
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        PrivateKey::random(
            &mut rng,
            russh::keys::Algorithm::Ecdsa {
                curve: russh::keys::EcdsaCurve::NistP256,
            },
        )
        .unwrap()
        .public_key()
        .clone()
    }

    fn as_pk(k: &PublicKey) -> PublicKeyOrCertificate {
        PublicKeyOrCertificate::PublicKey {
            key: k.clone(),
            hash_alg: None,
        }
    }

    #[test]
    fn accept_new_persists_known_hosts_and_blocks_cross_algorithm_mitm() {
        let tmp = TempDir::new().unwrap();
        let kh = tmp.path().join("nested").join("known_hosts");
        let ed_key = ed25519_pub(1);
        let alt_ed_key = ed25519_pub(2);
        let ecdsa_key = ecdsa_pub();

        // First connection learns Ed25519 key and creates parent + file.
        verify_and_maybe_learn(
            "example.internal",
            2222,
            HostKeyPolicy::AcceptNew,
            Some(&kh),
            &as_pk(&ed_key),
        )
        .unwrap();
        assert!(kh.exists());
        let saved = fs::read_to_string(&kh).unwrap();
        assert!(saved.starts_with("[example.internal]:2222 ssh-ed25519 "));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&kh).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Strict verification succeeds with learned key.
        verify_and_maybe_learn(
            "example.internal",
            2222,
            HostKeyPolicy::Strict,
            Some(&kh),
            &as_pk(&ed_key),
        )
        .unwrap();

        // Same-algorithm MITM rejected.
        let same_algo_err = verify_and_maybe_learn(
            "example.internal",
            2222,
            HostKeyPolicy::AcceptNew,
            Some(&kh),
            &as_pk(&alt_ed_key),
        )
        .unwrap_err();
        assert!(matches!(same_algo_err, KnownHostsError::Mismatch(_)));

        // Cross-algorithm MITM (ECDSA presented when Ed25519 recorded) MUST be rejected even under AcceptNew!
        let cross_algo_err = verify_and_maybe_learn(
            "example.internal",
            2222,
            HostKeyPolicy::AcceptNew,
            Some(&kh),
            &as_pk(&ecdsa_key),
        )
        .unwrap_err();
        assert!(matches!(cross_algo_err, KnownHostsError::Mismatch(_)));
    }

    #[test]
    fn accept_new_concurrent_tofu_writes_single_entry() {
        let tmp = TempDir::new().unwrap();
        let kh = Arc::new(tmp.path().join("known_hosts"));
        let key = Arc::new(ed25519_pub(7));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let kh = Arc::clone(&kh);
            let key = Arc::clone(&key);
            handles.push(std::thread::spawn(move || {
                verify_and_maybe_learn(
                    "race.example.com",
                    22,
                    HostKeyPolicy::AcceptNew,
                    Some(&kh),
                    &as_pk(&key),
                )
                .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let raw_kh = fs::read_to_string(&*kh).unwrap();
        let lines: Vec<_> = raw_kh.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "expected exactly 1 line, got: {lines:?}");
    }

    #[test]
    fn fail_closed_on_directory_or_malformed_known_hosts() {
        let tmp = TempDir::new().unwrap();
        let dir_as_kh = tmp.path().join("kh_dir");
        fs::create_dir(&dir_as_kh).unwrap();

        let key = ed25519_pub(3);
        let err = verify_and_maybe_learn(
            "host.test",
            22,
            HostKeyPolicy::AcceptNew,
            Some(&dir_as_kh),
            &as_pk(&key),
        )
        .unwrap_err();
        assert!(matches!(err, KnownHostsError::Invalid(_)));

        let malformed = tmp.path().join("malformed_kh");
        fs::write(&malformed, "@unknown-marker host.test ssh-ed25519 AAAA\n").unwrap();
        let err2 = verify_and_maybe_learn(
            "host.test",
            22,
            HostKeyPolicy::AcceptNew,
            Some(&malformed),
            &as_pk(&key),
        )
        .unwrap_err();
        assert!(matches!(err2, KnownHostsError::Invalid(_)));
        // Must NOT overwrite malformed known_hosts!
        assert_eq!(
            fs::read_to_string(&malformed).unwrap(),
            "@unknown-marker host.test ssh-ed25519 AAAA\n"
        );
    }

    #[test]
    fn supports_tabs_wildcards_negation_hashed_hosts_and_revoked() {
        let tmp = TempDir::new().unwrap();
        let kh = tmp.path().join("known_hosts");
        let k1 = ed25519_pub(11);
        let k2 = ed25519_pub(12);
        let k1_str = PublicKey::new(k1.key_data().clone(), "")
            .to_openssh()
            .unwrap();
        let k2_str = PublicKey::new(k2.key_data().clone(), "")
            .to_openssh()
            .unwrap();

        // Build |1| HMAC-SHA1 hashed entry for [hashed.example]:2200
        let salt = b"0123456789abcdef0123";
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, salt);
        let tag = hmac::sign(&hmac_key, b"[hashed.example]:2200");
        fn b64(bytes: &[u8]) -> String {
            const TBL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut s = String::new();
            for chunk in bytes.chunks(3) {
                let b0 = chunk[0];
                let b1 = *chunk.get(1).unwrap_or(&0);
                let b2 = *chunk.get(2).unwrap_or(&0);
                s.push(TBL[(b0 >> 2) as usize] as char);
                s.push(TBL[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
                s.push(if chunk.len() > 1 {
                    TBL[(((b1 & 0xf) << 2) | (b2 >> 6)) as usize] as char
                } else {
                    '='
                });
                s.push(if chunk.len() > 2 {
                    TBL[(b2 & 0x3f) as usize] as char
                } else {
                    '='
                });
            }
            s
        }
        let hashed_host = format!("|1|{}|{}", b64(salt), b64(tag.as_ref()));

        let body = format!(
            "# comment line\n\
             *.prod.example,!bastion.prod.example\t{k1_str}\t# prod wildcard\n\
             {hashed_host} {k1_str}\n\
             @revoked\trevoked.example\t{k2_str}\n\
             revoked.example\t{k2_str}\n"
        );
        fs::write(&kh, body).unwrap();

        // Wildcard matches web.prod.example (case-insensitive)
        verify_and_maybe_learn(
            "WEB.PROD.EXAMPLE",
            22,
            HostKeyPolicy::Strict,
            Some(&kh),
            &as_pk(&k1),
        )
        .unwrap();

        // Negation excludes bastion.prod.example
        let neg_err = verify_and_maybe_learn(
            "bastion.prod.example",
            22,
            HostKeyPolicy::Strict,
            Some(&kh),
            &as_pk(&k1),
        )
        .unwrap_err();
        assert!(matches!(neg_err, KnownHostsError::Unknown(_)));

        // Hashed [hashed.example]:2200 matches
        verify_and_maybe_learn(
            "hashed.example",
            2200,
            HostKeyPolicy::Strict,
            Some(&kh),
            &as_pk(&k1),
        )
        .unwrap();

        // @revoked beats matching plain line and AcceptNew
        let rev_err = verify_and_maybe_learn(
            "revoked.example",
            22,
            HostKeyPolicy::AcceptNew,
            Some(&kh),
            &as_pk(&k2),
        )
        .unwrap_err();
        assert!(matches!(rev_err, KnownHostsError::Revoked(_)));
    }

    #[test]
    fn validates_cert_authority_and_rejects_bad_principal_or_untrusted_ca() {
        let tmp = TempDir::new().unwrap();
        let kh = tmp.path().join("known_hosts");
        let ca = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[21u8; 32])),
            "ca",
        )
        .unwrap();
        let other_ca = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[22u8; 32])),
            "other-ca",
        )
        .unwrap();
        let host_priv = PrivateKey::new(
            KeypairData::Ed25519(Ed25519Keypair::from_seed(&[23u8; 32])),
            "host",
        )
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let mut builder = CertBuilder::new_with_random_nonce(
            &mut rng,
            host_priv.public_key(),
            now - 60,
            now + 3600,
        )
        .unwrap();
        builder.cert_type(CertType::Host).unwrap();
        builder.valid_principal("srv.example").unwrap();
        let cert = builder.sign(&ca).unwrap();

        let mut bad_ca_builder = CertBuilder::new_with_random_nonce(
            &mut rng,
            host_priv.public_key(),
            now - 60,
            now + 3600,
        )
        .unwrap();
        bad_ca_builder.cert_type(CertType::Host).unwrap();
        bad_ca_builder.valid_principal("srv.example").unwrap();
        let forged_cert = bad_ca_builder.sign(&other_ca).unwrap();

        let ca_pub = PublicKey::new(ca.public_key().key_data().clone(), "")
            .to_openssh()
            .unwrap();
        fs::write(&kh, format!("@cert-authority *.example {ca_pub}\n")).unwrap();

        // Valid cert + matching principal accepted
        verify_and_maybe_learn(
            "srv.example",
            22,
            HostKeyPolicy::Strict,
            Some(&kh),
            &PublicKeyOrCertificate::Certificate(cert.clone()),
        )
        .unwrap();

        // Wrong principal rejected
        let wrong_principal = verify_and_maybe_learn(
            "other.example",
            22,
            HostKeyPolicy::Strict,
            Some(&kh),
            &PublicKeyOrCertificate::Certificate(cert),
        )
        .unwrap_err();
        assert!(matches!(wrong_principal, KnownHostsError::Mismatch(_)));

        // Untrusted CA rejected
        let forged_err = verify_and_maybe_learn(
            "srv.example",
            22,
            HostKeyPolicy::Strict,
            Some(&kh),
            &PublicKeyOrCertificate::Certificate(forged_cert),
        )
        .unwrap_err();
        assert!(matches!(forged_err, KnownHostsError::Mismatch(_)));
    }
}
