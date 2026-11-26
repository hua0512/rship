//! CLI filter argument parsing, profile layering, and raw prefix path helpers.

use anyhow::{Context, Result};
use rship::config::TransferProfile;
use rship_core::filter::{
    FilterOptions, parse_duration_nanos, parse_exclude_lines, parse_files_from, parse_filter_rules,
};
use rship_core::path::RelPath;

use crate::cli::{FilterArgs, parse_byte_size};

/// Build [`FilterOptions`] by layering explicit CLI [`FilterArgs`] on top of an effective
/// [`TransferProfile`] (`[defaults]` + optional `--profile`).
///
/// - Unordered lists (`exclude`, `include`, `exclude_from`) append CLI onto profile entries.
/// - Ordered `--filter-from` files evaluate CLI rules before profile rules (first match wins).
/// - Scalar bounds (`min_size`, `max_size`, `min_age`, `max_age`) let explicit CLI flags win.
pub fn build_filter_options_with_profile(
    args: &FilterArgs,
    profile: &TransferProfile,
) -> Result<FilterOptions> {
    let mut includes = profile.include.clone();
    for pat in &args.include {
        if !includes.contains(pat) {
            includes.push(pat.clone());
        }
    }

    let mut excludes = profile.exclude.clone();
    for pat in &args.exclude {
        if !excludes.contains(pat) {
            excludes.push(pat.clone());
        }
    }
    for path in profile.exclude_from.iter().chain(args.exclude_from.iter()) {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read --exclude-from `{}`", path.display()))?;
        excludes.extend(parse_exclude_lines(&text));
    }

    let mut rules = Vec::new();
    // CLI `--filter-from` takes precedence over profile/default `filter_from` (first match wins).
    for path in args.filter_from.iter().chain(profile.filter_from.iter()) {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read --filter-from `{}`", path.display()))?;
        rules.extend(
            parse_filter_rules(&text)
                .with_context(|| format!("invalid rules in --filter-from `{}`", path.display()))?,
        );
    }

    let files_from_path = args.files_from.as_ref().map(|p| {
        std::fs::canonicalize(p)
            .unwrap_or_else(|_| p.clone())
            .to_string_lossy()
            .into_owned()
    });
    let files_from = if let Some(path) = &args.files_from {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read --files-from `{}`", path.display()))?;
        Some(parse_files_from(&text))
    } else {
        None
    };

    let min_size = args
        .min_size
        .as_deref()
        .or(profile.min_size.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let max_size = args
        .max_size
        .as_deref()
        .or(profile.max_size.as_deref())
        .map(parse_byte_size)
        .transpose()?;
    let min_age_ns = args
        .min_age
        .as_deref()
        .or(profile.min_age.as_deref())
        .map(parse_duration_nanos)
        .transpose()?;
    let max_age_ns = args
        .max_age
        .as_deref()
        .or(profile.max_age.as_deref())
        .map(parse_duration_nanos)
        .transpose()?;

    Ok(FilterOptions {
        includes,
        excludes,
        rules,
        files_from,
        files_from_path,
        min_size,
        max_size,
        min_age_ns,
        max_age_ns,
    })
}

pub fn join_raw_prefix(prefix: &RelPath, raw: &str) -> String {
    if prefix.is_root() {
        raw.to_string()
    } else if raw.is_empty() {
        prefix.as_str().to_string()
    } else {
        format!("{}/{}", prefix.as_str(), raw)
    }
}

pub fn strip_prefix_raw(raw: &str, prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return Some(raw.to_string());
    }
    if raw == prefix {
        return Some(String::new());
    }
    raw.strip_prefix(prefix)?
        .strip_prefix('/')
        .map(str::to_string)
}
