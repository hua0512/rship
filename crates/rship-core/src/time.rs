//! Wall-clock reads and wire-format timestamp formatting/parsing shared by every rship crate.
//!
//! Every formatter here is pinned byte-for-byte (see the golden tests) to what rship has always
//! sent on the wire or persisted: SigV4 `x-amz-date`, Azure `x-ms-date`, Graph/Drive/Dropbox
//! RFC 3339 bodies, and job-id stamps. Values cross this API as plain Unix integers so callers
//! need not depend on a date-time crate themselves; [`Timestamp`] is re-exported for the few
//! public signatures that take an instant.
//!
//! Parsers accept everything the previous `chrono` 0.4 based call sites accepted, with the same
//! results (including fractional digits past the ninth being ignored and a `:60` leap second
//! rolling the nanosecond value over into the next second), plus some extra ISO 8601 / RFC 2822
//! leniency inherited from `jiff`.

use std::borrow::Cow;
use std::fmt::Write as _;

use jiff::civil::{DateTime, Weekday};
use jiff::fmt::rfc2822;
use jiff::tz::{Offset, TimeZone};

pub use jiff::Timestamp;

const NANOS_PER_SEC: i64 = 1_000_000_000;

static RFC2822_PARSER: rfc2822::DateTimeParser = rfc2822::DateTimeParser::new();

/// Current wall-clock time as Unix seconds (floored).
pub fn now_unix_secs() -> i64 {
    floor_secs(Timestamp::now())
}

/// Current wall-clock time as Unix milliseconds (floored).
pub fn now_unix_ms() -> i64 {
    let ns = Timestamp::now().as_nanosecond();
    i64::try_from(ns.div_euclid(1_000_000)).unwrap_or(i64::MAX)
}

/// Current wall-clock time as Unix nanoseconds.
pub fn now_unix_nanos() -> i64 {
    i64::try_from(Timestamp::now().as_nanosecond()).unwrap_or(i64::MAX)
}

/// Minute of the current day (`0..1440`) in the system's local time zone.
///
/// The zone comes from `TZ` or the platform's configured zone (`/etc/localtime` on Unix, the
/// Windows time zone API on Windows) and falls back to UTC when it cannot be determined.
pub fn local_minute_of_day() -> u16 {
    let now = TimeZone::system().to_datetime(Timestamp::now());
    (i16::from(now.hour()) * 60 + i16::from(now.minute())) as u16
}

/// Unix seconds floored toward negative infinity (jiff's `as_second` truncates toward zero).
fn floor_secs(ts: Timestamp) -> i64 {
    let secs = ts.as_second();
    if ts.subsec_nanosecond() < 0 {
        secs - 1
    } else {
        secs
    }
}

/// Civil UTC datetime for `secs`, falling back to the current time when out of range.
fn utc_from_secs(secs: i64) -> DateTime {
    let ts = Timestamp::from_second(secs).unwrap_or_else(|_| Timestamp::now());
    Offset::UTC.to_datetime(ts)
}

/// Civil UTC datetime for `ns`; every `i64` nanosecond value is in range.
fn utc_from_nanos(ns: i64) -> DateTime {
    let ts = Timestamp::from_nanosecond(i128::from(ns)).unwrap_or_else(|_| Timestamp::now());
    Offset::UTC.to_datetime(ts)
}

/// Unix nanoseconds for `ts` plus one second when a `:60` leap second was clamped to `:59`.
fn leap_adjusted_nanos(ts: Timestamp, leap: bool) -> Option<i64> {
    let extra = if leap { i128::from(NANOS_PER_SEC) } else { 0 };
    i64::try_from(ts.as_nanosecond() + extra).ok()
}

/// Whether an RFC 3339 `HH:MM:SS` field (fixed offsets 11..19) holds a `60` leap second.
fn rfc3339_is_leap_second(raw: &str) -> bool {
    let b = raw.as_bytes();
    b.len() >= 19 && b[13] == b':' && b[16] == b':' && &b[17..19] == b"60"
}

/// Rewrite the RFC 3339 forms `chrono` accepted but `jiff` rejects: a U+2212 MINUS SIGN offset
/// and fractional seconds longer than nine digits (extra digits are dropped, not rounded).
fn normalize_rfc3339(raw: &str) -> Option<Cow<'_, str>> {
    let mut s = Cow::Borrowed(raw);
    if !raw.is_ascii() && raw.contains('\u{2212}') {
        s = Cow::Owned(raw.replace('\u{2212}', "-"));
    }
    let b = s.as_bytes();
    if b.get(19) == Some(&b'.') {
        let frac = b[20..].iter().take_while(|c| c.is_ascii_digit()).count();
        if frac > 9 {
            let mut owned = s.into_owned();
            owned.replace_range(29..20 + frac, "");
            s = Cow::Owned(owned);
        }
    }
    matches!(s, Cow::Owned(_)).then_some(s)
}

/// Parse RFC 3339, returning the instant (leap seconds clamped to `:59`) and a leap flag.
fn parse_rfc3339(raw: &str) -> Option<(Timestamp, bool)> {
    let ts = match raw.parse::<Timestamp>() {
        Ok(ts) => ts,
        Err(_) => normalize_rfc3339(raw)?.parse::<Timestamp>().ok()?,
    };
    Some((ts, rfc3339_is_leap_second(raw)))
}

/// Parse RFC 2822 / RFC 9110, returning the instant (leap seconds clamped) and a leap flag.
fn parse_http_date(raw: &str) -> Option<(Timestamp, bool)> {
    let ts = RFC2822_PARSER.parse_timestamp(raw).ok()?;
    // Comments are only allowed after the zone and numeric zones carry no `:`, so after a
    // successful parse the last `:` before any comment is the seconds separator (a `60`
    // after it cannot be a minute: the parser rejects minute 60).
    let body = raw.split('(').next().unwrap_or(raw);
    let leap = body.rfind(':').is_some_and(|i| {
        let rest = body[i + 1..].trim_start_matches(|c: char| c.is_ascii_whitespace());
        rest.as_bytes().starts_with(b"60")
            && !rest.as_bytes().get(2).is_some_and(u8::is_ascii_digit)
    });
    Some((ts, leap))
}

/// Parse an RFC 3339 timestamp (any offset, optional fractional seconds) into Unix nanoseconds.
///
/// Returns `None` when the input is malformed or outside the `i64` nanosecond range.
pub fn parse_rfc3339_to_nanos(raw: &str) -> Option<i64> {
    parse_rfc3339(raw).and_then(|(ts, leap)| leap_adjusted_nanos(ts, leap))
}

/// Parse an RFC 3339 timestamp into Unix seconds (floored toward negative infinity).
pub fn parse_rfc3339_to_secs(raw: &str) -> Option<i64> {
    parse_rfc3339(raw).map(|(ts, _)| floor_secs(ts))
}

/// Parse an RFC 2822 / RFC 9110 IMF-fixdate HTTP date (`Sun, 06 Nov 1994 08:49:37 GMT`,
/// numeric or obsolete zones) into Unix nanoseconds.
pub fn parse_http_date_to_nanos(raw: &str) -> Option<i64> {
    parse_http_date(raw).and_then(|(ts, leap)| leap_adjusted_nanos(ts, leap))
}

/// Parse an RFC 2822 / RFC 9110 HTTP date into Unix seconds.
pub fn parse_http_date_to_secs(raw: &str) -> Option<i64> {
    parse_http_date(raw).map(|(ts, _)| floor_secs(ts))
}

fn weekday_abbrev(wd: Weekday) -> &'static str {
    match wd {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    }
}

fn month_abbrev(month: i8) -> &'static str {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MONTHS[(month - 1) as usize]
}

/// `%Y`: four zero-padded digits, or a sign plus at least four digits outside `0..=9999`.
fn push_year(out: &mut String, year: i16) {
    let _ = if (0..=9999).contains(&year) {
        write!(out, "{year:04}")
    } else {
        write!(out, "{year:+05}")
    };
}

/// `YYYY-MM-DDTHH:MM:SS` (RFC 3339 extended date and time, no fraction or offset).
fn push_rfc3339_base(out: &mut String, dt: DateTime) {
    push_year(out, dt.year());
    let _ = write!(
        out,
        "-{:02}-{:02}T{:02}:{:02}:{:02}",
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second()
    );
}

/// `YYYYMMDDTHHMMSS` when `t_sep`, else `YYYYMMDDHHMMSS` (ISO 8601 basic).
fn push_basic(out: &mut String, dt: DateTime, t_sep: bool) {
    push_year(out, dt.year());
    let _ = write!(out, "{:02}{:02}", dt.month(), dt.day());
    if t_sep {
        out.push('T');
    }
    let _ = write!(out, "{:02}{:02}{:02}", dt.hour(), dt.minute(), dt.second());
}

/// Format Unix seconds as an RFC 9110 IMF-fixdate: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn format_http_date(unix_secs: i64) -> String {
    let dt = utc_from_secs(unix_secs);
    let mut out = String::with_capacity(29);
    let _ = write!(
        out,
        "{}, {:02} {} ",
        weekday_abbrev(dt.weekday()),
        dt.day(),
        month_abbrev(dt.month())
    );
    push_year(&mut out, dt.year());
    let _ = write!(
        out,
        " {:02}:{:02}:{:02} GMT",
        dt.hour(),
        dt.minute(),
        dt.second()
    );
    out
}

/// Format Unix seconds as ISO 8601 basic UTC (`20130524T000000Z`, SigV4 `x-amz-date`).
pub fn format_iso8601_basic(unix_secs: i64) -> String {
    let mut out = String::with_capacity(16);
    push_basic(&mut out, utc_from_secs(unix_secs), true);
    out.push('Z');
    out
}

/// Format Unix seconds as a compact UTC stamp (`20250116040000`) for job and run ids.
pub fn format_compact_utc(unix_secs: i64) -> String {
    let mut out = String::with_capacity(14);
    push_basic(&mut out, utc_from_secs(unix_secs), false);
    out
}

/// Format Unix seconds as RFC 3339 UTC with whole seconds: `2025-01-16T04:00:00Z`.
pub fn format_rfc3339_secs(unix_secs: i64) -> String {
    let mut out = String::with_capacity(20);
    push_rfc3339_base(&mut out, utc_from_secs(unix_secs));
    out.push('Z');
    out
}

/// Format Unix nanoseconds as RFC 3339 UTC with exactly three fractional digits (truncated):
/// `2025-01-16T04:00:00.123Z`.
pub fn format_rfc3339_millis(unix_nanos: i64) -> String {
    let dt = utc_from_nanos(unix_nanos);
    let mut out = String::with_capacity(24);
    push_rfc3339_base(&mut out, dt);
    let _ = write!(out, ".{:03}Z", dt.subsec_nanosecond() / 1_000_000);
    out
}

/// Format Unix nanoseconds as RFC 3339 with a `+00:00` offset and 0, 3, 6 or 9 fractional
/// digits, whichever is the shortest exact form: `2025-01-16T04:00:00.123456+00:00`.
pub fn format_rfc3339(unix_nanos: i64) -> String {
    let dt = utc_from_nanos(unix_nanos);
    let mut out = String::with_capacity(35);
    push_rfc3339_base(&mut out, dt);
    let nanos = dt.subsec_nanosecond();
    let _ = if nanos == 0 {
        Ok(())
    } else if nanos % 1_000_000 == 0 {
        write!(out, ".{:03}", nanos / 1_000_000)
    } else if nanos % 1_000 == 0 {
        write!(out, ".{:06}", nanos / 1_000)
    } else {
        write!(out, ".{nanos:09}")
    };
    out.push_str("+00:00");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden values below were produced by the original `chrono` 0.4 call sites and must never
    // change: they are what remote APIs receive and what persisted state contains.

    #[test]
    fn golden_http_date_imf_fixdate() {
        let cases = [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (-1, "Wed, 31 Dec 1969 23:59:59 GMT"),
            (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (1_737_000_000, "Thu, 16 Jan 2025 04:00:00 GMT"),
            (1_795_640_709, "Wed, 25 Nov 2026 21:05:09 GMT"),
            (1_795_744_800, "Fri, 27 Nov 2026 02:00:00 GMT"),
        ];
        for (secs, want) in cases {
            assert_eq!(format_http_date(secs), want, "secs={secs}");
            assert_eq!(parse_http_date_to_secs(want), Some(secs), "{want}");
        }
    }

    #[test]
    fn golden_iso8601_basic_and_compact() {
        let cases = [
            (0, "19700101T000000Z", "19700101000000"),
            (-1, "19691231T235959Z", "19691231235959"),
            (951_782_400, "20000229T000000Z", "20000229000000"),
            (1_369_353_600, "20130524T000000Z", "20130524000000"),
            (1_737_000_000, "20250116T040000Z", "20250116040000"),
            (1_795_640_709, "20261125T210509Z", "20261125210509"),
        ];
        for (secs, basic, compact) in cases {
            assert_eq!(format_iso8601_basic(secs), basic, "secs={secs}");
            assert_eq!(format_compact_utc(secs), compact, "secs={secs}");
        }
    }

    #[test]
    fn golden_rfc3339_secs_z() {
        assert_eq!(format_rfc3339_secs(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339_secs(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_rfc3339_secs(1_737_000_000), "2025-01-16T04:00:00Z");
        assert_eq!(format_rfc3339_secs(1_795_640_709), "2026-11-25T21:05:09Z");
    }

    #[test]
    fn golden_rfc3339_millis_and_auto_precision() {
        let cases = [
            (0, "1970-01-01T00:00:00.000Z", "1970-01-01T00:00:00+00:00"),
            (
                1_737_000_000_000_000_000,
                "2025-01-16T04:00:00.000Z",
                "2025-01-16T04:00:00+00:00",
            ),
            (
                1_737_000_000_123_000_000,
                "2025-01-16T04:00:00.123Z",
                "2025-01-16T04:00:00.123+00:00",
            ),
            (
                1_737_000_000_120_000_000,
                "2025-01-16T04:00:00.120Z",
                "2025-01-16T04:00:00.120+00:00",
            ),
            (
                1_737_000_000_123_456_000,
                "2025-01-16T04:00:00.123Z",
                "2025-01-16T04:00:00.123456+00:00",
            ),
            (
                1_737_000_000_123_400_000,
                "2025-01-16T04:00:00.123Z",
                "2025-01-16T04:00:00.123400+00:00",
            ),
            (
                1_737_000_000_123_456_789,
                "2025-01-16T04:00:00.123Z",
                "2025-01-16T04:00:00.123456789+00:00",
            ),
            (
                1_737_000_000_000_000_001,
                "2025-01-16T04:00:00.000Z",
                "2025-01-16T04:00:00.000000001+00:00",
            ),
            (
                1_737_000_000_999_999_999,
                "2025-01-16T04:00:00.999Z",
                "2025-01-16T04:00:00.999999999+00:00",
            ),
            (
                -1,
                "1969-12-31T23:59:59.999Z",
                "1969-12-31T23:59:59.999999999+00:00",
            ),
            (
                -1_500_000_000,
                "1969-12-31T23:59:58.500Z",
                "1969-12-31T23:59:58.500+00:00",
            ),
            (
                951_782_400_999_999_999,
                "2000-02-29T00:00:00.999Z",
                "2000-02-29T00:00:00.999999999+00:00",
            ),
        ];
        for (ns, millis, auto) in cases {
            assert_eq!(format_rfc3339_millis(ns), millis, "ns={ns}");
            assert_eq!(format_rfc3339(ns), auto, "ns={ns}");
            assert_eq!(parse_rfc3339_to_nanos(auto), Some(ns), "{auto}");
        }
    }

    #[test]
    fn golden_rfc3339_parse_accepts_every_chrono_form() {
        let base = 1_736_944_496_000_000_000_i64; // 2025-01-15T12:34:56Z
        let cases = [
            ("1970-01-01T00:00:00Z", 0),
            ("2025-01-15T12:34:56Z", base),
            ("2025-01-15T12:34:56.000Z", base),
            ("2025-01-15T12:34:56.1Z", base + 100_000_000),
            ("2025-01-15T12:34:56.123456Z", base + 123_456_000),
            // Azure emits 7 fractional digits.
            ("2025-01-15T12:34:56.1234567Z", base + 123_456_700),
            ("2025-01-15T12:34:56.123456789Z", base + 123_456_789),
            // Digits past the ninth are ignored.
            ("2025-01-15T12:34:56.1234567891234Z", base + 123_456_789),
            ("2025-01-15t12:34:56z", base),
            ("2025-01-15 12:34:56Z", base),
            ("2025-01-15T12:34:56+00:00", base),
            ("2025-01-15T12:34:56-00:00", base),
            ("2025-01-15T14:34:56.5+02:00", base + 500_000_000),
            ("2025-01-15T07:04:56-05:30", base),
            ("2025-01-15T12:34:56\u{2212}00:00", base),
            ("2025-01-15T07:34:56\u{2212}05:00", base),
            ("1969-12-31T23:59:59.5Z", -500_000_000),
        ];
        for (raw, want) in cases {
            assert_eq!(parse_rfc3339_to_nanos(raw), Some(want), "{raw}");
            assert_eq!(
                parse_rfc3339_to_secs(raw),
                Some(want.div_euclid(NANOS_PER_SEC)),
                "{raw}"
            );
        }
    }

    #[test]
    fn golden_leap_second_nanos_roll_over_but_secs_stay_on_59() {
        // chrono's representation: `:60` is second 59 plus 1e9 nanoseconds.
        assert_eq!(
            parse_rfc3339_to_nanos("2016-12-31T23:59:60Z"),
            Some(1_483_228_800_000_000_000)
        );
        assert_eq!(
            parse_rfc3339_to_nanos("2016-12-31T23:59:60.5Z"),
            Some(1_483_228_800_500_000_000)
        );
        assert_eq!(
            parse_rfc3339_to_secs("2016-12-31T23:59:60.5Z"),
            Some(1_483_228_799)
        );
        assert_eq!(
            parse_http_date_to_nanos("Sat, 31 Dec 2016 23:59:60 GMT"),
            Some(1_483_228_800_000_000_000)
        );
        assert_eq!(
            parse_http_date_to_secs("Sat, 31 Dec 2016 23:59:60 GMT"),
            Some(1_483_228_799)
        );
    }

    #[test]
    fn golden_rfc3339_secs_floor_and_range() {
        // rclone writes Go's zero time for tokens without expiry.
        assert_eq!(
            parse_rfc3339_to_secs("0001-01-01T00:00:00Z"),
            Some(-62_135_596_800)
        );
        assert_eq!(parse_rfc3339_to_nanos("0001-01-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_to_secs("1969-12-31T23:59:59.5Z"), Some(-1));
        assert_eq!(
            parse_rfc3339_to_secs("2024-03-01T10:20:30.123456789+08:00"),
            Some(1_709_259_630)
        );
    }

    #[test]
    fn rfc3339_parse_rejects_missing_offset_and_garbage() {
        for bad in [
            "",
            "2025-01-15T12:34:56",
            "2025-01-15T12:34:56Z ",
            "2025-01-15T12:34:56.Z",
            "2025-02-30T00:00:00Z",
            "Wed, 25 Nov 2026 21:05:09 GMT",
            "not a date",
        ] {
            assert_eq!(parse_rfc3339_to_nanos(bad), None, "{bad:?}");
            assert_eq!(parse_rfc3339_to_secs(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn golden_http_date_parse_accepts_every_chrono_form() {
        let rfc1123 = 784_111_777_000_000_000_i64; // Sun, 06 Nov 1994 08:49:37 GMT
        let cases = [
            ("Wed, 25 Nov 2026 21:05:09 GMT", 1_795_640_709_000_000_000),
            ("Wed, 25 Nov 2026 21:05:09 +0000", 1_795_640_709_000_000_000),
            ("Wed, 25 Nov 2026 23:05:09 +0200", 1_795_640_709_000_000_000),
            ("wed, 25 nov 2026 21:05:09 gmt", 1_795_640_709_000_000_000),
            ("25 Nov 2026 21:05:09 GMT", 1_795_640_709_000_000_000),
            ("Sun, 6 Nov 1994 08:49:37 GMT", rfc1123),
            ("Sun, 06 Nov 1994 08:49:37 UT", rfc1123),
            ("Sun, 06 Nov 94 08:49:37 GMT", rfc1123),
            ("Sun, 06 Nov 1994 08:49 GMT", rfc1123 - 37_000_000_000),
            ("Sun, 06 Nov 1994 03:49:37 EST", rfc1123),
            ("Sun, 06 Nov 1994 04:49:37 EDT", rfc1123),
            ("Sun, 06 Nov 1994 00:49:37 PST", rfc1123),
            ("Sun, 06 Nov 1994 08:49:37 Z", rfc1123),
            ("Sun, 06 Nov 1994 08:49:37 A", rfc1123),
            ("  Sun, 06 Nov 1994 08:49:37 GMT", rfc1123),
            ("Sun, 06 Nov 1994 08:49:37 GMT (comment)", rfc1123),
            ("Sun,06 Nov 1994 08:49:37 GMT", rfc1123),
        ];
        for (raw, want) in cases {
            assert_eq!(parse_http_date_to_nanos(raw), Some(want), "{raw}");
            assert_eq!(
                parse_http_date_to_secs(raw),
                Some(want.div_euclid(NANOS_PER_SEC)),
                "{raw}"
            );
        }
    }

    #[test]
    fn http_date_parse_rejects_wrong_weekday_and_other_layouts() {
        for bad in [
            "",
            "Mon, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            "2026-11-25T21:05:09Z",
            "1795640709",
        ] {
            assert_eq!(parse_http_date_to_nanos(bad), None, "{bad:?}");
            assert_eq!(parse_http_date_to_secs(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn wall_clock_reads_are_consistent() {
        let secs = now_unix_secs();
        let ms = now_unix_ms();
        let ns = now_unix_nanos();
        assert!(secs > 1_700_000_000);
        assert!((ms / 1_000 - secs).abs() <= 1);
        assert!((ns / NANOS_PER_SEC - secs).abs() <= 1);
        assert!(local_minute_of_day() < 1_440);
    }
}
