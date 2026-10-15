//! Small helpers shared across the crate: time, randomness, encoding.

use base64::Engine;
use rand::RngCore;
use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds.
pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Lower-case hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// `n` random bytes from the OS CSPRNG, hex encoded (so `2n` characters).
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    hex(&buf)
}

/// A random 64-bit value.
pub fn random_u64() -> u64 {
    rand::thread_rng().next_u64()
}

/// Base64url without padding (RFC 7515 §2).
pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Constant-time string comparison. Different lengths compare unequal
/// without leaking which byte differed.
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Parse the boolean spellings people put in environment variables.
pub fn parse_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" | "t" | "y" => Ok(true),
        "0" | "false" | "no" | "off" | "f" | "n" | "" => Ok(false),
        other => Err(format!("invalid boolean {other:?} (use true/false or 1/0)")),
    }
}

/// Split a comma separated list, trimming whitespace and dropping empties.
pub fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// Format a unix timestamp as RFC 3339 UTC (`2006-01-02T15:04:05Z`), the
/// shape Go's `time.Time` JSON encoding produces for whole seconds.
pub fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Parse the subset of RFC 3339 we emit (and Go emits) back to unix seconds.
/// Fractional seconds and offsets are tolerated; the offset is applied.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.len() < 20 {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let mo: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    let h: i64 = s.get(11..13)?.parse().ok()?;
    let mi: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let mut rest = s.get(19..)?;
    if let Some(frac) = rest.strip_prefix('.') {
        let end = frac
            .find(|c: char| !c.is_ascii_digit())
            .map(|i| i + 1)
            .unwrap_or(rest.len());
        rest = rest.get(end..)?;
    }
    let offset = match rest {
        "Z" | "z" | "" => 0,
        _ => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = rest.get(4..6)?.parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    let days = days_from_civil(y, mo, d);
    Some(days * 86_400 + h * 3600 + mi * 60 + sec - offset)
}

// Date algorithms from Howard Hinnant's "chrono-compatible low-level date
// algorithms"; proleptic Gregorian, valid for the whole i64 range we care about.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Strip a trailing dot from a DNS name (`idp.tn.ts.net.` -> `idp.tn.ts.net`).
pub fn trim_fqdn(name: &str) -> &str {
    name.strip_suffix('.').unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_roundtrip() {
        for ts in [0i64, 951_782_400, 1_700_000_000, 4_102_444_800, -86_400] {
            let s = rfc3339(ts);
            assert_eq!(parse_rfc3339(&s), Some(ts), "{s}");
        }
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(
            parse_rfc3339("2026-10-14T12:34:56.123456789-07:00"),
            parse_rfc3339("2026-10-14T19:34:56Z")
        );
        assert_eq!(parse_rfc3339("0001-01-01T00:00:00Z"), Some(-62_135_596_800));
        // malformed input must not panic (multi-byte char across the slice boundary)
        assert_eq!(parse_rfc3339("2026-10-14T12:34:56é"), None);
        assert_eq!(parse_rfc3339("2026-10-14T12:34:56.é"), None);
    }

    #[test]
    fn bool_parsing() {
        assert_eq!(parse_bool("1"), Ok(true));
        assert_eq!(parse_bool("TRUE"), Ok(true));
        assert_eq!(parse_bool("0"), Ok(false));
        assert_eq!(parse_bool(""), Ok(false));
        assert!(parse_bool("maybe").is_err());
    }

    #[test]
    fn ct_eq_lengths() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "abcd"));
    }

    #[test]
    fn random_hex_len() {
        assert_eq!(random_hex(16).len(), 32);
        assert_ne!(random_hex(16), random_hex(16));
    }
}
