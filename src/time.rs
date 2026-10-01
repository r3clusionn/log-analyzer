//! Timestamp parsing and formatting without a date library. All times are UTC milliseconds
//! since the Unix epoch.

/// Days from 1970-01-01 to the given civil date (proleptic Gregorian). Howard Hinnant's algorithm.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - (m <= 2) as i64;
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`].
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + (m <= 2) as i64;
    (y, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}

fn num(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    b.iter().try_fold(0u32, |a, d| a.checked_mul(10)?.checked_add((d - b'0') as u32))
}

#[allow(clippy::too_many_arguments)]
fn to_ms(y: i64, mo: u32, d: u32, h: u32, mi: u32, s: u32, ms: u32, offset_min: i32) -> Option<i64> {
    if !(1..=12).contains(&mo) || d == 0 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    let secs = days * 86_400 + h as i64 * 3600 + mi as i64 * 60 + s as i64 - offset_min as i64 * 60;
    Some(secs * 1000 + ms as i64)
}

/// Parses `±hhmm`, `±hh:mm`, `±hh` or `Z`. Returns (offset in minutes, bytes consumed).
fn zone(b: &[u8]) -> Option<(i32, usize)> {
    match b.first()? {
        b'Z' | b'z' => Some((0, 1)),
        &sign @ (b'+' | b'-') => {
            let (hh, mm, used) = if b.get(3) == Some(&b':') {
                (num(b.get(1..3)?)?, num(b.get(4..6)?)?, 6)
            } else if b.len() >= 5 && num(&b[3..5]).is_some() {
                (num(&b[1..3])?, num(&b[3..5])?, 5)
            } else {
                (num(b.get(1..3)?)?, 0, 3)
            };
            if hh > 14 || mm > 59 {
                return None;
            }
            let off = (hh * 60 + mm) as i32;
            Some((if sign == b'-' { -off } else { off }, used))
        }
        _ => None,
    }
}

/// Common Log Format time: `10/Oct/2023:13:55:36 +0000`.
pub fn parse_clf(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[2] != b'/' || b[6] != b'/' || b[11] != b':' || b[14] != b':' || b[17] != b':' {
        return None;
    }
    const MONTHS: [&[u8]; 12] =
        [b"jan", b"feb", b"mar", b"apr", b"may", b"jun", b"jul", b"aug", b"sep", b"oct", b"nov", b"dec"];
    let mon = b[3..6].to_ascii_lowercase();
    let mo = MONTHS.iter().position(|m| *m == mon.as_slice())? as u32 + 1;
    let off = if b.len() > 21 && b[20] == b' ' { zone(&b[21..])?.0 } else { 0 };
    to_ms(
        num(&b[7..11])? as i64,
        mo,
        num(&b[0..2])?,
        num(&b[12..14])?,
        num(&b[15..17])?,
        num(&b[18..20])?,
        0,
        off,
    )
}

/// ISO 8601 / RFC 3339 prefix: `2026-10-01T12:00:00.123Z`, `2026-10-01 12:00:00,123` and similar.
/// No zone means UTC. Returns the time and the number of bytes consumed.
pub fn parse_iso(s: &str) -> Option<(i64, usize)> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let mut used = 19;
    let mut ms = 0;
    if matches!(b.get(used), Some(b'.' | b',')) {
        let digits = b[used + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            return None;
        }
        let frac = &b[used + 1..used + 1 + digits.min(3)];
        ms = num(frac)? * 10u32.pow(3 - frac.len() as u32);
        used += 1 + digits;
    }
    let off = match zone(&b[used.min(b.len())..]) {
        Some((o, n)) => {
            used += n;
            o
        }
        None => 0,
    };
    let t = to_ms(
        num(&b[0..4])? as i64,
        num(&b[5..7])?,
        num(&b[8..10])?,
        num(&b[11..13])?,
        num(&b[14..16])?,
        num(&b[17..19])?,
        ms,
        off,
    )?;
    Some((t, used))
}

/// `2023-10-10 13:55:36` in UTC.
pub fn format_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let r = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", r / 3600, r % 3600 / 60, r % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_round_trip_across_centuries_and_leap_days() {
        for z in (-800_000..800_000).step_by(997) {
            let (y, m, d) = civil_from_days(z);
            assert_eq!(days_from_civil(y, m, d), z);
        }
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28), 2, "2000 is a leap year");
        assert_eq!(days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28), 1, "1900 is not");
    }

    #[test]
    fn clf_with_zones() {
        // 2023-10-10T13:55:36Z is 1696946136.
        assert_eq!(parse_clf("10/Oct/2023:13:55:36 +0000"), Some(1_696_946_136_000));
        assert_eq!(parse_clf("10/Oct/2023:13:55:36 +0200"), Some(1_696_946_136_000 - 7_200_000));
        assert_eq!(parse_clf("10/Oct/2023:13:55:36 -0330"), Some(1_696_946_136_000 + 12_600_000));
        assert_eq!(parse_clf("10/Oct/2023:13:55:36"), Some(1_696_946_136_000));
        for bad in ["", "10/Foo/2023:13:55:36 +0000", "32/Oct/2023:13:55:36 +0000", "10/Oct/2023:24:00:00 +0000", "garbage in here!!!!!!!"] {
            assert_eq!(parse_clf(bad), None, "{bad}");
        }
    }

    #[test]
    fn iso_variants() {
        assert_eq!(parse_iso("2023-10-10T13:55:36Z rest"), Some((1_696_946_136_000, 20)));
        assert_eq!(parse_iso("2023-10-10 13:55:36,123 [INFO]"), Some((1_696_946_136_123, 23)));
        assert_eq!(parse_iso("2023-10-10T13:55:36.5+02:00"), Some((1_696_946_136_500 - 7_200_000, 27)));
        assert_eq!(parse_iso("2023-10-10T13:55:36.123456Z").unwrap().0, 1_696_946_136_123);
        assert_eq!(parse_iso("2023-10-10T13:55:36 INFO").unwrap().1, 19);
        for bad in ["2023-13-10T00:00:00Z", "2023-02-30T00:00:00Z", "2023-10-10X13:55:36", "short", "2023-10-10T13:55:36."] {
            assert_eq!(parse_iso(bad), None, "{bad}");
        }
    }

    #[test]
    fn formatting() {
        assert_eq!(format_utc(1_696_946_136_000), "2023-10-10 13:55:36");
        assert_eq!(format_utc(0), "1970-01-01 00:00:00");
        assert_eq!(format_utc(-1000), "1969-12-31 23:59:59");
    }
}
