//! Line parsers for two families of log: web access logs (Apache and nginx combined/common, with
//! an optional trailing response time) and application logs that start with a timestamp and carry
//! a level word.

use crate::time::{parse_clf, parse_iso};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Access,
    App,
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Multiplier that turns a trailing numeric field into seconds: 1 for nginx `$request_time`,
    /// 0.001 for milliseconds, 1e-6 for Apache `%D`.
    pub latency_scale: f64,
}

impl Default for Options {
    fn default() -> Self {
        Options { latency_scale: 1.0 }
    }
}

#[derive(Debug, PartialEq)]
pub struct Access<'a> {
    pub ts_ms: i64,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes: u64,
    pub latency_s: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl Level {
    pub const ALL: [Level; 6] = [Level::Trace, Level::Debug, Level::Info, Level::Warn, Level::Error, Level::Fatal];

    pub fn name(self) -> &'static str {
        ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"][self as usize]
    }

    fn from_word(w: &str) -> Option<Level> {
        Some(match w.to_ascii_uppercase().as_str() {
            "TRACE" | "TRC" | "VERBOSE" => Level::Trace,
            "DEBUG" | "DBG" => Level::Debug,
            "INFO" | "INF" | "NOTICE" => Level::Info,
            "WARN" | "WARNING" | "WRN" => Level::Warn,
            "ERROR" | "ERR" | "SEVERE" => Level::Error,
            "FATAL" | "CRITICAL" | "CRIT" | "PANIC" => Level::Fatal,
            _ => return None,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct App<'a> {
    pub ts_ms: i64,
    pub level: Level,
    pub message: &'a str,
    pub latency_s: Option<f64>,
}

/// Parses a combined or common log line. Returns `None` for anything else.
pub fn parse_access<'a>(line: &'a str, opts: &Options) -> Option<Access<'a>> {
    let open = line.find('[')?;
    let close = open + line[open..].find(']')?;
    let ts_ms = parse_clf(&line[open + 1..close])?;
    let rest = line[close + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let q_end = rest.find('"')?;
    let request = &rest[..q_end];
    let mut parts = request.split(' ');
    let (method, path) = match (parts.next(), parts.next()) {
        (Some(m), Some(p)) => (m, p),
        // A request that never completed, for example a 408: `"-"`.
        (Some(m), None) => (m, ""),
        _ => ("-", ""),
    };
    let after = rest[q_end + 1..].trim_start();
    let mut fields = after.split_ascii_whitespace();
    let status: u16 = fields.next()?.parse().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let bytes = match fields.next()? {
        "-" => 0,
        b => b.parse().ok()?,
    };
    Some(Access { ts_ms, method, path, status, bytes, latency_s: trailing_latency(after, opts) })
}

/// Response time from `rt=`/`request_time=` keys, or a bare number as the last field.
fn trailing_latency(after_status: &str, opts: &Options) -> Option<f64> {
    for key in ["request_time=", "rt=", "$request_time="] {
        if let Some(i) = after_status.find(key) {
            let v: String = after_status[i + key.len()..]
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            return v.parse::<f64>().ok().map(|x| x * opts.latency_scale).filter(|x| x.is_finite());
        }
    }
    // Only after the closing quote of the user agent: the last field must be a bare number.
    let last = after_status.rsplit(' ').next()?;
    let tail_is_number = !last.is_empty()
        && last.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && last.bytes().any(|b| b.is_ascii_digit());
    if tail_is_number && after_status.contains('"') {
        return last.parse::<f64>().ok().map(|x| x * opts.latency_scale);
    }
    None
}

/// Parses `TIMESTAMP LEVEL message` with the level optionally bracketed or preceded by a
/// bracketed thread name.
pub fn parse_app<'a>(line: &'a str) -> Option<App<'a>> {
    let (ts_ms, used) = parse_iso(line)?;
    let mut rest = line[used..].trim_start();
    // Look at up to three leading tokens for the level word.
    for _ in 0..3 {
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let token = rest[..end].trim_matches(|c| matches!(c, '[' | ']' | ':' | '|' | '<' | '>'));
        if let Some(level) = Level::from_word(token) {
            let message = rest[end..].trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '-' || c == ']');
            return Some(App { ts_ms, level, message, latency_s: message_latency(message) });
        }
        rest = rest[end..].trim_start();
        if rest.is_empty() {
            break;
        }
    }
    None
}

/// First `123ms` / `1.5 ms` / `2.5s` style duration in a message, in seconds.
fn message_latency(msg: &str) -> Option<f64> {
    let b = msg.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'.')) {
            let start = i;
            while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                i += 1;
            }
            let value: f64 = msg[start..i].parse().ok()?;
            let unit = msg[i..].trim_start_matches(' ');
            let (scale, len) = if unit.starts_with("ms") {
                (0.001, 2)
            } else if unit.starts_with('s') && !unit[1..].starts_with(|c: char| c.is_ascii_alphabetic()) {
                (1.0, 1)
            } else {
                (0.0, 0)
            };
            if len > 0 && !unit[len..].starts_with(|c: char| c.is_ascii_alphabetic()) {
                return Some(value * scale);
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Picks a format from the first line that parses as one.
pub fn detect(sample: &str, opts: &Options) -> Option<Format> {
    for line in sample.lines().filter(|l| !l.trim().is_empty()).take(50) {
        if parse_access(line, opts).is_some() {
            return Some(Format::Access);
        }
        if parse_app(line).is_some() {
            return Some(Format::App);
        }
    }
    None
}

/// Collapses ids so that `/users/42` and `/users/97` count as one route.
pub fn normalize_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or("");
    if path.is_empty() {
        return "(none)".into();
    }
    let mut out = String::with_capacity(path.len());
    for (i, seg) in path.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        let hexish = seg.len() >= 8 && seg.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
        let numeric = !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
        out.push_str(if hexish || numeric { ":id" } else { seg });
    }
    out
}

/// Collapses numbers and ids in a message so repeated errors group together.
pub fn normalize_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len().min(160));
    let mut prev_digit = false;
    for c in msg.chars().take(160) {
        if c.is_ascii_digit() {
            if !prev_digit {
                out.push('#');
            }
            prev_digit = true;
        } else {
            out.push(c);
            prev_digit = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMBINED: &str = r#"203.0.113.9 - bob [10/Oct/2023:13:55:36 +0000] "GET /api/users/42?x=1 HTTP/1.1" 200 2326 "http://ref/" "Mozilla/5.0 (X11)""#;

    #[test]
    fn combined_line() {
        let a = parse_access(COMBINED, &Options::default()).unwrap();
        assert_eq!((a.method, a.path, a.status, a.bytes), ("GET", "/api/users/42?x=1", 200, 2326));
        assert_eq!(a.ts_ms, 1_696_946_136_000);
        assert_eq!(a.latency_s, None, "a user agent is not a latency");
    }

    #[test]
    fn nginx_trailing_request_time_and_key_forms() {
        let o = Options::default();
        let l = format!("{COMBINED} 0.250");
        assert_eq!(parse_access(&l, &o).unwrap().latency_s, Some(0.25));
        let l = format!("{COMBINED} rt=1.5 uct=0.001");
        assert_eq!(parse_access(&l, &o).unwrap().latency_s, Some(1.5));
        let ms = Options { latency_scale: 0.001 };
        let l = format!("{COMBINED} 250");
        assert_eq!(parse_access(&l, &ms).unwrap().latency_s, Some(0.25));
    }

    #[test]
    fn common_format_and_odd_requests() {
        let o = Options::default();
        let l = r#"1.2.3.4 - - [10/Oct/2023:13:55:36 +0000] "-" 408 -"#;
        let a = parse_access(l, &o).unwrap();
        assert_eq!((a.method, a.path, a.status, a.bytes), ("-", "", 408, 0));
        let l = r#"1.2.3.4 - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.0" 304 0"#;
        assert_eq!(parse_access(l, &o).unwrap().latency_s, None, "common format ends with the byte count");
    }

    #[test]
    fn access_rejects_garbage() {
        let o = Options::default();
        for bad in ["", "hello world", r#"x [bad time] "GET / HTTP/1.1" 200 1"#, r#"x [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 999 1"#, r#"x [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" abc 1"#] {
            assert!(parse_access(bad, &o).is_none(), "{bad}");
        }
    }

    #[test]
    fn app_line_shapes() {
        let a = parse_app("2023-10-10T13:55:36Z ERROR db: connection refused after 1500ms").unwrap();
        assert_eq!((a.level, a.message), (Level::Error, "db: connection refused after 1500ms"));
        assert_eq!(a.latency_s, Some(1.5));
        let a = parse_app("2023-10-10 13:55:36,123 [main] WARN  Slow query").unwrap();
        assert_eq!((a.level, a.message), (Level::Warn, "Slow query"));
        let a = parse_app("2023-10-10T13:55:36Z [INFO] started in 2.5s").unwrap();
        assert_eq!((a.level, a.latency_s), (Level::Info, Some(2.5)));
        assert!(parse_app("2023-10-10T13:55:36Z no level here at all").is_none());
        assert!(parse_app("    at com.example.Foo(Foo.java:12)").is_none());
    }

    #[test]
    fn durations_are_not_confused_with_other_numbers() {
        assert_eq!(message_latency("user 42 logged in"), None);
        assert_eq!(message_latency("served 3 items in 12ms"), Some(0.012));
        assert_eq!(message_latency("took 12 ms total"), Some(0.012));
        assert_eq!(message_latency("sessions: 5"), None);
        assert_eq!(message_latency("id abc123ms"), None);
    }

    #[test]
    fn detection() {
        let o = Options::default();
        assert_eq!(detect(COMBINED, &o), Some(Format::Access));
        assert_eq!(detect("\n2023-10-10T13:55:36Z INFO hi\n", &o), Some(Format::App));
        assert_eq!(detect("random\ntext\n", &o), None);
    }

    #[test]
    fn normalization() {
        assert_eq!(normalize_path("/api/users/42?x=1"), "/api/users/:id");
        assert_eq!(normalize_path("/o/3f2a9c1e-8b7d-4a55-9e01-0a1b2c3d4e5f/items"), "/o/:id/items");
        assert_eq!(normalize_path("/static/app.js"), "/static/app.js");
        assert_eq!(normalize_path(""), "(none)");
        assert_eq!(normalize_message("user 1234 failed after 15 tries"), "user # failed after # tries");
    }
}
