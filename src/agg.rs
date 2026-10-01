//! Per-block aggregates that merge in file order.
//!
//! Every worker turns one block of lines into a [`Partial`]. Partials are merged left to right, so
//! facts that depend on order (a timestamp going backwards, a long silence) are checked both inside
//! a block and across each block boundary.

use crate::hist::LogHist;
use crate::parse::{normalize_message, normalize_path, parse_access, parse_app, Format, Level, Options};
use std::collections::{BTreeMap, HashMap};

const MAX_EXAMPLES: usize = 5;
const MAX_KEYS: usize = 5000;
const OTHER: &str = "(other)";

#[derive(Clone, Debug, PartialEq)]
pub struct Anomaly {
    /// 1-based line number in the whole input.
    pub line: u64,
    pub ts_ms: i64,
    pub prev_ts_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct Minute {
    pub n: u64,
    pub errors: u64,
}

#[derive(Clone, Debug, Default)]
pub struct PathStat {
    pub n: u64,
    pub errors: u64,
    pub latency: LogHist,
}

#[derive(Clone, Debug)]
pub struct Edge {
    pub line: u64,
    pub ts_ms: i64,
}

#[derive(Clone, Debug, Default)]
pub struct Partial {
    pub lines: u64,
    pub parsed: u64,
    pub continuation: u64,
    pub bad_count: u64,
    pub bad_examples: Vec<(u64, String)>,
    pub minutes: BTreeMap<i64, Minute>,
    pub status: [u64; 6],
    pub bytes: u64,
    pub paths: HashMap<String, PathStat>,
    pub levels: [u64; 6],
    pub messages: HashMap<String, u64>,
    pub latency: LogHist,
    pub first: Option<Edge>,
    pub last: Option<Edge>,
    pub inversions: u64,
    pub inversion_examples: Vec<Anomaly>,
    pub gaps: u64,
    pub gap_examples: Vec<Anomaly>,
    pub gap_ms: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    /// A silence longer than this between consecutive lines is reported.
    pub gap_ms: i64,
}

fn push_capped<T>(v: &mut Vec<T>, item: T) {
    if v.len() < MAX_EXAMPLES {
        v.push(item);
    }
}

fn bump(map: &mut HashMap<String, u64>, key: String) {
    if let Some(c) = map.get_mut(&key) {
        *c += 1;
    } else if map.len() < MAX_KEYS {
        map.insert(key, 1);
    } else {
        *map.entry(OTHER.into()).or_insert(0) += 1;
    }
}

impl Partial {
    /// Order-dependent bookkeeping for one timestamped line. `line` is local to this block.
    fn observe_time(&mut self, line: u64, ts_ms: i64, th: &Thresholds) {
        if let Some(prev) = self.last.clone() {
            self.check_step(prev, Edge { line, ts_ms }, th, 0);
        } else {
            self.first = Some(Edge { line, ts_ms });
        }
        self.last = Some(Edge { line, ts_ms });
    }

    /// Compares two consecutive timestamps; `line_base` turns local line numbers into global ones.
    fn check_step(&mut self, prev: Edge, cur: Edge, th: &Thresholds, line_base: u64) {
        if cur.ts_ms < prev.ts_ms {
            self.inversions += 1;
            push_capped(
                &mut self.inversion_examples,
                Anomaly { line: line_base + cur.line, ts_ms: cur.ts_ms, prev_ts_ms: prev.ts_ms },
            );
        } else if cur.ts_ms - prev.ts_ms > th.gap_ms {
            self.gaps += 1;
            self.gap_ms = self.gap_ms.max(cur.ts_ms - prev.ts_ms);
            push_capped(
                &mut self.gap_examples,
                Anomaly { line: line_base + cur.line, ts_ms: cur.ts_ms, prev_ts_ms: prev.ts_ms },
            );
        }
    }

    fn record_minute(&mut self, ts_ms: i64, is_error: bool) {
        let m = self.minutes.entry(ts_ms.div_euclid(60_000)).or_default();
        m.n += 1;
        m.errors += is_error as u64;
    }

    fn record_path(&mut self, key: String, is_error: bool, latency: Option<f64>) {
        let key = if self.paths.contains_key(&key) || self.paths.len() < MAX_KEYS { key } else { OTHER.into() };
        let p = self.paths.entry(key).or_default();
        p.n += 1;
        p.errors += is_error as u64;
        if let Some(l) = latency {
            p.latency.add(l);
        }
    }

    /// Merges `next`, the block that follows this one in the file.
    pub fn merge(&mut self, next: Partial, th: &Thresholds) {
        let base = self.lines;
        if let (Some(prev), Some(first)) = (self.last.clone(), next.first.clone()) {
            self.check_step(prev, first, th, base);
        }
        self.lines += next.lines;
        self.parsed += next.parsed;
        self.continuation += next.continuation;
        self.bad_count += next.bad_count;
        for (l, s) in next.bad_examples {
            if self.bad_examples.len() < MAX_EXAMPLES {
                self.bad_examples.push((base + l, s));
            }
        }
        for (k, m) in next.minutes {
            let e = self.minutes.entry(k).or_default();
            e.n += m.n;
            e.errors += m.errors;
        }
        for i in 0..6 {
            self.status[i] += next.status[i];
            self.levels[i] += next.levels[i];
        }
        self.bytes += next.bytes;
        for (k, p) in next.paths {
            let key = if self.paths.contains_key(&k) || self.paths.len() < MAX_KEYS { k } else { OTHER.into() };
            let e = self.paths.entry(key).or_default();
            e.n += p.n;
            e.errors += p.errors;
            e.latency.merge(&p.latency);
        }
        for (k, c) in next.messages {
            if let Some(e) = self.messages.get_mut(&k) {
                *e += c;
            } else if self.messages.len() < MAX_KEYS {
                self.messages.insert(k, c);
            } else {
                *self.messages.entry(OTHER.into()).or_insert(0) += c;
            }
        }
        self.latency.merge(&next.latency);
        self.inversions += next.inversions;
        for a in next.inversion_examples {
            push_capped(&mut self.inversion_examples, Anomaly { line: a.line + base, ..a });
        }
        self.gaps += next.gaps;
        self.gap_ms = self.gap_ms.max(next.gap_ms);
        for a in next.gap_examples {
            push_capped(&mut self.gap_examples, Anomaly { line: a.line + base, ..a });
        }
        if self.first.is_none() {
            self.first = next.first.map(|e| Edge { line: e.line + base, ts_ms: e.ts_ms });
        }
        if let Some(l) = next.last {
            self.last = Some(Edge { line: l.line + base, ts_ms: l.ts_ms });
        }
    }
}

/// Parses one block of whole lines.
pub fn parse_block(block: &[u8], fmt: Format, opts: &Options, th: &Thresholds) -> Partial {
    let mut p = Partial::default();
    let mut rest = block;
    while !rest.is_empty() {
        let (raw, tail) = match rest.iter().position(|b| *b == b'\n') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, &rest[rest.len()..]),
        };
        rest = tail;
        p.lines += 1;
        let line_no = p.lines;
        let text = String::from_utf8_lossy(raw);
        let line = text.trim_end_matches('\r');
        // Blank lines still count toward `lines` so reported line numbers match the file.
        if line.trim().is_empty() {
            continue;
        }
        match fmt {
            Format::Access => match parse_access(line, opts) {
                Some(a) => {
                    p.parsed += 1;
                    let is_err = a.status >= 500;
                    p.status[(a.status / 100) as usize] += 1;
                    p.bytes += a.bytes;
                    p.observe_time(line_no, a.ts_ms, th);
                    p.record_minute(a.ts_ms, is_err);
                    if let Some(l) = a.latency_s {
                        p.latency.add(l);
                    }
                    p.record_path(format!("{} {}", a.method, normalize_path(a.path)), is_err, a.latency_s);
                }
                None => {
                    p.bad_count += 1;
                    push_capped(&mut p.bad_examples, (line_no, line.chars().take(120).collect()));
                }
            },
            Format::App => match parse_app(line) {
                Some(a) => {
                    p.parsed += 1;
                    p.levels[a.level as usize] += 1;
                    let is_err = a.level >= Level::Error;
                    p.observe_time(line_no, a.ts_ms, th);
                    p.record_minute(a.ts_ms, is_err);
                    if let Some(l) = a.latency_s {
                        p.latency.add(l);
                    }
                    if is_err {
                        bump(&mut p.messages, normalize_message(a.message));
                    }
                }
                // Stack traces and wrapped messages: not a timestamped line, not an error either.
                None if p.parsed > 0 || line.starts_with(char::is_whitespace) => p.continuation += 1,
                None => {
                    p.bad_count += 1;
                    push_capped(&mut p.bad_examples, (line_no, line.chars().take(120).collect()));
                }
            },
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn th() -> Thresholds {
        Thresholds { gap_ms: 60_000 }
    }

    fn app(block: &str) -> Partial {
        parse_block(block.as_bytes(), Format::App, &Options::default(), &th())
    }

    #[test]
    fn counts_levels_and_groups_error_messages() {
        let p = app("2023-10-10T00:00:00Z INFO ok\n2023-10-10T00:00:01Z ERROR user 11 failed\n2023-10-10T00:00:02Z ERROR user 22 failed\n  at Foo.bar(Foo.java:1)\n");
        assert_eq!((p.lines, p.parsed, p.continuation, p.bad_count), (4, 3, 1, 0));
        assert_eq!(p.levels[Level::Error as usize], 2);
        assert_eq!(p.messages.get("user # failed"), Some(&2));
        assert_eq!(p.minutes.values().map(|m| (m.n, m.errors)).collect::<Vec<_>>(), [(3, 2)]);
    }

    #[test]
    fn detects_backwards_time_and_gaps_inside_a_block() {
        let p = app("2023-10-10T00:00:10Z INFO a\n2023-10-10T00:00:05Z INFO b\n2023-10-10T00:05:00Z INFO c\n");
        assert_eq!(p.inversions, 1);
        assert_eq!(p.inversion_examples[0].line, 2);
        assert_eq!(p.gaps, 1);
        assert_eq!(p.gap_examples[0].line, 3);
        assert_eq!(p.gap_ms, 295_000);
    }

    #[test]
    fn merging_checks_the_block_boundary_and_offsets_line_numbers() {
        let a = app("2023-10-10T00:00:10Z INFO a\n2023-10-10T00:00:11Z INFO b\n");
        let b = app("2023-10-10T00:00:01Z INFO c\ngarbage\n2023-10-10T00:10:00Z INFO d\n");
        let mut m = a.clone();
        m.merge(b, &th());
        assert_eq!(m.lines, 5);
        assert_eq!(m.inversions, 1, "c is older than b across the border");
        assert_eq!(m.inversion_examples[0].line, 3);
        assert_eq!(m.gap_examples[0].line, 5);
        assert_eq!(m.last.as_ref().unwrap().line, 5);
        assert_eq!(m.first.as_ref().unwrap().line, 1);
        // `garbage` follows parsed lines, so it is a continuation, not a bad line.
        assert_eq!((m.continuation, m.bad_count), (1, 0));
    }

    #[test]
    fn merge_equals_parsing_the_whole_text() {
        let text = "2023-10-10T00:00:10Z ERROR boom 1\n2023-10-10T00:00:05Z INFO b\n2023-10-10T00:09:00Z WARN c 2\n2023-10-10T00:09:01Z ERROR boom 3\n";
        let whole = app(text);
        let lines: Vec<&str> = text.lines().collect();
        for split in 1..lines.len() {
            let mut left = app(&(lines[..split].join("\n") + "\n"));
            left.merge(app(&(lines[split..].join("\n") + "\n")), &th());
            assert_eq!(left.lines, whole.lines);
            assert_eq!(left.inversions, whole.inversions, "split {split}");
            assert_eq!(left.gaps, whole.gaps, "split {split}");
            assert_eq!(left.levels, whole.levels);
            assert_eq!(left.messages, whole.messages);
            assert_eq!(left.minutes.len(), whole.minutes.len());
        }
    }

    #[test]
    fn access_block_status_paths_latency() {
        let l = |s: u16, p: &str, rt: &str| {
            format!(r#"1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET {p} HTTP/1.1" {s} 100 "-" "ua" {rt}"#)
        };
        let block = [l(200, "/a/1", "0.1"), l(200, "/a/2", "0.3"), l(500, "/b", "2.0"), "junk".to_string()].join("\n");
        let p = parse_block(block.as_bytes(), Format::Access, &Options::default(), &th());
        assert_eq!((p.parsed, p.bad_count, p.bytes), (3, 1, 300));
        assert_eq!((p.status[2], p.status[5]), (2, 1));
        assert_eq!(p.paths["GET /a/:id"].n, 2);
        assert_eq!(p.paths["GET /b"].errors, 1);
        assert_eq!(p.latency.count(), 3);
        assert_eq!(p.bad_examples[0].0, 4);
    }

    #[test]
    fn crlf_blank_lines_and_missing_final_newline() {
        let p = app("2023-10-10T00:00:00Z INFO a\r\n\r\n2023-10-10T00:00:01Z INFO b");
        assert_eq!((p.lines, p.parsed), (3, 2));
    }
}
