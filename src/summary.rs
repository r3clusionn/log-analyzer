//! Turns a merged [`Partial`] into findings, and renders them as text or JSON.

use crate::agg::{Anomaly, Minute, Partial, PathStat};
use crate::parse::{Format, Level};
use crate::time::format_utc;
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_MINUTE_SPAN: i64 = 5_000_000;
const MIN_ROUTE_SAMPLES: u64 = 20;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Spike {
    pub minute_utc: String,
    pub count: u64,
    pub times_median: f64,
}

#[derive(Debug, Default, PartialEq)]
pub struct Traffic {
    pub median: f64,
    pub peak: u64,
    pub peak_minute: i64,
    pub spikes: Vec<(i64, u64)>,
    pub minutes: usize,
}

fn median(sorted: &[u64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        0.0
    } else if n % 2 == 1 {
        sorted[n / 2] as f64
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) as f64 / 2.0
    }
}

/// Spikes are minutes whose value exceeds the median by more than six robust deviations
/// (1.4826 x MAD, at least 1) and is at least double the median. Minutes with no traffic count as
/// zero, so a quiet night does not hide a daytime peak.
pub fn traffic(minutes: &BTreeMap<i64, Minute>, pick: impl Fn(&Minute) -> u64) -> Traffic {
    let (Some((&lo, _)), Some((&hi, _))) = (minutes.iter().next(), minutes.iter().next_back()) else {
        return Traffic::default();
    };
    if hi - lo > MAX_MINUTE_SPAN {
        return Traffic::default();
    }
    let series: Vec<u64> = (lo..=hi).map(|m| minutes.get(&m).map_or(0, &pick)).collect();
    let mut sorted = series.clone();
    sorted.sort_unstable();
    let med = median(&sorted);
    let mut dev: Vec<u64> = series.iter().map(|v| (*v as f64 - med).abs().round() as u64).collect();
    dev.sort_unstable();
    let scale = (1.4826 * median(&dev)).max(1.0);
    let threshold = med + 6.0 * scale;
    let (mut peak, mut peak_minute) = (0, lo);
    let mut spikes = Vec::new();
    for (i, v) in series.iter().enumerate() {
        if *v > peak {
            peak = *v;
            peak_minute = lo + i as i64;
        }
        if *v as f64 > threshold && *v as f64 >= 2.0 * med.max(1.0) {
            spikes.push((lo + i as i64, *v));
        }
    }
    spikes.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Traffic { median: med, peak, peak_minute, spikes, minutes: series.len() }
}

#[derive(Serialize)]
pub struct Latency {
    pub samples: u64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub p999_ms: f64,
    pub max_ms: f64,
}

#[derive(Serialize)]
pub struct Route {
    pub route: String,
    pub requests: u64,
    pub errors: u64,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

#[derive(Serialize)]
pub struct AnomalyOut {
    pub line: u64,
    pub at_utc: String,
    pub previous_utc: String,
}

#[derive(Serialize)]
pub struct Summary {
    pub format: &'static str,
    pub lines: u64,
    pub parsed: u64,
    pub unparseable: u64,
    pub continuation_lines: u64,
    pub first_utc: Option<String>,
    pub last_utc: Option<String>,
    pub median_per_minute: f64,
    pub peak_per_minute: u64,
    pub peak_minute_utc: Option<String>,
    pub traffic_spikes: Vec<Spike>,
    pub error_spikes: Vec<Spike>,
    pub status_classes: BTreeMap<String, u64>,
    pub levels: BTreeMap<String, u64>,
    pub bytes: u64,
    pub latency: Option<Latency>,
    pub slow_routes: Vec<Route>,
    pub error_routes: Vec<Route>,
    pub top_errors: Vec<(String, u64)>,
    pub out_of_order: u64,
    pub out_of_order_examples: Vec<AnomalyOut>,
    pub gaps: u64,
    pub longest_gap_seconds: f64,
    pub gap_examples: Vec<AnomalyOut>,
    pub unparseable_examples: Vec<(u64, String)>,
}

fn minute_label(m: i64) -> String {
    format_utc(m * 60_000)[..16].to_string()
}

fn anomalies(v: &[Anomaly]) -> Vec<AnomalyOut> {
    v.iter()
        .map(|a| AnomalyOut { line: a.line, at_utc: format_utc(a.ts_ms), previous_utc: format_utc(a.prev_ts_ms) })
        .collect()
}

fn route(name: &str, p: &PathStat) -> Route {
    let q = |x: f64| p.latency.quantile(x).map(|v| v * 1000.0);
    Route { route: name.to_string(), requests: p.n, errors: p.errors, p95_ms: q(0.95), p99_ms: q(0.99) }
}

pub fn summarize(fmt: Format, p: &Partial, top: usize) -> Summary {
    let all = traffic(&p.minutes, |m| m.n);
    let errs = traffic(&p.minutes, |m| m.errors);
    let spike = |t: &Traffic| -> Vec<Spike> {
        t.spikes
            .iter()
            .take(top)
            .map(|(m, c)| Spike {
                minute_utc: minute_label(*m),
                count: *c,
                // 0 means the minute was normally empty, so a ratio is meaningless.
                times_median: if t.median > 0.0 { *c as f64 / t.median } else { 0.0 },
            })
            .collect()
    };

    let mut status_classes = BTreeMap::new();
    let mut levels = BTreeMap::new();
    match fmt {
        Format::Access => {
            for (i, n) in p.status.iter().enumerate().skip(1) {
                if *n > 0 {
                    status_classes.insert(format!("{i}xx"), *n);
                }
            }
        }
        Format::App => {
            for l in Level::ALL {
                if p.levels[l as usize] > 0 {
                    levels.insert(l.name().to_string(), p.levels[l as usize]);
                }
            }
        }
    }

    let latency = (p.latency.count() > 0).then(|| {
        let q = |x: f64| p.latency.quantile(x).unwrap_or(0.0) * 1000.0;
        Latency {
            samples: p.latency.count(),
            p50_ms: q(0.5),
            p95_ms: q(0.95),
            p99_ms: q(0.99),
            p999_ms: q(0.999),
            max_ms: p.latency.max() * 1000.0,
        }
    });

    let mut slow: Vec<Route> = p
        .paths
        .iter()
        .filter(|(_, s)| s.latency.count() >= MIN_ROUTE_SAMPLES)
        .map(|(k, s)| route(k, s))
        .collect();
    slow.sort_by(|a, b| b.p95_ms.partial_cmp(&a.p95_ms).unwrap_or(std::cmp::Ordering::Equal).then(a.route.cmp(&b.route)));
    slow.truncate(top);

    let mut err_routes: Vec<Route> = p.paths.iter().filter(|(_, s)| s.errors > 0).map(|(k, s)| route(k, s)).collect();
    err_routes.sort_by(|a, b| b.errors.cmp(&a.errors).then(a.route.cmp(&b.route)));
    err_routes.truncate(top);

    let mut msgs: Vec<(String, u64)> = p.messages.iter().map(|(k, v)| (k.clone(), *v)).collect();
    msgs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    msgs.truncate(top);

    Summary {
        format: match fmt {
            Format::Access => "access",
            Format::App => "app",
        },
        lines: p.lines,
        parsed: p.parsed,
        unparseable: p.bad_count,
        continuation_lines: p.continuation,
        first_utc: p.minutes.keys().next().map(|m| minute_label(*m)),
        last_utc: p.minutes.keys().next_back().map(|m| minute_label(*m)),
        median_per_minute: all.median,
        peak_per_minute: all.peak,
        peak_minute_utc: (all.peak > 0).then(|| minute_label(all.peak_minute)),
        traffic_spikes: spike(&all),
        error_spikes: spike(&errs),
        status_classes,
        levels,
        bytes: p.bytes,
        latency,
        slow_routes: slow,
        error_routes: err_routes,
        top_errors: msgs,
        out_of_order: p.inversions,
        out_of_order_examples: anomalies(&p.inversion_examples),
        gaps: p.gaps,
        longest_gap_seconds: p.gap_ms as f64 / 1000.0,
        gap_examples: anomalies(&p.gap_examples),
        unparseable_examples: p.bad_examples.clone(),
    }
}

fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn duration(secs: f64) -> String {
    let s = secs.round() as u64;
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, s % 3600 / 60),
    }
}

fn ms(v: f64) -> String {
    if v >= 1000.0 { format!("{:.2}s", v / 1000.0) } else { format!("{v:.1}ms") }
}

pub fn render_text(s: &Summary, gap_threshold_s: f64) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{} log: {} lines, {} parsed, {} unparseable{}",
        s.format,
        thousands(s.lines),
        thousands(s.parsed),
        thousands(s.unparseable),
        if s.continuation_lines > 0 { format!(", {} continuation", thousands(s.continuation_lines)) } else { String::new() }
    );
    for (line, text) in &s.unparseable_examples {
        let _ = writeln!(o, "  line {line}: {text}");
    }
    if let (Some(a), Some(b)) = (&s.first_utc, &s.last_utc) {
        let _ = writeln!(o, "span:      {a} to {b} UTC");
    }
    if let Some(at) = &s.peak_minute_utc {
        let _ = writeln!(
            o,
            "traffic:   median {}/min, peak {}/min at {at}",
            thousands(s.median_per_minute.round() as u64),
            thousands(s.peak_per_minute)
        );
    }
    let list_spikes = |o: &mut String, title: &str, v: &[Spike]| {
        if v.is_empty() {
            return;
        }
        let _ = writeln!(o, "{title}");
        for sp in v {
            let rel = if sp.times_median > 0.0 { format!("{:.1}x median", sp.times_median) } else { "none normally".into() };
            let _ = writeln!(o, "  {}  {}/min  ({rel})", sp.minute_utc, thousands(sp.count));
        }
    };
    list_spikes(&mut o, "traffic spikes:", &s.traffic_spikes);
    list_spikes(&mut o, "error spikes:", &s.error_spikes);
    if !s.status_classes.is_empty() {
        let total: u64 = s.status_classes.values().sum();
        let parts: Vec<String> = s
            .status_classes
            .iter()
            .map(|(k, v)| format!("{k} {} ({:.2}%)", thousands(*v), *v as f64 * 100.0 / total.max(1) as f64))
            .collect();
        let _ = writeln!(o, "status:    {}", parts.join("  "));
    }
    if !s.levels.is_empty() {
        let parts: Vec<String> = s.levels.iter().map(|(k, v)| format!("{k} {}", thousands(*v))).collect();
        let _ = writeln!(o, "levels:    {}", parts.join("  "));
    }
    if let Some(l) = &s.latency {
        let _ = writeln!(
            o,
            "latency:   {} samples  p50 {}  p95 {}  p99 {}  p99.9 {}  max {}  (quantiles within 1%)",
            thousands(l.samples),
            ms(l.p50_ms),
            ms(l.p95_ms),
            ms(l.p99_ms),
            ms(l.p999_ms),
            ms(l.max_ms)
        );
    }
    if !s.slow_routes.is_empty() {
        let _ = writeln!(o, "slowest routes by p95 (at least {MIN_ROUTE_SAMPLES} timed requests):");
        for r in &s.slow_routes {
            let _ = writeln!(
                o,
                "  p95 {:>9}  p99 {:>9}  {:>9} req  {}",
                r.p95_ms.map_or("-".into(), ms),
                r.p99_ms.map_or("-".into(), ms),
                thousands(r.requests),
                r.route
            );
        }
    }
    if !s.error_routes.is_empty() {
        let _ = writeln!(o, "routes with the most 5xx:");
        for r in &s.error_routes {
            let _ = writeln!(o, "  {:>9} {:>6} of {:>9}  {}", thousands(r.errors), if r.errors == 1 { " error" } else { "errors" }, thousands(r.requests), r.route);
        }
    }
    if !s.top_errors.is_empty() {
        let _ = writeln!(o, "most common errors (numbers collapsed to #):");
        for (m, c) in &s.top_errors {
            let _ = writeln!(o, "  {:>9}  {m}", thousands(*c));
        }
    }
    let _ = writeln!(o, "timestamps:");
    if s.out_of_order == 0 {
        let _ = writeln!(o, "  in order");
    } else {
        let _ = writeln!(o, "  {} lines go backwards in time", thousands(s.out_of_order));
        for a in &s.out_of_order_examples {
            let _ = writeln!(o, "    line {}: {} after {}", a.line, a.at_utc, a.previous_utc);
        }
    }
    if s.gaps == 0 {
        let _ = writeln!(o, "  no silence longer than {}", duration(gap_threshold_s));
    } else {
        let _ = writeln!(
            o,
            "  {} silences longer than {}, longest {}",
            thousands(s.gaps),
            duration(gap_threshold_s),
            duration(s.longest_gap_seconds)
        );
        for a in &s.gap_examples {
            let _ = writeln!(o, "    line {}: {} after {}", a.line, a.at_utc, a.previous_utc);
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn series(values: &[u64]) -> BTreeMap<i64, Minute> {
        values.iter().enumerate().map(|(i, v)| (i as i64, Minute { n: *v, errors: 0 })).collect()
    }

    #[test]
    fn steady_traffic_has_no_spikes() {
        let t = traffic(&series(&[100, 102, 98, 101, 99, 103, 100, 97]), |m| m.n);
        assert!(t.spikes.is_empty());
        assert_eq!((t.median, t.peak), (100.0, 103));
    }

    #[test]
    fn a_burst_is_a_spike_and_ordering_is_by_size() {
        let mut v = vec![100u64; 60];
        v[10] = 900;
        v[40] = 1500;
        v[41] = 150; // a mild rise is not a spike
        let t = traffic(&series(&v), |m| m.n);
        assert_eq!(t.spikes, [(40, 1500), (10, 900)]);
        assert_eq!((t.peak, t.peak_minute), (1500, 40));
    }

    #[test]
    fn missing_minutes_count_as_zero() {
        let mut m = BTreeMap::new();
        m.insert(0, Minute { n: 10, errors: 0 });
        m.insert(100, Minute { n: 10, errors: 0 });
        let t = traffic(&m, |x| x.n);
        assert_eq!((t.minutes, t.median), (101, 0.0));
        assert_eq!(t.spikes.len(), 2, "both active minutes stand out against a silent hour");
    }

    #[test]
    fn empty_input_has_no_traffic() {
        assert_eq!(traffic(&BTreeMap::new(), |m| m.n), Traffic::default());
    }

    #[test]
    fn number_formatting() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(duration(59.0), "59s");
        assert_eq!(duration(3725.0), "1h 2m");
        assert_eq!(ms(12.34), "12.3ms");
        assert_eq!(ms(2500.0), "2.50s");
    }
}
