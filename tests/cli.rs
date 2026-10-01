//! Builds an access log with known planted facts and checks that the binary finds each one.

use std::io::Write;
use std::process::{Command, Stdio};

fn clf(secs: u32) -> String {
    format!("10/Oct/2023:{:02}:{:02}:{:02} +0000", secs / 3600, secs / 60 % 60, secs % 60)
}

fn line(secs: u32, path: &str, status: u16, rt: f64) -> String {
    format!(r#"10.0.0.1 - - [{}] "GET {path} HTTP/1.1" {status} 512 "-" "test-agent" {rt:.3}"#, clf(secs))
}

/// 80 minutes starting 12:00. Planted facts:
/// - 100 requests per minute, /api/items/N at 20-60 ms;
/// - minute 30 has 1200 requests (a spike);
/// - /slow answers in 2.0 s (50 requests);
/// - /boom returns 500 for 30 requests in minute 45 (an error spike);
/// - one line stamped 18 seconds before the line written just ahead of it (out of order) (out of order);
/// - nothing between minute 55 and minute 75 (a 19 minute silence);
/// - two junk lines.
fn planted_log() -> String {
    let start = 12 * 3600;
    let mut out = Vec::new();
    for minute in 0..=55u32 {
        let n = if minute == 30 { 1200 } else { 100 };
        for i in 0..n {
            let t = start + minute * 60 + (i * 59 / n).min(59);
            out.push(line(t, &format!("/api/items/{}", i + 1), 200, 0.02 + (i % 5) as f64 * 0.01));
        }
        if minute == 45 {
            out.extend((0..30).map(|_| line(start + 45 * 60 + 59, "/boom", 500, 0.1)));
        }
        if minute == 10 {
            out.extend((0..50).map(|_| line(start + 10 * 60 + 59, "/slow", 200, 2.0)));
        }
        if minute == 20 {
            out.push(line(start + 20 * 60 + 40, "/api/items/9", 200, 0.03));
            out.push("this is not a log line".into());
        }
    }
    out.extend((75..=79u32).flat_map(|minute| (0..100).map(move |i| line(start + minute * 60 + i * 59 / 100, "/api/items/1", 200, 0.03))));
    out.push("another junk line".into());
    out.join("\n") + "\n"
}

fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_logscan"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The process may exit before reading (bad arguments), so a broken pipe is fine here.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn finds_every_planted_fact() {
    let log = planted_log();
    let (code, out, err) = run(&["-", "--gap", "300"], &log);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("access log:"), "{out}");
    assert!(out.contains(", 2 unparseable"), "{out}");
    // Traffic spike at 12:30, exactly 1200 requests.
    assert!(out.contains("2023-10-10 12:30  1,200/min"), "{out}");
    // Error spike at 12:45 from /boom.
    assert!(out.contains("2023-10-10 12:45  30/min"), "{out}");
    assert!(out.lines().any(|l| l.contains("GET /boom") && l.contains("30 errors")), "{out}");
    // /slow tops the p95 list at about 2 s.
    let slow_line = out.lines().find(|l| l.contains("GET /slow")).expect("slow route listed");
    assert!(slow_line.contains("2.0") || slow_line.contains("1.9"), "{slow_line}");
    let first_route = out.lines().skip_while(|l| !l.starts_with("slowest routes")).nth(1).unwrap();
    assert!(first_route.contains("GET /slow"), "{first_route}");
    // Timestamps: one backwards line, one 20 minute silence.
    assert!(out.contains("1 lines go backwards in time"), "{out}");
    assert!(out.contains("1 silences longer than 5m 0s, longest 19m"), "{out}");
}

#[test]
fn json_output_matches_the_text_findings() {
    let log = planted_log();
    let (code, out, _) = run(&["-", "--json", "--gap", "300"], &log);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["format"], "access");
    assert_eq!(v["out_of_order"], 1);
    assert_eq!(v["gaps"], 1);
    assert_eq!(v["traffic_spikes"][0]["count"], 1200);
    assert_eq!(v["peak_per_minute"], 1200);
    assert_eq!(v["status_classes"]["5xx"], 30);
    assert!(v["latency"]["p999_ms"].as_f64().unwrap() > 1000.0);
    assert!(v["latency"]["p95_ms"].as_f64().unwrap() < 100.0);
}

#[test]
fn thread_count_and_block_size_do_not_change_the_answer() {
    let log = planted_log();
    let (_, a, _) = run(&["-", "--json", "-j", "1", "--block-mib", "64"], &log);
    let (_, b, _) = run(&["-", "--json", "-j", "6", "--block-mib", "1"], &log);
    assert_eq!(a, b);
}

#[test]
fn app_logs_report_levels_and_grouped_errors() {
    let mut log = String::new();
    for i in 0..300u32 {
        let (level, msg) = if i % 30 == 0 { ("ERROR", format!("payment {i} declined")) } else { ("INFO", format!("request {i} served in {}ms", i % 40)) };
        log += &format!("2023-10-10T12:{:02}:{:02}Z {level} {msg}\n", i / 60, i % 60);
        if i % 30 == 0 {
            log += "    at com.example.Pay.charge(Pay.java:88)\n";
        }
    }
    let (code, out, err) = run(&["-"], &log);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("app log:"), "{out}");
    assert!(out.contains("ERROR 10") && out.contains("INFO 290"), "{out}");
    assert!(out.contains("10  payment # declined"), "{out}");
    assert!(out.contains("10 continuation"), "{out}");
}

#[test]
fn errors_exit_with_code_2() {
    assert_eq!(run(&["-"], "").0, 2);
    assert_eq!(run(&["-"], "hello\nworld\n").0, 2);
    assert_eq!(run(&["definitely-missing.log"], "").0, 2);
    assert_eq!(run(&["-", "--gap", "0"], "x").0, 2);
}
