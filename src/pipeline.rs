//! Streaming parallel pipeline: one reader cuts the input into blocks of whole lines, worker
//! threads parse blocks into partial aggregates, and the calling thread merges them in file order.
//! Memory stays bounded: at most `2 * threads` blocks are waiting plus one per busy worker, and
//! partials are merged as soon as their turn comes.

use crate::agg::{parse_block, Partial, Thresholds};
use crate::parse::{detect, Format, Options};
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, Read};
use std::sync::mpsc::{channel, sync_channel};
use std::sync::Mutex;

#[derive(Clone, Debug)]
pub struct Config {
    /// 0 means one per CPU.
    pub threads: usize,
    pub block_bytes: usize,
    pub format: Option<Format>,
    pub parse: Options,
    pub thresholds: Thresholds,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            threads: 0,
            block_bytes: 4 << 20,
            format: None,
            parse: Options::default(),
            thresholds: Thresholds { gap_ms: 300_000 },
        }
    }
}

/// Reads about `target` bytes, extended to the end of the current line. False at end of input.
fn read_block<R: BufRead>(r: &mut R, target: usize, buf: &mut Vec<u8>) -> io::Result<bool> {
    buf.clear();
    let n = Read::by_ref(r).take(target as u64).read_to_end(buf)?;
    if n == 0 {
        return Ok(false);
    }
    if !buf.ends_with(b"\n") {
        r.read_until(b'\n', buf)?;
    }
    Ok(true)
}

pub fn analyze<R: Read + Send>(input: R, cfg: &Config) -> io::Result<(Format, Partial)> {
    let mut reader = BufReader::with_capacity(1 << 20, input);
    let mut first = Vec::new();
    if !read_block(&mut reader, cfg.block_bytes, &mut first)? {
        return Ok((cfg.format.unwrap_or(Format::Access), Partial::default()));
    }
    let fmt = match cfg.format {
        Some(f) => f,
        None => {
            let sample = String::from_utf8_lossy(&first[..first.len().min(64 * 1024)]);
            detect(&sample, &cfg.parse).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unrecognized log format, pass --format access|app")
            })?
        }
    };
    let threads = if cfg.threads == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        cfg.threads
    };

    let (work_tx, work_rx) = sync_channel::<(usize, Vec<u8>)>(threads * 2);
    let work_rx = Mutex::new(work_rx);
    let (res_tx, res_rx) = channel::<(usize, Partial)>();
    let mut total = Partial::default();

    let read_result = std::thread::scope(|s| {
        for _ in 0..threads {
            let res_tx = res_tx.clone();
            let work_rx = &work_rx;
            s.spawn(move || loop {
                let item = work_rx.lock().unwrap().recv();
                let Ok((idx, block)) = item else { break };
                let part = parse_block(&block, fmt, &cfg.parse, &cfg.thresholds);
                if res_tx.send((idx, part)).is_err() {
                    break;
                }
            });
        }
        drop(res_tx);

        let reader_thread = s.spawn(move || -> io::Result<()> {
            let mut idx = 0;
            let mut block = first;
            loop {
                if work_tx.send((idx, block)).is_err() {
                    return Ok(());
                }
                idx += 1;
                block = Vec::with_capacity(cfg.block_bytes + 4096);
                if !read_block(&mut reader, cfg.block_bytes, &mut block)? {
                    return Ok(());
                }
            }
        });

        let mut pending: BTreeMap<usize, Partial> = BTreeMap::new();
        let mut next = 0;
        for (idx, part) in res_rx {
            pending.insert(idx, part);
            while let Some(p) = pending.remove(&next) {
                total.merge(p, &cfg.thresholds);
                next += 1;
            }
        }
        reader_thread.join().expect("reader thread panicked")
    });
    read_result?;
    Ok((fmt, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn text(n: usize) -> String {
        (0..n)
            .map(|i| {
                let level = if i % 10 == 0 { "ERROR" } else { "INFO" };
                format!("2023-10-10T{:02}:{:02}:{:02}Z {level} item {i} took {}ms\n", i / 3600 % 24, i / 60 % 60, i % 60, i % 50)
            })
            .collect()
    }

    #[test]
    fn result_is_independent_of_block_size_and_thread_count() {
        let input = text(5000);
        let base = {
            let cfg = Config { threads: 1, block_bytes: 1 << 30, ..Config::default() };
            analyze(Cursor::new(input.clone()), &cfg).unwrap().1
        };
        assert_eq!((base.lines, base.parsed), (5000, 5000));
        for (threads, block) in [(1, 100), (4, 100), (8, 1000), (3, 7777)] {
            let cfg = Config { threads, block_bytes: block, ..Config::default() };
            let (fmt, p) = analyze(Cursor::new(input.clone()), &cfg).unwrap();
            assert_eq!(fmt, Format::App);
            assert_eq!((p.lines, p.parsed, p.inversions, p.gaps), (base.lines, base.parsed, base.inversions, base.gaps), "{threads}x{block}");
            assert_eq!(p.levels, base.levels);
            assert_eq!(p.messages, base.messages);
            assert_eq!(p.latency.count(), base.latency.count());
            assert_eq!(p.minutes.len(), base.minutes.len());
        }
    }

    #[test]
    fn boundary_anomalies_survive_tiny_blocks() {
        let input = "2023-10-10T00:00:10Z INFO a\n2023-10-10T00:00:05Z INFO b\n2023-10-10T01:00:00Z INFO c\n";
        let cfg = Config { threads: 2, block_bytes: 1, ..Config::default() };
        let (_, p) = analyze(Cursor::new(input), &cfg).unwrap();
        assert_eq!((p.lines, p.inversions, p.gaps), (3, 1, 1));
        assert_eq!(p.inversion_examples[0].line, 2);
        assert_eq!(p.gap_examples[0].line, 3);
    }

    #[test]
    fn empty_input_and_unknown_format() {
        let (_, p) = analyze(Cursor::new(""), &Config::default()).unwrap();
        assert_eq!(p.lines, 0);
        let err = analyze(Cursor::new("hello\nworld\n"), &Config::default()).unwrap_err();
        assert!(err.to_string().contains("--format"));
    }

    #[test]
    fn explicit_format_counts_bad_lines() {
        let cfg = Config { format: Some(Format::Access), ..Config::default() };
        let (_, p) = analyze(Cursor::new("nope\nstill nope\n"), &cfg).unwrap();
        assert_eq!((p.lines, p.parsed, p.bad_count), (2, 0, 2));
    }
}
