# Log analyzer

`logscan` streams a large log file in parallel and reports error rates, traffic spikes, latency percentiles and timestamp problems. It reads web access logs (Apache and nginx) and application logs that start with a timestamp and a level. For anyone who needs the shape of a multi-gigabyte log before opening it.

**Status:** v0.1.0, working. Measured on a 10 million line, 1.2 GB access log.

## Features

- Streaming and parallel: a reader cuts the input into blocks of whole lines, worker threads parse them, and partial results merge in file order. Reads files or standard input.
- Access logs: status classes, routes with ids collapsed (`/users/42` becomes `/users/:id`), routes with the most 5xx, response-time percentiles overall and per route.
- Application logs: counts per level, the most common error messages with numbers collapsed, and durations such as `took 120ms` pulled out of messages.
- Traffic and error spikes: per-minute counts compared with the median and a robust deviation (MAD), with quiet minutes counted as zero.
- Timestamp anomalies: lines that go backwards in time and silences longer than a threshold, with line numbers.
- Latency percentiles come from a mergeable log-bucket histogram, accurate to about 1%, using constant memory.
- `--json` output for scripts.

## How to install

Needs a Rust toolchain.

```sh
git clone https://github.com/r3clusionn/log-analyzer
cd log-analyzer
cargo install --path .
```

## How to use

```sh
logscan access.log
logscan app.log --gap 60 --top 10
zcat access.log.gz | logscan -
logscan access.log --json > summary.json
```

The format is detected from the first lines. A bare number at the end of an access log line is read as the response time: seconds by default (nginx `$request_time`), or set `--latency-unit ms|us` for other servers. `rt=` and `request_time=` keys are also recognized.

| Option | What it does |
|---|---|
| `-f access\|app` | Force the format instead of detecting it. |
| `--latency-unit s\|ms\|us` | Unit of a bare trailing number in access logs. |
| `--gap SECONDS` | Report silences longer than this between consecutive lines (default 300). |
| `--top N` | Entries per list (default 5). |
| `-j N`, `--block-mib N` | Worker threads and block size. |
| `--json` | Machine-readable summary. |

Output for a 10 million line synthetic log (see Benchmarks), abridged:

```text
access log: 10,000,000 lines, 10,000,000 parsed, 0 unparseable
span:      2023-10-10 13:55 to 2023-10-10 16:42 UTC
traffic:   median 60,000/min, peak 60,001/min at 2023-10-10 13:57
status:    2xx 9,501,643 (95.02%)  3xx 240,081 (2.40%)  4xx 200,024 (2.00%)  5xx 58,252 (0.58%)
latency:   10,000,000 samples  p50 36.3ms  p95 314.0ms  p99 568.7ms  p99.9 3.25s  max 74.45s
slowest routes by p95 (at least 20 timed requests):
  p95   546.6ms  p99   896.8ms  1,665,855 req  GET /search
timestamps:
  200 lines go backwards in time
    line 50000: 2023-10-10 13:56:19 after 2023-10-10 13:56:26
```

## How it works

Each block becomes a `Partial` aggregate, and `Partial::merge` combines two partials that are next
to each other in the file. Because order matters for timestamps, every partial remembers its first
and last timestamp and the border between two blocks is checked at merge time. The result does not
depend on block size or thread count; a test runs the same input at several of each and compares.

Gaps and backwards steps are judged between consecutive lines. That keeps results identical for any
block size, but it also means a single very stale line shows up as a backwards step and then as a
jump forward on the next line.

## Benchmarks

Windows 11, Intel Core i9-14900KF (24 threads), 32 GB RAM, NVMe SSD, file already in the cache.
The input is a synthetic nginx-format access log of 10,000,000 lines (1,218,802,484 bytes) made by
`scripts/gen_log.py` with a fixed seed. Median of 3 runs of the whole command.

| Threads | Time | Lines per second | Throughput |
|---|---|---|---|
| 1 | 6.84 s | 1.5 M | 178 MB/s |
| 4 | 1.68 s | 6.0 M | 726 MB/s |
| 8 | 0.90 s | 11.1 M | 1.36 GB/s |
| 16 | 0.54 s | 18.4 M | 2.24 GB/s |
| 24 (default) | 0.42 s | 23.9 M | 2.91 GB/s |

Correctness check: GNU awk 5.4.0 counted 58,252 lines with status 500 or above and 9,501,643 with a
2xx status, the same as `logscan`. The 200 out-of-order lines match the generator, which writes one
every 50,000 lines. awk did only that counting and took 3.2 s, so the two are not a like-for-like
speed comparison. Memory use was not measured. Real logs will differ from this synthetic one in
line length and route variety.

## Tests

`cargo test` runs 35 tests: timestamp parsing and civil-date math, parsers for each line shape,
histogram accuracy against exact quantiles, merge equivalence at every split point, block-size and
thread-count independence, and the binary on an access log with planted facts (a traffic spike, an
error spike, a slow route, an out-of-order line, a silence, junk lines) plus an application log.

## License

MIT (see `LICENSE`).
