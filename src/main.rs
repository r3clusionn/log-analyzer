use clap::{Parser, ValueEnum};
use logscan::agg::Thresholds;
use logscan::parse::{Format, Options};
use logscan::pipeline::{analyze, Config};
use logscan::summary::{render_text, summarize};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Fmt {
    Access,
    App,
}

#[derive(Clone, Copy, ValueEnum)]
enum Unit {
    S,
    Ms,
    Us,
}

#[derive(Parser)]
#[command(version, about = "Summarize large access and application logs")]
struct Cli {
    /// Log file, or - for standard input
    file: Option<PathBuf>,
    /// Log format (default: detected from the first lines)
    #[arg(short, long, value_enum)]
    format: Option<Fmt>,
    /// Unit of a bare trailing number in access logs: s for nginx $request_time, us for Apache %D
    #[arg(long, value_enum, default_value = "s")]
    latency_unit: Unit,
    /// Report silences longer than this many seconds between consecutive lines
    #[arg(long, default_value_t = 300.0)]
    gap: f64,
    /// Entries per list
    #[arg(long, default_value_t = 5)]
    top: usize,
    /// Worker threads (default: number of CPUs)
    #[arg(short = 'j', long, default_value_t = 0)]
    threads: usize,
    /// Block size in MiB handed to each worker
    #[arg(long, default_value_t = 4)]
    block_mib: usize,
    /// Print the summary as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("logscan: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    if !(cli.gap.is_finite() && cli.gap > 0.0) {
        return Err("--gap must be a positive number of seconds".into());
    }
    let input: Box<dyn Read + Send> = match cli.file.as_deref() {
        None => Box::new(std::io::stdin()),
        Some(p) if p.as_os_str() == "-" => Box::new(std::io::stdin()),
        Some(p) => Box::new(File::open(p).map_err(|e| format!("{}: {e}", p.display()))?),
    };
    let cfg = Config {
        threads: cli.threads,
        block_bytes: cli.block_mib.max(1) << 20,
        format: cli.format.map(|f| match f {
            Fmt::Access => Format::Access,
            Fmt::App => Format::App,
        }),
        parse: Options {
            latency_scale: match cli.latency_unit {
                Unit::S => 1.0,
                Unit::Ms => 1e-3,
                Unit::Us => 1e-6,
            },
        },
        thresholds: Thresholds { gap_ms: (cli.gap * 1000.0) as i64 },
    };
    let (fmt, partial) = analyze(input, &cfg).map_err(|e| e.to_string())?;
    if partial.lines == 0 {
        return Err("input is empty".into());
    }
    let summary = summarize(fmt, &partial, cli.top.max(1));
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?);
    } else {
        print!("{}", render_text(&summary, cli.gap));
    }
    Ok(())
}
