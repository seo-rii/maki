//! Engine throughput and latency over a configured, disposable volume.
//! An existing volume needs --destroy-data: its working set is overwritten.

mod latency;
mod workload;

use std::process::ExitCode;

use maki_format::error::FormatError;
use maki_nbdkit::daemon::DaemonError;
use serde::Serialize;

use latency::{Latencies, LatencyReport};

const USAGE: &str = "usage: maki-benchmark [--destroy-data] [--json] [--fua] [--concurrency 1..256]\n  [--access sequential|random] [--read-percent 0..100] [--working-set bytes]\n  [--flush-every operations] [--seed integer] <config.toml> [ops] [io-size]";
const MAX_OPERATIONS: u64 = 1_000_000_000;

struct Options {
    config_path: String,
    destroy_data: bool,
    json: bool,
    fua: bool,
    ops: u64,
    io_size: usize,
    concurrency: usize,
    random: bool,
    read_percent: Option<u64>,
    working_set: Option<u64>,
    flush_every: Option<u64>,
    seed: u64,
}

fn parse_args() -> Result<Options, String> {
    let mut positional = Vec::new();
    let mut options = Options {
        config_path: String::new(),
        destroy_data: false,
        json: false,
        fua: false,
        ops: 10_000,
        io_size: 4096,
        concurrency: 1,
        random: false,
        read_percent: None,
        working_set: None,
        flush_every: None,
        seed: 1,
    };
    let mut literal = false;
    let mut seen = std::collections::HashSet::new();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        if literal {
            positional.push(argument);
            continue;
        }
        if argument == "--" {
            literal = true;
            continue;
        }
        if !argument.starts_with('-') {
            positional.push(argument);
            continue;
        }
        if !seen.insert(argument.clone()) {
            return Err(format!("duplicate option: {argument}"));
        }
        match argument.as_str() {
            "--destroy-data" => options.destroy_data = true,
            "--json" => options.json = true,
            "--fua" => options.fua = true,
            "--concurrency" | "--access" | "--read-percent" | "--working-set" | "--flush-every"
            | "--seed" => {
                let value = arguments
                    .next()
                    .filter(|value| !value.starts_with('-'))
                    .ok_or_else(|| format!("missing value for {argument}"))?;
                match argument.as_str() {
                    "--concurrency" => {
                        options.concurrency =
                            value.parse().map_err(|_| "concurrency must be in 1..256")?;
                        if !(1..=256).contains(&options.concurrency) {
                            return Err("concurrency must be in 1..256".into());
                        }
                    }
                    "--access" => {
                        options.random = match value.as_str() {
                            "sequential" => false,
                            "random" => true,
                            _ => return Err("access must be sequential or random".into()),
                        }
                    }
                    "--read-percent" => {
                        let percent = value
                            .parse::<u64>()
                            .map_err(|_| "read-percent must be in 0..100")?;
                        if percent > 100 {
                            return Err("read-percent must be in 0..100".into());
                        }
                        options.read_percent = Some(percent);
                    }
                    "--working-set" => {
                        options.working_set =
                            Some(value.parse::<maki_format::config::ByteSize>()?.0)
                    }
                    "--flush-every" => {
                        let every = value
                            .parse::<u64>()
                            .map_err(|_| "flush-every must be positive")?;
                        if every == 0 {
                            return Err("flush-every must be positive".into());
                        }
                        options.flush_every = Some(every);
                    }
                    "--seed" => {
                        options.seed = value
                            .parse()
                            .map_err(|_| "seed must be a nonnegative integer")?
                    }
                    _ => unreachable!(),
                }
            }
            _ => return Err(format!("unknown option: {argument}")),
        }
    }
    if positional.is_empty() || positional.len() > 3 {
        return Err("expected a config and at most two workload arguments".into());
    }
    if let Some(ops) = positional.get(1) {
        options.ops = ops
            .parse::<u64>()
            .map_err(|_| "ops must be a positive integer")?;
    }
    if options.ops == 0 || options.ops > MAX_OPERATIONS {
        return Err(format!("ops must be in 1..{MAX_OPERATIONS}"));
    }
    if let Some(size) = positional.get(2) {
        options.io_size = size
            .parse::<usize>()
            .map_err(|_| "io-size must be a positive integer")?;
    }
    options.config_path = positional.remove(0);
    Ok(options)
}

#[derive(Serialize)]
struct OperationReport {
    elapsed_seconds: f64,
    mib_per_second: f64,
    iops: f64,
    latency: LatencyReport,
}

impl OperationReport {
    fn new(elapsed: std::time::Duration, io_size: usize, latencies: &Latencies) -> Self {
        let latency = latencies.report();
        // A positive interval also keeps output finite on a coarse timer.
        let elapsed_seconds = elapsed.as_secs_f64().max(1e-9);
        let iops = latency.samples as f64 / elapsed_seconds;
        Self {
            elapsed_seconds,
            mib_per_second: iops * io_size as f64 / (1024.0 * 1024.0),
            iops,
            latency,
        }
    }
}

#[derive(Serialize)]
struct Report {
    schema_version: u32,
    provider: String,
    operations: u64,
    io_size_bytes: usize,
    concurrency: usize,
    fua: bool,
    read_verified: bool,
    flush_us: f64,
    write: OperationReport,
    read: OperationReport,
    flush: OperationReport,
    workload: workload::Description,
    setup: workload::SetupReport,
    resources: workload::ResourceReport,
}

fn main() -> ExitCode {
    if std::env::args().len() == 2
        && matches!(std::env::args().nth(1).as_deref(), Some("--help" | "-h"))
    {
        println!("{USAGE}\nOverwrites a disposable volume; reports verified I/O and latency.");
        return ExitCode::SUCCESS;
    }
    let options = match parse_args() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let raw = match std::fs::read_to_string(&options.config_path) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!("error: {}: {error}", options.config_path);
            return ExitCode::FAILURE;
        }
    };
    let config = match maki_nbdkit::daemon::parse_and_validate(&raw) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Validate the workload before creating or recovering any backing state.
    let block = config.volume.device_block_size as usize;
    let io_size = options.io_size;
    if io_size == 0
        || io_size as u64 > config.nbd.maximum_io.0
        || io_size as u64 > config.volume.max_virtual_size.0
        || !io_size.is_multiple_of(block)
    {
        eprintln!(
            "io-size {io_size} must be a positive multiple of {block} no larger than \
             nbd.maximum_io ({}) or the device ({} bytes)",
            config.nbd.maximum_io.0, config.volume.max_virtual_size.0
        );
        return ExitCode::from(2);
    }
    let working_set_bytes = options.working_set.unwrap_or_else(|| {
        options
            .ops
            .min(config.volume.max_virtual_size.0 / io_size as u64)
            * io_size as u64
    });
    if working_set_bytes == 0
        || working_set_bytes > config.volume.max_virtual_size.0
        || !working_set_bytes.is_multiple_of(io_size as u64)
    {
        eprintln!("working-set must be a positive multiple of io-size no larger than the volume");
        return ExitCode::from(2);
    }
    match maki_nbdkit::daemon::create_volume_from_config_str(&raw) {
        Ok(_) => {}
        Err(DaemonError::Format(FormatError::AlreadyExists(_))) if options.destroy_data => {}
        Err(DaemonError::Format(FormatError::AlreadyExists(_))) => {
            eprintln!(
                "error: {} names an existing volume; the benchmark overwrites its \
                 data. Pass --destroy-data to run it anyway.",
                options.config_path
            );
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("error: cannot create the volume: {error}");
            return ExitCode::FAILURE;
        }
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("error: cannot start runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let engine = match runtime.block_on(maki_nbdkit::daemon::attach_from_config(&config)) {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("attach failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    let slots = engine.size() / io_size as u64;
    // Recovered volumes keep their on-disk geometry even when a copied
    // configuration describes a larger new volume. Recheck before any I/O.
    let actual_block = engine.geometry().device_block_size as usize;
    if slots == 0
        || io_size as u64 > engine.max_request_bytes()
        || !io_size.is_multiple_of(actual_block)
    {
        eprintln!(
            "io-size {io_size} does not fit the attached volume: size {}, block {}, maximum I/O {}",
            engine.size(),
            actual_block,
            engine.max_request_bytes()
        );
        return ExitCode::from(2);
    }
    let result: Result<Report, String> = runtime.block_on(async {
        let measured = workload::run(engine, &options, working_set_bytes).await?;
        Ok(Report {
            schema_version: 1,
            provider: config.crypto.provider.clone(),
            operations: options.ops,
            io_size_bytes: io_size,
            concurrency: options.concurrency,
            fua: options.fua,
            read_verified: true,
            flush_us: measured.final_flush_us,
            write: OperationReport::new(measured.write_elapsed, io_size, &measured.writes),
            read: OperationReport::new(measured.read_elapsed, io_size, &measured.reads),
            flush: OperationReport::new(measured.elapsed, 0, &measured.flushes),
            workload: workload::Description {
                mode: if options.read_percent.is_some() {
                    "mixed"
                } else {
                    "phased"
                },
                access: if options.random {
                    "random"
                } else {
                    "sequential"
                },
                read_percent: options.read_percent,
                working_set_bytes,
                flush_every_operations: options.flush_every,
                seed: options.seed,
            },
            setup: measured.setup,
            resources: measured.resources,
        })
    });
    let report = match result {
        Ok(report) => report,
        Err(error) => {
            eprintln!("benchmark failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if options.json {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("cannot encode report: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        for (name, stats) in [("write", &report.write), ("read", &report.read)] {
            println!(
                "{name}: {} x {io_size}B in {:.3}s ({:.1} MiB/s, {:.0} IOPS); \
                 latency us: mean {:.1}, p50 <= {:.1}, p95 <= {:.1}, p99 <= {:.1}, max {:.1}",
                stats.latency.samples,
                stats.elapsed_seconds,
                stats.mib_per_second,
                stats.iops,
                stats.latency.mean_us,
                stats.latency.p50_upper_us,
                stats.latency.p95_upper_us,
                stats.latency.p99_upper_us,
                stats.latency.max_us,
            );
        }
        let rss = report
            .resources
            .process_peak_rss_bytes
            .map(|bytes| format!("{bytes}B"))
            .unwrap_or_else(|| "unavailable".into());
        println!("concurrency: {}; access: {}; mode: {}; working set: {}B; peak pending: {}; process peak RSS: {rss}",
            report.concurrency, report.workload.access, report.workload.mode,
            report.workload.working_set_bytes, report.resources.peak_pending_operations);
        println!(
            "FUA: {}; final FLUSH: {:.1} us (included in write throughput); read verification: passed",
            report.fua, report.flush_us
        );
    }
    ExitCode::SUCCESS
}
