//! Engine throughput and latency over a configured, disposable volume.
//! An existing volume needs --destroy-data: its working set is overwritten.

mod latency;

use std::process::ExitCode;
use std::time::Instant;

use maki_format::error::FormatError;
use maki_nbdkit::daemon::DaemonError;
use serde::Serialize;

use latency::{Latencies, LatencyReport};

const USAGE: &str =
    "usage: maki-benchmark [--destroy-data] [--json] [--fua] <config.toml> [ops] [io-size]";

struct Options {
    config_path: String,
    destroy_data: bool,
    json: bool,
    fua: bool,
    ops: u64,
    io_size: usize,
}

fn parse_args() -> Result<Options, String> {
    let mut positional = Vec::new();
    let mut destroy_data = false;
    let mut json = false;
    let mut fua = false;
    let mut literal = false;
    for arg in std::env::args().skip(1) {
        if literal {
            positional.push(arg);
            continue;
        }
        let flag = match arg.as_str() {
            "--destroy-data" => Some(&mut destroy_data),
            "--json" => Some(&mut json),
            "--fua" => Some(&mut fua),
            "--" => {
                literal = true;
                continue;
            }
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => None,
        };
        if let Some(flag) = flag {
            if *flag {
                return Err(format!("duplicate option: {arg}"));
            }
            *flag = true;
        } else {
            positional.push(arg);
        }
    }
    if positional.is_empty() || positional.len() > 3 {
        return Err("expected a config and at most two workload arguments".into());
    }
    let ops = positional
        .get(1)
        .map_or(Ok(10_000), |v| v.parse::<u64>())
        .map_err(|_| "ops must be a positive integer")?;
    if ops == 0 {
        return Err("ops must be a positive integer".into());
    }
    let io_size = positional
        .get(2)
        .map_or(Ok(4096), |v| v.parse::<usize>())
        .map_err(|_| "io-size must be a positive integer")?;
    Ok(Options {
        config_path: positional.remove(0),
        destroy_data,
        json,
        fua,
        ops,
        io_size,
    })
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
    concurrency: u32,
    fua: bool,
    read_verified: bool,
    flush_us: f64,
    write: OperationReport,
    read: OperationReport,
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
    let ops = options.ops;
    let result: Result<Report, String> = runtime.block_on(async {
        let mut data = vec![0xA5u8; io_size];
        let mut writes = Latencies::new();
        let start = Instant::now();
        for i in 0..ops {
            let offset = (i % slots) * io_size as u64;
            data[..8].copy_from_slice(&offset.to_le_bytes());
            let began = Instant::now();
            engine
                .write(offset, &data, options.fua)
                .await
                .map_err(|error| format!("write at offset {offset} failed: {error}"))?;
            writes.record(began.elapsed());
        }
        let began = Instant::now();
        engine
            .flush()
            .await
            .map_err(|error| format!("final flush failed: {error}"))?;
        let flush_us = began.elapsed().as_secs_f64() * 1e6;
        let write = OperationReport::new(start.elapsed(), io_size, &writes);

        let mut reads = Latencies::new();
        let start = Instant::now();
        for i in 0..ops {
            let offset = (i % slots) * io_size as u64;
            let began = Instant::now();
            let actual = engine
                .read(offset, io_size)
                .await
                .map_err(|error| format!("read at offset {offset} failed: {error}"))?;
            reads.record(began.elapsed());
            data[..8].copy_from_slice(&offset.to_le_bytes());
            if actual != data {
                return Err(format!("read verification failed at offset {offset}"));
            }
        }
        let read = OperationReport::new(start.elapsed(), io_size, &reads);
        Ok(Report {
            schema_version: 1,
            provider: config.crypto.provider.clone(),
            operations: ops,
            io_size_bytes: io_size,
            concurrency: 1,
            fua: options.fua,
            read_verified: true,
            flush_us,
            write,
            read,
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
                "{name}: {ops} x {io_size}B in {:.3}s ({:.1} MiB/s, {:.0} IOPS); \
                 latency us: mean {:.1}, p50 <= {:.1}, p95 <= {:.1}, p99 <= {:.1}, max {:.1}",
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
        println!(
            "FUA: {}; final FLUSH: {:.1} us (included in write throughput); read verification: passed",
            report.fua, report.flush_us
        );
    }
    ExitCode::SUCCESS
}
