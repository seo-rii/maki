//! `maki-benchmark` — engine throughput measurement over a configured
//! volume (creates it if missing). It overwrites the start of the volume,
//! so an existing volume needs `--destroy-data` (R5-017).

use std::process::ExitCode;
use std::time::Instant;

use maki_format::error::FormatError;
use maki_nbdkit::daemon::DaemonError;

const USAGE: &str = "usage: maki-benchmark [--destroy-data] <config.toml> [ops] [io-size]";

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let destroy_data = match args.iter().position(|arg| arg == "--destroy-data") {
        Some(index) => {
            args.remove(index);
            true
        }
        None => false,
    };
    let Some(config_path) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let ops: u64 = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(10_000);
    let io_size: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(4096);

    let raw = match std::fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("error: {config_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let config = match maki_nbdkit::daemon::parse_and_validate(&raw) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Create the volume if it doesn't exist yet; an existing one holds data
    // the benchmark would overwrite.
    match maki_nbdkit::daemon::create_volume_from_config_str(&raw) {
        Ok(_) => {}
        Err(DaemonError::Format(FormatError::AlreadyExists(_))) if destroy_data => {}
        Err(DaemonError::Format(FormatError::AlreadyExists(_))) => {
            eprintln!(
                "error: {config_path} names an existing volume; the benchmark overwrites its \
                 data. Pass --destroy-data to run it anyway."
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: cannot create the volume: {e}");
            return ExitCode::FAILURE;
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let engine = match runtime.block_on(maki_nbdkit::daemon::attach_from_config(&config)) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("attach failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The engine refuses requests above nbd.maximum_io and misaligned ones
    // (F07); say so instead of panicking on the first I/O.
    let block = engine.geometry().device_block_size as usize;
    if io_size == 0 || io_size as u64 > engine.max_request_bytes() || !io_size.is_multiple_of(block)
    {
        eprintln!(
            "io-size {io_size} must be a positive multiple of {block} no larger than \
             nbd.maximum_io ({})",
            engine.max_request_bytes()
        );
        return ExitCode::from(2);
    }
    let size = engine.size();
    let slots = size / io_size as u64;
    if slots == 0 {
        eprintln!("io-size {io_size} is larger than the device ({size} bytes)");
        return ExitCode::from(2);
    }
    let data = vec![0xA5u8; io_size];

    let start = Instant::now();
    runtime.block_on(async {
        for i in 0..ops {
            let offset = (i % slots) * io_size as u64;
            engine.write(offset, &data, false).await.unwrap();
        }
        engine.flush().await.unwrap();
    });
    let write_elapsed = start.elapsed();

    let start = Instant::now();
    runtime.block_on(async {
        for i in 0..ops {
            let offset = (i % slots) * io_size as u64;
            let _ = engine.read(offset, io_size).await.unwrap();
        }
    });
    let read_elapsed = start.elapsed();

    let mib = (ops as f64 * io_size as f64) / (1024.0 * 1024.0);
    println!(
        "write: {ops} x {io_size}B in {write_elapsed:?} ({:.1} MiB/s, {:.0} IOPS)",
        mib / write_elapsed.as_secs_f64(),
        ops as f64 / write_elapsed.as_secs_f64()
    );
    println!(
        "read:  {ops} x {io_size}B in {read_elapsed:?} ({:.1} MiB/s, {:.0} IOPS)",
        mib / read_elapsed.as_secs_f64(),
        ops as f64 / read_elapsed.as_secs_f64()
    );
    ExitCode::SUCCESS
}
