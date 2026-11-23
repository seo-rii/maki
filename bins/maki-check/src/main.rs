//! `maki-check` — offline volume format checker (SPEC §43).
//!
//! `maki-check <root>` runs the fast metadata checks; `--deep` additionally
//! verifies checkpoint state, the key canary, the durable mark, the whole
//! journal (with the recovery scanner) and every allocated slot (review
//! M-018). The deep check takes the volume lock: run it after detach.

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;

use maki_backing::Backing;

const USAGE: &str =
    "usage: maki-check <volume-backing-root> [--deep] [--journal-segment-size <bytes>]";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// Write `text` to stdout and flush it.
///
/// `println!` panics when the write fails, and the panic replaces the
/// command's exit status with 101. A reader that has gone (`| head -1`,
/// `| grep -q`) has what it wanted, so a closed pipe is not an error and the
/// command keeps its own verdict; any other failure is returned for the
/// caller to report.
fn print_stdout(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
        _ => Ok(()),
    }
}

/// Print help or the version, which is all such a command produces.
fn print_result(text: &str) -> ExitCode {
    match print_stdout(text) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: writing the output failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    // The store reports adopted shards and repaired allocation maps through
    // `tracing`; the checker must not drop them (R4-001).
    maki_core::logging::install_default_logging();
    // Opening a volume keeps every shard data file open (BUG-124).
    if let Err(e) = maki_backing::raise_open_file_limit() {
        eprintln!("warning: cannot raise the open-file soft limit: {e}");
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut root: Option<&std::path::Path> = None;
    let mut deep = false;
    let mut segment_size: u64 = 256 << 20;
    let mut i = 0;
    while i < args.len() {
        match args[i].to_str() {
            Some("--help" | "-h") => return print_result(&format!("{USAGE}\n")),
            Some("--version" | "-V") => {
                return print_result(&format!("maki-check {}\n", env!("CARGO_PKG_VERSION")));
            }
            Some("--deep") => deep = true,
            Some("--journal-segment-size") => {
                i += 1;
                match args.get(i).and_then(|v| v.to_str()?.parse().ok()) {
                    Some(v) => segment_size = v,
                    None => return usage(),
                }
            }
            _ if args[i].as_encoded_bytes().starts_with(b"-") => return usage(),
            _ if root.is_none() => root = Some(std::path::Path::new(&args[i])),
            _ => return usage(),
        }
        i += 1;
    }
    let Some(root) = root else {
        return usage();
    };
    // `FileBacking::new` creates a missing root; an offline checker must
    // never mutate, so a root that is not an existing directory is refused
    // first (R5-026).
    let display = root.display();
    match std::fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            eprintln!("error: {display}: not a directory");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("error: {display}: {e}");
            return ExitCode::FAILURE;
        }
    }
    // A rollback-protected root keeps the volume inside an outer format that
    // only the configured daemon path can open (BUG-110).
    if root.join("rollback.format").exists() {
        eprintln!(
            "error: {display} is a rollback-protected backing; maki-check cannot open its \
             outer format. Run `maki check <config.toml> [--deep]` with the volume configuration"
        );
        return ExitCode::FAILURE;
    }
    let backing = match maki_backing::FileBacking::new(root) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {display}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let report = if deep {
        maki_core::check::deep_check(Arc::new(backing) as Arc<dyn Backing>, segment_size)
            .map_err(|e| e.to_string())
    } else {
        maki_format::checker::check_volume(&backing).map_err(|e| e.to_string())
    };
    match report {
        Ok(report) => {
            let mut text = String::new();
            for info in &report.info {
                text += &format!("info: {info}\n");
            }
            for warning in &report.warnings {
                text += &format!("warning: {warning}\n");
            }
            for error in &report.errors {
                text += &format!("ERROR: {error}\n");
            }
            let verdict = if report.ok() { "passed" } else { "FAILED" };
            text += &format!("check {verdict}\n");
            // A reader that has gone leaves the verdict to the exit status.
            // A report that could not be written is an error, which still
            // names the verdict.
            if let Err(error) = print_stdout(&text) {
                eprintln!("error: check {verdict}, but writing the report failed: {error}");
                return ExitCode::FAILURE;
            }
            if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
