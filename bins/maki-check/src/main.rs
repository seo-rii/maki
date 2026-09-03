//! `maki-check` — offline volume format checker (SPEC §43).
//!
//! `maki-check <root>` runs the fast metadata checks; `--deep` additionally
//! verifies checkpoint state, the key canary, the durable mark, the whole
//! journal (with the recovery scanner) and every allocated slot (review
//! M-018). The deep check takes the volume lock: run it after detach.

use std::process::ExitCode;
use std::sync::Arc;

use maki_backing::Backing;

fn usage() -> ExitCode {
    eprintln!("usage: maki-check <volume-backing-root> [--deep] [--journal-segment-size <bytes>]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut root: Option<String> = None;
    let mut deep = false;
    let mut segment_size: u64 = 256 << 20;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--deep" => deep = true,
            "--journal-segment-size" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse().ok()) {
                    Some(v) => segment_size = v,
                    None => return usage(),
                }
            }
            flag if flag.starts_with('-') => return usage(),
            path if root.is_none() => root = Some(path.to_string()),
            _ => return usage(),
        }
        i += 1;
    }
    let Some(root) = root else {
        return usage();
    };
    let backing = match maki_backing::FileBacking::new(root.as_str()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {root}: {e}");
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
            for info in &report.info {
                println!("info: {info}");
            }
            for warning in &report.warnings {
                println!("warning: {warning}");
            }
            for error in &report.errors {
                println!("ERROR: {error}");
            }
            if report.ok() {
                println!("check passed");
                ExitCode::SUCCESS
            } else {
                println!("check FAILED");
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
