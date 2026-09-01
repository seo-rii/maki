//! `maki-check` — offline volume format checker (SPEC §43).

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(root) = args.first() else {
        eprintln!("usage: maki-check <volume-backing-root>");
        return ExitCode::from(2);
    };
    let backing = match maki_backing::FileBacking::new(root.as_str()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: {root}: {e}");
            return ExitCode::FAILURE;
        }
    };
    match maki_format::checker::check_volume(&backing) {
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
