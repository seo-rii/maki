//! `maki` — administrative CLI (SPEC §7).
//!
//! Volume lifecycle (`volume create/inspect`, `check`) works everywhere;
//! runtime commands (`status`, `metrics`, `checkpoint`, `reload`) talk to
//! the daemon control socket (Unix). `attach`/`detach`/`grow` delegate to
//! the privileged helper.

use std::process::ExitCode;
use std::time::Duration;

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  maki volume create <config.toml>     initialize a volume's backing layout
  maki volume inspect <config.toml>    print volume metadata
  maki check <config.toml> [--deep]    offline format check (--deep: journal, checkpoint, slots)
  maki status <config.toml>            daemon status (control socket)
  maki metrics <config.toml>           metrics snapshot (control socket)
  maki checkpoint <config.toml>        graceful checkpoint (control socket)
  maki reload <config.toml> <section>  hot config reload (control socket)
  maki attach|detach|grow ...          delegated to maki-attach (privileged)"
    );
    ExitCode::from(2)
}

fn read_config(path: &str) -> Result<maki_format::config::VolumeConfig, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let cfg = maki_format::config::parse_config(&raw).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Default bound on a control-socket round trip. A stalled daemon (a
/// checkpoint holding the volume lock, a provider that never answers) must
/// not hang the operator's shell forever; `--timeout <seconds>` overrides.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(60);
/// A checkpoint legitimately takes a while on a large journal.
const CHECKPOINT_TIMEOUT: Duration = Duration::from_secs(600);

/// Remove `--timeout <seconds>` from the arguments, if present.
fn take_timeout(args: &mut Vec<String>) -> Result<Option<Duration>, String> {
    let Some(i) = args.iter().position(|a| a == "--timeout") else {
        return Ok(None);
    };
    let value = args
        .get(i + 1)
        .cloned()
        .ok_or_else(|| "--timeout needs a value in seconds".to_string())?;
    let secs: u64 = value
        .parse()
        .ok()
        .filter(|s| *s > 0)
        .ok_or_else(|| format!("--timeout: {value:?} is not a positive number of seconds"))?;
    args.drain(i..i + 2);
    Ok(Some(Duration::from_secs(secs)))
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let timeout = match take_timeout(&mut args) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match argv.as_slice() {
        ["volume", "create", config] => {
            let raw = match std::fs::read_to_string(config) {
                Ok(raw) => raw,
                Err(e) => return fail(format!("{config}: {e}")),
            };
            match maki_nbdkit::daemon::create_volume_from_config_str(&raw) {
                Ok(sb) => {
                    println!(
                        "created volume {} (uuid {}, {} bytes virtual, slot size {})",
                        sb.provider_type,
                        sb.volume_uuid,
                        sb.geometry.max_virtual_size,
                        sb.geometry.slot_size
                    );
                    if let Some(hint) = ownership_hint(running_as_root()) {
                        eprintln!("warning: {hint}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e.to_string()),
            }
        }
        ["volume", "inspect", config] => match inspect(config) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(e),
        },
        ["check", config] => match check(config, false) {
            Ok(clean) => {
                if clean {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => fail(e),
        },
        ["check", config, "--deep"] => match check(config, true) {
            Ok(clean) => {
                if clean {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => fail(e),
        },
        ["status", config] => control(
            config,
            "status",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["metrics", config] => control(
            config,
            "metrics",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["checkpoint", config] => control(
            config,
            "checkpoint",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CHECKPOINT_TIMEOUT),
        ),
        // The cache is the one section the daemon applies at runtime; it
        // needs the new size (O-09: without it the verb could never succeed).
        ["reload", config, "cache", "--max-bytes", max_bytes] => match max_bytes.parse::<u64>() {
            Ok(max_bytes) => control(
                config,
                "reload",
                Some("cache"),
                serde_json::json!({ "max_bytes": max_bytes }),
                timeout.unwrap_or(CONTROL_TIMEOUT),
            ),
            Err(_) => fail(format!("--max-bytes: {max_bytes:?} is not an integer")),
        },
        ["reload", _config, "cache"] => fail(
            "reload cache needs the new size: maki reload <config> cache --max-bytes <bytes>"
                .to_string(),
        ),
        ["reload", config, section] => control(
            config,
            "reload",
            Some(section),
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["attach", ..] | ["detach", ..] | ["grow", ..] => {
            eprintln!(
                "this operation requires the privileged helper: run `maki-attach {}` \
                 (or systemctl start maki-attach@<volume>)",
                argv.join(" ")
            );
            ExitCode::from(3)
        }
        _ => usage(),
    }
}

/// The backing tree is created owner-only; a root-created volume is
/// unreadable to the `maki` daemon user (SPEC 8: `maki:maki 0700`).
fn ownership_hint(as_root: bool) -> Option<&'static str> {
    as_root.then_some(
        "the volume tree was created owner-only by root; the daemon runs as the maki user \
         and cannot open it. Run `maki volume create` as that user (sudo -u maki ...) or \
         chown the tree to maki:maki before starting the service",
    )
}

#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: plain geteuid.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}

fn fail(message: String) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn inspect(config: &str) -> Result<(), String> {
    let cfg = read_config(config)?;
    let backing = maki_nbdkit::daemon::build_backing(&cfg).map_err(|e| e.to_string())?;
    let sb = maki_format::init::load_superblock(backing.as_ref()).map_err(|e| e.to_string())?;
    println!("volume:        {}", cfg.volume.name);
    println!("uuid:          {}", sb.volume_uuid);
    println!("provider:      {}", sb.provider_type);
    println!("compatibility: {}", sb.crypto_compatibility_id);
    println!("virtual size:  {}", sb.geometry.max_virtual_size);
    println!("unit size:     {}", sb.geometry.crypto_unit_size);
    println!("slot size:     {}", sb.geometry.slot_size);
    println!("generation:    {}", sb.generation);
    Ok(())
}

fn check(config: &str, deep: bool) -> Result<bool, String> {
    let cfg = read_config(config)?;
    let backing = maki_nbdkit::daemon::build_backing(&cfg).map_err(|e| e.to_string())?;
    let report = if deep {
        maki_core::check::deep_check(backing, cfg.backing.journal_segment_size.0)
            .map_err(|e| e.to_string())?
    } else {
        maki_format::checker::check_volume(backing.as_ref()).map_err(|e| e.to_string())?
    };
    for info in &report.info {
        println!("info: {info}");
    }
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
    for error in &report.errors {
        println!("ERROR: {error}");
    }
    println!("check {}", if report.ok() { "passed" } else { "FAILED" });
    Ok(report.ok())
}

#[cfg(unix)]
fn control(
    config: &str,
    command: &str,
    section: Option<&str>,
    payload: serde_json::Value,
    timeout: Duration,
) -> ExitCode {
    let cfg = match read_config(config) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let socket = maki_nbdkit::daemon::control_socket_path(&cfg);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let round_trip = async {
        let stream = tokio::net::UnixStream::connect(&socket)
            .await
            .map_err(|e| format!("{socket}: {e}"))?;
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut request = maki_control::protocol::Request::new(command);
        request.section = section.map(|s| s.to_string());
        request.payload = payload;
        maki_control::protocol::send_command(&mut wr, &request)
            .await
            .map_err(|e| e.to_string())?;
        maki_control::protocol::read_response(&mut rd)
            .await
            .map_err(|e| e.to_string())
    };
    let result: Result<serde_json::Value, String> = runtime.block_on(async {
        match tokio::time::timeout(timeout, round_trip).await {
            Ok(result) => result,
            Err(_elapsed) => Err(format!(
                "{command}: no response from {socket} within {}s; the daemon may be stalled \
                 (pass --timeout <seconds> to wait longer)",
                timeout.as_secs()
            )),
        }
    });
    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            if v["ok"] == serde_json::Value::Bool(true) {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => fail(e),
    }
}

#[cfg(not(unix))]
fn control(
    _config: &str,
    _command: &str,
    _section: Option<&str>,
    _payload: serde_json::Value,
    _timeout: Duration,
) -> ExitCode {
    fail("control socket commands require a Unix host".to_string())
}
