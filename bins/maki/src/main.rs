//! `maki` — administrative CLI (SPEC §7).
//!
//! Volume lifecycle (`volume create/inspect`, `check`) works everywhere;
//! runtime commands (`status`, `metrics`, `checkpoint`, `reload`) talk to
//! the daemon control socket (Unix). `attach`/`detach`/`grow` delegate to
//! the privileged helper.

use std::process::ExitCode;

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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
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
        ["status", config] => control(config, "status", None, serde_json::Value::Null),
        ["metrics", config] => control(config, "metrics", None, serde_json::Value::Null),
        ["checkpoint", config] => control(config, "checkpoint", None, serde_json::Value::Null),
        // The cache is the one section the daemon applies at runtime; it
        // needs the new size (O-09: without it the verb could never succeed).
        ["reload", config, "cache", "--max-bytes", max_bytes] => match max_bytes.parse::<u64>() {
            Ok(max_bytes) => control(
                config,
                "reload",
                Some("cache"),
                serde_json::json!({ "max_bytes": max_bytes }),
            ),
            Err(_) => fail(format!("--max-bytes: {max_bytes:?} is not an integer")),
        },
        ["reload", _config, "cache"] => fail(
            "reload cache needs the new size: maki reload <config> cache --max-bytes <bytes>"
                .to_string(),
        ),
        ["reload", config, section] => {
            control(config, "reload", Some(section), serde_json::Value::Null)
        }
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
    let result: Result<serde_json::Value, String> = runtime.block_on(async {
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
) -> ExitCode {
    fail("control socket commands require a Unix host".to_string())
}
