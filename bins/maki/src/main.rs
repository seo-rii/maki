//! `maki` — administrative CLI (SPEC §7).
//!
//! Volume lifecycle (`volume create/inspect`, `check`) works everywhere;
//! runtime commands (`status`, `metrics`, `checkpoint`, `drain`, `reload`) talk to
//! the daemon control socket (Unix). `attach`/`detach`/`grow` delegate to
//! the privileged helper.

use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage:
  maki volume create <config.toml> [--discard]  initialize a volume (opt-in v3 discard)
  maki volume inspect <config.toml>    print volume metadata
  maki volume witness <config.toml>    inspect remote authority without claiming a writer
  maki volume gc <config.toml>         reclaim quiescent remote writer namespaces
  maki volume resume-enrollment <admin-config> <fence> <storage-uuid> [--discard]
  maki volume snapshot <config.toml> <backup-dir>  capture an offline remote backing
  maki volume takeover <admin-config> <fence> <current-root-hex>
  maki volume restore <admin-config> <backup-dir> <fence> <current-root-hex> <snapshot-root-hex>
  maki check <config.toml> [--deep]    offline format check (--deep: journal, checkpoint, slots)
  maki status <config.toml>            daemon status (control socket)
  maki metrics <config.toml>           metrics snapshot (control socket)
  maki checkpoint <config.toml>        graceful checkpoint (control socket)
  maki drain <config.toml>             close I/O admission, flush and checkpoint
  maki reload <config.toml> cache --max-bytes <bytes> [--ttl <duration>]
  maki reload <config.toml> <section>  hot config reload (control socket)
    control commands take --socket <path> in place of <config.toml>, e.g.
    --socket /run/maki-control/<volume>/control.sock for maki-admin members
  maki attach|detach|grow ...          delegated to maki-attach (privileged)
  maki --help | --version";

/// Misuse: the usage on stderr, status 2.
fn usage() -> ExitCode {
    eprintln!("{USAGE}");
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

/// Remove `--socket <path>` from the arguments, if present.
fn take_socket(args: &mut Vec<String>) -> Result<Option<String>, String> {
    let Some(i) = args.iter().position(|a| a == "--socket") else {
        return Ok(None);
    };
    let value = args
        .get(i + 1)
        .cloned()
        .filter(|path| !path.is_empty() && !path.starts_with("--"))
        .ok_or_else(|| "--socket needs the control socket path".to_string())?;
    args.drain(i..i + 2);
    Ok(Some(value))
}

/// Where a control command connects (BUG-108). The volume configuration
/// names the socket; `--socket` gives it directly, for a `maki-admin` member
/// who cannot read the root-owned configuration. Non-Unix builds refuse
/// every control command before connecting.
#[cfg_attr(not(unix), allow(dead_code))]
enum ControlTarget<'a> {
    Config(&'a str),
    Socket(String),
}

#[cfg_attr(not(unix), allow(dead_code))]
impl ControlTarget<'_> {
    /// Only the socket address is needed: the configuration is parsed, not
    /// validated, so one edited for the next start cannot block `drain` on
    /// the running daemon.
    fn socket(&self) -> Result<String, String> {
        match self {
            Self::Socket(path) => Ok(path.clone()),
            Self::Config(config) => {
                let raw = std::fs::read_to_string(config).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        format!(
                            "{config}: {e}; without access to the volume configuration pass \
                             --socket /run/maki-control/<volume>/control.sock"
                        )
                    } else {
                        format!("{config}: {e}")
                    }
                })?;
                let cfg = maki_format::config::parse_config(&raw).map_err(|e| e.to_string())?;
                Ok(maki_nbdkit::daemon::control_socket_path(&cfg))
            }
        }
    }
}

fn main() -> ExitCode {
    // Store repairs and recovery decisions are reported through `tracing`;
    // an offline check or volume creation must show them too (R4-001).
    maki_core::logging::install_default_logging();
    // Opening a volume keeps every shard data file open (BUG-124).
    if let Err(e) = maki_backing::raise_open_file_limit() {
        eprintln!("warning: cannot raise the open-file soft limit: {e}");
    }
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    // Helper options belong to the helper, including its NBD --socket
    // override. Preserve them before interpreting any control options.
    if matches!(
        args.first().map(String::as_str),
        Some("attach" | "detach" | "grow")
    ) {
        return privileged_helper(&args);
    }
    let timeout = match take_timeout(&mut args) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let socket = match take_socket(&mut args) {
        Ok(socket) => socket,
        Err(e) => return fail(e),
    };
    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if let Some(socket) = socket {
        return control_by_socket(&argv, socket, timeout);
    }
    match argv.as_slice() {
        // BUG-112: asking for help is not misuse.
        ["--help" | "-h" | "help"] => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        ["--version" | "-V"] => {
            println!("maki {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["volume", "create", config] | ["volume", "create", config, "--discard"] => {
            let raw = match std::fs::read_to_string(config) {
                Ok(raw) => raw,
                Err(e) => return fail(format!("{config}: {e}")),
            };
            let created = if argv.len() == 4 {
                maki_nbdkit::daemon::create_volume_with_discard_from_config_str(&raw)
            } else {
                maki_nbdkit::daemon::create_volume_from_config_str(&raw)
            };
            match created {
                Ok(sb) => {
                    // The superblock does not record the volume name.
                    let name = maki_format::config::parse_config(&raw)
                        .map(|cfg| cfg.volume.name)
                        .unwrap_or_default();
                    println!(
                        "created volume {name} (provider {}, uuid {}, {} bytes virtual, slot size {})",
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
        ["volume", command, ..]
            if matches!(
                *command,
                "witness" | "snapshot" | "takeover" | "restore" | "resume-enrollment" | "gc"
            ) =>
        {
            match remote_volume(&argv[1..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(error),
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
            &ControlTarget::Config(config),
            "status",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["metrics", config] => control(
            &ControlTarget::Config(config),
            "metrics",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["checkpoint", config] => control(
            &ControlTarget::Config(config),
            "checkpoint",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CHECKPOINT_TIMEOUT),
        ),
        ["drain", config] => control(
            &ControlTarget::Config(config),
            "drain",
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(CHECKPOINT_TIMEOUT),
        ),
        ["reload", config, "cache", flags @ ..] => reload_cache(
            &ControlTarget::Config(config),
            flags,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["reload", config, section] => control(
            &ControlTarget::Config(config),
            "reload",
            Some(section),
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        // Retain the existing route when a leading --timeout was removed.
        ["attach", ..] | ["detach", ..] | ["grow", ..] => privileged_helper(&args),
        _ => usage(),
    }
}

fn privileged_helper(args: &[String]) -> ExitCode {
    eprintln!(
        "this operation requires the privileged helper: run `maki-attach {}` \
         (or systemctl start maki-attach@<volume>)",
        args.join(" ")
    );
    ExitCode::from(3)
}

/// The control commands with `--socket <path>` in place of the volume
/// configuration; any other command refuses the option.
fn control_by_socket(argv: &[&str], socket: String, timeout: Option<Duration>) -> ExitCode {
    let target = ControlTarget::Socket(socket);
    let simple = |command: &str, default: Duration| {
        control(
            &target,
            command,
            None,
            serde_json::Value::Null,
            timeout.unwrap_or(default),
        )
    };
    match argv {
        ["status"] => simple("status", CONTROL_TIMEOUT),
        ["metrics"] => simple("metrics", CONTROL_TIMEOUT),
        ["checkpoint"] => simple("checkpoint", CHECKPOINT_TIMEOUT),
        ["drain"] => simple("drain", CHECKPOINT_TIMEOUT),
        ["reload", "cache", flags @ ..] => {
            reload_cache(&target, flags, timeout.unwrap_or(CONTROL_TIMEOUT))
        }
        ["reload", section] => control(
            &target,
            "reload",
            Some(section),
            serde_json::Value::Null,
            timeout.unwrap_or(CONTROL_TIMEOUT),
        ),
        ["status" | "metrics" | "checkpoint" | "drain" | "reload", ..] => {
            fail("pass either a volume configuration or --socket <path>, not both".to_string())
        }
        _ => fail(
            "--socket applies only to the control commands (status, metrics, \
                   checkpoint, drain, reload)"
                .to_string(),
        ),
    }
}

fn reload_cache(target: &ControlTarget<'_>, flags: &[&str], timeout: Duration) -> ExitCode {
    let mut max_bytes = None;
    let mut ttl = None;
    let mut args = flags.iter();
    while let Some(flag) = args.next() {
        if !matches!(*flag, "--max-bytes" | "--ttl") {
            return fail(format!("reload cache: unknown option {flag:?}"));
        }
        let Some(value) = args.next() else {
            return fail(format!("reload cache: {flag} needs a value"));
        };
        match *flag {
            "--max-bytes" => {
                if max_bytes.is_some() {
                    return fail("reload cache: duplicate --max-bytes".into());
                }
                let Ok(value) = value.parse::<u64>() else {
                    return fail(format!("--max-bytes: {value:?} is not an integer"));
                };
                max_bytes = Some(value);
            }
            "--ttl" => {
                if ttl.is_some() {
                    return fail("reload cache: duplicate --ttl".into());
                }
                match value.parse::<maki_format::config::MakiDuration>() {
                    Ok(duration) if !duration.0.is_zero() => ttl = Some(*value),
                    _ => return fail(format!("--ttl: {value:?} is not a positive duration")),
                }
            }
            _ => unreachable!(),
        }
    }
    let Some(max_bytes) = max_bytes else {
        return fail("reload cache needs the new size: maki reload <config> cache --max-bytes <bytes> [--ttl <duration>]".into());
    };
    let mut payload = serde_json::json!({ "max_bytes": max_bytes });
    if let Some(ttl) = ttl {
        payload["ttl"] = serde_json::json!(ttl);
    }
    control(target, "reload", Some("cache"), payload, timeout)
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

fn witness_record(
    rpc: &dyn maki_backing::remote_witness::Rpc,
) -> Result<maki_backing::remote_witness::Record, String> {
    use maki_backing::remote_witness::{Action, Request};
    let record = rpc
        .call(&Request {
            authorization: None,
            operation_id: *uuid::Uuid::new_v4().as_bytes(),
            expected: None,
            action: Action::Inspect,
        })
        .map_err(|e| e.to_string())?;
    record.validate().map_err(|e| e.to_string())?;
    Ok(record)
}

fn approved_hash(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("approved roots must be 64 lower-case hexadecimal characters".into());
    }
    let mut hash = [0; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid approved root")?;
    }
    Ok(hash)
}

fn approved_record(
    rpc: &dyn maki_backing::remote_witness::Rpc,
    fence: &str,
    root: &str,
) -> Result<maki_backing::remote_witness::Record, String> {
    let fence: u64 = fence
        .parse()
        .map_err(|_| "expected fence must be an unsigned integer")?;
    let root = approved_hash(root)?;
    let record = witness_record(rpc)?;
    if record.fence != fence
        || record.current.as_ref().map(|current| current.anchor.root) != Some(root)
    {
        return Err("authority changed or approval does not match its current fence/root; inspect and obtain a new approval".into());
    }
    Ok(record)
}

fn confirm_released(
    rpc: &dyn maki_backing::remote_witness::Rpc,
    before: &maki_backing::remote_witness::Record,
    restored: bool,
) -> Result<maki_backing::remote_witness::Record, String> {
    use maki_backing::remote_witness::Phase;
    let after = witness_record(rpc)?;
    let old = before.current.as_ref().ok_or("uninitialized authority")?;
    let current = after
        .current
        .as_ref()
        .ok_or("authority lost its current descriptor")?;
    if after.identity != before.identity
        || after.phase != Phase::Released
        || Some(after.fence) != before.fence.checked_add(1)
        || Some(current.anchor.generation) != old.anchor.generation.checked_add(u64::from(restored))
        || Some(current.epoch) != old.epoch.checked_add(u64::from(restored))
        || (!restored && current.anchor.root != old.anchor.root)
    {
        return Err("transition or writer release could not be confirmed; inspect authority before proceeding".into());
    }
    Ok(after)
}

const SNAPSHOT_DESCRIPTOR_LIMIT: u64 = 64 * 1024;

fn read_snapshot(
    directory: &std::path::Path,
) -> Result<maki_backing::remote_witness::Descriptor, String> {
    use maki_backing::{Backing, FileBacking};
    if !directory.is_dir() {
        return Err("snapshot directory does not exist".into());
    }
    let disk = FileBacking::new(directory).map_err(|e| e.to_string())?;
    let file = disk
        .open("snapshot.json", false)
        .map_err(|e| e.to_string())?;
    let length = file.len().map_err(|e| e.to_string())?;
    if length == 0 || length > SNAPSHOT_DESCRIPTOR_LIMIT {
        return Err("invalid snapshot descriptor size".into());
    }
    let mut bytes = vec![0; length as usize];
    file.read_at(0, &mut bytes).map_err(|e| e.to_string())?;
    let descriptor: maki_backing::remote_witness::Descriptor =
        serde_json::from_slice(&bytes).map_err(|_| "invalid snapshot descriptor")?;
    descriptor.validate().map_err(|e| e.to_string())?;
    if serde_json::to_vec(&descriptor).map_err(|e| e.to_string())? != bytes
        || file.len().map_err(|e| e.to_string())? != length
    {
        return Err("snapshot descriptor is not canonical or changed while being read".into());
    }
    Ok(descriptor)
}

fn remote_volume(args: &[&str]) -> Result<(), String> {
    use maki_backing::remote_witness::Phase;
    use maki_backing::{Backing, FileBacking, RollbackBacking};
    use std::path::Path;
    #[cfg(not(target_os = "linux"))]
    if args.first() != Some(&"witness") {
        return Err("remote rollback volume operations are supported only on Linux".into());
    }
    let config = args
        .get(1)
        .ok_or("remote volume command requires a configuration file")?;
    let cfg = read_config(config)?;
    let remote = cfg
        .backing
        .rollback_protection
        .as_ref()
        .and_then(|rollback| rollback.remote.as_ref())
        .ok_or("command requires remote rollback protection")?;
    let rpc = maki_nbdkit::daemon::remote_witness_client(remote).map_err(|e| e.to_string())?;
    match args {
        ["witness", _] => {
            println!(
                "{}",
                serde_json::to_string(&witness_record(rpc.as_ref())?).map_err(|e| e.to_string())?
            );
        }
        ["gc", _] => {
            let report =
                RollbackBacking::collect_remote(Path::new(&cfg.backing.root), rpc.as_ref())
                    .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({
                    "removed": report.removed,
                    "skipped_live": report.skipped_live,
                    "skipped_unrecognized": report.skipped_unrecognized,
                    "retained": report.retained,
                })
            );
        }
        ["resume-enrollment", _, fence, identity]
        | ["resume-enrollment", _, fence, identity, "--discard"] => {
            let fence: u64 = fence
                .parse()
                .map_err(|_| "approved fence must be an unsigned integer")?;
            let identity = uuid::Uuid::parse_str(identity)
                .map_err(|_| "approved storage identity must be a UUID")?;
            if identity.is_nil() {
                return Err("approved storage identity must be nonzero".into());
            }
            let before = witness_record(rpc.as_ref())?;
            if before.identity != *identity.as_bytes()
                || before.fence != fence
                || before.current.is_some()
            {
                return Err(
                    "enrollment approval does not match a never-activated authority".into(),
                );
            }
            maki_nbdkit::daemon::resume_enrollment_from_config(
                &cfg,
                rpc.clone(),
                &before,
                args.len() == 5,
            )
            .map_err(|e| e.to_string())?;
            let after = witness_record(rpc.as_ref())?;
            if after.identity != before.identity
                || Some(after.fence) != before.fence.checked_add(1)
                || after.phase != Phase::Released
                || after.current.is_none()
            {
                return Err("enrollment initialized but writer release could not be confirmed; inspect authority before proceeding".into());
            }
            println!(
                "{}",
                serde_json::to_string(&after).map_err(|e| e.to_string())?
            );
        }
        ["snapshot", _, directory] => {
            let target = Path::new(directory);
            let backing = RollbackBacking::open_remote(Path::new(&cfg.backing.root), rpc.clone())
                .map_err(|e| e.to_string())?;
            let descriptor = backing.snapshot_remote(target).map_err(|e| e.to_string())?;
            let bytes = serde_json::to_vec(&descriptor).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > SNAPSHOT_DESCRIPTOR_LIMIT {
                return Err("snapshot descriptor exceeds bound".into());
            }
            let disk = FileBacking::new(target).map_err(|e| e.to_string())?;
            let _lock = disk.try_lock("snapshot.lock").map_err(|e| e.to_string())?;
            if disk.exists("snapshot.json").map_err(|e| e.to_string())? {
                return Err("snapshot descriptor already exists".into());
            }
            let file = disk
                .open("snapshot.json", true)
                .map_err(|e| e.to_string())?;
            file.write_at(0, &bytes).map_err(|e| e.to_string())?;
            file.set_len(bytes.len() as u64)
                .map_err(|e| e.to_string())?;
            file.sync_data().map_err(|e| e.to_string())?;
            disk.sync_dir("").map_err(|e| e.to_string())?;
            drop(backing);
            let released = witness_record(rpc.as_ref())?;
            if released.phase != Phase::Released || released.current.as_ref() != Some(&descriptor) {
                return Err("snapshot was copied but writer release could not be confirmed".into());
            }
            println!(
                "{}",
                serde_json::to_string(&descriptor).map_err(|e| e.to_string())?
            );
        }
        ["takeover", _, fence, root] => {
            let before = approved_record(rpc.as_ref(), fence, root)?;
            let backing = RollbackBacking::takeover_remote(
                Path::new(&cfg.backing.root),
                rpc.clone(),
                &before,
            )
            .map_err(|e| e.to_string())?;
            drop(backing);
            let record = confirm_released(rpc.as_ref(), &before, false)?;
            println!(
                "{}",
                serde_json::to_string(&record).map_err(|e| e.to_string())?
            );
        }
        ["restore", _, directory, fence, root, approved_source] => {
            let approved_source = approved_hash(approved_source)?;
            let source = read_snapshot(Path::new(directory))?;
            if source.anchor.root != approved_source {
                return Err("snapshot root does not match the independently approved root".into());
            }
            let before = approved_record(rpc.as_ref(), fence, root)?;
            let backing = RollbackBacking::restore_remote(
                Path::new(&cfg.backing.root),
                Path::new(directory),
                &source,
                rpc.clone(),
                &before,
            )
            .map_err(|e| e.to_string())?;
            drop(backing);
            let record = confirm_released(rpc.as_ref(), &before, true)?;
            println!(
                "{}",
                serde_json::to_string(&record).map_err(|e| e.to_string())?
            );
        }
        _ => return Err("invalid remote volume command arguments; see maki usage".into()),
    }
    Ok(())
}

fn existing_backing(
    cfg: &maki_format::config::VolumeConfig,
) -> Result<std::sync::Arc<dyn maki_backing::Backing>, String> {
    // Opening a remote RollbackBacking claims a writer and forks a namespace.
    // Diagnostic commands must not mutate the authority, even if they fail or
    // are killed before Drop can release that session.
    if cfg
        .backing
        .rollback_protection
        .as_ref()
        .is_some_and(|r| r.remote.is_some())
    {
        return Err("read-only remote backing inspection is not supported; use `maki volume witness` to inspect the authority without claiming a writer".into());
    }
    let root = std::path::Path::new(&cfg.backing.root);
    match std::fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(format!("{}: not a directory", root.display())),
        Err(error) => return Err(format!("{}: {error}", root.display())),
    }
    maki_nbdkit::daemon::build_backing(cfg).map_err(|error| error.to_string())
}

fn inspect(config: &str) -> Result<(), String> {
    let cfg = read_config(config)?;
    let backing = existing_backing(&cfg)?;
    let envelope = maki_format::superblock::load_volume_superblock(backing.as_ref())
        .map_err(|e| e.to_string())?;
    let sb = envelope.superblock;
    println!("volume:        {}", cfg.volume.name);
    println!("uuid:          {}", sb.volume_uuid);
    println!("provider:      {}", sb.provider_type);
    println!("compatibility: {}", sb.crypto_compatibility_id);
    println!("virtual size:  {}", sb.geometry.max_virtual_size);
    println!("unit size:     {}", sb.geometry.crypto_unit_size);
    println!("slot size:     {}", sb.geometry.slot_size);
    println!("generation:    {}", sb.generation);
    println!("metadata envelope: {}", envelope.metadata_version);
    let plan = sb.geometry.capacity_plan().map_err(|e| e.to_string())?;
    println!("maximum units:             {}", plan.num_units);
    println!("maximum shards:            {}", plan.num_shards);
    println!("full slot span bytes:      {}", plan.full_slot_span_bytes);
    println!("allocation map A/B bytes: {}", plan.allocation_map_ab_bytes);
    println!(
        "discard map A/B bytes:    {}",
        if envelope.metadata_version == maki_format::superblock::SUPERBLOCK_VERSION_V3 {
            plan.allocation_map_ab_bytes
        } else {
            0
        }
    );
    println!("catalog A/B bytes:        {}", plan.catalog_ab_bytes);
    Ok(())
}

fn check(config: &str, deep: bool) -> Result<bool, String> {
    let cfg = read_config(config)?;
    let backing = existing_backing(&cfg)?;
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
    target: &ControlTarget<'_>,
    command: &str,
    section: Option<&str>,
    payload: serde_json::Value,
    timeout: Duration,
) -> ExitCode {
    let socket = match target.socket() {
        Ok(socket) => socket,
        Err(e) => return fail(e),
    };
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
    _target: &ControlTarget<'_>,
    _command: &str,
    _section: Option<&str>,
    _payload: serde_json::Value,
    _timeout: Duration,
) -> ExitCode {
    fail("control socket commands require a Unix host".to_string())
}
