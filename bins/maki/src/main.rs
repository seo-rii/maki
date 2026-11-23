//! `maki` — administrative CLI (SPEC §7).
//!
//! Volume lifecycle (`volume create/inspect`, `check`) works everywhere;
//! runtime commands (`status`, `metrics`, `checkpoint`, `drain`, `reload`) talk to
//! the daemon control socket (Unix). `attach`/`detach`/`grow` are not run
//! here: `maki` prints the command for the privileged helper `maki-attach`
//! and exits 3.

// Output goes through `diagnostic!` and the stdout helpers below: the
// `print!` family panics when a write fails (a closed pipe, a full disk),
// which replaces the exit status with 101.
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::io::{self, Write};
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
    --socket /run/maki-control/<volume>/control.sock for maki-admin members,
    and --timeout <seconds> (default 60; 600 for checkpoint and drain)
  maki attach|detach|grow ...          not run here: prints the privileged maki-attach command to run (exit 3)
  maki --help | --version";

/// `eprintln!` that cannot panic. The macro panics when the write fails,
/// and stderr can be a pipe whose reader has gone: the panic would replace
/// the command's exit status with 101. A diagnostic that cannot be
/// delivered is dropped instead.
macro_rules! diagnostic {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), $($arg)*);
    }};
}

/// Misuse: the usage on stderr, status 2.
fn usage() -> ExitCode {
    diagnostic!("{USAGE}");
    ExitCode::from(2)
}

/// Misuse with its reason: an option or argument the command cannot use,
/// refused before anything is read or contacted. Status 2, like [`usage`];
/// a command that fails exits 1 ([`fail`]).
fn misuse(message: String) -> ExitCode {
    diagnostic!("error: {message}");
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

/// Print the result of a command that produces nothing else: output that
/// could not be written is its failure.
fn print_result(text: &str) -> Result<(), String> {
    print_stdout(text).map_err(|error| format!("writing the output failed: {error}"))
}

/// The exit status of a command that completes or reports one error.
fn finish(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(error),
    }
}

/// Read a volume configuration through the checked reader: the file decides
/// where plaintext and credentials go, so one another user could write or
/// substitute is refused before it is parsed (SPEC §8).
fn read_config_text(path: &std::path::Path) -> Result<String, String> {
    maki_nbdkit::config_file::read_volume_config(path)
        .map_err(|error| format!("{}: {error}", path.display()))
}

fn read_config(
    path: impl AsRef<std::path::Path>,
) -> Result<maki_format::config::VolumeConfig, String> {
    let path = path.as_ref();
    let raw = read_config_text(path)?;
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

/// The commands that take `--timeout`: the control commands, which bound
/// their round trip with it, and the helper verbs, whose delegation route
/// keeps a leading `--timeout` out of the printed `maki-attach` command.
const TIMEOUT_COMMANDS: [&str; 8] = [
    "status",
    "metrics",
    "checkpoint",
    "drain",
    "reload",
    "attach",
    "detach",
    "grow",
];

/// The command word: the first argument that is neither `--timeout` nor
/// `--socket` nor the value after one of them.
fn command_word(args: &[String]) -> Option<&str> {
    let mut args = args.iter().map(String::as_str);
    while let Some(arg) = args.next() {
        if !matches!(arg, "--timeout" | "--socket") {
            return Some(arg);
        }
        args.next();
    }
    None
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
    /// the running daemon. It is still read through the checked reader: a
    /// substituted file would send the command to another listener.
    fn socket(&self) -> Result<String, String> {
        match self {
            Self::Socket(path) => Ok(path.clone()),
            Self::Config(config) => {
                let path = std::path::Path::new(config);
                let raw = maki_nbdkit::config_file::read_volume_config(path).map_err(|e| {
                    if e.is_access_denied() {
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
        diagnostic!("warning: cannot raise the open-file soft limit: {e}");
    }
    let raw_args: Vec<_> = std::env::args_os().skip(1).collect();
    if let [volume, verb, config] = raw_args.as_slice() {
        if volume == "volume" && verb == "inspect" && config != "--socket" && config != "--timeout"
        {
            return match inspect(std::path::Path::new(config)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => fail(error),
            };
        }
    }
    let Ok(mut args) = raw_args
        .into_iter()
        .map(std::ffi::OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    else {
        diagnostic!("error: command-line arguments must be valid UTF-8");
        return ExitCode::from(2);
    };
    // Helper options belong to the helper, including its NBD --socket
    // override. Preserve them before interpreting any control options.
    if matches!(
        args.first().map(String::as_str),
        Some("attach" | "detach" | "grow")
    ) {
        return privileged_helper(&args);
    }
    // A command outside `TIMEOUT_COMMANDS` refuses `--timeout` as misuse,
    // whatever its value, rather than ignoring it.
    if args.iter().any(|arg| arg == "--timeout")
        && !command_word(&args).is_some_and(|command| TIMEOUT_COMMANDS.contains(&command))
    {
        return usage();
    }
    let timeout = match take_timeout(&mut args) {
        Ok(t) => t,
        Err(e) => return misuse(e),
    };
    // A leading --timeout can expose a helper verb. Route it before
    // interpreting the helper's NBD socket as a control socket.
    if matches!(
        args.first().map(String::as_str),
        Some("attach" | "detach" | "grow")
    ) {
        return privileged_helper(&args);
    }
    let socket = match take_socket(&mut args) {
        Ok(socket) => socket,
        Err(e) => return misuse(e),
    };
    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if let Some(socket) = socket {
        return control_by_socket(&argv, socket, timeout);
    }
    match argv.as_slice() {
        // BUG-112: asking for help is not misuse.
        ["--help" | "-h" | "help"] => finish(print_result(&format!("{USAGE}\n"))),
        ["--version" | "-V"] => finish(print_result(&format!(
            "maki {}\n",
            env!("CARGO_PKG_VERSION")
        ))),
        ["volume", "create", config] | ["volume", "create", config, "--discard"] => {
            let raw = match read_config_text(std::path::Path::new(config)) {
                Ok(raw) => raw,
                Err(e) => return fail(e),
            };
            let creation = match maki_nbdkit::daemon::VolumeCreationConfig::parse(&raw) {
                Ok(creation) => creation,
                Err(error) => return fail(error.to_string()),
            };
            match creation.create(argv.len() == 4) {
                Ok(sb) => {
                    let cfg = creation.config();
                    let name = &cfg.volume.name;
                    // Creation is already durable. Report output errors without
                    // making callers retry a successfully initialized volume.
                    let summary = writeln!(
                        io::stdout().lock(),
                        "created volume {name} (provider {}, uuid {}, {} bytes virtual, slot size {})",
                        sb.provider_type,
                        sb.volume_uuid,
                        sb.geometry.max_virtual_size,
                        sb.geometry.slot_size
                    );
                    if let Err(error) = summary {
                        if error.kind() != io::ErrorKind::BrokenPipe {
                            let _ = writeln!(
                                io::stderr().lock(),
                                "warning: volume {name} was created, but writing the creation summary failed: {error}"
                            );
                        }
                    }
                    if let Some(hint) = ownership_hint(running_as_root(), cfg) {
                        let _ = writeln!(io::stderr().lock(), "warning: {hint}");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => fail(e.to_string()),
            }
        }
        ["volume", verb, config, tail @ ..] => {
            // A malformed approval is misuse, refused before the
            // configuration is read.
            let command = match (*verb, tail) {
                ("witness", []) => Ok(RemoteVolume::Witness),
                ("gc", []) => Ok(RemoteVolume::Gc),
                ("snapshot", [directory]) => Ok(RemoteVolume::Snapshot { directory }),
                ("resume-enrollment", [fence, identity] | [fence, identity, "--discard"]) => {
                    enrollment_approval(fence, identity).map(|(fence, identity)| {
                        RemoteVolume::ResumeEnrollment {
                            fence,
                            identity,
                            discard: tail.len() == 3,
                        }
                    })
                }
                ("takeover", [fence, root]) => {
                    Approval::parse(fence, root).map(|approval| RemoteVolume::Takeover { approval })
                }
                ("restore", [directory, fence, root, approved_source]) => {
                    Approval::parse(fence, root).and_then(|approval| {
                        Ok(RemoteVolume::Restore {
                            directory,
                            approval,
                            approved_source: approved_hash(approved_source)?,
                        })
                    })
                }
                _ => return usage(),
            };
            let command = match command {
                Ok(command) => command,
                Err(error) => return misuse(error),
            };
            let inspects = matches!(command, RemoteVolume::Witness);
            match remote_volume(config, command) {
                // `witness` only reports.
                Ok(record) if inspects => finish(print_result(&record)),
                // The others have changed the authority or the backing by
                // now, and most refuse a retry with the same approval. Like
                // `volume create`, they report an output error and succeed.
                Ok(record) => {
                    if let Err(error) = print_stdout(&record) {
                        let _ = writeln!(
                            io::stderr().lock(),
                            "warning: volume {verb} completed, but writing its result failed: {error}"
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error),
            }
        }
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
        _ => usage(),
    }
}

fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_+-.,/@%:=".contains(&b))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn privileged_helper(args: &[String]) -> ExitCode {
    let command = args
        .iter()
        .map(|arg| shell_word(arg))
        .collect::<Vec<_>>()
        .join(" ");
    diagnostic!("this operation requires the privileged helper: run `maki-attach {command}`");
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
            misuse("pass either a volume configuration or --socket <path>, not both".to_string())
        }
        _ => misuse(
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
            return misuse(format!("reload cache: unknown option {flag:?}"));
        }
        let Some(value) = args.next() else {
            return misuse(format!("reload cache: {flag} needs a value"));
        };
        match *flag {
            "--max-bytes" => {
                if max_bytes.is_some() {
                    return misuse("reload cache: duplicate --max-bytes".into());
                }
                let Ok(value) = value.parse::<u64>() else {
                    return misuse(format!("--max-bytes: {value:?} is not an integer"));
                };
                max_bytes = Some(value);
            }
            "--ttl" => {
                if ttl.is_some() {
                    return misuse("reload cache: duplicate --ttl".into());
                }
                match value.parse::<maki_format::config::MakiDuration>() {
                    Ok(duration) if !duration.0.is_zero() => ttl = Some(*value),
                    _ => return misuse(format!("--ttl: {value:?} is not a positive duration")),
                }
            }
            _ => unreachable!(),
        }
    }
    let Some(max_bytes) = max_bytes else {
        return misuse("reload cache needs the new size: maki reload <config> cache --max-bytes <bytes> [--ttl <duration>]".into());
    };
    let mut payload = serde_json::json!({ "max_bytes": max_bytes });
    if let Some(ttl) = ttl {
        payload["ttl"] = serde_json::json!(ttl);
    }
    control(target, "reload", Some("cache"), payload, timeout)
}

/// The backing tree is created owner-only, and a root-owned entry in it is
/// unreadable to the `maki` daemon user (SPEC 8: `maki:maki 0700`). Root
/// creates each file and directory for the owner of the directory it creates
/// it in, so what it leaves root-owned is a backing root or local rollback
/// witness directory that root owns, such as one that did not exist and the
/// command had to create, and everything below one. Name each path that
/// holds such an entry.
fn ownership_hint(as_root: bool, cfg: &maki_format::config::VolumeConfig) -> Option<String> {
    if !as_root {
        return None;
    }
    let local_witness = cfg
        .backing
        .rollback_protection
        .as_ref()
        .filter(|rollback| rollback.remote.is_none() && !rollback.witness_root.is_empty())
        .map(|rollback| rollback.witness_root.as_str());
    let held: Vec<(&str, &str)> = [("the volume tree", cfg.backing.root.as_str())]
        .into_iter()
        .chain(local_witness.map(|witness| ("the rollback witness in", witness)))
        .filter(|(_, path)| holds_root_owned_entry(std::path::Path::new(path)))
        .collect();
    if held.is_empty() {
        return None;
    }
    let named: Vec<String> = held
        .iter()
        .map(|(what, path)| format!("{what} {path}"))
        .collect();
    let arguments: Vec<String> = held.iter().map(|(_, path)| shell_word(path)).collect();
    Some(format!(
        "{} {} entries created owner-only by root; the daemon runs as the maki user and \
         cannot open them. Run `maki volume create` as that user (sudo -u maki ...) or \
         `chown -R maki:maki {}` before starting the service",
        named.join(" and "),
        if held.len() == 1 { "holds" } else { "hold" },
        arguments.join(" ")
    ))
}

/// Whether `path` or anything below it is owned by root. An entry that
/// cannot be described counts, so the warning errs towards a hand-back.
#[cfg(unix)]
fn holds_root_owned_entry(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return true;
    };
    if metadata.uid() == 0 {
        return true;
    }
    if !metadata.is_dir() {
        return false;
    }
    match std::fs::read_dir(path) {
        Ok(mut entries) => entries.any(|entry| match entry {
            Ok(entry) => holds_root_owned_entry(&entry.path()),
            Err(_) => true,
        }),
        Err(_) => true,
    }
}

#[cfg(not(unix))]
fn holds_root_owned_entry(_path: &std::path::Path) -> bool {
    true
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
    diagnostic!("error: {message}");
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

/// The fence and current root an administrator approved for a takeover or
/// a restore.
struct Approval {
    fence: u64,
    root: [u8; 32],
}

impl Approval {
    fn parse(fence: &str, root: &str) -> Result<Self, String> {
        Ok(Self {
            fence: fence
                .parse()
                .map_err(|_| "expected fence must be an unsigned integer")?,
            root: approved_hash(root)?,
        })
    }
}

/// The fence and storage identity of the never-activated authority that
/// `resume-enrollment` is approved for.
fn enrollment_approval(fence: &str, identity: &str) -> Result<(u64, uuid::Uuid), String> {
    let fence = fence
        .parse()
        .map_err(|_| "approved fence must be an unsigned integer")?;
    let identity =
        uuid::Uuid::parse_str(identity).map_err(|_| "approved storage identity must be a UUID")?;
    if identity.is_nil() {
        return Err("approved storage identity must be nonzero".into());
    }
    Ok((fence, identity))
}

fn approved_record(
    rpc: &dyn maki_backing::remote_witness::Rpc,
    approval: &Approval,
) -> Result<maki_backing::remote_witness::Record, String> {
    let record = witness_record(rpc)?;
    if record.fence != approval.fence
        || record.current.as_ref().map(|current| current.anchor.root) != Some(approval.root)
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
    // Restore only reads the snapshot, which may be kept on read-only media.
    let disk = FileBacking::read_only(directory).map_err(|e| e.to_string())?;
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

enum RemoteVolume<'a> {
    Witness,
    Gc,
    Snapshot {
        directory: &'a str,
    },
    Takeover {
        approval: Approval,
    },
    Restore {
        directory: &'a str,
        approval: Approval,
        approved_source: [u8; 32],
    },
    ResumeEnrollment {
        fence: u64,
        identity: uuid::Uuid,
        discard: bool,
    },
}

/// Run a remote-volume command and return the line it reports: the
/// authority's record, the snapshot descriptor or the collection report.
fn remote_volume(config: &str, command: RemoteVolume<'_>) -> Result<String, String> {
    use maki_backing::remote_witness::Phase;
    use maki_backing::{Backing, FileBacking, RollbackBacking};
    use std::path::Path;
    #[cfg(not(target_os = "linux"))]
    if !matches!(command, RemoteVolume::Witness) {
        return Err("remote rollback volume operations are supported only on Linux".into());
    }
    let cfg = read_config(config)?;
    let remote = cfg
        .backing
        .rollback_protection
        .as_ref()
        .and_then(|rollback| rollback.remote.as_ref())
        .ok_or("command requires remote rollback protection")?;
    let rpc = maki_nbdkit::daemon::remote_witness_client(remote).map_err(|e| e.to_string())?;
    let mut line = match command {
        RemoteVolume::Witness => {
            serde_json::to_string(&witness_record(rpc.as_ref())?).map_err(|e| e.to_string())?
        }
        RemoteVolume::Gc => {
            let report =
                RollbackBacking::collect_remote(Path::new(&cfg.backing.root), rpc.as_ref())
                    .map_err(|e| e.to_string())?;
            serde_json::json!({
                "removed": report.removed,
                "skipped_live": report.skipped_live,
                "skipped_unrecognized": report.skipped_unrecognized,
                "skipped_unreadable": report.skipped_unreadable,
                "retained": report.retained,
                "counts": report.counts,
                "details_truncated": report.details_truncated,
            })
            .to_string()
        }
        RemoteVolume::ResumeEnrollment {
            fence,
            identity,
            discard,
        } => {
            // Initialization records the provider in the new superblock.
            // Refuse one this build cannot construct before asking the
            // authority anything (M-008).
            maki_nbdkit::daemon::check_provider_compiled(&cfg).map_err(|e| e.to_string())?;
            let before = witness_record(rpc.as_ref())?;
            if before.identity != *identity.as_bytes()
                || before.fence != fence
                || before.current.is_some()
            {
                return Err(
                    "enrollment approval does not match a never-activated authority".into(),
                );
            }
            maki_nbdkit::daemon::resume_enrollment_from_config(&cfg, rpc.clone(), &before, discard)
                .map_err(|e| e.to_string())?;
            let after = witness_record(rpc.as_ref())?;
            if after.identity != before.identity
                || Some(after.fence) != before.fence.checked_add(1)
                || after.phase != Phase::Released
                || after.current.is_none()
            {
                return Err("enrollment initialized but writer release could not be confirmed; inspect authority before proceeding".into());
            }
            serde_json::to_string(&after).map_err(|e| e.to_string())?
        }
        RemoteVolume::Snapshot { directory } => {
            let target = Path::new(directory);
            RollbackBacking::check_snapshot_destination(target).map_err(|e| e.to_string())?;
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
            serde_json::to_string(&descriptor).map_err(|e| e.to_string())?
        }
        RemoteVolume::Takeover { approval } => {
            let before = approved_record(rpc.as_ref(), &approval)?;
            let backing = RollbackBacking::takeover_remote(
                Path::new(&cfg.backing.root),
                rpc.clone(),
                &before,
            )
            .map_err(|e| e.to_string())?;
            drop(backing);
            let record = confirm_released(rpc.as_ref(), &before, false)?;
            serde_json::to_string(&record).map_err(|e| e.to_string())?
        }
        RemoteVolume::Restore {
            directory,
            approval,
            approved_source,
        } => {
            let source = read_snapshot(Path::new(directory))?;
            if source.anchor.root != approved_source {
                return Err("snapshot root does not match the independently approved root".into());
            }
            let before = approved_record(rpc.as_ref(), &approval)?;
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
            serde_json::to_string(&record).map_err(|e| e.to_string())?
        }
    };
    line.push('\n');
    Ok(line)
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

fn inspect(config: &std::path::Path) -> Result<(), String> {
    let cfg = read_config(config)?;
    let backing = existing_backing(&cfg)?;
    let envelope = maki_format::superblock::load_volume_superblock(backing.as_ref())
        .map_err(|e| e.to_string())?;
    let sb = envelope.superblock;
    let mut text = format!(
        "volume:        {}\n\
         uuid:          {}\n\
         provider:      {}\n\
         compatibility: {}\n\
         virtual size:  {}\n\
         unit size:     {}\n\
         slot size:     {}\n\
         generation:    {}\n\
         metadata envelope: {}\n",
        cfg.volume.name,
        sb.volume_uuid,
        sb.provider_type,
        sb.crypto_compatibility_id,
        sb.geometry.max_virtual_size,
        sb.geometry.crypto_unit_size,
        sb.geometry.slot_size,
        sb.generation,
        envelope.metadata_version,
    );
    let plan = match sb.geometry.capacity_plan() {
        Ok(plan) => plan,
        Err(error) => {
            // What the superblock says is still shown before the error.
            print_result(&text)?;
            return Err(error.to_string());
        }
    };
    text += &format!(
        "maximum units:             {}\n\
         maximum shards:            {}\n\
         full slot span bytes:      {}\n\
         allocation map A/B bytes: {}\n\
         discard map A/B bytes:    {}\n\
         catalog A/B bytes:        {}\n",
        plan.num_units,
        plan.num_shards,
        plan.full_slot_span_bytes,
        plan.allocation_map_ab_bytes,
        if envelope.metadata_version == maki_format::superblock::SUPERBLOCK_VERSION_V3 {
            plan.allocation_map_ab_bytes
        } else {
            0
        },
        plan.catalog_ab_bytes,
    );
    print_result(&text)
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
    // A reader that has gone leaves the verdict to the exit status. A report
    // that could not be written is an error, which still names the verdict.
    print_stdout(&text)
        .map_err(|error| format!("check {verdict}, but writing the report failed: {error}"))?;
    Ok(report.ok())
}

#[cfg(unix)]
async fn within_control_timeout<T>(
    timeout: Duration,
    round_trip: impl std::future::Future<Output = T>,
) -> Option<T> {
    let started = tokio::time::Instant::now();
    let result = tokio::time::timeout(timeout, round_trip).await.ok()?;
    // Tokio can poll a ready reply first when the CLI resumes after its timer.
    (started.elapsed() < timeout).then_some(result)
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
        let (rd, mut wr) = tokio::io::split(stream);
        let mut rd = tokio::io::BufReader::new(rd);
        let mut request = maki_control::protocol::Request::new(command);
        request.section = section.map(|s| s.to_string());
        request.payload = payload;
        maki_control::protocol::send_command(&mut wr, &request)
            .await
            .map_err(|e| e.to_string())?;
        maki_control::protocol::read_buffered_response(&mut rd)
            .await
            .map_err(|e| e.to_string())
    };
    let result: Result<serde_json::Value, String> = runtime.block_on(async {
        match within_control_timeout(timeout, round_trip).await {
            Some(result) => result,
            None => Err(format!(
                "{command}: no response from {socket} within {}s; the daemon may be stalled \
                 (pass --timeout <seconds> to wait longer)",
                timeout.as_secs()
            )),
        }
    });
    match result {
        Ok(v) => {
            let ok = v["ok"] == serde_json::Value::Bool(true);
            let mut out = io::stdout().lock();
            let written = serde_json::to_writer_pretty(&mut out, &v)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(out))
                .and_then(|()| out.flush());
            if let Err(error) = written {
                if error.kind() != io::ErrorKind::BrokenPipe {
                    let verdict = if ok { "success" } else { "failure" };
                    let _ = writeln!(io::stderr().lock(),
                        "{command}: daemon reported {verdict}, but writing the response failed: {error}");
                    return ExitCode::FAILURE;
                }
            }
            if ok {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_response_after_the_control_deadline_is_rejected() {
        let timeout = Duration::from_millis(5);
        let response = within_control_timeout(timeout, async {
            // The reply and timer are both ready before the executor regains control.
            std::thread::sleep(timeout * 2);
            "reply"
        })
        .await;
        assert_eq!(response, None);
    }
}
