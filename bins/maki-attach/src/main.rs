//! `maki-attach` — the privileged one-shot helper (SPEC §6).
//!
//! Attach parameters come from the root-owned configuration
//! `/etc/maki/attach/<volume>.toml` (review M-016), optionally overridden
//! on the command line; every value is hygiene-checked before it reaches a
//! system utility. Plans are printed for audit; execution runs on Linux
//! only, with NBD device allocation, mount-identity verification and
//! reverse rollback on failure.

// Output goes through `diagnostic!` and the stdout helpers below: the
// `print!` family panics when a write fails (a closed pipe, a full disk),
// which replaces the exit status with 101.
#![deny(clippy::print_stdout, clippy::print_stderr)]

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use maki_privileged::config::{self, AttachConfig, AttachOverrides};
use maki_privileged::plan::{
    plan_attach, plan_detach, plan_grow, AttachRequest, GrowRequest, Plan,
};

mod failed_start;

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

const USAGE: &str = "usage:
  maki-attach attach --volume <v> [--config <attach.toml>] [--nbd-device /dev/nbdN]
                     [--vg <vg>] [--lv <lv>] [--mountpoint <dir>] [--socket <path>]
                     [--uuid <volume-uuid>] [--fs-uuid <xfs-uuid>] [--init-sentinel] [--plan]
  maki-attach detach --volume <v> [...]
  maki-attach recover --volume <v> [...] (disconnected storage only; stop workloads first)
  maki-attach cleanup --volume <v> [...] (record-driven detach or recovery; stop workloads first)
  maki-attach recover-failed-start --volume <v> [--plan] (systemd ExecStopPost hook)
  maki-attach verify --volume <v> [--config <attach.toml>] [--plan]
  maki-attach grow   --volume <v> --size-bytes <n> [...]
  maki-attach nbd-connect --nbd-device /dev/nbdN --socket <path> --identifier <id>
                     [--block-size <n>] [--plan] (provisioning: outside any attachment)
  maki-attach nbd-disconnect --nbd-device /dev/nbdN --identifier <id> [--plan]
  maki-attach --help | --version

Without --config, /etc/maki/attach/<v>.toml is read when it exists. Execution
requires the volume UUID (config or --uuid); --plan prints the plan without it.";

/// Misuse: the usage on stderr, status 2.
fn usage() -> ExitCode {
    diagnostic!("{USAGE}");
    ExitCode::from(2)
}

/// Write `text` to stdout and flush it.
///
/// `print!` panics when the write fails, and the panic replaces the
/// helper's exit status with 101. A reader that has gone (`| head -3`) has
/// what it wanted, so a closed pipe is not an error; any other failure is
/// returned for the caller to report.
fn print_stdout(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(error),
        _ => Ok(()),
    }
}

/// Print a `--plan` preview, which is all that such a run produces: a plan
/// that could not be written is its failure.
fn print_plan(text: &str) -> Result<(), String> {
    print_stdout(text).map_err(|error| format!("writing the plan failed: {error}"))
}

fn flag_value<'a>(args: &'a [OsString], name: &str) -> Option<&'a OsStr> {
    let index = args.iter().position(|argument| argument == name)?;
    args.get(index + 1).map(OsString::as_os_str)
}

fn flag(args: &[OsString], name: &str) -> Option<String> {
    flag_value(args, name)?.to_str().map(str::to_owned)
}

/// Validate the complete command before reading configuration or printing a
/// plan. Missing values, duplicates and flags belonging to another verb are
/// usage errors; an omitted flag alone may select a default.
fn validate_arguments(args: &[OsString]) -> Result<(), String> {
    let verb = args
        .first()
        .ok_or("missing command")?
        .to_str()
        .ok_or("command must be valid UTF-8")?;
    if !matches!(
        verb,
        "attach" | "detach" | "recover" | "cleanup" | "grow" | "verify" | "recover-failed-start"
    ) {
        return Err(format!("unknown command {verb:?}"));
    }
    let mut seen = std::collections::HashSet::new();
    let mut arguments = args.iter().skip(1);
    while let Some(argument) = arguments.next() {
        let argument = argument.to_str().ok_or("option must be valid UTF-8")?;
        if !seen.insert(argument) {
            return Err(format!("duplicate option {argument}"));
        }
        let takes_value = match argument {
            "--volume" => true,
            "--config" if verb != "recover-failed-start" => true,
            "--plan" => false,
            "--init-sentinel" if verb == "attach" => false,
            "--size-bytes" if verb == "grow" => true,
            // The former relative option is refused with its reason: a retry
            // after a partial failure could not tell whether its increase
            // had already been applied.
            "--add-bytes" if verb == "grow" => {
                return Err("relative growth is unsupported; use --size-bytes with the \
                            absolute desired LV size and reuse it on retry"
                    .into());
            }
            "--nbd-device" | "--vg" | "--lv" | "--mountpoint" | "--socket" | "--uuid"
            | "--fs-uuid"
                if !matches!(verb, "verify" | "recover-failed-start") =>
            {
                true
            }
            _ => return Err(format!("unsupported argument {argument:?} for {verb}")),
        };
        if takes_value {
            let value = arguments
                .next()
                .filter(|value| !value.as_encoded_bytes().starts_with(b"-"))
                .ok_or_else(|| format!("missing value for {argument}"))?;
            if argument == "--config" {
                // Only syntax is checked through this display view. The filesystem
                // receives the original OS pathname, including non-Unicode bytes.
                config::check_argument(argument, &value.to_string_lossy())
            } else {
                let value = value.to_str().ok_or("option value must be valid UTF-8")?;
                config::check_argument(argument, value).and_then(|()| match argument {
                    // The name selects the configuration, the attachment
                    // state and the units: a malformed one is misuse, refused
                    // before any of them is read.
                    "--volume" if matches!(verb, "attach" | "verify") => {
                        config::check_volume_name(value)
                    }
                    "--volume" => config::check_instance_name(value),
                    _ => Ok(()),
                })
            }
            .map_err(|error| error.to_string())?;
        }
    }
    if !seen.contains("--volume") {
        return Err("missing --volume".into());
    }
    if verb == "grow" && !seen.contains("--size-bytes") {
        return Err("missing --size-bytes".into());
    }
    Ok(())
}

/// What `nbd-connect` and `nbd-disconnect` act on.
struct RawConnection {
    device: String,
    identifier: String,
    /// `nbd-connect` only.
    socket: Option<String>,
    block_size: u32,
    plan_only: bool,
}

/// The options of `nbd-connect` (`connect`) or `nbd-disconnect`: misuse is
/// a usage error, and a value these verbs must not take is refused.
fn raw_connection(args: &[OsString], connect: bool) -> Result<RawConnection, Refusal> {
    let mut seen = std::collections::HashSet::new();
    let mut values = std::collections::HashMap::new();
    let mut arguments = args.iter();
    while let Some(argument) = arguments.next() {
        let argument = argument.to_str().ok_or(Refusal::Usage)?;
        if !seen.insert(argument) {
            return Err(Refusal::Usage);
        }
        match argument {
            "--plan" => continue,
            "--nbd-device" | "--identifier" => {}
            "--socket" | "--block-size" if connect => {}
            _ => return Err(Refusal::Usage),
        }
        let value = arguments
            .next()
            .and_then(|value| value.to_str())
            .filter(|value| !value.starts_with('-'))
            .ok_or(Refusal::Usage)?;
        values.insert(argument, value.to_string());
    }
    let mut take = |name: &str| values.remove(name).ok_or(Refusal::Usage);
    let device = take("--nbd-device")?;
    let identifier = take("--identifier")?;
    let socket = if connect {
        Some(take("--socket")?)
    } else {
        None
    };
    let invalid = |error: config::ConfigError| Refusal::Invalid(error.to_string());
    if maki_privileged::probe::nbd_index(&device).is_none() {
        return Err(Refusal::Invalid(format!(
            "--nbd-device {device:?} is not a canonical /dev/nbdN"
        )));
    }
    config::check_raw_identifier(&identifier).map_err(invalid)?;
    if let Some(socket) = &socket {
        config::check_abs_path("--socket", socket).map_err(invalid)?;
    }
    let block_size = match values.remove("--block-size") {
        None => 4096,
        // Plain decimal digits only, as --size-bytes takes them.
        Some(text) => text
            .parse::<u32>()
            .ok()
            .filter(|_| text.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| {
                Refusal::Invalid(format!("--block-size {text:?} is not a block size"))
            })?,
    };
    config::check_device_block_size("--block-size", block_size)
        .map_err(|error| Refusal::Invalid(format!("block size: {error}")))?;
    Ok(RawConnection {
        device,
        identifier,
        socket,
        block_size,
        plan_only: seen.contains("--plan"),
    })
}

/// `nbd-connect` and `nbd-disconnect`: a connection outside any
/// attachment, for provisioning a new volume (and the qualification
/// runner), with the attach steps' own NBD code.
fn raw_nbd(verb: &str, args: &[OsString]) -> ExitCode {
    let connect = verb == "nbd-connect";
    let raw = match raw_connection(args, connect) {
        Ok(raw) => raw,
        Err(Refusal::Usage) => return usage(),
        Err(Refusal::Invalid(error)) => {
            diagnostic!("error: {error}");
            return ExitCode::from(2);
        }
    };
    let name = raw.device.strip_prefix("/dev/").unwrap_or(&raw.device);
    let step = match &raw.socket {
        // The line the executed step logs and reports.
        Some(socket) => maki_privileged::plan::PlannedStep::NbdConnect {
            socket: socket.clone(),
            device: raw.device.clone(),
            block_size: raw.block_size,
        }
        .executed_with(&raw.identifier),
        None => format!(
            "disconnect {name} over netlink, only while its backend identifier is '{}'",
            raw.identifier
        ),
    };
    let plan = format!(
        "# {verb} {} outside any attachment\n1. {step}\n",
        raw.device
    );
    if raw.plan_only {
        return match print_plan(&plan) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                diagnostic!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "linux")]
    {
        let result = match &raw.socket {
            Some(socket) => maki_privileged::exec::connect_raw(
                socket,
                &raw.device,
                raw.block_size,
                &raw.identifier,
            ),
            None => maki_privileged::exec::disconnect_raw(&raw.device, &raw.identifier),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                diagnostic!("error: {error}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        diagnostic!("{verb} requires Linux");
        ExitCode::from(3)
    }
}

/// The attach configuration a verb runs on: the file at `config_path` when
/// it was named with `--config` or exists, built-in defaults otherwise. An
/// executing verb runs as root on what the file says: only a root-controlled
/// file is accepted (R5-030). A plan executes nothing and reads any file.
fn attach_config(
    config_path: &Path,
    explicit: bool,
    plan_only: bool,
) -> Result<AttachConfig, String> {
    if !explicit && !config_path.exists() {
        return Ok(AttachConfig::default());
    }
    #[cfg(target_os = "linux")]
    if !plan_only {
        return maki_privileged::exec::load_trusted_config(config_path);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = plan_only;
    config::load(config_path).map_err(|e| e.to_string())
}

/// Why a verb has no plan: misuse, answered with the usage, or a value that
/// is refused for the reason given. Both exit with status 2.
enum Refusal {
    Usage,
    Invalid(String),
}

/// The request and plan of `attach`, `detach`, `recover`, `cleanup` or `grow`
/// for `volume`: `config` with the command-line overrides in `args` applied.
/// The failed-start hook rolls back with the plan of `cleanup --volume
/// <volume>`, which has no overrides.
fn verb_plan(
    verb: &str,
    volume: &str,
    config: AttachConfig,
    args: &[OsString],
    plan_only: bool,
) -> Result<(AttachRequest, Plan), Refusal> {
    let overrides = AttachOverrides {
        nbd_device: flag(args, "--nbd-device"),
        nbd_socket: flag(args, "--socket"),
        vg_name: flag(args, "--vg"),
        lv_name: flag(args, "--lv"),
        mountpoint: flag(args, "--mountpoint"),
        volume_uuid: flag(args, "--uuid"),
        fs_uuid: flag(args, "--fs-uuid"),
        init_sentinel: args.iter().any(|a| a == "--init-sentinel"),
    };
    let require_uuid = verb == "attach" && !plan_only;
    let request = if verb == "attach" {
        config.into_request(volume, overrides, require_uuid)
    } else {
        config.into_existing_request(volume, overrides, require_uuid)
    }
    .map_err(|e| Refusal::Invalid(e.to_string()))?;

    let plan = match verb {
        "attach" => plan_attach(&request),
        "detach" | "recover" | "cleanup" => plan_detach(&request),
        "grow" => {
            // Plain decimal digits only: `u64::from_str` accepts a leading
            // `+`, which turned an intended relative "+N" into an absolute
            // target that an existing larger LV already met (BUG-116).
            let Some(target) = flag(args, "--size-bytes")
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|size| *size > 0)
            else {
                return Err(Refusal::Usage);
            };
            // LVM refuses a byte size that is not sector aligned, so such a
            // target would fail on every attempt, retries included.
            if target % 512 != 0 {
                return Err(Refusal::Invalid(format!(
                    "--size-bytes {target} is not a multiple of 512; LVM refuses unaligned \
                     byte sizes"
                )));
            }
            plan_grow(&GrowRequest {
                volume: volume.to_string(),
                nbd_device: request.nbd_device.clone(),
                volume_uuid: request.volume_uuid.clone(),
                nbd_socket: request.nbd_socket.clone(),
                vg_name: request.vg_name.clone(),
                lv_name: request.lv_name.clone(),
                lvm_identity: request.lvm_identity.clone(),
                fs_uuid: request.fs_uuid.clone(),
                target_bytes: target,
                mountpoint: request.mountpoint.clone(),
            })
        }
        _ => return Err(Refusal::Usage),
    };
    Ok((request, plan))
}

fn main() -> ExitCode {
    // Executed steps and every halted rollback are reported through
    // `tracing`; without a sink they vanish and the operator sees only the
    // exit status.
    maki_privileged::logging::install_default_logging();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // Asking for help or the version is not misuse (BUG-112). Either is
    // answered only as the sole argument, before the arguments are
    // validated and before any configuration or attachment state is looked
    // at; anywhere else it is refused like any other unknown argument.
    if let [only] = args.as_slice() {
        let answer = match only.to_str() {
            Some("--help" | "-h" | "help") => Some(format!("{USAGE}\n")),
            Some("--version" | "-V") => {
                Some(format!("maki-attach {}\n", env!("CARGO_PKG_VERSION")))
            }
            _ => None,
        };
        if let Some(answer) = answer {
            return match print_stdout(&answer) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    diagnostic!("error: writing the output failed: {error}");
                    ExitCode::FAILURE
                }
            };
        }
    }
    // The provisioning verbs act on a device, not on a volume.
    if let Some(verb @ ("nbd-connect" | "nbd-disconnect")) =
        args.first().and_then(|verb| verb.to_str())
    {
        return raw_nbd(verb, &args[1..]);
    }
    if let Err(error) = validate_arguments(&args) {
        diagnostic!("error: {error}");
        return usage();
    }
    let Some(verb) = args.first().and_then(|verb| verb.to_str()) else {
        return usage();
    };
    let Some(volume) = flag(&args, "--volume") else {
        return usage();
    };
    let plan_only = args.iter().any(|a| a == "--plan");

    if verb == "recover-failed-start" {
        // Without Linux there is no systemd to run the hook and nothing it
        // could schedule: like every other action, it executes only on Linux.
        if !plan_only && !cfg!(target_os = "linux") {
            diagnostic!("failed-start recovery requires Linux");
            return ExitCode::from(3);
        }
        return match failed_start::run(&volume, plan_only) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                diagnostic!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }

    let explicit_config = flag_value(&args, "--config").map(Path::new);
    let config_path = explicit_config
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(config::default_path(&volume)));
    if verb == "verify" {
        if let Err(error) = config::check_volume_name(&volume) {
            diagnostic!("error: {error}");
            return ExitCode::from(2);
        }
        // Workload gates use only the root-controlled config. An argument
        // cannot replace its filesystem pin or any stored attachment identity.
        if let Err(error) = config::check_abs_path("config", &config_path.to_string_lossy()) {
            diagnostic!("error: {error}");
            return ExitCode::from(2);
        }
        if plan_only {
            let preview = format!(
                "# verify volume {volume}: PLAN ONLY; no live evidence has been checked\n\
                 Require trusted config {} with volume_uuid and fs_uuid, and existing trusted attachment state and lock.\n\
                 Check the connected backend identifier, complete persisted mapping proof and complete read/write XFS mount in this namespace.\n\
                 Read the pinned XFS UUID and volume sentinel; recheck kernel identity around reads. No write probe or repair.\n",
                config_path.display()
            );
            return match print_plan(&preview) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    diagnostic!("error: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(target_os = "linux")]
        {
            return match maki_privileged::exec::verify(&volume, &config_path) {
                Ok(()) => {
                    // The gate's answer is the exit status: a confirmation
                    // that cannot be written does not withdraw it.
                    if let Err(error) = print_stdout(&format!(
                        "verified current storage attachment for volume {volume}\n"
                    )) {
                        diagnostic!(
                            "warning: volume {volume} was verified, but writing the confirmation failed: {error}"
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    diagnostic!("error: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            diagnostic!("verification requires Linux");
            return ExitCode::from(3);
        }
    }
    let attach_config = match attach_config(&config_path, explicit_config.is_some(), plan_only) {
        Ok(cfg) => cfg,
        Err(e) => {
            diagnostic!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (request, plan) = match verb_plan(verb, &volume, attach_config, &args, plan_only) {
        Ok(planned) => planned,
        Err(Refusal::Usage) => return usage(),
        Err(Refusal::Invalid(reason)) => {
            diagnostic!("error: {reason}");
            return ExitCode::from(2);
        }
    };

    let mut printed = String::new();
    if verb == "recover" {
        printed += &format!("# recover disconnected volume {}; require an absent backend and unchanged persisted kernel identities before each conditional cleanup step\n", request.volume);
        // Recovery consumes the detach identity but never disconnects NBD.
        // Print only the conditional upper-layer cleanup it can execute.
        for (index, step) in plan.steps.iter().take(2).enumerate() {
            printed += &format!("{}. {step} (only if still present)\n", index + 1);
        }
    } else if verb == "cleanup" {
        printed += &format!("# cleanup volume {}; no trusted record is success; owned connected backend follows detach; known absent backend follows recovery; foreign or unreadable backend is preserved\n", request.volume);
        for (index, step) in plan.steps.iter().enumerate() {
            let condition = if index < 2 {
                "only if still present in the selected detach or recovery path"
            } else {
                "only for the owned connected backend detach path"
            };
            printed += &format!("{}. {step} ({condition})\n", index + 1);
        }
    } else {
        printed = plan.to_string();
    }
    if plan_only {
        return match print_plan(&printed) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                diagnostic!("error: {error}");
                ExitCode::FAILURE
            }
        };
    }
    // Before execution the plan is an audit copy of what follows. Whether it
    // could be written must not decide whether storage is attached, detached
    // or cleaned up: the exit status is the execution's.
    if let Err(error) = print_stdout(&printed) {
        diagnostic!("warning: writing the plan failed: {error}; continuing with {verb}");
    }

    #[cfg(target_os = "linux")]
    {
        let result = match verb {
            "recover" => maki_privileged::exec::recover(&plan),
            "cleanup" => maki_privileged::exec::cleanup(&plan),
            _ => maki_privileged::exec::execute(&plan),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                diagnostic!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        diagnostic!("execution requires Linux; plan printed above (--plan)");
        ExitCode::from(3)
    }
}
