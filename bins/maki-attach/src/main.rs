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
use maki_privileged::plan::{plan_attach, plan_detach, plan_grow, GrowRequest};

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
    let attach_config = if explicit_config.is_some() || config_path.exists() {
        // An executing verb runs as root on what the file says: only a
        // root-controlled file is accepted (R5-030). A plan executes
        // nothing and reads any file.
        #[cfg(target_os = "linux")]
        let loaded = if plan_only {
            config::load(&config_path).map_err(|e| e.to_string())
        } else {
            maki_privileged::exec::load_trusted_config(&config_path)
        };
        #[cfg(not(target_os = "linux"))]
        let loaded = config::load(&config_path).map_err(|e| e.to_string());
        match loaded {
            Ok(cfg) => cfg,
            Err(e) => {
                diagnostic!("error: {e}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        AttachConfig::default()
    };

    let overrides = AttachOverrides {
        nbd_device: flag(&args, "--nbd-device"),
        nbd_socket: flag(&args, "--socket"),
        vg_name: flag(&args, "--vg"),
        lv_name: flag(&args, "--lv"),
        mountpoint: flag(&args, "--mountpoint"),
        volume_uuid: flag(&args, "--uuid"),
        fs_uuid: flag(&args, "--fs-uuid"),
        init_sentinel: args.iter().any(|a| a == "--init-sentinel"),
    };
    let require_uuid = verb == "attach" && !plan_only;
    let request = if verb == "attach" {
        attach_config.into_request(&volume, overrides, require_uuid)
    } else {
        attach_config.into_existing_request(&volume, overrides, require_uuid)
    };
    let request = match request {
        Ok(r) => r,
        Err(e) => {
            diagnostic!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let plan = match verb {
        "attach" => plan_attach(&request),
        "detach" | "recover" | "cleanup" => plan_detach(&request),
        "grow" => {
            // Plain decimal digits only: `u64::from_str` accepts a leading
            // `+`, which turned an intended relative "+N" into an absolute
            // target that an existing larger LV already met (BUG-116).
            let Some(target) = flag(&args, "--size-bytes")
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|size| *size > 0)
            else {
                return usage();
            };
            // LVM refuses a byte size that is not sector aligned, so such a
            // target would fail on every attempt, retries included.
            if target % 512 != 0 {
                diagnostic!(
                    "error: --size-bytes {target} is not a multiple of 512; LVM refuses unaligned \
                     byte sizes"
                );
                return ExitCode::from(2);
            }
            plan_grow(&GrowRequest {
                volume,
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
        _ => return usage(),
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
