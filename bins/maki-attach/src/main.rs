//! `maki-attach` — the privileged one-shot helper (SPEC §6).
//!
//! Attach parameters come from the root-owned configuration
//! `/etc/maki/attach/<volume>.toml` (review M-016), optionally overridden
//! on the command line; every value is hygiene-checked before it reaches a
//! system utility. Plans are printed for audit; execution runs on Linux
//! only, with NBD device allocation, mount-identity verification and
//! reverse rollback on failure.

use std::process::ExitCode;

use maki_privileged::config::{self, AttachConfig, AttachOverrides};
use maki_privileged::plan::{plan_attach, plan_detach, plan_grow, GrowRequest};

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  maki-attach attach --volume <v> [--config <attach.toml>] [--nbd-device /dev/nbdN]
                     [--vg <vg>] [--lv <lv>] [--mountpoint <dir>] [--socket <path>]
                     [--uuid <volume-uuid>] [--fs-uuid <xfs-uuid>] [--init-sentinel] [--plan]
  maki-attach detach --volume <v> [...]
  maki-attach recover --volume <v> [...] (disconnected storage only; stop workloads first)
  maki-attach verify --volume <v> [--config <attach.toml>] [--plan]
  maki-attach grow   --volume <v> --size-bytes <n> [...]

Without --config, /etc/maki/attach/<v>.toml is read when it exists. Execution
requires the volume UUID (config or --uuid); --plan prints the plan without it."
    );
    ExitCode::from(2)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(verb) = args.first().cloned() else {
        return usage();
    };
    let Some(volume) = flag(&args, "--volume") else {
        return usage();
    };
    let plan_only = args.iter().any(|a| a == "--plan");

    // Every flag value is checked before it can reach a system utility.
    for name in [
        "--volume",
        "--config",
        "--nbd-device",
        "--vg",
        "--lv",
        "--mountpoint",
        "--socket",
        "--uuid",
        "--fs-uuid",
        "--size-bytes",
    ] {
        if let Some(value) = flag(&args, name) {
            if let Err(e) = config::check_argument(name, &value) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let config_path = flag(&args, "--config").unwrap_or_else(|| config::default_path(&volume));
    if verb == "verify" {
        // Workload gates use only the root-controlled config. An argument
        // cannot replace its filesystem pin or any stored attachment identity.
        let mut seen = std::collections::HashSet::new();
        let mut flags = args.iter().skip(1);
        while let Some(argument) = flags.next() {
            if !seen.insert(argument.as_str())
                || match argument.as_str() {
                    "--volume" | "--config" => flags.next().is_none(),
                    "--plan" => false,
                    _ => true,
                }
            {
                eprintln!("error: verify accepts only --volume, --config and --plan; identity overrides are forbidden");
                return ExitCode::from(2);
            }
        }
        if let Err(error) = config::check_abs_path("config", &config_path) {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
        if plan_only {
            println!("# verify volume {volume}: PLAN ONLY; no live evidence has been checked");
            println!("Require trusted config {config_path} with volume_uuid and fs_uuid, and existing trusted attachment state and lock.");
            println!("Check the connected backend identifier, complete persisted mapping proof and complete read/write XFS mount in this namespace.");
            println!("Read the pinned XFS UUID and volume sentinel; recheck kernel identity around reads. No write probe or repair.");
            return ExitCode::SUCCESS;
        }
        #[cfg(target_os = "linux")]
        {
            return match maki_privileged::exec::verify(&volume, &config_path) {
                Ok(()) => {
                    println!("verified current storage attachment for volume {volume}");
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("error: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("verification requires Linux");
            return ExitCode::from(3);
        }
    }
    let attach_config =
        if flag(&args, "--config").is_some() || std::path::Path::new(&config_path).exists() {
            match config::load(&config_path) {
                Ok(cfg) => cfg,
                Err(e) => {
                    eprintln!("error: {e}");
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
    let request = match attach_config.into_request(&volume, overrides, require_uuid) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let plan = match verb.as_str() {
        "attach" => plan_attach(&request),
        "detach" | "recover" => plan_detach(&request),
        "grow" => {
            if args.iter().any(|arg| arg == "--add-bytes") {
                eprintln!("error: relative growth is unsupported; use --size-bytes with the absolute desired LV size and reuse it on retry");
                return ExitCode::from(2);
            }
            let Some(target) = flag(&args, "--size-bytes")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|size| *size > 0)
            else {
                return usage();
            };
            plan_grow(&GrowRequest {
                volume,
                volume_uuid: request.volume_uuid.clone(),
                nbd_socket: request.nbd_socket.clone(),
                vg_name: request.vg_name.clone(),
                lv_name: request.lv_name.clone(),
                target_bytes: target,
                mountpoint: request.mountpoint.clone(),
            })
        }
        _ => return usage(),
    };

    if verb == "recover" {
        println!("# recover disconnected volume {}; require an absent backend and unchanged persisted kernel identities before each conditional cleanup step", request.volume);
        // Recovery consumes the detach identity but never disconnects NBD.
        // Print only the conditional upper-layer cleanup it can execute.
        for (index, step) in plan.steps.iter().take(2).enumerate() {
            println!("{}. {step} (only if still present)", index + 1);
        }
    } else {
        print!("{plan}");
    }
    if plan_only {
        return ExitCode::SUCCESS;
    }

    #[cfg(target_os = "linux")]
    {
        let result = if verb == "recover" {
            maki_privileged::exec::recover(&plan)
        } else {
            maki_privileged::exec::execute(&plan)
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("execution requires Linux; plan printed above (--plan)");
        ExitCode::from(3)
    }
}
