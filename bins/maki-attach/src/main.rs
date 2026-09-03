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
  maki-attach grow   --volume <v> --add-bytes <n> [...]

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
        "--add-bytes",
    ] {
        if let Some(value) = flag(&args, name) {
            if let Err(e) = config::check_argument(name, &value) {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let config_path = flag(&args, "--config").unwrap_or_else(|| config::default_path(&volume));
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
        "detach" => plan_detach(&request),
        "grow" => {
            let Some(add) = flag(&args, "--add-bytes").and_then(|v| v.parse().ok()) else {
                return usage();
            };
            plan_grow(&GrowRequest {
                volume,
                vg_name: request.vg_name.clone(),
                lv_name: request.lv_name.clone(),
                add_bytes: add,
                mountpoint: request.mountpoint.clone(),
            })
        }
        _ => return usage(),
    };

    print!("{plan}");
    if plan_only {
        return ExitCode::SUCCESS;
    }

    #[cfg(target_os = "linux")]
    {
        match maki_privileged::exec::execute(&plan) {
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
