//! `maki-attach` — the privileged one-shot helper (SPEC §6).
//! Plans are printed for audit; execution runs on Linux only.

use std::process::ExitCode;

use maki_privileged::plan::{plan_attach, plan_detach, plan_grow, AttachRequest, GrowRequest};

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  maki-attach attach --volume <v> [--nbd-device /dev/nbd0] [--vg <vg>] [--lv <lv>] [--mountpoint <dir>] [--uuid <volume-uuid>] [--plan]
  maki-attach detach --volume <v> [...]
  maki-attach grow   --volume <v> --add-bytes <n> [...] "
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

    let request = AttachRequest {
        volume: volume.clone(),
        nbd_socket: format!("/run/maki/{volume}/nbd.sock"),
        nbd_device: flag(&args, "--nbd-device").unwrap_or_else(|| "/dev/nbd0".to_string()),
        device_block_size: 4096,
        vg_name: flag(&args, "--vg").unwrap_or_else(|| format!("vg_maki_{volume}")),
        lv_name: flag(&args, "--lv").unwrap_or_else(|| "data".to_string()),
        mountpoint: flag(&args, "--mountpoint").unwrap_or_else(|| format!("/srv/{volume}")),
        volume_uuid: flag(&args, "--uuid").unwrap_or_default(),
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
