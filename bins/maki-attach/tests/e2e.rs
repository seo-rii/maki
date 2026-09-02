//! End-to-end test of `maki-attach` as a real process: `--plan` prints the
//! audited step sequence and executes nothing; missing arguments are usage
//! errors; on non-Linux hosts execution is refused (exit 3) after printing
//! the plan. The execution path itself is Linux-only (docs/operations.md).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(args)
        .output()
        .expect("spawn maki-attach")
}

#[test]
fn attach_plan_prints_ordered_steps_without_executing() {
    let out = run(&["attach", "--volume", "v1", "--plan"]);
    assert!(out.status.success(), "--plan must exit 0");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("# attach volume v1"), "{text}");
    assert!(text.contains("modprobe nbd"), "{text}");
    assert!(
        text.contains("nbd-client -unix /run/maki/v1/nbd.sock /dev/nbd0"),
        "{text}"
    );
    assert!(text.contains("/srv/v1"), "{text}");
    // Steps are numbered in execution order; modprobe precedes nbd-client.
    assert!(
        text.find("modprobe nbd").unwrap() < text.find("nbd-client").unwrap(),
        "{text}"
    );
}

#[test]
fn detach_and_grow_plans_print() {
    let out = run(&["detach", "--volume", "v2", "--plan"]);
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("vgchange -an"),
        "detach must deactivate LVM"
    );

    let out = run(&["grow", "--volume", "v3", "--add-bytes", "1048576", "--plan"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("grow"));

    // grow without --add-bytes is a usage error.
    let out = run(&["grow", "--volume", "v3", "--plan"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_volume_flag_is_a_usage_error() {
    let out = run(&["attach"]);
    assert_eq!(out.status.code(), Some(2));
}

/// Never run this on Linux: without `--plan` the binary would attempt the
/// real privileged steps there.
#[cfg(not(target_os = "linux"))]
#[test]
fn execution_is_refused_off_linux() {
    let out = run(&["attach", "--volume", "v9"]);
    assert_eq!(out.status.code(), Some(3), "non-Linux execution -> exit 3");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("# attach volume v9"),
        "plan still printed for audit"
    );
}
