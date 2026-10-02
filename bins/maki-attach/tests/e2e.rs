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
        text.contains("nbd-client -unix /run/maki/v1/nbd.sock nbd<auto>"),
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

    let out = run(&[
        "grow",
        "--volume",
        "v3",
        "--size-bytes",
        "1048576",
        "--plan",
    ]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("grow"));

    // grow without --size-bytes is a usage error.
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
    let out = run(&[
        "attach",
        "--volume",
        "v9",
        "--uuid",
        "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c",
    ]);
    assert_eq!(out.status.code(), Some(3), "non-Linux execution -> exit 3");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("# attach volume v9"),
        "plan still printed for audit"
    );
}

#[test]
fn grow_requires_an_absolute_target_for_safe_retries() {
    let out = run(&[
        "grow",
        "--volume",
        "v3",
        "--size-bytes",
        "2147483648",
        "--plan",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = String::from_utf8_lossy(&out.stdout);
    assert!(plan.contains("lvextend -L 2147483648b"), "{plan}");
    assert!(
        !plan.contains("+2147483648"),
        "retry must not add twice: {plan}"
    );
    let relative = run(&[
        "grow",
        "--volume",
        "v3",
        "--add-bytes",
        "1073741824",
        "--plan",
    ]);
    assert_eq!(
        relative.status.code(),
        Some(2),
        "ambiguous relative growth must be refused"
    );
}

#[test]
fn recovery_plan_only_lists_conditional_disconnected_storage_cleanup() {
    let out = run(&["recover", "--volume", "v1", "--plan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = String::from_utf8_lossy(&out.stdout);
    assert!(plan.contains("recover disconnected volume v1"), "{plan}");
    assert!(plan.contains("umount /srv/v1"), "{plan}");
    assert!(plan.contains("vgchange -an"), "{plan}");
    assert!(
        !plan.contains("nbd-client"),
        "recovery never disconnects a live backend: {plan}"
    );
    assert!(!plan.contains("systemctl"), "{plan}");
}

#[test]
fn cleanup_plan_describes_idempotent_record_driven_storage_cleanup() {
    let out = run(&["cleanup", "--volume", "v1", "--plan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let plan = String::from_utf8_lossy(&out.stdout);
    for contract in [
        "cleanup volume v1",
        "no trusted record is success",
        "owned connected backend follows detach",
        "known absent backend follows recovery",
        "foreign or unreadable backend is preserved",
    ] {
        assert!(plan.contains(contract), "missing {contract}: {plan}");
    }
    assert!(plan.contains("umount /srv/v1"), "{plan}");
    assert!(plan.contains("vgchange -an"), "{plan}");
    assert!(plan.contains("nbd-client -d"), "{plan}");
    assert!(!plan.contains("systemctl"), "{plan}");
}

#[test]
fn verify_plan_describes_the_workload_gate_without_claiming_live_evidence() {
    let out = run(&["verify", "--volume", "v1", "--plan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("verify volume v1"), "{text}");
    assert!(text.contains("PLAN ONLY"), "{text}");
    for evidence in [
        "trusted config",
        "backend identifier",
        "persisted mapping proof",
        "XFS UUID",
        "sentinel",
    ] {
        assert!(text.contains(evidence), "missing {evidence}: {text}");
    }
    for mutation in ["vgchange", "nbd-client", "mount -", "umount", "systemctl"] {
        assert!(!text.contains(mutation), "{text}");
    }
}

#[test]
fn verify_rejects_identity_overrides_unknown_flags_and_duplicate_options() {
    for extra in [
        vec!["--fs-uuid", "11111111-2222-4333-8444-555555555555"],
        vec!["--uuid", "11111111-2222-4333-8444-555555555555"],
        vec!["--nbd-device", "/dev/nbd3"],
        vec!["--mountpoint", "/srv/other"],
        vec!["--init-sentinel"],
        vec!["--unknown"],
        vec!["--volume", "other"],
        vec!["--plan"],
    ] {
        let mut arguments = vec!["verify", "--volume", "v1", "--plan"];
        arguments.extend(extra);
        let out = run(&arguments);
        assert_eq!(out.status.code(), Some(2), "{arguments:?}");
        assert!(
            out.stdout.is_empty(),
            "rejected input must not print successful verification"
        );
    }
}

/// R5-030: executing verbs run as root on whatever the attach config says
/// (mountpoint, VG, NBD socket), so a config a non-root user can write is a
/// privilege boundary. Only `verify` used the root-owned, descriptor-anchored
/// reader; attach, detach, grow, cleanup and recover now use it too. Plans
/// (`--plan`) still read any file, since they execute nothing.
#[cfg(target_os = "linux")]
#[test]
fn executing_verbs_refuse_an_attach_config_a_non_root_user_controls() {
    let uid = Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        // As root the file would be trusted and the verb would really run.
        eprintln!("skipping: running as root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.toml");
    std::fs::write(
        &path,
        "volume_uuid = \"0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c\"\nvg_name = \"vg_maki_v1\"\n",
    )
    .unwrap();
    let config = path.to_str().unwrap();
    for verb in ["attach", "detach", "cleanup", "recover"] {
        let out = run(&[verb, "--volume", "v1", "--config", config]);
        assert!(!out.status.success(), "{verb}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("root-owned"), "{verb}: {stderr}");
    }
    let out = run(&[
        "grow",
        "--volume",
        "v1",
        "--config",
        config,
        "--size-bytes",
        "1048576",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("root-owned"));
    // A plan reads the same file and still works.
    let out = run(&["attach", "--volume", "v1", "--config", config, "--plan"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
