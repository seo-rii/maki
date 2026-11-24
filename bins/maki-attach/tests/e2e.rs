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
        text.contains("connect 'nbd<auto>' to /run/maki/v1/nbd.sock over netlink"),
        "{text}"
    );
    assert!(
        text.contains("the export must advertise FLUSH and FUA"),
        "{text}"
    );
    assert!(!text.contains("nbd-client"), "{text}");
    assert!(text.contains("/srv/v1"), "{text}");
    // Steps are numbered in execution order; modprobe precedes the connect.
    assert!(
        text.find("modprobe nbd").unwrap() < text.find("over netlink").unwrap(),
        "{text}"
    );
}

#[test]
fn attach_plan_checks_socket_and_mountpoint_before_provisioning() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("attach.toml");
    std::fs::write(&config, "").unwrap();
    let socket = "/srv/maki-plan-fixture/nbd";
    let plan = |command: &str, mountpoint: &str| {
        run(&[
            command,
            "--volume",
            "v1",
            "--config",
            config.to_str().unwrap(),
            "--socket",
            socket,
            "--mountpoint",
            mountpoint,
            "--plan",
        ])
    };
    for mountpoint in [socket, "/srv/maki-plan-fixture/nbd/data"] {
        let out = plan("attach", mountpoint);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("nbd_socket"));
        assert!(plan("detach", mountpoint).status.success());
    }
    for sibling in [
        "/srv/maki-plan-fixture/nbd-data",
        r"/srv/maki-plan-fixture/nbd\data",
    ] {
        assert!(plan("attach", sibling).status.success());
    }
}

#[test]
fn attach_plan_requires_separate_lv_mount_and_socket_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("attach.toml");
    std::fs::write(&config, "").unwrap();
    let plan = |command: &str, flag: &str, path: &str| {
        run(&[
            command,
            "--plan",
            "--volume",
            "v1",
            "--config",
            config.to_str().unwrap(),
            "--vg",
            "maki-plan-vg",
            "--lv",
            "app-data",
            flag,
            path,
        ])
    };
    for device in [
        "/dev/maki-plan-vg/app-data",
        "/dev/mapper/maki--plan--vg-app--data",
    ] {
        for flag in ["--mountpoint", "--socket"] {
            for collision in [
                device.to_owned(),
                format!("{device}/child"),
                device.rsplit_once('/').unwrap().0.to_owned(),
            ] {
                let out = plan("attach", flag, &collision);
                assert_eq!(out.status.code(), Some(2), "{flag} {collision}");
                assert!(out.stdout.is_empty());
                assert!(plan("detach", flag, &collision).status.success());
            }
            assert!(plan("attach", flag, &format!("{device}-other"))
                .status
                .success());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn attach_plan_checks_existing_mountpoint_paths_and_linux_path_length() {
    let plan = |path: &str| run(&["attach", "--volume", "v1", "--mountpoint", path, "--plan"]);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    assert!(plan(dir.to_str().unwrap()).status.success());
    let file = dir.join("file");
    std::fs::write(&file, []).unwrap();
    for invalid in [&file, &file.join("child")] {
        let out = plan(invalid.to_str().unwrap());
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("mountpoint"));
        assert!(out.stdout.is_empty());
    }

    for (name, target) in [("dangling", dir.join("absent")), ("live", dir.to_owned())] {
        let link = dir.join(name);
        std::os::unix::fs::symlink(target, &link).unwrap();
        for invalid in [&link, &link.join("child")] {
            let out = plan(invalid.to_str().unwrap());
            assert_eq!(out.status.code(), Some(2));
            assert!(String::from_utf8_lossy(&out.stderr).contains("symlink"));
            assert!(out.stdout.is_empty());
        }
    }

    // Linux accepts up to 4095 path bytes plus the terminating NUL.
    let mut path = dir.join("uncreated").to_str().unwrap().to_owned();
    let component = format!("/{}", "a".repeat(127));
    while path.len() + component.len() <= 4095 {
        path.push_str(&component);
    }
    path.extend(std::iter::repeat_n('b', 4095 - path.len()));
    assert!(plan(&path).status.success());
    path.push('c');
    let out = plan(&path);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("mountpoint"));
    assert!(out.stdout.is_empty());
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
        "--nbd-device",
        "/dev/nbd7",
        "--plan",
    ]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("grow volume v3 on /dev/nbd7"));

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
        !plan.contains("over netlink"),
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
    assert!(
        plan.contains("disconnect 'nbd<auto>' over netlink"),
        "{plan}"
    );
    assert!(!plan.contains("nbd-client"), "{plan}");
    assert!(!plan.contains("systemctl"), "{plan}");
}

#[test]
fn plans_enforce_the_volume_format_name_limit() {
    assert!(run(&["cleanup", "--volume", &"a".repeat(65), "--plan"])
        .status
        .success());
    for command in ["attach", "verify"] {
        assert!(run(&[command, "--volume", &"a".repeat(64), "--plan"])
            .status
            .success());
        let out = run(&[command, "--volume", &"a".repeat(65), "--plan"]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("64"));
    }
}

#[test]
fn mapper_name_must_fit_after_escaping_both_lvm_names() {
    for (vg, lv, valid) in [
        ("v".repeat(63), "l".repeat(63), true),
        ("v".repeat(64), "l".repeat(63), false),
        (
            format!("v{}", "-".repeat(31)),
            format!("l{}", "-".repeat(31)),
            true,
        ),
        (
            format!("v{}", "-".repeat(31)),
            format!("l{}", "-".repeat(32)),
            false,
        ),
    ] {
        let out = run(&[
            "attach", "--volume", "v1", "--vg", &vg, "--lv", &lv, "--plan",
        ]);
        assert_eq!(out.status.success(), valid, "{vg}/{lv}");
        if !valid {
            assert!(out.stdout.is_empty());
            assert!(String::from_utf8_lossy(&out.stderr).contains("127"));
        }
    }
}

#[test]
fn attach_plans_reject_internal_lvm_names_only_for_the_selected_lv() {
    for name in [
        "snapshot",
        "pvmove1",
        "data_tmeta",
        "disk_rimage_0",
        "pool_cvol",
    ] {
        let out = run(&["attach", "--volume", "v1", "--lv", name, "--plan"]);
        assert_eq!(out.status.code(), Some(2), "{name}");
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("lv_name"));
    }
    let out = run(&[
        "attach",
        "--volume",
        "v1",
        "--vg",
        "pool_tmeta",
        "--lv",
        "daily_snapshot",
        "--plan",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn verify_rejects_invalid_volume_names_before_planning_or_execution() {
    for args in [
        vec!["verify", "--volume", "demo.one", "--plan"],
        vec!["verify", "--volume", "demo.one"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("volume name"));
    }
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
    for mutation in [
        "vgchange",
        "over netlink",
        "nbd-client",
        "mount -",
        "umount",
        "systemctl",
    ] {
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

#[cfg(unix)]
#[test]
fn plan_reads_a_config_with_a_non_utf8_filename() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join(std::ffi::OsStr::from_bytes(b"caf\xe9.toml"));
    std::fs::write(&path, "mountpoint = \"/srv/native-path\"\n").unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(["attach", "--volume", "example", "--plan", "--config"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("/srv/native-path"));

    let invalid_name = std::process::Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(["attach", "--plan", "--volume"])
        .arg(std::ffi::OsStr::from_bytes(b"t\xe9"))
        .output()
        .unwrap();
    assert_eq!(invalid_name.status.code(), Some(2));
}

#[test]
fn plans_preserve_command_arguments_with_spaces_and_apostrophes() {
    let mountpoint = "/srv/DB one's";
    for verb in ["attach", "detach", "grow"] {
        let mut args = vec![
            verb,
            "--volume",
            "audit",
            "--nbd-device",
            "/dev/nbd1",
            "--socket",
            "/run/DB socket",
            "--mountpoint",
            mountpoint,
            "--plan",
        ];
        if verb == "grow" {
            args.extend(["--size-bytes", "4096"]);
        }
        let out = run(&args);
        assert!(out.status.success(), "{:?}", out.stderr);
        let plan = String::from_utf8(out.stdout).unwrap();
        let quoted_mount = r"'/srv/DB one'\''s'";
        match verb {
            "attach" => {
                assert!(plan.contains("connect nbd1 to '/run/DB socket' over netlink (block size 4096, backend identifier '<generated-connection-uuid>'; the export must advertise FLUSH and FUA)"), "{plan}");
                assert!(
                    plan.contains(&format!("/dev/vg_maki_audit/data {quoted_mount}")),
                    "{plan}"
                );
            }
            "detach" => assert!(plan.contains(&format!("umount {quoted_mount}")), "{plan}"),
            _ => assert!(
                plan.contains(&format!("xfs_growfs {quoted_mount}")),
                "{plan}"
            ),
        }
    }
}
