//! Review M-016 for the `maki-attach` process: option-like and malformed
//! values never reach a system utility, execution refuses to run without a
//! volume UUID, and a root-owned attach configuration drives the plan.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(args)
        .output()
        .expect("spawn maki-attach")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn option_like_values_are_rejected_before_planning() {
    for args in [
        vec!["attach", "--volume", "v", "--nbd-device", "-d", "--plan"],
        vec![
            "attach",
            "--volume",
            "v",
            "--mountpoint",
            "--bind",
            "--plan",
        ],
        vec!["attach", "--volume", "v", "--vg", "-an", "--plan"],
        vec!["attach", "--volume", "v/../etc", "--plan"],
        vec!["attach", "--volume", "v", "--mountpoint", "srv/v", "--plan"],
        vec!["attach", "--volume", "v", "--uuid", "nope", "--plan"],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("# attach"),
            "no plan may be printed for rejected input: {args:?}"
        );
    }
}

#[test]
fn plan_mode_works_without_uuid_but_execution_requires_it() {
    let out = run(&["attach", "--volume", "v", "--plan"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("volume <unset>"));

    // Execution path (any platform reaches the request check first).
    let out = run(&["attach", "--volume", "v"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(
        text(&out).contains("volume_uuid is required"),
        "{}",
        text(&out)
    );
}

#[test]
fn attach_config_drives_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.toml");
    std::fs::write(
        &path,
        "volume_uuid = \"0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c\"\nnbd_device = \"/dev/nbd5\"\nmountpoint = \"/mnt/v\"\ndevice_block_size = 512\nfs_uuid = \"11111111-2222-3333-4444-555555555555\"\n",
    )
    .unwrap();
    let out = run(&[
        "attach",
        "--volume",
        "v",
        "--config",
        path.to_str().unwrap(),
        "--plan",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let plan = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        plan.contains("nbd-client -unix /run/maki/v/nbd.sock /dev/nbd5 -b 512"),
        "{plan}"
    );
    assert!(plan.contains("/mnt/v"), "{plan}");
    assert!(
        plan.contains("fs uuid 11111111-2222-3333-4444-555555555555"),
        "{plan}"
    );
    assert!(
        plan.contains("volume 0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c"),
        "{plan}"
    );

    // A flag overrides the file.
    let out = run(&[
        "attach",
        "--volume",
        "v",
        "--config",
        path.to_str().unwrap(),
        "--mountpoint",
        "/mnt/other",
        "--plan",
    ]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("/mnt/other"));

    // An unreadable or malformed file fails closed.
    let out = run(&[
        "attach",
        "--volume",
        "v",
        "--config",
        "/no/such.toml",
        "--plan",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    std::fs::write(&path, "volume_uuid = 5\n").unwrap();
    let out = run(&[
        "attach",
        "--volume",
        "v",
        "--config",
        path.to_str().unwrap(),
        "--plan",
    ]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
}
