//! BUG-168: actual unprivileged plan invocations, without device operations.
const MARKER: &str = "synthetic-private-attach-config-bug168";

fn run(text: &str) -> std::process::Output {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("attach.toml");
    std::fs::write(&path, text).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(["attach", "--volume", "review", "--plan", "--config"])
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn cli_does_not_print_rejected_config_input() {
    for input in [
        format!("init_sentinel = \"{MARKER}\"\n"),
        format!("{MARKER} = true\n"),
        format!("init_sentinel = \"{MARKER}\n"),
    ] {
        let output = run(&input);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("attach config parse error"));
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(bytes).contains(MARKER));
        }
    }
}

#[test]
fn cli_semantic_diagnostics_name_fields_without_echoing_values() {
    for (field, value) in [
        ("nbd_device", format!("/dev/{MARKER}")),
        ("nbd_socket", MARKER.to_string()),
        ("mountpoint", format!("/{MARKER}/..")),
        ("vg_name", format!("{MARKER}/invalid")),
        ("lv_name", format!("{MARKER}/invalid")),
        ("volume_uuid", MARKER.to_string()),
        ("fs_uuid", MARKER.to_string()),
    ] {
        let output = run(&format!("{field} = '{value}'\n"));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(field));
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!String::from_utf8_lossy(bytes).contains(MARKER));
        }
    }
}

#[test]
fn valid_attach_plan_still_succeeds() {
    let output = run("init_sentinel = true\n");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("attach volume review"));
}
