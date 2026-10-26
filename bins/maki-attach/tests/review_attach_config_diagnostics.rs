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
fn valid_attach_plan_still_succeeds() {
    let output = run("init_sentinel = true\n");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("attach volume review"));
}
