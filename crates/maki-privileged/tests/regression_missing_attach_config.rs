//! BUG-002: a required attach configuration must fail the start job.
//! A ConditionPathExists skip does not fail a Requires= dependency.

const ATTACH_UNIT: &str = include_str!("../../../packaging/systemd/maki-attach@.service");

#[test]
fn missing_attach_config_is_a_start_assertion() {
    let directives: Vec<_> = ATTACH_UNIT.lines().map(str::trim).collect();
    assert!(
        directives.contains(&"AssertPathExists=/etc/maki/attach/%i.toml"),
        "missing configuration must fail the attach job and its ordered Requires= dependents"
    );
    assert!(
        !directives.iter().any(|line| line.starts_with("Condition")),
        "an attach condition must not skip required mount verification"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn systemd_evaluates_the_packaged_assertion_against_missing_and_present_files() {
    use std::process::Command;

    if Command::new("systemd-analyze")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("systemd-analyze is unavailable; packaging declaration is checked separately");
        return;
    }
    let directive = ATTACH_UNIT
        .lines()
        .find(|line| line.starts_with("AssertPathExists="))
        .expect("required attach configuration must be an assertion");
    let scratch = std::env::temp_dir().join(format!(
        "maki-attach-assert-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&scratch).unwrap();
    let config = scratch.join("volume.toml");
    let assertion = format!(
        "{}={}",
        directive.split_once('=').unwrap().0,
        config.display()
    );
    let absent = Command::new("systemd-analyze")
        .args(["condition", &assertion])
        .output()
        .unwrap();
    assert!(
        !absent.status.success(),
        "absent config passed the assertion"
    );
    std::fs::write(&config, "# fixture\n").unwrap();
    let present = Command::new("systemd-analyze")
        .args(["condition", &assertion])
        .output()
        .unwrap();
    std::fs::remove_dir_all(scratch).unwrap();
    assert!(
        present.status.success(),
        "{}",
        String::from_utf8_lossy(&present.stderr)
    );
}
