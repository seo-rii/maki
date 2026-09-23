//! Upstream nbd-client 3.27.1 prints its version from the help path and exits
//! nonzero. The privileged runner must still parse and enforce that version.

#[test]
fn privileged_runner_tolerates_the_upstream_help_exit_status() {
    let runner = include_str!("../../../scripts/privileged-linux-validation.sh");

    assert!(
        runner.contains("nbd-client -h 2>&1") && runner.contains("head -n 1 || true"),
        "the runner must parse the version banner even though nbd-client -h exits nonzero"
    );
    assert!(
        !runner.contains("nbd-client -V 2>&1"),
        "upstream nbd-client 3.27.1 does not honor its advertised -V path"
    );
}
