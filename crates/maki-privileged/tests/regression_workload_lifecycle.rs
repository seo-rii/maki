//! R3-007: package one fail-closed lifecycle around daemon, attachment, and
//! workload recovery. Static checks remain useful on non-systemd CI hosts;
//! native systemd execution is covered by the privileged validation campaign.

use std::path::PathBuf;

fn repository_file(path: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(path))
        .unwrap_or_else(|error| panic!("missing repository file {path}: {error}"))
}

fn has_directive(unit: &str, section: &str, expected: &str) -> bool {
    let mut current = "";
    for raw in unit.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            current = line;
        } else if current == section && line == expected {
            return true;
        }
    }
    false
}

#[test]
fn daemon_failure_enters_the_single_recovery_path() {
    let daemon = repository_file("packaging/systemd/maki@.service");

    assert!(has_directive(
        &daemon,
        "[Unit]",
        "OnFailure=maki-recover@%i.service"
    ));
    assert!(has_directive(
        &daemon,
        "[Unit]",
        "OnFailureJobMode=replace-irreversibly"
    ));
    assert!(has_directive(
        &daemon,
        "[Unit]",
        "StartLimitIntervalSec=300"
    ));
    assert!(has_directive(&daemon, "[Unit]", "StartLimitBurst=3"));
    assert!(has_directive(
        &daemon,
        "[Unit]",
        "PartOf=maki-workload@%i.target"
    ));
    assert!(
        !daemon
            .lines()
            .any(|line| line.trim() == "Restart=on-failure"),
        "the daemon must not bypass cleanup by restarting itself"
    );
    assert!(
        !has_directive(&daemon, "[Install]", "WantedBy=multi-user.target"),
        "operators must enable the workload lifecycle target, not the daemon alone"
    );
}

#[test]
fn recovery_stops_every_storage_consumer_before_cleanup() {
    let recovery = repository_file("packaging/systemd/maki-recover@.service");

    for dependency in [
        "Conflicts=maki-workload@%i.target maki-attach@%i.service maki@%i.service",
        "After=maki-workload@%i.target maki-attach@%i.service maki@%i.service",
    ] {
        assert!(
            has_directive(&recovery, "[Unit]", dependency),
            "recovery must declare {dependency:?}"
        );
    }
    for service in [
        "Type=oneshot",
        "TimeoutStartSec=180",
        "ExecStart=/usr/bin/maki-attach cleanup --volume %i",
    ] {
        assert!(has_directive(&recovery, "[Service]", service));
    }
    assert!(has_directive(
        &recovery,
        "[Unit]",
        "OnSuccess=maki-workload@%i.target"
    ));
    assert!(has_directive(&recovery, "[Unit]", "JobTimeoutSec=360"));
    assert!(
        !recovery.contains("ExecStartPost="),
        "a failed cleanup must have no unconditional workload restart command"
    );
    assert!(
        !recovery.contains("RemainAfterExit=yes"),
        "successful recovery must return inactive so a later failure can run it again"
    );
}

#[test]
fn lifecycle_target_owns_attach_start_and_stop() {
    let target = repository_file("packaging/systemd/maki-workload@.target");
    let attach = repository_file("packaging/systemd/maki-attach@.service");

    assert!(has_directive(
        &target,
        "[Unit]",
        "Requires=maki-attach@%i.service"
    ));
    assert!(has_directive(
        &target,
        "[Unit]",
        "After=maki-attach@%i.service"
    ));
    assert!(has_directive(
        &target,
        "[Install]",
        "WantedBy=multi-user.target"
    ));

    for dependency in [
        "BindsTo=maki@%i.service",
        "After=maki@%i.service",
        "PartOf=maki-workload@%i.target",
    ] {
        assert!(has_directive(&attach, "[Unit]", dependency));
    }
    assert!(has_directive(
        &attach,
        "[Service]",
        "ExecStop=/usr/bin/maki-attach cleanup --volume %i"
    ));
    assert!(
        !has_directive(&attach, "[Install]", "WantedBy=multi-user.target"),
        "attach must be enabled only through the lifecycle target"
    );
}

#[test]
fn registered_workload_is_stopped_with_storage_and_verified_on_every_start() {
    let drop_in = repository_file("packaging/examples/maki-workload.service.d/10-maki.conf");

    for dependency in [
        "BindsTo=maki-attach@pg.service",
        "After=maki-attach@pg.service",
        "PartOf=maki-workload@pg.target",
        "Conflicts=maki-recover@pg.service",
    ] {
        assert!(has_directive(&drop_in, "[Unit]", dependency));
    }
    assert!(has_directive(
        &drop_in,
        "[Service]",
        "ExecStartPre=!/usr/bin/maki-attach verify --volume pg"
    ));
    assert!(has_directive(
        &drop_in,
        "[Install]",
        "RequiredBy=maki-workload@pg.target"
    ));
}
