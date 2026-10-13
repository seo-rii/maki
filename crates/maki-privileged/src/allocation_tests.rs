use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "maki-allocation-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        fixture.device("nbd2", "43:32");
        fixture.device("nbd3", "43:48");
        fixture
    }

    fn device(&self, name: &str, number: &str) {
        let root = self.0.join(name);
        std::fs::create_dir_all(root.join("holders")).unwrap();
        std::fs::write(root.join("dev"), number).unwrap();
    }

    fn partition(&self) {
        self.device("nbd2p1", "43:33");
        std::fs::write(self.0.join("nbd2p1/partition"), "1\n").unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn review_auto_allocation_skips_disconnected_root_holders() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("nbd2/holders/dm-0"), "").unwrap();
    assert_eq!(choose(&fixture.0, "").unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_skips_disconnected_partition_holders() {
    let fixture = Fixture::new();
    fixture.partition();
    std::fs::write(fixture.0.join("nbd2p1/holders/dm-0"), "").unwrap();
    assert_eq!(choose(&fixture.0, "").unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_skips_direct_and_partition_mounts() {
    for number in ["43:32", "43:33"] {
        let fixture = Fixture::new();
        fixture.partition();
        let mounts = format!("91 20 {number} / /srv/old rw - xfs /dev/old rw\n");
        assert_eq!(choose(&fixture.0, &mounts).unwrap(), "/dev/nbd3");
    }
}

#[test]
fn review_auto_allocation_skips_backend_without_pid() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("nbd2/backend"), "old-connection\n").unwrap();
    assert_eq!(choose(&fixture.0, "").unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_refuses_unreadable_or_malformed_observations() {
    for case in ["backend", "pid", "holders", "dev", "partition", "mountinfo"] {
        let fixture = Fixture::new();
        match case {
            "backend" | "pid" => {
                std::os::unix::fs::symlink(case, fixture.0.join("nbd2").join(case)).unwrap();
            }
            "holders" => {
                std::fs::remove_dir(fixture.0.join("nbd2/holders")).unwrap();
            }
            "dev" => {
                std::fs::write(fixture.0.join("nbd2/dev"), "not-a-device").unwrap();
            }
            "partition" => {
                fixture.partition();
                std::fs::write(fixture.0.join("nbd2p1/partition"), "2\n").unwrap();
            }
            _ => {}
        }
        let mounts = if case == "mountinfo" {
            "incomplete\n"
        } else {
            ""
        };
        assert!(choose(&fixture.0, mounts).is_err(), "accepted {case}");
    }
}

#[test]
fn review_auto_allocation_reports_no_device_when_all_are_occupied() {
    let fixture = Fixture::new();
    for name in ["nbd2", "nbd3"] {
        std::fs::write(fixture.0.join(name).join("holders/dm-0"), "").unwrap();
    }
    assert!(matches!(
        choose(&fixture.0, ""),
        Err(ExecError::NoFreeDevice)
    ));
}

#[test]
fn review_auto_allocation_uses_numeric_order_and_ignores_unrelated_mounts() {
    let fixture = Fixture::new();
    fixture.device("nbd10", "43:160");
    fixture.partition();
    assert_eq!(
        choose(&fixture.0, "91 20 8:1 / /srv/old rw - xfs /dev/sda1 rw\n").unwrap(),
        "/dev/nbd2"
    );
    std::fs::write(fixture.0.join("nbd2/pid"), "123\n").unwrap();
    std::fs::write(fixture.0.join("nbd2/backend"), "old-connection\n").unwrap();
    assert_eq!(choose(&fixture.0, "").unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_reads_mountinfo_before_choosing_a_device() {
    let fixture = Fixture::new();
    let mounts = fixture.0.join("mountinfo");
    assert!(allocate(&fixture.0, &mounts).is_err());
    std::fs::write(&mounts, "91 20 43:32 / /srv/old rw - xfs /dev/nbd2 rw\n").unwrap();
    assert_eq!(allocate(&fixture.0, &mounts).unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_skips_pid_without_backend() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("nbd2/pid"), "123\n").unwrap();
    assert_eq!(choose(&fixture.0, "").unwrap(), "/dev/nbd3");
}

#[test]
fn review_auto_allocation_refuses_oversized_mount_inventory() {
    let fixture = Fixture::new();
    let mounts = fixture.0.join("mountinfo");
    let file = std::fs::File::create(&mounts).unwrap();
    file.set_len(MAX_MOUNTINFO_BYTES as u64 + 1).unwrap();
    assert!(allocate(&fixture.0, &mounts).is_err());
}
