use super::*;
use crate::plan::AttachmentIdentity;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    root: std::path::PathBuf,
    record: BoundDeviceRecord,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "maki-detach-observe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(root.join("sys/nbd3/holders")).unwrap();
        std::fs::write(root.join("sys/nbd3/dev"), "43:3\n").unwrap();
        let mountpoint = root.join("mount");
        std::fs::create_dir(&mountpoint).unwrap();
        std::fs::write(
            mountpoint.join(crate::plan::SENTINEL_FILE),
            "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c\n",
        )
        .unwrap();
        Self {
            root,
            record: BoundDeviceRecord {
                version: 1,
                volume: "pg".into(),
                attachment: AttachmentIdentity {
                    volume_uuid: "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c".into(),
                    nbd_socket: "/run/maki/pg/nbd.sock".into(),
                    mountpoint: mountpoint.to_str().unwrap().into(),
                    vg_name: "vg-maki".into(),
                    lv_name: "data-lv".into(),
                },
                device: "/dev/nbd3".into(),
                connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
            },
        }
    }

    fn mapping(&self, name: &str, slave: &str) {
        let map = self.root.join("sys/dm-0");
        std::fs::create_dir_all(map.join("dm")).unwrap();
        std::fs::create_dir_all(map.join("slaves")).unwrap();
        std::fs::write(map.join("dm/name"), name).unwrap();
        std::fs::write(map.join("dm/uuid"), "LVM-fixture-uuid\n").unwrap();
        std::fs::write(map.join("dev"), "253:0\n").unwrap();
        std::fs::write(map.join("slaves").join(slave), "").unwrap();
        std::fs::write(self.root.join("sys/nbd3/holders/dm-0"), "").unwrap();
    }

    fn mountinfo(&self, device: &str, root: &str, fs: &str) -> String {
        format!(
            "40 25 {device} {root} {} rw - {fs} /dev/mapper/vg--maki-data--lv rw\n",
            self.record.attachment.mountpoint
        )
    }

    fn observe(&self, mounts: &str) -> io::Result<DetachObservation> {
        observe(&self.record, mounts, &self.root.join("sys"))
    }

    fn partition(&self) {
        std::fs::create_dir_all(self.root.join("sys/nbd3p1/holders")).unwrap();
        std::fs::write(self.root.join("sys/nbd3p1/partition"), "1\n").unwrap();
        std::fs::write(self.root.join("sys/nbd3p1/dev"), "43:4\n").unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn observation_distinguishes_complete_and_partial_detach() {
    let fixture = Fixture::new();
    let completed = fixture.observe("").unwrap();
    assert!(!completed.mounted && !completed.vg_active && !completed.nbd_in_use);
    fixture.mapping("vg--maki-data--lv", "nbd3");
    let unmounted = fixture.observe("").unwrap();
    assert!(!unmounted.mounted && unmounted.vg_active && unmounted.nbd_in_use);
    let attached = fixture
        .observe(&fixture.mountinfo("253:0", "/", "xfs"))
        .unwrap();
    assert!(attached.mounted && attached.vg_active && attached.nbd_in_use);
}

#[test]
fn replacement_mount_device_filesystem_subtree_or_sentinel_is_rejected() {
    let fixture = Fixture::new();
    fixture.mapping("vg--maki-data--lv", "nbd3");
    for (device, root, fs) in [
        ("253:1", "/", "xfs"),
        ("253:0", "/subdir", "xfs"),
        ("253:0", "/", "ext4"),
    ] {
        assert!(fixture
            .observe(&fixture.mountinfo(device, root, fs))
            .is_err());
    }
    std::fs::write(
        Path::new(&fixture.record.attachment.mountpoint).join(crate::plan::SENTINEL_FILE),
        "other-volume",
    )
    .unwrap();
    assert!(fixture
        .observe(&fixture.mountinfo("253:0", "/", "xfs"))
        .is_err());
}

#[test]
fn vg_mapping_on_a_different_device_or_unreadable_topology_is_rejected() {
    let fixture = Fixture::new();
    fixture.mapping("vg--maki-data--lv", "nbd4");
    std::fs::create_dir_all(fixture.root.join("sys/nbd4/slaves")).unwrap();
    assert!(fixture.observe("").is_err());
    std::fs::remove_file(fixture.root.join("sys/dm-0/slaves/nbd4")).unwrap();
    std::fs::write(fixture.root.join("sys/dm-0/slaves/dm-1"), "").unwrap();
    assert!(fixture.observe("").is_err());
}

#[test]
fn malformed_mountinfo_cannot_be_treated_as_an_absent_mount() {
    let fixture = Fixture::new();
    for text in [
        "malformed\n",
        "1 2 invalid / / rw - xfs /dev/x rw\n",
        "1 2 8:0 / / rw\n",
    ] {
        assert!(fixture.observe(text).is_err());
    }
}

#[test]
fn another_vg_with_an_escaped_hyphen_prefix_is_not_the_recorded_vg() {
    let fixture = Fixture::new();
    fixture.mapping("vg--maki--other-data--lv", "nbd4");
    std::fs::create_dir_all(fixture.root.join("sys/nbd4/slaves")).unwrap();
    std::fs::remove_file(fixture.root.join("sys/nbd3/holders/dm-0")).unwrap();
    let observed = fixture.observe("").unwrap();
    assert!(!observed.vg_active && !observed.nbd_in_use);
}

#[test]
fn an_active_holder_of_a_recorded_nbd_partition_prevents_disconnect() {
    let fixture = Fixture::new();
    fixture.partition();
    std::fs::write(fixture.root.join("sys/nbd3p1/holders/dm-9"), "").unwrap();
    let observed = fixture.observe("").unwrap();
    assert!(!observed.mounted && !observed.vg_active);
    assert!(
        observed.nbd_in_use,
        "a partition holder keeps the whole NBD device in use"
    );
}

#[test]
fn direct_mounts_of_the_recorded_nbd_or_its_partition_prevent_disconnect() {
    let fixture = Fixture::new();
    fixture.partition();
    for device in ["43:3", "43:4"] {
        let mounts = format!("44 25 {device} / /other-mount rw - xfs /dev/fixture rw\n");
        let observed = fixture.observe(&mounts).unwrap();
        assert!(!observed.mounted && !observed.vg_active);
        assert!(
            observed.nbd_in_use,
            "direct mount of {device} is still using the NBD device"
        );
    }
}
