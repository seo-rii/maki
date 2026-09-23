//! MAKI-018: encrypted swap must not recurse through a userspace NBD server.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use super::{linux::classify_swap_with, SwapSafety};

type Device = (u32, u32);

struct Topology {
    root: tempfile::TempDir,
    devices: HashMap<Device, PathBuf>,
    aliases: HashMap<String, Device>,
}

impl Topology {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for dir in [
            "dev/block",
            "block",
            "devices/pci/host",
            "devices/virtual/block",
        ] {
            fs::create_dir_all(root.path().join(dir)).unwrap();
        }
        Self {
            root,
            devices: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    fn add(&mut self, id: Device, name: &str, physical: bool) {
        let parent = if physical {
            "devices/pci/host/block"
        } else {
            "devices/virtual/block"
        };
        let path = self.root.path().join(parent).join(name);
        self.record(id, name, path.clone());
        fs::create_dir(path.join("slaves")).unwrap();
        if physical {
            symlink(
                self.root.path().join("devices/pci/host"),
                path.join("device"),
            )
            .unwrap();
        }
    }

    fn record(&mut self, id: Device, name: &str, path: PathBuf) {
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("dev"), format!("{}:{}\n", id.0, id.1)).unwrap();
        symlink(
            &path,
            self.root
                .path()
                .join(format!("dev/block/{}:{}", id.0, id.1)),
        )
        .unwrap();
        symlink(&path, self.root.path().join("block").join(name)).unwrap();
        self.devices.insert(id, path);
        self.aliases.insert(format!("/dev/{name}"), id);
    }

    fn partition(&mut self, id: Device, parent: Device, name: &str) {
        let path = self.devices[&parent].join(name);
        self.record(id, name, path.clone());
        fs::write(path.join("partition"), "1\n").unwrap();
    }

    fn crypt(&mut self, id: Device, name: &str) {
        self.add(id, name, false);
        fs::create_dir(self.devices[&id].join("dm")).unwrap();
        fs::write(
            self.devices[&id].join("dm/uuid"),
            "CRYPT-LUKS2-fixture-swap\n",
        )
        .unwrap();
        fs::write(self.devices[&id].join("dm/name"), "cryptswap\n").unwrap();
        self.aliases.insert("/dev/mapper/cryptswap".into(), id);
    }

    fn edge(&self, upper: Device, lower: Device) {
        let path = &self.devices[&lower];
        symlink(
            path,
            self.devices[&upper]
                .join("slaves")
                .join(path.file_name().unwrap()),
        )
        .unwrap();
    }

    fn classify(&self, name: &str) -> SwapSafety {
        classify_swap_with(name, self.root.path(), &|path| {
            self.aliases.get(path).copied()
        })
    }

    fn path(&self, id: Device) -> &Path {
        &self.devices[&id]
    }
}

#[test]
fn encrypted_swap_on_nbd_is_rejected() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((43, 0), "nbd0", false);
    t.edge((253, 0), (43, 0));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
    assert_eq!(t.classify("/dev/mapper/cryptswap"), SwapSafety::Unsafe);
}

#[test]
fn nbd_device_number_is_rejected_even_with_an_unexpected_name() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((43, 0), "unexpected-disk", true);
    t.edge((253, 0), (43, 0));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
}

#[test]
fn excessive_dependency_width_is_rejected() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    for index in 0..300 {
        t.add((8, index), &format!("disk{index}"), true);
        t.edge((253, 0), (8, index));
    }
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
}

#[test]
fn missing_or_inconsistent_device_identity_is_rejected() {
    for scenario in ["missing-identity", "changed-identity", "changed-dependency"] {
        let mut t = Topology::new();
        t.crypt((253, 0), "dm-0");
        t.add((8, 0), "sda", true);
        t.edge((253, 0), (8, 0));
        match scenario {
            "missing-identity" => fs::remove_file(t.root.path().join("dev/block/253:0")).unwrap(),
            "changed-identity" => fs::write(t.path((253, 0)).join("dev"), "253:5\n").unwrap(),
            "changed-dependency" => fs::write(t.path((8, 0)).join("dev"), "8:1\n").unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe, "{scenario}");
    }
}

#[test]
fn zram_alias_uses_actual_identity_and_missing_attribute_remains_ram_only() {
    let mut t = Topology::new();
    t.add((252, 0), "zram0", false);
    t.aliases
        .insert("/dev/disk/by-id/ram-swap".into(), (252, 0));
    assert_eq!(t.classify("/dev/disk/by-id/ram-swap"), SwapSafety::RamOnly);
    t.aliases.remove("/dev/zram0");
    assert_eq!(t.classify("/dev/zram0"), SwapSafety::Unsafe);
}

#[test]
fn nbd_partition_below_dm_and_md_is_rejected() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((9, 0), "md0", false);
    t.add((253, 1), "dm-1", false);
    t.add((43, 0), "nbd0", false);
    t.partition((43, 1), (43, 0), "nbd0p1");
    t.add((8, 0), "sda", true);
    t.edge((253, 0), (9, 0));
    t.edge((9, 0), (8, 0));
    t.edge((9, 0), (253, 1));
    t.edge((253, 1), (43, 1));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
}

#[test]
fn independent_disk_partitions_and_shared_dependencies_are_accepted() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((9, 0), "md0", false);
    t.add((253, 1), "dm-1", false);
    t.add((8, 0), "sda", true);
    t.partition((8, 1), (8, 0), "sda1");
    t.edge((253, 0), (9, 0));
    t.edge((253, 0), (253, 1));
    t.edge((9, 0), (8, 1));
    t.edge((253, 1), (8, 1));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Encrypted);
    assert_eq!(t.classify("/dev/sda1"), SwapSafety::Unsafe);
}

#[test]
fn dependency_cycles_are_rejected() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((253, 1), "dm-1", false);
    t.edge((253, 0), (253, 1));
    t.edge((253, 1), (253, 0));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
}

#[test]
fn excessively_deep_dependencies_are_rejected() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    for index in 1..=80 {
        t.add((253, index), &format!("dm-{index}"), false);
        t.edge((253, index - 1), (253, index));
    }
    t.add((8, 0), "sda", true);
    t.edge((253, 80), (8, 0));
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
}

#[test]
fn missing_invalid_and_unknown_leaf_topologies_are_rejected() {
    for scenario in [
        "missing-slaves",
        "invalid-slaves",
        "broken-slave",
        "unknown-virtual",
        "missing-device",
        "invalid-dev",
    ] {
        let mut t = Topology::new();
        t.crypt((253, 0), "dm-0");
        match scenario {
            "missing-slaves" => fs::remove_dir(t.path((253, 0)).join("slaves")).unwrap(),
            "invalid-slaves" => {
                fs::remove_dir(t.path((253, 0)).join("slaves")).unwrap();
                fs::write(t.path((253, 0)).join("slaves"), "not a directory").unwrap();
            }
            "broken-slave" => symlink(
                "/missing-dependency",
                t.path((253, 0)).join("slaves/missing"),
            )
            .unwrap(),
            "unknown-virtual" => {
                t.add((7, 0), "loop0", false);
                t.edge((253, 0), (7, 0));
            }
            "missing-device" => {
                t.add((8, 0), "sda", true);
                fs::remove_file(t.path((8, 0)).join("device")).unwrap();
                t.edge((253, 0), (8, 0));
            }
            "invalid-dev" => fs::write(t.path((253, 0)).join("dev"), "unknown").unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe, "{scenario}");
    }
}

#[test]
fn aliases_resolve_by_device_identity_and_names_do_not_prove_encryption() {
    let mut t = Topology::new();
    t.crypt((253, 0), "dm-0");
    t.add((8, 0), "sda", true);
    t.edge((253, 0), (8, 0));
    t.aliases
        .insert("/dev/disk/by-id/encrypted-swap".into(), (253, 0));
    assert_eq!(
        t.classify("/dev/disk/by-id/encrypted-swap"),
        SwapSafety::Encrypted
    );
    t.aliases.remove("/dev/dm-0"); // A regular file now has that name.
    assert_eq!(t.classify("/dev/dm-0"), SwapSafety::Unsafe);
    t.aliases.insert("/dev/mapper/cryptswap".into(), (8, 0));
    assert_eq!(t.classify("/dev/mapper/cryptswap"), SwapSafety::Unsafe);
}

#[test]
fn zram_writeback_uses_the_same_dependency_proof() {
    let mut t = Topology::new();
    t.add((252, 0), "zram0", false);
    fs::write(t.path((252, 0)).join("backing_dev"), "none\n").unwrap();
    assert_eq!(t.classify("/dev/zram0"), SwapSafety::RamOnly);
    t.crypt((253, 0), "dm-0");
    t.add((43, 0), "nbd0", false);
    t.edge((253, 0), (43, 0));
    fs::write(
        t.path((252, 0)).join("backing_dev"),
        "/dev/mapper/cryptswap\n",
    )
    .unwrap();
    assert_eq!(t.classify("/dev/zram0"), SwapSafety::Unsafe);
    fs::remove_file(t.path((253, 0)).join("slaves/nbd0")).unwrap();
    t.add((8, 0), "sda", true);
    t.edge((253, 0), (8, 0));
    assert_eq!(t.classify("/dev/zram0"), SwapSafety::Encrypted);
    // Read failures are distinct from an absent writeback attribute.
    fs::remove_file(t.path((252, 0)).join("backing_dev")).unwrap();
    fs::create_dir(t.path((252, 0)).join("backing_dev")).unwrap();
    assert_eq!(t.classify("/dev/zram0"), SwapSafety::Unsafe);
}

#[test]
fn empty_zram_writeback_attribute_is_ambiguous() {
    let mut t = Topology::new();
    t.add((252, 0), "zram0", false);
    for value in ["", " \n\t"] {
        fs::write(t.path((252, 0)).join("backing_dev"), value).unwrap();
        assert_eq!(t.classify("/dev/zram0"), SwapSafety::Unsafe);
    }
}
