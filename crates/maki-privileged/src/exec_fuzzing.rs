//! The fuzz harness's way into the helper's readers of command output and
//! of sysfs (`fuzz/harness`, targets `helper_reports` and `helper_sysfs`).
//! Built only with the `fuzzing` feature, which only the harness enables:
//! nothing here is part of the helper. Linux only, like the executor.
//!
//! [`reports`] reads what the commands the helper runs as root print, each
//! through the reader the executor hands it to: LVM's `fullreport` JSON
//! (`lvm_preflight::validate`), `blkid`'s label probe
//! (`lvm_preflight::probe_label`) and filesystem probe
//! (`verify_filesystem_probe`), `dmsetup info` (`verify_removal_info`),
//! `blockdev --getsize64` (`lv_size_of`) and `blkid -o value`
//! (`blkid_value`). Its first byte selects the command (modulo 6); for
//! every command but LVM the next byte is the exit (bit 0 a failure, bit 1
//! a line on stderr, bit 2, for the filesystem probe, no expected UUID) and
//! the rest is stdout. LVM's report is read against a fixed candidate set
//! (`/dev/nbd3` and its partition `/dev/nbd3p1`, whose label the probe
//! found) for `maki-vg/data`, pinned to the report's identity when bit 7 of
//! the first byte is set.
//!
//! [`sysfs`] builds a `/sys/class/block` and a mount table from its input
//! and runs a reader of the kernel's block topology over them. Its first
//! byte selects the reader (modulo 8, [`OBSERVE`] to [`CONNECTION`]); the
//! mount table follows, up to the first NUL byte; then one line per entry
//! of the tree: `path=content` writes an attribute (its content and a
//! newline, as sysfs does), `path/` makes a directory and `path>target` a
//! symbolic link to `target`, both relative to the tree's root. Paths are
//! up to six components of up to 64 bytes, any bytes but `/` and NUL, and
//! neither `.` nor `..`; other lines are skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use super::lvm_preflight::{self, Device, VerifiedLvm};
use super::{allocation, blkid_value, displaced, lv_size_of, recover, verify_filesystem_probe};
use crate::plan::{AttachmentIdentity, LvmIdentityPins};
use crate::state::BoundDeviceRecord;

pub const LVM_REPORT: u8 = 0;
pub const PV_LABEL: u8 = 1;
pub const FILESYSTEM: u8 = 2;
pub const DM_INFO: u8 = 3;
pub const LV_SIZE: u8 = 4;
pub const BLKID_VALUE: u8 = 5;
/// LVM's report: the attachment pins the identity the report names.
pub const PINNED: u8 = 0x80;
/// The exit byte: the command failed, wrote to stderr, and (filesystem
/// probe) no filesystem UUID is expected.
pub const FAILED: u8 = 1;
pub const STDERR: u8 = 2;
pub const UNEXPECTED: u8 = 4;

pub const OBSERVE: u8 = 0;
pub const ALLOCATE: u8 = 1;
pub const CAPTURE: u8 = 2;
pub const INTENT: u8 = 3;
pub const PREFLIGHT: u8 = 4;
pub const MAPPING: u8 = 5;
pub const DISPLACED: u8 = 6;
pub const CONNECTION: u8 = 7;

pub const PV_UUID: &str = "aB3dE5-fG7h-iJ9k-lM1n-oP3q-rS5t-uV7wX9";
pub const VG_UUID: &str = "Zy8xW6-vU4t-sR2q-pO0n-mL8k-jI6h-gF4eD2";
pub const LV_UUID: &str = "Qw1eR2-tY3u-iO4p-aS5d-fG6h-jK7l-zX8cV9";
pub const FS_UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";
pub const VG: &str = "maki-vg";
pub const LV: &str = "data";
pub const MOUNTPOINT: &str = "/mnt/maki";
pub const CONNECTION_ID: &str = "maki-11111111-2222-4333-8444-555555555555";
/// The device-mapper name of the attachment's LV.
pub const MAPPING_NAME: &str = "maki--vg-data";
/// The device a reservation of another volume's record takes.
pub const RESERVED: &str = "/dev/nbd1";

/// The kernel's numbers of the candidates, as their device nodes show them.
const NUMBERS: [(&str, (u32, u32)); 3] = [
    ("/dev/nbd3", (43, 48)),
    ("/dev/nbd3p1", (43, 49)),
    ("/dev/nbd3p2", (43, 50)),
];
const SECTORS: u64 = 2_097_152;
const PARTITION_START: u64 = 2048;

fn number(path: &Path) -> io::Result<(u32, u32)> {
    NUMBERS
        .iter()
        .find(|(name, _)| Path::new(name) == path)
        .map(|(_, number)| *number)
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
}

fn pins() -> LvmIdentityPins {
    LvmIdentityPins {
        pv_uuids: vec![PV_UUID.into()],
        vg_uuid: VG_UUID.into(),
        lv_uuid: LV_UUID.into(),
    }
}

/// The attachment's trusted record.
fn record(pinned: bool) -> BoundDeviceRecord {
    BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        attachment: AttachmentIdentity {
            volume_uuid: FS_UUID.into(),
            nbd_socket: "/run/maki/pg/nbd.sock".into(),
            mountpoint: MOUNTPOINT.into(),
            vg_name: VG.into(),
            lv_name: LV.into(),
            lvm_identity: pinned.then(pins),
        },
        device: "/dev/nbd3".into(),
        connection_id: CONNECTION_ID.into(),
        recovery: None,
        recovery_intent: None,
    }
}

/// The candidates preflight found: the device and its one partition.
fn devices() -> Vec<Device> {
    vec![
        Device {
            path: "/dev/nbd3".into(),
            number: (43, 48),
            start: 0,
            sectors: SECTORS,
        },
        Device {
            path: "/dev/nbd3p1".into(),
            number: (43, 49),
            start: PARTITION_START,
            sectors: SECTORS - PARTITION_START,
        },
    ]
}

fn labels() -> BTreeMap<String, String> {
    BTreeMap::from([("/dev/nbd3p1".to_string(), PV_UUID.to_string())])
}

/// LVM's `fullreport` of the attachment's volume group, as `lvm` prints it
/// for the preflight's report command.
pub fn report() -> String {
    format!(
        r#"  {{
      "report": [
          {{
              "vg": [
                  {{"vg_name":"{VG}", "vg_uuid":"{VG_UUID}", "vg_seqno":"3", "pv_count":"1", "vg_missing_pv_count":"0", "vg_partial":"0", "vg_exported":"0", "vg_systemid":"", "vg_lock_type":""}}
              ]
              ,
              "pv": [
                  {{"pv_name":"/dev/nbd3p1", "pv_uuid":"{PV_UUID}", "vg_uuid":"{VG_UUID}", "pv_missing":"0", "pv_duplicate":"0"}}
              ]
              ,
              "lv": [
                  {{"lv_name":"{LV}", "lv_uuid":"{LV_UUID}", "vg_uuid":"{VG_UUID}", "lv_layout":"linear"}}
              ]
              ,
              "pvseg": [
                  {{"pv_uuid":"{PV_UUID}"}}
              ]
              ,
              "seg": [
                  {{"lv_uuid":"{LV_UUID}"}}
              ]
          }}
      ]
  }}
"#
    )
}

/// What preflight verified from [`report`].
fn verified() -> VerifiedLvm {
    lvm_preflight::validate(
        report().as_bytes(),
        devices(),
        labels(),
        VG,
        LV,
        None,
        |path| number(Path::new(path)),
    )
    .expect("the sample report verifies")
}

fn output(exit: u8, stdout: &[u8]) -> Output {
    Output {
        status: ExitStatus::from_raw(if exit & FAILED != 0 { 2 << 8 } else { 0 }),
        stdout: stdout.to_vec(),
        stderr: if exit & STDERR != 0 {
            b"  WARNING: something\n".to_vec()
        } else {
            Vec::new()
        },
    }
}

/// Read the command output in `data` with the reader its first byte
/// selects, and return whether the reader accepted it. Panics where an
/// accepted output yields what the helper's later readers refuse.
pub fn reports(data: &[u8]) -> bool {
    let Some((&selector, rest)) = data.split_first() else {
        return false;
    };
    let command = (selector & 0x7f) % 6;
    if command == LVM_REPORT {
        let pinned = selector & PINNED != 0;
        let record = record(pinned);
        let Ok(verified) = lvm_preflight::validate(
            rest,
            devices(),
            labels(),
            VG,
            LV,
            record.attachment.lvm_identity.as_ref(),
            |path| number(Path::new(path)),
        ) else {
            return false;
        };
        // What preflight verifies is persisted before activation, and
        // recovery must accept it from the record.
        lvm_preflight::validate_recovery_identity(&record, &verified)
            .expect("recovery accepts what preflight verified");
        let persisted = serde_json::to_vec(&verified).expect("a verified identity encodes");
        assert_eq!(
            serde_json::from_slice::<VerifiedLvm>(&persisted).expect("and decodes"),
            verified
        );
        crate::config::check_lvm_uuid("VG UUID", verified.vg_uuid()).expect("a verified VG UUID");
        return true;
    }
    let Some((&exit, stdout)) = rest.split_first() else {
        return false;
    };
    let output = output(exit, stdout);
    let succeeded = exit & FAILED == 0;
    match command {
        PV_LABEL => match lvm_preflight::fuzzing::probe_label(&output) {
            Ok(label) => {
                assert!(succeeded && exit & STDERR == 0, "a failed probe read");
                if let Some(label) = label {
                    crate::config::check_lvm_uuid("PV UUID", &label).expect("a PV UUID");
                }
                true
            }
            Err(_) => false,
        },
        FILESYSTEM => {
            let expected = (exit & UNEXPECTED == 0).then_some(FS_UUID);
            let accepted = verify_filesystem_probe(expected, &output).is_ok();
            assert!(!accepted || succeeded, "a failed probe read");
            accepted
        }
        DM_INFO => {
            let accepted = recover::fuzzing::removal_info(
                MAPPING_NAME,
                &format!(
                    "LVM-{}{}",
                    VG_UUID.replace('-', ""),
                    LV_UUID.replace('-', "")
                ),
                (253, 3),
                &output,
            )
            .is_ok();
            assert!(!accepted || (succeeded && exit & STDERR == 0));
            accepted
        }
        LV_SIZE => match lv_size_of(&output) {
            Ok(size) => {
                assert!(succeeded && size > 0);
                true
            }
            Err(_) => false,
        },
        _ => match blkid_value(&output) {
            Some(value) => {
                assert!(succeeded && !value.is_empty() && value.trim() == value);
                true
            }
            None => false,
        },
    }
}

/// Where the trees of this process are built; one per call.
fn scratch() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "maki-fuzz-sysfs-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A path of the tree, if `bytes` is one.
fn tree_path(bytes: &[u8]) -> Option<&Path> {
    let components: Vec<&[u8]> = bytes.split(|byte| *byte == b'/').collect();
    let valid = (1..=6).contains(&components.len())
        && components.iter().all(|component| {
            !component.is_empty()
                && component.len() <= 64
                && *component != b"."
                && *component != b".."
                && !component.contains(&0)
        });
    valid.then(|| Path::new(OsStr::from_bytes(bytes)))
}

/// Make the tree `spec` describes below `root`. What cannot be made (an
/// entry below a file, a name taken) is skipped.
fn build(root: &Path, spec: &[u8]) {
    for line in spec.split(|byte| *byte == b'\n').take(128) {
        let link = line.iter().position(|byte| *byte == b'>');
        let assign = line.iter().position(|byte| *byte == b'=');
        if let Some(at) = link.filter(|at| assign.is_none_or(|assign| *at < assign)) {
            if let (Some(path), Some(target)) = (tree_path(&line[..at]), tree_path(&line[at + 1..]))
            {
                let path = root.join(path);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::os::unix::fs::symlink(root.join(target), path);
            }
        } else if let Some(at) = assign {
            if let Some(path) = tree_path(&line[..at]) {
                let path = root.join(path);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(path, [&line[at + 1..], b"\n"].concat());
            }
        } else if let Some(path) = line.strip_suffix(b"/").and_then(tree_path) {
            let _ = std::fs::create_dir_all(root.join(path));
        }
    }
}

/// Build the tree in `data`, run the reader its first byte selects over it
/// and its mount table, and return whether the reader accepted what it
/// observed. Panics where an accepted observation contradicts itself or
/// what a later reader of the same state must accept.
pub fn sysfs(data: &[u8]) -> bool {
    let Some((&selector, rest)) = data.split_first() else {
        return false;
    };
    let (mounts, spec) = match rest.iter().position(|byte| *byte == 0) {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, &[][..]),
    };
    let root = scratch();
    if std::fs::create_dir(&root).is_err() {
        return false;
    }
    build(&root, spec);
    let accepted = read(selector % 8, mounts, &root);
    let _ = std::fs::remove_dir_all(&root);
    accepted
}

fn read(reader: u8, mounts: &[u8], sysfs: &Path) -> bool {
    match reader {
        OBSERVE => match crate::detach::observe(&record(false), mounts, sysfs) {
            Ok(observed) => {
                assert!(!observed.writable || observed.mounted, "{observed:?}");
                true
            }
            Err(_) => false,
        },
        ALLOCATE => {
            let reserved = BTreeSet::from([RESERVED.to_string()]);
            match allocation::fuzzing::choose(sysfs, mounts, &reserved) {
                Ok(device) => {
                    assert!(!reserved.contains(&device), "{device} is reserved");
                    let index = crate::probe::nbd_index(&device).expect("an NBD device");
                    assert!(
                        !crate::nbd_kernel::device_shows_connection(sysfs, index)
                            .expect("the chosen device was read"),
                        "{device} shows a connection"
                    );
                    true
                }
                Err(_) => false,
            }
        }
        CAPTURE => {
            let mut record = record(false);
            let Ok(proof) = recover::capture(&record, mounts, sysfs) else {
                return false;
            };
            let persisted = serde_json::to_vec(&proof).expect("a proof encodes");
            assert_eq!(
                serde_json::from_slice::<recover::RecoveryProof>(&persisted).expect("and decodes"),
                proof
            );
            record.recovery = Some(proof);
            // The proof just captured authorizes the recovery of what it saw.
            recover::observe(&record, mounts, sysfs)
                .expect("recovery accepts the state its proof was captured from");
            let _ = lvm_preflight::recorded_scope(&record);
            let _ = recover::fuzzing::force_deactivation_target(&record, mounts, sysfs);
            true
        }
        INTENT => {
            let mut record = record(true);
            record.recovery_intent = Some(recover::RecoveryIntent::new(&verified()));
            let accepted = recover::observe_disconnected(&record, mounts, sysfs).is_ok();
            let _ = recover::observe(&record, mounts, sysfs);
            let _ = recover::fuzzing::inventory(&record, sysfs);
            accepted
        }
        PREFLIGHT => {
            let Ok(devices) = lvm_preflight::fuzzing::discover_at(sysfs, "/dev/nbd3", number)
            else {
                return false;
            };
            let (root, partitions) = devices.split_first().expect("the device itself");
            assert_eq!((root.path.as_str(), root.start), ("/dev/nbd3", 0));
            let mut numbers = BTreeSet::new();
            for device in &devices {
                assert!(numbers.insert(device.number), "{devices:?}");
            }
            for partition in partitions {
                assert!(partition.path.starts_with("/dev/nbd3p"));
                assert!(
                    partition.sectors > 0 && partition.start + partition.sectors <= root.sectors
                );
            }
            true
        }
        MAPPING => {
            let record = record(false);
            let verified = verified();
            let accepted = lvm_preflight::verify_mapping(&record, &verified, sysfs).is_ok();
            if accepted {
                lvm_preflight::verify_rollback_mapping(&record, &verified, sysfs)
                    .expect("a rollback accepts an activation preflight accepted");
            }
            accepted
        }
        DISPLACED => {
            let mut record = record(true);
            record.recovery_intent = Some(recover::RecoveryIntent::new(&verified()));
            let vg = displaced::recorded_vg_uuid(&record).expect("the record names its VG");
            displaced::remains(&record, &vg, mounts, sysfs).is_ok_and(|remains| remains.is_none())
        }
        _ => {
            let backend = super::nbd_backend_at(sysfs, "/dev/nbd3");
            let shows = crate::nbd_kernel::device_shows_connection(sysfs, 3);
            match (&backend, &shows) {
                (Ok(Some(backend)), Ok(shows)) => {
                    assert!(*shows, "backend {backend:?} without a connection");
                    assert!(!backend.is_empty() && backend.trim() == backend);
                }
                (Ok(None), Ok(shows)) => assert!(!shows, "a connection without a backend"),
                (Err(error), Ok(true)) if error.kind() == io::ErrorKind::Unsupported => {}
                _ => {}
            }
            matches!(backend, Ok(Some(_)))
        }
    }
}

/// `selector` followed by `bytes`.
fn input(selector: u8, bytes: &[u8]) -> Vec<u8> {
    [&[selector][..], bytes].concat()
}

/// The committed seeds of `helper_reports`: what the commands print on a
/// host with the attachment's volume group, and copies changed where the
/// helper must refuse them. A seed's name says what [`reports`] returns
/// for it (`valid-` true, `refused-` false, `noise-` either).
pub fn report_seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));
    let report = report();
    add("valid-lvm-report", input(LVM_REPORT, report.as_bytes()));
    add(
        "valid-lvm-report-pinned",
        input(LVM_REPORT | PINNED, report.as_bytes()),
    );
    let changed = |from: &str, to: &str| report.replacen(from, to, 1).into_bytes();
    add(
        "valid-lvm-report-hidden-lv",
        input(
            LVM_REPORT,
            &changed(
                r#""lv": ["#,
                &format!(
                    r#""lv": [{{"lv_name":"[data_tmeta]", "lv_uuid":"Ab1cD2-eF3g-hI4j-kL5m-nO6p-qR7s-tU8vW9", "vg_uuid":"{VG_UUID}", "lv_layout":"linear"}},"#
                ),
            ),
        ),
    );
    add(
        "refused-lvm-report-pinned-other-lv",
        input(
            LVM_REPORT | PINNED,
            &report
                .replace(LV_UUID, "Ab1cD2-eF3g-hI4j-kL5m-nO6p-qR7s-tU8vW9")
                .into_bytes(),
        ),
    );
    add(
        "refused-lvm-report-foreign-vg",
        input(
            LVM_REPORT,
            &changed(r#""vg_name":"maki-vg""#, r#""vg_name":"other""#),
        ),
    );
    add(
        "refused-lvm-report-partial-vg",
        input(
            LVM_REPORT,
            &changed(r#""vg_partial":"0""#, r#""vg_partial":"1""#),
        ),
    );
    add(
        "refused-lvm-report-system-id",
        input(
            LVM_REPORT,
            &changed(r#""vg_systemid":"""#, r#""vg_systemid":"host2""#),
        ),
    );
    add(
        "refused-lvm-report-pv-count",
        input(
            LVM_REPORT,
            &changed(r#""pv_count":"1""#, r#""pv_count":"2""#),
        ),
    );
    add(
        "refused-lvm-report-pv-outside-candidates",
        input(
            LVM_REPORT,
            &changed(r#""pv_name":"/dev/nbd3p1""#, r#""pv_name":"/dev/sda1""#),
        ),
    );
    add(
        "refused-lvm-report-pv-other-label",
        input(
            LVM_REPORT,
            &changed(r#""pv_name":"/dev/nbd3p1""#, r#""pv_name":"/dev/nbd3""#),
        ),
    );
    add(
        "refused-lvm-report-configured-lv-hidden",
        input(
            LVM_REPORT,
            &changed(r#""lv_name":"data""#, r#""lv_name":"[data]""#),
        ),
    );
    add(
        "refused-lvm-report-cachevol",
        input(
            LVM_REPORT,
            &changed(r#""lv_layout":"linear""#, r#""lv_layout":"cache,cachevol""#),
        ),
    );
    add(
        "refused-lvm-report-layout-token",
        input(
            LVM_REPORT,
            &changed(r#""lv_layout":"linear""#, r#""lv_layout":"Linear""#),
        ),
    );
    add(
        "refused-lvm-report-lv-of-another-vg",
        input(
            LVM_REPORT,
            &report
                .replacen(
                    &format!(r#""lv_uuid":"{LV_UUID}", "vg_uuid":"{VG_UUID}""#),
                    &format!(r#""lv_uuid":"{LV_UUID}", "vg_uuid":"{PV_UUID}""#),
                    1,
                )
                .into_bytes(),
        ),
    );
    add(
        "refused-lvm-report-two-groups",
        input(LVM_REPORT, &{
            let start = report
                .find(
                    r#"{
              "vg""#,
                )
                .expect("a group");
            let end = report.rfind("      ]").expect("the end of the groups");
            let group = report[start..end].trim_end().to_string();
            report
                .replacen(&group, &format!("{group},{group}"), 1)
                .into_bytes()
        }),
    );
    add(
        "refused-lvm-report-not-json",
        input(LVM_REPORT, &report.as_bytes()[..report.len() / 2]),
    );
    add(
        "refused-lvm-report-missing-field",
        input(LVM_REPORT, &changed(r#", "vg_lock_type":"""#, "")),
    );
    add(
        "noise-lvm-report",
        input(LVM_REPORT, &{
            let mut bytes = report.clone().into_bytes();
            bytes[300] ^= 0x01;
            bytes
        }),
    );

    let label = format!("UUID={PV_UUID}\nTYPE=LVM2_member\n");
    add(
        "valid-pv-label",
        input(PV_LABEL, &[&[0][..], label.as_bytes()].concat()),
    );
    add(
        "valid-pv-label-partition-table",
        input(PV_LABEL, b"\0PTTYPE=gpt\n"),
    );
    add(
        "valid-pv-label-other-type",
        input(PV_LABEL, b"\0TYPE=ext4\nUUID=x\n"),
    );
    add(
        "refused-pv-label-failed",
        input(PV_LABEL, &[&[FAILED][..], label.as_bytes()].concat()),
    );
    add(
        "refused-pv-label-warning",
        input(PV_LABEL, &[&[STDERR][..], label.as_bytes()].concat()),
    );
    add("refused-pv-label-nothing", input(PV_LABEL, b"\0"));
    add(
        "refused-pv-label-duplicate-field",
        input(
            PV_LABEL,
            &[&[0][..], label.as_bytes(), b"TYPE=LVM2_member\n"].concat(),
        ),
    );
    add(
        "refused-pv-label-over-partition-table",
        input(
            PV_LABEL,
            &[&[0][..], label.as_bytes(), b"PTTYPE=dos\n"].concat(),
        ),
    );
    add(
        "refused-pv-label-without-uuid",
        input(PV_LABEL, b"\0TYPE=LVM2_member\n"),
    );
    add(
        "refused-pv-label-line-without-value",
        input(PV_LABEL, b"\0TYPE\n"),
    );

    let filesystem = format!("DEVNAME=/proc/self/fd/7\nUUID={FS_UUID}\nTYPE=xfs\n");
    add(
        "valid-filesystem",
        input(FILESYSTEM, &[&[0][..], filesystem.as_bytes()].concat()),
    );
    add(
        "valid-filesystem-upper-case-uuid",
        input(
            FILESYSTEM,
            &[
                &[0][..],
                filesystem
                    .to_uppercase()
                    .replace("TYPE=XFS", "TYPE=xfs")
                    .as_bytes(),
            ]
            .concat(),
        ),
    );
    add(
        "valid-filesystem-first-boot",
        input(FILESYSTEM, b"\x04TYPE=xfs\n"),
    );
    add(
        "refused-filesystem-other-uuid",
        input(
            FILESYSTEM,
            &[&[0][..], filesystem.replace("0f7c", "1f7c").as_bytes()].concat(),
        ),
    );
    add(
        "refused-filesystem-ext4",
        input(
            FILESYSTEM,
            &[
                &[0][..],
                filesystem.replace("TYPE=xfs", "TYPE=ext4").as_bytes(),
            ]
            .concat(),
        ),
    );
    add(
        "refused-filesystem-two-types",
        input(
            FILESYSTEM,
            &[&[0][..], filesystem.as_bytes(), b"TYPE=xfs\n"].concat(),
        ),
    );
    add(
        "refused-filesystem-control-character",
        input(
            FILESYSTEM,
            &[
                &[0][..],
                filesystem.replace("DEVNAME=", "DEVNAME=\x1b").as_bytes(),
            ]
            .concat(),
        ),
    );
    add(
        "refused-filesystem-failed",
        input(FILESYSTEM, &[&[FAILED][..], filesystem.as_bytes()].concat()),
    );

    let info = format!(
        "{MAPPING_NAME}\tLVM-{}{}\t253\t3\t0\n",
        VG_UUID.replace('-', ""),
        LV_UUID.replace('-', "")
    );
    add(
        "valid-dm-info",
        input(DM_INFO, &[&[0][..], info.as_bytes()].concat()),
    );
    add(
        "refused-dm-info-open",
        input(
            DM_INFO,
            &[&[0][..], info.replace("\t3\t0\n", "\t3\t1\n").as_bytes()].concat(),
        ),
    );
    add(
        "refused-dm-info-other-minor",
        input(
            DM_INFO,
            &[
                &[0][..],
                info.replace("\t253\t3\t", "\t253\t4\t").as_bytes(),
            ]
            .concat(),
        ),
    );
    add(
        "refused-dm-info-two-lines",
        input(
            DM_INFO,
            &[&[0][..], info.as_bytes(), info.as_bytes()].concat(),
        ),
    );
    add(
        "refused-dm-info-warning",
        input(DM_INFO, &[&[STDERR][..], info.as_bytes()].concat()),
    );

    add("valid-lv-size", input(LV_SIZE, b"\x0010737418240\n"));
    add("refused-lv-size-zero", input(LV_SIZE, b"\x000\n"));
    add("refused-lv-size-negative", input(LV_SIZE, b"\x00-1\n"));
    add(
        "refused-lv-size-failed",
        input(LV_SIZE, b"\x0110737418240\n"),
    );

    add(
        "valid-blkid-value",
        input(BLKID_VALUE, format!("\0{FS_UUID}\n").as_bytes()),
    );
    add("refused-blkid-value-empty", input(BLKID_VALUE, b"\0 \n"));
    add(
        "refused-blkid-value-failed",
        input(BLKID_VALUE, format!("\x01{FS_UUID}\n").as_bytes()),
    );
    seeds
}

/// The tree of an attachment whose volume group is active on the partition
/// of its device, as `/sys/class/block` shows it: links into the device
/// directories, the partition below its disk.
fn activated() -> String {
    let uuid = format!(
        "LVM-{}{}",
        VG_UUID.replace('-', ""),
        LV_UUID.replace('-', "")
    );
    format!(
        "devices/nbd3/dev=43:48
devices/nbd3/size={SECTORS}
devices/nbd3/pid=4242
devices/nbd3/backend={CONNECTION_ID}
devices/nbd3/holders/
devices/nbd3/nbd3p1/dev=43:49
devices/nbd3/nbd3p1/size={}
devices/nbd3/nbd3p1/start={PARTITION_START}
devices/nbd3/nbd3p1/partition=1
devices/nbd3/nbd3p1/holders/dm-0=
devices/dm-0/dev=253:0
devices/dm-0/dm/name={MAPPING_NAME}
devices/dm-0/dm/uuid={uuid}
devices/dm-0/slaves/nbd3p1=
devices/dm-0/holders/
nbd3>devices/nbd3
nbd3p1>devices/nbd3/nbd3p1
dm-0>devices/dm-0
",
        SECTORS - PARTITION_START
    )
}

/// The same device before activation: no mapping, no holder.
fn connected() -> String {
    activated()
        .replace("holders/dm-0=", "holders/")
        .lines()
        .filter(|line| !line.contains("dm-0"))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// The mount table with the attachment's LV mounted at its mountpoint.
fn mounted(options: &str) -> String {
    format!(
        "22 1 252:1 / / rw,relatime shared:1 - xfs /dev/vda1 rw,attr2\n\
         40 22 253:0 / {MOUNTPOINT} {options} shared:40 - xfs /dev/mapper/{MAPPING_NAME} rw,attr2,inode64\n"
    )
}

const ROOT_ONLY: &str = "22 1 252:1 / / rw,relatime shared:1 - xfs /dev/vda1 rw,attr2\n";

fn tree(selector: u8, mounts: &str, tree: &str) -> Vec<u8> {
    [&[selector][..], mounts.as_bytes(), b"\0", tree.as_bytes()].concat()
}

/// The committed seeds of `helper_sysfs`: the trees and mount tables of an
/// attachment before and after activation and mount, and of free and used
/// devices, with copies changed where a reader must refuse them. A seed's
/// name says what [`sysfs`] returns for it (`valid-` true, `refused-`
/// false, `noise-` either).
pub fn sysfs_seeds() -> Vec<(String, Vec<u8>)> {
    let mut seeds: Vec<(String, Vec<u8>)> = Vec::new();
    let mut add = |name: &str, bytes: Vec<u8>| seeds.push((name.to_string(), bytes));
    let activated = activated();
    let connected = connected();
    let mounted_rw = mounted("rw,nosuid,nodev,noatime");

    add(
        "valid-observe-activated",
        tree(OBSERVE, ROOT_ONLY, &activated),
    );
    add(
        "valid-observe-mounted",
        tree(OBSERVE, &mounted_rw, &activated),
    );
    add(
        "valid-observe-nothing-attached",
        tree(OBSERVE, ROOT_ONLY, "devices/\n"),
    );
    add(
        "refused-observe-mapping-with-foreign-slave",
        tree(
            OBSERVE,
            ROOT_ONLY,
            &format!("{activated}devices/dm-0/slaves/sda=\nsda/dev=8:0\nsda/slaves/\n"),
        ),
    );
    add(
        "refused-observe-cyclic-mappings",
        tree(
            OBSERVE,
            ROOT_ONLY,
            &format!(
                "{activated}devices/dm-0/slaves/dm-1=\ndevices/dm-1/dm/name=maki--vg-pool\n\
                 devices/dm-1/dm/uuid=LVM-x\ndevices/dm-1/dev=253:1\ndevices/dm-1/slaves/dm-0=\n\
                 dm-1>devices/dm-1\n"
            ),
        ),
    );
    add(
        "refused-observe-mounted-other-filesystem",
        tree(
            OBSERVE,
            &mounted_rw.replace("- xfs /dev/mapper", "- ext4 /dev/mapper"),
            &activated,
        ),
    );
    add(
        "refused-observe-mounted-subtree",
        tree(
            OBSERVE,
            &mounted_rw.replace("253:0 / /mnt", "253:0 /sub /mnt"),
            &activated,
        ),
    );
    add(
        "refused-observe-device-number",
        tree(
            OBSERVE,
            ROOT_ONLY,
            &activated.replace("devices/nbd3/dev=43:48", "devices/nbd3/dev=43"),
        ),
    );
    add(
        "refused-observe-partition-number",
        tree(
            OBSERVE,
            ROOT_ONLY,
            &activated.replace("partition=1", "partition=2"),
        ),
    );
    add(
        "refused-observe-incomplete-mount-table",
        tree(OBSERVE, "22 1 252:1 / / rw\n", &activated),
    );
    add(
        "refused-observe-mapping-without-name",
        tree(
            OBSERVE,
            ROOT_ONLY,
            &activated.replace(&format!("devices/dm-0/dm/name={MAPPING_NAME}\n"), ""),
        ),
    );

    let free = "nbd0/dev=43:0\nnbd0/pid=7\nnbd0/holders/\nnbd1/dev=43:16\nnbd1/holders/\n\
                nbd2/dev=43:32\nnbd2/holders/\nnbd10/dev=43:160\nnbd10/holders/\n";
    add("valid-allocate", tree(ALLOCATE, ROOT_ONLY, free));
    add(
        "valid-allocate-past-a-backend",
        tree(
            ALLOCATE,
            ROOT_ONLY,
            &free.replace("nbd2/holders/\n", "nbd2/holders/\nnbd2/backend=maki-x\n"),
        ),
    );
    add(
        "refused-allocate-every-device-used",
        tree(
            ALLOCATE,
            "22 1 43:32 / /srv rw - xfs /dev/nbd2 rw\n",
            &free.replace("nbd10/holders/\n", "nbd10/holders/dm-4=\n"),
        ),
    );
    add(
        "refused-allocate-partition-number",
        tree(
            ALLOCATE,
            ROOT_ONLY,
            &format!("{free}nbd2p1/dev=43:33\nnbd2p1/partition=3\nnbd2p1/holders/\n"),
        ),
    );
    add(
        "refused-allocate-device-number",
        tree(ALLOCATE, ROOT_ONLY, &free.replace("43:32", "43:x")),
    );
    add(
        "refused-allocate-incomplete-mount-table",
        tree(ALLOCATE, "22 1 43:32 /\n", free),
    );

    add("valid-capture", tree(CAPTURE, ROOT_ONLY, &activated));
    add(
        "refused-capture-mounted",
        tree(CAPTURE, &mounted_rw, &activated),
    );
    add(
        "refused-capture-unrecorded-holder",
        tree(
            CAPTURE,
            ROOT_ONLY,
            &activated.replace("devices/nbd3/holders/\n", "devices/nbd3/holders/md0=\n"),
        ),
    );
    add(
        "refused-capture-another-mount-of-the-lv",
        tree(
            CAPTURE,
            "22 1 252:1 / / rw - xfs /dev/vda1 rw\n41 22 253:0 / /elsewhere rw - xfs /dev/dm-0 rw\n",
            &activated,
        ),
    );
    add(
        "refused-capture-not-activated",
        tree(CAPTURE, ROOT_ONLY, &connected),
    );

    add(
        "valid-intent-before-activation",
        tree(INTENT, ROOT_ONLY, &connected),
    );
    add(
        "valid-intent-reset-by-disconnect",
        tree(
            INTENT,
            ROOT_ONLY,
            "devices/nbd3/dev=43:48\ndevices/nbd3/size=0\ndevices/nbd3/holders/\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-intent-new-partition",
        tree(
            INTENT,
            ROOT_ONLY,
            &format!(
                "{connected}devices/nbd3/nbd3p2/dev=43:50\ndevices/nbd3/nbd3p2/size=8\n\
                 devices/nbd3/nbd3p2/start=4096\ndevices/nbd3/nbd3p2/partition=2\n\
                 devices/nbd3/nbd3p2/holders/\nnbd3p2>devices/nbd3/nbd3p2\n"
            ),
        ),
    );
    add(
        "refused-intent-mounted",
        tree(INTENT, &mounted_rw, &activated),
    );
    add(
        "refused-intent-changed-geometry",
        tree(
            INTENT,
            ROOT_ONLY,
            &connected.replace("start=2048", "start=4096"),
        ),
    );

    add("valid-preflight", tree(PREFLIGHT, ROOT_ONLY, &connected));
    add(
        "valid-preflight-whole-device",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            "devices/nbd3/dev=43:48\ndevices/nbd3/size=2097152\ndevices/nbd3/holders/\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-preflight-holder",
        tree(PREFLIGHT, ROOT_ONLY, &activated),
    );
    add(
        "refused-preflight-partition-outside-the-device",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            &connected.replace("start=2048", "start=2097000"),
        ),
    );
    add(
        "refused-preflight-partition-not-below-the-device",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            &connected.replace("devices/nbd3/nbd3p1", "devices/other/nbd3p1"),
        ),
    );
    add(
        "refused-preflight-node-of-another-device",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            &connected.replace("dev=43:49", "dev=43:50"),
        ),
    );
    add(
        "refused-preflight-empty-device",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            &connected.replace("size=2097152", "size=0"),
        ),
    );
    add(
        "refused-preflight-size-not-a-number",
        tree(
            PREFLIGHT,
            ROOT_ONLY,
            &connected.replace("size=2097152", "size=2097152 sectors"),
        ),
    );

    add("valid-mapping", tree(MAPPING, ROOT_ONLY, &activated));
    add(
        "refused-mapping-not-activated",
        tree(MAPPING, ROOT_ONLY, &connected),
    );
    add(
        "refused-mapping-other-lv-uuid",
        tree(
            MAPPING,
            ROOT_ONLY,
            &activated.replace(&LV_UUID.replace('-', ""), &PV_UUID.replace('-', "")),
        ),
    );
    add(
        "refused-mapping-second-target",
        tree(
            MAPPING,
            ROOT_ONLY,
            &format!(
                "{activated}devices/dm-1/dm/name={MAPPING_NAME}\ndevices/dm-1/dm/uuid=LVM-{}{}\n\
                 dm-1>devices/dm-1\n",
                VG_UUID.replace('-', ""),
                LV_UUID.replace('-', "")
            ),
        ),
    );

    add(
        "valid-displaced-nothing-remains",
        tree(
            DISPLACED,
            ROOT_ONLY,
            "devices/nbd3/dev=43:48\ndevices/nbd3/holders/\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-displaced-mapping-remains",
        tree(DISPLACED, ROOT_ONLY, &activated),
    );
    add(
        "refused-displaced-mount-remains",
        tree(
            DISPLACED,
            &mounted_rw,
            "devices/nbd3/dev=43:48\ndevices/nbd3/holders/\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-displaced-unknown-holder",
        tree(
            DISPLACED,
            ROOT_ONLY,
            "devices/nbd3/dev=43:48\ndevices/nbd3/holders/md0=\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "valid-displaced-another-vg-holds-it",
        tree(
            DISPLACED,
            ROOT_ONLY,
            &format!(
                "devices/nbd3/dev=43:48\ndevices/nbd3/holders/dm-5=\nnbd3>devices/nbd3\n\
                 dm-5/dm/uuid=LVM-{}{}\ndm-5/dev=253:5\n",
                PV_UUID.replace('-', ""),
                LV_UUID.replace('-', "")
            ),
        ),
    );

    add("valid-connection", tree(CONNECTION, "", &activated));
    add(
        "refused-connection-none",
        tree(
            CONNECTION,
            "",
            "devices/nbd3/dev=43:48\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-connection-pid-without-backend",
        tree(
            CONNECTION,
            "",
            "devices/nbd3/dev=43:48\ndevices/nbd3/pid=12\nnbd3>devices/nbd3\n",
        ),
    );
    add(
        "refused-connection-empty-backend",
        tree(
            CONNECTION,
            "",
            "devices/nbd3/backend= \nnbd3>devices/nbd3\n",
        ),
    );
    let mut noise = tree(OBSERVE, &mounted_rw, &activated);
    let at = noise.len() - 40;
    noise[at] ^= 0x01;
    add("noise-observe-mounted", noise);
    seeds
}
