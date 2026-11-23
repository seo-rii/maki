//! A trusted attach record can outlive its kernel connection: the helper is
//! killed between publishing the record and connecting, or between the
//! disconnect and retiring the record. The device such a record names stays
//! that volume's until one of its own verbs replaces or retires the record.
//!
//! Two volumes share one simulated kernel here: a sysfs tree and a mount
//! table that only the simulated commands change. Device allocation, the
//! backend probe, the mapping checks, every observation and the trusted
//! state are the production ones reading that tree.

use super::super::*;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::{parse, AttachOverrides};
use crate::plan::{plan_attach, plan_detach, AttachRequest, AUTO_NBD_DEVICE};

static NEXT_HOST: AtomicU64 = AtomicU64::new(0);

/// One volume's export: its Maki UUID and the LVM identity on its PV.
struct Export {
    volume: &'static str,
    volume_uuid: &'static str,
    pv_uuid: &'static str,
    vg_uuid: &'static str,
    lv_uuid: &'static str,
}

const PG: Export = Export {
    volume: "pg",
    volume_uuid: "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c",
    pv_uuid: "111111-2222-3333-4444-5555-6666-777777",
    vg_uuid: "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg",
    lv_uuid: "hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn",
};

const DB: Export = Export {
    volume: "db",
    volume_uuid: "1f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2d",
    pv_uuid: "222222-2222-3333-4444-5555-6666-777777",
    vg_uuid: "bbbbbb-bbbb-cccc-dddd-eeee-ffff-gggggg",
    lv_uuid: "iiiiii-iiii-jjjj-kkkk-llll-mmmm-nnnnnn",
};

/// A volume whose image was cloned from pg's: the same LVM identity under
/// another Maki volume and VG name.
const CLONE: Export = Export {
    volume: "clone",
    volume_uuid: "2f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2e",
    pv_uuid: PG.pv_uuid,
    vg_uuid: PG.vg_uuid,
    lv_uuid: PG.lv_uuid,
};

fn request(export: &Export) -> AttachRequest {
    parse(&format!("volume_uuid = '{}'\n", export.volume_uuid))
        .unwrap()
        .into_request(export.volume, AttachOverrides::default(), true)
        .unwrap()
}

/// The same attachment with administrator LVM pins.
fn pinned(export: &Export) -> AttachRequest {
    parse(&format!(
        "volume_uuid = '{}'\n[lvm_identity]\npv_uuids = ['{}']\nvg_uuid = '{}'\nlv_uuid = '{}'\n",
        export.volume_uuid, export.pv_uuid, export.vg_uuid, export.lv_uuid
    ))
    .unwrap()
    .into_request(export.volume, AttachOverrides::default(), true)
    .unwrap()
}

/// A host with `/dev/nbd3` and `/dev/nbd4`, nothing connected or mounted.
struct Host {
    root: PathBuf,
    sysfs: PathBuf,
    mountinfo: PathBuf,
    /// The helper dies right before this command runs.
    killed_before: Option<&'static str>,
    /// The helper dies right after this command took effect.
    killed_after: Option<&'static str>,
    commands: Vec<&'static str>,
    /// Backend reads so far, and a change to the simulated kernel made just
    /// before the given read.
    backend_reads: Cell<usize>,
    before_backend_read: Option<(usize, Change)>,
    /// What LVM finds on the host; see [`Lvm`].
    lvm: RefCell<Lvm>,
}

/// A disk that is no NBD device and carries a volume group of its own.
struct Disk {
    device: &'static str,
    vg_name: &'static str,
    vg_uuid: &'static str,
    lv_name: &'static str,
    lv_bytes: u64,
}

/// LVM as its commands see the host: the PV of each volume's NBD export
/// while the export is connected, and other disks. A command without
/// `--devices` scans what the host's LVM configuration admits, all of it or
/// everything but the NBD devices (a devices file or filter that leaves
/// them out); `--devices` replaces that scan. A VG name that two visible
/// VGs carry is refused, as LVM refuses it.
#[derive(Default)]
struct Lvm {
    disks: Vec<Disk>,
    scan_leaves_out_nbd: bool,
    /// The daemon behind every NBD connection serves no reads.
    nbd_unreadable: bool,
    /// The volume each connection identifier exports.
    exports: BTreeMap<String, &'static str>,
    /// LV sizes of the NBD exports, by VG UUID; 1 GiB until extended.
    export_bytes: BTreeMap<&'static str, u64>,
    /// Each command that acted on a VG, and that VG's UUID.
    acted_on: Vec<(&'static str, &'static str)>,
}

/// One volume group a command can find.
struct Found {
    device: String,
    vg_name: String,
    vg_uuid: &'static str,
    lv_name: &'static str,
}

/// LVM's refusal: a command that ran to its end with status 5.
fn lvm_failed(step: &PlannedStep) -> ExecError {
    ExecError::StepFailed {
        step: step.to_string(),
        status: Some(5),
        stderr: "external command output omitted".into(),
    }
}

/// A change another actor makes to the simulated kernel.
type Change = fn(&Host);

impl Host {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "maki-stale-record-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_HOST.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let host = Self {
            sysfs: root.join("sys"),
            mountinfo: root.join("mountinfo"),
            root,
            killed_before: None,
            killed_after: None,
            commands: Vec::new(),
            backend_reads: Cell::new(0),
            before_backend_read: None,
            lvm: RefCell::default(),
        };
        for index in [3, 4] {
            let device = host.sysfs.join(format!("nbd{index}"));
            std::fs::create_dir_all(device.join("holders")).unwrap();
            std::fs::write(device.join("dev"), format!("43:{index}\n")).unwrap();
            std::fs::write(device.join("size"), "0\n").unwrap();
        }
        std::fs::write(
            &host.mountinfo,
            "21 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n",
        )
        .unwrap();
        host
    }

    fn state(&self) -> TrustedState {
        TrustedState::open_beneath(
            File::open(&self.root).unwrap(),
            Path::new("state"),
            self.root.metadata().unwrap().uid(),
        )
        .unwrap()
    }

    fn mounts(&self) -> Vec<u8> {
        std::fs::read(&self.mountinfo).unwrap()
    }

    fn mounted(&self, mountpoint: &str) -> bool {
        String::from_utf8(self.mounts())
            .unwrap()
            .contains(&format!(" / {mountpoint} "))
    }

    fn nbd(&self, device: &str) -> PathBuf {
        self.sysfs.join(device.strip_prefix("/dev/").unwrap())
    }

    /// The sysfs directory of the active mapping of `vg`'s data LV.
    fn mapping(&self, vg: &str) -> Option<PathBuf> {
        std::fs::read_dir(&self.sysfs)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                std::fs::read_to_string(path.join("dm/name"))
                    .is_ok_and(|name| name.trim() == format!("{vg}-data"))
            })
    }

    fn activate(&self, record: &BoundDeviceRecord) {
        let export = export_of(record);
        let vg = &record.attachment.vg_name;
        let nbd = record.device.strip_prefix("/dev/").unwrap();
        let index = (0..)
            .find(|index| !self.sysfs.join(format!("dm-{index}")).exists())
            .unwrap();
        let mapping = self.sysfs.join(format!("dm-{index}"));
        for directory in ["dm", "slaves", "holders"] {
            std::fs::create_dir_all(mapping.join(directory)).unwrap();
        }
        std::fs::write(mapping.join("dm/name"), format!("{vg}-data\n")).unwrap();
        std::fs::write(
            mapping.join("dm/uuid"),
            format!(
                "LVM-{}{}\n",
                export.vg_uuid.replace('-', ""),
                export.lv_uuid.replace('-', "")
            ),
        )
        .unwrap();
        std::fs::write(mapping.join("dev"), format!("253:{index}\n")).unwrap();
        std::fs::write(mapping.join("slaves").join(nbd), "").unwrap();
        std::fs::write(
            self.sysfs
                .join(nbd)
                .join("holders")
                .join(format!("dm-{index}")),
            "",
        )
        .unwrap();
    }

    /// The volume groups LVM finds with `devices` as its `--devices`, or
    /// through its own scan.
    fn lvm_finds(&self, devices: Option<&[&str]>) -> Vec<Found> {
        let lvm = self.lvm.borrow();
        let admitted = |device: &str, nbd: bool| match devices {
            Some(listed) => listed.contains(&device),
            None => !(nbd && lvm.scan_leaves_out_nbd),
        };
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&self.sysfs).unwrap() {
            let device = format!("/dev/{}", entry.unwrap().file_name().to_str().unwrap());
            let Ok(Some(identifier)) = nbd_backend_at(&self.sysfs, &device) else {
                continue;
            };
            let Some(volume) = lvm.exports.get(&identifier) else {
                continue;
            };
            let export = [PG, DB, CLONE]
                .into_iter()
                .find(|export| export.volume == *volume)
                .unwrap();
            if admitted(&device, true) && !lvm.nbd_unreadable {
                found.push(Found {
                    device,
                    vg_name: format!("vg_maki_{}", export.volume),
                    vg_uuid: export.vg_uuid,
                    lv_name: "data",
                });
            }
        }
        for disk in &lvm.disks {
            if admitted(disk.device, false) {
                found.push(Found {
                    device: disk.device.into(),
                    vg_name: disk.vg_name.into(),
                    vg_uuid: disk.vg_uuid,
                    lv_name: disk.lv_name,
                });
            }
        }
        found
    }

    /// Run `vgchange` or `lvextend` with `args` against [`Lvm`].
    fn simulate_lvm(
        &self,
        step: &PlannedStep,
        program: &str,
        args: &[String],
    ) -> Result<(), ExecError> {
        let mut devices = None;
        let mut selected = None;
        let mut deactivate = false;
        let mut bytes = None;
        let mut positional = Vec::new();
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--devices" => devices = Some(args.next().unwrap().clone()),
                "--select" => {
                    selected = Some(args.next().unwrap().strip_prefix("vg_uuid=").unwrap())
                }
                "--config" => {
                    args.next().unwrap();
                }
                "-an" => deactivate = true,
                "--activate" => deactivate = args.next().unwrap() == "n",
                "-L" => {
                    bytes = Some(
                        args.next()
                            .unwrap()
                            .strip_suffix('b')
                            .unwrap()
                            .parse::<u64>()
                            .unwrap(),
                    )
                }
                option if option.starts_with('-') => panic!("fixture LVM option {option}"),
                _ => positional.push(arg.clone()),
            }
        }
        let listed: Option<Vec<&str>> = devices.as_deref().map(|list| list.split(',').collect());
        let found = self.lvm_finds(listed.as_deref());
        let named = |name: &str| -> Result<Vec<&Found>, ExecError> {
            let matching: Vec<_> = found.iter().filter(|vg| vg.vg_name == name).collect();
            // Not found, or the same name on two visible VGs.
            if matching.len() != 1 {
                return Err(lvm_failed(step));
            }
            Ok(matching)
        };
        let targets: Vec<&Found> = match (program, positional.as_slice()) {
            ("vgchange", [name]) if deactivate => named(name)?,
            ("vgchange", []) if deactivate => found.iter().collect(),
            ("lvextend", [path]) => {
                let (vg, lv) = path.split_once('/').unwrap();
                named(vg)?
                    .into_iter()
                    .filter(|vg| vg.lv_name == lv)
                    .collect()
            }
            _ => panic!("fixture LVM command {program} {positional:?}"),
        };
        // `--select` filters what was found; selecting nothing succeeds.
        for target in targets
            .into_iter()
            .filter(|vg| selected.is_none_or(|uuid| vg.vg_uuid == uuid))
        {
            let mut lvm = self.lvm.borrow_mut();
            lvm.acted_on.push((
                if program == "lvextend" {
                    "lvextend"
                } else {
                    "vgchange"
                },
                target.vg_uuid,
            ));
            let on_nbd = target.device.starts_with("/dev/nbd");
            match bytes {
                Some(bytes) => {
                    let current = if on_nbd {
                        *lvm.export_bytes.get(target.vg_uuid).unwrap_or(&(1 << 30))
                    } else {
                        lvm.disks
                            .iter()
                            .find(|disk| disk.vg_uuid == target.vg_uuid)
                            .unwrap()
                            .lv_bytes
                    };
                    if bytes <= current {
                        return Err(lvm_failed(step));
                    }
                    if on_nbd {
                        lvm.export_bytes.insert(target.vg_uuid, bytes);
                    } else {
                        lvm.disks
                            .iter_mut()
                            .find(|disk| disk.vg_uuid == target.vg_uuid)
                            .unwrap()
                            .lv_bytes = bytes;
                    }
                }
                None if on_nbd => {
                    drop(lvm);
                    self.deactivate(&target.vg_name);
                }
                // The other disk's VG is not active.
                None => {}
            }
        }
        Ok(())
    }

    fn deactivate(&self, vg: &str) {
        while let Some(mapping) = self.mapping(vg) {
            let name = mapping.file_name().unwrap().to_owned();
            for slave in std::fs::read_dir(mapping.join("slaves")).unwrap() {
                let holder = self
                    .sysfs
                    .join(slave.unwrap().file_name())
                    .join("holders")
                    .join(&name);
                std::fs::remove_file(holder).unwrap();
            }
            std::fs::remove_dir_all(mapping).unwrap();
        }
    }

    /// One external command of the helper, with the points at which the
    /// helper process can be killed around it.
    fn command(
        &mut self,
        kind: &'static str,
        effect: impl FnOnce(&Self) -> Result<(), ExecError>,
    ) -> Result<(), ExecError> {
        if self.killed_before == Some(kind) {
            panic!("fixture: helper killed before {kind}");
        }
        self.commands.push(kind);
        effect(self)?;
        if self.killed_after == Some(kind) {
            panic!("fixture: helper killed after {kind}");
        }
        Ok(())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn export_of(record: &BoundDeviceRecord) -> Export {
    [PG, DB, CLONE]
        .into_iter()
        .find(|export| record.attachment.vg_name == format!("vg_maki_{}", export.volume))
        .expect("fixture volume")
}

impl System for Host {
    fn lvm_preflight(
        &mut self,
        record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        let export = export_of(record);
        let number = (43, nbd_index(&record.device).unwrap());
        let report = serde_json::json!({"report": [{
            "vg": [{"vg_name": record.attachment.vg_name, "vg_uuid": export.vg_uuid,
                "vg_seqno": "1", "pv_count": "1", "vg_missing_pv_count": "0", "vg_partial": "0",
                "vg_exported": "0", "vg_systemid": "", "vg_lock_type": ""}],
            "pv": [{"pv_name": record.device, "pv_uuid": export.pv_uuid,
                "vg_uuid": export.vg_uuid, "pv_missing": "0", "pv_duplicate": "0"}],
            "lv": [{"lv_name": "data", "lv_uuid": export.lv_uuid,
                "vg_uuid": export.vg_uuid, "lv_layout": "linear"}]
        }]});
        Ok(lvm_preflight::validate(
            &serde_json::to_vec(&report).unwrap(),
            vec![lvm_preflight::Device {
                path: record.device.clone(),
                number,
                start: 0,
                sectors: 1024,
            }],
            [(record.device.clone(), export.pv_uuid.to_string())].into(),
            &record.attachment.vg_name,
            &record.attachment.lv_name,
            record.attachment.lvm_identity.as_ref(),
            |path| {
                if path == record.device {
                    Ok(number)
                } else {
                    Err(io::Error::other("foreign device"))
                }
            },
        )?)
    }
    fn activate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
        attempted: &mut bool,
    ) -> Result<(), ExecError> {
        if &self.lvm_preflight(record)? != verified {
            return Err(identity_error("fixture LVM metadata changed"));
        }
        *attempted = true;
        self.command("lvm-activate", |host| {
            host.activate(record);
            Ok(())
        })
    }
    fn verify_activated_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        lvm_preflight::verify_mapping(record, verified, &self.sysfs)
    }
    fn verify_rollback_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        lvm_preflight::verify_rollback_mapping(record, verified, &self.sysfs)
    }
    fn deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        self.command("lvm-deactivate", |host| {
            host.deactivate(&record.attachment.vg_name);
            Ok(())
        })
    }
    fn recover_deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        self.deactivate_lvm(record, verified)
    }
    fn deactivate_lvm_from_proof(&mut self, record: &BoundDeviceRecord) -> Result<(), ExecError> {
        self.command("dmsetup-remove", |host| {
            host.deactivate(&record.attachment.vg_name);
            Ok(())
        })
    }
    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        recover::capture(record, &self.mounts(), &self.sysfs).map(Some)
    }
    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        recover::observe(record, &self.mounts(), &self.sysfs)
    }
    fn disconnected_recovery_observation(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<DetachObservation> {
        recover::observe_disconnected(record, &self.mounts(), &self.sysfs)
    }
    /// The size `blockdev` reports for the active LV `vg/lv`.
    fn lv_size(&self, vg: &str, lv: &str) -> Result<u64, ExecError> {
        let mapping = self
            .mapping(vg)
            .filter(|_| lv == "data")
            .ok_or_else(|| identity_error("fixture LV is not active"))?;
        let uuid = std::fs::read_to_string(mapping.join("dm/uuid")).unwrap();
        let export = [PG, DB, CLONE]
            .into_iter()
            .find(|export| uuid.starts_with(&format!("LVM-{}", export.vg_uuid.replace('-', ""))))
            .unwrap();
        Ok(*self
            .lvm
            .borrow()
            .export_bytes
            .get(export.vg_uuid)
            .unwrap_or(&(1 << 30)))
    }
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        self.command(step.kind(), |host| {
            match step {
                PlannedStep::NbdConnect { device, socket, .. } => {
                    let volume = [PG.volume, DB.volume, CLONE.volume]
                        .into_iter()
                        .find(|volume| socket == &format!("/run/maki/{volume}/nbd.sock"))
                        .unwrap();
                    host.lvm
                        .borrow_mut()
                        .exports
                        .insert(identifier.unwrap().into(), volume);
                    let nbd = host.nbd(device);
                    std::fs::write(nbd.join("pid"), "4242\n").unwrap();
                    std::fs::write(nbd.join("backend"), format!("{}\n", identifier.unwrap()))
                        .unwrap();
                    std::fs::write(nbd.join("size"), "1024\n").unwrap();
                }
                PlannedStep::NbdDisconnect { device } => {
                    let nbd = host.nbd(device);
                    std::fs::remove_file(nbd.join("pid")).unwrap();
                    std::fs::remove_file(nbd.join("backend")).unwrap();
                    std::fs::write(nbd.join("size"), "0\n").unwrap();
                }
                PlannedStep::MountXfs { device, mountpoint } => {
                    let vg = device.split('/').nth(2).unwrap();
                    let mapping = host.mapping(vg).expect("the VG is active");
                    let number = std::fs::read_to_string(mapping.join("dev")).unwrap();
                    let mut mounts = host.mounts();
                    mounts.extend_from_slice(
                        format!(
                            "40 21 {} / {mountpoint} rw,noatime,nosuid,nodev - xfs \
                             /dev/mapper/{vg}-data rw\n",
                            number.trim()
                        )
                        .as_bytes(),
                    );
                    std::fs::write(&host.mountinfo, mounts).unwrap();
                }
                PlannedStep::Umount { mountpoint } => {
                    let mounts = String::from_utf8(host.mounts()).unwrap();
                    let kept: String = mounts
                        .lines()
                        .filter(|line| !line.contains(&format!(" / {mountpoint} ")))
                        .map(|line| format!("{line}\n"))
                        .collect();
                    std::fs::write(&host.mountinfo, kept).unwrap();
                }
                // The commands an unscoped step runs.
                PlannedStep::LvmDeactivate { vg_name } => {
                    host.simulate_lvm(step, "vgchange", &["-an".into(), vg_name.clone()])?
                }
                PlannedStep::LvExtend {
                    vg_name,
                    lv_name,
                    target_bytes,
                    ..
                } => host.simulate_lvm(
                    step,
                    "lvextend",
                    &[
                        "-L".into(),
                        format!("{target_bytes}b"),
                        format!("{vg_name}/{lv_name}"),
                    ],
                )?,
                // The filesystem follows the LV it is on.
                PlannedStep::XfsGrowfs { .. } => {}
                PlannedStep::LvmActivate { .. } => {
                    return Err(identity_error("unexpected fixture step"))
                }
                // Module load, block size and the probes change no kernel state.
                _ => {}
            }
            Ok(())
        })
    }
    fn wait_ready(&mut self, _: &PlannedStep, _: &str) -> Result<(), ExecError> {
        Ok(())
    }
    fn allocate(&mut self) -> Result<String, ExecError> {
        super::allocate(&self.sysfs, &self.mountinfo)
    }
    fn allocate_excluding(&mut self, reserved: &BTreeSet<String>) -> Result<String, ExecError> {
        super::allocate_excluding(&self.sysfs, &self.mountinfo, reserved)
    }
    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        let read = self.backend_reads.get() + 1;
        self.backend_reads.set(read);
        if let Some((at, change)) = self.before_backend_read {
            if at == read {
                change(self);
            }
        }
        nbd_backend_at(&self.sysfs, device)
    }
    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        crate::detach::observe(record, &self.mounts(), &self.sysfs)
    }
    fn displaced_remains(
        &self,
        record: &BoundDeviceRecord,
        vg_uuid: &str,
    ) -> io::Result<Option<String>> {
        displaced::remains(
            record,
            vg_uuid,
            &std::fs::read(&self.mountinfo)?,
            &self.sysfs,
        )
    }
}

fn killed(run: impl FnOnce()) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).is_err()
}

/// How a record came to outlive its connection.
#[derive(Clone, Copy, Debug)]
enum Left {
    /// Attach was killed after publishing the record, before connecting.
    ByKilledAttach,
    /// Cleanup was killed after the disconnect, before retiring the record.
    ByKilledCleanup,
}

/// Volume pg holds a record for `/dev/nbd3` and nothing else: no connection,
/// no mapping and no mount.
fn stale_record(left: Left) -> (Host, TrustedState, BoundDeviceRecord) {
    let mut host = Host::new();
    let state = host.state();
    let pg = request(&PG);
    match left {
        Left::ByKilledAttach => {
            host.killed_before = Some("nbd-connect");
            assert!(killed(|| {
                let _ = execute_with(&plan_attach(&pg), Some(&state), &mut host);
            }));
            host.killed_before = None;
        }
        Left::ByKilledCleanup => {
            execute_with(&plan_attach(&pg), Some(&state), &mut host).unwrap();
            host.killed_after = Some("nbd-disconnect");
            assert!(killed(|| {
                let _ = cleanup_with(&plan_detach(&pg), &state, &mut host);
            }));
            host.killed_after = None;
        }
    }
    let record = state
        .read("pg")
        .unwrap()
        .expect("the record outlives the killed helper");
    assert_eq!(record.device, "/dev/nbd3");
    assert_eq!(host.backend("/dev/nbd3").unwrap(), None);
    assert!(host.mapping("vg_maki_pg").is_none() && !host.mounted("/srv/pg"));
    host.commands.clear();
    (host, state, record)
}

fn assert_attached(host: &Host, record: &BoundDeviceRecord) {
    assert_eq!(
        host.backend(&record.device).unwrap().as_ref(),
        Some(&record.connection_id)
    );
    assert!(record.recovery.is_some());
    assert!(host.mapping(&record.attachment.vg_name).is_some());
    assert!(host.mounted(&record.attachment.mountpoint));
}

fn run_verb(
    verb: &str,
    request: &AttachRequest,
    state: &TrustedState,
    host: &mut Host,
) -> Result<(), ExecError> {
    match verb {
        "cleanup" => cleanup_with(&plan_detach(request), state, host),
        "recover" => recover_with(&plan_detach(request), state, host),
        "detach" => execute_with(&plan_detach(request), Some(state), host),
        "attach" => execute_with(&plan_attach(request), Some(state), host),
        _ => unreachable!(),
    }
}

const VERBS: [&str; 4] = ["cleanup", "recover", "detach", "attach"];

fn another_volume_is_allocated_another_device(left: Left) {
    let (mut host, state, stale) = stale_record(left);

    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();

    let other = state.read("db").unwrap().unwrap();
    assert_eq!(
        other.device, "/dev/nbd4",
        "the device volume pg's record names was handed to volume db"
    );
    assert_attached(&host, &other);
    assert_eq!(state.read("pg").unwrap(), Some(stale));
}

#[test]
fn a_record_published_before_a_killed_connect_keeps_its_device() {
    another_volume_is_allocated_another_device(Left::ByKilledAttach);
}

#[test]
fn a_record_left_by_a_killed_cleanup_keeps_its_device() {
    another_volume_is_allocated_another_device(Left::ByKilledCleanup);
}

/// The recorded volume then meets its device without a backend. Cleanup,
/// recover and detach retire the record without a command; attach replaces
/// it and may take its own recorded device again. The other volume, attached
/// in between, is not touched.
#[test]
fn every_verb_of_the_recorded_volume_converges_beside_the_other_volume() {
    for left in [Left::ByKilledAttach, Left::ByKilledCleanup] {
        for verb in VERBS {
            let (mut host, state, stale) = stale_record(left);
            execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
            let other = state.read("db").unwrap().unwrap();
            host.commands.clear();

            run_verb(verb, &request(&PG), &state, &mut host)
                .unwrap_or_else(|error| panic!("{left:?}, {verb}: {error}"));

            if verb == "attach" {
                let renewed = state.read("pg").unwrap().unwrap();
                assert_eq!(renewed.device, "/dev/nbd3", "{left:?}");
                assert_ne!(renewed.connection_id, stale.connection_id, "{left:?}");
                assert_attached(&host, &renewed);
            } else {
                assert!(
                    host.commands.is_empty(),
                    "{left:?}, {verb}: {:?}",
                    host.commands
                );
                assert!(state.read("pg").unwrap().is_none(), "{left:?}, {verb}");
            }
            assert_eq!(
                state.read("db").unwrap(),
                Some(other.clone()),
                "{left:?}, {verb}"
            );
            assert_attached(&host, &other);
        }
    }
}

/// A system that knows only the kernel's view of free devices.
struct KernelView(Host);

impl System for KernelView {
    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        self.0.run_step(step, identifier)
    }
    fn wait_ready(&mut self, step: &PlannedStep, device: &str) -> Result<(), ExecError> {
        self.0.wait_ready(step, device)
    }
    fn allocate(&mut self) -> Result<String, ExecError> {
        self.0.allocate()
    }
    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        self.0.backend(device)
    }
    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.0.detach_observation(record)
    }
}

/// The executor checks the device it is about to connect against the
/// records itself, whatever chose it: a chooser that cannot look past a
/// recorded device is refused before the record is published or the device
/// connected.
#[test]
fn a_chooser_that_sees_only_the_kernel_cannot_take_a_recorded_device() {
    let (host, state, stale) = stale_record(Left::ByKilledAttach);
    let mut system = KernelView(host);

    let error = execute_with(&plan_attach(&request(&DB)), Some(&state), &mut system)
        .expect_err("attached on a device another volume's record names")
        .to_string();

    assert!(
        error.contains("/dev/nbd3") && error.contains("volume pg"),
        "{error}"
    );
    assert_eq!(system.0.commands, ["modprobe-nbd"]);
    assert!(state.read("db").unwrap().is_none());
    assert_eq!(state.read("pg").unwrap(), Some(stale));
}

/// A pinned `nbd_device` does not go through allocation, so the same rule is
/// applied to it: another volume's record keeps its device.
#[test]
fn a_pinned_device_named_by_another_volumes_record_is_refused() {
    for left in [Left::ByKilledAttach, Left::ByKilledCleanup] {
        let (mut host, state, stale) = stale_record(left);
        let mut db = request(&DB);
        db.nbd_device = "/dev/nbd3".into();

        let error = execute_with(&plan_attach(&db), Some(&state), &mut host)
            .expect_err("attached on a device another volume's record names")
            .to_string();

        assert!(
            error.contains("/dev/nbd3") && error.contains("volume pg"),
            "{error}"
        );
        assert!(host.commands.is_empty(), "{left:?}: {:?}", host.commands);
        assert!(state.read("db").unwrap().is_none());
        assert_eq!(state.read("pg").unwrap(), Some(stale));

        // A device no record names is the pin's to take, and the recorded
        // volume may pin its own device.
        db.nbd_device = "/dev/nbd4".into();
        execute_with(&plan_attach(&db), Some(&state), &mut host).unwrap();
        let mut pg = request(&PG);
        pg.nbd_device = "/dev/nbd3".into();
        execute_with(&plan_attach(&pg), Some(&state), &mut host).unwrap();
        assert_attached(&host, &state.read("db").unwrap().unwrap());
        assert_attached(&host, &state.read("pg").unwrap().unwrap());
    }
}

/// A record that cannot be read may name any device, so no device can be
/// shown to be unclaimed: every attach is refused before its first command,
/// and the refusal names the record.
#[test]
fn a_record_that_cannot_be_read_refuses_every_attach_and_is_named() {
    let valid = |volume: &str| {
        serde_json::to_vec(&BoundDeviceRecord {
            version: 1,
            volume: volume.into(),
            attachment: (&request(&PG)).into(),
            device: "/dev/nbd3".into(),
            connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
            recovery: None,
            recovery_intent: None,
        })
        .unwrap()
    };
    for (name, content, mode) in [
        // A device-only record of an earlier helper.
        ("pg.nbd", b"/dev/nbd3\n".to_vec(), 0o600),
        // A record stored under another volume's name.
        ("pg.nbd", valid("other"), 0o600),
        // A record readable by other users.
        ("pg.nbd", valid("pg"), 0o644),
        // A record name no volume can have.
        ("not a volume.nbd", valid("pg"), 0o600),
    ] {
        for device in [AUTO_NBD_DEVICE, "/dev/nbd4"] {
            let mut host = Host::new();
            let state = host.state();
            let path = host.root.join("state").join(name);
            std::fs::write(&path, &content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let mut db = request(&DB);
            db.nbd_device = device.into();

            let error = execute_with(&plan_attach(&db), Some(&state), &mut host)
                .expect_err("attached beside a record that cannot be read")
                .to_string();

            assert!(error.contains(name), "{name:?}, {device}: {error}");
            assert!(host.commands.is_empty(), "{name:?}: {:?}", host.commands);
            assert!(state.read("db").unwrap().is_none());
            assert_eq!(std::fs::read(&path).unwrap(), content);
        }
    }
}

/// The lock file and a temporary record left by a killed write are not
/// records, and the volume's own record is judged by its own checks.
#[test]
fn entries_that_are_not_other_volumes_records_reserve_nothing() {
    let mut host = Host::new();
    let state = host.state();
    drop(state.lock().unwrap());
    let leftover = host
        .root
        .join("state/.pg.4242.maki-11111111-2222-4333-8444-555555555555.tmp");
    std::fs::write(&leftover, b"{\"version\":1,\"vol").unwrap();

    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();

    assert_eq!(state.read("db").unwrap().unwrap().device, "/dev/nbd3");
    assert!(leftover.exists());
}

/// Only an attach takes a device, under the lock that covers the records.
/// A plan that would bind a free device to a later step without connecting
/// it has no record to protect it and none to respect.
#[test]
fn a_plan_that_does_not_connect_cannot_allocate_a_device() {
    let mut host = Host::new();
    let mut plan = plan_attach(&request(&DB));
    plan.steps
        .retain(|step| matches!(step, PlannedStep::SetBlockSize { .. }));

    assert!(execute_with(&plan, None, &mut host).is_err());

    assert!(host.commands.is_empty(), "{:?}", host.commands);
}

/// A recorded device that carries a connection under another identity: a
/// second volume attached on it by a helper that did not read the records,
/// or an NBD client outside the helper. This record names no VG UUID, so no
/// mapping on the host can be shown not to be its volume group's: every verb
/// of the recorded volume keeps refusing and keeps the record, and the
/// refusal says how to resolve it. Records that name their VG UUID are
/// retired once nothing of them remains (`displaced_record`).
#[test]
fn a_recorded_device_under_another_identity_is_refused_with_the_way_out() {
    let mut host = Host::new();
    let state = host.state();
    let (pg, db) = (request(&PG), request(&DB));
    execute_with(&plan_attach(&db), Some(&state), &mut host).unwrap();
    let other = state.read("db").unwrap().unwrap();
    let stale = BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        attachment: (&pg).into(),
        device: other.device.clone(),
        connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
        recovery: None,
        recovery_intent: None,
    };
    state.write(&stale).unwrap();
    host.commands.clear();

    for verb in VERBS {
        let error = run_verb(verb, &pg, &state, &mut host)
            .expect_err(verb)
            .to_string();
        assert!(
            error.contains(
                "/dev/nbd3 is recorded for volume pg but is connected under another identity"
            ),
            "{verb}: {error}"
        );
        assert!(
            error.contains("maki-attach cleanup --volume pg"),
            "{verb}: {error}"
        );
        assert!(host.commands.is_empty(), "{verb}: {:?}", host.commands);
        assert_eq!(state.read("pg").unwrap(), Some(stale.clone()), "{verb}");
        assert_eq!(state.read("db").unwrap(), Some(other.clone()), "{verb}");
        assert_attached(&host, &other);
    }

    // The way out the refusal names: once the device's present user is
    // detached, cleanup retires the record without a command, and both
    // volumes attach again, each on its own device.
    execute_with(&plan_detach(&db), Some(&state), &mut host).unwrap();
    host.commands.clear();
    cleanup_with(&plan_detach(&pg), &state, &mut host).unwrap();
    assert!(host.commands.is_empty(), "{:?}", host.commands);
    assert!(state.read("pg").unwrap().is_none());
    execute_with(&plan_attach(&db), Some(&state), &mut host).unwrap();
    execute_with(&plan_attach(&pg), Some(&state), &mut host).unwrap();
    let (first, second) = (
        state.read("db").unwrap().unwrap(),
        state.read("pg").unwrap().unwrap(),
    );
    assert_ne!(first.device, second.device);
    assert_attached(&host, &first);
    assert_attached(&host, &second);
}

#[path = "review_displaced_attach_record.rs"]
mod displaced_record;

#[path = "review_lvm_device_scope.rs"]
mod lvm_device_scope;
