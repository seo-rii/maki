//! Round-5 audit (slug `privileged-steps`): plan x step x failure-mode sweep.
//!
//! The production executor (`execute_with`, `cleanup_with`, `recover_with`),
//! the production observers (`detach::observe`, `recover::observe*`,
//! `recover::capture`, `lvm_preflight::verify_*`, `allocation::allocate`,
//! `nbd_backend_at`) and the production trusted state run against a simulated
//! kernel: a fake `/sys/class/block` tree plus a fake mount table that only
//! the simulated commands mutate. Every external command and every
//! observation is a numbered injection point: fail before the effect, fail
//! after the effect, time out, or kill the helper (panic) before/after.
//!
//! Lives in a scratch copy of the crate because `System`, the executor entry
//! points and the observers are crate-private. To run it in the real tree,
//! copy this file to `crates/maki-privileged/src/` and append
//! `#[cfg(test)] #[path = "audit5_steps.rs"] mod audit5_steps;` to `exec.rs`.

use super::*;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::config::{parse, AttachOverrides};
use crate::plan::{plan_attach, plan_detach, plan_grow, AttachRequest, GrowRequest};

static SEQ: AtomicU64 = AtomicU64::new(0);
const DEATH: &str = "AUDIT5-HELPER-DEATH";

fn quiet_deaths() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let text = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_default();
            if !text.contains(DEATH) {
                previous(info);
            }
        }));
    });
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Vol {
    name: &'static str,
    uuid: &'static str,
    vg_uuid: &'static str,
    lv_uuid: &'static str,
    pv_uuid: &'static str,
}

const PG: Vol = Vol {
    name: "pg",
    uuid: "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c",
    vg_uuid: "aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg",
    lv_uuid: "hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn",
    pv_uuid: "111111-2222-3333-4444-5555-6666-777777",
};
const DB: Vol = Vol {
    name: "db",
    uuid: "1f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2d",
    vg_uuid: "bbbbbb-bbbb-cccc-dddd-eeee-ffff-gggggg",
    lv_uuid: "iiiiii-iiii-jjjj-kkkk-llll-mmmm-nnnnnn",
    pv_uuid: "222222-2222-3333-4444-5555-6666-777777",
};
const VOLS: [Vol; 2] = [PG, DB];

fn vol_of_vg(vg: &str) -> Option<Vol> {
    VOLS.into_iter().find(|v| format!("vg_maki_{}", v.name) == vg)
}

#[derive(Clone, Debug)]
struct Conn {
    id: String,
    /// Volume whose daemon serves this connection.
    export: String,
    link_alive: bool,
    disconnect_requested: bool,
}

#[derive(Clone, Debug)]
struct Dm {
    k: u32,
    vg: String,
    lv: String,
    uuid: String,
    slave: String,
    foreign: bool,
}

#[derive(Clone, Debug)]
struct Mount {
    dev: (u32, u32),
    root: String,
    path: String,
    fstype: String,
    opts: String,
    source: String,
    sopts: String,
    ours: bool,
}

#[derive(Default, Clone, Debug)]
struct Kernel {
    nbd: BTreeMap<u32, Option<Conn>>,
    dm: Vec<Dm>,
    mounts: Vec<Mount>,
    lv_size: BTreeMap<String, u64>,
    fs_size: BTreeMap<String, u64>,
    sentinel: BTreeMap<String, String>,
    daemon_alive: BTreeMap<String, bool>,
    foreign_ids: BTreeSet<String>,
    busy_mount: bool,
    extra_block: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    /// Killed by a signal before any effect: what `run()` reports for a
    /// child whose wait status has no exit code (`status: None`).
    SignalBefore,
    FailBefore,
    FailAfter,
    TimeoutBefore,
    TimeoutAfter,
    DieBefore,
    DieAfter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObsFault {
    Err,
    Die,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hook {
    ForeignMountOnTop,
    ForeignXfsOnTop,
    NestedMount,
    OurLvMountedElsewhere,
    ForeignHolder,
    BackendReplaced,
    BackendDropped,
    DaemonDies,
    ForeignSameNameVg,
}

pub(super) struct World {
    dir: PathBuf,
    sysfs: PathBuf,
    mountinfo: PathBuf,
    k: RefCell<Kernel>,
    cmds: Cell<usize>,
    obs: Cell<usize>,
    fault: Option<(usize, Fault)>,
    obs_fault: Option<(usize, ObsFault)>,
    obs_hook: Cell<Option<(usize, Hook)>>,
    cmd_hook: Cell<Option<(usize, Hook)>>,
    hook_target: RefCell<Option<AttachRequest>>,
    trace: RefCell<Vec<String>>,
    violations: RefCell<Vec<String>>,
    /// Model knob: whether LVM can deactivate a VG whose PV cannot be read.
    lvm_works_without_pv: bool,
    /// Model knob: a `--select vg_uuid=` command whose PV cannot be read exits
    /// 0 without deactivating anything (selection matched no VG).
    lvm_select_noop_without_pv: bool,
    /// Model knob: the kernel tears the NBD config down when the server dies
    /// (ioctl-style); the netlink default keeps pid/backend until disconnect.
    kernel_drops_dead_backend: bool,
}

fn step_failed(what: &str) -> ExecError {
    ExecError::StepFailed {
        step: what.into(),
        status: Some(5),
        stderr: "external command output omitted".into(),
    }
}

fn timed_out() -> ExecError {
    ExecError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "external command exceeded its execution deadline",
    ))
}

fn esc(name: &str) -> String {
    name.replace('-', "--")
}

impl World {
    pub(super) fn new() -> Self {
        quiet_deaths();
        let dir = std::env::temp_dir().join(format!(
            "maki-audit5-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut kernel = Kernel::default();
        kernel.nbd.insert(3, None);
        kernel.nbd.insert(4, None);
        for vol in VOLS {
            kernel.daemon_alive.insert(vol.name.into(), true);
        }
        let world = Self {
            sysfs: dir.join("sys"),
            mountinfo: dir.join("mountinfo"),
            dir,
            k: RefCell::new(kernel),
            cmds: Cell::new(0),
            obs: Cell::new(0),
            fault: None,
            obs_fault: None,
            obs_hook: Cell::new(None),
            cmd_hook: Cell::new(None),
            hook_target: RefCell::new(None),
            trace: RefCell::new(Vec::new()),
            violations: RefCell::new(Vec::new()),
            lvm_works_without_pv: false,
            lvm_select_noop_without_pv: false,
            kernel_drops_dead_backend: false,
        };
        world.materialize();
        world
    }

    pub(super) fn state(&self) -> TrustedState {
        TrustedState::open_beneath(
            File::open(&self.dir).unwrap(),
            Path::new("state"),
            self.dir.metadata().unwrap().uid(),
        )
        .unwrap()
    }

    pub(super) fn request(&self, vol: Vol) -> AttachRequest {
        let mountpoint = self.dir.join(format!("mnt-{}", vol.name));
        let _ = std::fs::create_dir(&mountpoint);
        let mut request = parse(&format!(
            "volume_uuid = '{}'\ninit_sentinel = true\n",
            vol.uuid
        ))
        .unwrap()
        .into_request(vol.name, AttachOverrides::default(), true)
        .unwrap();
        request.mountpoint = mountpoint.to_str().unwrap().into();
        request
    }

    fn reset_injection(&mut self) {
        self.cmds.set(0);
        self.obs.set(0);
        self.fault = None;
        self.obs_fault = None;
        self.obs_hook.set(None);
        self.cmd_hook.set(None);
        self.trace.borrow_mut().clear();
    }

    fn mount_text(&self) -> String {
        let k = self.k.borrow();
        let mut text = String::from("21 1 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n");
        for (index, mount) in k.mounts.iter().enumerate() {
            text.push_str(&format!(
                "{} 21 {}:{} {} {} {} - {} {} {}\n",
                40 + index,
                mount.dev.0,
                mount.dev.1,
                mount.root,
                mount.path,
                mount.opts,
                mount.fstype,
                mount.source,
                mount.sopts
            ));
        }
        text
    }

    /// Kernel bookkeeping after any change, then rewrite the fake sysfs.
    fn settle(&self) {
        {
            let mut k = self.k.borrow_mut();
            let dm = k.dm.clone();
            let mounts = k.mounts.clone();
            let drop_dead = self.kernel_drops_dead_backend;
            for (index, slot) in k.nbd.iter_mut() {
                let name = format!("nbd{index}");
                let held = dm.iter().any(|d| d.slave == name)
                    || mounts.iter().any(|m| m.dev == (43, *index));
                if let Some(conn) = slot {
                    if (conn.disconnect_requested && !held) || (drop_dead && !conn.link_alive) {
                        *slot = None;
                    }
                }
            }
        }
        self.materialize();
    }

    fn materialize(&self) {
        let k = self.k.borrow();
        let _ = std::fs::remove_dir_all(&self.sysfs);
        std::fs::create_dir_all(&self.sysfs).unwrap();
        for (index, conn) in &k.nbd {
            let root = self.sysfs.join(format!("nbd{index}"));
            std::fs::create_dir_all(root.join("holders")).unwrap();
            std::fs::write(root.join("dev"), format!("43:{index}\n")).unwrap();
            std::fs::write(
                root.join("size"),
                if conn.is_some() { "1024\n" } else { "0\n" },
            )
            .unwrap();
            if let Some(conn) = conn {
                std::fs::write(root.join("pid"), "4242\n").unwrap();
                std::fs::write(root.join("backend"), format!("{}\n", conn.id)).unwrap();
            }
        }
        for name in &k.extra_block {
            let root = self.sysfs.join(name);
            std::fs::create_dir_all(root.join("holders")).unwrap();
            std::fs::create_dir_all(root.join("slaves")).unwrap();
            std::fs::write(root.join("dev"), "8:0\n").unwrap();
        }
        for dm in &k.dm {
            let root = self.sysfs.join(format!("dm-{}", dm.k));
            std::fs::create_dir_all(root.join("dm")).unwrap();
            std::fs::create_dir_all(root.join("slaves")).unwrap();
            std::fs::create_dir_all(root.join("holders")).unwrap();
            std::fs::write(root.join("dev"), format!("253:{}\n", dm.k)).unwrap();
            std::fs::write(
                root.join("dm/name"),
                format!("{}-{}\n", esc(&dm.vg), esc(&dm.lv)),
            )
            .unwrap();
            std::fs::write(root.join("dm/uuid"), format!("{}\n", dm.uuid)).unwrap();
            std::fs::write(root.join("slaves").join(&dm.slave), "").unwrap();
            let slave_holders = self.sysfs.join(&dm.slave).join("holders");
            std::fs::create_dir_all(&slave_holders).unwrap();
            std::fs::write(slave_holders.join(format!("dm-{}", dm.k)), "").unwrap();
        }
        drop(k);
        std::fs::write(&self.mountinfo, self.mount_text()).unwrap();
    }

    fn violation(&self, text: String) {
        self.violations.borrow_mut().push(text);
    }

    fn apply_hook(&self, hook: Hook) {
        let target = self.hook_target.borrow().clone().expect("hook target");
        {
            let mut k = self.k.borrow_mut();
            match hook {
                Hook::ForeignMountOnTop => k.mounts.push(Mount {
                    dev: (8, 1),
                    root: "/".into(),
                    path: target.mountpoint.clone(),
                    fstype: "ext4".into(),
                    opts: "rw,relatime".into(),
                    source: "/dev/sda1".into(),
                    sopts: "rw".into(),
                    ours: false,
                }),
                Hook::ForeignXfsOnTop => k.mounts.push(Mount {
                    dev: (253, 77),
                    root: "/".into(),
                    path: target.mountpoint.clone(),
                    fstype: "xfs".into(),
                    opts: "rw,nosuid,nodev".into(),
                    source: "/dev/mapper/other-data".into(),
                    sopts: "rw".into(),
                    ours: false,
                }),
                Hook::NestedMount => k.mounts.push(Mount {
                    dev: (0, 55),
                    root: "/".into(),
                    path: format!("{}/sub", target.mountpoint),
                    fstype: "tmpfs".into(),
                    opts: "rw".into(),
                    source: "tmpfs".into(),
                    sopts: "rw".into(),
                    ours: false,
                }),
                Hook::OurLvMountedElsewhere => {
                    if let Some(dm) = k.dm.iter().find(|d| d.vg == target.vg_name).cloned() {
                        k.mounts.push(Mount {
                            dev: (253, dm.k),
                            root: "/".into(),
                            path: "/mnt/audit5-elsewhere".into(),
                            fstype: "xfs".into(),
                            opts: "rw".into(),
                            source: "/dev/mapper/x".into(),
                            sopts: "rw".into(),
                            ours: true,
                        });
                    }
                }
                Hook::ForeignHolder => k.dm.push(Dm {
                    k: 99,
                    vg: "othervg".into(),
                    lv: "x".into(),
                    uuid: "LVM-foreignforeign".into(),
                    slave: "nbd3".into(),
                    foreign: true,
                }),
                Hook::BackendReplaced => {
                    let id = "maki-ffffffff-ffff-4fff-8fff-ffffffffffff".to_string();
                    k.foreign_ids.insert(id.clone());
                    if let Some(Some(conn)) = k.nbd.get_mut(&3) {
                        conn.id = id;
                    } else {
                        k.nbd.insert(
                            3,
                            Some(Conn {
                                id,
                                export: "db".into(),
                                link_alive: true,
                                disconnect_requested: false,
                            }),
                        );
                    }
                }
                Hook::BackendDropped => {
                    k.nbd.insert(3, None);
                }
                Hook::DaemonDies => {
                    k.daemon_alive.insert(target.volume.clone(), false);
                    for conn in k.nbd.values_mut().flatten() {
                        if conn.export == target.volume {
                            conn.link_alive = false;
                        }
                    }
                }
                Hook::ForeignSameNameVg => {
                    k.extra_block.push("sda".into());
                    k.dm.push(Dm {
                        k: 98,
                        vg: target.vg_name.clone(),
                        lv: "data".into(),
                        uuid: "LVM-localdisklocaldisk".into(),
                        slave: "sda".into(),
                        foreign: true,
                    });
                }
            }
        }
        self.settle();
    }

    pub(super) fn kill_daemon(&self, volume: &str) {
        {
            let mut k = self.k.borrow_mut();
            k.daemon_alive.insert(volume.into(), false);
            for conn in k.nbd.values_mut().flatten() {
                if conn.export == volume {
                    conn.link_alive = false;
                }
            }
        }
        self.settle();
    }

    pub(super) fn start_daemon(&self, volume: &str) {
        self.k.borrow_mut().daemon_alive.insert(volume.into(), true);
    }

    /// One injectable observation.
    fn observe_point(&self, what: &str) -> io::Result<()> {
        let n = self.obs.get() + 1;
        self.obs.set(n);
        self.trace.borrow_mut().push(format!("o{n}:{what}"));
        if let Some((at, hook)) = self.obs_hook.get() {
            if at == n {
                self.obs_hook.set(None);
                self.apply_hook(hook);
            }
        }
        match self.obs_fault {
            Some((at, ObsFault::Err)) if at == n => {
                Err(io::Error::other("audit5: unreadable observation"))
            }
            Some((at, ObsFault::Die)) if at == n => panic!("{DEATH} at observation {n} ({what})"),
            _ => Ok(()),
        }
    }

    /// One injectable external command.
    fn command<T>(
        &mut self,
        what: &str,
        effect: impl FnOnce(&mut Self) -> Result<T, ExecError>,
    ) -> Result<T, ExecError> {
        let n = self.cmds.get() + 1;
        self.cmds.set(n);
        self.trace.borrow_mut().push(format!("c{n}:{what}"));
        if let Some((at, hook)) = self.cmd_hook.get() {
            if at == n {
                self.cmd_hook.set(None);
                self.apply_hook(hook);
            }
        }
        let fault = self.fault.filter(|(at, _)| *at == n).map(|(_, f)| f);
        match fault {
            Some(Fault::DieBefore) => panic!("{DEATH} before command {n} ({what})"),
            Some(Fault::FailBefore) => return Err(step_failed(what)),
            Some(Fault::SignalBefore) => {
                return Err(ExecError::StepFailed {
                    step: what.into(),
                    status: None,
                    stderr: "external command output omitted".into(),
                })
            }
            Some(Fault::TimeoutBefore) => return Err(timed_out()),
            _ => {}
        }
        let result = effect(self);
        self.settle();
        match fault {
            Some(Fault::DieAfter) => panic!("{DEATH} after command {n} ({what})"),
            Some(Fault::FailAfter) if result.is_ok() => Err(step_failed(what)),
            Some(Fault::TimeoutAfter) if result.is_ok() => Err(timed_out()),
            _ => result,
        }
    }

    fn nbd_of(device: &str) -> u32 {
        crate::probe::nbd_index(device).expect("nbd device")
    }

    fn conn(&self, device: &str) -> Option<Conn> {
        self.k
            .borrow()
            .nbd
            .get(&Self::nbd_of(device))
            .cloned()
            .flatten()
    }

    fn readable(&self, nbd_name: &str) -> bool {
        let index: u32 = nbd_name.trim_start_matches("nbd").parse().unwrap_or(u32::MAX);
        self.k
            .borrow()
            .nbd
            .get(&index)
            .cloned()
            .flatten()
            .is_some_and(|conn| conn.link_alive)
    }

    fn report_for(&self, record: &BoundDeviceRecord) -> Result<Vec<u8>, ExecError> {
        let conn = self
            .conn(&record.device)
            .filter(|conn| conn.link_alive)
            .ok_or_else(|| identity_error("audit5: PV unreadable"))?;
        let vol = VOLS
            .into_iter()
            .find(|v| v.name == conn.export)
            .expect("export volume");
        Ok(serde_json::to_vec(&serde_json::json!({"report": [{
            "vg": [{"vg_name": format!("vg_maki_{}", vol.name), "vg_uuid": vol.vg_uuid,
                "vg_seqno": "1", "pv_count": "1", "vg_missing_pv_count": "0", "vg_partial": "0",
                "vg_exported": "0", "vg_systemid": "", "vg_lock_type": ""}],
            "pv": [{"pv_name": record.device, "pv_uuid": vol.pv_uuid,
                "vg_uuid": vol.vg_uuid, "pv_missing": "0", "pv_duplicate": "0"}],
            "lv": [{"lv_name": "data", "lv_uuid": vol.lv_uuid,
                "vg_uuid": vol.vg_uuid, "lv_layout": "linear"}]
        }]}))
        .unwrap())
    }

    fn preflight(&self, record: &BoundDeviceRecord) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        let index = Self::nbd_of(&record.device);
        let conn = self
            .conn(&record.device)
            .filter(|conn| conn.link_alive)
            .ok_or_else(|| identity_error("audit5: PV unreadable"))?;
        let vol = VOLS.into_iter().find(|v| v.name == conn.export).unwrap();
        let observed =
            crate::detach::observe_kernel(record, self.mount_text().as_bytes(), &self.sysfs)?;
        if observed.mounted || observed.vg_active || observed.nbd_in_use {
            return Err(identity_error(
                "LVM preflight found an existing mount, mapping, or holder",
            ));
        }
        Ok(lvm_preflight::validate(
            &self.report_for(record)?,
            vec![lvm_preflight::Device {
                path: record.device.clone(),
                number: (43, index),
                start: 0,
                sectors: 1024,
            }],
            [(record.device.clone(), vol.pv_uuid.to_string())].into(),
            &record.attachment.vg_name,
            &record.attachment.lv_name,
            record.attachment.lvm_identity.as_ref(),
            |path| {
                if path == record.device {
                    Ok((43, index))
                } else {
                    Err(io::Error::other("foreign device"))
                }
            },
        )?)
    }

    /// `vgchange -an` for every active mapping of `vg` (optionally limited to
    /// the PVs on `only_slave`). LVM has to read the VG metadata from the PV.
    fn lvm_deactivate(&mut self, vg: &str, only_slave: Option<&str>) -> Result<(), ExecError> {
        let targets: Vec<Dm> = self
            .k
            .borrow()
            .dm
            .iter()
            .filter(|d| d.vg == vg && only_slave.is_none_or(|slave| d.slave == slave))
            .cloned()
            .collect();
        if targets.is_empty() {
            // Nothing visible: LVM either finds an inactive VG (exit 0) or no
            // VG at all (exit 5). Report the latter when the PV is unreadable.
            return Ok(());
        }
        for dm in &targets {
            if !self.lvm_works_without_pv && !self.readable(&dm.slave) && dm.slave != "sda" {
                if self.lvm_select_noop_without_pv && only_slave.is_some() {
                    return Ok(());
                }
                return Err(step_failed("vgchange: volume group not found (PV unreadable)"));
            }
            if self
                .k
                .borrow()
                .mounts
                .iter()
                .any(|m| m.dev == (253, dm.k))
            {
                return Err(step_failed("vgchange: logical volume in use"));
            }
        }
        for dm in &targets {
            if dm.foreign {
                self.violation(format!(
                    "LVM deactivation removed a FOREIGN mapping dm-{} of VG {vg}",
                    dm.k
                ));
            }
        }
        self.k
            .borrow_mut()
            .dm
            .retain(|d| !(d.vg == vg && only_slave.is_none_or(|slave| d.slave == slave)));
        Ok(())
    }

    // ---- facts for the oracles ----

    pub(super) fn backend_id(&self, index: u32) -> Option<String> {
        self.k
            .borrow()
            .nbd
            .get(&index)
            .cloned()
            .flatten()
            .map(|conn| conn.id)
    }

    /// (nbd indexes connected to `vol`'s export, vg mapped, mounted)
    pub(super) fn live(&self, vol: Vol, request: &AttachRequest) -> (Vec<u32>, bool, bool) {
        let k = self.k.borrow();
        let connected = k
            .nbd
            .iter()
            .filter(|(_, conn)| conn.as_ref().is_some_and(|c| c.export == vol.name))
            .map(|(index, _)| *index)
            .collect();
        let vg = format!("vg_maki_{}", vol.name);
        let mapped = k.dm.iter().any(|d| d.vg == vg && !d.foreign);
        let mounted = k
            .mounts
            .iter()
            .any(|m| m.ours && m.path == request.mountpoint);
        (connected, mapped, mounted)
    }

    pub(super) fn nothing_live(&self, vol: Vol, request: &AttachRequest) -> bool {
        let (connected, mapped, mounted) = self.live(vol, request);
        connected.is_empty() && !mapped && !mounted
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl System for World {
    fn lvm_preflight(
        &mut self,
        record: &BoundDeviceRecord,
    ) -> Result<lvm_preflight::VerifiedLvm, ExecError> {
        self.command("lvm-preflight", |w| w.preflight(record))
    }

    fn activate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
        attempted: &mut bool,
    ) -> Result<(), ExecError> {
        if &self.preflight(record)? != verified {
            return Err(identity_error(
                "LVM metadata or candidate identity changed before activation",
            ));
        }
        verify_connection(record, self)?;
        *attempted = true;
        self.command("vgchange-activate", |w| {
            let conn = w
                .conn(&record.device)
                .filter(|conn| conn.link_alive)
                .ok_or_else(|| step_failed("vgchange: PV unreadable"))?;
            let vol = VOLS.into_iter().find(|v| v.name == conn.export).unwrap();
            let mut k = w.k.borrow_mut();
            let next = (0..).find(|n| !k.dm.iter().any(|d| d.k == *n)).unwrap();
            k.dm.push(Dm {
                k: next,
                vg: format!("vg_maki_{}", vol.name),
                lv: "data".into(),
                uuid: format!(
                    "LVM-{}{}",
                    vol.vg_uuid.replace('-', ""),
                    vol.lv_uuid.replace('-', "")
                ),
                slave: record.device.trim_start_matches("/dev/").into(),
                foreign: false,
            });
            Ok(())
        })
    }

    fn verify_activated_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        self.observe_point("verify-activated-lvm")?;
        lvm_preflight::verify_mapping(record, verified, &self.sysfs)
    }

    fn verify_rollback_lvm(
        &self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> io::Result<()> {
        self.observe_point("verify-rollback-lvm")?;
        lvm_preflight::verify_rollback_mapping(record, verified, &self.sysfs)
    }

    fn deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        _verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        verify_connection(record, self)?;
        let slave = record.device.trim_start_matches("/dev/").to_string();
        let vg = record.attachment.vg_name.clone();
        self.command("vgchange-deactivate-scoped", |w| {
            w.lvm_deactivate(&vg, Some(&slave))
        })
    }

    fn recover_deactivate_lvm(
        &mut self,
        record: &BoundDeviceRecord,
        verified: &lvm_preflight::VerifiedLvm,
    ) -> Result<(), ExecError> {
        lvm_preflight::verify_recovery_rollback_mapping(record, verified, &self.sysfs)?;
        if self.backend(&record.device)?.is_some() {
            return Err(identity_error(
                "NBD backend reappeared before recovery deactivation",
            ));
        }
        let slave = record.device.trim_start_matches("/dev/").to_string();
        let vg = record.attachment.vg_name.clone();
        self.command("vgchange-deactivate-recovery", |w| {
            w.lvm_deactivate(&vg, Some(&slave))
        })
    }

    fn deactivate_lvm_from_proof(&mut self, record: &BoundDeviceRecord) -> Result<(), ExecError> {
        verify_connection(record, self)?;
        if record.recovery.is_none() {
            return Err(identity_error("attachment has no completed recovery proof"));
        }
        let observed = recover::observe(record, self.mount_text().as_bytes(), &self.sysfs)?;
        if observed.mounted {
            return Err(identity_error(
                "cannot directly deactivate a mounted recovery mapping",
            ));
        }
        if !observed.vg_active {
            return Ok(());
        }
        let vg = record.attachment.vg_name.clone();
        let slave = record.device.trim_start_matches("/dev/").to_string();
        self.command("dmsetup-remove", |w| {
            let before = w.lvm_works_without_pv;
            w.lvm_works_without_pv = true; // dmsetup needs no metadata
            let result = w.lvm_deactivate(&vg, Some(&slave));
            w.lvm_works_without_pv = before;
            result
        })
    }

    fn recovery_proof(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<Option<recover::RecoveryProof>> {
        self.observe_point("recovery-proof")?;
        recover::capture(record, self.mount_text().as_bytes(), &self.sysfs).map(Some)
    }

    fn recovery_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.observe_point("recovery-observation")?;
        recover::observe(record, self.mount_text().as_bytes(), &self.sysfs)
    }

    fn disconnected_recovery_observation(
        &self,
        record: &BoundDeviceRecord,
    ) -> io::Result<DetachObservation> {
        self.observe_point("disconnected-recovery-observation")?;
        recover::observe_disconnected(record, self.mount_text().as_bytes(), &self.sysfs)
    }

    fn lv_size(&self, vg: &str, _lv: &str) -> Result<u64, ExecError> {
        self.observe_point("lv-size")?;
        let k = self.k.borrow();
        let dm = k
            .dm
            .iter()
            .find(|d| d.vg == vg)
            .ok_or_else(|| identity_error("logical volume size probe failed"))?;
        if !k
            .nbd
            .values()
            .flatten()
            .any(|conn| conn.link_alive && format!("vg_maki_{}", conn.export) == dm.vg)
        {
            return Err(identity_error("logical volume size probe failed"));
        }
        Ok(*k.lv_size.get(vg).unwrap_or(&(1 << 30)))
    }

    fn run_step(&mut self, step: &PlannedStep, identifier: Option<&str>) -> Result<(), ExecError> {
        let step = step.clone();
        let identifier = identifier.map(str::to_owned);
        self.command(step.kind(), move |w| match &step {
            PlannedStep::ModprobeNbd => Ok(()),
            PlannedStep::NbdConnect { socket, device, .. } => {
                let export = socket
                    .strip_prefix("/run/maki/")
                    .and_then(|rest| rest.strip_suffix("/nbd.sock"))
                    .expect("default socket path")
                    .to_string();
                let mut k = w.k.borrow_mut();
                if !k.daemon_alive.get(&export).copied().unwrap_or(false) {
                    return Err(step_failed("nbd-client: connection refused"));
                }
                let slot = k.nbd.get_mut(&Self::nbd_of(device)).expect("nbd exists");
                if slot.is_some() {
                    return Err(step_failed("nbd-client: device busy"));
                }
                *slot = Some(Conn {
                    id: identifier.clone().expect("identifier"),
                    export,
                    link_alive: true,
                    disconnect_requested: false,
                });
                Ok(())
            }
            PlannedStep::SetBlockSize { device, .. } => {
                if w.conn(device).is_some_and(|conn| conn.link_alive) {
                    Ok(())
                } else {
                    Err(step_failed("blockdev: cannot open"))
                }
            }
            PlannedStep::LvmActivate { .. } => Err(identity_error(
                "LVM activation requires a connected record and verified preflight",
            )),
            PlannedStep::LvmDeactivate { vg_name } => w.lvm_deactivate(vg_name, None),
            PlannedStep::VerifyFilesystemIdentity { device, .. } => {
                let k = w.k.borrow();
                let ok = k.dm.iter().any(|d| {
                    format!("/dev/{}/{}", d.vg, d.lv) == *device
                        && k.nbd.values().flatten().any(|conn| {
                            conn.link_alive && format!("vg_maki_{}", conn.export) == d.vg
                        })
                });
                if ok {
                    Ok(())
                } else {
                    Err(step_failed("blkid: probe failed"))
                }
            }
            PlannedStep::MountXfs { device, mountpoint } => {
                let mut k = w.k.borrow_mut();
                let Some(dm) = k
                    .dm
                    .iter()
                    .find(|d| format!("/dev/{}/{}", d.vg, d.lv) == *device)
                    .cloned()
                else {
                    return Err(step_failed("mount: special device does not exist"));
                };
                let readable = k
                    .nbd
                    .iter()
                    .any(|(index, conn)| {
                        format!("nbd{index}") == dm.slave
                            && conn.as_ref().is_some_and(|conn| conn.link_alive)
                    })
                    || dm.slave == "sda";
                if !readable {
                    return Err(step_failed("mount: can't read superblock"));
                }
                k.mounts.push(Mount {
                    dev: (253, dm.k),
                    root: "/".into(),
                    path: mountpoint.clone(),
                    fstype: "xfs".into(),
                    opts: "rw,noatime,nosuid,nodev".into(),
                    source: format!("/dev/mapper/{}-{}", esc(&dm.vg), esc(&dm.lv)),
                    sopts: "rw,attr2,inode64".into(),
                    ours: !dm.foreign,
                });
                Ok(())
            }
            PlannedStep::VerifyMountDevice { mountpoint, .. }
            | PlannedStep::VerifyMountIdentity { mountpoint, .. }
            | PlannedStep::WriteSentinel { mountpoint, .. } => {
                let nbd_device: Option<&String> = match &step {
                    PlannedStep::VerifyMountDevice { nbd_device, .. }
                    | PlannedStep::VerifyMountIdentity { nbd_device, .. } => Some(nbd_device),
                    _ => None,
                };
                let mut k = w.k.borrow_mut();
                let Some(top) = k.mounts.iter().rev().find(|m| m.path == *mountpoint).cloned()
                else {
                    return Err(ExecError::Verify(crate::verify::MountVerifyError(
                        "nothing is mounted at the mountpoint".into(),
                    )));
                };
                let Some(dm) = k.dm.iter().find(|d| (253, d.k) == top.dev).cloned() else {
                    return Err(ExecError::Verify(crate::verify::MountVerifyError(
                        "could not resolve the block devices under the mounted filesystem".into(),
                    )));
                };
                if let Some(nbd_device) = nbd_device {
                    if format!("/dev/{}", dm.slave) != *nbd_device {
                        return Err(ExecError::Verify(crate::verify::MountVerifyError(
                            "the mounted filesystem is not stored only on the NBD device".into(),
                        )));
                    }
                }
                match &step {
                    PlannedStep::WriteSentinel { volume_uuid, .. } => {
                        if !top.ours {
                            drop(k);
                            w.violation("sentinel written into a FOREIGN filesystem".into());
                            return Ok(());
                        }
                        match k.sentinel.get(&dm.vg) {
                            Some(existing) if existing != volume_uuid => {
                                Err(step_failed("sentinel mismatch"))
                            }
                            _ => {
                                k.sentinel.insert(dm.vg.clone(), volume_uuid.clone());
                                Ok(())
                            }
                        }
                    }
                    PlannedStep::VerifyMountIdentity { volume_uuid, .. } => {
                        if k.sentinel.get(&dm.vg) != Some(volume_uuid) {
                            return Err(ExecError::Verify(crate::verify::MountVerifyError(
                                "Maki volume sentinel is missing or unreadable".into(),
                            )));
                        }
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            PlannedStep::Umount { mountpoint } => {
                let mut k = w.k.borrow_mut();
                let Some(position) = k.mounts.iter().rposition(|m| m.path == *mountpoint) else {
                    return Err(step_failed("umount: not mounted"));
                };
                if k.busy_mount {
                    return Err(step_failed("umount: target is busy"));
                }
                let removed = k.mounts.remove(position);
                drop(k);
                if !removed.ours {
                    w.violation(format!(
                        "umount removed a FOREIGN mount ({} on {})",
                        removed.fstype, removed.path
                    ));
                }
                Ok(())
            }
            PlannedStep::NbdDisconnect { device } => {
                let mut k = w.k.borrow_mut();
                let foreign = k.foreign_ids.clone();
                let Some(Some(conn)) = k.nbd.get_mut(&Self::nbd_of(device)) else {
                    return Err(step_failed("nbd-client -d: not configured"));
                };
                let hit_foreign = foreign.contains(&conn.id);
                conn.disconnect_requested = true;
                conn.link_alive = false;
                drop(k);
                if hit_foreign {
                    w.violation(format!("nbd-client -d disconnected a FOREIGN backend on {device}"));
                }
                Ok(())
            }
            PlannedStep::LvExtend {
                vg_name,
                target_bytes,
                ..
            } => {
                let mut k = w.k.borrow_mut();
                let Some(dm) = k.dm.iter().find(|d| d.vg == *vg_name).cloned() else {
                    return Err(step_failed("lvextend: VG not found"));
                };
                let readable = k
                    .nbd
                    .iter()
                    .any(|(index, conn)| {
                        format!("nbd{index}") == dm.slave
                            && conn.as_ref().is_some_and(|conn| conn.link_alive)
                    })
                    || dm.slave == "sda";
                if !readable {
                    return Err(step_failed("lvextend: PV unreadable"));
                }
                let entry = k.lv_size.entry(vg_name.clone()).or_insert(1 << 30);
                if *target_bytes <= *entry {
                    return Err(step_failed("lvextend: new size matches existing size"));
                }
                *entry = *target_bytes;
                drop(k);
                if dm.foreign {
                    w.violation(format!("lvextend grew a FOREIGN VG {vg_name}"));
                }
                Ok(())
            }
            PlannedStep::XfsGrowfs { mountpoint } => {
                let mut k = w.k.borrow_mut();
                let Some(top) = k.mounts.iter().rev().find(|m| m.path == *mountpoint).cloned()
                else {
                    return Err(step_failed("xfs_growfs: not a mounted XFS filesystem"));
                };
                if top.fstype != "xfs" {
                    return Err(step_failed("xfs_growfs: not a mounted XFS filesystem"));
                }
                let dm = k.dm.iter().find(|d| (253, d.k) == top.dev).cloned();
                if !top.ours {
                    drop(k);
                    w.violation(format!("xfs_growfs ran on a FOREIGN mount at {mountpoint}"));
                    return Ok(());
                }
                if let Some(dm) = dm {
                    let size = *k.lv_size.get(&dm.vg).unwrap_or(&(1 << 30));
                    k.fs_size.insert(dm.vg, size);
                }
                Ok(())
            }
        })
    }

    fn wait_ready(&mut self, _step: &PlannedStep, device: &str) -> Result<(), ExecError> {
        let device = device.to_string();
        self.command("wait-ready", move |w| {
            if w.conn(&device).is_some_and(|conn| conn.link_alive) {
                Ok(())
            } else {
                Err(ExecError::Step {
                    step: "nbd-connect".into(),
                    message: "did not become ready".into(),
                })
            }
        })
    }

    fn allocate(&mut self) -> Result<String, ExecError> {
        self.observe_point("allocate")?;
        allocation::allocate(&self.sysfs, &self.mountinfo)
    }

    fn backend(&self, device: &str) -> io::Result<Option<String>> {
        self.observe_point("backend")?;
        nbd_backend_at(&self.sysfs, device)
    }

    fn detach_observation(&self, record: &BoundDeviceRecord) -> io::Result<DetachObservation> {
        self.observe_point("detach-observation")?;
        crate::detach::observe(record, self.mount_text().as_bytes(), &self.sysfs)
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Outcome {
    Ok,
    Err(String),
    Died,
}

pub(super) fn drive(f: impl FnOnce() -> Result<(), ExecError>) -> Outcome {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => Outcome::Ok,
        Ok(Err(error)) => Outcome::Err(error.to_string()),
        Err(payload) => {
            let text = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            assert!(text.contains(DEATH), "unexpected panic in executor: {text}");
            Outcome::Died
        }
    }
}

pub(super) fn attach(world: &mut World, state: &TrustedState, request: &AttachRequest) -> Outcome {
    drive(|| execute_with(&plan_attach(request), Some(state), world))
}
pub(super) fn detach(world: &mut World, state: &TrustedState, request: &AttachRequest) -> Outcome {
    drive(|| execute_with(&plan_detach(request), Some(state), world))
}
pub(super) fn cleanup(world: &mut World, state: &TrustedState, request: &AttachRequest) -> Outcome {
    drive(|| cleanup_with(&plan_detach(request), state, world))
}
pub(super) fn recover_verb(
    world: &mut World,
    state: &TrustedState,
    request: &AttachRequest,
) -> Outcome {
    drive(|| recover_with(&plan_detach(request), state, world))
}
fn grow_request(request: &AttachRequest, target: u64) -> GrowRequest {
    GrowRequest {
        volume: request.volume.clone(),
        nbd_device: request.nbd_device.clone(),
        volume_uuid: request.volume_uuid.clone(),
        nbd_socket: request.nbd_socket.clone(),
        vg_name: request.vg_name.clone(),
        lv_name: request.lv_name.clone(),
        lvm_identity: request.lvm_identity.clone(),
        target_bytes: target,
        fs_uuid: request.fs_uuid.clone(),
        mountpoint: request.mountpoint.clone(),
    }
}
pub(super) fn grow(
    world: &mut World,
    state: &TrustedState,
    request: &AttachRequest,
    target: u64,
) -> Outcome {
    drive(|| execute_with(&plan_grow(&grow_request(request, target)), Some(state), world))
}

/// What must hold after ANY run, however it ended.
fn check_record_matches_reality(
    world: &World,
    state: &TrustedState,
    vol: Vol,
    request: &AttachRequest,
    context: &str,
    problems: &mut Vec<String>,
) {
    for violation in world.violations.borrow().iter() {
        problems.push(format!("{context}: SAFETY {violation}"));
    }
    let record = state.read(vol.name).unwrap_or_else(|error| {
        problems.push(format!("{context}: record unreadable: {error}"));
        None
    });
    let (connected, mapped, mounted) = world.live(vol, request);
    if connected.is_empty() && !mapped && !mounted {
        return;
    }
    let Some(record) = record else {
        problems.push(format!(
            "{context}: LEAK live resources without a trusted record (nbd {connected:?}, mapped {mapped}, mounted {mounted})"
        ));
        return;
    };
    let index = World::nbd_of(&record.device);
    for live in &connected {
        if *live != index {
            problems.push(format!(
                "{context}: LEAK nbd{live} serves {} but the record names {}",
                vol.name, record.device
            ));
        } else if world.backend_id(*live).as_deref() != Some(&record.connection_id) {
            problems.push(format!(
                "{context}: record identity differs from the live backend on nbd{live}"
            ));
        }
    }
}

fn fully_attached(world: &World, state: &TrustedState, vol: Vol, request: &AttachRequest) -> bool {
    let (connected, mapped, mounted) = world.live(vol, request);
    let record = state.read(vol.name).ok().flatten();
    connected.len() == 1
        && mapped
        && mounted
        && record.as_ref().is_some_and(|record| {
            record.recovery.is_some()
                && record.recovery_intent.is_none()
                && World::nbd_of(&record.device) == connected[0]
                && world.backend_id(connected[0]).as_deref() == Some(&record.connection_id)
        })
}

fn clean(world: &World, state: &TrustedState, vol: Vol, request: &AttachRequest) -> bool {
    world.nothing_live(vol, request) && state.read(vol.name).ok().flatten().is_none()
}

fn count_points(run: impl FnOnce(&mut World, &TrustedState, &AttachRequest)) -> (usize, usize, Vec<String>) {
    let mut world = World::new();
    let state = world.state();
    let request = world.request(PG);
    run(&mut world, &state, &request);
    let trace = world.trace.borrow().clone();
    (world.cmds.get(), world.obs.get(), trace)
}

#[derive(Clone, Copy, Debug)]
enum Inject {
    Cmd(usize, Fault),
    Obs(usize, ObsFault),
}

fn arm(world: &mut World, inject: Inject) {
    world.reset_injection();
    match inject {
        Inject::Cmd(at, fault) => world.fault = Some((at, fault)),
        Inject::Obs(at, fault) => world.obs_fault = Some((at, fault)),
    }
}

const CMD_FAULTS: [Fault; 6] = [
    Fault::FailBefore,
    Fault::FailAfter,
    Fault::TimeoutBefore,
    Fault::TimeoutAfter,
    Fault::DieBefore,
    Fault::DieAfter,
];

fn injections(cmds: usize, obs: usize) -> Vec<Inject> {
    let mut all = Vec::new();
    for at in 1..=cmds {
        for fault in CMD_FAULTS {
            all.push(Inject::Cmd(at, fault));
        }
    }
    for at in 1..=obs {
        for fault in [ObsFault::Err, ObsFault::Die] {
            all.push(Inject::Obs(at, fault));
        }
    }
    all
}

/// How the lifecycle continues after a failed or killed helper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Follow {
    /// maki-recover@: daemon stopped (Conflicts=), then `cleanup`, then a
    /// fresh lifecycle (daemon start, attach).
    RecoverUnit,
    /// Operator: `cleanup` with the daemon still running, then attach.
    CleanupLive,
    /// Operator or systemd restart: attach again straight away.
    RetryAttach,
}

fn print_report(title: &str, rows: &[String], problems: &[String]) {
    println!("==== {title}: {} cases, {} problems", rows.len(), problems.len());
    for row in rows {
        println!("{row}");
    }
    for problem in problems {
        println!("PROBLEM {problem}");
    }
}

#[test]
fn audit5_matrix_attach() {
    let (cmds, obs, trace) = count_points(|world, state, request| {
        assert_eq!(attach(world, state, request), Outcome::Ok);
        assert!(fully_attached(world, state, PG, request));
    });
    println!("attach baseline: {cmds} commands, {obs} observations\n{}", trace.join(" "));
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for inject in injections(cmds, obs) {
        for follow in [Follow::RecoverUnit, Follow::CleanupLive, Follow::RetryAttach] {
            let mut world = World::new();
            let state = world.state();
            let request = world.request(PG);
            arm(&mut world, inject);
            let first = attach(&mut world, &state, &request);
            let point = world.trace.borrow().last().cloned().unwrap_or_default();
            let context = format!("attach {inject:?} [{point}] -> {first:?}");
            check_record_matches_reality(&world, &state, PG, &request, &context, &mut problems);
            let after = format!(
                "live={:?} record={}",
                world.live(PG, &request),
                state
                    .read("pg")
                    .map(|r| r.map_or("none".to_string(), |r| format!(
                        "{}{}{}",
                        r.device,
                        if r.recovery.is_some() { "+proof" } else { "" },
                        if r.recovery_intent.is_some() { "+intent" } else { "" }
                    )))
                    .unwrap_or_else(|e| format!("ERR {e}"))
            );
            if first == Outcome::Ok {
                if !fully_attached(&world, &state, PG, &request) {
                    problems.push(format!("{context}: reported success but is not fully attached ({after})"));
                }
                continue;
            }
            if let Outcome::Err(text) = &first {
                if !text.contains("FAILED") && text.contains("rolled back") && !clean(&world, &state, PG, &request) {
                    // A rollback that claims to be complete must leave nothing.
                    problems.push(format!("{context}: clean rollback claimed but {after}"));
                }
            }
            world.reset_injection();
            let mut tail = String::new();
            match follow {
                Follow::RecoverUnit => {
                    world.kill_daemon("pg");
                    let c = cleanup(&mut world, &state, &request);
                    tail.push_str(&format!("cleanup(dead daemon)={c:?}; "));
                    if c != Outcome::Ok || !clean(&world, &state, PG, &request) {
                        problems.push(format!(
                            "{context}: maki-recover@ cleanup did not converge: {c:?} live={:?} record={}",
                            world.live(PG, &request),
                            state.read("pg").ok().flatten().is_some()
                        ));
                    }
                    world.start_daemon("pg");
                }
                Follow::CleanupLive => {
                    let c = cleanup(&mut world, &state, &request);
                    tail.push_str(&format!("cleanup(live daemon)={c:?}; "));
                    if c != Outcome::Ok || !clean(&world, &state, PG, &request) {
                        problems.push(format!(
                            "{context}: live cleanup did not converge: {c:?} live={:?} record={}",
                            world.live(PG, &request),
                            state.read("pg").ok().flatten().is_some()
                        ));
                    }
                }
                Follow::RetryAttach => {}
            }
            world.reset_injection();
            let again = attach(&mut world, &state, &request);
            tail.push_str(&format!("attach={again:?}"));
            check_record_matches_reality(&world, &state, PG, &request, &format!("{context} / retry"), &mut problems);
            match (&again, follow) {
                (Outcome::Ok, _) => {
                    if !fully_attached(&world, &state, PG, &request) {
                        problems.push(format!("{context}: retry reported success but is not fully attached"));
                    }
                }
                (other, Follow::RetryAttach) => {
                    // A refusal is acceptable only if cleanup then converges.
                    world.reset_injection();
                    let c = cleanup(&mut world, &state, &request);
                    world.reset_injection();
                    let third = attach(&mut world, &state, &request);
                    tail.push_str(&format!("; cleanup={c:?}; attach={third:?}"));
                    if c != Outcome::Ok || third != Outcome::Ok {
                        problems.push(format!("{context}: retry {other:?}, then cleanup {c:?}, attach {third:?}"));
                    }
                }
                (other, _) => problems.push(format!("{context}: attach after cleanup failed: {other:?}")),
            }
            rows.push(format!("{context} | {after} | {follow:?}: {tail}"));
        }
    }
    print_report("attach", &rows, &problems);
    assert!(problems.is_empty(), "{} problems", problems.len());
}

fn attached_world() -> (World, TrustedState, AttachRequest) {
    let mut world = World::new();
    let state = world.state();
    let request = world.request(PG);
    assert_eq!(attach(&mut world, &state, &request), Outcome::Ok);
    assert!(fully_attached(&world, &state, PG, &request));
    world.reset_injection();
    (world, state, request)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Teardown {
    Detach,
    CleanupLive,
    CleanupDeadDaemon,
    CleanupDeadDaemonKernelDropped,
}

fn teardown(kind: Teardown, world: &mut World, state: &TrustedState, request: &AttachRequest) -> Outcome {
    match kind {
        Teardown::Detach => detach(world, state, request),
        _ => cleanup(world, state, request),
    }
}

#[test]
fn audit5_matrix_teardown() {
    let mut all_rows = Vec::new();
    let mut problems = Vec::new();
    for kind in [
        Teardown::Detach,
        Teardown::CleanupLive,
        Teardown::CleanupDeadDaemon,
        Teardown::CleanupDeadDaemonKernelDropped,
    ] {
        let prepare = |world: &mut World| match kind {
            Teardown::CleanupDeadDaemon => world.kill_daemon("pg"),
            Teardown::CleanupDeadDaemonKernelDropped => {
                world.kernel_drops_dead_backend = true;
                world.kill_daemon("pg");
            }
            _ => {}
        };
        let (mut world, state, request) = attached_world();
        prepare(&mut world);
        let baseline = teardown(kind, &mut world, &state, &request);
        let (cmds, obs) = (world.cmds.get(), world.obs.get());
        println!(
            "{kind:?} baseline: {baseline:?}, {cmds} commands, {obs} observations: {} | clean={}",
            world.trace.borrow().join(" "),
            clean(&world, &state, PG, &request)
        );
        if baseline != Outcome::Ok || !clean(&world, &state, PG, &request) {
            problems.push(format!(
                "{kind:?}: baseline did not converge: {baseline:?} live={:?}",
                world.live(PG, &request)
            ));
        }
        for inject in injections(cmds, obs) {
            let (mut world, state, request) = attached_world();
            prepare(&mut world);
            arm(&mut world, inject);
            let first = teardown(kind, &mut world, &state, &request);
            let point = world.trace.borrow().last().cloned().unwrap_or_default();
            let context = format!("{kind:?} {inject:?} [{point}] -> {first:?}");
            check_record_matches_reality(&world, &state, PG, &request, &context, &mut problems);
            if first == Outcome::Ok && !clean(&world, &state, PG, &request) {
                problems.push(format!("{context}: success but live={:?}", world.live(PG, &request)));
            }
            // Retry the same verb up to three times, as an operator or a
            // restarted unit would.
            let mut tail = String::new();
            let mut converged = first == Outcome::Ok;
            for _ in 0..3 {
                if converged {
                    break;
                }
                world.reset_injection();
                let next = cleanup(&mut world, &state, &request);
                tail.push_str(&format!("cleanup={next:?}; "));
                check_record_matches_reality(&world, &state, PG, &request, &format!("{context} / retry"), &mut problems);
                converged = next == Outcome::Ok;
            }
            if !converged || !clean(&world, &state, PG, &request) {
                problems.push(format!(
                    "{context}: did not converge: {tail} live={:?} record={}",
                    world.live(PG, &request),
                    state.read("pg").ok().flatten().is_some()
                ));
            } else {
                world.start_daemon("pg");
                world.reset_injection();
                let again = attach(&mut world, &state, &request);
                tail.push_str(&format!("attach={again:?}"));
                if again != Outcome::Ok {
                    problems.push(format!("{context}: re-attach after teardown failed: {again:?}"));
                }
            }
            all_rows.push(format!("{context} | {tail}"));
        }
    }
    // "The kernel drops pid/backend when the server dies while a mapping
    // still holds the device" is not what netlink NBD does (an open device
    // keeps its config): listed for the record, not counted.
    let (model_only, problems): (Vec<String>, Vec<String>) = problems
        .into_iter()
        .partition(|problem| problem.starts_with("CleanupDeadDaemonKernelDropped"));
    for line in &model_only {
        println!("MODEL-ONLY {line}");
    }
    print_report("teardown", &all_rows, &problems);
    assert!(problems.is_empty(), "{} problems", problems.len());
}

#[test]
fn audit5_matrix_grow() {
    const TARGET: u64 = 2 << 30;
    let (mut world, state, request) = attached_world();
    assert_eq!(grow(&mut world, &state, &request, TARGET), Outcome::Ok);
    let (cmds, obs) = (world.cmds.get(), world.obs.get());
    println!("grow baseline: {cmds} commands, {obs} observations: {}", world.trace.borrow().join(" "));
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for inject in injections(cmds, obs) {
        let (mut world, state, request) = attached_world();
        arm(&mut world, inject);
        let first = grow(&mut world, &state, &request, TARGET);
        let point = world.trace.borrow().last().cloned().unwrap_or_default();
        let context = format!("grow {inject:?} [{point}] -> {first:?}");
        check_record_matches_reality(&world, &state, PG, &request, &context, &mut problems);
        if !fully_attached(&world, &state, PG, &request) {
            problems.push(format!("{context}: grow disturbed the attachment"));
        }
        world.reset_injection();
        let again = grow(&mut world, &state, &request, TARGET);
        let lv = world.k.borrow().lv_size.get("vg_maki_pg").copied();
        let fs = world.k.borrow().fs_size.get("vg_maki_pg").copied();
        if again != Outcome::Ok || lv != Some(TARGET) || fs != Some(TARGET) {
            problems.push(format!("{context}: retry {again:?} lv={lv:?} fs={fs:?}"));
        }
        // And the attachment still detaches.
        world.reset_injection();
        let down = cleanup(&mut world, &state, &request);
        if down != Outcome::Ok || !clean(&world, &state, PG, &request) {
            problems.push(format!("{context}: cleanup after grow: {down:?}"));
        }
        rows.push(format!("{context} | retry={again:?} lv={lv:?} fs={fs:?}"));
    }
    print_report("grow", &rows, &problems);
    assert!(problems.is_empty(), "{} problems", problems.len());
}

// ---------------------------------------------------------------------------
// (c) The kernel state changes under the helper: another actor's mount,
// holder, mapping or NBD connection appears at observation k (visible to
// that observation and every later one) or right before command k (the
// inherent check-to-use window).
// ---------------------------------------------------------------------------

const HOOKS: [Hook; 9] = [
    Hook::ForeignMountOnTop,
    Hook::ForeignXfsOnTop,
    Hook::NestedMount,
    Hook::OurLvMountedElsewhere,
    Hook::ForeignHolder,
    Hook::BackendReplaced,
    Hook::BackendDropped,
    Hook::DaemonDies,
    Hook::ForeignSameNameVg,
];

fn hook_sweep(
    title: &str,
    prepare: impl Fn() -> (World, TrustedState, AttachRequest),
    verb: impl Fn(&mut World, &TrustedState, &AttachRequest) -> Outcome,
) -> (Vec<String>, Vec<String>) {
    let (mut world, state, request) = prepare();
    let _ = verb(&mut world, &state, &request);
    let (cmds, obs) = (world.cmds.get(), world.obs.get());
    drop(world);
    let mut rows = Vec::new();
    let mut problems = Vec::new();
    for hook in HOOKS {
        for (at_obs, limit) in [(true, obs), (false, cmds)] {
            for at in 1..=limit {
                let (mut world, state, request) = prepare();
                world.reset_injection();
                *world.hook_target.borrow_mut() = Some(request.clone());
                if at_obs {
                    world.obs_hook.set(Some((at, hook)));
                } else {
                    world.cmd_hook.set(Some((at, hook)));
                }
                let outcome = verb(&mut world, &state, &request);
                let after: Vec<String> = {
                    let trace = world.trace.borrow();
                    let key = format!("{}{at}:", if at_obs { "o" } else { "c" });
                    let position = trace.iter().position(|entry| entry.starts_with(&key));
                    position
                        .map(|p| trace[p..].iter().filter(|e| e.starts_with('c')).cloned().collect())
                        .unwrap_or_default()
                };
                let context = format!(
                    "{title} {hook:?} at {}{at} -> {outcome:?}; commands from the change on: {after:?}",
                    if at_obs { "o" } else { "c" }
                );
                for violation in world.violations.borrow().iter() {
                    if at_obs {
                        problems.push(format!("{context}: SAFETY {violation}"));
                    } else {
                        // The change lands after the helper's last look and
                        // before a path/name/index addressed command: the
                        // inherent check-to-use window. Listed, not counted.
                        println!("INHERENT-WINDOW {context}: {violation}");
                    }
                }
                rows.push(format!(
                    "{context} | live={:?} record={}",
                    world.live(PG, &request),
                    state.read("pg").ok().flatten().is_some()
                ));
            }
        }
    }
    (rows, problems)
}

#[test]
fn audit5_hooks() {
    let fresh = || {
        let world = World::new();
        let state = world.state();
        let request = world.request(PG);
        (world, state, request)
    };
    let mut total = 0;
    for (title, rows, problems) in [
        {
            let (r, p) = hook_sweep("attach", fresh, attach);
            ("attach", r, p)
        },
        {
            let (r, p) = hook_sweep("detach", attached_world, detach);
            ("detach", r, p)
        },
        {
            let (r, p) = hook_sweep("cleanup", attached_world, cleanup);
            ("cleanup", r, p)
        },
        {
            let (r, p) = hook_sweep("grow", attached_world, |w, s, r| grow(w, s, r, 2 << 30));
            ("grow", r, p)
        },
    ] {
        print_report(&format!("hooks/{title}"), &rows, &problems);
        total += problems.len();
    }
    assert_eq!(total, 0, "{total} safety problems");
}

// ---------------------------------------------------------------------------
// Scenario: two volumes with automatic device allocation.
// ---------------------------------------------------------------------------

/// A helper for volume `pg` dies after publishing its record and before the
/// kernel shows its connection. The record names /dev/nbd3; nothing is
/// connected. A second volume's attach (queued on the attach lock) then
/// allocates the lowest free device: the same /dev/nbd3.
#[test]
fn audit5_stale_record_device_is_reallocated_and_wedges_the_first_volume() {
    let mut world = World::new();
    let state = world.state();
    let pg = world.request(PG);
    let db = world.request(DB);

    // c3 is nbd-connect: die before it (record already published).
    arm(&mut world, Inject::Cmd(3, Fault::DieBefore));
    assert_eq!(attach(&mut world, &state, &pg), Outcome::Died);
    let stale = state.read("pg").unwrap().expect("record published before connect");
    assert_eq!(stale.device, "/dev/nbd3");
    assert!(world.nothing_live(PG, &pg));

    // The other volume attaches next and is handed the recorded device.
    world.reset_injection();
    assert_eq!(attach(&mut world, &state, &db), Outcome::Ok);
    let other = state.read("db").unwrap().unwrap();
    println!("pg record: {} / db record: {}", stale.device, other.device);
    assert_eq!(other.device, "/dev/nbd3", "allocation ignores other volumes' records");

    // Now every verb for pg refuses, although nothing of pg exists.
    world.reset_injection();
    let c = cleanup(&mut world, &state, &pg);
    world.reset_injection();
    let r = recover_verb(&mut world, &state, &pg);
    world.reset_injection();
    let d = detach(&mut world, &state, &pg);
    world.reset_injection();
    let a = attach(&mut world, &state, &pg);
    println!("cleanup(pg) = {c:?}\nrecover(pg) = {r:?}\ndetach(pg)  = {d:?}\nattach(pg)  = {a:?}");
    assert!(world.violations.borrow().is_empty());
    assert!(fully_attached(&world, &state, DB, &db), "db must be untouched");
    let wedged = [&c, &r, &d, &a].iter().all(|o| matches!(o, Outcome::Err(_)))
        && state.read("pg").unwrap().is_some();
    // The defect: pg cannot be attached or cleaned up while db is attached.
    assert!(
        !wedged,
        "volume pg is wedged by its own stale record while db uses /dev/nbd3"
    );
}

// ---------------------------------------------------------------------------
// Finding A: the activation-intent window and the packaged recovery order.
// ---------------------------------------------------------------------------

/// The attach helper is killed after `vgchange --activate y` took effect and
/// before the mapping proof replaced the pre-activation intent (the child
/// `vgchange` finishes on its own). `maki-recover@` then runs: its
/// `Conflicts=maki@%i.service` + `After=` stop the daemon FIRST, and only
/// then `maki-attach cleanup`. The intent path needs LVM to read the PV, the
/// proof fallback refuses an intent, so nothing can remove the mapping.
#[test]
fn audit5_intent_window_death_cannot_be_cleaned_after_the_daemon_is_stopped() {
    let mut wedged = Vec::new();
    for select_noop in [false, true] {
        let mut world = World::new();
        world.lvm_select_noop_without_pv = select_noop;
        let state = world.state();
        let request = world.request(PG);
        // c7 is `vgchange --activate y`; die right after its effect.
        arm(&mut world, Inject::Cmd(7, Fault::DieAfter));
        assert_eq!(attach(&mut world, &state, &request), Outcome::Died);
        let record = state.read("pg").unwrap().unwrap();
        assert!(record.recovery_intent.is_some() && record.recovery.is_none());
        assert_eq!(world.live(PG, &request), (vec![3], true, false));

        // Control: with the daemon still serving the device, cleanup works.
        {
            let mut control = World::new();
            let control_state = control.state();
            let control_request = control.request(PG);
            arm(&mut control, Inject::Cmd(7, Fault::DieAfter));
            assert_eq!(attach(&mut control, &control_state, &control_request), Outcome::Died);
            control.reset_injection();
            assert_eq!(cleanup(&mut control, &control_state, &control_request), Outcome::Ok);
            assert!(clean(&control, &control_state, PG, &control_request));
        }

        // Packaged lifecycle: ExecStopPost -> maki-recover@ -> daemon stopped.
        world.kill_daemon("pg");
        let mut outcomes = Vec::new();
        for _ in 0..3 {
            world.reset_injection();
            outcomes.push(cleanup(&mut world, &state, &request));
        }
        world.reset_injection();
        let explicit_recover = recover_verb(&mut world, &state, &request);
        world.reset_injection();
        let explicit_detach = detach(&mut world, &state, &request);
        // A new daemon process does not revive the old kernel connection.
        world.start_daemon("pg");
        world.reset_injection();
        let after_restart = cleanup(&mut world, &state, &request);
        world.reset_injection();
        let reattach = attach(&mut world, &state, &request);
        println!(
            "select_noop={select_noop}\n cleanup x3 = {outcomes:?}\n recover = {explicit_recover:?}\n detach = {explicit_detach:?}\n cleanup after daemon restart = {after_restart:?}\n attach = {reattach:?}\n live = {:?} record = {}",
            world.live(PG, &request),
            state.read("pg").unwrap().is_some()
        );
        assert!(world.violations.borrow().is_empty());
        if !(clean(&world, &state, PG, &request) || reattach == Outcome::Ok) {
            wedged.push(format!("select_noop={select_noop}: live={:?}", world.live(PG, &request)));
        }
    }
    assert!(
        wedged.is_empty(),
        "no product path removes the active mapping: {wedged:?}"
    );
}

// ---------------------------------------------------------------------------
// Double faults: a failed/killed attach, then a failed/killed cleanup.
// ---------------------------------------------------------------------------

#[test]
fn audit5_matrix_attach_then_cleanup_double_fault() {
    let (cmds, obs, _) = count_points(|world, state, request| {
        assert_eq!(attach(world, state, request), Outcome::Ok);
    });
    let mut problems = Vec::new();
    let mut cases = 0;
    for first in injections(cmds, obs) {
        // Only deaths leave partial state behind (failures roll back).
        if !matches!(
            first,
            Inject::Cmd(_, Fault::DieBefore | Fault::DieAfter) | Inject::Obs(_, ObsFault::Die)
        ) {
            continue;
        }
        for daemon_dead in [false, true] {
            // Count the cleanup's own injection points for this start state.
            let prepare = || {
                let mut world = World::new();
                let state = world.state();
                let request = world.request(PG);
                arm(&mut world, first);
                let outcome = attach(&mut world, &state, &request);
                if daemon_dead {
                    world.kill_daemon("pg");
                }
                world.reset_injection();
                (world, state, request, outcome)
            };
            let (mut world, state, request, outcome) = prepare();
            if outcome == Outcome::Ok {
                continue;
            }
            let base = cleanup(&mut world, &state, &request);
            let (c, o) = (world.cmds.get(), world.obs.get());
            let base_converged = base == Outcome::Ok && clean(&world, &state, PG, &request);
            for second in injections(c, o) {
                cases += 1;
                let (mut world, state, request, _) = prepare();
                arm(&mut world, second);
                let hit = cleanup(&mut world, &state, &request);
                let context = format!(
                    "attach {first:?}, daemon_dead={daemon_dead}, cleanup {second:?} -> {hit:?}"
                );
                check_record_matches_reality(&world, &state, PG, &request, &context, &mut problems);
                let mut converged = hit == Outcome::Ok && clean(&world, &state, PG, &request);
                let mut tail = Vec::new();
                for _ in 0..3 {
                    if converged {
                        break;
                    }
                    world.reset_injection();
                    let next = cleanup(&mut world, &state, &request);
                    converged = next == Outcome::Ok && clean(&world, &state, PG, &request);
                    tail.push(next);
                }
                if base_converged && !converged {
                    problems.push(format!(
                        "{context}: baseline cleanup converges but after this fault it does not: {tail:?} live={:?}",
                        world.live(PG, &request)
                    ));
                }
            }
        }
    }
    println!("double-fault cases: {cases}, problems: {}", problems.len());
    for problem in &problems {
        println!("PROBLEM {problem}");
    }
    assert!(problems.is_empty());
}

// ---------------------------------------------------------------------------
// Bound mismatch: preflight admits 64 LVs, the post-activation proof 63.
// ---------------------------------------------------------------------------

#[test]
fn audit5_preflight_admits_a_vg_the_proof_capture_then_refuses() {
    let world = World::new();
    let state = world.state();
    let request = world.request(PG);
    let record = BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        attachment: (&request).into(),
        device: "/dev/nbd3".into(),
        connection_id: "maki-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c".into(),
        recovery: None,
        recovery_intent: None,
    };
    let _ = state;
    for lv_count in [63usize, 64] {
        // The LVM report with `lv_count` linear LVs (the configured `data` first).
        let mut lvs = vec![serde_json::json!({"lv_name": "data", "lv_uuid": PG.lv_uuid,
            "vg_uuid": PG.vg_uuid, "lv_layout": "linear"})];
        for index in 1..lv_count {
            lvs.push(serde_json::json!({"lv_name": format!("extra{index}"),
                "lv_uuid": format!("{index:06}-iiii-jjjj-kkkk-llll-mmmm-nnnnnn"),
                "vg_uuid": PG.vg_uuid, "lv_layout": "linear"}));
        }
        let report = serde_json::to_vec(&serde_json::json!({"report": [{
            "vg": [{"vg_name": "vg_maki_pg", "vg_uuid": PG.vg_uuid, "vg_seqno": "1",
                "pv_count": "1", "vg_missing_pv_count": "0", "vg_partial": "0",
                "vg_exported": "0", "vg_systemid": "", "vg_lock_type": ""}],
            "pv": [{"pv_name": "/dev/nbd3", "pv_uuid": PG.pv_uuid, "vg_uuid": PG.vg_uuid,
                "pv_missing": "0", "pv_duplicate": "0"}],
            "lv": lvs
        }]}))
        .unwrap();
        let preflight = lvm_preflight::validate(
            &report,
            vec![lvm_preflight::Device {
                path: "/dev/nbd3".into(),
                number: (43, 3),
                start: 0,
                sectors: 1024,
            }],
            [("/dev/nbd3".to_string(), PG.pv_uuid.to_string())].into(),
            "vg_maki_pg",
            "data",
            None,
            |_| Ok((43, 3)),
        );
        // What `vgchange --activate y` then creates: one mapping per LV.
        let sysfs = world.dir.join(format!("sys-{lv_count}"));
        let nbd = sysfs.join("nbd3");
        std::fs::create_dir_all(nbd.join("holders")).unwrap();
        std::fs::write(nbd.join("dev"), "43:3\n").unwrap();
        std::fs::write(nbd.join("size"), "1024\n").unwrap();
        for index in 0..lv_count {
            let (name, uuid) = if index == 0 {
                ("data".to_string(), PG.lv_uuid.to_string())
            } else {
                (
                    format!("extra{index}"),
                    format!("{index:06}-iiii-jjjj-kkkk-llll-mmmm-nnnnnn"),
                )
            };
            let dm = sysfs.join(format!("dm-{index}"));
            std::fs::create_dir_all(dm.join("dm")).unwrap();
            std::fs::create_dir_all(dm.join("slaves")).unwrap();
            std::fs::create_dir_all(dm.join("holders")).unwrap();
            std::fs::write(dm.join("dev"), format!("253:{index}\n")).unwrap();
            std::fs::write(dm.join("dm/name"), format!("vg_maki_pg-{name}\n")).unwrap();
            std::fs::write(
                dm.join("dm/uuid"),
                format!("LVM-{}{}\n", PG.vg_uuid.replace('-', ""), uuid.replace('-', "")),
            )
            .unwrap();
            std::fs::write(dm.join("slaves/nbd3"), "").unwrap();
            std::fs::write(nbd.join(format!("holders/dm-{index}")), "").unwrap();
        }
        let mapping = preflight
            .as_ref()
            .map_err(|e| e.to_string())
            .and_then(|verified| {
                lvm_preflight::verify_mapping(&record, verified, &sysfs).map_err(|e| e.to_string())
            });
        let proof = recover::capture(&record, b"", &sysfs).map(|_| ());
        println!(
            "{lv_count} LVs: preflight={:?} verify_mapping={mapping:?} proof={proof:?}",
            preflight.as_ref().map(|_| ()).map_err(|e| e.to_string())
        );
        assert_eq!(
            preflight.is_ok(),
            proof.is_ok(),
            "{lv_count} LVs: preflight admits a VG whose activated topology the proof capture refuses"
        );
    }
}

// ---------------------------------------------------------------------------
// Doc check: "only an exited command with a nonzero status may continue"
// (docs/operations.md, the dmsetup fallback of `cleanup`).
// ---------------------------------------------------------------------------

#[test]
fn audit5_signal_killed_vgchange_also_enters_the_dmsetup_fallback() {
    let (mut world, state, request) = attached_world();
    // c2 of a connected cleanup is the plain `vgchange -an`. Here the daemon
    // is alive and LVM would have worked: the command is killed by a signal
    // (OOM killer, SIGSEGV) before doing anything.
    arm(&mut world, Inject::Cmd(2, Fault::SignalBefore));
    let outcome = cleanup(&mut world, &state, &request);
    let trace = world.trace.borrow().join(" ");
    println!("{outcome:?}\n{trace}");
    assert!(
        !trace.contains("dmsetup-remove"),
        "a vgchange terminated by a signal (no exit status) entered the direct dmsetup removal"
    );
}

// ---------------------------------------------------------------------------
// The daemon (not the helper) dies at every point of an attach, a detach and
// a grow; the helper keeps running. Then the packaged recovery: cleanup with
// the daemon gone, a new daemon, a new attach.
// ---------------------------------------------------------------------------

#[test]
fn audit5_daemon_death_at_every_point() {
    let mut problems = Vec::new();
    let mut rows = Vec::new();
    type Prepare = fn() -> (World, TrustedState, AttachRequest);
    type Verb = fn(&mut World, &TrustedState, &AttachRequest) -> Outcome;
    fn fresh() -> (World, TrustedState, AttachRequest) {
        let world = World::new();
        let state = world.state();
        let request = world.request(PG);
        (world, state, request)
    }
    fn grow_verb(w: &mut World, s: &TrustedState, r: &AttachRequest) -> Outcome {
        grow(w, s, r, 2 << 30)
    }
    let verbs: [(&str, Prepare, Verb); 4] = [
        ("attach", fresh, attach),
        ("detach", attached_world, detach),
        ("cleanup", attached_world, cleanup),
        ("grow", attached_world, grow_verb),
    ];
    for (title, prepare, verb) in verbs {
        let (mut world, state, request) = prepare();
        let _ = verb(&mut world, &state, &request);
        let (cmds, obs) = (world.cmds.get(), world.obs.get());
        drop(world);
        for (at_obs, limit) in [(true, obs), (false, cmds)] {
            for at in 1..=limit {
                let (mut world, state, request) = prepare();
                world.reset_injection();
                *world.hook_target.borrow_mut() = Some(request.clone());
                if at_obs {
                    world.obs_hook.set(Some((at, Hook::DaemonDies)));
                } else {
                    world.cmd_hook.set(Some((at, Hook::DaemonDies)));
                }
                let first = verb(&mut world, &state, &request);
                let context = format!(
                    "{title}: daemon dies at {}{at} -> {first:?}",
                    if at_obs { "o" } else { "c" }
                );
                check_record_matches_reality(&world, &state, PG, &request, &context, &mut problems);
                let record = state.read("pg").ok().flatten();
                let shape = format!(
                    "live={:?} record={}",
                    world.live(PG, &request),
                    record.as_ref().map_or("none".into(), |r| format!(
                        "{}{}",
                        if r.recovery.is_some() { "proof" } else { "" },
                        if r.recovery_intent.is_some() { "intent" } else { "" }
                    ))
                );
                let mounted_over_dead = world.live(PG, &request).2;
                // maki@ failed -> OnFailure=maki-recover@ -> cleanup.
                let mut tail = Vec::new();
                let mut converged = false;
                for _ in 0..3 {
                    world.reset_injection();
                    let next = cleanup(&mut world, &state, &request);
                    converged = next == Outcome::Ok && clean(&world, &state, PG, &request);
                    tail.push(next);
                    if converged {
                        break;
                    }
                }
                if !converged {
                    problems.push(format!("{context}: {shape}: cleanup never converged: {tail:?}"));
                } else {
                    world.start_daemon("pg");
                    world.reset_injection();
                    let again = attach(&mut world, &state, &request);
                    if again != Outcome::Ok {
                        problems.push(format!("{context}: re-attach failed: {again:?}"));
                    }
                }
                rows.push(format!(
                    "{context} | {shape} | mounted over dead daemon after the verb: {mounted_over_dead} | cleanup: {tail:?}"
                ));
            }
        }
    }
    print_report("daemon death", &rows, &problems);
    assert!(problems.is_empty(), "{} problems", problems.len());
}

/// Finding B, second way in: a planned stop. `cleanup` for `pg` is killed
/// (TimeoutStopSec, OOM) after `nbd-client -d` and before the record is
/// retired. `db` starts later and is handed the freed device; `pg` can then
/// not be started again while `db` runs.
#[test]
fn audit5_killed_detach_leaves_a_record_that_blocks_the_next_start() {
    let (mut world, state, pg) = attached_world();
    let db = world.request(DB);
    // c3 of a connected cleanup is `nbd-client -d`.
    arm(&mut world, Inject::Cmd(3, Fault::DieAfter));
    assert_eq!(cleanup(&mut world, &state, &pg), Outcome::Died);
    assert!(world.nothing_live(PG, &pg));
    assert!(state.read("pg").unwrap().is_some(), "record outlives the killed cleanup");

    world.reset_injection();
    assert_eq!(attach(&mut world, &state, &db), Outcome::Ok);
    assert_eq!(state.read("db").unwrap().unwrap().device, "/dev/nbd3");

    world.reset_injection();
    let start = attach(&mut world, &state, &pg);
    world.reset_injection();
    let recover = cleanup(&mut world, &state, &pg);
    println!("attach(pg) = {start:?}\ncleanup(pg) = {recover:?}");
    assert!(fully_attached(&world, &state, DB, &db));
    assert_eq!(start, Outcome::Ok, "pg cannot start while db holds the device its stale record names");
}

/// The other half of the doc check, on the REAL command runner: a child
/// killed by a signal comes back from `command::capture` as a completed
/// `Output` without an exit code, and `run()` turns it into the very
/// `ExecError::StepFailed` (with `status: None`) that the cleanup fallback
/// matches with `StepFailed { .. }`.
#[test]
fn audit5_real_runner_reports_a_signal_kill_as_step_failed_without_status() {
    let step = PlannedStep::LvmDeactivate {
        vg_name: "vg_maki_pg".into(),
    };
    // `sh` stands in for vgchange and kills itself with SIGKILL.
    let error = run(&step, "sh", &["-c", "kill -KILL $$"]).unwrap_err();
    println!("{error:?}");
    match error {
        ExecError::StepFailed { status, .. } => {
            assert_eq!(status, None, "a signal kill carries no exit status");
        }
        other => panic!("expected StepFailed, got {other:?}"),
    }
    // An ordinary nonzero exit is the same variant, with a status.
    match run(&step, "sh", &["-c", "exit 5"]).unwrap_err() {
        ExecError::StepFailed { status, .. } => assert_eq!(status, Some(5)),
        other => panic!("expected StepFailed, got {other:?}"),
    }
}
