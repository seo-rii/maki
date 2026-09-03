//! Deterministic operation plans for the privileged helper (SPEC §6).
//! Plans are pure data: auditable, testable, and rendered before execution.
//!
//! Review M-016: an attach may leave the NBD device unassigned
//! ([`AUTO_NBD_DEVICE`]); the executor allocates a free device under the
//! attach lock and binds it into the plan before running it. Every plan can
//! be rolled back: [`rollback_steps`] derives the compensating steps for the
//! prefix that already ran, in reverse order.

use std::fmt;

/// Placeholder for "allocate a free `/dev/nbdN` at execution time".
pub const AUTO_NBD_DEVICE: &str = "/dev/nbd<auto>";

/// Name of the sentinel file the mount guard reads (SPEC §39).
pub const SENTINEL_FILE: &str = ".maki-sentinel";

#[derive(Debug, Clone)]
pub struct AttachRequest {
    pub volume: String,
    pub nbd_socket: String,
    /// A concrete `/dev/nbdN`, or [`AUTO_NBD_DEVICE`].
    pub nbd_device: String,
    pub device_block_size: u32,
    pub vg_name: String,
    pub lv_name: String,
    pub mountpoint: String,
    /// The Maki volume UUID the mounted filesystem's sentinel must carry.
    pub volume_uuid: String,
    /// Expected XFS filesystem UUID (`None` = not pinned).
    pub fs_uuid: Option<String>,
    /// Write the sentinel if the filesystem has none yet (first boot).
    pub init_sentinel: bool,
}

#[derive(Debug, Clone)]
pub struct GrowRequest {
    pub volume: String,
    pub vg_name: String,
    pub lv_name: String,
    pub add_bytes: u64,
    pub mountpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannedStep {
    ModprobeNbd,
    NbdConnect {
        socket: String,
        device: String,
        block_size: u32,
    },
    SetBlockSize {
        device: String,
        block_size: u32,
    },
    LvmActivate {
        vg_name: String,
    },
    LvmDeactivate {
        vg_name: String,
    },
    MountXfs {
        device: String,
        mountpoint: String,
    },
    /// Create `<mountpoint>/.maki-sentinel` holding the volume UUID if it
    /// does not exist yet; never overwrite a different value.
    WriteSentinel {
        mountpoint: String,
        volume_uuid: String,
    },
    VerifyMountIdentity {
        mountpoint: String,
        volume_uuid: String,
        fs_uuid: Option<String>,
        nbd_device: String,
    },
    Umount {
        mountpoint: String,
    },
    NbdDisconnect {
        device: String,
    },
    LvExtend {
        vg_name: String,
        lv_name: String,
        add_bytes: u64,
    },
    XfsGrowfs {
        mountpoint: String,
    },
}

impl PlannedStep {
    pub fn kind(&self) -> &'static str {
        match self {
            PlannedStep::ModprobeNbd => "modprobe-nbd",
            PlannedStep::NbdConnect { .. } => "nbd-connect",
            PlannedStep::SetBlockSize { .. } => "set-block-size",
            PlannedStep::LvmActivate { .. } => "lvm-activate",
            PlannedStep::LvmDeactivate { .. } => "lvm-deactivate",
            PlannedStep::MountXfs { .. } => "mount-xfs",
            PlannedStep::WriteSentinel { .. } => "write-sentinel",
            PlannedStep::VerifyMountIdentity { .. } => "verify-mount-identity",
            PlannedStep::Umount { .. } => "umount",
            PlannedStep::NbdDisconnect { .. } => "nbd-disconnect",
            PlannedStep::LvExtend { .. } => "lvextend",
            PlannedStep::XfsGrowfs { .. } => "xfs-growfs",
        }
    }

    /// Replace the auto-allocation placeholder with a concrete device.
    fn bind_device(&mut self, device: &str) {
        let fields: [&mut String; 1] = match self {
            PlannedStep::NbdConnect { device: d, .. }
            | PlannedStep::SetBlockSize { device: d, .. }
            | PlannedStep::NbdDisconnect { device: d }
            | PlannedStep::VerifyMountIdentity { nbd_device: d, .. } => [d],
            _ => return,
        };
        for field in fields {
            if field == AUTO_NBD_DEVICE {
                *field = device.to_string();
            }
        }
    }
}

impl fmt::Display for PlannedStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlannedStep::ModprobeNbd => write!(f, "modprobe nbd"),
            PlannedStep::NbdConnect {
                socket,
                device,
                block_size,
            } => write!(f, "nbd-client -unix {socket} {device} -b {block_size}"),
            PlannedStep::SetBlockSize { device, block_size } => {
                write!(f, "blockdev --setbsz {block_size} {device}")
            }
            PlannedStep::LvmActivate { vg_name } => write!(f, "vgchange -ay {vg_name}"),
            PlannedStep::LvmDeactivate { vg_name } => write!(f, "vgchange -an {vg_name}"),
            PlannedStep::MountXfs { device, mountpoint } => {
                write!(f, "mount -t xfs -o noatime {device} {mountpoint}")
            }
            PlannedStep::WriteSentinel {
                mountpoint,
                volume_uuid,
            } => write!(
                f,
                "write sentinel {mountpoint}/{SENTINEL_FILE} = {volume_uuid} (only if absent)"
            ),
            PlannedStep::VerifyMountIdentity {
                mountpoint,
                volume_uuid,
                fs_uuid,
                nbd_device,
            } => write!(
                f,
                "verify mount identity at {mountpoint} (volume {volume_uuid}, fs uuid {}, nbd {nbd_device})",
                fs_uuid.as_deref().unwrap_or("unpinned")
            ),
            PlannedStep::Umount { mountpoint } => write!(f, "umount {mountpoint}"),
            PlannedStep::NbdDisconnect { device } => write!(f, "nbd-client -d {device}"),
            PlannedStep::LvExtend {
                vg_name,
                lv_name,
                add_bytes,
            } => write!(f, "lvextend -L +{add_bytes}b {vg_name}/{lv_name}"),
            PlannedStep::XfsGrowfs { mountpoint } => write!(f, "xfs_growfs {mountpoint}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub description: String,
    pub steps: Vec<PlannedStep>,
}

impl Plan {
    /// True if any step still refers to [`AUTO_NBD_DEVICE`].
    pub fn needs_device_allocation(&self) -> bool {
        self.steps.iter().any(|s| {
            matches!(
                s,
                PlannedStep::NbdConnect { device, .. }
                | PlannedStep::SetBlockSize { device, .. }
                | PlannedStep::NbdDisconnect { device }
                | PlannedStep::VerifyMountIdentity { nbd_device: device, .. }
                if device == AUTO_NBD_DEVICE
            )
        })
    }

    /// Bind an allocated device into every placeholder.
    pub fn bind_device(&mut self, device: &str) {
        for step in &mut self.steps {
            step.bind_device(device);
        }
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# {}", self.description)?;
        for (i, step) in self.steps.iter().enumerate() {
            writeln!(f, "{}. {}", i + 1, step)?;
        }
        Ok(())
    }
}

pub fn plan_attach(request: &AttachRequest) -> Plan {
    let mut steps = vec![
        PlannedStep::ModprobeNbd,
        PlannedStep::NbdConnect {
            socket: request.nbd_socket.clone(),
            device: request.nbd_device.clone(),
            block_size: request.device_block_size,
        },
        PlannedStep::SetBlockSize {
            device: request.nbd_device.clone(),
            block_size: request.device_block_size,
        },
        PlannedStep::LvmActivate {
            vg_name: request.vg_name.clone(),
        },
        PlannedStep::MountXfs {
            device: format!("/dev/{}/{}", request.vg_name, request.lv_name),
            mountpoint: request.mountpoint.clone(),
        },
    ];
    if request.init_sentinel {
        steps.push(PlannedStep::WriteSentinel {
            mountpoint: request.mountpoint.clone(),
            volume_uuid: request.volume_uuid.clone(),
        });
    }
    steps.push(PlannedStep::VerifyMountIdentity {
        mountpoint: request.mountpoint.clone(),
        volume_uuid: request.volume_uuid.clone(),
        fs_uuid: request.fs_uuid.clone(),
        nbd_device: request.nbd_device.clone(),
    });
    Plan {
        description: format!("attach volume {}", request.volume),
        steps,
    }
}

pub fn plan_detach(request: &AttachRequest) -> Plan {
    Plan {
        description: format!("detach volume {}", request.volume),
        steps: vec![
            PlannedStep::Umount {
                mountpoint: request.mountpoint.clone(),
            },
            PlannedStep::LvmDeactivate {
                vg_name: request.vg_name.clone(),
            },
            PlannedStep::NbdDisconnect {
                device: request.nbd_device.clone(),
            },
        ],
    }
}

/// Online growth (SPEC §38): `lvextend` then `xfs_growfs`; no NBD resize.
pub fn plan_grow(request: &GrowRequest) -> Plan {
    Plan {
        description: format!("grow volume {}", request.volume),
        steps: vec![
            PlannedStep::LvExtend {
                vg_name: request.vg_name.clone(),
                lv_name: request.lv_name.clone(),
                add_bytes: request.add_bytes,
            },
            PlannedStep::XfsGrowfs {
                mountpoint: request.mountpoint.clone(),
            },
        ],
    }
}

/// Compensating steps for an already-executed prefix, newest first: a
/// mount is unmounted, an activated VG deactivated, a connected NBD device
/// disconnected. Steps without side effects that outlive a failure (module
/// load, block-size hint, sentinel, verification, growth) have none.
pub fn rollback_steps(executed: &[PlannedStep]) -> Vec<PlannedStep> {
    executed
        .iter()
        .rev()
        .filter_map(|step| match step {
            PlannedStep::MountXfs { mountpoint, .. } => Some(PlannedStep::Umount {
                mountpoint: mountpoint.clone(),
            }),
            PlannedStep::LvmActivate { vg_name } => Some(PlannedStep::LvmDeactivate {
                vg_name: vg_name.clone(),
            }),
            PlannedStep::NbdConnect { device, .. } => Some(PlannedStep::NbdDisconnect {
                device: device.clone(),
            }),
            _ => None,
        })
        .collect()
}
