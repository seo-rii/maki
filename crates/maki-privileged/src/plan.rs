//! Deterministic operation plans for the privileged helper (SPEC §6).
//! Plans are pure data: auditable, testable, and rendered before execution.

use std::fmt;

#[derive(Debug, Clone)]
pub struct AttachRequest {
    pub volume: String,
    pub nbd_socket: String,
    pub nbd_device: String,
    pub device_block_size: u32,
    pub vg_name: String,
    pub lv_name: String,
    pub mountpoint: String,
    pub volume_uuid: String,
}

#[derive(Debug, Clone)]
pub struct GrowRequest {
    pub volume: String,
    pub vg_name: String,
    pub lv_name: String,
    pub add_bytes: u64,
    pub mountpoint: String,
}

#[derive(Debug, Clone)]
pub enum PlannedStep {
    ModprobeNbd,
    NbdConnect {
        socket: String,
        device: String,
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
    VerifyMountIdentity {
        mountpoint: String,
        volume_uuid: String,
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
            PlannedStep::VerifyMountIdentity { .. } => "verify-mount-identity",
            PlannedStep::Umount { .. } => "umount",
            PlannedStep::NbdDisconnect { .. } => "nbd-disconnect",
            PlannedStep::LvExtend { .. } => "lvextend",
            PlannedStep::XfsGrowfs { .. } => "xfs-growfs",
        }
    }
}

impl fmt::Display for PlannedStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlannedStep::ModprobeNbd => write!(f, "modprobe nbd"),
            PlannedStep::NbdConnect { socket, device } => {
                write!(f, "nbd-client -unix {socket} {device}")
            }
            PlannedStep::SetBlockSize { device, block_size } => {
                write!(f, "blockdev --setbsz {block_size} {device}")
            }
            PlannedStep::LvmActivate { vg_name } => write!(f, "vgchange -ay {vg_name}"),
            PlannedStep::LvmDeactivate { vg_name } => write!(f, "vgchange -an {vg_name}"),
            PlannedStep::MountXfs { device, mountpoint } => {
                write!(f, "mount -t xfs -o noatime {device} {mountpoint}")
            }
            PlannedStep::VerifyMountIdentity {
                mountpoint,
                volume_uuid,
            } => write!(
                f,
                "verify mount identity at {mountpoint} (volume {volume_uuid})"
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
    Plan {
        description: format!("attach volume {}", request.volume),
        steps: vec![
            PlannedStep::ModprobeNbd,
            PlannedStep::NbdConnect {
                socket: request.nbd_socket.clone(),
                device: request.nbd_device.clone(),
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
            PlannedStep::VerifyMountIdentity {
                mountpoint: request.mountpoint.clone(),
                volume_uuid: request.volume_uuid.clone(),
            },
        ],
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
