//! Plan executor (Linux only): runs each planned step via the corresponding
//! system utility. Kept deliberately trivial — all decision logic lives in
//! the pure planner and verifier so it is testable everywhere.

use std::process::Command;

use crate::plan::{Plan, PlannedStep};

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("step {step:?} failed with status {status:?}: {stderr}")]
    StepFailed {
        step: String,
        status: Option<i32>,
        stderr: String,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn run(step: &PlannedStep, program: &str, args: &[&str]) -> Result<(), ExecError> {
    tracing::info!("maki-attach: {step}");
    let out = Command::new(program).args(args).output()?;
    if !out.status.success() {
        return Err(ExecError::StepFailed {
            step: step.to_string(),
            status: out.status.code(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

pub fn execute(plan: &Plan) -> Result<(), ExecError> {
    for step in &plan.steps {
        match step {
            PlannedStep::ModprobeNbd => run(step, "modprobe", &["nbd"])?,
            PlannedStep::NbdConnect { socket, device } => {
                run(step, "nbd-client", &["-unix", socket, device, "-b", "4096"])?
            }
            PlannedStep::SetBlockSize { device, block_size } => run(
                step,
                "blockdev",
                &["--setbsz", &block_size.to_string(), device],
            )?,
            PlannedStep::LvmActivate { vg_name } => run(step, "vgchange", &["-ay", vg_name])?,
            PlannedStep::LvmDeactivate { vg_name } => run(step, "vgchange", &["-an", vg_name])?,
            PlannedStep::MountXfs { device, mountpoint } => run(
                step,
                "mount",
                &["-t", "xfs", "-o", "noatime", device, mountpoint],
            )?,
            PlannedStep::VerifyMountIdentity { .. } => {
                // Gathered observations feed `verify::verify_mount_identity`;
                // wiring is in the maki-attach binary.
            }
            PlannedStep::Umount { mountpoint } => run(step, "umount", &[mountpoint.as_str()])?,
            PlannedStep::NbdDisconnect { device } => run(step, "nbd-client", &["-d", device])?,
            PlannedStep::LvExtend {
                vg_name,
                lv_name,
                add_bytes,
            } => run(
                step,
                "lvextend",
                &[
                    "-L",
                    &format!("+{add_bytes}b"),
                    &format!("{vg_name}/{lv_name}"),
                ],
            )?,
            PlannedStep::XfsGrowfs { mountpoint } => {
                run(step, "xfs_growfs", &[mountpoint.as_str()])?
            }
        }
    }
    Ok(())
}
