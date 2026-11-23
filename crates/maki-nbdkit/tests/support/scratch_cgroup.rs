//! A private cgroup-v2 group for tests of `[security.memory_budget]`
//! admission.
//!
//! Admission reads the process's cgroup membership first and refuses a
//! process in the root of the hierarchy before it opens the mount table. A
//! test run as root in a container or a CI shell usually sits there, so a
//! test comparing two verdicts would compare that refusal with itself.
//! Children that [`enter`] a [`Group`] get past the membership check, as a
//! daemon in a service cgroup does. [`stops_before_the_cgroup`] recognises a
//! verdict that still came from an earlier stage.

use std::path::{Path, PathBuf};

/// Phrases of verdicts that come from the membership file or the mount
/// table rather than from the cgroup.
const BEFORE_THE_CGROUP: [&str; 6] = [
    "membership",
    "mountinfo",
    "cgroup-v2 mount",
    "nested mount",
    "subtree cgroup mount",
    "cgroup path",
];

/// Whether admission refused before it used the cgroup the mount table
/// leads to: a comparison of such verdicts does not reach the table checks.
pub fn stops_before_the_cgroup(verdict: &str) -> bool {
    BEFORE_THE_CGROUP
        .iter()
        .any(|stage| verdict.contains(stage))
}

/// A private, empty cgroup-v2 group under the hierarchy's mount, removed
/// when dropped (the children that joined it have exited by then).
pub struct Group(PathBuf);

impl Group {
    /// Where the hierarchy has the memory controller, the group's
    /// `memory.max` is set to `budget_bytes`, so admission of a
    /// configuration with that budget runs to its end. `Err` is the reason
    /// the host does not permit the group.
    pub fn create(label: &str, budget_bytes: u64) -> Result<Self, String> {
        let table = std::fs::read("/proc/self/mountinfo").map_err(|e| e.to_string())?;
        let mut mounts = table.split(|&byte| byte == b'\n').filter_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            let (mount, filesystem) = line.split_once(" - ")?;
            (filesystem.split(' ').next() == Some("cgroup2"))
                .then(|| mount.split(' ').nth(4).map(PathBuf::from))
                .flatten()
        });
        let (Some(mount), None) = (mounts.next(), mounts.next()) else {
            return Err("no single cgroup-v2 mount in this namespace".into());
        };
        let name = format!("maki-review-memory-budget-{}-{label}", std::process::id());
        let group = mount.join(name);
        std::fs::create_dir(&group)
            .map_err(|e| format!("cannot create a cgroup-v2 group under {mount:?}: {e}"))?;
        let group = Self(group);
        let limit = group.0.join("memory.max");
        if limit.exists() {
            std::fs::write(&limit, budget_bytes.to_string())
                .map_err(|e| format!("cannot set {limit:?}: {e}"))?;
        }
        Ok(group)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir(&self.0) {
            eprintln!("cannot remove the test cgroup {:?}: {error}", self.0);
        }
    }
}

/// Move the calling process into the group at `group`.
pub fn enter(group: &Path) -> std::io::Result<()> {
    std::fs::write(group.join("cgroup.procs"), "0")
}
