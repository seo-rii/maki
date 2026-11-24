//! The XFS mount runs as root onto a path the configuration names, and a
//! workload could own directories along that path (for example a
//! `postgres`-owned parent). `mount(8)` resolves symlinks, so a workload
//! that replaced the mountpoint with a symlink to `/etc` got a filesystem
//! it controls mounted over `/etc`, and neither rollback nor detach could
//! undo it (they look for a mount at the configured path). The helper now
//! refuses a mountpoint unless every ancestor is a real directory owned by
//! a trusted uid and not writable by group or others (so the path cannot
//! change between the check and the mount) and the mountpoint itself is a
//! real directory, not a symlink.
#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use maki_privileged::exec::check_mount_target;

fn trusted() -> Vec<u32> {
    // SAFETY: geteuid has no preconditions.
    vec![0, unsafe { libc::geteuid() }]
}

/// Why a mountpoint below `directory` has to be refused whatever the test
/// builds there, or `None`: every component from `/` down is a real
/// directory owned by a trusted uid and closed to group and others. This
/// restates the rule on purpose, so that choosing where the fixtures go
/// never asks the function under test.
fn untrusted_component(directory: &Path) -> Option<String> {
    let mut prefix = PathBuf::new();
    for component in directory.components() {
        prefix.push(component);
        let meta = match std::fs::symlink_metadata(&prefix) {
            Ok(meta) => meta,
            Err(error) => return Some(format!("{}: {error}", prefix.display())),
        };
        if !meta.is_dir() {
            return Some(format!("{} is not a real directory", prefix.display()));
        }
        if !trusted().contains(&meta.uid()) {
            return Some(format!(
                "{} is owned by uid {}",
                prefix.display(),
                meta.uid()
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Some(format!(
                "{} has mode {:04o}",
                prefix.display(),
                meta.mode() & 0o7777
            ));
        }
    }
    None
}

/// A directory with an explicit mode: the rule under test looks at the
/// group and other write bits, which `create_dir` alone takes from the
/// umask.
fn directory(path: &Path, mode: u32) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A fresh tree for one test, removed when the test ends.
struct Tree(PathBuf);

impl Tree {
    /// The build's scratch directory is the usual place for fixtures, but
    /// the rule refuses it when the build tree is group-writable (made
    /// under umask 002) or belongs to a third user, and `/tmp` is
    /// world-writable by design. The first candidate the rule accepts is
    /// used. With none the test fails: returning early would report a pass
    /// that checked nothing.
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "maki-mount-target-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let candidates = [
            Some(PathBuf::from(env!("CARGO_TARGET_TMPDIR"))),
            Some(std::env::temp_dir()),
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        ];
        let mut refused = Vec::new();
        for candidate in candidates.into_iter().flatten() {
            match Self::below(&candidate, &name) {
                Ok(tree) => return tree,
                Err(reason) => refused.push(format!("  {}: {reason}", candidate.display())),
            }
        }
        panic!(
            "no usable place for the mount-target fixtures: they need a directory this user \
             can write, below ancestors that are all real directories owned by root or by \
             this user and not writable by group or others. Tried:\n{}\nPoint TMPDIR at \
             such a directory to run these tests.",
            refused.join("\n")
        );
    }

    /// A fresh tree below `candidate`, or why it cannot be there.
    fn below(candidate: &Path, name: &str) -> Result<Self, String> {
        // A symlink on the way to the candidate is the host's business; the
        // tests plant the ones they are about.
        let base = std::fs::canonicalize(candidate).map_err(|error| error.to_string())?;
        if let Some(reason) = untrusted_component(&base) {
            return Err(reason);
        }
        let root = base.join(name);
        std::fs::create_dir(&root).map_err(|error| error.to_string())?;
        let tree = Self(root);
        std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
        Ok(tree)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn directory(&self, name: &str) -> PathBuf {
        let path = self.join(name);
        directory(&path, 0o755);
        path
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_real_directory_below_trusted_ancestors_is_accepted() {
    let root = Tree::new();
    let mountpoint = root.directory("data");
    check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn a_symlinked_mountpoint_is_refused() {
    let root = Tree::new();
    let elsewhere = root.directory("elsewhere");
    let mountpoint = root.join("data");
    std::os::unix::fs::symlink(&elsewhere, &mountpoint).unwrap();
    let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
    assert!(error.to_string().contains("symlink"), "{error}");
    // The directory it points at is acceptable: the link is the only fault.
    check_mount_target(elsewhere.to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn a_symlinked_ancestor_is_refused() {
    let root = Tree::new();
    let real = root.directory("real");
    directory(&real.join("data"), 0o755);
    std::os::unix::fs::symlink(&real, root.join("link")).unwrap();
    let mountpoint = root.join("link").join("data");
    let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
    assert!(error.to_string().contains("symlink"), "{error}");
    check_mount_target(real.join("data").to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn an_ancestor_writable_by_others_or_owned_by_an_untrusted_uid_is_refused() {
    let root = Tree::new();
    let parent = root.directory("parent");
    let mountpoint = parent.join("data");
    directory(&mountpoint, 0o755);
    for mode in [0o777, 0o775, 0o757] {
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
        assert!(error.to_string().contains("writable"), "{mode:o}: {error}");
    }
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    // Only root trusted: the test user's directories are not.
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        assert!(check_mount_target(mountpoint.to_str().unwrap(), &[0]).is_err());
    }
    check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap();
}

#[test]
fn a_missing_or_non_directory_mountpoint_is_refused() {
    let root = Tree::new();
    assert!(check_mount_target(root.join("absent").to_str().unwrap(), &trusted()).is_err());
    std::fs::write(root.join("file"), b"x").unwrap();
    std::fs::set_permissions(root.join("file"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let error = check_mount_target(root.join("file").to_str().unwrap(), &trusted()).unwrap_err();
    assert!(error.to_string().contains("not a directory"), "{error}");
}

/// R5-024: the mountpoint directory itself had no owner or mode rule, so a
/// workload owning it could `fusermount` over it between the check and the
/// mount: XFS then stacked on the FUSE mount, verification failed and the
/// rollback halted with XFS mounted. The directory is hidden once the
/// volume is mounted, so requiring it to be root-owned and not writable by
/// group or others costs workloads nothing (the volume's own root carries
/// their ownership).
#[test]
fn a_mountpoint_owned_or_writable_by_others_is_refused() {
    let root = Tree::new();
    let mountpoint = root.directory("data");
    for mode in [0o777, 0o775, 0o757] {
        std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap_err();
        assert!(error.to_string().contains("writable"), "{mode:o}: {error}");
    }
    std::fs::set_permissions(&mountpoint, std::fs::Permissions::from_mode(0o755)).unwrap();
    check_mount_target(mountpoint.to_str().unwrap(), &trusted()).unwrap();
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        let error = check_mount_target(mountpoint.to_str().unwrap(), &[0, 0]).unwrap_err();
        assert!(error.to_string().contains("owned by uid"), "{error}");
    }
}

/// The fixture's own claims: the place it picks satisfies the rule, the
/// rule it restates notices a writable or symlinked component, and the tree
/// does not outlive the test.
#[test]
fn the_fixture_tree_is_trusted_and_removed() {
    let root = Tree::new();
    assert_eq!(untrusted_component(&root.0), None);
    let open = root.directory("open");
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(untrusted_component(&open).unwrap().contains("mode 0775"));
    std::os::unix::fs::symlink(&root.0, root.join("link")).unwrap();
    assert!(untrusted_component(&root.join("link"))
        .unwrap()
        .contains("not a real directory"));
    let path = root.0.clone();
    drop(root);
    assert!(!path.exists());
}
