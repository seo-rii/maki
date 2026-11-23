//! Audit round 5 (remote-admin-crash): one namespace directory the daemon
//! user cannot open stops remote GC for every higher-fence namespace, and
//! the automatic pass hides the error. Not part of the maintained suite.
//!
//! `takeover`, `restore` and `resume-enrollment` run as root and create the
//! new writer namespace for the daemon user: `mkdirat`, then `fchown`. A
//! process death between the two (SIGKILL here, delivered by strace at the
//! `fchown`) leaves an empty `remote-<fence>-<session>` directory owned by
//! root, mode 0700. The documented consequence is "an empty root-owned
//! directory, which later runs open as it is". The daemon user's GC cannot:
//! `gc_retire` treats EACCES as a storage error and returns it, so
//! `collect_within` stops at that entry. Entries are visited in name order,
//! which is fence order, so every namespace with a higher fence is never
//! reclaimed. `open_remote` ignores the GC error, the volume keeps
//! attaching, and each attach, takeover or snapshot from then on leaves a
//! whole arena behind (2 x capacity plus two manifest slots) until the
//! filesystem fills and the next attach cannot reserve its namespace.
//!
//! Needs root (to create the root-owned leftover and to drop to `nobody`),
//! `setpriv` and `strace`; skips otherwise.

#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use maki_backing::remote_witness::{Action, CanonicalState, Record, Request, Role, Rpc};
use maki_backing::{Backing, RollbackBacking};

const CAPACITY: u64 = 16 * 4096;
const IDENTITY: [u8; 16] = [0x6C; 16];
const NOBODY: u32 = 65534;

/// The authority, shared by the processes of this test through one file.
struct FileAuthority {
    path: PathBuf,
    role: Role,
}

impl Rpc for FileAuthority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        let state = CanonicalState::decode(&std::fs::read(&self.path)?)?;
        let next = state.apply(self.role, request)?;
        if next != state {
            let staged = self.path.with_extension("next");
            std::fs::write(&staged, next.encode()?)?;
            std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o666))?;
            std::fs::rename(&staged, &self.path)?;
        }
        Ok(next.record().clone())
    }
}

fn rpc(top: &Path, role: Role) -> Arc<dyn Rpc> {
    Arc::new(FileAuthority {
        path: top.join("authority/state"),
        role,
    })
}

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        operation_id: [0; 16],
        expected: None,
        action: Action::Inspect,
        authorization: None,
    })
    .unwrap()
}

fn commit(backing: &RollbackBacking, tag: &[u8]) {
    let file = backing.open("probe", true).unwrap();
    file.write_at(0, tag).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

/// One command of the volume's life, run by the user the parent chose.
#[test]
fn audit5_gc_child() {
    let (Ok(command), Ok(top)) = (
        std::env::var("AUDIT5_GC_CHILD"),
        std::env::var("AUDIT5_GC_TOP"),
    ) else {
        return;
    };
    let top = Path::new(&top);
    let root = top.join("root");
    match command.as_str() {
        // `maki volume create`, as the daemon user.
        "create" => {
            let backing =
                RollbackBacking::create_remote(&root, rpc(top, Role::Writer), CAPACITY).unwrap();
            commit(&backing, b"created");
        }
        // `maki volume takeover`, as root with the administrator key.
        "takeover" => {
            let admin = rpc(top, Role::Admin);
            let before = inspect(admin.as_ref());
            drop(RollbackBacking::takeover_remote(&root, admin, &before).unwrap());
        }
        // A daemon start and clean stop, as the daemon user.
        "attach" => {
            let backing = RollbackBacking::open_remote(&root, rpc(top, Role::Writer)).unwrap();
            commit(&backing, b"attached");
        }
        // `maki volume gc`, as the daemon user.
        "gc" => {
            match RollbackBacking::collect_remote(&root, rpc(top, Role::Writer).as_ref()) {
                Ok(report) => println!("GC-OK removed={}", report.counts.removed),
                Err(error) => println!("GC-ERR {error}"),
            }
        }
        other => panic!("unknown command {other}"),
    }
}

fn child(top: &Path, command: &str, as_daemon: bool, kill_at_fchown: bool) -> std::process::Output {
    let exe = std::env::current_exe().unwrap();
    let mut invocation = if kill_at_fchown {
        let mut strace = Command::new("strace");
        strace.args([
            "-f",
            "-o",
            "/dev/null",
            "-e",
            "trace=fchown",
            "-e",
            "inject=fchown:signal=SIGKILL:when=1",
        ]);
        strace
    } else if as_daemon {
        let mut setpriv = Command::new("setpriv");
        setpriv.args([
            "--reuid",
            &NOBODY.to_string(),
            "--regid",
            &NOBODY.to_string(),
            "--clear-groups",
            "--",
        ]);
        setpriv
    } else {
        Command::new(&exe)
    };
    if kill_at_fchown || as_daemon {
        invocation.arg(&exe);
    }
    invocation
        .args(["audit5_gc_child", "--exact", "--nocapture", "--test-threads=1"])
        .env("AUDIT5_GC_CHILD", command)
        .env("AUDIT5_GC_TOP", top)
        .output()
        .expect("setpriv and strace are required")
}

fn must(top: &Path, command: &str, as_daemon: bool) -> String {
    let output = child(top, command, as_daemon, false);
    assert!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn namespaces(root: &Path) -> Vec<(String, u32)> {
    let mut names: Vec<(String, u32)> = std::fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name().to_string_lossy().contains("remote-0"))
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.metadata().unwrap().uid(),
            )
        })
        .collect();
    names.sort();
    names
}

fn fixture() -> Option<tempfile::TempDir> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root");
        return None;
    }
    let top = tempfile::tempdir().unwrap();
    std::fs::set_permissions(top.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    // The daemon user's backing root, as `install -d -o maki -g maki -m 0700`.
    let root = top.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::os::unix::fs::chown(&root, Some(NOBODY), Some(NOBODY)).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let authority = top.path().join("authority");
    std::fs::create_dir(&authority).unwrap();
    std::fs::set_permissions(&authority, std::fs::Permissions::from_mode(0o777)).unwrap();
    let state = authority.join("state");
    std::fs::write(
        &state,
        CanonicalState::initial(IDENTITY).unwrap().encode().unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o666)).unwrap();
    Some(top)
}

#[test]
fn control_gc_reclaims_every_predecessor_without_a_leftover() {
    let Some(top) = fixture() else { return };
    let root = top.path().join("root");
    must(top.path(), "create", true);
    must(top.path(), "takeover", false);
    for _ in 0..3 {
        must(top.path(), "attach", true);
    }
    assert_eq!(namespaces(&root).len(), 1, "{:?}", namespaces(&root));
    assert!(must(top.path(), "gc", true).contains("GC-OK"));
}

#[test]
fn gc_keeps_reclaiming_past_a_namespace_the_daemon_cannot_open() {
    let Some(top) = fixture() else { return };
    let root = top.path().join("root");
    must(top.path(), "create", true);
    // The administrator's root-run takeover dies between creating the new
    // namespace directory and giving it to the daemon user.
    let killed = child(top.path(), "takeover", false, true);
    assert!(!killed.status.success(), "the takeover must have been killed");
    let leftover: Vec<_> = namespaces(&root)
        .into_iter()
        .filter(|(_, uid)| *uid == 0)
        .collect();
    assert_eq!(leftover.len(), 1, "one root-owned directory is left: {leftover:?}");
    assert_eq!(
        std::fs::read_dir(root.join(&leftover[0].0)).unwrap().count(),
        0,
        "and it is empty"
    );
    // The administrator runs the takeover again; it completes.
    must(top.path(), "takeover", false);
    // The daemon starts and stops three times. Every start still succeeds.
    for _ in 0..3 {
        must(top.path(), "attach", true);
    }
    let gc = must(top.path(), "gc", true);
    let left = namespaces(&root);
    // The current namespace and the unopenable leftover may stay; every
    // other predecessor has a free lifetime lock and must be reclaimed.
    assert!(
        left.len() <= 2 && gc.contains("GC-OK"),
        "GC stopped at the root-owned leftover: `maki volume gc` as the daemon user says \
         {:?}, and {} namespaces remain (each a full arena): {left:#?}",
        gc.find("GC-")
            .map(|at| gc[at..].lines().next().unwrap_or(""))
            .unwrap_or(""),
        left.len()
    );
}

/// The same stop without root or a crash: any entry `gc_retire` cannot
/// examine for a reason other than "missing / symlink / not a directory"
/// ends the pass. Here a stale lower-fence namespace holds a directory named
/// like one of its files (EISDIR), which whoever can write the backing root
/// can create (the threat model of the non-UTF-8 name, AUD-078).
#[test]
fn gc_keeps_reclaiming_past_a_namespace_it_cannot_examine() {
    use std::sync::Mutex;
    struct Memory(Mutex<CanonicalState>, Role);
    impl Rpc for Memory {
        fn call(&self, request: &Request) -> io::Result<Record> {
            let mut state = self.0.lock().unwrap();
            let next = state.apply(self.1, request)?;
            *state = next;
            Ok(state.record().clone())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let writer: Arc<dyn Rpc> = Arc::new(Memory(
        Mutex::new(CanonicalState::initial(IDENTITY).unwrap()),
        Role::Writer,
    ));
    let backing = RollbackBacking::create_remote(&root, writer.clone(), CAPACITY).unwrap();
    commit(&backing, b"created");
    drop(backing);
    // Sorts before the real fence-1 namespace.
    let odd = root.join("remote-0000000000000001-00000000000000000000000000000001");
    std::fs::create_dir(&odd).unwrap();
    std::fs::write(odd.join("rollback.lock"), b"").unwrap();
    std::fs::create_dir(odd.join("rollback.arena")).unwrap();
    for _ in 0..3 {
        let backing = RollbackBacking::open_remote(&root, writer.clone()).unwrap();
        commit(&backing, b"attached");
    }
    let gc = RollbackBacking::collect_remote(&root, writer.as_ref());
    let left = namespaces(&root);
    assert!(
        gc.is_ok() && left.len() <= 2,
        "GC stopped at the entry it could not examine: {:?}; {} namespaces remain: {left:#?}",
        gc.err().map(|e| e.to_string()),
        left.len()
    );
}
