//! Audit round 3 (witness-service): `maki volume restore` only needs to read
//! its snapshot, yet every snapshot access goes through `FileBacking`, whose
//! files are always opened O_RDWR, plus a root operation lock created inside
//! the backup. A backup kept on read-only media (an `ro` mount, an immutable
//! or WORM copy, the natural way to keep an approved backup unchanged) can
//! therefore never be restored: the command fails with EROFS before it asks
//! the authority anything. The parent builds a protected volume and a
//! snapshot, then re-runs this binary in a private mount namespace (as root)
//! with the snapshot bind-mounted read-only.
#![cfg(target_os = "linux")]
use maki_backing::remote_witness::{Action, Descriptor, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

struct LocalRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}
impl Rpc for LocalRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
    }
}
fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}

fn restore(root: &Path, witness: &Path, snapshot: &Path, source: &Descriptor) -> io::Result<()> {
    let store = Arc::new(Mutex::new(StateStore::open(witness)?));
    let admin = Arc::new(LocalRpc {
        store,
        role: Role::Admin,
    });
    let expected = inspect(admin.as_ref());
    RollbackBacking::restore_remote(root, snapshot, source, admin, &expected).map(drop)
}

#[test]
fn child_restore_from_readonly_snapshot() {
    let Some(root) = std::env::var_os("AUDIT3_RO_ROOT") else {
        return;
    };
    let witness = std::env::var_os("AUDIT3_RO_WITNESS").unwrap();
    let snapshot = std::env::var_os("AUDIT3_RO_SNAPSHOT").unwrap();
    let source: Descriptor =
        serde_json::from_str(&std::env::var("AUDIT3_RO_SOURCE").unwrap()).unwrap();
    // Reading still works on the read-only mount.
    assert!(std::fs::read(Path::new(&snapshot).join("rollback.format")).is_ok());
    let outcome = restore(
        Path::new(&root),
        Path::new(&witness),
        Path::new(&snapshot),
        &source,
    );
    println!("AUDIT3-RESTORE-OUTCOME {outcome:?}");
}

#[test]
fn approved_snapshot_on_readonly_media_cannot_be_restored() {
    if std::env::var_os("AUDIT3_RO_ROOT").is_some() {
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: needs root for a private read-only bind mount");
        return;
    }
    let base = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = base.path().join("root");
    let witness = base.path().join("witness");
    let snapshot = base.path().join("snapshot");
    let copy = base.path().join("copy");
    std::fs::create_dir(&witness).unwrap();
    let source = {
        let store = Arc::new(Mutex::new(StateStore::create(&witness, [1; 16]).unwrap()));
        let writer = Arc::new(LocalRpc {
            store: store.clone(),
            role: Role::Writer,
        });
        let backing = RollbackBacking::create_remote(&root, writer.clone(), 32 * 4096).unwrap();
        let file = backing.open("payload", true).unwrap();
        file.write_at(0, b"snapshot").unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        let source = backing.snapshot_remote(&snapshot).unwrap();
        file.write_at(0, b"latest!!").unwrap();
        file.sync_data().unwrap();
        drop(file);
        drop(backing);
        source
    };
    let before = std::fs::read(witness.join("remote.state")).unwrap();
    let script = format!(
        "mount --bind '{s}' '{s}' && mount -o remount,bind,ro '{s}' && exec '{exe}' --exact child_restore_from_readonly_snapshot --nocapture --test-threads=1",
        s = snapshot.display(),
        exe = std::env::current_exe().unwrap().display()
    );
    let output = std::process::Command::new("unshare")
        .args(["-m", "--propagation", "private", "sh", "-c", &script])
        .env("AUDIT3_RO_ROOT", &root)
        .env("AUDIT3_RO_WITNESS", &witness)
        .env("AUDIT3_RO_SNAPSHOT", &snapshot)
        .env("AUDIT3_RO_SOURCE", serde_json::to_string(&source).unwrap())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find_map(|line| line.find("AUDIT3-RESTORE-OUTCOME").map(|at| &line[at..]))
        .unwrap_or_else(|| {
            panic!(
                "child did not run: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .to_owned();
    eprintln!("read-only snapshot: {line}");
    // Nothing changed at the authority: the refusal precedes the claim.
    assert_eq!(std::fs::read(witness.join("remote.state")).unwrap(), before);
    // Control: the same snapshot copied to writable storage restores.
    assert!(std::process::Command::new("cp")
        .arg("-a")
        .arg(&snapshot)
        .arg(&copy)
        .status()
        .unwrap()
        .success());
    let control = restore(&root, &witness, &copy, &source);
    eprintln!("writable copy: {control:?}");
    assert!(control.is_ok());
    assert!(
        line.contains("Ok(())"),
        "an approved snapshot on read-only media is refused: {line}"
    );
}
