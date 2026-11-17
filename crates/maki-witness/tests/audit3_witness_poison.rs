//! Audit round 3 (witness-service): a publication failure that happens before
//! `remote.state` is touched (the temporary file's write or fdatasync, which
//! leave the durable state exactly as published) still poisons the served
//! authority for good. `maki-witness serve` neither reopens nor exits, so the
//! frontend answers every later request, Inspect included, "unavailable"
//! until an operator restarts it, although the storage is healthy again and
//! the state file never changed. This is the outage BUG-176 removed from the
//! read path ("EMFILE, ENOMEM, a transient EIO ... prove nothing").
use std::io;
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Request, Role, SessionAuthorization, StateStore};
use maki_backing::{Backing, BackingFile, FileBacking, VolumeLock};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    TempOpen,
    TempWrite,
    TempSync,
}

struct Faulty {
    inner: FileBacking,
    fault: Arc<Mutex<Option<Fault>>>,
}
struct FaultyFile {
    inner: Arc<dyn BackingFile>,
    fault: Arc<Mutex<Option<Fault>>>,
    temporary: bool,
}
fn fire(fault: &Mutex<Option<Fault>>, point: Fault, errno: i32) -> io::Result<()> {
    let mut slot = fault.lock().unwrap();
    if *slot == Some(point) {
        *slot = None;
        return Err(io::Error::from_raw_os_error(errno));
    }
    Ok(())
}
impl BackingFile for FaultyFile {
    fn read_at(&self, o: u64, b: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(o, b)
    }
    fn write_at(&self, o: u64, b: &[u8]) -> io::Result<()> {
        if self.temporary {
            fire(&self.fault, Fault::TempWrite, libc::ENOSPC)?;
        }
        self.inner.write_at(o, b)
    }
    fn set_len(&self, n: u64) -> io::Result<()> {
        self.inner.set_len(n)
    }
    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.temporary {
            fire(&self.fault, Fault::TempSync, libc::EIO)?;
        }
        self.inner.sync_data()
    }
}
impl Backing for Faulty {
    fn open(&self, p: &str, c: bool) -> io::Result<Arc<dyn BackingFile>> {
        if p == "remote.next" {
            fire(&self.fault, Fault::TempOpen, libc::EMFILE)?;
        }
        Ok(Arc::new(FaultyFile {
            inner: self.inner.open(p, c)?,
            fault: self.fault.clone(),
            temporary: p == "remote.next",
        }))
    }
    fn exists(&self, p: &str) -> io::Result<bool> {
        self.inner.exists(p)
    }
    fn remove(&self, p: &str) -> io::Result<()> {
        self.inner.remove(p)
    }
    fn rename(&self, a: &str, b: &str) -> io::Result<()> {
        self.inner.rename(a, b)
    }
    fn create_dir_all(&self, p: &str) -> io::Result<()> {
        self.inner.create_dir_all(p)
    }
    fn list(&self, p: &str) -> io::Result<Vec<String>> {
        self.inner.list(p)
    }
    fn sync_dir(&self, p: &str) -> io::Result<()> {
        self.inner.sync_dir(p)
    }
    fn try_lock(&self, p: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(p)
    }
}

fn inspect() -> Vec<u8> {
    serde_json::to_vec(&Request {
        authorization: None,
        operation_id: [9; 16],
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}

#[test]
fn pre_rename_publication_failure_poisons_the_served_authority_until_restart() {
    let mut poisoned = Vec::new();
    for point in [Fault::TempOpen, Fault::TempWrite, Fault::TempSync] {
        let dir = tempfile::tempdir().unwrap();
        drop(StateStore::create(dir.path(), [7; 16]).unwrap());
        let published = std::fs::read(dir.path().join("remote.state")).unwrap();
        let fault = Arc::new(Mutex::new(None));
        let store = StateStore::open_backing(Arc::new(Faulty {
            inner: FileBacking::new(dir.path()).unwrap(),
            fault: fault.clone(),
        }))
        .unwrap();
        // The handler `maki-witness serve` installs for a local state_dir.
        let handler = maki_witness::state_handler(store);
        let record: maki_backing::remote_witness::Record =
            serde_json::from_value(handler(Role::Writer, &inspect()).unwrap()).unwrap();
        let claim = serde_json::to_vec(&Request {
            authorization: Some(SessionAuthorization::from_bytes([5; 32])),
            operation_id: [1; 16],
            expected: Some(record),
            action: Action::Claim,
        })
        .unwrap();
        *fault.lock().unwrap() = Some(point);
        assert!(handler(Role::Writer, &claim).is_err(), "{point:?}");
        // One failure, now cleared; storage is healthy again.
        assert_eq!(*fault.lock().unwrap(), None);
        // The durable state was never touched: the failure preceded rename.
        assert_eq!(
            std::fs::read(dir.path().join("remote.state")).unwrap(),
            published,
            "{point:?}"
        );
        let mut outcomes = Vec::new();
        for _ in 0..3 {
            outcomes.push(handler(Role::Writer, &inspect()).map(|_| ()));
            outcomes.push(handler(Role::Writer, &claim).map(|_| ()));
        }
        let failed = outcomes.iter().filter(|r| r.is_err()).count();
        eprintln!(
            "{point:?}: {failed}/{} later requests failed; first error: {:?}",
            outcomes.len(),
            outcomes.iter().find_map(|r| r.as_ref().err().map(|e| (e.kind(), e.to_string())))
        );
        if failed != 0 {
            poisoned.push(point);
        }
    }
    assert!(
        poisoned.is_empty(),
        "{poisoned:?}: an unchanged, healthy authority keeps refusing every request \
         (wire `Unavailable`) until the process is restarted"
    );
}
