//! BUG-132: an unreadable local manifest is not proof of rollback.

use super::*;
use crate::MemBacking;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Open,
    Header,
    Body,
    Len,
}

struct Fault {
    path: &'static str,
    stage: Stage,
    errno: i32,
}

type PendingFault = Arc<Mutex<Option<Fault>>>;

fn fail_once(fault: &PendingFault, path: &str, stage: Stage) -> io::Result<()> {
    let mut fault = fault.lock();
    if fault
        .as_ref()
        .is_some_and(|fault| fault.path == path && fault.stage == stage)
    {
        return Err(io::Error::from_raw_os_error(fault.take().unwrap().errno));
    }
    Ok(())
}

struct FaultFile {
    inner: Arc<dyn BackingFile>,
    path: &'static str,
    fault: PendingFault,
}

impl BackingFile for FaultFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        fail_once(
            &self.fault,
            self.path,
            if offset == 0 {
                Stage::Header
            } else {
                Stage::Body
            },
        )?;
        self.inner.read_at(offset, bytes)
    }
    fn len(&self) -> io::Result<u64> {
        fail_once(&self.fault, self.path, Stage::Len)?;
        self.inner.len()
    }
    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.inner.write_at(offset, bytes)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

struct FaultDisk {
    inner: Arc<MemBacking>,
    fault: PendingFault,
}

impl Backing for FaultDisk {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        let Some(name) = MANIFESTS.iter().find(|name| **name == path) else {
            return self.inner.open(path, create);
        };
        fail_once(&self.fault, path, Stage::Open)?;
        Ok(Arc::new(FaultFile {
            inner: self.inner.open(path, create)?,
            path: name,
            fault: self.fault.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }
    fn remove(&self, path: &str) -> io::Result<()> {
        self.inner.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        self.inner.list(path)
    }
    fn sync_dir(&self, path: &str) -> io::Result<()> {
        self.inner.sync_dir(path)
    }
    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }
}

struct Fixture {
    disk: Arc<MemBacking>,
    witness: tempfile::TempDir,
    manifest: Manifest,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        // The injected backing is memory-only; the witness uses ordinary
        // temporary files and needs no second filesystem or root privilege.
        let disk = Arc::new(MemBacking::new());
        let witness = tempfile::tempdir().unwrap();
        let arena = disk.open(ARENA, true).unwrap();
        reserve_storage(disk.as_ref(), arena.as_ref(), PAGE).unwrap();
        let marker = disk.open(MARKER, true).unwrap();
        marker.write_at(0, MAGIC).unwrap();
        let payload = [0x53; PAGE as usize];
        arena.write_at(0, &payload).unwrap();
        let manifest = Manifest {
            format: 1,
            identity: [17; 16],
            generation: 0,
            capacity: PAGE,
            next_id: 2,
            entries: BTreeMap::from([("data".into(), Entry::File(1))]),
            files: BTreeMap::from([(
                1,
                Node {
                    len: PAGE,
                    pages: BTreeMap::from([(
                        0,
                        PageRef {
                            slot: 0,
                            hash: page_digest(&[17; 16], &payload),
                        },
                    )]),
                    reserved: BTreeSet::from([0]),
                },
            )]),
        };
        let bytes = manifest.encode().unwrap();
        for slot in 0..2 {
            write_manifest(disk.as_ref(), slot, &bytes).unwrap();
        }
        drop(
            FileWitness::create(
                witness.path(),
                manifest.identity,
                digest(b"maki.rollback.manifest.v1\0", &bytes),
            )
            .unwrap(),
        );
        Self {
            disk,
            witness,
            manifest,
            bytes,
        }
    }

    fn fail(&self, slot: usize, stage: Stage, errno: i32) -> Arc<FaultDisk> {
        Arc::new(FaultDisk {
            inner: self.disk.clone(),
            fault: Arc::new(Mutex::new(Some(Fault {
                path: MANIFESTS[slot],
                stage,
                errno,
            }))),
        })
    }

    fn error(&self, disk: Arc<dyn Backing>) -> io::Error {
        match RollbackBacking::open_backing(disk, self.witness.path()) {
            Ok(_) => panic!("unreadable or invalid selected manifest must refuse open"),
            Err(error) => error,
        }
    }

    fn assert_payload(backing: &RollbackBacking) {
        let mut bytes = [0; PAGE as usize];
        backing
            .open("data", false)
            .unwrap()
            .read_at(0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0x53; PAGE as usize]);
    }
}

#[test]
fn transient_manifest_io_preserves_errno_and_retry_data() {
    for selected in 0..2 {
        for stage in [Stage::Open, Stage::Header, Stage::Body, Stage::Len] {
            for errno in [libc::EACCES, libc::EIO, libc::EMFILE, libc::ETIMEDOUT] {
                for missing in [true, false] {
                    let fixture = Fixture::new();
                    let other = MANIFESTS[1 - selected];
                    if missing {
                        fixture.disk.remove(other).unwrap();
                    } else {
                        fixture
                            .disk
                            .open(other, false)
                            .unwrap()
                            .write_at(0, &[0; 8])
                            .unwrap();
                    }
                    let anchor = std::fs::read(fixture.witness.path().join("anchor")).unwrap();
                    let fault = fixture.fail(selected, stage, errno);
                    assert_eq!(fixture.error(fault.clone()).raw_os_error(), Some(errno));
                    assert!(
                        fault.fault.lock().is_none(),
                        "must reach the selected I/O boundary"
                    );
                    assert_eq!(
                        std::fs::read(fixture.witness.path().join("anchor")).unwrap(),
                        anchor,
                        "a read failure cannot change the independent anchor"
                    );
                    let mut bytes = vec![0; fixture.bytes.len()];
                    fixture
                        .disk
                        .open(MANIFESTS[selected], false)
                        .unwrap()
                        .read_at(8, &mut bytes)
                        .unwrap();
                    assert_eq!(bytes, fixture.bytes);
                    // The failed open released both locks. Once the I/O fault
                    // clears, the same persisted evidence must be usable.
                    let recovered =
                        RollbackBacking::open_backing(fault, fixture.witness.path()).unwrap();
                    Fixture::assert_payload(&recovered);
                }
            }
        }
    }
}

#[test]
fn a_verified_redundant_manifest_survives_an_io_failure() {
    for stage in [Stage::Open, Stage::Header, Stage::Body, Stage::Len] {
        let fixture = Fixture::new();
        let fault = fixture.fail(0, stage, libc::EIO);
        let recovered =
            RollbackBacking::open_backing(fault.clone(), fixture.witness.path()).unwrap();
        assert!(fault.fault.lock().is_none());
        assert_eq!(recovered.state.lock().manifest_slot, 1);
        Fixture::assert_payload(&recovered);
    }
}

#[test]
fn absent_truncated_and_wrong_root_manifests_remain_invalid_data() {
    for damage in ["missing", "header", "body", "length", "root"] {
        let fixture = Fixture::new();
        fixture.disk.remove(MANIFESTS[0]).unwrap();
        let file = fixture.disk.open(MANIFESTS[1], false).unwrap();
        match damage {
            "missing" => fixture.disk.remove(MANIFESTS[1]).unwrap(),
            "header" => file.set_len(4).unwrap(),
            "body" => file.set_len(8).unwrap(),
            "length" => file.write_at(0, &[0; 8]).unwrap(),
            "root" => file.write_at(8, b"wrong").unwrap(),
            _ => unreachable!(),
        }
        assert_eq!(
            fixture.error(fixture.disk.clone()).kind(),
            io::ErrorKind::InvalidData,
            "{damage}"
        );
    }
}

#[test]
fn authenticated_invalid_manifest_contents_are_not_storage_errors() {
    for damage in ["json", "capacity", "namespace", "canonical"] {
        let mut fixture = Fixture::new();
        fixture.manifest.generation = 1;
        let bytes = match damage {
            "json" => b"{invalid-json}".to_vec(),
            "capacity" => {
                fixture.manifest.capacity = 0;
                fixture.manifest.encode().unwrap()
            }
            "namespace" => {
                fixture
                    .manifest
                    .entries
                    .insert("../outside".into(), Entry::Directory);
                fixture.manifest.encode().unwrap()
            }
            "canonical" => {
                let mut bytes = fixture.manifest.encode().unwrap();
                bytes.push(b' ');
                bytes
            }
            _ => unreachable!(),
        };
        for slot in 0..2 {
            write_manifest(fixture.disk.as_ref(), slot, &bytes).unwrap();
        }
        let mut witness = FileWitness::open(fixture.witness.path()).unwrap();
        witness
            .advance(digest(b"maki.rollback.manifest.v1\0", &bytes))
            .unwrap();
        drop(witness);
        assert_eq!(
            fixture.error(fixture.disk.clone()).kind(),
            io::ErrorKind::InvalidData,
            "{damage}"
        );
    }
}
