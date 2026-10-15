use super::*;
use crate::{MemBacking, VolumeLock};

#[derive(Clone, Copy)]
enum Stage {
    Open,
    Read,
    Len,
}
struct FailingFile {
    inner: Arc<dyn BackingFile>,
    stage: Stage,
    kind: io::ErrorKind,
}
impl BackingFile for FailingFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        if matches!(self.stage, Stage::Read) {
            return Err(self.kind.into());
        }
        self.inner.read_at(offset, bytes)
    }
    fn len(&self) -> io::Result<u64> {
        if matches!(self.stage, Stage::Len) {
            return Err(self.kind.into());
        }
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
    inner: MemBacking,
    path: &'static str,
    stage: Stage,
    kind: io::ErrorKind,
}
impl Backing for FaultDisk {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        if path != self.path {
            return self.inner.open(path, create);
        }
        if matches!(self.stage, Stage::Open) {
            return Err(self.kind.into());
        }
        Ok(Arc::new(FailingFile {
            inner: self.inner.open(path, create)?,
            stage: self.stage,
            kind: self.kind,
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
fn fixture() -> (MemBacking, Descriptor) {
    let disk = MemBacking::new();
    let manifest = Manifest {
        format: 1,
        identity: [1; 16],
        generation: 7,
        capacity: PAGE,
        next_id: 1,
        entries: BTreeMap::new(),
        files: BTreeMap::new(),
    };
    let bytes = manifest.encode().unwrap();
    let arena = disk.open(ARENA, true).unwrap();
    reserve_storage(&disk, arena.as_ref(), PAGE).unwrap();
    write_manifest(&disk, 0, &bytes).unwrap();
    write_manifest(&disk, 1, &bytes).unwrap();
    let descriptor = Descriptor {
        anchor: Anchor {
            identity: manifest.identity,
            generation: 7,
            root: digest(b"maki.rollback.manifest.v1\0", &bytes),
        },
        epoch: 1,
        namespace: "fixture".into(),
    };
    (disk, descriptor)
}
fn error_kind(disk: &dyn Backing, descriptor: &Descriptor) -> io::ErrorKind {
    match load_generation(disk, descriptor) {
        Ok(_) => panic!("unexpected success"),
        Err(error) => error.kind(),
    }
}
#[test]
fn io_failure_is_preserved_when_the_other_manifest_is_missing_or_corrupt() {
    for stage in [Stage::Open, Stage::Read, Stage::Len] {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::TimedOut,
            io::ErrorKind::Other,
        ] {
            for missing in [true, false] {
                let (disk, descriptor) = fixture();
                if missing {
                    disk.remove(MANIFESTS[1]).unwrap();
                } else {
                    disk.open(MANIFESTS[1], false)
                        .unwrap()
                        .write_at(0, &[0; 8])
                        .unwrap();
                }
                let disk = FaultDisk {
                    inner: disk,
                    path: MANIFESTS[0],
                    stage,
                    kind,
                };
                assert_eq!(error_kind(&disk, &descriptor), kind);
            }
        }
    }
}
#[test]
fn a_verified_redundant_copy_still_recovers_from_an_io_failure() {
    for stage in [Stage::Open, Stage::Read, Stage::Len] {
        let (disk, descriptor) = fixture();
        let disk = FaultDisk {
            inner: disk,
            path: MANIFESTS[0],
            stage,
            kind: io::ErrorKind::Other,
        };
        assert!(load_generation(&disk, &descriptor).is_ok());
    }
}
#[test]
fn arena_io_failure_is_not_corruption() {
    let (disk, descriptor) = fixture();
    let disk = FaultDisk {
        inner: disk,
        path: ARENA,
        stage: Stage::Len,
        kind: io::ErrorKind::TimedOut,
    };
    assert_eq!(error_kind(&disk, &descriptor), io::ErrorKind::TimedOut);
}
#[test]
fn missing_truncated_and_invalid_manifests_are_still_invalid_data() {
    for length in [0, 4, 8] {
        let (disk, descriptor) = fixture();
        disk.remove(MANIFESTS[0]).unwrap();
        let file = disk.open(MANIFESTS[1], false).unwrap();
        file.set_len(length).unwrap();
        if length == 8 {
            file.write_at(0, &[0; 8]).unwrap();
        }
        assert_eq!(error_kind(&disk, &descriptor), io::ErrorKind::InvalidData);
    }
    let (disk, mut descriptor) = fixture();
    let bytes = b"{invalid-json}";
    descriptor.anchor.root = digest(b"maki.rollback.manifest.v1\0", bytes);
    for side in 0..2 {
        write_manifest(&disk, side, bytes).unwrap();
    }
    assert_eq!(error_kind(&disk, &descriptor), io::ErrorKind::InvalidData);
}
