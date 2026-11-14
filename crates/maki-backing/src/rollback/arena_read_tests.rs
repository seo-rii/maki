//! BUG-185: unavailable arena reads are not proof of changed evidence.

use super::*;
use crate::MemBacking;
use std::sync::atomic::{AtomicBool, Ordering};

struct ReadFault {
    skip: usize,
    error: io::Error,
}

struct FaultArena {
    inner: Arc<dyn BackingFile>,
    read_fault: Mutex<Option<ReadFault>>,
    fail_write: AtomicBool,
}

impl FaultArena {
    fn fail_read(&self, skip: usize, error: io::Error) {
        let mut fault = self.read_fault.lock();
        assert!(fault.is_none());
        *fault = Some(ReadFault { skip, error });
    }
}

impl BackingFile for FaultArena {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        let mut fault = self.read_fault.lock();
        if let Some(pending) = fault.as_mut() {
            if pending.skip == 0 {
                // A failed exact read may already have changed its scratch
                // buffer. Those unverified bytes must never become a page.
                bytes[0] = 0xee;
                return Err(fault.take().unwrap().error);
            }
            pending.skip -= 1;
        }
        drop(fault);
        self.inner.read_at(offset, bytes)
    }

    fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.fail_write.swap(false, Ordering::Relaxed) {
            self.inner.write_at(offset, &bytes[..1])?;
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        self.inner.write_at(offset, bytes)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn sync_data(&self) -> io::Result<()> {
        self.inner.sync_data()
    }
}

struct Fixture {
    disk: Arc<MemBacking>,
    witness: tempfile::TempDir,
    arena: Arc<FaultArena>,
}

impl Fixture {
    fn new() -> (Self, RollbackBacking) {
        // The arena is memory-only, so the witness needs no second filesystem.
        // Assemble the same local State used by public create/open, then use
        // ordinary Backing/BackingFile operations for every tested request.
        let disk = Arc::new(MemBacking::new());
        let witness = tempfile::tempdir().unwrap();
        let arena = Arc::new(FaultArena {
            inner: disk.open(ARENA, true).unwrap(),
            read_fault: Mutex::new(None),
            fail_write: AtomicBool::new(false),
        });
        let capacity = 3 * PAGE;
        reserve_storage(disk.as_ref(), arena.as_ref(), capacity).unwrap();
        disk.open(MARKER, true).unwrap().write_at(0, MAGIC).unwrap();
        let manifest = Manifest {
            format: 1,
            identity: [0x85; 16],
            generation: 0,
            capacity,
            next_id: 1,
            entries: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        let bytes = manifest.encode().unwrap();
        write_manifest(disk.as_ref(), 0, &bytes).unwrap();
        let authority = FileWitness::create(
            witness.path(),
            manifest.identity,
            digest(b"maki.rollback.manifest.v1\0", &bytes),
        )
        .unwrap();
        let lock = disk.try_lock("rollback.lock").unwrap();
        let backing = RollbackBacking::assemble_witness(
            disk.clone(),
            arena.clone(),
            Witness::Local(authority),
            lock,
            manifest,
            0,
        );
        let file = backing.open("data", true).unwrap();
        file.write_at(0, &[0x52; 2 * PAGE as usize]).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        (
            Self {
                disk,
                witness,
                arena,
            },
            backing,
        )
    }

    fn reopen(&self) -> RollbackBacking {
        RollbackBacking::open_backing(self.disk.clone(), self.witness.path()).unwrap()
    }

    fn anchor(&self) -> Vec<u8> {
        std::fs::read(self.witness.path().join("anchor")).unwrap()
    }
}

fn read(file: &dyn BackingFile) -> Vec<u8> {
    let mut bytes = vec![0; 2 * PAGE as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

fn first_page_offset(backing: &RollbackBacking) -> u64 {
    let state = backing.state.lock();
    let Entry::File(id) = &state.entries["data"] else {
        panic!("fixture data must be a file")
    };
    state.files[id].pages[&0].slot * PAGE
}

#[test]
fn transient_reads_preserve_errors_and_allow_existing_handles_to_retry() {
    for errno in [libc::EIO, libc::ETIMEDOUT, libc::ENOMEM] {
        let (fixture, backing) = Fixture::new();
        let file = backing.open("data", false).unwrap();
        let peer = backing.open("data", false).unwrap();
        let anchor = fixture.anchor();
        fixture
            .arena
            .fail_read(0, io::Error::from_raw_os_error(errno));
        let mut bytes = [0; 1];
        let error = file.read_at(0, &mut bytes).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno));
        assert_eq!(error.kind(), io::Error::from_raw_os_error(errno).kind());
        assert_eq!(bytes, [0], "unverified scratch bytes must not escape");
        assert!(fixture.arena.read_fault.lock().is_none());
        assert_eq!(fixture.anchor(), anchor);
        backing.check_freshness().unwrap();
        assert_eq!(read(file.as_ref()), vec![0x52; 2 * PAGE as usize]);
        assert_eq!(read(peer.as_ref()), vec![0x52; 2 * PAGE as usize]);

        peer.write_at(17, b"retry").unwrap();
        peer.sync_data().unwrap();
        drop((file, peer, backing));
        let reopened = fixture.reopen();
        let mut expected = vec![0x52; 2 * PAGE as usize];
        expected[17..22].copy_from_slice(b"retry");
        assert_eq!(
            read(reopened.open("data", false).unwrap().as_ref()),
            expected
        );
    }
}

#[test]
fn read_failure_after_a_write_prefix_can_be_retried_and_synced() {
    let (fixture, backing) = Fixture::new();
    let file = backing.open("data", false).unwrap();
    let anchor = fixture.anchor();
    fixture
        .arena
        .fail_read(1, io::Error::from_raw_os_error(libc::EIO));
    let offset = PAGE - 4;
    let payload = b"abcdefgh";
    assert_eq!(
        file.write_at(offset, payload).unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(fixture.anchor(), anchor, "no new pages were committed");
    backing.check_freshness().unwrap();
    let mut expected = vec![0x52; 2 * PAGE as usize];
    expected[offset as usize..PAGE as usize].copy_from_slice(&payload[..4]);
    assert_eq!(read(file.as_ref()), expected, "only the prefix was written");

    file.write_at(offset, payload).unwrap();
    file.sync_data().unwrap();
    drop((file, backing));
    let reopened = fixture.reopen();
    expected[offset as usize..offset as usize + payload.len()].copy_from_slice(payload);
    assert_eq!(
        read(reopened.open("data", false).unwrap().as_ref()),
        expected
    );
}

#[test]
fn retry_authenticates_pages_and_damage_stops_all_handles_after_restoration() {
    for truncate in [false, true] {
        let (fixture, backing) = Fixture::new();
        let file = backing.open("data", false).unwrap();
        let peer = backing.open("data", false).unwrap();
        let anchor = fixture.anchor();
        fixture
            .arena
            .fail_read(0, io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(
            file.read_at(0, &mut [0; 1]).unwrap_err().raw_os_error(),
            Some(libc::EIO)
        );
        backing.check_freshness().unwrap();

        let arena = &fixture.arena.inner;
        let mut original = vec![0; arena.len().unwrap() as usize];
        arena.read_at(0, &mut original).unwrap();
        let page = first_page_offset(&backing);
        if truncate {
            arena.set_len(page + PAGE - 1).unwrap();
        } else {
            arena.write_at(page, &[0x99]).unwrap();
        }
        let error = peer.read_at(0, &mut [0; 1]).unwrap_err();
        assert_eq!(
            error.kind(),
            if truncate {
                io::ErrorKind::UnexpectedEof
            } else {
                io::ErrorKind::InvalidData
            }
        );
        arena.set_len(original.len() as u64).unwrap();
        arena.write_at(0, &original).unwrap();
        assert_eq!(fixture.anchor(), anchor);
        assert!(file.read_at(0, &mut [0; 1]).is_err());
        assert!(peer.write_at(0, b"refused").is_err());
        assert!(peer.sync_data().is_err());
        assert!(backing.check_freshness().is_err());
    }
}

#[test]
fn missing_or_invalid_page_errors_still_stop_the_session() {
    for kind in [io::ErrorKind::NotFound, io::ErrorKind::InvalidData] {
        let (fixture, backing) = Fixture::new();
        let file = backing.open("data", false).unwrap();
        fixture
            .arena
            .fail_read(0, io::Error::new(kind, "invalid referenced page"));
        assert_eq!(file.read_at(0, &mut [0; 1]).unwrap_err().kind(), kind);
        assert!(fixture.arena.read_fault.lock().is_none());
        assert!(file.read_at(0, &mut [0; 1]).is_err());
        assert!(backing.check_freshness().is_err());
    }
}

#[test]
fn partial_arena_write_failure_still_requires_reopen() {
    let (fixture, backing) = Fixture::new();
    let file = backing.open("data", false).unwrap();
    let anchor = fixture.anchor();
    fixture.arena.fail_write.store(true, Ordering::Relaxed);
    assert_eq!(
        file.write_at(0, b"uncertain").unwrap_err().raw_os_error(),
        Some(libc::EIO)
    );
    assert!(!fixture.arena.fail_write.load(Ordering::Relaxed));
    assert_eq!(fixture.anchor(), anchor);
    assert!(file.read_at(0, &mut [0; 1]).is_err());
    assert!(file.sync_data().is_err());
    assert!(backing.check_freshness().is_err());
    drop((file, backing));
    let reopened = fixture.reopen();
    assert_eq!(
        read(reopened.open("data", false).unwrap().as_ref()),
        vec![0x52; 2 * PAGE as usize]
    );
}
