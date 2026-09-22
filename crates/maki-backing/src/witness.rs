//! A small trusted local witness, stored outside the backing it protects.
//!
//! This detects a backing snapshot that is older than the independently
//! managed witness directory. It does not protect against rollback or
//! tampering of the whole host, including this directory.

use std::cell::Cell;
use std::fmt;
use std::io;
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::{Backing, FileBacking, VolumeLock};

const MAGIC: &[u8; 8] = b"MAKIWIT1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"maki-file-witness-anchor-v1\0";
const BODY_LEN: usize = 72;
const ENCODED_LEN: usize = BODY_LEN + 32;
const MAX_GENERATION: u64 = i64::MAX as u64;
const ANCHOR_FILE: &str = "anchor";
const TEMP_FILE: &str = "anchor.next";
const LOCK_FILE: &str = "witness.lock";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    pub identity: [u8; 16],
    pub generation: u64,
    pub root: [u8; 32],
}

pub struct FileWitness {
    backing: Arc<dyn Backing>,
    anchor: Anchor,
    poisoned: Cell<bool>,
    _lock: Box<dyn VolumeLock>,
}

impl fmt::Debug for FileWitness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileWitness")
            .field("anchor", &self.anchor)
            .field("poisoned", &self.poisoned.get())
            .finish_non_exhaustive()
    }
}

impl FileWitness {
    pub fn create(path: &Path, identity: [u8; 16], root: [u8; 32]) -> io::Result<Self> {
        validate_identity(&identity)?;
        let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(path)?);
        let lock = backing.try_lock(LOCK_FILE)?;
        if backing.exists(ANCHOR_FILE)? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "witness anchor already exists",
            ));
        }

        let anchor = Anchor {
            identity,
            generation: 0,
            root,
        };
        // FileBacking's confined rename replaces an existing target. Install
        // an empty target only after the locked non-existence check; a crash
        // here leaves invalid enrollment rather than a silently usable anchor.
        let target = backing.open(ANCHOR_FILE, true)?;
        target.set_len(0)?;
        target.sync_data()?;
        publish_anchor(backing.as_ref(), &anchor)?;

        Ok(Self {
            backing,
            anchor,
            poisoned: Cell::new(false),
            _lock: lock,
        })
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "witness path is not a directory",
                ));
            }
            Err(error) => return Err(error),
        }
        let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(path)?);
        Self::open_backing(backing)
    }

    fn open_backing(backing: Arc<dyn Backing>) -> io::Result<Self> {
        let lock = backing.try_lock(LOCK_FILE)?;
        let anchor = read_anchor(backing.as_ref())?;
        // A prior process may have observed rename success and directory-sync
        // failure. Re-publish the exact validated record before returning so
        // callers never reclaim data based only on page-cache-visible state.
        publish_anchor(backing.as_ref(), &anchor)?;
        Ok(Self {
            backing,
            anchor,
            poisoned: Cell::new(false),
            _lock: lock,
        })
    }

    pub fn anchor(&self) -> &Anchor {
        &self.anchor
    }

    pub fn verify_current(&self) -> io::Result<()> {
        self.ensure_usable()?;
        let result = read_anchor(self.backing.as_ref()).and_then(|current| {
            if current == self.anchor {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "witness anchor changed while locked",
                ))
            }
        });
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    pub fn advance(&mut self, root: [u8; 32]) -> io::Result<()> {
        self.ensure_usable()?;
        self.verify_current()?;
        let generation = self
            .anchor
            .generation
            .checked_add(1)
            .filter(|generation| *generation <= MAX_GENERATION)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "witness generation exhausted")
            })?;
        let next = Anchor {
            identity: self.anchor.identity,
            generation,
            root,
        };

        let result = publish_anchor(self.backing.as_ref(), &next);
        if let Err(error) = result {
            // A failed write, sync, rename, or directory sync can leave either
            // record durable. Reopening is required to resolve that outcome.
            self.poisoned.set(true);
            return Err(error);
        }
        self.anchor = next;
        Ok(())
    }

    fn ensure_usable(&self) -> io::Result<()> {
        if self.poisoned.get() {
            Err(io::Error::other(
                "witness state is uncertain; reopen it before continuing",
            ))
        } else {
            Ok(())
        }
    }
}

fn write_temporary(backing: &dyn Backing, bytes: &[u8; ENCODED_LEN]) -> io::Result<()> {
    let file = backing.open(TEMP_FILE, true)?;
    file.set_len(0)?;
    file.write_at(0, bytes)?;
    file.set_len(ENCODED_LEN as u64)?;
    file.sync_data()
}

fn publish_anchor(backing: &dyn Backing, anchor: &Anchor) -> io::Result<()> {
    write_temporary(backing, &encode(anchor))?;
    backing.rename(TEMP_FILE, ANCHOR_FILE)?;
    backing.sync_dir("")
}

fn read_anchor(backing: &dyn Backing) -> io::Result<Anchor> {
    let file = backing.open(ANCHOR_FILE, false)?;
    if file.len()? != ENCODED_LEN as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid witness anchor length",
        ));
    }
    let mut bytes = [0; ENCODED_LEN];
    file.read_at(0, &mut bytes)?;
    decode(&bytes)
}

fn encode(anchor: &Anchor) -> [u8; ENCODED_LEN] {
    let mut bytes = [0; ENCODED_LEN];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[16..32].copy_from_slice(&anchor.identity);
    bytes[32..40].copy_from_slice(&anchor.generation.to_le_bytes());
    bytes[40..BODY_LEN].copy_from_slice(&anchor.root);
    let checksum = checksum(&bytes[..BODY_LEN]);
    bytes[BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn decode(bytes: &[u8; ENCODED_LEN]) -> io::Result<Anchor> {
    if &bytes[..8] != MAGIC || bytes[8..10] != VERSION.to_le_bytes() || bytes[10..16] != [0; 6] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported witness anchor format",
        ));
    }
    let expected = checksum(&bytes[..BODY_LEN]);
    if bytes[BODY_LEN..] != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "witness anchor checksum mismatch",
        ));
    }

    let identity = bytes[16..32].try_into().expect("fixed identity slice");
    if identity == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "witness identity must not be nil",
        ));
    }
    let generation = u64::from_le_bytes(bytes[32..40].try_into().expect("fixed generation slice"));
    if generation > MAX_GENERATION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "witness generation exceeds supported range",
        ));
    }
    Ok(Anchor {
        identity,
        generation,
        root: bytes[40..BODY_LEN].try_into().expect("fixed root slice"),
    })
}

fn validate_identity(identity: &[u8; 16]) -> io::Result<()> {
    if *identity == [0; 16] {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "witness identity must not be nil",
        ))
    } else {
        Ok(())
    }
}

fn checksum(body: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(body);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::sync::{Arc, Mutex};

    use tempfile::tempdir;

    use super::{Anchor, FileWitness, ENCODED_LEN};
    use crate::{Backing, BackingFile, FileBacking, VolumeLock};

    const IDENTITY: [u8; 16] = *b"volume-identity!";
    const ROOT_A: [u8; 32] = [0x11; 32];
    const ROOT_B: [u8; 32] = [0x22; 32];

    #[test]
    fn create_round_trips_and_refuses_overwrite() {
        let dir = tempdir().unwrap();
        let witness = FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap();
        assert_eq!(
            witness.anchor(),
            &Anchor {
                identity: IDENTITY,
                generation: 0,
                root: ROOT_A,
            }
        );
        drop(witness);

        let reopened = FileWitness::open(dir.path()).unwrap();
        assert_eq!(reopened.anchor().root, ROOT_A);
        drop(reopened);
        assert_eq!(
            FileWitness::create(dir.path(), IDENTITY, ROOT_B)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
    }

    #[test]
    fn open_rejects_missing_truncated_and_bad_checksum_records() {
        let missing = tempdir().unwrap();
        assert_eq!(
            FileWitness::open(missing.path()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );

        let truncated = tempdir().unwrap();
        fs::write(truncated.path().join("anchor"), [0u8; ENCODED_LEN - 1]).unwrap();
        assert_eq!(
            FileWitness::open(truncated.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let corrupted = tempdir().unwrap();
        let witness = FileWitness::create(corrupted.path(), IDENTITY, ROOT_A).unwrap();
        drop(witness);
        let anchor_path = corrupted.path().join("anchor");
        let mut bytes = fs::read(&anchor_path).unwrap();
        bytes[40] ^= 1;
        fs::write(anchor_path, bytes).unwrap();
        assert_eq!(
            FileWitness::open(corrupted.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn open_does_not_create_a_missing_witness_directory() {
        let parent = tempdir().unwrap();
        let missing = parent.path().join("not-enrolled");
        assert_eq!(
            FileWitness::open(&missing).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(!missing.exists());
    }

    #[test]
    fn lifetime_lock_excludes_a_second_writer() {
        let dir = tempdir().unwrap();
        let witness = FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap();
        assert_eq!(
            FileWitness::open(dir.path()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        drop(witness);
        FileWitness::open(dir.path()).unwrap();
    }

    #[test]
    fn advance_is_monotonic_and_persistent() {
        let dir = tempdir().unwrap();
        let mut witness = FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap();
        witness.advance(ROOT_B).unwrap();
        assert_eq!(witness.anchor().generation, 1);
        assert_eq!(witness.anchor().root, ROOT_B);
        witness.verify_current().unwrap();
        drop(witness);

        let reopened = FileWitness::open(dir.path()).unwrap();
        assert_eq!(reopened.anchor().generation, 1);
        assert_eq!(reopened.anchor().root, ROOT_B);
    }

    #[test]
    fn advance_rejects_an_externally_changed_anchor() {
        let dir = tempdir().unwrap();
        let mut witness = FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap();
        let anchor_path = dir.path().join("anchor");
        fs::write(
            anchor_path,
            super::encode(&Anchor {
                identity: IDENTITY,
                generation: 1,
                root: ROOT_B,
            }),
        )
        .unwrap();

        assert_eq!(
            witness.advance(ROOT_B).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(witness.anchor().generation, 0);
    }

    #[test]
    fn detected_external_change_poisons_even_if_old_anchor_is_restored() {
        let dir = tempdir().unwrap();
        let witness = FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap();
        let original = fs::read(dir.path().join("anchor")).unwrap();
        fs::write(
            dir.path().join("anchor"),
            super::encode(&Anchor {
                identity: IDENTITY,
                generation: 1,
                root: ROOT_B,
            }),
        )
        .unwrap();
        assert_eq!(
            witness.verify_current().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        fs::write(dir.path().join("anchor"), original).unwrap();
        assert!(witness.verify_current().is_err());
    }

    #[test]
    fn advance_faults_poison_and_reopen_resolves_an_exact_record() {
        for fail_at in [
            FailAt::TempWrite,
            FailAt::TempSync,
            FailAt::Rename,
            FailAt::DirectorySync,
        ] {
            let dir = tempdir().unwrap();
            drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
            let fault = Arc::new(FaultBacking::new(dir.path()).expect("create fault backing"));
            let backing: Arc<dyn Backing> = fault.clone();
            let mut witness = FileWitness::open_backing(backing).unwrap();
            fault.arm(fail_at);

            assert!(witness.advance(ROOT_B).is_err(), "fault {fail_at:?}");
            assert!(
                witness.verify_current().is_err(),
                "fault {fail_at:?} must poison the handle"
            );
            drop(witness);

            let reopened = FileWitness::open(dir.path()).unwrap();
            let old = Anchor {
                identity: IDENTITY,
                generation: 0,
                root: ROOT_A,
            };
            let new = Anchor {
                identity: IDENTITY,
                generation: 1,
                root: ROOT_B,
            };
            assert!(
                reopened.anchor() == &old || reopened.anchor() == &new,
                "fault {fail_at:?} left a torn record"
            );
        }
    }

    #[test]
    fn open_refuses_every_republish_durability_failure() {
        for fail_at in [
            FailAt::TempWrite,
            FailAt::TempSync,
            FailAt::Rename,
            FailAt::DirectorySync,
        ] {
            let dir = tempdir().unwrap();
            drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
            let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
            fault.arm(fail_at);
            let backing: Arc<dyn Backing> = fault;
            assert!(
                FileWitness::open_backing(backing).is_err(),
                "open returned before surviving {fail_at:?}"
            );
        }
    }

    #[test]
    fn open_republishes_the_selected_anchor_before_returning() {
        let dir = tempdir().unwrap();
        drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
        let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
        let backing: Arc<dyn Backing> = fault.clone();

        let reopened = FileWitness::open_backing(backing).unwrap();
        assert_eq!(reopened.anchor().generation, 0);
        assert_eq!(reopened.anchor().root, ROOT_A);
        assert_eq!(
            fault.trace(),
            ["temp_write", "temp_sync", "rename", "directory_sync"]
        );
    }

    #[test]
    fn encoding_has_a_fixed_vector() {
        let anchor = Anchor {
            identity: [0x01; 16],
            generation: 0x0102_0304_0506_0708,
            root: [0x02; 32],
        };
        assert_eq!(
            hex(&super::encode(&anchor)),
            "4d414b495749543101000000000000000101010101010101010101010101010108070605040302010202020202020202020202020202020202020202020202020202020202020202edf667782ddfb50401148fac4a0714b36c457e25c438451d7d01a4bb1a4b75fa"
        );
    }

    #[test]
    fn decoding_rejects_unknown_format_nil_identity_and_excess_generation() {
        let anchor = Anchor {
            identity: IDENTITY,
            generation: 7,
            root: ROOT_A,
        };

        let mut unknown_version = super::encode(&anchor);
        unknown_version[8..10].copy_from_slice(&2u16.to_le_bytes());
        resign(&mut unknown_version);
        assert_eq!(
            super::decode(&unknown_version).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut nil_identity = super::encode(&anchor);
        nil_identity[16..32].fill(0);
        resign(&mut nil_identity);
        assert_eq!(
            super::decode(&nil_identity).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut excessive_generation = super::encode(&anchor);
        excessive_generation[32..40].copy_from_slice(&(super::MAX_GENERATION + 1).to_le_bytes());
        resign(&mut excessive_generation);
        assert_eq!(
            super::decode(&excessive_generation).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn resign(bytes: &mut [u8; ENCODED_LEN]) {
        let checksum = super::checksum(&bytes[..super::BODY_LEN]);
        bytes[super::BODY_LEN..].copy_from_slice(&checksum);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailAt {
        TempWrite,
        TempSync,
        Rename,
        DirectorySync,
    }

    struct FaultBacking {
        inner: FileBacking,
        pending: Arc<Mutex<Option<FailAt>>>,
        trace: Arc<Mutex<Vec<&'static str>>>,
    }

    impl FaultBacking {
        fn new(path: &std::path::Path) -> io::Result<Self> {
            Ok(Self {
                inner: FileBacking::new(path)?,
                pending: Arc::new(Mutex::new(None)),
                trace: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn arm(&self, fail_at: FailAt) {
            *self.pending.lock().unwrap() = Some(fail_at);
        }

        fn trace(&self) -> Vec<&'static str> {
            self.trace.lock().unwrap().clone()
        }

        fn fail(&self, at: FailAt) -> io::Result<()> {
            let mut pending = self.pending.lock().unwrap();
            if *pending == Some(at) {
                *pending = None;
                Err(io::Error::other(format!("injected {at:?} failure")))
            } else {
                Ok(())
            }
        }
    }

    struct FaultFile {
        inner: Arc<dyn BackingFile>,
        pending: Arc<Mutex<Option<FailAt>>>,
        trace: Arc<Mutex<Vec<&'static str>>>,
        temporary: bool,
    }

    impl BackingFile for FaultFile {
        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
            self.inner.read_at(offset, buffer)
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
            if self.temporary {
                self.trace.lock().unwrap().push("temp_write");
                let mut pending = self.pending.lock().unwrap();
                if *pending == Some(FailAt::TempWrite) {
                    *pending = None;
                    return Err(io::Error::other("injected temporary write failure"));
                }
            }
            self.inner.write_at(offset, data)
        }

        fn set_len(&self, len: u64) -> io::Result<()> {
            self.inner.set_len(len)
        }

        fn allocate_range(&self, offset: u64, len: u64) -> io::Result<()> {
            self.inner.allocate_range(offset, len)
        }

        fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
            self.inner.punch_hole(offset, len)
        }

        fn len(&self) -> io::Result<u64> {
            self.inner.len()
        }

        fn sync_data(&self) -> io::Result<()> {
            if self.temporary {
                self.trace.lock().unwrap().push("temp_sync");
                let mut pending = self.pending.lock().unwrap();
                if *pending == Some(FailAt::TempSync) {
                    *pending = None;
                    return Err(io::Error::other("injected temporary sync failure"));
                }
            }
            self.inner.sync_data()
        }
    }

    impl Backing for FaultBacking {
        fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
            Ok(Arc::new(FaultFile {
                inner: self.inner.open(path, create)?,
                pending: Arc::clone(&self.pending),
                trace: Arc::clone(&self.trace),
                temporary: path == super::TEMP_FILE,
            }))
        }

        fn exists(&self, path: &str) -> io::Result<bool> {
            self.inner.exists(path)
        }

        fn remove(&self, path: &str) -> io::Result<()> {
            self.inner.remove(path)
        }

        fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            self.trace.lock().unwrap().push("rename");
            self.fail(FailAt::Rename)?;
            self.inner.rename(from, to)
        }

        fn create_dir_all(&self, path: &str) -> io::Result<()> {
            self.inner.create_dir_all(path)
        }

        fn list(&self, dir: &str) -> io::Result<Vec<String>> {
            self.inner.list(dir)
        }

        fn sync_dir(&self, dir: &str) -> io::Result<()> {
            self.trace.lock().unwrap().push("directory_sync");
            self.fail(FailAt::DirectorySync)?;
            self.inner.sync_dir(dir)
        }

        fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
            self.inner.try_lock(path)
        }

        fn free_bytes(&self) -> io::Result<Option<u64>> {
            self.inner.free_bytes()
        }
    }
}
