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

use crate::{Backing, FileBacking, FileOwner, VolumeLock};

const MAGIC: &[u8; 8] = b"MAKIWIT1";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"maki-file-witness-anchor-v1\0";
const BODY_LEN: usize = 72;
const ENCODED_LEN: usize = BODY_LEN + 32;
const MAX_GENERATION: u64 = i64::MAX as u64;
const ANCHOR_FILE: &str = "anchor";
const TEMP_FILE: &str = "anchor.next";
const LOCK_FILE: &str = "witness.lock";

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// True when this relative path would occupy or descend through a witness file.
    pub fn reserves_path(relative: &Path) -> bool {
        [ANCHOR_FILE, TEMP_FILE, LOCK_FILE]
            .iter()
            .any(|file| relative.starts_with(file))
    }

    /// Whether `name` is an entry that a creation leaves in the witness
    /// directory before it publishes the anchor: the lock, and the record
    /// under its temporary name, which nothing reads.
    pub(crate) fn left_by_an_unpublished_creation(name: &str) -> bool {
        [LOCK_FILE, TEMP_FILE].contains(&name)
    }

    pub fn create(path: &Path, identity: [u8; 16], root: [u8; 32]) -> io::Result<Self> {
        validate_identity(&identity)?;
        Self::create_backing(Arc::new(FileBacking::new(path)?), identity, root)
    }

    pub(crate) fn create_backing(
        backing: Arc<dyn Backing>,
        identity: [u8; 16],
        root: [u8; 32],
    ) -> io::Result<Self> {
        validate_identity(&identity)?;
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
        // The first record is published like every later one: written and
        // synced under the temporary name, renamed into place, and the
        // directory synced. A creation that a kill, a power loss or a
        // failure stops before the rename leaves no anchor (the next one
        // removes what it left under the temporary name), and one that got
        // past it left the complete record. No anchor is replaced, so the
        // record is the directory owner's: in a directory another user
        // owns, a root process creates it for that user (`FileBacking`),
        // and in a root-owned one it is root's. Run as root, the temporary
        // record must be one of root's or that owner's files, as for every
        // later publication (`hand_over_temporary`, SPEC §8).
        let owner = if running_as_root() {
            backing.directory_owner("")?
        } else {
            None
        };
        write_temporary(backing.as_ref(), &encode(&anchor), owner)?;
        backing.rename(TEMP_FILE, ANCHOR_FILE)?;
        backing.sync_dir("")?;

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

    pub(crate) fn open_backing(backing: Arc<dyn Backing>) -> io::Result<Self> {
        let lock = backing.try_lock(LOCK_FILE)?;
        let anchor = read_anchor(backing.as_ref())?;
        // A prior process may have observed rename success and directory-sync
        // failure. Re-publish the exact validated record before returning so
        // callers never reclaim data based only on page-cache-visible state.
        // The new file keeps the replaced record's owner (`replaced_owner`).
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
        if let Err(error) = &result {
            // A failed read does not establish that the published anchor
            // changed. Refuse this operation and compare again next time.
            // Missing, incomplete or invalid records do prove a change.
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData
            ) {
                self.poisoned.set(true);
            }
        }
        result
    }

    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned.get()
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

fn write_temporary(
    backing: &dyn Backing,
    bytes: &[u8; ENCODED_LEN],
    owner: Option<FileOwner>,
) -> io::Result<()> {
    // Whoever left a file under the temporary name (a failed earlier
    // publication, or anyone who can write the directory) may still hold a
    // writable descriptor of it, and would keep it on the published anchor.
    // Remove it, so the record is a file created here: for the directory's
    // owner when root creates it in a directory another user owns
    // (`FileBacking`).
    match backing.remove(TEMP_FILE) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let file = backing.open(TEMP_FILE, true)?;
    let handed_over = match owner {
        Some(owner) if hand_over_temporary(file.owner()?, owner)? => Some(owner),
        _ => None,
    };
    // A file put back under the name since the removal is opened as it is.
    // It is emptied first, so handing it over gives nobody bytes they could
    // not read before.
    file.set_len(0)?;
    // Hand the new record over before it holds a byte; `publish_anchor`
    // renames it over the anchor only after this change is synced with it.
    if let Some(owner) = handed_over {
        file.set_owner(owner).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "cannot keep the witness anchor's owner (uid {}, gid {}): {error}",
                    owner.uid, owner.gid
                ),
            )
        })?;
    }
    file.write_at(0, bytes)?;
    file.set_len(ENCODED_LEN as u64)?;
    // fdatasync need not persist an owner change; fsync does.
    if handed_over.is_some() {
        file.sync_all()
    } else {
        file.sync_data()
    }
}

/// Whether root gives the temporary record, owned by `temporary`, to
/// `owner` before writing it. The record is the file just created, for the
/// directory's owner or, in a root-owned directory, for root. A file put
/// back under its name after the stale one was removed is opened as it is
/// instead: one of root's or of the record owner's uid gives nobody anything
/// (that owner can rewrite the anchor already), and is handed over like a
/// new one. One of any other user is refused, never given away: its owner
/// may hold a writable descriptor of it, which would then rewrite the
/// published anchor.
fn hand_over_temporary(temporary: Option<FileOwner>, owner: FileOwner) -> io::Result<bool> {
    match temporary {
        Some(temporary) if temporary == owner => Ok(false),
        Some(temporary) if temporary.uid != 0 && temporary.uid != owner.uid => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the witness directory holds an {TEMP_FILE} of uid {}, neither root's nor the \
                 anchor owner's (uid {}); find out who put it there before opening the witness",
                temporary.uid, owner.uid
            ),
        )),
        _ => Ok(true),
    }
}

fn publish_anchor(backing: &dyn Backing, anchor: &Anchor) -> io::Result<()> {
    write_temporary(backing, &encode(anchor), replaced_owner(backing)?)?;
    backing.rename(TEMP_FILE, ANCHOR_FILE)?;
    backing.sync_dir("")
}

/// The owner a publication must keep. The new record is a file this process
/// creates, so a root process (an offline `maki check --deep` or `maki
/// volume inspect`) would otherwise replace the daemon user's anchor with a
/// root-owned one the daemon can no longer open. Only root can give a file
/// to another user, and only root needs to: any other process creates the
/// record as itself. The mode is not copied; every publication creates the
/// record owner-only (`0600`), unless root or the record's owner puts a file
/// back under the temporary name meanwhile (`hand_over_temporary`).
fn replaced_owner(backing: &dyn Backing) -> io::Result<Option<FileOwner>> {
    if !running_as_root() {
        return Ok(None);
    }
    let replaced = backing.open(ANCHOR_FILE, false)?.owner()?;
    publication_owner(backing.directory_owner("")?, replaced)
}

/// Whom root publishes the record for, given the witness directory's owner
/// and the replaced anchor's. In a directory another user owns, every file
/// root creates is that user's (`FileBacking`), and the record is too: an
/// anchor root owns there is what a root run that did not keep the owner
/// left, and goes back to the directory's owner. An anchor of a third user
/// is refused rather than given to either: whoever owns the directory can
/// put any file there, and root must not hand a record to a user it cannot
/// tell is the volume's. A root-owned directory keeps the replaced
/// anchor's owner.
fn publication_owner(
    directory: Option<FileOwner>,
    replaced: Option<FileOwner>,
) -> io::Result<Option<FileOwner>> {
    let (Some(directory), Some(anchor)) = (directory, replaced) else {
        return Ok(replaced);
    };
    if directory.uid == 0 || anchor.uid == directory.uid {
        Ok(Some(anchor))
    } else if anchor.uid == 0 {
        Ok(Some(directory))
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "the witness directory belongs to uid {} but its anchor to uid {}; give both to \
                 the daemon user before opening the witness",
                directory.uid, anchor.uid
            ),
        ))
    }
}

fn running_as_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn read_anchor(backing: &dyn Backing) -> io::Result<Anchor> {
    let file = backing.open(ANCHOR_FILE, false)?;
    let len = file.len()?;
    if len == 0 {
        // Never completed by this release, which publishes the anchor whole.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the witness anchor is empty: either a volume create of an earlier release did not \
             complete, or this witness lost its state. Only if the volume was never attached, \
             remove the empty anchor and run volume create again, which refuses a backing that \
             holds committed data; otherwise restore the witness directory",
        ));
    }
    if len != ENCODED_LEN as u64 {
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

/// [`decode`] of a record of any length, for the crate's crash models.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn decode_anchor(bytes: &[u8]) -> io::Result<Anchor> {
    let bytes: &[u8; ENCODED_LEN] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid witness anchor length"))?;
    decode(bytes)
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
    use crate::{Backing, BackingFile, FileBacking, FileOwner, VolumeLock};

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
    fn transient_anchor_reads_refuse_only_the_current_operation() {
        for fail_at in [FailAt::AnchorOpen, FailAt::AnchorLen, FailAt::AnchorRead] {
            let dir = tempdir().unwrap();
            drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
            let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
            let mut witness = FileWitness::open_backing(fault.clone()).unwrap();
            let before = witness.anchor().clone();

            fault.arm(fail_at);
            assert!(witness.verify_current().is_err(), "{fail_at:?}");
            assert!(!witness.is_poisoned(), "{fail_at:?}");
            witness.verify_current().unwrap();
            assert_eq!(witness.anchor(), &before);

            fault.arm(fail_at);
            assert!(witness.advance(ROOT_B).is_err(), "{fail_at:?}");
            assert!(!witness.is_poisoned(), "{fail_at:?}");
            assert_eq!(witness.anchor(), &before);
            assert_eq!(FileWitness::anchor(&witness).generation, 0);
            witness.advance(ROOT_B).unwrap();
            assert_eq!(witness.anchor().generation, 1);
            assert_eq!(witness.anchor().root, ROOT_B);
        }
    }

    #[test]
    fn a_transient_read_is_followed_by_a_fresh_comparison() {
        let dir = tempdir().unwrap();
        drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
        let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
        let witness = FileWitness::open_backing(fault.clone()).unwrap();
        fault.arm(FailAt::AnchorRead);
        assert!(witness.verify_current().is_err());
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
        assert!(witness.is_poisoned());
    }

    #[test]
    fn missing_truncated_corrupt_and_short_read_anchors_poison_permanently() {
        for fault in 0..4 {
            let dir = tempdir().unwrap();
            drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
            let backing = Arc::new(FaultBacking::new(dir.path()).unwrap());
            let witness = FileWitness::open_backing(backing.clone()).unwrap();
            let path = dir.path().join("anchor");
            let original = fs::read(&path).unwrap();
            let expected = match fault {
                0 => {
                    fs::remove_file(&path).unwrap();
                    io::ErrorKind::NotFound
                }
                1 => {
                    fs::write(&path, &original[..ENCODED_LEN - 1]).unwrap();
                    io::ErrorKind::InvalidData
                }
                2 => {
                    let mut corrupt = original.clone();
                    corrupt[40] ^= 1;
                    fs::write(&path, corrupt).unwrap();
                    io::ErrorKind::InvalidData
                }
                _ => {
                    backing.arm(FailAt::AnchorShortRead);
                    io::ErrorKind::UnexpectedEof
                }
            };
            assert_eq!(witness.verify_current().unwrap_err().kind(), expected);
            fs::write(&path, original).unwrap();
            assert!(witness.is_poisoned());
            assert!(witness.verify_current().is_err());
        }
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
    fn only_root_gives_a_new_record_the_replaced_owner_and_syncs_it_first() {
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let dir = tempdir().unwrap();
        drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
        let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
        // The anchor reports an owner this process's new files do not have.
        fault.report_anchor_owner(daemon);
        let backing: Arc<dyn Backing> = fault.clone();
        let mut witness = FileWitness::open_backing(backing).unwrap();
        witness.advance(ROOT_B).unwrap();
        drop(witness);

        if super::running_as_root() {
            let publish = [
                "temp_owner",
                "temp_write",
                "temp_sync_all",
                "rename",
                "directory_sync",
            ];
            assert_eq!(fault.trace(), [publish, publish].concat());
            assert_eq!(fault.given(), [daemon, daemon]);

            // A refused owner change refuses the open: publishing a record
            // the owner cannot open would lock it out of its witness.
            let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
            fault.report_anchor_owner(daemon);
            fault.arm(FailAt::TempOwner);
            let backing: Arc<dyn Backing> = fault.clone();
            let error = FileWitness::open_backing(backing).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("uid 4242, gid 4343"), "{error}");
            assert_eq!(fault.trace(), ["temp_owner"]);
        } else {
            // Nobody else can give a file away; they publish as themselves.
            let publish = ["temp_write", "temp_sync", "rename", "directory_sync"];
            assert_eq!(fault.trace(), [publish, publish].concat());
            assert!(fault.given().is_empty());
        }
    }

    #[test]
    fn root_publishes_for_the_directory_owner_and_refuses_a_third_anchor_owner() {
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let other = FileOwner {
            uid: 4444,
            gid: 4545,
        };
        let root = FileOwner { uid: 0, gid: 0 };
        let dir = tempdir().unwrap();
        drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
        // A daemon-owned directory with a root-owned anchor: what a root
        // run that did not keep the anchor's owner left, here with the
        // temporary file of a failed publication.
        std::fs::write(dir.path().join(super::TEMP_FILE), b"left behind").unwrap();
        let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
        fault.report_directory_owner(daemon);
        fault.report_anchor_owner(root);
        let backing: Arc<dyn Backing> = fault.clone();
        drop(FileWitness::open_backing(backing).unwrap());

        // An anchor of a third user in the daemon's directory.
        let refused = Arc::new(FaultBacking::new(dir.path()).unwrap());
        refused.report_directory_owner(daemon);
        refused.report_anchor_owner(other);
        let backing: Arc<dyn Backing> = refused.clone();
        let opened = FileWitness::open_backing(backing);

        if super::running_as_root() {
            // The record goes back to the directory's owner.
            assert_eq!(
                fault.trace(),
                [
                    "temp_owner",
                    "temp_write",
                    "temp_sync_all",
                    "rename",
                    "directory_sync"
                ]
            );
            assert_eq!(fault.given(), [daemon]);
            // Refused before anything is written or given away.
            let error = opened.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("uid 4242"), "{error}");
            assert!(error.to_string().contains("uid 4444"), "{error}");
            assert!(refused.trace().is_empty());
            assert!(refused.given().is_empty());
        } else {
            // Nobody else can give a file away; they publish as themselves.
            let publish = ["temp_write", "temp_sync", "rename", "directory_sync"];
            assert_eq!(fault.trace(), publish);
            drop(opened.unwrap());
            assert_eq!(refused.trace(), publish);
            assert!(fault.given().is_empty() && refused.given().is_empty());
        }
    }

    #[test]
    fn root_publishes_for_the_anchor_or_directory_owner_it_can_trust() {
        use super::publication_owner;
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let daemon_group = FileOwner {
            uid: 4242,
            gid: 4646,
        };
        let other = FileOwner {
            uid: 4444,
            gid: 4545,
        };
        let root = FileOwner { uid: 0, gid: 0 };
        // A backing without ownership, or an anchor without one, keeps
        // whatever the anchor reports.
        assert_eq!(publication_owner(None, None).unwrap(), None);
        assert_eq!(publication_owner(None, Some(other)).unwrap(), Some(other));
        assert_eq!(publication_owner(Some(daemon), None).unwrap(), None);
        // A root-owned directory keeps the replaced anchor's owner.
        for anchor in [root, daemon, other] {
            assert_eq!(
                publication_owner(Some(root), Some(anchor)).unwrap(),
                Some(anchor)
            );
        }
        // The directory owner's own anchor keeps its owner and group.
        assert_eq!(
            publication_owner(Some(daemon_group), Some(daemon)).unwrap(),
            Some(daemon)
        );
        // A root-owned anchor goes back to the directory's owner.
        assert_eq!(
            publication_owner(Some(daemon), Some(root)).unwrap(),
            Some(daemon)
        );
        // A third user's anchor is given to nobody.
        let error = publication_owner(Some(daemon), Some(other)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn root_hands_over_only_a_temporary_record_of_root_or_the_record_owner() {
        use super::hand_over_temporary;
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let daemon_group = FileOwner {
            uid: 4242,
            gid: 4646,
        };
        let other = FileOwner {
            uid: 4444,
            gid: 4545,
        };
        let root = FileOwner { uid: 0, gid: 0 };
        let root_group = FileOwner { uid: 0, gid: 4343 };
        // The record owner's own file needs no change.
        assert!(!hand_over_temporary(Some(daemon), daemon).unwrap());
        assert!(!hand_over_temporary(Some(root), root).unwrap());
        // Root's file, whatever its group, is handed over.
        assert!(hand_over_temporary(Some(root), daemon).unwrap());
        assert!(hand_over_temporary(Some(root_group), daemon).unwrap());
        // So is the record owner's file in another group: the directory's
        // group when the anchor keeps its own.
        assert!(hand_over_temporary(Some(daemon_group), daemon).unwrap());
        // A file without an owner is asked to change, which such a backing
        // refuses.
        assert!(hand_over_temporary(None, daemon).unwrap());
        // Anyone else's file is refused, for any record owner.
        for owner in [daemon, root] {
            let error = hand_over_temporary(Some(other), owner).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains("uid 4444"), "{error}");
            assert!(
                error.to_string().contains(&format!("uid {}", owner.uid)),
                "{error}"
            );
        }
        assert!(hand_over_temporary(Some(daemon), other).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_temporary_record_left_in_the_directory_is_never_published() {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let dir = tempdir().unwrap();
        drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
        // Whoever left this file may still hold a writable descriptor.
        let left = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.path().join(super::TEMP_FILE))
            .unwrap();
        left.write_all_at(b"left behind", 0).unwrap();

        let mut witness = FileWitness::open(dir.path()).unwrap();
        let anchor = dir.path().join(super::ANCHOR_FILE);
        let published = fs::read(&anchor).unwrap();
        assert_ne!(
            fs::metadata(&anchor).unwrap().ino(),
            left.metadata().unwrap().ino(),
            "the file left behind was published"
        );
        // Writing through the kept descriptor changes nothing published.
        left.write_all_at(&[0xa5; ENCODED_LEN], 0).unwrap();
        assert_eq!(fs::read(&anchor).unwrap(), published);
        witness.verify_current().unwrap();
        witness.advance(ROOT_B).unwrap();
        drop(witness);
        assert_eq!(FileWitness::open(dir.path()).unwrap().anchor().root, ROOT_B);
    }

    #[test]
    fn root_hands_over_a_temporary_record_put_back_only_by_root_or_the_record_owner() {
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let other = FileOwner {
            uid: 4444,
            gid: 4545,
        };
        let root = FileOwner { uid: 0, gid: 0 };
        for planter in [root, daemon, other] {
            let dir = tempdir().unwrap();
            drop(FileWitness::create(dir.path(), IDENTITY, ROOT_A).unwrap());
            let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
            fault.report_directory_owner(daemon);
            fault.report_anchor_owner(daemon);
            // Someone who can write the directory puts a record back under
            // the temporary name once the stale one is removed.
            fault.replant_temporary(b"put back", planter);
            let backing: Arc<dyn Backing> = fault.clone();
            let opened = FileWitness::open_backing(backing);

            if !super::running_as_root() {
                // Nobody else can give a file away; they publish as
                // themselves.
                drop(opened.unwrap());
                assert_eq!(
                    fault.trace(),
                    ["temp_write", "temp_sync", "rename", "directory_sync"],
                    "{planter:?}"
                );
                assert!(fault.given().is_empty());
            } else if planter == other {
                // Root gives the record to nobody and publishes nothing.
                let error = opened.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert!(error.to_string().contains("uid 4444"), "{error}");
                assert!(error.to_string().contains("uid 4242"), "{error}");
                assert!(fault.trace().is_empty());
                assert!(fault.given().is_empty());
            } else if planter == daemon {
                // The record owner's own file needs no change.
                drop(opened.unwrap());
                assert_eq!(
                    fault.trace(),
                    ["temp_write", "temp_sync", "rename", "directory_sync"]
                );
                assert!(fault.given().is_empty());
            } else {
                // Root's own file is emptied and then handed over.
                drop(opened.unwrap());
                assert_eq!(
                    fault.trace(),
                    [
                        "temp_owner",
                        "temp_write",
                        "temp_sync_all",
                        "rename",
                        "directory_sync"
                    ]
                );
                assert_eq!(fault.given(), [daemon]);
            }
        }
    }

    /// The first record follows the same rule: `create` removes a stale
    /// temporary record, and a file someone who can write the directory
    /// puts back under that name before it is opened again is published
    /// only if it is root's or the directory owner's, whose record it is.
    #[test]
    fn root_creates_the_first_record_only_in_a_file_of_root_or_the_directory_owner() {
        let daemon = FileOwner {
            uid: 4242,
            gid: 4343,
        };
        let other = FileOwner {
            uid: 4444,
            gid: 4545,
        };
        let root = FileOwner { uid: 0, gid: 0 };
        for planter in [other, root, daemon] {
            let dir = tempdir().unwrap();
            let fault = Arc::new(FaultBacking::new(dir.path()).unwrap());
            fault.report_directory_owner(daemon);
            fault.replant_temporary(b"put back", planter);
            let backing: Arc<dyn Backing> = fault.clone();
            let created = FileWitness::create_backing(backing, IDENTITY, ROOT_A);

            if !super::running_as_root() {
                drop(created.unwrap());
                assert_eq!(
                    fault.trace(),
                    ["temp_write", "temp_sync", "rename", "directory_sync"],
                    "{planter:?}"
                );
                assert!(fault.given().is_empty());
            } else if planter == other {
                let error = created.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
                assert!(error.to_string().contains("uid 4444"), "{error}");
                assert!(error.to_string().contains("uid 4242"), "{error}");
                assert!(fault.trace().is_empty());
                assert!(fault.given().is_empty());
                assert!(!dir.path().join(super::ANCHOR_FILE).exists());
            } else if planter == daemon {
                drop(created.unwrap());
                assert_eq!(
                    fault.trace(),
                    ["temp_write", "temp_sync", "rename", "directory_sync"]
                );
                assert!(fault.given().is_empty());
            } else {
                drop(created.unwrap());
                assert_eq!(
                    fault.trace(),
                    [
                        "temp_owner",
                        "temp_write",
                        "temp_sync_all",
                        "rename",
                        "directory_sync"
                    ]
                );
                assert_eq!(fault.given(), [daemon]);
            }
        }
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
        AnchorOpen,
        AnchorLen,
        AnchorRead,
        AnchorShortRead,
        TempOwner,
        TempWrite,
        TempSync,
        Rename,
        DirectorySync,
    }

    struct FaultBacking {
        inner: FileBacking,
        pending: Arc<Mutex<Option<FailAt>>>,
        trace: Arc<Mutex<Vec<&'static str>>>,
        anchor_owner: Mutex<Option<FileOwner>>,
        directory_owner: Mutex<Option<FileOwner>>,
        replant: Mutex<Option<(Vec<u8>, FileOwner)>>,
        temporary_owner: Mutex<Option<FileOwner>>,
        given: Arc<Mutex<Vec<FileOwner>>>,
    }

    impl FaultBacking {
        fn new(path: &std::path::Path) -> io::Result<Self> {
            Ok(Self {
                inner: FileBacking::new(path)?,
                pending: Arc::new(Mutex::new(None)),
                trace: Arc::new(Mutex::new(Vec::new())),
                anchor_owner: Mutex::new(None),
                directory_owner: Mutex::new(None),
                replant: Mutex::new(None),
                temporary_owner: Mutex::new(None),
                given: Arc::new(Mutex::new(Vec::new())),
            })
        }

        fn arm(&self, fail_at: FailAt) {
            *self.pending.lock().unwrap() = Some(fail_at);
        }

        fn trace(&self) -> Vec<&'static str> {
            self.trace.lock().unwrap().clone()
        }

        /// Make the anchor report `owner` instead of its real owner.
        fn report_anchor_owner(&self, owner: FileOwner) {
            *self.anchor_owner.lock().unwrap() = Some(owner);
        }

        /// Make the witness directory report `owner` instead of its real
        /// owner.
        fn report_directory_owner(&self, owner: FileOwner) {
            *self.directory_owner.lock().unwrap() = Some(owner);
        }

        /// Once the temporary record is next removed, put a file holding
        /// `bytes` back under its name and report it as `owner`'s: what
        /// anyone who can write the directory may do between that removal
        /// and the creation that follows.
        fn replant_temporary(&self, bytes: &[u8], owner: FileOwner) {
            *self.replant.lock().unwrap() = Some((bytes.to_vec(), owner));
        }

        /// Owners given to temporary files. They are recorded, not applied,
        /// so the tests need no privilege.
        fn given(&self) -> Vec<FileOwner> {
            self.given.lock().unwrap().clone()
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
        anchor: bool,
        reported_owner: Option<FileOwner>,
        given: Arc<Mutex<Vec<FileOwner>>>,
    }

    impl BackingFile for FaultFile {
        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<()> {
            if self.anchor {
                let mut pending = self.pending.lock().unwrap();
                match *pending {
                    Some(FailAt::AnchorRead) => {
                        *pending = None;
                        return Err(io::Error::other("injected anchor read failure"));
                    }
                    Some(FailAt::AnchorShortRead) => {
                        *pending = None;
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    _ => {}
                }
            }
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
            if self.anchor {
                let mut pending = self.pending.lock().unwrap();
                if *pending == Some(FailAt::AnchorLen) {
                    *pending = None;
                    return Err(io::Error::other("injected anchor stat failure"));
                }
            }
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

        fn sync_all(&self) -> io::Result<()> {
            if self.temporary {
                self.trace.lock().unwrap().push("temp_sync_all");
                let mut pending = self.pending.lock().unwrap();
                if *pending == Some(FailAt::TempSync) {
                    *pending = None;
                    return Err(io::Error::other("injected temporary sync failure"));
                }
            }
            self.inner.sync_all()
        }

        fn owner(&self) -> io::Result<Option<FileOwner>> {
            match self.reported_owner {
                Some(owner) => Ok(Some(owner)),
                None => self.inner.owner(),
            }
        }

        fn set_owner(&self, owner: FileOwner) -> io::Result<()> {
            assert!(self.temporary, "only a new record is given away");
            assert_eq!(
                self.inner.len().unwrap(),
                0,
                "a file is handed over only once it holds nothing"
            );
            self.trace.lock().unwrap().push("temp_owner");
            let mut pending = self.pending.lock().unwrap();
            if *pending == Some(FailAt::TempOwner) {
                *pending = None;
                return Err(io::Error::from_raw_os_error(1));
            }
            self.given.lock().unwrap().push(owner);
            Ok(())
        }
    }

    impl Backing for FaultBacking {
        fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
            if path == super::ANCHOR_FILE {
                self.fail(FailAt::AnchorOpen)?;
            }
            Ok(Arc::new(FaultFile {
                inner: self.inner.open(path, create)?,
                pending: Arc::clone(&self.pending),
                trace: Arc::clone(&self.trace),
                temporary: path == super::TEMP_FILE,
                anchor: path == super::ANCHOR_FILE,
                reported_owner: if path == super::ANCHOR_FILE {
                    *self.anchor_owner.lock().unwrap()
                } else if path == super::TEMP_FILE {
                    *self.temporary_owner.lock().unwrap()
                } else {
                    None
                },
                given: Arc::clone(&self.given),
            }))
        }

        fn exists(&self, path: &str) -> io::Result<bool> {
            self.inner.exists(path)
        }

        fn remove(&self, path: &str) -> io::Result<()> {
            let removed = self.inner.remove(path);
            if path == super::TEMP_FILE {
                if let Some((bytes, owner)) = self.replant.lock().unwrap().take() {
                    self.inner.open(path, true)?.write_at(0, &bytes)?;
                    *self.temporary_owner.lock().unwrap() = Some(owner);
                }
            }
            removed
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

        fn directory_owner(&self, dir: &str) -> io::Result<Option<FileOwner>> {
            match *self.directory_owner.lock().unwrap() {
                Some(owner) => Ok(Some(owner)),
                None => self.inner.directory_owner(dir),
            }
        }
    }
}
