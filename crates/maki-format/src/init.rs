//! Volume initialization (mkfs): create the durable on-disk layout (SPEC §21).

use maki_backing::{Backing, RollbackBacking};

use crate::ab::AbStore;
use crate::catalog::ShardCatalog;
use crate::checkpoint::{CheckpointState, CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use crate::durable_proof::{DurableProofStore, DURABLE_PROOF_A, DURABLE_PROOF_B};
use crate::error::FormatError;
use crate::layout;
use crate::superblock::{
    load_volume_superblock, Superblock, VolumeSuperblock, SUPERBLOCK_VERSION_V2,
    SUPERBLOCK_VERSION_V3,
};

/// Why [`create_in_rollback_backing`] failed.
#[derive(Debug, thiserror::Error)]
pub enum RollbackCreateError {
    /// The backing or its witness refused the creation, or failed.
    #[error(transparent)]
    Backing(std::io::Error),
    /// The volume inside the backing could not be initialized.
    #[error(transparent)]
    Volume(#[from] FormatError),
}

/// Create a volume in a local rollback-protected backing: `create` enrolls
/// the backing with its witness (and continues an enrollment that stopped
/// before its witness anchor), and the volume is then initialized inside
/// it. `open` must open the existing pair against its witness
/// (`RollbackBacking::open`).
///
/// A command that stopped after the anchor and before the volume's
/// superblock left a pair that `create` refuses, because it never writes
/// over an anchor, and that holds no volume. Running the command again
/// continues it: when `create` refuses an existing pair, the pair is
/// opened, and if it holds nothing but an unfinished creation
/// ([`unfinished_creation`]) what that creation left is removed and the
/// volume is initialized anew.
///
/// That judgement is only made on a pair that opens. Opening authenticates
/// the manifest and every committed page against the witness anchor, so
/// what is judged is exactly what was committed: damage to a used volume
/// (its superblock pages, its manifest slots, its anchor, a witness that is
/// not mounted) fails the open and keeps the refusal, it never looks like
/// an unfinished creation. And a volume that was ever attached cannot hold
/// what is required: no superblock copy and nothing a creation does not
/// write before its superblock. Every other pair is refused with `create`'s
/// own error and left as it is.
pub fn create_in_rollback_backing(
    create: impl FnOnce() -> std::io::Result<RollbackBacking>,
    open: impl FnOnce() -> std::io::Result<RollbackBacking>,
    capacity: u64,
    superblock: Superblock,
    discard: bool,
) -> Result<(RollbackBacking, Superblock), RollbackCreateError> {
    let backing = match create() {
        Ok(backing) => backing,
        Err(refusal) if refusal.kind() == std::io::ErrorKind::AlreadyExists => {
            continue_creation(open, capacity, refusal)?
        }
        Err(error) => return Err(RollbackCreateError::Backing(error)),
    };
    let superblock = if discard {
        create_volume_with_discard(&backing, superblock)?
    } else {
        create_volume(&backing, superblock)?
    };
    Ok((backing, superblock))
}

/// The pair `create` refused with `refusal`, opened and emptied of an
/// unfinished creation, or `refusal`.
fn continue_creation(
    open: impl FnOnce() -> std::io::Result<RollbackBacking>,
    capacity: u64,
    refusal: std::io::Error,
) -> Result<RollbackBacking, RollbackCreateError> {
    // A pair that does not open is not judged at all.
    let Ok(backing) = open() else {
        return Err(RollbackCreateError::Backing(refusal));
    };
    // Serialize with a creation and an attach inside the backing, as
    // `create_volume` does.
    let volume_lock = backing
        .try_lock(layout::VOLUME_LOCK)
        .map_err(RollbackCreateError::Backing)?;
    if !unfinished_creation(&backing)? {
        return Err(RollbackCreateError::Backing(refusal));
    }
    // The witnessed manifest fixes the capacity the interrupted creation
    // reserved; the daemon refuses a configuration that names another.
    let reserved = backing.capacity().map_err(RollbackCreateError::Backing)?;
    if reserved != capacity {
        return Err(RollbackCreateError::Backing(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "an interrupted creation of this volume reserved capacity {reserved}, the \
                 configuration names {capacity}: create the volume with capacity {reserved}, or \
                 empty the backing and witness directories to start over"
            ),
        )));
    }
    // Start over inside the backing: the new volume has a new identity, and
    // records of the interrupted one (its durable proof) would not match it.
    for name in [layout::SHARD_CATALOG_A].into_iter().chain(CREATION_FILES) {
        match backing.remove(name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(FormatError::from(error).into()),
        }
    }
    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        if backing.exists(dir).map_err(FormatError::from)? {
            backing.sync_dir(dir).map_err(FormatError::from)?;
        }
    }
    backing.sync_dir("").map_err(FormatError::from)?;
    drop(volume_lock);
    Ok(backing)
}

/// What a creation writes at the root of the backing before its superblock.
const CREATION_ROOT: [&str; 5] = [
    layout::VOLUME_LOCK,
    layout::SHARD_CATALOG_A,
    layout::DATA_DIR,
    layout::JOURNAL_DIR,
    layout::CHECKPOINT_DIR,
];

/// What a creation writes in the layout directories before its superblock.
const CREATION_FILES: [&str; 5] = [
    DURABLE_PROOF_A,
    DURABLE_PROOF_B,
    layout::JOURNAL_DURABLE_MARK,
    CHECKPOINT_STATE_A,
    CHECKPOINT_STATE_B,
];

/// Whether `backing` holds nothing but what [`create_volume`] leaves when it
/// stops before its superblock, its commit point: no superblock copy, and
/// no entry other than the lock, the first shard-catalog copy, the three
/// layout directories, the durable proof, the initial checkpoint state and
/// the journal's durable mark, still empty. An empty backing qualifies.
///
/// A volume that was ever attached holds a superblock copy; one that
/// acknowledged a write also holds a journal segment or a shard, and a
/// durable mark that was written. So this is evidence of an unfinished
/// creation only where the content of `backing` is authenticated, as a
/// rollback-protected backing's is once it has opened against its witness.
/// On a plain directory the same files are also what a used volume whose
/// superblock copies were lost or damaged looks like: never judge one with
/// this.
pub fn unfinished_creation(backing: &dyn Backing) -> Result<bool, FormatError> {
    for name in backing.list("")? {
        if !CREATION_ROOT.contains(&name.as_str()) {
            return Ok(false);
        }
    }
    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        let entries = match backing.list(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if entries
            .iter()
            .any(|entry| !CREATION_FILES.contains(&format!("{dir}/{entry}").as_str()))
        {
            return Ok(false);
        }
    }
    match backing.open(layout::JOURNAL_DURABLE_MARK, false) {
        Ok(mark) => Ok(mark.len()? == 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

/// Create a new volume in an empty backing root. Everything created here is
/// durable when this returns (dirs synced), so a crash immediately after
/// creation leaves a valid volume.
pub fn create_volume(
    backing: &dyn Backing,
    superblock: Superblock,
) -> Result<Superblock, FormatError> {
    create_volume_with_metadata_version(backing, superblock, SUPERBLOCK_VERSION_V2)
}

/// Create a new volume whose v3 envelope opts into per-shard discard metadata.
pub fn create_volume_with_discard(
    backing: &dyn Backing,
    superblock: Superblock,
) -> Result<Superblock, FormatError> {
    create_volume_with_metadata_version(backing, superblock, SUPERBLOCK_VERSION_V3)
}

fn create_volume_with_metadata_version(
    backing: &dyn Backing,
    mut superblock: Superblock,
    metadata_version: u32,
) -> Result<Superblock, FormatError> {
    // Library callers can supply a model directly, including its derived
    // geometry. Check the exact envelope with the reader before touching the
    // backing, so every successful initialization yields a readable volume.
    Superblock::decode(&superblock.encode_metadata_version(metadata_version)?)?;
    // Serialize the empty-root checks with initialization and attach. The
    // guard remains live through the final directory sync: a lock file's
    // presence alone does not prevent another creator from publishing a
    // different UUID over this volume's metadata (BUG-039).
    let _volume_lock = backing.try_lock(layout::VOLUME_LOCK)?;
    if backing.exists(layout::SUPERBLOCK_A)? || backing.exists(layout::SUPERBLOCK_B)? {
        return Err(FormatError::AlreadyExists(
            "volume superblock already present".to_string(),
        ));
    }
    // The rest of an earlier volume's root-level metadata is refused too: a
    // stale key canary would fail the new volume's first attach as a key
    // mismatch, and a stale shard-catalog copy would remain the fallback
    // side until the first catalog commit. The volume lock carries no
    // volume state (and was just taken), so it may exist.
    for name in layout::ROOT_METADATA {
        if backing.exists(name)? {
            return Err(FormatError::AlreadyExists(format!(
                "backing root is not empty: {name} belongs to an earlier volume; \
                 use an empty root"
            )));
        }
    }
    // Any file left in the layout directories belongs to an earlier volume:
    // slot headers carry no volume UUID, so the new volume would adopt its
    // shards and serve their ciphertext instead of zeros (R5-018). Every
    // entry counts, so `list` refuses a name that is not UTF-8 here instead
    // of skipping it.
    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        let entries = match backing.list(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if let Some(entry) = entries.first() {
            return Err(FormatError::AlreadyExists(format!(
                "backing root is not empty: {dir}/{entry} belongs to an earlier volume; \
                 use an empty root"
            )));
        }
    }

    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        backing.create_dir_all(dir)?;
    }

    // The exclusion API does not promise that its lock file is durable.
    // Persist it explicitly; the root sync below stabilizes its dirent.
    let lock_file = backing.open(layout::VOLUME_LOCK, true)?;
    lock_file.sync_data()?;

    // The superblock is the commit point and is published last: until a
    // copy of it is durable the root is not a volume, so an interrupted
    // creation never resembles an initialized volume missing its catalog,
    // checkpoint state or durable proof (BUG-100). Required evidence is
    // initialized first, too: an interrupted initialization must never
    // resemble a legacy volume or an empty history whose proof files were
    // simply lost.
    DurableProofStore::initialize(backing, superblock.volume_uuid)?;

    // Empty shard catalog (single copy now; second side written on first
    // update).
    let cat_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    let mut catalog = ShardCatalog::new();
    cat_ab.store(backing, &mut catalog)?;

    // Initial checkpoint state (sequence 0), both copies: recovery requires
    // a valid copy on every initialized volume, so that losing the state
    // can never be mistaken for "never checkpointed".
    let ck_ab = AbStore::new(CHECKPOINT_STATE_A, CHECKPOINT_STATE_B);
    let mut state = CheckpointState::default();
    ck_ab.store(backing, &mut state)?;
    ck_ab.store(backing, &mut state)?;

    // The journal writer's durable mark (empty = no information yet); its
    // dirent is made durable here so the first mark write never depends on
    // a later directory fsync.
    let mark = backing.open(layout::JOURNAL_DURABLE_MARK, true)?;
    mark.set_len(0)?;
    mark.sync_data()?;

    // Make every dirent above durable before the superblock can be.
    backing.sync_dir(layout::DATA_DIR)?;
    backing.sync_dir(layout::JOURNAL_DIR)?;
    backing.sync_dir(layout::CHECKPOINT_DIR)?;
    backing.sync_dir("")?;

    // Both superblock copies, so a single later torn write can never leave
    // the volume unreadable. A failure or a kill from here on can leave a
    // readable copy that is not durable (or only copy A): the root is then a
    // volume this function refuses, and writable recovery makes both copies
    // durable before anything else (`persist_volume_superblock`).
    superblock.generation = 0;
    let sb_ab = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B);
    let mut envelope = VolumeSuperblock {
        superblock,
        metadata_version,
    };
    sb_ab.store(backing, &mut envelope)?; // side A, gen 1
    sb_ab.store(backing, &mut envelope)?; // side B, gen 2
    backing.sync_dir("")?;

    Ok(envelope.superblock)
}

/// Load the current superblock of an existing volume.
pub fn load_superblock(backing: &dyn Backing) -> Result<Superblock, FormatError> {
    Ok(load_volume_superblock(backing)?.superblock)
}
