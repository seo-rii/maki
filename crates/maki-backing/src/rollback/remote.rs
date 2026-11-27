//! Each remote session writes only its own physical namespace. A revoked
//! session may finish an already-started write, but cannot publish or reclaim
//! any page of the root the next session copies.
use super::*;
use crate::remote_witness::{
    namespace, Action, Descriptor, Phase, Record, Request, Rpc, SessionAuthorization,
};
use crate::witness::Anchor;

use super::enrollment::Enrollment;
use super::gc::{namespace_fence, GcReport, OperationGuard, OPERATION_LOCK, TOMBSTONE};

const REMOTE_MAGIC: &[u8] = b"MAKI-REMOTE-WITNESS-COW-V2\n";

pub(super) enum Witness {
    Local(FileWitness),
    Remote(Box<RemoteSession>),
}

impl Witness {
    pub(super) fn anchor(&self) -> &Anchor {
        match self {
            Self::Local(witness) => witness.anchor(),
            Self::Remote(witness) => &witness.descriptor.anchor,
        }
    }
    pub(super) fn verify_current(&self) -> io::Result<()> {
        match self {
            Self::Local(witness) => witness.verify_current(),
            Self::Remote(witness) => {
                if inspect(witness.rpc.as_ref())? != witness.record {
                    return Err(invalid("remote writer revoked or witness changed"));
                }
                Ok(())
            }
        }
    }
    /// Whether a failed freshness check stops the session. A local witness
    /// records proven anchor changes and uncertain publications itself; a
    /// transient read failure only refuses this operation. A remote Inspect
    /// changes nothing, so a witness
    /// that could not be asked (timeout, refused or reset connection, a
    /// local socket error, an unavailable quorum) only refuses this
    /// operation; the next check
    /// either matches again or observes the change (BUG-103). A mismatch,
    /// an invalid or denied answer stops the session for good. The kinds
    /// match the ones the failover client treats as final.
    pub(super) fn stops_session(&self, error: &io::Error) -> bool {
        match self {
            Self::Local(witness) => witness.is_poisoned(),
            Self::Remote(_) => stops_remote_session(error),
        }
    }
    pub(super) fn advance(&mut self, root: [u8; 32]) -> io::Result<()> {
        match self {
            Self::Local(witness) => witness.advance(root),
            Self::Remote(witness) => {
                let anchor = Anchor {
                    identity: witness.descriptor.anchor.identity,
                    generation: witness
                        .descriptor
                        .anchor
                        .generation
                        .checked_add(1)
                        .ok_or_else(|| invalid("remote generation exhausted"))?,
                    root,
                };
                let record = transact(
                    witness.rpc.as_ref(),
                    &witness.record,
                    &witness.authorization,
                    Action::Advance {
                        anchor: anchor.clone(),
                    },
                )?;
                let mut descriptor = witness.descriptor.clone();
                descriptor.anchor = anchor;
                if record.current.as_ref() != Some(&descriptor)
                    || record.fence != witness.record.fence
                    || record.session != witness.record.session
                    || record.phase != Phase::Active
                {
                    return Err(invalid("remote advance response does not match candidate"));
                }
                witness.record = record;
                witness.descriptor = descriptor;
                Ok(())
            }
        }
    }
}

/// Whether a failed remote freshness check stops a session for good
/// ([`Witness::stops_session`]): a mismatch, an invalid or denied answer.
pub(super) fn stops_remote_session(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::NotFound
    )
}

pub(super) struct RemoteSession {
    root: Arc<FileBacking>,
    rpc: Arc<dyn Rpc>,
    record: Record,
    descriptor: Descriptor,
    authorization: SessionAuthorization,
}

impl Drop for RemoteSession {
    fn drop(&mut self) {
        // A failed or ambiguous release leaves the authority occupied. The
        // operator must explicitly take over; Drop never lowers its fence.
        let _ = transact(
            self.rpc.as_ref(),
            &self.record,
            &self.authorization,
            Action::Release,
        );
    }
}

pub(super) fn inspect(rpc: &dyn Rpc) -> io::Result<Record> {
    let record = rpc.call(&Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
        authorization: None,
    })?;
    record.validate()?;
    Ok(record)
}

fn transact(
    rpc: &dyn Rpc,
    expected: &Record,
    authorization: &SessionAuthorization,
    action: Action,
) -> io::Result<Record> {
    let request = Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: Some(expected.clone()),
        action,
        authorization: Some(authorization.clone()),
    };
    let record = match rpc.call(&request) {
        Ok(record) => record,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput
                    | io::ErrorKind::InvalidData
                    | io::ErrorKind::PermissionDenied
                    | io::ErrorKind::WouldBlock
            ) =>
        {
            return Err(error)
        }
        // Retry only this exact operation. A response may have been lost after
        // the independent authority durably committed it.
        Err(_) => rpc.call(&request)?,
    };
    record.validate()?;
    if record.identity != expected.identity || record.last_operation != request.operation_id {
        return Err(invalid("remote transaction response identity mismatch"));
    }
    Ok(record)
}

/// A descriptor-confined view; all operations stay beneath a pinned root fd.
struct Scope {
    root: Arc<dyn Backing>,
    prefix: String,
}
impl Scope {
    fn path(&self, name: &str) -> io::Result<String> {
        path::validate(name, true)?;
        Ok(if name.is_empty() {
            self.prefix.clone()
        } else {
            format!("{}/{name}", self.prefix)
        })
    }
}
impl Backing for Scope {
    fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.root.open(&self.path(name)?, create)
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        self.root.exists(&self.path(name)?)
    }
    fn remove(&self, name: &str) -> io::Result<()> {
        self.root.remove(&self.path(name)?)
    }
    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.root.rename(&self.path(from)?, &self.path(to)?)
    }
    fn create_dir_all(&self, name: &str) -> io::Result<()> {
        self.root.create_dir_all(&self.path(name)?)
    }
    fn list(&self, name: &str) -> io::Result<Vec<String>> {
        self.root.list(&self.path(name)?)
    }
    fn sync_dir(&self, name: &str) -> io::Result<()> {
        self.root.sync_dir(&self.path(name)?)
    }
    fn try_lock(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.root.try_lock(&self.path(name)?)
    }
    fn is_read_only(&self) -> bool {
        self.root.is_read_only()
    }
    fn try_lock_shared_existing(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.root.try_lock_shared_existing(&self.path(name)?)
    }
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.root.free_bytes()
    }
}

fn remote_root(root: &Path, create: bool) -> io::Result<Arc<FileBacking>> {
    open_root(root, create, false)
}

/// The snapshot root a restore copies from, through a read-only view: a
/// restore only reads it, so it may be kept where nothing can change it.
/// [`ReadOnlyRollbackBacking::open_remote`] reads a volume's root so too.
pub(super) fn backup_root(root: &Path) -> io::Result<Arc<FileBacking>> {
    open_root(root, false, true)
}

fn open_root(root: &Path, create: bool, read_only: bool) -> io::Result<Arc<FileBacking>> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote rollback backing requires Linux",
        ));
    }
    if !create && !root.is_dir() {
        return Err(missing());
    }
    let disk = Arc::new(if read_only {
        FileBacking::read_only(root)?
    } else {
        FileBacking::new(root)?
    });
    if !create {
        let marker = disk.open(MARKER, false)?;
        let mut bytes = vec![0; REMOTE_MAGIC.len()];
        if marker.len()? != bytes.len() as u64 {
            return Err(invalid("not a remote rollback backing"));
        }
        marker.read_at(0, &mut bytes)?;
        if bytes != REMOTE_MAGIC {
            return Err(invalid("not a remote rollback backing"));
        }
    }
    Ok(disk)
}

/// Refuse a root in which a creation has published anything. What may be
/// there is what a creation leaves before its format marker is published:
/// the root locks, the marker under its staging name, and, from a release
/// that wrote the marker in place, a marker that was created and never
/// completely written. Such a root holds no namespace, tombstone or binding,
/// so no volume data and nothing that names a volume, and no authority has
/// accepted anything in it: a creation claims its authority only once the
/// marker and the binding are durable. For rollback protection it is an
/// empty directory. A complete marker is a creation that got further, which
/// enrollment recovery continues.
///
/// `creation` is the binding of the creation that asks, and a snapshot
/// destination has none. A creation also continues a root in which the
/// binding outlived the marker. A release whose enrollment recovery staged
/// the binding before the marker's name was durable could leave that after
/// a power loss: the binding under its staging name, which nothing reads
/// and the creation writes again from the start, or published. A published
/// binding is accepted only if it is exactly `creation`, the binding this
/// creation would write. The caller has established that the authority of
/// that identity is released and was never activated, so no volume was ever
/// enrolled under it, here or anywhere, and the root holds nothing else. A
/// binding for another authority or capacity belongs to another creation,
/// and one that cannot be read cannot be told from a damaged one: both are
/// refused and left as they are.
fn require_empty_remote_root(disk: &dyn Backing, creation: Option<&Enrollment>) -> io::Result<()> {
    examine_remote_root(disk, creation)?.map_err(|occupied| occupied.refusal())
}

/// What keeps a creation from continuing a root.
enum Occupied {
    /// An entry no creation leaves before its marker is published, or a
    /// marker that is complete or foreign.
    NotEmpty,
    /// A staged name that holds something a creation cannot write again
    /// from the start, with what opening it answered.
    NotReplaceable(&'static str, io::Error),
    /// A published binding for another authority or capacity.
    AnotherCreation,
    /// A published binding that cannot be read.
    UnreadableBinding,
}

impl Occupied {
    fn refusal(&self) -> io::Error {
        match self {
            Self::NotEmpty | Self::UnreadableBinding => input(NOT_EMPTY),
            Self::NotReplaceable(name, cause) => {
                not_replaceable(name, cause, "remove it, or use an empty backing root")
            }
            Self::AnotherCreation => input(ANOTHER_CREATION),
        }
    }
}

const NOT_EMPTY: &str = "remote enrollment requires an empty backing";
const ANOTHER_CREATION: &str = "this backing root holds the binding of an interrupted creation \
    for another authority or capacity: create the volume with that creation's authority and \
    capacity, or use an empty backing root";

/// `way_out` is what continues the root for the command that refuses it.
fn not_replaceable(name: &str, cause: &io::Error, way_out: &str) -> io::Error {
    input(format!(
        "this backing root holds {name}, which is not a regular file that can be written again \
         ({cause}): {way_out}"
    ))
}

/// A staged name is accepted because the file under it is never read: the
/// next attempt writes it again from the start. That holds only for what
/// this process can open as a file to write, a regular file with one name.
/// A link, a directory, a FIFO or a file with a second name would fail the
/// attempt when it opens the entry. Under the binding's staged name that is
/// after the marker was published: a link or a directory there fails every
/// later attempt the same way, while a FIFO or a second name is removed by
/// the failed attempt and `resume-enrollment` continues the root. A link or
/// a directory under the marker's staged name fails before anything is
/// published, and every attempt, since `publish_marker` can remove neither.
///
/// Returns what opening the entry answered when the answer is about the
/// entry: its kind, its links, or the right to open it. Any other failure
/// (an I/O error, no descriptor left) says nothing about the entry and is
/// the caller's error as it is; a good file must not be called unwritable
/// for it.
pub(super) fn unwritable(disk: &dyn Backing, name: &str) -> io::Result<Option<io::Error>> {
    match disk.open(name, false) {
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::InvalidInput | io::ErrorKind::PermissionDenied
            ) || error
                .raw_os_error()
                .is_some_and(|code| ENTRY_KIND_ERRORS.contains(&code)) =>
        {
            Ok(Some(error))
        }
        Err(error) => Err(error),
    }
}

/// What the system answers an open for an entry that is not a file to open:
/// a symbolic link, a directory, a FIFO or socket nobody reads.
#[cfg(unix)]
const ENTRY_KIND_ERRORS: [i32; 4] = [libc::ELOOP, libc::EISDIR, libc::ENXIO, libc::ENOTDIR];
#[cfg(not(unix))]
const ENTRY_KIND_ERRORS: [i32; 0] = [];

fn examine_remote_root(
    disk: &dyn Backing,
    creation: Option<&Enrollment>,
) -> io::Result<Result<(), Occupied>> {
    let mut binding = false;
    let mut staged = Vec::new();
    for name in disk.list("")? {
        let unpublished = match name.as_str() {
            super::ENROLL_LOCK | OPERATION_LOCK => true,
            super::MARKER_NEXT => {
                staged.push(super::MARKER_NEXT);
                true
            }
            MARKER => super::unwritten_marker(disk, REMOTE_MAGIC)?,
            enrollment::FILE_NEXT => {
                staged.push(enrollment::FILE_NEXT);
                creation.is_some()
            }
            enrollment::FILE => {
                binding = true;
                creation.is_some()
            }
            _ => false,
        };
        if !unpublished {
            return Ok(Err(Occupied::NotEmpty));
        }
    }
    staged.sort_unstable();
    for name in staged {
        if let Some(cause) = unwritable(disk, name)? {
            return Ok(Err(Occupied::NotReplaceable(name, cause)));
        }
    }
    Ok(match (binding, creation) {
        (true, Some(creation)) => match Enrollment::load(disk) {
            Ok(found) if found == *creation => Ok(()),
            Ok(_) => Err(Occupied::AnotherCreation),
            Err(_) => Err(Occupied::UnreadableBinding),
        },
        _ => Ok(()),
    })
}

/// Publish the format marker. Called with both root operation and
/// enrollment locks held. Until it is published the creation can simply be
/// run again (`super::publish_marker`).
///
/// A binding that outlived its marker was accepted as it reads, and readable
/// bytes are not proof of durability. Publishing the marker syncs the
/// directory, which makes every name in it durable: the binding's bytes are
/// written and synced again first, or a power loss could leave a published
/// marker beside a binding that names nothing.
fn initialize_remote_root(disk: &dyn Backing, creation: Option<&Enrollment>) -> io::Result<()> {
    require_empty_remote_root(disk, creation)?;
    if let Some(creation) = creation {
        if disk.exists(enrollment::FILE)? {
            Enrollment::load_or_create(disk, creation.identity, creation.capacity)?;
        }
    }
    super::publish_marker(disk, REMOTE_MAGIC)
}

/// What enrollment recovery writes in the root it has validated, before the
/// independent authority can accept enrollment: the marker again, then the
/// binding. The crash model runs this function, so the order here is the
/// order that is tested.
///
/// A readable legacy marker may be cache-only, and so may its name: the
/// directory sync of the creation that published it may have failed, or the
/// creation may have been killed before it. Where the binding is staged
/// next, as a new file or over one an earlier attempt left, the marker's
/// name is made durable first, so that no power loss leaves a binding
/// without its marker. Where a binding is already published, the directory
/// is not synced here: that would make the name of a binding durable whose
/// bytes may not be, and the rewrite of the binding syncs its bytes and then
/// the directory. A staged binding that cannot be written again is refused
/// before anything is written. Called with both root operation and
/// enrollment locks held.
fn republish_root(disk: &dyn Backing, identity: [u8; 16], capacity: u64) -> io::Result<()> {
    let bound = disk.exists(enrollment::FILE)?;
    // Only this one name is looked for: an entry whose name is not UTF-8 is
    // not it, and is no reason to refuse a root that recovery continues.
    if !bound
        && disk
            .list_skipping_non_utf8("")?
            .iter()
            .any(|name| name == enrollment::FILE_NEXT)
    {
        if let Some(cause) = unwritable(disk, enrollment::FILE_NEXT)? {
            return Err(not_replaceable(
                enrollment::FILE_NEXT,
                &cause,
                "remove it and resume again",
            ));
        }
    }
    let marker = disk.open(MARKER, false)?;
    marker.write_at(0, REMOTE_MAGIC)?;
    marker.set_len(REMOTE_MAGIC.len() as u64)?;
    marker.sync_data()?;
    if !bound {
        disk.sync_dir("")?;
    }
    Enrollment::load_or_create(disk, identity, capacity).map(drop)
}

/// Say what to do with a root that enrollment recovery cannot open because
/// its creation stopped before the marker was published, while the approved
/// authority is still one a creation accepts (released, never activated).
/// Recovery continues a published root with the administrator's approval;
/// this one needs none. A root creation refuses for what it holds under the
/// binding's names gets a message that says what continues it. Under a
/// claimed authority a root without a marker is not an interrupted creation,
/// and keeps its own refusal.
fn unpublished(root: &Path, expected: &Record, capacity: u64, error: io::Error) -> io::Error {
    if expected.phase != Phase::Released {
        return error;
    }
    let creation = Enrollment {
        identity: expected.identity,
        capacity,
    };
    let examined =
        FileBacking::read_only(root).and_then(|disk| examine_remote_root(&disk, Some(&creation)));
    let message = match examined {
        Ok(Ok(())) => {
            "this backing root's creation stopped before it published the format marker: create \
             the volume again instead of resuming"
                .to_string()
        }
        Ok(Err(Occupied::UnreadableBinding)) => {
            "this backing root has no format marker and holds a remote.enrollment that cannot be \
             read: move that file out of the backing root, keep it, and create the volume again"
                .to_string()
        }
        Ok(Err(Occupied::NotEmpty)) | Err(_) => return error,
        Ok(Err(Occupied::NotReplaceable(name, cause))) => {
            not_replaceable(name, &cause, "remove it and create the volume again").to_string()
        }
        Ok(Err(occupied)) => occupied.refusal().to_string(),
    };
    io::Error::new(error.kind(), message)
}

fn collect_after_activation(
    guard: &OperationGuard<'_>,
    rpc: &dyn Rpc,
    only: Option<&BTreeSet<String>>,
) {
    // An accepted root is already durable. GC failure postpones reclamation;
    // it must not turn a successful activation into an ambiguous writer loss.
    // Nothing else reports this pass, and every namespace it leaves behind
    // keeps a whole arena, so say what it could not do. The events carry
    // namespace names and error text only.
    match guard.collect_within(rpc, only) {
        Ok(report) => {
            if let Some(first) = report.skipped_unreadable.first() {
                tracing::warn!(
                    count = report.counts.skipped_unreadable,
                    namespace = %first.name,
                    error = %first.error,
                    "automatic remote GC kept retired writer namespaces it could not examine; \
                     `maki volume gc` lists each with its error"
                );
            }
            if let Some(first) = report.unfinished.first() {
                tracing::warn!(
                    count = report.counts.unfinished,
                    namespace = %first.name,
                    error = %first.error,
                    "automatic remote GC could not finish retiring writer namespaces; \
                     `maki volume gc` lists each with its error"
                );
            }
        }
        Err(error) => tracing::warn!(
            %error,
            "automatic remote GC did not complete; retired writer namespaces stay on the \
             backing until a pass completes (`maki volume gc`)"
        ),
    }
}

/// The only manifest a never-activated authority's session can have written:
/// the empty generation-0 candidate of its initial activation.
fn empty_manifest(identity: [u8; 16], capacity: u64) -> Manifest {
    Manifest {
        format: 1,
        identity,
        generation: 0,
        capacity,
        next_id: 1,
        entries: BTreeMap::new(),
        files: BTreeMap::new(),
    }
}

/// Show that a root resumed for a never-activated authority holds nothing
/// another volume can own, before the root is bound or the authority is
/// claimed. A missing binding proves nothing: activated roots written before
/// the binding existed have none (the restore form of this is BUG-187). Such
/// an authority never accepted a descriptor, so it never advanced, restored
/// or ran GC. Each namespace in its root is the candidate its current claim
/// names, or an abandoned initial candidate whose manifest slots hold the
/// empty generation-0 manifest for this identity and capacity, a torn part
/// of it (a byte is either that byte or a reserved zero), or nothing. A
/// tombstone or any other manifest belongs to another volume's history:
/// refuse, and let automatic GC retire only the namespaces examined here.
fn unactivated_candidates(
    disk: &FileBacking,
    expected: &Record,
    capacity: u64,
) -> io::Result<BTreeSet<String>> {
    let bytes = empty_manifest(expected.identity, capacity).encode()?;
    let mut image = (bytes.len() as u64).to_le_bytes().to_vec();
    image.extend_from_slice(&bytes);
    let pending = namespace(expected.fence, expected.session);
    let foreign = |name: &str| {
        invalid(format!(
            "this backing root holds remote state that a never-activated authority \
             cannot have written ({name}); check backing.root before retrying"
        ))
    };
    let mut candidates = BTreeSet::new();
    let mut after = None;
    loop {
        let page = disk.gc_entries(after.as_deref())?;
        if page.is_empty() {
            break;
        }
        after = page.last().cloned();
        for entry in page {
            // Names Maki writes are ASCII, so one that is not UTF-8 is
            // neither a namespace nor a tombstone of any volume.
            let Ok(entry) = entry.into_string() else {
                continue;
            };
            if entry
                .strip_prefix(TOMBSTONE)
                .is_some_and(|original| namespace_fence(original).is_some())
            {
                return Err(foreign(&entry));
            }
            if namespace_fence(&entry).is_none() {
                // GC never reclaims an unrecognized entry.
                continue;
            }
            if entry != pending {
                let candidate = disk.gc_scope(&entry)?;
                for slot in MANIFESTS {
                    let file = match candidate.open(slot, false) {
                        Ok(file) => file,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(error) => return Err(error),
                    };
                    let mut prefix = vec![0; file.len()?.min(image.len() as u64) as usize];
                    file.read_at(0, &mut prefix)?;
                    if prefix
                        .iter()
                        .zip(&image)
                        .any(|(byte, expected)| *byte != 0 && byte != expected)
                    {
                        return Err(foreign(&entry));
                    }
                }
            }
            candidates.insert(entry);
        }
    }
    Ok(candidates)
}

pub(super) fn scope(root: Arc<dyn Backing>, name: &str) -> io::Result<Arc<dyn Backing>> {
    path::validate(name, false)?;
    if name.contains('/') || !name.starts_with("remote-") {
        return Err(invalid("invalid remote namespace"));
    }
    Ok(Arc::new(Scope {
        root,
        prefix: name.into(),
    }))
}

/// Authenticate the authority's current generation in this root *before* a
/// claim or takeover changes the authority. A configuration that names
/// another volume's witness would otherwise raise that volume's fence (or
/// revoke its live writer) and only then fail to find the data (BUG-107).
/// GC applies the same check before trusting an authority.
pub(super) fn holds_current(disk: &Arc<FileBacking>, record: &Record) -> io::Result<Manifest> {
    let current = record
        .current
        .as_ref()
        .ok_or_else(|| invalid("uninitialized remote backing"))?;
    let source = scope(disk.clone(), &current.namespace)
        .map_err(|_| invalid("remote authority's current namespace is not valid in this root"))?;
    let (manifest, _) = load_generation(source.as_ref(), current).map_err(not_current)?;
    Ok(manifest)
}

/// The refusal of a root in which the authority's current generation does
/// not authenticate (`error` is the InvalidData proof of that), in the
/// words attach, takeover, snapshot and GC all use. Any other error, such
/// as unreadable storage, does not establish a root/authority mismatch: it
/// is returned with its classification and the underlying OS error.
pub(super) fn not_current(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::InvalidData {
        invalid(format!(
            "this backing root does not hold the remote authority's current generation \
             ({error}); check the witness address and backing root before retrying"
        ))
    } else {
        error
    }
}

/// What [`load_generation`] finds in a namespace that holds no candidate
/// for the descriptor, a missing namespace included.
pub(super) fn no_witnessed_manifest() -> io::Error {
    invalid("no exact remote witnessed manifest")
}

pub(super) fn load_generation(
    disk: &dyn Backing,
    descriptor: &Descriptor,
) -> io::Result<(Manifest, Vec<u8>)> {
    let mut storage_error = None;
    for name in MANIFESTS {
        let candidate = (|| {
            let file = disk.open(name, false)?;
            let mut header = [0; 8];
            file.read_at(0, &mut header)?;
            let len = u64::from_le_bytes(header);
            // The length is unauthenticated. A canonical manifest fits its
            // slot, so refuse one the file cannot hold before allocating.
            if len == 0
                || len > manifest_bound(MAX_CAPACITY) - 8
                || len > file.len()?.saturating_sub(8)
            {
                return Err(invalid("invalid remote manifest length"));
            }
            let mut bytes = vec![0; len as usize];
            file.read_at(8, &mut bytes)?;
            if digest(b"maki.rollback.manifest.v1\0", &bytes) != descriptor.anchor.root {
                return Err(invalid("remote root mismatch"));
            }
            let (manifest, canonical) = parse_manifest(&bytes).map_err(|refusal| {
                invalid(match refusal {
                    ManifestRefusal::Encoding => "invalid remote manifest encoding",
                    ManifestRefusal::Content => "invalid remote manifest content",
                    ManifestRefusal::Size => "invalid remote manifest size",
                })
            })?;
            if canonical != bytes
                || manifest.identity != descriptor.anchor.identity
                || manifest.generation != descriptor.anchor.generation
                || file.len()? != manifest_bound(manifest.capacity)
            {
                return Err(invalid(
                    "invalid remote manifest identity or canonical bytes",
                ));
            }
            let arena = disk.open(ARENA, false)?;
            if arena.len()? != manifest.capacity * 2 {
                return Err(invalid("remote arena length mismatch"));
            }
            Ok((manifest, bytes))
        })();
        match candidate {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::InvalidData
                ) => {}
            Err(error) => {
                // Try the redundant copy, but do not report unreadable storage
                // as proven corruption when no exact candidate can be read.
                if storage_error.is_none() {
                    storage_error = Some(error);
                }
            }
        }
    }
    Err(storage_error.unwrap_or_else(no_witnessed_manifest))
}

fn copy_generation(
    source: Option<&dyn Backing>,
    target: &dyn Backing,
    manifest: &Manifest,
    bytes: &[u8],
) -> io::Result<Arc<dyn BackingFile>> {
    let arena = target.open(ARENA, true)?;
    reserve_storage(target, arena.as_ref(), manifest.capacity)?;
    if let Some(source) = source {
        let old = source.open(ARENA, false)?;
        let mut page = vec![0; PAGE as usize];
        for node in manifest.files.values() {
            for reference in node.pages.values() {
                old.read_at(reference.slot * PAGE, &mut page)?;
                if page_digest(&manifest.identity, &page) != reference.hash {
                    return Err(invalid("source page authentication failed"));
                }
                arena.write_at(reference.slot * PAGE, &page)?;
            }
        }
    }
    arena.sync_data()?;
    write_manifest(target, 0, bytes)?;
    target.sync_dir("")?;
    Ok(arena)
}

impl RollbackBacking {
    /// Resume only an independently approved, never-activated authority.
    /// The immutable local identity/capacity binding cannot be replaced.
    pub fn recover_enrollment_remote(
        root: &Path,
        rpc: Arc<dyn Rpc>,
        capacity: u64,
        expected: &Record,
    ) -> io::Result<Self> {
        validate_capacity(capacity)?;
        expected.validate()?;
        if expected.current.is_some() || !matches!(expected.phase, Phase::Released | Phase::Claimed)
        {
            return Err(input(
                "cannot recover enrollment after its first activation",
            ));
        }
        let disk = remote_root(root, false)
            .map_err(|error| unpublished(root, expected, capacity, error))?;
        let guard = OperationGuard::acquire(disk.as_ref())?;
        let _enrollment = disk.try_lock(super::ENROLL_LOCK)?;
        if inspect(rpc.as_ref())? != *expected {
            return Err(invalid("enrollment approval is stale"));
        }
        // The approval proves the authority, not this directory. Refuse a
        // different binding or another volume's state before the root or the
        // authority changes.
        Enrollment::verify_if_present(disk.as_ref(), expected.identity, capacity)?;
        let candidates = unactivated_candidates(&disk, expected, capacity)?;
        republish_root(disk.as_ref(), expected.identity, capacity)?;
        let authorization = SessionAuthorization::generate()?;
        let claim = transact(
            rpc.as_ref(),
            expected,
            &authorization,
            Action::RecoverEnrollment,
        )?;
        let result =
            Self::activate_empty(disk.clone(), capacity, claim, rpc.clone(), authorization)?;
        collect_after_activation(&guard, rpc.as_ref(), Some(&candidates));
        Ok(result)
    }

    pub fn collect_remote(root: &Path, rpc: &dyn Rpc) -> io::Result<GcReport> {
        let disk = remote_root(root, false)?;
        OperationGuard::acquire(disk.as_ref())?.collect(rpc)
    }

    pub fn create_remote(root: &Path, rpc: Arc<dyn Rpc>, capacity: u64) -> io::Result<Self> {
        validate_capacity(capacity)?;
        let expected = inspect(rpc.as_ref())?;
        if expected.current.is_some() || expected.phase != Phase::Released {
            return Err(input("remote witness already enrolled or occupied"));
        }
        let disk = remote_root(root, true)?;
        let guard = OperationGuard::acquire(disk.as_ref())?;
        let _enrollment = disk.try_lock(super::ENROLL_LOCK)?;
        let creation = Enrollment {
            identity: expected.identity,
            capacity,
        };
        initialize_remote_root(disk.as_ref(), Some(&creation))?;
        Enrollment::load_or_create(disk.as_ref(), expected.identity, capacity)?;
        let authorization = SessionAuthorization::generate()?;
        let claim = transact(rpc.as_ref(), &expected, &authorization, Action::Claim)?;
        let result =
            Self::activate_empty(disk.clone(), capacity, claim, rpc.clone(), authorization)?;
        collect_after_activation(&guard, rpc.as_ref(), None);
        Ok(result)
    }

    fn activate_empty(
        disk: Arc<FileBacking>,
        capacity: u64,
        claim: Record,
        rpc: Arc<dyn Rpc>,
        authorization: SessionAuthorization,
    ) -> io::Result<Self> {
        let manifest = empty_manifest(claim.identity, capacity);
        Self::activate_fork(disk, None, manifest, 0, claim, rpc, authorization)
    }

    pub fn open_remote(root: &Path, rpc: Arc<dyn Rpc>) -> io::Result<Self> {
        Self::open_remote_checked(root, rpc, |_| Ok::<_, io::Error>(()))
    }

    /// [`Self::open_remote`], which lets `check` read the authority's current
    /// generation before it claims a writer, and refuses what `check`
    /// refuses with nothing claimed: the authority and the root are as they
    /// were. Attach compares its configuration so.
    ///
    /// `check` runs where the claim would be sent: with the root's operation
    /// lock held exclusively, after the one inspection the open sends and
    /// once the generation that inspection names authenticates in the root
    /// (its manifest, exactly, and the arena's size). It runs only when the
    /// authority is released: otherwise the claim is refused anyway, as it
    /// was. The view it is given ([`ReadOnlyRollbackBacking::before_claim`])
    /// reads only what `check` reads, every page authenticated against that
    /// manifest, and changes nothing. No writer runs in the root meanwhile,
    /// and the claim carries the inspected record, so an authority that
    /// changed in between refuses it.
    pub fn open_remote_checked<E: From<io::Error>>(
        root: &Path,
        rpc: Arc<dyn Rpc>,
        check: impl FnOnce(&ReadOnlyRollbackBacking) -> Result<(), E>,
    ) -> Result<Self, E> {
        let disk = remote_root(root, false)?;
        let guard = OperationGuard::acquire(disk.as_ref())?;
        let expected = inspect(rpc.as_ref())?;
        let manifest = holds_current(&disk, &expected)?;
        if expected.phase == Phase::Released {
            let current = expected
                .current
                .as_ref()
                .ok_or_else(|| invalid("uninitialized remote backing"))?;
            let namespace = scope(disk.clone(), &current.namespace)?;
            check(&ReadOnlyRollbackBacking::before_claim(
                namespace.as_ref(),
                manifest,
            )?)?;
        }
        let authorization = SessionAuthorization::generate()?;
        let claim = transact(rpc.as_ref(), &expected, &authorization, Action::Claim)?;
        let result = Self::fork_current(disk.clone(), claim, rpc.clone(), authorization)?;
        collect_after_activation(&guard, rpc.as_ref(), None);
        Ok(result)
    }

    pub fn takeover_remote(root: &Path, rpc: Arc<dyn Rpc>, expected: &Record) -> io::Result<Self> {
        let disk = remote_root(root, false)?;
        let guard = OperationGuard::acquire(disk.as_ref())?;
        holds_current(&disk, expected)?;
        let authorization = SessionAuthorization::generate()?;
        let claim = transact(rpc.as_ref(), expected, &authorization, Action::Takeover)?;
        let result = Self::fork_current(disk.clone(), claim, rpc.clone(), authorization)?;
        collect_after_activation(&guard, rpc.as_ref(), None);
        Ok(result)
    }

    fn fork_current(
        disk: Arc<FileBacking>,
        claim: Record,
        rpc: Arc<dyn Rpc>,
        authorization: SessionAuthorization,
    ) -> io::Result<Self> {
        let source = claim
            .current
            .as_ref()
            .ok_or_else(|| invalid("uninitialized remote backing"))?;
        let source_disk = scope(disk.clone(), &source.namespace)?;
        let (manifest, _) = load_generation(source_disk.as_ref(), source)?;
        Self::activate_fork(
            disk,
            Some(source_disk),
            manifest,
            source.epoch,
            claim,
            rpc,
            authorization,
        )
    }

    fn activate_fork(
        disk: Arc<FileBacking>,
        source: Option<Arc<dyn Backing>>,
        manifest: Manifest,
        epoch: u64,
        claim: Record,
        rpc: Arc<dyn Rpc>,
        authorization: SessionAuthorization,
    ) -> io::Result<Self> {
        claim.validate()?;
        if !matches!(claim.phase, Phase::Claimed | Phase::RestoreClaimed) {
            return Err(invalid("remote writer was not claimed"));
        }
        let name = namespace(claim.fence, claim.session);
        if disk.exists(&name)? {
            return Err(input("remote writer namespace already exists"));
        }
        disk.create_dir_all(&name)?;
        disk.sync_dir("")?;
        let target = scope(disk.clone(), &name)?;
        let disk_lock = target.try_lock(super::LOCK)?;
        let bytes = manifest.encode()?;
        let arena = copy_generation(source.as_deref(), target.as_ref(), &manifest, &bytes)?;
        disk.sync_dir("")?;
        let descriptor = Descriptor {
            anchor: Anchor {
                identity: manifest.identity,
                generation: manifest.generation,
                root: digest(b"maki.rollback.manifest.v1\0", &bytes),
            },
            epoch,
            namespace: name,
        };
        let record = transact(
            rpc.as_ref(),
            &claim,
            &authorization,
            Action::Activate {
                descriptor: descriptor.clone(),
            },
        )?;
        if record.current.as_ref() != Some(&descriptor)
            || record.phase != Phase::Active
            || record.fence != claim.fence
            || record.session != claim.session
        {
            return Err(invalid(
                "remote activation does not match durable candidate",
            ));
        }
        Ok(Self::assemble_witness(
            target,
            arena,
            Witness::Remote(Box::new(RemoteSession {
                root: disk,
                rpc,
                record,
                descriptor,
                authorization,
            })),
            disk_lock,
            manifest,
            0,
        ))
    }

    /// Source descriptor is an administrator-approved backup root, not an
    /// automatically trusted value obtained from the untrusted backup files.
    pub fn restore_remote(
        root: &Path,
        source_root: &Path,
        source: &Descriptor,
        rpc: Arc<dyn Rpc>,
        expected: &Record,
    ) -> io::Result<Self> {
        expected.validate()?;
        let disk = remote_root(root, false)?;
        let guard = OperationGuard::acquire(disk.as_ref())?;
        // Every operation that changes a root holds its operation lock
        // exclusively, so sharing it keeps them all off the source while it
        // is read, as an exclusive lock did, without needing write access to
        // the snapshot. Everything read from it is authenticated against the
        // approved descriptor before it is used.
        let backup = backup_root(source_root)?;
        let _source_lock = backup.try_lock_shared(OPERATION_LOCK)?;
        let source_disk = scope(backup.clone(), &source.namespace)?;
        let (mut manifest, _) = load_generation(source_disk.as_ref(), source)?;
        let current = expected
            .current
            .as_ref()
            .ok_or_else(|| invalid("cannot restore an unenrolled witness"))?;
        if manifest.identity != expected.identity {
            return Err(invalid(
                "snapshot identity differs from the approved authority",
            ));
        }
        // The approved backup proves the source, not the target directory.
        // Refuse a different enrolled volume before changing the authority or
        // creating a namespace that automatic GC could mistake for its data.
        // A valid binding still permits repair of a damaged current generation.
        if !Enrollment::verify_if_present(disk.as_ref(), expected.identity, manifest.capacity)? {
            // Older activated roots and snapshot copies have no supplementary
            // binding. Only their exact current generation can establish the
            // target identity; never synthesize a binding from the backup.
            let target = holds_current(&disk, expected)?;
            if target.capacity != manifest.capacity {
                return Err(invalid("snapshot capacity differs from the target volume"));
            }
        }
        let generation = current
            .anchor
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("restore generation exhausted"))?;
        let epoch = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| invalid("restore epoch exhausted"))?;
        let authorization = SessionAuthorization::generate()?;
        let claim = transact(
            rpc.as_ref(),
            expected,
            &authorization,
            Action::ClaimRestore {
                source: source.clone(),
            },
        )?;
        manifest.generation = generation;
        let result = Self::activate_fork(
            disk.clone(),
            Some(source_disk),
            manifest,
            epoch,
            claim,
            rpc.clone(),
            authorization,
        )?;
        collect_after_activation(&guard, rpc.as_ref(), None);
        Ok(result)
    }

    /// Refuse an occupied or unreadable destination before claiming a writer.
    /// A missing directory is created by the copy, which rechecks emptiness
    /// under the destination locks even if this preflight succeeded.
    pub fn check_snapshot_destination(target: &Path) -> io::Result<()> {
        match FileBacking::read_only(target) {
            Ok(disk) => require_empty_remote_root(&disk, None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Copy the committed state under the session mutex. The caller must keep
    /// the returned descriptor separately from the potentially rolled-back data.
    pub fn snapshot_remote(&self, target: &Path) -> io::Result<Descriptor> {
        let mut state = self.state.lock();
        state.check()?;
        let (descriptor, source_root) = match &state.witness {
            Witness::Remote(witness) => (witness.descriptor.clone(), witness.root.clone()),
            Witness::Local(_) => return Err(input("snapshot requires remote witness backing")),
        };
        let _source_guard = OperationGuard::acquire(source_root.as_ref())?;
        let disk = remote_root(target, true)?;
        let _target_guard = OperationGuard::acquire(disk.as_ref())?;
        let _enrollment = disk.try_lock(super::ENROLL_LOCK)?;
        initialize_remote_root(disk.as_ref(), None)?;
        disk.create_dir_all(&descriptor.namespace)?;
        disk.sync_dir("")?;
        let scope = scope(disk.clone(), &descriptor.namespace)?;
        let bytes = state.committed.encode()?;
        copy_generation(
            Some(state.disk.as_ref()),
            scope.as_ref(),
            &state.committed,
            &bytes,
        )?;
        disk.sync_dir("")?;
        state.check()?;
        Ok(descriptor)
    }
}

#[cfg(test)]
#[path = "remote_load_tests.rs"]
mod load_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "remote_creation_tests.rs"]
mod creation_tests;
