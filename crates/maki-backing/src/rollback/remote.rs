//! Each remote session writes only its own physical namespace. A revoked
//! session may finish an already-started write, but cannot publish or reclaim
//! any page of the root the next session copies.
use super::*;
use crate::remote_witness::{namespace, Action, Descriptor, Phase, Record, Request, Rpc};
use crate::witness::Anchor;

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

pub(super) struct RemoteSession {
    rpc: Arc<dyn Rpc>,
    record: Record,
    descriptor: Descriptor,
}

impl Drop for RemoteSession {
    fn drop(&mut self) {
        // A failed or ambiguous release leaves the authority occupied. The
        // operator must explicitly take over; Drop never lowers its fence.
        let _ = transact(self.rpc.as_ref(), &self.record, Action::Release);
    }
}

fn inspect(rpc: &dyn Rpc) -> io::Result<Record> {
    let record = rpc.call(&Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })?;
    record.validate()?;
    Ok(record)
}

fn transact(rpc: &dyn Rpc, expected: &Record, action: Action) -> io::Result<Record> {
    let request = Request {
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: Some(expected.clone()),
        action,
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
    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.root.free_bytes()
    }
}

fn remote_root(root: &Path, create: bool) -> io::Result<Arc<dyn Backing>> {
    if !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "remote rollback backing requires Linux",
        ));
    }
    if !create && !root.is_dir() {
        return Err(missing());
    }
    let disk: Arc<dyn Backing> = Arc::new(FileBacking::new(root)?);
    if create {
        let _lock = disk.try_lock("remote.enroll.lock")?;
        if disk
            .list("")?
            .iter()
            .any(|name| name != "remote.enroll.lock")
        {
            return Err(input("remote enrollment requires an empty backing"));
        }
        let marker = disk.open(MARKER, true)?;
        marker.write_at(0, REMOTE_MAGIC)?;
        marker.sync_data()?;
        disk.sync_dir("")?;
    } else {
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

fn scope(root: Arc<dyn Backing>, name: &str) -> io::Result<Arc<dyn Backing>> {
    path::validate(name, false)?;
    if name.contains('/') || !name.starts_with("remote-") {
        return Err(invalid("invalid remote namespace"));
    }
    Ok(Arc::new(Scope {
        root,
        prefix: name.into(),
    }))
}

fn load_generation(disk: &dyn Backing, descriptor: &Descriptor) -> io::Result<(Manifest, Vec<u8>)> {
    for name in MANIFESTS {
        let candidate = (|| {
            let file = disk.open(name, false)?;
            let mut header = [0; 8];
            file.read_at(0, &mut header)?;
            let len = u64::from_le_bytes(header);
            if len == 0 || len > manifest_bound(MAX_CAPACITY) - 8 {
                return Err(invalid("invalid remote manifest length"));
            }
            let mut bytes = vec![0; len as usize];
            file.read_at(8, &mut bytes)?;
            if digest(b"maki.rollback.manifest.v1\0", &bytes) != descriptor.anchor.root {
                return Err(invalid("remote root mismatch"));
            }
            let manifest: Manifest = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            manifest.validate()?;
            if manifest.encode()? != bytes
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
        if let Ok(value) = candidate {
            return Ok(value);
        }
    }
    Err(invalid("no exact remote witnessed manifest"))
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
    pub fn create_remote(root: &Path, rpc: Arc<dyn Rpc>, capacity: u64) -> io::Result<Self> {
        validate_capacity(capacity)?;
        let expected = inspect(rpc.as_ref())?;
        if expected.current.is_some() || expected.phase != Phase::Released {
            return Err(input("remote witness already enrolled or occupied"));
        }
        let disk = remote_root(root, true)?;
        let claim = transact(rpc.as_ref(), &expected, Action::Claim)?;
        let manifest = Manifest {
            format: 1,
            identity: claim.identity,
            generation: 0,
            capacity,
            next_id: 1,
            entries: BTreeMap::new(),
            files: BTreeMap::new(),
        };
        Self::activate_fork(disk, None, manifest, 0, claim, rpc)
    }

    pub fn open_remote(root: &Path, rpc: Arc<dyn Rpc>) -> io::Result<Self> {
        let disk = remote_root(root, false)?;
        let expected = inspect(rpc.as_ref())?;
        let claim = transact(rpc.as_ref(), &expected, Action::Claim)?;
        Self::fork_current(disk, claim, rpc)
    }

    pub fn takeover_remote(root: &Path, rpc: Arc<dyn Rpc>, expected: &Record) -> io::Result<Self> {
        let disk = remote_root(root, false)?;
        let claim = transact(rpc.as_ref(), expected, Action::Takeover)?;
        Self::fork_current(disk, claim, rpc)
    }

    fn fork_current(disk: Arc<dyn Backing>, claim: Record, rpc: Arc<dyn Rpc>) -> io::Result<Self> {
        let source = claim
            .current
            .as_ref()
            .ok_or_else(|| invalid("uninitialized remote backing"))?;
        let source_disk = scope(disk.clone(), &source.namespace)?;
        let (manifest, _) = load_generation(source_disk.as_ref(), source)?;
        Self::activate_fork(disk, Some(source_disk), manifest, source.epoch, claim, rpc)
    }

    fn activate_fork(
        disk: Arc<dyn Backing>,
        source: Option<Arc<dyn Backing>>,
        manifest: Manifest,
        epoch: u64,
        claim: Record,
        rpc: Arc<dyn Rpc>,
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
        let disk_lock = target.try_lock("rollback.lock")?;
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
                rpc,
                record,
                descriptor,
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
        let disk = remote_root(root, false)?;
        let backup = remote_root(source_root, false)?;
        let source_disk = scope(backup, &source.namespace)?;
        let (mut manifest, _) = load_generation(source_disk.as_ref(), source)?;
        let current = expected
            .current
            .as_ref()
            .ok_or_else(|| invalid("cannot restore an unenrolled witness"))?;
        let generation = current
            .anchor
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("restore generation exhausted"))?;
        let epoch = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| invalid("restore epoch exhausted"))?;
        let claim = transact(
            rpc.as_ref(),
            expected,
            Action::ClaimRestore {
                source: source.clone(),
            },
        )?;
        manifest.generation = generation;
        Self::activate_fork(disk, Some(source_disk), manifest, epoch, claim, rpc)
    }

    /// Copy the committed state under the session mutex. The caller must keep
    /// the returned descriptor separately from the potentially rolled-back data.
    pub fn snapshot_remote(&self, target: &Path) -> io::Result<Descriptor> {
        let mut state = self.state.lock();
        state.check()?;
        let descriptor = match &state.witness {
            Witness::Remote(witness) => witness.descriptor.clone(),
            Witness::Local(_) => return Err(input("snapshot requires remote witness backing")),
        };
        let disk = remote_root(target, true)?;
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
