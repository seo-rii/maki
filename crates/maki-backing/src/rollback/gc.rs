//! Coordinated reclamation of retired remote writer namespaces.

use std::collections::BTreeSet;
use std::io;

use crate::file::GcRemoval;
use crate::remote_witness::{namespace, Action, Record, Request, Rpc};
use crate::{Backing, FileBacking, VolumeLock};

const TOMBSTONE: &str = ".remote-gc-";
const MAGIC: &[u8] = b"MAKI-REMOTE-WITNESS-COW-V2\n";

fn namespace_fence(name: &str) -> Option<u64> {
    let bytes = name.as_bytes();
    if bytes.len() != 56
        || !bytes.starts_with(b"remote-")
        || bytes[23] != b'-'
        || !bytes[7..23]
            .iter()
            .chain(&bytes[24..])
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        || bytes[24..].iter().all(|b| *b == b'0')
    {
        return None;
    }
    u64::from_str_radix(&name[7..23], 16)
        .ok()
        .filter(|fence| *fence != 0)
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

#[derive(Debug, Default, Eq, PartialEq)]
pub struct GcReport {
    pub removed: Vec<String>,
    pub skipped_live: Vec<String>,
    pub skipped_unrecognized: Vec<String>,
    pub retained: Vec<String>,
}

/// Every physical remote fork holds this guard until activation completes.
pub struct OperationGuard<'a> {
    disk: &'a FileBacking,
    _lock: Box<dyn VolumeLock>,
}

impl<'a> OperationGuard<'a> {
    pub fn acquire(disk: &'a FileBacking) -> io::Result<Self> {
        Ok(Self {
            disk,
            _lock: disk.try_lock("remote.operation.lock")?,
        })
    }

    /// Reclaim only lower fencing sessions whose lifetime lock is no longer
    /// held. The caller's root guard excludes every concurrent physical fork.
    /// Authority outages or changes stop reclamation before the next candidate.
    pub fn collect(&self, rpc: &dyn Rpc) -> io::Result<GcReport> {
        let marker = self.disk.open("rollback.format", false)?;
        let mut bytes = [0; MAGIC.len()];
        if marker.len()? != bytes.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC requires remote rollback backing",
            ));
        }
        marker.read_at(0, &mut bytes)?;
        if bytes != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GC requires remote rollback backing",
            ));
        }
        let record = inspect(rpc)?;
        let current = record.current.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "GC requires an enrolled authority",
            )
        })?;
        // The format marker carries no identity. Authenticate the exact
        // physical current root before trusting this authority's fencing floor.
        // This also refuses accidentally configured authorities for other data.
        let current_disk = self.disk.gc_scope(&current.namespace)?;
        super::remote::load_generation(&current_disk, current)?;
        let mut retained = BTreeSet::from([current.namespace.as_str()]);
        if let Some(source) = &record.restore_source {
            retained.insert(source.namespace.as_str());
        }
        let pending = namespace(record.fence, record.session);
        retained.insert(pending.as_str());
        let mut report = GcReport::default();
        for entry in self.disk.gc_entries()? {
            if [
                "rollback.format",
                "remote.enroll.lock",
                "remote.operation.lock",
                "remote.enrollment",
            ]
            .contains(&entry.as_str())
            {
                continue;
            }
            let (original, retired) = entry
                .strip_prefix(TOMBSTONE)
                .map(|name| (name, true))
                .unwrap_or((&entry, false));
            let Some(fence) = namespace_fence(original) else {
                report.skipped_unrecognized.push(entry);
                continue;
            };
            if fence >= record.fence || retained.contains(original) {
                report.retained.push(entry);
                continue;
            }
            if inspect(rpc)? != record {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "GC authority changed",
                ));
            }
            match self.disk.gc_retire(original, retired)? {
                GcRemoval::Removed => report.removed.push(original.to_owned()),
                GcRemoval::Live => report.skipped_live.push(entry),
                GcRemoval::Unrecognized => report.skipped_unrecognized.push(entry),
            }
        }
        Ok(report)
    }
}
