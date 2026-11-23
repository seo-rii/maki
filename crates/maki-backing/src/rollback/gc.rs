//! Coordinated reclamation of retired remote writer namespaces.

use std::collections::BTreeSet;
use std::io;

use crate::file::GcRemoval;
use crate::remote_witness::{namespace, Action, Record, Request, Rpc};
use crate::{Backing, FileBacking, VolumeLock};

pub(super) const TOMBSTONE: &str = ".remote-gc-";
/// Held exclusively by every operation that changes a remote root.
pub(super) const OPERATION_LOCK: &str = "remote.operation.lock";
const MAGIC: &[u8] = b"MAKI-REMOTE-WITNESS-COW-V2\n";
const REPORT_DETAIL_LIMIT: usize = 4096;

pub(super) fn namespace_fence(name: &str) -> Option<u64> {
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
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })?;
    record.validate()?;
    Ok(record)
}

/// Totals across all pages, including names omitted from the report details.
#[derive(Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct GcCounts {
    pub removed: u64,
    pub skipped_live: u64,
    pub skipped_unrecognized: u64,
    pub skipped_unreadable: u64,
    pub unfinished: u64,
    pub retained: u64,
}

/// A lower-fence namespace, or the tombstone of one, that a pass could not
/// open or examine, with the error that stopped it. The pass changed nothing
/// about it and went on; a later pass examines it again.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GcUnreadable {
    pub name: String,
    pub error: String,
}

/// A lower-fence namespace, or the tombstone of one, that passed
/// examination and whose retirement stopped at a step that changes it alone
/// (renaming it to its tombstone, an unlink in it, the sync of its
/// directory, removing it), with the error, which names the step. `name` is
/// the entry as the pass left it: the namespace if renaming it failed, its
/// tombstone otherwise. The pass went on; a later pass resumes it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct GcUnfinished {
    pub name: String,
    pub error: String,
}

/// Each array contains at most the first 4,096 entries in its category.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct GcReport {
    pub removed: Vec<String>,
    pub skipped_live: Vec<String>,
    pub skipped_unrecognized: Vec<String>,
    pub skipped_unreadable: Vec<GcUnreadable>,
    pub unfinished: Vec<GcUnfinished>,
    pub retained: Vec<String>,
    pub counts: GcCounts,
    pub details_truncated: bool,
}

enum Disposition {
    Removed,
    Live,
    Unrecognized,
    Retained,
}

impl GcReport {
    fn record(&mut self, disposition: Disposition, name: String) {
        let (details, count) = match disposition {
            Disposition::Removed => (&mut self.removed, &mut self.counts.removed),
            Disposition::Live => (&mut self.skipped_live, &mut self.counts.skipped_live),
            Disposition::Unrecognized => (
                &mut self.skipped_unrecognized,
                &mut self.counts.skipped_unrecognized,
            ),
            Disposition::Retained => (&mut self.retained, &mut self.counts.retained),
        };
        *count += 1;
        if details.len() < REPORT_DETAIL_LIMIT {
            details.push(name);
        } else {
            self.details_truncated = true;
        }
    }

    fn unreadable(&mut self, name: String, error: &io::Error) {
        self.counts.skipped_unreadable += 1;
        if self.skipped_unreadable.len() < REPORT_DETAIL_LIMIT {
            self.skipped_unreadable.push(GcUnreadable {
                name,
                error: error.to_string(),
            });
        } else {
            self.details_truncated = true;
        }
    }

    fn unfinished(&mut self, name: String, error: &io::Error) {
        self.counts.unfinished += 1;
        if self.unfinished.len() < REPORT_DETAIL_LIMIT {
            self.unfinished.push(GcUnfinished {
                name,
                error: error.to_string(),
            });
        } else {
            self.details_truncated = true;
        }
    }
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
            _lock: disk.try_lock(OPERATION_LOCK)?,
        })
    }

    /// Reclaim only lower fencing sessions whose lifetime lock is no longer
    /// held. The caller's root guard excludes every concurrent physical fork.
    /// Authority outages or changes stop reclamation before the next candidate.
    ///
    /// What ends a pass with an error is a failure that leaves it unable to
    /// tell what may be deleted, or to delete it durably: the authority
    /// (unavailable, invalid, or changed since the pass began), the root (its
    /// marker, the authority's current generation in it, its binding, its
    /// listing, its mount identity, its syncs), and an entry that changed
    /// identity while the pass retired it, which names that namespace. A
    /// lower-fence namespace the pass cannot open or examine is not such a
    /// failure: nothing about it has been changed and every other candidate
    /// is judged on its own lock and contents, so it is kept, reported under
    /// `skipped_unreadable` with the error, and the pass goes on. Nor is a
    /// step of a retirement that changes that candidate alone (renaming it,
    /// which changes nothing when it fails, an unlink in it, the sync of its
    /// directory, removing it): once renamed, its tombstone is durable, and
    /// every other candidate's deletion rests on its own examination, lock
    /// and durable tombstone. It is kept as the step left it, reported under
    /// `unfinished` with the error, and a later pass resumes it.
    pub fn collect(&self, rpc: &dyn Rpc) -> io::Result<GcReport> {
        self.collect_within(rpc, None)
    }

    /// [`Self::collect`], retiring only the named namespaces when `only` is
    /// set; every other entry is retained. Enrollment recovery reclaims
    /// nothing it has not itself shown to belong to its authority.
    pub(super) fn collect_within(
        &self,
        rpc: &dyn Rpc,
        only: Option<&BTreeSet<String>>,
    ) -> io::Result<GcReport> {
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
        let capacity = super::remote::load_generation(&current_disk, current)?
            .0
            .capacity;
        // A foreign current namespace may already have been copied into this
        // root. Its valid manifest must not authorize deleting the enrolled
        // volume's data. Legacy roots without a binding retain the exact
        // current-generation proof above, including partial tombstone cleanup.
        super::enrollment::Enrollment::verify_if_present(self.disk, record.identity, capacity)?;
        let mut retained = BTreeSet::from([current.namespace.as_str()]);
        if let Some(source) = &record.restore_source {
            retained.insert(source.namespace.as_str());
        }
        let pending = namespace(record.fence, record.session);
        retained.insert(pending.as_str());
        let mut report = GcReport::default();
        let mut after = None;
        loop {
            let page = self.disk.gc_entries(after.as_deref())?;
            if page.is_empty() {
                break;
            }
            // Save the original name before retirement can rename it. A
            // successful retirement removes its tombstone in this pass, and
            // an unfinished one leaves it before this cursor (tombstones sort
            // first) for the next pass; an error stops collection, and the
            // next pass starts at the root.
            after = page.last().cloned();
            for entry in page {
                // Namespaces, tombstones and root files are ASCII. A name
                // that is not UTF-8 is unknown like any other: keep it.
                let entry = match entry.into_string() {
                    Ok(entry) => entry,
                    Err(entry) => {
                        let name = entry.to_string_lossy().into_owned();
                        report.record(Disposition::Unrecognized, name);
                        continue;
                    }
                };
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
                    report.record(Disposition::Unrecognized, entry);
                    continue;
                };
                if fence >= record.fence
                    || retained.contains(original)
                    || only.is_some_and(|names| !names.contains(original))
                {
                    report.record(Disposition::Retained, entry);
                    continue;
                }
                if inspect(rpc)? != record {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "GC authority changed",
                    ));
                }
                let removal = self.disk.gc_retire(original, retired).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("GC stopped while retiring {entry}: {error}"),
                    )
                })?;
                match removal {
                    GcRemoval::Removed => report.record(Disposition::Removed, original.to_owned()),
                    GcRemoval::Live => report.record(Disposition::Live, entry),
                    GcRemoval::Unrecognized => report.record(Disposition::Unrecognized, entry),
                    GcRemoval::Unreadable(error) => report.unreadable(entry, &error),
                    GcRemoval::Unfinished { tombstone, error } => {
                        let name = if tombstone && !retired {
                            format!("{TOMBSTONE}{original}")
                        } else {
                            entry
                        };
                        report.unfinished(name, &error)
                    }
                }
            }
        }
        Ok(report)
    }
}
