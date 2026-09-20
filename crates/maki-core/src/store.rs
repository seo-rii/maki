//! Slot store: shard data files, allocation maps, shard catalog (SPEC §22).
//!
//! Read classification (SPEC §22):
//! - shard absent from catalog → unwritten zero
//! - allocation bit 0 → unwritten zero
//! - bit 1, slot invalid/missing → EIO (never fabricated data)
//! - bit 1, slot valid → ciphertext
//!
//! Shard creation protocol: data file + allocation map are created, synced,
//! and their dirents made durable *before* the catalog commits the shard —
//! a crash in between leaves harmless orphans, never a cataloged shard with
//! missing metadata. Every catalog commit publishes the whole in-memory
//! catalog, so a shard adopted at open (see below) gets its map stored
//! before *any* commit — the one in `persist_allocations` and the one made
//! by another shard's creation alike (K-03).
//!
//! Allocation persistence: a shard's dirty flag is cleared only after the
//! data-directory fsync that makes the fresh A/B copy's dirent durable has
//! succeeded. Clearing it earlier lets a retried checkpoint skip the step,
//! after which a crash can drop the never-dir-synced copy and reclassify
//! written slots as unwritten zeros.
//!
//! Slot headers are authoritative; the catalog and the allocation maps are
//! accelerators. An A/B record can legitimately fall back to its older side
//! (a torn write during a crash, or later damage to the newer copy), and the
//! older side does not know about the newest shard or the most recently
//! allocated slots. Treating "bit 0" as unwritten would then return zeros
//! for checkpointed data. So a data file the catalog does not list is
//! adopted at open, and a slot whose bit is 0 is probed: a header that
//! decodes for that unit is served (or, if its body is damaged, reported as
//! EIO), and only a slot with no valid header reads as zeros.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use maki_backing::{Backing, BackingFile};
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::catalog::ShardCatalog;
use maki_format::geometry::Geometry;
use maki_format::layout;
use maki_format::slot::SlotHeader;
use maki_format::superblock::{load_volume_superblock, SUPERBLOCK_VERSION_V3};
use maki_format::FormatError;

use crate::error::CoreError;
use crate::fp;

pub enum SlotRead {
    /// Unwritten: reads as zeros.
    Zero,
    /// Valid ciphertext with its write sequence.
    Ciphertext { write_sequence: u64, data: Vec<u8> },
}

struct Shard {
    alloc: AllocationMap,
    alloc_ab: AbStore,
    data: Arc<dyn BackingFile>,
    dirty_alloc: bool,
    /// At least one allocation-map copy of this shard is on disk. False only
    /// for a shard adopted at open with no valid copy: the catalog must not
    /// name it until `commit_adopted_maps` has stored one (K-03).
    map_stored: bool,
    discard: Option<AllocationMap>,
    discard_ab: Option<AbStore>,
    dirty_discard: bool,
}

pub(crate) struct CheckpointSlotTarget {
    unit: u64,
    offset: u64,
    data: Arc<dyn BackingFile>,
}

pub(crate) struct CheckpointSlotPlan {
    targets: Vec<CheckpointSlotTarget>,
    shards: Vec<Arc<dyn BackingFile>>,
    max_ciphertext_size: usize,
}

impl CheckpointSlotPlan {
    pub(crate) fn write(
        &self,
        index: usize,
        write_sequence: u64,
        ciphertext: &[u8],
    ) -> Result<(), CoreError> {
        if ciphertext.len() > self.max_ciphertext_size {
            return Err(CoreError::Corrupt(format!(
                "ciphertext {} exceeds max {}",
                ciphertext.len(),
                self.max_ciphertext_size
            )));
        }
        let target = self.targets.get(index).ok_or_else(|| {
            CoreError::Corrupt("checkpoint slot plan does not match its snapshot".into())
        })?;
        let header = SlotHeader {
            unit_index: target.unit,
            write_sequence,
            ciphertext_len: ciphertext.len() as u32,
            flags: 0,
            ciphertext_crc: crc32fast::hash(ciphertext),
        };
        let mut buf = Vec::with_capacity(64 + ciphertext.len());
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(ciphertext);
        target.data.write_at(target.offset, &buf)?;
        Ok(())
    }

    pub(crate) fn sync_shards(&self) -> Result<(), CoreError> {
        for shard in &self.shards {
            fp("checkpoint.shard_sync")?;
            shard.sync_data()?;
        }
        Ok(())
    }
}

pub struct SlotStore {
    backing: Arc<dyn Backing>,
    geometry: Geometry,
    catalog: ShardCatalog,
    catalog_ab: AbStore,
    /// Shards adopted from the data directory that the loaded catalog copy
    /// did not list; persisted with the next allocation persist.
    catalog_dirty: bool,
    shards: HashMap<u64, Shard>,
    /// Units whose bit was repaired from slot headers at open.
    repaired_units: Vec<u64>,
    discard_enabled: bool,
    /// A bounded post-recovery scan retries physical release of persisted
    /// tombstones. No extra per-unit bitmap or payload history is retained.
    reclaim_cursor: Option<(u64, u64)>,
}

/// Shard index of a `shard-XXXXXXXX.dat` file name, verified by
/// round-tripping through [`layout::shard_data`].
fn parse_shard_data_name(name: &str) -> Option<u64> {
    let hex = name.strip_prefix("shard-")?.strip_suffix(".dat")?;
    let idx = u64::from_str_radix(hex, 16).ok()?;
    (layout::shard_data(idx) == format!("{}/{name}", layout::DATA_DIR)).then_some(idx)
}

/// Header of a slot whose allocation bit is clear, if one decodes for
/// `unit`. A short file, a hole, or garbage all mean "unwritten".
fn probe_header(
    geometry: &Geometry,
    shard: &Shard,
    unit: u64,
    in_shard: u64,
    file_len: u64,
) -> Result<Option<SlotHeader>, CoreError> {
    let offset = geometry.slot_offset(in_shard);
    if offset + 64 > file_len {
        return Ok(None);
    }
    let mut header_bytes = [0u8; 64];
    shard
        .data
        .read_at(offset, &mut header_bytes)
        .map_err(|e| CoreError::Corrupt(format!("unit {unit}: slot read failed: {e}")))?;
    Ok(SlotHeader::decode(&header_bytes)
        .ok()
        .filter(|h| h.unit_index == unit && h.write_sequence > 0))
}

/// Units of `shard` whose bit is clear but whose slot holds a header for
/// them. One header read per cleared slot.
fn probe_shard(geometry: &Geometry, shard: &Shard, shard_idx: u64) -> Result<Vec<u64>, CoreError> {
    let len = shard.data.len()?;
    let per_shard = geometry.units_per_shard();
    let mut out = Vec::new();
    for in_shard in 0..shard.alloc.units() {
        if shard
            .discard
            .as_ref()
            .is_some_and(|discard| discard.get(in_shard))
        {
            continue;
        }
        if shard.alloc.get(in_shard) {
            continue;
        }
        let unit = shard_idx * per_shard + in_shard;
        if probe_header(geometry, shard, unit, in_shard, len)?.is_some() {
            out.push(unit);
        }
    }
    Ok(out)
}

impl SlotStore {
    /// Capture immutable positional-I/O targets for already reserved units.
    /// A journal record is never published before `reserve_slot`, so a
    /// missing shard here is an internal/on-disk contradiction rather than
    /// an opportunity to create metadata outside the volume lock.
    pub(crate) fn checkpoint_slot_plan(
        &self,
        units: impl IntoIterator<Item = u64>,
    ) -> Result<CheckpointSlotPlan, CoreError> {
        let mut targets = Vec::new();
        let mut shard_files = std::collections::BTreeMap::new();
        for unit in units {
            let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
            let shard = self.shards.get(&shard_idx).ok_or_else(|| {
                CoreError::Corrupt(format!(
                    "checkpoint unit {unit} has no reserved shard {shard_idx}"
                ))
            })?;
            targets.push(CheckpointSlotTarget {
                unit,
                offset: self.geometry.slot_offset(in_shard),
                data: shard.data.clone(),
            });
            shard_files
                .entry(shard_idx)
                .or_insert_with(|| shard.data.clone());
        }
        Ok(CheckpointSlotPlan {
            targets,
            shards: shard_files.into_values().collect(),
            max_ciphertext_size: self.geometry.max_ciphertext_size as usize,
        })
    }

    /// Open the store, loading catalog and validating every cataloged
    /// shard's allocation metadata (SPEC §27 "validate allocation metadata").
    /// Data files the catalog copy does not list are adopted (see module
    /// docs); a missing allocation map for such a shard is an empty one.
    pub fn open(backing: Arc<dyn Backing>, geometry: Geometry) -> Result<Self, CoreError> {
        let discard_enabled =
            load_volume_superblock(backing.as_ref())?.metadata_version == SUPERBLOCK_VERSION_V3;
        let catalog_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
        let mut catalog = catalog_ab
            .load::<ShardCatalog>(backing.as_ref())?
            .ok_or_else(|| CoreError::Corrupt("no valid shard catalog".to_string()))?;

        let mut catalog_dirty = false;
        let mut orphans: Vec<u64> = Vec::new();
        for name in backing.list(layout::DATA_DIR)? {
            if let Some(idx) = parse_shard_data_name(&name) {
                if !catalog.contains(idx) && idx < geometry.num_shards() {
                    orphans.push(idx);
                }
            }
        }
        orphans.sort_unstable();
        for idx in &orphans {
            tracing::warn!(
                shard = idx,
                "shard data file not listed by the loaded catalog copy; adopting it"
            );
            catalog.insert(*idx);
            catalog_dirty = true;
        }
        let adopted: BTreeSet<u64> = orphans.into_iter().collect();

        let mut shards = HashMap::new();
        let mut repaired_units: Vec<u64> = Vec::new();
        for shard_idx in catalog.shard_indices() {
            if shard_idx >= geometry.num_shards() {
                return Err(CoreError::Corrupt(format!(
                    "catalog shard {shard_idx} out of range"
                )));
            }
            let alloc_ab = AbStore::new(
                layout::shard_alloc_a(shard_idx),
                layout::shard_alloc_b(shard_idx),
            );
            let (side_a, side_b) = alloc_ab.side_generations::<AllocationMap>(backing.as_ref())?;
            let (alloc, dirty_alloc, map_stored) =
                match alloc_ab.load::<AllocationMap>(backing.as_ref())? {
                    // An adopted shard's copy may be readable only from the
                    // page cache (its sync failed, then the process
                    // restarted — K-01): nothing proves it durable, so it is
                    // re-stored before any catalog commit names the shard.
                    Some(alloc) => (alloc, false, !adopted.contains(&shard_idx)),
                    // A shard the catalog never committed may have died before
                    // its (empty) map was stored: start it empty.
                    None if adopted.contains(&shard_idx) => {
                        (AllocationMap::new(geometry.units_per_shard()), true, false)
                    }
                    // SPEC §27: a cataloged shard with no valid copy refuses
                    // attach rather than guess (offline repair territory).
                    None => {
                        return Err(CoreError::Corrupt(format!(
                            "shard {shard_idx}: no valid allocation map copy"
                        )))
                    }
                };
            if alloc.units() != geometry.units_per_shard() {
                return Err(CoreError::Corrupt(format!(
                    "shard {shard_idx}: allocation map size mismatch"
                )));
            }
            let data = backing
                .open(&layout::shard_data(shard_idx), false)
                .map_err(|e| {
                    CoreError::Corrupt(format!("shard {shard_idx}: data file missing: {e}"))
                })?;
            let mut shard = Shard {
                alloc,
                alloc_ab,
                data,
                dirty_alloc,
                map_stored,
                discard: None,
                discard_ab: None,
                dirty_discard: false,
            };
            if discard_enabled {
                let discard_ab = AbStore::new(
                    layout::shard_discard_a(shard_idx),
                    layout::shard_discard_b(shard_idx),
                );
                let (discard_a, discard_b) =
                    discard_ab.side_generations::<AllocationMap>(backing.as_ref())?;
                let discard = discard_ab
                    .load::<AllocationMap>(backing.as_ref())?
                    .ok_or_else(|| {
                        CoreError::Corrupt(format!("shard {shard_idx}: no valid discard map copy"))
                    })?;
                if discard.units() != geometry.units_per_shard() {
                    return Err(CoreError::Corrupt(format!(
                        "shard {shard_idx}: discard map size mismatch"
                    )));
                }
                shard.discard = Some(discard);
                shard.discard_ab = Some(discard_ab);
                // Both sides may decode yet diverge after an interrupted
                // two-copy publication. Always rewrite the selected logical
                // state into both copies before journal reclamation/punching.
                let _ = (discard_a, discard_b);
                shard.dirty_discard = true;
            }
            // With one copy invalid or absent the loaded copy may be the
            // older generation, which does not list the newest slots: audit
            // the shard's headers and repair the map in memory (persisted
            // by the next allocation persist). Healthy shards (both copies
            // valid) skip this.
            if side_a.is_none() || side_b.is_none() {
                let found = probe_shard(&geometry, &shard, shard_idx)?;
                if !found.is_empty() {
                    tracing::warn!(
                        shard = shard_idx,
                        slots = found.len(),
                        "allocation map copy behind the slots; repaired from slot headers"
                    );
                    for unit in &found {
                        let (_, in_shard) = geometry.shard_of_unit(*unit);
                        shard.alloc.set(in_shard, true);
                    }
                    shard.dirty_alloc = true;
                    repaired_units.extend(found);
                }
            }
            shards.insert(shard_idx, shard);
        }

        Ok(Self {
            backing,
            geometry,
            catalog,
            catalog_ab,
            catalog_dirty,
            shards,
            repaired_units,
            discard_enabled,
            reclaim_cursor: None,
        })
    }

    /// Units whose allocation bit was set from their slot header at open
    /// because the loaded allocation copy did not list them (see module
    /// docs). Empty on a healthy volume; the next allocation persist writes
    /// the repaired map.
    pub fn repaired_allocations(&self) -> &[u64] {
        &self.repaired_units
    }

    /// True when a checkpoint should persist metadata even with nothing new
    /// to apply: an adopted shard or a repaired allocation map is pending.
    pub fn has_pending_repairs(&self) -> bool {
        self.catalog_dirty
            || self
                .shards
                .values()
                .any(|s| s.dirty_alloc || s.dirty_discard)
    }

    pub(crate) fn supports_discard(&self) -> bool {
        self.discard_enabled
    }

    pub(crate) fn has_pending_reclamation(&self) -> bool {
        self.reclaim_cursor.is_some()
    }

    /// Call only after bounded replay has applied every surviving record.
    /// A tombstone seen halfway through replay may precede a reserved write.
    pub(crate) fn schedule_reclamation(&mut self) {
        self.reclaim_cursor = self
            .catalog
            .shard_indices()
            .find(|idx| {
                self.shards[idx]
                    .discard
                    .as_ref()
                    .is_some_and(|map| map.set_count() > 0)
            })
            .map(|idx| (idx, 0));
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Number of cataloged shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Make the complete on-disk slot range available before its journal
    /// record can be accepted. A successful Linux reservation uses
    /// `posix_fallocate`, so a later checkpoint cannot lose its completion
    /// space to an unrelated filesystem consumer.
    pub fn reserve_slot(&mut self, unit: u64) -> Result<(), CoreError> {
        if unit >= self.geometry.num_units() {
            return Err(CoreError::Corrupt(format!(
                "unit {unit} beyond the device ({} units)",
                self.geometry.num_units()
            )));
        }
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        if let Err(error) = self.ensure_shard(shard_idx) {
            // Metadata codecs wrap their underlying I/O. At this live write
            // boundary callers need the storage error class (ENOSPC/EIO),
            // not a format classification for otherwise valid metadata.
            return Err(match error {
                CoreError::Format(FormatError::Io(error)) => CoreError::Io(error),
                error => error,
            });
        }
        let shard = self.shards.get(&shard_idx).unwrap();
        shard
            .data
            .allocate_range(self.geometry.slot_offset(in_shard), self.geometry.slot_size)?;
        Ok(())
    }

    /// Every allocated unit, in ascending order (offline check input).
    ///
    /// Allocation maps stay borrowed while unit IDs are streamed. Traversal
    /// stores only the sorted shard indices, so auxiliary memory grows with
    /// the shard count rather than the number of allocated units.
    pub fn allocated_units(&self) -> impl Iterator<Item = u64> + '_ {
        let mut shards: Vec<u64> = self.shards.keys().copied().collect();
        shards.sort_unstable();
        let per_shard = self.geometry.units_per_shard();
        shards.into_iter().flat_map(move |shard_idx| {
            let shard = &self.shards[&shard_idx];
            (0..shard.alloc.units()).filter_map(move |in_shard| {
                (shard.alloc.get(in_shard)
                    && !shard
                        .discard
                        .as_ref()
                        .is_some_and(|discard| discard.get(in_shard)))
                .then_some(shard_idx * per_shard + in_shard)
            })
        })
    }

    /// Lowest allocated unit, if any slot has ever been checkpointed.
    pub fn first_allocated_unit(&self) -> Option<u64> {
        let mut shards: Vec<u64> = self.shards.keys().copied().collect();
        shards.sort_unstable();
        for shard_idx in shards {
            let shard = &self.shards[&shard_idx];
            if shard.alloc.set_count() == 0 {
                continue;
            }
            if let Some(in_shard) = (0..shard.alloc.units()).find(|u| {
                shard.alloc.get(*u)
                    && !shard
                        .discard
                        .as_ref()
                        .is_some_and(|discard| discard.get(*u))
            }) {
                return Some(shard_idx * self.geometry.units_per_shard() + in_shard);
            }
        }
        None
    }

    fn ensure_shard(&mut self, shard_idx: u64) -> Result<(), CoreError> {
        if self.shards.contains_key(&shard_idx) {
            return Ok(());
        }
        // A v3 data-file orphan cannot be interpreted safely without its
        // discard history: an older catalog copy may have omitted a real,
        // previously trimmed shard. Stabilize both empty maps before the
        // first creation of the data file. A crash may leave maps alone;
        // they are harmless and a retry rewrites the same empty state.
        let (discard, discard_ab) = if self.discard_enabled {
            let discard_ab = AbStore::new(
                layout::shard_discard_a(shard_idx),
                layout::shard_discard_b(shard_idx),
            );
            let mut discard = AllocationMap::new(self.geometry.units_per_shard());
            discard_ab.store(self.backing.as_ref(), &mut discard)?;
            discard_ab.store(self.backing.as_ref(), &mut discard)?;
            fp("store.shard_dirsync")?;
            self.backing.sync_dir(layout::DATA_DIR)?;
            (Some(discard), Some(discard_ab))
        } else {
            (None, None)
        };

        // 1. data file, full sparse size, synced
        fp("store.shard_create")?;
        let data_path = layout::shard_data(shard_idx);
        let data = self.backing.open(&data_path, true)?;
        let physical = self.geometry.units_per_shard() * self.geometry.slot_size;
        data.set_len(physical)?;
        data.sync_data()?;
        // 2. Both empty allocation-map copies, synced. Checkpoint alternates
        // between them, so publishing a journal record before the second
        // file exists would leave checkpoint completion exposed to ENOSPC.
        let alloc_ab = AbStore::new(
            layout::shard_alloc_a(shard_idx),
            layout::shard_alloc_b(shard_idx),
        );
        let mut alloc = AllocationMap::new(self.geometry.units_per_shard());
        alloc_ab.store(self.backing.as_ref(), &mut alloc)?;
        alloc_ab.store(self.backing.as_ref(), &mut alloc)?;
        // 3. dirents durable before the catalog names the shard. The commit
        //    below publishes the whole in-memory catalog, so a shard adopted
        //    at open needs its map on disk first as well (K-03 residual: an
        //    interrupted checkpoint after this commit, then a power loss,
        //    otherwise leaves a cataloged shard with no allocation copy,
        //    which every later attach refuses).
        self.commit_adopted_maps()?;
        self.persist_discards()?;
        fp("store.shard_dirsync")?;
        self.backing.sync_dir(layout::DATA_DIR)?;
        // 4. catalog commit
        fp("store.catalog_store")?;
        self.catalog.insert(shard_idx);
        self.catalog_ab
            .store(self.backing.as_ref(), &mut self.catalog)?;
        self.backing.sync_dir("")?;

        self.shards.insert(
            shard_idx,
            Shard {
                alloc,
                alloc_ab,
                data,
                dirty_alloc: false,
                map_stored: true,
                discard,
                discard_ab,
                dirty_discard: false,
            },
        );
        Ok(())
    }

    /// Store the allocation map of every adopted shard that has no copy on
    /// disk yet and make the data-directory dirents durable, so that a
    /// catalog commit can never name a shard without an allocation copy.
    /// Their in-memory map holds only what open proved from slot headers.
    fn commit_adopted_maps(&mut self) -> Result<(), CoreError> {
        let pending: Vec<u64> = self
            .shards
            .iter()
            .filter(|(_, s)| !s.map_stored)
            .map(|(idx, _)| *idx)
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        for idx in &pending {
            fp("store.adopted_alloc_store")?;
            let shard = self.shards.get_mut(idx).unwrap();
            shard
                .alloc_ab
                .store(self.backing.as_ref(), &mut shard.alloc)?;
        }
        self.backing.sync_dir(layout::DATA_DIR)?;
        for idx in &pending {
            let shard = self.shards.get_mut(idx).unwrap();
            shard.map_stored = true;
            shard.dirty_alloc = false;
        }
        Ok(())
    }

    /// Write a slot (checkpoint path). Durability comes from
    /// `sync_shard_data` + `persist_allocations`.
    pub fn write_slot(
        &mut self,
        unit: u64,
        write_sequence: u64,
        ciphertext: &[u8],
    ) -> Result<(), CoreError> {
        if ciphertext.len() > self.geometry.max_ciphertext_size as usize {
            return Err(CoreError::Corrupt(format!(
                "ciphertext {} exceeds max {}",
                ciphertext.len(),
                self.geometry.max_ciphertext_size
            )));
        }
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        self.ensure_shard(shard_idx)?;
        let header = SlotHeader {
            unit_index: unit,
            write_sequence,
            ciphertext_len: ciphertext.len() as u32,
            flags: 0,
            ciphertext_crc: crc32fast::hash(ciphertext),
        };
        let mut buf = Vec::with_capacity(64 + ciphertext.len());
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(ciphertext);
        let shard = self.shards.get_mut(&shard_idx).unwrap();
        shard
            .data
            .write_at(self.geometry.slot_offset(in_shard), &buf)?;
        Ok(())
    }

    pub fn mark_allocated(&mut self, unit: u64) -> Result<(), CoreError> {
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        self.ensure_shard(shard_idx)?;
        let shard = self.shards.get_mut(&shard_idx).unwrap();
        if !shard.alloc.get(in_shard) {
            shard.alloc.set(in_shard, true);
            shard.dirty_alloc = true;
        }
        Ok(())
    }

    pub fn sync_shard_data(&mut self, shard_idx: u64) -> Result<(), CoreError> {
        if let Some(shard) = self.shards.get(&shard_idx) {
            shard.data.sync_data()?;
        }
        Ok(())
    }

    /// Persist all dirty allocation maps (A/B), make any new metadata file
    /// dirents durable, and only then clear the dirty flags. A failure at
    /// any step leaves every affected shard dirty so a retry redoes the
    /// whole step.
    pub fn persist_allocations(&mut self) -> Result<(), CoreError> {
        // Adopted shards whose map is not proven on disk are stored here
        // too, before the catalog commit below can name them (K-03).
        let dirty: Vec<u64> = self
            .shards
            .iter()
            .filter(|(_, s)| s.dirty_alloc || !s.map_stored)
            .map(|(idx, _)| *idx)
            .collect();
        if !dirty.is_empty() {
            for idx in &dirty {
                fp("checkpoint.alloc_store")?;
                let shard = self.shards.get_mut(idx).unwrap();
                shard
                    .alloc_ab
                    .store(self.backing.as_ref(), &mut shard.alloc)?;
            }
            fp("checkpoint.alloc_dirsync")?;
            self.backing.sync_dir(layout::DATA_DIR)?;
            for idx in &dirty {
                let shard = self.shards.get_mut(idx).unwrap();
                shard.dirty_alloc = false;
                shard.map_stored = true;
            }
        }
        // The catalog commits an adopted shard only *after* its allocation
        // map exists on disk (same order as `ensure_shard`): a failure or
        // crash in between must leave an orphan, never a cataloged shard
        // with no allocation copy, which no later attach could open (K-03).
        if self.catalog_dirty {
            fp("store.catalog_store")?;
            self.catalog_ab
                .store(self.backing.as_ref(), &mut self.catalog)?;
            self.backing.sync_dir("")?;
            self.catalog_dirty = false;
        }
        Ok(())
    }

    pub(crate) fn set_discarded(&mut self, unit: u64, discarded: bool) -> Result<(), CoreError> {
        if !self.discard_enabled {
            return Err(CoreError::Invalid(
                "discard is not enabled for this volume".into(),
            ));
        }
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        let shard = self.shards.get_mut(&shard_idx).ok_or_else(|| {
            CoreError::Corrupt(format!("discard unit {unit} has no existing shard"))
        })?;
        let map = shard.discard.as_mut().ok_or_else(|| {
            CoreError::Corrupt(format!("shard {shard_idx}: discard map unavailable"))
        })?;
        if map.get(in_shard) != discarded {
            map.set(in_shard, discarded);
            shard.dirty_discard = true;
        }
        Ok(())
    }

    pub(crate) fn persist_discards(&mut self) -> Result<(), CoreError> {
        let dirty: Vec<u64> = self
            .shards
            .iter()
            .filter(|(_, shard)| shard.dirty_discard)
            .map(|(idx, _)| *idx)
            .collect();
        if dirty.is_empty() {
            return Ok(());
        }
        for idx in &dirty {
            let shard = self.shards.get_mut(idx).unwrap();
            let ab = shard.discard_ab.as_ref().ok_or_else(|| {
                CoreError::Corrupt(format!("shard {idx}: discard map store unavailable"))
            })?;
            let map = shard.discard.as_mut().unwrap();
            fp("discard.store")?;
            ab.store(self.backing.as_ref(), map)?;
            fp("discard.store")?;
            ab.store(self.backing.as_ref(), map)?;
        }
        fp("discard.dirsync")?;
        self.backing.sync_dir(layout::DATA_DIR)?;
        for idx in dirty {
            self.shards.get_mut(&idx).unwrap().dirty_discard = false;
        }
        Ok(())
    }

    /// Retry at most 4096 slot positions from one shard per checkpoint.
    /// The caller must hold the publication lock, stabilize discard metadata,
    /// and exclude every unit with a newer overlay reservation. Advance only
    /// after both hole punching and its data sync succeed, so a failure retries
    /// the same bounded range. Unsupported punching completes the hint.
    pub(crate) fn retry_reclamation(
        &mut self,
        can_punch: impl Fn(u64) -> bool,
    ) -> Result<(), CoreError> {
        let Some((idx, start)) = self.reclaim_cursor else {
            return Ok(());
        };
        let shard = &self.shards[&idx];
        if shard.dirty_discard {
            return Err(CoreError::Durability(
                "reclamation requires durable discard metadata".into(),
            ));
        }
        let map = shard
            .discard
            .as_ref()
            .expect("reclaim cursor requires v3 map");
        let end = start.saturating_add(4096).min(map.units());
        let base = idx * self.geometry.units_per_shard();
        let units = (start..end)
            .filter(|in_shard| map.get(*in_shard))
            .map(|in_shard| base + in_shard)
            .filter(|unit| can_punch(*unit));
        self.punch_slots(units)?;
        self.reclaim_cursor = if end < map.units() {
            Some((idx, end))
        } else {
            self.catalog
                .shard_indices()
                .find(|next| {
                    *next > idx
                        && self.shards[next]
                            .discard
                            .as_ref()
                            .is_some_and(|map| map.set_count() > 0)
                })
                .map(|next| (next, 0))
        };
        Ok(())
    }

    pub(crate) fn punch_slots(
        &self,
        units: impl IntoIterator<Item = u64>,
    ) -> Result<(), CoreError> {
        let mut by_shard: std::collections::BTreeMap<u64, Vec<u64>> = Default::default();
        for unit in units {
            let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
            by_shard.entry(shard_idx).or_default().push(in_shard);
        }
        for (shard_idx, mut slots) in by_shard {
            let shard = self.shards.get(&shard_idx).ok_or_else(|| {
                CoreError::Corrupt(format!("discard shard {shard_idx} does not exist"))
            })?;
            slots.sort_unstable();
            slots.dedup();
            let mut punched = false;
            let mut start = 0;
            while start < slots.len() {
                let mut end = start + 1;
                while end < slots.len() && slots[end] == slots[end - 1] + 1 {
                    end += 1;
                }
                let first = slots[start];
                let count = (end - start) as u64;
                let len = self.geometry.slot_size.checked_mul(count).ok_or_else(|| {
                    CoreError::Corrupt("discard punch range length overflow".into())
                })?;
                fp("discard.punch")?;
                match shard.data.punch_hole(self.geometry.slot_offset(first), len) {
                    Ok(()) => punched = true,
                    Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {}
                    Err(error) => return Err(CoreError::Io(error)),
                }
                start = end;
            }
            if punched {
                shard.data.sync_data()?;
            }
        }
        Ok(())
    }

    /// SPEC §22 read classification.
    pub fn read_slot(&self, unit: u64) -> Result<SlotRead, CoreError> {
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        let Some(shard) = self.shards.get(&shard_idx) else {
            return Ok(SlotRead::Zero);
        };
        if shard
            .discard
            .as_ref()
            .is_some_and(|discard| discard.get(in_shard))
        {
            return Ok(SlotRead::Zero);
        }
        let offset = self.geometry.slot_offset(in_shard);
        let header = if shard.alloc.get(in_shard) {
            let mut header_bytes = [0u8; 64];
            shard
                .data
                .read_at(offset, &mut header_bytes)
                .map_err(|e| CoreError::Corrupt(format!("unit {unit}: slot read failed: {e}")))?;
            let header = SlotHeader::decode(&header_bytes).map_err(|e| {
                CoreError::Corrupt(format!(
                    "unit {unit}: allocated but slot header invalid: {e}"
                ))
            })?;
            if header.unit_index != unit {
                return Err(CoreError::Corrupt(format!(
                    "unit {unit}: slot header claims unit {}",
                    header.unit_index
                )));
            }
            header
        } else {
            // Bit clear: unwritten unless the slot itself says otherwise
            // (allocation copy behind the data, see module docs).
            let len = shard.data.len()?;
            match probe_header(&self.geometry, shard, unit, in_shard, len)? {
                None => return Ok(SlotRead::Zero),
                Some(header) => {
                    tracing::warn!(
                        unit,
                        "slot holds data its allocation map copy does not list; serving it"
                    );
                    header
                }
            }
        };
        if header.ciphertext_len > self.geometry.max_ciphertext_size {
            return Err(CoreError::Corrupt(format!(
                "unit {unit}: ciphertext_len {} exceeds max",
                header.ciphertext_len
            )));
        }
        let mut data = vec![0u8; header.ciphertext_len as usize];
        shard
            .data
            .read_at(offset + 64, &mut data)
            .map_err(|e| CoreError::Corrupt(format!("unit {unit}: ciphertext read failed: {e}")))?;
        if crc32fast::hash(&data) != header.ciphertext_crc {
            return Err(CoreError::Corrupt(format!(
                "unit {unit}: ciphertext CRC mismatch"
            )));
        }
        Ok(SlotRead::Ciphertext {
            write_sequence: header.write_sequence,
            data,
        })
    }

    /// Shards touched by the given unit list (for checkpoint fdatasync).
    pub fn shards_of_units<'a>(&self, units: impl Iterator<Item = &'a u64>) -> BTreeSet<u64> {
        units.map(|u| self.geometry.shard_of_unit(*u).0).collect()
    }
}
