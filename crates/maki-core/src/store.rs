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
//! missing metadata.
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
    /// Open the store, loading catalog and validating every cataloged
    /// shard's allocation metadata (SPEC §27 "validate allocation metadata").
    /// Data files the catalog copy does not list are adopted (see module
    /// docs); a missing allocation map for such a shard is an empty one.
    pub fn open(backing: Arc<dyn Backing>, geometry: Geometry) -> Result<Self, CoreError> {
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
            let (alloc, dirty_alloc) = match alloc_ab.load::<AllocationMap>(backing.as_ref())? {
                Some(alloc) => (alloc, false),
                // A shard the catalog never committed may have died before
                // its (empty) map was stored: start it empty.
                None if adopted.contains(&shard_idx) => {
                    (AllocationMap::new(geometry.units_per_shard()), true)
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
            };
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
        self.catalog_dirty || self.shards.values().any(|s| s.dirty_alloc)
    }

    pub fn geometry(&self) -> &Geometry {
        &self.geometry
    }

    /// Number of cataloged shards.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Every allocated unit, in ascending order (offline check input).
    pub fn allocated_units(&self) -> Vec<u64> {
        let mut shards: Vec<u64> = self.shards.keys().copied().collect();
        shards.sort_unstable();
        let per_shard = self.geometry.units_per_shard();
        let mut out = Vec::new();
        for shard_idx in shards {
            let shard = &self.shards[&shard_idx];
            for in_shard in 0..shard.alloc.units() {
                if shard.alloc.get(in_shard) {
                    out.push(shard_idx * per_shard + in_shard);
                }
            }
        }
        out
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
            if let Some(in_shard) = (0..shard.alloc.units()).find(|u| shard.alloc.get(*u)) {
                return Some(shard_idx * self.geometry.units_per_shard() + in_shard);
            }
        }
        None
    }

    fn ensure_shard(&mut self, shard_idx: u64) -> Result<(), CoreError> {
        if self.shards.contains_key(&shard_idx) {
            return Ok(());
        }
        // 1. data file, full sparse size, synced
        fp("store.shard_create")?;
        let data_path = layout::shard_data(shard_idx);
        let data = self.backing.open(&data_path, true)?;
        let physical = self.geometry.units_per_shard() * self.geometry.slot_size;
        data.set_len(physical)?;
        data.sync_data()?;
        // 2. empty allocation map, synced
        let alloc_ab = AbStore::new(
            layout::shard_alloc_a(shard_idx),
            layout::shard_alloc_b(shard_idx),
        );
        let mut alloc = AllocationMap::new(self.geometry.units_per_shard());
        alloc_ab.store(self.backing.as_ref(), &mut alloc)?;
        // 3. dirents durable before the catalog names the shard
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
            },
        );
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
        if self.catalog_dirty {
            fp("store.catalog_store")?;
            self.catalog_ab
                .store(self.backing.as_ref(), &mut self.catalog)?;
            self.backing.sync_dir("")?;
            self.catalog_dirty = false;
        }
        let dirty: Vec<u64> = self
            .shards
            .iter()
            .filter(|(_, s)| s.dirty_alloc)
            .map(|(idx, _)| *idx)
            .collect();
        if dirty.is_empty() {
            return Ok(());
        }
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
            self.shards.get_mut(idx).unwrap().dirty_alloc = false;
        }
        Ok(())
    }

    /// SPEC §22 read classification.
    pub fn read_slot(&self, unit: u64) -> Result<SlotRead, CoreError> {
        let (shard_idx, in_shard) = self.geometry.shard_of_unit(unit);
        let Some(shard) = self.shards.get(&shard_idx) else {
            return Ok(SlotRead::Zero);
        };
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
