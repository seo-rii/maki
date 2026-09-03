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
    shards: HashMap<u64, Shard>,
}

impl SlotStore {
    /// Open the store, loading catalog and validating every cataloged
    /// shard's allocation metadata (SPEC §27 "validate allocation metadata").
    pub fn open(backing: Arc<dyn Backing>, geometry: Geometry) -> Result<Self, CoreError> {
        let catalog_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
        let catalog = catalog_ab
            .load::<ShardCatalog>(backing.as_ref())?
            .ok_or_else(|| CoreError::Corrupt("no valid shard catalog".to_string()))?;

        let mut shards = HashMap::new();
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
            let alloc = alloc_ab
                .load::<AllocationMap>(backing.as_ref())?
                .ok_or_else(|| {
                    CoreError::Corrupt(format!("shard {shard_idx}: no valid allocation map copy"))
                })?;
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
            shards.insert(
                shard_idx,
                Shard {
                    alloc,
                    alloc_ab,
                    data,
                    dirty_alloc: false,
                },
            );
        }

        Ok(Self {
            backing,
            geometry,
            catalog,
            catalog_ab,
            shards,
        })
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
        if !shard.alloc.get(in_shard) {
            return Ok(SlotRead::Zero);
        }
        let offset = self.geometry.slot_offset(in_shard);
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
