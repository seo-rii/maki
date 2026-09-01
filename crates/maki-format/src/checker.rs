//! Format checker (`maki check` / `maki-check`): offline consistency
//! verification of a volume's metadata (SPEC §43; deep slot checks are
//! exercised further by recovery in Phase 3).

use maki_backing::Backing;

use crate::ab::AbStore;
use crate::allocation::AllocationMap;
use crate::catalog::ShardCatalog;
use crate::error::FormatError;
use crate::layout;
use crate::superblock::Superblock;

#[derive(Debug, Default)]
pub struct CheckReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
}

impl CheckReport {
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn check_volume(backing: &dyn Backing) -> Result<CheckReport, FormatError> {
    let mut report = CheckReport::default();

    let sb_ab = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B);
    let superblock = match sb_ab.load::<Superblock>(backing)? {
        Some(sb) => sb,
        None => {
            report
                .errors
                .push("no valid superblock copy found".to_string());
            return Ok(report);
        }
    };
    report.info.push(format!(
        "superblock: volume {} generation {} slot_size {}",
        superblock.volume_uuid, superblock.generation, superblock.geometry.slot_size
    ));

    let cat_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B);
    let catalog = match cat_ab.load::<ShardCatalog>(backing)? {
        Some(c) => c,
        None => {
            report.errors.push("no valid shard catalog".to_string());
            return Ok(report);
        }
    };
    report
        .info
        .push(format!("catalog: {} shard(s)", catalog.len()));

    let geometry = &superblock.geometry;
    for shard in catalog.shard_indices() {
        if shard >= geometry.num_shards() {
            report
                .errors
                .push(format!("catalog shard {shard} out of range"));
            continue;
        }
        let alloc_ab = AbStore::new(layout::shard_alloc_a(shard), layout::shard_alloc_b(shard));
        match alloc_ab.load::<AllocationMap>(backing)? {
            None => report
                .errors
                .push(format!("shard {shard}: no valid allocation map")),
            Some(map) => {
                if map.units() != geometry.units_per_shard() {
                    report.errors.push(format!(
                        "shard {shard}: allocation map covers {} units, geometry says {}",
                        map.units(),
                        geometry.units_per_shard()
                    ));
                }
                if map.set_count() > 0 && !backing.exists(&layout::shard_data(shard))? {
                    report.errors.push(format!(
                        "shard {shard}: {} allocated unit(s) but data file missing",
                        map.set_count()
                    ));
                }
            }
        }
        if !backing.exists(&layout::shard_data(shard))? {
            report
                .warnings
                .push(format!("shard {shard}: data file not yet created"));
        }
    }

    // Orphaned shard files (exist but not in catalog) are a warning: they can
    // result from a crash between file creation and catalog update, and are
    // ignored by reads.
    if backing.exists(layout::DATA_DIR)? {
        for name in backing.list(layout::DATA_DIR)? {
            if let Some(hex) = name
                .strip_prefix("shard-")
                .and_then(|n| n.strip_suffix(".dat"))
            {
                if let Ok(idx) = u64::from_str_radix(hex, 16) {
                    if !catalog.contains(idx) {
                        report
                            .warnings
                            .push(format!("orphaned shard data file {name} (index {idx})"));
                    }
                }
            }
        }
    }

    Ok(report)
}
