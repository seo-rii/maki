//! Format checker (`maki check` / `maki-check`): offline consistency
//! verification of a volume's metadata (SPEC §43; deep slot checks are
//! exercised further by recovery in Phase 3).

use std::io::ErrorKind;

use maki_backing::Backing;

use crate::ab::{AbRecord, AbStore};
use crate::allocation::AllocationMap;
use crate::catalog::ShardCatalog;
use crate::checkpoint::{CHECKPOINT_STATE_A, CHECKPOINT_STATE_B};
use crate::durable_proof::DurableProofStore;
use crate::error::FormatError;
use crate::layout;
use crate::superblock::{
    load_volume_superblock_with_fallback, SUPERBLOCK_VERSION_V2, SUPERBLOCK_VERSION_V3,
};

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

    let (envelope, invalid_copy) = match load_volume_superblock_with_fallback(backing) {
        Ok(envelope) => envelope,
        Err(error @ FormatError::Io(_)) => return Err(error),
        Err(error) => {
            report
                .errors
                .push(format!("no valid superblock policy: {error}"));
            return Ok(report);
        }
    };
    if let Some(path) = invalid_copy {
        report.warnings.push(format!(
            "superblock: {path} is missing or invalid (A/B fallback in use)"
        ));
    }
    let superblock = envelope.superblock;
    if matches!(
        envelope.metadata_version,
        SUPERBLOCK_VERSION_V2 | SUPERBLOCK_VERSION_V3
    ) {
        match DurableProofStore::load(backing, superblock.volume_uuid) {
            Ok(proof) => report.info.push(format!(
                "required durable proof: sequence {}",
                proof.durable_sequence
            )),
            Err(error @ FormatError::Io(_)) => return Err(error),
            Err(error) => report
                .errors
                .push(format!("required durable proof: {error}")),
        }
    } else {
        report.warnings.push("legacy v1 volume: writable recovery requires explicit migration; tail inspection cannot establish a missing durable horizon".into());
    }
    report.info.push(format!(
        "superblock: volume {} generation {} slot_size {}",
        superblock.volume_uuid, superblock.generation, superblock.geometry.slot_size
    ));

    // Recovery requires at least one checkpoint state file. The deep check
    // handles decoding and comparing its contents.
    let mut has_checkpoint_file = false;
    for path in [CHECKPOINT_STATE_A, CHECKPOINT_STATE_B] {
        match backing.open(path, false) {
            Ok(_) => has_checkpoint_file = true,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) if matches!(e.kind(), ErrorKind::IsADirectory | ErrorKind::InvalidInput) => {
                report
                    .errors
                    .push(format!("invalid checkpoint state file {path}: {e}"));
            }
            Err(e) => return Err(e.into()),
        }
    }
    if !has_checkpoint_file {
        report
            .errors
            .push("no checkpoint state file is present".into());
    }

    // Valid sizes follow from the geometry; longer copies are never read
    // (R5-025).
    let cat_ab = AbStore::new(layout::SHARD_CATALOG_A, layout::SHARD_CATALOG_B).with_max_len(
        ShardCatalog::max_encoded_len(superblock.geometry.num_shards()),
    );
    let (catalog, copies) = cat_ab.load_with_copy_count::<ShardCatalog>(backing)?;
    let catalog = match catalog {
        Some(c) => c,
        None => {
            report.errors.push("no valid shard catalog".to_string());
            return Ok(report);
        }
    };
    // Creation intentionally publishes the empty generation-one catalog once.
    if copies == 1 && catalog.generation() > 1 {
        report
            .warnings
            .push("shard catalog has one valid copy".into());
    }
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
        check_allocation_map(
            backing,
            shard,
            geometry.units_per_shard(),
            true,
            &mut report,
        )?;
        if envelope.metadata_version == SUPERBLOCK_VERSION_V3 {
            check_discard_map(backing, shard, geometry.units_per_shard(), &mut report)?;
        }

        // A cataloged shard always has a data file: shard creation makes the
        // data file's dirent durable *before* the catalog names the shard, so
        // a missing one is not a pending state ("not yet created") but
        // corruption that recovery refuses to attach — SlotStore::open opens
        // every cataloged shard's data file unconditionally, whatever its
        // allocation map says. Report it as an error, matching recovery,
        // rather than a benign warning that lets `maki check` pass on a
        // volume `maki attach` would reject.
        check_data_file(backing, shard, &mut report)?;
    }

    // A shard data file the loaded catalog copy does not list results from a
    // crash between file creation and the catalog update, or from a fallback
    // to an older catalog copy. Recovery adopts it and serves its slots
    // (S-01); one beyond the geometry is never read. Only the canonical
    // spelling is a shard file, exactly as recovery parses it.
    let entries = match backing.list(layout::DATA_DIR) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            report
                .errors
                .push("required data directory is missing".into());
            return Ok(report);
        }
        Err(error) => return Err(error.into()),
    };
    for name in entries {
        let Some(idx) = layout::parse_shard_data(&name) else {
            continue;
        };
        if catalog.contains(idx) {
            continue;
        }
        let warning = if idx < geometry.num_shards() {
            if !check_data_file(backing, idx, &mut report)? {
                continue;
            }
            let allocation_ok =
                check_allocation_map(backing, idx, geometry.units_per_shard(), false, &mut report)?;
            let discard_ok = envelope.metadata_version != SUPERBLOCK_VERSION_V3
                || check_discard_map(backing, idx, geometry.units_per_shard(), &mut report)?;
            format!(
                "shard data file {name} (index {idx}) is not in the catalog; {}",
                match (allocation_ok, discard_ok) {
                    (false, _) => "invalid allocation metadata prevents recovery from adopting it",
                    (_, false) => "invalid discard metadata prevents recovery from adopting it",
                    (true, true) => "recovery adopts it",
                }
            )
        } else {
            format!(
                "shard data file {name} (index {idx}) lies beyond the volume \
                     geometry and is ignored"
            )
        };
        report.warnings.push(warning);
    }

    Ok(report)
}

/// Recovery can start an uncataloged shard with an empty map if neither side
/// decodes. Any map it actually selects must match the stored geometry.
fn check_allocation_map(
    backing: &dyn Backing,
    shard: u64,
    units: u64,
    cataloged: bool,
    report: &mut CheckReport,
) -> Result<bool, FormatError> {
    let store = AbStore::new(layout::shard_alloc_a(shard), layout::shard_alloc_b(shard))
        .with_max_len(AllocationMap::encoded_len(units));
    let (map_units, copies) = store
        .load_with_copy_count_by::<AllocationMap, _>(backing, AllocationMap::decode_geometry)?;
    match map_units {
        Some(found) if found != units => report.errors.push(format!(
            "shard {shard}: allocation map covers {found} units, geometry says {units}"
        )),
        Some(_) if copies == 1 => {
            report.warnings.push(format!(
                "shard {shard}: allocation map has one valid copy; using fallback"
            ));
            return Ok(true);
        }
        None if cataloged => report
            .errors
            .push(format!("shard {shard}: no valid allocation map")),
        _ => return Ok(true),
    }
    Ok(false)
}

/// Recovery opens each cataloged or adoptable shard as a data file.
fn check_data_file(
    backing: &dyn Backing,
    shard: u64,
    report: &mut CheckReport,
) -> Result<bool, FormatError> {
    match backing.open(&layout::shard_data(shard), false) {
        Ok(_) => Ok(true),
        Err(error) => {
            let reason = match error.kind() {
                ErrorKind::NotFound => "data file is missing",
                ErrorKind::IsADirectory | ErrorKind::InvalidInput => "invalid data file",
                _ => return Err(error.into()),
            };
            report
                .errors
                .push(format!("shard {shard}: {reason}: {error}"));
            Ok(false)
        }
    }
}

/// V3 adoption needs the same discard evidence as a cataloged shard. Keep
/// both fast-check paths consistent; actual I/O errors remain inconclusive.
fn check_discard_map(
    backing: &dyn Backing,
    shard: u64,
    units: u64,
    report: &mut CheckReport,
) -> Result<bool, FormatError> {
    let discard_ab = AbStore::new(
        layout::shard_discard_a(shard),
        layout::shard_discard_b(shard),
    )
    .with_max_len(AllocationMap::encoded_len(units));
    let (map_units, copies) = discard_ab
        .load_with_copy_count_by::<AllocationMap, _>(backing, AllocationMap::decode_geometry)?;
    let Some(found) = map_units else {
        report
            .errors
            .push(format!("shard {shard}: no valid discard map"));
        return Ok(false);
    };
    if found != units {
        report.errors.push(format!(
            "shard {shard}: discard map covers {found} units, geometry says {units}"
        ));
        return Ok(false);
    }
    if copies == 1 {
        report.warnings.push(format!(
            "shard {shard}: discard map has one valid copy; using fallback"
        ));
    }
    Ok(true)
}
