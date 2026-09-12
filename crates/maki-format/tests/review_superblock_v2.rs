//! A distinct metadata envelope prevents old writers from opening v2 volumes.

use maki_backing::{Backing, MemBacking};
use maki_backing::{BackingFile, VolumeLock};
use maki_format::ab::AbStore;
use maki_format::geometry::Geometry;
use maki_format::superblock::{load_volume_superblock, VolumeSuperblock, SUPERBLOCK_VERSION_V2};
use maki_format::superblock::{Superblock, SUPERBLOCK_SIZE};
use maki_format::{layout, FormatError};
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use uuid::Uuid;

fn superblock() -> Superblock {
    Superblock {
        generation: 1,
        volume_uuid: Uuid::from_u128(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF),
        provider_type: "remote-http".into(),
        crypto_compatibility_id: "vendor-profile-v1".into(),
        key_identity: "key-1".into(),
        geometry: Geometry::compute(4096, 4096, 512, 4384, 16 << 40, 64 << 30).unwrap(),
        format_version: 1,
        created_unix: 1_756_684_800,
    }
}

fn envelope_version(mut bytes: Vec<u8>, version: u32) -> Vec<u8> {
    bytes[8..12].copy_from_slice(&version.to_le_bytes());
    let crc = crc32fast::hash(&bytes[..SUPERBLOCK_SIZE - 4]);
    bytes[SUPERBLOCK_SIZE - 4..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[test]
fn manually_encoded_v2_envelope_preserves_the_superblock_model() {
    let expected = superblock();
    let bytes = envelope_version(expected.encode(), 2);
    assert_eq!(
        Superblock::decode(&bytes).unwrap(),
        expected,
        "metadata v2 must not silently change the cryptographic context format"
    );
}

#[test]
fn legacy_superblock_encoding_remains_the_frozen_v1_vector() {
    let bytes = superblock().encode();
    assert_eq!(bytes.len(), SUPERBLOCK_SIZE);
    assert_eq!(&bytes[..8], b"MAKISB01");
    assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
    let frozen_crc: u32 = include!("golden/superblock_v1.crc");
    assert_eq!(crc32fast::hash(&bytes[..SUPERBLOCK_SIZE - 4]), frozen_crc);
}

fn write_copy(backing: &dyn Backing, path: &str, value: &Superblock, version: u32) {
    let file = backing.open(path, true).unwrap();
    file.set_len(SUPERBLOCK_SIZE as u64).unwrap();
    file.write_at(0, &envelope_version(value.encode(), version))
        .unwrap();
}

fn load_volume_model(backing: &dyn Backing) -> Result<Superblock, FormatError> {
    load_volume_superblock(backing).map(|record| record.superblock)
}

#[test]
fn mixed_valid_envelope_versions_refuse_loading_in_both_orders() {
    for (a, b) in [(1, 2), (2, 1)] {
        let backing = MemBacking::new();
        write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), a);
        let mut newest = superblock();
        newest.generation = 2;
        write_copy(&backing, layout::SUPERBLOCK_B, &newest, b);
        assert!(
            matches!(load_volume_model(&backing), Err(FormatError::Invalid(_))),
            "must not complete an interrupted metadata upgrade or downgrade"
        );
    }
}

#[test]
fn a_crc_valid_unknown_version_cannot_be_hidden_by_an_older_copy() {
    for (a, b) in [(1, 3), (3, 1)] {
        let backing = MemBacking::new();
        write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), a);
        let mut newest = superblock();
        newest.generation = 20;
        write_copy(&backing, layout::SUPERBLOCK_B, &newest, b);
        assert!(
            matches!(
                load_volume_model(&backing),
                Err(FormatError::Unsupported(_))
            ),
            "unknown versions are not torn copies, even if their generation is older"
        );
    }
}

#[test]
fn a_future_envelope_with_a_different_size_cannot_fall_back_to_v2() {
    for side in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        for length in [12, 16, 64, SUPERBLOCK_SIZE - 1, SUPERBLOCK_SIZE + 1, 8192] {
            let backing = MemBacking::new();
            write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), 2);
            write_copy(&backing, layout::SUPERBLOCK_B, &superblock(), 2);
            let mut bytes = envelope_version(superblock().encode(), 3);
            bytes.resize(length, 0);
            if length >= 16 {
                let crc = crc32fast::hash(&bytes[..length - 4]);
                bytes[length - 4..].copy_from_slice(&crc.to_le_bytes());
            }
            let file = backing.open(side, false).unwrap();
            file.set_len(length as u64).unwrap();
            file.write_at(0, &bytes).unwrap();
            assert!(
                matches!(
                    load_volume_superblock(&backing),
                    Err(FormatError::Unsupported(_))
                ),
                "unknown envelope {side} length {length} must not be classified as a torn v2 copy"
            );
        }
    }
}

#[test]
fn same_generation_conflicting_superblocks_refuse_loading() {
    let backing = MemBacking::new();
    write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), 1);
    let mut conflict = superblock();
    conflict.volume_uuid = Uuid::from_u128(99);
    write_copy(&backing, layout::SUPERBLOCK_B, &conflict, 1);
    assert!(
        matches!(load_volume_model(&backing), Err(FormatError::Invalid(_))),
        "A/B path order cannot resolve two identities at one generation"
    );
}

#[test]
fn explicit_envelopes_roundtrip_through_ab_storage_without_changing_crypto_context() {
    for metadata_version in [1, SUPERBLOCK_VERSION_V2] {
        let backing = MemBacking::new();
        let mut record = VolumeSuperblock {
            superblock: superblock(),
            metadata_version,
        };
        let v1 = record.superblock.encode();
        let encoded = record.encode();
        assert_eq!(
            &encoded[12..SUPERBLOCK_SIZE - 4],
            &v1[12..SUPERBLOCK_SIZE - 4]
        );
        assert_eq!(VolumeSuperblock::decode(&encoded).unwrap(), record);
        let ab = AbStore::new(layout::SUPERBLOCK_A, layout::SUPERBLOCK_B);
        ab.store(&backing, &mut record).unwrap();
        ab.store(&backing, &mut record).unwrap();
        assert_eq!(load_volume_superblock(&backing).unwrap(), record);
        assert_eq!(record.superblock.format_version, 1);
    }
}

// This freezes the original decoder's validation order and version gate. Once
// version 1 is established, the model decoder has the same payload layout.
fn legacy_v1_decoder(bytes: &[u8]) -> Result<Superblock, FormatError> {
    if bytes.len() < SUPERBLOCK_SIZE {
        return Err(FormatError::Truncated("superblock".into()));
    }
    let bytes = &bytes[..SUPERBLOCK_SIZE];
    if &bytes[..8] != b"MAKISB01" {
        return Err(FormatError::BadMagic("superblock".into()));
    }
    maki_format::codec::strip_verify_crc(bytes, "superblock")?;
    let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if version != 1 {
        return Err(FormatError::Unsupported(format!(
            "superblock version {version}"
        )));
    }
    Superblock::decode(bytes)
}

#[test]
fn old_v1_reader_gate_rejects_the_new_envelope() {
    let value = superblock();
    assert_eq!(legacy_v1_decoder(&value.encode()).unwrap(), value);
    let bytes = VolumeSuperblock {
        superblock: value,
        metadata_version: SUPERBLOCK_VERSION_V2,
    }
    .encode();
    assert!(matches!(
        legacy_v1_decoder(&bytes),
        Err(FormatError::Unsupported(_))
    ));
}

#[test]
fn valid_highest_generation_wins_and_identical_ties_are_allowed() {
    for (ga, gb) in [(1, 9), (9, 1), (9, 9)] {
        let backing = MemBacking::new();
        let mut value = superblock();
        value.generation = ga;
        write_copy(&backing, layout::SUPERBLOCK_A, &value, 2);
        value.generation = gb;
        write_copy(&backing, layout::SUPERBLOCK_B, &value, 2);
        let loaded = load_volume_superblock(&backing).unwrap();
        assert_eq!(loaded.metadata_version, 2);
        assert_eq!(loaded.superblock.generation, ga.max(gb));
    }
}

#[test]
fn same_generation_conflicts_include_ignored_padding() {
    let backing = MemBacking::new();
    write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), 2);
    let mut bytes = superblock().encode();
    bytes[SUPERBLOCK_SIZE - 5] = 1;
    bytes = envelope_version(bytes, 2);
    backing
        .open(layout::SUPERBLOCK_B, true)
        .unwrap()
        .write_at(0, &bytes)
        .unwrap();
    assert_eq!(Superblock::decode(&bytes).unwrap(), superblock());
    assert!(matches!(
        load_volume_superblock(&backing),
        Err(FormatError::Invalid(_))
    ));
}

#[test]
fn torn_copies_can_fall_back_but_are_never_repaired_by_loading() {
    for version in [1, 2] {
        for damaged_side in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
            for damage in 0..5 {
                let backing = MemBacking::new();
                write_copy(&backing, layout::SUPERBLOCK_A, &superblock(), version);
                write_copy(&backing, layout::SUPERBLOCK_B, &superblock(), version);
                let mut bytes = envelope_version(superblock().encode(), version);
                match damage {
                    0 => bytes.clear(),
                    1 => bytes.truncate(SUPERBLOCK_SIZE / 2),
                    2 => bytes[100] ^= 1,
                    3 => bytes.push(0),
                    _ => {
                        bytes = envelope_version(bytes, 999);
                        bytes[100] ^= 1;
                    }
                }
                let file = backing.open(damaged_side, false).unwrap();
                file.set_len(bytes.len() as u64).unwrap();
                file.write_at(0, &bytes).unwrap();
                assert_eq!(
                    load_volume_superblock(&backing).unwrap().metadata_version,
                    version
                );
                let mut after = vec![0; bytes.len()];
                file.read_at(0, &mut after).unwrap();
                assert_eq!(
                    after, bytes,
                    "loading must not complete a format conversion"
                );
                assert_eq!(file.len().unwrap(), bytes.len() as u64);
            }
        }
    }
    assert!(matches!(
        load_volume_superblock(&MemBacking::new()),
        Err(FormatError::Invalid(_))
    ));
}

#[derive(Clone, Copy)]
enum Fault {
    Open(io::ErrorKind),
    Length(io::ErrorKind),
    Read(io::ErrorKind),
    ReportLength(u64),
    ReportLengthRead(u64, io::ErrorKind),
}

struct FaultBacking {
    inner: MemBacking,
    side: &'static str,
    fault: Fault,
    reads: Arc<AtomicUsize>,
}

struct FaultFile {
    inner: Arc<dyn BackingFile>,
    fault: Fault,
    reads: Arc<AtomicUsize>,
}

impl BackingFile for FaultFile {
    fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(bytes.len(), Ordering::SeqCst);
        if let Fault::Read(kind) | Fault::ReportLengthRead(_, kind) = self.fault {
            return Err(io::Error::new(kind, "injected metadata read"));
        }
        self.inner.read_at(offset, bytes)
    }
    fn len(&self) -> io::Result<u64> {
        match self.fault {
            Fault::Length(kind) => Err(io::Error::new(kind, "injected metadata length")),
            Fault::ReportLength(length) | Fault::ReportLengthRead(length, _) => Ok(length),
            _ => self.inner.len(),
        }
    }
    fn write_at(&self, _: u64, _: &[u8]) -> io::Result<()> {
        panic!("loader must not write")
    }
    fn set_len(&self, _: u64) -> io::Result<()> {
        panic!("loader must not truncate")
    }
    fn sync_data(&self) -> io::Result<()> {
        panic!("loader must not sync")
    }
}

impl Backing for FaultBacking {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        assert!(!create, "loader must not create files");
        if path != self.side {
            return self.inner.open(path, false);
        }
        if let Fault::Open(kind) = self.fault {
            return Err(io::Error::new(kind, "injected metadata open"));
        }
        Ok(Arc::new(FaultFile {
            inner: self.inner.open(path, false)?,
            fault: self.fault,
            reads: self.reads.clone(),
        }))
    }
    fn exists(&self, path: &str) -> io::Result<bool> {
        self.inner.exists(path)
    }
    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        self.inner.list(path)
    }
    fn remove(&self, _: &str) -> io::Result<()> {
        panic!("loader must not remove")
    }
    fn rename(&self, _: &str, _: &str) -> io::Result<()> {
        panic!("loader must not rename")
    }
    fn create_dir_all(&self, _: &str) -> io::Result<()> {
        panic!("loader must not create directories")
    }
    fn sync_dir(&self, _: &str) -> io::Result<()> {
        panic!("loader must not sync directories")
    }
    fn try_lock(&self, _: &str) -> io::Result<Box<dyn VolumeLock>> {
        panic!("caller owns the volume lock")
    }
}

fn faulty(backing_side: &'static str, fault: Fault) -> FaultBacking {
    let inner = MemBacking::new();
    write_copy(&inner, layout::SUPERBLOCK_A, &superblock(), 2);
    write_copy(&inner, layout::SUPERBLOCK_B, &superblock(), 2);
    FaultBacking {
        inner,
        side: backing_side,
        fault,
        reads: Arc::default(),
    }
}

#[test]
fn hard_open_length_and_read_errors_are_not_invalid_copies() {
    for side in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
            for fault in [Fault::Open(kind), Fault::Length(kind), Fault::Read(kind)] {
                let backing = faulty(side, fault);
                assert!(
                    matches!(load_volume_superblock(&backing), Err(FormatError::Io(error)) if error.kind() == kind)
                );
            }
        }
        for fault in [
            Fault::Open(io::ErrorKind::NotFound),
            Fault::Read(io::ErrorKind::UnexpectedEof),
        ] {
            assert_eq!(
                load_volume_superblock(&faulty(side, fault))
                    .unwrap()
                    .metadata_version,
                2
            );
        }
    }
}

#[test]
fn wrong_sized_superblock_reads_are_bounded_to_the_version_header() {
    for side in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        for length in [
            0,
            8,
            12,
            SUPERBLOCK_SIZE as u64 - 1,
            SUPERBLOCK_SIZE as u64 + 1,
            u64::MAX,
        ] {
            let backing = faulty(side, Fault::ReportLength(length));
            assert_eq!(
                load_volume_superblock(&backing).unwrap().metadata_version,
                2
            );
            assert_eq!(
                backing.reads.load(Ordering::SeqCst),
                if length >= 12 { 12 } else { 0 }
            );
        }
    }
}

#[test]
fn future_size_header_read_errors_preserve_io_classification() {
    for side in [layout::SUPERBLOCK_A, layout::SUPERBLOCK_B] {
        for length in [12, 64, 8192, u64::MAX] {
            for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::Other] {
                let backing = faulty(side, Fault::ReportLengthRead(length, kind));
                assert!(
                    matches!(load_volume_superblock(&backing), Err(FormatError::Io(error)) if error.kind() == kind)
                );
                assert_eq!(backing.reads.load(Ordering::SeqCst), 12);
            }
            let backing = faulty(
                side,
                Fault::ReportLengthRead(length, io::ErrorKind::UnexpectedEof),
            );
            assert_eq!(
                load_volume_superblock(&backing).unwrap().metadata_version,
                2
            );
            assert_eq!(backing.reads.load(Ordering::SeqCst), 12);
        }
    }
}
