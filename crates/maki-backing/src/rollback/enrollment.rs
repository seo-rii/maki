//! Immutable binding of an explicitly approved initial volume identity/capacity.
//! Calls that create this binding must hold the root enrollment lock and must
//! establish independently that the remote authority has never activated.
use super::*;

const FILE: &str = "remote.enrollment";
const MAGIC: &[u8; 8] = b"MAKIRE01";
const DOMAIN: &[u8] = b"maki.remote.enrollment.v1\0";
const LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Enrollment {
    pub(super) identity: [u8; 16],
    pub(super) capacity: u64,
}
impl Enrollment {
    pub(super) fn load(disk: &dyn Backing) -> io::Result<Self> {
        let file = disk.open(FILE, false)?;
        if file.len()? != LENGTH as u64 {
            return Err(invalid("invalid enrollment metadata length"));
        }
        let mut bytes = [0; LENGTH];
        file.read_at(0, &mut bytes)?;
        Self::decode(&bytes)
    }

    /// Bind only an explicitly approved, never-activated authority. Existing
    /// bytes must match exactly; this operation cannot replace another binding.
    /// The caller holds the root enrollment lock until its remote claim ends.
    pub(super) fn load_or_create(
        disk: &dyn Backing,
        identity: [u8; 16],
        capacity: u64,
    ) -> io::Result<Self> {
        let expected = Self { identity, capacity };
        let bytes = expected.encode()?;
        if disk.exists(FILE)? && Self::load(disk)? != expected {
            return Err(invalid(
                "enrollment identity or capacity differs from approval",
            ));
        }
        // Failed writeback can leave readable bytes clean and non-durable.
        // Rewrite the exact validated binding before retrying its sync.
        let file = disk.open(FILE, true)?;
        file.write_at(0, &bytes)?;
        file.set_len(LENGTH as u64)?;
        file.sync_data()?;
        disk.sync_dir("")?;
        Ok(expected)
    }

    fn encode(&self) -> io::Result<[u8; LENGTH]> {
        if self.identity == [0; 16] {
            return Err(input("nil enrollment identity"));
        }
        validate_capacity(self.capacity)?;
        let mut bytes = [0; LENGTH];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..24].copy_from_slice(&self.identity);
        bytes[24..32].copy_from_slice(&self.capacity.to_le_bytes());
        let checksum = digest(DOMAIN, &bytes[..32]);
        bytes[32..].copy_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != LENGTH
            || &bytes[..8] != MAGIC
            || digest(DOMAIN, &bytes[..32]) != bytes[32..]
        {
            return Err(invalid("invalid enrollment metadata envelope or checksum"));
        }
        let identity = bytes[8..24].try_into().expect("checked fixed length");
        let capacity = u64::from_le_bytes(bytes[24..32].try_into().expect("checked fixed length"));
        let enrollment = Self { identity, capacity };
        enrollment
            .encode()
            .map_err(|_| invalid("invalid enrollment identity or capacity"))?;
        Ok(enrollment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    const ID: [u8; 16] = [11; 16];
    #[test]
    fn enrollment_metadata_create_reopen_and_republish_exact_binding() {
        let dir = tempdir().unwrap();
        let disk = FileBacking::new(dir.path()).unwrap();
        assert!(Enrollment::load(&disk).is_err());
        let expected = Enrollment {
            identity: ID,
            capacity: PAGE,
        };
        assert_eq!(
            Enrollment::load_or_create(&disk, ID, PAGE).unwrap(),
            expected
        );
        assert_eq!(Enrollment::load(&disk).unwrap(), expected);
        assert_eq!(
            Enrollment::load_or_create(&disk, ID, PAGE).unwrap(),
            expected
        );
        assert_eq!(
            disk.open(FILE, false).unwrap().len().unwrap(),
            LENGTH as u64
        );
    }
    #[test]
    fn enrollment_metadata_never_rebinds_foreign_identity_or_different_capacity() {
        let dir = tempdir().unwrap();
        let disk = FileBacking::new(dir.path()).unwrap();
        Enrollment::load_or_create(&disk, ID, PAGE).unwrap();
        assert!(Enrollment::load_or_create(&disk, [12; 16], PAGE).is_err());
        assert!(Enrollment::load_or_create(&disk, ID, PAGE * 2).is_err());
        assert_eq!(
            Enrollment::load(&disk).unwrap(),
            Enrollment {
                identity: ID,
                capacity: PAGE
            }
        );
    }
    #[test]
    fn enrollment_metadata_invalid_binding_never_creates_file() {
        let dir = tempdir().unwrap();
        let disk = FileBacking::new(dir.path()).unwrap();
        for (identity, capacity) in [
            ([0; 16], PAGE),
            (ID, 0),
            (ID, PAGE - 1),
            (ID, MAX_CAPACITY + PAGE),
        ] {
            assert!(Enrollment::load_or_create(&disk, identity, capacity).is_err());
            assert!(!disk.exists(FILE).unwrap());
        }
    }
    #[test]
    fn enrollment_metadata_exact_length_magic_identity_capacity_and_checksum_are_required() {
        let valid = Enrollment {
            identity: ID,
            capacity: PAGE,
        }
        .encode()
        .unwrap();
        for size in 0..LENGTH {
            assert!(Enrollment::decode(&valid[..size]).is_err(), "length {size}");
        }
        let mut too_long = valid.to_vec();
        too_long.push(0);
        assert!(Enrollment::decode(&too_long).is_err());
        for offset in 0..LENGTH {
            let mut bytes = valid;
            bytes[offset] ^= 1;
            assert!(Enrollment::decode(&bytes).is_err(), "offset {offset}");
        }
        for case in 0..3 {
            let mut bytes = valid;
            match case {
                0 => bytes[7] = b'2',
                1 => bytes[8..24].fill(0),
                _ => bytes[24..32].copy_from_slice(&0u64.to_le_bytes()),
            }
            let checksum = digest(DOMAIN, &bytes[..32]);
            bytes[32..].copy_from_slice(&checksum);
            assert!(Enrollment::decode(&bytes).is_err(), "resigned case {case}");
        }
    }
    #[test]
    fn enrollment_metadata_corrupt_existing_file_is_never_silently_replaced() {
        let dir = tempdir().unwrap();
        let disk = FileBacking::new(dir.path()).unwrap();
        let file = disk.open(FILE, true).unwrap();
        file.write_at(0, b"interrupted or foreign metadata")
            .unwrap();
        file.sync_data().unwrap();
        let before = file.len().unwrap();
        assert!(Enrollment::load_or_create(&disk, ID, PAGE).is_err());
        assert_eq!(file.len().unwrap(), before);
    }
    #[test]
    fn enrollment_metadata_v1_has_an_independent_fixed_golden_vector() {
        let bytes = Enrollment {
            identity: ID,
            capacity: PAGE,
        }
        .encode()
        .unwrap();
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[8..24], &ID);
        assert_eq!(&bytes[24..32], &PAGE.to_le_bytes());
        let hash: String = Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hash,
            "d43d8be11df7fdef5dac3f703c17208376c3dc03412350b74e728790c7e178b2"
        );
        assert_eq!(
            Enrollment::decode(&bytes).unwrap(),
            Enrollment {
                identity: ID,
                capacity: PAGE
            }
        );
    }
    #[test]
    fn enrollment_metadata_every_partial_write_fails_without_changing_existing_bytes() {
        let dir = tempdir().unwrap();
        let disk = FileBacking::new(dir.path()).unwrap();
        let canonical = Enrollment {
            identity: ID,
            capacity: PAGE,
        }
        .encode()
        .unwrap();
        let file = disk.open(FILE, true).unwrap();
        for count in 0..LENGTH {
            file.set_len(0).unwrap();
            file.write_at(0, &canonical[..count]).unwrap();
            file.set_len(count as u64).unwrap();
            file.sync_data().unwrap();
            assert!(
                Enrollment::load_or_create(&disk, ID, PAGE).is_err(),
                "partial {count}"
            );
            assert_eq!(file.len().unwrap(), count as u64, "unchanged {count}");
        }
        file.set_len((LENGTH + 1) as u64).unwrap();
        file.write_at(0, &canonical).unwrap();
        file.sync_data().unwrap();
        assert!(Enrollment::load_or_create(&disk, ID, PAGE).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn enrollment_metadata_symlink_cannot_replace_an_outside_binding() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("metadata");
        let original = b"outside metadata must be preserved";
        std::fs::write(&target, original).unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(FILE)).unwrap();
        let disk = FileBacking::new(root.path()).unwrap();
        assert!(Enrollment::load(&disk).is_err());
        assert!(Enrollment::load_or_create(&disk, ID, PAGE).is_err());
        assert_eq!(std::fs::read(target).unwrap(), original);
    }

    #[derive(Default)]
    struct WritebackState {
        dirty: bool,
        fail_next_sync: bool,
        durable: Option<Vec<u8>>,
    }
    struct WritebackBacking {
        cache: crate::MemBacking,
        state: Arc<std::sync::Mutex<WritebackState>>,
    }
    impl WritebackBacking {
        fn new() -> Self {
            Self {
                cache: crate::MemBacking::new(),
                state: Arc::new(std::sync::Mutex::new(WritebackState {
                    fail_next_sync: true,
                    ..WritebackState::default()
                })),
            }
        }
        fn lose_page_cache(&self) {
            let durable = self.state.lock().unwrap().durable.clone();
            match durable {
                Some(bytes) => {
                    let file = self.cache.open(FILE, true).unwrap();
                    file.set_len(0).unwrap();
                    file.write_at(0, &bytes).unwrap();
                }
                None => self.cache.remove(FILE).unwrap(),
            }
        }
    }
    struct WritebackFile {
        cache: Arc<dyn BackingFile>,
        state: Arc<std::sync::Mutex<WritebackState>>,
    }
    impl BackingFile for WritebackFile {
        fn read_at(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
            self.cache.read_at(offset, bytes)
        }
        fn write_at(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
            self.cache.write_at(offset, bytes)?;
            self.state.lock().unwrap().dirty = true;
            Ok(())
        }
        fn set_len(&self, len: u64) -> io::Result<()> {
            // Updating EOF does not redirty content lost to failed writeback.
            self.cache.set_len(len)
        }
        fn len(&self) -> io::Result<u64> {
            self.cache.len()
        }
        fn sync_data(&self) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            if state.fail_next_sync {
                state.fail_next_sync = false;
                state.dirty = false;
                return Err(io::Error::other("injected clean-page writeback loss"));
            }
            if state.dirty {
                let mut bytes = vec![0; self.cache.len()? as usize];
                self.cache.read_at(0, &mut bytes)?;
                state.durable = Some(bytes);
                state.dirty = false;
            }
            Ok(())
        }
    }
    impl Backing for WritebackBacking {
        fn open(&self, name: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
            assert_eq!(name, FILE, "the model isolates one enrollment record");
            Ok(Arc::new(WritebackFile {
                cache: self.cache.open(name, create)?,
                state: self.state.clone(),
            }))
        }
        fn exists(&self, name: &str) -> io::Result<bool> {
            self.cache.exists(name)
        }
        fn remove(&self, name: &str) -> io::Result<()> {
            self.cache.remove(name)
        }
        fn rename(&self, from: &str, to: &str) -> io::Result<()> {
            self.cache.rename(from, to)
        }
        fn create_dir_all(&self, name: &str) -> io::Result<()> {
            self.cache.create_dir_all(name)
        }
        fn list(&self, name: &str) -> io::Result<Vec<String>> {
            self.cache.list(name)
        }
        fn sync_dir(&self, name: &str) -> io::Result<()> {
            self.cache.sync_dir(name)
        }
        fn try_lock(&self, name: &str) -> io::Result<Box<dyn VolumeLock>> {
            self.cache.try_lock(name)
        }
    }

    #[test]
    fn writeback_model_plain_sync_retry_cannot_persist_clean_page_cache() {
        let disk = WritebackBacking::new();
        let file = disk.open(FILE, true).unwrap();
        file.write_at(0, b"clean readable evidence").unwrap();
        assert!(file.sync_data().is_err());
        file.set_len(file.len().unwrap()).unwrap();
        file.sync_data().unwrap();
        disk.sync_dir("").unwrap();
        assert!(file.len().unwrap() > 0);
        disk.lose_page_cache();
        assert!(!disk.exists(FILE).unwrap());
    }

    #[test]
    fn readable_enrollment_after_failed_sync_is_rewritten_before_recovery_acknowledges_it() {
        let disk = WritebackBacking::new();
        assert!(Enrollment::load_or_create(&disk, ID, PAGE).is_err());
        // Linux leaves failed-writeback bytes readable but clean. Sync alone
        // cannot persist them; the existing binding must be rewritten first.
        let expected = Enrollment {
            identity: ID,
            capacity: PAGE,
        };
        assert_eq!(Enrollment::load(&disk).unwrap(), expected);
        assert_eq!(
            Enrollment::load_or_create(&disk, ID, PAGE).unwrap(),
            expected
        );
        disk.lose_page_cache();
        assert_eq!(Enrollment::load(&disk).unwrap(), expected);
    }
}
