use std::io;

use maki_backing::{Backing, BackingFile, MemBacking};

struct UnsupportedFile;

impl BackingFile for UnsupportedFile {
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<()> {
        unimplemented!()
    }

    fn write_at(&self, _offset: u64, _data: &[u8]) -> io::Result<()> {
        unimplemented!()
    }

    fn set_len(&self, _len: u64) -> io::Result<()> {
        unimplemented!()
    }

    fn len(&self) -> io::Result<u64> {
        unimplemented!()
    }

    fn sync_data(&self) -> io::Result<()> {
        unimplemented!()
    }
}

#[test]
fn backings_without_hole_punch_support_report_unsupported() {
    assert_eq!(
        UnsupportedFile.punch_hole(0, 1).unwrap_err().kind(),
        io::ErrorKind::Unsupported
    );
}

#[test]
fn memory_hole_punch_zeroes_only_the_existing_intersection() {
    let backing = MemBacking::new();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, b"abcdefghij").unwrap();

    file.punch_hole(3, 4).unwrap();
    let mut contents = [0; 10];
    file.read_at(0, &mut contents).unwrap();
    assert_eq!(&contents, b"abc\0\0\0\0hij");
    assert_eq!(file.len().unwrap(), 10);

    file.punch_hole(8, 20).unwrap();
    file.read_at(0, &mut contents).unwrap();
    assert_eq!(&contents, b"abc\0\0\0\0h\0\0");
    assert_eq!(file.len().unwrap(), 10);
    file.punch_hole(100, 50).unwrap();
    file.punch_hole(u64::MAX, 0).unwrap();
    assert_eq!(file.len().unwrap(), 10);
}

#[test]
fn memory_hole_punch_rejects_overflow_without_mutation() {
    let backing = MemBacking::new();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, b"unchanged").unwrap();

    assert_eq!(
        file.punch_hole(u64::MAX - 1, 4).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    let mut contents = [0; 9];
    file.read_at(0, &mut contents).unwrap();
    assert_eq!(&contents, b"unchanged");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use maki_backing::FileBacking;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    const MIB: usize = 1024 * 1024;

    fn unsupported(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP)
        )
    }

    #[test]
    fn real_hole_punch_is_durable_preserves_length_and_releases_blocks() {
        let temporary = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(temporary.path()).unwrap();
        let file = backing.open("data", true).unwrap();
        let contents = vec![0x5a; 16 * MIB];
        file.write_at(0, &contents).unwrap();
        file.sync_data().unwrap();
        let blocks_before = fs::metadata(temporary.path().join("data"))
            .unwrap()
            .blocks();

        if let Err(error) = file.punch_hole((4 * MIB) as u64, (8 * MIB) as u64) {
            if unsupported(&error) {
                eprintln!("filesystem does not support physical hole punching: {error}");
                return;
            }
            panic!("hole punch failed: {error}");
        }
        file.sync_data().unwrap();
        drop(file);

        let blocks_after = fs::metadata(temporary.path().join("data"))
            .unwrap()
            .blocks();
        assert!(
            blocks_after < blocks_before,
            "physical blocks did not decrease"
        );
        let reopened = backing.open("data", false).unwrap();
        assert_eq!(reopened.len().unwrap(), (16 * MIB) as u64);
        let mut before = [0; 1];
        let mut hole = vec![1; 8 * MIB];
        let mut after = [0; 1];
        reopened.read_at((4 * MIB - 1) as u64, &mut before).unwrap();
        reopened.read_at((4 * MIB) as u64, &mut hole).unwrap();
        reopened.read_at((12 * MIB) as u64, &mut after).unwrap();
        assert_eq!(before, [0x5a]);
        assert!(hole.iter().all(|byte| *byte == 0));
        assert_eq!(after, [0x5a]);

        reopened
            .allocate_range((4 * MIB) as u64, (8 * MIB) as u64)
            .unwrap();
        reopened
            .write_at((4 * MIB) as u64, &contents[..8 * MIB])
            .unwrap();
        reopened.sync_data().unwrap();
        let mut rewritten = [0; 1];
        reopened.read_at((8 * MIB) as u64, &mut rewritten).unwrap();
        assert_eq!(rewritten, [0x5a]);
    }

    #[test]
    fn real_hole_punch_handles_unaligned_and_out_of_file_ranges() {
        let temporary = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(temporary.path()).unwrap();
        let file = backing.open("data", true).unwrap();
        file.write_at(0, &[0x7b; 8192]).unwrap();

        if let Err(error) = file.punch_hole(123, 4567) {
            if unsupported(&error) {
                eprintln!("filesystem does not support hole punching: {error}");
                return;
            }
            panic!("hole punch failed: {error}");
        }
        let mut contents = [0; 8192];
        file.read_at(0, &mut contents).unwrap();
        assert!(contents[..123].iter().all(|byte| *byte == 0x7b));
        assert!(contents[123..4690].iter().all(|byte| *byte == 0));
        assert!(contents[4690..].iter().all(|byte| *byte == 0x7b));

        file.punch_hole(16_384, 4096).unwrap();
        file.punch_hole(u64::MAX, 0).unwrap();
        assert_eq!(file.len().unwrap(), 8192);
        let before_overflow = contents;
        assert_eq!(
            file.punch_hole(u64::MAX - 1, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(file.len().unwrap(), 8192);
        file.read_at(0, &mut contents).unwrap();
        assert_eq!(contents, before_overflow);
        assert_eq!(
            file.punch_hole(i64::MAX as u64 - 1, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        file.read_at(0, &mut contents).unwrap();
        assert_eq!(contents, before_overflow);
    }
}
