use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
const UUID: &str = "11111111-2222-3333-4444-555555555555";

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-atomic-sentinel-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn mountpoint(&self) -> &str {
        self.0.to_str().unwrap()
    }
    fn step(&self) -> PlannedStep {
        PlannedStep::WriteSentinel {
            mountpoint: self.mountpoint().into(),
            volume_uuid: UUID.into(),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn every_publication_failure_retries_complete_bytes_and_required_syncs() {
    for fault in [
        "write",
        "file-sync",
        "publish",
        "published",
        "directory-sync",
    ] {
        let fixture = Fixture::new();
        let first =
            write_sentinel_with_boundary(&fixture.step(), fixture.mountpoint(), UUID, |boundary| {
                if boundary == fault {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            });
        assert!(first.is_err(), "{fault}");
        let expected_published = matches!(fault, "published" | "directory-sync");
        assert_eq!(
            fixture.0.join(SENTINEL_FILE).exists(),
            expected_published,
            "{fault}"
        );
        assert_eq!(
            std::fs::read_dir(&fixture.0).unwrap().count(),
            usize::from(expected_published),
            "temporary left after {fault}"
        );
        let mut retried = Vec::new();
        write_sentinel_with_boundary(&fixture.step(), fixture.mountpoint(), UUID, |boundary| {
            retried.push(boundary);
            Ok(())
        })
        .unwrap();
        assert!(
            retried.contains(&"write")
                && retried.contains(&"file-sync")
                && retried.contains(&"directory-sync"),
            "{fault}: {retried:?}"
        );
        assert_eq!(
            std::fs::read(fixture.0.join(SENTINEL_FILE)).unwrap(),
            format!("{UUID}\n").as_bytes()
        );
    }
}

#[test]
fn same_uuid_is_rewritten_to_exact_length_before_sync_and_resynced_on_retry() {
    let fixture = Fixture::new();
    let path = fixture.0.join(SENTINEL_FILE);
    std::fs::write(&path, format!("{UUID}\n     ")).unwrap();
    let mut writes = 0;
    let first =
        write_sentinel_with_boundary(&fixture.step(), fixture.mountpoint(), UUID, |boundary| {
            if boundary == "write" {
                writes += 1;
            }
            if boundary == "file-sync" {
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    format!("{UUID}\n").as_bytes()
                );
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        });
    assert!(first.is_err());
    write_sentinel_with_boundary(&fixture.step(), fixture.mountpoint(), UUID, |boundary| {
        if boundary == "write" {
            writes += 1;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(
        writes, 2,
        "retry must re-dirty bytes instead of plain fsync"
    );
}

#[test]
fn foreign_sentinel_and_links_are_never_replaced_or_rewritten() {
    use std::os::unix::fs::{symlink, MetadataExt};
    for kind in ["foreign", "symlink", "hardlink", "partial"] {
        let fixture = Fixture::new();
        let path = fixture.0.join(SENTINEL_FILE);
        let target = fixture.0.join("target");
        let bytes = if kind == "partial" {
            b"11111111-2".to_vec()
        } else {
            b"foreign sentinel\n".to_vec()
        };
        match kind {
            "symlink" => {
                std::fs::write(&target, &bytes).unwrap();
                symlink(&target, &path).unwrap();
            }
            "hardlink" => {
                std::fs::write(&target, format!("{UUID}\n")).unwrap();
                std::fs::hard_link(&target, &path).unwrap();
            }
            _ => std::fs::write(&path, &bytes).unwrap(),
        }
        let before = std::fs::read(&path).unwrap();
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        assert!(
            write_sentinel(&fixture.step(), fixture.mountpoint(), UUID).is_err(),
            "{kind}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{kind}");
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
    }
}

#[test]
fn concurrent_publication_cannot_replace_foreign_sentinel() {
    let fixture = Fixture::new();
    let path = fixture.0.join(SENTINEL_FILE);
    let result =
        write_sentinel_with_boundary(&fixture.step(), fixture.mountpoint(), UUID, |boundary| {
            if boundary == "publish" {
                std::fs::write(&path, "foreign sentinel\n")?;
            }
            Ok(())
        });
    assert!(result.is_err());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "foreign sentinel\n"
    );
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}
