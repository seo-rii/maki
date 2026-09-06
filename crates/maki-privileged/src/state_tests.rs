use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "maki-trusted-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    fn state(&self) -> io::Result<TrustedState> {
        TrustedState::open_beneath(
            File::open(&self.0)?,
            Path::new("state"),
            self.0.metadata()?.uid(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record() -> BoundDeviceRecord {
    BoundDeviceRecord {
        version: 1,
        volume: "pg".into(),
        attachment: crate::plan::AttachmentIdentity {
            volume_uuid: "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c".into(),
            nbd_socket: "/run/maki/pg/nbd.sock".into(),
            mountpoint: "/srv/pg".into(),
            vg_name: "vg_maki_pg".into(),
            lv_name: "data".into(),
        },
        device: "/dev/nbd3".into(),
        connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
    }
}

#[test]
fn records_round_trip_atomically_with_private_regular_files() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    let lock = state.lock().unwrap();
    assert_eq!(lock.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    assert!(state.read("pg").unwrap().is_none());
    let mut entry = record();
    state.write(&entry).unwrap();
    assert_eq!(state.read("pg").unwrap(), Some(entry.clone()));
    let meta = fixture.0.join("state/pg.nbd").metadata().unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    entry.device = "/dev/nbd4".into();
    state.write(&entry).unwrap();
    assert_eq!(state.read("pg").unwrap(), Some(entry));
    state.remove("pg").unwrap();
    assert!(state.read("pg").unwrap().is_none());
}

#[test]
fn untrusted_directory_owner_and_writable_ancestors_are_rejected() {
    let fixture = Fixture::new();
    let uid = fixture.0.metadata().unwrap().uid();
    assert!(TrustedState::open_beneath(
        File::open(&fixture.0).unwrap(),
        Path::new("state"),
        uid.wrapping_add(1),
    )
    .is_err());
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(fixture.state().is_err());
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(fixture.0.join("state")).unwrap();
    std::fs::set_permissions(
        fixture.0.join("state"),
        std::fs::Permissions::from_mode(0o707),
    )
    .unwrap();
    assert!(fixture.state().is_err());
}

#[test]
fn symlink_directories_locks_and_records_are_not_followed() {
    let fixture = Fixture::new();
    let target = fixture.0.join("target");
    std::fs::create_dir(&target).unwrap();
    symlink(&target, fixture.0.join("state")).unwrap();
    assert!(fixture.state().is_err());
    std::fs::remove_file(fixture.0.join("state")).unwrap();
    let state = fixture.state().unwrap();
    std::fs::write(target.join("fixture"), "unchanged").unwrap();
    for name in ["attach.lock", "pg.nbd"] {
        symlink(target.join("fixture"), fixture.0.join("state").join(name)).unwrap();
    }
    assert!(state.lock().is_err());
    assert!(state.read("pg").is_err());
    assert_eq!(
        std::fs::read_to_string(target.join("fixture")).unwrap(),
        "unchanged"
    );
}

#[test]
fn malformed_legacy_oversized_and_shared_records_fail_closed() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    state.write(&record()).unwrap();
    let path = fixture.0.join("state/pg.nbd");
    for text in [
        "/dev/nbd3\n".to_string(),
        "x".repeat(RECORD_MAX_BYTES as usize + 1),
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(state.read("pg").is_err());
    }
    std::fs::write(&path, serde_json::to_vec(&record()).unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    assert!(state.read("pg").is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::hard_link(&path, fixture.0.join("linked")).unwrap();
    assert!(state.read("pg").is_err());
}

#[test]
fn record_names_cannot_escape_the_open_directory() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    for name in ["../pg", "/pg", "pg/other", ".", ".."] {
        assert!(state.read(name).is_err(), "{name}");
        assert!(state.remove(name).is_err(), "{name}");
        let mut entry = record();
        entry.volume = name.into();
        assert!(state.write(&entry).is_err(), "{name}");
    }
}
