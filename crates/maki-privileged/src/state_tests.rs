use super::*;

/// Fixture directories are named by pid + wall clock; the clock can repeat
/// within one process (coarse ticks), so a per-process sequence keeps them
/// unique.
static FIXTURE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
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
                | (u128::from(FIXTURE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
                    << 96)
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
            lvm_identity: None,
        },
        device: "/dev/nbd3".into(),
        connection_id: "maki-11111111-2222-4333-8444-555555555555".into(),
        recovery: None,
        recovery_intent: None,
    }
}

#[test]
fn records_round_trip_atomically_with_private_regular_files() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    let lock = state.lock().unwrap();
    assert_eq!(
        lock.0.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
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
fn encoded_record_bound_is_shared_by_reads_and_writes_without_losing_prior_state() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    let mut entry = record();
    // JSON escaping counts toward the encoded bound, not just the input's
    // string length. This remains a canonical absolute path.
    entry.attachment.nbd_socket = format!("/{}", "\"".repeat(4096));
    let initial_size = serde_json::to_vec(&entry).unwrap().len();
    assert!(initial_size > 4096);
    entry
        .attachment
        .nbd_socket
        .push_str(&"x".repeat(RECORD_MAX_BYTES as usize - initial_size));
    assert_eq!(
        serde_json::to_vec(&entry).unwrap().len(),
        RECORD_MAX_BYTES as usize
    );
    state.write(&entry).unwrap();
    assert_eq!(state.read("pg").unwrap(), Some(entry.clone()));

    let before = std::fs::read(fixture.0.join("state/pg.nbd")).unwrap();
    entry.attachment.nbd_socket.push('x');
    assert!(state.write(&entry).is_err());
    assert_eq!(
        std::fs::read(fixture.0.join("state/pg.nbd")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read_dir(fixture.0.join("state")).unwrap().count(),
        1
    );
    entry.attachment.nbd_socket.pop();
    assert_eq!(state.read("pg").unwrap(), Some(entry));
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

#[test]
fn verification_never_creates_a_missing_state_directory_or_lock() {
    let fixture = Fixture::new();
    let owner = fixture.0.metadata().unwrap().uid();
    assert!(TrustedState::open_existing_beneath(
        File::open(&fixture.0).unwrap(),
        Path::new("missing"),
        owner,
    )
    .is_err());
    assert!(!fixture.0.join("missing").exists());
    let state = fixture.state().unwrap();
    assert!(state.lock_existing().is_err());
    assert!(!fixture.0.join("state/attach.lock").exists());
    drop(state.lock().unwrap());
    assert!(state.lock_existing().is_ok());
}

#[test]
fn verify_config_loading_pins_trusted_descriptors_and_bounds_content() {
    let fixture = Fixture::new();
    let owner = fixture.0.metadata().unwrap().uid();
    let config = fixture.0.join("volume.toml");
    std::fs::write(&config, "volume_uuid = 'test'\n").unwrap();
    let load = || {
        read_config_beneath(
            File::open(&fixture.0).unwrap(),
            Path::new("volume.toml"),
            owner,
        )
    };
    assert_eq!(load().unwrap(), "volume_uuid = 'test'\n");
    assert!(read_config_beneath(
        File::open(&fixture.0).unwrap(),
        Path::new("volume.toml"),
        owner.wrapping_add(1)
    )
    .is_err());
    let linked = fixture.0.join("linked");
    std::fs::hard_link(&config, &linked).unwrap();
    assert!(load().is_err());
    std::fs::remove_file(linked).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(load().is_err());
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&config, vec![b'x'; CONFIG_MAX_BYTES as usize + 1]).unwrap();
    assert!(load().is_err());
    std::fs::remove_file(&config).unwrap();
    symlink("missing", &config).unwrap();
    assert!(load().is_err());
    assert!(!fixture.0.join("missing").exists());
}

/// A child forked from this process that waits before its `exec` until it is
/// dropped. Until then it holds a copy of every descriptor this process had
/// when it forked, as each command the helper runs does between its fork and
/// its `exec`.
struct PausedChild {
    resume: std::io::PipeWriter,
    spawner: Option<std::thread::JoinHandle<io::Result<std::process::ExitStatus>>>,
}

impl PausedChild {
    fn fork() -> Self {
        use std::os::unix::process::CommandExt;
        let (mut forked, forked_writer) = std::io::pipe().unwrap();
        let (resume_reader, resume) = std::io::pipe().unwrap();
        let parent_end = resume.as_raw_fd();
        let mut command = std::process::Command::new("/bin/true");
        // SAFETY: the hook runs in the forked child before `exec` and only
        // closes, writes and reads pipe descriptors; it allocates nothing.
        unsafe {
            command.pre_exec(move || {
                // Without the parent's write end, a parent that dies without
                // resuming the child ends its wait instead of hanging it.
                drop(std::os::fd::OwnedFd::from_raw_fd(parent_end));
                (&forked_writer).write_all(&[1])?;
                (&resume_reader).read_exact(&mut [0])?;
                Ok(())
            });
        }
        // `spawn` returns only once the child has exec'd.
        let spawner = std::thread::spawn(move || command.spawn()?.wait());
        forked.read_exact(&mut [0]).expect("the child forked");
        Self {
            resume,
            spawner: Some(spawner),
        }
    }
}

impl Drop for PausedChild {
    fn drop(&mut self) {
        let _ = self.resume.write_all(&[1]);
        let status = self.spawner.take().unwrap().join();
        if !std::thread::panicking() {
            assert!(status.unwrap().unwrap().success());
        }
    }
}

/// The failed-start hook must not queue behind another volume's helper for
/// as long as that one runs: its lock attempt ends at its deadline, and
/// succeeds once the lock is free.
#[test]
fn a_bounded_lock_attempt_gives_up_at_its_deadline() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    let held = state.lock().unwrap();
    let started = Instant::now();
    let error = state
        .lock_until(started + Duration::from_millis(150))
        .err()
        .expect("the lock is held");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() >= Duration::from_millis(150));
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(held);
    let lock = state.lock_until(Instant::now()).unwrap();
    assert!(
        state.lock_until(Instant::now()).is_err(),
        "a bounded attempt took a lock that is held"
    );
    drop(lock);
}

/// The attach lock is a `flock` on `attach.lock`, which belongs to the open
/// file description. A command forked meanwhile shares that description until
/// its `exec`; when releasing only closed the helper's descriptor, the next
/// attach, detach, grow or verification waited for that child.
#[test]
fn a_released_attach_lock_is_free_while_a_forked_child_holds_its_descriptor() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    drop(state.lock().unwrap());
    for existing in [false, true] {
        let lock = if existing {
            state.lock_existing()
        } else {
            state.lock()
        }
        .unwrap();
        let child = PausedChild::fork();
        drop(lock);
        // `lock` blocks; probe without waiting for the child.
        let probe = File::open(fixture.0.join("state/attach.lock")).unwrap();
        assert!(
            probe.try_lock().is_ok(),
            "existing={existing}: a released attach lock stayed held for a forked child"
        );
        drop((probe, child));
    }
}

/// Allocation asks which devices other volumes' records name. The lock, a
/// temporary record of a killed write and the asking volume's own record are
/// not such records.
#[test]
fn recorded_devices_of_other_volumes_are_listed_by_device() {
    let fixture = Fixture::new();
    let state = fixture.state().unwrap();
    let _lock = state.lock().unwrap();
    assert!(state.devices_of_other_volumes("db").unwrap().is_empty());
    let mut entry = record();
    state.write(&entry).unwrap();
    entry.volume = "minio".into();
    entry.device = "/dev/nbd7".into();
    state.write(&entry).unwrap();
    std::fs::write(
        fixture
            .0
            .join("state/.pg.4242.maki-11111111-2222-4333-8444-555555555555.tmp"),
        b"{\"version\":1,\"vol",
    )
    .unwrap();

    let devices = |volume: &str| {
        state
            .devices_of_other_volumes(volume)
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        devices("db"),
        [
            ("/dev/nbd3".to_string(), "pg".to_string()),
            ("/dev/nbd7".to_string(), "minio".to_string()),
        ]
    );
    assert_eq!(
        devices("pg"),
        [("/dev/nbd7".to_string(), "minio".to_string())]
    );
    // The listing follows the held descriptor, not the directory's path.
    std::fs::rename(fixture.0.join("state"), fixture.0.join("moved")).unwrap();
    assert_eq!(
        devices("minio"),
        [("/dev/nbd3".to_string(), "pg".to_string())]
    );
}

/// A `<volume>.nbd` entry that is not a readable trusted record could name
/// any device: the listing fails and names it instead of leaving it out.
#[test]
fn an_unreadable_record_fails_the_listing_and_is_named() {
    for (name, content, mode) in [
        ("pg.nbd", b"/dev/nbd3\n".to_vec(), 0o600),
        ("pg.nbd", serde_json::to_vec(&record()).unwrap(), 0o640),
        ("minio.nbd", serde_json::to_vec(&record()).unwrap(), 0o600),
        ("pg vol.nbd", serde_json::to_vec(&record()).unwrap(), 0o600),
        (".nbd", Vec::new(), 0o600),
    ] {
        let fixture = Fixture::new();
        let state = fixture.state().unwrap();
        let path = fixture.0.join("state").join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        let error = state.devices_of_other_volumes("db").unwrap_err();
        assert!(
            error.to_string().contains(&format!("/{name}\"")),
            "{name:?}: {error}"
        );
    }
    // A symlink and a directory under a record's name are refused too.
    for obstruct in ["symlink", "directory"] {
        let fixture = Fixture::new();
        let state = fixture.state().unwrap();
        state.write(&record()).unwrap();
        let path = fixture.0.join("state/minio.nbd");
        if obstruct == "symlink" {
            symlink("pg.nbd", &path).unwrap();
        } else {
            std::fs::create_dir(&path).unwrap();
        }
        assert!(
            state.devices_of_other_volumes("db").is_err(),
            "accepted a {obstruct} as a record"
        );
    }
}
