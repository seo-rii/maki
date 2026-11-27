//! Many volumes stopping together (AUD-197). After its disconnect, a detach
//! or cleanup waits up to 15 s for the device to let go of the connection
//! (`await_release`) while something still holds it open. That wait ran
//! under the global attach lock, so when the devices of many volumes were
//! held open and the volumes stopped together, their cleanups queued on the
//! lock for 15 s each, and from about the eighth on reached the attach
//! unit's `TimeoutStopSec=120`.
//!
//! The wait runs without the lock. A verb lets go of it once the device
//! still shows the connection after the disconnect, and takes it again, in
//! turn, before it decides anything from what the wait showed: under the
//! lock it reads the volume's record again and goes on only if that is
//! still the record it disconnected. While it waits, only another helper of
//! the same volume can replace or retire the record; until then it still
//! names the device, so no other volume's attach and no provisioning connect
//! takes the device, and such a helper finds what it would find had this one
//! been killed during the wait.

use super::*;

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex};

/// The attachment of `volume` (Maki volume UUID `uuid`) on its pinned
/// `device`, made by a system of its own beside the others on `state`.
fn attached(
    state: &TrustedState,
    volume: &str,
    uuid: &str,
    device: &str,
) -> (AttachRequest, FakeSystem) {
    let mut request = parse(&format!("volume_uuid = '{uuid}'\n"))
        .unwrap()
        .into_request(volume, AttachOverrides::default(), true)
        .unwrap();
    request.nbd_device = device.into();
    let mut report = lvm_report_fixture();
    report["report"][0]["vg"][0]["vg_name"] = request.vg_name.clone().into();
    report["report"][0]["pv"][0]["pv_name"] = device.into();
    let mut system = FakeSystem {
        lvm_report: Some(report),
        ..Default::default()
    };
    execute_with(&plan_attach(&request), Some(state), &mut system).unwrap();
    assert_eq!(state.read(volume).unwrap().unwrap().device, device);
    system.steps.clear();
    (request, system)
}

/// Every sleep of a detach's or cleanup's wait finds the attach lock free:
/// another volume's helper can take it meanwhile. The verb still retires the
/// record in the same run once the device has let go, and leaves the lock
/// free.
#[test]
fn a_teardown_waits_for_a_held_open_device_without_the_attach_lock() {
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let request = request();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        system.steps.clear();
        system.linger = Some(Linger {
            sleeps: 7,
            then: Released::Gone,
        });
        let free = Arc::new(Mutex::new(Vec::new()));
        let (seen, root) = (free.clone(), fixture.0.clone());
        system.on_sleep = Some(Box::new(move |_, _| {
            seen.lock().unwrap().push(lock_is_free(&state_at(&root)));
        }));

        tear_down(verb, &request, &state, &mut system)
            .unwrap_or_else(|error| panic!("{verb}: {error}"));

        assert_eq!(
            *free.lock().unwrap(),
            [true; 7],
            "{verb}: the wait held the lock"
        );
        assert_eq!(system.sleeps, vec![NBD_RELEASE_INTERVAL; 7], "{verb}");
        assert_eq!(
            system.steps,
            ["umount", "lvm-deactivate", "nbd-disconnect"],
            "{verb}"
        );
        assert!(
            state.read("pg").unwrap().is_none(),
            "{verb}: the record was kept"
        );
        assert!(lock_is_free(&state), "{verb}: the lock stayed held");
    }
}

/// A device that shows no connection at the first look after the disconnect
/// needs no wait, and its teardown keeps its one turn on the lock: every
/// look at the device, the last included, is made with the lock held. A
/// teardown that let go of the lock there anyway would queue again, behind
/// every helper waiting for the lock, for nothing.
#[test]
fn a_device_that_lets_go_at_once_keeps_the_teardowns_one_turn() {
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let request = request();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        system.steps.clear();
        let free = Arc::new(Mutex::new(Vec::new()));
        let (seen, root) = (free.clone(), fixture.0.clone());
        system.on_backend = Some(Box::new(move || {
            seen.lock().unwrap().push(lock_is_free(&state_at(&root)));
        }));

        tear_down(verb, &request, &state, &mut system)
            .unwrap_or_else(|error| panic!("{verb}: {error}"));

        let free = free.lock().unwrap();
        assert!(!free.is_empty(), "{verb}");
        assert!(
            free.iter().all(|free| !free),
            "{verb}: a look found the lock let go of: {free:?}"
        );
        assert!(system.sleeps.is_empty(), "{verb}: {:?}", system.sleeps);
        assert!(state.read("pg").unwrap().is_none(), "{verb}");
    }
}

/// What the helpers of two volumes stopping together tell each other.
#[derive(Default)]
struct Board {
    /// The volumes whose helper has disconnected their device.
    disconnected: BTreeSet<&'static str>,
    /// The volumes whose device has let go of its connection.
    released: BTreeSet<&'static str>,
}

/// A monitoring tool holds every volume's device open, and closes them only
/// once the device of every volume has been disconnected. With the waits
/// under the attach lock they ran one after the other: the helper that
/// disconnected first waited out its 15 s with the lock held while the other
/// queued for it, and failed. Now the second disconnects while the first
/// waits, both devices let go, and each helper retires its own record in
/// one run.
#[test]
fn teardowns_of_two_held_open_devices_wait_side_by_side() {
    const VOLUMES: [(&str, &str, &str); 2] = [
        ("pg", "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c", "/dev/nbd3"),
        ("db", "1f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2d", "/dev/nbd4"),
    ];
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let board = Arc::new((Mutex::new(Board::default()), Condvar::new()));
        let helpers: Vec<_> = VOLUMES
            .iter()
            .map(|&(volume, uuid, device)| {
                let (request, mut system) = attached(&state, volume, uuid, device);
                // The disconnect leaves the device showing the connection.
                system.defer_disconnect = true;
                let (board, root) = (board.clone(), fixture.0.clone());
                system.on_sleep = Some(Box::new(move |system, _| {
                    let (shared, changed) = &*board;
                    let mut seen = shared.lock().unwrap();
                    if system.steps.contains(&"nbd-disconnect") && seen.disconnected.insert(volume)
                    {
                        changed.notify_all();
                    }
                    let probe = state_at(&root);
                    let started = Instant::now();
                    loop {
                        if seen.disconnected.len() == VOLUMES.len() {
                            system.backends.remove(device);
                            seen.released.insert(volume);
                            return;
                        }
                        // The other helper waits for the lock that this one
                        // holds through its wait: it cannot disconnect, and
                        // this sleep passes with the device held.
                        if probe.lock_waiters() > 0 {
                            return;
                        }
                        assert!(
                            started.elapsed() < Duration::from_secs(60),
                            "{volume}: the other helper neither queued for the lock nor \
                             disconnected"
                        );
                        seen = changed
                            .wait_timeout(seen, Duration::from_millis(1))
                            .unwrap()
                            .0;
                    }
                }));
                (volume, request, system, state_at(&fixture.0))
            })
            .collect();

        let results: Vec<_> = std::thread::scope(|scope| {
            let running: Vec<_> = helpers
                .into_iter()
                .map(|(volume, request, mut system, state)| {
                    scope.spawn(move || {
                        let result = tear_down(verb, &request, &state, &mut system);
                        (volume, result.map_err(|error| error.to_string()), system)
                    })
                })
                .collect();
            running
                .into_iter()
                .map(|helper| helper.join().unwrap())
                .collect()
        });

        for (volume, result, system) in &results {
            assert_eq!(result, &Ok(()), "{verb} of {volume}");
            assert_eq!(
                system.steps,
                ["umount", "lvm-deactivate", "nbd-disconnect"],
                "{verb} of {volume}"
            );
            assert!(state.read(volume).unwrap().is_none(), "{verb} of {volume}");
        }
        // A device let go only once both were disconnected: each helper's
        // wait ended after the other's disconnect.
        let seen = board.0.lock().unwrap();
        assert_eq!(seen.released.len(), VOLUMES.len(), "{verb}");
        assert!(lock_is_free(&state), "{verb}: the lock stayed held");
    }
}

/// Another attach of the same volume can run while the helper waits: it
/// finds the record of a disconnected attachment with nothing left of it,
/// as after a helper killed during its wait, and replaces it before it
/// connects. Under the lock again the waiting helper reads the record anew,
/// keeps the new attachment's record and leaves it alone.
#[test]
fn a_record_replaced_during_the_wait_is_kept() {
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let request = request();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        let disconnected = state.read("pg").unwrap().unwrap();
        let nonce = std::fs::read_to_string("/proc/sys/kernel/random/uuid").unwrap();
        let replacing = BoundDeviceRecord {
            connection_id: format!("maki-{}", nonce.trim()),
            ..disconnected.clone()
        };
        system.steps.clear();
        system.defer_disconnect = true;
        let attaching = Arc::new(Mutex::new(None));
        let (started, root, record) = (attaching.clone(), fixture.0.clone(), replacing.clone());
        system.on_sleep = Some(Box::new(move |system, sleep| {
            if sleep != 3 {
                return;
            }
            let Ok(held) = state_at(&root).lock_until(Instant::now()) else {
                return;
            };
            // The opener lets go, and the other attach takes the lock first.
            system.backends.remove("/dev/nbd3");
            let (root, record) = (root.clone(), record.clone());
            *started.lock().unwrap() = Some(std::thread::spawn(move || {
                let state = state_at(&root);
                let queued = Instant::now();
                while state.lock_waiters() == 0 && queued.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                state.write(&record).unwrap();
                drop(held);
            }));
        }));

        let result = tear_down(verb, &request, &state, &mut system);
        if let Some(attach) = attaching.lock().unwrap().take() {
            attach.join().unwrap();
        }

        let error = result
            .expect_err("the waiting helper went on with a record it had not disconnected")
            .to_string();
        assert!(
            error.contains("attach record was replaced while this helper waited"),
            "{verb}: {error}"
        );
        assert_eq!(state.read("pg").unwrap(), Some(replacing), "{verb}");
        assert_eq!(
            system.steps,
            ["umount", "lvm-deactivate", "nbd-disconnect"],
            "{verb}"
        );
        assert_eq!(system.sleeps, vec![NBD_RELEASE_INTERVAL; 3], "{verb}");
    }
}

/// The attach that replaces the record during the wait can connect the same
/// device, which the allocator hands out again once it shows no connection:
/// the wait then ends at a look that shows the new attachment's backend
/// identifier. The waiting helper must not report that as a disconnect that
/// has not completed, whose advice to run cleanup again would tear the new
/// attachment down: under the lock again it finds the replaced record and
/// says so, and leaves the record and the connection alone.
#[test]
fn a_device_connected_again_for_a_replaced_record_ends_the_wait_as_replaced() {
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let request = request();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        let disconnected = state.read("pg").unwrap().unwrap();
        let nonce = std::fs::read_to_string("/proc/sys/kernel/random/uuid").unwrap();
        let replacing = BoundDeviceRecord {
            connection_id: format!("maki-{}", nonce.trim()),
            ..disconnected.clone()
        };
        system.steps.clear();
        system.defer_disconnect = true;
        let (root, record) = (fixture.0.clone(), replacing.clone());
        system.on_sleep = Some(Box::new(move |system, sleep| {
            if sleep != 3 {
                return;
            }
            let state = state_at(&root);
            let Ok(_attaching) = state.lock_until(Instant::now()) else {
                return;
            };
            // The opener lets go; the other attach writes its record, then
            // connects the device under its own identifier.
            state.write(&record).unwrap();
            system
                .backends
                .insert("/dev/nbd3".into(), record.connection_id.clone());
        }));

        let error = tear_down(verb, &request, &state, &mut system)
            .expect_err("the waiting helper succeeded beside another attachment")
            .to_string();

        assert!(
            error.contains("attach record was replaced while this helper waited"),
            "{verb}: {error}"
        );
        assert!(!error.contains("cleanup retry"), "{verb}: {error}");
        assert_eq!(state.read("pg").unwrap(), Some(replacing.clone()), "{verb}");
        assert_eq!(
            system.backends.get("/dev/nbd3"),
            Some(&replacing.connection_id),
            "{verb}"
        );
        assert_eq!(
            system.steps,
            ["umount", "lvm-deactivate", "nbd-disconnect"],
            "{verb}"
        );
        assert_eq!(system.sleeps, vec![NBD_RELEASE_INTERVAL; 3], "{verb}");
    }
}

/// Another cleanup of the same volume can run while the helper waits: once
/// the device has let go it finds a disconnected record with nothing left of
/// it and retires it. The waiting helper then finds no record under the
/// lock, which is what its own run would have left: it succeeds and does
/// nothing more.
#[test]
fn a_record_another_helper_retired_during_the_wait_ends_the_run() {
    for verb in ["detach", "cleanup"] {
        let fixture = Fixture::new();
        let state = fixture.state();
        let request = request();
        let mut system = FakeSystem::default();
        execute_with(&plan_attach(&request), Some(&state), &mut system).unwrap();
        system.steps.clear();
        system.defer_disconnect = true;
        let retired = Arc::new(Mutex::new(None));
        let (outcome, root, plan) = (retired.clone(), fixture.0.clone(), plan_detach(&request));
        system.on_sleep = Some(Box::new(move |system, sleep| {
            if sleep != 3 || !lock_is_free(&state_at(&root)) {
                return;
            }
            system.backends.remove("/dev/nbd3");
            let mut other = FakeSystem::default();
            let result = cleanup_on(&plan, &state_at(&root), &mut other);
            *outcome.lock().unwrap() =
                Some((result.map_err(|error| error.to_string()), other.steps));
        }));

        let (result, log) = logged(|| tear_down(verb, &request, &state, &mut system));

        result.unwrap_or_else(|error| panic!("{verb}: {error}"));
        assert_eq!(
            retired.lock().unwrap().take(),
            Some((Ok(()), Vec::new())),
            "{verb}: the other cleanup did not run while this helper waited"
        );
        assert!(state.read("pg").unwrap().is_none(), "{verb}");
        assert_eq!(
            system.steps,
            ["umount", "lvm-deactivate", "nbd-disconnect"],
            "{verb}"
        );
        assert!(
            log.contains("another helper retired the attach record of volume pg"),
            "{verb}: {log}"
        );
    }
}
