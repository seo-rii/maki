//! A device the kernel keeps refusing as busy. Something has the
//! unconnected device open (a udev probe that does not end, a monitoring
//! agent, a leaked descriptor), and an open shows nowhere in sysfs: no
//! `pid`, no backend identifier, no holder, no mount. Automatic allocation
//! therefore hands out the same lowest device on every attempt, to every
//! volume on the host, while the devices above it are free.
//!
//! An attach that allocated its device itself gives such a device up for
//! the next free one, within one step's time. The record moves first, under
//! the attach lock, so a record published before a connect still keeps its
//! device and no two volumes are ever handed the same one. A pinned
//! `nbd_device` is never given up.

use super::*;

fn connects(host: &Host) -> usize {
    host.commands
        .iter()
        .filter(|command| **command == "nbd-connect")
        .count()
}

fn shows_no_connection(host: &Host, device: &str) -> bool {
    host.backend(device).unwrap().is_none() && !host.nbd(device).join("pid").exists()
}

/// The attach ends on the next free device, with everything it then does
/// bound to that device, and the device it gave up is nobody's.
#[test]
fn an_attach_moves_past_an_allocated_device_that_stays_busy() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);

    execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host)
        .unwrap_or_else(|error| panic!("the attach did not move on: {error}"));

    let record = state.read("pg").unwrap().unwrap();
    assert_eq!(record.device, "/dev/nbd4");
    assert_attached(&host, &record);
    assert_eq!(connects(&host), 2, "{:?}", host.commands);
    assert!(shows_no_connection(&host, "/dev/nbd3"));
    let mapping = host.mapping("vg_maki_pg").unwrap();
    assert!(mapping.join("slaves/nbd4").exists(), "the VG is on nbd4");
    // Each device was asked for under an identifier of its own. The record
    // carries the one that connected, and every later step that names a
    // device names that device.
    let [(first, given_up), (second, connected)] = host.connect_requests.as_slice() else {
        panic!("{:?}", host.connect_requests);
    };
    assert_eq!(
        (first.as_str(), second.as_str()),
        ("/dev/nbd3", "/dev/nbd4")
    );
    assert_ne!(given_up, connected);
    assert_eq!(&record.connection_id, connected);
    assert!(!host.named_devices.is_empty());
    assert!(
        host.named_devices
            .iter()
            .all(|(_, device)| device == "/dev/nbd4"),
        "{:?}",
        host.named_devices
    );

    // The teardown follows the record to the device it names.
    execute_with(&plan_detach(&request(&PG)), Some(&state), &mut host).unwrap();
    assert!(state.read("pg").unwrap().is_none());
    assert!(shows_no_connection(&host, "/dev/nbd4"));

    // Once the opener lets go, the device is handed out again.
    host.refused_connects.clear();
    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
    assert_eq!(state.read("db").unwrap().unwrap().device, "/dev/nbd3");
}

/// The record names the next device, under an identifier of its own, before
/// that device is connected: a helper killed in between leaves the state a
/// killed attach always left, which keeps the device for its volume.
#[test]
fn the_record_moves_to_the_next_device_before_that_is_connected() {
    let mut host = Host::new();
    host.add_device(5);
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);
    // What the first record says, read when the helper dies before the
    // first connect.
    host.killed_before_connecting = Some("/dev/nbd3");
    assert!(killed(|| {
        let _ = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host);
    }));
    let first = state.read("pg").unwrap().unwrap();
    assert_eq!(first.device, "/dev/nbd3");
    cleanup_with(&plan_detach(&request(&PG)), &state, &mut host).unwrap();

    host.killed_before_connecting = Some("/dev/nbd4");
    assert!(killed(|| {
        let _ = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host);
    }));
    host.killed_before_connecting = None;

    let moved = state
        .read("pg")
        .unwrap()
        .expect("the record outlives the killed helper");
    assert_eq!(moved.device, "/dev/nbd4");
    assert_ne!(moved.connection_id, first.connection_id);
    assert!(moved.recovery.is_none() && moved.recovery_intent.is_none());
    assert!(shows_no_connection(&host, "/dev/nbd4"));

    // Another volume is handed neither the device held open nor the one the
    // record names.
    host.commands.clear();
    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
    let other = state.read("db").unwrap().unwrap();
    assert_eq!(other.device, "/dev/nbd5");
    assert_attached(&host, &other);
    assert_eq!(state.read("pg").unwrap(), Some(moved));

    // The recorded volume's own verbs end the state as they always did.
    host.commands.clear();
    cleanup_with(&plan_detach(&request(&PG)), &state, &mut host).unwrap();
    assert!(host.commands.is_empty(), "{:?}", host.commands);
    assert!(state.read("pg").unwrap().is_none());
}

/// Two volumes beside a device that stays busy: each gets a device of its
/// own or none, never the other's.
#[test]
fn volumes_beside_a_busy_device_never_share_one() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);

    execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host).unwrap();
    let first = state.read("pg").unwrap().unwrap();
    assert_eq!(first.device, "/dev/nbd4");

    // The only device left for the second volume is the busy one.
    host.commands.clear();
    let error = execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host)
        .expect_err("attached without a free device")
        .to_string();
    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&host), 1, "{:?}", host.commands);
    assert!(state.read("db").unwrap().is_none(), "a record was left");
    assert_eq!(state.read("pg").unwrap(), Some(first.clone()));
    assert_attached(&host, &first);

    host.refused_connects.clear();
    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
    let second = state.read("db").unwrap().unwrap();
    assert_eq!(second.device, "/dev/nbd3");
    assert_attached(&host, &second);
    assert_attached(&host, &first);
}

/// A device another volume's record names is not a "next free device",
/// connected or not.
#[test]
fn a_busy_device_never_moves_an_attach_onto_a_recorded_device() {
    for left in [Left::ByKilledAttach, Left::ByKilledCleanup] {
        // Volume pg's record names /dev/nbd3, which shows nothing.
        let (mut host, state, stale) = stale_record(left);
        host.refused_connects.insert("/dev/nbd4", Refused::Busy);

        let error = execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host)
            .expect_err("attached beside a busy device and a recorded one")
            .to_string();

        assert!(
            error.contains("Device or resource busy"),
            "{left:?}: {error}"
        );
        assert_eq!(connects(&host), 1, "{left:?}: {:?}", host.commands);
        assert!(shows_no_connection(&host, "/dev/nbd3"), "{left:?}");
        assert!(state.read("db").unwrap().is_none(), "{left:?}");
        assert_eq!(state.read("pg").unwrap(), Some(stale), "{left:?}");
    }
}

/// The administrator chose a pinned device: it is never given up.
#[test]
fn a_pinned_device_that_stays_busy_is_not_given_up() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);
    let mut pg = request(&PG);
    pg.nbd_device = "/dev/nbd3".into();

    let error = execute_with(&plan_attach(&pg), Some(&state), &mut host)
        .expect_err("attached with its pinned device busy")
        .to_string();

    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&host), 1, "{:?}", host.commands);
    assert!(shows_no_connection(&host, "/dev/nbd4"));
    assert!(state.read("pg").unwrap().is_none(), "a record was left");
}

/// Only a device that stayed busy is given up. Any other refusal, and a
/// busy device that carries a connection by the time the helper looks, end
/// the attach as before: rollback judges what the device shows.
#[test]
fn only_a_device_that_stayed_busy_and_shows_nothing_is_given_up() {
    for (refused, record_kept) in [
        (Refused::Otherwise, false),
        (Refused::BusyThenConnectedByAnother, true),
    ] {
        let mut host = Host::new();
        let state = host.state();
        host.refused_connects.insert("/dev/nbd3", refused);

        assert!(execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host).is_err());

        assert_eq!(connects(&host), 1, "{:?}", host.commands);
        assert!(shows_no_connection(&host, "/dev/nbd4"));
        // A device under another connection keeps the record, as a
        // rollback that meets a foreign backend always has.
        let record = state.read("pg").unwrap();
        assert_eq!(record.is_some(), record_kept);
        assert!(record.is_none_or(|record| record.device == "/dev/nbd3"));
    }
}

/// All the devices tried share the time of one step: with none left, the
/// first busy device ends the attach.
#[test]
fn no_other_device_is_tried_once_the_steps_time_is_over() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);
    let _over = command::finish_by(Instant::now());

    let error = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host)
        .expect_err("attached after its time was over")
        .to_string();

    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&host), 1, "{:?}", host.commands);
    assert!(shows_no_connection(&host, "/dev/nbd4"));
    assert!(state.read("pg").unwrap().is_none());
}

/// The step's time is looked at again once a device has stayed busy: a
/// device that used it up is the last one tried.
#[test]
fn no_other_device_is_tried_when_the_busy_one_used_the_steps_time() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);
    host.refusal_takes = Duration::from_millis(400);
    let _limit = command::finish_by(Instant::now() + Duration::from_millis(300));

    let error = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host)
        .expect_err("attached on another device after its time was over")
        .to_string();

    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&host), 1, "{:?}", host.commands);
    assert!(shows_no_connection(&host, "/dev/nbd4"));
    assert!(state.read("pg").unwrap().is_none());
}

/// A chooser that cannot leave a device out offers the busy one again: the
/// attach ends there instead of trying it for ever.
#[test]
fn a_chooser_that_offers_the_busy_device_again_ends_the_attach() {
    let mut host = Host::new();
    let state = host.state();
    host.refused_connects.insert("/dev/nbd3", Refused::Busy);
    let mut system = KernelView(host);

    let error = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut system)
        .expect_err("attached on a device that stays busy")
        .to_string();

    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&system.0), 1, "{:?}", system.0.commands);
    assert!(state.read("pg").unwrap().is_none());
}

/// Every device free and busy: the attach ends with the busy refusal once
/// each has been tried once, and leaves no record.
#[test]
fn an_attach_ends_when_every_free_device_stays_busy() {
    let mut host = Host::new();
    let state = host.state();
    for device in ["/dev/nbd3", "/dev/nbd4"] {
        host.refused_connects.insert(device, Refused::Busy);
    }

    let error = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host)
        .expect_err("attached with every device busy")
        .to_string();

    assert!(error.contains("Device or resource busy"), "{error}");
    assert_eq!(connects(&host), 2, "{:?}", host.commands);
    assert!(state.read("pg").unwrap().is_none(), "a record was left");
}
