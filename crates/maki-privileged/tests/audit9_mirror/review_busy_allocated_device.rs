//! Round-9 audit (slug `r8-privileged`): the device move of #383 against the
//! older machinery, on the crate's own two-volume simulated kernel.
//!
//! This file is NOT the crate's `review_busy_allocated_device.rs`. It takes
//! that module's place in the mirror `tests/audit9_mirror/` (every production
//! source there is a symbolic link into `src/`), because the module is the
//! one `review_stale_attach_record.rs` declares below the `Host` harness, and
//! `System`, `execute_with`, `cleanup_with` and
//! `finish_interrupted_activation_with` are crate-private. The crate's own
//! tests of that name run in `cargo test -p maki-privileged --lib`.
//!
//! What is swept here and not there:
//! - another actor changing a device right before every backend read of an
//!   attach that moves from the held `/dev/nbd3` to `/dev/nbd4` (the moved
//!   connection vanishes; the moved device, or the one given up, is found
//!   under somebody else's connection, with or without a backend identifier);
//! - the helper dying before and after every command that follows the move,
//!   then the packaged order (failed-start hook, cleanup) and the next
//!   attaches of both volumes;
//! - a second volume attaching beside a moved one, and the moved one's
//!   detach, cleanup, recover and grow.
//!
//! Invariants: nothing but a connect ever names the device that was given up;
//! a device under somebody else's connection is never disconnected; no
//! connection made by the helper is live on a device its record does not
//! name; a successful attach is recorded on the device it ended on.

use super::*;

use crate::plan::{plan_grow, GrowRequest};

std::thread_local! {
    /// How many connects the helper had asked for when the scheduled change
    /// was applied (`usize::MAX` while it has not been).
    static CONNECTS_AT_CHANGE: Cell<usize> = const { Cell::new(usize::MAX) };
}

const HELD: &str = "/dev/nbd3";
const NEXT: &str = "/dev/nbd4";
const FOREIGN: &str = "another-client";

/// What a device shows, read without counting as one of the executor's
/// backend reads.
fn shown(host: &Host, device: &str) -> io::Result<Option<String>> {
    nbd_backend_at(&host.sysfs, device)
}

fn note_change(host: &Host) {
    CONNECTS_AT_CHANGE.set(host.connect_requests.len());
}

fn connect_foreign(host: &Host, device: &str, with_backend: bool) {
    let nbd = host.nbd(device);
    std::fs::write(nbd.join("pid"), "777\n").unwrap();
    if with_backend {
        std::fs::write(nbd.join("backend"), format!("{FOREIGN}\n")).unwrap();
    } else {
        let _ = std::fs::remove_file(nbd.join("backend"));
    }
    std::fs::write(nbd.join("size"), "2048\n").unwrap();
}

fn the_moved_connection_vanishes(host: &Host) {
    note_change(host);
    let nbd = host.nbd(NEXT);
    let _ = std::fs::remove_file(nbd.join("pid"));
    let _ = std::fs::remove_file(nbd.join("backend"));
    std::fs::write(nbd.join("size"), "0\n").unwrap();
}

fn the_moved_device_is_somebody_elses(host: &Host) {
    note_change(host);
    connect_foreign(host, NEXT, true);
}

fn the_moved_device_has_an_ioctl_client(host: &Host) {
    note_change(host);
    connect_foreign(host, NEXT, false);
}

fn the_held_device_is_somebody_elses(host: &Host) {
    note_change(host);
    connect_foreign(host, HELD, true);
}

fn the_held_device_has_an_ioctl_client(host: &Host) {
    note_change(host);
    connect_foreign(host, HELD, false);
}

const CHANGES: [(&str, Change, &str, bool); 5] = [
    ("the moved connection vanishes", the_moved_connection_vanishes, NEXT, false),
    ("nbd4 is somebody else's", the_moved_device_is_somebody_elses, NEXT, true),
    ("nbd4 has an ioctl client", the_moved_device_has_an_ioctl_client, NEXT, true),
    ("nbd3 is somebody else's", the_held_device_is_somebody_elses, HELD, true),
    ("nbd3 has an ioctl client", the_held_device_has_an_ioctl_client, HELD, true),
];

/// A host with `/dev/nbd3` held open by something sysfs does not show, and
/// `/dev/nbd4` and `/dev/nbd5` free.
fn held_host() -> (Host, TrustedState) {
    let mut host = Host::new();
    host.add_device(5);
    host.refused_connects.insert(HELD, Refused::Busy);
    let state = host.state();
    CONNECTS_AT_CHANGE.set(usize::MAX);
    (host, state)
}

/// Every identifier the helper asked the kernel to connect a device under.
fn ours(host: &Host) -> Vec<String> {
    host.connect_requests
        .iter()
        .map(|(_, identifier)| identifier.clone())
        .collect()
}

/// The invariants that hold however an attach of volume pg ended.
fn check(host: &Host, state: &TrustedState, context: &str, problems: &mut Vec<String>) {
    // Nothing but the connect itself ever names the device given up.
    for (kind, device) in &host.named_devices {
        if device == HELD {
            problems.push(format!("{context}: {kind} named {HELD}, the device given up"));
        }
    }
    // A foreign connection is still there: nobody disconnected it. (A
    // connect of the same device asked for after the change would overwrite
    // it in this model, where the real kernel answers busy; such a run says
    // nothing about the disconnect.)
    let record = state.read("pg").unwrap();
    let helper_made = ours(host);
    for device in [HELD, NEXT, "/dev/nbd5"] {
        let shows = shown(host, device);
        if let Ok(Some(backend)) = &shows {
            // A connection the helper made must be the recorded one.
            if helper_made.contains(backend)
                && record.as_ref().is_none_or(|record| {
                    record.device != device || &record.connection_id != backend
                })
            {
                problems.push(format!(
                    "{context}: {device} carries the helper's connection {backend}, which the \
                     record ({:?}) does not name",
                    record.as_ref().map(|record| (&record.device, &record.connection_id))
                ));
            }
        }
    }
    if record.is_none()
        && (host.mapping("vg_maki_pg").is_some() || host.mounted("/srv/pg"))
    {
        problems.push(format!("{context}: a mapping or a mount without a record"));
    }
}

/// Another actor changes a device right before each backend read of an
/// attach that moves from the held device to the next one.
#[test]
fn audit9_a_moved_attach_never_acts_on_what_is_not_its_own() {
    let (mut baseline, state) = held_host();
    execute_with(&plan_attach(&request(&PG)), Some(&state), &mut baseline).unwrap();
    assert_eq!(state.read("pg").unwrap().unwrap().device, NEXT);
    let reads = baseline.backend_reads.get();
    assert!(reads > 10, "{reads} backend reads");
    drop(baseline);

    let mut problems = Vec::new();
    let (mut attached, mut refused, mut kept) = (0, 0, 0);
    for (name, change, device, plants_foreign) in CHANGES {
        for at in 1..=reads {
            let (mut host, state) = held_host();
            host.before_backend_read = Some((at, change));
            let result = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host);
            let context = format!("{name} before backend read {at} -> {:?}", result.as_ref().map_err(|error| error.to_string()));
            check(&host, &state, &context, &mut problems);

            let applied = CONNECTS_AT_CHANGE.get();
            let record = state.read("pg").unwrap();
            if plants_foreign && applied != usize::MAX {
                let connected_since = host.connect_requests[applied..]
                    .iter()
                    .any(|(target, _)| target == device);
                let still_foreign = match shown(&host, device) {
                    Ok(Some(backend)) => backend == FOREIGN,
                    // The ioctl client: a pid without a backend identifier.
                    Err(_) => host.nbd(device).join("pid").exists(),
                    Ok(None) => false,
                };
                if !connected_since && !still_foreign {
                    problems.push(format!(
                        "{context}: somebody else's connection on {device} is gone"
                    ));
                }
                if host
                    .named_devices
                    .iter()
                    .any(|(kind, target)| *kind == "nbd-disconnect" && target == device)
                    && !connected_since
                    && device == HELD
                {
                    problems.push(format!("{context}: {HELD} was disconnected"));
                }
            }
            match (&result, &record) {
                (Ok(()), Some(record)) => {
                    attached += 1;
                    if record.device == HELD {
                        problems.push(format!("{context}: attached on the held device"));
                    }
                }
                (Ok(()), None) => problems.push(format!("{context}: success without a record")),
                (Err(_), Some(record)) => {
                    kept += 1;
                    // A record is kept only over something: a device that is
                    // not provably free, a mapping or a mount.
                    let free = matches!(shown(&host, &record.device), Ok(None));
                    if free && host.mapping("vg_maki_pg").is_none() && !host.mounted("/srv/pg") {
                        problems.push(format!(
                            "{context}: a record for {} was kept over nothing",
                            record.device
                        ));
                    }
                }
                (Err(_), None) => refused += 1,
            }
        }
    }
    println!("attached {attached}, refused and clean {refused}, refused with a record {kept}");
    assert!(attached > 0 && refused + kept > 0);
    assert!(
        problems.is_empty(),
        "{} problems, the first 30:\n{}",
        problems.len(),
        problems.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}

/// The helper dies before or after each command that follows the move. The
/// record names the device the helper was working on, the packaged order
/// (failed-start hook while the daemon serves, then cleanup) ends the state,
/// the device given up is never touched, and both volumes attach afterwards.
#[test]
fn audit9_a_moved_attach_killed_at_any_later_command_is_cleaned_up() {
    let (mut baseline, state) = held_host();
    execute_with(&plan_attach(&request(&PG)), Some(&state), &mut baseline).unwrap();
    let kinds: Vec<&'static str> = {
        let second_connect = baseline
            .commands
            .iter()
            .enumerate()
            .filter(|(_, kind)| **kind == "nbd-connect")
            .nth(1)
            .expect("the baseline connects twice")
            .0;
        let mut kinds: Vec<_> = baseline.commands[second_connect..].to_vec();
        kinds.dedup();
        kinds
    };
    assert!(kinds.len() >= 5, "{kinds:?}");
    drop(baseline);

    let mut problems = Vec::new();
    for kind in kinds {
        for after in [false, true] {
            // `nbd-connect` before: the helper dies before its first
            // connect, which the crate's own tests cover; here the move.
            let (mut host, state) = held_host();
            if kind == "nbd-connect" && !after {
                host.killed_before_connecting = Some(NEXT);
            } else if after {
                host.killed_after = Some(kind);
            } else {
                host.killed_before = Some(kind);
            }
            let died = killed(|| {
                let _ = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host);
            });
            let context = format!("killed {} {kind}", if after { "after" } else { "before" });
            if !died {
                problems.push(format!("{context}: the helper did not die"));
                continue;
            }
            host.killed_before = None;
            host.killed_after = None;
            host.killed_before_connecting = None;
            check(&host, &state, &context, &mut problems);
            let record = state.read("pg").unwrap();
            match &record {
                Some(record) if record.device == NEXT => {}
                other => problems.push(format!(
                    "{context}: the record names {:?}, not the device the helper moved to",
                    other.as_ref().map(|record| &record.device)
                )),
            }

            // The packaged order after a failed start.
            host.commands.clear();
            host.named_devices.clear();
            let detach = plan_detach(&request(&PG));
            let hook = finish_interrupted_activation_with(&detach, &state, &mut host);
            let cleanup = cleanup_with(&detach, &state, &mut host);
            if cleanup.is_err()
                || state.read("pg").unwrap().is_some()
                || !matches!(shown(&host, NEXT), Ok(None))
                || host.mapping("vg_maki_pg").is_some()
                || host.mounted("/srv/pg")
            {
                problems.push(format!(
                    "{context}: hook {:?}, cleanup {:?}, record {}, nbd4 {:?}",
                    hook.as_ref().map_err(|error| error.to_string()),
                    cleanup.as_ref().map_err(|error| error.to_string()),
                    state.read("pg").unwrap().is_some(),
                    shown(&host, NEXT),
                ));
            }
            check(&host, &state, &format!("{context}, after the recovery"), &mut problems);

            // Both volumes attach, each on a device of its own, while the
            // first device is still held.
            let pg = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host);
            let db = execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host);
            let devices = (
                state.read("pg").unwrap().map(|record| record.device),
                state.read("db").unwrap().map(|record| record.device),
            );
            if pg.is_err() || db.is_err() || devices != (Some(NEXT.into()), Some("/dev/nbd5".into()))
            {
                problems.push(format!(
                    "{context}: the next attaches: pg {:?}, db {:?}, on {devices:?}",
                    pg.as_ref().map_err(|error| error.to_string()),
                    db.as_ref().map_err(|error| error.to_string()),
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

fn grow(export: &Export, target_bytes: u64) -> Plan {
    let request = request(export);
    plan_grow(&GrowRequest {
        volume: request.volume.clone(),
        nbd_device: request.nbd_device.clone(),
        volume_uuid: request.volume_uuid.clone(),
        nbd_socket: request.nbd_socket.clone(),
        vg_name: request.vg_name.clone(),
        lv_name: request.lv_name.clone(),
        lvm_identity: request.lvm_identity.clone(),
        target_bytes,
        fs_uuid: request.fs_uuid.clone(),
        mountpoint: request.mountpoint.clone(),
    })
}

/// Two volumes beside a held device, each moved once: every later verb of
/// either follows its own record and leaves the other alone.
#[test]
fn audit9_verbs_of_two_moved_volumes_follow_their_own_records() {
    let (mut host, state) = held_host();
    execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host).unwrap();
    execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
    let pg = state.read("pg").unwrap().unwrap();
    let db = state.read("db").unwrap().unwrap();
    assert_eq!((pg.device.as_str(), db.device.as_str()), (NEXT, "/dev/nbd5"));
    assert_attached(&host, &pg);
    assert_attached(&host, &db);
    // Each volume asked for the held device once and was moved once.
    assert_eq!(
        host.connect_requests
            .iter()
            .map(|(device, _)| device.as_str())
            .collect::<Vec<_>>(),
        [HELD, NEXT, HELD, "/dev/nbd5"]
    );
    assert!(host.named_devices.iter().all(|(_, device)| device != HELD));

    // Grow follows the record to the moved device.
    host.named_devices.clear();
    execute_with(&grow(&PG, 2 << 30), Some(&state), &mut host).unwrap();
    assert_eq!(
        host.lvm.borrow().acted_on.last(),
        Some(&("lvextend", PG.vg_uuid))
    );
    assert_attached(&host, &db);

    // A second attach of an attached volume is refused and changes nothing.
    let again = execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host)
        .expect_err("attached twice")
        .to_string();
    assert!(again.contains("still connected"), "{again}");
    assert_eq!(state.read("pg").unwrap(), Some(pg.clone()));

    // pg's teardown, by each verb that can end it, leaves db alone; pg then
    // takes its device again (the held one is tried first and given up).
    for verb in ["detach", "cleanup"] {
        host.named_devices.clear();
        run_verb(verb, &request(&PG), &state, &mut host).unwrap();
        assert!(state.read("pg").unwrap().is_none(), "{verb}");
        assert!(matches!(shown(&host, NEXT), Ok(None)), "{verb}");
        assert!(
            host.named_devices
                .iter()
                .all(|(_, device)| device == NEXT),
            "{verb}: {:?}",
            host.named_devices
        );
        assert_attached(&host, &db);
        assert_eq!(state.read("db").unwrap(), Some(db.clone()));
        execute_with(&plan_attach(&request(&PG)), Some(&state), &mut host).unwrap();
        let back = state.read("pg").unwrap().unwrap();
        assert_eq!(back.device, NEXT, "{verb}");
        assert_attached(&host, &back);
    }

    // Recover refuses a connected attachment and changes nothing.
    let before = state.read("pg").unwrap();
    assert!(run_verb("recover", &request(&PG), &state, &mut host).is_err());
    assert_eq!(state.read("pg").unwrap(), before);
    assert_attached(&host, &db);
}

/// The record that a refused connect leaves under somebody else's connection
/// (the crate pins that it is kept): what the volume's next verbs do with it
/// on the device the helper moved to, with and without administrator pins.
#[test]
fn audit9_a_record_kept_on_the_moved_device_under_another_connection() {
    for with_pins in [false, true] {
        let (mut host, state) = held_host();
        host.refused_connects
            .insert(NEXT, Refused::BusyThenConnectedByAnother);
        let pg = if with_pins { pinned(&PG) } else { request(&PG) };
        let error = execute_with(&plan_attach(&pg), Some(&state), &mut host)
            .expect_err("attached under somebody else's connection")
            .to_string();
        println!("pins {with_pins}: first attach: {error}");
        let kept = state.read("pg").unwrap().expect("the record is kept");
        assert_eq!(kept.device, NEXT);
        assert_eq!(shown(&host, NEXT).unwrap().as_deref(), Some(FOREIGN));
        // The helper never connected anything: both requests were refused.
        assert_eq!(host.connect_requests.len(), 2);
        assert!(host.named_devices.is_empty(), "{:?}", host.named_devices);

        // The other volume is not handed the foreign device, the recorded
        // one (the same), nor the held one.
        execute_with(&plan_attach(&request(&DB)), Some(&state), &mut host).unwrap();
        assert_eq!(state.read("db").unwrap().unwrap().device, "/dev/nbd5");

        host.refused_connects.remove(NEXT);
        for verb in ["cleanup", "attach"] {
            let result = run_verb(verb, &pg, &state, &mut host);
            println!(
                "pins {with_pins}: {verb}: {:?}",
                result.as_ref().map_err(|error| error.to_string())
            );
            // Whatever the verb says, the foreign connection is untouched.
            assert_eq!(shown(&host, NEXT).unwrap().as_deref(), Some(FOREIGN));
            if with_pins {
                // The record names its VG UUID: it is retired. No device is
                // left for the attach (nbd3 held, nbd4 foreign, nbd5 db's).
                if verb == "cleanup" {
                    result.unwrap();
                    assert!(state.read("pg").unwrap().is_none());
                } else {
                    assert!(result.is_err());
                    assert!(state.read("pg").unwrap().is_none());
                }
            } else {
                let refusal = result.expect_err("acted beside a foreign backend").to_string();
                assert!(refusal.contains("not retired automatically"), "{refusal}");
                assert_eq!(state.read("pg").unwrap(), Some(kept.clone()));
            }
        }
    }
}
