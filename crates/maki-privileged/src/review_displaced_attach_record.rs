//! A recorded device that carries another connection: another volume
//! attached on it by a helper from before records reserved their devices,
//! or an NBD client started outside the helper. The record is retired, under
//! the attach lock and without a command, only when the host shows that
//! nothing of the recorded attachment remains. Otherwise every verb refuses,
//! keeps the record and says why.

use super::*;
use crate::plan::{plan_grow, GrowRequest};

/// The identifier of an NBD client started outside the helper.
const FOREIGN: &str = "foreign-client";

/// What volume pg's record holds besides its device.
#[derive(Clone, Copy, Debug)]
enum Holds {
    /// The mapping proof: a cleanup was killed after the disconnect.
    Proof,
    /// The activation intent: an attach was killed right after activating,
    /// and its mapping and connection were then removed by hand.
    Intent,
    /// Administrator LVM pins only: an attach was killed before connecting.
    Pins,
    /// No VG UUID at all: an attach without pins was killed before
    /// connecting.
    Nothing,
}

/// What carries the recorded device now.
#[derive(Clone, Copy, Debug)]
enum By {
    /// Volume db, attached by a helper that did not read pg's record.
    Volume,
    /// An NBD client started outside the helper, without a record.
    Client,
    /// Volume clone, whose image carries pg's LVM identity: connected, with
    /// its VG deactivated by a detach that was then killed.
    Clone,
    /// Volume db, connected by an attach killed right after the connect: its
    /// record names no VG UUID yet.
    Connecting,
}

fn connect(host: &Host, device: &str, identifier: &str) {
    let nbd = host.nbd(device);
    std::fs::write(nbd.join("pid"), "777\n").unwrap();
    std::fs::write(nbd.join("backend"), format!("{identifier}\n")).unwrap();
    std::fs::write(nbd.join("size"), "2048\n").unwrap();
}

fn disconnect(host: &Host, device: &str) {
    let nbd = host.nbd(device);
    std::fs::remove_file(nbd.join("pid")).unwrap();
    std::fs::remove_file(nbd.join("backend")).unwrap();
    std::fs::write(nbd.join("size"), "0\n").unwrap();
}

/// A mapping of pg's data LV, left over `/dev/nbd3`'s device number when
/// its connection went: it now reads whatever is connected there.
fn map_pg_on_nbd3(host: &Host) {
    let mapping = host.sysfs.join("dm-7");
    for directory in ["dm", "slaves", "holders"] {
        std::fs::create_dir_all(mapping.join(directory)).unwrap();
    }
    std::fs::write(mapping.join("dm/name"), "vg_maki_pg-data\n").unwrap();
    std::fs::write(
        mapping.join("dm/uuid"),
        format!(
            "LVM-{}{}\n",
            PG.vg_uuid.replace('-', ""),
            PG.lv_uuid.replace('-', "")
        ),
    )
    .unwrap();
    std::fs::write(mapping.join("dev"), "253:7\n").unwrap();
    std::fs::write(mapping.join("slaves/nbd3"), "").unwrap();
    std::fs::write(host.nbd("/dev/nbd3").join("holders/dm-7"), "").unwrap();
}

fn append_mount(host: &Host, line: &str) {
    let mut mounts = host.mounts();
    mounts.extend_from_slice(line.as_bytes());
    std::fs::write(&host.mountinfo, mounts).unwrap();
}

/// Volume pg's record names `/dev/nbd3`, which carries another connection,
/// and nothing of pg's attachment is left on the host.
fn displaced(holds: Holds, by: By) -> (Host, TrustedState, BoundDeviceRecord, AttachRequest) {
    let mut host = Host::new();
    let state = host.state();
    let pg = match holds {
        Holds::Pins => pinned(&PG),
        _ => request(&PG),
    };
    match holds {
        Holds::Proof => {
            execute_with(&plan_attach(&pg), Some(&state), &mut host).unwrap();
            host.killed_after = Some("nbd-disconnect");
            assert!(killed(|| {
                let _ = cleanup_with(&plan_detach(&pg), &state, &mut host);
            }));
        }
        Holds::Intent => {
            host.killed_after = Some("lvm-activate");
            assert!(killed(|| {
                let _ = execute_with(&plan_attach(&pg), Some(&state), &mut host);
            }));
            host.deactivate("vg_maki_pg");
            disconnect(&host, "/dev/nbd3");
        }
        Holds::Pins | Holds::Nothing => {
            host.killed_before = Some("nbd-connect");
            assert!(killed(|| {
                let _ = execute_with(&plan_attach(&pg), Some(&state), &mut host);
            }));
        }
    }
    host.killed_before = None;
    host.killed_after = None;
    let stale = state
        .read("pg")
        .unwrap()
        .expect("the record outlives the killed helper");
    let (proof, intent, pins) = (
        stale.recovery.is_some(),
        stale.recovery_intent.is_some(),
        stale.attachment.lvm_identity.is_some(),
    );
    assert_eq!(
        (proof, intent, pins),
        match holds {
            Holds::Proof => (true, false, false),
            Holds::Intent => (false, true, false),
            Holds::Pins => (false, false, true),
            Holds::Nothing => (false, false, false),
        },
        "{holds:?}"
    );
    assert_eq!(stale.device, "/dev/nbd3");
    assert_eq!(host.backend("/dev/nbd3").unwrap(), None);

    // A helper that did not read the records hands the device out.
    let without_pg = |host: &mut Host, attach: &mut dyn FnMut(&mut Host)| {
        state.remove("pg").unwrap();
        attach(host);
        state.write(&stale).unwrap();
    };
    match by {
        By::Volume => without_pg(&mut host, &mut |host| {
            execute_with(&plan_attach(&request(&DB)), Some(&state), host).unwrap();
        }),
        By::Client => connect(&host, "/dev/nbd3", FOREIGN),
        By::Clone => without_pg(&mut host, &mut |host| {
            let clone = request(&CLONE);
            execute_with(&plan_attach(&clone), Some(&state), host).unwrap();
            host.killed_after = Some("lvm-deactivate");
            assert!(killed(|| {
                let _ = execute_with(&plan_detach(&clone), Some(&state), host);
            }));
            host.killed_after = None;
        }),
        By::Connecting => without_pg(&mut host, &mut |host| {
            host.killed_after = Some("nbd-connect");
            assert!(killed(|| {
                let _ = execute_with(&plan_attach(&request(&DB)), Some(&state), host);
            }));
            host.killed_after = None;
        }),
    }
    let occupant = host.backend("/dev/nbd3").unwrap();
    assert!(occupant.is_some_and(|identifier| identifier != stale.connection_id));
    assert!(host.mapping("vg_maki_pg").is_none() && !host.mounted("/srv/pg"));
    host.commands.clear();
    (host, state, stale, pg)
}

/// Every file of the simulated kernel below `path`, with its contents.
fn tree(path: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    files.sort();
    files
}

fn grow(request: &AttachRequest) -> Plan {
    plan_grow(&GrowRequest {
        volume: request.volume.clone(),
        nbd_device: AUTO_NBD_DEVICE.into(),
        volume_uuid: request.volume_uuid.clone(),
        nbd_socket: request.nbd_socket.clone(),
        vg_name: request.vg_name.clone(),
        lv_name: request.lv_name.clone(),
        lvm_identity: request.lvm_identity.clone(),
        target_bytes: 2 << 30,
        fs_uuid: None,
        mountpoint: request.mountpoint.clone(),
    })
}

/// The beginning every refusal of a recorded device under another identity
/// keeps, and the way out it names.
const UNDER_ANOTHER_IDENTITY: &str =
    "/dev/nbd3 is recorded for volume pg but is connected under another identity; refusing ";
const WAY_OUT: &str = "maki-attach cleanup --volume pg";

/// Every verb refuses with `reason`, runs nothing, changes nothing of the
/// simulated kernel and keeps the record.
fn assert_kept(
    host: &mut Host,
    state: &TrustedState,
    stale: &BoundDeviceRecord,
    pg: &AttachRequest,
    reason: &str,
    case: &str,
) {
    let kernel = tree(&host.sysfs);
    let mounts = std::fs::read(&host.mountinfo).ok();
    let others = (state.read("db").unwrap(), state.read("clone").unwrap());
    for verb in VERBS {
        let error = run_verb(verb, pg, state, host)
            .expect_err(&format!("{case}, {verb}: retired"))
            .to_string();
        for expected in [UNDER_ANOTHER_IDENTITY, WAY_OUT, reason] {
            assert!(error.contains(expected), "{case}, {verb}: {error}");
        }
        assert!(
            host.commands.is_empty(),
            "{case}, {verb}: {:?}",
            host.commands
        );
        assert_eq!(
            state.read("pg").unwrap().as_ref(),
            Some(stale),
            "{case}, {verb}"
        );
        assert_eq!(
            (state.read("db").unwrap(), state.read("clone").unwrap()),
            others,
            "{case}, {verb}"
        );
        assert_eq!(tree(&host.sysfs), kernel, "{case}, {verb}");
        assert_eq!(
            std::fs::read(&host.mountinfo).ok(),
            mounts,
            "{case}, {verb}"
        );
    }
}

/// Cleanup, recover and detach retire the record without a command; attach
/// replaces it and takes another device. Neither touches the connection on
/// the recorded device or anything of the volume that uses it.
#[test]
fn a_displaced_record_is_retired_once_nothing_of_its_attachment_remains() {
    for holds in [Holds::Proof, Holds::Intent, Holds::Pins] {
        for by in [By::Volume, By::Client] {
            for verb in VERBS {
                let case = format!("{holds:?}, {by:?}, {verb}");
                let (mut host, state, stale, pg) = displaced(holds, by);
                let (kernel, mounts) = (tree(&host.sysfs), host.mounts());
                let device = tree(&host.nbd("/dev/nbd3"));
                let other = state.read("db").unwrap();

                run_verb(verb, &pg, &state, &mut host)
                    .unwrap_or_else(|error| panic!("{case}: {error}"));

                if verb == "attach" {
                    let renewed = state.read("pg").unwrap().unwrap();
                    assert_eq!(renewed.device, "/dev/nbd4", "{case}");
                    assert_ne!(renewed.connection_id, stale.connection_id, "{case}");
                    assert_attached(&host, &renewed);
                    assert_eq!(tree(&host.nbd("/dev/nbd3")), device, "{case}");
                } else {
                    assert!(host.commands.is_empty(), "{case}: {:?}", host.commands);
                    assert!(state.read("pg").unwrap().is_none(), "{case}");
                    assert_eq!(tree(&host.sysfs), kernel, "{case}");
                    assert_eq!(host.mounts(), mounts, "{case}");
                }
                assert_eq!(state.read("db").unwrap(), other, "{case}");
                match by {
                    By::Volume => assert_attached(&host, other.as_ref().unwrap()),
                    _ => assert_eq!(
                        host.backend("/dev/nbd3").unwrap().as_deref(),
                        Some(FOREIGN),
                        "{case}"
                    ),
                }
            }
        }
    }
}

/// Cleanup retires only the record its configuration describes, as its
/// connected and disconnected paths act only on that one.
#[test]
fn cleanup_retires_only_the_record_its_configuration_describes() {
    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Client);
    let mut moved = pg.clone();
    moved.mountpoint = "/srv/elsewhere".into();
    let mut pinned_elsewhere = pg.clone();
    pinned_elsewhere.nbd_device = "/dev/nbd4".into();
    for request in [moved, pinned_elsewhere] {
        let error = cleanup_with(&plan_detach(&request), &state, &mut host)
            .expect_err("retired the record of another configuration")
            .to_string();
        assert!(
            error.contains("cleanup configuration does not match the trusted attach record"),
            "{error}"
        );
        assert!(host.commands.is_empty(), "{:?}", host.commands);
        assert_eq!(state.read("pg").unwrap().as_ref(), Some(&stale));
    }
}

/// An attach pinned to the device its own record names retires the record,
/// then finds the device taken like any other.
#[test]
fn an_attach_pinned_to_its_displaced_device_retires_the_record_and_connects_nothing() {
    for (by, refusal) in [
        (By::Volume, "named by the attach record of volume db"),
        (By::Client, "requested NBD device is already connected"),
    ] {
        let (mut host, state, _stale, mut pg) = displaced(Holds::Proof, by);
        pg.nbd_device = "/dev/nbd3".into();
        let device = tree(&host.nbd("/dev/nbd3"));

        let error = execute_with(&plan_attach(&pg), Some(&state), &mut host)
            .expect_err("attached on a device another connection carries")
            .to_string();

        assert!(error.contains(refusal), "{by:?}: {error}");
        assert!(host.commands.is_empty(), "{by:?}: {:?}", host.commands);
        assert!(state.read("pg").unwrap().is_none(), "{by:?}");
        assert_eq!(tree(&host.nbd("/dev/nbd3")), device, "{by:?}");
    }
}

/// A grow needs the live attachment. It neither grows nor retires, and its
/// refusal says that cleanup retires a record of which nothing remains.
#[test]
fn grow_refuses_a_displaced_record_and_points_to_cleanup() {
    for holds in [Holds::Proof, Holds::Intent, Holds::Pins, Holds::Nothing] {
        for by in [By::Volume, By::Client] {
            let (mut host, state, stale, pg) = displaced(holds, by);
            let kernel = tree(&host.sysfs);

            let error = execute_with(&grow(&pg), Some(&state), &mut host)
                .expect_err("grew an attachment that is not connected")
                .to_string();

            for expected in [
                "/dev/nbd3 is recorded for volume pg but is connected under another identity; \
                 refusing to grow",
                "cleanup retires the record",
                WAY_OUT,
            ] {
                assert!(error.contains(expected), "{holds:?}, {by:?}: {error}");
            }
            assert!(host.commands.is_empty(), "{holds:?}, {by:?}");
            assert_eq!(state.read("pg").unwrap(), Some(stale), "{holds:?}, {by:?}");
            assert_eq!(tree(&host.sysfs), kernel, "{holds:?}, {by:?}");
        }
    }
}

/// A mapping of the recorded VG over the device's number now reads the
/// other connection's data. It is not the helper's to remove, and the record
/// stays the only authority over it.
#[test]
fn a_mapping_of_the_recorded_volume_group_keeps_the_record() {
    for by in [By::Volume, By::Client] {
        let (mut host, state, stale, pg) = displaced(Holds::Proof, by);
        map_pg_on_nbd3(&host);
        assert_kept(
            &mut host,
            &state,
            &stale,
            &pg,
            "dm-7 is a mapping of the recorded volume group on /dev/nbd3; it now reads \
             the other connection's data",
            &format!("{by:?}"),
        );
    }

    // One that holds no device at all, such as a mapping whose table was
    // replaced by an error target, is the recorded attachment's all the same.
    let (mut host, state, stale, pg) = displaced(Holds::Intent, By::Client);
    map_pg_on_nbd3(&host);
    std::fs::remove_file(host.sysfs.join("dm-7/slaves/nbd3")).unwrap();
    std::fs::remove_file(host.nbd("/dev/nbd3").join("holders/dm-7")).unwrap();
    assert_kept(
        &mut host,
        &state,
        &stale,
        &pg,
        "dm-7 is a mapping of the recorded volume group",
        "unattached mapping",
    );
}

/// A holder of the device or of one of its partitions that is not a
/// device-mapper device cannot be told apart from the recorded attachment's.
#[test]
fn a_holder_that_is_not_a_mapping_keeps_the_record() {
    for holder_of in ["nbd3", "nbd3p1"] {
        let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Client);
        let partition = host.sysfs.join("nbd3p1");
        std::fs::create_dir_all(partition.join("holders")).unwrap();
        std::fs::write(partition.join("partition"), "1\n").unwrap();
        std::fs::write(partition.join("dev"), "43:97\n").unwrap();
        let md = host.sysfs.join("md0");
        for directory in ["holders", "slaves"] {
            std::fs::create_dir_all(md.join(directory)).unwrap();
        }
        std::fs::write(md.join("dev"), "9:0\n").unwrap();
        std::fs::write(md.join("slaves").join(holder_of), "").unwrap();
        std::fs::write(host.sysfs.join(holder_of).join("holders/md0"), "").unwrap();

        assert_kept(
            &mut host,
            &state,
            &stale,
            &pg,
            &format!("md0 holds /dev/{holder_of} and is not a device-mapper device"),
            holder_of,
        );
    }
}

/// A mount at the recorded mountpoint, whatever its source, and a mount of
/// a mapping of the recorded VG anywhere.
#[test]
fn a_mount_of_the_recorded_attachment_keeps_the_record() {
    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Client);
    append_mount(&host, "50 21 0:45 / /srv/pg rw,relatime - tmpfs tmpfs rw\n");
    assert_kept(
        &mut host,
        &state,
        &stale,
        &pg,
        "something is mounted at the recorded mountpoint /srv/pg",
        "mountpoint",
    );

    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Volume);
    map_pg_on_nbd3(&host);
    append_mount(
        &host,
        "51 21 253:7 / /mnt/copy rw,relatime - xfs /dev/mapper/vg_maki_pg-data rw\n",
    );
    assert_kept(
        &mut host,
        &state,
        &stale,
        &pg,
        "dm-7, a mapping of the recorded volume group, is mounted",
        "mapping",
    );
}

/// An observation that cannot be made never reads as "nothing remains".
#[test]
fn an_observation_that_cannot_be_read_keeps_the_record() {
    for case in ["mountinfo", "holders", "holder uuid", "mapping uuid"] {
        let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Volume);
        match case {
            "mountinfo" => {
                std::fs::remove_file(&host.mountinfo).unwrap();
                std::fs::create_dir(&host.mountinfo).unwrap();
            }
            "holders" => std::fs::remove_dir_all(host.nbd("/dev/nbd3").join("holders")).unwrap(),
            "holder uuid" => {
                std::fs::remove_file(host.mapping("vg_maki_db").unwrap().join("dm/uuid")).unwrap()
            }
            "mapping uuid" => {
                let other = host.sysfs.join("dm-9");
                for directory in ["dm", "slaves", "holders"] {
                    std::fs::create_dir_all(other.join(directory)).unwrap();
                }
                std::fs::write(other.join("dm/name"), "root\n").unwrap();
                std::fs::write(other.join("dev"), "253:9\n").unwrap();
            }
            _ => unreachable!(),
        }
        assert_kept(&mut host, &state, &stale, &pg, "cannot be read", case);
    }
}

/// A connected device whose backend cannot be read is not shown to carry
/// another connection: every verb fails on that observation, as before.
#[test]
fn an_unreadable_backend_keeps_the_record() {
    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Client);
    std::fs::remove_file(host.nbd("/dev/nbd3").join("backend")).unwrap();
    for verb in VERBS {
        let error = run_verb(verb, &pg, &state, &mut host)
            .expect_err(verb)
            .to_string();
        assert!(error.contains("no backend identifier"), "{verb}: {error}");
        assert!(host.commands.is_empty(), "{verb}: {:?}", host.commands);
        assert_eq!(state.read("pg").unwrap().as_ref(), Some(&stale), "{verb}");
    }
}

/// When another record names the device, its VG UUID has to differ from
/// the recorded one: a cloned image's identical UUID, or a record that names
/// none, leaves the mapping check unable to tell the two volumes apart.
#[test]
fn another_record_on_the_device_must_name_another_volume_group() {
    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Clone);
    assert_kept(
        &mut host,
        &state,
        &stale,
        &pg,
        "the attach record of volume clone names /dev/nbd3 with the same VG UUID",
        "clone",
    );

    let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Connecting);
    assert_kept(
        &mut host,
        &state,
        &stale,
        &pg,
        "the attach record of volume db names /dev/nbd3 and carries no VG UUID",
        "connecting",
    );
}

/// Without a VG UUID no mapping can be shown not to be the recorded VG's.
#[test]
fn a_record_without_a_vg_uuid_keeps_the_record() {
    for by in [By::Volume, By::Client] {
        let (mut host, state, stale, pg) = displaced(Holds::Nothing, by);
        assert_kept(
            &mut host,
            &state,
            &stale,
            &pg,
            "the record carries no VG UUID",
            &format!("{by:?}"),
        );
    }
}

/// The device's connection must stay the same across both observations of
/// the host, and the host must show nothing both times.
#[test]
fn a_change_while_the_host_is_observed_keeps_the_record() {
    fn client_leaves(host: &Host) {
        disconnect(host, "/dev/nbd3");
    }
    fn mapping_appears(host: &Host) {
        map_pg_on_nbd3(host);
    }
    for verb in ["cleanup", "recover"] {
        for (read, change, reason) in [
            (
                2,
                client_leaves as Change,
                "changed while the host was observed",
            ),
            (3, client_leaves, "changed while the host was observed"),
            (
                2,
                mapping_appears,
                "is a mapping of the recorded volume group",
            ),
        ] {
            let (mut host, state, stale, pg) = displaced(Holds::Proof, By::Client);
            host.backend_reads.set(0);
            host.before_backend_read = Some((read, change));

            let error = run_verb(verb, &pg, &state, &mut host)
                .expect_err(&format!("{verb}, read {read}: retired"))
                .to_string();

            assert!(error.contains(reason), "{verb}, read {read}: {error}");
            assert!(host.commands.is_empty(), "{verb}: {:?}", host.commands);
            assert_eq!(state.read("pg").unwrap().as_ref(), Some(&stale), "{verb}");
        }
    }
}
