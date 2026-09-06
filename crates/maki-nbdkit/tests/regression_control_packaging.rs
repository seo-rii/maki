//! BUG-009: admin access depends on every parent directory, not just the
//! control socket mode. Model the packaged POSIX permissions without
//! creating system users, groups, directories or services.

use std::collections::HashMap;
use std::path::Path;

use maki_format::config::parse_config;
use maki_nbdkit::daemon::control_socket_path;

const UNIT: &str = include_str!("../../../packaging/systemd/maki@.service");
const TMPFILES: &str = include_str!("../../../packaging/tmpfiles.d/maki.conf");
const CONFIG: &str = include_str!("../../../packaging/examples/postgres-prod.toml");

fn directive<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then_some(value)
        })
        .unwrap_or_else(|| panic!("missing {name} directive"))
}

#[derive(Clone)]
struct Directory {
    owner: String,
    group: String,
    mode: u32,
}

fn directories(volume: &str) -> HashMap<String, Directory> {
    let mut directories = HashMap::new();
    for line in TMPFILES.lines().filter(|line| line.starts_with("d ")) {
        let fields: Vec<_> = line.split_whitespace().collect();
        directories.insert(
            fields[1].to_string(),
            Directory {
                owner: fields[3].into(),
                group: fields[4].into(),
                mode: u32::from_str_radix(fields[2], 8).unwrap(),
            },
        );
    }
    for runtime in directive(UNIT, "RuntimeDirectory").split_whitespace() {
        directories.insert(
            format!("/run/{}", runtime.replace("%i", volume)),
            Directory {
                owner: directive(UNIT, "User").into(),
                group: directive(UNIT, "Group").into(),
                mode: u32::from_str_radix(directive(UNIT, "RuntimeDirectoryMode"), 8).unwrap(),
            },
        );
    }
    directories
}

fn can_traverse(
    directories: &HashMap<String, Directory>,
    socket: &str,
    user: &str,
    groups: &[&str],
) -> bool {
    Path::new(socket)
        .parent()
        .unwrap()
        .ancestors()
        .take_while(|path| *path != Path::new("/run"))
        .all(|path| {
            let directory = directories.get(path.to_str().unwrap()).unwrap_or_else(|| {
                panic!("runtime ancestor {} is not provisioned", path.display())
            });
            let bit = if directory.owner == user {
                0o100
            } else if groups.contains(&directory.group.as_str()) {
                0o010
            } else {
                0o001
            };
            directory.mode & bit != 0
        })
}

#[test]
fn control_default_and_packaged_example_use_the_admin_runtime_tree() {
    let mut config = parse_config(CONFIG).unwrap();
    let expected = format!("/run/maki-control/{}/control.sock", config.volume.name);
    assert_eq!(config.control.socket.as_deref(), Some(expected.as_str()));
    config.control.socket = None;
    assert_eq!(control_socket_path(&config), expected);
    config.control.socket = Some("/tmp/rootless-maki-control.sock".into());
    assert_eq!(
        control_socket_path(&config),
        "/tmp/rootless-maki-control.sock"
    );
}

#[test]
fn admin_reaches_control_without_access_to_nbd_or_helper_state() {
    let mut config = parse_config(CONFIG).unwrap();
    config.control.socket = None;
    let paths = directories(&config.volume.name);
    let control = control_socket_path(&config);
    let nbd = format!("/run/maki/{}/nbd.sock", config.volume.name);
    assert!(
        can_traverse(&paths, &control, "administrator", &["maki-admin"]),
        "admin cannot reach {control}"
    );
    assert!(
        !can_traverse(&paths, &nbd, "administrator", &["maki-admin"]),
        "admin can reach NBD socket"
    );
    assert!(!can_traverse(
        &paths,
        "/run/maki-attach/attach.lock",
        "administrator",
        &["maki-admin"]
    ));
    assert!(!can_traverse(&paths, &control, "unrelated", &[]));
    assert!(can_traverse(
        &paths,
        &control,
        "maki",
        &["maki", "maki-admin"]
    ));
    assert!(can_traverse(&paths, &nbd, "maki", &["maki", "maki-admin"]));
    assert_eq!(
        directive(UNIT, "Group"),
        "maki",
        "daemon retains config/backing group access"
    );
    assert!(UNIT
        .lines()
        .any(|line| line == "ReadWritePaths=/run/maki-control/%i"));
}
