//! The committed seed corpus, replayed on the stable toolchain.
//!
//! `fuzz/seeds/<target>/` holds the seeds a coverage-guided run of each
//! fuzz target starts from. Every one of them is fed here through its
//! target's entry function (`maki_fuzz_harness`), which the target itself
//! calls, so the default suite runs what the fuzzer runs: a seed that
//! crashes a target fails this test, and so does a valid seed the code no
//! longer accepts or an invalid one it accepts. The targets of the root
//! helper's NBD handshake and netlink answer reader and of maki-backing's
//! own records are required here: before them, no fuzzer read the bytes a
//! root process takes from the volume daemon and from a netlink socket. So
//! are the targets of the witness's RPC and etcd readers, of the remote
//! crypto providers' response readers and of the helper's readers of
//! command output and of sysfs: before them, no fuzzer read what a witness
//! peer, etcd, a crypto endpoint, LVM, blkid, dmsetup or the kernel's block
//! topology hands those readers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use maki_fuzz_harness::seeds::{self, Expect};
use maki_fuzz_harness::TARGETS;

/// Every fuzz target there must be.
const REQUIRED: [&str; 16] = [
    "format_decoders",
    "format_records",
    "journal_scan",
    "config_parse",
    "endpoint_url",
    "probe_parsers",
    "nbd_handshake",
    "nbd_netlink",
    "backing_records",
    "witness_rpc",
    "witness_etcd",
    "http_response",
    "websocket_response",
    "grpc_response",
    "helper_reports",
    "helper_sysfs",
];

/// Targets whose code is built on Linux only: the root helper's kernel NBD
/// connection and its executor.
const LINUX_ONLY: [&str; 4] = [
    "nbd_handshake",
    "nbd_netlink",
    "helper_reports",
    "helper_sysfs",
];

/// The largest seed file: one handshake seed is longer than the client's
/// 64 KiB byte limit.
const MAX_SEED_BYTES: usize = 72 << 10;

fn fuzz_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn seed_dir() -> PathBuf {
    fuzz_dir().join("seeds")
}

/// `(name, path)` of every `[[bin]]` in `fuzz/Cargo.toml`.
fn binaries() -> Vec<(String, String)> {
    binaries_in(&std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap())
}

/// `(name, path)` of every `[[bin]]` in the manifest `manifest`, read line
/// by line: a Windows checkout may end its lines with CRLF.
fn binaries_in(manifest: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let mut lines = manifest.lines().map(str::trim).peekable();
    while let Some(line) = lines.next() {
        if line != "[[bin]]" {
            continue;
        }
        let mut body = Vec::new();
        while let Some(line) = lines.next_if(|line| !line.starts_with('[')) {
            body.push(line);
        }
        let value = |key: &str| {
            body.iter()
                .find_map(|line| line.strip_prefix(&format!("{key} = \"")))
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or_else(|| panic!("a [[bin]] without {key}: {body:?}"))
                .to_string()
        };
        found.push((value("name"), value("path")));
    }
    found
}

/// The files of `target`'s seed directory, by name.
fn committed(target: &str) -> Vec<(String, Vec<u8>)> {
    let directory = seed_dir().join(target);
    let Ok(entries) = std::fs::read_dir(&directory) else {
        return Vec::new();
    };
    let mut files: Vec<(String, Vec<u8>)> = entries
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            (name, std::fs::read(entry.path()).unwrap())
        })
        .collect();
    files.sort();
    files
}

fn sorted<'a>(names: impl IntoIterator<Item = &'a str>) -> BTreeSet<&'a str> {
    names.into_iter().collect()
}

/// A Windows checkout with `core.autocrlf` (Git for Windows's default, and
/// the runners') gives `fuzz/Cargo.toml` CRLF line ends: its targets are the
/// same.
#[test]
fn the_manifests_targets_are_read_whatever_its_line_ends() {
    let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml"))
        .unwrap()
        .replace("\r\n", "\n");
    let targets = binaries_in(&manifest);
    assert_eq!(targets.len(), REQUIRED.len(), "{targets:?}");
    assert_eq!(binaries_in(&manifest.replace('\n', "\r\n")), targets);
}

#[test]
fn every_fuzz_target_has_an_entry_a_binary_and_seeds() {
    let required = sorted(REQUIRED);
    let entries = sorted(TARGETS.iter().map(|target| target.name));
    let binaries = binaries();
    let binary_names = sorted(binaries.iter().map(|(name, _)| name.as_str()));
    let directories: Vec<String> = std::fs::read_dir(seed_dir())
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect()
        })
        .unwrap_or_default();
    let directories = sorted(directories.iter().map(String::as_str));
    let missing = |found: &BTreeSet<&str>| -> Vec<&'static str> {
        REQUIRED
            .into_iter()
            .filter(|name| !found.contains(name))
            .collect()
    };
    assert_eq!(
        (
            missing(&entries),
            missing(&binary_names),
            missing(&directories)
        ),
        (Vec::new(), Vec::new(), Vec::new()),
        "fuzz targets without an entry function, without a [[bin]] in fuzz/Cargo.toml, \
         and without committed seeds"
    );
    assert_eq!(entries, required, "entry functions that are not required");
    assert_eq!(
        binary_names, required,
        "[[bin]] targets that are not required"
    );
    assert_eq!(directories, required, "seed directories of no target");

    for (name, path) in &binaries {
        assert_eq!(path, &format!("fuzz_targets/{name}.rs"));
        let source = std::fs::read_to_string(fuzz_dir().join(path)).unwrap();
        assert!(
            source.contains(&format!("maki_fuzz_harness::{name}(data)")),
            "{path} must hand its input to maki_fuzz_harness::{name}"
        );
    }
    for target in TARGETS {
        let linux_only = LINUX_ONLY.contains(&target.name);
        assert_eq!(
            target.entry.is_some(),
            cfg!(target_os = "linux") || !linux_only,
            "{}: an entry exists exactly where its code is built",
            target.name
        );
    }
}

/// Whether the committed seeds of `target` are in another byte order than
/// this host's, which reads them differently.
fn foreign_byte_order(target: &str) -> bool {
    cfg!(target_endian = "big") && seeds::LITTLE_ENDIAN.contains(&target)
}

#[test]
fn every_committed_seed_replays_through_its_target() {
    let mut replayed = 0;
    let mut skipped = Vec::new();
    let mut own_byte_order = Vec::new();
    for target in TARGETS {
        let Some(entry) = target.entry else {
            skipped.push(target.name);
            continue;
        };
        // A big-endian host replays the seeds its generator writes in its
        // own byte order, with the same names and so the same expectations.
        let files = if foreign_byte_order(target.name) {
            own_byte_order.push(target.name);
            seeds::all()
                .into_iter()
                .filter(|seed| seed.target == target.name)
                .map(|seed| (seed.name, seed.bytes))
                .collect()
        } else {
            committed(target.name)
        };
        for (name, bytes) in files {
            assert!(
                bytes.len() <= MAX_SEED_BYTES,
                "{}/{name}: {} bytes",
                target.name,
                bytes.len()
            );
            let accepted = entry(&bytes);
            match Expect::of(&name) {
                Some(Expect::Accepted) => assert!(accepted, "{}/{name} was refused", target.name),
                Some(Expect::Refused) => assert!(!accepted, "{}/{name} was accepted", target.name),
                Some(Expect::Either) | None => {}
            }
            replayed += 1;
        }
    }
    assert_eq!(
        skipped,
        if cfg!(target_os = "linux") {
            Vec::new()
        } else {
            LINUX_ONLY.to_vec()
        }
    );
    assert_eq!(
        own_byte_order,
        if cfg!(all(target_os = "linux", target_endian = "big")) {
            seeds::LITTLE_ENDIAN.to_vec()
        } else {
            Vec::new()
        }
    );
    assert!(replayed > 0, "no seed was replayed");
}

/// The generator's seeds are committed as it writes them. The committed
/// directories may hold more (a reproducer of a crash a run found, say).
#[test]
fn the_committed_seeds_are_what_the_generator_writes() {
    let generated = seeds::all();
    if std::env::var_os("MAKI_FUZZ_WRITE_SEEDS").is_some_and(|value| value == "1") {
        // A big-endian host's netlink seeds are not the committed ones.
        for seed in generated
            .iter()
            .filter(|seed| !foreign_byte_order(seed.target))
        {
            let directory = seed_dir().join(seed.target);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(directory.join(&seed.name), &seed.bytes).unwrap();
        }
    }
    let mut names = BTreeSet::new();
    for seed in &generated {
        assert!(
            names.insert((seed.target, seed.name.as_str())),
            "{}/{} is generated twice",
            seed.target,
            seed.name
        );
        assert!(
            Expect::of(&seed.name).is_some(),
            "{}/{}: a seed's name starts with valid-, refused- or noise-",
            seed.target,
            seed.name
        );
        if foreign_byte_order(seed.target) {
            continue;
        }
        let path = seed_dir().join(seed.target).join(&seed.name);
        let found = std::fs::read(&path).unwrap_or_default();
        assert!(
            found == seed.bytes,
            "{} does not hold what the generator writes ({} bytes, {} expected); run \
             MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p maki-fuzz-harness --test review_fuzz_corpus",
            path.display(),
            found.len(),
            seed.bytes.len()
        );
    }
}
