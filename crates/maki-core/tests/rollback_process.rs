//! Process-interruption coverage for the Linux rollback backing.
//!
//! `SIGKILL` loses the child process's in-memory working view, which is the
//! boundary this test exercises. It does not simulate host page-cache loss or
//! claim to be a power-loss test.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use maki_backing::RollbackBacking;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use uuid::Uuid;

const UNIT: u32 = 512;
const CYCLES: u8 = 8;
const CHILD_ROLE: &str = "MAKI_ROLLBACK_PROCESS_CHILD";
const ROOT_ENV: &str = "MAKI_ROLLBACK_PROCESS_ROOT";
const WITNESS_ENV: &str = "MAKI_ROLLBACK_PROCESS_WITNESS";
const CYCLE_ENV: &str = "MAKI_ROLLBACK_PROCESS_CYCLE";

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xfeed_bacc_7072_6f63_6573_7300_0000_0001),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 4096).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn ciphertext(byte: u8) -> Vec<u8> {
    vec![byte; (UNIT + 8) as usize]
}

fn open_volume(root: &Path, witness: &Path) -> (Volume, Arc<RollbackBacking>) {
    let backing = Arc::new(RollbackBacking::open(root, witness).unwrap());
    let volume = Volume::recover(backing.clone(), options()).unwrap();
    (volume, backing)
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Data { sequence: u64, byte: u8 },
    Discard { sequence: u64 },
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }

    fn kill_and_wait(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.kill_and_wait();
    }
}

#[test]
fn rollback_process_child() {
    if std::env::var_os(CHILD_ROLE).is_none() {
        return;
    }

    let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
    let witness = PathBuf::from(std::env::var_os(WITNESS_ENV).unwrap());
    let cycle: u8 = std::env::var(CYCLE_ENV).unwrap().parse().unwrap();
    let (mut volume, _backing) = open_volume(&root, &witness);
    let write_unit = u64::from(cycle % 4);
    let discard_unit = u64::from((cycle + 1) % 4);
    let durable_byte = 0x20 + cycle;
    let checkpoint_cycle = cycle.is_multiple_of(2);

    let write_sequence = volume
        .write_ct(write_unit, &ciphertext(durable_byte), checkpoint_cycle)
        .unwrap();
    if !checkpoint_cycle {
        volume.flush().unwrap();
    }
    println!("ACK W {write_unit} {write_sequence} {durable_byte}");
    std::io::stdout().flush().unwrap();

    let discard_sequence = volume.discard_ct(discard_unit, !checkpoint_cycle).unwrap();
    if checkpoint_cycle {
        volume.flush().unwrap();
    }
    println!("ACK D {discard_unit} {discard_sequence}");
    std::io::stdout().flush().unwrap();

    if checkpoint_cycle {
        volume.checkpoint().unwrap();
    }

    // These changes intentionally remain outside every durability boundary.
    volume
        .write_ct(write_unit, &ciphertext(0xd0 + cycle), false)
        .unwrap();
    volume
        .write_ct(discard_unit, &ciphertext(0xe0 + cycle), false)
        .unwrap();
    println!("READY");
    std::io::stdout().flush().unwrap();

    loop {
        std::thread::park();
    }
}

#[test]
fn acknowledged_state_survives_repeated_process_interruption() {
    let root = tempfile::tempdir().unwrap();
    let witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let oracle = tempfile::tempdir().unwrap();
    let oracle_path = oracle.path().join("acknowledgements.log");
    let mut oracle_file = OpenOptions::new()
        .create_new(true)
        .append(true)
        .open(&oracle_path)
        .unwrap();

    let backing =
        Arc::new(RollbackBacking::create(root.path(), witness.path(), 256 * 1024).unwrap());
    init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    drop(backing);

    // Seed every unit used as a discard target so every child discard appends
    // its own record and therefore has a new, independently checkable sequence.
    let (mut volume, backing) = open_volume(root.path(), witness.path());
    let mut expected = BTreeMap::new();
    for unit in 0..4 {
        let byte = 0x10 + unit as u8;
        let sequence = volume.write_ct(unit, &ciphertext(byte), true).unwrap();
        expected.insert(unit, Expected::Data { sequence, byte });
    }
    volume.checkpoint().unwrap();
    drop((volume, backing));

    let executable = std::env::current_exe().unwrap();
    for cycle in 0..CYCLES {
        let prior_sequence = expected
            .values()
            .map(|state| match state {
                Expected::Data { sequence, .. } | Expected::Discard { sequence } => *sequence,
            })
            .max()
            .unwrap_or(0);
        let expected_write_unit = u64::from(cycle % 4);
        let expected_discard_unit = u64::from((cycle + 1) % 4);
        let expected_byte = 0x20 + cycle;
        let mut child = ChildGuard(Some(
            Command::new(&executable)
                .args(["--exact", "rollback_process_child", "--nocapture"])
                .env(CHILD_ROLE, "1")
                .env(ROOT_ENV, root.path())
                .env(WITNESS_ENV, witness.path())
                .env(CYCLE_ENV, cycle.to_string())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        ));
        let stdout = child.child_mut().stdout.take().unwrap();
        let (lines_tx, lines_rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if lines_tx.send(line).is_err() {
                    break;
                }
            }
        });

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut ack_count = 0;
        let mut write_sequence = None;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = lines_rx
                .recv_timeout(remaining)
                .unwrap_or_else(|error| {
                    panic!("cycle {cycle}: child did not become ready: {error}")
                })
                .unwrap();
            if let Some(ack) = line.strip_prefix("ACK ") {
                let fields: Vec<_> = ack.split_ascii_whitespace().collect();
                match ack_count {
                    0 => {
                        assert_eq!(fields.len(), 4, "cycle {cycle}: malformed write ACK");
                        assert_eq!(fields[0], "W", "cycle {cycle}: write ACK must be first");
                        let unit = fields[1].parse::<u64>().unwrap();
                        let sequence = fields[2].parse::<u64>().unwrap();
                        let byte = fields[3].parse::<u8>().unwrap();
                        assert_eq!(unit, expected_write_unit, "cycle {cycle}: wrong write unit");
                        assert_eq!(byte, expected_byte, "cycle {cycle}: wrong write byte");
                        assert!(
                            sequence > prior_sequence,
                            "cycle {cycle}: write sequence did not advance"
                        );
                        write_sequence = Some(sequence);
                        expected.insert(unit, Expected::Data { sequence, byte });
                    }
                    1 => {
                        assert_eq!(fields.len(), 3, "cycle {cycle}: malformed discard ACK");
                        assert_eq!(fields[0], "D", "cycle {cycle}: discard ACK must be second");
                        let unit = fields[1].parse::<u64>().unwrap();
                        let sequence = fields[2].parse::<u64>().unwrap();
                        assert_eq!(
                            unit, expected_discard_unit,
                            "cycle {cycle}: wrong discard unit"
                        );
                        assert!(
                            sequence > write_sequence.unwrap(),
                            "cycle {cycle}: discard sequence did not follow write"
                        );
                        expected.insert(unit, Expected::Discard { sequence });
                    }
                    _ => panic!("cycle {cycle}: received more than two ACKs"),
                }
                ack_count += 1;
                writeln!(oracle_file, "{cycle} {ack}").unwrap();
                oracle_file.flush().unwrap();
                oracle_file.sync_all().unwrap();
            } else if line == "READY" {
                assert_eq!(ack_count, 2, "cycle {cycle}: READY before both valid ACKs");
                break;
            }
        }

        child.kill_and_wait();

        let (volume, reopened_backing) = open_volume(root.path(), witness.path());
        let mut latest_sequence = 0;
        for (&unit, state) in &expected {
            match *state {
                Expected::Data { sequence, byte } => {
                    let (recovered_sequence, recovered) = volume.read_ct(unit).unwrap().unwrap();
                    assert_eq!(recovered_sequence, sequence, "cycle {cycle}, unit {unit}");
                    assert_eq!(recovered, ciphertext(byte), "cycle {cycle}, unit {unit}");
                    latest_sequence = latest_sequence.max(sequence);
                }
                Expected::Discard { sequence } => {
                    assert!(
                        volume.read_ct(unit).unwrap().is_none(),
                        "cycle {cycle}, unit {unit}"
                    );
                    latest_sequence = latest_sequence.max(sequence);
                }
            }
        }
        assert_eq!(
            volume.journal_durable_sequence(),
            latest_sequence,
            "cycle {cycle}: recovery did not select the latest acknowledged generation"
        );
        drop((volume, reopened_backing));
    }
}
