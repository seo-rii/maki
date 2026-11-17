//! A power loss kills every process. A `Volume` of the process that died can
//! still be reachable from a test after `crash*()`, but nothing it does
//! afterwards may succeed or change what recovery finds: no real process
//! creates, writes or syncs a file once the power is gone. Its open file
//! handles already die with the crash; these cases need *new* handles from
//! the backing (a journal roll and its durable-proof publication, a
//! checkpoint that only publishes metadata and deletes a journal segment),
//! so the process's own view of the backing (`CrashableBacking::process`)
//! must die with it too. The same holds for an `Engine`.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Duration;

use maki_backing::Backing;
use maki_core::engine::{CheckpointPolicy, Engine, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};
use maki_test_support::{CrashableBacking, FakeCryptoProvider};

const CT: usize = 520;

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

fn volume_backing() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume_with_discard(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xA2DE_AD00),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, CT as u32, 512 * 64, 512 * 64).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    backing
}

/// Every file and its bytes, as the next recovery would find them.
fn snapshot(backing: &CrashableBacking) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut dirs = vec![String::new()];
    while let Some(dir) = dirs.pop() {
        for name in backing.list(&dir).unwrap() {
            let path = if dir.is_empty() {
                name
            } else {
                format!("{dir}/{name}")
            };
            match backing.open(&path, false) {
                Ok(file) => {
                    let mut bytes = vec![0; file.len().unwrap() as usize];
                    file.read_at(0, &mut bytes).unwrap();
                    files.insert(path, bytes);
                }
                Err(error) if error.kind() == ErrorKind::IsADirectory => dirs.push(path),
                Err(error) => panic!("{path}: {error}"),
            }
        }
    }
    files
}

/// Seven FUA records fill a 4 KiB journal segment.
const UNITS: std::ops::Range<u64> = 0..7;

/// A pre-crash volume whose active journal segment is full of FUA records:
/// its next append rolls into a segment it creates through the backing.
fn volume_with_a_full_segment(backing: &CrashableBacking) -> Volume {
    let mut volume = Volume::recover(backing.process(), options()).unwrap();
    for unit in UNITS {
        volume.write_ct(unit, &[0x11; CT], true).unwrap();
    }
    volume
}

#[test]
fn a_volume_of_the_dead_process_cannot_acknowledge_a_write_after_a_power_loss() {
    let backing = volume_backing();
    let mut dead = volume_with_a_full_segment(&backing);

    backing.crash_all_lost();
    let crashed = snapshot(&backing);

    let zombie = dead.write_ct(1, &[0xEE; CT], true);
    drop(dead);
    assert!(
        zombie.is_err(),
        "a process killed by the power loss acknowledged a FUA write afterwards: {zombie:?}"
    );
    assert!(
        snapshot(&backing) == crashed,
        "the dead process changed the files recovery reads"
    );

    let recovered = Volume::recover(backing.process(), options()).unwrap();
    assert_eq!(
        recovered.read_ct(1).unwrap().map(|(_, ct)| ct[0]),
        Some(0x11),
        "recovery serves a write of the dead process"
    );
}

/// A checkpoint of nothing but discards writes no slot, so it needs no
/// handle the crash killed: it publishes the checkpoint state and discard
/// maps through new handles and deletes the journal segment it covers.
#[test]
fn a_volume_of_the_dead_process_cannot_checkpoint_after_a_power_loss() {
    let backing = volume_backing();
    let mut dead = Volume::recover(backing.process(), options()).unwrap();
    for unit in UNITS {
        dead.write_ct(unit, &[0x11; CT], true).unwrap();
    }
    dead.checkpoint().unwrap();
    for unit in UNITS {
        dead.discard_ct(unit, true).unwrap();
    }

    backing.crash_all_lost();
    let crashed = snapshot(&backing);

    let zombie = dead.checkpoint();
    drop(dead);
    assert!(
        zombie.is_err(),
        "a process killed by the power loss checkpointed afterwards: {zombie:?}"
    );
    assert!(
        snapshot(&backing) == crashed,
        "the dead process changed the files recovery reads"
    );

    let recovered = Volume::recover(backing.process(), options()).unwrap();
    for unit in UNITS {
        assert!(
            recovered.read_ct(unit).unwrap().is_none(),
            "unit {unit}: its FUA discard is durable"
        );
    }
}

fn engine_options() -> EngineOptions {
    EngineOptions {
        volume: options(),
        checkpoint: CheckpointPolicy {
            journal_high_watermark_bytes: u64::MAX,
            emergency_reserve_bytes: 0,
            low_space_checkpoint_bytes: 0,
            interval: Duration::from_secs(3600),
            ..Default::default()
        },
        ..Default::default()
    }
}

async fn attach(backing: &CrashableBacking) -> Engine {
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(512)),
        engine_options(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_engine_of_the_dead_process_cannot_write_or_checkpoint_after_a_power_loss() {
    let backing = volume_backing();
    let dead = attach(&backing).await;
    for unit in UNITS {
        dead.write(unit * 512, &[0x11; 512], true).await.unwrap();
    }

    backing.crash_all_lost();
    let crashed = snapshot(&backing);

    let write = dead.write(512, &[0xEE; 512], true).await;
    let checkpoint = dead.checkpoint().await;
    dead.stop_checkpoint_worker().await;
    drop(dead);
    assert!(
        write.is_err(),
        "an engine killed by the power loss acknowledged a FUA write afterwards"
    );
    assert!(
        checkpoint.is_err(),
        "an engine killed by the power loss checkpointed afterwards: {checkpoint:?}"
    );
    assert!(
        snapshot(&backing) == crashed,
        "the dead engine changed the files recovery reads"
    );

    let engine = attach(&backing).await;
    for unit in UNITS {
        assert_eq!(
            engine.read(unit * 512, 512).await.unwrap(),
            vec![0x11; 512],
            "unit {unit}"
        );
    }
}

/// The process started after the power loss, and the test's own backing,
/// keep working; a restart (a new process without a power loss) does not
/// end the earlier process's view.
#[test]
fn processes_started_after_the_power_loss_keep_working() {
    let backing = volume_backing();
    let mut dead = volume_with_a_full_segment(&backing);
    backing.crash_all_lost();
    assert!(dead.write_ct(1, &[0xEE; CT], true).is_err());
    drop(dead);

    let first = backing.process();
    let mut volume = Volume::recover(first.clone(), options()).unwrap();
    volume.write_ct(1, &[0x22; CT], true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    // Restart: the first post-crash process exits, a second one recovers.
    let mut volume = Volume::recover(backing.process(), options()).unwrap();
    volume.write_ct(2, &[0x33; CT], true).unwrap();
    assert!(
        first.exists("superblock.a").unwrap(),
        "a restart is not a power loss"
    );
    drop(volume);

    backing.crash_all_lost();
    let recovered = Volume::recover(backing.process(), options()).unwrap();
    assert_eq!(
        recovered.read_ct(1).unwrap().map(|(_, ct)| ct[0]),
        Some(0x22)
    );
    assert_eq!(
        recovered.read_ct(2).unwrap().map(|(_, ct)| ct[0]),
        Some(0x33)
    );
    assert!(
        backing.exists("superblock.a").unwrap(),
        "the test's own backing outlives every power loss"
    );
}
