//! BUG-074: accepted journal minima admit the advertised maximum request
//! after an empty start or a reclaim that retains the active segment.

use std::sync::Arc;
use std::time::Duration;

use maki_core::engine::{CheckpointPolicy, Engine, EngineLimits, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::config::{parse_config, VolumeConfig};
use maki_format::init;
use maki_format::journal::{max_record_len, minimum_journal_limit};
use maki_format::superblock::Superblock;
use maki_test_support::{CrashableBacking, FakeCryptoProvider, ManualClock};
use uuid::Uuid;

const REQUEST: u64 = 1 << 20;
const SEGMENT: u64 = 4096;

fn config(unit: u32) -> VolumeConfig {
    let count = REQUEST.div_ceil(u64::from(unit)) + 1;
    let limit = minimum_journal_limit(SEGMENT, max_record_len(unit + 8), count).unwrap();
    let config = parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "journal-progress"
max_virtual_size = "4MiB"
device_block_size = 512
crypto_unit_size = {unit}
shard_logical_size = "2MiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [{unit}]
max_ciphertext_size = {}
[[crypto.http.endpoint]]
name = "unused"
url = "http://127.0.0.1:1"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
[backing]
root = "/unused"
journal_segment_size = "{SEGMENT}B"
journal_max_bytes = "{limit}B"
journal_emergency_reserve_bytes = "0B"
checkpoint_reserve_bytes = "0B"
[nbd]
minimum_io = 512
preferred_io = 512
maximum_io = "{REQUEST}B"
"#,
        unit + 8
    ))
    .unwrap();
    config.validate().unwrap();
    config
}

fn superblock(config: &VolumeConfig) -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x74),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: config.geometry().unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(config: &VolumeConfig) -> Engine {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock(config)).unwrap();
    let engine = Engine::attach(
        backing,
        Arc::new(FakeCryptoProvider::new(config.volume.crypto_unit_size)),
        EngineOptions {
            volume: VolumeOptions {
                journal_segment_size: SEGMENT,
            },
            checkpoint: CheckpointPolicy {
                journal_max_bytes: config.backing.journal_max_bytes.0,
                journal_high_watermark_bytes: config.backing.journal_max_bytes.0 / 2,
                max_pending_bytes: config.limits.max_journal_pending_bytes.0,
                emergency_reserve_bytes: 0,
                low_space_checkpoint_bytes: 0,
                interval: Duration::from_secs(3600),
            },
            limits: EngineLimits {
                max_request_bytes: REQUEST,
                ..Default::default()
            },
            clock: Some(Arc::new(ManualClock::new())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    engine.stop_checkpoint_worker().await;
    engine
}

#[tokio::test]
async fn accepted_minimum_admits_maximum_writes_from_an_empty_journal() {
    for unit in [512, 8192] {
        let config = config(unit);
        let engine = attach(&config).await;
        let data = vec![0x74; REQUEST as usize];
        engine.write(0, &data, true).await.unwrap();
        assert_eq!(engine.read(0, data.len()).await.unwrap(), data);
        assert!(engine.stats().await.journal_total_bytes <= config.backing.journal_max_bytes.0);
    }
}

#[tokio::test]
async fn accepted_minimum_admits_unaligned_maximum_writes_after_reclaim() {
    for unit in [512, 8192] {
        let config = config(unit);
        let engine = attach(&config).await;
        engine
            .write(0, &vec![0x20; unit as usize], true)
            .await
            .unwrap();
        engine.checkpoint().await.unwrap();
        let data = vec![0x75; REQUEST as usize];
        engine.write(512, &data, true).await.unwrap();
        assert_eq!(engine.read(512, data.len()).await.unwrap(), data);
        assert_eq!(engine.read(0, 512).await.unwrap(), vec![0x20; 512]);
        assert!(engine.stats().await.journal_total_bytes <= config.backing.journal_max_bytes.0);
    }
}

#[test]
fn shared_append_projection_matches_actual_segment_growth_for_variable_records() {
    let config = config(8192);
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock(&config)).unwrap();
    let mut volume = Volume::recover(
        backing,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap();
    for (unit, length) in [520, 4008, 4048, 4049, 8200, 520, 8200]
        .into_iter()
        .enumerate()
    {
        let before = volume.journal_total_bytes();
        let projected = volume.journal_append_footprint([length as u64 + 32]);
        volume
            .write_ct(unit as u64, &vec![0x74; length], true)
            .unwrap();
        assert_eq!(volume.journal_total_bytes() - before, projected);
    }
}
