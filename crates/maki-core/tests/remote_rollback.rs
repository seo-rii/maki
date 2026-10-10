//! Real remote-authority fencing must guard paths that serve no backing bytes.
#![cfg(target_os = "linux")]

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, RollbackBacking};
use maki_core::engine::{CheckpointPolicy, Engine, EngineCacheConfig, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use uuid::Uuid;

const UNIT: u32 = 512;

struct RoleRpc {
    store: Arc<Mutex<StateStore>>,
    role: Role,
}
impl Rpc for RoleRpc {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.store.lock().unwrap().handle(self.role, request)
    }
}

struct Fixture {
    root: tempfile::TempDir,
    _authority: tempfile::TempDir,
    admin: Arc<RoleRpc>,
}
impl Fixture {
    fn create() -> (Self, Volume, Arc<RollbackBacking>) {
        let root = tempfile::tempdir().unwrap();
        let authority = tempfile::tempdir().unwrap();
        let store = Arc::new(Mutex::new(
            StateStore::create(authority.path(), [1; 16]).unwrap(),
        ));
        let writer = Arc::new(RoleRpc {
            store: store.clone(),
            role: Role::Writer,
        });
        let admin = Arc::new(RoleRpc {
            store,
            role: Role::Admin,
        });
        let backing =
            Arc::new(RollbackBacking::create_remote(root.path(), writer, 1024 * 1024).unwrap());
        let superblock = Superblock {
            generation: 0,
            volume_uuid: Uuid::from_u128(0xfeed_fece),
            provider_type: "fake".into(),
            crypto_compatibility_id: "test-profile-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, UNIT, 512, UNIT + 8, 16 * UNIT as u64, 4096).unwrap(),
            format_version: 1,
            created_unix: 0,
        };
        init::create_volume(backing.as_ref(), superblock).unwrap();
        let volume = recover(backing.clone());
        (
            Self {
                root,
                _authority: authority,
                admin,
            },
            volume,
            backing,
        )
    }

    fn current(&self) -> Record {
        self.admin
            .call(&Request {
                operation_id: [0; 16],
                expected: None,
                action: Action::Inspect,
            })
            .unwrap()
    }

    fn takeover(&self) -> Arc<RollbackBacking> {
        Arc::new(
            RollbackBacking::takeover_remote(self.root.path(), self.admin.clone(), &self.current())
                .unwrap(),
        )
    }
}

fn recover(backing: Arc<RollbackBacking>) -> Volume {
    Volume::recover(
        backing,
        VolumeOptions {
            journal_segment_size: 4096,
        },
    )
    .unwrap()
}

async fn engine(volume: Volume) -> Engine {
    let engine = Engine::attach_recovered(
        volume,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions {
            cache: Some(EngineCacheConfig {
                max_bytes: 4 * UNIT as u64,
                ttl: Duration::from_secs(60),
                verify_on_hit: false,
            }),
            checkpoint: CheckpointPolicy {
                emergency_reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // The test exercises the user's reads deterministically; background
    // checkpoint scheduling must not race our explicit revocation boundary.
    engine.stop_checkpoint_worker().await;
    engine
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_takeover_rejects_a_proven_plaintext_cache_hit_in_old_engine() {
    let (fixture, volume, old_backing) =
        tokio::task::spawn_blocking(Fixture::create).await.unwrap();
    let old_engine = engine(volume).await;
    old_engine
        .write(0, &[0x52; UNIT as usize], true)
        .await
        .unwrap();
    old_engine.read(0, UNIT as usize).await.unwrap();
    let hits = old_engine.monitoring_snapshot().stats.cache_hits;
    assert_eq!(
        old_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    assert!(
        old_engine.monitoring_snapshot().stats.cache_hits > hits,
        "fixture must actually serve a plaintext cache hit"
    );

    let (fixture, new_backing, new_volume) = tokio::task::spawn_blocking(move || {
        let new_backing = fixture.takeover();
        let new_volume = recover(new_backing.clone());
        (fixture, new_backing, new_volume)
    })
    .await
    .unwrap();
    let error = old_engine
        .read(0, UNIT as usize)
        .await
        .expect_err("remote revocation must precede cached plaintext delivery");
    assert!(
        error.to_string().contains("remote writer revoked"),
        "{error}"
    );
    assert!(old_engine
        .write(0, &[0x33; UNIT as usize], true)
        .await
        .is_err());
    let new_engine = engine(new_volume).await;
    assert_eq!(
        new_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    assert!(old_backing.check_freshness().is_err());
    drop((old_engine, old_backing));
    assert_eq!(
        new_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x52; UNIT as usize]
    );
    drop((new_engine, new_backing, fixture));
}

#[test]
fn remote_takeover_rejects_pending_overlay_reads_and_preserves_acknowledged_data() {
    let (fixture, mut volume, old_backing) = Fixture::create();
    let durable = vec![0x41; (UNIT + 8) as usize];
    let pending = vec![0x42; (UNIT + 8) as usize];
    volume.write_ct(0, &durable, true).unwrap();
    volume.write_ct(0, &pending, false).unwrap();
    assert!(volume.overlay_len() > 0);
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, pending);

    let new_backing = fixture.takeover();
    let error = volume
        .read_ct(0)
        .expect_err("pending overlay must not bypass the real remote witness");
    assert!(
        error.to_string().contains("remote writer revoked"),
        "{error}"
    );
    let recovered = recover(new_backing.clone());
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, durable);
    drop((volume, old_backing));
    assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, durable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn administrative_restore_rejects_cached_newer_plaintext_and_recovers_snapshot() {
    let (fixture, volume, old_backing) =
        tokio::task::spawn_blocking(Fixture::create).await.unwrap();
    let old_engine = engine(volume).await;
    old_engine
        .write(0, &[0x61; UNIT as usize], true)
        .await
        .unwrap();
    let snapshot = tempfile::tempdir().unwrap();
    let snapshot_backing = old_backing.clone();
    let (snapshot, descriptor) = tokio::task::spawn_blocking(move || {
        let descriptor = snapshot_backing.snapshot_remote(snapshot.path()).unwrap();
        (snapshot, descriptor)
    })
    .await
    .unwrap();
    old_engine
        .write(0, &[0x62; UNIT as usize], true)
        .await
        .unwrap();
    old_engine.read(0, UNIT as usize).await.unwrap();
    let hits = old_engine.monitoring_snapshot().stats.cache_hits;
    assert_eq!(
        old_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x62; UNIT as usize]
    );
    assert!(old_engine.monitoring_snapshot().stats.cache_hits > hits);
    let (fixture, restored, volume) = tokio::task::spawn_blocking(move || {
        let before = fixture.current();
        let restored = Arc::new(
            RollbackBacking::restore_remote(
                fixture.root.path(),
                snapshot.path(),
                &descriptor,
                fixture.admin.clone(),
                &before,
            )
            .unwrap(),
        );
        let after = fixture.current();
        assert_eq!(
            after.current.as_ref().unwrap().epoch,
            before.current.as_ref().unwrap().epoch + 1
        );
        let volume = recover(restored.clone());
        (fixture, restored, volume)
    })
    .await
    .unwrap();
    assert!(old_engine.read(0, UNIT as usize).await.is_err());
    let restored_engine = engine(volume).await;
    assert_eq!(
        restored_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x61; UNIT as usize]
    );
    drop((old_engine, old_backing));
    assert_eq!(
        restored_engine.read(0, UNIT as usize).await.unwrap(),
        vec![0x61; UNIT as usize]
    );
    drop((restored_engine, restored, fixture));
}
