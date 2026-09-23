use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;
use maki_crypto::scheduler::BatchScheduler;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, RandomPrefixProvider, SecretBuffer, SystemClock,
};
use tokio::sync::Notify;

const LOGICAL: usize = 4096;
const PREFIX: u32 = 256;
const EXPANDED: u32 = LOGICAL as u32 + PREFIX;
const BASE_PROFILE: &str = "prefix-admission-base-v1";
const OUTER_PROFILE: &str = "maki-random-prefix-v1:256:prefix-admission-base-v1";

struct BlockingProvider {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

impl BlockingProvider {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
        }
    }
}

#[async_trait]
impl CryptoProvider for BlockingProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "blocking-prefix-test".into(),
            crypto_compatibility_id: BASE_PROFILE.into(),
            supported_plaintext_sizes: vec![EXPANDED],
            max_ciphertext_size: EXPANDED,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 1,
                max_bytes: u64::from(EXPANDED),
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        _context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(items
            .iter()
            .map(|item| CiphertextUnit {
                unit_index: item.unit_index,
                data: item.data.expose().iter().map(|byte| byte ^ 0x5a).collect(),
            })
            .collect())
    }

    async fn decrypt_batch(
        &self,
        _context: &CryptoContext,
        _items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        unreachable!("the admission regression only exercises encryption")
    }
}

fn config() -> maki_format::config::VolumeConfig {
    let raw = r#"
config_schema_version = 1
[volume]
name = "prefix-admission"
max_virtual_size = "64KiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "64KiB"
[crypto]
provider = "local-aes-xts"
crypto_compatibility_id = "prefix-admission-base-v1"
random_prefix_bytes = 256
key = { source = "env", name = "PREFIX_ADMISSION_TEST_KEY" }
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 4352
target_bytes = 4352
max_wait = "1us"
[crypto.capabilities]
supported_plaintext_sizes = [4352]
max_ciphertext_size = 4352
[limits]
max_pending_crypto_items = 3
max_pending_crypto_bytes = 8192
max_crypto_inflight_batches = 1
[backing]
root = "/tmp/maki-prefix-admission-test"
journal_emergency_reserve_bytes = "0B"
"#;
    let config = maki_format::config::parse_config(raw).unwrap();
    config.validate().unwrap();
    config
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xaced),
        format_version: 1,
        crypto_compatibility_id: OUTER_PROFILE.into(),
    }
}

fn unit(index: u64) -> PlaintextUnit {
    PlaintextUnit {
        unit_index: index,
        data: SecretBuffer::from_slice(&vec![index as u8; LOGICAL]),
    }
}

async fn wait_for(label: &str, predicate: impl Fn() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

#[tokio::test]
async fn pending_budget_counts_expanded_prefix_bytes() {
    let config = config();
    let raw = Arc::new(BlockingProvider::new());
    let wrapped = Arc::new(
        RandomPrefixProvider::new(raw.clone(), LOGICAL as u32, PREFIX, OUTER_PROFILE.into())
            .await
            .unwrap(),
    );
    let scheduler = Arc::new(BatchScheduler::with_unit_size(
        wrapped,
        maki_nbdkit::daemon::scheduler_config(&config),
        Arc::new(SystemClock::new()),
        LOGICAL as u32,
    ));
    let stats = scheduler.stats();

    let first = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.encrypt_batch(&context(), &[unit(1)]).await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), raw.entered.notified())
        .await
        .expect("first provider call did not start");

    let second = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move { scheduler.encrypt_batch(&context(), &[unit(2)]).await })
    };
    wait_for("one queued request", || stats.pending_items() == 1).await;

    let (third_started, third_entered) = tokio::sync::oneshot::channel();
    let third = {
        let scheduler = scheduler.clone();
        tokio::spawn(async move {
            third_started.send(()).unwrap();
            scheduler.encrypt_batch(&context(), &[unit(3)]).await
        })
    };
    // On this current-thread runtime the third task continues from the
    // synchronous send into admission until it yields. Awaiting the signal
    // proves it has attempted admission before the queue assertion.
    tokio::time::timeout(std::time::Duration::from_secs(2), third_entered)
        .await
        .expect("third request did not start")
        .unwrap();
    assert_eq!(
        stats.pending_items(),
        1,
        "8192 raw bytes hold only one expanded 4352-byte queued unit"
    );
    assert_eq!(stats.pending_bytes(), LOGICAL as u64);

    raw.release.notify_one();
    wait_for("second provider call", || {
        raw.calls.load(Ordering::SeqCst) >= 2
    })
    .await;
    raw.release.notify_one();
    wait_for("third provider call", || {
        raw.calls.load(Ordering::SeqCst) >= 3
    })
    .await;
    raw.release.notify_one();
    for task in [first, second, third] {
        task.await.unwrap().unwrap();
    }
    assert_eq!(stats.pending_items(), 0);
    assert_eq!(stats.pending_bytes(), 0);
}
