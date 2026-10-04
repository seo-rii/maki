//! R5-039: an HTTP mapping without `items_path` sends one request per unit.
//! Grouping units into batches for it only made the provider send them one
//! after another, so such a mapping counts as one item per batch; the
//! engine then runs a request's single-unit batches concurrently under the
//! configured callback and in-flight limits.

use maki_format::config::parse_config;
use maki_nbdkit::daemon::scheduler_config;

fn configuration(batched: bool) -> String {
    let mut ops = String::new();
    for op in ["encrypt", "decrypt"] {
        let (body, response) = if batched {
            (
                format!("items_path = \"/items\"\n[crypto.http.{op}.body.item_fields]\n\"/data\" = {{ source = \"payload\", encoding = \"base64\" }}\n\"/unit\" = {{ source = \"unit_index\" }}\n"),
                "items_path = \"/items\"\nitem_index_path = \"/unit\"\ndata_path = \"/data\"\n",
            )
        } else {
            (
                format!("[crypto.http.{op}.body.fields]\n\"/data\" = {{ source = \"payload\", encoding = \"base64\" }}\n\"/unit\" = {{ source = \"unit_index\" }}\n"),
                "data_path = \"/data\"\n",
            )
        };
        ops += &format!(
            "[crypto.http.{op}]\npath = \"/{op}\"\n[crypto.http.{op}.body]\ntype = \"json\"\n{body}[crypto.http.{op}.response]\ntype = \"json\"\nencoding = \"base64\"\n{response}"
        );
    }
    format!(
        r#"
config_schema_version = 1
[volume]
name = "per-item"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "review-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[crypto.batch]
max_items = 64
[[crypto.http.endpoint]]
name = "local"
url = "http://127.0.0.1:9"
{ops}[backing]
root = "/unused-per-item"
"#
    )
}

#[test]
fn a_per_item_http_mapping_counts_as_one_item_per_batch() {
    let config = parse_config(&configuration(false)).unwrap();
    config.validate().unwrap();
    assert_eq!(config.effective_batch_max_items(), 1);
    let scheduler = scheduler_config(&config);
    // The engine sends single-unit batches; the scheduler dispatches each at
    // once instead of holding it back to coalesce, and still accepts the
    // multi-item requests of the attach self-test (review R04).
    assert_eq!(scheduler.target_items, 1);
    assert_eq!(scheduler.max_items, 64);
}

#[test]
fn a_batched_http_mapping_keeps_the_configured_batch_size() {
    let config = parse_config(&configuration(true)).unwrap();
    config.validate().unwrap();
    assert_eq!(config.effective_batch_max_items(), 64);
    assert_eq!(scheduler_config(&config).max_items, 64);
    assert!(scheduler_config(&config).target_items > 1);
}

/// The engine sizes its batches from the provider's own capabilities; the
/// HTTP provider builds them itself, so it must report the effective size
/// too (the first fix changed only the daemon's copy and did nothing).
#[tokio::test]
async fn the_http_provider_reports_one_item_per_batch_for_a_per_item_mapping() {
    use maki_crypto::CryptoProvider;
    use maki_crypto_local::keysource::MapKeySource;
    for (batched, expected) in [(false, 1), (true, 64)] {
        let config = parse_config(&configuration(batched)).unwrap();
        let provider = maki_crypto_http::HttpCryptoProvider::from_config(
            &config,
            "http://127.0.0.1:9",
            &MapKeySource::new(),
        )
        .unwrap();
        assert_eq!(
            provider.capabilities().await.unwrap().batch.max_items,
            expected,
            "batched {batched}"
        );
    }
}
