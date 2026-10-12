#![cfg(unix)]
//! Observe every credential-shaped allocation while the current-thread
//! daemon resolves metadata. No pointer is read after deallocation.
use maki_nbdkit::daemon::{build_provider, create_volume_from_config_str};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static COPIES: Cell<usize> = const { Cell::new(0) };
}
struct Observer;
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if WATCHING.try_with(Cell::get).unwrap_or(false) && layout.size() >= 64 {
            let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            if bytes
                .windows(64)
                .any(|window| window.iter().all(|byte| *byte == b'M'))
            {
                let _ = COPIES.try_with(|counter| counter.set(counter.get() + 1));
            }
        }
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Observer = Observer;

#[tokio::test]
async fn resolution_and_endpoint_errors_release_no_unerased_credential_copies() {
    for (bad_endpoint, invalid_utf8, later_resolution_failure) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("token");
        let root = directory.path().join("volume");
        let mut bytes = vec![b'M'; 256];
        if invalid_utf8 {
            bytes.push(0xff);
        }
        std::fs::write(&token, &bytes).unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let url = if bad_endpoint {
            "malformed-url"
        } else {
            "http://127.0.0.1:9"
        };
        let later_metadata = if later_resolution_failure {
            format!(
                "z_later = {{ source = \"file\", name = \"{}\" }}\n",
                directory.path().join("missing-key").display()
            )
        } else {
            String::new()
        };
        let raw = format!(
            r#"
config_schema_version = 1
[volume]
name = "metadata-erasure"
max_virtual_size = "1MiB"
[crypto]
provider = "remote-grpc"
crypto_compatibility_id = "review-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4124
[[crypto.grpc.endpoint]]
name = "one"
url = "{url}"
[crypto.grpc.metadata]
authorization = {{ source = "file", name = "{}", format = "Bearer {{}} repeat={{}} repeat={{}}" }}
{later_metadata}[backing]
root = "{}"
"#,
            token.display(),
            root.display()
        );
        let config = maki_format::config::parse_config(&raw).unwrap();
        if !bad_endpoint && !invalid_utf8 && !later_resolution_failure {
            create_volume_from_config_str(&raw).unwrap();
        }
        COPIES.with(|counter| counter.set(0));
        WATCHING.with(|watching| watching.set(true));
        let result = build_provider(&config).await;
        let correct_result =
            result.is_err() == (bad_endpoint || invalid_utf8 || later_resolution_failure);
        drop(result);
        WATCHING.with(|watching| watching.set(false));
        assert!(correct_result, "unexpected build outcome");
        assert_eq!(COPIES.with(Cell::get), 0, "bad_endpoint={bad_endpoint} invalid_utf8={invalid_utf8}: credential copy freed without erasure");
    }
}
