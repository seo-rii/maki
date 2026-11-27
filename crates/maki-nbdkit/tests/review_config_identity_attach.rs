//! Attach compares the configuration's crypto identity with the volume's
//! before it loads a provider credential, as it does the geometry.
//!
//! The provider type, the key identity and the compatibility id (which the
//! random prefix length derives) are fixed at creation (SPEC §20). For a
//! local provider, attach compared them only after it had built the
//! provider, so a changed configuration loaded the key first and was then
//! refused, or failed on the key itself (a 32-byte key read as an XTS key)
//! without naming the setting.
//! `maki check` compares the same settings with the same function, which
//! needs the comparison to stand on its own: here no key exists at all, and
//! each changed setting must still be refused as an identity mismatch that
//! names both values. A remote provider's configuration is compared the
//! same way, before any request reaches an endpoint, at attach and when only
//! the provider is built (`build_provider_with_endpoints`). In both, the
//! dispatcher refused a changed compatibility id or provider type as
//! "remote configuration does not match the locked volume identity/geometry"
//! without saying which setting or values. Over WebSocket and gRPC no
//! connection is even opened to the endpoint for such a configuration.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use maki_core::engine::AttachError;
use maki_nbdkit::daemon::{
    attach_from_config, build_provider_with_endpoints, create_volume_from_config_str,
    parse_and_validate, DaemonError,
};
use maki_test_support::http_chaos::{ResponseSpec, TestServer};

const SIV_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn write_key(path: &std::path::Path) {
    std::fs::write(path, SIV_KEY).unwrap();
    // A file credential must be owner-only (SPEC 9).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn config(root: &str, provider: &str, compat: &str, prefix: u32, key: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "identity-attach"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "128KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "{compat}"
random_prefix_bytes = {prefix}
key = {{ source = "file", name = "{key}" }}
[crypto.capabilities]
supported_plaintext_sizes = [{plaintext}]
max_ciphertext_size = 4384
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
"#,
        plaintext = 4096 + prefix
    )
}

#[tokio::test]
async fn a_changed_crypto_identity_is_refused_before_any_credential_is_loaded() {
    let directory = tempfile::tempdir().unwrap();
    let path = |name: &str| {
        directory
            .path()
            .join(name)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let (root, key) = (path("volume"), path("vol.key"));
    let created = config(&root, "local-aes-gcm-siv", "local-profile-v1", 0, &key);
    let parsed = parse_and_validate(&created).unwrap();
    write_key(std::path::Path::new(&key));
    create_volume_from_config_str(&created).unwrap();
    let engine = attach_from_config(&parsed).await.unwrap();
    engine.write(0, &[0x3c; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);

    let renamed = path("renamed.key");
    for (setting, changed, configured, stored) in [
        (
            "provider",
            config(&root, "local-aes-xts", "local-profile-v1", 0, &key),
            "\"local-aes-xts\"".to_owned(),
            "\"local-aes-gcm-siv\"".to_owned(),
        ),
        (
            "key identity",
            config(&root, "local-aes-gcm-siv", "local-profile-v1", 0, &renamed),
            format!("{renamed:?}"),
            format!("{key:?}"),
        ),
        (
            "compatibility id",
            config(&root, "local-aes-gcm-siv", "local-profile-v2", 0, &key),
            "\"local-profile-v2\"".to_owned(),
            "\"local-profile-v1\"".to_owned(),
        ),
        (
            "compatibility id",
            config(&root, "local-aes-gcm-siv", "local-profile-v1", 16, &key),
            "\"maki-random-prefix-v1:16:local-profile-v1\"".to_owned(),
            "\"local-profile-v1\"".to_owned(),
        ),
    ] {
        let changed = parse_and_validate(&changed).unwrap();
        // No credential exists under either name: the configuration must be
        // refused before the provider would load one.
        std::fs::remove_file(&key).unwrap();
        let error = match attach_from_config(&changed).await {
            Ok(_) => panic!("accepted a changed {setting}"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
            "{setting}: {message}"
        );
        assert!(message.contains(setting), "{message}");
        assert!(
            message.contains(&format!(
                "volume was created with {setting} {stored}, configuration says {configured}"
            )),
            "{message}"
        );
        write_key(std::path::Path::new(&key));
    }

    let engine = attach_from_config(&parsed).await.unwrap();
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x3c; 4096]);
}

fn remote_config(root: &str, url: &str, compat: &str, prefix: u32) -> String {
    let transport = format!(
        r#"
[crypto.http]
max_response_bytes = 4096
timeout = "1s"
[[crypto.http.endpoint]]
name = "only"
url = "{url}"
[crypto.http.encrypt]
path = "/encrypt"
[crypto.http.decrypt]
path = "/decrypt"
"#
    );
    remote_config_for("remote-http", &transport, root, compat, prefix)
}

/// A remote volume's configuration for `provider`, whose `transport`
/// section names its endpoint.
fn remote_config_for(
    provider: &str,
    transport: &str,
    root: &str,
    compat: &str,
    prefix: u32,
) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "identity-remote"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "{provider}"
crypto_compatibility_id = "{compat}"
random_prefix_bytes = {prefix}
availability_policy = "bounded-error"
max_operation_time = "1s"
[crypto.capabilities]
supported_plaintext_sizes = [{plaintext}]
max_ciphertext_size = 528
stateless = true
[crypto.batch]
max_items = 1
target_items = 1
max_bytes = 528
target_bytes = 528
max_wait = "0ms"
{transport}
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[cache]
mode = "off"
"#,
        plaintext = 512 + prefix
    )
}

#[tokio::test]
async fn a_remote_provider_is_not_contacted_for_a_configuration_the_volume_refuses() {
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let server = TestServer::start(Arc::new(move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let created = remote_config(&root, &server.url(), "remote-v1", 0);
    create_volume_from_config_str(&created).unwrap();
    for (changed, configured) in [
        (
            remote_config(&root, &server.url(), "remote-v2", 0),
            "\"remote-v2\"",
        ),
        (
            remote_config(&root, &server.url(), "remote-v1", 16),
            "\"maki-random-prefix-v1:16:remote-v1\"",
        ),
    ] {
        let changed = parse_and_validate(&changed).unwrap();
        let attached = attach_from_config(&changed).await.err();
        let built = build_provider_with_endpoints(&changed).await.err();
        for error in [attached, built] {
            let error = error.expect("a changed compatibility id was accepted");
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{message}"
            );
            assert!(
                message.contains(&format!(
                    "volume was created with compatibility id \"remote-v1\", configuration \
                     says {configured}"
                )),
                "{message}"
            );
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);

    // The fixture itself attaches through the endpoint it counts.
    let engine = attach_from_config(&parse_and_validate(&created).unwrap())
        .await
        .unwrap();
    engine.write(0, &[0x2d; 512], true).await.unwrap();
    assert_eq!(engine.read(0, 512).await.unwrap(), [0x2d; 512]);
    assert!(requests.load(Ordering::SeqCst) > 0);
}

/// A remote configuration over a volume another provider created, and over a
/// remote volume whose superblock records a key identity (which no remote
/// configuration has, so only a superblock written by hand or by another
/// tool carries one): attach and `build_provider_with_endpoints` compare the
/// provider type and the key identity before any endpoint is asked. They
/// refused a changed provider type as "remote configuration does not match
/// the locked volume identity/geometry", and did not compare the key
/// identity before probing the endpoint.
#[tokio::test]
async fn a_remote_configuration_is_compared_by_provider_type_and_key_identity() {
    use maki_backing::FileBacking;
    use maki_format::superblock::{Superblock, CRYPTO_FORMAT_VERSION};

    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let server = TestServer::start(Arc::new(move |request| {
        counted.fetch_add(1, Ordering::SeqCst);
        ResponseSpec::raw(request.body.iter().map(|byte| byte ^ 0x5a).collect())
    }))
    .await;
    let directory = tempfile::tempdir().unwrap();
    for (index, (provider_type, key_identity, refusal)) in [
        (
            "remote-grpc",
            "",
            "volume was created with provider \"remote-grpc\", configuration says \"remote-http\"",
        ),
        (
            "local-aes-gcm-siv",
            "/etc/maki/vol.key",
            "volume was created with provider \"local-aes-gcm-siv\", configuration says \
             \"remote-http\"",
        ),
        (
            "remote-http",
            "stray-key",
            "volume was created with key identity \"stray-key\", configuration says \"\"",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let root = directory
            .path()
            .join(index.to_string())
            .to_string_lossy()
            .replace('\\', "/");
        let config =
            parse_and_validate(&remote_config(&root, &server.url(), "remote-v1", 0)).unwrap();
        let stored = Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: provider_type.into(),
            crypto_compatibility_id: config.crypto.effective_compatibility_id(),
            key_identity: key_identity.into(),
            geometry: config.geometry().unwrap(),
            format_version: CRYPTO_FORMAT_VERSION,
            created_unix: 0,
        };
        maki_format::init::create_volume(&FileBacking::new(&root).unwrap(), stored).unwrap();
        let attached = attach_from_config(&config).await.err();
        let built = build_provider_with_endpoints(&config).await.err();
        for error in [attached, built] {
            let error =
                error.unwrap_or_else(|| panic!("{provider_type} {key_identity:?} accepted"));
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{message}"
            );
            assert!(message.contains(refusal), "{message}");
        }
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

/// A loopback WebSocket endpoint that answers each request with the XOR of
/// its items, and the number of connections it has accepted.
async fn websocket_endpoint() -> (String, Arc<AtomicUsize>) {
    use base64::Engine as _;
    use futures_util::{SinkExt as _, StreamExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let (mut sink, mut source) = socket.split();
                let base64 = base64::engine::general_purpose::STANDARD;
                while let Some(Ok(message)) = source.next().await {
                    let Ok(text) = message.into_text() else {
                        continue;
                    };
                    let request: serde_json::Value = serde_json::from_str(&text).unwrap();
                    let items: Vec<serde_json::Value> = request["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let data = base64.decode(item["data"].as_str().unwrap()).unwrap();
                            let data: Vec<u8> = data.iter().map(|byte| byte ^ 0x5a).collect();
                            serde_json::json!({"unit": item["unit"], "data": base64.encode(data)})
                        })
                        .collect();
                    let response = serde_json::json!({"id": request["id"], "items": items});
                    let _ = sink.send(response.to_string().into()).await;
                }
            });
        }
    });
    (format!("ws://{address}"), connections)
}

mod grpc {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use maki_crypto_grpc::{CryptoBatchRequest, CryptoBatchResponse, CryptoItem};
    use tonic::codegen::{http, BoxFuture, Service, StdError};

    /// Every call answered with the XOR of its items.
    #[derive(Clone)]
    struct Xor;

    impl tonic::server::NamedService for Xor {
        const NAME: &'static str = "maki.CryptoService";
    }

    impl tonic::server::UnaryService<CryptoBatchRequest> for Xor {
        type Response = CryptoBatchResponse;
        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

        fn call(&mut self, request: tonic::Request<CryptoBatchRequest>) -> Self::Future {
            let items = request
                .into_inner()
                .items
                .into_iter()
                .map(|item| CryptoItem {
                    unit_index: item.unit_index,
                    data: item.data.iter().map(|byte| byte ^ 0x5a).collect(),
                })
                .collect();
            Box::pin(async move { Ok(tonic::Response::new(CryptoBatchResponse { items })) })
        }
    }

    impl<B> Service<http::Request<B>> for Xor
    where
        B: tonic::codegen::Body + Send + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, request: http::Request<B>) -> Self::Future {
            let service = self.clone();
            Box::pin(async move {
                let codec =
                    tonic::codec::ProstCodec::<CryptoBatchResponse, CryptoBatchRequest>::default();
                Ok(tonic::server::Grpc::new(codec)
                    .unary(service, request)
                    .await)
            })
        }
    }

    /// The listener's connections, each counted when it is accepted.
    struct Counting(tokio::net::TcpListener, Arc<AtomicUsize>);

    impl tonic::codegen::tokio_stream::Stream for Counting {
        type Item = std::io::Result<tokio::net::TcpStream>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            match self.0.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => {
                    self.1.fetch_add(1, Ordering::SeqCst);
                    Poll::Ready(Some(Ok(stream)))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    /// A loopback gRPC endpoint serving [`Xor`], and the number of
    /// connections it has accepted.
    pub async fn endpoint() -> (String, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let incoming = Counting(listener, connections.clone());
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(Xor)
                .serve_with_incoming(incoming)
                .await;
        });
        (format!("http://{address}"), connections)
    }
}

/// Neither attach nor `build_provider_with_endpoints` opens a connection to
/// the endpoint of `provider`, configured by `transport`, for a volume that
/// another provider created (`other`, a remote one, or a local one), for a
/// volume whose superblock records a key identity, or for a changed
/// compatibility id; the configuration the volume was created with then
/// attaches through that endpoint, which `connections` counts.
async fn refused_without_a_connection(
    provider: &str,
    other: &str,
    transport: &str,
    connections: &AtomicUsize,
) {
    use maki_backing::FileBacking;
    use maki_format::superblock::{Superblock, CRYPTO_FORMAT_VERSION};

    let directory = tempfile::tempdir().unwrap();
    for (index, (provider_type, key_identity, refusal)) in [
        (
            other,
            "",
            format!(
                "volume was created with provider \"{other}\", configuration says \"{provider}\""
            ),
        ),
        (
            "local-aes-gcm-siv",
            "/etc/maki/vol.key",
            format!(
                "volume was created with provider \"local-aes-gcm-siv\", configuration says \
                 \"{provider}\""
            ),
        ),
        (
            provider,
            "stray-key",
            "volume was created with key identity \"stray-key\", configuration says \"\""
                .to_owned(),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let root = directory
            .path()
            .join(format!("stored-{index}"))
            .to_string_lossy()
            .replace('\\', "/");
        let config = parse_and_validate(&remote_config_for(
            provider,
            transport,
            &root,
            "remote-v1",
            0,
        ))
        .unwrap();
        let stored = Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::new_v4(),
            provider_type: provider_type.into(),
            crypto_compatibility_id: config.crypto.effective_compatibility_id(),
            key_identity: key_identity.into(),
            geometry: config.geometry().unwrap(),
            format_version: CRYPTO_FORMAT_VERSION,
            created_unix: 0,
        };
        maki_format::init::create_volume(&FileBacking::new(&root).unwrap(), stored).unwrap();
        let attached = attach_from_config(&config).await.err();
        let built = build_provider_with_endpoints(&config).await.err();
        for error in [attached, built] {
            let error =
                error.unwrap_or_else(|| panic!("{provider_type} {key_identity:?} accepted"));
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{provider}: {message}"
            );
            assert!(message.contains(&refusal), "{provider}: {message}");
        }
    }
    assert_eq!(connections.load(Ordering::SeqCst), 0, "{provider}");

    let root = directory
        .path()
        .join("volume")
        .to_string_lossy()
        .replace('\\', "/");
    let created = remote_config_for(provider, transport, &root, "remote-v1", 0);
    create_volume_from_config_str(&created).unwrap();
    for (changed, configured) in [
        (
            remote_config_for(provider, transport, &root, "remote-v2", 0),
            "\"remote-v2\"",
        ),
        (
            remote_config_for(provider, transport, &root, "remote-v1", 16),
            "\"maki-random-prefix-v1:16:remote-v1\"",
        ),
    ] {
        let changed = parse_and_validate(&changed).unwrap();
        let attached = attach_from_config(&changed).await.err();
        let built = build_provider_with_endpoints(&changed).await.err();
        for error in [attached, built] {
            let error = error.expect("a changed compatibility id was accepted");
            let message = error.to_string();
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{provider}: {message}"
            );
            assert!(
                message.contains(&format!(
                    "volume was created with compatibility id \"remote-v1\", configuration \
                     says {configured}"
                )),
                "{provider}: {message}"
            );
        }
    }
    assert_eq!(connections.load(Ordering::SeqCst), 0, "{provider}");

    // The fixture itself attaches through the endpoint it counts.
    let engine = attach_from_config(&parse_and_validate(&created).unwrap())
        .await
        .unwrap();
    engine.write(0, &[0x2d; 512], true).await.unwrap();
    assert_eq!(engine.read(0, 512).await.unwrap(), [0x2d; 512]);
    assert!(connections.load(Ordering::SeqCst) > 0, "{provider}");
}

#[tokio::test]
async fn a_websocket_endpoint_is_not_connected_to_for_a_configuration_the_volume_refuses() {
    let (url, connections) = websocket_endpoint().await;
    let transport = format!(
        "[crypto.websocket]\ntimeout = \"1s\"\n\
         [[crypto.websocket.endpoint]]\nname = \"only\"\nurl = \"{url}\"\n"
    );
    refused_without_a_connection("remote-websocket", "remote-grpc", &transport, &connections).await;
}

#[tokio::test]
async fn a_grpc_endpoint_is_not_connected_to_for_a_configuration_the_volume_refuses() {
    let (url, connections) = grpc::endpoint().await;
    let transport = format!(
        "[crypto.grpc]\ntimeout = \"1s\"\n\
         [[crypto.grpc.endpoint]]\nname = \"only\"\nurl = \"{url}\"\n"
    );
    refused_without_a_connection("remote-grpc", "remote-websocket", &transport, &connections).await;
}
