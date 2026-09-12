//! Inspect only initialized, selected allocations before returning them to
//! System. These tests make no claim about tonic's separate codec buffers.

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use prost::bytes::Bytes;
use prost::Message;
use tonic::codec::Codec;
use tonic::codegen::tokio_stream::StreamExt;
use tonic::codegen::{http, BoxFuture, Service};

use super::{
    protected::{WireItem, WireRequest, WireResponse},
    GrpcCryptoProvider, GrpcProviderSpec,
};
use maki_crypto::{CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, SecretBuffer};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static WATCHED: AtomicUsize = AtomicUsize::new(0);
static WATCH_NEXT_SIZE: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicBool = AtomicBool::new(false);
static ZEROIZED: AtomicBool = AtomicBool::new(false);

struct InspectDeallocation;

// SAFETY: all memory comes from and returns to System. Explicitly watched
// vectors have their entire capacity initialized first. An allocation selected
// by size is initialized here before it is returned to the caller. We inspect
// only that live allocation, before dealloc, and allocate nothing while doing so.
unsafe impl GlobalAlloc for InspectDeallocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null()
            && layout.size() != 0
            && WATCH_NEXT_SIZE
                .compare_exchange(layout.size(), 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            unsafe { ptr.write_bytes(0, layout.size()) };
            WATCHED.store(ptr as usize, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED.load(Ordering::SeqCst) == ptr as usize {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            ZEROIZED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            RELEASED.store(true, Ordering::SeqCst);
            WATCHED.store(0, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: InspectDeallocation = InspectDeallocation;

fn reset_observer() {
    WATCHED.store(0, Ordering::SeqCst);
    WATCH_NEXT_SIZE.store(0, Ordering::SeqCst);
    RELEASED.store(false, Ordering::SeqCst);
    ZEROIZED.store(false, Ordering::SeqCst);
}

fn watched_item() -> WireItem {
    reset_observer();
    let mut data = vec![0xC7; 256];
    data.resize(data.capacity(), 0xC7);
    data.truncate(64); // Secret material also occupies initialized spare capacity.
    WATCHED.store(data.as_ptr() as usize, Ordering::SeqCst);
    WireItem {
        unit_index: 7,
        data,
    }
}

fn assert_zeroized() {
    assert!(
        RELEASED.load(Ordering::SeqCst),
        "tracked allocation was not released"
    );
    assert!(
        ZEROIZED.load(Ordering::SeqCst),
        "owned plaintext was released without zeroizing its full capacity"
    );
}

fn request(item: WireItem) -> WireRequest {
    WireRequest {
        volume_id: "volume".into(),
        compatibility_id: "profile".into(),
        items: vec![item],
        format_version: 1,
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::noop();
    future.poll(&mut Context::from_waker(waker))
}

#[test]
fn owned_request_and_response_drop_erase_spare_capacity() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    drop(request(watched_item()));
    assert_zeroized();
    drop(WireResponse {
        items: vec![watched_item()],
    });
    assert_zeroized();
}

#[test]
fn message_clear_erases_before_a_later_reallocation() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut item = watched_item();
    item.clear();
    assert!(item.data.is_empty());
    assert_eq!(item.unit_index, 0);
    item.data.reserve(2048);
    assert_zeroized();
}

#[test]
fn duplicate_bytes_field_erases_old_allocation_before_growing() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let replacement = super::CryptoItem {
        unit_index: 9,
        data: vec![0x35; 2048],
    }
    .encode_to_vec();
    let mut item = watched_item();
    item.merge(Bytes::from(replacement)).unwrap();
    assert_zeroized();
    assert_eq!(item.unit_index, 9);
    assert!(item.data.iter().all(|byte| *byte == 0x35));
    assert_eq!(item.data.len(), 2048);
}

#[test]
fn malformed_replacement_erases_the_previous_bytes_field() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Truncated length varint, insufficient bytes, and wrong wire type.
    for malformed in [&[0x12, 0x80][..], &[0x12, 10, 1][..], &[0x10, 1][..]] {
        let mut item = watched_item();
        assert!(item.merge(malformed).is_err());
        item.data.reserve(2048);
        assert_zeroized();
    }
}

#[test]
fn parent_message_clear_erases_child_allocations() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut request = request(watched_item());
    request.clear();
    assert!(request.items.is_empty());
    assert_zeroized();
    let mut response = WireResponse {
        items: vec![watched_item()],
    };
    response.clear();
    assert!(response.items.is_empty());
    assert_zeroized();
}

#[test]
fn protected_messages_preserve_the_public_wire_encoding() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Frozen item: uint64 field 1 = 300; bytes field 2 = 00 7f ff.
    let frozen = [0x08, 0xac, 0x02, 0x12, 0x03, 0x00, 0x7f, 0xff];
    let item = WireItem::decode(&frozen[..]).unwrap();
    assert_eq!(item.unit_index, 300);
    assert_eq!(item.data, [0x00, 0x7f, 0xff]);
    assert_eq!(item.encode_to_vec(), frozen);
    assert_eq!(item.encoded_len(), frozen.len());

    for index in [0, 1, 127, 128, u64::MAX] {
        let public = super::CryptoBatchRequest {
            volume_id: "volume".into(),
            compatibility_id: "profile".into(),
            items: vec![
                super::CryptoItem {
                    unit_index: index,
                    data: vec![0, 0x7f, 0xff],
                },
                super::CryptoItem::default(),
            ],
            format_version: 2,
        };
        let bytes = public.encode_to_vec();
        let protected = WireRequest::decode(bytes.as_slice()).unwrap();
        assert_eq!(protected.encode_to_vec(), bytes);
        assert_eq!(protected.encoded_len(), bytes.len());
        assert_eq!(
            super::CryptoBatchRequest::decode(protected.encode_to_vec().as_slice()).unwrap(),
            public
        );

        let public = super::CryptoBatchResponse {
            items: public.items,
        };
        let bytes = public.encode_to_vec();
        let protected = WireResponse::decode(bytes.as_slice()).unwrap();
        assert_eq!(protected.encode_to_vec(), bytes);
        assert_eq!(protected.encoded_len(), bytes.len());
        assert_eq!(
            super::CryptoBatchResponse::decode(protected.encode_to_vec().as_slice()).unwrap(),
            public
        );
    }
    let mut unknown = frozen.to_vec();
    unknown.extend_from_slice(&[0x18, 1]); // Unknown varint field is still skipped.
    assert_eq!(
        WireItem::decode(unknown.as_slice())
            .unwrap()
            .encode_to_vec(),
        frozen
    );
}

#[test]
fn partial_nested_decode_failure_erases_the_item_before_parent_push() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const PAYLOAD: usize = 8209;
    let mut nested = super::CryptoItem {
        unit_index: 7,
        data: vec![0xC7; PAYLOAD],
    }
    .encode_to_vec();
    nested.push(0); // Invalid key after the complete data field, inside the item.
    let mut wire = vec![0x0a];
    prost::encoding::encode_varint(nested.len() as u64, &mut wire);
    wire.extend_from_slice(&nested);
    let wire = Bytes::from(wire); // Byte slices remain shared; only item data allocates PAYLOAD.
    reset_observer();
    WATCH_NEXT_SIZE.store(PAYLOAD, Ordering::SeqCst);
    assert!(WireResponse::decode(wire).is_err());
    assert_eq!(
        WATCH_NEXT_SIZE.load(Ordering::SeqCst),
        0,
        "item data allocation was not observed"
    );
    assert_zeroized();
}

#[test]
fn successful_transfer_keeps_allocation_until_secret_buffer_drop() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut item = watched_item();
    let address = item.data.as_ptr();
    let secret = SecretBuffer::from_vec(std::mem::take(&mut item.data));
    drop(item);
    assert!(!RELEASED.load(Ordering::SeqCst));
    assert_eq!(secret.expose().as_ptr(), address);
    assert!(secret.expose().iter().all(|byte| *byte == 0xC7));
    drop(secret);
    assert_zeroized();
}

struct HoldRequest;
impl Service<http::Request<tonic::body::BoxBody>> for HoldRequest {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::BoxBody>) -> Self::Future {
        Box::pin(async move {
            std::future::pending::<()>().await;
            drop(request);
            Ok(http::Response::new(tonic::body::empty_body()))
        })
    }
}

#[test]
fn canceling_tonic_before_encoding_drops_the_owned_request_item() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut client = tonic::client::Grpc::new(HoldRequest);
    let codec = tonic::codec::ProstCodec::<WireRequest, WireResponse>::default();
    let mut exchange = Box::pin(client.unary(
        tonic::Request::new(request(watched_item())),
        http::uri::PathAndQuery::from_static("/crypto/Encrypt"),
        codec,
    ));
    assert!(poll_once(exchange.as_mut()).is_pending());
    assert!(
        !RELEASED.load(Ordering::SeqCst),
        "request must still own its item while pending"
    );
    drop(exchange);
    assert_zeroized();
}

#[test]
fn tonic_encoding_releases_the_original_owned_item_with_zeroization() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut codec = tonic::codec::ProstCodec::<WireRequest, WireResponse>::default();
    let source = tonic::codegen::tokio_stream::iter([Ok(request(watched_item()))]);
    let mut body = Box::pin(tonic::codec::EncodeBody::new_client(
        codec.encoder(),
        source,
        None,
        None,
    ));
    let waker = Waker::noop();
    let result = tonic::codegen::Body::poll_frame(body.as_mut(), &mut Context::from_waker(waker));
    assert!(matches!(result, Poll::Ready(Some(Ok(_)))));
    assert_zeroized(); // The separate encoded tonic buffer is intentionally not watched.
}

struct ReplyBody(Option<tonic::body::BoxBody>);

impl Service<http::Request<tonic::body::BoxBody>> for ReplyBody {
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: http::Request<tonic::body::BoxBody>) -> Self::Future {
        std::future::ready(Ok(http::Response::builder()
            .header("content-type", "application/grpc")
            .body(self.0.take().unwrap())
            .unwrap()))
    }
}

#[test]
fn canceling_tonic_after_decode_before_trailers_erases_the_response_item() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    const PAYLOAD: usize = 8209;
    // The fixture's public response is constructed before observation starts.
    let fixture = super::CryptoBatchResponse {
        items: vec![super::CryptoItem {
            unit_index: 7,
            data: vec![0xC7; PAYLOAD],
        }],
    };
    let source = tonic::codegen::tokio_stream::iter([Ok(fixture)])
        .chain(tonic::codegen::tokio_stream::pending());
    let mut server_codec =
        tonic::codec::ProstCodec::<super::CryptoBatchResponse, super::CryptoBatchRequest>::default(
        );
    let body = tonic::body::boxed(tonic::codec::EncodeBody::new_client(
        server_codec.encoder(),
        source,
        None,
        None,
    ));
    let mut client = tonic::client::Grpc::new(ReplyBody(Some(body)));
    let mut exchange = Box::pin(client.unary(
        tonic::Request::new(WireRequest::default()),
        http::uri::PathAndQuery::from_static("/crypto/Decrypt"),
        tonic::codec::ProstCodec::<WireRequest, WireResponse>::default(),
    ));
    reset_observer();
    WATCH_NEXT_SIZE.store(PAYLOAD, Ordering::SeqCst);
    assert!(poll_once(exchange.as_mut()).is_pending());
    assert_eq!(
        WATCH_NEXT_SIZE.load(Ordering::SeqCst),
        0,
        "response item was not decoded"
    );
    assert_ne!(WATCHED.load(Ordering::SeqCst), 0);
    assert!(
        !RELEASED.load(Ordering::SeqCst),
        "decoded item must survive the pending trailers"
    );
    drop(exchange);
    assert_zeroized();
}

#[test]
fn private_wire_debug_does_not_print_plaintext_bytes() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let debug = format!("{:?}", request(watched_item()));
    assert!(
        !debug.contains("199"),
        "wire Debug exposed plaintext byte values"
    );
    assert!(debug.contains("redacted"));
}

#[test]
fn provider_request_size_rejection_erases_owned_item() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let provider = test_provider("http://127.0.0.1:1", 1);
        let context = test_context();
        let result = provider
            .call(
                provider.encrypt_path.clone(),
                &context,
                vec![watched_item()],
            )
            .await;
        assert!(matches!(result, Err(CryptoError::NonRetryableRequest(_))));
        assert_zeroized();
    });
}

fn test_provider(url: &str, max_message_bytes: usize) -> GrpcCryptoProvider {
    GrpcCryptoProvider::new(GrpcProviderSpec {
        url: url.into(),
        encrypt_path: "/crypto/Encrypt".into(),
        decrypt_path: "/crypto/Decrypt".into(),
        metadata: vec![],
        capabilities: maki_crypto::CryptoCapabilities {
            provider_id: "lifetime-test".into(),
            crypto_compatibility_id: "profile".into(),
            supported_plaintext_sizes: vec![64, 8209],
            max_ciphertext_size: 8209,
            stateless: true,
            retry_safe: true,
            batch: maki_crypto::BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 1 << 20,
            },
            integrity: maki_crypto::Capability::Absent,
            context_binding: maki_crypto::Capability::Absent,
            replay_protection: maki_crypto::Capability::Absent,
        },
        timeout: std::time::Duration::from_secs(1),
        max_message_bytes,
    })
    .unwrap()
}

fn test_context() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::nil(),
        format_version: 1,
        crypto_compatibility_id: "profile".into(),
    }
}

#[derive(Clone)]
struct FixedReply(Arc<Mutex<Option<super::CryptoBatchResponse>>>);

impl tonic::server::NamedService for FixedReply {
    const NAME: &'static str = "crypto";
}

impl tonic::server::UnaryService<super::CryptoBatchRequest> for FixedReply {
    type Response = super::CryptoBatchResponse;
    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

    fn call(&mut self, _: tonic::Request<super::CryptoBatchRequest>) -> Self::Future {
        let response = self.0.lock().unwrap().take().unwrap();
        Box::pin(async move { Ok(tonic::Response::new(response)) })
    }
}

impl<B> Service<http::Request<B>> for FixedReply
where
    B: tonic::codegen::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            let codec = tonic::codec::ProstCodec::<
                super::CryptoBatchResponse,
                super::CryptoBatchRequest,
            >::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(handler, request)
                .await)
        })
    }
}

struct ListenerStream(tokio::net::TcpListener);

impl tonic::codegen::tokio_stream::Stream for ListenerStream {
    type Item = std::io::Result<tokio::net::TcpStream>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.poll_accept(cx) {
            Poll::Ready(Ok((stream, _))) => Poll::Ready(Some(Ok(stream))),
            Poll::Ready(Err(error)) => Poll::Ready(Some(Err(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[test]
fn provider_response_rejection_and_success_preserve_secret_ownership() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        const PAYLOAD: usize = 8209;
        // One actual RPC each: wrong count, wrong unit, successful transfer.
        for requested in [&[7, 8][..], &[8][..], &[7][..]] {
            let fixture = FixedReply(Arc::new(Mutex::new(Some(super::CryptoBatchResponse {
                items: vec![super::CryptoItem {
                    unit_index: 7,
                    data: vec![0xC7; PAYLOAD],
                }],
            }))));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(fixture)
                    .serve_with_incoming(ListenerStream(listener))
                    .await
                    .unwrap();
            });
            let provider = test_provider(&url, 1 << 20);
            let inputs: Vec<_> = requested
                .iter()
                .map(|index| CiphertextUnit {
                    unit_index: *index,
                    data: vec![0x11; 64],
                })
                .collect();
            reset_observer();
            WATCH_NEXT_SIZE.store(PAYLOAD, Ordering::SeqCst);
            let result = provider.decrypt_batch(&test_context(), &inputs).await;
            assert_eq!(
                WATCH_NEXT_SIZE.load(Ordering::SeqCst),
                0,
                "response item allocation was not observed"
            );
            if requested == [7] {
                let output = result.unwrap();
                assert_eq!(output.len(), 1);
                assert_eq!(
                    output[0].data.expose().as_ptr() as usize,
                    WATCHED.load(Ordering::SeqCst)
                );
                assert!(!RELEASED.load(Ordering::SeqCst));
                assert_eq!(output[0].data.len(), PAYLOAD);
                assert!(output[0].data.expose().iter().all(|byte| *byte == 0xC7));
                drop(output);
            } else {
                assert!(matches!(result, Err(CryptoError::Contract(_))));
            }
            assert_zeroized();
            server.abort();
            let _ = server.await;
        }
    });
}
