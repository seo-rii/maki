use super::*;

fn provider(address: std::net::SocketAddr, timeout: Duration) -> WsCryptoProvider {
    let mut provider = super::decoded_response_tests::provider();
    provider.spec.url = format!("ws://{address}");
    provider.spec.timeout = timeout;
    provider
}

#[tokio::test]
async fn exhausted_tls_preparation_budget_does_not_open_a_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider = provider(listener.local_addr().unwrap(), Duration::from_millis(10));
    let result = provider
        .connect_with_tls(|| {
            std::thread::sleep(Duration::from_millis(20));
            Ok(None)
        })
        .await;
    assert!(matches!(result, Err(CryptoError::Retryable(ref message))
        if message == "websocket connect timeout"));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "expired root preparation must not start a TCP connection"
    );
}

#[tokio::test(start_paused = true)]
async fn network_receives_only_the_budget_left_after_tls_preparation() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let budget = Duration::from_secs(5);
    let provider = provider(listener.local_addr().unwrap(), budget);
    let started = tokio::time::Instant::now();
    let connection = provider.connect_with_tls(|| {
        // Model synchronous preparation while retaining deterministic control
        // of the subsequent network timeout. No task can advance a paused
        // current-thread runtime while this synchronous loader is running.
        tokio::time::resume();
        std::thread::sleep(Duration::from_millis(20));
        tokio::time::pause();
        Ok(None)
    });
    tokio::pin!(connection);
    assert!(futures_util::poll!(&mut connection).is_pending());
    let preparation_elapsed = started.elapsed();
    assert!(preparation_elapsed >= Duration::from_millis(20));
    assert!(preparation_elapsed < budget);
    tokio::time::advance(budget - preparation_elapsed + Duration::from_millis(1)).await;
    assert!(
        matches!(futures_util::poll!(&mut connection),
            std::task::Poll::Ready(Err(CryptoError::Retryable(ref message)))
                if message == "websocket connect timeout"),
        "TLS preparation must not grant the network a fresh full timeout"
    );
}
