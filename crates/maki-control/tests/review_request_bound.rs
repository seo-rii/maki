//! Outgoing requests must fit the same framing accepted by the server.

use maki_control::protocol::{read_line, send_command, ProtocolError, Request, MAX_LINE};
use serde_json::json;

fn request_with_size(size: usize) -> Request {
    let overhead = serde_json::to_vec(&Request::new("")).unwrap().len();
    let request = Request::new(&"x".repeat(size - overhead));
    assert_eq!(serde_json::to_vec(&request).unwrap().len(), size);
    request
}

#[tokio::test]
async fn exact_frame_boundary_round_trips_without_counting_the_newline() {
    let request = request_with_size(MAX_LINE);
    let mut wire = Vec::new();
    send_command(&mut wire, &request).await.unwrap();
    assert_eq!(wire.len(), MAX_LINE + 1);
    assert_eq!(wire.last(), Some(&b'\n'));
    let line = read_line(&mut wire.as_slice()).await.unwrap();
    let received: Request = serde_json::from_slice(&line).unwrap();
    assert_eq!(received.command, request.command);
}

#[tokio::test]
async fn one_byte_over_the_frame_boundary_is_rejected_before_writing() {
    let mut wire = Vec::new();
    let result = send_command(&mut wire, &request_with_size(MAX_LINE + 1)).await;
    assert!(
        matches!(result, Err(ProtocolError::LineTooLong)),
        "{result:?}"
    );
    assert!(
        wire.is_empty(),
        "a rejected request must not write a partial frame"
    );
}

#[tokio::test]
async fn json_escaping_counts_toward_the_request_limit() {
    let mut request = Request::new("reload");
    request.section = Some("cache".into());
    request.payload = json!({"value": "\u{0001}".repeat(MAX_LINE / 6)});
    assert!(serde_json::to_vec(&request).unwrap().len() > MAX_LINE);
    let mut wire = Vec::new();
    let result = send_command(&mut wire, &request).await;
    assert!(
        matches!(result, Err(ProtocolError::LineTooLong)),
        "{result:?}"
    );
    assert!(
        wire.is_empty(),
        "JSON escaping must not bypass the wire limit"
    );
}

#[tokio::test]
async fn rejected_request_leaves_the_stream_usable_for_the_next_command() {
    let (mut writer, mut reader) = tokio::io::duplex(2 * MAX_LINE);
    let result = send_command(&mut writer, &request_with_size(MAX_LINE + 1)).await;
    assert!(
        matches!(result, Err(ProtocolError::LineTooLong)),
        "{result:?}"
    );
    send_command(&mut writer, &Request::new("status"))
        .await
        .unwrap();
    let line = read_line(&mut reader).await.unwrap();
    let received: Request = serde_json::from_slice(&line).unwrap();
    assert_eq!(received.command, "status");
}
