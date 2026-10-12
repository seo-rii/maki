//! BUG-046: endpoint queries must not swallow the operation's path.

#[path = "common/request_capture.rs"]
mod request_capture;
use request_capture::{exchange, Case};

fn check(base_suffix: &str, operation_path: &str, configured_query: bool, expected_target: &str) {
    let observed = exchange(Case {
        base_suffix,
        operation_path,
        method: "POST",
        canonical_method: "POST",
        expected_target,
        configured_query,
        decrypt: false,
    });
    assert!(
        observed.result.is_ok(),
        "wire={} result={:?}",
        observed.request_line,
        observed.result
    );
    assert_eq!(
        observed.request_line,
        format!("POST {expected_target} HTTP/1.1")
    );
}

#[test]
fn operation_path_precedes_base_query_and_keeps_the_path_prefix() {
    check(
        "/gateway?tenant=demo",
        "/encrypt",
        false,
        "/gateway/encrypt?tenant=demo",
    );
}

#[test]
fn base_operation_and_configured_queries_are_appended_in_order() {
    check(
        "/gateway?tenant=demo",
        "/encrypt?mode=x%2Fy",
        true,
        "/gateway/encrypt?tenant=demo&mode=x%2Fy&trace=requested+value",
    );
    check(
        "/gateway?mode=base",
        "/encrypt?mode=operation",
        true,
        "/gateway/encrypt?mode=base&mode=operation&trace=requested+value",
    );
}

#[test]
fn trailing_slash_normalization_affects_only_the_base_path() {
    check("/gateway/", "/encrypt", false, "/gateway/encrypt");
    check(
        "/gateway/?tenant=demo/",
        "/encrypt",
        false,
        "/gateway/encrypt?tenant=demo/",
    );
    check("/", "/encrypt", false, "/encrypt");
}

#[test]
fn escaped_path_and_query_components_preserve_their_encoding() {
    check(
        "/gate%2Fway/?tenant=a%2Fb",
        "/en%2Fcrypt?opt=c%2Fd",
        true,
        "/gate%2Fway/en%2Fcrypt?tenant=a%2Fb&opt=c%2Fd&trace=requested+value",
    );
    check(
        "/gate%3Fway?tenant=a%23b",
        "/en%25crypt",
        false,
        "/gate%3Fway/en%25crypt?tenant=a%23b",
    );
}

#[test]
fn empty_query_and_fragment_components_do_not_change_the_operation_path() {
    check(
        "/gateway?empty=",
        "/encrypt?flag",
        false,
        "/gateway/encrypt?empty=&flag",
    );
    check(
        "/gateway?",
        "/encrypt?mode=demo",
        false,
        "/gateway/encrypt?mode=demo",
    );
    check(
        "/gateway?tenant=demo",
        "/encrypt?",
        true,
        "/gateway/encrypt?tenant=demo&trace=requested+value",
    );
    check(
        "/gateway?tenant=demo#base",
        "/encrypt?mode=run#operation",
        false,
        "/gateway/encrypt?tenant=demo&mode=run",
    );
}
