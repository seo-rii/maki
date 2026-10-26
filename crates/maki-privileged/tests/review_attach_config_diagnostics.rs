//! BUG-168: parser diagnostics retain locations, never configuration input.
use maki_privileged::config::parse;
use std::error::Error;

const MARKER: &str = "synthetic-private-attach-config-bug168";

fn assert_redacted(mut error: &(dyn Error + 'static)) {
    loop {
        let display_leaks = error.to_string().contains(MARKER);
        let debug_leaks = format!("{error:?}").contains(MARKER);
        assert!(
            !display_leaks && !debug_leaks,
            "configuration exposed by Display: {display_leaks}, Debug: {debug_leaks}"
        );
        match error.source() {
            Some(source) => error = source,
            None => break,
        }
    }
}

#[test]
fn rejected_value_is_absent_from_error_chain() {
    let error = parse(&format!("init_sentinel = \"{MARKER}\"\n")).unwrap_err();
    assert_redacted(&error);
}

#[test]
fn unknown_field_is_absent_from_error_chain() {
    let error = parse(&format!("{MARKER} = true\n")).unwrap_err();
    assert_redacted(&error);
}

#[test]
fn syntax_error_is_absent_from_error_chain() {
    let error = parse(&format!("init_sentinel = \"{MARKER}\n")).unwrap_err();
    assert_redacted(&error);
}

#[test]
fn nested_schema_error_is_absent_from_error_chain() {
    let error = parse(&format!("[lvm_identity]\n{MARKER} = true\n")).unwrap_err();
    assert_redacted(&error);
}

#[test]
fn diagnostic_keeps_the_error_location_without_source_text() {
    let error = parse(&format!(
        "# unicode comment: 한글\ninit_sentinel = \"{MARKER}\"\n"
    ))
    .unwrap_err();
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("attach config parse error"));
    assert!(diagnostic.contains("line 2, column 17"));
    assert_redacted(&error);
}

#[test]
fn valid_attach_config_still_parses() {
    let uuid = "abcdef12-2345-6789-abcd-ef0123456789";
    let config = parse(&format!("volume_uuid = \"{uuid}\"\ninit_sentinel = true\n")).unwrap();
    assert_eq!(config.volume_uuid.as_deref(), Some(uuid));
    assert!(config.init_sentinel);
}
