//! BUG-168: diagnostics retain locations/field names, never rejected input.
use maki_privileged::config::{parse, AttachOverrides};
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
fn semantic_errors_identify_fields_without_rejected_values() {
    for (field, value) in [
        ("nbd_device", format!("/dev/{MARKER}")),
        ("nbd_socket", MARKER.to_string()),
        ("nbd_socket", format!("-{MARKER}")),
        ("nbd_socket", format!("/{MARKER}/")),
        ("nbd_socket", format!("/{MARKER}/../socket")),
        ("nbd_socket", format!("/{MARKER}//socket")),
        ("mountpoint", MARKER.to_string()),
        ("vg_name", format!("{MARKER}/invalid")),
        ("lv_name", format!("{MARKER}/invalid")),
        ("volume_uuid", MARKER.to_string()),
        ("fs_uuid", MARKER.to_string()),
    ] {
        let config = parse(&format!("{field} = '{value}'\n")).unwrap();
        let error = config
            .into_request("review", AttachOverrides::default(), false)
            .unwrap_err();
        assert!(error.to_string().contains(field));
        assert_redacted(&error);
    }
    for field in ["pv_uuids", "vg_uuid", "lv_uuid"] {
        let mut pins = [
            "pv_uuids = ['111111-2222-3333-4444-5555-6666-777777']".to_string(),
            "vg_uuid = 'aaaaaa-bbbb-cccc-dddd-eeee-ffff-gggggg'".to_string(),
            "lv_uuid = 'hhhhhh-iiii-jjjj-kkkk-llll-mmmm-nnnnnn'".to_string(),
        ];
        let index = match field {
            "pv_uuids" => 0,
            "vg_uuid" => 1,
            _ => 2,
        };
        pins[index] = if index == 0 {
            format!("{field} = ['{MARKER}']")
        } else {
            format!("{field} = '{MARKER}'")
        };
        let config = parse(&format!("[lvm_identity]\n{}\n", pins.join("\n"))).unwrap();
        let error = config
            .into_request("review", AttachOverrides::default(), false)
            .unwrap_err();
        assert!(error.to_string().contains(&format!("lvm_identity.{field}")));
        assert_redacted(&error);
    }
}

#[test]
fn invalid_overrides_and_volume_names_do_not_echo_values() {
    let error = parse("")
        .unwrap()
        .into_request(
            "review",
            AttachOverrides {
                nbd_socket: Some(MARKER.to_string()),
                ..Default::default()
            },
            false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("nbd_socket"));
    assert_redacted(&error);

    let error = parse("")
        .unwrap()
        .into_request(
            &format!("{MARKER}/invalid"),
            AttachOverrides::default(),
            false,
        )
        .unwrap_err();
    assert!(error.to_string().contains("volume name"));
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
