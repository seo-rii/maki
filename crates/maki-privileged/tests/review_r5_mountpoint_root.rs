//! R5-019: `mountpoint = "/"` passed both the lexical path check and the
//! pre-mount ancestor check. Mounting the volume over the host root hides
//! the running system; detach would then unmount `/`.

use maki_privileged::config::{parse, AttachOverrides};

const UUID: &str = "0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

#[test]
fn the_host_root_is_never_a_mountpoint() {
    let text = format!("volume_uuid = \"{UUID}\"\nmountpoint = \"/\"\nvg_name = \"vg_maki_pg\"\n");
    let error = parse(&text)
        .unwrap()
        .into_request("pg", AttachOverrides::default(), true)
        .unwrap_err();
    assert!(error.to_string().contains("mountpoint"), "{error}");

    let text = format!("volume_uuid = \"{UUID}\"\nvg_name = \"vg_maki_pg\"\n");
    let overrides = AttachOverrides {
        mountpoint: Some("/".into()),
        ..AttachOverrides::default()
    };
    assert!(parse(&text)
        .unwrap()
        .into_request("pg", overrides, true)
        .is_err());
}
