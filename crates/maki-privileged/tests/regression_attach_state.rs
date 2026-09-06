//! BUG-003: privileged helper state must not live below daemon-owned paths.

use maki_privileged::plan::BOUND_DEVICE_RECORD_DIR;

#[test]
fn helper_records_have_their_own_root_owned_runtime_directory() {
    assert_eq!(BOUND_DEVICE_RECORD_DIR, "/run/maki-attach");
    let tmpfiles = include_str!("../../../packaging/tmpfiles.d/maki.conf");
    let state = tmpfiles
        .lines()
        .map(|line| line.split_whitespace().collect::<Vec<_>>())
        .find(|fields| fields.get(1) == Some(&BOUND_DEVICE_RECORD_DIR))
        .expect("helper state directory must be provisioned");
    assert_eq!(&state[2..5], &["0700", "root", "root"]);
}

#[cfg(target_os = "linux")]
#[test]
fn attach_lock_shares_the_trusted_state_directory() {
    assert_eq!(
        maki_privileged::exec::ATTACH_LOCK_PATH,
        "/run/maki-attach/attach.lock"
    );
}
