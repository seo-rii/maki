//! The privileged validation runner exercises the shipped path: the helper
//! negotiates and connects NBD devices itself, so the runner neither
//! requires, installs nor probes nbd-client. Its raw fixture connects and
//! disconnects with the helper's provisioning verbs, and the unprivileged
//! disconnect probe sends the helper's own netlink request, so the kernel's
//! refusal is what it checks.

#[test]
fn the_privileged_runner_needs_no_nbd_client() {
    let runner = include_str!("../../../scripts/privileged-linux-validation.sh");
    let wrapper = include_str!("../../../scripts/privileged_validation_nbd.py");
    for (name, text) in [("runner", runner), ("wrapper", wrapper)] {
        assert!(
            !text.contains("nbd-client"),
            "the {name} still uses nbd-client"
        );
    }
    assert!(
        wrapper.contains("\"nbd-connect\"") && wrapper.contains("\"nbd-disconnect\""),
        "the raw fixture must connect and disconnect with the helper's verbs"
    );
    assert!(
        runner.contains(
            "\"$attach_bin\" nbd-disconnect --nbd-device \"$device\" --identifier \
             \"$nbd_connection_id\""
        ),
        "the unprivileged disconnect probe must run the helper's own request"
    );
}
