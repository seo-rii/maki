//! `nbd-connect` and `nbd-disconnect` connect a new volume's export outside
//! any attachment, with the helper's own NBD code, for provisioning (see
//! `docs/getting-started/first-volume.md`) and for the qualification
//! fixtures. No `nbd-client` is involved. Their arguments are checked like
//! every other verb's before anything runs, and a raw connection can never
//! take an identifier of the form attach records use.

use std::process::{Command, Output};

const SOCKET: &str = "/run/maki/pg/nbd.sock";
const IDENTIFIER: &str = "maki-bootstrap-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-attach"))
        .args(args)
        .output()
        .expect("spawn maki-attach")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn the_plans_name_the_device_socket_block_size_and_identifier() {
    let connect = [
        "nbd-connect",
        "--nbd-device",
        "/dev/nbd4",
        "--socket",
        SOCKET,
        "--identifier",
        IDENTIFIER,
        "--plan",
    ];
    let out = run(&connect);
    assert!(out.status.success(), "{}", text(&out));
    let plan = String::from_utf8_lossy(&out.stdout);
    assert!(
        plan.contains(&format!(
            "connect nbd4 to {SOCKET} over netlink (block size 4096, backend identifier \
             '{IDENTIFIER}'; the export must advertise FLUSH and FUA)"
        )),
        "{plan}"
    );
    assert!(plan.contains("outside any attachment"), "{plan}");
    let out = run(&[&connect[..7], &["--block-size", "512", "--plan"]].concat());
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("(block size 512,"),
        "{}",
        text(&out)
    );

    let out = run(&[
        "nbd-disconnect",
        "--nbd-device",
        "/dev/nbd4",
        "--identifier",
        IDENTIFIER,
        "--plan",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let plan = String::from_utf8_lossy(&out.stdout);
    assert!(
        plan.contains(&format!(
            "disconnect nbd4 over netlink, only while its backend identifier is '{IDENTIFIER}'"
        )),
        "{plan}"
    );
    assert!(!plan.contains("nbd-client"), "{plan}");
}

#[test]
fn misuse_is_answered_with_the_usage() {
    let connect = |extra: &[&'static str]| {
        let mut args = vec!["nbd-connect"];
        args.extend_from_slice(extra);
        args
    };
    for args in [
        connect(&["--socket", SOCKET, "--identifier", IDENTIFIER, "--plan"]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--identifier",
            IDENTIFIER,
            "--plan",
        ]),
        connect(&["--nbd-device", "/dev/nbd4", "--socket", SOCKET, "--plan"]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--socket",
            SOCKET,
            "--identifier",
            IDENTIFIER,
            "--volume",
            "pg",
            "--plan",
        ]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--socket",
            SOCKET,
            "--identifier",
            IDENTIFIER,
            "--identifier",
            IDENTIFIER,
            "--plan",
        ]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--socket",
            SOCKET,
            "--identifier",
            IDENTIFIER,
            "--vg",
            "vg",
            "--plan",
        ]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--socket",
            SOCKET,
            "--identifier",
        ]),
        connect(&[
            "--nbd-device",
            "/dev/nbd4",
            "--socket",
            SOCKET,
            "--identifier",
            "--plan",
        ]),
        vec!["nbd-disconnect", "--identifier", IDENTIFIER, "--plan"],
        vec!["nbd-disconnect", "--nbd-device", "/dev/nbd4", "--plan"],
        vec![
            "nbd-disconnect",
            "--nbd-device",
            "/dev/nbd4",
            "--identifier",
            IDENTIFIER,
            "--socket",
            SOCKET,
            "--plan",
        ],
        vec![
            "nbd-disconnect",
            "--nbd-device",
            "/dev/nbd4",
            "--identifier",
            IDENTIFIER,
            "--block-size",
            "512",
            "--plan",
        ],
    ] {
        let out = run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(text(&out).contains("usage:"), "{args:?}: {}", text(&out));
    }
}

#[test]
fn values_a_raw_connection_must_not_take_are_refused() {
    let connect = |device: &str, socket: &str, identifier: &str, block: &str| {
        [
            "nbd-connect",
            "--nbd-device",
            device,
            "--socket",
            socket,
            "--identifier",
            identifier,
            "--block-size",
            block,
            "--plan",
        ]
        .map(String::from)
        .to_vec()
    };
    let record_form = "maki-0f7c2b1a-3d4e-4f5a-8b6c-7d8e9f0a1b2c";
    let long = "m".repeat(256);
    for (args, why) in [
        (
            connect("/dev/nbd4", SOCKET, record_form, "4096"),
            "attach record",
        ),
        (
            connect(
                "/dev/nbd4",
                SOCKET,
                &format!("maki-{}", record_form["maki-".len()..].to_uppercase()),
                "4096",
            ),
            "attach record",
        ),
        (
            connect("/dev/nbd4", SOCKET, "maki bootstrap", "4096"),
            "identifier",
        ),
        (connect("/dev/nbd4", SOCKET, &long, "4096"), "identifier"),
        (
            connect("/dev/nbd04", SOCKET, IDENTIFIER, "4096"),
            "/dev/nbdN",
        ),
        (connect("/dev/sda", SOCKET, IDENTIFIER, "4096"), "/dev/nbdN"),
        (connect("nbd4", SOCKET, IDENTIFIER, "4096"), "/dev/nbdN"),
        (
            connect("/dev/nbd4", "run/maki/pg/nbd.sock", IDENTIFIER, "4096"),
            "absolute",
        ),
        (
            connect("/dev/nbd4", SOCKET, IDENTIFIER, "1000"),
            "block size",
        ),
        (
            connect("/dev/nbd4", SOCKET, IDENTIFIER, "256"),
            "block size",
        ),
        (
            connect("/dev/nbd4", SOCKET, IDENTIFIER, "+512"),
            "block size",
        ),
        (
            connect("/dev/nbd4", SOCKET, IDENTIFIER, "4096x"),
            "block size",
        ),
        (
            [
                "nbd-disconnect",
                "--nbd-device",
                "/dev/nbd4",
                "--identifier",
                record_form,
                "--plan",
            ]
            .map(String::from)
            .to_vec(),
            "attach record",
        ),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_maki-attach"))
            .args(&args)
            .output()
            .expect("spawn maki-attach");
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
        assert!(out.stdout.is_empty(), "{args:?}");
        assert!(text(&out).contains(why), "{args:?}: {}", text(&out));
    }
}

#[test]
fn help_lists_the_provisioning_verbs() {
    let out = run(&["--help"]);
    let usage = String::from_utf8_lossy(&out.stdout);
    for verb in ["nbd-connect", "nbd-disconnect"] {
        assert!(usage.contains(&format!("maki-attach {verb} ")), "{usage}");
    }
}
