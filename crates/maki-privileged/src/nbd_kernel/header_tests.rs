//! The kernel constants the helper writes by hand, checked against the
//! installed UAPI headers (`<linux/nbd.h>`, `<linux/nbd-netlink.h>`,
//! `<linux/netlink.h>`, `<linux/genetlink.h>`): a C probe compiled with the
//! system compiler prints each one, as `review_abi.rs` does for nbdkit's.
//!
//! Without the headers or a C compiler the check is skipped with a notice;
//! `MAKI_TEST_REQUIRE_NBD_HEADERS=1`, which CI sets, makes that a failure.

use super::handshake;
use super::netlink;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

const REQUIRE: &str = "MAKI_TEST_REQUIRE_NBD_HEADERS";

const HEADERS: [&str; 4] = [
    "/usr/include/linux/nbd.h",
    "/usr/include/linux/nbd-netlink.h",
    "/usr/include/linux/netlink.h",
    "/usr/include/linux/genetlink.h",
];

const PROBE: &str = r#"
#include <linux/genetlink.h>
#include <linux/nbd-netlink.h>
#include <linux/nbd.h>
#include <linux/netlink.h>
#include <stdio.h>
#define P(name) printf("%s %lld\n", #name, (long long)(name))
int main(void) {
  P(NETLINK_GENERIC); P(NLMSG_HDRLEN); P(GENL_HDRLEN); P(NLA_HDRLEN);
  P(NLM_F_REQUEST); P(NLM_F_ACK); P(NLMSG_NOOP); P(NLMSG_ERROR); P(NLMSG_DONE);
  P(NLA_F_NESTED); P(NLA_F_NET_BYTEORDER);
  printf("NLA_TYPE_MASK %lld\n", (long long)(NLA_TYPE_MASK & 0xffff));
  P(GENL_ID_CTRL); P(CTRL_CMD_NEWFAMILY); P(CTRL_CMD_GETFAMILY);
  P(CTRL_ATTR_FAMILY_ID); P(CTRL_ATTR_FAMILY_NAME); P(CTRL_ATTR_MAXATTR);
  printf("NBD_GENL_FAMILY_NAME %s\n", NBD_GENL_FAMILY_NAME);
  P(NBD_GENL_VERSION); P(NBD_CMD_CONNECT); P(NBD_CMD_DISCONNECT);
  P(NBD_ATTR_INDEX); P(NBD_ATTR_SIZE_BYTES); P(NBD_ATTR_BLOCK_SIZE_BYTES);
  P(NBD_ATTR_TIMEOUT); P(NBD_ATTR_SERVER_FLAGS); P(NBD_ATTR_CLIENT_FLAGS);
  P(NBD_ATTR_SOCKETS); P(NBD_ATTR_DEAD_CONN_TIMEOUT); P(NBD_ATTR_DEVICE_LIST);
  P(NBD_ATTR_BACKEND_IDENTIFIER); P(NBD_SOCK_ITEM); P(NBD_SOCK_FD);
  P(NBD_FLAG_HAS_FLAGS); P(NBD_FLAG_READ_ONLY); P(NBD_FLAG_SEND_FLUSH);
  P(NBD_FLAG_SEND_FUA); P(NBD_FLAG_SEND_TRIM);
  /* Newer than some distributions' headers (Ubuntu 24.04 lacks these). */
#ifdef NBD_FLAG_ROTATIONAL
  P(NBD_FLAG_ROTATIONAL);
#endif
#ifdef NBD_FLAG_SEND_WRITE_ZEROES
  P(NBD_FLAG_SEND_WRITE_ZEROES);
#endif
#ifdef NBD_FLAG_CAN_MULTI_CONN
  P(NBD_FLAG_CAN_MULTI_CONN);
#endif
  return 0;
}
"#;

/// Every constant and its value in this crate; the last three may be
/// missing from an older header.
fn expected() -> Vec<(&'static str, String, bool)> {
    let n = |value: i64| value.to_string();
    vec![
        ("NETLINK_GENERIC", n(netlink::NETLINK_GENERIC.into()), true),
        ("NLMSG_HDRLEN", n(netlink::NLMSG_HDRLEN as i64), true),
        ("GENL_HDRLEN", n(netlink::GENL_HDRLEN as i64), true),
        ("NLA_HDRLEN", n(netlink::NLA_HDRLEN as i64), true),
        ("NLM_F_REQUEST", n(netlink::NLM_F_REQUEST.into()), true),
        ("NLM_F_ACK", n(netlink::NLM_F_ACK.into()), true),
        ("NLMSG_NOOP", n(netlink::NLMSG_NOOP.into()), true),
        ("NLMSG_ERROR", n(netlink::NLMSG_ERROR.into()), true),
        ("NLMSG_DONE", n(netlink::NLMSG_DONE.into()), true),
        ("NLA_F_NESTED", n(netlink::NLA_F_NESTED.into()), true),
        (
            "NLA_F_NET_BYTEORDER",
            n(netlink::NLA_F_NET_BYTEORDER.into()),
            true,
        ),
        ("NLA_TYPE_MASK", n(netlink::NLA_TYPE_MASK.into()), true),
        ("GENL_ID_CTRL", n(netlink::GENL_ID_CTRL.into()), true),
        (
            "CTRL_CMD_NEWFAMILY",
            n(netlink::CTRL_CMD_NEWFAMILY.into()),
            true,
        ),
        (
            "CTRL_CMD_GETFAMILY",
            n(netlink::CTRL_CMD_GETFAMILY.into()),
            true,
        ),
        (
            "CTRL_ATTR_FAMILY_ID",
            n(netlink::CTRL_ATTR_FAMILY_ID.into()),
            true,
        ),
        (
            "CTRL_ATTR_FAMILY_NAME",
            n(netlink::CTRL_ATTR_FAMILY_NAME.into()),
            true,
        ),
        (
            "CTRL_ATTR_MAXATTR",
            n(netlink::CTRL_ATTR_MAXATTR.into()),
            true,
        ),
        (
            "NBD_GENL_FAMILY_NAME",
            netlink::NBD_GENL_FAMILY_NAME.into(),
            true,
        ),
        (
            "NBD_GENL_VERSION",
            n(netlink::NBD_GENL_VERSION.into()),
            true,
        ),
        ("NBD_CMD_CONNECT", n(netlink::NBD_CMD_CONNECT.into()), true),
        (
            "NBD_CMD_DISCONNECT",
            n(netlink::NBD_CMD_DISCONNECT.into()),
            true,
        ),
        ("NBD_ATTR_INDEX", n(netlink::NBD_ATTR_INDEX.into()), true),
        (
            "NBD_ATTR_SIZE_BYTES",
            n(netlink::NBD_ATTR_SIZE_BYTES.into()),
            true,
        ),
        (
            "NBD_ATTR_BLOCK_SIZE_BYTES",
            n(netlink::NBD_ATTR_BLOCK_SIZE_BYTES.into()),
            true,
        ),
        (
            "NBD_ATTR_TIMEOUT",
            n(netlink::NBD_ATTR_TIMEOUT.into()),
            true,
        ),
        (
            "NBD_ATTR_SERVER_FLAGS",
            n(netlink::NBD_ATTR_SERVER_FLAGS.into()),
            true,
        ),
        (
            "NBD_ATTR_CLIENT_FLAGS",
            n(netlink::NBD_ATTR_CLIENT_FLAGS.into()),
            true,
        ),
        (
            "NBD_ATTR_SOCKETS",
            n(netlink::NBD_ATTR_SOCKETS.into()),
            true,
        ),
        (
            "NBD_ATTR_DEAD_CONN_TIMEOUT",
            n(netlink::NBD_ATTR_DEAD_CONN_TIMEOUT.into()),
            true,
        ),
        (
            "NBD_ATTR_DEVICE_LIST",
            n(netlink::NBD_ATTR_DEVICE_LIST.into()),
            true,
        ),
        (
            "NBD_ATTR_BACKEND_IDENTIFIER",
            n(netlink::NBD_ATTR_BACKEND_IDENTIFIER.into()),
            true,
        ),
        ("NBD_SOCK_ITEM", n(netlink::NBD_SOCK_ITEM.into()), true),
        ("NBD_SOCK_FD", n(netlink::NBD_SOCK_FD.into()), true),
        (
            "NBD_FLAG_HAS_FLAGS",
            n(handshake::NBD_FLAG_HAS_FLAGS.into()),
            true,
        ),
        (
            "NBD_FLAG_READ_ONLY",
            n(handshake::NBD_FLAG_READ_ONLY.into()),
            true,
        ),
        (
            "NBD_FLAG_SEND_FLUSH",
            n(handshake::NBD_FLAG_SEND_FLUSH.into()),
            true,
        ),
        (
            "NBD_FLAG_SEND_FUA",
            n(handshake::NBD_FLAG_SEND_FUA.into()),
            true,
        ),
        (
            "NBD_FLAG_SEND_TRIM",
            n(handshake::NBD_FLAG_SEND_TRIM.into()),
            true,
        ),
        (
            "NBD_FLAG_ROTATIONAL",
            n(handshake::NBD_FLAG_ROTATIONAL.into()),
            false,
        ),
        (
            "NBD_FLAG_SEND_WRITE_ZEROES",
            n(handshake::NBD_FLAG_SEND_WRITE_ZEROES.into()),
            false,
        ),
        (
            "NBD_FLAG_CAN_MULTI_CONN",
            n(handshake::NBD_FLAG_CAN_MULTI_CONN.into()),
            false,
        ),
    ]
}

/// Skip with `reason`, or fail when the headers are required.
fn unavailable(reason: &str, required: bool) -> Result<(), String> {
    if required {
        return Err(format!(
            "{REQUIRE}=1 requires the NBD header check, but {reason}"
        ));
    }
    eprintln!("skipping the NBD UAPI header check: {reason} (set {REQUIRE}=1 to fail instead)");
    Ok(())
}

fn probe() -> Result<Option<BTreeMap<String, String>>, String> {
    let required = std::env::var_os(REQUIRE).is_some_and(|value| value == "1");
    if let Some(missing) = HEADERS.iter().find(|header| !Path::new(header).is_file()) {
        unavailable(
            &format!("{missing} is not installed (linux-libc-dev)"),
            required,
        )?;
        return Ok(None);
    }
    let directory = std::env::temp_dir().join(format!(
        "maki-nbd-header-probe-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&directory).map_err(|error| error.to_string())?;
    let source = directory.join("probe.c");
    let binary = directory.join("probe");
    let result = (|| {
        std::fs::write(&source, PROBE).map_err(|error| error.to_string())?;
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let compiled = match Command::new(&cc)
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
        {
            Ok(output) => output,
            Err(error) => {
                unavailable(
                    &format!("the C compiler {cc:?} cannot run ({error})"),
                    required,
                )?;
                return Ok(None);
            }
        };
        if !compiled.status.success() {
            return Err(format!(
                "the probe does not compile against the installed headers:\n{}",
                String::from_utf8_lossy(&compiled.stderr)
            ));
        }
        let output = Command::new(&binary)
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err("the probe failed".into());
        }
        let mut values = BTreeMap::new();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let (name, value) = line.split_once(' ').ok_or("malformed probe output")?;
            values.insert(name.to_string(), value.to_string());
        }
        Ok(Some(values))
    })();
    let _ = std::fs::remove_dir_all(&directory);
    result
}

#[test]
fn the_constants_match_the_installed_kernel_headers() {
    let Some(installed) = probe().unwrap_or_else(|error| panic!("{error}")) else {
        return;
    };
    for (name, value, always) in expected() {
        match installed.get(name) {
            Some(found) => assert_eq!(found, &value, "{name}"),
            None => assert!(!always, "{name} is missing from the probe"),
        }
    }
    for name in installed.keys() {
        assert!(
            expected().iter().any(|(known, _, _)| known == name),
            "{name} is probed but not compared"
        );
    }
}

#[test]
fn missing_headers_fail_only_when_they_are_required() {
    assert!(unavailable("a header is missing", false).is_ok());
    let error = unavailable("a header is missing", true).unwrap_err();
    assert!(
        error.contains(REQUIRE) && error.contains("a header is missing"),
        "{error}"
    );
}
