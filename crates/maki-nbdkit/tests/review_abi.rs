//! F08 (third review): the nbdkit C ABI the shim mirrors by hand is checked
//! against the *installed* header, not against comments. A C probe is
//! compiled with the distribution's `nbdkit-plugin.h` at API version 2 and
//! prints every constant and field offset the shim depends on; they must
//! equal what `maki_nbdkit::plugin::abi_layout` reports. Skips (loudly)
//! when the header or a C compiler is missing; CI's nightly job installs
//! `nbdkit-plugin-dev` so it runs there.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::process::Command;

const PROBE: &str = r#"
#define NBDKIT_API_VERSION 2
#include <nbdkit-plugin.h>
#include <stddef.h>
#include <stdio.h>
#define OFF(f) printf("%s %zu\n", #f, offsetof(struct nbdkit_plugin, f))
int main(void) {
  printf("NBDKIT_API_VERSION %d\n", NBDKIT_API_VERSION);
  printf("NBDKIT_THREAD_MODEL_PARALLEL %d\n", NBDKIT_THREAD_MODEL_PARALLEL);
  printf("NBDKIT_FUA_NONE %d\n", NBDKIT_FUA_NONE);
  printf("NBDKIT_FUA_EMULATE %d\n", NBDKIT_FUA_EMULATE);
  printf("NBDKIT_FUA_NATIVE %d\n", NBDKIT_FUA_NATIVE);
  printf("NBDKIT_FLAG_FUA %d\n", NBDKIT_FLAG_FUA);
  OFF(_struct_size); OFF(_api_version); OFF(_thread_model);
  OFF(name); OFF(longname); OFF(version); OFF(description);
  OFF(load); OFF(unload); OFF(config); OFF(config_complete); OFF(config_help);
  OFF(open); OFF(close); OFF(get_size);
  OFF(can_write); OFF(can_flush); OFF(is_rotational); OFF(can_trim);
  OFF(_pread_v1); OFF(_pwrite_v1); OFF(_flush_v1); OFF(_trim_v1); OFF(_zero_v1);
  OFF(errno_is_preserved); OFF(dump_plugin); OFF(can_zero); OFF(can_fua);
  OFF(pread); OFF(pwrite); OFF(flush); OFF(trim); OFF(zero);
  printf("sizeof_full %zu\n", sizeof(struct nbdkit_plugin));
  return 0;
}
"#;

fn probe_header() -> Option<BTreeMap<String, usize>> {
    if !std::path::Path::new("/usr/include/nbdkit-plugin.h").exists() {
        eprintln!("nbdkit-plugin.h not installed; ABI probe skipped");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("probe.c");
    let bin = dir.path().join("probe");
    std::fs::write(&src, PROBE).unwrap();
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let compiled = match Command::new(&cc).arg(&src).arg("-o").arg(&bin).output() {
        Ok(out) => out,
        Err(e) => {
            eprintln!("{cc} unavailable ({e}); ABI probe skipped");
            return None;
        }
    };
    assert!(
        compiled.status.success(),
        "probe failed to compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let out = Command::new(&bin).output().unwrap();
    assert!(out.status.success());
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let (k, v) = line.split_once(' ').unwrap();
        map.insert(k.to_string(), v.parse::<usize>().unwrap());
    }
    Some(map)
}

#[test]
fn shim_constants_and_layout_match_the_installed_header() {
    let Some(header) = probe_header() else {
        return;
    };
    let mut mismatches = Vec::new();
    for (name, ours) in maki_nbdkit::plugin::abi_layout() {
        if name == "sizeof_prefix" {
            continue;
        }
        match header.get(name) {
            Some(theirs) if *theirs == ours => {}
            Some(theirs) => mismatches.push(format!("{name}: shim {ours}, header {theirs}")),
            None => mismatches.push(format!("{name}: not in the header probe")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "ABI mismatch:\n{}",
        mismatches.join("\n")
    );
    let prefix = maki_nbdkit::plugin::abi_layout()
        .into_iter()
        .find(|(k, _)| *k == "sizeof_prefix")
        .unwrap()
        .1;
    assert!(
        header["sizeof_full"] >= prefix,
        "declared prefix {prefix} exceeds the header's struct ({})",
        header["sizeof_full"]
    );
    assert_eq!(
        maki_nbdkit::plugin::can_fua_value() as usize,
        header["NBDKIT_FUA_NATIVE"],
        "can_fua must answer NBDKIT_FUA_NATIVE"
    );
}
