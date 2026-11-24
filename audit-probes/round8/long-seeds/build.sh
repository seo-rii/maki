#!/bin/bash
# usage: build.sh <flavor: rel|da> <crate> <test-target>
# Builds one integration-test binary (release, no debuginfo) and prints its path.
#  rel = plain release;  da = release + debug-assertions + overflow-checks
#        (the product's own check_invariants() sanitizer stays on).
set -u
flavor=$1; crate=$2; test=$3
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
export RUST_BACKTRACE=0 CARGO_PROFILE_RELEASE_DEBUG=0
case $flavor in
  rel) export CARGO_TARGET_DIR=/home/user/tgt/audit8-release ;;
  da)  export CARGO_TARGET_DIR=/home/user/tgt/audit8-release/da
       export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true ;;
  *) echo "bad flavor"; exit 2 ;;
esac
cd /home/user/wt/audit8 || exit 2
log=$D/logs/build-$flavor-$crate-$test.log
nice -n 15 cargo test -p "$crate" --release --locked -j ${BUILD_JOBS:-1} --test "$test" --no-run --message-format=json-render-diagnostics 2> "$log" \
  | python3 -c '
import sys, json
exe = None
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("target", {}).get("name") == sys.argv[1]:
        exe = m["executable"]
print(exe or "BUILD-FAILED")
' "$test" > "$D/bin-$flavor-$crate-$test.path"
cat "$D/bin-$flavor-$crate-$test.path"
grep -E "^(error|warning: unused)" "$log" | sort | uniq -c | head -20
tail -3 "$log"
