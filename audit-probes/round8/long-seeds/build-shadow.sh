#!/bin/bash
# usage: build-shadow.sh <crate>   -> builds the crate's --lib unit tests from the shadow workspace (da flavor)
set -u
crate=$1
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
export RUST_BACKTRACE=0 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_TARGET_DIR=/home/user/tgt/audit8-release/shadow
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true
cd $D/shadow/ws || exit 2
log=$D/logs/build-shadow-$crate.log
nice -n 15 cargo test -p "$crate" --release --locked -j ${BUILD_JOBS:-1} --lib --no-run --message-format=json-render-diagnostics 2> "$log" \
  | python3 -c '
import sys, json
exe = None
for line in sys.stdin:
    try:
        m = json.loads(line)
    except Exception:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m.get("profile", {}).get("test"):
        exe = m["executable"]
print(exe or "BUILD-FAILED")
' > "$D/bin-shadow-$crate.path"
cat "$D/bin-shadow-$crate.path"
grep -E "^error" -A 14 "$log" | head -60
tail -2 "$log"
