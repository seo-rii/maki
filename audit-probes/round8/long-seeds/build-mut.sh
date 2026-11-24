#!/bin/bash
# Builds a test target of the MUTATION shadow (worktree copy + scratchpad/ss4/mutations.patch,
# planted bugs gated by MAKI_MUT=<name>), da flavor.  usage: build-mut.sh <crate> <test>
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
crate=$1; test=$2
export RUST_BACKTRACE=0 CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_TARGET_DIR=/home/user/tgt/audit8-release/mut
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=true
cd $D/shadow/mut || exit 2
log=$D/logs/build-mut-$crate-$test.log
nice -n 15 cargo test -p "$crate" --release --locked -j 1 --test "$test" --no-run --message-format=json-render-diagnostics 2> "$log" \
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
' "$test" > "$D/bin-mut-$crate-$test.path"
cat "$D/bin-mut-$crate-$test.path"; grep -E "^error" -A 12 "$log" | head -40; tail -1 "$log"
