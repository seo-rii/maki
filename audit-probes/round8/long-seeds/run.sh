#!/bin/bash
# usage: run.sh <log-name> <test-binary> <test-filter-or-empty> [extra libtest args...]
# Environment is passed through. Runs niced, single libtest thread, logs under logs/.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
name=$1; bin=$2; filter=$3; shift 3
export RUST_BACKTRACE=0
cd /home/user/wt/audit8/crates/maki-core
{
  echo "### $(date -u +%FT%TZ) start $name: $bin $filter $* env: $(env | grep -E '^(AUDIT|MAKI)' | tr '\n' ' ')"
  time nice -n 15 "$bin" $filter --test-threads=1 --nocapture "$@"
  echo "### $(date -u +%FT%TZ) exit $? $name"
} > "$D/logs/$name.log" 2>&1
