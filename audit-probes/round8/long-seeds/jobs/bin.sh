#!/bin/bash
# usage: bin.sh <name> <crate> <bin-path-file> <test-filter|-> <seeds-per-round> <seed-base> [VAR=VALUE ...]
# Runs a worktree test binary with AUDIT8_SEED_START = base + ROUND*seeds, AUDIT8_SEED_COUNT = seeds.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
name=$1; crate=$2; binfile=$3; filter=$4; count=$5; base=$6; shift 6
[ "$filter" = "-" ] && filter=""
bin=$(cat $D/$binfile)
start=$(( base + ${ROUND:-0} * count ))
log=$D/logs/q2-bin-$name.r${ROUND:-0}.log
t0=$(date -u +%FT%TZ)
( cd /home/user/wt/audit8/crates/$crate && env RUST_BACKTRACE=0 AUDIT8_SEED_START=$start AUDIT8_SEED_COUNT=$count "$@" \
    nice -n 15 "$bin" $filter --test-threads=1 --nocapture > $log 2>&1 )
rc=$?
echo "$t0 round=${ROUND:-0} bin=$name seeds=$start..$((start+count)) rc=$rc $(grep -a -E '^test result' $log | tr '\n' ' ' | cut -c1-300)" >> $D/logs/q2-summary.log
if [ $rc -ne 0 ]; then
  cp $log $D/fail/bin-$name-seeds$start.log
  echo "bin $name seeds=$start..$((start+count)) FAILED (fail/bin-$name-seeds$start.log): $(grep -a -E 'panicked|assertion' $log | head -3 | tr '\n' ' ' | cut -c1-400)" >> $D/logs/q2-failures.log
fi
