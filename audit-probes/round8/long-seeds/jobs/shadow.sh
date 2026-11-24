#!/bin/bash
# usage: shadow.sh <name> <crate> <test-filter> <seeds-per-round> <seed-base> [VAR=VALUE ...]
# Runs an inline (crate-private) sweep of the shadow workspace on a fresh seed
# range: base + ROUND * seeds-per-round.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
name=$1; crate=$2; filter=$3; count=$4; base=$5; shift 5
bin=$(cat $D/bin-shadow-$crate.path)
start=$(( base + ${ROUND:-0} * count ))
log=$D/logs/q2-shadow-$name.r${ROUND:-0}.log
t0=$(date -u +%FT%TZ)
( cd $D/shadow/ws/crates/$crate && env RUST_BACKTRACE=0 AUDIT8_SEED_START=$start AUDIT8_SEED_COUNT=$count "$@" \
    nice -n 15 "$bin" "$filter" --test-threads=1 --nocapture > $log 2>&1 )
rc=$?
echo "$t0 round=${ROUND:-0} shadow=$name seeds=$start..$((start+count)) rc=$rc $(grep -a -E '^AUDIT8|test result' $log | tr '\n' ' ' | cut -c1-600)" >> $D/logs/q2-summary.log
if [ $rc -ne 0 ]; then
  cp $log $D/fail/shadow-$name-seeds$start.log
  echo "shadow $name seeds=$start..$((start+count)) FAILED (fail/shadow-$name-seeds$start.log)" >> $D/logs/q2-failures.log
fi
