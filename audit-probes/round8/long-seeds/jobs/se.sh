#!/bin/bash
# usage: se.sh <name> <flavor rel|da> <test-group> <secs-per-pair> <seed-base> [VAR=VALUE ...]
# One group of the ported engine sweep harness on fresh seeds (base + ROUND*1e6).
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
name=$1; flavor=$2; group=$3; secs=$4; base=$5; shift 5
bin=$(cat $D/bin-$flavor-maki-core-audit8_sweep_engine.path)
start=$(( base + ${ROUND:-0} * 1000000 ))
log=$D/logs/q2-se-$name.r${ROUND:-0}.log
t0=$(date -u +%FT%TZ)
( cd /home/user/wt/audit8/crates/maki-core && env RUST_BACKTRACE=0 AUDIT8_SEED_START=$start AUDIT8_SEED_COUNT=1000000 \
    AUDIT_BUDGET_SECS=$secs AUDIT_REPORT_LIMIT=20 "$@" nice -n 15 "$bin" $group --exact --test-threads=1 --nocapture > $log 2>&1 )
rc=$?
pairs=$(grep -a -c "AUDIT-SWEEP" $log)
seeds=$(grep -a -o "run=[0-9]*" $log | cut -d= -f2 | paste -sd+ | bc)
echo "$t0 round=${ROUND:-0} se=$name flavor=$flavor group=$group seeds_from=$start rc=$rc pairs=$pairs seeds_run=$seeds fails=$(grep -a -c 'AUDIT-FAIL' $log)" >> $D/logs/q2-summary.log
grep -a "AUDIT-FAIL" $log | sed "s/^/se $name r${ROUND:-0} /" >> $D/logs/q2-failures.log
if [ $rc -ne 0 ]; then cp $log $D/fail/se-$name-r${ROUND:-0}.log; fi
