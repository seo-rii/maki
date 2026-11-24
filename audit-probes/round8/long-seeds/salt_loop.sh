#!/bin/bash
# usage: salt_loop.sh <crate> <mode: default|gates> <budget-secs>
# Runs the crate's audit8_salted binary (da flavor), one module per process,
# for successive AUDIT8_SALT values (continuing where the last call stopped)
# until the budget is used. Per-(salt, module) results: logs/salted-<crate>-<mode>.tsv;
# failing outputs: fail/salted/<crate>-<module>-salt<N>.log
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
crate=$1; mode=$2; budget=$3
bin=$(cat $D/bin-da-$crate-audit8_salted.path 2>/dev/null)
[ -x "$bin" ] || { echo "no binary for $crate"; exit 2; }
cd /home/user/wt/audit8/crates/$crate || exit 2
mods=$(grep -E '^mod ' tests/audit8_salted.rs | sed -E 's/mod ([a-z0-9_]+);/\1/')
flag=""
if [ "$mode" = gates ]; then
  flag="--ignored"
  mods=$(for m in $mods; do grep -q '#\[ignore' tests/audit8_salted/$m.rs && echo $m; done)
fi
state=$D/salt-$crate-$mode.next
salt=$(cat $state 2>/dev/null || echo 1)
mkdir -p $D/fail/salted
end=$(( $(date +%s) + budget ))
export RUST_BACKTRACE=0
while [ $(date +%s) -lt $end ] && [ ! -e $D/STOP_SALT ]; do
  for m in $mods; do
    [ $(date +%s) -lt $end ] || break 2
    s=$(date +%s)
    out=$(AUDIT8_SALT=$salt nice -n 15 "$bin" "$m::" --test-threads=1 $flag 2>&1)
    rc=$?
    res=$(echo "$out" | grep -a -E "^test result" | tail -1 | cut -c1-120)
    printf "%s\t%s\t%s\t%s\t%ss\trc=%s\t%s\n" "$(date -u +%T)" "$crate" "$salt" "$m" "$(( $(date +%s) - s ))" "$rc" "$res" >> $D/logs/salted-$crate-$mode.tsv
    if [ $rc -ne 0 ]; then
      echo "$out" > $D/fail/salted/$crate-$m-salt$salt.log
      echo "$out" | grep -a -E "^test .* FAILED|panicked at" | head -20 | sed "s/^/$crate salt=$salt /" >> $D/logs/salted-failures.log
    fi
  done
  salt=$((salt+1)); echo $salt > $state
done
