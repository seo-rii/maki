#!/bin/bash
# Round-8 fuzz rotation: one libFuzzer process at a time, niced, forever
# (until $D/STOP_FUZZ exists). Corpora persist under corpora/<target>,
# crashes under artifacts/<target>/, per-slice summaries in logs/fuzz-summary.log.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
FB=/home/user/tgt/audit8-release/fuzz/x86_64-unknown-linux-gnu/release
export RUST_BACKTRACE=1
round=0
while [ ! -e $D/STOP_FUZZ ]; do
  round=$((round+1))
  # target:seconds:max_len
  for spec in $(cat $D/fuzz-targets.txt); do
    [ -e $D/STOP_FUZZ ] && break
    t=${spec%%:*}; rest=${spec#*:}; secs=${rest%%:*}; maxlen=${rest#*:}
    [ -x $FB/$t ] || continue
    mkdir -p $D/corpora/$t $D/artifacts/$t $D/seeds/$t
    vp=$(( round % 2 ))
    cd $D/artifacts/$t
    start=$(date -u +%FT%TZ)
    nice -n 15 $FB/$t $D/corpora/$t $D/seeds/$t -max_total_time=$secs -timeout=120 -rss_limit_mb=4096 \
        -max_len=$maxlen -use_value_profile=$vp -artifact_prefix=$D/artifacts/$t/ -print_final_stats=1 \
        > $D/logs/fuzz-$t.last.log 2>&1
    rc=$?
    execs=$(grep -a "stat::number_of_executed_units" $D/logs/fuzz-$t.last.log | awk '{print $2}')
    cov=$(grep -a -E "^#[0-9]+" $D/logs/fuzz-$t.last.log | tail -1 | sed -E 's/.*cov: ([0-9]+) ft: ([0-9]+) corp: ([0-9]+).*/cov=\1 ft=\2 corp=\3/')
    echo "$start round=$round target=$t secs=$secs vp=$vp rc=$rc execs=$execs $cov" >> $D/logs/fuzz-summary.log
    if [ $rc -ne 0 ]; then
      cp $D/logs/fuzz-$t.last.log $D/logs/fuzz-$t.crash-round$round.log
    fi
  done
done
echo "$(date -u +%FT%TZ) rotation stopped" >> $D/logs/fuzz-summary.log
