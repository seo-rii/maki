#!/bin/bash
# Round-8 queue 2: one job at a time, forever (until $D/STOP_Q2 exists).
# jobs file ($D/q2-jobs.txt) is re-read every round; lines:
#   fuzz  <target> <secs> <max_len>
#   sweep <log-name> <crate-dir> <bin-path-file> <test-name> <budget-secs> <seed-base> [VAR=VALUE ...]
# A sweep's seed range starts at seed-base + round * 1_000_000.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
FB=/home/user/tgt/audit8-release/fuzz/x86_64-unknown-linux-gnu/release
round=$(cat $D/q2.round 2>/dev/null || echo 0)
while [ ! -e $D/STOP_Q2 ]; do
  round=$((round+1)); echo $round > $D/q2.round
  mapfile -t jobs < $D/q2-jobs.txt
  for job in "${jobs[@]}"; do
    [ -e $D/STOP_Q2 ] && break
    set -- $job
    kind=$1
    case "$kind" in
      fuzz)
        t=$2; secs=$3; maxlen=$4
        [ -x $FB/$t ] || continue
        mkdir -p $D/corpora/$t $D/artifacts/$t $D/seeds/$t
        vp=$(( round % 2 ))
        start=$(date -u +%FT%TZ)
        ( cd $D/artifacts/$t && RUST_BACKTRACE=1 nice -n 15 $FB/$t $D/corpora/$t $D/seeds/$t -max_total_time=$secs -timeout=120 \
            -rss_limit_mb=4096 -max_len=$maxlen -use_value_profile=$vp -artifact_prefix=$D/artifacts/$t/ \
            -print_final_stats=1 > $D/logs/fuzz-$t.last.log 2>&1 )
        rc=$?
        execs=$(grep -a "stat::number_of_executed_units" $D/logs/fuzz-$t.last.log | awk '{print $2}')
        cov=$(grep -a -E "^#[0-9]+" $D/logs/fuzz-$t.last.log | tail -1 | sed -E 's/.*cov: ([0-9]+) ft: ([0-9]+) corp: ([0-9]+).*/cov=\1 ft=\2 corp=\3/')
        echo "$start round=$round target=$t secs=$secs vp=$vp rc=$rc execs=$execs $cov" >> $D/logs/fuzz-summary.log
        [ $rc -ne 0 ] && cp $D/logs/fuzz-$t.last.log $D/logs/fuzz-$t.crash-round$round.log
        ;;
      salt)
        crate=$2; mode=$3; budget=$4
        start=$(date -u +%FT%TZ)
        before=$(cat $D/salt-$crate-$mode.next 2>/dev/null || echo 1)
        $D/salt_loop.sh $crate $mode $budget >> $D/logs/q2.out 2>&1
        echo "$start round=$round salt crate=$crate mode=$mode salts=$before..$(cat $D/salt-$crate-$mode.next 2>/dev/null) failures_so_far=$(grep -c . $D/logs/salted-failures.log 2>/dev/null)" >> $D/logs/q2-summary.log
        ;;
      sweep)
        name=$2; dir=$3; binfile=$4; test=$5; budget=$6; base=$7; shift 7
        bin=$(cat $D/$binfile 2>/dev/null)
        [ -x "$bin" ] || { echo "$(date -u +%FT%TZ) round=$round sweep $name: no binary" >> $D/logs/q2-summary.log; continue; }
        start=$(date -u +%FT%TZ)
        log=$D/logs/q2-$name.r$round.log
        ( cd $dir && env RUST_BACKTRACE=0 AUDIT8_SEED_START=$((base + round * 1000000)) AUDIT8_SEED_COUNT=100000000 \
            AUDIT8_BUDGET_SECS=$budget AUDIT8_FAIL_DIR=$D/fail/$name "$@" \
            nice -n 15 "$bin" $test --exact --test-threads=1 --nocapture > $log 2>&1 )
        rc=$?
        echo "$start round=$round sweep=$name rc=$rc $(grep -a -E 'AUDIT8-SWEEP|AUDIT-SWEEP' $log | tail -1 | cut -c1-900)" >> $D/logs/q2-summary.log
        grep -a "AUDIT8-FAIL" $log | head -50 >> $D/logs/q2-failures.log
        ;;
      *)
        # any other kind is a script under jobs/: jobs/<kind>.sh <args...> (ROUND exported)
        if [ -x "$D/jobs/$kind.sh" ]; then
          shift
          ROUND=$round "$D/jobs/$kind.sh" "$@" >> $D/logs/q2.out 2>&1
        fi
        ;;
    esac
  done
done
echo "$(date -u +%FT%TZ) q2 stopped" >> $D/logs/q2-summary.log
