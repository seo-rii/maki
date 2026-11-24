#!/bin/bash
# usage: mutmatrix.sh   (once: skips if results exist)
# Oracle validation: every planted bug of scratchpad/ss4/mutations.patch (MAKI_MUT=<name>) against
#   A = the committed r3b profile at its committed seed count, no faults (seeds 0..120 x 4 cycles)
#   B = the committed profile with 150 permille sync faults (seeds 0..80)
#   C = the widened sequential sweep (random profile, 250 seeds)
#   D = the widened concurrent sweep (random profile, 100 seeds)
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
out=$D/logs/mutmatrix.tsv
[ -e $out.done ] && exit 0
bin=$(cat $D/bin-mut-maki-core-audit8_r3b_seeds.path 2>/dev/null)
[ -x "$bin" ] || { echo "mutmatrix: no mutant binary yet" >> $D/logs/q2-summary.log; exit 0; }
cd $D/shadow/mut/crates/maki-core
run() { # mutation label test env...
  mutation=$1; label=$2; test=$3; shift 3
  r=$(env RUST_BACKTRACE=0 MAKI_MUT=$mutation "$@" nice -n 15 timeout 900 "$bin" $test --exact --test-threads=1 --nocapture 2>&1 | grep -a -E "AUDIT8-SWEEP|test result" | tr '\n' ' ')
  fails=$(echo "$r" | grep -o "failures=[0-9]*" | head -1 | cut -d= -f2)
  seeds=$(echo "$r" | grep -o " seeds=[0-9]* " | head -1 | tr -d ' ' | cut -d= -f2)
  printf "%s\t%s\tfailing_seeds=%s\tof=%s\n" "$mutation" "$label" "${fails:-?}" "${seeds:-?}" >> $out
}
for m in none flush_nosync fua_nosync ckpt_skip_volatile ckpt_nondurable cache_stale buf_noclear recovery_nosync journal_norewrite ab_nopreserve overlay_unbounded; do
  run $m A-committed-nofault audit8_r3b_seq AUDIT8_PROFILE=committed AUDIT8_FAULTS=0 AUDIT8_CYCLES=4 AUDIT8_SEED_START=0 AUDIT8_SEED_COUNT=120
  run $m B-committed-faults audit8_r3b_seq AUDIT8_PROFILE=committed AUDIT8_FAULTS=150 AUDIT8_CYCLES=4 AUDIT8_SEED_START=0 AUDIT8_SEED_COUNT=80
  run $m C-widened-seq audit8_r3b_seq AUDIT8_SEED_START=900000 AUDIT8_SEED_COUNT=250
  run $m D-widened-concurrent audit8_r3b_concurrent AUDIT8_SEED_START=900000 AUDIT8_SEED_COUNT=100
done
touch $out.done
echo "$(date -u +%FT%TZ) mutmatrix done: $(wc -l < $out) rows" >> $D/logs/q2-summary.log
