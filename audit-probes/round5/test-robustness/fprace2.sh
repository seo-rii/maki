#!/bin/bash
cd /home/user/wt/audit5/crates/maki-core
export TMPDIR=${TMPDIR_OVERRIDE:-/home/user/tgt/audit5-tr-tmp/fprace} RUST_BACKTRACE=0 CARGO_MANIFEST_DIR=/home/user/wt/audit5/crates/maki-core
mkdir -p /tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness/logs/fprace2; fails=0
for i in $(seq 1 $1); do
  out=$(/home/user/tgt/audit5/debug/deps/review_audit-377def3c10b5b830 --test-threads=16 short_plaintext_is_a_contract_error_not_a_panic idle_checkpoint_reclaims_covered_segments_left_by_a_failed_deletion adopted_shard_is_never_cataloged_without_an_allocation_copy 2>&1)
  if [ $? -ne 0 ]; then fails=$((fails+1)); echo "$out" > /tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness/logs/fprace2/fail-$i.log; fi
done
echo "fprace2 runs=$1 fails=$fails" >> /tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness/logs/fprace2/result.txt
