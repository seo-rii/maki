#!/bin/bash
cd /home/user/wt/audit5/crates/maki-core
export TMPDIR=${TMPDIR_OVERRIDE:-/home/user/tgt/audit5-tr-tmp/fprace} RUST_BACKTRACE=0 CARGO_MANIFEST_DIR=/home/user/wt/audit5/crates/maki-core
mkdir -p "$TMPDIR"; fails=0
for i in $(seq 1 $1); do
  out=$(/home/user/tgt/audit5/debug/deps/review_storage-8ffcd39b98272bbd --test-threads=16 recovery_rejects_oversized_segment_before_allocation failed_append_after_roll_still_promotes_durable_versions failed_seal_sync_does_not_lose_active_segment_durability failed_fua_sync_still_publishes_the_journaled_record 2>&1)
  if [ $? -ne 0 ]; then fails=$((fails+1)); echo "$out" > /tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness/logs/fprace/fail-$i.log; fi
done
echo "fprace runs=$1 fails=$fails" >> /tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness/logs/fprace/result.txt
