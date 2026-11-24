#!/bin/bash
# Chain B (replaces the queued A2/A3 after chain A's reclaim_gate group): one job at a time on
# thread 1, most distinctive first. Stops before the next job when $D/STOP_CHAIN_B exists.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
while pgrep -f "audit8_sweep_engine.* audit2_reclaim_gate" > /dev/null; do sleep 10; done
b() { cat $D/bin-da-maki-core-audit8_$1.path; }
SE=$(b sweep_engine)
export AUDIT8_WORKERS=2 AUDIT_REPORT_LIMIT=20
step() { [ -e $D/STOP_CHAIN_B ] && exit 0; "$@"; }
step env AUDIT8_SEED_START=12100000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=40 $D/run.sh B-se-r8_geometry "$SE" audit8_r8_geometry --exact
step env AUDIT8_SEED_START=8000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=45 $D/run.sh B-se-damage_pairs "$SE" audit2_damage_pairs --exact
step env AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=300 AUDIT_CYCLES=8 $D/run.sh B-sweep_rollback "$(b sweep_rollback)" ""
step env AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=200 $D/run.sh B-rollback_namespace_model "$(b rollback_namespace_model)" ""
step env AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=8000 $D/run.sh B-recovery_interrupt "$(b recovery_interrupt)" ""
step env AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=10000 $D/run.sh B-flush_crash "$(b flush_crash)" acknowledged_durable_requests_survive_power_loss_under_overlap --exact
step env AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=4000 $D/run.sh B-linearizable "$(b linearizable)" overlapping_concurrent_requests_are_linearizable --exact
for seed in $(seq 100 119); do
  step env AUDIT8_SEED_START=$seed AUDIT8_SEED_COUNT=5000 $D/run.sh B-metadata_mutation-$seed "$(b metadata_mutation)" crc_valid_metadata_mutations_check_and_recovery_agree --exact
done
step env AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=8000 $D/run.sh B-covered_slot_crash "$(b covered_slot_crash)" ""
step env AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=3000 $D/run.sh B-linearizable_prefix "$(b linearizable_prefix)" ""
step env AUDIT8_SEED_START=12500000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=40 AUDIT_CYCLES=6 AUDIT_OPS_LO=15 AUDIT_OPS_HI=70 $D/run.sh B-se-r8_geometry-long "$SE" audit8_r8_geometry --exact
step env AUDIT4_EXTREME=1 AUDIT8_SEED_START=9500000 AUDIT8_SEED_COUNT=4000 $D/run.sh B-flush_crash-extreme "$(b flush_crash)" acknowledged_durable_requests_survive_power_loss_under_overlap --exact
step env AUDIT4_EXTREME=1 AUDIT8_SEED_START=9500000 AUDIT8_SEED_COUNT=2000 $D/run.sh B-linearizable-extreme "$(b linearizable)" overlapping_concurrent_requests_are_linearizable --exact
step env AUDIT8_SEED_START=13000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=40 AUDIT_CYCLES=6 AUDIT_OPS_LO=15 AUDIT_OPS_HI=70 $D/run.sh B-se-random-long "$SE" audit2_random --exact
step env AUDIT8_SEED_START=8000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=30 $D/run.sh B-se-round1_modes "$SE" audit2_round1_modes --exact
