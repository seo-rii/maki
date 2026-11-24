#!/bin/bash
# Chain A: ported engine sweep harness (audit8_sweep_engine, release +
# debug-assertions), every test group, fresh seeds 8_000_000.., 45 s per
# (cfg, mode) pair, default workload shape (4 cycles, 6..40 ops).
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
B=$(cat $D/bin-da-maki-core-audit8_sweep_engine.path)
export AUDIT8_SEED_START=8000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=45 AUDIT_REPORT_LIMIT=20
for g in audit2_random audit2_recovery_chains audit2_targeted_sync audit2_cancel_sequential audit2_cancel_concurrent audit2_reclaim_gate audit2_damage_pairs audit2_round1_modes; do
  [ -e $D/STOP_CHAIN_A ] && break
  $D/run.sh A-se-$g "$B" $g --exact
done
