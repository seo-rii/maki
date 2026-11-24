#!/bin/bash
# Chain A3 (after A and A2, same thread): remaining ported harnesses, fresh seeds.
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
while pgrep -f "chainA.sh|chainA2.sh" > /dev/null; do sleep 20; done
b() { cat $D/bin-da-maki-core-audit8_$1.path; }
export AUDIT8_WORKERS=2
for seed in $(seq 100 139); do
  [ -e $D/STOP_CHAIN_A ] && exit
  AUDIT8_SEED_START=$seed AUDIT8_SEED_COUNT=5000 $D/run.sh A3-metadata_mutation-$seed "$(b metadata_mutation)" crc_valid_metadata_mutations_check_and_recovery_agree --exact
done
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=20000 $D/run.sh A3-covered_slot_crash "$(b covered_slot_crash)" ""
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=420 $D/run.sh A3-rollback_namespace_model "$(b rollback_namespace_model)" ""
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=600 AUDIT_CYCLES=8 $D/run.sh A3-sweep_rollback "$(b sweep_rollback)" ""
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=11000000 AUDIT8_SEED_COUNT=6000 $D/run.sh A3-linearizable_prefix "$(b linearizable_prefix)" ""
[ -e $D/STOP_CHAIN_A ] && exit
SE=$(cat $D/bin-da-maki-core-audit8_sweep_engine.path)
AUDIT8_SEED_START=12100000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=60 AUDIT_REPORT_LIMIT=20 $D/run.sh A3-se-r8_geometry "$SE" audit8_r8_geometry --exact
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=12500000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=60 AUDIT_CYCLES=6 AUDIT_OPS_LO=15 AUDIT_OPS_HI=70 AUDIT_REPORT_LIMIT=20 $D/run.sh A3-se-r8_geometry-long "$SE" audit8_r8_geometry --exact
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=13000000 AUDIT8_SEED_COUNT=1000000 AUDIT_BUDGET_SECS=40 AUDIT_CYCLES=6 AUDIT_OPS_LO=15 AUDIT_OPS_HI=70 AUDIT_REPORT_LIMIT=20 $D/run.sh A3-se-random-long "$SE" audit2_random --exact
