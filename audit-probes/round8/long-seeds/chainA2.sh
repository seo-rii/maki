#!/bin/bash
# Chain A2 (runs after chain A on the same thread): the other ported engine
# harnesses with fresh seeds 9_000_000...
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
while pgrep -f chainA.sh > /dev/null; do sleep 20; done
FC=$(cat $D/bin-da-maki-core-audit8_flush_crash.path)
LN=$(cat $D/bin-da-maki-core-audit8_linearizable.path)
RI=$(cat $D/bin-da-maki-core-audit8_recovery_interrupt.path)
export AUDIT8_WORKERS=2
AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=20000 $D/run.sh A2-recovery_interrupt "$RI" ""
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=40000 $D/run.sh A2-flush_crash "$FC" acknowledged_durable_requests_survive_power_loss_under_overlap --exact
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT8_SEED_START=9000000 AUDIT8_SEED_COUNT=8000 $D/run.sh A2-linearizable "$LN" overlapping_concurrent_requests_are_linearizable --exact
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT4_EXTREME=1 AUDIT8_SEED_START=9500000 AUDIT8_SEED_COUNT=6000 $D/run.sh A2-flush_crash-extreme "$FC" acknowledged_durable_requests_survive_power_loss_under_overlap --exact
[ -e $D/STOP_CHAIN_A ] && exit
AUDIT4_EXTREME=1 AUDIT8_SEED_START=9500000 AUDIT8_SEED_COUNT=3000 $D/run.sh A2-linearizable-extreme "$LN" overlapping_concurrent_requests_are_linearizable --exact
