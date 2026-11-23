#!/bin/bash
S=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness
cd $S
until grep -q 'DONE u077' $S/logs/matrix.progress 2>/dev/null; do sleep 10; done
PKGS="maki-backing maki-nbdkit maki-privileged maki-control maki-witness maki-witness-cli maki maki-attach maki-check maki-crypto maki-test-support maki-cache maki-format maki-crypto-local maki-crypto-http maki-crypto-websocket maki-crypto-grpc maki-benchmark maki-core"
for cond in "$@"; do
  case $cond in
    base2) args="";;
    nobody2) args="--uid 65534";;
    nobody002) args="--uid 65534 --umask 002";;
    t16a|t16b|t16c) args="--threads 16";;
    t1) args="--threads 1";;
  esac
  for p in $PKGS; do
    python3 run.py $p $cond $args >> $S/logs/matrix-$cond.out 2>&1
  done
  echo "DONE $cond $(date +%T)" >> $S/logs/matrix.progress
done
