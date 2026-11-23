#!/bin/bash
S=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness
cd $S
PKGS="maki-nbdkit maki-privileged maki-control maki-witness maki-witness-cli maki maki-attach maki-check maki-crypto maki-test-support maki-cache maki-format maki-crypto-local maki-crypto-http maki-crypto-websocket maki-crypto-grpc maki-benchmark maki-core"
for cond in "$@"; do
  case $cond in
    base) args="";;
    u002) args="--umask 002";;
    u077) args="--umask 077";;
    nobody) args="--uid 65534";;
    t16a|t16b|t16c) args="--threads 16";;
  esac
  for p in $PKGS; do
    [ "$cond" = base -o "$cond" = nobody -o "$cond" = u002 -o "$cond" = u077 ] || true
    python3 run.py $p $cond $args >> $S/logs/matrix-$cond.out 2>&1
  done
  echo "DONE $cond $(date +%T)" >> $S/logs/matrix.progress
done
