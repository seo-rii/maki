#!/bin/bash
# usage: sweep.sh <name> <first> <last> <transport> [chaos.py options]
name=$1; first=$2; last=$3; t=$4; shift 4
cd "$(dirname "$0")"
for seed in $(seq $first $last); do
  out=$(setsid timeout 600 python3.12 chaos.py $t --seed $seed "$@" 2>&1 | grep -v Deprecat)
  echo "$out" | head -1 >> logs/$name.summary
  if ! echo "$out" | head -1 | grep -q "^ok "; then echo "$out" > logs/$name.seed$seed.txt; fi
done
echo "sweep $name done" >> logs/$name.summary
