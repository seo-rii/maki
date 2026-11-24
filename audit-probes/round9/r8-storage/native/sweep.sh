#!/bin/bash
# usage: sweep.sh <name> <first-seed> <last-seed> [crash.py options...]
# One line per seed in logs/<name>.summary; full output of failing seeds in logs/<name>-<seed>.log
cd "$(dirname "$0")"
name=$1; first=$2; last=$3; shift 3
mkdir -p logs
for seed in $(seq $first $last); do
  out=logs/$name-$seed.log
  timeout 1200 /usr/bin/python3.12 ${SCRIPT:-crash.py} --seed $seed --quiet "$@" > $out 2>&1
  rc=$?
  echo "rc=$rc $(grep '^seed ' $out | tail -1)" >> logs/$name.summary
  if [ $rc -eq 0 ]; then rm -f $out; fi
done
echo "done" >> logs/$name.summary
