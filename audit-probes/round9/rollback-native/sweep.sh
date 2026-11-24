#!/bin/bash
# usage: [SCRIPT=rpl.py] ./sweep.sh <name> <first> <last> [options]; one line per seed in logs/<name>.summary
cd "$(dirname "$0")"
name=$1; first=$2; last=$3; shift 3
script=${SCRIPT:-rpl.py}
for seed in $(seq "$first" "$last"); do
  out=logs/$name-$seed.out
  timeout ${SEED_TIMEOUT:-1800} python3.12 "$script" --seed "$seed" --quiet "$@" > "$out" 2>&1
  rc=$?
  line=$(grep -E "^seed $seed " "$out" | tail -1)
  echo "rc=$rc ${line:-seed $seed NO SUMMARY}" >> logs/$name.summary
  if [ $rc -eq 0 ]; then rm -f "$out"; fi
done
echo "sweep $name done" >> logs/$name.summary
