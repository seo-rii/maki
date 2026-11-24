#!/bin/bash
# exits when the shard damage sweep finished, or after 30 minutes
cd "$(dirname "$0")"
for i in $(seq 1 180); do
  if grep -q "^exit" sweep-shard-damage1.log 2>/dev/null; then break; fi
  sleep 10
done
grep -E "AUDIT-SWEEP|AUDIT-FAIL" sweep-shard-damage1.log | sed -E 's/ \| .*//' | cut -c1-300
