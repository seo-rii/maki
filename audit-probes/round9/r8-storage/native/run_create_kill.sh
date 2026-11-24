#!/bin/bash
# Round 9: the create_kill.py matrix; one log per run in logs/.
cd "$(dirname "$0")"
run() { name=$(echo "$*" | tr ' ' '_' | tr -d '-'); timeout 5400 python3 create_kill.py "$@" > "logs/ck-$name.log" 2>&1; echo "$* -> exit $? : $(tail -1 logs/ck-$name.log)" >> logs/ck-summary.txt; }
run local kill --mid
run local kill --discard
run plain kill --mid --discard
run local EIO
run local ENOSPC --mid
run plain EIO
run plain ENOSPC --discard
run local kill --second capacity
run local kill --second discard
run local kill --second shard --mid
run plain kill --second discard
