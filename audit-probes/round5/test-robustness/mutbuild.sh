#!/bin/bash
# usage: mutbuild.sh <label> <cargo test selection args...>   (private copy, private target)
S=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness
label=$1; shift
cd /home/user/tgt/audit5-tr-mut/src
export CARGO_TARGET_DIR=/home/user/tgt/audit5-tr-mut/target
cargo test "$@" --locked --no-run -j3 --message-format=json 2> $S/mut/$label.err > $S/mut/$label.json
echo "exit=$?" >> $S/mut/$label.err
python3 - "$label" <<'PY'
import json,sys
S='/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
label=sys.argv[1]; out=[]
for line in open(f'{S}/mut/{label}.json'):
    try: e=json.loads(line)
    except Exception: continue
    if e.get('reason')=='compiler-artifact' and e.get('profile',{}).get('test') and e.get('executable'):
        t=e['target']; out.append((t['name'],','.join(t['kind']),e['executable'],e.get('manifest_path','')))
open(f'{S}/bins/mut-{label}.txt','w').write(''.join('\t'.join(o)+'\n' for o in out))
print(label, len(out), 'test binaries')
PY
tail -2 $S/mut/$label.err
