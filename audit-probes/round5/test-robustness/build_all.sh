#!/bin/bash
# Build each crate's tests once; record executables.
S=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness
cd /home/user/wt/audit5
export CARGO_TARGET_DIR=/home/user/tgt/audit5
for pkg in "$@"; do
  avail=$(df --output=avail -BG /home/user | tail -1 | tr -dc 0-9)
  while [ "$avail" -lt 5 ]; do sleep 60; avail=$(df --output=avail -BG /home/user | tail -1 | tr -dc 0-9); done
  echo "== $pkg start $(date +%T)" >> $S/logs/build.log
  cargo test -p "$pkg" --locked --no-run --message-format=json 2> $S/logs/build-$pkg.err > $S/logs/build-$pkg.json
  echo "== $pkg exit=$? $(date +%T)" >> $S/logs/build.log
  python3 - "$pkg" <<'PY'
import json,sys
pkg=sys.argv[1]
S='/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
out=[]
for line in open(f'{S}/logs/build-{pkg}.json'):
    try: e=json.loads(line)
    except Exception: continue
    if e.get('reason')=='compiler-artifact' and e.get('profile',{}).get('test') and e.get('executable'):
        t=e['target']
        out.append((t['name'],','.join(t['kind']),e['executable'],e.get('manifest_path','')))
    if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='maki_nbdkit' and 'cdylib' in e['target'].get('crate_types',[]):
        for f in e.get('filenames',[]):
            if f.endswith('.so'): open(f'{S}/bins/PLUGIN-{pkg}','w').write(f)
with open(f'{S}/bins/{pkg}.txt','w') as f:
    for o in out: f.write('\t'.join(o)+'\n')
PY
done
echo ALLDONE >> $S/logs/build.log
