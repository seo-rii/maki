#!/usr/bin/env python3
"""reps.py <N> <threads> <pkg>:<bin>[,<bin>...] ...   repeat prebuilt test binaries; keep failing logs."""
import os, re, shutil, subprocess, sys, time
S = '/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
N = int(sys.argv[1]); threads = sys.argv[2]
tag = os.environ.get('REP_TAG', 'rep')
out = f'{S}/logs/{tag}'; os.makedirs(out, exist_ok=True)
tmpbase = f'/home/user/tgt/audit5-tr-tmp/{tag}'
for spec in sys.argv[3:]:
    pkg, names = spec.split(':'); names = set(names.split(',')) if names != '*' else None
    bins = [l.rstrip('\n').split('\t') for l in open(f'{S}/bins/{pkg}.txt') if l.strip()]
    plugin = None
    p = f'{S}/bins/PLUGIN-{pkg}'
    if os.path.exists(p): plugin = open(p).read().strip()
    for name, kind, exe, manifest in bins:
        if names is not None and name not in names: continue
        fails = 0; t0 = time.time(); failed_tests = {}
        for i in range(N):
            tmp = f'{tmpbase}/{pkg}-{name}'
            shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp, mode=0o755)
            env = {k: v for k, v in os.environ.items() if not k.startswith('CARGO_')}
            cwd = os.path.dirname(manifest)
            env.update(RUST_BACKTRACE='0', TMPDIR=tmp, CARGO_MANIFEST_DIR=cwd, NO_COLOR='1')
            if plugin: env['MAKI_NBDKIT_TEST_PLUGIN'] = plugin
            try:
                r = subprocess.run([exe, f'--test-threads={threads}'], cwd=cwd, env=env, capture_output=True, text=True, errors='replace', timeout=900, stdin=subprocess.DEVNULL)
                rc = r.returncode; txt = r.stdout + r.stderr
            except subprocess.TimeoutExpired as e:
                rc = 'TIMEOUT'; txt = (e.stdout or b'').decode(errors='replace') + (e.stderr or b'').decode(errors='replace') if isinstance(e.stdout, bytes) else str(e.stdout) + str(e.stderr)
            if rc != 0:
                fails += 1
                open(f'{out}/{pkg}.{name}.fail{i}.log', 'w').write(txt)
                for t in re.findall(r'^test (\S+) \.\.\. FAILED', txt, re.M): failed_tests[t] = failed_tests.get(t, 0) + 1
                if rc == 'TIMEOUT': failed_tests['<TIMEOUT>'] = failed_tests.get('<TIMEOUT>', 0) + 1
            shutil.rmtree(tmp, ignore_errors=True)
        print(f'{pkg}/{name}: {N - fails}/{N} ok  {time.time() - t0:.0f}s  {failed_tests if fails else ""}', flush=True)
