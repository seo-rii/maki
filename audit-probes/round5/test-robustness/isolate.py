#!/usr/bin/env python3
"""Run every test of every prebuilt binary alone (--exact) to find tests that need another test's side effects."""
import os, re, shutil, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
S = '/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
out = f'{S}/logs/isolate'; os.makedirs(out, exist_ok=True)
pkgs = sys.argv[1:]
jobs = []
for pkg in pkgs:
    plugin = None
    p = f'{S}/bins/PLUGIN-{pkg}'
    if os.path.exists(p): plugin = open(p).read().strip()
    for line in open(f'{S}/bins/{pkg}.txt'):
        if not line.strip(): continue
        name, kind, exe, manifest = line.rstrip('\n').split('\t')
        cwd = os.path.dirname(manifest)
        env = {k: v for k, v in os.environ.items() if not k.startswith('CARGO_')}
        env.update(RUST_BACKTRACE='0', CARGO_MANIFEST_DIR=cwd, NO_COLOR='1')
        if plugin: env['MAKI_NBDKIT_TEST_PLUGIN'] = plugin
        lst = subprocess.run([exe, '--list', '--format', 'terse'], cwd=cwd, env=env, capture_output=True, text=True).stdout
        tests = [l[:-len(': test')] for l in lst.split('\n') if l.endswith(': test')]
        for t in tests: jobs.append((pkg, name, exe, cwd, env, t))
def run(job):
    pkg, name, exe, cwd, env, t = job
    tmp = f'/home/user/tgt/audit5-tr-tmp/i/{abs(hash((pkg, name, t))) % 10**9}'
    os.makedirs(tmp, exist_ok=True)
    e = dict(env); e['TMPDIR'] = tmp
    try:
        r = subprocess.run([exe, '--exact', t, '--test-threads=1'], cwd=cwd, env=e, capture_output=True, text=True, errors='replace', timeout=600, stdin=subprocess.DEVNULL)
        rc = r.returncode; txt = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        rc = 'TIMEOUT'; txt = ''
    shutil.rmtree(tmp, ignore_errors=True)
    ran = re.search(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored', txt)
    if rc != 0 or not ran or (ran.group(1) == '0' and ran.group(3) == '0'):
        open(f'{out}/{pkg}.{name}.{t.replace("::", ".")[:120]}.log', 'w').write(txt)
        return f'ISOLATED-FAIL {pkg}/{name}::{t} rc={rc}'
    return None
t0 = time.time(); bad = []
with ThreadPoolExecutor(max_workers=2) as ex:
    for res in ex.map(run, jobs):
        if res: bad.append(res); print(res, flush=True)
print(f'ISOLATE DONE pkgs={pkgs} tests={len(jobs)} failures={len(bad)} secs={time.time() - t0:.0f}', flush=True)
