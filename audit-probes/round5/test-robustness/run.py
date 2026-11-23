#!/usr/bin/env python3
"""Run a crate's prebuilt test binaries under a condition; summarize.

usage: run.py <pkg> <label> [--umask OCT] [--uid N] [--threads N] [--only name,name]
              [--extra ARG ...] [--timeout S] [--copy]
"""
import argparse, json, os, re, shutil, subprocess, sys, time
S = '/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit5-test-robustness'
ap = argparse.ArgumentParser()
ap.add_argument('pkg'); ap.add_argument('label')
ap.add_argument('--umask'); ap.add_argument('--uid', type=int)
ap.add_argument('--threads', type=int, default=2)
ap.add_argument('--only'); ap.add_argument('--skip')
ap.add_argument('--timeout', type=int, default=1500)
ap.add_argument('--filter', default=None)
ap.add_argument('--ignored', action='store_true')
ap.add_argument('--env', action='append', default=[])
a = ap.parse_args()
bins = [l.rstrip('\n').split('\t') for l in open(f'{S}/bins/{a.pkg}.txt') if l.strip()]
only = set(a.only.split(',')) if a.only else None
skip = set(a.skip.split(',')) if a.skip else set()
logdir = f'{S}/logs/{a.label}/{a.pkg}'
os.makedirs(logdir, exist_ok=True)
tmp = f'/home/user/tgt/audit5-tr-tmp/{a.label}-{a.pkg}'
shutil.rmtree(tmp, ignore_errors=True)
os.makedirs(tmp + '/tmp'); os.makedirs(tmp + '/home')
if a.uid is not None:
    for d in (tmp, tmp + '/tmp', tmp + '/home'):
        os.chown(d, a.uid, a.uid)
os.chmod(tmp + '/tmp', int(os.environ.get('TR_TMPMODE','755'), 8)); os.chmod(tmp + '/home', 0o700); os.chmod(tmp, 0o755)
plugin = None
p = f'{S}/bins/PLUGIN-{a.pkg}'
if os.path.exists(p): plugin = open(p).read().strip()
tot = dict(passed=0, failed=0, ignored=0)
rows = []
for name, kind, exe, manifest in bins:
    if only and name not in only: continue
    if name in skip: continue
    cwd = os.path.dirname(manifest)
    env = {k: v for k, v in os.environ.items() if not k.startswith('CARGO_') and k not in ('MAKI_NBDKIT_TEST_PLUGIN',)}
    env.update(RUST_BACKTRACE='0', TMPDIR=tmp + '/tmp', HOME=tmp + '/home', CARGO_MANIFEST_DIR=cwd,
               CARGO_PKG_NAME=a.pkg, CARGO=shutil.which('cargo') or 'cargo', NO_COLOR='1')
    if plugin: env['MAKI_NBDKIT_TEST_PLUGIN'] = plugin
    if a.uid is not None and a.label != 'nobody':
        # a clean login-like environment for the unprivileged user
        keep = {k: env[k] for k in ('RUST_BACKTRACE','TMPDIR','HOME','CARGO_MANIFEST_DIR','CARGO_PKG_NAME','NO_COLOR','MAKI_NBDKIT_TEST_PLUGIN','LANG') if k in env}
        env = keep
        env['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
        env['USER'] = env['LOGNAME'] = 'nobody'
    for kv in a.env:
        k, v = kv.split('=', 1); env[k] = v
    cmd = [exe, f'--test-threads={a.threads}', '--show-output']
    if a.ignored: cmd.append('--ignored')
    if a.filter: cmd.append(a.filter)
    if a.uid is not None:
        cmd = ['setpriv', '--reuid', str(a.uid), '--regid', str(a.uid), '--clear-groups'] + cmd
    pre = None
    if a.umask: pre = lambda: os.umask(int(a.umask, 8))
    t0 = time.time()
    log = f'{logdir}/{name}.{kind}.log'
    with open(log, 'w') as f:
        try:
            rc = subprocess.run(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT,
                                preexec_fn=pre, timeout=a.timeout, stdin=subprocess.DEVNULL).returncode
        except subprocess.TimeoutExpired:
            rc = 'TIMEOUT'
    dt = time.time() - t0
    txt = open(log, errors='replace').read()
    res = re.findall(r'^test (\S+)(?: - should panic)? \.\.\. (ok|FAILED|ignored)', txt, re.M)
    # tests whose line got split by interleaved output
    ok = sum(1 for _, r in res if r == 'ok'); fl = [n for n, r in res if r == 'FAILED']; ig = sum(1 for _, r in res if r == 'ignored')
    m = re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored', txt)
    if m:
        ok, nfl, ig = int(m.group(2)), int(m.group(3)), int(m.group(4))
    else:
        nfl = len(fl)
    failed_names = re.findall(r'^    (\S+)$', txt.split('\nfailures:\n')[-1], re.M) if '\nfailures:\n' in txt else fl
    tot['passed'] += ok; tot['failed'] += nfl; tot['ignored'] += ig
    rows.append(dict(bin=name, kind=kind, rc=rc, passed=ok, failed=nfl, ignored=ig, secs=round(dt, 1), failures=sorted(set(failed_names)), summary=bool(m)))
    flag = '' if (rc == 0 and m) else '  <<<<<'
    print(f'{a.pkg}/{name}[{kind}] rc={rc} pass={ok} fail={nfl} ign={ig} {dt:.1f}s{flag}', flush=True)
    for n in sorted(set(failed_names)): print('     FAILED', n, flush=True)
left = []
for root, ds, fs in os.walk(tmp):
    for x in ds + fs:
        left.append(os.path.relpath(os.path.join(root, x), tmp))
json.dump(dict(pkg=a.pkg, label=a.label, total=tot, rows=rows, leftovers=left[:200], n_leftovers=len(left)), open(f'{logdir}/SUMMARY.json', 'w'), indent=1)
print(f'TOTAL {a.pkg} [{a.label}] passed={tot["passed"]} failed={tot["failed"]} ignored={tot["ignored"]} leftovers_in_tmp={len(left)}')
