#!/usr/bin/env python3
"""Totals of every campaign log under logs/ (re-runnable at any time)."""
import glob, re, os, collections
D = os.path.dirname(os.path.abspath(__file__))
L = D + '/logs/'
def kv(line):
    return {k: int(v) for k, v in re.findall(r'([a-z_\-]+)=(\d+)', line)}
# 1. ported engine sweep harness (AUDIT-SWEEP lines)
tot = collections.Counter(); pairs = 0; fails = 0; groups = collections.Counter()
for f in sorted(glob.glob(L + 'A-se-*.log') + glob.glob(L + 'B-se-*.log') + glob.glob(L + 'q2-se-*.log')):
    for line in open(f, errors='replace'):
        if 'AUDIT-SWEEP' in line:
            pairs += 1
            head, _, stats = line.partition('|')
            m = re.search(r'run=(\d+)', head); seeds = int(m.group(1)) if m else 0
            tot['seeds'] += seeds
            groups[os.path.basename(f)] += seeds
            m = re.search(r'failures=(\d+)', head); fails += int(m.group(1)) if m else 0
            for k, v in kv(stats).items():
                tot[k] += v
print(f'[sweep_engine] pairs={pairs} seeds={tot["seeds"]} failures={fails}')
print('   ' + ' '.join(f'{k}={tot[k]}' for k in ['ops', 'crashes', 'recoveries-checked', 'chain-steps', 'chain-interrupted', 'double-crashes', 'batches', 'race-reads', 'heals', 'midop-deaths', 'cancelled-write', 'cancelled-trim', 'cancelled-flush', 'cancelled-checkpoint', 'cancelled-read', 'attach-cancelled', 'damaged', 'checks', 'bound-samples'] if k in tot))
for g, n in groups.items():
    print(f'   {g}: {n} seeds')
# 2. audit8_r3b_seeds (AUDIT8-SWEEP lines)
by = collections.defaultdict(collections.Counter)
for f in sorted(glob.glob(L + 'q2-*.r*.log')):
    for line in open(f, errors='replace'):
        if 'AUDIT8-SWEEP' in line:
            m = re.search(r'test=(\S+) profile=(\S+) seeds=(\d+)\.\.(\d+) failures=(\d+)', line)
            if not m: continue
            flavor = 'rel' if os.path.basename(f).startswith('q2-rel_') else 'da'
            key = f'{m.group(1)}/{m.group(2)}/{flavor}'
            by[key]['seeds'] += int(m.group(4)) - int(m.group(3)); by[key]['failures'] += int(m.group(5))
            by[key].setdefault('ranges', 0)
            for k, v in kv(line.partition('|')[2]).items():
                if k != 'seeds':
                    by[key][k] += v
            by[key]['range_' + m.group(3) + '..' + m.group(4)] = 1
for key, c in by.items():
    ranges = ' '.join(k[6:] for k in c if k.startswith('range_'))
    print(f'[r3b_seeds {key}] seeds={c["seeds"]} failures={c["failures"]} ops={c["ops"]} power_losses={c["power_losses"]}+{c["all_lost"]} restarts={c["restarts"]} pins={c["pins"]} attach_retries={c["attach_retries"]} auto_rolls={c["auto_rolls"]} damaged={c["damaged"]} damage_attached={c["damage_attached"]} ranges: {ranges}')
# 3. salted committed tests
for f in sorted(glob.glob(L + 'salted-*.tsv')):
    rows = [l.rstrip('\n').split('\t') for l in open(f)]
    salts = sorted({int(r[2]) for r in rows})
    bad = collections.Counter(r[3] for r in rows if r[5] != 'rc=0')
    print(f'[salted {os.path.basename(f)[7:-4]}] salts {salts[0]}..{salts[-1]} ({len(salts)}), module runs {len(rows)}, failing module runs {dict(bad)}')
# 4. fuzz
agg = collections.defaultdict(lambda: [0, 0, 0, 0])
for line in open(L + 'fuzz-summary.log'):
    m = re.search(r'target=(\S+) secs=(\d+) vp=\d rc=(\d+) execs=(\d*) (?:cov=(\d+))?', line)
    if m:
        a = agg[m.group(1)]; a[0] += int(m.group(2)); a[1] += int(m.group(4) or 0); a[2] = max(a[2], int(m.group(5) or 0)); a[3] += (m.group(3) != '0')
for t, a in agg.items():
    print(f'[fuzz {t}] seconds={a[0]} execs={a[1]} cov={a[2]} nonzero_exits={a[3]} corpus={len(os.listdir(D + "/corpora/" + t)) if os.path.isdir(D + "/corpora/" + t) else 0}')
# 5. other q2 jobs
for line in open(L + 'q2-summary.log'):
    if ' shadow=' in line or ' bin=' in line or ' se=' in line:
        print('[q2] ' + line.strip()[:420])
