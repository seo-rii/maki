#!/bin/bash
# Round-8 audit (long-seeds): build a SHADOW copy of the worktree (the tree
# itself is not touched) in which the crate-private inline crash sweeps of
# maki-backing and maki-privileged take their seeds from AUDIT8_SEED_START /
# AUDIT8_SEED_COUNT (and tearing from AUDIT8_TEAR), and four multi-interruption
# sweeps are appended (shadow-patches/*.rs).
set -eu
D=/tmp/claude-0/-home-user-maki/16a7de9d-9e60-54fe-9449-1b52e7abee3d/scratchpad/audit8-long-seeds
W=/home/user/wt/audit8
SH=$D/shadow/ws
rm -rf "$SH"; mkdir -p "$SH"
( cd $W && tar cf - --exclude=.git --exclude=target --exclude='audit8_*' . ) | ( cd "$SH" && tar xf - )
python3 - "$SH" "$D/shadow-patches" <<'PY'
import re, sys
SH, P = sys.argv[1], sys.argv[2]
B = SH + '/crates/maki-backing/src'
# seed/tear helpers, test builds only
lib = open(B + '/lib.rs').read()
lib += '''
/// AUDIT ROUND 8 (shadow copy only): seed range and tear granularity of the
/// inline crash sweeps from the environment.
#[cfg(test)]
pub(crate) mod a8 {
    fn get(name: &str) -> Option<u64> {
        std::env::var(name).ok().and_then(|v| v.parse().ok())
    }
    pub fn seeds(default: std::ops::RangeInclusive<u64>) -> std::ops::RangeInclusive<u64> {
        match (get("AUDIT8_SEED_START"), get("AUDIT8_SEED_COUNT")) {
            (Some(start), Some(count)) if count > 0 => start..=start + count - 1,
            (Some(start), None) => start..=start + (default.end() - default.start()),
            (None, Some(count)) if count > 0 => 0..=count - 1,
            _ => default,
        }
    }
    pub fn tear(default: usize) -> usize {
        get("AUDIT8_TEAR").map(|v| v as usize).unwrap_or(default)
    }
}
'''
open(B + '/lib.rs', 'w').write(lib)
total = 0
for rel, chain in [('rollback/local_creation_tests.rs', 'local_creation_chain.rs'),
                   ('rollback/remote_creation_tests.rs', 'remote_creation_chain.rs'),
                   ('remote_witness_init_tests.rs', 'witness_init_chain.rs'),
                   ('rollback/review_restore.rs', None)]:
    s = open(f'{B}/{rel}').read()
    s, n1 = re.subn(r'for seed in 0\.\.=(\d+) \{', r'for seed in crate::a8::seeds(0..=\1) {', s)
    s, n2 = re.subn(r'for seed in 0\.\.(\d+) \{', lambda m: f'for seed in crate::a8::seeds(0..={int(m.group(1)) - 1}) {{', s)
    s, n3 = re.subn(r'\.with_tearing\(512\)', '.with_tearing(crate::a8::tear(512))', s)
    if chain:
        s += open(f'{P}/{chain}').read()
    if rel == 'rollback/local_creation_tests.rs':
        s += open(f'{P}/local_commit_chain.rs').read()
    open(f'{B}/{rel}', 'w').write(s)
    print(rel, 'seed loops', n1 + n2, 'tear sites', n3)
    total += n1 + n2
assert total >= 6, total
# Oracle self-test for the commit-chain sweep: two planted bugs in the shadow
# copy's commit path, off unless the named environment variable is set.
R = B + '/rollback.rs'
r = open(R).read()
a = '''            self.arena.sync_data()?;
            write_manifest(self.disk.as_ref(), slot, &bytes)?;
            self.witness
                .advance(digest(b"maki.rollback.manifest.v1\\0", &bytes))'''
assert a in r, 'commit body changed'
r = r.replace(a, '''            if std::env::var_os("A8_MUT_ARENA_NOSYNC").is_none() {
                self.arena.sync_data()?;
            }
            if std::env::var_os("A8_MUT_ANCHOR_FIRST").is_some() {
                self.witness
                    .advance(digest(b"maki.rollback.manifest.v1\\0", &bytes))?;
                return write_manifest(self.disk.as_ref(), slot, &bytes);
            }
            write_manifest(self.disk.as_ref(), slot, &bytes)?;
            self.witness
                .advance(digest(b"maki.rollback.manifest.v1\\0", &bytes))''')
open(R, 'w').write(r)
print('rollback.rs: commit-path mutations planted (env-gated)')
V = SH + '/crates/maki-privileged/src/review_step_faults.rs'
s = open(V).read() + open(f'{P}/step_faults_chain.rs').read()
open(V, 'w').write(s)
print('maki-privileged step-fault chain appended')
PY
echo "shadow ready: $SH"
