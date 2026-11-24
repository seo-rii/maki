# Round 8, native-nbdkit probes

Code under test: `/home/user/wt/audit8` at 956e354. Nothing here modifies it.

## Setup

- `apt-get install -y python3-libnbd nbdkit-plugin-dev` (libnbd 1.20.0; the
  Python module is built for python3.12 only, so every probe runs with
  `/usr/bin/python3.12`).
- `bin/`: debug `libmaki_nbdkit.so`, `maki`, `maki-check` from
  `CARGO_TARGET_DIR=/home/user/tgt/audit8 CARGO_PROFILE_DEV_DEBUG=0 cargo build -p maki-nbdkit --locked -j 2`
  and `-p maki`. `bin-release/`: the same from
  `CARGO_TARGET_DIR=/home/user/tgt/audit8-release CARGO_PROFILE_RELEASE_DEBUG=0 cargo build --release -p maki-nbdkit --locked -j 2`
  and `-p maki`. Select with `MAKI_PLUGIN=... MAKI_BIN=...` (default `bin/`).
- `plshim.so`: `gcc -O2 -Wall -shared -fPIC -o plshim.so plshim.c -ldl -lpthread`.
- Volumes live under `/tmp/a8n` (and tmpfs mounts `/tmp/a8n-tmpfs-*`,
  `/tmp/a8n-pl-*`, unmounted at exit). Provider `local-aes-gcm-siv`, key file.

## Probes

| File | What | Run |
|---|---|---|
| `mk.py` | helpers: config, create, start nbdkit and wait for READY, self-describing sector pattern | (library) |
| `smoke.py` | nbdinfo, flags, one write, status | `python3.12 smoke.py [--discard]` |
| `fastzero_abort.py` | finding F1 | `python3.12 fastzero_abort.py` (exit 1 = reproduced) |
| `sem.py` | single-connection semantics vs a byte model, restarts | `python3.12 sem.py [--only v2,v3,v2-cache,v3-cache,v3-unit8k]` |
| `conc.py` | connections, RMW concurrency, disconnects, stuck client, admission limits, control socket, signals, fork/modes | `python3.12 conc.py [--only second,rmw,disconnect,stuck,admission,control,sigterm,two,fork,early]` |
| `big.py` | 8 GiB export, 4 GiB trim/zero, 64 MiB write | `python3.12 big.py` |
| `tools.py` | nbdcopy, nbdinfo --map, mkfs.ext4/debugfs/dd/fallocate through nbdfuse, kill -9 | `python3.12 tools.py` |
| `drift.py` | settings changed between kill -9 and restart | `python3.12 drift.py` |
| `closedfds.py` | fds 0-2 closed / stderr on /dev/full | `python3.12 closedfds.py closed|full` |
| `crash.py` | randomized workload, kill -9 / SIGTERM at random moments (also during recovery), per-sector oracle; `--tmpfs` full filesystem; `--filters` nbdkit filters; `--plant` self-test | `python3.12 crash.py --seed N [--cycles 30] [--profile ...]` |
| `plshim.c`, `pl.py` | power-loss images of the real data path (write/sync log, strict POSIX replay, cuts, fault injection); `--plant-sync`, `--plant-k01` self-tests | `python3.12 pl.py --seed N [--cycles 12] [--fault ...] [--marks 12]` |
| `exh.py` | one scripted volume life; an image after EVERY sync/dir sync/create/unlink/truncate/allocate/punch and every N-th write, both phases (run + recovery + clean stop) | `python3.12 exh.py --seed N [--discard] [--every 6]` |
| `create_pl.py` | power loss at every call boundary of `maki volume create` (finding F2 shows as 8 FAILs) | `python3.12 create_pl.py [--discard]` |
| `create_empty_superblock.py` | finding F2 through the real CLI and daemon | `python3.12 create_empty_superblock.py` (exit 1 = reproduced) |
| `create_interrupted.py` | the documented "not a volume, empty the root" outcome (inode exhaustion) | `python3.12 create_interrupted.py [--discard]` |
| `check_readonly.py` | `maki check [--deep]`, `volume inspect` make no modifying call | `python3.12 check_readonly.py` |
| `corrupt.py` | bit flips / zeroed blocks / truncation / deletion of backing files, then the plugin | `python3.12 corrupt.py --seed N [--iters 150] [--discard] [--faults K]` |
| `sweep.sh` | seed ranges; one line per seed in `logs/<name>.summary`, output of failing seeds kept | `[SCRIPT=pl.py] ./sweep.sh <name> <first> <last> [options]` |

`nbdkit-src/`: nbdkit `server/protocol.c` and `server/backend.c` at v1.36.3,
v1.38.5 and master, plus connections/sockets/main at v1.36.3 (from
gitlab.com/nbdkit/nbdkit), for F1 and the SIGTERM observation.

Cargo test for F1: `crates/maki-nbdkit/tests/audit8_native_fast_zero.rs`.

Cargo test for F2: `crates/maki-format/tests/audit8_create_empty_superblock.rs`.

## Sweeps that ran (logs/*.summary; every line is one seed)

| Name | Command | Result |
|---|---|---|
| k1, k2 | `./sweep.sh k1 100 124 --cycles 30`, `./sweep.sh k2 200 224 --cycles 30` (debug) | 50/50 ok; 1652 kill -9, 213 SIGTERM, 34,483 acknowledged writes/zeros/trims |
| k3rel | `MAKI_PLUGIN=bin-release/... ./sweep.sh k3rel 1000 1019 --cycles 30` (release, kills during recovery) | 20/20 ok; 639 kills + 347 during recovery, 101 SIGTERM |
| t1, t2 | `./sweep.sh t1 300 314 --cycles 16 --tmpfs 16m --allow-errors` (t2: `--reserve 256KiB --ckpt-reserve 512KiB`) | 30/30 ok; 8,806 ENOSPC answers, 3 refused restarts (reserve 0 only) that recovered once space was back, 120 "space released" cycles in which writes resumed |
| geo | `crash.py --seed 71|72 --cycles 15 --profile v3unit512|v3blk4k|v2unit16k|v3unit16k|v3unit1k` (release) | 10/10 ok (v3blk4k after a harness read-size fix) |
| p1 | `SCRIPT=pl.py ./sweep.sh p1 500 519 --cycles 12` | 20/20 ok; 1,680 power-loss images |
| p2, p2b | `... p2 600 619 --cycles 10 --fault sync=0.03,write=0.02` | 19/20 ok + seed 604 a harness artifact (kill between a call and its log record; tolerated since, rerun p2b ok); 1,407 images, 2,855 injected-fault errors |
| p4 | `... p4 800 819 --cycles 10 --fault sync=0.02,write=0.02,dsync=0.03,trunc=0.02,alloc=0.02,unlink=0.2,werrno=28` | 20/20 ok; 1,400 images |
| p5 | `... p5 900 911 --cycles 8 --marks 12` | 12/12 ok; 1,154 images, 594 of them right after an unlink or hole punch |
| p6rel | release plugin, `... p6rel 1100 1111 --cycles 12` | 12/12 ok; 1,008 images |
| exh | `exh.py --seed 1 --every 6`, `exh.py --seed 2 --discard --every 6` (release) | ok; 2,658 + 3,813 images |
| corrupt | seeds 1-5 (release) | 770 damaged volumes: 169 refused, 194 units EIO, 0 stale, 0 wrong, 0 crashes |
