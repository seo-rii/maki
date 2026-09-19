# Background storage regression runs

`scripts/storage-repeat-validation.py` repeats existing storage tests on the
local Linux host without an interactive agent watching them. It creates no
cloud resources. The parser corpus campaign remains separate and deferred.

```sh
# First check one round, including extended DB/persistence gates.
python3 -B scripts/storage-repeat-validation.py start --rounds 1 --max-seconds 1800

# After that passes, leave 100 rounds in the background (six-hour limit).
python3 -B scripts/storage-repeat-validation.py start --rounds 100 --max-seconds 21600

# Read the latest run's state or request cancellation.
python3 -B scripts/storage-repeat-validation.py status
python3 -B scripts/storage-repeat-validation.py cancel

# Select an older run explicitly.
python3 -B scripts/storage-repeat-validation.py status --run-dir /absolute/run/directory
```

`start` returns the run directory and supervisor PID after archiving the source
and launching the supervisor. Logs live under a unique `~/logs/maki-storage-*`
directory. The log root and run directory use mode 0700; logs and JSON records
are created with mode 0600. Keep that directory to inspect results later.

The five suites run sequentially, including all ignored tests, with one libtest
thread per suite:

| Suite | Checked behavior |
| --- | --- |
| `phase11_dbsim` | WAL-style transaction model, provider outage, crash recovery; extended gate runs 500 fixed seeds |
| `phase12_powerloss` | FLUSH/FUA persistence in the backing crash model; extended gate runs 500 seeds per scenario |
| `review_stress` | Concurrent readers/writers, checkpoints, recoverable I/O failures, acknowledged data after simulated crashes |
| `review_r3_space_admission` | Space headroom, reservation failures, retry, one real-file physical block reservation check |
| `review_r3_recovery_memory` | Recovery allocation regressions for distinct and repeatedly overwritten units |

Rounds reuse the existing fixed seeds. Thread scheduling can vary, but repetition
does not enlarge the seed set. Each suite starts a new process, so this is not a
continuous-service memory-growth measurement. DB and power-loss suites use
`CrashableBacking`; they do not qualify real DB engines, kernel device stacks,
or physical power loss. Allocation tests do not establish a universal RSS bound.

## Frozen inputs and outcomes

The tracked working tree must be clean. `start` archives exact Git HEAD,
excluding untracked files, and copies its runner into the run directory before
launching. `config.json` records the source revision, archive/runner hashes and
compiler versions. The snapshot is compiled offline with `Cargo.lock`, at most
two build jobs, and the repository's existing target cache. Missing cached
dependencies fail the run. Executables are copied into the private directory;
`binaries.json` records their hashes and enumerated test counts. Do not edit the
snapshot, copied runner or binaries of a running job.

`status.json` records the current suite, completed rounds, passed test invocations,
errors and final exit code. `results.jsonl` records successful suite invocations.
Individual build/list/test logs are retained. A pass requires all requested
rounds, successful exits, and exactly the enumerated number of passing tests,
with none ignored or filtered out. Zero tests cannot pass. The passed count
includes repeated invocations, not just unique cases.

Cancellation creates `STOP`; the supervisor terminates its current child process
group and records `cancelled`. A suite timeout or the campaign deadline leaves
an incomplete result. The default suite timeout is 900 seconds; build timeout is
at most 1,800 seconds within the overall budget. Output growth beyond 64 MiB per
child is checked periodically and stops the child; this is a stop threshold,
not an exact file-size cap. Less than 512 MiB free before a suite also stops the
run. Starting requires at least 2 GiB free.

After host reboot or premature supervisor death, `status` detects a missing or
reused PID using the boot ID and process start time and reports `interrupted`,
never `passed`. There is no automatic restart. Use `cancel` for ordinary stops.

To validate the runner's exit/result accounting and cancellation:

```sh
python3 -B -m unittest discover -s scripts -p test_storage_repeat_validation.py -v
```

## Initial execution, 2026-09-19

The first frozen-source run at `57ee9cbdf8918b52041467b748fef30818b283dd`
completed one round: **36 passed**, no ignored/filtered tests, supervisor exit
**0**, 152.8 seconds including build. The suites passed 3, 4, 2, 14 and 13 tests
respectively in the table's order. This includes both extended ignored gates.
The private evidence directory is
`/home/seorii/logs/maki-storage-20260919T143502Z-840206` (supervisor PID 1261500).

Runner development followed RED before implementation and GREEN for seven
regressions. The complete Python validation suite subsequently passed 60 tests,
and the Debian package suite passed three. Both exited 0; logs are under
`/home/seorii/logs/maki-storage-runner-checks-20260919T143734Z`
(supervisor PID 1278408). These package checks use fixture artifacts and do not
repeat the earlier real-host package upgrade campaign.

A subsequent 100-round run is intended for background execution. Starting it
does not establish success; consult its own terminal status and logs before
recording any additional qualification result.
