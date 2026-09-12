# Native process and cgroup fault validation — 2026-09-12

The native process and Docker cgroup campaigns preserved the tested durable
ACKs. **They do not qualify production operation or host power loss.** An
availability check did not reach READY within 30 seconds at the original
32 MiB cap in two trials with 22 MiB of completed pressure writes. The final
trial, with 21.75 MiB completed before OOM, did recover at 32 MiB. Recovery at
192 MiB succeeded. These outcomes do not establish reliable availability at
32 MiB or a minimum-memory sizing rule.

Related: [qualification tiers](testing.md),
[production readiness review](production-readiness-review-2026-09-08.md),
[durable recovery contract](durable-recovery.md).

## Environment and isolation

- Host: Debian Linux `6.1.0-53-cloud-amd64`, Docker `29.1.2`, cgroup v2 with
  the systemd driver. This host is not WSL and has no `wsl.exe`.
- Product source: `e894ae57fea294966bcb7ec84593732c55cbc220` (latest product
  change `2a3f023`). Normal release binaries were built without fake-provider;
  `CARGO_PROFILE_RELEASE_DEBUG=0` disabled symbols, not optimization or runtime checks.
- The Docker image contains Debian's nbdkit `1.42.3-1`, the native plugin and
  CLI, with a real local AES-GCM-SIV provider and a disposable key. Image ID:
  `sha256:3e7783ad7858b6b9b80c61203d7f1b4a5b2786174af9a8f0d61fcf0080474e85`.
- Each case creates a private 128 MiB logical volume. Containers run as the
  invoking UID with no network, no capabilities, no new privileges, a read-only
  root filesystem and one writable disposable bind mount. No kernel NBD device,
  LVM, XFS, production service, shared cgroup, or existing container is changed.
- The Python/libnbd client and its fsynced ACK ledger live on the host, outside
  the target container and its writable mount. nbdkit is PID 1. There is no
  memory stress sidecar that could become the OOM victim instead.

## Executed checks

The [Docker runner](../scripts/cgroup-validation.py) completed three cases.
Each initial workload performed eight FLUSH batches of 128 distinct 4 KiB units
and 64 FUA writes, overwriting those same units across rounds. The final latest
image contains 136 independently checked units. Unbarriered writes use other
offsets and are excluded from the durable oracle.

| Case | Fault and observation | Recovery result |
|---|---|---|
| CPU and memory limits | 96 MiB memory, swap disabled, 0.25 CPU, 64 tasks; kernel CPU throttling occurred, then explicit SIGKILL with `OOMKilled=false` | All 136 durable units matched through authenticated NBD reads; offline deep check passed |
| Freeze and resume | Docker cgroup pause for 0.5 s; a new client could not complete or add an ACK while frozen; it completed after unpause, followed by SIGKILL | All 136 latest durable units matched; deep check passed |
| Workload OOM | The target remained alive after lowering memory to 32 MiB with swap disabled. Distinct unbarriered pressure writes then caused PID 1 to exit with `OOMKilled=true`, exit 137 | At 192 MiB, all 136 durable units matched; deep check passed |
| Restart at original cap | Each trial's post-OOM data, 32 MiB memory and no swap | Two 22 MiB pressure trials timed out without READY; the final 21.75 MiB trial recovered and verified 136 units. The cap is **not reliably qualified** |

In the final trial the CPU case recorded four throttled periods. The OOM
client completed 87 writes of 256 KiB; its 88th write failed. The 32 MiB
recovery touched the exact `memory.max` ceiling and recorded 329 memory-max
events, with no recovery OOM. In the earlier timeout trials the client had
completed 88 such writes. Different journal tails and run conditions prevent
interpreting this as an exact allocation threshold or a deterministic sizing
formula. No acknowledged data mismatch was found in any successful readback.

The freeze case starts a new connection after pausing. It does not demonstrate
a partially executed engine write being frozen. The OOM predicate requires
completed pressure I/O and Docker's OOM classification: exit 137 alone is
insufficient. A startup timeout is recorded as unavailable, never as successful
recovery. `results.json`'s top-level `passed` covers the campaign's durability
checks and completed observations; inspect `recovery_at_32m.ready` separately.

The [native Rust regression](../crates/maki-nbdkit/tests/review_r3_native_crash.rs)
adds six cases using disposable fake-provider volumes, nbdkit and libnbd:

- FLUSH and FUA each survive three SIGKILL/restart cycles by default.
- A connected client attempting FUA against a stopped/killed daemon reports an
  error and adds no durable ACK; earlier acknowledged data survives restart.
- Removing or truncating the acknowledged journal segment refuses startup
  without READY.
- An intentionally wrong external expected byte is rejected even by an
  optimized Python interpreter. The initial regression failed under `-O`;
  explicit error checks replaced Python assertions before the final pass.

All six native tests passed with `PYTHONOPTIMIZE=1`; focused strict Clippy and
formatting passed. The native regression commit `0509fe3` also passed
[Linux and Windows CI](https://github.com/seo-rii/maki/actions/runs/34694167299).
Thirteen Python harness tests cover failed barriers, missing
data, empty/truncated oracles, optimized execution, OOM classification, actual
pressure progress, immutable image selection, timeout cleanup and startup
metrics. Linux CI runs these oracle tests and the native regression. The Docker
campaign remains opt-in and is not silently treated as a CI pass.

The complete harness commit `8123f9d` passed
[Linux and Windows CI](https://github.com/seo-rii/maki/actions/runs/34694557732):
formatting, strict Clippy and workspace tests, plus the 13 fault-oracle tests
on Linux. The expensive scheduled release gates were not rerun for these test
and documentation changes.

## Evidence

All long-running commands used private background logs; their final exit status
was recorded before bounded inspection. The final native GREEN log is
`/home/seorii/logs/maki-r3-native-crash-optimized-green-20260912T123542.534405Z.log`
(PID 1086758, exit 0). Its actual negative RED is
`/home/seorii/logs/maki-r3-native-crash-optimized-red-20260912T123317.934465Z.log`
(PID 1069538, exit 101).

The complete Docker artifacts are under
`/home/seorii/logs/maki-cgroup-native-20260912-evidence/`: `results.json`, host ACK
ledgers, pressure progress and bounded logs captured after each container exited.
The launcher log is
`/home/seorii/logs/maki-r3-cgroup-native-final-evidence-20260912T123818.793378Z.log`
(PID 1102835, exit 0, 12.01 s). The final 13 oracle tests passed with exit 0
(PID 1102604,
`/home/seorii/logs/maki-r3-cgroup-final-unit-20260912T123818.427708Z.log`).
These disposable encrypted backing trees and their test keys are
retained in private directories for inspection; they are not committed. All
containers created by the completed campaign were removed.

The 32 MiB timeout evidence is retained separately:
`/home/seorii/logs/maki-cgroup-native-20260912-verified/results.json` records
`recovery_at_32m.ready=false` and a still-running process after 30 s; its
subsequent 192 MiB recovery passed (launcher PID 1091005, exit 0, 41.74 s,
`/home/seorii/logs/maki-r3-cgroup-native-campaign-verified-20260912T123607.929264Z.log`).
That earlier runner had not yet collected the current cgroup before READY, so
its startup-memory samples are explicitly unavailable; they must not be used
as memory measurements. The first timeout trial's pressure count is in
`/home/seorii/logs/maki-cgroup-native-20260912-final/results.json`; it ended with campaign exit 1
(PID 1070487,
`/home/seorii/logs/maki-r3-cgroup-native-campaign-final-20260912T123339.152084Z.log`).

The release build completed with exit 0 (PID 1022389,
`/home/seorii/logs/maki-r3-cgroup-release-build-20260912T122106.829706Z.log`).
The CLI SHA-256 is `a483da59bc53ad05cae1393bc3274311e45ef20a574a8499f83d2dca6cf35f9f`;
the plugin SHA-256 is `25af501de315eecf3d6eb0572d4cd92edb547d50e916fb90da48b5dd7825bdbf`.

## Reproduce on a disposable Linux test host

Prerequisites: Docker with cgroup v2 memory/swap/CPU/PID support, Python 3,
host `libnbd.so.0`, Rust, and a compatible Debian container base. Docker access
is required, but the runner does not request sudo or privileged containers.
The image build installs nbdkit **inside the new test image**. The runner pins
the inspected image ID and refuses automatic pulls.

From the repository root, the following records PID, log and final status from
launch. It preserves all artifacts and leaves its uniquely tagged test image.

```bash
umask 077
mkdir -p "$HOME/logs"
chmod 0700 "$HOME/logs"
run_dir=$(mktemp -d "$HOME/logs/maki-cgroup.XXXXXXXX")
cat >"$run_dir/run.sh" <<'SH'
set -euo pipefail
repo=$1
run_dir=$2
trap 'result=$?; printf "%s\n" "$result" >"$run_dir/status"' EXIT
cd "$repo"
export CARGO_TARGET_DIR="$repo/target"
export CARGO_INCREMENTAL=0 CARGO_PROFILE_RELEASE_DEBUG=0
git rev-parse HEAD >"$run_dir/source-revision"
cargo build --release --locked -p maki -p maki-nbdkit -j2
mkdir "$run_dir/image"
cp target/release/maki target/release/libmaki_nbdkit.so "$run_dir/image/"
sha256sum "$run_dir/image/"* >"$run_dir/binary-sha256"
image="maki-cgroup-validation:local-$(date -u +%Y%m%dT%H%M%SZ)-$$"
printf '%s\n' "$image" >"$run_dir/image-tag"
docker build --pull=false -t "$image" -f scripts/cgroup-validation.Dockerfile "$run_dir/image"
python3 -B -m unittest discover -s scripts -p test_cgroup_validation.py -v
python3 -B scripts/cgroup-validation.py --image "$image" --output "$run_dir/artifacts" --rounds 8
SH
nohup bash "$run_dir/run.sh" "$PWD" "$run_dir" >"$run_dir/run.log" 2>&1 </dev/null &
printf '%s\n' "$!" >"$run_dir/pid"
printf 'PID %s; log %s/run.log; status %s/status\n' "$(cat "$run_dir/pid")" "$run_dir" "$run_dir"
```

Wait for the process to exit before inspecting bounded log excerpts. Do not
remove the output directory while a target container exists. A failed Docker
daemon operation can prevent cleanup; owned containers have unique
`maki-fault-*` names and a `maki.failure-validation` label. Inspect that run's
identity before cleanup and never use a global prune or kill command.

## Limits and WSL

Memory figures from cgroup accounting include charged cache and kernel memory;
they are not a process RSS bound. The OOM workload deliberately exceeded its
memory cap. Recovery at 192 MiB does not prove bounded recovery for every
journal or a production sizing recommendation. Distinct-unit replay memory and
restart latency remain open (MAKI-025/028).

The host kernel and page cache survived every SIGKILL, container OOM and pause.
These cases cannot show which writes would survive loss of the host or device
cache. There was no actual database, kernel-NBD/LVM/XFS crash, WSL termination,
VM power cut, or long-duration soak in this campaign.

For a future WSL trial, use a dedicated Windows test host and keep the ACK
oracle outside the terminated VM. Microsoft's `wsl --shutdown` terminates all
running distributions and the WSL 2 utility VM; `wsl --terminate <name>` targets
one distribution. Neither should be run against the shared development session
as an incidental test, and neither is evidence of physical power loss by itself.
[Microsoft WSL command reference](https://learn.microsoft.com/en-us/windows/wsl/basic-commands)

Resource semantics and the distinction between OOM, SIGKILL and graceful stop:
[Linux cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
[Docker resource limits](https://docs.docker.com/engine/containers/resource_constraints/),
[Docker kill](https://docs.docker.com/reference/cli/docker/container/kill/),
[Docker stop](https://docs.docker.com/reference/cli/docker/container/stop/).
