# Review remediation log

The [independent code and architecture review dated 2026-09-02](qualification/historical-reviews/external-review-2026-09-02.md)
rated Maki a strong alpha but a production **No-Go**,
and listed 18 findings (M-001 … M-018). This page tracks what has been done
about each one, in the review's own order, and records subsequent reviews and
their regression evidence.

These dated sections preserve the findings and evidence from each review
pass. For current support and limits, use [Status](status.md). The
[R3 readiness record](qualification/historical-reviews/production-readiness-review-2026-09-08.md)
is the historical record of that review.
Later fixes can supersede an older section's remaining-work list. The
[2026-10-15 boundary follow-up](review-boundaries-2026-10-15.md) distinguishes
proposed PR fixes from remote-main changes and combined qualification.

Status values: **Fixed** (regression test landed and passes), **Partial**
(behaviour improved, remaining gap described), **Open**.

## Third follow-up round (2026-11-27): AUD-205–AUD-210

No audit preceded this round either. After the second follow-up round's
records change ([#409](https://github.com/seo-rii/maki/pull/409), `main` at
`b2d3bf9`), the owner asked for pull requests for everything still open, all
of it to be processed before the next release. The round took up the eight
items of the second follow-up round's open list
([below](#not-closed-in-the-second-follow-up-round)), not the older rounds'
lists. Six pull requests were merged into `main` on 2026-11-27:
[#410](https://github.com/seo-rii/maki/pull/410) at `3c3baf6`,
[#414](https://github.com/seo-rii/maki/pull/414) at `4bd47b7`,
[#415](https://github.com/seo-rii/maki/pull/415) at `c2c46c7`,
[#411](https://github.com/seo-rii/maki/pull/411) at `32efe0b`,
[#413](https://github.com/seo-rii/maki/pull/413) at `52eca7c` and
[#412](https://github.com/seo-rii/maki/pull/412) at `627d3cc`. AUD-205 (#410)
lets detach and cleanup wait for a held-open device without the global attach
lock, so that the stop-time cleanups of many volumes no longer queue on it
(part of the list's fourth item). AUD-206 (#414), the first item, makes the
gRPC transport reach the other address family within a `timeout` under 600 ms
and tests the connect behaviours that had been read from the code; the HTTP
transport cannot do the same under reqwest, and the owner chose to keep
reqwest, document the limitation and warn about such a `timeout`. AUD-207
(#411), the second and third items, makes attach compare a remote-protected
volume's configuration before it claims a writer, bounds a remote read-only
view's inspections to three or four per command, and tests the view on volumes
that hold data. AUD-208 (#413), the fourth and fifth items, has CI's
`kernel-lifecycle` job reach cleanup's disconnected recovery, stop the
first-volume block partway and continue it, and stop three volumes together.
AUD-209 (#412), the seventh, boots Debian 12 and Rocky Linux 9 guests in CI
and runs the guides and the privileged runner in them. AUD-210 (#415), the
sixth, adds a dispatched workflow for the 24 CPU-hour fuzz qualification,
whose first 24 CPU-hour campaign had not finished when this was written and
had already failed both of `nbd_handshake`'s shards at libFuzzer's memory
limit. The eighth item, that `v0.1.0-rc.2` predates the round before, stands.
Notes in that list and in the rows of AUD-194, AUD-197, AUD-199 and AUD-201 to
AUD-204 say what each changed. None of these items had lost or corrupted data.
Each row's **Behaviour change** states what the code did before. Every fix
landed after a test commit that failed without it, with these exceptions:
#414's gRPC change, whose test needs the IPv6 loopback address that its
author's host lacked, so its failure before the fix was read, not seen, and it
first ran on GitHub with the fix (the unit test of the new delay came with the
function); #411's last fix (`07fdb34`), which added two variants to the probe
test of its test commit because the function they call is new there; and three
commits to the CI tools of #413 and #415 without a failing test of their own:
`f933c7c`, which kept the program writer's loop that emits each step as it was
and required `dmsetup` only with `--kill-daemon`, and changed no test, and
`245a3c8` and `bc144d9`, each with its test change in the same commit. Other
fix commits also adjust the fixtures or expectations of the tests before them.
AUD-205, AUD-207 and AUD-208 are **Fixed**. AUD-206, AUD-209 and AUD-210 are
**Partial**: the HTTP transport keeps its 300 ms, the guests are virtual
machines rather than bare-metal hosts and the EL9 one runs Rocky Linux, not
RHEL, and the campaign has not finished and cannot qualify `nbd_handshake`. No
change alters a record format or a golden vector. The operator-visible changes
are listed in the [changelog](../CHANGELOG.md#changed).

Every pull request had an independent review before it merged, four were
blocked at least once, and none of the findings concerns code that was already
on `main`. The review of #415 blocked on one false claim: the pull request, a
workflow comment and a test comment said that a fuzz shard's record is written
when GitHub interrupts the step, but the runner signals only the step's own
process, which was bash, and bash does not pass the signal on; the test had
signalled the Python process directly (AUD-210). The first review of #411
returned MERGE with six points, the first of them that a read-only command
asked the authority again before it reported what it read but not before it
reported a failure, as SPEC §27 required; its delta review blocked on the same
rule for a failure that stops the view, a page that no longer authenticates,
which was still reported without asking; the second delta review returned
MERGE and left one note open (AUD-207). The review of #413 blocked because the
pull request's merge of `main` with #410 had replaced the two cleanup dispatch
tests and lost a third that both parents had, and because the status page said
that no stop together with #410 had been recorded while one had passed; its
notes also found the release by hand checking the identifier the device showed
against itself (AUD-208). The review of #412 blocked on three false statements
(the README's "CI checks the userspace only" for RHEL 9, two sentences of the
pull request's text, and a label check described as wider than it was), and a
delta review on two wording errors, which the coordinator corrected (AUD-209).
The reviews of #410 returned MERGE, but one of the first review's six notes
was a defect of the change: a wait ended by a replacing attach's new
connection to the same device failed with "disconnect has not completed",
whose advice, a cleanup, would have torn the new attachment down (AUD-205).
The reviews of #414 returned MERGE with notes (AUD-206). Four defects that
were already on `main` came to light in the round: the scheduled `fuzz` job's
`-max_len=4096` cut `nbd_netlink`'s 16,392-byte seed (AUD-210); the RHEL
guide's `rpm -q nbdkit-selinux` failed its install block when the module is
absent, as the guide expects (AUD-209); the privileged runner's wait for its
opener used `kill -0` on the PID of a process that sudo had started, which the
first Debian 12 guest run caught (AUD-209); and the `nbd_handshake` target's
entry function spawns a thread for every input, which, by the coordinator's
measurements, makes a process built with AddressSanitizer grow with its
executions, so every `nbd_handshake` process of the 24 CPU-hour campaign ran
out of memory (AUD-210). CI also found the stop together's driver reading
systemd too early and then after systemd had forgotten the units (AUD-208),
and, after #412 merged `main` with #413, one of #412's tests relying on a real
`sleep` that #413's test harness stubs out (AUD-209). Every pull request's
checks passed at the head that merged (`eb9d850`, `aff8126`, `2c0f40c`,
`07fdb34`, `a2db40e`, `45f9e83`), both Windows jobs among them; these results
are the coordinator's records. The `nightly-gates`, `fuzz` and
`etcd-qualification` jobs run only on the schedule, on dispatch and on
`review/integration-*` pull requests, so they ran on none of the six, and no
push run on `main` or dispatch of the whole workflow after these merges is
among the coordinator's records.

The `kernel-lifecycle` job ran #413's new steps on GitHub's runner VMs at
`a6c2006` (run 45963474039), `f933c7c` (run 45964165633), `8b9ef4d` (run
45969555304), `31b7ef8` (run 45976243048, the merge of `main` with #410) and
`a2db40e`, the head that merged (run 45985806469); the logs of all but the
first are kept, and the figures below are from them. The four used the
`ubuntu-26.04` image with systemd 259, nbdkit 1.46.2 and lvm2 2.03.31, in
version 20261116.202.1 with Linux `7.0.0-1020-azure`, except the run at
`8b9ef4d`, on an AWS-hosted runner with version 20261116.88.1 and Linux
`7.0.0-1016-aws`. #413's text gave Linux `7.0.0-1020-azure` for its runs at
`a6c2006`, `f933c7c` and `8b9ef4d`, the status page and the runbook for those
and the one at `31b7ef8`, and the testing guide for the job's runs with these
steps, without naming them; none of them named the run at `a2db40e`. This
records change scopes the kernel to the runs whose logs are kept. In each the
privileged runner ended `RESULT: PASS (45 checks)`. The detach with the opener
exited 0 after 2212, 2197, 2700 and 2191 ms. After the first kill of nbdkit
cleanup logged that the device showed the attachment's connection and took the
detach path (1106 to 1168 ms). After the second, `kernel-disconnect` was
acknowledged, the device still showed the connection's backend identifier with
XFS mounted on the LV and after the unmount by hand, and showed none once the
LV's mapping was removed; cleanup then logged disconnected recovery, exited 0
after 12 to 18 ms and left nothing, and a fourth attach and the final detach
followed. The quick start and both stopped quick starts ended with `every
documented step succeeded`; the stopped ones printed the shim's `mkfs.xfs:
failed once by documented_quickstart.py` before `Bootstrap stopped at line
191`, and its `vgchange: …` line before `Bootstrap stopped at line 211`. The
stop together of three volumes, each device held 10 s after its disconnect,
failed at `f933c7c` and `8b9ef4d` on its driver's reading of systemd, and
their journals show the stops queued on the global attach lock, before #410:
they began within 0.02 s of each other and ended about 10.2, 20.3 and 30.5 s
after. At `31b7ef8` and `a2db40e`, with #410, the stops took 10.183, 10.246
and 10.310 s, and 10.209, 10.153 and 10.214 s, every attach unit having
stopped 10.388 and 10.488 s after the request.

#412's guest jobs booted their guests under KVM on the runner VMs (Linux
`7.0.0-1020-azure` in every guest job's log kept): Debian 12 with Linux
`6.1.0-54-amd64` (Debian 6.1.190-1), systemd 252.39, nbdkit 1.32.5 and lvm2
2.03.16, and Rocky Linux 9.9 with Linux `5.14.0-741.22.1.el9_9`, systemd 252,
`nbdkit-server` 1.38.5, lvm2 2.03.33 and `selinux-policy-targeted` 38.1.86,
enforcing. In the first run (45963320112, at `9b3beb5`) both guides suites ran
every step, on Rocky its 14, after which `getenforce` printed `Enforcing`, no
AVC or SELinux error was recorded since boot, the nbdkit of
`maki@demo.service` and the helper of the attach unit had run in
`unconfined_service_t`, and every label then checked matched the guide; the
Rocky runner passed with 35 checks, and the Debian runner failed after 23: its
wait for the opener ended at its first look, on a refused `kill -0`. With the
wait reading `/proc` (run 45971009031, at `279181a`) all four guest jobs
passed, as the coordinator records; the one log of that run that is kept, the
Debian runner's, shows 36 checks and a detach that waited 2265 ms. At #412's
merged head (run 46003496455, at `45f9e83`, with #413) the runners passed with
45 checks on Debian and 44 on Rocky, each taking cleanup's detach path after
the first kill and its disconnected recovery after the second, with the device
showing the connection with XFS mounted and after the unmount and none once
the mapping was removed; on Rocky SELinux was still enforcing, auditd was
active and no AVC or SELinux error was recorded. That run's guides logs are
not kept; the coordinator records that they passed. #414's first run
(45965982844, at `18c734d`) ran, in `pr (ubuntu-latest)` with
`MAKI_TEST_REQUIRE_IPV6=1`, the two HTTP and two gRPC tests that need the IPv6
loopback address, the gRPC dead-address test within one family and the
WebSocket connect tests, all passing, and in its root step, which reported `27
of 27 targets passed as root`, the packet-drop test in a private network
namespace. After #415 merged, the coordinator dispatched
`fuzz-qualification.yml` on `main` at `c2c46c7` with `cpu_hours=0.1` (run
45978498661), and it succeeded. Its summary planned one shard of 4 processes
per target, each to be charged 90 CPU seconds within 18,000 s, and reports for
each of the 16 targets 0.14 to 0.17 CPU-hours charged and 0.17 process-hours,
from 984,180 executions (`nbd_handshake`) to 141,035,497 (`format_decoders`),
no input that a process stopped on, and the verdict qualified for that
request; its shards ran on runners with five CPU models and Ubuntu's `-azure`
and `-aws` kernels. The 24 CPU-hour campaign was dispatched next, on `main` at
`32efe0b` (run 45983119347, `shard_hours=5`, `max_parallel=16`, 32 shards),
and had not finished when this was written. At the coordinator's check at
14:26 UTC on 2026-11-27 both `nbd_handshake` shards had failed, and 16 shards
of the second wave were still running; no other shard's result is recorded
here. By the two shards' records (`fuzz-stats-nbd_handshake-1` and `-2`), each
of their 4 libFuzzer processes ended in its first round with status 71 and
`ERROR: libFuzzer: out-of-memory (used: 2049Mb; limit: 2048Mb)` (2050Mb for
two of them), after 10,042,005 to 10,433,159 executions and 5,688 to 8,803 of
its 10,800 CPU seconds, at coverage 337 and 580 to 582 features, on a runner
with an AMD EPYC 7763, image 20261122.9.1 and Linux `7.0.0-1020-azure`. Among
the 8 inputs they stopped on (`fuzz-crashes-nbd_handshake-*`) is the empty
one, so memory grew with the executions, not with an input. The summary fails
unless every target qualified, so this campaign cannot qualify
`nbd_handshake`; the coordinator's measurements of the cause are in the open
list. GitHub's hosted runners are virtual machines, so none of these runs was
on bare metal, and Rocky Linux is a rebuild of RHEL, not RHEL.

#410 reports the `maki-privileged` unit suite (346 passed and 1 ignored at its
last code head) and its 19 integration targets (97 passed), `maki-attach`
(73), its test binaries replayed as uid 65534 with an empty `/run`, and its
eight new tests 40 times in a row with four test threads, all on the crate's
fake system with real `flock`s. #414 reports `maki-crypto-http` (199),
`maki-format` (335), `maki-crypto-grpc` (166), `maki-nbdkit` (343) and `maki`
(100) on stable 1.97.0 as root, and its connect tests as uid 65534; its host
has no IPv6, so the four IPv6 tests skipped there and their mutations were not
run. #411 reports `maki-backing` (431), `maki` (109), `maki-witness` (66),
`maki-nbdkit` (345) and three `maki-core` files (22) as root with
`MAKI_TEST_REQUIRE_NBDKIT=1` and `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, its
five changed or new test binaries as uid 65534, and the two etcd gates in
three runs with the digest-checked etcd v3.6.5. #415 reports the Python
suites, the `maki-fuzz-harness`, `maki-witness` and `maki-privileged` test
binaries as uid 65534, real libFuzzer runs of `helper_sysfs` and
`nbd_handshake` with one process, the only two targets it built, and the s390x
replay under `qemu-s390x` 8.2.2. #413 reports `maki-privileged` (443) and
`maki-attach` (73) and the Python suites; its host has no `/dev/nbd*`,
`modprobe` or systemd as PID 1, so its kernel steps first ran on GitHub. #412
changes no Rust; it reports the Python suites and booted both pinned images on
its host under TCG (it has no KVM) through boot, copy-in, facts and finish,
which found three faults, all fixed. Each pull request that changes a crate
reports strict Clippy on 1.94.0 and 1.100.0 for each one, and every one
reports fails-before runs of its test commits, mutation checks, the Python
suites and the link checker. Every mutation reported was caught by a committed
test, some only once a test had been added, apart from four: #414's removal of
the gRPC delay's call, which only the IPv6 test covers and which was not run
where that test runs; #414's dropped provider check in the HTTP warning,
equivalent since validation refuses `[crypto.http]` for any other provider;
#415's interruption of the merge's leader rather than its process group, which
it found equivalent; and the first-volume block's mountpoint `! -L`, which
#413 argues equivalent on Linux (AUD-208). None reports a run of the
workspace-wide suite or of the release gates, a Windows run outside CI, a
remote provider on a kernel device, or a real power loss.

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-205 | Since AUD-197 ([#398](https://github.com/seo-rii/maki/pull/398)), after its disconnect a detach or cleanup waits up to 15 s, looking every 100 ms, for the device to let go of the connection while something holds it open (`exec::await_release`), and it waited holding the global attach lock (`/run/maki-attach/attach.lock`). When many volumes' devices are held open and the volumes stop together, their stop-time cleanups queued on that lock for 15 s each, and from about the eighth on reached the attach unit's `TimeoutStopSec=120`, the later ones before they had changed anything (the second follow-up round's open list, fourth item). On the test commit `0665927`, on the crate's fake system with real `flock`s on a temporary state directory, each of the seven sleeps of a detach's wait found the lock held, and of two volumes torn down on two threads, each device letting go only once both had been disconnected, the first waited out its 150 looks holding the lock while the other was queued for it (seen in `/proc/locks`) and failed with "disconnect has not completed". On a kernel, #413's runs before this change measured the queue: three held-open stops that began together ended about 10.2, 20.3 and 30.5 s later (AUD-208). | A refactoring (`92fb8e0`) has `execute` and `cleanup` open the attach state and call `execute_on` and `cleanup_on`, which take its lock for the run before any record is read; `recover` takes it itself, and `AttachLock` and `lock_attach`, which nothing else used, are removed. The run's lock is a `Turn`: held by the run itself (`Turn::Held`) for detach and cleanup, or by the caller for the whole run (`Turn::Kept`) for the failed-start hook's rollback, whose 30 s for commands count from when it got the lock and whose bounds (15 + 40 + 30 s) leave no room for a second turn, and for the tests that hold the lock themselves. `await_release` calls a `waiting` callback before each sleep, where a held turn lets go of the lock, so a first look after the disconnect that shows no connection or another backend identifier keeps the lock and reads nothing again. A wait that ends with this connection still shown, or with a backend that cannot be read, fails as before without taking the lock again. One that ends with no connection or another identifier takes the lock again, in turn (a blocking `flock`; the released `StateLock` unlocks before it closes), and reads the volume's record again (`record_after_wait`): the record it disconnected goes on to the unchanged final teardown checks, or, beside another connection, fails with "disconnect has not completed"; no record, which another helper of the volume removes only once nothing of the attachment remains, ends the run as a success with an `INFO` line that says so; another record fails the run with "the volume's attach record was replaced while this helper waited for … to let go of the disconnected connection: another helper attached volume … again. That record and its attachment are left as they are". The pull request's case that this is safe: during the wait the volume is already unmounted, its VG deactivated and its device disconnected, the helper runs and writes nothing, and the record still names the device, so other volumes' attach and `nbd-connect` leave the device alone (SPEC §8) and their other verbs act on their own records; a helper of the same volume, which only an operator's command is, finds what a helper killed during its wait leaves, which every verb already handles. A per-volume lock was not chosen: every verb and the hook would need one lock order, and the re-read is needed anyway after a kill. The first review returned MERGE with six notes. One was a defect of the change: while the wait had let go of the lock, an operator's `attach` of the same volume could replace the record and, once the device showed no connection, connect the same device under its own identifier; the wait then ended at a look that showed it and failed, without the lock, with "disconnect has not completed; keeping the attach record for cleanup retry", and a cleanup run on that advice would have torn the new attachment down. Such a wait now takes the lock again and reads the record (`7876689`, `472fedf`). The other notes put the change for another volume's attach during the wait into the documents, the trap's citation of `recover_tests.rs`, and clearer wording in the man page and the operations guide. The delta review's two notes brought a test of a record retired beside another connection (`e193025`) and the rule, in the documents, that the lock is taken again only after a wait that let go of it (`5d27d67`), and after a last check the coordinator corrected SPEC §6's "whatever the device shows", untrue for a backend that cannot be read (`eb9d850`). SPEC §6, maki-attach(8), the operations guide (its prerequisites, the privileged helper and the paragraphs on many volumes stopping together), the storage recovery guide, the status page, the testing guide and the development guide's NBD trap say so. **Behaviour change:** when many volumes stop together with their devices held open, each cleanup holds the lock only for its own steps (the unmount, the VG deactivation and the disconnect) and the checks before the record is retired, the waits run side by side, and no cleanup waits for another volume's opener; a device held open for the whole 15 s still fails its own cleanup 15 s after its own disconnect, the volume torn down and only the record kept. A cleanup that waited has a second turn on the lock, behind every helper that took it meanwhile, an attach of another volume included (up to its 180 s start timeout), and systemd can end it there, after its volume is torn down; before, the stop timeout ended later cleanups in their first turn, before they had changed anything. How long the steps still taken one at a time last on a host is not measured, so how many volumes can stop within 120 s is not known. During a detach's wait an `attach` of the same volume is refused while the device shows the connection, where it waited for the lock and went on from what the detach had left, and once the device lets go it may replace the record, after which the waiting command fails as above; a `cleanup` or `recover` of the volume retires the record, and the waiting command then succeeds. Another volume's attach pinned to that device is refused at once ("… is named by the attach record of volume …"), and an automatic one for which it was the last free device fails with no free NBD device, where both waited for the lock; run them again once the detach has finished. The first-volume block's `flock -n` now gets the lock during such a wait instead of stopping, and `nbd-connect` still refuses the device. The failed-start hook is unchanged, and its 40 s lock wait now queues behind other helpers' steps, not their waits. A detach or cleanup whose device shows no connection at the first look keeps its one turn. `maki_privileged::exec::AttachLock` and `lock_attach` are gone from the crate's API. | maki-privileged `review_release_wait_lock.rs` (the crate's fake system, real `flock`s): `a_teardown_waits_for_a_held_open_device_without_the_attach_lock`, `teardowns_of_two_held_open_devices_wait_side_by_side`, `a_record_replaced_during_the_wait_is_kept` and `a_record_another_helper_retired_during_the_wait_ends_the_run`, which failed before (339 passed and 4 failed on the test commit), `a_device_that_lets_go_at_once_keeps_the_teardowns_one_turn`, added after the fix as the only test that a release before the first look fails, and from the reviews `a_device_connected_again_for_a_replaced_record_ends_the_wait_as_replaced`, which failed on the first fix, and `a_record_retired_during_the_wait_ends_the_run_beside_another_connection`; `recover_tests.rs`: `the_failed_start_rollback_keeps_the_attach_lock_through_its_wait`; the existing wait tests and the step-fault sweeps now run through `execute_on` and `cleanup_on`. On a kernel, #413's stop together (AUD-208) | [#410](https://github.com/seo-rii/maki/pull/410) |

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-206 | AUD-201 left every remote transport losing time to a dead address (the second follow-up round's open list, first item). The HTTP transport, whose connector reqwest builds, kept hyper-util's 300 ms before the other address family, so with an HTTP `timeout` of 300 ms or less the other family was never tried while the first did not answer, and below 600 ms it had less than half of the time. The gRPC provider builds that connector itself and left the delay at 300 ms too, so, read from the code, a gRPC call with such a `timeout` whose first family did not answer failed, retryable and unsent, and only a later call could be served by the other family. The HTTP 300 ms, a single-address host keeping the whole `timeout`, reqwest's bound over resolution and TLS and the gRPC connector with a dead address had been read from the code, not tested; that attach sends nothing to an endpoint before the configuration comparison was tested for the HTTP provider only (third item); and no route that drops packets had been used. The pull request read hyper-util 0.1.20 (`HttpConnector::new_with_resolver` sets 300 ms and only `set_happy_eyeballs_timeout` changes it), reqwest 0.12.28 and 0.13.5 (neither calls it outside the HTTP/3 client) and the gRPC provider; its test of the gRPC delay needs the IPv6 loopback address, which the author's host lacked, so the failure before the fix was read, not seen. | **Partial.** The gRPC connector now waits `min(300 ms, timeout / 2)` before it dials the other family (`other_family_delay`, passed to `set_happy_eyeballs_timeout`), the WebSocket transport's rule as one fixed value, since hyper-util takes one delay for every connect, set when the provider is built: half of the call's `timeout`, counted from the dial, after resolution. For HTTP the pull request found no sound way under reqwest: `dns_resolver` and `resolve_to_addrs` choose and order the addresses, but the connector still splits them by family; a shorter `connect_timeout` is also a single address's whole share and reqwest's bound over the whole connect (that mutation fails 7 of the 9 HTTP connect tests); a `connector_layer` service can read the URI through `Unnameable`'s `Debug` but must return reqwest's `Conn`, which it cannot build, so it can only pass reqwest's own connect on; `local_address` drops the other family; IPv4-mapped IPv6 addresses need dual-stack sockets; two clients raced per family could both send a request that is not retry-safe; and a resolver that dials both families itself costs an extra connection per connect and still races reqwest's own. What would work, a change to reqwest or an HTTP client of Maki's own on hyper-util, the owner chose not to do: the HTTP transport keeps its 300 ms, documented and warned about. `VolumeConfig::warnings` (maki-format) lists settings that are valid but serve badly, and refuses nothing; its first is a `remote-http` `[crypto.http] timeout` under 600 ms (`HTTP_SHORT_TIMEOUT`): "[crypto.http] timeout is 300ms: while the first address family of an endpoint's host does not answer, the other family gets less than half of a timeout under 600 ms and is never tried at 300 ms or less, so such a host can fail every connect". `maki volume create` prints it to stderr after the volume is created, `maki check` and `--deep` add it to their report as a `warning:` line, and attach logs it at the warning level once the configuration matches the volume, before any endpoint is asked. New tests pin what had been read: a single-address HTTP host, a resolver that never answers and a TLS peer that never answers each end at the `timeout` as a request timeout, retryable and not marked unsent; with the IPv6 loopback address, HTTP dials IPv4 at 300 ms with a 400 ms `timeout` and never with 300 ms, and gRPC gives way to IPv4 after 300 ms with 10 s and at 100 ms with 200 ms, serving that call; a gRPC dead address before a live one of its family costs its share. A gRPC test resolver (`test_resolver::TestResolver`; hyper-util's `GaiResolver` outside tests) and a private `build_resolving` give those tests their addresses. As root, a thread unshares its network namespace, brings `lo` up, drops every SYN to 127.0.0.2 with `nft`, or `iptables` where `nft` is missing or fails, shows that a connect there times out instead of being refused, and requires the live address after it to serve once the first share has run out; without root the test skips, and as root it fails when neither program installs the rule. WebSocket and gRPC attach get the HTTP test's counterpart: a volume another provider created, a recorded key identity and a changed compatibility id are refused as an identity mismatch naming both values, with no connection accepted by the endpoint. The workflow sets `MAKI_TEST_REQUIRE_IPV6=1`, so the IPv6 tests fail in CI instead of skipping, and `scripts/run_root_tests.py` passes it on and runs `maki-crypto-http`'s unit tests as root. The review returned MERGE with six notes, among them the `connector_layer` reason, which had missed `Unnameable`'s `Debug`, a warning that says when its condition holds (`a59895a`, `326222a`) and the `iptables` fallback (`1ec866c`); the delta review returned MERGE with two notes on the pull request's text, which the coordinator corrected. The configuration guide, the status page, the operations guide, maki(8), the testing guide, the architecture page, the development guide's AUD-193 trap and two source comments say so. **Behaviour change:** over gRPC with a `timeout` under 600 ms the other family is dialed after half the `timeout` instead of 300 ms, so a call whose first family does not answer can be served by the other one (at 300 ms or less such a call used to fail), and a first family slower than half the `timeout` has an attempt on the other beside it; nothing changes at 600 ms or more, or over WebSocket. Over HTTP nothing changes on the wire, and a `remote-http` configuration with a `timeout` under 600 ms gets the warning from `volume create`, `check` and attach; it is still accepted, and the check's verdict and exit status are unchanged. For developers, the HTTP and gRPC tests of the other family fail without the IPv6 loopback address wherever the workflow runs them, and the root-only step creates a network namespace and installs a packet filter rule in it. | maki-crypto-grpc `connect_tests.rs` (Linux, paused time, a tonic server that records each accept): `with_a_short_timeout_the_other_family_starts_halfway_and_serves_the_call` (IPv6; its failure before the fix read, not seen), `a_dead_ipv6_address_gives_way_to_ipv4_after_300_ms` and `a_dead_address_before_a_live_one_of_its_family_costs_its_share`, and in `lib.rs`, on every platform, `the_other_family_waits_300_ms_or_half_of_a_shorter_timeout`; maki-crypto-http `connect_tests.rs`: `a_host_with_one_address_keeps_the_whole_timeout`, `a_resolution_that_never_returns_ends_at_the_request_timeout`, `a_tls_peer_that_never_answers_ends_at_the_request_timeout_unmarked`, `below_600_ms_the_other_family_starts_after_300_ms_and_has_less_than_half`, `with_a_timeout_of_300_ms_the_other_family_is_never_dialed` and, as root, `a_route_that_drops_packets_leaves_the_next_address_its_share`; maki-nbdkit `review_config_identity_attach.rs`: `a_websocket_endpoint_is_not_connected_to_for_a_configuration_the_volume_refuses` and `a_grpc_endpoint_is_not_connected_to_for_a_configuration_the_volume_refuses`; `review_http_timeout_warning.rs` in maki-nbdkit (`maki_check_warns_about_an_http_timeout_under_600_ms`, `attach_warns_about_an_http_timeout_under_600_ms`) and in `bins/maki` (`create_and_check_warn_about_an_http_timeout_under_600_ms`), which failed before; `scripts/test_root_tests_validation.py`: `test_every_job_requires_the_ipv6_loopback_address`. The IPv6 and root-only tests in run 45965982844 (above) | [#414](https://github.com/seo-rii/maki/pull/414) |

### Rollback protection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-207 | The second and third items of the second follow-up round's open list. With remote rollback protection, attach compared the configuration with the superblock only after `RollbackBacking::open_remote` had opened the backing to write, which claims a writer at the authority (`Action::Claim`) and copies the current generation into a namespace of its own, where the volume is then recovered (AUD-194); a remote provider built on its own (`build_provider_with_endpoints`, which recovers the volume to probe its endpoints) did the same. On the test commit, with a real TLS witness server that records each request's action, an attach refused for another compatibility id sent 174 requests (one `claim`, one `activate`, ten `advance`s, one `release` and 161 inspections), and the claim raised the authority's fence and replaced its session and current namespace; a superblock page that does not authenticate was found only by the copy into the claimed namespace (`source page authentication failed`). The read-only view of AUD-202 asked the authority before every backing operation, each time over a TLS connection of its own: on a 1 MiB volume written through the daemon's NBD adapter, `volume inspect`, `check` and `check --deep` sent 9, 37 and 174 inspections with 8 units written, and 9, 58 and 328 with 64. The view had been run only on volumes without data slots, the refusal of a snapshot destination was read from the code, no read-only `maki check` of a protected backing with a mismatched configuration had run, and no etcd-backed authority had been read through the view. | `RollbackBacking::open_remote_checked(root, rpc, check)` is `open_remote` with a check where the claim would be sent: with the root's operation lock held exclusively, after the open's one inspection, once `holds_current` has authenticated the authority's current generation in the root, and only while the authority is released (an occupied one refuses the claim first, as before). The check gets a `ReadOnlyRollbackBacking` that the new `before_claim` builds from the manifest `holds_current` decoded: it reads only what the check reads, each page authenticated against that manifest, holds no lock, asks the authority nothing and changes nothing, and what the check refuses is returned before the claim. `open_remote` is `open_remote_checked` with a check that accepts, so on a released authority every caller builds that view, which opens the arena once more and reads its size. `maki-nbdkit`'s attach and the provider-only path of `dispatch_endpoint_set` open through `build_backing_to_attach`, whose check (`refuse_before_claim`) refuses a configured `backing.rollback_protection.capacity` that differs and then reads the two superblock copies (`load_volume_superblock`) and refuses the first mismatch with attach's own comparison and errors (`refuse_configuration_mismatch`); a read that fails is refused there too, and a generation without a valid superblock is left to recovery, after the claim, as before. Attach compares again after recovery. A normal attach with a remote witness sends no request and takes no lock more than before, and reads at most two 4 KiB pages more, each with its SHA-256 page digest. A remote read-only view now asks its authority while it opens (twice, as before) and in `Backing::check_freshness`, and a record that differs from the one it opened on stops it for good; a local witness is still read before every operation. `maki`'s `check` and `inspect` ask once they have read everything, before they print their report (`still_current`), and the deep check also before its verdict, so `volume inspect` and `check` send three inspections and `check --deep` four, whatever the volume holds. The pull request's argument that this keeps SPEC §27's freshness rule: while the view is open its shared locks keep out every operation that changes the root, every read is authenticated against the manifest it opened on, and the authority's record never takes an earlier value again (a claim raises the fence, an activation or a release moves the phase on within it, an advance raises the generation), so a record that is equal at the end was equal at every read in between. What the bound gives up: a command whose authority changed reads to the end before it fails, and a transient failure to reach the authority matters only while the view opens and at the last inspections. The first review returned MERGE with six points: a read-only command asked the authority before it reported what it read but not before it reported a failure, as SPEC §27 required; SPEC §20's new rule named too much; the guides gave one of a snapshot destination's two refusals; a sentence of the pull request's text was false; the view built before a claim logged a stopped read-only session; and the `etcd-qualification` job should run its ignored gates one at a time (on the author's host the existing quorum test had once failed at startup right after the new one in the same process). Now `open_remote` asks once more before it reports a failure met after its second inspection, `maki_nbdkit::daemon::read_failure` does the same for a failure through any backing that `build_backing_to_read` opened, SPEC §20 says that attach "MUST NOT claim a writer for a configuration that this comparison refuses" and names what is still found after the claim, the guides give both refusals, the pre-claim view logs no stop (`View::logs_stop`), and the job runs `--test etcd_ha -- --ignored --test-threads=1`. The delta review blocked: a failure that stopped the view (a committed page that no longer authenticates, an arena read that is short or missing) was reported without asking, since a stopped view answered `check_freshness` without a request, so a takeover made after the open went unreported. `Backing::ask_witness_again` (by default `check_freshness`) now answers `WitnessAnswer::Selects`, `Stopped(reason)` or `Unanswered(error)`, `ReadOnlyRollbackBacking` asks also once it has stopped on what it read, and `read_failure` and the CLI's last inspection, now `maki_nbdkit::daemon::still_current`, report the witness's answer instead of the failure and name an authority that cannot be asked beside it. The second delta review returned MERGE: `ask_witness_again` only chooses an error message, and no writer gains a new path to its witness; one note stays open (below). SPEC §20 and §27, the configuration, operations and remote witness guides, maki(8), the status page and the testing guide say so. **Behaviour change:** with a remote witness, attach and a remote provider built on its own refuse a configuration whose immutable settings or protected capacity do not match the authority's current generation before they claim a writer, after one inspection, with the authority's record and the root unchanged and the error attach gave after recovery; a superblock page that does not authenticate is refused there with `rollback arena page authentication failed`, with nothing claimed. An authority that a writer holds still refuses the claim first. `maki volume inspect`, `maki check` and `maki check --deep` of a remote-protected volume send three inspections (four for `--deep`) instead of one per backing operation. An authority that changes while one of them reads fails it at the end, before its report (`the remote authority changed after the backing was opened read-only`), where it failed at the next operation, and a command that fails after the open reports the authority's change instead of its own error, or names an authority it could not ask beside it. Operations of the view other than `check_freshness` no longer ask a remote authority. No format, configuration or exit status changes. | maki-nbdkit `review_remote_attach_comparison.rs` (a recording TLS witness): `a_mismatched_configuration_is_refused_before_a_writer_is_claimed`, `a_remote_provider_built_on_its_own_compares_before_the_claim_too` and `a_superblock_page_that_does_not_authenticate_is_refused_before_the_claim`, which failed before, and `an_occupied_authority_keeps_the_claim_refusal`; `bins/maki` `remote_admin.rs`: `a_remote_volume_holding_data_is_read_with_three_inspections_per_command` and `a_damaged_data_slot_of_a_remote_volume_is_an_error_read_only`, which failed before, `a_mismatched_configuration_fails_a_read_only_check_of_a_remote_volume`, `a_configuration_pointed_at_a_snapshot_destination_is_refused_read_only` and `an_authority_that_changes_while_a_command_reads_fails_the_command`, and from the reviews `an_authority_that_changes_before_a_command_fails_is_reported_instead`, which failed on `018d702`, and `a_view_stopped_by_a_page_still_asks_the_authority_before_the_failure_is_reported`, which failed on `654d2b2`; `review_read_only_backing.rs`: `a_protected_volume_holding_data_is_checked_read_only`, `a_damaged_data_slot_of_a_protected_volume_is_an_error_read_only` and `a_mismatched_configuration_fails_a_read_only_check_of_a_protected_volume`; maki-backing `review_read_only_rollback.rs`: `a_writable_remote_open_runs_its_check_before_the_claim`, `a_remote_read_only_view_asks_the_authority_only_when_asked` and `an_authority_that_changes_after_a_remote_read_only_open_stops_the_view`, the last two of which failed before, `a_witness_that_changes_after_a_read_only_open_stops_the_view`, and from the reviews `a_remote_read_only_open_that_fails_reports_an_authority_that_changed`, `a_view_read_before_a_claim_logs_no_stopped_read_only_session`, `a_remote_view_stopped_by_a_page_asks_its_authority_again` and `a_local_view_stopped_by_a_page_reads_its_witness_again`; maki-nbdkit `review_read_only_daemon_volume.rs` (nbdkit serves the plugin while `nbdcopy --flush` writes 64 KiB, then the view reads the local and the remote volume: `slots: 16 allocated, 0 invalid`, verdict `unproven`); maki-witness `etcd_ha.rs` `a_remote_volume_on_an_etcd_quorum_is_read_with_inspections_only` (ignored, three etcd members; the `etcd-qualification` job), which failed before with 5 inspections; `scripts/test_ci_gate_validation.py` `test_the_etcd_gates_run_one_at_a_time` | [#411](https://github.com/seo-rii/maki/pull/411) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-208 | The fourth and fifth items of the second follow-up round's open list. In both `kernel-lifecycle` runs of #406 the killed daemon's device still showed its connection when cleanup started, so cleanup took its detach path, and its disconnected recovery had not run on a kernel; nothing in cleanup's output named the path it took, and a disconnected recovery that finds nothing left runs no step and prints nothing. Several volumes stopping together with their devices held open had not been run. The first-volume block had run on a kernel only as a run that does not stop. No real `lvm fullreport`, `blkid`, `dmsetup info` or sysfs tree of an attachment had been kept for the helper's fuzz targets. The quick start's program writer did not see `&&` or `\|\|` lists below a block's level, where `set -e` does not stop at their failure either. Three first-volume mutations (`set -C` dropped where the staged configuration is written, the mountpoint's `! -L` dropped, `boot_id` dropped from a record's required values) passed `main`'s 27 provisioning tests. | `maki-attach cleanup` logs the path it takes before its first step, in `cleanup_in`, which both lock variants run. The privileged runner's `--kill-daemon` kills nbdkit again after the third attach (`kill_nbdkit`, `start_nbdkit`) and leaves the device showing no connection with the record in place: it reads the record and refuses one that names another connection or device; `privileged_validation_nbd.py kernel-disconnect --volume` sends `NBD_CMD_DISCONNECT` over generic netlink, under the attach lock, for the identifier the volume's record names on that device (`maki-<uuid>`, which the helper's own `nbd-disconnect` refuses); and only while the device still shows the connection does the runner unmount XFS and then `dmsetup remove` the LV's mapping, logging what the device shows after each step. Cleanup must then log disconnected recovery and leave nothing, and a new nbdkit and a fourth attach compare the data before the final detach; with `--kill-daemon` the runner needs `dmsetup`. After the first attach `scripts/privileged_validation_capture.py` captures, as root and read-only, with the helper's arguments, an environment of `PATH` and `LC_ALL=C` and 15 s each, LVM's `fullreport`, the two `blkid` probes, `dmsetup info`, `blockdev --getsize64` of the LV and `blkid -o value -s UUID` of the mount source (the first 64 KiB of each stream), the device's sysfs nodes in the `helper_sysfs` input's format and the mount table, into `helper-outputs.json`, which holds no key or payload. `documented_quickstart.py --stop-once mkfs.xfs\|vgchange` writes the program with the bootstrap's first run under a shim first on `PATH` that fails that command once; after `mkfs.xfs` the next run must release the export, stop `maki@demo.service`, remove its record and fail, the volume is reset as the recovery notes say and a third run starts over; after `vgchange` the next run must finish. `scripts/stop-together-validation.py` provisions `stop1` to `stop3` with the quick start's blocks, holds each device open with the opener (now `--hold`), stops the three targets with one `systemctl stop`, waits for each attach unit to stop, and reads when each stop began and ended from PID 1's journal; it fails after its report on a failed stop, an opener that did not see its disconnect or a leftover, and requires neither overlap nor a queue. The `kernel-lifecycle` job runs the two stopped quick starts and then the stop together, with a 10 s hold, once the quick start has succeeded, and its limit rises from 100 to 150 minutes. The program writer reads every line `declare -f` prints below a block's level, at any depth, and refuses one with `&&` or `\|\|` unless `DEEPER_LISTS` names it for that block: the guides' three such lines (`wait_stopped`'s two returns and the unmount check's `\|\| echo`), which a test requires the list to be exactly. New provisioning tests take a staged name of the record or of the configuration with a link or a file between the block's `rm -f` and its write, which must be refused with nothing written through, and refuse a record without `boot_id` or `volume_uuid`; the mountpoint's `! -L` is equivalent on Linux, since `stat -c %u:%a` does not follow a link and a link's mode is `0777`, so `0:700` never matches one, and it still passes the 28 provisioning tests. CI found the stop together's driver wrong twice: at `a6c2006` and `f933c7c` it read the attach units' timestamps when `systemctl stop` returned (after 0.032 s at `f933c7c`), before the units had stopped, and at `8b9ef4d` it waited, but systemd had garbage-collected each stopped unit and `systemctl show` loaded a fresh one whose timestamps were 0. The review blocked on two findings: the merge of `main` with #410 (`31b7ef8`) had replaced the two cleanup dispatch tests and lost `acknowledged_but_incomplete_disconnect_preserves_cleanup_authority_for_retry`, which both parents had and the development guide's NBD trap and this log cite (restored as `main` has it, `b661622`, after which every test function of both parents was found by file and name, apart from the two this pull request replaced), and the status page said that no stop together with #410 had been recorded while one had passed. Its notes found that the release by hand passed `kernel-disconnect` the identifier the device showed, so that check compared it with itself (`d27f5cd`, `69d3079`), that nothing pinned the path's line before the first step (`f264043`), that the documents said the mount keeps the attributes where the runs show only the mapping, and three wordings. The delta review returned MERGE with one note, the status page's 30.7 s for `8b9ef4d`'s queue, which is the driver's polling time where the journal shows 30.5 s, corrected by the coordinator (`a2db40e`). The testing guide, the status page, the operations guide, the runbook, maki-attach(8) and a development guide trap say so. **Behaviour change:** `maki-attach cleanup` writes one more `INFO` line to standard error, `<device> shows the attachment's connection; cleanup follows the detach path` or `<device> shows no connection; cleanup follows disconnected recovery`; nothing else in the helper changes. The privileged runner's `--kill-daemon` kills nbdkit twice, releases its device by hand once and needs `dmsetup`, and the program writer refuses a list below a block's level that `DEEPER_LISTS` does not name. | `crates/maki-privileged/src/exec_tests.rs`: `cleanup_dispatches_an_owned_connection_to_detach` and `cleanup_dispatches_a_known_absent_connection_to_recovery` (both lock variants, the path's line before the first step), which failed before with an empty log, and the restored `acknowledged_but_incomplete_disconnect_preserves_cleanup_authority_for_retry`; `scripts/test_privileged_lifecycle_validation.py`: `test_cleanup_must_take_the_path_for_what_the_device_showed`, `test_the_release_by_hand_stops_once_the_device_shows_no_connection`, `test_a_release_by_hand_that_leaves_a_connection_or_no_record_stops_the_run`, `test_only_the_connection_the_attach_record_names_is_released_by_hand`, `test_the_helpers_outputs_are_captured_as_root_into_the_run_directory` and the capture's `HelperOutputs`; `scripts/test_privileged_nbd_ownership_validation.py` (`KernelDisconnect`, `test_only_the_connection_the_volumes_record_names_is_disconnected` among them); `scripts/test_documented_quickstart_validation.py`: `StoppedBootstrap`, `test_lists_below_the_blocks_level_are_refused_at_every_depth`, `test_only_the_lists_read_for_a_block_are_accepted_below_its_level`, `test_the_allow_list_is_the_guides_lists_below_the_block_level` and `test_a_negated_or_a_background_command_is_not_seen` (the gap that remains); `scripts/test_stop_together_validation.py`, `test_the_stop_times_are_the_journals_for_the_stop_job_after_the_request` and `test_the_times_survive_the_units_garbage_collection_and_a_late_journal` among them; `scripts/test_docs_provisioning_validation.py`: `test_a_staged_name_taken_after_its_removal_is_never_written_through` and the records without a volume UUID or a boot ID in `test_a_record_that_cannot_be_read_is_refused_before_anything_runs`; `scripts/test_ci_gate_validation.py`: `test_the_stopped_quick_starts_and_the_stop_together_follow_the_quick_start` among others. The job's runs (above) | [#413](https://github.com/seo-rii/maki/pull/413) |
| AUD-209 | The seventh item of the second follow-up round's open list, and the support matrix's RHEL 9 row: nothing had run on a booted RHEL or Debian host, and RHEL 9 had never attached a kernel device or run under enforcing SELinux. On `b2d3bf9` `ci.yml` booted no guest (it named neither `qemu-system`, `cloud-init` nor `/dev/kvm`), the `rhel9` job ran in a CentOS Stream 9 container on Ubuntu's kernel, and the RHEL guide's SELinux section said "nothing was run with SELinux enforcing". The RHEL guide's install block ended with `rpm -q nbdkit-selinux   # expected: package nbdkit-selinux is not installed`, and `rpm -q` exits 1 for an absent package, so the block failed exactly when the module was absent, as the guide expects: with stand-ins for `dnf` and `rpm` its status was 1, and the program `documented_quickstart.py` writes would have stopped there. | **Partial.** Four jobs in `ci.yml` run on every event of the workflow, each step with a `timeout-minutes` and each job's limit above the sum of the limits of the steps one run executes. `debian12-package` builds the four packaged binaries and the package in `debian:12` with `dpkg-shlibdeps`, and `el9-package` the RPM in the CentOS Stream 9 container, as the release workflow does, each as version `0.0.0~ci` with its `source-revision` and `SHA256SUMS`. `debian12-guest` and `el9-guest` run on `ubuntu-latest` itself, with a fresh guest for each suite (`guides`, `runner`) and `/dev/kvm` opened to the runner user by a udev rule. `scripts/booted-host-validation.py` fetches the pinned image and checks its digest (Debian's generic image `debian-12-generic-amd64-20261112-2660.qcow2`, with Debian's standard kernel; Rocky's `Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2`, from `pub/rocky/9.9` and then the vault), which the job caches under a key of its pin with no fallback, and boots it under QEMU with `accel=kvm`, 2 vCPUs and 4 GiB on a 30 GiB qcow2 overlay, with a NoCloud seed that creates a key-only user `ci` with passwordless sudo and pins a host key made for the run; it reaches the guest over SSH on `127.0.0.1` only, with that host key alone, and runs each phase under `sudo timeout`. `scripts/booted-host-guest.py` runs each phase as root: `facts` (on EL9 it requires `getenforce` to print `Enforcing`, and never sets the mode), `prepare`, `guides` (the program `documented_quickstart.py` writes, with `--installation rhel` on EL9, beside the package; nothing of `demo` may remain), `runner` (the runner's tools, the package unpacked, `nbd` loaded, and `privileged-linux-validation.sh --kill-daemon --prebuilt DIR` run as `ci`), on EL9 `selinux` after either suite (enforcing, auditd active, no `ausearch` record that names `maki` or `nbd`, and after the guides the nbdkit of `maki@demo.service` in `unconfined_service_t` and the guide's labels on the binaries, `/usr/sbin/nbdkit`, the plugin, the five directories, the four unit files and `/dev/nbd0`), `versions` and `finish`, which collects logs, the journal, the audit log and the console without a key, a backing, the seed or a disk. Rocky Linux was chosen over AlmaLinux because it rebuilds RHEL's published sources unchanged. `privileged-linux-validation.sh --prebuilt DIR` runs copies of the given `maki`, `maki-attach` and `libmaki_nbdkit.so`, hashes them, records `artifact-origin`, and needs neither Cargo nor rustc. The RHEL guide's line is now `! rpm -q nbdkit-selinux`, with a sentence saying that it fails if the module is installed. The first run caught a defect of the runner that was on `main` since AUD-203: its wait for the opener tested the opener's PID with `kill -0`, and that PID is sudo's, which checks its policy with real, effective and saved uid 0 (sudoers' `PERM_ROOT`), so for that moment the invoking user may not signal it; the Debian guest's run stopped so at its first look ("the opener did not start holding /dev/nbd15"), and the wait now reads `/proc/PID/stat`, a zombie counting as gone (`8bd2daa`, `279181a`). After the third merge of `main`, which brought #413's fragment harness with `sleep` stubbed out, the wait's 200 looks took less than the test opener's real 0.3 s, and `pr (ubuntu-latest)` failed twice on that test (runs 45993876175 and 45995468328); the tests now count the wait's looks (`45f9e83`). The review blocked on three false statements: the README still said that CI checks RHEL 9's userspace only, two sentences of the pull request's text were false, and the label check was described as wider than it was (it now checks every unit file the package installs). Its notes brought the time limit inside `sudo`, two surviving mutations killed, auditd required, the boot step's limits and the image cache. A delta review blocked on two wording errors, which the coordinator corrected (`c233185`), and a last one after the third merge returned MERGE with a note the coordinator also took (`6fd03ce`). The README, both installation guides, the testing guide, the status page, the support matrix, the runbook and SPEC §55 say what the jobs run and that the guests are virtual machines on GitHub's hardware, not bare-metal hosts, and every one of them that names the Rocky guest says that Rocky Linux is not RHEL; they state no result. Nothing runs on RHEL itself, on bare metal or through a power loss. **Behaviour change:** none in the shipped binaries, units or packages. In the RHEL guide's install block the module check is `! rpm -q nbdkit-selinux`. The privileged runner accepts `--prebuilt DIR`, writes `artifact-origin` in every run and no longer signals the opener to see whether it runs; `documented_quickstart.py` accepts `--installation`. Every pull request runs six more job runs: two release builds and four guests. | `scripts/test_ci_gate_validation.py` (`BootedHostJobs`), `scripts/test_booted_host_validation.py`, `RhelInstallation` in `scripts/test_documented_quickstart_validation.py` (`test_the_install_step_stops_the_program_only_when_the_selinux_module_is_installed` among them) and `PrebuiltArtifactPath` in `scripts/test_privileged_artifact_validation.py`, which failed before (56 of the four modules' 109 tests); from the first CI run, in `scripts/test_privileged_lifecycle_validation.py`, `test_the_wait_does_not_signal_the_opener_that_sudo_started`, `test_an_opener_that_exits_before_holding_the_device_ends_the_wait_at_once` and `test_a_process_runs_until_it_exits_whoever_owns_it`; from the review `test_every_unit_the_package_installs_and_the_quick_starts_device_are_labelled`, `test_the_guides_phase_fails_with_the_program_and_with_what_it_left`, `test_nothing_is_collected_from_where_keys_or_backings_live`, `test_a_file_that_holds_a_private_key_is_never_packed` and the image cache's tests; after the third merge, the guest runner phase's `dmsetup` package and the RHEL program's list check at every depth (`9219a3a`). The guest jobs' runs (above) | [#412](https://github.com/seo-rii/maki/pull/412) |
| AUD-210 | The sixth item of the second follow-up round's open list (AUD-204): no fuzz run had reached SPEC §56's 24 CPU-hours per target, and nothing in the repository could run a campaign longer than the scheduled `fuzz` job's 30 seconds per target. The size limits of etcd's answer (256 KiB) and of the witness state (64 KiB) lay beyond the job's 4096-byte inputs, and checking every target against the bounds its readers check found a defect on `main`: the job passed `-max_len=4096` to `nbd_netlink`, and libFuzzer reads at most `-max_len` bytes of a seed (`FileToVector` in libfuzzer-sys 0.4.13's `FuzzerLoop.cpp`), so it cut the 16,392-byte seed `refused-lookup-datagram-beyond-the-buffer` to 4,096 bytes. No big-endian host had been used: the replay's big-endian path had only been compiled. A crashing `helper_sysfs` input left its tree in the temporary directory, which the pull request reproduced under real libFuzzer with a temporary assertion (exit 77, a crash file, and `maki-fuzz-sysfs-18493-181` left behind); a process ended at a timeout, at the memory limit or by a kill leaves its tree too. | **Partial.** `.github/workflows/fuzz-qualification.yml` runs only when dispatched (`targets`, `cpu_hours` 24 by default, `shard_hours` at most 5, `max_parallel` at most 20; `contents: read`, every step under bash, inputs reaching the shell only through `env`, one campaign at a time), in five jobs that `scripts/fuzz_campaign.py` plans and records. `plan` splits each target's CPU-hours into equal shares for shards of 4 libFuzzer processes, one per vCPU, each with a wall budget of `shard_hours`, at least half again its share (at the defaults 2 shards a target, each process to be charged 10,800 CPU seconds within 18,000 s). `build` builds every target once as the `fuzz` job does and keeps the binaries with their digests. Each `fuzz` job checks the digests and `exec`s the script, whose processes share one corpus from the seeds and fuzz in rounds until the kernel has charged each its share (user and system time from `wait4`), with a watchdog for a process past its round's time, a bound on rounds that end early, and its record, marked interrupted, written before the runner's SIGTERM when GitHub interrupts the step. `merge` merges each target's seeds and shard corpora with `-merge=1` and reads the merged corpus's coverage from one `-runs=0` run. `summary` tabulates per target the CPU-hours, process-hours, executions, edges, features, corpus size and the inputs a process stopped on, with the revision, the toolchain and the runners, and fails unless every target qualified. `scripts/fuzz_campaign.py` holds each target's `-max_len`, beyond the bound its readers check and at least its longest seed (`format_decoders` and `format_records` 8,192, `config_parse`, `nbd_handshake`, `backing_records`, `witness_rpc` and `helper_reports` 70,000, `nbd_netlink` 140,000, `witness_etcd` 270,000, the others 4,096), and the scheduled `fuzz` job reads it from there. A `big-endian-seeds` job cross-builds `review_fuzz_corpus` for `s390x-unknown-linux-gnu` with Rust 1.94.0, checks that the target is big-endian and runs the replay under `qemu-s390x` on every change. `helper_sysfs` builds each input's tree in a directory of its process's own (`maki-fuzz-sysfs-trees-<pid>-<nanoseconds>-<n>`, mode 0700, held under an exclusive `flock`): a panic hook removes a crashing input's tree before libFuzzer's abort, `atexit` removes the directory, a process's first input removes every such directory whose lock it can take, and one that such a sweep removed before its maker locked it is detected by its inode; it panics, with the path and the error, where it cannot make its directory or a tree, where before it silently refused every input of such a run. `witness_etcd` gains five seeds at and beyond etcd's 256 KiB answer and the 64 KiB state. The review blocked on one false claim: the pull request, a workflow comment and a test comment said that a shard's record is written when GitHub interrupts the step, but GitHub's runner signals only the step's own process, which was bash running the step's script, and bash does not pass the signal on to the command it waits for; the old test had signalled the Python process directly. Both steps now `exec` the script, a shard keeps its signal handlers until its record is written, interrupts every libFuzzer process at once and kills one still running 2 s later, and the merge runs libFuzzer in a process group of its own; tests replay the runner's sequence (SIGINT, SIGTERM 7.5 s later, a kill 2.5 s after that) on the steps' own scripts under the same bash command line. Its five nits brought the wording of interrupted processes, the `helper_reports` bound, the bound on early rounds and two corrections of how the measurements are worded. The delta review returned MERGE. The testing guide (the CI table, a `-max_len` table and a "Fuzz qualification" section), SPEC §55 and the development guide (the map's `fuzz/` row and a trap about `-max_len`) say so. The 24 CPU-hour campaign had not finished when this was written, and both of its `nbd_handshake` shards had failed, every process at libFuzzer's 2048 MB memory limit after about 10 million executions, a growth the coordinator traced to that target's entry function (above, and the open list). **Behaviour change:** none for the helper, a record format or a golden vector; the `fuzzing` feature is still enabled only by the harness. The scheduled `fuzz` job's `-max_len` is each target's value above, where it was 8,192 for the two format targets, 70,000 for `nbd_handshake` and 4,096 for the rest, so `nbd_netlink` now reads its 16,392-byte seed whole. The `big-endian-seeds` job runs on every pull request and push. `witness_etcd` has five more seeds, two of them 256 KiB long. | `scripts/test_ci_gate_validation.py` (`BigEndianSeedReplay`, `FuzzQualificationWorkflow` and the `fuzz` job's lengths) and `scripts/test_fuzz_qualification_validation.py` (the plan, the rounds, CPU time, the records, the merge and the summary against stand-in fuzzers; each length against the bound in the Rust source, and every seed against its length), with 14 failures and 1 error of 51 and 29 errors and 3 failures of 32 before; `fuzz/harness/tests/review_sysfs_trees.rs`: `a_crashing_input_leaves_no_tree_behind`, `the_trees_of_ended_processes_are_removed_and_a_running_ones_kept` and `a_process_that_starts_keeps_the_trees_of_one_that_runs`, which did not build before (without the crash test, both others failed); from the review `StepCancellation` (`test_a_cancelled_shard_step_keeps_its_record_and_leaves_no_fuzzer`, `test_a_process_that_ignores_the_interrupt_is_killed_in_time`, `test_a_cancelled_merge_step_keeps_its_record_and_leaves_no_fuzzer`), which failed at `bc144d9`; the `big-endian-seeds` job in CI; the 0.1 CPU-hour dispatch (above) | [#415](https://github.com/seo-rii/maki/pull/415) |

### Not closed in the third follow-up round

Each item was checked against `main` at `627d3cc`, with the six pull requests
merged.

- The 24 CPU-hour-per-target qualification has no passing result (AUD-210):
  the campaign dispatched on `main` at `32efe0b` (run 45983119347) had not
  finished when this was written, both of its `nbd_handshake` shards had
  failed (next item), and nothing here qualifies a target, so the testing
  guide's parser fuzzing row stays **Partial**. Of the second wave's 16 shards,
  still running at the coordinator's check at 14:26 UTC, no result is
  recorded. The workflow has run to its end once, as the 0.1 CPU-hour
  dispatch at `c2c46c7`; its verdict is recorded as its summary gave it, and
  the merge jobs' own output was not inspected for this record. No recorded
  run was interrupted by GitHub's runner, whose sequence the tests replay. Not
  fuzzed or not seeded: the two readers that use fixed paths; inputs at the
  bounds of `config_parse`, `backing_records` and `helper_reports`, whose
  lengths let a run get there but which no seed reaches; and the outputs
  `scripts/privileged_validation_capture.py` captures, which are kept in the
  job's artifact and which no seed or test reads. The s390x replay is
  user-mode emulation of `review_fuzz_corpus` alone, not an s390x machine or
  kernel, and no other suite runs on s390x.
- `nbd_handshake` runs out of memory under the qualification (AUD-210): in
  run 45983119347 all 8 processes of its two shards ended at libFuzzer's
  2048 MB limit after about 10 million executions each, the empty input among
  those they stopped on. The coordinator traced it, on an AddressSanitizer
  build of `627d3cc`, to the target's entry function (`fuzz/harness/src/nbd.rs`,
  `nbd_handshake`, there since AUD-200), which spawns and joins one
  `std::thread` for every input: without a sanitizer the process's RSS stayed
  flat over 400,000 runs, under the AddressSanitizer build that CI uses it grew
  by about 170 bytes per execution (180 MB after 600,000 runs), and with one
  writer thread reused it levelled off (134 MB after 3 million runs). A fix is
  in a separate pull request, not merged when this was written; after it, the
  target is to be qualified by a dispatch of its own. Until then
  `nbd_handshake` is not qualified.
- The HTTP transport keeps hyper-util's 300 ms before the other address
  family under reqwest (AUD-206): it is documented, and a `timeout` under
  600 ms is warned about, not changed, so with an HTTP `timeout` of 300 ms or
  less the other family is never tried while the first does not answer, and
  below 600 ms it has less than half of the time. Changing that needs a change
  to reqwest or an HTTP client of Maki's own on hyper-util. The HTTP shares
  stay fixed. The gRPC delay is set when the provider is built and counted
  from the dial, after resolution, so a slow resolution shortens what the
  other family has. A mutation that drops the gRPC delay's call passes every
  test that runs without the IPv6 loopback address, and was not run where
  that test runs. Still read from the code, not tested: the bound on a connect
  that hyper-util finishes in the background for its pool, reqwest's own
  bound over resolution and TLS (the same `timeout` as the request's, which a
  request cannot tell apart), and the 1 s SYN retransmission the
  configuration guide cites. The tests reach IPv6 only on loopback, and a
  route that drops packets only as a packet filter in a private network
  namespace, as root; no dual-stack host was used.
- After a page failure, a read-only command whose witness then answers with a
  denial or an invalid answer reports the session stop that answer caused
  and drops the page's error (AUD-207, from the second delta review of #411):
  the command still fails, but the damage is not named. Local protected and
  plain backings still compare after opening the backing and recovery,
  takeover, restore and enrollment recovery compare nothing before their
  claim, and with a remote witness attach still loads the witness client's
  TLS identity and sends one inspection before it compares, since the
  superblock it compares is authenticated only through the authority. The
  `etcd-qualification` job, which runs on the schedule and on dispatch, has
  not yet run the view's etcd gate test or the `--test-threads=1` that #411
  set. No volume that a kernel NBD device wrote was checked read-only, and no
  remote witness on another host was used. The second follow-up round's other
  limits of the read-only view stand: a writer that died was stood in for by
  a lost release, the failover client was used only for `inspect`, and a
  device mounted read-only, an NFS export and `errors=remount-ro` were not
  run.
- Kernel steps ran only on GitHub's runner VMs (Ubuntu 26.04.1, Linux 7.0)
  and in the two KVM guests (Debian 12's Linux 6.1, Rocky Linux 9.9's 5.14),
  with the local provider, one volume at a time apart from the stop together,
  and nbdkit killed only while the filesystem was idle after a sync (AUD-208,
  AUD-209). The stop together measured three volumes with a 10 s hold on one
  runner, not eight or more, nor a device held for the whole 15 s. How long
  the steps that still take the attach lock one at a time last on a host (an
  unmount that writes back a large page cache, above all), and so how many
  volumes can stop within `TimeoutStopSec=120`, is not known, and an attach
  of another volume can hold up either of a cleanup's turns on the lock for
  up to 180 s (AUD-205). How often something holds a device open at a detach
  on a production host, and whether it lets go within 15 s, is not known. The
  runs show an LV mapping keeping a disconnected connection's attributes; XFS
  was mounted on the mapping, so the mount's own effect is not told apart.
  `maki-attach grow` runs in no kernel job.
- The quick start's program writer still does not see a negated or a
  background command, and its check relies on the layout of Bash's `declare
  -f`, against which it was written with Bash 5.2.21 (AUD-208). The
  first-volume block's mountpoint `! -L` is argued equivalent on Linux and
  still passes the provisioning tests.
- The booted guests are virtual machines on GitHub's hardware with QEMU's
  user-mode network and a qcow2 overlay on the runner's disk with QEMU's
  default `cache=writeback`, not bare-metal hosts, and Rocky Linux is a
  rebuild of RHEL, not RHEL: RHEL itself, its own kernel build and AlmaLinux
  are not run (AUD-209). No guest is rebooted, and none runs `maki-attach
  grow` or a remote provider. The guides suite refreshes the guest's package
  lists before the guide's install, so a host without them is not tested; the
  RHEL guide's metapackage case, and what its SELinux section says beyond the
  job's checks, are read from the policy; and an image pin that Rocky's mirror
  no longer serves keeps the jobs passing only while GitHub's cache holds the
  image.
- Two gaps of the pull requests' own runs: #413's replays as uid 65534 and
  its run of all `scripts/test_*.py` were not repeated after its merge of
  `main` with #410, and no pull request reports rendering the man pages it
  changed (#410's host had no groff).
- Nothing in this round ran through a real power loss. CI's Windows jobs are
  the only Windows runs, and CI the only kernel runs: the `kernel-lifecycle`
  job, the guest jobs and the `pr` job's root-only step.
- A round-10 code audit of these changes was in progress when this was
  written; its findings and their fixes are recorded separately.
- `v0.1.0-rc.2`, tagged at `92d4dd4`, predates the second follow-up round and
  this one, and no later release candidate had been tagged when this was
  written.

## Second follow-up round (2026-11-26): AUD-201–AUD-204

No audit preceded this round either. After the follow-up round's records
change ([#404](https://github.com/seo-rii/maki/pull/404), `main` at `92d4dd4`,
where `v0.1.0-rc.2` is tagged), the owner asked to go on implementing what
that round had left open ([below](#not-closed-in-the-follow-up-round)). Four
pull requests were merged into `main` on 2026-11-26:
[#405](https://github.com/seo-rii/maki/pull/405) at `8be209c`,
[#407](https://github.com/seo-rii/maki/pull/407) at `1ff1e24`,
[#406](https://github.com/seo-rii/maki/pull/406) at `35c8e06` and
[#408](https://github.com/seo-rii/maki/pull/408) at `c3cf27a`. AUD-201 (#405)
gives each address of an HTTP endpoint's host a share of a connect timeout,
which the HTTP transport did not set, and lets the WebSocket transport reach
the other address family when little of its deadline is left. AUD-202 (#407)
lets `maki check` and `maki volume inspect` read a rollback-protected backing
read-only, which completes AUD-195. AUD-203 (#406) is a CI job that drives
whole attachments, with the detach wait of AUD-197, and then the documented
installation, quick start and first-volume block of AUD-199 through a runner's
kernel and systemd. AUD-204 (#408) adds fuzz targets for the readers that
AUD-200 left without one. Notes in the follow-up round's list say what each
closed or changed. None of these items had lost or corrupted data. Each row's
**Behaviour change** states what the code did before. Every change landed
test-first, apart from `maki-backing`'s tests of #407's new view, which use
its API and came with it (`97d82bb`), and #408's classifier tests
(`f836a53`), which a review asked for after the classifier's fix, whose two
seeds had come first (`9f08137`). All four rows are **Fixed**, and AUD-195's
**Partial** is complete. No change alters a record format or a golden vector.
The operator-visible changes are listed in the
[changelog](../CHANGELOG.md#changed).

Every pull request had an independent review before it merged, and three of
them were blocked at least once: #405 and #407 on false statements, #406 first
on a check that did not check and then on wording. #408's three recorded
reviews returned MERGE, the first two with notes. The review of #405 found the
code right and two sentences of the pull request's text false (which
`maki-nbdkit` tests build HTTP providers, and which row of a mutated test
fails), and asked that a connect timeout be reported as one; a delta review
found the configuration guide's "a share that ran out reads connect timeout"
false when a refused address comes first, corrected by the coordinator before
the merge (AUD-201). The review of #407 blocked on three false statements:
SPEC §27 and the refusal said that nothing is read when a lock file is
missing, while both opens read part of the backing before they took their last
lock, which the code was changed to avoid; the reason the documents gave for
reading an unwritable root read-only was false for a `0500` root holding
`0600` files; and the remote witness guide said that the check loads no key
(AUD-202). The first review of #406 found that the runner's "detach waited for
the opener" check did not check it, and listed nine smaller points; the
coordinator added a change from the first run's log. Each of its five reviews
also concerned what the quick start's program writer says it refuses: the
first found the description wrong, the second found the code narrower and
coarser than the description, the third and the fourth each found one phrase
that did not match the code, and the coordinator rewrote those two; the fifth
returned MERGE with an optional point that was taken (AUD-203). The reviews of
#408 found that the JSON oracles' skip of serde_json's raw-value key was
matched by its bytes, so an escaped key failed two targets on serde_json's own
reading, an ambiguous refusal that no seed covered, and later that nothing
checked that the oracles run (AUD-204). None of the review findings recorded
concerns code that was already on `main`. Every pull request's checks passed
at the head that merged (`3af9f7c`, `d108e37`, `87b4395`, `f836a53`), both
Windows jobs among them, and #406's included the `kernel-lifecycle` job. The
`nightly-gates`, `fuzz` and `etcd-qualification` jobs run only on the
schedule, on dispatch and on `review/integration-*` pull requests, so they ran
on none of the four. On `main` the push runs passed at `35c8e06` (run
45775419483, the first push run with the `kernel-lifecycle` job) and at
`c3cf27a` (run 45778267117). A dispatch of the whole workflow at `c3cf27a`
(run 45781903832) then passed all eleven jobs, `nightly-gates`,
`etcd-qualification` and `fuzz` among them. Its `fuzz` job was the first to
run the seven new targets on GitHub's runner: it built all sixteen targets and
ran each for 31 seconds from its seeds without a crash, from 66,830 inputs for
`helper_sysfs` to 13,582,061 for `format_decoders`. The jobs' results are the
coordinator's records; the `fuzz` job's figures are from its log.

The `kernel-lifecycle` job ran on #406 at least twice, and the logs of two runs
are kept: run 45759304959, on the merge of `c3d734d` (the first head) into
`92d4dd4`, and run 45767537362, on the merge of `b9054ed` into `1ff1e24`. Both
ran on GitHub's `ubuntu-26.04` image, version 20261116.202.1: Ubuntu 26.04.1
LTS, kernel `7.0.0-1020-azure`, systemd 259, with nbdkit 1.46.2 and lvm2
2.03.31 from Ubuntu's archive. In both the privileged runner passed, with 33
checks and then 36 (the review's three attach checks added). The detach with
the opener exited 0 after 2202 ms and 2193 ms. The opener's read failed with
`EIO` after three served reads, at 0.152 s and 0.151 s, while the device still
showed the connection's backend identifier, which stayed until the opener
closed the device at 2.152 s; then the device showed no connection. The data
read back after the reattach, nbdkit was killed with `SIGKILL` under the
mount, `maki-attach cleanup` released the attachment without it in 1104 ms and
1149 ms, a new nbdkit recovered the volume, the third attach read the data
back, and the final detach left nothing. In both runs the killed daemon's
device still showed its connection, so cleanup took its detach path; its
disconnected-recovery path did not run. The documented program then ran all
13 steps (the package install, the key, `volume create`, the first-volume
block on `/dev/nbd0`, the attach unit's start, a planned stop whose deep check
said `clean`, the restart and the clean-up) and printed "every documented step
succeeded". In the first run each LVM command of the first-volume block
printed `File descriptor 9 (/run/maki-attach/attach.lock) leaked on …
invocation`; the second run's log has no such line. Ubuntu 26.04 is not among
the platforms of the
[support matrix](deployment/support-matrix.md#host-platform), which lists
Ubuntu 22.04 and 24.04 as not qualified, and these runs qualify nothing: one
local-provider volume at a time, on one image's kernel, with one `SIGKILL` of
nbdkit while the filesystem is idle after a sync, which is not a power loss.

#405 reports Linux debug runs of `maki-crypto-http` (193 tests),
`maki-crypto-websocket` (149) and twelve `maki-nbdkit` test binaries that build
HTTP, WebSocket and gRPC providers (52), the HTTP connect tests 15 times in a
row and 20 more in four concurrent copies, and the two crates' unit tests as
uid 65534 with an empty `/run`. #407 reports the `maki-backing`,
`maki-nbdkit`, `maki` and `maki-check` suites as root with
`MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, its new and changed test executables as
uid 65534 with an empty `/run`, and `strace` of `inspect`, `check` and
`check --deep`, run as uid 65534, on a local volume with both directories
`0500` and on read-only bind mounts, and on a remote one (a `maki-witness
serve` authority) on a `0500`, a writable and a read-only bind-mounted root:
the 15 commands exited 0, their 2,846 trace lines hold no open for writing, no
truncation, allocation, sync, rename or unlink, one write per command to its
own stdout and only shared locks, and every entry of the directories and of the
authority's state was unchanged, while a writable `maki check` of the same
local volume, the positive control, made 37 opens for writing. #406 changes
no crate; it reports the Python suites, the two Rust test files that read the
runner, ShellCheck 0.9.0 and the opener's direct read of a regular file, and
its host has no `/dev/nbd*`, `modprobe` or KVM, so the job's steps first ran on
GitHub. #408 reports the suites of the five crates it changes and of the
harness, `review_fuzz_corpus` as uid 65534, and libFuzzer with
AddressSanitizer from the committed seeds for 4 minutes per new target (from
178,474 inputs for `helper_sysfs` to 8,464,077 for `helper_reports`) and 15
seconds per older one, without a crash; after review, `cargo +nightly fuzz
build` of all sixteen targets and 60 seconds each of `websocket_response` and
`http_response`. Each pull request that changes a crate reports strict Clippy
on 1.94.0 and 1.100.0 for each one (#408 with and without `--features
fuzzing`; #407 also for `x86_64-pc-windows-msvc` for `maki-backing`), and every
one fails-before runs of its test commits, mutation checks, `cargo fmt
--check`, the Python suites and the link checker. Every mutation reported was
caught by a committed test, some only once the test had been strengthened
(#406's mutations of one arm of the opener's check and of the program file's
writing, #407's N2, N11 and N21, #408's `wire_error` and envelope
mutations). None reports a run of the workspace-wide suite or of the release
gates, a run on Windows outside CI, on a booted RHEL or Debian host, with a
remote provider or rollback protection on a kernel device, or through a real
power loss.

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-201 | The HTTP transport built its client with `.timeout(spec.timeout)` alone. reqwest 0.12.28 then builds hyper-util's `HttpConnector` with `connect_timeout` unset (`async_impl/client.rs`: `set_connect_timeout(config.connect_timeout)`, `None` unless the builder sets it), and hyper-util 0.1.20 limits an address's TCP connect only when it is set (`ConnectingTcpRemote::new` divides it by the family's address count). So an address that never answered held the request until its `timeout`, and a live address after it in the same family was never dialed. The pull request reproduced it on `92d4dd4` with a probe it did not commit: a name resolved, through reqwest's `resolve_to_addrs`, to a loopback listener whose full accept queue drops SYNs and then to a live endpoint, with a 10 s `timeout` under paused time, was still pending at 9.999 s with nothing accepted, and failed at 10.001 s as `request timeout: error sending request`, not marked unsent. The WebSocket transport started the other address family a fixed 300 ms after the first attempt (AUD-198), so with 300 ms or less left of its connect deadline (a short `timeout`, or a request that had waited for the connection mutex) a first family that never answered held the connect to its deadline: with a 200 ms `timeout`, a dead IPv6 address and a live IPv4 one, IPv4 had not been dialed at 101 ms. Both were on the follow-up round's open list. | The HTTP provider builds its client with `.connect_timeout(spec.timeout)` as well. hyper-util divides it equally among the addresses of each family and dials them in turn, and reqwest also bounds the whole connect, resolution and TLS included, by it (`with_timeout` in `connect.rs`); since the request's own timer starts first, no connect outlasts its request, and a connect that hyper-util finishes in the background for its pool ends at the same bound (read, not tested). `new` calls a private `with_client(spec, adjust)`, which passes the builder through `adjust` last, so that the tests resolve the name to addresses of their own. reqwest 0.12.28 never calls `set_happy_eyeballs_timeout`, so the HTTP transport keeps hyper-util's 300 ms before the other family. *Changed on 2026-11-27 by AUD-206 ([#414](https://github.com/seo-rii/maki/pull/414)): no option of reqwest 0.12.28 or 0.13.5 changes it, so the HTTP transport keeps it and a `remote-http` `timeout` under 600 ms gets a configuration warning; the gRPC transport starts the other family after `min(300 ms, timeout / 2)`.* The WebSocket dialer starts the other family after `OTHER_FAMILY_DELAY.min(left / 2)`, `left` measured when the dial begins, so that family always has at least half of what was left; with 600 ms or more left, or without a deadline, nothing changes, and a first family that fails outright still starts it at once. Review found the code right and two sentences of the pull request's text false, and asked that a connect timeout say so: a timeout that is also `is_connect` now reads "connect timeout: …" where it read "request timeout: …", still retryable and marked unsent. A delta review found the configuration guide's "a share that ran out reads connect timeout" false when a refused address comes first, since hyper-util keeps a family's first error; the coordinator corrected it before the merge. The status page, the configuration guide (a paragraph under [remote HTTP mapping](configuration.md#remote-http-mapping), and the WebSocket rule), the architecture page, the testing guide, the module documentation and the development guide's AUD-193 trap (the HTTP seam, the full accept queue, and polling such a test's loopback I/O in a loop that yields under paused time) say so; SPEC says nothing about per-address connects. **Behaviour change:** over HTTP, a host that resolves to several addresses of one family is no longer held by the first that does not answer: each of a family's `n` addresses may take `timeout / n`, so a dead address before a live one costs half the `timeout` for two. When every address fails within its share, the request fails then, before its `timeout`, as a retryable connection failure marked unsent, which the dispatcher may send to another endpoint even for a provider that is not `retry_safe`; it reads "connect timeout: …" when the first address's share ran out and "transport error: …" when the first refused the connection. Before, it failed at `timeout` as "request timeout: …", not marked. The shares are fixed, as in the gRPC connector: an address refused at once does not pass its time on, and a live address slower than its share to accept the connection is given up. A host with one address per family keeps the whole `timeout`, and addresses still connecting at the `timeout` end as a request timeout, as before. Over WebSocket, with less than 600 ms of the connect left when the addresses are dialed, the other family starts halfway to the deadline instead of after 300 ms. | maki-crypto-http `connect_tests.rs` (Linux, paused time; the endpoint's name resolved through reqwest's override; an address that never answers is a loopback listener with a full accept queue, which the fixture first shows to time out rather than refuse): `a_first_address_that_never_answers_leaves_the_next_one_of_its_family_its_share` and `addresses_that_all_fail_within_their_shares_fail_the_request_unsent_before_its_timeout`, which failed before (the second also on the first fix, before the wording change), and the control `addresses_that_never_answer_hold_the_request_until_its_timeout_and_no_longer`; maki-crypto-websocket `connect_address_tests.rs`: `a_short_timeout_starts_the_other_family_at_half_of_what_is_left` and `a_request_with_little_time_left_after_a_wait_starts_the_other_family_at_half_of_it`, which failed before | [#405](https://github.com/seo-rii/maki/pull/405) |

### Offline checks

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-202 | AUD-195 left rollback-protected backings out. On Linux `maki check`, `maki check --deep` and `maki volume inspect` refused a local protected backing whose backing root or witness directory the user may not write before anything was opened ("… cannot be written by this process, and a rollback-protected backing cannot be checked or inspected read-only: …"): `RollbackBacking::open` re-dirties and syncs every committed page, rewrites the selected manifest and the format marker, reserves storage, publishes the witness anchor again and takes `rollback.lock` and `witness.lock` exclusively. `maki` refused a remote one on every root, writable or not ("read-only remote backing inspection is not supported; use `maki volume witness` …"): `RollbackBacking::open_remote` claims a writer at the authority (`Action::Claim`) and copies the current generation into a namespace of its own, and the remote witness guide said the commands refuse it "until a read-only backing view is implemented". On the test commit (`92d4dd4` with the new tests, run as root without CAP_DAC_OVERRIDE for the commands) 7 of the 9 tests of `bins/maki`'s `review_read_only_backing.rs` failed with the local refusal and 4 of the 18 of `remote_admin.rs` with the remote one. | A new `maki_backing::ReadOnlyRollbackBacking` (`rollback/read_only.rs`) opens both kinds only to read. It makes the writable open's authentication, whose checks moved unchanged out of `open_witnessed` into `open_marker`, `select_manifest`, `open_arena` and `authenticate_pages`, which both opens call: the format marker; the manifest the witness selects, by its digest, canonical encoding, identity, generation and slot size; the arena's size; and every committed page against its digest. The remote open uses the writer's `holds_current`, then `authenticate_pages`. It creates, writes, syncs and removes nothing below the backing root or in the witness directory: it opens both through `FileBacking::read_only`, reads the local anchor under the new `FileWitness::lock_read_only` and `open_read_only` without publishing it, and every change through the view fails with `ReadOnlyFilesystem`; `is_read_only()` is true, so the check adds its `read-only check:` warning and the deep verdict is `unproven`. It takes the locks that keep a writer out shared with `try_lock_shared_existing`, never creating them, and holds them while it is open: `rollback.lock` and `witness.lock` with a local witness, and with a remote one the root's `remote.operation.lock` and the current namespace's `rollback.lock`, before it reads anything in either directory but a remote root's format marker. A lock held exclusively refuses the open ("… is held by another process (…)"), and so does a missing one ("… is missing, and a read-only open cannot create it: …"). It sends the authority only `Action::Inspect`, once after the operation lock and again once both locks are held, and refuses a record that changed in between; nothing claims, creates a namespace, writes an operation guard or sends `Release`. As in a writer's view, every operation then asks the witness first and every read authenticates its pages again, and a mismatch, or a page that is missing, short or does not authenticate, stops the view for good. *Changed on 2026-11-27 by AUD-207 ([#411](https://github.com/seo-rii/maki/pull/411)): a remote view asks its authority only while it opens and in `check_freshness`, which the commands call once they have read everything, before they print their report, so `inspect` and `check` send three inspections and `check --deep` four; a local witness is still read before every operation, and a writer's view is unchanged.* `build_backing_to_read` opens a local protected backing through `build_backing`, unchanged, only where this process may write both its backing root and its witness directory, and otherwise through the view, after which it refuses an unfinished creation and a capacity that differs from the stored one as `build_backing` does; a remote one always through the view; and `maki` no longer refuses remote backings. Review blocked on three false statements. SPEC §27 said that the open reads nothing when a lock is missing, and the refusal that nothing was read, while the local open read `rollback.format` before it found `witness.lock` missing and the remote open read the selected manifest slot and opened the arena before it took the namespace's lock: the opens now take their locks first (`02007cf`, `d108e37`). The documents said that a root the user may not write is read read-only because a writable open fails there, which is false for a `0500` root holding `0600` files (the review ran `RollbackBacking::open` on one as uid 65534, and it returned Ok); they now say that the root decides, as for a plain backing. The remote witness guide said that the check loads no key, and the operations guide and maki(8) that it loads no credential, while it loads the witness client's TLS private key to ask the authority. SPEC §27, maki(8), maki-check(8), the [operations guide](operations.md#checking-a-backing-that-cannot-be-written), the rollback and remote witness guides and the status page say so. **Behaviour change:** a local protected backing whose backing root or witness directory the user may not write (a read-only mount, a `0500` directory, an immutable one) is checked and inspected read-only, where it was refused; a remote-protected one is, on every root, where `maki` refused it, and its authority receives only inspections. Such a report has a `warning: read-only check:` line and the deep verdict `unproven`; exit statuses are unchanged. To ask a remote authority the commands now load the witness client's TLS identity (`client_key_file` and its certificates), but no volume key or provider credential. Read-only, `inspect` and both checks refuse a protected backing that a daemon or another writer holds and one whose lock file is missing, and a daemon that starts while one of them runs fails to take its lock (with a remote witness, attach fails at the operation lock): unlike on a plain backing, the fast check and `inspect` take a lock here. By the code, a configuration pointed at a snapshot destination is refused, since `maki volume snapshot` creates no `rollback.lock` in the namespace it copies; that was not tested. A remote view sends one inspection per backing operation, each over a connection of its own, as a writer's view does, so a deep check of a large remote volume sends many. *Changed on 2026-11-27 by AUD-207 ([#411](https://github.com/seo-rii/maki/pull/411)): a remote view's command sends three inspections, four for `check --deep`, whatever the volume holds, and the refusal of a snapshot destination is tested.* Damage, a manifest the witness does not select, a capacity mismatch and an unfinished creation are refused as attach refuses them. Nothing changes for a local pair whose two directories can both be written or for a plain backing, and `maki-check <root>` still refuses protected roots, as its page now says. | `bins/maki` `review_read_only_backing.rs`: `a_protected_backing_it_cannot_write_is_checked_read_only` (root, witness and both `0500`; a writable pair is still `clean`), `a_damaged_page_of_a_protected_backing_it_cannot_write_is_an_error`, `a_protected_backing_whose_witness_selects_no_manifest_in_it_is_an_error`, `a_protected_backing_in_use_or_without_its_lock_is_refused_read_only`, `a_protected_backing_of_another_capacity_is_refused_read_only_too`, `an_unfinished_protected_creation_is_named_read_only_too` and `check_and_inspect_read_a_backing_on_a_read_only_mount` (read-only bind mounts of the root, the witness and both), and `remote_admin.rs`: `diagnostic_commands_read_a_remote_volume_with_inspections_only` (a recording handler on the TLS witness server sees only `inspect`, and the record and the root's bytes, modes and modification times are unchanged), the rewritten `diagnostic_commands_never_claim_or_fork_a_remote_writer`, `resume_enrollment_requires_admin_identity_fence_and_completes_volume_initialization` and `volume_cli_uses_identity_pinned_frontend_failover_for_create_and_witness`, all of which failed before; maki-backing `review_read_only_rollback.rs`, 14 tests of the new type, among them `a_local_read_only_open_authenticates_what_a_writable_open_does` (five kinds of damage, each refused with the writable open's error and nothing changed), `a_local_read_only_open_excludes_a_writer_and_admits_a_reader`, `a_remote_read_only_open_sends_only_inspections_and_changes_nothing`, `an_authority_that_changes_while_a_remote_read_only_open_locks_is_refused` and `a_remote_read_only_open_reads_an_active_authority_whose_writer_is_gone`, and from the review `a_local_read_only_open_refuses_a_missing_lock_before_it_reads_the_marker`, which failed on the first fix, as did the access order now recorded in `a_local_read_only_open_asks_for_no_change_even_where_one_is_allowed` and the missing namespace lock of `a_remote_read_only_open_authenticates_the_current_generation`; `scripts/test_docs_accuracy_validation.py` now finds the witness's error kinds in `stops_remote_session` | [#407](https://github.com/seo-rii/maki/pull/407) |

### Tests, CI and fuzzing

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-203 | The detach and cleanup wait of AUD-197 and the first-volume block of AUD-199 had never run with a real kernel NBD device, udev, device-mapper, LVM, XFS and systemd (the follow-up round's open list). CI's root-only kernel test (`review_nbd_kernel.rs`) reaches the shared wait only through the provisioning disconnect, and no CI job built a whole attachment: on `92d4dd4` `ci.yml` ran neither `scripts/privileged-linux-validation.sh`, nor the quick start, nor the first-volume block, and that runner never ran `maki-attach detach` or killed its nbdkit; it ended its attachment with `maki-attach cleanup`, run twice. | A `kernel-lifecycle` job in `ci.yml` runs on every event of the workflow (pull requests, pushes to `main`, dispatch and the schedule) on the `ubuntu-latest` runner VM itself, with its kernel, udev and systemd. It loads `nbd` with `nbds_max=16 max_part=8`, from `linux-modules-extra` when the kernel keeps the module there, runs `scripts/privileged-linux-validation.sh --install-missing --kill-daemon --device /dev/nbd15 --confirm-wipe /dev/nbd15` as the runner user, then builds the four packaged binaries and the Debian package from the commit and runs, with `sudo bash`, the program that `scripts/documented_quickstart.py` writes: the Debian guide's install blocks, the quick start's blocks and, as its step 4, the first-volume block, in one shell under `set -e -o pipefail`, each block's status checked. It then requires that no attach record, mount at `/srv/demo`, active unit of the volume or NBD connection remains. That step runs also when the runner's has failed; on a failure the job prints the runner's and the components' logs, the kernel log, the units' journal and the devices, mappings and records, and it keeps the logs, without the sources, the builds or a key file, as `kernel-lifecycle-logs`. After its workload, the runner now writes and fsyncs 32 MiB beside the SQLite database and records the SHA-256 of both, and runs `maki-attach detach` while `scripts/privileged_validation_opener.py`, as root, holds the device open: the opener reads the first block with `O_DIRECT` every 50 ms until a read fails, requires `EIO` with the connection still shown, keeps the device open two seconds more, writes, flushed, that it is closing it, closes it and requires that the device shows no connection within 5 s. The runner requires that line in `detach-opener.txt` when the detach returns, so a detach that did not wait for the close fails, and then attaches again with `init_sentinel = false` and compares the hashes. With the new `--kill-daemon` it sends `SIGKILL` to its nbdkit under the mount (status 137), requires `maki-attach cleanup` to release the attachment without the daemon, starts a new nbdkit, which must negotiate, attaches a third time, compares the hashes and detaches. *Changed on 2026-11-27 by AUD-208 ([#413](https://github.com/seo-rii/maki/pull/413)): it then kills nbdkit again and releases the device by hand, so that cleanup takes its disconnected recovery, and attaches a fourth time before the final detach; cleanup logs the path it takes.* Each attach must show the mount, a backend identifier and the attach record, and each teardown must leave no mount, holder, `backend` or `pid` attribute, size or record; a look for the record that fails stops the run. The program writer refuses a block that Bash cannot read and one with `&&` or `\|\|` text on the lines that the [testing guide](testing.md#automated-ci) names (those that Bash's `declare -f` prints at the block's own level, up to the last such line, before the last line it prints at that level, that ends in `;` or holds a here-document's command), and does not see such lists inside compound commands, brace groups or functions. *Changed on 2026-11-27 by AUD-208: it now reads them at every depth and refuses one that `DEEPER_LISTS` does not name for its block; a negated or a background command is still not seen.* The first-volume block exports `LVM_SUPPRESS_FD_WARNINGS=1` before it opens the attach lock on descriptor 9, which its LVM commands inherit. The first review found that the runner printed "detach waited for the opener to close" after the release check alone: since the opener closed the device on its own two seconds after the disconnect, a detach that returned at once passed too, which the review reproduced with a helper that returned a second before the close. Its nine smaller points brought, among other things, tests of each arm of the opener's checks, a pin that the job's essential steps are not skipped and that the runner step's status is the runner's, a record check that fails when the look fails, attach checks that make the release check non-vacuous, and a corrected description of the program writer; the coordinator asked for the LVM variable from the first run's log. The four later reviews concerned that description, which now states the rule as the code applies it. The testing guide, the status page, the runbook (with a dated note that no recorded result includes the new checks) and SPEC §55 say so. **Behaviour change:** none in the shipped binaries, units or package. The first-volume block no longer prints LVM's warning about descriptor 9 for each of its LVM commands; what it runs and records is unchanged. The runner detaches with an opener and attaches again in every run, takes `--kill-daemon` and writes more evidence files, which the runbook lists. Every pull request runs the job, which builds in release mode twice. | `scripts/test_privileged_lifecycle_validation.py` (the runner against mocks, the opener on a scripted device and clock): `test_every_run_detaches_with_an_opener_and_attaches_again`, `test_kill_daemon_cleans_up_after_a_killed_nbdkit_and_detaches_at_the_end`, `test_the_cleanup_trap_releases_an_opener_before_any_helper_cleanup`, `test_a_released_attachment_passes_and_each_leftover_fails` and the opener's cases, `test_attributes_gone_while_held_open_are_refused` among them, and from the review `test_a_detach_that_returns_before_the_opener_closed_the_device_fails` (a helper that returns at once), `test_a_record_that_cannot_be_looked_for_fails_both_ways` and `test_an_attachment_shows_what_a_teardown_must_remove`; `scripts/test_documented_quickstart_validation.py`: `test_the_first_failure_stops_the_program_and_names_its_step`, `test_the_bootstrap_is_the_block_the_provisioning_tests_run`, `test_a_list_before_the_last_command_is_refused` and `test_lists_inside_compound_commands_groups_and_functions_are_not_seen` (the known gap) *(replaced on 2026-11-27 by AUD-208's `test_lists_below_the_blocks_level_are_refused_at_every_depth`, `test_only_the_lists_read_for_a_block_are_accepted_below_its_level` and `test_a_negated_or_a_background_command_is_not_seen`)*; `scripts/test_ci_gate_validation.py`: `test_runs_on_every_change_on_a_runner_vm`, `test_the_privileged_runner_drives_the_whole_lifecycle_as_the_runner_user`, and from the review `test_the_essential_steps_are_not_skipped` and `test_the_runners_status_is_the_steps`; `scripts/test_docs_provisioning_validation.py`: `test_lvm_is_told_not_to_warn_about_the_lock_descriptor`. On the test commit 28 of the 46 tests of the four touched modules failed and 7 errored, and 16 of 65 failed and one class's setup errored on the first head with the review's tests. The job's runs 45759304959 and 45767537362 (above) | [#406](https://github.com/seo-rii/maki/pull/406) |
| AUD-204 | AUD-200 left these readers of untrusted bytes without a coverage-guided target (the follow-up round's open list): the witness's RPC (a client's reading of a server's answer frame, a server's reading of a request frame and of the operation in it) and its etcd store's reading of etcd's answers; the HTTP, WebSocket and gRPC providers' readers of a crypto endpoint's responses, of which `review_fuzz_transport.rs` covers part of the HTTP path with seeded random responses; and the root helper's readers of the output of the commands it runs as root and of sysfs, beyond the mountinfo and device-name parsers of `probe_parsers`. On `92d4dd4` `fuzz/Cargo.toml` had nine targets, none of which depended on `maki-witness`, a remote provider or `maki_privileged::exec`. The generator added the `nbd_netlink` seeds, a little-endian host's, only under `cfg(all(target_os = "linux", target_endian = "little"))`, so a big-endian host skipped them by name and `netlink_seeds` was unused there. | Seven targets follow #401's design: each `fuzz_targets/*.rs` is one line that calls its entry in `fuzz/harness`, which calls a doc-hidden module of the crate behind a `fuzzing` feature that only the harness enables and that adds no dependency (`maki-privileged` still has no crypto dependency). `witness_rpc` reads a server's answer frame as `Rpc::call` does, and a request frame as the server does, handing its operation to the file authority's own `state_handler` over a `StateStore` on a `MemBacking` in one of four states, with a writer, admin or unlisted certificate; the client must read back what the server answered. `witness_etcd` reads etcd's answers to the store's range read and its two transactions. `http_response`, `websocket_response` and `grpc_response` read a response as each provider does: the HTTP body's bounded accumulation, its JSON mappings of one item and of a batch, a raw body and the status; the WebSocket connection reader's handling of one message and `parse_response`; gRPC's initial headers, the body as tonic polls `BoundedResponseBody`, `map_status` and the message. `helper_reports` (Linux) reads LVM's `fullreport` against a candidate set, `blkid`'s two probes, `dmsetup info`, `blockdev --getsize64` and `blkid -o value`, and `helper_sysfs` (Linux) a `/sys/class/block` tree and a mount table that the input builds in a directory of its own, as detach's observation, allocation, recovery's capture and observations, preflight's discovery and mapping check, the displaced-record check and the connection attributes read them. Readers that were inline are now functions that production calls in the same order (the witness client's `parse_response` and `answer`, the server's `parse_request` and `wire_error`, etcd's `answer`, `created`, `transaction`, `compared` and `snapshot`, the WebSocket reader's `receive`, gRPC's `initial_headers`, `decode_response` and `echoed`, the HTTP provider's `parse_item` and `parse_batch`, the helper's `lv_size_of` and `blkid_value`), and `lvm_preflight`, `recover` and `allocation` gain `fuzzing` modules that forward to their private readers. The JSON oracles hold the HTTP provider's selective parser and the WebSocket reader to `serde_json::Value`, and skip a document with an object whose first key decodes to serde_json's private raw-value token, which `Value` reads as raw JSON under the `raw_value` feature that `maki-witness` enables. `fuzz/Cargo.toml` gains seven `[[bin]]` entries and patches `hyper`, `rustls` and `tungstenite` as the workspace does; 270 seeds are committed, 458 in all. A big-endian host now generates the netlink seeds in its own byte order and replays those under the same names, neither comparing nor writing the committed files. Two readers that use fixed paths are not fuzzed: `wait_nbd_ready`'s read of `/sys/block/nbdN/size` and `nbd_connected`'s check for `/sys/block/nbdN/pid`. No run found a crash. The review, asked to check first that the extractions keep the behaviour, returned MERGE with seven notes. Among them, the JSON oracles matched the raw-value token by its bytes, so the same key with an escaped `$` (`\u0024serde_json::private::RawValue`), which `Value` decodes to the token, made `websocket_response` and `http_response` panic on documents that are serde_json's own reading; two seeds committed first (`9f08137`) made the replay panic until the oracles walked the document with serde_json's deserializer (`707168f`). A narrowed envelope check survived until a seed with an ambiguous `unsupported-context` refusal was added, `helper_sysfs` removes its tree on every exit of the replay, a doc comment went back to its function, and the testing guide no longer claims a size limit that the job's inputs cannot reach. The delta review, also MERGE, found that nothing checked that the oracles run: a classifier that skipped every document still passed the replay. The unit tests that `f836a53` adds for it fail for a classifier that always or never skips, and the confirmation of that commit returned MERGE. The testing guide's fuzzing section and the docs-accuracy pin of the witness's wire-error mapping follow. **Behaviour change:** none for the helper, the daemon, the witness or a provider: the moved code is unchanged and runs in the same order. A release build (`-p maki -p maki-attach -p maki-check -p maki-nbdkit`, or `-p maki-witness-cli`) does not enable the features, while `cargo build --workspace` does, through feature unification, adding the doc-hidden modules. For developers, the default suite replays 270 more seeds (`helper_sysfs`'s create and remove temporary directories), a change to one of these readers may need its seeds written again, and the scheduled `fuzz` job builds a larger graph and runs seven more targets for 30 seconds each. *Changed on 2026-11-27 by AUD-210 ([#415](https://github.com/seo-rii/maki/pull/415)): the `fuzz` job gives each target the `-max_len` of `scripts/fuzz_campaign.py`, where it had cut `nbd_netlink`'s 16,392-byte seed to 4,096 bytes, the seeds are also replayed on s390x under `qemu-user`, `helper_sysfs` removes the trees of crashing and ended processes, and a dispatched workflow runs the 24 CPU-hour qualification, whose first campaign found every `nbd_handshake` process running out of memory (AUD-210).* | `fuzz/harness/tests/review_fuzz_corpus.rs`: `every_fuzz_target_has_an_entry_a_binary_and_seeds` (seven targets without an entry and a `[[bin]]`) and `the_manifests_targets_are_read_whatever_its_line_ends` (nine targets for sixteen), which failed before, `every_committed_seed_replays_through_its_target`, which with the review's two seeds failed before the oracles' fix, and `the_committed_seeds_are_what_the_generator_writes`; `scripts/test_ci_gate_validation.py` (`FuzzJob`: at least sixteen targets, the seven by name, every patch of the workspace), whose four checks failed before; from the delta review, `only_a_first_key_that_decodes_to_the_token_skips_the_reference` in the `fuzzing` modules of `maki-crypto-http` and `maki-crypto-websocket`, which fails for a classifier that always or never skips; the libFuzzer runs on #408's host, and the `fuzz` job of run 45781903832 on `c3cf27a`, 31 seconds per target without a crash | [#408](https://github.com/seo-rii/maki/pull/408) |

### Not closed in the second follow-up round

Each item was checked against `main` at `c3cf27a`, with the four pull
requests merged.

- Every remote transport still loses time to a dead address on every connect:
  about 300 ms for a dead family, and an address's share within a family
  (AUD-201). The HTTP transport keeps hyper-util's 300 ms before the other
  family, which reqwest 0.12 does not expose, so with an HTTP `timeout` of
  300 ms or less the other family is never tried when the first does not
  answer, and below 600 ms it has less than half of the time. Its shares are
  fixed: an address refused at once leaves its time to no other, and a live
  address slower than `timeout / n` to accept the connection is given up. The
  gRPC transport's connector, read and not tested, ends its last address at
  the timeout and then starts the other family in its background connect
  worker, which can serve a later call. Read from the code and not tested: the
  HTTP 300 ms and the short-`timeout` limitation, a single-address host
  keeping the whole `timeout`, the bound on a connect that hyper-util finishes
  in the background, reqwest's bound over resolution and TLS, and the 1 s SYN
  retransmission that the configuration guide cites. The HTTP tests run on
  Linux only; their dead address is a full accept queue on #405's host (Linux
  6.18), and the WebSocket ones are the test dialer's. No dual-stack host or
  real route that drops packets was used.
  *Changed on 2026-11-27 by AUD-206
  ([#414](https://github.com/seo-rii/maki/pull/414)): the gRPC connector
  starts the other family after `min(300 ms, timeout / 2)`, so a call with a
  `timeout` under 600 ms reaches it. The HTTP transport keeps the 300 ms,
  which no option of reqwest 0.12.28 or 0.13.5 changes, and a `remote-http`
  `timeout` under 600 ms now gets a warning from `volume create`, `check` and
  attach. Tests now cover a single-address HTTP host, a resolver and a TLS
  peer that never answer, the HTTP and gRPC cases of the other family on the
  IPv6 loopback address (run on GitHub), a gRPC dead address before a live one
  of its family, and, as root, a packet filter that drops SYNs in a private
  network namespace. What remains is in the third follow-up round's open
  list.*
- The volumes that the CLI tests and the `strace` runs read through the
  read-only rollback view were made by `volume create` and hold no data slots,
  so no volume that a daemon wrote through NBD was checked that way; the
  `maki-backing` tests read a payload of several pages with a hole (AUD-202).
  That a configuration pointed at a snapshot destination is refused is read
  from the code, not tested. A writer that died was stood in for by a lost
  release, not a killed daemon; no etcd-quorum authority was used, and the
  failover client only for `inspect`. A device mounted read-only, an NFS or
  other read-only export and `errors=remount-ro` after a real I/O error were
  not run; the mounts were read-only bind mounts. While a check holds the
  locks, a daemon that starts fails to take them, and a remote one fails its
  attach at the operation lock; how many inspections a deep check of a large
  remote volume sends was not measured. A writable `check` or `inspect` of a
  local protected pair still rewrites its pages, manifest, marker and witness
  record. On a plain backing the fast check and `inspect` take no lock and
  only the root decides, so a writable root whose files cannot be written
  still fails as before. Only Linux asks: rollback protection is Linux-only,
  and the new tests run on Linux only.
  *Changed on 2026-11-27 by AUD-207
  ([#411](https://github.com/seo-rii/maki/pull/411)): tests read, through the
  view, local and remote protected volumes written through the plugin's
  adapter and through nbdkit, a damaged data slot included, and refuse a
  configuration pointed at a snapshot destination; a remote view's command
  sends three inspections (four for `check --deep`) whatever the volume holds;
  and an ignored gate of the `etcd-qualification` job reads a volume on a
  three-member etcd quorum through the view, which has not run on GitHub yet.
  The rest of the item stands.*
- `maki check` compares only what the superblock stores (AUD-194): a different
  key under the same name, an unavailable credential, a provider that fails
  its self-test and endpoints that are unreachable or not interchangeable are
  found only at attach. Attach compares after opening the backing and
  recovery, so with remote rollback protection it loads the witness client's
  TLS identity and claims a writer at the authority before it refuses a
  mismatched configuration; that case was not run, nor a `maki check` of a
  protected backing read read-only with a mismatched configuration. That
  attach sends no request to an endpoint before the comparison is tested for
  the HTTP provider only.
  *Changed on 2026-11-27 by AUD-207
  ([#411](https://github.com/seo-rii/maki/pull/411)) and AUD-206
  ([#414](https://github.com/seo-rii/maki/pull/414)): with a remote witness,
  attach and a remote provider built on its own compare the settings fixed at
  creation and the protected capacity with the authority's current generation
  before they claim a writer, after one inspection that changes nothing; a
  read-only `maki check` of a local and of a remote protected backing with a
  mismatched configuration is tested; and that attach sends nothing to an
  endpoint before the comparison is now tested for WebSocket and gRPC
  endpoints too. Attach still loads the witness client's TLS identity before
  it compares, and what `maki check` cannot compare is unchanged.*
- CI's `kernel-lifecycle` job runs one local-provider volume at a time on
  GitHub's `ubuntu-latest` image, whose kernel changes with the image
  (Ubuntu 26.04.1 and `7.0.0-1020-azure` in the two runs whose logs are kept),
  not on the Debian 12 primary platform or RHEL 9, and kills nbdkit once while
  the filesystem is idle after a sync (AUD-203). In both runs the killed
  daemon's device still showed its connection, so cleanup's disconnected-
  recovery path has not run on a kernel. The opener is the runner's own and
  holds the device for two seconds: how often something holds a device open
  at a detach on a production host, whether it lets go within 15 s, and many
  volumes stopping together, whose cleanups queue on the attach lock for up
  to 15 s each and from about the eighth on reach `TimeoutStopSec=120`, remain
  unmeasured. The quick start's program writer does not see `&&` or `||`
  lists inside compound commands, brace groups or functions, nor a negated or
  background command, where a failure lets the program go on, and its check
  relies on the layout of Bash's `declare -f`, against which it was written
  with Bash 5.2.21.
  *Changed on 2026-11-27 by AUD-205
  ([#410](https://github.com/seo-rii/maki/pull/410)), AUD-208
  ([#413](https://github.com/seo-rii/maki/pull/413)) and AUD-209
  ([#412](https://github.com/seo-rii/maki/pull/412)): the job also kills
  nbdkit a second time and releases its device by hand, and cleanup then took
  its disconnected recovery in every run whose log is kept, as it did in the
  booted Debian 12 and Rocky Linux 9 guests. Detach and cleanup let go of the
  attach lock for their wait, and three volumes whose devices were held 10 s
  after their disconnects then stopped together within about 10.5 s, where
  their stops had queued to about 30.5 s. The program writer reads lists at
  every depth against an allow-list. More volumes, a device held for the whole
  15 s, how long the steps under the lock take on a host and how often a
  device is held open on a production host remain unmeasured, and a negated or
  a background command is still not seen.*
- The first-volume block ran on a kernel only as a run that does not stop
  (AUD-203). A run that stops, and one that continues from its record, ran
  only against the suite's mocks (AUD-199). The three mutations that the
  follow-up round's delta review found equivalent or failing closed (`set -C`
  dropped when the staged configuration is written, the mountpoint's `! -L`
  dropped, and `boot_id` dropped from the values a record must hold) each
  still pass the 27 provisioning tests at `c3cf27a`, rerun for this record.
  *Changed on 2026-11-27 by AUD-208
  ([#413](https://github.com/seo-rii/maki/pull/413)): CI's `kernel-lifecycle`
  job runs the block once stopped at `mkfs.xfs` and once at `vgchange`, each
  by a shim that fails that command once, and runs it again as the recovery
  notes say, on the runner's kernel; the booted guests run it as a run that
  does not stop (AUD-209). New provisioning tests kill the `set -C` and
  `boot_id` mutations, and the mountpoint's `! -L` is argued equivalent on
  Linux.*
- No fuzz run has reached the 24 CPU-hour-per-target qualification (AUD-204):
  the seven new targets ran 4 minutes each on #408's host, in one process with
  `-max_len=4096`, before the review changed the JSON oracles, after which
  `http_response` and `websocket_response` ran 60 seconds each. The `fuzz` job
  did not run on #408; on GitHub's runner the new targets have run once, 31
  seconds each from their seeds without a crash, in the dispatch on `main` at
  `c3cf27a` (run 45781903832). Not fuzzed: the two readers that use fixed paths, and the size limits of etcd's
  answer (256 KiB) and of the witness state (64 KiB), which lie beyond the
  job's 4096-byte inputs. The helper's targets read synthetic trees and
  outputs written to the documented formats, not ones captured from a real
  LVM, `blkid`, `dmsetup` or kernel. The JSON oracles compare no
  document whose object's first key decodes to serde_json's raw-value token.
  No big-endian host was used (its replay and generator paths compile on
  little-endian hosts through `cfg!`), the new modules were built for Windows
  only by CI, and under libFuzzer a crashing `helper_sysfs` input leaves its
  tree in the temporary directory.
  *Changed on 2026-11-27 by AUD-210
  ([#415](https://github.com/seo-rii/maki/pull/415)): `fuzz-qualification.yml`
  runs the campaign when dispatched; its 0.1 CPU-hour dispatch at `c2c46c7`
  (run 45978498661) succeeded, and the 24 CPU-hour campaign dispatched at
  `32efe0b` (run 45983119347) had not finished when this was written, but had
  already failed both `nbd_handshake` shards: every process ran out of memory
  at libFuzzer's 2048 MB limit, which the coordinator traced to that target's
  entry function (the third follow-up round's open list), so that campaign
  cannot qualify it. Each target now has its `-max_len` (`witness_etcd`
  270,000, with seeds at etcd's 256 KiB answer and the 64 KiB state), CI
  replays the seeds on s390x under `qemu-user`, and `helper_sysfs` removes the
  trees of crashing and ended processes. The two readers that use fixed paths
  are still not fuzzed, and the helper's targets still read synthetic inputs.*
- Nothing in this round ran on a booted RHEL or Debian host or through a real
  power loss. CI's Windows jobs are the only Windows runs, and CI the only
  kernel runs: the `kernel-lifecycle` job, and the `pr` job's root-only step,
  which connects a real `/dev/nbdN` in `review_nbd_kernel.rs`.
  *Changed on 2026-11-27 by AUD-209
  ([#412](https://github.com/seo-rii/maki/pull/412)): on every change CI boots
  Debian 12's generic cloud image and Rocky Linux 9.9's GenericCloud image,
  SELinux enforcing, as KVM guests on GitHub's runner VMs, and runs, in one
  guest of each, the installation guide's host steps, the quick start and the
  first-volume bootstrap, and in another the privileged runner; at #412's
  merged head all four guest jobs passed. These are virtual machines, not
  bare-metal hosts, Rocky Linux is not RHEL, and nothing has run through a
  real power loss.*
- `v0.1.0-rc.2`, tagged at this round's base `92d4dd4`, predates the round,
  and no later release candidate had been tagged when this was written.

## Follow-up round (2026-11-25): AUD-194–AUD-200

No audit preceded this round. After the ninth round's records change
([#396](https://github.com/seo-rii/maki/pull/396), `main` at `04bbc90`), the
owner approved fixing the most useful of the items that the ninth and eighth
rounds had left open: four first (the WebSocket connect, the comparison that
`maki check` did not make, the first-volume script's failure path and the fuzz
targets of AUD-180), then three more (detach and cleanup waiting for the
disconnect, the exit status of `maki-witness init` for a nil identity, and
`check` and `inspect` on a backing they cannot write). None of these items had
lost or corrupted data. Seven pull requests,
[#397](https://github.com/seo-rii/maki/pull/397) to
[#403](https://github.com/seo-rii/maki/pull/403), were merged into `main` on
2026-11-25 (#397 at `2be800c`, #398 at `08fd3f8`, #399 at `35ec8af`, #400 at
`9692e8a`, #401 at `c861636`, #402 at `4711a07`, #403 at `cd596ce`). AUD-194
to AUD-196 are the offline checks and the command line (#399, #403, #397),
AUD-197 the privileged helper (#398), AUD-198 the remote providers (#400),
AUD-199 the provisioning guide (#402), and AUD-200 the fuzz targets (#401).
AUD-194 and AUD-199 close two of the ninth audit's three observations and
AUD-195 the third in part, AUD-198 the ninth round's open item on the
WebSocket connect, and AUD-196, AUD-197 and AUD-200 items of the eighth
round's open list; notes in those lists say so. Each row's **Behaviour
change** states what the code did before. Every code fix landed test-first,
apart from a refinement made in review whose test came in the same commit
(`37b0c77`, AUD-195); in #401's build configuration, the `libfuzzer-sys` pin
came with its test (`43f6b63`). AUD-195 is **Partial**: a rollback-protected
backing that cannot be written is refused with the reason, since that layer
has no read-only open. Every other row is **Fixed**. No change alters a record
format or a golden vector; AUD-199 adds a file that the provisioning block
writes on the host. The operator-visible changes are listed in the
[changelog](../CHANGELOG.md#breaking-changes). *AUD-195 was completed on
2026-11-26 by AUD-202 ([#407](https://github.com/seo-rii/maki/pull/407)): such
a backing is now read through a read-only view of that layer.*

Every pull request had an independent review before it merged. #397's was a
light review and found nothing; each of the other six led to new commits. In
#398 the review found the cause the documents gave false: the round's task
description, and from it the first documentation commit, said that udev's
probe after the disconnect is what keeps the `pid` and `backend` attributes,
but in CentOS Stream 9's `drivers/block/nbd.c` the disconnect's change event
is sent in `nbd_config_put`, in the same section that removes them, so only
something that already held the device open at the disconnect keeps them. It
also asked for a test of the failed-start hook's wait and for the raw
disconnect's test to run on a manual clock instead of sleeping, and a delta
review found one false sentence about a host shutdown, corrected before the
merge (AUD-197). In #399 it found the pull request's text wrong about what
`main` did for a remote provider, and "before any credential is loaded" false
with a remote witness, whose TLS identity opening the backing loads; a delta
review found "only" false, since process hardening runs first. Both were
corrected, and the review's notes also brought a test that a remote
configuration is compared by provider type and key identity, and the words
`unset` and `none` for a key identity that one side does not have (AUD-194).
The review of #400 found that a connect made after the request had waited for
the connection mutex still took a full `timeout` of its own, asked for a test
that a TLS failure is not retried at another address, and had the status page
name the HTTP transport's exposure again (AUD-198). In #401 it found that the
seed replay read the fuzz manifest by its LF line ends, so in a checkout with
CRLF line ends, as a Windows checkout has, it found no target; the delta
review checked the refactoring that made the targets run the readers' own code
(AUD-200). In #402 it found the message of a released run false for one that
stopped in `mkfs.xfs` or before it had read the filesystem's UUID ("before it
created the filesystem"), seven mutations of the block that no test caught, no
syncs of the record or of the attach configuration, an existing mountpoint
taken over unchecked and a record read loosely; the delta review found the
three mutations that still survive equivalent or failing closed (AUD-199). The
review of #403 ran the commands under strace in 15 states and saw no write
through the read-only view; its notes led the probe to ask the view's own
pinned root descriptor, and a delta review found one false sentence in the
pull request's text, corrected before the merge (AUD-195). Every pull
request's checks passed at the head that merged, both Windows jobs among them.
A dispatch of the whole workflow on `main` at `cd596ce` (run 45722124367) then
passed all ten jobs, both Windows jobs, the release gates, `rhel9` and the new
`fuzz` job among them. It was the `fuzz` job's first run on GitHub's runner:
it built every target and ran each from its seeds, and it uploaded no crash
input, so no target crashed.

#397 was checked with its crate's 28 tests, strict Clippy on 1.94.0 and
1.100.0 and `cargo fmt --check`. #398 to #401 and #403 report Linux debug
runs, in isolated build directories, of the changed crates' suites and of the
crates that use the change, and strict Clippy on both toolchains for every
changed crate; #402 changes no crate. The six report `cargo fmt --check`, the
Python suites and the link checker, with fails-before runs of the test commits
and mutation checks; every mutation was caught but the three of #402 above.
They also ran their new tests as uid 65534 with an empty `/run` in a private
mount namespace. #401 ran each new target under libFuzzer with
AddressSanitizer for 12 minutes and each older one for 150 seconds, from the
committed seeds, without a crash, and the `fuzz` job's build and run steps
with the pinned nightly and `cargo-fuzz`, outside a runner. #401 and #403 ran
Clippy for `x86_64-pc-windows-msvc`, and #401 reproduced a Windows checkout's
line ends with `core.autocrlf=true`. #403 ran its commands on a read-only bind
mount in a private mount namespace, on an immutable root, and as root without
CAP_DAC_OVERRIDE on a tree it may not write. #402's block ran against the
suite's mocks, and ShellCheck 0.11.0 checked it. None of the pull requests
reports a run of the workspace-wide suite or of the release gates. Nothing ran
on a real kernel NBD device outside CI's root-only tests (the host of #398 has
no `nbd` module), with udev, device-mapper or LVM, under systemd with these
units, on a booted RHEL or Debian host, on Windows outside CI, or through a
real power loss. What keeps a disconnected connection showing (AUD-197) and
the HTTP transport's connect timeout (the open list) were read from the
source.

### Offline checks and command line

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-194 | `maki check <config.toml>` and `maki check <config.toml> --deep` never compared the configuration with the volume they checked. A configuration whose geometry, provider, key name, compatibility id or random prefix length differed from what the superblock stores passed with status 0, and attach then refused it. The ninth audit saw it for the compatibility id, the prefix and the maximum ciphertext size; the pull request reproduced it on `04bbc90` for those, the provider and the key name, and its test shows it for every setting fixed at creation. Attach itself compared only the geometry before it built the provider. For a local provider the engine compared the provider type and key identity, and the self-test the compatibility id, after the provider had been built with its key: with the key file removed, each such change failed with `provider fatal: credential "vol.key" unavailable — failing closed`, not with the setting. For a remote provider the dispatcher (`dispatch_endpoint_set`) refused a changed provider type or compatibility id as `unsupported: remote configuration does not match the locked volume identity/geometry`, which names neither the setting nor the values, and did not compare the key identity. An observation of the ninth audit. | One function, `maki_nbdkit::daemon::configuration_mismatches`, compares the configuration with the superblock alone: the six geometry fields (`volume.device_block_size`, `volume.crypto_unit_size`, `volume.shard_logical_size`, `volume.max_virtual_size`, `backing.slot_alignment`, `crypto.capabilities.max_ciphertext_size`), `nbd.minimum_io` against the stored geometry once that matches, `crypto.provider`, the key identity `crypto.key.name` (a volume an older build created with a `key/.` path still matches the corrected `key`, as attach accepted) and the derived compatibility id, named as `crypto.random_prefix_bytes` or `crypto.crypto_compatibility_id`, whichever part differs. A side without a key identity is named `unset` (the configuration) or `none` (the volume). Attach of an existing volume refuses at the first mismatch before `prepare_provider`, so no provider credential is loaded and no provider transport is built; process hardening, opening the backing and recovery come first, since the superblock compared is the one recovery selects. *Changed on 2026-11-27 by AUD-207 ([#411](https://github.com/seo-rii/maki/pull/411)): with a remote witness the open compares the same settings, and the protected capacity, with the authority's current generation before it claims a writer, and attach compares again after recovery.* The dispatcher's own check is replaced by the same function, and the engine's and the self-test's checks stay behind it. `maki check` and `--deep` print one `ERROR: configuration mismatch: <setting> is <value> in the configuration, the volume has <value>; attach refuses this configuration` line per mismatch after their report and fail. The deep verdict still describes the volume only, so a configuration error is not reported as damage to restore from backup. The values printed are sizes, the provider type, the key's name, compatibility ids and the prefix length, none of them secret under SPEC §9. `check` loads no credential and contacts no provider: a different key under the same name, an unavailable credential, a provider that fails its self-test and unreachable endpoints are still found only at attach. *Changed on 2026-11-26 by AUD-202 ([#407](https://github.com/seo-rii/maki/pull/407)): `check` now also reads a remote-protected backing, read-only, and to ask its authority loads the witness client's TLS identity; it still loads no provider credential.* `maki-check <root>` reads no configuration, and `maki volume inspect` does not compare the geometry or crypto identity. maki(8), maki-check(8), the operations and configuration guides and SPEC §20 and §27 say so. **Behaviour change:** `check` and `check --deep` exit 1 where they exited 0 for such a configuration, and a matching one prints one more `info:` line. Attach refuses a changed provider, key name, compatibility id or prefix length before it loads any provider credential. For a local provider a compatibility id or prefix mismatch is `crypto identity mismatch: volume was created with compatibility id "…", configuration says "…"` (`AttachError::IdentityMismatch`) where it was `provider fatal: crypto compatibility mismatch: …` after the key was loaded, and a provider change whose key does not fit the new provider reports the provider. For a remote provider, at attach and in `build_provider_with_endpoints`, a changed provider type or compatibility id is `crypto identity mismatch: …` where it was `DaemonError::Unsupported`, and a volume that records a key identity is refused before any probe. The geometry and NBD messages are unchanged. | `bins/maki` `review_check_config_identity.rs`: `every_setting_fixed_at_creation_is_compared_with_the_volume`, `a_prefixed_volume_is_compared_by_prefix_length_and_base_id` and `a_legacy_key_path_suffix_matches_the_corrected_path` (each with and without `--deep`), which failed before, and from the review `a_key_identity_one_side_does_not_have_is_named_as_missing`; maki-nbdkit `review_config_identity_attach.rs`: `a_changed_crypto_identity_is_refused_before_any_credential_is_loaded` and `a_remote_provider_is_not_contacted_for_a_configuration_the_volume_refuses` (no request reaches the HTTP endpoint), which failed before, and from the review `a_remote_configuration_is_compared_by_provider_type_and_key_identity`, which fails with `main`'s `daemon.rs`; five unit tests in `daemon.rs`, `nbd_sizes_are_compared_once_the_geometry_matches` among them | [#399](https://github.com/seo-rii/maki/pull/399) |
| AUD-195 | `maki volume inspect`, `maki check`, `maki check --deep` and `maki-check` failed on a backing they cannot write: they opened every file read-write, and the deep check took the volume lock exclusively, creating `volume.lock` when it was missing. On `9692e8a`, with a volume's root bind-mounted read-only in a private mount namespace, each ended with `error: Read-only file system (os error 30)` and status 1, and on a tree whose files and directories the user may not write (`0400`/`0500`) with `Permission denied (os error 13)`. An observation of the ninth audit. | **Partial.** On Linux the commands open the backing root as a `FileBacking::read_only` view (AUD-093), which creates, probes and syncs nothing, and ask that view's pinned root descriptor whether this process may write it (`FileBacking::may_write`: `faccessat` with `W_OK` and `AT_EACCESS`; no on a read-only mount, EROFS, for a directory without write permission, EACCES, and for an immutable one, EPERM). Where it may, nothing changes. Where it may not, they read through that view, which opens files `O_RDONLY`. `maki` chooses in one place, `maki_nbdkit::daemon::build_backing_to_read`, which on the read-only path still refuses a `rollback.format` without the configuration's stanza, as `build_backing` does, and `maki-check` asks the same probe. Only the root decides. `Backing` gains `is_read_only` and `try_lock_shared_existing`, which opens an existing lock file read-only, locks it shared without waiting and never creates it. Through a read-only view the fast check adds the warning `read-only check: the backing was opened read-only, so nothing was written, synced or repaired. …` (`READ_ONLY_CHECK`), since what was read may exist only in the page cache (K-01). The deep check takes the lock shared, which excludes a writer for the whole check and admits other read-only checks, does not run without `volume.lock` ("volume lock: volume.lock is missing, and a read-only check cannot create it: …"), reports the records recovery would replay and its journal repairs as warnings, and states the verdict `unproven`, or `unrecoverable` when it finds damage, never `clean` or `recoverable`. `inspect` and the fast check take no lock, as before. A local rollback-protected backing whose root or witness directory cannot be written is refused before anything is opened, with the directory, its setting and the reason ("… cannot be written by this process, and a rollback-protected backing cannot be checked or inspected read-only: opening it re-publishes its authenticated state and the witness anchor before anything is read …"): `RollbackBacking::open` rewrites that state, and no read-only open of that layer exists (the open list). Review found that the first version asked about the root by its path and then opened the path again for the view; the view that answers is now the view that is read. Other platforms, which serve development only, open every root as before. SPEC §27, maki(8), maki-check(8), the [operations guide](operations.md#checking-a-backing-that-cannot-be-written), the rollback guide and the status page say so. *Completed on 2026-11-26 by AUD-202 ([#407](https://github.com/seo-rii/maki/pull/407)): a local protected backing whose root or witness directory cannot be written, and every remote-protected one, is read through a read-only view that authenticates it as attach does; the refusal is gone, and its test `a_protected_backing_it_cannot_write_is_refused_with_the_reason` is now `a_protected_backing_it_cannot_write_is_checked_read_only`.* **Behaviour change:** on a backing root the user may not write, the four commands work read-only where they failed with EROFS, EACCES or EPERM. Every such report has a `warning: read-only check:` line, and records to replay and journal repairs are warnings where a writable check reports them as `info:`. Exit statuses are unchanged (an `ERROR:` gives 1, otherwise 0), so an `unproven` report exits 0, and a script that needs `clean` reads the verdict line. A root that is not writable while its files are (`0500` with `0600` files), which a writable check used to read, is now checked read-only: its deep verdict is `unproven` where it was `clean`, and a missing `volume.lock` stops the deep check. A protected backing that cannot be written is refused with the reason where it failed with the system's error or whatever its open met first. Nothing changes on a writable backing. | maki-core `review_read_only_check.rs`: `a_deep_check_through_a_read_only_view_changes_nothing_and_is_never_clean`, `a_read_only_deep_check_reports_what_recovery_would_change_as_warnings`, `a_read_only_deep_check_refuses_a_volume_a_writer_holds`, `a_read_only_deep_check_never_creates_the_lock_file_and_does_not_run_without_it` and `the_fast_check_through_a_read_only_view_says_what_it_cannot_prove`, which failed before, and `a_read_only_deep_check_excludes_a_writer_while_it_reads`; `bins/maki` `review_read_only_backing.rs`: `check_and_inspect_read_a_tree_they_may_not_write`, `check_and_inspect_read_a_backing_on_a_read_only_mount` and `a_protected_backing_it_cannot_write_is_refused_with_the_reason`, which failed before, and `a_protected_root_without_its_configuration_is_refused_read_only_too`; `bins/maki-check` `review_read_only_backing.rs`: `maki_check_reads_a_tree_it_may_not_write` and `maki_check_reads_a_root_on_a_read_only_mount`, which failed before, and `maki_check_reads_an_immutable_root`; both binaries' files are listed in `scripts/run_root_tests.py`; maki-backing `file::tests`: `a_shared_lock_of_an_existing_file_creates_nothing_and_excludes_a_writer`, `a_writable_root_may_be_written_and_a_missing_one_is_not_created` and, from the review, `may_write_answers_for_the_root_the_view_holds_not_for_its_path` | [#403](https://github.com/seo-rii/maki/pull/403) |
| AUD-196 | `maki-witness init <dir> <nil-uuid>` and `maki-witness init-etcd <config> <nil-uuid>` exited 1, the status of a failed command, where `maki volume resume-enrollment` refuses a nil identity as misuse with status 2 and the binaries refuse a bad argument with 2 before anything is read or created (AUD-137, AUD-190). The nil UUID parses as a UUID: `init` handed it to the state store, which refused it ("nil remote witness identity") before it created anything, and `init-etcd` read its configuration first. The eighth audit noted it as cosmetic. | `volume_identity`, which these two commands use and no other does, refuses the nil identity with `maki-witness: volume identity must be nonzero` and status 2 before anything is read or created, as it already refused a word that is not a UUID. A command whose arguments are well formed and that then fails still exits 1. **Behaviour change:** status 2 and that message where the commands exited 1. | `a_nil_volume_identity_exits_2_before_anything_is_created` (`bins/maki-witness` `review_misuse_status.rs`: both commands, nothing on stdout, no state directory created), which failed before with status 1 | [#397](https://github.com/seo-rii/maki/pull/397) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-197 | When anything holds `/dev/nbdN` open at the disconnect (a probe of an earlier event, a monitoring tool, multipathd, an operator's `blkid`), the kernel acknowledges `NBD_CMD_DISCONNECT` while the device still shows the connection's `pid` and `backend` attributes, and refuses a new connect, until that opener has closed it. Since AUD-165 `maki-attach nbd-disconnect` waits for that; detach and cleanup did not. Their final teardown (`execute_with_options`) read the backend once, right after the acknowledgement, and in that state failed with "disconnect has not completed; keeping the attach record for cleanup retry", so an operator's `maki-attach detach`, or a `systemctl stop` whose `ExecStop` runs `maki-attach cleanup`, failed and had to be run again; the failed-start hook's rollback, which runs detach's steps, did the same. Reproduced on the crate's fake system and on the step-fault model's simulated kernel, where an opener that sysfs does not show keeps the device showing the connection; not on a real kernel, and how often it happens on a host is not known. The eighth round's open list kept it. | The provisioning disconnect's loop becomes one wait, `exec::await_release`: it looks at the device and, while the device still shows the disconnected connection, looks again every 100 ms until its time is up, then returns what the device showed last. A connection under another backend identifier means that the disconnected one is gone; a look that cannot be read, a connection without an identifier among them, ends the wait with its error. The time is 15 s, never more than is left of the deadline the caller set for all of its commands (`finish_by`, the failed-start hook's 30 s), and the last sleep is cut short to end at that bound; once that deadline has passed, the wait is a single look. Detach and cleanup wait on the executor's injectable `Clock`, `nbd-disconnect` on the clock its caller passes (`RealClock` in production). Detach, cleanup and the hook's rollback call the wait in place of their single read, and what follows is unchanged and in the same order: a device that shows any backend after the wait keeps the record with the same refusal (this connection, which a later run finishes once nothing holds the device open, or one made since under another identifier, which a later cleanup retires only by the displaced-record rules); an unreadable backend fails the command; otherwise the final teardown's observations decide, under the attach lock, before the record is removed. Attach's rollback does not wait. Review found the cause the documents gave false: the round's task description, and the first documentation commit, said that udev's probe after the disconnect keeps the attributes, but by CentOS Stream 9's `drivers/block/nbd.c` the disconnect's own change event is sent in `nbd_config_put`, in the same section that removes them, and the probe it starts opens the device afterwards; that probe is what makes an immediate reconnect busy (AUD-150). SPEC §6, maki-attach(8), the [operations guide](operations.md#prerequisites) and the development guide's NBD trap say so, and the attach unit's comment on its stop timeout counts the wait. **Behaviour change:** a detach or cleanup whose device lets go within 15 s of the disconnect succeeds in one run where it failed; one whose device does not keeps the record and fails with the same message and exit status as before, up to 15 s later. The attach lock stays held during the wait, so another volume's helper can wait up to 15 s longer for it. When many volumes stop together and every device is held open for the whole 15 s, their stop-time cleanups queue on the lock, and from about the eighth on they reach `TimeoutStopSec=120`, the later ones before they have changed anything: the record is kept and the stop fails by timeout. *Changed on 2026-11-27 by AUD-205 ([#410](https://github.com/seo-rii/maki/pull/410)): detach and cleanup let go of the lock for the wait and take it again in turn before they act, and the failed-start hook keeps it; on a kernel three held-open stops then ended together after about 10 s instead of one after another.* In a planned stop the daemon keeps serving and the stop can be retried; at a host shutdown nothing retries it, and a filesystem such a cleanup did not unmount stays mounted for the rest of the shutdown on a device whose daemon is gone (the operations guide says so). In the failed-start hook the wait is part of its 30 s for commands, and its three bounds still add up to 15 + 40 + 30 = 85 s inside the unit's 120 s. | maki-privileged `exec_tests.rs`: `detach_and_cleanup_wait_for_a_backend_that_outlives_its_disconnect` (a backend that lingers for 1, 7 or 150 looks is detached or cleaned up in one run, without a second disconnect, and the volume attaches again), `a_backend_that_outlives_the_wait_keeps_the_record`, `another_connection_during_the_wait_ends_it_and_keeps_the_record`, `an_unreadable_backend_during_the_wait_fails_and_keeps_the_record` and `the_wait_ends_by_the_callers_deadline`; `review_step_faults.rs`: `a_teardown_retires_its_record_once_the_opener_lets_go_during_its_wait` and the extended `every_verb_keeps_the_record_of_a_backend_that_outlived_its_disconnect`. These seven failed before (seven failed and 330 passed on the test commit). From the review, `the_failed_start_hook_waits_for_an_opener_after_its_disconnect` (`review_step_faults.rs`), and `a_raw_disconnect_waits_until_the_device_shows_no_connection` now runs on a manual clock and pins the shortened last sleep | [#398](https://github.com/seo-rii/maki/pull/398) |

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-198 | The WebSocket transport opened its connection with `tokio_tungstenite::connect_async_tls_with_config` under one connect deadline. That function makes one `TcpStream::connect("host:port")`, which tries the resolved addresses one after another with no limit for any of them, so an address that never answered held every connect until the deadline, and the address after it, which would have served, was never tried: an IPv6 route that drops packets, or `localhost` resolving to `::1` first on Windows beside a listener on IPv4 only (AUD-193). The ninth round left it open and the status page stated it. With a test resolver and dialer under paused time, a name resolving to an address that never answers and then to a listener, with a 10 s timeout, had still not dialed the second address at 5 s, and the connect failed as a timeout at 10 s. | The provider resolves the URL's host itself, through a private `Dialer` (in production `tokio::net::lookup_host` and `TcpStream::connect`; the tests substitute both), dials the addresses, and runs TLS and the upgrade over the stream with `client_async_tls_with_config`. The addresses are split into the first address's family and the other family, each in the resolver's order. The other family starts 300 ms after the first attempt, or at once when the first family has failed, as hyper-util's connector does for the gRPC transport. Within a family each address but the last may take an equal share of what is left of the deadline and the last has the rest, so one refused at once leaves its time to those after it; the last failure is returned. The first stream that connects wins and the other family's pending attempt is dropped, which closes its socket. Only the TCP connect is raced: TLS and the upgrade run on the winning stream, and their failure, an endpoint failure, is not retried at another address. The first version only shared out the deadline, which still cost a dual-stack host whose IPv6 route drops packets half the timeout on every connect; the family race was added before the review. Review found that the connect's deadline, which predates the round, was the connect's own: it ran a full `timeout` from the start of the connect, while the request attempt's timer starts before the request waits for the connection mutex. On `main` that timer ended such a connect anyway, but with the shares a request that had waited 6 s of 10 s for the mutex dialed its dead first address at 6 s with a 5 s share, and timed out before the live second address was dialed. The connect now ends at the earlier of the attempt's deadline and its own `timeout`, and one whose attempt is over when the mutex is taken opens no socket. Kept: the TLS server name and the certificate check use the URL's host, never a resolved address; the configured trust and client identity; the frame and message limits; no redirect is followed and no proxy read; the connection mutex and the one deadline over resolution, dial and handshake (C-05); a connect failure is retryable and marked unsent; a dying connection fails only its own generation. The [configuration guide](configuration.md#websocket-and-grpc-contracts), the architecture page and the status page describe the connect and how it differs from gRPC's connector, and the development guide's AUD-193 trap now keeps the IP literal for tests that depend on connect timing and names the dialer seam. **Behaviour change:** a host that resolves to several addresses is no longer held by the first that does not answer. A dead first family before a live other one costs about 300 ms per connect, and a dead address before a live one of the same family at most its share of what is left of `timeout` (half of it for two). A host with one address, such as an IP literal, behaves as before, and when no address answers the connect still fails at its deadline with "websocket connect timeout", retryable and marked unsent. A connect opened after the request waited for the mutex now ends with the request's attempt and reports "websocket connect timeout" where the request reported "websocket request timeout"; both are retryable and unsent. | maki-crypto-websocket `connect_address_tests.rs` (most of its tests on paused time, with the substituted resolver and dialer): `a_first_address_that_never_answers_leaves_the_next_one_its_share_of_the_deadline`, `an_address_refused_at_once_leaves_its_share_to_the_addresses_after_it`, `addresses_that_never_answer_fail_as_a_connect_timeout_at_the_deadline`, `a_request_to_addresses_that_never_answer_fails_retryable_and_unsent_within_the_timeout`, `a_dead_ipv6_address_gives_way_to_ipv4_after_300_ms`, `a_preferred_address_that_connects_after_the_other_family_started_drops_that_attempt`, `both_families_dead_fail_at_the_deadline_with_each_family_dialed_on_its_schedule` and, from the review, `a_connect_after_a_wait_for_the_connection_shares_what_the_request_has_left`, which failed before; the controls `a_refused_preferred_family_starts_the_other_family_at_once`, `a_tls_failure_at_the_first_address_is_not_retried_at_the_next` and `an_upgrade_refused_at_the_first_address_is_not_retried_at_the_other_family` (both from the review), `the_certificate_is_verified_for_the_url_host_and_named_to_the_server`, `a_certificate_for_the_resolved_address_alone_is_refused`, `a_resolution_that_never_returns_ends_at_the_connect_deadline`, `the_resolver_is_asked_for_the_url_host_and_the_scheme_port` and `the_system_resolver_reaches_a_listener_by_name` | [#400](https://github.com/seo-rii/maki/pull/400) |

### Provisioning

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-199 | The provisioning guide's first-volume block stops at any failed command and does not clean up, and everything it had created was known only to shell variables, lost with the shell: the connection identifier, the PV, VG and LV UUIDs and the filesystem UUID. When `maki-attach nbd-disconnect` failed after its 15 s wait, the guide said to run `nbd-disconnect` again ("run it again"), without saying how to finish once the identifier and the UUIDs were lost with the shell, and the same held for every step that can fail after the daemon has started. On `04bbc90`, with the suite's mocks, a first run that stopped at the disconnect printed only `Bootstrap stopped at line 103; preserve the layout and inspect it before retrying.`, left no record and the device connected under `maki-bootstrap-<uuid>`; a second run started from the beginning and stopped in its own preflight with `/dev/nbd0 is in use`, never asking for the disconnect again. An observation of the ninth audit. | Only the guide's block and prose change. Before its first change to the host (starting `maki@demo.service`) the block creates a record, `/etc/maki/attach/demo.bootstrap` (root, mode `0600`): the values a later run must share, the volume UUID, the connection identifier and the host's boot ID, then the PV, VG and LV UUIDs once read and validated, then the filesystem UUID. Each version is written and synced under `demo.bootstrap.next` (a leftover staged file is removed, never written into), linked to the record's name the first time and renamed over it afterwards, and the directory is synced, so the record's name never holds an empty or cut-short file and a record that appears during a fresh run stops it. A value that holds a control character is refused before the record exists. A run that stops prints the record and how to go on. Running the block again takes the attach lock first and reads the record instead of checking for unused resources; before any storage, helper or service command it refuses a record that is not a regular file of root's with mode `0600`, has a line it cannot read, an unknown or repeated name, a missing value, a value that differs from the block's or an invalid identity, and it reports a changed boot ID as a restart. A run that does not stop and a continuing run end alike. If the device has holders, it checks the connection, the size, the live VG UUID read with `--devices` and that every holder is an `LVM-<VG UUID>` mapping, then deactivates the VG with `--devices`; it runs `nbd-disconnect` with the recorded identifier and stops the daemon. With a recorded filesystem it makes the mountpoint (an existing one only if it is the empty root-owned `0700` directory a run made, never through a symlink) and the attach configuration (staged, synced and linked; an existing one kept only if it is a regular file with exactly the record's content), syncs them, and only then removes the record. Without one it prints and removes the record and fails, saying that it released the export and that there is nothing to attach. The prose says what must not be done while a record exists (keep it, leave the daemon as it is, release the connection only through the block and never with `nbd-client -d`, and do not activate the VG, mount or format the LV, start the workload or run another bootstrap), what to do after a restart or for a refused record, and how to find what keeps a device open (`udevadm settle`, `fuser -v`); the quick start and the testing guide point to it. Review found the release's message ("before it created the filesystem") false for a run that stopped in `mkfs.xfs` or before it had read the filesystem's UUID, seven mutations of the block that no test caught, no syncs of the record or the configuration, an existing mountpoint taken over unchecked and the record read loosely; all were fixed, and a mutation then showed that a record appearing during a fresh run was merged, which linking the first copy now refuses. The RHEL and Debian installation guides hold no copy of the procedure. **Behaviour change:** a bootstrap that stops after starting the daemon leaves `/etc/maki/attach/<volume>.bootstrap`, and while that file exists, running the block continues from it where a second run failed its preflight. A run that does not stop reads the VG UUID once more and checks the device's holders before it deactivates the VG, syncs the record's copies, the configuration and their directory, and leaves no record or staged file; the attach configuration it writes is unchanged. | `scripts/test_docs_provisioning_validation.py` (`ProvisioningContract`, which runs the guide's block against mocks and runs it again after a stop at each step): `test_every_stop_after_the_first_change_is_recorded_and_printed`, `test_the_next_run_releases_an_unfinished_bootstrap`, `test_the_next_run_finishes_a_formatted_bootstrap`, `test_a_disconnect_that_stays_busy_is_run_again_until_it_succeeds` and the tests of the record's reading, durability and release; 11 of the first 17 tests failed on the base's guide, 12 of 25 on the first fix's, and `test_a_record_that_appears_during_a_fresh_run_is_never_replaced` before its fix. `test_a_record_another_user_owns_is_refused` needs root *Changed on 2026-11-27 by AUD-208 ([#413](https://github.com/seo-rii/maki/pull/413)): a run stopped at `mkfs.xfs` or at `vgchange` and continued from its record ran on a kernel in CI, and `test_a_staged_name_taken_after_its_removal_is_never_written_through` and two more refused records (without a volume UUID, without a boot ID) kill two of the three mutations that had survived; the third is argued equivalent.* | [#402](https://github.com/seo-rii/maki/pull/402) |

### Tests and fuzzing

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-200 | What the root helper parses had no fuzz target, no target had a seed corpus, and nothing built the fuzz crate (AUD-180's open item). At `04bbc90` `fuzz/` held six targets (`format_decoders`, `format_records`, `journal_scan`, `config_parse`, `endpoint_url`, `probe_parsers`), `fuzz/.gitignore` ignored `corpus`, and `ci.yml` did not mention fuzzing. `maki-attach` runs the NBD handshake on the volume daemon's socket and reads the kernel's netlink answer as root, on bytes that an unprivileged daemon and a netlink socket send; only the seeded property tests of `nbd_kernel/property_tests.rs` exercised those readers. The decoders of `maki-backing`'s own records were in no target. And `fuzz/`, a Cargo workspace of its own without a committed `Cargo.lock`, did not get the root's `[patch.crates-io]`: it resolved `serde_json` 1.0.151 and `bytes` 1.12.2 from crates.io, not the vendored copies production builds, so a fuzz run of the JSON records would have tested another decoder. | Each target's body moves into a function of `fuzz/harness` (`maki-fuzz-harness`, a member of the root workspace), and each `fuzz_targets/*.rs` is one line that calls it; a function panics where the code broke a rule its target checks. Three targets are new. `nbd_handshake` (Linux) runs `nbd_kernel::handshake::negotiate` against a server that sends the input and requires the client not to wait on a finished server, to read at most its 64 KiB, to send nothing but its one request and only after a greeting that offers fixed newstyle, to accept only an export the kernel may use and to read exactly the handshake. `nbd_netlink` (Linux) feeds datagrams to the helper's own loop over the kernel's answer, moved unchanged into `netlink::collect`, hands the result to the readers of the family lookup, `NBD_CMD_CONNECT` and `NBD_CMD_DISCONNECT`, and requires that a verdict be what the kernel sends. `backing_records` decodes the local witness anchor, the remote enrollment binding, the remote witness state, the rollback manifest (its decode, validation and canonical encoding now one `parse_manifest`, which local open and the remote `load_generation` call too), a manifest slot as the check of an interrupted creation reads it, and remote namespace names, which GC and the witness's records must read alike, and requires an accepted record to be its own encoding. `maki-privileged` and `maki-backing` expose this behind a `fuzzing` feature that only the harness enables and that adds no dependency; `maki-privileged` still has no crypto dependency. `fuzz/seeds/<target>/` commits 188 seeds, the code's own encodings (for the handshake and the netlink answer, the bytes nbdkit and the kernel send) with copies cut short or changed, named `valid-`, `refused-` or `noise-` by what the target must do with them, generated by `fuzz/harness/src/seeds.rs` and kept byte-exact by `.gitattributes`. `review_fuzz_corpus.rs`, in the default suite, replays every seed on the stable toolchain, requires each of the nine targets to have an entry function, a `[[bin]]` and seeds, and checks that the committed seeds are what the generator writes. A `fuzz` job runs where `nightly-gates` runs (schedule, dispatch, `review/integration-*` pull requests), with a token that may only read the repository, the pinned `nightly-2026-11-24` and `cargo-fuzz` 0.13.2: it copies `Cargo.lock` to `fuzz/Cargo.lock`, builds every target and runs each one that `cargo fuzz list` names for 30 seconds from its seeds. A list that cannot be read or is empty fails it, and a crash fails it and uploads the input. `fuzz/Cargo.toml` patches the vendored `serde_json` and `bytes` as the root does and pins `libfuzzer-sys` and `arbitrary` exactly, and `scripts/test_ci_gate_validation.py` pins the job. Review found that the replay read the fuzz manifest by its LF line ends, so in a checkout with CRLF line ends, as a Windows checkout has, it found no target and the test failed; the reader now walks the manifest's lines, and a test feeds it both line ends. Its notes also led the targets to call the readers' own code (`resolved`, `disconnected`, `parse_manifest`) rather than copies of their rules, which the delta review checked is behaviour-identical. The [testing guide](testing.md#fuzzing) gains a section on fuzzing, SPEC §55 names the job, and the development guide maps the harness and gains a trap for the fuzz workspace's patches; this records change adds one for line ends. **Behaviour change:** none for the helper, the daemon or a packaged binary: the moved loop and readers are unchanged, and a release build (`-p maki -p maki-attach -p maki-check -p maki-nbdkit`) does not turn the feature on, while `cargo build --workspace` does, through feature unification, adding the two doc-hidden modules. For developers, the default suite replays the seeds, a change to an encoding needs them written again (`MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p maki-fuzz-harness --test review_fuzz_corpus`), and the scheduled tier gains a job of about 10 to 15 minutes. | `fuzz/harness/tests/review_fuzz_corpus.rs`: `every_fuzz_target_has_an_entry_a_binary_and_seeds` (which reported the three new targets without an entry, a `[[bin]]` or seeds), `every_committed_seed_replays_through_its_target`, `the_committed_seeds_are_what_the_generator_writes` and, from the review, `the_manifests_targets_are_read_whatever_its_line_ends`, which fails on any checkout with the old reader; `scripts/test_ci_gate_validation.py` (`FuzzJob` and the opt-in condition), whose tests failed before; the `fuzz` job's first run on GitHub, in the dispatch of run 45722124367 on `cd596ce`, without a crash | [#401](https://github.com/seo-rii/maki/pull/401) |

### Not closed in the follow-up round

Each item was checked against `main` at `cd596ce`, with the seven pull
requests merged.

- The HTTP transport sets no connect timeout. Maki gives reqwest only
  `.timeout(spec.timeout)`, and reqwest 0.12.28 then builds its
  `HttpConnector` with `connect_timeout` unset, so a dead address before a
  live one of the same family can take the whole request `timeout`; the other
  family still starts after 300 ms. This is read from the code
  (`async_impl/client.rs`) and not tested: the transport has no seam to model
  an address that never answers, and setting `connect_timeout` would also cut
  a slow but live first address at its share. The status page states it.
  *Closed by AUD-201 ([#405](https://github.com/seo-rii/maki/pull/405)): the
  client is built with `connect_timeout(timeout)`, which hyper-util divides
  among a family's addresses, so a dead address before a live one of its
  family costs its share, half the `timeout` for two; tested on Linux with an
  address whose full accept queue drops SYNs. What remains is in the second
  follow-up round's open list.*
- A dead endpoint address still costs time on every connect: about 300 ms for
  a dead family, and its share of what is left of the timeout within a family
  (AUD-198). With a WebSocket `timeout` of 300 ms or less, the other family is
  never tried when the first does not answer; the gRPC transport's connector,
  read and not tested, ends its last address at the timeout and then starts
  the other family in its background connect worker, which can serve a later
  call. No dual-stack host or real route that drops packets was used: the
  addresses that never answer are the test dialer's, and `localhost` resolving
  to `::1` first on Windows comes from AUD-193's record.
  *Changed by AUD-201 ([#405](https://github.com/seo-rii/maki/pull/405)): with
  less than 600 ms of a connect left, the WebSocket transport starts the other
  family halfway to its deadline, so a `timeout` of 300 ms or less still
  reaches it. The HTTP transport keeps the limitation (reqwest 0.12 does not
  expose hyper-util's 300 ms), and the gRPC connector is unchanged.*
- The detach wait (AUD-197): what keeps a disconnected connection showing is
  read from the CentOS Stream 9 driver, and nothing has shown how often
  something holds a device open at a detach's disconnect, or whether it lets
  go within 15 s. CI's root-only kernel test reaches the shared wait through
  the provisioning disconnect only; detach and cleanup need a whole
  attachment, which it does not build. When the devices of many volumes are
  all held open and the volumes stop together, their cleanups queue on the
  attach lock for 15 s each and, from about the eighth on, reach
  `TimeoutStopSec=120`; the operations guide says what that leaves.
  *Changed by AUD-203 ([#406](https://github.com/seo-rii/maki/pull/406)): CI's
  `kernel-lifecycle` job detaches a whole attachment while another process
  holds the device open. In its two runs whose logs are kept (Ubuntu 26.04.1,
  kernel `7.0.0-1020-azure`), the opener's read failed with `EIO` while the
  device still showed the connection's backend identifier, which stayed until
  the opener closed the device two seconds later, as read from the driver;
  in both runs detach waited for the close (2202 ms and 2193 ms) and succeeded
  in a single invocation.
  The cleanup after nbdkit was killed found the device still connected and
  took its detach path both times, so its disconnected-recovery path has not
  run on a kernel. How often a real opener holds a device, and many volumes
  stopping together, remain unmeasured.*
  *Changed on 2026-11-27 by AUD-205
  ([#410](https://github.com/seo-rii/maki/pull/410)): detach and cleanup wait
  without the attach lock, so the cleanups no longer queue on it for their
  waits; three volumes stopping together were measured on a kernel (AUD-208).*
- `maki check` compares only what the superblock stores (AUD-194): a different
  key under the same name, an unavailable credential, a provider that fails
  its self-test and endpoints that are unreachable or not interchangeable are
  found only at attach, as maki(8) says. Attach compares after opening the
  backing and recovery, so with remote rollback protection it loads the
  witness client's TLS identity and claims a writer at the authority before it
  refuses a mismatched configuration; that case was not run. That attach sends
  no request to an endpoint before the comparison is tested for the HTTP
  provider only; WebSocket and gRPC go through the same functions.
  *Changed by AUD-202 ([#407](https://github.com/seo-rii/maki/pull/407)):
  `maki check` now also reads a remote-protected backing, read-only, and
  compares the configuration with it; to ask the authority it loads the
  witness client's TLS identity, and it sends only inspections. Attach is
  unchanged.*
- A rollback-protected backing whose root or witness directory cannot be
  written is refused, not checked, since that layer has no read-only open, and
  a writable `check` or `inspect` of a protected backing still rewrites its
  pages, manifest, marker and witness record (AUD-195). Only the root decides:
  a writable root whose files cannot be written still fails as before. The
  fast check and `inspect` take no lock, read-only or not. Only Linux asks; on
  other platforms every root opens as before, and CI's Windows jobs are the
  only Windows runs of the new in-process tests. A device mounted read-only,
  an NFS or other read-only export, and `errors=remount-ro` after a real I/O
  error were not run; the mount tested is a read-only bind mount. *Changed by
  AUD-202 ([#407](https://github.com/seo-rii/maki/pull/407)): a local
  protected backing whose root or witness directory cannot be written, and
  every remote one, is read through a read-only view that authenticates it as
  attach does, writes nothing and asks a remote authority only to inspect, and
  through that view the fast check and `inspect` take the writer's locks
  shared. A local pair whose two directories can both be written is still
  opened to write, which takes those locks exclusively, and rewritten; the rest
  of the item stands.*
- The first-volume block (AUD-199) ran only against the suite's mocks: no real
  `maki-attach`, kernel NBD device, LVM, device-mapper, udev, XFS or systemd
  was used, and the holder check relies on two layouts read from documentation
  (a holder under `holders/`, the dm UUID `LVM-<VG UUID><LV UUID>`). Three
  mutations survive, which the delta review found equivalent or failing
  closed: `set -C` dropped when the staged configuration is written, the
  mountpoint's symlink test (`! -L`) dropped, and `boot_id` dropped from the
  required values.
  *Changed by AUD-203 ([#406](https://github.com/seo-rii/maki/pull/406)): CI's
  `kernel-lifecycle` job runs the block as written, after the Debian guide's
  install of a package built from the commit, under systemd with the installed
  units. In its two runs whose logs are kept (Ubuntu 26.04.1, kernel
  `7.0.0-1020-azure`, LVM 2.03.31) a run that did not stop connected
  `/dev/nbd0` with the real `maki-attach`, created the PV, VG, LV and XFS,
  passed the device-mapper UUID and holder checks, deactivated the VG,
  disconnected and wrote the attach configuration, which the quick start then
  attached. A run that stops, and one that continues from its record, still
  ran only against the mocks, and the three mutations still pass the tests.
  The block now exports `LVM_SUPPRESS_FD_WARNINGS=1`, so its LVM commands no
  longer warn about the lock's descriptor.*
- No fuzz run has reached the 24 CPU-hour-per-target qualification: the new
  targets ran 12 minutes each on #401's host, the others less (AUD-200). Not
  fuzzed: `maki-witness`'s RPC and the witness's decoding of requests, the
  crypto providers' HTTP, WebSocket and gRPC response parsers
  (`review_fuzz_transport.rs` covers part of the HTTP path), and the helper's
  readers of sysfs and of command output beyond what `probe_parsers` reaches.
  The `nbd_netlink` seeds are in little-endian byte order: on a big-endian
  host the replay skips them by name, which was checked by reading, and the
  generator's `netlink_seeds` is unused there.
  *Changed by AUD-204 ([#408](https://github.com/seo-rii/maki/pull/408)):
  seven targets read the witness's RPC, its etcd store's reading of etcd's
  answers, the three providers' response readers and the helper's readers of
  command output and sysfs, and a big-endian host now replays netlink seeds
  that its generator makes in its own byte order (checked by reading). The new
  targets ran 4 minutes each on #408's host; the qualification is still
  outstanding.*
- Nothing in this round ran on a real kernel NBD device outside CI's root-only
  tests, with udev, device-mapper or LVM, under systemd with these units, on a
  booted RHEL or Debian host or through a real power loss. CI's Windows jobs
  are the only Windows runs.
  *Changed on 2026-11-26 by AUD-203
  ([#406](https://github.com/seo-rii/maki/pull/406)): CI's `kernel-lifecycle`
  job runs whole attachments through a runner's kernel NBD, udev,
  device-mapper, LVM and XFS, and the quick start under systemd with the
  installed units, on GitHub's Ubuntu runner; nothing has run on a booted RHEL
  or Debian host or through a real power loss.*
- `v0.1.0-rc.1` predates the eighth, the ninth and this round, and no later
  release candidate had been tagged when this was written. *`v0.1.0-rc.2` was
  tagged at `92d4dd4` on 2026-11-26, after this round's records change, so it
  includes this round.*

## Ninth round (2026-11-25): AUD-181–AUD-193

A ninth internal audit examined the eighth round's code: `main` at `27cc86e`
with the branches of #387 and #388 merged into it locally (`1d4c7ea`).
`main` at `e37a2da`, after those two and the eighth round's records change
had merged, differs from that tree only in tests and documents, and the
fixes were written on it. The audit took five angles: the privileged
helper's NBD connection and the RPM, which the eighth round had changed; the
control socket, the command-line tools and guides that earlier rounds had
not compared with the code; storage after the eighth round's changes;
rollback protection and the witness through the real plugin and commands;
and the remote crypto providers through the real plugin. No crash, kill or
injected I/O fault lost or corrupted an acknowledged write. What it found is
one finding of medium severity, AUD-181: a shard-catalog copy that recovery
read from the page cache was never stored again, so writes were acknowledged
for a shard that no durable catalog copy named, against SPEC §14. A crash
alone lost nothing, but after one, a single lost data file made the shard
read as zeros where attach should have refused. Seven findings are of low
severity and three are wrong statements in the documents; review found or
confirmed two more defects that predate the round, AUD-182 and AUD-186. Six
pull requests, [#390](https://github.com/seo-rii/maki/pull/390) to
[#395](https://github.com/seo-rii/maki/pull/395), were merged into `main` on
2026-11-25 (#390 at `de1d889`, #393 at `ef934a2`, #392 at `abf6504`, #391 at
`dc303eb`, #394 at `e941404`, #395 at `c5c036a`). AUD-181 and AUD-182 are
storage (#394), AUD-183 to AUD-187 rollback protection (#391, and #395 for
AUD-187), AUD-188 and AUD-189 the remote providers (#392), AUD-190 the
command line (#393), AUD-191 the log (#395), AUD-192 the documentation
(#390), and AUD-193 what CI found in #392. AUD-181 narrows the exception
that the S-01 truncation residual made for a short data file, and AUD-188
changes how an attach treats a lone remote endpoint; both rows state the
earlier rule and what is kept. Every code fix landed test-first. AUD-189 is
**Partial**: the gRPC case the audit reported, a TLS 1.3 server's refusal of
the client certificate, cannot be classified without owning the TLS stream
and is documented instead, while the TLS failure that reaches a call when
the channel reconnects is fixed. Every other row is **Fixed**. No change
alters a record format or a golden vector. The operator-visible changes are
listed in the [changelog](../CHANGELOG.md#breaking-changes).

Every pull request was read before it merged. #393 had no independent
review: its diff was read by the maintainer who merged it. Each of the other
five had one, and each review led to new commits before the merge. In #390
the first correction of the man page left out the gate configuration that
`verify` reads, whose errors carry the run-as-root hint too; the document
test now pins the hint's call sites (AUD-192). In #391 the review found the
rollback guide's new paragraph false for `maki-benchmark` and for the
backing-root checks that `check`, `inspect` and the benchmark make before
they open the backing, which then got the same wording, and the statement
that the error kinds were unchanged false for a witness path through a
symbolic link, for which the code went back to `main`'s kinds (AUD-184). A
second reading found that the new rule for reserved names refused for good a
root-owned `rollback.format.next` that a creation run as root leaves when it
is killed before it gives the file away, which `main` continued in two runs;
the merged code continues it in one (AUD-186). A third reading corrected
wording only, and that commit was read, not reviewed again. In #392 the
review found that a lone endpoint of a provider that is not retry-safe was
sent an uncertain request twice, by the probe and again by the self-test,
after a warning that said the attach would wait while it failed at once;
that an endpoint failure in an attempt other than the last was ignored; and
that the reconnect test slept (AUD-188, AUD-189). In #394 it found that the
headline test ran a checkpoint between the acknowledged write and the power
loss, so it also passed when the catalog was stored only by that checkpoint,
after the record: with the catalog stored that way, the whole maki-core
suite passed. It also confirmed and reproduced AUD-182 on the same path,
which the implementer had noted without a test. In #395 it found the
operations guide's advice wrong for an uncertain commit and for a page that
fails authentication, three of the five places that stop a session untested
(reverting any of them left all 137 `maki-backing` unit tests passing), and
that the fix commit's message was wrong to say that the control server's
limits bound the new log lines; a delta check then found that a restart
alone does not reopen a volume with a remote witness whose session stopped
(AUD-187, AUD-191). That last correction, to the guide, was read, not
reviewed again. CI found one thing the local runs had not (AUD-193).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy on 1.94.0 and 1.100.0, `cargo fmt --check`, the Python suites
and the link checker, with fails-before runs of the test commits and
mutation checks. #391, #393, #394 and #395 also ran their new tests as uid
65534 with an empty `/run` in a private mount namespace. #394 ran the
extended gates `phase_r3b_media_damage_gate_full` and
`phase_r3b_durability_gate_full` at its head, one at a time in the debug
profile, and `trim_power_loss_gate_full` and `phase12_gate_full` at its
first head. Both of its reviews ran the two r3b gates again and a cut sweep
of 35,224 runs; the first also ran 11,000 random fault histories at the
first head and 3,000 on `main`, the second 6,000 at the head, all without a
failure. #392, #394 and #395 ran Maki's plugin in nbdkit 1.36.3: #394 also
through a probe with libnbd that damaged a volume written through the
plugin, #395 under a daemon whose `fdatasync` failed during `maki
checkpoint` and `maki drain` and beside one that `maki volume takeover`
replaced. #391 and #393 drove their built binaries by hand, #393 under
strace. The audit itself ran, without a violation: a model of the helper's
device move with five kinds of foreign change at each of the fifteen backend
reads of a moved attach, the busy retry against a real nbdkit, and the RPM
in a CentOS Stream 9 root (upgrade from `v0.1.0-rc.1`, dnf's refusal to
remove Maki or a package it needs, the conflicts, reinstall, downgrade and
`rpm -e` under a record); hostile control clients, 182 stops by SIGTERM or
SIGKILL under racing control verbs, and 1,080 damaged volumes on which the
offline tools and attach agreed; crash-only sweeps (17,654 seeds with
metadata sync faults, and 24,387 seeds around the catalog window of AUD-181
with 159,087 injected catalog sync failures), the shard states at open
crossed with a fault at each operation (97,560 runs on v2, 97,152 on v3),
and 3,275 power-loss images of the real plugin, none refused; for rollback
protection 3,274 remote and 4,456 local power-loss images, every one opened,
1,221 remote and 1,092 local images with the backing rolled back and 570
with the witness rolled back, none accepted with older data, 1,193 cuts
inside takeover, claim, fork, activation and GC, and a three-member etcd
3.6.6 with TLS through quorum loss; and for the providers 15 TLS cases
through nbdkit on the three transports, chaos sweeps with kills and
restarts, salted response fuzzers (8,000 calls each for WebSocket and gRPC,
three times 8,000 for HTTP) and certificate fields that carry escape
sequences, none of which reached a log. Nothing ran on a real kernel NBD
device outside CI's root-only tests, with udev, device-mapper or LVM, under
systemd with these units (the `TimeoutStartSec` path of AUD-188 is read from
the unit), on a RHEL kernel or through a real power loss. The audit's host
has no IPv6, and the cause of AUD-193 was found by reading, with no Windows
host.

### Storage

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-181 | `SlotStore::open` took the loaded shard-catalog copy as durable and stored it again only when it adopted an orphan data file. The first store of the catalog that names a new shard can fail at its `fdatasync`, which refuses the write that needed the shard; after a plain restart the page cache still shows that copy (K-01). The writer then acknowledged FUA writes, FLUSHes and checkpoints for the shard while no durable catalog copy named it, against SPEC §14 ("Both allocation-map copies and the catalog entry of a newly touched shard MUST already be durable" before a journal record is accepted) and §27. The allocation maps the same open loads are stored again before the first reservation (BUG-043); the catalog was not. In the audit's reproduction, after the failed sync, a restart, acknowledged FUA writes, a FLUSH and two checkpoints, a power loss left the catalog copies at generation 1 (the creation's empty catalog) and none. A crash alone lost nothing, since open adopts a data file the catalog does not list: a crash-only sweep around the window found no failure. But what depends on the catalog naming the shard went with it, and two other gaps decided what a damaged volume then served. Open and the fast checker found shards only through the loaded catalog copy and the `*.dat` names, so the allocation copies of a shard without a data file were never read: one lost data file made the whole shard read as zeros, its checkpointed units included, and `maki check --deep` reported no error and no warning, where a cataloged shard with a missing data file refuses attach (BUG-027). And open took an uncataloged shard whose loaded allocation map lists nothing for one whose creation never finished before it looked at the slot headers, so a slot beyond the end of its short file was a hole. With the newest allocation copy and the data file's tail damaged as well, checkpointed units beyond the cut read as zeros; the first attach then grew the file back, stored the map and cataloged the shard, after which the next attach and the deep check saw a healthy shard. Through the real plugin, a volume whose newest catalog and allocation copies were each cut by a byte and whose data file was cut inside a slot passed the deep check ("deep check verdict: clean") and served a flushed, checkpointed unit beyond the cut as zeros, while it served a unit below the cut from its slot. The reproductions fail on `956e354` as well, and the open-time rule they meet is in the repository's first commit. | Three test-first steps in `crates/maki-core/src/store.rs` and the fast checker. (1) `catalog_dirty` starts set whenever the loaded catalog names a shard. The allocation persist that the first reservation of a loaded shard and an idle checkpoint already ran (every loaded map is unproven at open) now stores the catalog too, after every unproven map and data-file size, as the commit of an adopted catalog always did (K-03); the preserve-first step of `AbStore::store` rewrites and syncs the readable copy before the other side is written, and AUD-171's emptying of an undecodable side applies unchanged. No write record is accepted for a loaded shard before that store; a v3 discard tombstone needs no slot, is appended without a reservation and is applied to the shard in memory, cataloged or adopted. The empty catalog of a new volume is left as created. (2) Open and the fast checker also collect the shards that have an allocation-map copy (`layout::parse_shard_alloc`, the exact names only). For a shard the loaded catalog copy does not name and that has no data file, a selected copy that lists a slot at a position of the device refuses attach ("shard N: data file missing: the loaded catalog copy does not name the shard, but its allocation map lists written slots") and is an error of the fast check and, through the slot store's open, of the deep check; a valid copy of the wrong size refuses too. A checkpoint writes into a shard only after its creation made the data file durable, so such a map proves the file existed. A copy that lists nothing, or no valid copy, is what an interrupted creation leaves (its maps are stored before the data-directory sync that publishes the data file) and stays harmless. Discard maps are not used to find shards: a set discard bit means zeros, not lost data. (3) An uncataloged shard with an empty loaded map counts as never written into only if no slot of the device below the end of its file has a header byte that is not zero, counting a header the end of the file cuts (`holds_written_slot`). Only a slot write puts bytes there, and a data file's size is proven durable before the first slot write into it, so the headers cannot fall back to an earlier generation as the catalog and the map can. Otherwise a short file is truncation: its cleared slots beyond the end are marked allocated and read as EIO, as for a cataloged shard (S-01). SPEC §22 states the rules (§14 already stated the first), and the [architecture guide](architecture.md) names the new refusal. Review before the merge took the checkpoint out of the headline test (`9b336f5`): a checkpoint stores the catalog too, so with it the case also passed when the catalog was stored only after the record. A reviewer's mutant that stored the loaded catalog only in a checkpoint's allocation persist passed the whole maki-core suite (579 tests, the audit's eight reproductions among them, untracked then). The development guide's S-01 trap states the third condition and the refusal, and gains a trap for tests of an ordering rule. **Behaviour change:** every attach of a volume whose catalog names a shard stores the catalog once more, at the first write into a loaded shard, the first idle checkpoint or recovery's replay of records into a loaded shard, whichever comes first; reads still write nothing, and a failed store fails that write or checkpoint, which the next one retries. A cataloged shard whose data file is truncated has its damage marks stored and its file grown back at that point too, so the deep check afterwards reports those units as allocated slots with an invalid header rather than as units beyond the end of a truncated file. A volume with a shard as in (2) no longer attaches and both checks report it, where it attached and read zeros. A short uncataloged shard with a written slot reads EIO beyond its end, where it read zeros. Open now reads the allocation copies of (2) and the headers of (3), and an I/O error on either fails the attach (the deep check reports it as inconclusive). `holds_written_slot` costs up to one 64-byte read per slot of the device for each shard that open adopts with an empty map, at every open until the first write or idle checkpoint catalogs the shard. Kept: an interrupted creation still reads as unwritten and is completed by the next write, and a shard whose size no sync has proven is still sized again before its first write. | maki-core `review_shard_readiness.rs`: `cached_catalog_entry_after_failed_sync_is_stored_before_fua` (v2 and v3; "shard 0: catalog entry must precede ACK" before the fix); `review_shard_evidence.rs`: `allocation_copies_that_list_slots_without_a_data_file_refuse_attach` and `a_short_uncataloged_shard_with_a_written_slot_reads_eio_beyond_its_end` (the file cut inside slot 4, or inside the header of the first written slot), which failed before, and the control `allocation_copies_that_list_nothing_without_a_data_file_stay_harmless`; `reading_recovered_shards_defers_allocation_republication` passes unchanged; the extended gates `phase_r3b_media_damage_gate_full` and `phase_r3b_durability_gate_full` | [#394](https://github.com/seo-rii/maki/pull/394) |
| AUD-182 | Noted without a test by the implementer of #394, then confirmed and reproduced by its review, on the same path; identical on `e37a2da`. Both catalog commits publish the whole in-memory catalog, and a cataloged shard's short file is truncation damage, so a shard whose data-file size no sync has proven must not be named. The allocation persist's commit proved the size of every such shard; a new shard's creation (`ensure_shard`) proved only the shards whose allocation maps were not stored yet. An adopted shard can have its maps stored and its size proof fail, since the persist stores the maps and marks them proven before its catalog step. A later write into a new shard then cataloged the adopted shard with a size no sync had established: after a power loss its data file had length zero and every unit of it, none ever written, read as EIO, and the fast check reported nothing. | The persist's loop is a helper, `prove_unproven_data_files`, which `ensure_shard` now runs as well, after storing the adopted shards' maps and before the data-directory sync and the catalog store. **Behaviour change:** a new shard's creation proves the size of every shard whose size is not proven before its catalog commit: an adopted shard's file is set to its size and synced, and a truncated shard's damage marks are stored before its file is grown back. A failure there fails the write that needed the new shard, which the next write retries. | `adopted_shard_whose_size_proof_failed_is_sized_before_another_shard_catalogs_it` (maki-core `review_shard_readiness.rs`, v2 and v3), which failed before: unit 0 of the adopted shard, never written, read as "allocated but slot header invalid" | [#394](https://github.com/seo-rii/maki/pull/394) |

### Rollback protection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-183 | `maki volume gc` on a remote backing root that does not hold the authority's current generation (the root restored to an earlier state, or another volume's root) refused before it deleted anything, but said only "No such file or directory (os error 2)" when the current namespace was missing, and "no exact remote witnessed manifest" when the namespace held an older generation. Nine `gc` runs of the audit on restored or foreign roots printed the first. Attach, `volume takeover` and `volume snapshot` refuse the same roots with "this backing root does not hold the remote authority's current generation (...); check the witness address and backing root before retrying". | GC and attach's check (`holds_current`) word the refusal through one function, `not_current`. `maki volume gc` and the automatic pass after an activation, whose `WARN` carries the error, refuse such a root in attach's words, and a missing namespace is reported as attach finds it, with no candidate manifest. An error that does not prove a mismatch, such as unreadable storage or a namespace that crosses a mount, keeps its text. What GC retains and deletes is unchanged. The automatic pass cannot meet a missing current namespace, which it has just activated, and is not tested on its own. | `gc_on_a_root_without_the_current_namespace_says_what_it_found`, `gc_on_a_root_whose_current_namespace_is_older_says_what_it_found` (maki-backing `review_remote_gc_foreign_root.rs`), which failed before | [#391](https://github.com/seo-rii/maki/pull/391) |
| AUD-184 | A protected local volume whose `backing.rollback_protection.witness_root` does not exist (a typo, or a witness filesystem whose mount point is empty after a reboot) failed in the daemon with "startup failed: adapter error (errno 5): No such file or directory (os error 2)", and `maki check`, `check --deep`, `maki volume inspect` and `maki-benchmark` printed the bare error: `RollbackBacking::open` resolved both paths, with the system's error, before the worded refusals of a missing marker or anchor (AUD-169), which it reaches only once both directories exist. A backing root or witness directory the user may not open got a bare "Permission denied (os error 13)" from the same path. | A new module, `maki_backing::configured` (`BACKING_ROOT`, `WITNESS_ROOT`), opens a configured directory read-only, creates nothing, and words an error met on it with the directory, its path, the setting that names it and what to check, for example "the rollback witness directory <path> (`backing.rollback_protection.witness_root`) does not exist: check the configured path for a typo and that the filesystem that holds it is mounted", or, for a path that is not a directory, what is wrong with it (a symbolic link, which is not followed; a path through one; a component that is not a directory). `RollbackBacking::open` checks both directories this way first. Review before the merge found the rollback guide's new paragraph false for `maki-benchmark` and for the backing-root checks that `check`, `inspect` and the benchmark make before they open the backing ("<root>: not a directory", "unsupported: backing root is not a directory"); `existing_backing` in `maki` and `volume_layout_present` in maki-nbdkit now use the module too. It also found that the claim of unchanged error kinds was false for a witness path through a symbolic link: the kinds are again those that opening the pair gave, the system's, and InvalidInput for a witness path that, followed, is not a directory. `volume create`, which creates missing directories before it opens anything, is unchanged, and `maki-benchmark` still creates both where the backing root holds no volume. The [rollback guide](rollback-protection.md) says what each command does. **Behaviour change:** message texts. Because the checks run first, a backing root that is a file on the witness's filesystem is NotADirectory where the independence check made it InvalidInput, and a witness the user may not open beside a root without its marker is PermissionDenied where the marker check made it NotFound. `check` and `inspect` word a backing root they cannot open this way for plain volumes too. The benchmark's refusal of a root that is not a directory is an I/O error where it was `DaemonError::Unsupported` (status 1 either way), and `maki-benchmark` on a symbolically linked backing root that holds a volume, without `--destroy-data`, exits 1 ("... is a symbolic link, which is not followed") where it exited 2. Other exit statuses and the daemon's errno 5 are unchanged. | maki-backing `review_rollback_configured_dirs.rs`: `a_missing_witness_directory_is_named_with_its_setting`, `a_missing_backing_root_is_named_with_its_setting`, `a_witness_path_that_is_a_file_is_named_with_its_setting`, `a_backing_root_that_is_a_file_is_named_with_its_setting`, `a_path_that_is_not_a_directory_is_named_with_what_is_wrong`, `a_backing_root_path_that_is_not_a_directory_is_named_with_what_is_wrong`, `a_directory_this_user_may_not_open_is_named_with_its_setting` (run unprivileged), control `creation_still_makes_a_missing_witness_directory`; `a_root_that_cannot_be_opened_is_named_with_its_setting` and `a_root_this_user_may_not_open_is_named_with_its_setting` in `bins/maki` `review_existing_repository.rs`, and `a_root_that_is_not_a_directory_is_named_with_its_setting` and `a_root_this_user_may_not_open_is_named_with_its_setting` in maki-benchmark `review_rollback_reuse.rs` | [#391](https://github.com/seo-rii/maki/pull/391) |
| AUD-185 | A local backing without its format marker was refused with "either a volume create did not complete here, which running volume create again continues, or this is not the volume's backing root" (AUD-169), and `volume create` appended that text to its own refusal. But `volume create` refuses, and keeps refusing, a pair that holds anything an interrupted creation does not leave: the `lost+found` of a filesystem mounted at the backing root, another file in the witness directory, a manifest slot that holds data. In the audit's reproduction with a `lost+found`, two runs of `create` each refused and each said that running it again continues the creation. | The refusal makes the judgement `volume create` makes (the per-entry rule of `require_unpublished_local` moves, unchanged, into one function). Where nothing in either directory stops a creation, it still says that running `volume create` again continues it. Otherwise it names, per directory, the entries that stop it (sorted, quoted, at most four and a count of the rest) and offers nothing: "this rollback backing holds no format marker (rollback.format), and volume create does not continue a creation here: the backing directory holds "lost+found", which an interrupted creation does not leave. Either this is not the volume's backing root, or volume create needs directories that hold nothing else". When either directory cannot be listed, it offers nothing either. The open lists the witness directory read-only for this and opens the witness only after the marker check, as before. What `volume create` accepts, refuses and continues is unchanged. | maki-backing `review_unmarked_local_root.rs`: `a_backing_root_holding_lost_and_found_is_not_offered_to_create`, `a_witness_directory_holding_another_file_is_not_offered_to_create`, `a_manifest_slot_holding_data_is_not_offered_to_create`, controls `an_interrupted_creation_is_still_offered_to_create_which_continues_it` and `a_root_that_cannot_be_listed_is_offered_nothing`; maki-format `a_root_without_a_marker_that_create_refuses_is_not_said_to_be_continued` (`review_interrupted_volume_create.rs`) | [#391](https://github.com/seo-rii/maki/pull/391) |
| AUD-186 | Found by the review of #391; it predates the round. A local creation writes the names it reserves (`rollback.format.next`, `rollback.arena` and the manifest slots `rollback.manifest.0` and `.1`) again from the start, which holds only for a regular file with one name, and its check of the backing did not look at the kind of entry it found. The review ran the creation twice for each planted entry on `e37a2da`. A directory, a symbolic link, a FIFO or a second name under `rollback.arena` let it publish its marker and then fail on the entry, at that run and every later one. A symbolic link or a directory under `rollback.format.next` failed every run before the marker was published (ELOOP, EISDIR), since the failed run's cleanup can remove neither; a FIFO or a second name there failed the first run, whose cleanup removed it, and the second run created the volume. Any of the four under a manifest slot was refused before anything was published, with the bare error of the open that checks the slot's contents (`unpublished_slot`: the system's for a link or a directory, `FileBacking`'s unworded one for a FIFO or a second name). A file under one of these names that the user may not open is also what a creation run as root leaves when it is killed between creating the file under its name and giving it to the directory's owner (with `O_CREAT` and `O_EXCL`, then `fchown`, on a filesystem without unnamed temporary files): `main` failed on such an arena with the bare "Permission denied" after publishing the marker and on such a slot before publishing anything, and for the staged marker the failed run removed the file and the next one created the volume. | Each of these names is accepted only as a regular file with one name that this user can open, with the check #387 gave the remote staged names (`unwritable`); anything else is refused before anything is published, the refusal names the entry, and the refusal of a root without its marker (AUD-185) does not offer `create`. The staged marker, which nothing reads, is the exception: `publish_marker` removes whatever is under its name before it stages the marker, as a leftover `anchor.next` is removed (AUD-111), so an entry there that this user may not open is removed (only that name) and the creation continues; a directory or a symbolic link there is still refused, since `FileBacking` removes neither. An arena or a slot this user may not open is refused before anything changes, with the kind PermissionDenied and the way out: "the backing directory holds "rollback.arena", which this user may not open (Permission denied (os error 13)): give it to the user this command runs as (chown), let that user read and write it (chmod) and run the command again". The first version refused the root-owned staged marker for good, a state `main` continued in two runs (the first failed with `Permission denied` and removed the file); the review's second reading found it, and the daemon user's `volume create` now continues it in one run. `publish_marker` is shared with the remote root's creation, whose #387 check still refuses a staged marker the user may not open before it. The development guide's AUD-111 traps say so. **Behaviour change:** `volume create` refuses a root whose arena, slot or staged marker (one this user may open) is not a regular file with one name with "rollback enrollment requires empty backing and witness directories" followed by the open's refusal that names the entry. For the arena it used to publish its marker and then fail at every run, for a link or a directory under the staged marker's name to fail every run before the marker, and for a slot to fail with the bare error of that open. A FIFO or a second name under the staged marker's name that this user may open, which `main`'s failed first run removed, is now refused until it is removed. A staged marker this user may not open is removed and the creation continues in one run, and an arena or slot this user may not open is refused with the way out. | maki-backing `review_unmarked_local_root.rs`: `a_reserved_name_that_is_not_a_regular_file_is_not_offered_to_create`, `a_staged_marker_this_user_may_not_open_is_replaced_in_one_run` and `a_reserved_file_this_user_may_not_open_is_named_with_the_way_out` (mode-000 files, run unprivileged); `review_root_staged_marker.rs`, which needs root, is listed in `scripts/run_root_tests.py` and runs the daemon user's commands as uid 65534: `a_staged_marker_root_left_is_continued_by_the_daemon_user`, `an_arena_root_left_is_named_with_the_way_out_and_continued_once_given_back` | [#391](https://github.com/seo-rii/maki/pull/391) |
| AUD-187 | A rollback-protected session stops for good when it observes a change it did not make or cannot tell the outcome of its own commit: after `maki volume takeover` or a restore beside a live daemon, for example, or an older local anchor put back. Every later read, write, FLUSH and checkpoint then fails with EIO. The stop was recorded only inside the backing, so `Engine::state` kept answering `ready`: `maki status` showed `state: ready` with no degraded reason and `maki_volume_state` 1. It changed only when the checkpoint worker's next pass failed, about 30 s later, and never when the journal had already been checkpointed: the audit saw `ready` for all of the 75 s it watched while every request failed, and the log held only the failed requests. | `Backing` gains `session_stopped()`, which defaults to `None` and answers without storage or witness I/O. The rollback backing routes every place that stops its session through one `State::stop`: a witness check that stops it, a failed or uncertain manifest commit, a missing, short or invalid referenced arena page, a page that fails authentication and a failed arena write. `stop` records the first cause in a `OnceLock`, read without the state lock (commits hold that lock across witness calls), and logs one `WARN`, `rollback session stopped: <cause>; every operation fails until the volume is opened again against the witness`. `Engine::state`, and through it `maki status`, `stats()` and `maki_volume_state`, reports such a volume as degraded with `rollback session stopped: <cause>; every request fails until the volume is attached again; if another writer took it over, leave this daemon stopped`, ahead of any checkpoint or journal state; nothing clears it. Which failures stop a session, and what a stopped one refuses, are unchanged. The [operations guide](operations.md#failure-handling) says what to do for each group of causes. Review found three of the five stop sites, the arena page cases, untested: reverting any of them left all 137 `maki-backing` unit tests passing. A delta check found that with a remote witness a restart alone does not reopen the volume: the stopped daemon's shutdown drain fails, so it never releases its session, and the authority refuses the next daemon's claim until `maki volume takeover`, which keeps every acknowledged write; with a local witness a restart reopens it. The guide says so. **Behaviour change:** such a volume reports `state: degraded`, the reason above and `maki_volume_state` 2 from the first request that finds the stop, where it reported `ready` until a worker pass failed, or for good, and the daemon logs one new `WARN` per stopped session. Before any request has asked the witness, status still says `ready`, since status does not call the witness, and a remote witness that is unreachable still refuses each operation without stopping the session. | maki-core `review_stopped_session_state.rs`: `a_takeover_beside_a_live_engine_degrades_it_at_its_first_refused_request` (a remote witness over an in-process authority, the journal checkpointed before the takeover) and `an_older_local_anchor_put_back_degrades_the_engine_at_its_first_refused_request`, which failed with "a stopped session reported ready" and count every such warning; the rollback unit tests that cut a commit check the recorded cause; from the review, the arena tests of `maki-backing` pin the cause of each page stop, `an_older_page_put_back_stops_the_session_on_authentication` among them | [#395](https://github.com/seo-rii/maki/pull/395) |

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-188 | The daemon probes each endpoint of a set on its own at attach and refuses the attach with "no remote endpoint is reachable; attach refused" when none passes. A lone endpoint skipped that probe and was left to the engine's self-test, which goes through the dispatcher, and under the default `stall` the dispatcher waits for an endpoint without end. An attach whose only endpoint had a certificate for another host, an untrusted CA or a refused client certificate, on any of the three transports, therefore never ended: in the audit's runs it logged nothing, bound no control socket, sent no `READY` and did not end on SIGTERM, which nbdkit ignores while its startup callback runs. Two endpoints failing the same way were refused in 0.3 s, and one under `bounded-error` in 4.3 s. Under systemd `maki@` would be killed at `TimeoutStartSec` with no Maki line naming the cause. The configuration guide said that the attach fails when no other endpoint is reachable, and the changelog that a single private gRPC endpoint that no root vouches for still fails at the self-test's handshake. | A lone endpoint is probed like the endpoints of a set, with three attempts for a `retry_safe` provider and one otherwise. Across its attempts the probe records the first endpoint failure and whether any attempt may have reached the endpoint. An endpoint failure in any attempt (a TLS authentication failure, a 401, 403 or 404, an invalid WebSocket upgrade) refuses the attach under either policy, and so does a failure after which the request of a provider that is not `retry_safe` may have reached the endpoint (a 5xx, a timeout, a lost response), since that request is never sent again (SPEC §18). A lone endpoint whose failures were all transient is left to the dispatcher under the policy only when the probe's request may be sent again (the provider is `retry_safe`, or every attempt failed before the request left Maki), after a `WARN`: ``endpoint "only" unreachable at attach (retryable: HTTP 503); it is the only endpoint, so the attach keeps retrying it under the `stall` availability policy``. Every refusal names each endpoint's failure (the first endpoint failure among its attempts, otherwise the last), for example `no remote endpoint is reachable; attach refused ("only": endpoint fatal: HTTP 401)`. Rejected: refusing every lone endpoint that fails its probe, which broke `transient_5xx_is_ridden_out_by_the_dispatcher` and would keep a volume down after its provider restarted while the daemon started, since `maki@` has no `Restart=`. Kept: a set whose endpoints are all transiently down is refused, as before. Review before the merge found that a lone endpoint of a provider that is not retry-safe was sent an uncertain request twice, by the probe and then by the self-test, after a warning that said the attach would wait while it failed at once (`main` sent it once, and `non_retry_safe_initial_canary_probe_must_be_sent_only_once` guards the same rule for sets), and that an endpoint failure in an attempt other than the last was ignored. SPEC §34 and §35, the [configuration guide](configuration.md#websocket-and-grpc-contracts) and the PostgreSQL guide state the rule. **Behaviour change:** a lone endpoint gets one more self-test and canary round at attach, the probe's before the engine's own. One that fails the self-test with anything but a transport failure is refused with "endpoint "<name>" failed its self-test: ...", the message a set's endpoint already got, and a lone endpoint's refusal states its cause with no "quarantined" warning before it. `normal_dispatch_does_not_resend_non_retry_safe_request` now serves the probe first and pins what it pinned. The engine's self-test after a passed probe still goes through the dispatcher, so under `stall` an endpoint that fails afterwards is waited for without a warning of its own (SPEC §35). | maki-nbdkit `review_single_endpoint_attach.rs`: `an_only_endpoint_with_another_hosts_certificate_refuses_the_attach_with_the_tls_failure` and `an_only_endpoint_of_a_provider_that_is_not_retry_safe_is_probed_once`, each over HTTP, WebSocket and gRPC, and `an_only_endpoint_that_is_away_is_named_and_waited_for_under_stall`, which failed before, the control `an_only_endpoint_that_serves_still_attaches_under_stall`, and from the review `a_non_retry_safe_lone_endpoint_is_sent_an_uncertain_request_once`, `an_endpoint_failure_in_any_probe_attempt_refuses_the_attach` and the control `a_non_retry_safe_lone_endpoint_whose_failure_was_not_sent_is_waited_for`; `a_retry_safe_lone_endpoint_probe_is_retried_three_times` and `a_non_retry_safe_lone_endpoint_probe_is_sent_only_once_and_refused` (`review_attach_retry.rs`); `transient_5xx_is_ridden_out_by_the_dispatcher` (`phase8_daemon.rs`) unchanged | [#392](https://github.com/seo-rii/maki/pull/392) |
| AUD-189 | The gRPC provider classified a TLS failure that reached a call as retryable: it recognised TLS errors only in its own connection attempt, and `map_status` classified every status by its code. A TLS 1.3 server refuses a missing or untrusted client certificate after the client has finished its side of the handshake, so the refusal reaches the first call, as `Unknown`, `Cancelled` or `Unavailable`. The endpoint's circuit was therefore not opened at once, a lone endpoint under `stall` was retried without end (AUD-188), and nothing named TLS. HTTP and WebSocket report the same refusal as an endpoint failure ("TLS authentication or protocol failure") when they read the server's alert, and gRPC did under TLS 1.2, where the refusal happens inside the handshake; the configuration guide said it is an endpoint failure on all three transports. The pull request found a second way in: tonic also dials inside an established channel, so when the connection under a cached channel closes, the next call reconnects there, and a handshake that fails then (a server restarted with a certificate the client does not trust) reaches the call as a status whose source holds the rustls error. | **Partial.** `map_status` walks a local status's source chain with the connection attempt's own classifier and returns the endpoint failure `grpc TLS authentication or protocol failure` when the chain holds a rustls error. Nothing a peer sends can claim one: a status decoded from its trailers has no source, and the chain of one made from an HTTP/2 reset or GOAWAY ends in an `h2::Error`, which has no source of its own. Unlike other errors that are not retryable, such a failure does not keep the cached channel: the next call reconnects through the provider's payload-free connection attempt, not through tonic's reconnect with the request queued. The reported case is not fixed. h2 keeps only the kind and text of the connection's error, or hyper cancels the call with "connection closed", and Maki never classifies by text; recognising it would need Maki to own the TLS stream (replacing tonic's connector, or putting `http` in `:scheme` on the wire) or a patched h2. The [configuration guide](configuration.md#provider-error-signals) and the [status page](status.md#known-limitations) state the limitation. The refused call counts as sent, so a lone such endpoint of a `retry_safe` provider is waited for under `stall` after AUD-188's warning, which says `retryable: grpc status Unknown from remote crypto provider`, while one of a provider that is not retry-safe (the default) is refused at attach under either policy, with that status named in the refusal. Review made the reconnect test stop sleeping: it tells a call that reconnected inside its channel from one handed to the dying connection by the proxy's connection count. **Behaviour change:** a TLS error inside a gRPC call is `EndpointFatal`, which opens the endpoint's circuit at once instead of after `failure_threshold` failures. | maki-crypto-grpc `review_tls_failure_in_call.rs`: `a_certificate_refused_when_a_cached_channel_reconnects_is_an_endpoint_failure` and `a_local_status_whose_source_is_a_tls_error_is_an_endpoint_failure`, which failed before; controls `a_status_without_a_tls_source_keeps_the_class_of_its_code`, `a_status_a_peer_sends_cannot_claim_a_tls_failure` (trailers and an HTTP/2 reset that name a TLS failure in their text) and `a_tls12_refusal_inside_the_handshake_is_an_endpoint_failure`; the limitation is pinned by `a_tls13_refusal_of_a_missing_client_certificate_reaches_the_call_as_its_status`, `a_tls13_refusal_of_an_untrusted_client_certificate_reaches_the_call_as_its_status` and `mtls_rejects_missing_client_identity_and_accepts_configured_identity` (`tls_tests.rs`) | [#392](https://github.com/seo-rii/maki/pull/392) |

### Command line

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-190 | `maki` bound the word after a command to the configuration path whatever it was. With the configuration forgotten, `maki check --deep` opened a file named `--deep` and exited 1 with `error: --deep: No such file or directory (os error 2)`, and so did `maki status --help`, `maki volume create --discard`, `maki volume inspect --help`, `maki drain --bogus` and every other word where `maki` expects a volume or administrator configuration, a backup directory or a reload section. maki(8) and AUD-137 say that misuse, a misplaced option included, exits 2 before anything is read, and the option after the configuration (`maki check /x.toml --bogus`) already did. `maki-witness` had the same pattern for the path of `init`, `init-etcd`, `serve`, `inspect` and `fingerprint`, and `maki-witness init --state <uuid>` created a state directory named `--state` in the working directory and exited 0. | `maki` refuses a word that starts with `-` in those places with `error: expected the volume configuration, found the option "--deep"` (or the backup directory, the administrator configuration, the reload section), then the usage, and exits 2 before it opens any file or socket; with `--socket` the reload section is checked too, and `volume inspect`, which takes its path as raw bytes before the UTF-8 check (AUD-144), hands a leading `-` to the same refusal, where it excluded only `--socket` and `--timeout`. `maki-witness` refuses such a word with `maki-witness: <command>: expected a path, found the option "--state"`, the usage and status 2, before it opens a configuration or certificate or creates a state directory. `--help` after a command is misuse like any other misplaced option, the rule `review_cli_help.rs` pins for `maki-attach`, `maki-witness` and `maki-benchmark` (help and version are honoured only as the sole argument, AUD-123). A file whose name starts with `-` is named `./-name`; nothing reads a configuration from standard input, so a bare `-` never meant one. maki(8) and the testing guide say so. `maki-check` and `maki-benchmark` already treat every such word as an option and are unchanged. This pull request had no independent review. **Behaviour change:** those command lines exit 2 with the reason and the usage, where they exited 1, or 0 for `maki-witness init --state <uuid>`; a file really named after an option is now given as `./--name`. | `an_option_where_a_path_belongs_exits_2_before_anything_is_read` (`bins/maki` `review_misuse_status.rs`, 21 command lines in a directory that holds a file of each option's name that is not a configuration; the control `maki check ./--deep` still opens its file and exits 1) and `an_option_where_a_path_belongs_exits_2_before_anything_is_read_or_created` (`bins/maki-witness` `review_misuse_status.rs`, six command lines), which failed before | [#393](https://github.com/seo-rii/maki/pull/393) |

### Observability

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-191 | The [observability guide](observability.md#logs) said that "a `state: degraded` in `maki status` therefore has a matching `WARN` line". A checkpoint requested with `maki checkpoint`, or run by `maki drain`, that failed left the volume degraded (`checkpoint failed: ...`), and a failed drain also left I/O admission closed, so every NBD request was refused with ESHUTDOWN, yet the daemon logged nothing: only the checkpoint worker logged its own failures. The audit failed every `fdatasync` during one `maki checkpoint` and one `maki drain` of a real daemon; status reported `degraded` and `io_state: failed`, and the daemon's log was empty. | The control backend logs `requested checkpoint failed: <error>` when a `checkpoint` verb fails, and the drain gate logs `drain failed: <error>; I/O admission stays closed until a drain succeeds` for the `drain` verb and for the drain that shutdown runs, where it comes before the plugin's existing unload `ERROR`. Each is one `WARN` per failed request; a request that succeeds logs nothing, and the worker's lines are unchanged. With AUD-187 the guide's sentence holds for the failures it lists (an `ERROR` line for a stopped engine); it names the new lines, and the operations guide's log table lists them. No rate limit is applied. The control server runs one checkpoint, reload or drain at a time and serves at most 64 sessions, which bounds concurrency, not rate: in review one session logged 5,000 such lines in 2.3 s while checkpoint syncs failed. Only root, the daemon user and members of the control socket's group can send these requests, as for the per-session error line the server already logs without a limit. The fix commit's message said that the session and verb limits bound the number of lines; the pull request's text corrects it. | maki-nbdkit `review_requested_checkpoint_log.rs` (on `ManualClock`): `a_failed_requested_checkpoint_logs_one_warning_with_its_error`, `a_failed_drain_logs_one_warning_with_its_error`, which failed before with no line logged | [#395](https://github.com/seo-rii/maki/pull/395) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-192 | Three statements were false for the code. maki-attach(8)'s EXIT STATUS said that an error about the attachment file, the state directory or its lock "says to run the command as root when the caller lacks the permission". Only `state::named` adds that hint, for the state directory, its lock and the gate configuration that `verify` reads; `maki-attach attach --plan` run without root on an unreadable configuration printed `error: attach config /etc/maki/attach/demo.toml: Permission denied (os error 13)`. The same page gave `--block-size` as "a power of two from 512", without the upper bound the code enforces, the kernel's page size (an observation of the audit). And the [witness service guide](remote-witness-service.md) said that a `remote.state` that changes, disappears or stops decoding while `serve` holds its lock makes it answer unavailable until a restart. A changed or undecodable record is answered first as an invalid request, which a client takes as final, so it stops the session that sent it, and only the later requests as unavailable; a removed file is answered as unavailable, and `serve` logs nothing about either. | The three sentences say what the code does. Review before the merge found that the first correction of the man page left out the gate configuration of `verify`; the document test now pins the hint's one source, `state::named`, and its callers, the state files and the gate configuration of `verify`, so a new caller fails it, beside the page's sentence. | `scripts/test_docs_accuracy_validation.py` (`HelperAndWitnessStatements`): `test_the_run_as_root_hint_comes_with_the_state_files_and_the_gates_configuration`, `test_the_block_size_bound_is_the_kernel_page_size`, `test_a_changed_witness_state_is_refused_first_as_invalid` | [#390](https://github.com/seo-rii/maki/pull/390) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-193 | CI stopped #392 for something its author's runs had not shown. On the `latest-stable (windows-latest)` job two tests of `review_single_endpoint_attach.rs` failed on the WebSocket transport, the attach still running at their 30 s bound, while HTTP and gRPC passed. Their URLs named `localhost`, which Windows resolves to `::1` first, and the listeners serve IPv4 only; a refused connect there takes about 2 s. The WebSocket transport (`tokio_tungstenite::connect_async_tls_with_config`, one `TcpStream::connect` over the resolved addresses in turn) runs its whole connect under one deadline, so `::1` used up the tests' 2 s transport timeout on every attempt. Each probe attempt failed as a connect timeout, which is transient and unsent, and the attach kept waiting for its lone endpoint, as AUD-188 intends, instead of meeting the certificate. The cause was found by reading, with no Windows host; maki-crypto-websocket's `wss_tls.rs` and `review_default_trust.rs` already used the IP literal for this reason, while the HTTP and gRPC crates' `review_default_trust.rs` name `localhost` and pass on Windows, since those transports divide the connect timeout or try the other address family. | A test-only commit before the merge (`251572f`) names `127.0.0.1` in those URLs. The certificate still names another host, so the assertions are unchanged, and nothing is gated on the platform. The transport is unchanged (the open list), and the [status page](status.md#known-limitations) now states the limitation. The development guide gains a trap: tests of the WebSocket transport, and tests that depend on connect timing, reach a loopback listener by its IP literal. *Changed by AUD-198 ([#400](https://github.com/seo-rii/maki/pull/400)): the transport races the address families and shares its connect deadline among the addresses, and the trap keeps the IP literal for tests that depend on connect timing.* | The `pr` and `latest-stable` jobs on Windows; `an_only_endpoint_with_another_hosts_certificate_refuses_the_attach_with_the_tls_failure` and `an_only_endpoint_of_a_provider_that_is_not_retry_safe_is_probed_once` (maki-nbdkit `review_single_endpoint_attach.rs`) | [#392](https://github.com/seo-rii/maki/pull/392) |

### Not closed in the ninth round

Each item was checked against `main` at `c5c036a`, with the six pull
requests merged.

- A gRPC server that refuses the client certificate under TLS 1.3 is still
  reported with a retryable status (`grpc status Unknown`, `Cancelled` or
  `Unavailable`) that counts as sent. A lone such endpoint of a `retry_safe`
  provider is therefore waited for under `stall` after AUD-188's warning;
  one of a provider that is not retry-safe, the default, is refused at
  attach with that status named. The configuration guide states both, and
  the status page the classification (AUD-189). Recognising the refusal
  needs Maki to own the TLS stream or a patched h2. On any transport, a
  server that resets the connection before the client has read its alert
  leaves only a lost connection, which is retryable.
- The WebSocket transport runs its whole connect under one deadline and
  tries the resolved addresses in turn, so a host whose first address does
  not answer loses that time on every connect: `localhost` that resolves to
  `::1` first costs about 2 s on Windows for a listener on IPv4 only, and an
  IPv6 route that drops packets makes every connect time out. The gRPC
  transport divides its connect timeout across the addresses, and the HTTP
  transport's connector tries the other address family after 300 ms. Found
  while CI's failure of AUD-193 was explained, not changed; the status page
  states it. The audit's host has no IPv6, so the dropped route was not run.
  *Closed by AUD-198 ([#400](https://github.com/seo-rii/maki/pull/400)): the
  transport resolves the host itself, starts the other address family 300 ms
  after the first, and gives each address of a family but the last an equal
  share of what is left of the request attempt's deadline. What remains is in
  the follow-up round's open list.*
- Under `stall` an attach still waits for a lone endpoint whose failures
  were only transient and whose request may be sent again, now after a
  `WARN` (AUD-188), and for an endpoint that fails after its probe passed,
  with no warning of its own. nbdkit did not end on SIGTERM while its
  startup callback ran in the audit's runs, so outside systemd such a wait
  ends only when the endpoint answers or SIGKILL ends the process; under
  systemd `maki@` is killed at `TimeoutStartSec=180`, which was read from
  the unit and not run.
- The S-01 truncation residual, narrowed by AUD-181: when a cut leaves no
  written header byte of any slot below the end of the file (a file
  truncated to zero length, or one whose written slots all lie beyond the
  cut), and the catalog copy that names the shard and every allocation copy
  that lists its slots are lost as well, the shard still looks like one
  whose creation never finished, and its units beyond the cut read as zeros.
  So does a lost data file whose shard also lost that catalog copy and every
  allocation copy that lists a slot. Each needs all of them lost together;
  none of the round's runs found such a case.
- `holds_written_slot` costs up to one 64-byte read per slot for each shard
  that open adopts with an empty allocation map, at every open until the
  first write or idle checkpoint catalogs the shard: 262,144 small reads of
  a sparse file for a shard of 262,144 units whose creation never finished.
  Neither that nor the catalog store that every attach now adds was measured
  on a target system, and recovery's other A/B records were not reviewed
  again (AUD-181).
- A control session can make the daemon log as many `WARN` lines as it sends
  failing `checkpoint` or `drain` requests (5,000 in 2.3 s in review); there
  is no rate limit, and only root, the daemon user and members of the
  control socket's group can send them (AUD-191).
- A rollback session that has stopped reports `ready` until a request asks
  the witness, since status does not call it, and a remote witness that is
  unreachable refuses each operation without stopping the session, so status
  stays `ready` meanwhile (AUD-187). With a remote witness a daemon whose
  session stopped never releases it, and the next daemon's claim is refused
  until `maki volume takeover`; the operations guide says so.
- The refusals of AUD-184 come from a check made before the backing is
  opened: a directory that disappears between the two still gives the bare
  error. A directory the user may not open is tested only unprivileged,
  where a mode-000 directory refuses the user; run as root, that test prints
  a skip notice and passes, and CI's unprivileged run executes it. The
  automatic GC pass after an activation shares
  AUD-183's wording but is not tested on its own.
- `maki-attach` takes its paths as values of named options (`--config
  <path>`) and was not examined for an option given as such a value
  (AUD-190).
- Observations of the audit, not changed: the provisioning guide's
  first-volume script stops when `nbd-disconnect` fails after its wait, and
  "run it again" does not say how to finish with the identities the script
  had read into shell variables; `maki check` exits 0 for a configuration
  whose compatibility id, random prefix or maximum ciphertext size no longer
  matches the volume, which attach refuses (no document says that `check`
  compares them); and `check` and `inspect` fail on a backing mounted
  read-only with "Read-only file system", because they open the backing for
  writing and sync it. *Closed on 2026-11-25: the first by AUD-199
  ([#402](https://github.com/seo-rii/maki/pull/402)), whose block records the
  run in a root-only file and continues from it; the second by AUD-194
  ([#399](https://github.com/seo-rii/maki/pull/399)), with which both checks
  compare those settings and fail on a difference; the third in part by
  AUD-195 ([#403](https://github.com/seo-rii/maki/pull/403)), with which a
  plain backing whose root cannot be written is checked read-only, while a
  rollback-protected one is refused with the reason.* *AUD-202
  ([#407](https://github.com/seo-rii/maki/pull/407)) closed the rest of the
  third on 2026-11-26: a rollback-protected backing is read read-only too.*
  Two things recorded before were seen again: WebSocket
  and gRPC keep plaintext copies of the last units in transport buffers
  after the volume goes idle (MAKI-015, the [status
  page](status.md#known-limitations)), and a SIGTERM while the only endpoint
  stalls after attach is served only once the endpoint heals, with no
  `TimeoutStopSec` in `maki@`. One run of the audit's local power-loss
  harness stopped on a mismatch between its model and the disk (the witness
  anchor and its staged name) that did not recur in twelve new seeds; it was
  not classified further.
- Nothing in this round ran on a real kernel NBD device outside CI's
  root-only tests, with udev, device-mapper or LVM, under systemd with these
  units, on a booted RHEL host or through a real power loss; the kernel side
  of the eighth round's NBD changes was checked against the source again,
  not run. CI's Windows jobs are the only Windows runs.
- `v0.1.0-rc.1` predates the eighth and ninth rounds, and no later release
  candidate had been tagged when this was written.

## Eighth round (2026-11-24): AUD-159–AUD-180

An eighth internal audit, of `main` at `956e354` (after the sixth and seventh
rounds; also the commit of the first release candidate, `v0.1.0-rc.1`), was
organised by angle again. Six reviewers compared the maintained documents with
the code; looked at how the last rounds' changes interact on the merged tree;
installed the published Debian and RPM packages in clean roots and followed
the guides; drove the helper's NBD connection against a real nbdkit and a
simulated kernel; ran the plugin in a real nbdkit under kills, power-loss
images, a full disk and damaged volumes; and spent machine time on long seeded
sweeps and fuzzing. None of this lost or corrupted an acknowledged write or
served wrong data. What they found is one finding of medium severity, AUD-161
(on RHEL 9 the documented `dnf remove maki` under an attached volume kept Maki
and erased the packages it needs), and otherwise low-severity findings and
wrong statements in the documents. Ten pull requests,
[#379](https://github.com/seo-rii/maki/pull/379) to
[#388](https://github.com/seo-rii/maki/pull/388), were merged into `main` on
2026-11-24 (#380 at `9dd523b`, #381 at `6d8b2f9`, #379 at `d888fbf`, #384 at
`02b1471`, #383 at `bf8e926`, #382 at `03a329d`, #385 at `d31aaf2`, #386 at
`27cc86e`, #387 at `e12dafd`, #388 at `d5ca5c1`). Three change documented design decisions
(AUD-159 to AUD-161), and each of those rows states the earlier behaviour,
what replaced it and what is kept; AUD-159 closes an item of the fifth and
sixth rounds' open list, and AUD-162 and AUD-172 each change one earlier rule
and say so. AUD-162 to AUD-165 are the helper's NBD connection, AUD-166 to
AUD-168 its messages, AUD-169 and AUD-170 volume creation, AUD-171 the A/B
records, AUD-172 remote enrollment, AUD-173 to AUD-175 packaging and release
tooling, AUD-176 to AUD-178 the documentation, AUD-179 what CI found in
this round's own pull requests, and AUD-180 the randomized tests. Every code fix landed test-first. All rows are
**Fixed**; AUD-165 and the precaution of AUD-178 rest on reading and were not
exercised on a real host, which the open list keeps. No change alters a record
format or a golden vector: AUD-170 adds one transient file name,
`superblock.next`, and after AUD-171 an A/B side can be found empty where it
held torn bytes, which every release reads as an invalid copy. The
operator-visible changes are listed in the
[changelog](../CHANGELOG.md#breaking-changes).

Every pull request was read before it merged. One reading found a blocking
defect, in #388, which was fixed before the merge (AUD-180); no other did.
#380 and #384 had no independent review: their diffs were read by the
maintainer who merged them, and #384 also had its `rhel9` job. Review led to
new commits for five of the others: before the merge in #379, #382, #387 and
#388, and for #383 in #385. In #379 it widened the scan for a guide that has `sudo`
select a user, limited the check of the `runuser` form to commands, corrected
what the document suite says about its own pins, narrowed a root-target
exemption and added the callback lock to SPEC §6 (AUD-176 to AUD-178). In #382
it changed six things: the missing-anchor message, which steered an operator
into enrolling a witness directory that is not mounted, the order of the
capacity comparison, the reason a refused pair does not open, the wording of
the plain refusal, the staged handle left open across its rename, and a
control that used an invented segment name (AUD-159, AUD-169, AUD-170). #383
merged as reviewed, and its three follow-ups landed with #385: a test that
pins the real look at a negotiated connection in the negative direction, a
timing window in the root-only kernel test, and a comment's wording (AUD-162,
AUD-165). In #387 two reviews each found a regression of the change itself,
fixed before the merge (AUD-172). In #388 it found that the change had moved
coverage of the durability sweeps instead of only adding it: with every seed
on a three-record journal segment, no workload ended with more than three
unsynced records any more. Each seed now takes one of three segments, and
the sweeps assert both properties; that fix was read, not reviewed again
independently (AUD-180). CI found three things that the local runs had not
(AUD-179). This records change,
[#389](https://github.com/seo-rii/maki/pull/389), adds what the review of #386
left for the documents: where the emptying step of AUD-171 can fail for want
of space, and what it assumes of the backing filesystem.

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change, strict
Clippy, `cargo fmt --check`, the Python suites and the link checker, with
fails-before runs of the test commits and mutation checks. #382 also ran its
release gate, #386 four of maki-core's extended gates, one at a time in the
debug profile and two rebases before its head, #388 six release gates, and
after review again the three whose sweeps it changed, and #384 a replay of the whole
`rhel9` job in a CentOS Stream 9 root. #381 and #383 ran against nbdkit 1.36.3
with Maki's plugin, and #381 against stock clients (libnbd, `qemu-io`,
`qemu-img`, `nbdcopy`). #382 killed a real `maki volume create` 240 times, and
the review of #387 replayed about 65,000 crash images of the real commands on
the pull request's first version, about 34,000 of them of the remote commands
against the authority's state machine, without a violation. Otherwise these
are repository tests over crash models, simulated and scripted kernels, a real
nbdkit and package builds in CentOS Stream 9 roots. The root-only kernel
tests, one of them new (AUD-162), run in CI's root step on GitHub's Ubuntu
runners; the hosts the pull requests were written on have no `nbd` module.
Nothing ran with udev, device-mapper or LVM, on a RHEL kernel, under enforcing
SELinux or through a real power loss, and the changed release workflow has not
run.

### Design changes

| ID | Earlier behaviour | Change | Regression | PR |
|---|---|---|---|---|
| AUD-159 | A local `maki volume create` enrolls the backing, publishes the witness anchor and then initializes the volume inside the backing in several commits that end with the superblock. Since AUD-136 a later `create` completes a creation that stopped before the anchor, and by that row's decision it never wrote over an anchor: a command that stopped after the anchor left a pair that `create` refused ("rollback enrollment requires empty backing and witness directories") and that held no volume (the daemon, `maki check` and `maki volume inspect` said "no valid superblock"), so both directories had to be emptied by hand. The fifth and sixth rounds' open list kept this as found by reading. It needs no more than a kill: a SIGKILL at delays spread over the command's run landed in that window in 21 of 240 runs, and in 8 of 60 in a second series. | `create` continues a local creation wherever it stopped before its superblock. When the enrollment refuses an existing pair, `maki_format::init::create_in_rollback_backing` opens the pair against its witness, which authenticates the manifest and every committed page against the anchor, and continues only if `unfinished_creation` finds no superblock copy and no entry other than what a creation writes before its superblock: the volume lock, the first shard-catalog copy, a staged `superblock.next`, the `data`, `journal` and `checkpoint` directories with the durable proof, the initial checkpoint state and a durable mark that is still empty. The capacity must be the one the interrupted run reserved, which the witnessed manifest fixes; another is refused with both values. The command then removes what that run left, syncs the directories and initializes the volume anew, with a new volume UUID. Every other pair keeps the enrollment's refusal and is left unchanged: one that does not open, whose refusal now carries why ("...; the existing pair does not open against its witness either: ..."), and one that opens and holds a superblock copy or anything else. "No valid superblock" is not evidence that a volume was never used, because damage to a used volume looks the same; the rule rests on what damage cannot produce and a used volume cannot hold. Damage to superblock pages, manifest slots or the anchor, and a witness that is not mounted, fail the open. A volume that was ever attached holds a superblock copy, nothing removes one, and the rule goes by which entries exist, not by whether a copy decodes. Rejected: a durable "creation in progress" marker (one more single-copy record to make durable, which an older release would ignore) and publishing the anchor only when the volume is complete (the volume is initialized through the backing, whose every commit advances the anchor). SPEC §21 states the rule as MUST, and the [rollback guide](rollback-protection.md#local-configuration-and-creation) and [operations](operations.md) describe it. **Behaviour change:** `create` on a local pair that has an anchor used to refuse always; it now continues the pair if, and only if, it holds an unfinished creation, and only with that creation's capacity (before the anchor another capacity is still accepted, as since AUD-136). A refused `create` now opens the pair first, which takes the witness lock and re-publishes the witness record without advancing it; beside a witness directory that is not mounted this leaves a `witness.lock` there. `RollbackBacking::create_on` and `open_on`, hidden from the documentation, expose the constructors over caller-supplied backings for the crash model. Kept from AUD-136's decision: no enrollment replaces an anchor, and nothing that committed a superblock is created over. | maki-format `review_interrupted_volume_create.rs`, the whole command on the crash model with the backing and the witness on two machines: `a_creation_killed_at_any_operation_can_be_continued`, `a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued`, `a_creation_whose_operation_failed_can_be_run_again`, `a_continued_creation_that_is_interrupted_again_can_be_continued`, `a_creation_stopped_right_after_the_anchor_is_continued`, `a_creation_stopped_before_its_superblock_is_continued`, `a_continuation_with_another_capacity_is_refused_with_both_values`, `an_acknowledged_volume_is_never_created_over_whatever_cuts_its_commits`, `an_undisturbed_creation_is_refused_by_a_second_one`, the controls `a_used_volume_with_damaged_superblocks_is_never_created_over`, `a_used_volume_with_damaged_manifest_slots_is_never_created_over`, `a_used_volume_whose_anchor_is_missing_or_empty_is_never_created_over`, `a_used_volume_beside_an_unmounted_witness_is_never_created_over`, `an_authenticated_volume_without_superblocks_that_holds_more_is_never_created_over` and `a_volume_with_one_superblock_copy_is_never_created_over`, from the review `a_refused_pair_that_does_not_open_says_why`, and the ignored release gate `gate_a_creation_cut_anywhere_in_any_way_can_be_continued_and_used`; maki-nbdkit `review_interrupted_volume_create.rs`, a real creation killed in a child process by a seccomp filter or stopped at one backing operation: `create_killed_at_the_volumes_first_page_can_be_run_again`, `create_killed_while_it_publishes_the_volumes_first_commit_can_be_run_again`, `create_stopped_at_any_step_of_the_volumes_initialization_is_continued` | [#382](https://github.com/seo-rii/maki/pull/382) |
| AUD-160 | R5-036 made WRITE_ZEROES native and chose `can_fast_zero` 0, because partial units are written and a zero is never known to be faster than a write; `zero_v2` refused a request that carried the fast-zero flag with ENOTSUP, and SPEC §48 said "no fast zero". On an nbdkit built with assertions the refusal never ran. nbdkit accepts `NBD_CMD_FLAG_FAST_ZERO` on a WRITE_ZEROES request without looking at the advertised flags (`validate_request`, `server/protocol.c`) and then asserts in `backend_zero` (`server/backend.c`) that the backend's `can_fast_zero` is 1. One such request from any client of the volume's NBD socket aborted the whole daemon: with Ubuntu 24.04's nbdkit 1.36.3 the assertion `c->can_fast_zero == 1` failed and the server ended with SIGABRT, and every request in flight with it; data acknowledged by FLUSH or FUA was intact after the restart. The Linux NBD driver never sets the flag, so this needs a userspace client, and libnbd refuses to send an unadvertised flag unless its strict mode is switched off. | The plugin answers `can_fast_zero` with 1 and keeps refusing every fast zero request with ENOTSUP, before the handle is read and before anything is changed. The NBD protocol lets a server set the flag and always fail such requests with `NBD_ENOTSUP`, and nbdkit's plugin documentation accepts a plugin that always fails a fast zero. The pull request read the nbdkit sources of 1.32.5 (Debian 12), 1.36.3 (Ubuntu 24.04, the version it ran) and 1.38.5 (EL9): with the flag advertised the request passes the assertion and reaches the plugin's `.zero`, and for a fast zero that fails with ENOTSUP nbdkit neither falls back to `.pwrite` nor retries, and sends `NBD_ENOTSUP`. It compared every other capability assertion of `backend.c` with `validate_request` and with what the plugin answers; FAST_ZERO was the one flag accepted without having been advertised. SPEC §48 requires the refusal and the advertisement and gives the reason; [space reclamation](space-reclamation.md) and [operations](operations.md) follow. **Behaviour change:** the export advertises `NBD_FLAG_SEND_FAST_ZERO` (bit 11), so its transmission flags are 0x084d on a default volume and 0x086d on a discard volume, where they were 0x004d and 0x006d. `maki-attach` forwards the word to the kernel unchanged (SPEC §6), and the kernel's NBD driver does not read that bit (the CentOS Stream 9 source). A fast zero request is answered `NBD_ENOTSUP` and changes nothing, where it ended a server built with assertions. Kept from R5-036's decision: no zero request is ever served as a fast one. | maki-nbdkit `review_fast_zero.rs`, the plugin in a real nbdkit and a raw NBD client over the helper's handshake source: `a_fast_zero_request_is_refused_with_enotsup_and_changes_nothing` (a default and a discard volume; the flag alone, with NO_HOLE and with FUA; two ranges of whole units and the whole export; the server keeps running, and the same request without the flag zeroes exactly its range) and `the_export_advertises_fast_zero_next_to_its_other_flags`; the unit test `fast_zero_is_advertised_and_every_request_refused_with_enotsup` (`plugin.rs`); `the_plugin_passes_the_helpers_handshake_with_flush_and_fua` (`review_helper_nbd_handshake.rs`) now requires the flag among those the helper sees; `native_nbd_zero_longer_than_the_maximum_block_size` (`review_r5_write_zeroes.rs`), which pinned that fast zero is not advertised, requires it and a libnbd `nbd_zero` with the fast-zero flag that is refused with ENOTSUP and changes nothing | [#381](https://github.com/seo-rii/maki/pull/381) |
| AUD-161 | The RPM's `%preun` refuses an erase under a live attachment, as the Debian `prerm` does (AUD-154), and the RHEL guide removed the package with `dnf remove maki`. rpm 4.16 has no scriptlet that can stop a transaction: a failing `%preun` keeps that one package and rpm runs the rest. dnf installs `nbdkit-server`, `lvm2`, `xfsprogs` and `kmod` as Maki's dependencies and removes unused dependencies with the package that needed them (`clean_requirements_on_remove`, on by default). With the published `v0.1.0-rc.1` RPM installed as the guide says and an attachment record present, `dnf remove maki` printed the refusal and "Error in PREUN scriptlet" and then erased 15 packages: Maki stayed installed with unsatisfied dependencies and without `/usr/sbin/nbdkit`, `vgchange` and `modprobe`, which detach and cleanup need. The same mechanism defeated the conflict with `nbdkit-selinux`: `dnf install --allowerasing nbdkit` installed the module beside Maki. The guide, the RPM README and the seventh round's open list described `%preun` as stopping such transactions, and the `rhel9` job and the package suite only ever ran `rpm -e maki`. apt stops at a `prerm` that fails, so the Debian package was not affected. This is the round's one finding of medium severity. | The RPM installs `/etc/dnf/protected.d/maki.conf`, a `%config(noreplace)` file that names `maki`. dnf then refuses, before it changes anything, a transaction that would remove Maki ("The operation would result in removing the following protected packages: maki") or a package it requires ("... broken dependencies for the following protected packages: maki"), attached or not. The RPM also declares `Conflicts: nbdkit`, the metapackage, beside `Conflicts: nbdkit-selinux`: with Maki protected and only the module refused, `dnf install --allowerasing nbdkit` satisfied the metapackage's `(nbdkit-selinux if selinux-policy-targeted)` another way and proposed to replace `selinux-policy-targeted` with `selinux-policy-mls`; with the conflict the command fails naming it. `%preun` is unchanged. The pull request tried the alternatives in a CentOS Stream 9 root with the published RPM and rejected them: protecting only the dependencies (dnf still runs Maki's removal against `%preun`, and `--allowerasing` still installs the module), having the guide install the dependencies by name (a host set up another way gets nothing) and documentation alone. The RHEL guide's ["Upgrading and removal"](getting-started/installation-rhel.md#upgrading-and-removal), `packaging/rpm/README.md`, the support matrix, operations and the testing guide follow, and the seventh round's open-list item was corrected in place. **Behaviour change:** on RHEL 9 `dnf remove maki` is always refused, whether or not a volume is attached, and so is a dnf transaction that removes a package Maki requires. Maki is removed with `rpm -e maki`, which `%preun` still refuses under an attachment; `dnf autoremove` then removes the dependencies nothing else needs. Reinstalling and upgrading are not refused. The RPM installs one file outside `/usr` and cannot be installed beside the `nbdkit` metapackage, also on a host without the targeted policy; nbdkit's plugin and filter packages install beside it. An operator can still lift the protection for one command (`--setopt=protected_packages=`) and get the old transaction, which the guide warns against. Kept from AUD-154: `%preun`'s check, and that `maki@` stays startable under enforcing SELinux by the policy. The `v0.1.0-rc.1` RPM has no protection file and keeps the old behaviour until it is upgraded. | `scripts/test_rpm_package.py`: `test_dnf_is_told_not_to_remove_the_package` (the installed file names only the package, is `%config(noreplace)` and says how to remove it) and `test_package_conflicts_with_the_nbdkit_selinux_module` (both conflicts, unversioned); `test_the_built_rpm_is_installed_checked_and_refuses_removal_under_a_record` (`scripts/test_ci_gate_validation.py`); `test_guide_and_package_readme_say_how_the_package_is_removed` and `test_guide_and_package_readme_quote_the_spec_conflicts` (`scripts/test_docs_rhel_installation_validation.py`); the `rhel9` job, which under an attachment record requires dnf to refuse `dnf remove -y maki`, `dnf remove -y lvm2` and `dnf install -y --allowerasing nbdkit`, each for the reason dnf prints, then finds `maki`, `nbdkit-server`, `lvm2`, `xfsprogs` and `kmod` installed, the metapackage and the module absent and `rpm -V maki` clean, and without the record requires dnf to refuse again and `rpm -e` to take the protection file with the package | [#384](https://github.com/seo-rii/maki/pull/384) |

### NBD connection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-162 | The busy retry of AUD-150 negotiated a fresh connection to the daemon for every attempt, on the reasoning that the kernel's cleanup of a refused connect may have shut the socket down. Maki's plugin serves one connection at a time, and nbdkit closes a connection a moment after its client did, so the fresh handshake met the plugin's one slot still taken by the helper's own previous connection and was answered `NBD_REP_ERR_UNKNOWN` to `NBD_OPT_GO`. The helper took that for a final refusal, and the attach failed with a handshake error although the device and the daemon were both free a moment later. Against nbdkit 1.36.3 with Maki's plugin on a loaded host, the pull request measured a handshake right after a closed one refused 256 times of 300 with no pause and 2 times of 1500 after 100 ms, the retry's own interval. The same answer can meet the first handshake of an attach that follows a detach or an `nbd-disconnect`, without any busy device. In the CentOS Stream 9 source the kernel answers the `EBUSY` of AUD-150 from the `config_refs` check at the start of `nbd_genl_connect`, before it takes the socket, so the reason for a fresh connection did not hold for that answer. | A connect has two answers that mean "busy" and retries both every 100 ms within the busy window (AUD-164) and the step's deadline, each time only after checking that the device still shows no connection; every other answer stays final. After the kernel's `EBUSY` the next request goes out on the connection that is already negotiated, as long as it is still open with nothing to read on it, which the helper checks with a non-blocking `MSG_PEEK` that consumes nothing. Only a connection that fails the check is replaced, and the helper closes it before it opens the next. The daemon's `NBD_REP_ERR_UNKNOWN` to `NBD_OPT_GO` is told apart in the handshake and retried wherever it arrives. A server without a default export answers the same and cannot be told apart, so the wait is bounded and the final refusal names both reasons ("... it is busy with another connection ..., or the server has no default export"). nbdkit answers every failed `.open` with `NBD_REP_ERR_UNKNOWN` and no message, so the plugin cannot send a distinguishable error; it logs a warning for each second connection it refuses ("refused an NBD connection: the volume serves one connection at a time, and one is open"), at most once a second with the count it suppressed. SPEC §6 states both answers and what is reused. **Earlier decision changed:** AUD-150 and SPEC §6 said that each retry runs on a fresh connection to the daemon. What that protected is kept: a connection that was shut down, was closed by the daemon, was reset or has unread bytes is never handed to the kernel again. **Behaviour change:** a handshake that the daemon answers with "export not available" is retried for up to 5 s instead of failing the attach at once, so a server that really has no default export is refused after 5 s; every other wrong server is still refused immediately. Seeded property tests of the handshake and of the netlink answer were added with this change, in the unit suite; `fuzz/` has no target for either, which the audit noted (the open list). *Closed by AUD-200 ([#401](https://github.com/seo-rii/maki/pull/401)): `nbd_handshake` and `nbd_netlink` fuzz both.* | `crates/maki-privileged/src/nbd_kernel/retry_tests.rs`, against a scripted daemon and kernel on a manual clock: `a_busy_device_is_retried_on_the_negotiated_connection`, `a_connection_that_is_no_longer_usable_is_negotiated_again`, `an_unavailable_export_is_retried_until_the_daemon_serves_it`, `an_unavailable_export_after_a_busy_device_is_retried`, `an_export_that_stays_unavailable_is_refused_when_the_window_ends`, `a_device_that_shows_a_connection_is_not_retried`, `every_other_answer_is_final`; `only_the_refusal_of_an_unavailable_export_is_told_apart` (`nbd_kernel/handshake_tests.rs`); `a_negotiated_connection_is_reusable_only_while_open_and_silent`, `a_new_negotiation_closes_the_earlier_connection_first` and, from the review, `a_connection_the_daemon_closed_or_wrote_to_is_not_offered_again` (`nbd_kernel/tests.rs`); against nbdkit with Maki's plugin, `a_second_connection_is_answered_unavailable_until_the_first_is_closed` and `the_daemon_says_why_it_refuses_a_second_connection` (maki-nbdkit `review_helper_nbd_handshake.rs`); `nbd_kernel/property_tests.rs`: `a_handshake_of_any_bytes_stays_within_its_limits`, `a_handshake_reads_exactly_its_own_bytes`, `only_the_kernels_verdict_is_read_from_a_datagram_of_any_bytes`, `the_socket_reads_only_its_requests_answer_from_the_kernel`; as root on the CI runner's kernel, `a_device_held_open_is_connected_once_it_is_released` (`review_nbd_kernel.rs`: a device held open for 700 ms is connected only after its opener let go) | [#383](https://github.com/seo-rii/maki/pull/383), [#385](https://github.com/seo-rii/maki/pull/385) |
| AUD-163 | Something that keeps an unconnected device open shows nowhere in sysfs: no `pid`, no backend identifier, no holder, no mount. Automatic allocation therefore chose the same lowest free device on every attempt and for every volume, so one stuck opener of a device failed every attach on the host that did not pin a device, with the devices above it free. In the audit's run three attaches in a row targeted `nbd3` while `nbd4` was free. | When the kernel answered `EBUSY` until the retries ended, for a device the attach allocated itself, the attach gives that device up for the next free one instead of failing. Under the attach lock it replaces its own record with one that names the next device, with a connection identifier of its own, before it connects that device; it applies every check of a first device to it, never takes a device another volume's record names, and stops when no other device is free or the chooser offers the busy one again. All the devices tried share the time of one connect step. A pinned `nbd_device` is never given up, and neither is a device that shows a backend by the time the helper looks, which rollback judges as before. The helper logs a warning and prints a second `# bound NBD device:` line when it moves. A connect that stayed busy to the end has its own error, which says that something has kept the unconnected device open. SPEC §6 states the move and its limits. **Behaviour change:** an attach without a pinned device can end on a higher device than the lowest free one; the record is the authority, as before. | `crates/maki-privileged/src/review_busy_allocated_device.rs`, over the simulated kernel of `review_stale_attach_record.rs`: `an_attach_moves_past_an_allocated_device_that_stays_busy`, `the_record_moves_to_the_next_device_before_that_is_connected`, `volumes_beside_a_busy_device_never_share_one`, `a_busy_device_never_moves_an_attach_onto_a_recorded_device`, `a_pinned_device_that_stays_busy_is_not_given_up`, `only_a_device_that_stayed_busy_and_shows_nothing_is_given_up`, `no_other_device_is_tried_once_the_steps_time_is_over`, `no_other_device_is_tried_when_the_busy_one_used_the_steps_time`, `a_chooser_that_offers_the_busy_device_again_ends_the_attach`, `an_attach_ends_when_every_free_device_stays_busy`; the busy end in `an_unanswered_nbd_step_is_an_io_error_of_unknown_outcome` (`exec_tests.rs`); new sweeps of `review_step_faults.rs`, whose simulated kernel gained an opener that makes a connect busy and keeps `pid` and `backend` after an acknowledged disconnect, a daemon that dies and a second free device: `an_attach_past_a_held_device_converges_under_every_fault`, `an_opener_during_an_attach_fails_it_cleanly_or_not_at_all`, `a_faulted_attach_beside_an_opener_converges_once_it_lets_go`, `a_teardown_beside_an_opener_keeps_its_record_until_the_backend_is_gone`, `a_daemon_that_dies_during_an_attach_leaves_what_cleanup_ends`, `a_daemon_that_dies_during_a_teardown_leaves_what_cleanup_ends`, `every_verb_keeps_the_record_of_a_backend_that_outlived_its_disconnect` | [#383](https://github.com/seo-rii/maki/pull/383) |
| AUD-164 | The 5-second busy window of AUD-150 was counted from before the first handshake, so a slow handshake or a slow kernel answer shortened it or used it up, while SPEC §6 said that the helper retries "for up to 5 s". | The window is 5 s counted from the first busy answer of either kind; the step's deadline still ends it earlier. SPEC §6 says so. | `the_busy_window_starts_at_the_first_busy_answer`, `a_device_busy_for_the_whole_window_is_refused_as_busy`, `an_export_that_stays_unavailable_is_refused_when_the_window_ends` and `the_retries_end_at_the_steps_deadline` (`nbd_kernel/retry_tests.rs`) | [#383](https://github.com/seo-rii/maki/pull/383) |
| AUD-165 | `maki-attach nbd-disconnect` returned as soon as the kernel had acknowledged the disconnect. The kernel keeps the device's `pid` and `backend` attributes, and refuses a new connect, until the last opener has closed the device (the seventh round's open list), and udev probes a device after a disconnect. A provisioning script that went on to check that the device is free, as the validation runner's raw-NBD wrapper does at once, could therefore fail on a disconnect that had succeeded. Found by reading: it needs a real kernel with udev and was not reproduced. | `nbd-disconnect` waits up to 15 s, looking every 100 ms, until the device no longer shows the connection it disconnected. If it still does, the command fails and says that something still has the device open and that it can be run again. A connection that another netlink client made in the meantime, under a backend identifier of its own, counts as gone; one that shows no identifier, as an ioctl client's does, is read as unreadable and fails the command. Detach and cleanup are unchanged: they report a backend that outlived its disconnect at once ("disconnect has not completed; keeping the attach record for cleanup retry"), keep the record and succeed on a later run. *Changed by AUD-197 ([#398](https://github.com/seo-rii/maki/pull/398)): detach, cleanup and the failed-start hook's rollback now share this wait. #398's review corrected the cause this row gives: by the CentOS Stream 9 source the disconnect's change event is sent in `nbd_config_put`, in the same section that removes `pid` and `backend`, so the probe it starts does not keep them; only an opener that already held the device at the disconnect does.* SPEC §6 states the wait. **Behaviour change:** `nbd-disconnect` can take up to 15 s and fails with exit status 1 where it returned 0 while the device still showed the connection. | `a_raw_disconnect_waits_until_the_device_shows_no_connection` (`crates/maki-privileged/src/exec_tests.rs`, with the unreadable identifier as one of its cases); as root on the CI runner's kernel, the assertion after the disconnect in `a_provisioning_connection_is_disconnected_only_under_its_own_identifier` (`review_nbd_kernel.rs`) | [#383](https://github.com/seo-rii/maki/pull/383) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-166 | A plan cannot know the backend identifier of an attach's connection, which is made when the attach runs, and prints `'<generated-connection-uuid>'` in its place. The executed step printed the same text: the log line and the error of `maki-attach nbd-connect --identifier X` named an identifier that was never sent, while `nbd-connect --plan` named `X`. For an attach, the line of a failed connect is the only place that could say which connection it was. | `PlannedStep::executed_with` renders a connect step with the identifier it sends; the plan's line is the same text with the placeholder. The connect step logs and reports that line, and the wait for the device carries it in its error, in an attach and in `nbd-connect`; `nbd-connect --plan` prints the same line. The plan of an attach still shows the placeholder, and `maki-attach(8)` says so. | `an_executed_connect_names_the_identifier_it_sends` and `an_attach_whose_device_never_becomes_ready_names_its_identifier` (`crates/maki-privileged/src/exec_tests.rs`) | [#385](https://github.com/seo-rii/maki/pull/385) |
| AUD-167 | `maki-attach <verb> --plan`, run by a user who may not search `/etc/maki/attach`, printed the plan of the built-in defaults with exit status 0, beside a configuration that pins another volume group, filesystem UUID and volume UUID: the code asked `Path::exists`, which answers "no" for every error. The manual page said that an attachment file that cannot be read returns 1. | Only a default configuration path that does not exist (`NotFound`) selects the built-in defaults. The path itself is examined, not what a link at it leads to, as the trusted reader of the executing verbs does. Any other answer is read like a file named with `--config`, and that read fails with the path, for `--plan` and for the executing verbs. The manual page and the operations guide say so. **Behaviour change:** `--plan` for a default configuration that cannot be examined exits 1 with the path, where it printed a plan from the defaults and exited 0; an executing verb in that situation fails at the configuration, where it went on with the defaults and failed later. A dangling symbolic link at the default path is an error, not "no configuration". | `only_a_default_path_that_does_not_exist_selects_the_defaults` and `a_default_path_the_caller_may_not_examine_is_an_error` (unit tests in `bins/maki-attach/src/main.rs`; the second checks only without root) | [#385](https://github.com/seo-rii/maki/pull/385) |
| AUD-168 | `maki-attach verify` printed `error: No such file or directory (os error 2)` and nothing else when the attach state directory, its lock or the volume's configuration was missing, which is what a workload gate meets after a boot and before the first attach. Every executing verb run without root printed `error: Permission denied (os error 13)`. On a host without `kmod` an attach ended with the same bare "No such file" line for the missing `modprobe`. A failed command was reported as `failed with status Some(1)`, and one that a signal ended as `status None`. | An error about the attach state directory or `attach.lock` names it by its path (`attach state directory /run/maki-attach: ...`, `attach lock /run/maki-attach/attach.lock: ...`), and one about the configuration that `verify` reads names that file (`attach config <path>: ...`). When the caller is not the user the state belongs to, a permission refusal ends with `; run this command as root`. A program that cannot be started is named (`cannot run modprobe: ...`). A failed step prints `failed with status 1`, and `failed without an exit status (a signal ended it)` where there is none. Each error keeps its `io::ErrorKind`, which is all the callers read, and exit statuses are unchanged. Other errors of the helper can still be a bare operating-system error (the open list). | `a_missing_state_directory_or_lock_is_named` and `a_refused_state_directory_or_lock_is_named` (`crates/maki-privileged/src/state_tests.rs`), `a_gate_names_the_configuration_it_cannot_read` (`workload_verify_tests.rs`), `a_step_whose_program_cannot_be_started_names_it` and `a_failed_step_prints_its_exit_status_as_a_number` (`exec_tests.rs`), the text pinned in `cleanup_does_not_fallback_when_lvm_was_killed_by_a_signal` (`recover_tests.rs`), and of the built helper `verify_names_the_file_it_cannot_open` and `an_executing_verb_without_root_names_the_state_directory_and_root` (maki-attach `review_attach_messages.rs`; the second checks only without root, AUD-179) | [#385](https://github.com/seo-rii/maki/pull/385) |

### Volume creation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-169 | The daemon, `maki check` and `maki volume inspect` reported an interrupted local creation only as "No such file or directory (os error 2)" before its anchor, where `create` already continues the pair (AUD-136), and as a bare "no valid superblock" after it. Neither says that a creation did not complete or what continues it. | Opening a pair without its format marker says that the backing holds no format marker and names the two causes: a creation that did not complete, which `volume create` continues, or a wrong backing root. Opening one without its anchor names its causes (the creation did not complete, or the witness is not mounted or lost its state) and the way out of each, and tells the operator to make sure first that the directory is the mounted witness, because `create` enrolls a pair that committed nothing into whatever directory is configured. After the anchor the daemon's open says "no valid superblock: this volume's creation did not complete (its rollback-protected backing holds only an unfinished creation); run `maki volume create` again, which continues it", before it compares the capacity. The error kinds are unchanged (`NotFound`, and "invalid"). Review before the merge changed two of these: the anchor message first suggested `create` without the check of the mount, which beside a witness that is not mounted enrolls anew into the empty mount point, after which the real witness refuses the pair (no data is involved); and under a configuration with another capacity the open said "protected backing capacity mismatch" before it named the unfinished creation. **Behaviour change:** for a pair left after its anchor, the daemon, `check` and `inspect` fail when the backing is opened, so `maki check` prints the error and exits 1 without a report where it printed a failed report. *Changed by AUD-184 and AUD-185 ([#391](https://github.com/seo-rii/maki/pull/391)): a backing root or witness directory that cannot be opened is named with its setting before the marker is looked for, and a pair without its marker is offered `volume create` only where `create` continues it.* | `open_names_an_interrupted_creation_and_what_continues_it` (maki-backing `review_interrupted_local_create.rs`); the three tests of maki-nbdkit `review_interrupted_volume_create.rs` (AUD-159), each of which also requires the daemon's open to name the creation and `create` | [#382](https://github.com/seo-rii/maki/pull/382) |
| AUD-170 | On any backing, a creation created `superblock.a` and then wrote it. Stopped in between (a kill, a failed write, a power loss that kept the name and not the bytes), it left a superblock file without a superblock, which `create` refused as "volume superblock already present", from the name alone, while the daemon, `check` and `inspect` said "no valid superblock": neither of the two outcomes the operations guide described. The audit reproduced it with a 0-byte `superblock.a`. | The first superblock copy is written and synced as `superblock.next`, closed and renamed to `superblock.a`, so a superblock name never holds anything but a superblock; the second copy's store rewrites and syncs the first and syncs the directory before it writes its own side, as before. `superblock.next` belongs to the root metadata: a creation refuses a root that holds one. A superblock file that holds no superblock can still exist (an earlier release left one, and damage to both copies of a used volume looks the same): `create` refuses such a root as what it is, with both causes and what the operator may do, and never initializes it again. A superblock of a version this release cannot use, and copies that could not be read, are refused with their own cause. Every case still refuses as "already exists", and a root that holds a superblock keeps the old text. SPEC §21's tree lists the transient file, and [operations](operations.md) describes the third state. No record format changes: the staged file holds the bytes `superblock.a` always held. | maki-format `review_create_first_superblock.rs`: `a_superblock_name_never_holds_anything_but_a_superblock` (a creation ended on the crash model before each of its operations, as a process death and with power losses, with and without discard support), `a_superblock_file_that_holds_none_is_refused_as_that_and_left_alone` and, from the review, `a_superblock_that_cannot_be_used_is_refused_with_its_own_cause` | [#382](https://github.com/seo-rii/maki/pull/382) |

### A/B records

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-171 | Two interrupted stores of an A/B record could add up to a valid copy of the first one. A store that a power loss cuts leaves its target side invalid; recovery falls back to the other side, and the next store targets the same side again with the same generation, one above the other side's. `AbStore` wrote that record in place. Two records with the same generation begin with the same bytes (magic, version, generation) and share every part of the payload that did not change. When the first cut kept every sector of its record except the shared ones and the second cut kept only the shared ones, the side held the earlier record complete, with a valid CRC, and `load` selected it by generation, although every recovery in between had found that side invalid: metadata the volume had moved on from came back, and no store of it was ever acknowledged. It needs a record longer than one torn-write unit. On the crash model with a 2080-byte allocation map and 512-byte sectors: side A holds the acknowledged value 34 at generation 3; a store of 37 to side B is cut and loses only its first sector; a store of 43 is cut when only its first sector has reached the disk; the pair then loads 37. Latent: the audit's sweeps revived attempts this way and found no acknowledged record lost or regressed. | In `AbStore::store_with_images`, after the preserve-first step and before the generation is advanced, a target that exists but does not decode is truncated to zero length and that is synced (`fdatasync`) before the record is written. From then on a cut leaves the side empty, partly the new record with zeros elsewhere, or the new record, never bytes of an earlier attempt; if power is lost before that sync returns, nothing of the new record exists yet. The truncation is issued and synced on every attempt, also when the file already reads as empty, because a truncation whose sync failed is not known to be on the disk. A target that decodes is opened and overwritten as before, and one that does not exist is created. Kept: the preserve-first rule, and the decision not to empty a target whose sync failed (BUG-001, which subsumed N-09). Only a side that does not decode is emptied, and only before it is written. The pull request checked by reading that every A/B user stores through this function. One side has since come to be written another way: the first superblock copy of a new volume is staged as `superblock.next` and renamed (AUD-170); that side does not exist beforehand, so the rule does not concern it. One error path changed with the order of the steps: a target that cannot be opened now fails the store before the caller's record takes the new generation, where the generation was advanced first. SPEC §43 states the rule as MUST, and the [architecture guide](architecture.md) describes it. **Behaviour change:** a store whose target exists and does not decode issues one truncation and one `fdatasync` more, and fails if that sync fails. After a power loss during such a store the side can be found empty where it held torn bytes. Emptying frees the side's blocks and the write allocates them again, so on a filesystem with no free block that store can fail with `ENOSPC` where the overwrite in place needed no new space; the other copy is untouched and the side stays invalid. The review injected `ENOSPC` into that write, at a checkpoint and at an attach whose checkpoint-state side was torn: both failed with an error, acknowledged data stayed readable, and both succeeded once space returned. The rule relies on what the journal's tail truncation and the shard data files already rely on: a synced truncation is durable, and a file grown after it reads as zeros where nothing was written. A filesystem that can show old blocks in a file after a crash does not give that; SPEC §43 and the [support matrix](deployment/support-matrix.md#backing-store-below-maki) state the assumption since this record was written (the open list). | maki-format `review_ab_torn_reuse.rs`, on the crash model: `a_second_cut_store_does_not_complete_the_first`, `chains_of_cut_stores_never_revive_an_attempt_a_power_loss_lost` (500 seeded chains of cut stores of a 2080-byte map on 512-byte sectors), `a_truncation_whose_sync_failed_is_repeated_before_the_side_is_written` and `only_a_side_that_does_not_decode_is_emptied_first` (the operations of a store for a decodable, an undecodable and an absent target), which failed before; `seeded_chains_never_lose_regress_or_revive_a_record` (checkpoint state, the catalog and the map over five torn-write units) passed before and after. These tests pin a revived attempt for the 2080-byte map only; AUD-180 adds two that do for 4096- and 9000-byte maps, the durable proof and checkpoint state, and an ignored gate. A sweep in review that was not committed (40,000 seeds for each of 18 combinations of record type and torn-write unit, and the durable proof through `advance`) passed with the fix and reported revived attempts on the store as it was for checkpoint state, three map sizes and the proof. The key canary and the superblock are covered by the shared code path, not by a test of their own | [#386](https://github.com/seo-rii/maki/pull/386) |

### Remote enrollment

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-172 | A remote `volume create` publishes the format marker (`rollback.format`), then the binding (`remote.enrollment`), and asks the authority for a claim only once both are durable; `volume resume-enrollment` continues a root whose marker is readable. Recovery rewrote and synced the marker's bytes, but not the directory, and then wrote the binding. When the creation before it had failed in the directory sync that publishes the marker, or was killed between the rename and that sync, the marker was readable while its name was not durable, and a power loss during recovery could keep the binding, staged as `remote.enrollment.next` or published, and lose the marker. `volume create` then answered `remote enrollment requires an empty backing` and `resume-enrollment` `No such file or directory`, although nothing had been claimed and the guide said of a root without `rollback.format` that nothing has to be removed by hand. The audit reproduced it with a creation that was interrupted twice. | Recovery makes the marker's name durable before it stages a binding: `republish_root` syncs the directory after the marker's bytes. Where it found a published binding it does not sync the directory there, which would make durable the name of a binding whose bytes may not be; the rewrite of the binding that follows syncs its bytes and then the directory. `volume create` continues a root in which a binding was left without a marker, as it continues every other root without one. A staged binding is never read: the creation writes it again from the start. A published binding is accepted only if it is exactly the one this creation would write, for the identity of the authority, which `create_remote` has already found released and never activated, and for the capacity asked for; its bytes are written and synced again before the marker is published. The root may hold nothing else. Everything else is refused and left as it is: a binding for another authority or capacity ("this backing root holds the binding of an interrupted creation for another authority or capacity: ..."), and one that cannot be read, which keeps `remote enrollment requires an empty backing`; under an authority that is claimed or was activated `create` refuses before it opens the root, as before. `resume-enrollment` on such a root says to create the volume again where creation would continue it, and a snapshot destination accepts neither a staged nor a published binding. Review found a regression in the first version: with a symbolic link or a directory planted under `remote.enrollment.next` and no marker, `create` published the marker and then failed on the entry, and nothing continued that root. Both commands now refuse, before they change anything, a staged binding or marker that is not a regular file with one name that they can open ("... is not a regular file that can be written again ..."), with the way out that works for the command. A second review found that this check stopped recovery at an unrelated entry whose name is not UTF-8, and called a good staged file unwritable after an unrelated failure such as an I/O error; both are fixed. **Earlier decision changed:** only a root that holds nothing but the locks and an unpublished marker counted as an interrupted creation. What that rule protects is kept: a root that holds a namespace, a tombstone or any other entry, a marker that is complete or foreign, a binding that is not this creation's or cannot be read, and any root under an authority that is claimed or was activated are refused and not written to. **Behaviour change:** `volume create` continues the two roots above; `resume-enrollment` performs one more directory sync and fails if that fails; on a root without a marker that holds a binding it answers with the way out instead of `No such file or directory` while the approved authority is released, and keeps its refusal under a claimed one. No file format changes. The [rollback guide](rollback-protection.md#resume-interrupted-initial-enrollment) follows. | The crash model `crates/maki-backing/src/rollback/remote_creation_tests.rs`, which runs the root steps of both commands: `enrollment_recovery_makes_the_marker_durable_before_it_stages_the_binding`, `enrollment_recovery_makes_the_marker_durable_before_it_writes_over_a_staged_binding`, `enrollment_recovery_syncs_no_directory_before_a_binding_it_found_is_durable`, `creation_makes_a_binding_it_found_durable_before_it_publishes_the_marker`, `a_binding_left_without_a_marker_is_continued_by_creation_from_any_cut`, `a_creation_interrupted_repeatedly_is_continued_by_exactly_one_command` (seeded chains of interrupted commands, each ended by the continuing command and a power loss) and `a_staged_file_that_fails_to_open_for_an_unrelated_reason_is_not_called_unwritable`; maki-backing `review_binding_without_marker.rs`, the whole commands on a real directory against an in-memory authority: `create_continues_a_staged_binding_left_without_a_marker`, `create_continues_its_own_binding_published_without_a_marker`, `a_planted_staged_binding_is_never_read`, `recovery_is_not_stopped_by_an_entry_whose_name_is_not_utf8` and eight controls that compare the root and the authority's record before and after a refusal, among them `control_a_staged_entry_that_cannot_be_written_again_is_refused_and_left`, `control_a_binding_for_another_authority_or_capacity_is_refused_and_left`, `control_no_root_without_a_marker_is_continued_once_the_authority_was_claimed_or_activated` and `control_a_snapshot_destination_that_holds_a_binding_is_refused` | [#387](https://github.com/seo-rii/maki/pull/387) |

### Packaging and release

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-173 | The RPM's provides depended on the build host. rpm's sysusers dependency generator comes with `systemd-rpm-macros`: a host that has it gave a package that provides `user(maki)`, `group(maki)` and `group(maki-admin)`, and the release workflow's container, which has not, gave one without them from the same artifacts, version and `SOURCE_DATE_EPOCH`, although `packaging/rpm/README.md` called the build reproducible for a given epoch and rpm version. The published `v0.1.0-rc.1` RPM has none of the three. | `maki.spec` declares the three provides, unversioned, and turns the generator off (`%global __sysusers_provides %{nil}`), so the header does not depend on whether the build host has it. The README says what the reproducibility claim holds for, and the guide and the README quote the provides. **Behaviour change:** the RPM provides `user(maki)`, `group(maki)` and `group(maki-admin)` wherever it is built; the `v0.1.0-rc.1` RPM lacks them. | `scripts/test_rpm_package.py`: `test_package_provides_the_user_and_groups_it_creates` and `test_provides_do_not_depend_on_the_build_hosts_dependency_generators` (a build under a stand-in generator must give the same file as one without); `test_guide_and_package_readme_quote_the_spec_provides` (`scripts/test_docs_rhel_installation_validation.py`); the `rhel9` job requires each of the three provides exactly once in the RPM it built | [#384](https://github.com/seo-rii/maki/pull/384) |
| AUD-174 | The `publish` job of the release workflow decides whether a release, a draft or a tag of the requested name exists through `before="$(state)"`. Inside a command substitution bash turns errexit off, so when a `gh api` query in `state()` failed, the function went on with the file that query had left, and `scripts/release_assets.py state` read an empty releases file as an empty list and an empty refs file as `[]`, printed `release=none` and `tag=none` with status 0, and the step created the draft. With the step's script taken from the workflow and a stand-in `gh` that holds a published pre-release and its tag, two `gh api` calls that exit 1 without output were enough for `gh release create` to be called. The `check` job runs the same queries in the step's own shell, where errexit applies, and was not affected. | `state()` returns the failure of each query itself, so `before="$(state)"` and `after="$(state)"` stop the step. `release_assets.py state` prints a state only for complete answers and refuses, with one `release-assets:` line and nothing on stdout, an empty or blank releases or refs file ("... the query was not answered, which does not show that there are none"), text that is not JSON, an error object, entries that are not objects, more than one refs answer and a matching ref without a full commit id. The pull request looked for the same pattern in every command substitution, pipeline and or-list of `release.yml` and `ci.yml` and found `state()` the only place where a failure was hidden. [Releasing](releasing.md#publishing-a-pre-release) says that a failed or cut-off query refuses the run. **Behaviour change:** a release run whose query of the releases or of the tag fails in the `publish` job fails there, having created nothing. | `scripts/test_release_workflow_validation.py`: `test_a_query_that_fails_is_never_read_as_a_free_tag` (the publish step and the check job's step against a stand-in `gh` whose queries fail without output, with an HTTP error body or after the first page of a listing), `test_a_query_without_a_complete_answer_is_refused_not_read_as_none`, `test_the_publish_step_stops_at_a_query_that_fails`; `test_a_query_that_fails_after_publication_deletes_nothing` passed before and after | [#380](https://github.com/seo-rii/maki/pull/380) |
| AUD-175 | `scripts/prepare_release.py` runs `git -C <its source tree>`, and Git looks for a repository in every parent directory. In a source tree that is not a checkout of its own, such as the published source archive unpacked below another checkout, `--print-version` printed the outer repository's workspace version, commit count and commit with status 0, and `--output` would have archived and built the outer `HEAD`. Unpacked on its own, the archive failed with Git's raw "fatal: not a git repository", and nothing documented how to build a package from a published archive. | The script stops, before it reads anything else, unless `git rev-parse --show-toplevel` names the source tree itself; a checkout reached through a symbolic link and a linked worktree keep working. A tree inside another repository is refused with both paths ("... is not the top level of a Git checkout: it lies inside the repository at ..."), and a tree without a repository with "... is not a Git checkout: a candidate version counts the commits below the source ..."; both messages say that a published archive's version is `package.version` in the manifest published beside it. [Releasing](releasing.md#rebuilding-from-a-published-source-archive) gains the supported way to rebuild from a published archive: the version and `source.source_date_epoch` from the Debian manifest, handed to `build-deb.py`. **Behaviour change:** `--print-version` and `--output` fail in a source tree that is not the top level of its own Git checkout. | `scripts/test_release_preparation.py`: `test_source_tree_below_another_repository_is_refused_before_output_or_building`, `test_source_archive_without_history_says_where_its_version_is_recorded`, `test_documented_rebuild_from_a_source_archive_carries_the_recorded_version` (the guide's block run against a candidate's source archive and manifest); `test_linked_worktree_and_symlinked_checkout_are_their_own_top_level` passed before and after | [#380](https://github.com/seo-rii/maki/pull/380) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-176 | Seven statements in maintained documents were false for the code, the workflow or the tree. The testing guide said that the `MAKI_LOG` fallback warning names the value; both sinks print a fixed reason and the directive's index, and each has a test that forbids the value. The rollback guide said that `volume create` over an interrupted remote creation answers `remote enrollment requires an empty backing`; once the creation had claimed the authority the answer is `remote witness already enrolled or occupied`, because `create_remote` asks the authority before it looks at the root. The same guide said that `create` and the daemon answer an empty `anchor` of an earlier release alike; `create` says `rollback enrollment requires empty backing and witness directories`. `SECURITY.md` and the changelog's header said that there is no tagged release, although the release workflow tags `v0.1.0-rc.<n>`. The testing guide's tier table listed formatting as a blocking check on Ubuntu and Windows; both jobs run `cargo fmt --all --check` on Linux only. The status page carried "Last updated: 2026-11-17" over later changes. SPEC §11 did not list `packaging/rpm/`, and the README's layout named only the Debian builder. | Each statement is corrected, and `scripts/test_docs_accuracy_validation.py` reads the source and the document of each. Two of its tests compare structures: the directories SPEC §11 lists against `packaging/`, and the commands of the guides against the forms of AUD-177. The others pin prose by an exact phrase, present or absent: they keep a quoted message equal to the string its source returns and keep a corrected sentence from being put back, and a page that says the same false thing in other words passes, which the suite's docstring and the testing guide say after review. | `scripts/test_docs_accuracy_validation.py`: `test_each_refusal_of_volume_create_is_quoted_as_the_source_returns_it`, `test_the_refusal_of_a_claimed_authority_is_told_apart_from_the_backing_check`, `test_the_documents_say_the_warning_gives_a_reason_and_never_the_value`, `test_rows_of_jobs_that_format_on_linux_only_say_so`, `test_the_specification_lists_every_packaging_directory`, `test_the_readme_names_both_package_builders`, `test_no_document_says_there_is_no_tagged_release` | [#379](https://github.com/seo-rii/maki/pull/379) |
| AUD-177 | The quick start, the README outline, operations, the PostgreSQL guide, the rollback guide and the witness guide ran commands as the daemon user or the witness account with `sudo -u`. Neither package depends on sudo, and a minimal Debian 12 or RHEL 9 installation has none, so the quick start's creation step cannot run on a host that has only the package and its dependencies. `maki volume create` itself gave the same advice in the warning it prints when run as root ("... as that user (sudo -u maki ...)"). The provisioning suite replaced `sudo` with a shell function before it ran the quick start's block, so CI never met the missing program. | The guides, which run as root, use `runuser -u <user> -- <command>`; `runuser` comes with util-linux, which both packages require. The warning of `maki volume create` gives `runuser -u maki -- maki volume create <config.toml>`. The provisioning suite runs the quick start's block unchanged, with nothing on `PATH` but stand-ins for `install`, `maki` and `runuser`. The document suite scans every maintained guide and manual page: it reads the words after `sudo` as sudo does, so a user option is found wherever it stands among sudo's own, while an option of the command and sudo used to become root are left alone; and a command that runs `runuser`, in a fenced block or in a code span that starts with it, must have the form above. `su` is not checked: util-linux ships it as well. The first version of the scan looked for `sudo -u` word for word and took every line with the word `runuser` for a command; review widened the one and narrowed the other, and limited the root-target exemption of the `maki` unit tests to the text they assert. **Behaviour change:** the warning's text; the guides need a root shell and no sudo. | `scripts/test_docs_accuracy_validation.py`: `test_no_guide_switches_user_through_sudo`, `test_sudo_is_judged_by_its_own_options_and_not_by_those_of_its_command`, `test_every_runuser_command_names_the_user_and_ends_its_options`, `test_a_mention_of_runuser_is_no_command_and_a_malformed_command_is_found`, `test_both_packages_require_the_package_that_ships_runuser`; `test_quickstart_create_block_stops_at_each_failed_command` (`scripts/test_docs_provisioning_validation.py`); `the_ownership_hint_reaches_the_daemon_user_without_sudo` (unit test in `bins/maki/src/main.rs`) and `root_create_names_a_volume_directory_it_had_to_create` (maki `review_root_created_ownership.rs`, needs root); `test_a_source_exempted_for_a_text_it_asserts_probes_nothing_else` (`scripts/test_root_tests_validation.py`) | [#379](https://github.com/seo-rii/maki/pull/379) |
| AUD-178 | Two facts an operator needs were missing. SPEC §6 and the helper's documentation said that a disconnect stuck on a daemon that stopped reading (AUD-151) blocks every other `nbd` request; it holds more than that. And the provisioning guide created the volume group without turning LVM's autoactivation off, although `maki-attach` activates the VG itself and refuses an attach that finds it active. | SPEC §6 and the module documentation of `nbd_kernel` say that the `nbd` generic-netlink family does not set `parallel_ops`, so the kernel runs each of its requests under the global generic-netlink mutex, which every family without `parallel_ops` shares, the control family that answers family lookups among them: while a request is stuck, no request to any such family runs and no client resolves a family ID, on the whole host. SPEC §6 adds, after review, that the request also holds the callback lock `cb_lock` for reading, so that registering or unregistering a family waits and later requests to every family queue behind that writer. This is read in the kernel's NBD driver, `net/netlink/genetlink.c` and `kernel/locking/rwsem.c` of Linux 6.1 and the CentOS Stream 9 kernel, not observed on a stuck device. The [provisioning guide](getting-started/first-volume.md#1-provision-and-record-the-layout) creates the VG with `--setautoactivation n` and says why, as a precaution: by the udev rules that Debian 12 and RHEL 9 ship, LVM's event activation acts on a device that is not a device-mapper, MD or loop device only at its `add` event, and a kernel NBD device that already exists gets `change` events on connect and disconnect, so the rule does not normally act on a Maki volume; it can when an `add` event is handled while the export is connected, as right after the module was loaded. Plain activation ignores the property, so the helper's own activation is unaffected. [Storage recovery](storage-recovery.md) points to it. Nothing of this was exercised on a host (the open list). **Behaviour change:** a volume provisioned from the guide has a VG with autoactivation off; existing volume groups keep what they have. | `test_success_pins_created_layout_and_formats_without_force` (`scripts/test_docs_provisioning_validation.py`: the guide's `vgcreate` passes `--setautoactivation n`, and its `lvcreate` takes no activation option); no suite can decide the kernel statements | [#379](https://github.com/seo-rii/maki/pull/379) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-179 | CI stopped three of this round's pull requests for things their authors' runs had not shown. #383 failed strict Clippy on the baseline toolchain, 1.94.0, which refuses `!deadline.is_some_and(..)` as a boolean that can be simplified (`clippy::nonminimal_bool`); newer toolchains do not report it. #382 failed strict Clippy on the latest stable, 1.100.0, which deprecates `fetch_update` for `try_update`, a method that is not stable on the baseline toolchain. #385's new test of the built helper required every executing verb run without root to be refused at the attach state directory; `verify` never creates that directory, so on CI's clean runner it names the directory as missing, and the test had passed locally only because an earlier run had left `/run/maki-attach` behind. | Each was fixed with a new commit before the merge: the deadline check reads `deadline.is_none_or(..)` with no change in behaviour (`5b87839`), the test's counter is a compare-exchange loop that builds on both toolchains (`5b604e4`), and the helper test expects the missing-directory line for `verify` when the directory does not exist (`8db5e71`). The last led the pull request to run the helper's cases that depend on the caller's privilege as an unprivileged user with and without the directory, with an empty `/run` in a private mount namespace. The development guide gains three traps: run strict Clippy on both toolchains before pushing; a test that passes as root, or because of what an earlier run left on the host, says nothing about CI's unprivileged run on a clean host; and AUD-160's rule for a capability that nbdkit asserts. | The `pr` and `latest-stable` jobs, which run strict Clippy on 1.94.0 and on the latest stable; `an_executing_verb_without_root_names_the_state_directory_and_root` (maki-attach `review_attach_messages.rs`) with and without the directory | [#383](https://github.com/seo-rii/maki/pull/383), [#382](https://github.com/seo-rii/maki/pull/382), [#385](https://github.com/seo-rii/maki/pull/385) |
| AUD-180 | Five gaps in the randomized tests. (1) `review_r3b_durability.rs` and `review_trim_power_loss.rs` said that a tiny journal makes automatic rolls and checkpoints happen constantly, but the constant they called the journal's size was the shard size and the engine ran with the default 256 MiB segment: on the committed seeds no workload of either file, and none of the release gates built on them, rolled the journal once. (2) A sync-fault sweep could not be run again from its seed: the sweeps fail a sync chosen by a seeded generator, one draw per sync, and the slot store wrote the allocation maps, discard maps and data-file sizes of several shards in the iteration order of a `HashMap`, so the same draw met a different file from one run to the next. (3) `deep_check_reports_allocation_repair_and_idle_checkpoint_persists_it` needed a stale allocation-map copy and left that to its workload: it passed for its hard-coded seed and failed at its precondition for others, and it did not check that the repair was persisted. (4) The decoder fuzz target `format_decoders` lacked the durable proof and the volume superblock envelope, and since every decoder checks a CRC-32 before it reads a field, from an empty corpus it reached almost no image behind a checksum. (5) The rule of AUD-171 was pinned for the 2080-byte map only. | The sweeps' seeds take turns between three journal segments: the default one (no rolls, long unsynced tails), one of three records (constant rolls) and one of sixteen (some of each) (`segment_for`). The first version gave every seed the three-record segment; review found that a roll seals and syncs the segment it leaves, so no workload then ended with more than three unsynced records, where about a third of the sequential sweep's power losses and restarts had (119 of 332, up to 39 records; 52 of 147, up to 50). The sweeps now return their rolls and the workloads that end in a power loss or a restart with more than three unsynced records, and every default-suite sweep and gate asserts a minimum of each below the measured count. The slot store writes the metadata of several shards in ascending shard order (`crates/maki-core/src/store.rs`, four lists); the shards are independent and the commit points come after the loops, so nothing a volume can observe changes, which the review confirmed. The deep-check test makes the stale copy itself, runs for four seeds and requires the repaired bit in both map copies after the idle checkpoint. `format_decoders` gains the two decoders, and a new target, `format_records`, repairs the checksum first and requires every accepted record to encode within its type's bound and to decode to the same record again. The chain test of AUD-171 is generic over the record, with two more tests that fail on the store as it was before the rule, and an ignored release gate. | `a_sync_fault_sweep_runs_the_same_way_twice_from_one_seed` and `adopted_orphans_are_sized_in_shard_order` (maki-core `review_r3b_durability.rs`), `a_sync_fault_sweep_without_the_worker_runs_the_same_way_twice_from_one_seed` (`review_trim_power_loss.rs`), the roll and long-tail minimums asserted by the sweeps of both files and by `phase_r3b_durability_gate_full`, `phase_r3b_concurrent_gate_full` and `trim_power_loss_gate_full`, `deep_check_reports_allocation_repair_and_idle_checkpoint_persists_it` (`review_corruption.rs`), `chains_of_cut_stores_never_revive_a_record_of_a_page_or_more`, `chains_of_cut_stores_never_revive_a_durable_proof_or_checkpoint_state` and the gate `ab_torn_reuse_gate_full` (maki-format `review_ab_torn_reuse.rs`); the fuzz target `format_records` | [#388](https://github.com/seo-rii/maki/pull/388) |

### Not closed in the eighth round

Each item was checked against `main` at `d5ca5c1`, with the ten pull requests
merged.

- Nothing in this round ran on a real kernel NBD device outside the three
  root-only kernel tests of CI, with udev, device-mapper or LVM, on a RHEL
  kernel or under enforcing SELinux. What the kernel does for the busy answers
  (AUD-162), with the `pid` and `backend` attributes after a disconnect
  (AUD-165), with the transmission flag of AUD-160 and under the
  generic-netlink locks (AUD-178) is read from the CentOS Stream 9 source, and
  for the locks also from Linux 6.1. The seventh round's items on the helper's
  own connect, on RHEL 9 and on the unbounded kernel wait stand.
- LVM's event activation may activate a VG on `/dev/nbdN` behind the helper
  when an `add` event of the device is handled while the export is connected.
  The provisioning guide now creates the VG with autoactivation off as a
  precaution; neither the race nor the precaution was exercised on a host, LVM
  was not run for it, and the privileged validation runner creates its VG
  without the property (AUD-178).
- The device move does not look for what holds a busy device open, and a host
  on which every free device stays busy still fails the attach, after one
  connect per device within the step's time (AUD-163). A pinned device that
  stays busy still fails as busy. Detach and cleanup do not wait as
  `nbd-disconnect` does: they report a backend that outlived its disconnect at
  once, keep the record and succeed on a later run (AUD-165). *Closed by
  AUD-197 ([#398](https://github.com/seo-rii/maki/pull/398)): detach, cleanup
  and the failed-start hook's rollback share `nbd-disconnect`'s wait, and keep
  the record only when the device still shows a connection after it.*
  A server without
  a default export is refused only after the 5-second window (AUD-162).
- Other errors of the helper can still be a bare operating-system error: a
  record that cannot be written or read back, and reads below `/proc` and
  `/sys` that are not already worded. A failed step's message still carries
  the command's status and not its error output (AUD-168).
- `fuzz/` has no target for the helper's handshake parser or for its reading
  of the netlink answer, where a root process parses bytes that the daemon and
  a netlink socket send. The seeded property tests of AUD-162
  (`nbd_kernel/property_tests.rs`) run both over random, cut and mutated input
  in the unit suite; no fuzzer does. No seed corpus is committed for any
  fuzz target, the decoders of `maki-backing`'s own records are in none, and
  no CI job builds the fuzz crate (AUD-180). *Closed by AUD-200
  ([#401](https://github.com/seo-rii/maki/pull/401)): `nbd_handshake`,
  `nbd_netlink` and `backing_records` fuzz the handshake client, the reading
  of the netlink answer and `maki-backing`'s records; every target has
  committed seeds, which the default suite replays; and a scheduled `fuzz` job
  builds the crate and runs each target for 30 seconds. Not closed: no run has
  reached the 24 CPU-hour-per-target qualification, and `maki-witness`'s RPC,
  the providers' response parsers and the helper's other readers of sysfs and
  command output have no target.*
- The A/B rule of AUD-171 ran only on the in-memory crash model, not on a real
  filesystem or through a real power loss. A store that empties a torn side
  needs free blocks again and can fail with `ENOSPC` on a filesystem that has
  none, where it fails closed; the configuration and operations guides say so.
  The rule, like the journal's tail truncation and the shard data files,
  assumes that a synced truncation is durable and that a file grown after it
  reads as zeros where nothing was written. A filesystem that can show old
  blocks in a file after a crash, as ext4 mounted with `data=writeback` can by
  its own documentation, does not give that, here or elsewhere in the format;
  SPEC §43 and the support matrix now state the assumption, and the matrix
  does not distinguish mount options. `SlotStore::open` still reads a shard's
  slot headers only when fewer than two copies of its allocation map are
  valid; that this is sound with the rule is an argument from the code, and no
  test of AUD-171 exercises the probe. *Changed by AUD-181
  ([#394](https://github.com/seo-rii/maki/pull/394)): open also reads the slot
  headers of every shard it adopts with an empty allocation map, up to the
  first written one (`holds_written_slot`).* The committed tests pin a revived
  attempt for three map sizes, the durable proof and checkpoint state
  (AUD-171, AUD-180); the key canary and the superblock only through the
  shared code path.
- A remote creation that stops after its first activation is unchanged: the
  authority is enrolled by then, and neither AUD-159 nor AUD-172 applies. A
  `remote.enrollment` that an older binary wrote in place and left empty or
  incomplete is still refused and needs the documented manual step, with or
  without a marker, and a root left with a binding for another capacity can
  only be continued with that capacity or replaced by an empty directory. An
  entry under a lock file's name or under `rollback.format` itself that is not
  a regular file still fails with the system's error. A staged file that
  another user owns and the command cannot open is refused by the new check;
  that case needs root to set up and has no test (AUD-172).
- The continuation of AUD-159 covers local witness mode only, and no real
  power loss was run. A witness directory that is not mounted is still
  enrolled into by `create` when the backing committed nothing, which the new
  message warns about; and a refused `create` leaves a `witness.lock` in such
  a directory.
- The trim sweep is still not repeatable from a seed while its background
  checkpoint worker runs: reclamation and the workload's requests reach the
  backing in an order the scheduling of the two tasks decides, and only the
  repeatability test stops the worker. The concurrent sweep is not repeatable
  by design (AUD-180).
- `v0.1.0-rc.1` predates every change of this round, and no later release
  candidate had been tagged when this was written: its RPM has neither the dnf
  protection nor the provides (AUD-161, AUD-173), its plugin does not
  advertise fast zero (AUD-160), and its helper and `maki volume create`
  behave as the findings describe. The changed release workflow has not run on
  GitHub, and how `gh` fails is modelled by a stand-in, not observed. The
  publish step still does not retry a failed query: the run fails and is
  dispatched again. What `gh release view`, `edit` and `delete` do with two
  drafts of one name was not tried (AUD-174). dnf 4.14 and microdnf 3.9 were
  tried for AUD-161; other libdnf front ends and dnf 5 were not.
- The audit saw `maki-witness init <dir> <nil-uuid>` exit 1 where a
  `maki volume resume-enrollment` with a nil identity exits 2, and noted it as
  cosmetic. Neither command changed in this round. *Closed by AUD-196
  ([#397](https://github.com/seo-rii/maki/pull/397)): `init` and `init-etcd`
  refuse a nil identity with status 2 before anything is read or created.*
- The document pins of AUD-176 look for exact phrases: a page that says a
  corrected thing wrongly in other words passes them. `sudo` used to become
  root remains in the key-rotation and storage-recovery guides, and `su` is
  not checked (AUD-177).

## Seventh round (2026-11-24): AUD-147–AUD-158

The project owner asked for Maki to run on a stock RHEL 9 and its rebuilds,
and on stock Debian 12 and 13, without `nbd-client`, keeping every safety
property the attach identity gives. Two pull requests, merged into `main` on
2026-11-24 (#375 at `3aa27ea`, then #374 at `ae7f885`), did that:
[#375](https://github.com/seo-rii/maki/pull/375) makes the privileged helper
connect and disconnect NBD devices itself, and
[#374](https://github.com/seo-rii/maki/pull/374) adds an RPM package, a RHEL 9
installation guide and a CI job in a CentOS Stream 9 container. Both change
documented design decisions, with the owner's approval (AUD-147 and AUD-148);
each of those rows states the earlier behaviour, what replaced it and what is
kept. AUD-149 to AUD-152 are the helper's NBD connection, AUD-153 and AUD-154
the packaging, AUD-155 and AUD-156 the tests and CI, and AUD-157 and AUD-158
the documentation. Every code change landed test-first. This records change,
[#376](https://github.com/seo-rii/maki/pull/376), also corrects the reason
that SPEC §6, a documentation comment and the refusal message of the helper,
and a test's comment gave for requiring FLUSH and FUA (AUD-149), with no
change in behaviour. All rows are **Fixed**, except that AUD-151 documents a
kernel wait the helper cannot bound, which the open list keeps. No change
alters the on-disk format or the golden vectors. The operator-visible changes
are listed in the [changelog](../CHANGELOG.md#breaking-changes).

Review before the merges changed both pull requests. In #375 it added the
busy retry (AUD-150), after a kernel test failed in CI on a device still held
open after the other test's disconnect, a race that an attach right after a
detach hits as well; it corrected what SPEC §6 said the time bound covers
(AUD-151) and the claim that every campaign used `nbd-client` 3.27.1
(AUD-157); and it added tests for three rules nothing pinned: the family
check, the step deadline under the caller's deadline, and the provisioning
connect's checks. In #374 it fixed the `rhel9` job, which failed as root in
the runner's uid-1001 workspace (AUD-156), and made the RPM conflict with
`nbdkit-selinux`, which the `nbdkit` metapackage would otherwise bring in
(AUD-154).

#375 reports Linux debug runs, in isolated build directories, of
maki-privileged, maki-attach and maki-nbdkit with nbdkit 1.36.3 installed,
strict Clippy (also for the Windows target of maki-privileged and
maki-attach), `cargo fmt --check`, the Python suites and the link checker,
with fails-before runs of each test commit and mutation checks;
maki-privileged's normal dependencies and `Cargo.lock` are unchanged
(PRIV-010). Its CI ran the root-only kernel tests on GitHub's Ubuntu runners,
which load `nbd` with plain `modprobe`: run 45320467425 found the busy
device, and run 45328047753 passed every job, with 23 of 23 root targets
passing as root. #374 changes no Rust source. It reports replays of the
`rhel9` job in CentOS Stream 9 roots built with `dnf --installroot` and the
Python suites on Ubuntu 24.04. Its `rhel9` job passed at `48e8662` (run
45325384438) and, with #375 merged in, at `85905ef` (run 45331522712), where
every job passed; there the EL9 container also ran #375's handshake tests
against nbdkit 1.38.5 and Maki's plugin and its constant check against EL9's
kernel headers, while the kernel tests skipped for want of the `nbd` module.
These are unit tests over scripted servers and kernels, a real
nbdkit, and two tests that connect a kernel NBD device on a CI runner; no
external campaign, systemd attach, RHEL kernel, SELinux-enforcing run or
attach on RHEL exercised either change.

### Design changes

| ID | Earlier behaviour | Change | Regression | PR |
|---|---|---|---|---|
| AUD-147 | `maki-attach` ran `nbd-client -unix <socket> nbdN -b <bs> -identifier <id>` for its connect step and `nbd-client -d nbdN` for its disconnect, and the provisioning guide and the privileged validation runner ran it for a new volume's raw export. The attach identity (SPEC §8: the record's unique connection identifier must match the live backend before detach, immediately before every disconnect and in rollback) rests on the kernel's backend identifier, which `nbd-client` sets over netlink only from 3.27. Stock RHEL 9 ships no `nbd-client` (EPEL 9 has 3.25), Debian 12 ships 3.24 and Debian 13 3.26.1, so every host needed a source-built 3.27: the Debian package depended on `nbd-client (>= 1:3.27.0)` and the Debian guide carried a backport recipe (AUD-104). | The helper performs both steps itself, in the Linux-only module `maki_privileged::nbd_kernel`, which `run_step`'s `NbdConnect` and `NbdDisconnect` arms call. The `System` seam is unchanged, so the simulated-kernel harnesses still drive the executor, and maki-privileged gains no dependency (PRIV-010). A connect looks up the kernel's `nbd` generic-netlink family and refuses one whose highest attribute is below `NBD_ATTR_BACKEND_IDENTIFIER`, connects to the daemon's socket, runs the handshake of AUD-149 and sends one `NBD_CMD_CONNECT` with the device index, the export's size, the plan's block size, the 16-bit transmission flags unchanged, the record's connection identifier as `NBD_ATTR_BACKEND_IDENTIFIER` and the socket, in `nbd-client` 3.27's attribute order and nested with `NLA_F_NESTED` as libnl does, with no timeout or client flags. A disconnect sends `NBD_CMD_DISCONNECT` with the index. Answers are accepted only from netlink port 0, for the request's sequence number and the socket's port, in the shapes the kernel sends. Every descriptor is close-on-exec, and the helper's own descriptor of the daemon's socket is closed in every outcome. A kernel error reply, a failed family lookup or a failed handshake is a failed step (`ExecError::Step`); an answer that could not be read after the request was sent is an I/O error (`ExecError::Io`, a timeout still `TimedOut`) whose effect is unknown, as a command that ran out of time was. Attach rollback, detach, cleanup and the failed-start hook already re-observe the backend identifier after any failure and none branches on the variant, so their decisions are unchanged. SPEC §6 gains an "NBD connection" section with these MUST rules, and §8 says that the live backend is the kernel's backend identifier. The owner approved changing SPEC so that the helper owns the connect, and kept the identity rule. The alternatives were rejected for reasons verified in the CentOS Stream 9 and 10 kernel sources: relaxing the identity rule would not help, because RHEL 9's base repositories ship no `nbd-client` at all; the sysfs `pid` attribute names the process that connected, which exits, so the number can be reused; `diskseq` is not incremented on a netlink connect or disconnect; and ioctl mode changes the dead-daemon semantics that detach, cleanup and recovery rely on (a netlink connection keeps its `pid` and `backend` after its server died, until it is disconnected) and sets no backend identifier. The helper logs the socket peer's pid and uid (`SO_PEERCRED`) at info level and enforces neither: documented flows run nbdkit outside the volume's unit (the [Run nbdkit](operations.md#run-nbdkit) procedure, the privileged validation runner), and where an attach configuration pins them, the `[lvm_identity]` and `fs_uuid` UUIDs already refuse a socket that serves another volume before anything is mounted. **Behaviour change:** no program runs for the NBD steps. The plan shows `connect nbdN to <socket> over netlink (block size B, backend identifier '<generated-connection-uuid>'; the export must advertise FLUSH and FUA)` and `disconnect nbdN over netlink` instead of the `nbd-client` command lines. A kernel whose `nbd` family takes no backend identifier is refused before connecting; with `nbd-client` the attach failed after connecting. The generic-netlink header carries version 1, where `nbd-client` sent 0, which the kernel ignores. Kept: the identity rule and every check built on it. An attachment that `nbd-client` 3.27 connected stays detachable, because the helper reads the same `/sys/block/nbdN/backend` attribute that `-identifier` set and disconnects through the same netlink request ([prerequisites](operations.md#prerequisites), SPEC §6, §8). | `crates/maki-privileged/src/nbd_kernel/netlink_tests.rs`: golden bytes `the_family_lookup_is_libnls_getfamily_request`, `connect_carries_nbd_clients_attributes_in_its_order_and_nesting` and `disconnect_names_only_the_device_index`, `the_kernel_reads_the_connect_request_it_expects`, and the reading of replies `the_family_reply_gives_the_id_and_the_highest_attribute`, `the_connect_reply_names_the_device_index`, `an_acknowledged_request_returns_the_replies_before_the_acknowledgement`, `a_negative_errno_is_the_kernels_refusal`, `an_answer_the_kernel_does_not_send_is_an_error`; `nbd_kernel/tests.rs`: `the_kernel_gets_the_negotiated_size_and_flags_unchanged`, `an_export_is_opened_on_a_blocking_close_on_exec_socket_without_timeouts`, `a_refused_handshake_closes_the_socket_and_names_the_reason`, `the_netlink_socket_is_close_on_exec`, `a_malformed_identifier_or_block_size_is_refused_before_the_socket`; `the_constants_match_the_installed_kernel_headers` (`nbd_kernel/header_tests.rs`, a C probe against the UAPI headers); from the review, `a_family_without_the_backend_identifier_is_refused` (`nbd_kernel/retry_tests.rs`: highest attribute 9 refused, 10 accepted); `crates/maki-privileged/src/exec_tests.rs`: `nbd_steps_start_no_external_program`, `nbd_steps_address_the_validated_kernel_index`, `an_unanswered_nbd_step_is_an_io_error_of_unknown_outcome`; the plan texts in `attach_plan_binds_the_allocated_device_everywhere` and `nbd_connect_uses_the_configured_block_size` (maki-privileged `review_priv.rs`), `attach_plan_prints_ordered_steps_without_executing` and `cleanup_plan_describes_idempotent_record_driven_storage_cleanup` (maki-attach `e2e.rs`) and `attach_config_drives_the_plan` (`review_attach.rs`); against a real nbdkit, `the_helper_negotiates_an_nbdkit_memory_export` (maki-privileged `review_nbd_handshake_nbdkit.rs`); as root on the CI runner's kernel, `the_helper_connects_and_disconnects_a_kernel_nbd_device` (`review_nbd_kernel.rs`: the backend identifier, the size, `queue/write_cache` `write back` and `queue/fua` 1 in sysfs, a write and an fsync, the device free after the disconnect) | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-148 | `maki@.service`, and SPEC §10's copy of it, ran `ExecStart=/usr/bin/nbdkit`, Debian's path. EL9's `nbdkit-server` installs `/usr/sbin/nbdkit`, so the unit could not start there (`systemd-analyze verify` in a CentOS Stream 9 root: "Command /usr/bin/nbdkit is not executable: No such file or directory"). The design brief proposed a bare `ExecStart=nbdkit`, which systemd resolves through a fixed search path since 239, so that one unit would serve both families. | The unit keeps an absolute path, and the RPM builder rewrites exactly its one `ExecStart=/usr/bin/nbdkit` line to `/usr/sbin/nbdkit`, refusing a unit without exactly one such line; the Debian package installs the unit unchanged, with a comment that explains the absolute path. The bare name was rejected: systemd's fixed path starts with `/usr/local/sbin` and `/usr/local/bin` (`systemd-path search-binaries-default` on EL9: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin`), and whatever it found there would receive the volume's configuration and crypto credential. Debian 12 and 13 still honour `/etc/staff-group-for-usr-local`, which makes `/usr/local/*` writable by group `staff`; systemd 252's `systemd.service(5)` says "Using an absolute path is recommended to avoid ambiguity" (257 dropped the sentence; the 239 NEWS entry recommends absolute paths); and `ExecSearchPath=` needs systemd 250, above the declared minimum of 249, where it would be ignored. SPEC §10 gains a MUST: the unit names nbdkit by the absolute path where the distribution's nbdkit package installs it, never by a bare program name. **Behaviour change:** none in the Debian package; the RPM's unit runs `/usr/sbin/nbdkit`. | `scripts/test_rpm_package.py`: `test_daemon_unit_runs_the_distribution_nbdkit_by_absolute_path` (the installed unit differs from the source in that one line only) and `test_a_unit_without_exactly_one_debian_nbdkit_start_is_refused` (a bare `ExecStart=nbdkit`, the RPM path, two such lines and another `ExecStart=` are each refused); the `rhel9` job checks the installed line and runs `systemd-analyze verify` on the installed units | [#374](https://github.com/seo-rii/maki/pull/374) |

### NBD connection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-149 | `nbd-client` connected whatever export the server offered. In the CentOS Stream 9 source (`nbd_set_size`), an export without `NBD_FLAG_SEND_FLUSH` gives the device no write cache, so FLUSH requests complete without reaching the server and FUA writes go out as plain writes: a filesystem barrier would be acknowledged without reaching the journal (SPEC §12). With `SEND_FLUSH` but without `NBD_FLAG_SEND_FUA` the device has a write cache without FUA, and the block layer emulates every FUA write with a full flush, which does reach the server. The kernel ignores `NBD_FLAG_HAS_FLAGS` (only its debugfs dump reads it), but the NBD protocol gives the other bits no meaning without it. Maki's plugin always advertises FLUSH and FUA (`can_flush` 1, `can_fua` native), so only a server that is not Maki's could do this. With the handshake in the helper, a root process also parses bytes that the daemon, an unprivileged user, sends. | The handshake (`nbd_kernel::handshake`) is fixed-newstyle: the client flags (`NO_ZEROES` echoed only when offered), one `NBD_OPT_GO` for the default export with no information requests, then exactly one `NBD_INFO_EXPORT` before `NBD_REP_ACK`. It never negotiates structured replies, extended headers, metadata contexts or TLS, none of which the kernel's client implements, and never falls back to `NBD_OPT_EXPORT_NAME`: nbdkit answers `NBD_OPT_GO` in every release the project documents (checked in the 1.32.5 source and against 1.36.3), and a server that cannot is not Maki's. Every byte is untrusted: each reply's length is checked before any of it is read (at most 4098 bytes, a 4096-byte string and its type), the handshake reads at most 64 KiB, and every wait ends at the step's deadline (AUD-151). An export without `HAS_FLAGS`, `SEND_FLUSH` and `SEND_FUA`, of size 0 or above 2^63 − 1 bytes, or from a server without fixed newstyle or `NBD_OPT_GO` is refused before the kernel sees the socket: `SEND_FLUSH` is required for durability, `SEND_FUA` by policy (a flush per FUA write would also be durable, and the kernel test pins `queue/fua` 1) and `HAS_FLAGS` by the protocol. The handshake's waits use `poll(2)` and per-call `MSG_DONTWAIT`, never a socket timeout or `O_NONBLOCK`, because the kernel keeps using the socket: a receive timeout left on it would fail an idle device's reads. The only socket timeout ever set is an `SO_SNDTIMEO` of the time left, which bounds a `connect(2)` that a full listen backlog makes wait, and it is cleared again before the handshake (`nbd_kernel::connect_socket`). SPEC §6 states these rules. The reason SPEC §6, the handshake's documentation and its refusal message first gave, that without any of the three flags the kernel completes FLUSH and FUA without sending them, held only for `SEND_FLUSH`; [#376](https://github.com/seo-rii/maki/pull/376) corrects all three, the comment of maki-nbdkit's `review_helper_nbd_handshake.rs` and this row, and the refusal message now reads "Maki requires SEND_FLUSH for durability, SEND_FUA by policy and HAS_FLAGS by the NBD protocol". What is refused is unchanged. **Behaviour change:** an export that `nbd-client` accepted is refused when it lacks one of the three flags, has size 0, or comes from a server without fixed newstyle or `NBD_OPT_GO`. | `crates/maki-privileged/src/nbd_kernel/handshake_tests.rs`, against scripted servers on a socketpair: `the_client_sends_its_flags_and_one_go_for_the_default_export_and_nothing_else`, `no_zeroes_is_echoed_only_when_the_server_offers_it`, `the_transmission_flags_are_returned_exactly_as_the_server_sent_them`, `the_negotiated_socket_keeps_no_timeout_or_nonblocking_mode`, `information_the_client_did_not_ask_for_is_skipped`, `a_server_without_fixed_newstyle_is_refused_before_any_option`, `an_oldstyle_server_or_another_magic_is_refused_before_anything_is_sent`, `every_error_reply_to_go_is_a_refusal_without_a_fallback`, `go_must_report_the_export_exactly_once_before_its_acknowledgement`, `a_reply_of_another_shape_is_refused`, `a_reply_longer_than_the_cap_is_refused_before_any_of_it_is_read`, `the_whole_handshake_has_a_byte_limit`, `a_stream_that_ends_early_is_an_unexpected_end`, `an_export_without_flush_fua_or_flags_is_refused`, `an_export_of_size_zero_or_beyond_the_kernels_range_is_refused`; against nbdkit's eval exports, `a_real_export_without_flush_or_fua_is_refused` (maki-privileged `review_nbd_handshake_nbdkit.rs`); against Maki's plugin, `the_plugin_passes_the_helpers_handshake_with_flush_and_fua` (maki-nbdkit `review_helper_nbd_handshake.rs`, which compiles the handshake source by path: FLUSH, FUA and write zeroes always, TRIM exactly with discard, never read-only); `an_export_is_opened_on_a_blocking_close_on_exec_socket_without_timeouts` (`nbd_kernel/tests.rs`: no `SO_RCVTIMEO` or `SO_SNDTIMEO` and no `O_NONBLOCK` once the export is open; no test fills the listen backlog). Mutation checks in the pull request: forwarding the flags without FUA, accepting an export without FLUSH, reading past the cap, sending `NBD_OPT_STRUCTURED_REPLY` | [#375](https://github.com/seo-rii/maki/pull/375), [#376](https://github.com/seo-rii/maki/pull/376) |
| AUD-150 | In CI's root-only step (run 45320467425) the provisioning kernel test passed, and the other kernel test then failed: "the kernel refused NBD_CMD_CONNECT for nbd0: Device or resource busy (os error 16)", right after the first had disconnected nbd0. The kernel refuses `NBD_CMD_CONNECT` with `EBUSY` while the device's configuration has a reference, and opening an unconnected `/dev/nbdN` allocates one and holds it while the device is open; sysfs shows no `pid` and no `backend` meanwhile. udev probes a device on the change event of a disconnect, so this is a production race too: an attach right after a detach (the allocator takes the lowest free index again), or while anything else has the device open, failed the same way, as it did with `nbd-client`. Found in CI and by review. | A connect retries an `EBUSY` answer every 100 ms for up to 5 s, never past the step's deadline or the `finish_by` deadline. Each retry negotiates a fresh connection to the daemon, because the kernel's cleanup of a refused connect may shut down the socket it was given, and runs only after checking that the device still shows no connection (no `pid`, no backend identifier); a device that shows one is refused without another request ("nbdN was busy and now shows a connection; refusing to connect it"), and every other answer stays final. SPEC §6 and [operations](operations.md#prerequisites) state the retry. *Superseded in part by AUD-162 and AUD-164 ([#383](https://github.com/seo-rii/maki/pull/383)): a retry after the kernel's `EBUSY` keeps the negotiated connection while that is still usable, the daemon's unavailable export is retried as well, and the 5 s count from the first busy answer.* The two kernel tests take different devices (the lowest and the highest free one), so neither depends on udev's probe of the other's device. **Behaviour change:** a connect of a device that something has open succeeds once the opener lets go within 5 s; a device held open longer still fails as busy. | `crates/maki-privileged/src/nbd_kernel/retry_tests.rs`, against a scripted kernel and a manual clock: `a_busy_device_is_retried_until_the_kernel_connects_it`, `a_device_busy_for_the_whole_window_is_refused_as_busy`, `the_retries_end_at_the_steps_deadline`, `a_device_that_shows_a_connection_is_not_retried`, `every_other_answer_is_final`, `a_device_shows_a_connection_by_its_pid_or_backend`; on the runner's kernel `the_helper_connects_and_disconnects_a_kernel_nbd_device` (`review_nbd_kernel.rs`), whose second connect of the connected device is the kernel's busy refusal that the retry refuses once the device shows a connection (its expectation corrected after run 45324767463) | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-151 | The first version of SPEC §6 bounded each connect and disconnect in time by the limit of an external step command (120 s) and by the thread's `finish_by` deadline, the failed-start hook's command budget (AUD-143). That holds for the helper's own waits but not for the kernel's work on a request, which runs inside the `sendto(2)` that sends it, in uninterruptible mutex waits; the kernel runs the `nbd` family's requests one at a time. `NBD_CMD_DISCONNECT` takes each connection's transmit lock and writes `NBD_CMD_DISC` to the daemon's socket, which has no send timeout (the kernel sets one only with `NBD_ATTR_TIMEOUT`, which the helper does not send), so a daemon that stopped reading with a full send buffer holds the helper, and with it the attach lock, until it reads again or its socket closes. With `nbd-client` the helper could abandon a child stuck the same way at the step limit and release the lock, leaving the same kernel state. Nothing tested that `step_deadline` takes an earlier `finish_by` deadline that has not yet passed. Found by review. | SPEC §6 and the module documentation say exactly what is bounded: the socket connect, the handshake, the busy retries and the wait for the kernel's answer end by the step limit or the earlier `finish_by` deadline (`command::step_deadline`), and no step starts once that deadline has passed. The kernel's work inside the send is not bounded, and no interruption is implemented, because a signal cannot end the mutex wait. In the helper's flows the unmount and the VG deactivation come first when they are needed; both need the daemon to serve I/O and are bounded commands, so they fail first when it has stopped, and a detach retry whose earlier attempt completed them goes straight to the disconnect. The outer bound is the unit's start or stop timeout, and a task in an uninterruptible wait ends only when the wait does. Documentation, with tests of the bounded part. | `an_nbd_steps_deadline_is_the_step_limit_or_an_earlier_finish_by` (`crates/maki-privileged/src/command_tests.rs`, from the review: the deadline itself under a future `finish_by`, the 120 s limit without one and under a later one); `no_time_left_means_nothing_is_attempted`, `a_daemon_that_never_answers_is_left_at_the_deadline` and `a_socket_that_cannot_be_reached_is_a_plain_failure` (`nbd_kernel/tests.rs`); `a_server_that_stalls_is_left_at_the_deadline` (`nbd_kernel/handshake_tests.rs`); `the_retries_end_at_the_steps_deadline` (`nbd_kernel/retry_tests.rs`). No test covers the kernel's wait | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-152 | Creating a new volume's PV, VG, LV and XFS needs its export connected once, outside any attachment. The [provisioning guide](getting-started/first-volume.md) and the privileged validation runner's raw-NBD wrapper (`scripts/privileged_validation_nbd.py`) ran `nbd-client` 3.27 for that. | `maki-attach nbd-connect --nbd-device /dev/nbdN --socket <path> --identifier <id> [--block-size <n>]` connects such an export with the attach steps' own code and waits until the kernel shows the identifier, and `maki-attach nbd-disconnect --nbd-device /dev/nbdN --identifier <id>` disconnects it. Both have plans and strict options, and `--block-size` shares `device_block_size`'s check. They refuse an identifier of the attach-record form (`maki-` and a UUID), so a raw connection can never pass for an attachment. `nbd-connect` refuses a device that shows a connection, whose backend cannot be read, or that any trusted record names; `nbd-disconnect` touches only a device connected under its own identifier and does nothing for one without a connection. Neither takes the attach lock: the provisioning procedure and the validation wrapper hold it for their whole run and must not wait for themselves. SPEC §6 states these rules and `maki-attach(8)` documents the verbs. A review before the merge found the provisioning connect's checks untested on a disconnected device that a trusted record names; they now run on a given device tree and record set, and are tested. **Behaviour change:** two new verbs, which the provisioning guide and the runner use. | `bins/maki-attach/tests/review_nbd_provisioning.rs`: `the_plans_name_the_device_socket_block_size_and_identifier`, `misuse_is_answered_with_the_usage`, `values_a_raw_connection_must_not_take_are_refused`, `help_lists_the_provisioning_verbs`; `crates/maki-privileged/src/exec_tests.rs`: `a_raw_connection_takes_only_a_free_device_no_record_names`, `a_raw_disconnect_touches_only_its_own_connection` and, from the review, `a_raw_connect_checks_the_device_and_its_values_before_connecting`; on the runner's kernel `a_provisioning_connection_is_disconnected_only_under_its_own_identifier` (`review_nbd_kernel.rs`); `scripts/test_docs_provisioning_validation.py` runs the guide's procedure with the verbs | [#375](https://github.com/seo-rii/maki/pull/375) |

### Packaging

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-153 | The Debian package's `Depends` listed `nbd-client (>= 1:3.27.0)`, and the Debian guide had an "nbd-client 3.27 or later" section with a backport recipe (AUD-104). The privileged validation runner (`scripts/privileged-linux-validation.sh`) required, installed and version-checked `nbd-client` 3.27, connected its raw fixture with it, and probed the kernel's refusal of an unprivileged disconnect with `nbd-client -d`. | `Depends` no longer lists `nbd-client`. The guide's section becomes one sentence: a source-built `nbd-client` is no longer used, and attachments it connected stay detachable; an HTML anchor keeps the old links working, and the recipe and its tests are gone. The runner neither requires nor installs `nbd-client`: its ownership fixture connects and disconnects with the helper it built (`--helper`, `nbd-connect` and `nbd-disconnect`) inside its attach lock, and the unprivileged disconnect probe runs the helper's own `nbd-disconnect` as the invoking user. Only the kernel's `Operation not permitted` for `NBD_CMD_DISCONNECT`, with the run's backend still connected, counts as denial: that is the kernel's own `CAP_SYS_ADMIN` check of the request. The status page, support matrix, operations, README, SECURITY, release, deployment, quick start and index pages, the PostgreSQL checklist, the example configurations and the privileged validation procedure follow; the procedure's dated results are unchanged. **Behaviour change:** the Debian package installs without `nbd-client`, and the runner no longer needs it. | `test_package_owns_runtime_artifacts_but_not_live_configuration` (`scripts/test_debian_package.py`) and `test_bundle_has_committed_source_dependencies_and_verifiable_manifest` (`scripts/test_release_preparation.py`): no `nbd-client` among the dependencies; `scripts/test_docs_installation_validation.py`: `test_no_step_of_the_guide_builds_or_installs_nbd_client`, `test_the_guide_says_a_source_built_nbd_client_is_no_longer_used`, `test_guide_quotes_the_package_builder_static_depends`; `the_privileged_runner_needs_no_nbd_client` (maki-privileged `regression_runner_without_nbd_client.rs`, which replaces `regression_nbd_client_version_probe.rs`) and `privileged_validation_uses_production_crypto_and_pinned_attach_identity` (`phase7_priv.rs`); `test_the_kernels_refusal_is_denial_evidence` and `test_disconnect_usage_and_setup_errors_are_not_denial_evidence` (`scripts/test_privileged_denial_validation.py`); `scripts/test_privileged_nbd_ownership_validation.py` with the helper's verbs | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-154 | Maki was packaged for Debian only; RHEL 9 and its rebuilds had no package, and the support matrix said "No packaging". | `packaging/rpm/build-rpm.py` and `packaging/rpm/maki.spec` package prebuilt release artifacts like `build-deb.py`: the same files at the same paths, root-owned with the same modes, the same units (with AUD-148's rewrite), sysusers and tmpfiles rules, examples, `NEWS.gz`, manual pages and notice, and the binaries byte for byte (no stripping, debuginfo split or build-id links). `Requires: nbdkit-server, lvm2, xfsprogs, util-linux, systemd >= 249, kmod` and `Conflicts: nbdkit-selinux`. rpm adds the shared-library requirements; its generator ignores `PT_INTERP`, so the builder adds the build host's owner of the ELF loader (`glibc`) and refuses a loader no package owns. `%post` runs `systemd-sysusers`, `systemd-tmpfiles --create` and `daemon-reload` like the Debian `postinst`, `%postun` reloads after an erase, and `%preun` refuses an erase under a live attachment with the Debian `prerm`'s check and never blocks an upgrade; no scriptlet starts, stops or restarts a service. Two differences are deliberate: the Apache-2.0 text under `/usr/share/licenses/maki/` (both license files are `%license`) and no `changelog.Debian.gz`. `SOURCE_DATE_EPOCH` is required, 1990 or later: rpm 4.16 reports an earlier changelog year as "bad date in %changelog" and still exits 0 with a package that has no changelog entry, which a replay found with the Debian builder's default of 0. Why `nbdkit-server` and the conflict, read from the CentOS Stream 9 targeted policy (`selinux-policy-targeted` 38.1.87) with `sesearch`: the `nbdkit` metapackage requires `nbdkit-selinux` on any host with the targeted policy, and that module labels `/usr/sbin/nbdkit` `nbdkit_exec_t` for libvirt (only `virtd_t` transitions to `nbdkit_t`), while the policy gives systemd's `init_t` neither a transition for that type nor permission to execute it, so by the policy an enforcing host would refuse to start `maki@`. Without the module Maki's files take default labels, and the daemon and the helper both run in `unconfined_service_t`. A review before the merge found that requiring `nbdkit-server` alone left the module one `dnf install nbdkit`, or one package that needs the metapackage, away, and `maki@` would then fail only at its next start, possibly the next boot; with the conflict dnf refuses such a transaction and names the conflict. **Cost:** Maki cannot be installed beside the module, so neither a libvirt or virt-v2v host that needs it nor a host where SELinux is permissive or disabled, where the module is harmless, can run Maki ([RHEL guide](getting-started/installation-rhel.md#selinux)). | `scripts/test_rpm_package.py`: `test_package_declares_the_el9_runtime_and_no_nbd_client`, from the review `test_package_conflicts_with_the_nbdkit_selinux_module`, `test_files_are_root_owned_with_the_debian_modes`, `test_installed_history_manuals_and_license_texts`, `test_scriptlets_create_users_and_directories_and_never_touch_a_service`, `test_preun_refuses_removal_while_a_volume_is_attached`, `test_preun_refuses_removal_while_a_maki_unit_is_active_or_recovering`, `test_preun_fails_closed_when_systemd_cannot_be_queried`, `test_preun_allows_idle_removal_and_never_blocks_an_upgrade`, `test_the_debian_builder_artifact_checks_apply`, `test_native_package_requires_the_loader_owner_and_its_libraries`, `test_source_date_epoch_must_be_given_and_datable_by_rpm`, `test_build_is_reproducible`, and, against the Debian package built from the same stub artifacts (`dpkg-deb` required in the `pr` job by `MAKI_TEST_REQUIRE_DPKG_DEB=1`), `test_both_packages_install_the_same_files_with_the_same_modes`, `test_both_packages_refuse_removal_with_the_same_check` and `test_both_packages_declare_the_same_runtime_components`; the `rhel9` job builds, installs, verifies and removes the real RPM (AUD-156) | [#374](https://github.com/seo-rii/maki/pull/374) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-155 | The new NBD tests need root and the `nbd` module, nbdkit, or the UAPI headers and a C compiler, and skip with a notice otherwise; a skipped test passes unseen. No CI step loaded the `nbd` module, so nothing showed whether GitHub's runners can. | The workflow sets `MAKI_TEST_REQUIRE_NBDKIT=1` and `MAKI_TEST_REQUIRE_NBD_HEADERS=1` for every job, as it already sets `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM`, and the `pr` and `latest-stable` jobs install `linux-libc-dev`. A step before the root-only step loads `nbd`, installing `linux-modules-extra-$(uname -r)` if the module is not there, and fails when neither works; the root-only step sets `MAKI_TEST_REQUIRE_NBD=1`, `review_nbd_kernel.rs` is in `ROOT_TARGETS`, and `scripts/run_root_tests.py` passes the three switches on. GitHub's Ubuntu runner loads `nbd` with plain `modprobe`; run 45320467425 found AUD-150's busy device, and run 45328047753 passed both kernel tests as root ("root-only tests: 23 of 23 targets passed as root") and every other job. A review before the merge found that the header check's skip-path test printed a skip notice, which the root runner listed as a skip; it prints none now. | `test_the_root_step_has_the_nbd_module_and_every_job_requires_the_nbd_tools` (`scripts/test_root_tests_validation.py`); `missing_headers_fail_only_when_they_are_required` (`crates/maki-privileged/src/nbd_kernel/header_tests.rs`); the two tests of `review_nbd_kernel.rs` | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-156 | CI ran on Ubuntu and Windows only: nothing built or tested Maki in a RHEL 9 userspace (glibc 2.34, nbdkit 1.38 at `/usr/sbin/nbdkit`, lvm2 2.03.33, systemd 252, rpm 4.16, Python 3.9). | A `rhel9` job runs on every change in `quay.io/centos/centos:stream9`, the public upstream of RHEL 9 (Rocky Linux and AlmaLinux rebuild RHEL later; UBI lacks CRB and `nbdkit-devel`), with a 60-minute timeout. It installs its tools from BaseOS and AppStream, plus `nbdkit-devel` from CRB for the ABI header: `nbdkit-server` and `nbdkit-basic-plugins` rather than the `nbdkit` metapackage, and `kernel-headers`, whose NBD headers the constant probes of AUD-155 require there. It uses the baseline toolchain, builds the four packaged artifacts in release mode against glibc 2.34, runs `review_abi.rs` against EL9's `nbdkit-plugin.h` and the `maki-privileged`, `maki-attach` and `maki-nbdkit` suites with `--no-fail-fast` (the native tests load Maki's plugin into EL9's nbdkit 1.38), runs the RPM contract, and builds the real RPM: `glibc` and `GLIBC_2.34` symbols must be among its requirements, dnf installs it (its `Requires` bring lvm2, xfsprogs and kmod, and neither the metapackage nor `nbdkit-selinux` may come) and must refuse `nbdkit-selinux` beside it, and `rpm -V`, the created users, groups and directories, `systemd-analyze verify` and a refused `rpm -e` under an attachment record precede its removal. The Ubuntu `pr` job installs `rpm` and `cpio` and runs the RPM contract with `MAKI_TEST_REQUIRE_DPKG_DEB=1`. Before the merge, the job's first CI run (45319539805) failed in the suites step, and review traced it: a container job's steps run as root, while the workspace, `RUNNER_TEMP` and `HOME` belong to the runner's uid 1001. `regression_mount_target.rs` found no fixture directory whose ancestors are root's and closed to others (seven tests), and root's `git` refused the workspace ("dubious ownership", because `actions/checkout` trusts it only in a temporary git configuration), which would have left `SOURCE_DATE_EPOCH` empty for the RPM step. A step after the checkout adds the workspace to root's `safe.directory` and exports a root-owned `0755` `TMPDIR` below `/var/lib`. An earlier replay in a chroot, where root owned the whole tree, had passed; a replay that reproduced the container's ownership (a uid-1001 workspace and `HOME`, root steps with Docker's default capabilities) showed both failures before the change and none after. The job passed at `48e8662` (run 45325384438) and, with #375 merged in, at `85905ef` (run 45331522712, every job of the run passing), where `review_helper_nbd_handshake.rs`, `review_nbd_handshake_nbdkit.rs` and the header check of AUD-155 ran against nbdkit 1.38.5-12.el9 and EL9's kernel headers; the kernel tests skip there, because the container has no `nbd` module and only the Ubuntu root step sets `MAKI_TEST_REQUIRE_NBD`. | `scripts/test_ci_gate_validation.py`, `RhelUserspaceJob`: `test_runs_on_every_change_in_a_centos_stream_9_container`, `test_uses_the_baseline_toolchain_and_its_own_cache`, `test_installs_from_baseos_appstream_and_crb_only`, `test_builds_tests_and_packages_what_the_debian_package_ships`, `test_the_built_rpm_is_installed_checked_and_refuses_removal_under_a_record` and, from the review, `test_root_in_the_runner_owned_workspace` | [#374](https://github.com/seo-rii/maki/pull/374) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-157 | The first version of #375 wrote on the status page, in the support matrix's Debian 12 GCE row and in operations that every external campaign had used `nbd-client` 3.27.1. Several campaigns never attached a kernel NBD device (the GCE workload-VM resets, Firecracker and the cgroup campaigns used userspace libnbd), and the 2026-09-02 privileged run used `nbd-client` 3.24. Found by review. | All three say that every campaign that attached a kernel NBD device did so through `nbd-client` (3.27.1 where the report names the version; 3.24 in the 2026-09-02 privileged run) and predates the helper's own connect, and the status page that the others attached none. Four kernel-NBD reports (the 2026-09-17 fresh-host restore, the 2026-09-18 PostgreSQL crash and remote-provider database runs, the 2026-09-19 cross-host TLS run) name no client version. The testing guide's external checklist says its kernel-NBD coverage was through `nbd-client`, and the privileged validation procedure's scope names the netlink `NBD_CMD_DISCONNECT` its probe sends. The dated reports under `docs/qualification/` are unchanged ([status](status.md)). | No test pins the wording; `scripts/check_docs_links.py` | [#375](https://github.com/seo-rii/maki/pull/375) |
| AUD-158 | There was no installation path for RHEL 9 and its rebuilds. | [`docs/getting-started/installation-rhel.md`](getting-started/installation-rhel.md) covers the repositories (BaseOS and AppStream; CRB only for the ABI test; no EPEL), the packages and the versions seen on CentOS Stream 9 on 2026-11-24, the toolchain (rustup with Rust 1.94.0; AppStream's `rust-toolset` 1.99.1 meets the lockfile's declared minimums, the highest being 1.88, but no job builds with it), the build and installation, `modprobe nbd` and `modules-load.d`, the LVM devices file (on by default in lvm2 2.03.33: do not list `/dev/nbd*` in it, because every LVM command of the helper passes `--devices`), SELinux (read from the policy, nothing run enforcing; default labels, an unconfined daemon and helper, AUD-154's conflict, and how to look for denials with `ausearch -m AVC`) and the status: not qualified, with what has never run. The support matrix's RHEL 9 row says what CI checks and that RHEL 9 is not qualified; Fedora (not built or tested) and RHEL 8 (unsupported: systemd 239 lacks `OnSuccess=`) get rows of their own; the status page has one line, and the README, the documentation index and `packaging/rpm/README.md` link the guide. The testing guide describes the job and the RPM suite. | `scripts/test_docs_rhel_installation_validation.py`: `test_guide_and_package_readme_quote_the_spec_static_requires`, `test_packages_come_from_baseos_and_appstream_only`, `test_the_nbdkit_metapackage_is_never_installed`, `test_rpm_builder_calls_use_options_it_accepts`, `test_guide_says_rhel_9_is_not_qualified`, `test_guide_is_linked_where_installation_guides_are_listed` and, from the review, `test_guide_and_package_readme_quote_the_spec_conflicts` | [#374](https://github.com/seo-rii/maki/pull/374) |

### Not closed in the seventh round

Each item was checked against `main` with both pull requests merged.

- No external campaign, systemd attach or attach on a host of its own has
  run the helper's own connect: the evidence is unit tests over scripted
  servers and kernels, a real nbdkit, and the two root-only kernel tests on
  GitHub's Ubuntu runner (AUD-147, AUD-155). Every campaign that attached a
  kernel NBD device did so through `nbd-client` (AUD-157). The runner's
  unprivileged disconnect probe has not run against a real kernel
  (AUD-153). That an attachment `nbd-client` 3.27 connected detaches with
  the new helper follows from the kernel interface (the same sysfs
  attribute and netlink request); it was not run.
- Nothing ran on a RHEL kernel or its `nbd` driver or with SELinux
  enforcing, and nothing attached, detached or grew a device on RHEL 9 or a
  rebuild. The `rhel9` job runs on the Ubuntu runner's kernel, in a
  container where the kernel NBD tests and the root-only tests that need a
  private mount namespace or a writable cgroup tree skip (the Ubuntu job
  runs them as root). The
  SELinux analysis is read from the policy, not observed. Rocky Linux and
  AlmaLinux were not tested, Fedora is not built or tested, only an x86_64
  RPM has been built (the other architectures' checks run on stub
  artifacts), and no job builds with AppStream's `rust-toolset`. RHEL 9
  stays not qualified (AUD-154, AUD-156, AUD-158).
- The kernel's own work on an NBD request is not bounded: a daemon that
  stopped reading with a full send buffer holds `NBD_CMD_DISCONNECT`, the
  helper and the attach lock until it reads again or its socket closes. The
  unit's timeout is the outer bound, and a task in an uninterruptible wait
  ends only when the wait does; with `nbd-client` the helper could abandon
  such a child at the step limit (AUD-151).
- The RPM conflicts with `nbdkit-selinux`: Maki cannot be installed on a
  host that needs the module for libvirt or virt-v2v, nor on one where
  SELinux is permissive or disabled and the module would be harmless
  (AUD-154). *Corrected on 2026-11-24: this item said that
  `dnf --allowerasing` resolves a conflicting transaction by removing Maki,
  which `%preun` refuses while a volume is attached. `%preun` refused only
  Maki's own erase and dnf ran the rest of the transaction: it installed the
  module beside Maki, and a plain `dnf remove maki` under an attachment kept
  Maki and erased `nbdkit-server`, `lvm2`, `xfsprogs` and `kmod`. The RPM
  is now a dnf-protected package and also conflicts with the `nbdkit`
  metapackage, so dnf refuses both transactions before it changes anything
  ([RHEL 9 removal](getting-started/installation-rhel.md#upgrading-and-removal)).*
- A device that something holds open for longer than the 5-second busy
  window still fails the connect as busy (AUD-150). *Changed by AUD-163 and
  AUD-164 ([#383](https://github.com/seo-rii/maki/pull/383)): an attach that
  allocated the device itself moves to the next free one; a pinned device
  still fails as busy, and the window counts from the first busy answer.*
- The CentOS Stream 9 source answers the sixth round's question: the
  backend can outlive a successful `NBD_CMD_DISCONNECT`, because the kernel
  removes the `pid` and `backend` attributes only when the last reference
  to the device's configuration is dropped. Detach and cleanup already
  allow for it: since `5d985d8` (2026-11-14, when the helper still ran
  `nbd-client -d`) they read the backend again after their steps and, while
  it still shows, keep the record and fail with "disconnect has not
  completed; keeping the attach record for cleanup retry", and attach
  rollback retires its record only once no backend shows. That is tested
  against a fake system
  (`acknowledged_but_incomplete_disconnect_preserves_cleanup_authority_for_retry`,
  maki-privileged `exec_tests.rs`). What has not run is the real case: on a
  real kernel, a detach that meets an opener, such as a udev probe, fails
  and needs a retry. *Changed by AUD-197
  ([#398](https://github.com/seo-rii/maki/pull/398)): detach and cleanup wait
  up to 15 s for the device to stop showing the connection, and keep the
  record and fail only if it still shows one then. By the CentOS Stream 9
  source an opener that already held the device at the disconnect keeps the
  attributes, not the probe that the disconnect's own change event starts. The
  real case still has not run.*
- The socket peer's pid and uid are logged, not checked. Every `maki@`
  instance runs as the same `maki` user, so only the `[lvm_identity]` and
  `fs_uuid` pins, where an attach configuration sets them, refuse a socket
  that serves another volume before anything is mounted; the 2026-10-15
  volume-isolation item stays open (AUD-147).
- The native nbdkit tests that existed before still skip without nbdkit:
  `MAKI_TEST_REQUIRE_NBDKIT=1` covers only the new NBD tests (AUD-155).

## Sixth round, follow-ups (2026-11-23): AUD-133–AUD-146

After the fifth round's pull requests had been reviewed and merged, the
maintainer asked for three things: one default TLS trust for the three remote
transports, the second half of [#354](https://github.com/seo-rii/maki/pull/354)
(retiring a displaced attach record automatically, which #354 had left out),
and a closer look at the issues the earlier pull requests recorded as left,
with a fix wherever one proved real. Ten pull requests,
[#363](https://github.com/seo-rii/maki/pull/363) to
[#372](https://github.com/seo-rii/maki/pull/372), were merged into `main` on
2026-11-23. Five change documented design decisions (AUD-133 to AUD-137); each
row states the earlier behaviour, what replaced it and what is kept of what
the earlier decision protected. The others fix what the closer look confirmed
(AUD-138 to AUD-145), and AUD-146 a CI formatting step that the workspace's
new test files pushed past the Windows command-line limit. The fifth round had found LVM's name resolution behind
AUD-135 by reading; it was reproduced with LVM 2.03.16 on loop devices. Every
code fix landed test-first. All rows are **Fixed**; AUD-141 documents and pins
classifications without changing them. No change alters the on-disk format or
the golden vectors. The operator-visible changes are listed in the
[changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy, `cargo fmt --check` and the documentation link checker, with
fails-before runs of the test commits and mutation checks; #364 also ran
maki-crypto's two phase 5 gates. Review before the merges changed eight of
them, each with tests: #363 (the volume-name check and the status off
Linux), #364 (a GOAWAY that refuses a call), #365 (a rename the root refuses),
#366 (damaged manifest slots and the first anchor's temporary file), #367
(holders that are not LVM mappings), #368 (what growth is bound to), #369
(erasure of the private keys its identity split decodes) and #371 (a rollback
profile that would have skipped); #370 had two test corrections. The rows
record how. Each pull request's own CI run passed, both Windows jobs'
clippy and workspace tests included; `main` itself failed its Windows
formatting step from #369's merge until #372 (AUD-146). These are repository tests over simulated kernels, crash models,
fake endpoints and local TLS servers. No kernel NBD device, device-mapper
activation, systemd failed start, real nbdkit, public TLS endpoint or physical
power loss was exercised, and LVM ran only against loop devices without
device-mapper.

### Design changes

| ID | Earlier behaviour | Change | Regression | PR |
|---|---|---|---|---|
| AUD-133 | Without a `ca_file`, the three remote transports trusted different roots, as the configuration guide has said since AUD-125. `remote-http` (reqwest's `rustls-tls`) trusted only the public roots compiled into the binary (webpki-roots) and never read the host's trust store, so a private CA installed in the system bundle or named by `SSL_CERT_FILE` authenticated a gRPC or WebSocket endpoint but not an HTTP one. `remote-grpc` (tonic's `tls-native-roots`) trusted only the host's trust store: on an image whose store is empty an `https://` endpoint without `ca_file` was refused when the provider was built, so attach failed, and no public endpoint was reachable from such an image. BUG-097 had made a configured CA usable there by asking tonic for the native roots only when the store held certificates or no CA was configured, so a gRPC deployment with `ca_file` on an empty store trusted that CA alone. `remote-websocket` trusted both sets. In all three a `ca_file` added to the roots. | All three verify the server against one set of roots from `maki_crypto::tls_trust::trusted_roots`, behind a `tls-trust` feature that only the transport crates enable (maki-privileged does not depend on maki-crypto, PRIV-010): the union of the host's trust store, read best effort through rustls-native-certs (the system bundle, or `SSL_CERT_FILE`/`SSL_CERT_DIR` when either is set, unparsable entries skipped), the compiled-in webpki-roots set, and the configured CA bundle, parsed as strictly as before (every member a valid certificate, a bundle without one refused). HTTP builds its rustls client configuration itself and hands it to reqwest with `use_preconfigured_tls`; it splits the combined identity PEM the way reqwest's `Identity::from_pem` did and erases a decoded key it does not use. Redirect refusal (C-01), no environment proxy and the classification of typed TLS errors are unchanged. gRPC hands tonic the roots as trust anchors and drops `tls-native-roots` and BUG-097's empty-store probe: the set is never empty, so the provider is always built, and an endpoint that none of the roots vouches for fails at the handshake as `EndpointFatal`. WebSocket behaves as before. The remote witness client is not a crypto transport and still trusts only its configured CA, over mutual TLS 1.3 with a pinned server name; SPEC §18 now says so. A review before the merge added tests that the identity split erases every private key it decodes. **Behaviour change:** HTTP also trusts the host's store, so a private CA installed there authenticates an HTTP endpoint without a TLS section. gRPC also trusts the compiled-in public roots and no longer refuses construction on a host whose store is empty: a public endpoint is reachable from such an image, a private one that none of the roots vouches for is refused at the handshake instead of at construction, and a deployment with `ca_file` on an empty store, which trusted that CA alone, now also accepts a server whose certificate chains to a public root and matches the endpoint's name. No setting restores CA-only trust, so no transport can be restricted to a private CA. The CA bundle errors read the same in all three transports, and an HTTP client identity that rustls rejects is reported as `bad client identity: …`. The wider rule was chosen because one rule is easier to state and audit than three, because a private CA installed in the host's store, the usual way to distribute one, now works for every transport, and because images without a system bundle keep reaching public endpoints. What BUG-097 protected is kept: a configured CA authenticates its endpoint on a host whose store is empty. No transport can disable verification ([providers](configuration.md#providers)). | `the_host_store_and_ca_file_add_to_the_compiled_in_roots` in `tests/review_default_trust.rs` of maki-crypto-http, maki-crypto-websocket and maki-crypto-grpc, each a binary of its own because it points `SSL_CERT_FILE` and `SSL_CERT_DIR` at a test bundle (it failed for HTTP and gRPC before); unit tests `the_default_roots_hold_every_compiled_in_public_root` and `a_configured_ca_is_added_to_the_compiled_in_roots` (`crates/maki-crypto-http/src/trust_tests.rs`, `crates/maki-crypto-websocket/src/trust_tests.rs`) and `the_trust_anchors_hold_the_compiled_in_roots_and_the_configured_ca` (`crates/maki-crypto-grpc/src/tls_tests.rs`); the BUG-097 test, now `an_empty_host_trust_store_does_not_prevent_construction` (maki-crypto-grpc `review_custom_ca_trust.rs`); from the review, `identity_split_erases_a_replaced_private_key` and `identity_split_errors_erase_the_decoded_private_key` (`crates/maki-crypto-http/src/sensitive_tests.rs`) | [#369](https://github.com/seo-rii/maki/pull/369) |
| AUD-134 | A trusted attach record whose NBD device was connected under another identity was refused by every verb of its volume (attach, cleanup and with it `maki-recover@`, recover and detach) until root removed the record by hand, even when nothing of the recorded attachment was left on the host. AUD-120 kept this on purpose: sysfs shows what holds a device, not under which connection it was set up, and the 2026-09-19 package campaign had qualified the refusal on a real kernel. Since AUD-120 the helper no longer creates this state itself; it remains for an NBD client started outside the helper and for two volumes left sharing a device by a helper from before AUD-120. | Attach, cleanup, recover and detach retire such a record under the attach lock, without running a command and without touching the device or its connection, when observation proves that nothing of the recorded attachment remains: the device's backend is readable, is not the recorded one and is the same after each of two observations of the host; the record names its VG UUID (in its mapping proof, its pre-activation intent, which stores the verified LVM identity, or the administrator pins, which must all agree) and no device-mapper device on the host belongs to that VG; every holder of the device and of its partitions is readable and is an LVM mapping of another VG (a device-mapper uuid of `LVM-` followed by another VG's UUID and an LV UUID, an internal-LV suffix allowed); nothing is mounted at the recorded mountpoint and no mount is of a mapping of the recorded VG; and no other volume's record names the device with the same VG UUID (a cloned image) or with none. A holder is attributed by the VG UUID that device-mapper carries, not by the connection, which answers AUD-120's objection. Cleanup first compares its configuration with the record, as its other paths do. Cleanup, recover and detach then succeed, attach goes on as for a volume without a record (allocation leaves the connected device out) and grow refuses and names cleanup. Every refusal keeps AUD-120's text and way out and adds `The record is not retired automatically: <reason>`. The observations live in `crates/maki-privileged/src/displaced.rs`, which the executor reaches through a provided `displaced_remains` method of its system seam; its default refuses. A review before the merge found that the first version accepted any device-mapper holder whose uuid did not name the recorded VG (a crypt, multipath or partition mapping, one without a uuid, a cut-short LVM uuid); only an LVM mapping of another VG is accepted now. **Behaviour change:** the four verbs retire such a record instead of refusing; detach's first check says "refusing to detach"; cleanup with a configuration that does not match the record is refused with "cleanup configuration does not match the trusted attach record". Kept: a record that names no VG UUID (an attach without `[lvm_identity]` pins that stopped before the connect, which is the state AUD-120's first killed-helper window leaves, or a record from before activation intents) keeps the refusal and the documented manual step; a foreign backend is never touched; any observation that cannot be read keeps the record. The retirement has not been run against a real kernel, and the campaign's refusal is superseded for a record that names its VG UUID (SPEC §8, [privileged helper](operations.md#privileged-helper)). | `crates/maki-privileged/src/review_displaced_attach_record.rs`, in AUD-120's simulated-kernel harness beside a running second volume and beside an outside NBD client: `a_displaced_record_is_retired_once_nothing_of_its_attachment_remains` (every verb, records holding a proof, an intent or only pins), `cleanup_retires_only_the_record_its_configuration_describes`, `an_attach_pinned_to_its_displaced_device_retires_the_record_and_connects_nothing`, `grow_refuses_a_displaced_record_and_points_to_cleanup`, `a_mapping_of_the_recorded_volume_group_keeps_the_record`, `a_holder_that_is_not_a_mapping_keeps_the_record`, `a_mount_of_the_recorded_attachment_keeps_the_record`, `an_observation_that_cannot_be_read_keeps_the_record`, `another_record_on_the_device_must_name_another_volume_group`, `a_record_without_a_vg_uuid_keeps_the_record`, `a_change_while_the_host_is_observed_keeps_the_record` (11 of 12 failed before), the control `an_unreadable_backend_keeps_the_record`, and from the review `a_mapping_holder_that_is_not_another_volume_groups_keeps_the_record`; AUD-120's `a_recorded_device_under_another_identity_is_refused_with_the_way_out` (`review_stale_attach_record.rs`) now pins the refusal for a record that names no VG UUID | [#367](https://github.com/seo-rii/maki/pull/367) |
| AUD-135 | Attach activates with `--devices <verified PVs> --select vg_uuid=<verified>`, and its rollback and the deactivation of an activation intent were scoped the same way. Grow ran `lvextend -L <n>b <vg>/<lv>`, and detach, cleanup and recovery of a record with a mapping proof, or of an old record without proof or intent, ran `vgchange -an <vg>`: LVM resolved the name over its own device scan. The [R5 section](#fifth-review-2026-10-01-r5-001r5-034) kept this ("Considered and left as is"): the kernel observation before either command proves that every mapping of the VG depends only on the NBD device, LVM refuses an ambiguous duplicate name, and scoping needs the verified LVM identity at detach and grow time. With LVM 2.03.16 (Debian 12's version) on two loop devices each carrying a VG of the volume's name, without device-mapper (name resolution and metadata only): with both PVs in LVM's scan both commands exit 5, "Multiple VGs found with the same name"; with the volume's PV outside the scan (a devices file, `filter` or `global_filter` that leaves it out) `lvextend` extended the other disk's LV and `vgchange -an` deactivated the other VG; with the volume's PV gone (a dead daemon, recovery after the backend went) `vgchange -an` read only the other disk. In the executor that meant: on a host whose scan leaves out `/dev/nbd*` grow and detach never worked, and with a namesake there grow reported success after extending the other disk's LV; with both VGs in the scan grow, detach and recovery were refused; after a daemon death beside a namesake, cleanup's deactivation succeeded on the other VG, so the proof-scoped `dmsetup` fallback, which runs only after a nonzero exit, was never reached, and cleanup and `maki-recover@` stopped at "earlier detach steps have not completed". The three reasons hold only in part: the observation sees active mappings only, LVM refuses a duplicate only when it sees both VGs, and the record already holds the verified identity. | The executor builds both commands from the trusted record. The candidate devices are the mapping proof's (the NBD device and the partitions attach recorded) or the activation intent's verified devices, or the NBD device alone for a record from before both. The VG UUID comes from the proof (every mapping's dm uuid is `LVM-<VG UUID><LV UUID>`, spelled with LVM's dashes for `--select`), from the intent, or, for a record with neither, from the administrator pins, which must agree with the proof or intent. For those records deactivation runs `vgchange --devices <recorded> --activate n --select vg_uuid=<recorded> --config "devices { allow_changes_with_duplicate_pvs=0 }" <vg>`. It still names the VG, because LVM exits 5 when it cannot find a named VG on those devices, while a selection alone exits 0 without doing anything; the nonzero exit keeps cleanup's fallback reachable after the daemon died. Growth runs `lvextend --devices <recorded> --config "…" -L <n>b <vg>/<lv>`: `lvextend` has no `--select`, so its scope is the recorded devices, after the live check that the mapping is the recorded one. The commands reach the system seam through a provided `run_scoped_lvm`, and the real system's `run_step` refuses the unscoped forms. A review before the merge corrected SPEC, which bound growth to the VG UUID as well, and the plan and step texts, which claimed a VG UUID selection for every record. **Behaviour change:** on a host whose devices file or filter leaves out `/dev/nbd*`, grow, detach and recovery find the volume's VG; beside a VG of the same name on another disk they act on the volume's VG and never on the other, and cleanup after a daemon death reaches its fallback. The plan and step texts read `vgchange -an <vg>, on the recorded PVs only and by the recorded VG UUID where the record names one` and `lvextend -L <n>b <vg>/<lv>, on the recorded PVs only`. A mapping proof whose dm uuids do not name one VG UUID is refused before any command (real LVM never produces one). An old record without proof or intent is scoped to its NBD device, so such an attachment whose PV is a partition now fails detach with "not found" and keeps the record. Kept: the live observations before each command and the scope of activation, attach rollback and intent deactivation, which were already scoped (SPEC §39, [privileged helper](operations.md#privileged-helper)). | `crates/maki-privileged/src/review_lvm_device_scope.rs`, an LVM model in AUD-120's simulated kernel that resolves VG names over the volumes' NBD exports and another disk's inactive VG of the same name, with LVM's scan including or leaving out the NBD devices: `grow_extends_the_recorded_lv_and_never_a_namesake`, `detach_deactivates_the_recorded_volume_group_and_never_a_namesake`, `cleanup_after_the_daemon_died_reaches_its_fallback_beside_a_namesake`, `recovery_never_deactivates_a_namesake` (all four failed before; each one's case without the other VG on a full scan is a control), `every_kind_of_record_scopes_its_commands_to_what_attach_verified`, and from the review `the_plan_states_the_scope_each_kind_of_record_gets`; `a_proof_scopes_lvm_to_its_recorded_devices_and_vg_uuid` (`crates/maki-privileged/src/recover.rs`) | [#368](https://github.com/seo-rii/maki/pull/368) |
| AUD-136 | A local rollback creation (`RollbackBacking::create`, run by `maki volume create`) created `rollback.format` and then wrote it, reserved the arena and both manifest slots, wrote the initial manifest into slot 0 in two writes, installed an empty witness `anchor` and only then published the first record into it. Until the anchor is published nothing can open the volume and nothing was acknowledged, but `create` required both directories to be empty ("interrupted enrollment is deliberately not resumed implicitly"). A creation that stopped anywhere after its first file therefore left a pair that `create` refused ("rollback enrollment requires empty backing and witness directories") and that `open` refused too ("invalid rollback format marker", "No such file or directory" for a missing anchor, "invalid witness anchor length" for the placeholder). The likeliest case needs no crash: a capacity the filesystem cannot hold fails the arena reservation with ENOSPC, and `create` again with a smaller capacity was refused. | The marker is written and synced as `rollback.format.next` and renamed into place (the step remote creation uses since AUD-114); the first anchor is published like every later one (`anchor.next` written and synced, renamed, the directory synced), with no placeholder; and the initial manifest goes into slot 0 with its length in one write. `create` completes the creation over a backing directory that holds only what a creation writes (the lock; the marker staged, published, or created and never written by an earlier release; the arena and the two manifest slots), as long as slot 1 holds only zeros and slot 0 only zeros or, at its recorded length, the empty generation-0 manifest, beside a witness directory that holds only `witness.lock` and `anchor.next`. A creation never writes slot 1, and every volume that committed anything wrote it before its witness moved on, so `create` never creates over a used volume, whatever the witness directory holds (an empty one included, which is what an unmounted witness mount looks like), short of both slots lost or zeroed entirely. Still refused and left as found: slots that hold anything else, a marker of another format, other entries, and any `anchor`, including the empty one earlier releases left, which is also what a truncated anchor looks like; for that one `create` and `open` say that the creation did not complete or the witness lost its state, and that only for a volume never attached may the empty file be removed. Run as root, the first record keeps SPEC §8's rule for temporary records: a file of any user but root and the witness directory's owner under `anchor.next` is refused, never published. A review before the merge found that the first version accepted manifest slots that did not decode, so a committed volume whose slots took damage, beside a witness directory without an anchor, was created over, and that as root it published the first anchor from whatever file stood under `anchor.next`; both are fixed with tests, and the root unit test made maki-backing's unit tests part of the root-only CI step (AUD-129). **Behaviour change:** local `create` completes a pair that holds only what an interrupted creation leaves, with nothing to remove by hand, where it refused every pair that was not empty. Kept from the old rule: creation never replaces or recreates an existing anchor and never creates over a backing with committed data, and a new anchor carries a new random identity, so no earlier copy of any backing matches it; the witness's freshness and rollback guarantees and everything after the anchor is published are unchanged. A `maki volume create` that stops after publishing the anchor, while it initializes the volume inside the backing, is still refused by a later `create` ([local configuration and creation](rollback-protection.md#local-configuration-and-creation)). *Superseded by AUD-159 ([#382](https://github.com/seo-rii/maki/pull/382)): a later `create` continues such a creation.* | maki-backing `review_interrupted_local_create.rs`, a real `RollbackBacking::create` in a child process killed by a seccomp filter or failed with ENOSPC: `create_killed_at_its_first_write_can_be_run_again`, `create_that_ran_out_of_space_for_its_arena_can_be_run_again`, `create_killed_while_writing_its_witness_anchor_can_be_run_again`, `create_that_ran_out_of_space_for_its_witness_anchor_can_be_run_again` (all four failed before), `create_completes_a_backing_whose_marker_was_never_written`, from the review `create_refuses_a_committed_backing_whose_manifest_slots_are_damaged`, `create_refuses_a_second_manifest_slot_that_holds_anything` and `create_refuses_the_initial_manifest_in_the_second_slot`, controls `control_create_refuses_a_used_backing_beside_an_empty_witness_directory`, `control_create_and_open_refuse_a_witness_that_holds_an_empty_anchor` and `control_create_refuses_a_backing_that_holds_anything_else`; the crash model `crates/maki-backing/src/rollback/local_creation_tests.rs` (`a_creation_killed_at_any_operation_can_be_continued`, `a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued`, `a_creation_whose_operation_failed_can_be_run_again`, `an_undisturbed_creation_is_refused_by_a_second_one`, `control_a_committed_volume_is_never_created_over`); `root_creates_the_first_record_only_in_a_file_of_root_or_the_directory_owner` (`crates/maki-backing/src/witness.rs`) and its real-directory counterpart `root_create_never_publishes_a_temporary_record_another_user_left_in_the_witness` (maki-backing `review_root_created_ownership.rs`, needs root) | [#366](https://github.com/seo-rii/maki/pull/366) |
| AUD-137 | The binaries did not agree on the exit status of misuse. `maki-witness` exited 1, the status of a failed command, for an unknown command, a missing or extra argument and a volume identity that is not a UUID. `maki` exited 2 only for an unknown command, a wrong argument count and `--timeout` on a command without a control round trip (AUD-095); its option errors exited 1: `--timeout` without a positive number of seconds, `--socket` without a path, beside a configuration or on a command without a control round trip, and every malformed `reload cache` option. A malformed fence, current root, snapshot root or storage identity given to `maki volume takeover`, `restore` or `resume-enrollment` was noticed only after the configuration had been read and the witness client built, and exited 1. `maki-attach` checked the `--volume` name rule only while building the request from the attach file, so `recover-failed-start --volume a.b`, and the other verbs with a malformed name and an unreadable `--config`, exited 1; and off Linux `recover-failed-start` without `--plan` exited 0 or 1 where every other action exited 3. | One convention for the five binaries, which `maki(8)` and `maki-attach(8)` now state in an EXIT STATUS section (`maki-check(8)` already did): 0 for success; 1 for a failure (an error, a failing check, a refused request, a configuration or attach file that cannot be read, is not trusted or does not parse); 2 for misuse, refused before anything is changed (an unknown or misplaced option, a wrong argument count, a malformed argument, approval or volume name), which `maki` and `maki-witness` check before they read anything and `maki-attach` before it reads its attach file, while `maki-attach` and `maki-benchmark` also exit 2 for a value that fails validation against the configuration they have read; 3 for `maki attach`, `detach` and `grow`, which print the `maki-attach` command, and for every `maki-attach` action, `recover-failed-start` included, run without `--plan` off Linux. `maki` parses a remote command's approval before it reads the configuration; an approval that is well formed but does not match the authority still fails with 1 after the authority has been asked. A review before the merge found the first version's manual page wrong for `recover-failed-start`; argument validation now applies the name rule, and the 64-byte bound for `attach` and `verify`, to `--volume` before any file is read, and the hook exits 3 off Linux without `--plan`. **Behaviour change:** `maki-witness` misuse exits 2 instead of 1 with the same output; `maki`'s `--timeout`, `--socket` and `reload cache` option errors and its malformed approvals exit 2 instead of 1 with the same messages, and a malformed approval is reported before a missing or unreadable configuration; `maki-attach` with a malformed `--volume` exits 2 with the usage for every verb, before any file is read; off Linux, `recover-failed-start` without `--plan` exits 3. A script that detects misuse by status 1 must test for 2. Kept: a command that fails still exits 1, and `maki-benchmark` keeps status 2 for runs it refuses after reading the configuration, as documented. *Completed by AUD-190 ([#393](https://github.com/seo-rii/maki/pull/393)): an option given where `maki` or `maki-witness` expects a path was taken for the path and exited 1, or 0 where `maki-witness init` created a state directory of that name; it now exits 2 before anything is read.* | `review_misuse_status.rs` in `bins/maki-witness` (`an_unknown_command_or_a_wrong_argument_count_exits_2_with_the_usage`, `a_volume_identity_that_is_not_a_uuid_exits_2_before_anything_is_created`, control `a_command_that_fails_still_exits_1`) and in `bins/maki` (`malformed_options_and_approvals_exit_2_before_anything_is_read`, 27 command lines whose configuration and socket do not exist, so that a command reading either would fail with 1 too; control `well_formed_commands_that_fail_still_exit_1`); `diagnostics_nobody_reads_do_not_replace_the_exit_status` (`review_closed_output.rs` of both binaries) expects 2 for its misuse cases; from the review, `a_malformed_volume_name_is_refused_before_any_configuration_is_read` (bins/maki-attach `review_strict_arguments.rs`, every verb) and `hook_rejects_device_overrides_and_invalid_instance_names` (`review_failed_start.rs`, with and without `--plan`); `the_hook_executes_only_on_linux` checks the status 3 on the Windows runner only | [#363](https://github.com/seo-rii/maki/pull/363) |

### Remote rollback and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-138 | Remote namespace GC retires a quiescent stale namespace by renaming it to its `.remote-gc-` tombstone, syncing the root, unlinking the namespace's files, syncing its directory, unlinking its lifetime lock and removing the directory. Any failure from the rename on ended the pass, which AUD-113 kept on purpose. A failure that persists for one namespace therefore ended every pass. A namespace directory GC may read but not write (an administrator's `chmod a-w`, a tree copied back with the modes of a read-only copy) passes examination, is renamed and then fails at its first unlink, on that pass and on every later one; tombstones sort before every namespace, so no later pass reached a namespace again. Every activation left its predecessor on disk, each with a full arena, while the automatic pass only logged that it had not completed and `maki volume gc` failed with "GC stopped while retiring .remote-gc-…: Permission denied (os error 13)"; with a real `create_remote` and three attaches two namespaces remained instead of one. An immutable or append-only namespace directory fails the same way at its rename (EPERM), changing nothing, and the namespaces piled up behind it. | A step that changes the candidate alone now records it, and the pass goes on: an unlink in it, the sync of its directory, its removal, and its rename when the namespace's own directory is immutable or append-only and the root is neither (EPERM with that flag on the namespace and none on the root, read with `FS_IOC_GETFLAGS`; nothing is renamed). Once renamed, its tombstone is already durable, because the root is synced before the first unlink, and every other candidate's deletion still rests on its own examination, lifetime lock and durable tombstone, so continuing deletes nothing that was not proven quiescent and retired. The entry is kept as the step left it and reported under a new `unfinished` list of `{"name", "error"}` objects with a `counts.unfinished` total: `name` is the entry as GC left it (the namespace if its rename failed, its tombstone otherwise) and the error names the step, for example `unlinking rollback.arena: Permission denied (os error 13)`. A later pass meets the tombstone first and resumes it. Renaming a directory inside its parent needs write permission on the parent, not on the directory, so every other rename failure (no write permission on the root, a read-only or full filesystem, an append-only or immutable root, an I/O error) is the root's and still ends the pass, as do the root's mount identity and directory syncs, an entry that changed identity while it was being retired, and every authority and root failure that ended it before. The automatic pass logs one `WARN` naming the first unfinished entry, its error and the count. Two reviews before the merge found that a rename the root refused was reported as one unfinished namespace per candidate, with `maki volume gc` exiting 0, and that an append-only root refuses a rename with the same EPERM as an immutable namespace; such a rename now ends the pass. **Behaviour change:** for the steps above `maki volume gc` exits 0 and lists the entry under `unfinished`, where it failed, and its JSON report has one more array and one more `counts` field. AUD-113 kept the failure pass-ending because "the root has been changed and the failure is about completing that change durably"; that remains true of the root sync, which still ends the pass, but not of the later steps, which change only that tombstone. The guide says to correct the mode, owner or flag the error names and run GC again rather than remove the files by hand ([retire old writer namespaces](remote-witness-service.md#retire-old-writer-namespaces)). | maki-backing `review_remote_gc_unreadable.rs`: `gc_reclaims_past_a_tombstone_whose_files_it_cannot_unlink` (mode `0500`, with the capabilities that let root ignore modes cleared on the test's thread) and `gc_reclaims_past_a_namespace_it_cannot_rename` (the immutable flag; needs root), both failing before, `the_automatic_pass_logs_the_namespaces_it_could_not_finish_retiring`, and from the reviews `a_rename_the_root_refuses_ends_the_pass` and `an_append_only_root_ends_the_pass` (needs root; also with both flags set); the pinned unlink-failure test, now `unlink_failure_keeps_the_durable_tombstone_for_a_later_pass_without_touching_current` (`remote_gc.rs`); `gc_reports_a_tombstone_it_cannot_empty_and_reclaims_the_rest` (`bins/maki` `remote_admin.rs`, with CAP_DAC_OVERRIDE dropped from the bounding set) | [#365](https://github.com/seo-rii/maki/pull/365) |
| AUD-139 | A remote `maki volume create` wrote `remote.enrollment`, the binding, in place after its format marker. Killed between creating and writing it, cut by a power loss that kept the name but not the bytes, or failing the write (a full disk), it left an empty or torn binding beside the published marker. The authority is claimed only after the binding is durable, so nothing was lost, but `create` refused the root (its marker is published), `resume-enrollment` refused the binding ("invalid enrollment metadata length", or "envelope or checksum" for a torn one), and the next daemon start refused an "uninitialized remote backing": the operator had to move the file out of the backing root by hand before recovery continued. AUD-114 left this. | The binding is written and synced as `remote.enrollment.next`, renamed to `remote.enrollment` and the directory synced. A failed staging is removed, and one that a kill or a power loss leaves is never read and is truncated and written again through a new descriptor by the next attempt. A published binding is still validated against the approval and rewritten with its exact bytes before its syncs are retried. `resume-enrollment` therefore continues a creation cut anywhere in the binding step, with no manual step. *Superseded in part by AUD-172 ([#387](https://github.com/seo-rii/maki/pull/387)): a recovery that a power loss interrupted could still leave the binding without its marker, a root that neither command continued; recovery now makes the marker's name durable first, and `create` continues such a root.* An invalid `remote.enrollment` that an older binary left is refused exactly as before, because it cannot be told apart from a damaged binding, and keeps its documented quarantine step. `maki-witness init-etcd` has no such window: it writes the initial record with one compare-and-put transaction. A separate commit makes four tests of AUD-115 pass under `umask 002` with the fixture helpers of AUD-132 ([resume interrupted initial enrollment](rollback-protection.md#resume-interrupted-initial-enrollment)). | maki-backing `review_interrupted_enrollment.rs`: `create_killed_while_writing_its_binding_is_resumed` and `create_whose_binding_write_failed_is_resumed` (a real `create_remote` in a child process that a seccomp filter kills at, or fails with ENOSPC, its first 64-byte write; both failed before), `enrollment_recovery_writes_over_a_staged_binding_left_behind`, and the kept control `control_an_unwritten_binding_is_quarantined_before_enrollment_recovery_continues`; the crash model `crates/maki-backing/src/rollback/remote_creation_tests.rs`: `a_creation_killed_at_any_operation_of_its_binding_can_be_continued`, `a_creation_cut_by_a_power_loss_at_any_operation_of_its_binding_can_be_continued`, `a_creation_whose_binding_operation_failed_can_be_continued` (all three failed before) | [#366](https://github.com/seo-rii/maki/pull/366) |

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-140 | Since AUD-110 and AUD-116, background validation of a quarantined endpoint relabels as retryable a request refused without an integrity verdict from either peer, the set's own admission refusal and every verdict-class failure of the validated reference, so that only proof of another contract excludes the endpoint. One class still reached the self-test and the cross-endpoint check unchanged: a `ProviderFatal` error that the candidate's own provider or transport returned. The self-test returned it as is and the cross-endpoint check folded it into "endpoints are not interchangeable", so one such error, on any validation encrypt or decrypt, excluded the candidate until the daemon restarted, although it says that this endpoint cannot serve the request now (a backend that reports itself misconfigured), not that it holds another key. The daemon cannot reach it: its transports return `ProviderFatal` only for their own configuration, never for a reply, and the reachability probe at attach makes the same requests through the same configuration first. The `EndpointSet` API, which accepts any provider, did. | `ValidationProvider::failure` relabels a `ProviderFatal` from either peer like a generic refusal: the attempt is inconclusive, and the endpoint is validated again after `validation_interval` with the existing doubling backoff and serves only after a complete successful validation. The candidate's `UnsupportedContext` stays a verdict, since it is also the answer a context probe expects for its field, and so does every verdict the checks compute from replies. `EndpointValidator` states which errors decide the candidate's fate, and that a layer a validator stacks above the views must not report a refusal of its own with those classes; SPEC §34 adds the provider failure to the inconclusive outcomes. The other paths that compute a validation outcome were checked: in the daemon the only layer above the views is the random-prefix wrapper, whose construction and batch checks cannot fail once attach has succeeded, because configuration validation requires the in-flight byte limits to hold a full ciphertext batch. Its one runtime failure, a failing operating-system random source (or a failed allocation of the expanded batch), is `ProviderFatal` and still excludes the candidate; it is not transient on Linux and fails every encrypt the volume serves as well. **Behaviour change:** in background validation a `ProviderFatal` error of the candidate's own provider no longer marks it `rejected: true`; it stays quarantined and is validated again every `circuit_breaker.open_initial`, doubling to `open_max`, with a warning per attempt. Attach still refuses such an endpoint, and a running daemon sees no change. | `a_fatal_error_of_the_candidates_own_provider_defers_the_endpoint` (maki-crypto `review_endpoint_revalidation.rs`, ManualClock: a `ProviderFatal` on a validation encrypt or decrypt, under the cross-endpoint check alone or after the self-test; all four cases failed before) | [#364](https://github.com/seo-rii/maki/pull/364) |
| AUD-141 | Three statements of the provider error documentation (AUD-127) were missing or too broad. What a WebSocket `integrity` or `unsupported-context` error frame whose envelope is not exact does to its request and its connection was written nowhere. SPEC §18 and the configuration guide said that every transport classifies a reply that breaks its framing as a contract violation, but a WebSocket upgrade reply that is not a valid upgrade is `EndpointFatal`, and an HTTP/2 reset or GOAWAY under a gRPC call reaches the caller as the status tonic derives from it. And SPEC §22 pointed to §21 for the discard map right above the layout §22 gives, whose paragraph repeated the read rule. | Documented as the code behaves, with tests that pin it. An inexact envelope fails only its request, with `Contract("remote crypto provider returned an invalid probe error envelope")`; the transport does not resend it, also with `retry_safe`, the dispatcher charges the endpoint's breaker and never sends that operation to it again (R5-005), and the request is not marked completed, so the connection takes no new request and closes once the requests already on it finish. A tamper probe answered this way fails the self-test with that contract violation, never as an integrity failure. A well-formed error frame with an undefined reason is a contract violation that keeps the connection, and repeated members are read last-value-wins. The framing rule is scoped to message framing on an established connection (the HTTP/1.1 head, chunked coding and a close-delimited body; the gRPC length prefix, message count and final status; WebSocket frames). An HTTP/2 reset, and a GOAWAY that refuses the call (its last stream id is below the call's), is classified by its code: throttled for `ENHANCE_YOUR_CALM`, an endpoint failure for `INADEQUATE_SECURITY`, retryable for every other code; a GOAWAY that accepted the call and then closes the connection is retryable whatever its code. A call that a GOAWAY refused counts as sent, because the last stream id is the peer's statement and not proof that no request byte was written (SPEC §18), so only a retry-safe provider fails it over. A review before the merge corrected the first version, which called every GOAWAY retryable. | maki-crypto-websocket `review_probe_envelope.rs`: `an_invalid_probe_envelope_fails_its_request_and_retires_the_connection` (eight inexact envelopes, each beside a sibling request that completes), `a_well_formed_error_with_an_unknown_reason_keeps_the_connection`, `a_repeated_class_is_read_from_its_last_member`, `a_tamper_probe_answered_with_an_invalid_envelope_fails_the_self_test_without_a_verdict`; `an_upgrade_reply_that_breaks_the_handshake_is_an_endpoint_failure` (`review_upgrade_errors.rs`); maki-crypto-grpc `review_http2_errors.rs`: `an_http2_error_is_classified_by_the_status_it_maps_to`, `a_goaway_that_refuses_the_call_is_classified_by_its_code_like_a_reset` (a raw HTTP/2 peer, from the review), `a_call_refused_by_goaway_fails_over_only_when_retry_safe`; they pass before and after | [#364](https://github.com/seo-rii/maki/pull/364) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-142 | The failed-start hook (AUD-118) waited for the attach unit's control group to settle and loaded `/etc/maki/attach/<volume>.toml` before anything checked whether the volume's trusted record held an activation intent, and `exec::finish_interrupted_activation` opened the trusted state, creating `/run/maki-attach` if it was missing, before its own pre-check. Most failed starts leave no intent. A start that failed only because the attach configuration was invalid or not root-controlled (mode `0664`) was therefore logged as "could not roll back an interrupted LVM activation of volume pg: attach config …", although nothing had been activated, and an unreadable record or state directory was reported the same way. The operations guide said the hook rolls back "after it has queued the coordinator"; it does so after asking for it, also when systemd refuses the request (a masked coordinator). And nothing tested the binary's wiring: removing the rollback call from `failed_start.rs`, or building its plan differently from `cleanup`'s, passed every test. | The hook reads the record first, with the new `exec::interrupted_activation`, which takes no lock, loads no configuration and treats a missing state directory as no record. Only a record that holds an activation intent leads to the settle wait, the attach configuration and the rollback; a failed start without one writes no journal line, and every other outcome names the activation it is about. `finish_interrupted_activation` opens the state the same read-only way. The hook's effects (the manager queries, the record read, the settle wait, the configuration, the rollback, the journal) go through a small `Host` seam, and the hook builds its plan with `verb_plan("cleanup", ...)` and reads its configuration with `attach_config`, as `cleanup` does, so the two cannot drift apart. **Behaviour change:** the hook stops after reading the record when it holds no intent, and no longer creates `/run/maki-attach`. Its journal lines are: none without an intent; "cannot tell whether volume pg has an interrupted LVM activation to roll back: …; leaving all cleanup to the recovery coordinator" for an unreadable record; "volume pg has an interrupted LVM activation, but processes of the failed start are still running, or …" for an unsettled unit; "did not roll back the interrupted LVM activation of volume pg: under the attach lock its record no longer holds the activation intent, or its device no longer carries the recorded connection; …" where nothing was logged before; and "could not roll back the interrupted LVM activation …", which read "an interrupted". The guide says that the rollback also runs when the coordinator request is refused ([systemd deployment](operations.md#systemd-deployment)). | unit tests in `bins/maki-attach/src/failed_start.rs`: `without_an_interrupted_activation_the_hook_reads_no_configuration`, `an_unreadable_attach_record_is_reported_as_what_could_not_be_checked`, `an_interrupted_activation_with_an_unusable_configuration_names_both`, `an_unsettled_unit_leaves_the_interrupted_activation_to_the_coordinator`, `a_rollback_that_finds_nothing_to_do_under_the_lock_says_so` (all five failed before), and the wiring tests `an_interrupted_activation_is_rolled_back_with_the_plan_cleanup_runs`, `the_rollback_runs_when_the_manager_refuses_the_coordinator`, `only_the_running_start_job_lets_the_hook_act`, `the_rollback_reads_only_a_trusted_attach_configuration` | [#370](https://github.com/seo-rii/maki/pull/370) |
| AUD-143 | The hook's rollback waited for the global attach lock by retrying a non-blocking `flock` every 50 ms, and the lock wait and the commands shared one 30-second deadline. Every other helper (attach, detach, cleanup, grow, verify) blocks in `flock`, and the kernel serves blocked requests in order. Nothing hands the lock over at release: the first waiter is woken and takes the lock itself, and a non-blocking attempt wins only if it lands in that gap, which attempts 50 ms apart practically never do. The hook therefore got the lock practically only when nobody was queued: on the test host a retrying waiter got the lock in none of five two-second windows while three helpers kept queueing, and blocked waiters were served in arrival order in 30 of 30 trials. On a host attaching several volumes, which is when a start timeout (it counts the time queued on the lock) is likely, every helper that queued while the hook waited overtook it, and a lock granted late left the scoped deactivation little or no time; the volume then ended in the state the operations guide calls a second fault. | `TrustedState::lock_until` makes a blocking `flock` request on a thread of its own, so the request keeps its place in the queue. A wait that reaches its deadline is abandoned: a lock granted to it later is dropped with the channel it is sent into, which releases it, and the helper's exit ends a request still queued. The lock wait and the commands have separate budgets: up to 40 s for the lock after the 15-second settle wait, then 30 s for the commands, counted from when the lock is held. With about 2 s to kill a command at its deadline the hook runs at most 87 s, three quarters of the attach unit's `TimeoutStopSec=120`, which leaves the rest for its two `systemctl` calls; the coordinator's `JobTimeoutSec=360`, which runs from when the hook queues it, also covers the daemon's stop (systemd's default of 90 s) and the coordinator's own cleanup (`TimeoutStartSec=180`): 87 + 90 + 180 = 357 s. The unit timeouts are unchanged. **Behaviour change:** the lock wait is queued instead of polled, and with an intent to roll back the hook can take up to about 87 s instead of about 47 s; `exec::finish_interrupted_activation` takes a lock deadline and a command budget. An attach of another volume can hold the lock for up to its 180-second start timeout, longer than any wait these timeouts leave room for; the guide names contention of that length as one way into the second-fault state. The in-order service of blocked `flock` requests was observed on Linux and is what the queue test checks; POSIX does not specify it. | `a_bounded_lock_wait_is_served_before_helpers_that_queue_after_it` (`crates/maki-privileged/src/state_tests.rs`, sequenced on `/proc/locks` rather than on sleeps) and `the_failed_start_rollback_has_its_command_budget_once_it_holds_the_lock` (`recover_tests.rs`), both failing before; `the_rollback_budget_fits_the_packaged_timeouts` (`bins/maki-attach/src/failed_start.rs`) holds the bounds to the unit timeouts | [#370](https://github.com/seo-rii/maki/pull/370) |

### Command line and plugin

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-144 | `maki-witness` collected its arguments with `std::env::args`, which panics on an argument that is not UTF-8: `maki-witness fingerprint "$(printf '/tmp/\xff.pem')"` exited 101 with a Rust panic message (AUD-122 left this). In the nbdkit plugin five lines were written with `eprintln!`: an unknown parameter and a non-UTF-8 `config=` value in `config`, a missing `config=` in `config_complete`, a failed startup, and a failed shutdown in `unload`. `eprintln!` panics when the write fails (a log pipe whose reader has gone, a full log file); each call sits inside a panic boundary, so nbdkit was not aborted, but the boundary set EIO and logged a caught panic in place of the reason, and in `unload` the panic skipped the `tracing` event after the line. `cargo doc --workspace` warned "output filename collision at doc/maki_witness/index.html": the `maki-witness` binary and the `maki_witness` library document into the same directory, so the binary's page could replace the library's. SPEC §7 listed none of the six remote-volume commands. | `maki-witness` reads `args_os` and refuses an argument that is not UTF-8 with "maki-witness: command-line arguments must be valid UTF-8" and status 2, as `maki` does; paths in other encodings are not accepted, because the state directory and the certificates are also named in configuration files, which are UTF-8. The other binaries already refuse such an argument with 2 or accept it as a path (the `maki volume inspect`, `maki-check`, `maki-attach --config` and `maki-benchmark` configuration paths). The plugin's five lines go through a `diagnostic!` macro, like the binaries', which drops a line stderr cannot take; the text is unchanged and nothing moves to `tracing`, because `config` runs before the subscriber is installed and scripts match the plain `maki-nbdkit: startup failed:` line. Every library crate except the test-support crate now denies `clippy::print_stdout` and `clippy::print_stderr` outside its tests, as the binaries do since AUD-122. The `maki-witness` binary target sets `doc = false`. SPEC §7 lists the remote-volume commands and says what each does, that they reach the witness directly rather than through the control socket, that all but `witness` need Linux, and which approval `takeover`, `restore` and `resume-enrollment` take. | `an_argument_that_is_not_utf8_is_refused_with_status_2` (bins/maki-witness `review_misuse_status.rs`, which exited 101 before) and `an_argument_that_is_not_utf8_exits_2` (bins/maki, passing before and after); `refusals_reach_an_unread_stderr_without_a_panic` (`crates/maki-nbdkit/src/plugin.rs`: the four refusals in a copy of the test binary whose stderr is a pipe with its read end closed; four panics before); `scripts/test_doc_output_validation.py`: `test_workspace_targets_document_into_distinct_directories` (failed on the collision), `test_a_binary_named_like_another_packages_library_collides`, `test_a_binary_named_like_its_own_library_is_not_documented`. The `unload` line was not executed: a failing shutdown needs a running native attach | [#363](https://github.com/seo-rii/maki/pull/363) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-145 | Three groups of tests depended on the machine they ran on. The rollback fixtures took `/dev/shm` as the second filesystem a local witness needs: 36 fixtures in 20 files failed where `/dev/shm` does not exist (80 tests across maki-backing, maki-core, maki-nbdkit, maki-benchmark and `maki`) and, with `TMPDIR` on `/dev/shm`, with "rollback witness must be outside the backing tree on a different filesystem" (69 tests). The socket fixtures of maki-control, maki-nbdkit, `maki` and maki-format bind or configure their sockets below `TMPDIR`, and a socket path holds at most 107 bytes on Linux: with a 100-byte `TMPDIR` 63 tests failed, and some tests that expect an error passed only because of that one, the missing socket of `review_misuse_status.rs` (AUD-137) among them. The campaign entry points of `cgroup-validation.py`, `gcp-reset-validation.py` and `storage-repeat-validation.py` set the process umask to `0077` and left it there; thirteen tests call them in-process, so in CI's single discover run every later Python test ran under `0077`. These are the two environment dependencies AUD-132 left, and one more. | `tests/support/other_filesystem.rs` (five identical copies, in maki-backing, maki-core, maki-nbdkit, maki-benchmark and `maki`) makes a `0700` witness directory in the first of `/dev/shm`, `/run/user/<uid>`, `/var/tmp`, `/tmp`, `TMPDIR` and `/run` whose `st_dev` differs from the backing tree's; where none qualifies, the test prints that it is skipped and lists each candidate and why it was refused. A skipped test passes, and a run that does not show passing tests' output would not show why, so `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1` makes the helper panic with the same reason instead: the CI workflow sets it for every job, `scripts/run_root_tests.py` passes it on, and the background runner's `rollback` profile sets it for its suites. `tests/support/short_dir.rs` (maki-control, maki-nbdkit, `maki`, maki-format) makes a `0700` directory in the shortest of `TMPDIR`, `/tmp` and `/var/tmp` for every fixture that binds or configures a socket. The three Python test classes save the umask in `setUp` and restore it at cleanup. A review before the merge found that the guides promised a skip notice in the background runner's logs, which never show passing tests' output, so the `rollback` profile would have passed without a second filesystem where it used to fail; the variable addresses that, and the docs say that the profile fails. Test code, the CI environment, the background runner's suite environment and the documents that named `/dev/shm` change; production socket paths and the witness independence check do not. | `a_missing_second_filesystem_fails_only_when_one_is_required` and `every_copy_of_the_helper_is_the_same` (maki-backing `review_other_filesystem.rs`); `test_rollback_suites_fail_instead_of_skipping_without_a_second_filesystem` (`scripts/test_storage_repeat_validation.py`); `test_an_unprivileged_caller_compiles_as_itself_and_runs_each_target_through_sudo` (`scripts/test_root_tests_validation.py`) checks that the root runner passes the variable on; the pass and fail counts per crate with no `/dev/shm`, with `TMPDIR` on it and with a 100-byte `TMPDIR`, before and after, are in the pull request | [#371](https://github.com/seo-rii/maki/pull/371) |
| AUD-146 | The Windows jobs of CI (the baseline and the latest-stable matrix) ran `cargo fmt --all --check` as their first step. On Windows `cargo fmt --all` passes every target's root file to one rustfmt command line, and with the test files the 2026-11-23 pull requests added that line exceeded the Windows limit: the step failed before it checked anything ("The filename or extension is too long", os error 206), so the jobs' clippy and test steps did not run. `main`'s Windows jobs failed this way on the pushes of #369 (`31dda33`), #367 and #368; its run at #370 (`2e8bcce`) had passed. Each pull request's own run, which tests the merge with `main` as it was when the run started, passed both Windows jobs in full: those of #367 and #368 started before #369 merged, and #365, #366 and #371 were run again after this change had merged and `main` had been merged into them. | Formatting does not depend on the platform, so the step runs on Linux only (`if: runner.os == 'Linux'`, renamed `fmt (Linux)`) in both matrices: both Linux jobs still check formatting, and the Windows jobs go on to clippy and the workspace tests. The [testing guide](testing.md#run-checks-locally) says to check formatting on Windows one package at a time with `cargo fmt -p <package> --check`. CI and documentation only. This pull request's own run, of `main` at `a83ed3e` (with #363 to #370) and the change, passed both Windows jobs, clippy and the workspace tests included; its merge (`1086f81`) ended the failure on `main`. | No test pins the step's platform; the CI contract suites that read the workflow pass with it: `scripts/test_ci_gate_validation.py`, `scripts/test_ci_security_validation.py`, `scripts/test_root_tests_validation.py` and maki-nbdkit `regression_control_packaging.rs` | [#372](https://github.com/seo-rii/maki/pull/372) |

### Not closed in the fifth and sixth rounds

Each item was checked against `main` at `ff1c85f`, with all ten pull
requests merged.

- A trusted record written before the connect by an attach without
  `[lvm_identity]` pins, or one from before activation intents, names no VG
  UUID. If its device is found connected under another identity, every verb
  still refuses, and the documented manual removal is the only way out while
  the device's present user must stay up (AUD-134).
- The retirement of a displaced record (AUD-134) and the scoped LVM commands
  (AUD-135) rest on simulated kernels and, for the commands, on LVM 2.03.16
  over loop devices without device-mapper. Neither has run against a real
  kernel NBD device and device-mapper, the 2026-09-19 package campaign that
  qualified the refusal has not been repeated, and that `--devices` replaces a
  devices file and filters was observed on that LVM version, not on
  Debian 13's. `lvextend` cannot be bound to the VG UUID. An LVM command
  started by hand while a verb runs does not take the attach lock. An old
  record without proof or intent whose PV is a partition now fails detach
  with "not found" and keeps the record.
- A local `maki volume create` that stops after it has published the witness
  anchor, while it initializes the volume inside the backing (killed, or a
  capacity too small for the layout), is still refused by a later `create`
  and has no automatic continuation: if the volume was never attached, both
  directories are emptied by hand and the volume is created again (AUD-136;
  found by reading, not reproduced). *Closed by AUD-159
  ([#382](https://github.com/seo-rii/maki/pull/382)): a plain kill reproduced it,
  and `create` now continues a creation that stopped after its anchor and
  before its superblock.*
- The failed-start hook's lock wait relies on the kernel serving blocked
  `flock` requests in order, which was observed on Linux and is not
  specified by POSIX (AUD-143). The binary's glue to systemd, LVM and the
  kernel is not exercised by the tests, and the packaged-lifecycle CI fixture
  never creates an activation intent. Another volume's attach can hold the
  lock longer than the hook may wait, and a daemon that stops before the
  intent is consumed leaves the second-fault state with its manual
  `dmsetup remove`; without the unified cgroup hierarchy the hook leaves
  everything to the coordinator, and an interrupted multi-LV activation has
  no product path once the daemon has stopped (AUD-118, AUD-142).
- No transport's default trust has been shown to complete a handshake with a
  real public endpoint: the tests show that each transport's roots hold the
  compiled-in public roots. No transport can be restricted to a private CA
  alone, and nothing was run on macOS (AUD-133).
- `maki-attach recover-failed-start` exiting 3 off Linux is checked only on
  the Windows CI runner. The plugin's `unload` diagnostic, an executing
  `maki-attach` verb continuing after its plan could not be written, the
  `verify` confirmation line and the real device announcement inside a real
  attach were not executed (AUD-122, AUD-137, AUD-144).
- In background validation, a failing operating-system random source in the
  random-prefix wrapper is still `ProviderFatal` and excludes the candidate
  (AUD-140).
- Remote GC reports a failed sync of a tombstone's directory, or a failed
  removal of the directory, like an unlink failure, but no test injects
  either. Remote GC is unsupported off Linux, where it was not run, and
  nothing was built on macOS (AUD-113, AUD-138).
- The acknowledged stop after `maki drain` depends on cleanup's
  single-mapping fallback, and no campaign has run a stop after a drain on a
  VG with an additional LV; the man pages were checked at the macro level,
  not rendered with `groff` (AUD-126).
- The size of a real `lvm fullreport` for 64 logical volumes was not
  measured against the 64 KiB report bound, and layouts with internal
  mappings (thin pools, RAID) remain unqualified (AUD-121). Whether
  `nbd-client -d` can return while the kernel still shows the backend was not
  examined (AUD-120). *Answered with AUD-147 ([#375](https://github.com/seo-rii/maki/pull/375)): yes.
  In the CentOS Stream 9 source the kernel answers `NBD_CMD_DISCONNECT`,
  which `nbd-client -d` and now the helper itself send, with success, and
  the device keeps its `pid` and `backend` for as long as anything has it
  open. Detach and cleanup keep the record until the backend is gone, which
  is tested against a fake system; a detach on a real kernel that meets an
  opener has not run (the
  [seventh round's open list](#not-closed-in-the-seventh-round)).*
- The documented attach configuration examples are listed by the
  documentation guard but not parsed, because `maki-privileged` owns that
  schema (AUD-125). The key canary's plaintext derivation is described in
  `canary.rs` only; maki-core does not pin that a discard map file holds the
  allocation-map record, and the helper's runtime attach record and the wire
  protocols have no frozen vector (AUD-127, AUD-128).
- `dropping_locked_buffers_releases_their_pages` needs an allocator that keeps
  a freed 64 KiB block mapped, as glibc does; with one that unmaps it, the
  test passes on correct code but would not see a missing `munlock`
  (AUD-130).

## Internal audit, fifth round (2026-11-23): AUD-113–AUD-132

A fifth internal audit, of `main` at `e6f52d6` (after the fourth round's
thirteen pull requests), was organised by angle rather than by subsystem.
Seven reviewers compared the configuration guide, the operator guides and
manual pages, and SPEC with the code; looked at how the fourth round's changes
interact on the merged tree; traced every step of the privileged helper and
what each failure leaves; crashed the remote administrative operations; and
examined how robust the test suite is. A crash-image replay of the remote
entry points (about 39,000 images cut from `strace` recordings, for process
death, power loss and torn writes), a model of the etcd authority, fault
sweeps of the privileged helper (4,588 cases: faults at every attach,
teardown and grow step, double faults, daemon deaths and the actions of a
foreign actor) and repeated parallel runs of the test suite found no lost
acknowledged write, no accepted rollback, no stranded enrolled volume and no
helper command that touched a foreign object; what they found besides is
below. Seventeen pull requests,
[#346](https://github.com/seo-rii/maki/pull/346) to
[#362](https://github.com/seo-rii/maki/pull/362), were merged into `main` on
2026-11-23. #346 recorded the fourth round (the next section). #350, #351 and
#353 to #358 fix code (AUD-113 to AUD-123), #347, #348, #349 and #359 correct
documentation (AUD-124 to AUD-127), and #352 and #360 to #362 fix tests and
CI (AUD-128 to AUD-132). AUD-117 closes an item of the fourth round's open
list. Every code fix landed test-first, and every documentation statement
was checked against the code named with it. All rows are **Fixed**. Apart
from AUD-121 and the documentation and test rows, each row changes documented
behaviour and says how. No change alters the on-disk format or an existing
golden vector; AUD-128 adds vectors for the formats that had none. What this
round left and the sixth round did not close is listed at the end of the
[sixth round](#sixth-round-follow-ups-2026-11-23-aud-133aud-146).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy, `cargo fmt --check` and the documentation link checker, with
fails-before runs of the test commits and mutation checks. #350 and #351 also
ran maki-crypto's two phase 5 gates, and #357 and #358 a crash-image replay
of the remote entry points against their branches. A tree that merged all
seventeen branches passed formatting, the link checker, strict Clippy, the
workspace tests as root and the Python suites before the merges. Review
changed two of them: #348's manual page once #356 had merged, and #357's
root-run test fixture and its entry in #360's list. CI passed on each pull
request, which for #356 includes the packaged-lifecycle job's new marker
check on a disposable systemd host and for #360 the first run of the
root-only step. Otherwise these are repository tests over simulated kernels,
crash models, fake endpoints, private mount namespaces and local files; no
kernel NBD/LVM/XFS stack, systemd failed start, real nbdkit, vendor endpoint
or physical power loss was exercised.

### Remote rollback and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-113 | Remote namespace GC ended a pass at the first stale namespace it could not open or examine. While examining a candidate, `gc_retire` treated only a missing entry, a symlink, a non-directory and invalid contents as "unrecognized, keep and go on" and returned any other error, which stopped `collect_within`. Entries are visited in name order, which is fence order, so every namespace with a higher fence than the bad one stayed on disk, each with a full arena (twice the capacity plus two manifest slots). The automatic pass after each attach, takeover and restore discarded the error without a log line, so every command kept succeeding while the backing filled, and `maki volume gc` printed only "Permission denied (os error 13)" without naming an entry. Two ways there were reproduced. A `maki volume takeover` run as root that dies between `mkdirat` and `fchown` of the new namespace leaves an empty root-owned `0700` directory, the documented leftover of an interrupted root run (AUD-111); the rerun completes, and from then on every pass of the daemon user failed on that directory with EACCES: after three attaches five namespaces remained instead of two. And, with no root and no crash, a stale namespace holding a directory named `rollback.arena` failed with EISDIR. | Retirement has two phases. The first opens and checks one candidate and changes nothing: the collision check against its tombstone or original name, the directory, its mount and identity, its listing, each file and the lifetime lock. An error there concerns that candidate only, so the pass keeps the namespace, records it under a new `skipped_unreadable` list of `{"name", "error"}` objects with the step that failed and the system error (`opening the namespace directory: Permission denied (os error 13)`) and a `counts.skipped_unreadable` total, and goes on. A lock file that cannot be opened or tried is such an error, never a free lock, so a tombstone whose lock cannot be opened keeps its files. Everything that leaves a pass unable to tell what may be deleted, or to delete it durably, still ends it, and the error names the namespace: an unavailable, invalid or changed authority; a root whose marker, current generation, binding, listing or mount identity cannot be read; and any failure once the retirement of a candidate has begun. Which namespaces are retained (current, pending, restore source, equal or higher fence), the lifetime-lock rule and the tombstone-before-unlink order are unchanged. The automatic pass logs through `tracing`, a new dependency of maki-backing: one `WARN` with the error when the pass did not complete, or naming the first namespace it could not examine and how many there were. A review before the merge made the root-run test build its fixture with the `shared_dir` helper, since a `TMPDIR` private to root failed it, and added its target to `ROOT_TARGETS` (AUD-129). **Behaviour change:** `maki volume gc` exits 0 and lists such an entry under `skipped_unreadable` where it failed, and its JSON report has one more array and one more `counts` field. Unreadable entries are a list of their own because, unlike an unrecognized entry, which GC never removes, a later pass retires one once it can be examined, and the operator needs the error to act. AUD-138 later let the retirement steps that change only one tombstone continue as well ([retire old writer namespaces](remote-witness-service.md#retire-old-writer-namespaces)). | maki-backing `review_remote_gc_unreadable.rs`: `gc_reclaims_past_a_namespace_it_may_not_open` (mode `0000`, with the capabilities that let root ignore modes cleared on the test's thread), `gc_reclaims_past_a_namespace_holding_a_directory_named_like_its_arena`, `a_retired_namespace_whose_lock_cannot_be_opened_keeps_its_files`, `gc_as_the_daemon_reclaims_past_the_namespace_a_killed_root_takeover_left` (a root takeover in a child that a seccomp filter kills at its first `fchown`, a rerun and three attaches as uid 65534; needs root), all four failing before, the control `control_gc_refuses_a_root_whose_current_namespace_it_cannot_open`, and `the_automatic_pass_logs_the_namespaces_it_could_not_examine`, `the_automatic_pass_logs_why_it_did_not_complete`; `gc_reports_a_namespace_it_cannot_examine_and_reclaims_the_rest` (`bins/maki` `remote_admin.rs`) | [#357](https://github.com/seo-rii/maki/pull/357) |
| AUD-114 | A remote `maki volume create` created `rollback.format`, the format marker, and then wrote it. Killed between the two, cut by a power loss that kept the name but not the data, or failing the write (a full disk, a quota, an I/O error), it left an empty or torn marker with the authority still at fence 0. `volume create` then refused the root ("remote enrollment requires an empty backing") and `volume resume-enrollment` refused it too ("not a remote rollback backing"). Nothing was lost, because a creation claims its authority only after the marker and the binding are durable, but no command and no guide continued it. In the audit's crash-image replay these cuts, and those inside the binding step that follows, which had a documented manual exit, were the only violations. | The marker is written and synced as `rollback.format.next`, renamed to `rollback.format` and the directory synced, so the published name never holds an empty or torn marker. A failed write or sync removes the staged file again, and one that a kill or a power loss leaves is truncated and written again through a new descriptor by the next attempt, never synced as it is. `volume create`, and a snapshot, which initializes its target the same way, accepts a root that holds only what a creation leaves before its marker is published: the two root locks, the staged marker and a `rollback.format` that is empty or a torn copy of the marker (each byte the marker's or zero), which older binaries left. A complete marker is still refused by `create` and continued by `resume-enrollment`; an unwritten marker beside a namespace, a tombstone, a binding or any other entry, and a marker that is not a torn copy, are refused and left as found. *Superseded in part by AUD-172 ([#387](https://github.com/seo-rii/maki/pull/387)): a root that holds a staged binding, or the published binding of this very creation, and no complete marker is continued by `create`.* `resume-enrollment` on such a root under a released authority says to create the volume again; under a claimed authority a root without a marker is not an interrupted creation and keeps its refusal. **Behaviour change:** `volume create` completes a root that holds a staged or unwritten marker and nothing else, where it refused every root holding more than the two lock files. For rollback protection such a root is an empty directory: it holds no namespace, tombstone or binding, so no volume data and nothing that names a volume, and no authority has accepted anything in it. `create` still requires an authority that never activated, so no enrolled volume can be created over, and the marker carries no identity. The binding was still written in place; AUD-139 changed that ([resume interrupted initial enrollment](rollback-protection.md#resume-interrupted-initial-enrollment)). | maki-backing `review_interrupted_enrollment.rs`: `create_killed_before_the_marker_is_written_can_be_completed` (a real `create_remote` in a child process that a seccomp filter kills at its first file write), `create_whose_marker_write_failed_can_be_retried` (every file write refused by a zero file-size limit), `create_completes_a_root_whose_marker_was_created_and_never_written`, `snapshot_reuses_a_target_whose_marker_was_never_written` (the four failed before), `create_completes_a_root_that_holds_only_a_staged_marker`, `enrollment_recovery_sends_an_unpublished_root_back_to_creation`, controls `control_a_published_marker_is_continued_by_enrollment_recovery_only`, `control_create_refuses_an_unwritten_marker_that_is_not_alone_and_a_foreign_marker` and `control_an_unwritten_binding_is_quarantined_before_enrollment_recovery_continues`; the crash model `crates/maki-backing/src/rollback/remote_creation_tests.rs` (`a_creation_killed_at_any_operation_can_be_continued`, `a_creation_cut_by_a_power_loss_at_any_operation_can_be_continued`, `a_creation_whose_operation_failed_can_be_retried`, `a_marker_whose_sync_failed_is_written_again_before_it_is_published`); `volume_create_whose_marker_write_failed_can_be_run_again` (`bins/maki` `remote_admin.rs`) | [#358](https://github.com/seo-rii/maki/pull/358) |
| AUD-115 | `maki-witness init` created an empty `remote.state` on purpose, synced it, and then wrote `remote.next` and renamed it over the placeholder. Failing or dying after the placeholder, it left a directory for which `init` answered "remote witness already enrolled" and `serve` "invalid remote witness length", while the service guide warns never to delete or reinitialize an authority and gave no procedure. | `init` no longer creates the placeholder. It publishes the first record like every later one (`remote.next` written and synced, renamed to `remote.state`, the directory synced), so an `init` that fails or is cut before the rename leaves a directory without `remote.state` and can be run again. An empty `remote.state` is still refused by `init` and by `serve` and never replaced; both now say that either an earlier initialization did not complete or the authority lost its state, and that only an authority that was never served and that no volume was enrolled with may have `remote.state` and `remote.next` removed and be initialized again. `serve` on a directory without state says that the witness is not initialized. Completing an existing empty `remote.state` was rejected: it is byte for byte what an enrolled authority whose state file was truncated looks like, and initializing that again would reset its fence to zero. This widens nothing: `init` has always accepted exactly the directories without a `remote.state` entry, and it only stops manufacturing an invalid one. What the placeholder protected is kept: an interrupted enrollment is never usable as state, since it is either absent, which `serve` refuses, or the complete initial record, which `serve` makes durable before it answers; and an authority initialized again by mistake has no current root, so attach, takeover, enrollment recovery and create all refuse a backing that holds a volume's data for it ([initialize a local authority](remote-witness-service.md#initialize-a-local-authority)). | maki-backing `review_interrupted_enrollment.rs`: `witness_init_killed_before_its_state_is_written_can_be_run_again`, `witness_init_whose_state_write_failed_can_be_run_again`, `an_empty_witness_state_is_refused_with_its_causes_and_the_way_out` (the three failed before), controls `control_an_enrolled_authority_whose_state_was_truncated_is_never_initialized_again`, `control_init_writes_over_a_staged_state_left_behind` and `control_an_authority_initialized_again_accepts_none_of_the_existing_backing`; the crash model `crates/maki-backing/src/remote_witness_init_tests.rs` (seven tests, among them `an_init_killed_at_any_operation_can_be_run_again_or_served`, `an_init_cut_by_a_power_loss_at_any_operation_can_be_run_again_or_served` and `an_enrolled_authority_is_never_initialized_again_whatever_interrupts_it`); bins/maki-witness `review_interrupted_init.rs`: `init_whose_state_write_failed_can_be_run_again`, `init_and_serve_refuse_an_empty_state_file_and_say_what_to_do` | [#358](https://github.com/seo-rii/maki/pull/358) |

### Remote providers

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-116 | An endpoint that was unreachable at attach is quarantined and validated in the background against a validated peer, and since AUD-110 only proof that it serves another contract excludes it for the life of the set. One class of reply was still turned into such a proof: a request refused without an integrity verdict, a `NonRetryableRequest` that is not `Integrity`. The HTTP transport makes one of every generic 4xx (400, 409, 413, 421, 425, 431, or 422 without the `maki-crypto-error` header), WebSocket of a `bad-request` reply and gRPC of `InvalidArgument`, `NotFound`, `OutOfRange` or a bare `FailedPrecondition`. The checks validation runs were written for attach and fold such a reply into a `ProviderFatal` verdict: the self-test when it answers a negative probe ("the capability is not proven"), and the cross-endpoint check when it answers either decrypt of the other peer's ciphertext ("endpoints are not interchangeable"). The validated reference's own refusal was folded the same way, since only its `Contract`, `ProviderFatal` and `UnsupportedContext` errors were relabelled (BUG-068), and so was a validation RPC that the set's own byte budget refused before sending it. One such reply, a proxy's 421 during the first validation after an outage for example, kept a healthy endpoint out until the daemon restarted, and the volume ran on one endpoint with no further validation attempt. No data was at risk. | `ValidationProvider`, the view of one endpoint that only background validation hands to those checks, relabels a refusal without an integrity verdict as retryable before the checks see it, whichever peer sent it, and routes the set's own admission refusal of a validation RPC the same way. The attempt is then inconclusive: the endpoint stays quarantined, serves nothing and is validated again after `validation_interval` with the existing doubling backoff. `Integrity` is kept from both peers: it is the reply a negative probe must get, and for a decrypt of the other peer's ciphertext it is the evidence of another key, also when the validated reference refuses the candidate's ciphertext with it. A wrong plaintext, a foreign compatibility id, a claimed capability not honoured and the candidate's explicit refusal of the volume's context stay verdicts. Attach does not use the view: its verdicts keep their class and text, and a generic refusal of a negative probe or of the peer's ciphertext still refuses the attach. The daemon's canary check already treated only `Integrity` as conclusive. **Behaviour change:** an endpoint that answers background validation with a generic refusal stays quarantined and is validated again every `circuit_breaker.open_initial`, doubling to `open_max` (30 s by default), with a warning per attempt, instead of being marked `rejected: true` after the first such reply. One that always answers so (a provider that returns a plain 400 for tampered ciphertext, or one that holds another key and reports that as a plain 400) is never admitted, as before, but is now probed for as long as the daemon runs, like an endpoint that stays unreachable. The reasoning is AUD-110's: such a reply shows that one exchange failed, the transports themselves refuse to infer integrity from it, and the permanent exclusion protected no data (SPEC §34, [endpoint validation](configuration.md#websocket-and-grpc-contracts)). | maki-crypto `review_endpoint_revalidation.rs` (ManualClock, fake endpoints): `one_generic_request_refusal_defers_the_endpoint_until_it_revalidates` (five cases: the candidate refuses a context probe, the tamper probe or the decrypt of the reference's ciphertext; the reference refuses the decrypt of the candidate's, with and without the candidate's self-test first) and `a_validation_rpc_over_the_admission_limit_only_defers_the_endpoint`, both failing before; controls `a_failure_of_the_validated_reference_never_excludes_the_candidate` (the BUG-068 relabelling, which no test covered), `at_attach_a_generic_request_refusal_still_refuses_with_a_verdict` and the extended `proof_of_another_contract_excludes_the_endpoint_for_the_life_of_the_set`; maki-nbdkit `review_endpoint_identity.rs`: `a_generic_refusal_defers_a_recovered_endpoint_until_it_validates` (one HTTP 421 to the tamper probe or to either cross-endpoint decrypt, over the HTTP wire contract; failing before) and the control `attach_still_refuses_an_endpoint_after_a_generic_refusal` | [#350](https://github.com/seo-rii/maki/pull/350) |
| AUD-117 | `EndpointSet::with_plaintext_size` binds a set to one plaintext size, as the daemon binds its set to the volume's provider unit (BUG-058), and the set then refuses a whole call when one unit has another size. Its `capabilities()` still listed every size its endpoints have in common: BUG-058 had deliberately preserved "the advertised capability intersection", and two tests pinned that a bound set reports what an unbound one does. Since AUD-099 the batch scheduler admits each unit against the sizes the layer below reports. With endpoints that declare 256 and 128 bytes and a set bound to 256, a 128-byte encrypt was therefore admitted, coalesced with a healthy 256-byte request, and the set refused the call: the healthy request failed with "plaintext unit exceeds the common endpoint contract" although no RPC was made (with a provider that is not retry-safe, a rejected batch is never re-sent request by request). The fourth round's open list recorded this from reading. The daemon cannot reach it: the engine sends only units of `crypto_unit_size`, and with a random prefix the wrapper above the set declares only the logical size. | A bound set's capabilities list the bound size alone. The reported contract is what the set serves: the common contract of its endpoints, less what its own RPC byte budget and its binding refuse. Batch limits, the maximum ciphertext size, the security claims and retry safety are unchanged and remain the intersection over every configured endpoint, quarantined ones included (R3-004); an unbound set reports every common size as before. The scheduler needed no change, and the 128-byte request is now refused alone at admission. Every other caller only asks whether the size it uses is listed, and that is the bound one. Making the scheduler require its own unit size instead was rejected: the set would keep advertising a contract it does not honour to every other caller, and the scheduler would refuse sizes that an unbound set serves. **Behaviour change:** for a provider profile that declares `[512, 4096]` the daemon's set reports `[512]`, and with a random prefix a profile that declares `[512 + prefix, 4096]` reports `[512 + prefix]`. What BUG-058 protected is kept: the report is still derived from every endpoint and never from one, so a batch built against it fits whichever endpoint it is routed to, and binding changes no limit or security claim. CLAUDE.md's R3-004 note says what a bound set reports. | `a_unit_the_stack_refuses_before_sending_fails_alone` (maki-crypto `review_scheduler_local_refusal.rs`, with a new stack whose endpoint also declares half the unit; failing before) and the control `a_set_not_bound_to_one_size_serves_every_common_size`; `a_bound_set_reports_only_the_plaintext_size_it_serves` and the rewritten BUG-058 test `selected_unit_splits_decrypt_logically_even_with_expanded_ciphertext` (`review_pinned_endpoint_unit.rs`); maki-nbdkit `review_endpoint_volume_unit.rs` (`multiple_supported_sizes_use_the_selected_unit_at_attach_and_runtime`, `selected_provider_unit_includes_the_random_prefix`) | [#351](https://github.com/seo-rii/maki/pull/351) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-118 | An attach helper that dies between `vgchange --activate y` taking effect and the mapping proof (the unit's `TimeoutStartSec=180` expires, and it also counts the time queued on the global attach lock; the OOM killer; `systemctl kill`) leaves a trusted record that holds only the pre-activation intent, with the VG's mapping active and unmounted. The intent's only cleanup is a device-scoped `vgchange --activate n`, for which LVM reads the volume group from the NBD device. The packaged failed-start path could not provide that: the `ExecStopPost` hook only queued `maki-recover@`, whose `Conflicts=`/`After=maki@` stop the daemon before `maki-attach cleanup` runs. LVM then cannot read the PV, the `dmsetup` fallback refuses a record without the completed mapping proof, and a restarted daemon does not take over the old kernel connection. Every recovery attempt failed until the start limit, the next attach refused with "recorded device is still connected", and the volume stayed down until someone removed the mapping by hand, which the guide told operators not to do. The refusal ("scoped LVM rollback failed; rolled back 0 step(s)", or "earlier detach steps have not completed") said neither what was left nor why. | On the evidence it already required (a failed `ExecStart` and the original start job still running) the hook queues the coordinator as before and then calls `exec::finish_interrupted_activation`. That acts only on a record that holds an activation intent and whose device still carries the recorded backend identifier, and takes the connected-detach path without its unmount step: verify the intent against the live kernel state, scoped deactivation, verified disconnect, retire the record. This is the rollback the dead helper would have run. Every other record is left to the coordinator, which stops the registered workloads first. The daemon keeps serving meanwhile, because the coordinator's stop job for `maki@` is ordered after the attach unit's stop job, which cannot finish before `ExecStopPost` does. Two bounds kept the hook inside `TimeoutStopSec=120` and the coordinator's `JobTimeoutSec=360`: it waits up to 15 s until it is the only process in the attach unit's control group, read from the unified hierarchy (a `vgchange` that defers signals can outlive the helper there), and does nothing if the group does not settle or cannot be read; the rollback then had 30 s (`TrustedState::lock_until`, and `command::finish_by` for every command). Letting cleanup remove the intent's mapping with `dmsetup remove` once LVM cannot read the PV was rejected: it would extend direct device-mapper mutation to a state identified only by LVM metadata read before activation, when ordering the existing LVM path before the daemon stop covers the failure. What remains is a double fault, the daemon stopping before the intent is consumed. That stays a refusal, which now says what it is (`scoped LVM deactivation of the interrupted activation on /dev/nbdN failed (...)` or `... left its mapping active`, then "LVM reads the volume group from that device and can deactivate the mapping only while the volume's daemon serves it; keeping the attach record"), and the [operations guide](operations.md#interrupted-activation-after-the-daemon-stopped) gives the manual step. After a zero exit the mapping is observed again, because a `--select` that cannot read the PV may match no volume group and succeed. **Behaviour change:** `maki-attach recover-failed-start` changes storage in this one case (scoped VG deactivation, NBD disconnect and record removal under the attach lock, never an unmount) and reads `/etc/maki/attach/<volume>.toml` for it, like `cleanup`; `--config` is still refused and `--plan` prints one more line. The hook can take longer when it has an intent to roll back or leftover processes to wait for, and the refusal text for an intent whose scoped deactivation fails or has no effect changed for `cleanup`, `detach` and the hook. AUD-142 and AUD-143 later changed the order of its checks and its lock wait. | `crates/maki-privileged/src/review_step_faults.rs` (the production executor, observers, allocation and trusted state over a simulated kernel in which LVM needs the device served and `dmsetup` and `nbd-client -d` do not; every command of attach, detach, cleanup and the hook's rollback exits nonzero, is killed by a signal, times out or loses its helper, before and after its effect, every observation fails or loses its helper, and the packaged order must converge with everything live named by the trusted record): `an_attach_killed_in_the_activation_window_is_recovered_by_the_packaged_units`, `a_failed_attach_start_converges_through_the_packaged_recovery`, `a_faulted_rollback_in_the_failed_start_hook_leaves_cleanup_to_the_coordinator`, `an_interrupted_activation_nothing_serves_stays_refused_until_the_mapping_is_removed` (the four failed before), `a_faulted_teardown_converges_when_cleanup_is_retried`, `the_failed_start_hook_touches_only_an_interrupted_activation`; `the_failed_start_rollback_has_no_unmount_to_run`, `the_failed_start_rollback_queues_for_the_attach_lock_only_with_an_intent` (`recover_tests.rs`); `a_bounded_lock_attempt_gives_up_at_its_deadline` (`state_tests.rs`); `a_callers_deadline_ends_a_command_before_its_own_timeout` (`command_tests.rs`); `failed_start_plan_finishes_an_interrupted_activation_before_the_daemon_stops` (bins/maki-attach `review_failed_start.rs`, failing before); `only_the_attach_units_own_unified_control_group_is_inspected`, `a_control_group_is_settled_only_when_this_hook_is_alone_in_it` (`bins/maki-attach/src/failed_start.rs`); the packaged-lifecycle fixture's marker after the real hook, which refuses a daemon stop before the end of the attach unit's stop phase (`test_daemon_outlives_the_attach_units_stop_phase`, `test_stop_phase_marker_follows_the_real_hook` in `scripts/test_systemd_lifecycle_validation.py`) | [#356](https://github.com/seo-rii/maki/pull/356) |
| AUD-119 | Cleanup's `dmsetup` fallback for a record with a completed mapping proof is documented in three places to run only after an exited `vgchange -an` returns nonzero. The step runner reports a command terminated by a signal as a failed step without an exit status, and the fallback matched any failed step, so a `vgchange` killed by the OOM killer or by a crash went straight to direct removal. | The fallback requires an exit status other than zero, as documented: a nonzero exit is LVM's own refusal, while a killed LVM said nothing and may have stopped halfway. A signal-killed `vgchange` keeps the record, as a timeout does, and the next cleanup runs LVM again. **Behaviour change:** a `vgchange -an` terminated by a signal no longer leads to `dmsetup remove` in the same cleanup run. | `cleanup_does_not_fallback_when_lvm_was_killed_by_a_signal` (`crates/maki-privileged/src/recover_tests.rs`, failing before: cleanup removed the mapping directly and returned success); `a_step_killed_by_a_signal_reports_no_exit_status` (`exec_tests.rs`, the real step runner on a child that kills itself) | [#356](https://github.com/seo-rii/maki/pull/356) |
| AUD-120 | A trusted attach record (`/run/maki-attach/<volume>.nbd`) is published before `nbd-client` connects and retired after the disconnect, so it can outlive its kernel connection: the helper is killed between publishing the record and connecting, or between `nbd-client -d` and removing the record, or the removal fails. The record then names a device that shows no backend, holder or mount. Automatic NBD allocation read only sysfs and the mount table, never the other volumes' records, so the next auto-allocating attach of another volume was handed that device. From then on every verb of the first volume found a connection it does not own on its recorded device and refused: cleanup ("recorded NBD device has a foreign backend; refusing cleanup", so `maki-recover@` failed too), recover, detach and attach ("recorded device is still connected"). The first volume could not start until the second was detached or root deleted the record by hand. | Under the attach lock, which `execute`, `recover` and `cleanup` hold from before their first read to their return and under which every record is written and removed, attach reads every record before it chooses a device. Automatic allocation leaves out a device that another volume's record names, and the device an attach is about to connect, pinned or allocated, is checked against the same records again, so a pinned `nbd_device` that another volume's record names is refused with a message naming that volume and its cleanup. The volume's own record is not a reservation against itself. Both killed-helper windows end in the same state, a record whose device has no backend, which every verb of the recorded volume already handled and which is now pinned beside a running second volume: attach replaces the record, and cleanup, recover and detach retire it without running a command. A `<volume>.nbd` entry that cannot be read as a trusted record (wrong owner or mode, a symlink or directory, invalid content, a record stored under another volume's name, a name no volume can have) refuses the attach and names the file, because leaving it out would hand out the device it may name; the lock file and the temporary name a killed write leaves are not records. The executor asks its system seam through a provided `allocate_excluding`. **Behaviour change:** an attach is refused while any `<volume>.nbd` entry cannot be read as a trusted record; a pinned `nbd_device` that another volume's record names is refused even when the device is free in sysfs; a record without a connection holds its device number until that volume's next attach, cleanup, detach or recover, or until `/run` is cleared, and if every device is connected, in use or recorded, attach fails with the "no free /dev/nbdN device" error, whose text now mentions records; a plan that needs a device but connects none is refused (no verb builds one); and the refusals for a recorded device under another identity share one message that names the device, the volume and the way out. Such a record was still refused by every verb and kept, because sysfs shows what holds a device but not under which connection it was set up; AUD-134 later retires one that names its VG UUID (SPEC §8, [privileged helper](operations.md#privileged-helper)). | `crates/maki-privileged/src/review_stale_attach_record.rs` (the production executor, allocation, backend probe, observers, mapping checks and trusted state for two volumes over one simulated kernel; a killed helper is a panic at a command boundary): `a_record_published_before_a_killed_connect_keeps_its_device`, `a_record_left_by_a_killed_cleanup_keeps_its_device`, `every_verb_of_the_recorded_volume_converges_beside_the_other_volume`, `a_chooser_that_sees_only_the_kernel_cannot_take_a_recorded_device`, `a_pinned_device_named_by_another_volumes_record_is_refused`, `a_record_that_cannot_be_read_refuses_every_attach_and_is_named`, `a_plan_that_does_not_connect_cannot_allocate_a_device`, `a_recorded_device_under_another_identity_is_refused_with_the_way_out` (all eight failed before) and the control `entries_that_are_not_other_volumes_records_reserve_nothing`; `devices_named_by_trusted_records_are_not_free` (`allocation_tests.rs`); `recorded_devices_of_other_volumes_are_listed_by_device`, `an_unreadable_record_fails_the_listing_and_is_named` (`state_tests.rs`) | [#354](https://github.com/seo-rii/maki/pull/354) |
| AUD-121 | LVM preflight admits up to 64 candidate devices (the NBD device and its partitions) and a volume group of up to 64 logical volumes, and attach then activates all of them, but the kernel inventory behind the post-activation mapping proof held at most 64 nodes, devices and mappings together. A 64-LV volume group therefore passed every check before activation, was activated and failed proof capture with "recovery topology exceeds the supported bound"; attach rolled back and did the same on every attempt until the start limit, and with p partitions on the device the real limit was 63 − p logical volumes. Cleanup of a pre-activation intent takes the same inventory, so an interrupted 64-LV activation could not be cleaned up by the helper either. The existing 64-LV test used the trait-default proof capture, which records no proof. | The inventory holds what preflight admits, `MAX_DEVICES + MAX_LVS` = 128 nodes: the 64 candidate devices plus one mapping per logical volume, which is what activation can leave behind verified (the mapping check accepts a mapping only under the exact device-mapper name of a reported LV, and the kernel keeps those names unique). The bound on one node's holders or slaves stays 64. Lowering preflight to what a 64-node proof holds was rejected: the supported size would have dropped to 63 LVs on a whole-device PV, below the 64 that the tests call supported and that this log records as the recovery limit. The preflight refusal of a 65th LV, which already happened before anything was activated, now names the limit. The largest admitted topology encodes to 62,014 bytes, within the 256 KiB record limit; an earlier helper reads a record with more than 64 proof nodes but refuses to observe that topology, as before. [Storage recovery](storage-recovery.md#checking-lvm-before-activation) states both limits. | `supported_lvm_inventory_sizes_persist_activation_intent_and_attach` and `hidden_lvm_names_persist_activation_intent_and_attach` (`crates/maki-privileged/src/exec_tests.rs`, whose fixture now creates one kernel mapping per reported LV and runs the production mapping verification, proof capture and recovery observers), `oversized_lvm_inventory_is_rejected_before_activation`; `the_largest_inventory_preflight_admits_is_proven_and_recorded`, `an_interrupted_64_lv_activation_is_recovered_from_its_intent` (`recover_tests.rs`); all five failed before | [#355](https://github.com/seo-rii/maki/pull/355) |

### Command line

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-122 | The five command-line binaries printed with `println!` and `eprintln!`, which panic when the write fails, so a command whose output could not be written exited 101 with a Rust panic message instead of its own status. With a stdout reader that had gone, `set -o pipefail; maki check "$cfg" --deep \| grep -q 'deep check verdict: clean'` failed on a clean volume, and so did `maki --help \| head -1`, `--version`, `check`, `volume inspect`, `volume witness`, both `maki-check` reports, every `maki-attach --plan` preview, `maki-witness --help`, `fingerprint` and `inspect`, and `maki-benchmark --help`. A `maki volume takeover` that had already moved the fence looked like a crash, and `maki-witness serve` started with a stdout nobody reads died on its listening line before serving. A full destination panicked the same way. With a stderr nobody reads every diagnostic did too, so misuse (2), the `maki attach` instruction (3) and every reported error (1) became 101. Inside an executing `maki-attach` verb, its logging sink reported an event it could not write with `eprintln!`, so the helper panicked at the first step it logged, and the executor announced an automatically allocated NBD device with `println!` after loading the NBD module and before connecting. | Every stdout and stderr writer of `maki`, `maki-check`, `maki-attach`, `maki-witness` and `maki-benchmark` follows the rule that the control commands, `volume create`, `maki-witness init` and the benchmark report already had. A closed stdout (EPIPE) is not a failure: the command prints nothing more and exits with its own verdict, so a clean check exits 0 and a failed one 1. Any other failure to write stdout is reported on stderr; a command whose output is its result then exits 1 (help, version, `volume inspect`, `volume witness`, `check` in both binaries, a `--plan` preview, `maki-witness` help, version, fingerprint, inspect and the listening line), and the check names the verdict ("check passed, but writing the report failed"). A command that completed a change before it reports (`volume gc`, `snapshot`, `takeover`, `restore`, `resume-enrollment`, `maki-attach verify`) only warns and keeps its status, as `volume create` does, and an executing `maki-attach` verb prints its plan as an audit copy whose failed write never decides whether storage is attached, detached or cleaned up. A diagnostic that stderr cannot take is dropped and the status stands. The `maki-attach` logging sink drops an event it cannot write, and the device announcement is a method of the executor's system interface whose real implementation ignores a failed write. The five binaries deny `clippy::print_stdout` and `clippy::print_stderr`. **Behaviour change:** commands that exited 101 on an unwritable stdout or stderr exit with the status above; nothing that succeeded before fails now. | `review_closed_output.rs` in `bins/maki` (`a_clean_check_stays_clean_when_the_stdout_reader_has_gone`, `a_failed_check_still_fails_when_the_stdout_reader_has_gone`, `a_report_that_cannot_be_written_fails_the_command_and_names_the_verdict`, `help_and_version_succeed_when_the_stdout_reader_has_gone`, `diagnostics_nobody_reads_do_not_replace_the_exit_status`, `a_log_event_nobody_reads_does_not_stop_the_command`), `bins/maki-check` (`the_verdict_survives_a_stdout_reader_that_has_gone`), `bins/maki-attach` (`plans_succeed_when_the_stdout_reader_has_gone`, `a_plan_that_cannot_be_written_fails_the_preview`, `a_log_event_nobody_reads_does_not_stop_the_helper`), `bins/maki-witness` (`a_service_nobody_listens_to_still_serves_and_can_be_inspected`, `a_fingerprint_nobody_reads_is_not_an_error`, `a_result_that_cannot_be_written_is_an_error`) and `bins/maki-benchmark` (`help_that_cannot_be_written_fails`), with a pipe whose read end is closed before the child starts and `/dev/full` for the other write failure; `a_closed_stdout_fails_neither_an_inspection_nor_a_completed_takeover`, `an_unwritable_record_fails_an_inspection_but_not_a_completed_takeover` (`bins/maki` `remote_admin.rs`); `events_nobody_reads_are_dropped_without_a_panic` (`crates/maki-privileged/src/logging.rs`); `an_attach_that_allocates_its_device_survives_an_unread_stdout` (`exec_tests.rs`) | [#353](https://github.com/seo-rii/maki/pull/353) |
| AUD-123 | Four smaller defects in the same output. `maki-attach --help`, `-h` and `--version` were usage errors (status 2, `unknown command "--help"`), `maki-witness --version` printed the usage as an error (status 1) and `maki-benchmark --version` was an unknown option, although `maki` and `maki-check` answer both. `maki --help` listed `maki attach\|detach\|grow` as "delegated to maki-attach (privileged)", while `maki` only prints the `maki-attach` command and exits 3. `maki-attach grow --add-bytes <n>` was refused as `unsupported argument "--add-bytes"`, because argument validation ran before the branch that explains the removed option. And the rejections of `security.madv_dontdump` without `disable_core_dump` and of `cache.lock_memory` with `security.memory_lock_mode = "off"` held a line break followed by seventeen spaces, an escaped newline where a string continuation was meant. | `maki-attach` answers `--help`, `-h` and `help` (usage on stdout, status 0) and `--version` and `-V` (`maki-attach <package version>`); `maki-witness` and `maki-benchmark` gain `--version` and `-V` in the same form. As in `maki`, each is honoured only as the sole argument and before anything else: `maki-attach` answers before it validates arguments, so no configuration, lock or attachment state is touched, and `maki-attach attach --help` is still an unsupported argument. The `maki` usage line for the helper verbs reads "not run here: prints the privileged maki-attach command to run (exit 3)". `maki-attach grow --add-bytes` is refused during validation with the explanation the unreachable branch carried ("relative growth is unsupported; use --size-bytes with the absolute desired LV size and reuse it on retry"), still with status 2 before any configuration is read. The two validation messages are one line each. **Behaviour change:** those help and version forms exit 0 instead of 2 or 1, and the three usage texts gain a `--help \| --version` line. | `review_cli_help.rs` in `bins/maki-attach` (`help_is_printed_to_stdout_and_succeeds`, `version_names_the_package_version`, `help_and_version_are_honoured_only_as_the_sole_argument`, control `misuse_still_exits_two_with_usage_on_stderr`), `bins/maki-witness` (`help_names_the_version_option_and_goes_to_stdout`) and `bins/maki-benchmark` (`version_with_another_argument_is_still_a_usage_error`); `usage_says_the_helper_verbs_only_print_the_command_to_run` (bins/maki `review_helper_cli_delegation.rs`); `relative_growth_is_refused_with_its_reason` (bins/maki-attach `review_strict_arguments.rs`); `memory_hardening_rejections_are_one_line` (maki-format `review_config.rs`, whose shared `err` helper now holds every rejection the file asserts to one line) | [#353](https://github.com/seo-rii/maki/pull/353) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-124 | SPEC and the design documents had drifted from the code. The most consequential statement was in SPEC §43, which required recovery to refuse "corruption before a valid successor record": recovery dropped that rule because unsynced records persist in any order (M-007, S-04), and §27 forbids it, so an implementer following §43 would refuse healthy crash states. SPEC §21 and the §27 flow named envelope v2 only, although `maki volume create --discard` writes v3 and recovery accepts both. §22's read classification had no discard map, said that a slot served despite a cleared allocation bit has its bit "repaired in memory", which only the open-time audit does, and cited the wrong sections. §37 stated the swap check without its condition (`security.require_secure_swap_policy`, `false` by default); §11 listed module directories that do not exist and left out the `maki-witness` crate and binary and `packaging/debian`; §7 left out `drain`. The architecture page said recovery "rebuilds the in-memory overlay" and quoted heap figures from a 2026-09-12 fixture, the testing page said the etcd gate is not scheduled and omitted `trim_power_loss_gate_full`, and the status page said raw discards are admitted below the emergency reserve. Five module comments were wrong, among them the WebSocket module's response example, which lacked the unit echo the transport requires. | Documentation and comments only. §43 classifies journal damage by the durable proof and mark and points to §27; §21 names v2 and v3 and lists the shard files, the discard maps included; §22 adds the discard map, states that the read path repairs nothing and cites §14 and §27; §37 states the condition; §11 lists the modules that exist; §7 lists `drain`. The architecture page describes recovery as validating without payload, replaying the accepted records into their slots in 1 MiB batches and starting with an empty overlay, and states the bounds the memory tests assert instead of figures; the durable-recovery page marks its volume-recovery measurements as intermediate. The testing page lists the scheduled `etcd-qualification` job and the trim gate, and the status page says that tombstones are spared only the checkpoint headroom. SPEC §10's conceptual unit, which differs from the packaged one, is left as it is. | — | [#347](https://github.com/seo-rii/maki/pull/347) |
| AUD-125 | The configuration and transport documents described behaviour the code does not have. The configuration guide gave one default TLS trust for the three remote transports, while each trusted different roots: HTTP the compiled-in public roots only, gRPC the host's trust store only (with no `ca_file` and an empty store, attach was refused), WebSocket both. A private CA in the host's store therefore authenticated a gRPC or WebSocket endpoint and was refused by HTTP. Byte sizes were said to accept values such as `4KiB`, but nine byte-valued keys are plain integers and refuse a suffix; the remote witness `timeout_ms` is an integer of milliseconds, not a duration string; validation compares the batch byte limit with the provider plaintext unit (`volume.crypto_unit_size + crypto.random_prefix_bytes`), not with one crypto unit; `cache.lock_memory` and `cache.zeroize_on_evict` were presented as selecting the locking and erasure of cache entries, which neither does; the reclamation guide said that a failed punch leaves the cursor and that a stalled scan is not rerun, both stale since BUG-184; `maki_crypto_latency_seconds` exports no `_max`; and the key-rotation guide said writable recovery requires v2. Only the SPEC §57 example and one packaged example were checked by a test. | Each statement was corrected against the code; the TLS text described the three behaviours, which AUD-133 later replaced with one. `crates/maki-format/tests/review_docs_config_examples.rs` walks README.md, SPEC.md, docs/ (without the dated reports), examples/ and packaging/. Every complete volume configuration must pass `parse_config` and `validate` as written, and every other `toml` block that holds sections of one is merged into the quick-start example and must load too. Blocks of another schema are listed, and an unlisted or unparseable block, a listed block that is gone, a new example file of unknown schema and a complete configuration outside a `toml` block fail. A second test pins the nine integer-only keys and requires the configuration guide to name exactly these. | `documented_volume_configurations_load`, `byte_keys_documented_as_plain_integers_refuse_a_size_string` (maki-format `review_docs_config_examples.rs`; the second failed before) | [#349](https://github.com/seo-rii/maki/pull/349) |
| AUD-126 | Eight statements of the operator guides and the packaged manual pages did not match the code or the packaging. The guides presented the stop after `maki drain` (unmount, drain, stop the lifecycle target) as deactivating the VG like any other stop. A drained daemon refuses every read, so the plain `vgchange -an` fails, an explicit `maki-attach detach` after a drain stops there with the record kept, and only cleanup's single-mapping `dmsetup` fallback finishes a single-LV attachment, which a VG with an additional LV defeats. The rollback guide's backup step 2 gave a stop order that contradicts the key-rotation procedure it cites. The PostgreSQL guide's `pg_createcluster` fails beside the default `main` cluster the Debian package creates, and its next step would then register the unit of that default cluster, whose data directory is on the host filesystem. "Command-line flags override individual values" overstated which `maki-attach` flags exist and which verbs take them. `maki-attach(8)`, `maki(8)` and `maki-check(8)` omitted options or misdescribed them, and CONTRIBUTING.md said the Unix-only suites are skipped on macOS. | Documentation and manual pages only. The guides name a drained daemon next to a dead one, say that the acknowledged stop depends on the single-mapping fallback, and detach a VG with an additional LV or an internal mapping with `maki-attach detach` before `maki drain`. The backup step gives the runbook's order (unmount, drain acknowledgement, target stop, wait for every unit to become inactive). The PostgreSQL guide checks `pg_lsclusters` first and says how to avoid or drop an empty default cluster. The override sentence lists the seven overrides and the verbs that refuse them. `maki-attach(8)` documents every action and option and, after AUD-118 merged, that `recover-failed-start` reads the default attach file; `maki(8)` documents `--timeout`; `maki-check(8)` says that no `--journal-segment-size` changes the verdict. The helper's behaviour after a drain was checked with throwaway tests on the recovery fixture. | — | [#348](https://github.com/seo-rii/maki/pull/348) |
| AUD-127 | Two things an implementer needs were written down nowhere. A provider that declares integrity passes the attach tamper probe only by answering with `maki-crypto-error: auth-tag-mismatch` or `context-mismatch` on HTTP 422 or gRPC `FailedPrecondition`, or with `error.class = "integrity"` and one of those reasons over WebSocket. SPEC §18 named only the two `unsupported-*` tokens and the configuration guide none, so a provider written from the documents could not know what to answer, and any other refusal ends the attach with "the capability is not proven". And SPEC gave a field layout for the durable proof alone, with no byte order and no bit order for the allocation bitmap. Smaller: §43 called slot headers and journal record headers "versioned", although their magic is their only format identifier; §7 listed `maki attach`, `detach` and `grow` without saying that they only print the helper command, and omitted `checkpoint` and `drain`; the testing page omitted the nightly release build's refusal of `provider = "fake"`; the key-rotation guide gave a campaign's stop order wrongly; the space-reclamation status paragraph contradicted the status page; CLAUDE.md called the privileged-executor and process-hardening suites Unix-only; eight rustdoc links were broken. | SPEC §18, a new [provider error signals](configuration.md#provider-error-signals) section of the configuration guide, the gRPC proto example and the three transports' module docs give the tokens and each transport's complete classification table, what a negative probe accepts at attach and what the cross-endpoint check makes of a refusal. SPEC §14, §21 to §23, §26 and §27 give every record's byte layout (unsigned little-endian integers, a UUID's 16 bytes in text order, a trailing CRC-32 over the preceding bytes, the prefix every A/B record shares, the bitmap least significant bit first), checked by assembling each record by hand and comparing its CRC-32 with the frozen vectors, AUD-128's included. The smaller statements are corrected and the eight links fixed. AUD-141 later scoped the framing sentence of the tables. | — | [#359](https://github.com/seo-rii/maki/pull/359) |

### Tests and CI

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-128 | SPEC §43 says the on-disk records use encodings "with frozen golden vectors", and CLAUDE.md and CONTRIBUTING.md say a failing `tests/golden/*.crc` is how a developer learns that compatibility broke, but `crates/maki-format/tests/golden/` froze six encodings. Nothing froze the allocation map (`MAKIALC1`, which is also the v3 discard map), the shard catalog, the checkpoint state, the durable proof, the journal segment header or the v2 and v3 superblock envelopes. Every test of those codecs goes through the same `encode` and `decode`, so a changed magic, version, field order or byte order passed the whole maki-format suite while making every existing volume unreadable. `journal_record_v1.crc` hashes a whole self-checksummed record, so its value depends on the payload alone, and the v1 superblock fixture has equal device block and crypto unit sizes, so swapping those fields went unnoticed. The rollback-protected backing's vectors came from an empty manifest and the initial witness state, so a reordered field of a nested record broke every populated manifest with the suite passing. | Test only. `crates/maki-format/tests/review_golden_vectors.rs` adds eight vectors, `allocation_map_v1.crc`, `shard_catalog_v1.crc`, `checkpoint_state_v1.crc`, `durable_proof_v1.crc`, `segment_header_v1.crc`, `journal_record_header_v1.crc` (over the 28 header bytes before the header's CRC), `superblock_v2.crc` and `superblock_v3.crc`, each the CRC-32 of the image without its trailing self-checksum, and writes each expected image out byte by byte from the documented layout, from fixtures with a distinct value in every field; the decoder must read the hand-assembled bytes back. An inventory test fails for a record magic without a vector and for a vector no record accounts for. Three maki-backing tests compare the encoders with literals for a populated manifest, a witness state with a descriptor, and the local marker with a manifest slot. The values were computed independently with Python's `zlib.crc32` before the tests first ran. In the mutation runs, at least one change per record (its magic, version, a byte order or a field order) passed all 297 earlier maki-format tests and fails the new ones. No production code, format or existing vector changed. | maki-format `review_golden_vectors.rs`: `allocation_map_golden_vector_frozen`, `shard_catalog_golden_vector_frozen`, `checkpoint_state_golden_vector_frozen`, `durable_proof_golden_vector_frozen`, `segment_header_golden_vector_frozen`, `journal_record_header_golden_vector_frozen`, `superblock_envelope_v2_and_v3_golden_vectors_frozen`, `every_record_magic_has_a_frozen_vector`; `populated_manifest_has_a_fixed_vector`, `local_marker_and_manifest_slot_have_fixed_encodings` (`crates/maki-backing/src/rollback.rs`), `active_state_has_a_fixed_golden_vector` (`crates/maki-backing/src/remote_witness.rs`) | [#352](https://github.com/seo-rii/maki/pull/352) |
| AUD-129 | About 35 regression tests give a fixture to another user, run a binary as the daemon user, enter a private mount namespace or set the immutable flag, and five more do so for half of what they check; without root each prints why it is skipped and reports `ok`. Every CI job ran cargo as the unprivileged runner user, so in CI these tests asserted nothing: with the "owned by another user" refusal disabled at its five sites, or with AUD-111's root-created entries left root-owned, every suite still passed unprivileged, while as root 12 and 11 tests fail. Also, `python3 -B -m unittest discover -s scripts` wrote `scripts/__pycache__` into the checkout, because four suites start child interpreters without `-B`, and the script test modules ran only because 24 of 28 match the discovery pattern and the other four are named. | The Linux baseline job runs `python3 -B scripts/run_root_tests.py --open-build-tree --workspace --locked` after the workspace tests. The script reuses that compilation as the runner user and starts only the test executables in its `ROOT_TARGETS` list as root through `sudo -n`, each with a scratch `TMPDIR` that other users can search. It fails when root is not available (nothing is compiled or skipped), when a test that ran as root still reports that it needs root, and when the run leaves an entry owned by root in the checkout or the build tree, and it repeats every other skip notice at the end. `--open-build-tree` lets uid 65534 reach the built binaries below a `0750` home directory for the duration of the run. That root is expected is enforced by the step, not by an environment variable read at some 45 sites in the tests. `scripts/test_root_tests_validation.py` keeps the list complete: it scans test sources for the ways a test probes its privilege (`geteuid`, a "needs root" notice, `chown`, `unshare`, `id -u`) and fails for such a source that is neither listed nor classified as not needing root, for a listed target that is gone or no longer probes, and for a missing or reworded workflow step. The three `python -O -c` children get `-B`, a check after the job's last Python step fails when `scripts/__pycache__` exists, and `scripts/test_ci_gate_validation.py` requires every `scripts/test_*.py` to be run by the job. AUD-113 added its root-gated target to the list, and AUD-136 maki-backing's unit tests (`crates/maki-backing/src/lib.rs`). CI, scripts and documentation only. | `scripts/test_root_tests_validation.py` (with stand-in cargo, sudo and test executables): `test_every_source_that_probes_its_privilege_is_classified`, `test_listed_targets_and_classifications_still_exist`, `test_without_root_nothing_is_compiled_or_run`, `test_skip_notices_are_listed_and_one_that_blames_root_fails_the_run`, `test_entries_left_owned_by_root_fail_the_run`, `test_a_build_tree_closed_to_other_users_is_refused_or_opened_for_the_run`; `test_the_pull_request_job_runs_every_script_test_module` and `test_bytecode_gate_follows_the_suites_and_rejects_a_cache_directory` (`scripts/test_ci_gate_validation.py`); `test_fixture_interpreters_write_no_bytecode_next_to_the_wrapper` (`scripts/test_privileged_nbd_ownership_validation.py`) | [#360](https://github.com/seo-rii/maki/pull/360) |
| AUD-130 | Three tests passed without reaching what they check. The six tests of `check_mount_target` (maki-privileged `regression_mount_target.rs`) first asked the function under test whether their own fixture location was acceptable and returned when it was not, so in a build tree whose scratch directory is group-writable (one made under `umask 002`) all six passed without an assertion, also with the symlink refusal removed. Their fixed `target/tmp/mount-target-<name>` directories were never removed, so an unprivileged run after a root run failed six of six with EPERM, and two concurrent runs deleted each other's trees. `dropping_locked_buffers_releases_their_pages` (maki-crypto `review_secret.rs`) relied on a 1 MiB `RLIMIT_MEMLOCK`, which does not bind a privileged process, and on the allocator handing each buffer a new range, which it does not, so it passed with `munlock` removed from `SecretBuffer`'s drop, as root and unprivileged (the fourth round's open list). `unrelated_mount_path_bytes_do_not_change_memory_budget_admission` (maki-nbdkit) compared two verdicts that, in the root of the cgroup-v2 hierarchy (a container or a CI shell), were both the membership refusal admission gives before it opens the mount table. | Test code only. Each mount-target test builds a fresh tree with explicit modes, removed when it ends, in the first of the build's scratch directory, `TMPDIR`, `XDG_RUNTIME_DIR` and `HOME` that a restatement of the rule in the test file accepts, and fails, listing why each candidate was refused, where none does; the symlink tests also assert that the directory behind the link is accepted, and the mode tests cover group-only and other-only write bits. The page-release test reads `VmLck` from `/proc/self/status`, which counts locked pages whether or not the limit binds and whatever addresses the allocator returns: eight live buffers must raise it by their size, and dropping them must return it to its start, so a `munlock` that releases only the first page of a range fails it too. The path-bytes test joins a scratch cgroup-v2 group (`tests/support/scratch_cgroup.rs`, shared with `review_memory_budget_mount_table.rs`), so admission reads and parses the table, and prints that it was skipped, with the verdict, where admission still stops earlier. | `a_symlinked_mountpoint_is_refused`, `a_symlinked_ancestor_is_refused`, `an_ancestor_writable_by_others_or_owned_by_an_untrusted_uid_is_refused`, `a_mountpoint_owned_or_writable_by_others_is_refused` and the new `the_fixture_tree_is_trusted_and_removed` (maki-privileged `regression_mount_target.rs`); `dropping_locked_buffers_releases_their_pages` (maki-crypto `review_secret.rs`); `unrelated_mount_path_bytes_do_not_change_memory_budget_admission` (maki-nbdkit `review_memory_budget_mountinfo.rs`); each now fails with the protected code removed, where it passed before | [#361](https://github.com/seo-rii/maki/pull/361) |
| AUD-131 | `recovery_rejects_oversized_segment_before_allocation` (maki-core `review_storage.rs`) arms no failpoint and did not hold `failpoints::test_lock()`, but its write passes `journal.append.write` and `journal.sync`, which three tests of the same binary arm for exactly one hit. Run between an arming test's `fail_n_times` and that test's own write, it consumed the failure, panicked on it and left the arming test's assertion false (9 of 3,000 runs of the binary under load). `phase3_gate_full` had the same gap and failed at once under `--include-ignored`. And the testing page says that on a host without nbdkit the native cases report that they were skipped, but eighteen did not: the twelve start-up and six crash tests share a probe cached in a `OnceLock` whose initializer printed the notice, so only the first caller in each binary carried it, and the native trim and block-size negotiation tests re-execute themselves and dropped the child's standard error, which holds its notice. | Both maki-core tests take the failpoint lock; a scan of every test binary that arms a failpoint found three more files with an unlocked test, none of which can reach a failpoint its binary arms. Every native test that cannot run prints the notice in its own output, and the two self-re-executing tests forward their child's standard error. Test code only. | `recovery_rejects_oversized_segment_before_allocation` (`review_storage.rs`: no failure in 6,000 runs of the binary under the same load) and `phase3_gate_full` (`phase3.rs`, 17 of 17 under `--include-ignored --test-threads=16`); the native notices in maki-nbdkit `review_r3_native_startup.rs`, `review_r3_native_crash.rs`, `review_discard.rs` and `review_nbd_limits.rs` | [#361](https://github.com/seo-rii/maki/pull/361) |
| AUD-132 | Three groups of tests failed, or passed for the wrong reason, because of the environment they ran in. Under `umask 002`, the default for ordinary users with a private group on Debian and Ubuntu, 81 tests failed as root and 77 as an unprivileged user while CI, at `umask 022`, was green: `tempfile::tempdir()` made the remote witness state directory `0775`, which `StateStore::create` refuses (69 tests of maki-backing, three of maki-core, four of maki-nbdkit), and `std::fs::write` made the witness server configuration `0664`, which `maki-witness serve` refuses. As root with a `TMPDIR` private to that user (pam_tmpdir's `/tmp/user/0`, a `mktemp -d` directory), five root-only tests failed with EACCES, because nobody else can search down to a `0755` directory below it. On a host whose trust store is empty or unreadable, five maki-crypto-grpc tests failed with "invalid TLS configuration": they built their provider with `GrpcTlsConfig::default()`, which then trusted the host's roots and nothing else. | Test code only: the fixtures state what they need, through helpers pulled in with `#[path]`. `tests/support/private_dir.rs` (maki-backing, maki-core, maki-nbdkit) makes a `0700` directory and `tests/support/witness_config.rs` (the witness CLI) writes a configuration `0644`, both with `set_permissions`, which the umask does not touch. `tests/support/shared_dir.rs` (the witness CLI, `maki`, `maki-check`) makes a `0755` directory in the first of `TMPDIR`, `/tmp` and `/var/tmp` that every user may search down from `/`, and the affected cases print why they are skipped where none qualifies. The five gRPC tests configure a test CA. Three assertions that passed under `umask 002` for the wrong reason, a mode refusal in place of the check under test, now reach their check. The fixtures' dependence on `/dev/shm` and on a short `TMPDIR` was left (AUD-145). | the helpers above, and the pass and fail counts per crate under `umask 022` and `002`, as root and as uid 65534, with a `0700` `TMPDIR` and without host roots, before and after, in the pull request | [#362](https://github.com/seo-rii/maki/pull/362) |

## Internal audit, fourth round (2026-11-23): AUD-098–AUD-112

A fourth internal audit, of `main` at `4b21e47`, read the 143 pull requests
merged since the third round
([#190](https://github.com/seo-rii/maki/pull/190) to
[#332](https://github.com/seo-rii/maki/pull/332)) and covered storage and
recovery (with randomized crash, linearizability and media-damage sweeps),
crypto dispatch, secret handling and the plaintext cache, configuration and
the privileged helper, rollback protection and the witness, and the release
scripts and documentation. The storage sweeps and the rollback and witness
review found no defect; that review did not cover remote mode under a power
loss of the volume host, a process death inside the administrative
operations, or the etcd and failover code. Thirteen pull requests,
[#333](https://github.com/seo-rii/maki/pull/333) to
[#345](https://github.com/seo-rii/maki/pull/345), were merged into `main` on
2026-11-23. #333 to #338 fix the audit's eight findings (AUD-098 to AUD-105).
#339 to #344 change design decisions that earlier sections record as
deliberate or list as open (AUD-106 to AUD-111); each row states the earlier
behaviour, what replaced it and what is kept of what the earlier decision
protected. #345 adds tests for the preserve-first A/B store rule, which the
audit's planted-bug runs showed the randomized sweeps barely guard (AUD-112).
Two recorded decisions were examined again and kept: recovery's refusal of
exhausted counters (AUD-056) and `serve` not exiting when its store is
poisoned (AUD-092). Every code fix landed test-first: its commit message and
pull request name the regression that failed before the change. AUD-104
corrects documentation and AUD-112 is test only; all rows are **Fixed**.
AUD-103 and AUD-106 to AUD-111 change documented behaviour. No change alters
the on-disk format or the golden vectors. The operator-visible changes are
listed in the [changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy, `cargo fmt --check` and the documentation link checker, and
most report mutation checks: the new tests fail when the fix is removed or
weakened. #338 also ran maki-core's eight ignored release gates one at a time
in debug, and #342 and #343 the two maki-crypto phase 5 gates. Review and
follow-up work before the merges changed five of the pull requests; the rows
record how (AUD-102, AUD-103, AUD-106, AUD-109 and AUD-111). These are
repository tests with fake endpoints, a manual clock, private mount
namespaces and local files; no kernel NBD/LVM/XFS stack, systemd unit, real
nbdkit, vendor endpoint, candidate release build, nbd-client backport build
or physical power loss was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-098 | Since `FileBacking::list` stopped converting names lossily ([#236](https://github.com/seo-rii/maki/pull/236)), it fails with `InvalidData` at the first entry whose name is not UTF-8. Three scans that look only for the volume's own file names, which are all ASCII, called it: opening the slot store (`data/`), recovery's journal scan (`journal/`) and the fast check (`data/`). One such file in either directory of a plain `FileBacking` volume (`data/caf\xe9.bak` left by a restore from another system or by an editor) made every attach of that volume fail and left `maki check` and `maki check --deep` inconclusive. Before #236 the converted name matched no shard or segment name and was ignored. Rollback-protected volumes keep their own manifest namespace and were not affected. The same class as AUD-040, AUD-078 and AUD-082. | `Backing` gains `list_skipping_non_utf8`, which leaves out names that are not UTF-8 and returns every other name exactly. Its default calls `list`, which is exact for `MemBacking`, `CrashableBacking` and the rollback manifest namespace, whose names are all UTF-8; `FileBacking` overrides it, on Linux through the byte-name visitor that now serves both listings. The three scans use it and still act only on names that parse as a shard or segment. Callers that must account for every entry keep `list` and still refuse such a name: volume creation's check that the layout directories are empty and the empty-root checks of local and remote rollback enrollment. Neither listing converts a name lossily, so a listed name always opens the entry it was read from. No scan reports such an entry, as neither check reports other unknown names. | maki-core `review_non_utf8_entries.rs`: `attach_skips_non_utf8_names_in_the_data_directory`, `checks_skip_non_utf8_names_in_the_data_directory`, `attach_skips_non_utf8_names_in_the_journal_directory`, `checks_skip_non_utf8_names_in_the_journal_directory`, control `control_ascii_names_that_are_not_volume_files_are_ignored`; maki-format `review_non_utf8_entries.rs`: `fast_check_skips_non_utf8_names_and_still_finds_an_uncataloged_shard`, control `control_creation_still_refuses_a_non_utf8_entry_in_a_layout_directory`; maki-backing `review_list_non_utf8.rs`: `skipping_listing_returns_each_utf8_name_exactly_and_no_other`, control `rollback_enrollment_still_refuses_a_root_holding_a_non_utf8_entry`; the namespace parity table covers the new method for both in-memory backings and Linux `FileBacking` | [#338](https://github.com/seo-rii/maki/pull/338) |

### Remote providers and secrets

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-099 | `EndpointSet` and the random-prefix wrapper check every unit of a call before the first RPC and refuse the whole call for one unit they cannot carry: an empty ciphertext, a ciphertext above the declared maximum, or plaintext of a size the contract does not accept or above its batch byte limit. The batch scheduler checked a decrypt request only against the maximum ciphertext size and an encrypt request not at all, so such a request joined a coalesced batch. With a provider that is not retry-safe a rejected batch is never re-sent request by request (R5-004), so the refusal reached every caller of the batch although nothing had been sent. On a volume, a slot whose CRC-valid header records an empty ciphertext (a v2 zero-length record, AUD-062, or damaged media) made every healthy read coalesced with it fail with EIO. | Both scheduler lanes apply the per-unit checks at admission, against the inner provider's declared contract: a decrypt unit must be 1 to `max_ciphertext_size` bytes, an encrypt unit a supported plaintext size within the batch byte limit. A request that fails them is refused alone, as `NonRetryableRequest`, before it is queued or charged, and never joins a batch. A rejection the provider returns after a batch may have been sent still reaches every request of the batch when the provider is not retry-safe, and errors raised before any RPC are not marked as not sent. The storage layer still serves a zero-length v2 slot as ciphertext (AUD-062); its read still fails, now alone. | `a_unit_the_stack_refuses_before_sending_fails_alone` (maki-crypto `review_scheduler_local_refusal.rs`: twelve cases through the endpoint set, an endpoint declaring a size above its batch byte limit and the random-prefix wrapper, nine of which failed before) and the control `a_rejection_after_sending_still_reaches_every_coalesced_request`; `a_healthy_read_coalesced_with_an_empty_slot_still_succeeds` (maki-core `review_coalesced_empty_slot.rs`) | [#334](https://github.com/seo-rii/maki/pull/334) |
| AUD-100 | Before an encrypt result is accepted, `CheckedProvider` (the engine's pinned provider, the random-prefix layers, each `EndpointSet` endpoint and the self-test) searches it for its own plaintext (BUG-105). The search was KMP, and its failure table, one machine word per plaintext byte (32 KiB for a 4 KiB unit), lived in an ordinary vector: not page-locked under `memory_lock_mode = "secure-buffers"` and freed without erasure. The table is a pure function of the unit's plaintext. For a unit whose bytes take two values (an allocation bitmap, a 0x00/0xFF block) the freed table alone reconstructs the plaintext; for other data it records which positions repeat earlier ones. This contradicted the transport-memory guide, which says that no unlocked copy of the plaintext exists during local encryption. | The search is Crochemore-Perrin two-way string matching. It needs only a critical factorization of the unit, keeps a few positions in registers or on the stack and allocates nothing. It stays linear in the worst case (at most 2n + 5m byte comparisons for an n-byte result and an m-byte unit), which is what the KMP search was introduced for, and accepts and refuses the same results. Keeping KMP with a guarded table was rejected: it would add a page-locked allocation, its erasure and two system calls to every check. Stack and register state during the search stays outside the page-lock claim, as it does for the ciphers ([transport memory](transport-memory.md#local-providers-and-key-material)). | maki-crypto `review_plaintext_scan_memory.rs`: `checking_an_encrypt_result_frees_no_unerased_scan_state`, `an_accepted_encrypt_result_is_checked_without_heap_allocation`, `checked_provider_frees_no_unerased_scan_state`; unit tests in `crates/maki-crypto/src/checked.rs`, held to the comparison bound: `search_matches_slice_windows_over_three_letters_exhaustively`, `search_matches_slice_windows_for_periodic_and_planted_needles`, `adversarial_near_matches_have_linear_comparison_cost` | [#335](https://github.com/seo-rii/maki/pull/335) |

### Privileged helper and daemon admission

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-101 | Linux prints a mount whose source string is empty as an empty field in `/proc/self/mountinfo`: `- tmpfs  rw,mode=755`, with two spaces before the super options; `mount -t tmpfs '' /dir` creates one. The privileged helper's shared field splitter and the daemon's memory-budget parser split records on spaces and dropped empty fields, so such a record had two filesystem fields where both required three. One such mount anywhere in the namespace then failed, for every volume, NBD allocation and with it every attach ("incomplete mount inventory during NBD allocation"); detach, cleanup, attach rollback, recovery, grow, LVM preflight and the workload `verify` gate ("incomplete mountinfo observation"); and the start of a memory-budgeted daemon ("malformed mountinfo fields"). The post-mount verifier did not fail but read the super options as the mount's source. AUD-040 and AUD-082 had fixed only how these parsers treat path bytes. | Both parsers split a record by field position, as the kernel's `show_mountinfo` writes it. Before the separator field (a single `-`), single spaces separate at least six fields, none of them empty; after it come exactly three, the filesystem type, the source and the super options, which run to the end of the record, and only the source may be empty. The helper's callers (allocation, the detach, rollback, recovery, grow and LVM-preflight observation, the recovery mount check and the verify gate) read named fields from one shared `probe::mount_record`. Still refused: a missing separator or filesystem field, an empty type, empty super options, and an empty field before the separator, which is newly refused because the old splitter skipped a doubled space there and the kernel writes none. | maki-privileged `review_mountinfo_empty_source.rs`: `an_empty_mount_source_is_an_empty_field`, `records_with_another_empty_field_are_not_mounts`, and `review_empty_source_mounts_do_not_block_privileged_observation` in a private mount namespace (needs root; skips with the reason otherwise); inline `review_auto_allocation_reads_empty_mount_sources_as_empty_fields`, `empty_mount_sources_keep_detach_observation_exact`, `empty_mount_sources_keep_recovery_and_gate_checks_exact` and their refusal controls; `empty_mount_sources_are_empty_fields`, `records_with_other_empty_fields_still_refuse` (`crates/maki-nbdkit/src/security/memory.rs`); `empty_source_mounts_do_not_change_memory_budget_admission` (maki-nbdkit `review_memory_budget_mount_table.rs`, a private mount namespace and cgroup) | [#337](https://github.com/seo-rii/maki/pull/337) |
| AUD-102 | Memory-budget admission read the whole mount table with a fixed 1 MiB bound and refused a larger one ("oversized kernel field /proc/self/mountinfo"). The table is host state with one record per mount, so a host with a few thousand mounts refused every memory-budgeted volume, while the privileged helper's NBD allocation accepts a table of up to 16 MiB and its other observations read the table without a bound. | Admission reads the table as a stream of records. Only a single record is bounded, to 1 MiB including its newline, which was the bound on the whole table, so no table accepted before is refused. A first pass checks every record and finds the cgroup-v2 mount; that record can follow a mount that shadows it, so a second pass checks every other mountpoint against it. Each pass computes a SHA-256 digest of the bytes it read and the two must agree. The recheck after the controller files are read compares a third read's digest with the first, replacing AUD-082's byte comparison, so admission still refuses a table that changes while it runs, and the table is no longer held in memory while the controller files are read. `maki-nbdkit` gains a direct dependency on `sha2`, which was already in its dependency graph. A follow-up before the merge found that the recheck (membership, the mount-table digest and `RLIMIT_MEMLOCK`, read again after the controller files) had no test: removing any of its comparisons left every test passing, as it had before this change. The reads admission makes outside the controller files now go through a small `Kernel` trait (`LiveKernel` opens, bounds and checks as before), and a test kernel changes its state once admission has checked the mount. | `large_mount_tables_do_not_change_memory_budget_admission` (maki-nbdkit `review_memory_budget_mount_table.rs`: 4096 bind mounts, a table above 1 MiB); unit tests in `crates/maki-nbdkit/src/security/memory.rs`: `the_mount_table_is_read_as_a_stream_of_bounded_records`, `every_pass_reads_and_checks_the_same_whole_table`, `recheck_refuses_membership_mount_table_and_memlock_changed_during_admission` | [#337](https://github.com/seo-rii/maki/pull/337) |

### Release tooling and documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-103 | `scripts/prepare_release.py` copied the caller's whole environment into the candidate build but recorded only `RUSTC`, the Rust flag variables, the target linker and the compiler wrappers in `manifest.json`. Release-profile overrides (`CARGO_PROFILE_RELEASE_PANIC`, `CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS`, `CARGO_PROFILE_RELEASE_OPT_LEVEL`, `CARGO_PROFILE_RELEASE_LTO`), `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*`, the C toolchain variables the aws-lc-sys and ring build scripts read (`CC`, `CFLAGS`, `AR`, `CMAKE_*`, `PKG_CONFIG_*`) and Cargo configuration files above the build directory or in `CARGO_HOME` reached `cargo build` without a trace. With `CARGO_PROFILE_RELEASE_PANIC=abort` in the operator's shell, the packaged nbdkit plugin lost the `catch_unwind` boundaries of its callbacks, adapter and start-up, so a panic would abort nbdkit instead of returning EIO, while the manifest recorded none of it. | The command refuses `CARGO_PROFILE_RELEASE_*`, `RUSTC_BOOTSTRAP`, `CARGO_UNSTABLE_*` and Cargo-internal `__CARGO_*` variables before building, and refuses a `[profile.release]` or `[unstable]` table, or a file it cannot parse, in Cargo configuration outside the committed source. It records `CARGO_INCREMENTAL`, `CARGO_BUILD_INCREMENTAL` and the native toolchain inputs of the selected target (plain, `HOST_` or `TARGET_` prefixed and per-target spellings) in `compiler_environment`, and lists every Cargo configuration file it finds outside the committed source, in Cargo's search order, with its SHA-256 in a new `cargo_configuration` field. `maki-nbdkit` no longer compiles unless panics unwind (a `compile_error!` under `cfg(not(panic = "unwind"))`), so `RUSTFLAGS="-C panic=abort"` or a committed profile cannot remove the boundary either. A review before the merge found that Cargo's configuration `include` key works on a stable toolchain and that the first version neither refused nor recorded an included file, which could carry either table; an `include` outside the committed source is now refused. **Behaviour change:** a candidate build that inherited such a variable or configuration stops before building; commit a needed profile change instead ([releasing](releasing.md#prepare-and-inspect)). Candidate builds are still not hermetic: the recorded inputs are not refused. | `scripts/test_release_preparation.py`: `test_release_profile_and_unstable_toolchain_overrides_are_refused_before_building`, `test_manifest_records_native_toolchain_inputs_of_the_selected_target`, `test_cargo_configuration_outside_the_committed_source_is_recorded_or_refused` (including a string include in the `CARGO_HOME` configuration and a table include in an ancestor's); maki-nbdkit `review_panic_strategy.rs`: `the_crate_refuses_to_build_without_unwinding_panics`, `the_guard_is_compiled_into_the_crate` | [#336](https://github.com/seo-rii/maki/pull/336) |
| AUD-104 | The Debian guide's nbd-client 3.27 backport recipe only printed the downloaded tarball's SHA-256, for comparison with the same origin; ran without errexit, so a failed `apt source`, `cd` or `uupdate` did not stop the paste; and finally installed whatever `../nbd-client_3.27.1-*_amd64.deb` existed, possibly a stale package from an earlier attempt, with the architecture hard-coded. The guide's quoted `Depends` line also omitted `systemd (>= 249)`. | Documentation, with a test of the documented recipe. The repository records no trusted digest for `nbd-3.27.1.tar.xz`, so the [guide](getting-started/installation-debian.md#nbd-client-327-or-later) requires the operator to verify the upstream OpenPGP signature with an independently confirmed release key before the first build and to export the verified digest as `NBD_TARBALL_SHA256`. The recipe runs in a subshell under `set -euo pipefail`, builds in a new `mktemp -d` directory, checks the tarball with `sha256sum --check --strict` before `uupdate`, and installs exactly the `nbd-client` package named by the rebased changelog version and `dpkg --print-architecture`, then prints its digest. The `Depends` quote matches the package builder's static list and says that the `dpkg-shlibdeps` entries follow. | `scripts/test_docs_installation_validation.py`, which runs the documented recipe against recording stubs: `test_recipe_installs_exactly_the_client_package_it_built`, `test_tarball_must_match_the_verified_digest_before_anything_is_built`, `test_a_failed_step_stops_the_recipe`, `test_guide_quotes_the_package_builder_static_depends`. *Superseded by AUD-153 ([#375](https://github.com/seo-rii/maki/pull/375)):* the recipe and its first three tests are gone; `test_no_step_of_the_guide_builds_or_installs_nbd_client` pins that no step of the guide builds or installs `nbd-client`, and the `Depends` test stays | [#336](https://github.com/seo-rii/maki/pull/336) |
| AUD-105 | `scripts/check_docs_links.py` finds block quote and list item margins on the tab-expanded line, then rebuilds the rest of the line from the raw text. When the margin ended exactly where a tab begins, or was followed by spaces and then a tab, the raw tab was kept and the indented-code test counted it as four columns, although a tab only advances to the next tab stop of the whole line, one to three columns past such a margin. A quoted line or a list item continuation indented that way was treated as indented code, so a broken link on it passed although GitHub renders it as a link. The same miscount hid a heading's anchor and missed a fence or HTML block opened after such a margin, so the lines inside it were checked as Markdown text. No document in the repository was affected. | The rebuild also expands the indentation that follows the margin with the line's tab stops, as the margin already was, and keeps literal tabs only in the body (code spans, link labels). Every later indentation test (indented code, fence and HTML block openers, headings, thematic breaks, setext underlines, table rows, reference definitions) reads the rebuilt content and sees the right columns. | `scripts/test_docs_links.py`: `test_tab_after_a_container_margin_advances_only_to_the_next_tab_stop`, `test_blocks_after_a_container_margin_ending_at_a_tab_use_its_columns`, control `test_tabs_reaching_four_columns_after_a_container_margin_start_indented_code` | [#333](https://github.com/seo-rii/maki/pull/333) |

### Design changes

| ID | Earlier behaviour | Change | Regression | PR |
|---|---|---|---|---|
| AUD-106 | SPEC §8 only recommended `/etc/maki/volumes/*.toml root:maki 0640`, and the second round's open list recorded that nothing enforced it. The daemon (`NbdAdapter::open_config` and the plugin's native start-up, which share one reader), every `maki` command that takes a configuration and `maki-benchmark` read the file with a plain `read_to_string`. A file its group or others could write, a file owned by an unrelated user, a symlink and a file with a second hard link were loaded like the operator's own, although the configuration names the provider and its endpoints, TLS trust, credential references, the backing root and the rollback witness: whoever could change the file, or substitute another under its name, could send the volume's plaintext and the referenced credentials to an endpoint of their choosing. | Every loader reads the file through one checked reader, `maki_nbdkit::config_file::read_volume_config`. On Unix it opens the path with `O_NOFOLLOW` and `O_NONBLOCK` and, on the descriptor it then reads, refuses anything but a regular file of at most 1 MiB with exactly one link, owned by root or by the process's effective user, with no group or other write permission; each refusal names the problem. Group and other read stay allowed, because the recommended `root:maki 0640` needs group read and a configuration holds credential references, never secrets. This is the witness configuration's owner and mode rule (AUD-075) with the attach configuration's single link (R5-030). Non-Unix builds check the regular file and the size bound. `maki-check` takes a backing root, not a configuration, and `maki-attach --plan` still reads any file. **Behaviour change:** the daemon fails attach, and every `maki` command and `maki-benchmark` refuse before parsing, for a configuration that is a symlink, has a second hard link, is owned by a user other than root and the loading process's user (so commands run as root refuse a file the daemon user owns), or is writable by its group or others (as one written under `umask 002` is, or one with a POSIX ACL that grants write access). The remedy is `install -m 0640 -o root -g maki`, and the [upgrade section](operations.md#upgrading-the-runtime-layout) lists the affected files with a `find` command. The directories above the file are not checked. A follow-up before the merge found that under `umask 002` the test fixtures' configurations were `0664`, so 91 tests of maki-nbdkit, `maki` and `maki-benchmark` failed there while CI, at `umask 022`, passed; the fixtures are now written through `tests/support/volume_config.rs`, which sets `0644` explicitly. | `review_volume_config_file.rs` in maki-nbdkit (`group_or_world_writable_configurations_are_refused`, `a_symlinked_configuration_is_refused`, `a_hardlinked_configuration_is_refused_under_both_names`, `a_directory_is_not_a_configuration`, `a_configuration_owned_by_another_user_is_refused`, `root_owned_and_own_configurations_still_load`, and the guard `documented_installations_produce_an_accepted_configuration` over every documented `install` of a volume configuration and the tmpfiles rule), in `bins/maki` (`group_or_world_writable_configurations_are_refused_by_every_loader`, `symlinked_and_hardlinked_configurations_are_refused_by_every_loader`, `a_configuration_owned_by_another_user_is_refused_by_every_loader`, `root_owned_and_own_configurations_still_load_in_every_loader`) and in `bins/maki-benchmark` (`untrusted_configurations_are_refused_and_own_ones_load`); unit tests `an_oversized_configuration_is_refused_before_it_is_read`, `a_fifo_is_refused_without_waiting_for_a_writer` (`crates/maki-nbdkit/src/config_file.rs`) | [#339](https://github.com/seo-rii/maki/pull/339) |
| AUD-107 | The attach self-test proves a declared context binding with one negative probe per context field (R3-006); for the compatibility id it decrypted the first test unit under `<id>.selftest-probe`. With `crypto.random_prefix_bytes` the self-test runs on the random-prefix wrapper, whose compatibility id is the volume's derived `maki-random-prefix-v1:<n>:<base>`, and the wrapper refused every other outer id itself, before any request, with `UnsupportedContext(CompatibilityId)`: exactly the field refusal the probe accepts as proof. The provider, which receives the base id on the wire, was never asked, as the [2026-10-14 open list](#open-after-this-pass) recorded. A remote provider that declares context binding but ignores the compatibility id therefore attached with a prefix, while the same provider without one was refused with "compatibility id decrypts to the original plaintext". This held for the engine's attach self-test, each endpoint's own self-test in a multi-endpoint set and background validation of quarantined endpoints. | The probe goes through a sealed `CryptoProvider` hook, `decrypt_compatibility_probe`, which receives the caller's own context and lets the layer that puts the id on the wire choose the foreign one. The wrapper checks the request as for any decrypt, translates the derived id to the base id and forwards the probe, so the inner provider is asked to decrypt under `<base id>.selftest-probe`, the probe it receives on a volume without a prefix; the reply passes the wrapper's pinned result checks before the prefix is removed. `BatchScheduler` forwards the probe under the caller's deadline and `CheckedProvider` with its result checks; providers and `EndpointSet` keep the default, an ordinary decrypt under the foreign id. The self-test judges the reply as before, and a prefixed volume's self-test sends one more decrypt than it did. **Behaviour change:** a provider that declares context binding but ignores the compatibility id is refused at attach with a prefix too. For volume I/O the wrapper still refuses, before any request, a context whose compatibility id is not its own, and the error class is still `ProviderFatal`, but the error is `CryptoError::ProviderFatal` instead of `UnsupportedContext(CompatibilityId)`: the wrapper translates the id without binding it, so its refusal is not the field evidence a provider gives, and a layer above it that does not forward the probe now fails the self-test closed instead of certifying a binding nobody exercised. SPEC §17 and §18 and the [random-prefix guide](random-plaintext-prefix.md#existing-volumes-and-endpoint-compatibility) describe the forwarded probe. | maki-crypto `review_prefix_context_probe.rs`: `a_provider_ignoring_the_compatibility_id_fails_with_and_without_the_prefix`, `a_provider_binding_the_compatibility_id_passes_with_and_without_the_prefix`, `a_providers_explicit_refusal_is_forwarded_through_the_prefix`, `a_malformed_probe_reply_is_refused_before_the_prefix_is_removed`, `the_wrappers_own_refusal_never_proves_context_binding`; maki-nbdkit `random_prefix_remote.rs`: `daemon_refuses_an_endpoint_ignoring_the_profile_with_or_without_prefix`, `daemon_probes_a_binding_endpoint_alike_with_or_without_prefix`; the pinned assertion in `rejects_bad_inputs_before_invoking_inner` (maki-crypto `random_prefix.rs`) expects the new error | [#340](https://github.com/seo-rii/maki/pull/340) |
| AUD-108 | Every lock Maki takes is a `flock(2)` lock on a lock file: the volume lock, the rollback backing, enrollment and GC operation locks, the local and remote witness locks (all through `FileBacking::try_lock` and `try_lock_shared`), the lock GC holds while it retires a namespace, the privileged helper's `attach.lock` and the control socket's directory lock. Each was released only by closing its descriptor. A `flock` lock belongs to the open file description, and a child forked by any thread holds a copy of every descriptor, close-on-exec ones included, until its `exec` closes them; every `Command::spawn` forks such a child. A lock released while one had not yet reached its `exec` stayed held for it. An immediate `Volume::recover` after `create_volume` or after a detach then failed with `AlreadyAttached` (the intermittent failure of maki-check's `deep_check_finds_slot_damage_on_a_real_volume`, whose sibling tests spawn `maki-check` processes), a closed `RollbackBacking` or remote witness store could not be reopened, the next attach-lock or socket-directory user waited for the child's `exec`, and remote GC reported a namespace no handle used any more as live. Four test files serialized lock tests around process spawns instead. A standalone probe with two threads spawning `/bin/true` found the lock still held in 5,241 to 6,946 of 20,000 re-locks after a close-only release, and in none after an explicit unlock. | Each lock guard calls `File::unlock` (`flock(fd, LOCK_UN)`) before its descriptor closes: `FileBacking`'s `FileLock`, which the GC retirement lock now also uses, the privileged helper's new `StateLock`, returned by `TrustedState::lock` and `lock_existing`, and the control socket's new `DirectoryLock`. `LOCK_UN` acts on the open file description, so the lock ends when its holder releases it, whatever children still share that description. Acquisition, the lock files and their close-on-exec descriptors are unchanged, and the in-memory, rollback and crash-model locks already released when their guard dropped. The four test-side workarounds are removed. **Behaviour change:** remote GC used to keep a namespace live after its lifetime lock was dropped, for as long as a child forked while the lock was held still had the lock's descriptor; a test pinned this with a raw `fork` child that never execs. A lifetime lock now ends when its holder drops it. The lock exists to keep a namespace while a `State` handle may still use it, no product process uses a namespace through an inherited descriptor (every child the product spawns execs), and a held lock still keeps its namespace. The [architecture page](architecture.md#backing-namespace) and a CLAUDE.md trap state the rule. | maki-backing `review_lock_release.rs`: `a_dropped_lock_is_free_while_a_forked_child_still_holds_its_descriptor`, `a_closed_rollback_backing_reopens_while_a_forked_child_holds_its_descriptors`, `a_closed_remote_witness_store_reopens_while_a_forked_child_holds_its_descriptor`; `a_detached_volume_reattaches_while_a_forked_child_holds_the_lock_descriptor` (maki-core `review_lock_release.rs`); `a_released_attach_lock_is_free_while_a_forked_child_holds_its_descriptor` (`crates/maki-privileged/src/state_tests.rs`); `a_released_socket_directory_lock_is_free_while_a_forked_child_holds_its_descriptor` (`crates/maki-control/src/uds_lock_tests.rs`); the pinned GC test, now `a_dropped_lifetime_lock_is_free_while_a_forked_child_holds_its_descriptor` (maki-backing `remote_gc.rs`), requires the namespace to be retired while the child still waits, and `retired_namespace_with_a_live_lifetime_lock_is_never_unlinked` keeps the held-lock rule | [#341](https://github.com/seo-rii/maki/pull/341) |
| AUD-109 | Under `bounded-error` the dispatcher's deadline exits did not answer the same way. At the top of a retry pass, right after a failed RPC and in endpoint admission (AUD-069) the operation returned the last endpoint error with that error's class, `throttled: HTTP 429` for example; an RPC cut off by the deadline returned the bare retryable "operation deadline exceeded" and dropped that error. The batch scheduler, which every remote volume uses, starts a caller's budget before queueing, so that budget normally runs out before the dispatcher's own, and such a caller always got the bare deadline error, whatever its endpoints had answered. `maki_crypto_deadline_exceeded_total` had matching gaps. The exit right after a failed RPC did not increment it. With batching it counted the callers whose error text was the deadline error (BUG-154): a caller that got an endpoint error when the dispatcher's deadline ended its call was missed, and a caller that got a nested endpoint set's deadline error long before its own budget ran out was counted. | All of the dispatcher's deadline exits (before the first pass, at the top of a pass, right after a failed RPC, in admission, with an RPC in flight) go through one function, which increments the counter once and returns the last endpoint error of the RPC batch in progress with its own class, or the deadline error when no endpoint failed that batch. Each scheduler caller has a dispatch observer, which reaches the provider call serving its request (the coalesced batch or a per-request re-send) through a task-local; the outermost dispatcher records its latest endpoint error and its own deadline exits there, and a caller that leaves on its own timer returns that error. The scheduler counts a caller whose own budget ran out, or whose dispatcher ended the call at its deadline, instead of matching error text. A dispatcher hides the observer from its own endpoints, so a nested set's expiry stays that peer's failure, counted by the nested set alone, as [#318](https://github.com/seo-rii/maki/pull/318) made it. A review before the merge changed two things. SPEC and the guides said the answer was the last error of the whole operation, while the dispatcher reports per RPC batch (one batch of items with its retries and failovers); the per-batch rule is now the stated and pinned one, through the scheduler as directly, because an earlier batch of a split call that failed and has since succeeded does not explain why the call is late. And what the dispatcher reported at or after a scheduler caller's deadline (a late failure, or the start of the next RPC batch, which clears the record) could still change that caller's answer, depending on which task ran first; the observer now records nothing at or after the caller's deadline. **Behaviour change:** an RPC cut off by the deadline, and a scheduler caller whose own budget ran out, return the last endpoint error that the RPC batch in progress received before the deadline, with that error's class (`Throttled`, `EndpointFatal`, or `ProviderFatal` for a contract violation while another peer remained), instead of `Retryable("operation deadline exceeded")`, which remains the answer when nothing failed that batch. Every expired operation counts exactly once, whatever it returns, and a caller whose error is a nested peer's deadline error, received before its own budget ran out, is no longer counted. An endpoint error returned through the scheduler at the caller's deadline never carries the not-sent mark. A result that arrives at or after the deadline is still discarded, and breaker and quarantine charging and the classification of each endpoint error are unchanged (SPEC §35, [metrics](operations.md#metrics-and-health)). | maki-crypto `review_deadline_exits.rs` (14 tests, among them `an_rpc_cut_off_by_the_deadline_returns_the_last_endpoint_error`, `a_deadline_right_after_a_failed_rpc_is_counted`, `scheduler_callers_leaving_at_their_deadline_return_the_last_endpoint_error`, `a_dispatcher_deadline_reaching_a_scheduler_caller_is_counted_whatever_it_returns`, `a_nested_peer_deadline_is_not_a_scheduler_callers_deadline`, and from the review `a_split_call_reports_only_the_request_in_progress`, `a_failure_after_a_scheduler_callers_deadline_is_not_its_answer`, `a_request_started_after_a_scheduler_callers_deadline_keeps_its_answer`); maki-nbdkit `review_deadline_metrics.rs`: `an_endpoint_error_at_the_callers_deadline_is_exported`, `an_endpoint_error_at_the_dispatchers_deadline_is_exported` | [#342](https://github.com/seo-rii/maki/pull/342) |
| AUD-110 | An endpoint that was unreachable at attach is quarantined and validated in the background against a validated peer (M-011). Every validation error of the `ProviderFatal` class marked it `rejected`, which is never cleared, and `Contract` (a reply that does not parse, is truncated or has the wrong shape) is in that class. The self-test also turned a malformed reply to a negative probe into a "capability is not proven" verdict, and the cross-endpoint check a malformed reply to the candidate's decrypt into "endpoints are not interchangeable". BUG-068 recorded this as deliberate: "candidate errors and actual cross-key failures remain conclusive". One bad exchange during validation (a batch reply one item short, an empty success, a proxy error page while the endpoint restarts) therefore excluded a healthy endpoint until the daemon restarted, and a volume with two endpoints stayed on one for the rest of the process. The opposite gap existed for the key canary: with an integrity-capable provider an endpoint holding another key refuses the canary with `Integrity`, which the daemon's validator passed through unchanged, so such an endpoint was deferred and validated again forever instead of rejected. | Background validation rejects an endpoint only on evidence that it serves another contract: a `ProviderFatal` verdict, which the self-test, the cross-endpoint check and the daemon's canary check reach only from definitive replies (another compatibility id, a decrypt to the wrong plaintext, a claimed capability it does not honour, or a refusal of ciphertext the other endpoint produced or attach authenticated), or an explicit `UnsupportedContext` refusal of the volume's real context. Every other failure is inconclusive: transport errors and timeouts, admission limits, `Contract` replies and the validated reference's own failures. The daemon's validator reports a candidate's `Integrity` refusal of the canary as the canary mismatch. After an inconclusive attempt the endpoint stays quarantined and is validated again after `validation_interval` (the daemon uses `circuit_breaker.open_initial`), the spacing doubling after each further inconclusive attempt up to `circuit_breaker.open_max`, measured on the set's injectable clock; it is admitted only when a later run of the same validator succeeds in full. The self-test and the cross-endpoint check return a malformed reply as `Contract`; attach still refuses such an endpoint. **Behaviour change:** a candidate's malformed reply no longer excludes it for the life of the set; a candidate that refuses the volume canary with an integrity failure is rejected instead of deferred forever; and inconclusive attempts back off to `open_max` (30 s by default) instead of repeating at the fixed interval, so a long-unreachable endpoint is probed less often and may be admitted up to `open_max` after it recovers. Kept: only validated endpoints are candidates for a request, the capability intersection covers every configured endpoint (R3-004), validation RPCs are charged like serving ones (BUG-067), and proven incompatibility is permanent. The permanent exclusion protected no data, because an endpoint with another key, compatibility id or canary cannot pass a complete validation (SPEC §34, [configuration](configuration.md#websocket-and-grpc-contracts)). *Superseded in part by AUD-116 ([#350](https://github.com/seo-rii/maki/pull/350)) and AUD-140 ([#364](https://github.com/seo-rii/maki/pull/364)):* of the refusals of the other endpoint's ciphertext, only an integrity failure shows another key. A request refused without an integrity verdict, from either peer, the set's own admission refusal of a validation RPC and a `ProviderFatal` error of the candidate's own provider are inconclusive too; attach keeps its verdicts. | maki-crypto `review_endpoint_revalidation.rs`: `one_malformed_validation_reply_defers_the_endpoint_until_it_revalidates`, `inconclusive_validations_back_off_exponentially_up_to_the_breaker_cap`, `a_flapping_endpoint_never_receives_a_request_before_it_validates`, `a_readmitted_endpoint_keeps_the_aggregate_contract`, control `proof_of_another_contract_excludes_the_endpoint_for_the_life_of_the_set`; the pinned BUG-068 tests, now `malformed_candidate_is_never_admitted_but_is_revalidated` and `different_key_candidate_is_rejected_for_the_life_of_the_set` (`review_endpoint_validation.rs`); maki-nbdkit `review_endpoint_identity.rs`: `recovered_quarantined_endpoint_whose_canary_is_refused_is_rejected`, control `a_failed_canary_exchange_defers_a_recovered_endpoint_until_it_validates` | [#343](https://github.com/seo-rii/maki/pull/343) |
| AUD-111 | An offline command run as root on a volume the daemon user owns (`maki check --deep`, `maki-check --deep`, `maki volume inspect`, and the local rollback backing and witness open they perform) takes `volume.lock`, `rollback.lock` and `witness.lock` and reserves both manifest slots. When a restore or a copy had dropped one of those files, `FileBacking` recreated it as the invoking user, `root:root 0600`, and the daemon then failed to attach with EACCES until someone ran `chown -R` (the second round's open list). The same held for every file and directory a root `maki volume create`, `takeover`, `restore` or `resume-enrollment` added to a backing root the daemon user owns, which is why those procedures carried a `chown -R maki:maki` step. Republishing the local witness anchor kept the replaced anchor's owner whatever the directory's owner was (AUD-080): a root-owned anchor stayed root's, and an anchor of a third user in the daemon's directory was published for that user. | On Linux, a process running as root creates each file and directory below a `FileBacking` root (a volume's backing root, a remote namespace, a local witness directory) for the owner, uid and gid, of the directory it creates it in, when that owner is not root. A new file is created unnamed with `O_TMPFILE`, given away with `fchown` and synced with `fsync` before it is linked under its name (with `AT_EMPTY_PATH`, or through the descriptor's `/proc/self/fd` link, since `AT_EMPTY_PATH` needs CAP_DAC_READ_SEARCH before Linux 6.10), so the name never shows a root-owned file, even after a crash. On a filesystem without unnamed files it is created under its name with `O_EXCL`, given away before anything is written and removed again if that fails. A directory is given away after `mkdirat` only while it is empty and root's, and removed again on a refused change. An entry that already exists is opened as it is and never changes owner, a non-root process creates entries as itself, and the backing root itself stays its creator's. For the witness anchor, a new `Backing::directory_owner` lets the republish compare the directory's owner with the replaced anchor's: in a directory another user owns, that user's anchor keeps its owner, a root-owned anchor is published for the directory's owner, and an anchor of a third user is refused with an error naming both uids; a root-owned directory keeps the replaced anchor's owner. A review before the merge found that the republish wrote the record into whatever file `anchor.next` named and renamed that file over the anchor: a file someone had put there, or a failed publication had left, became the anchor, a writable descriptor of it kept open could rewrite the anchor afterwards, and a root run gave such a file of a third user to the record's owner. A leftover `anchor.next` is now removed before the record is created, for every user. A file put back under that name meanwhile is opened as it is and emptied; root hands it over only when root or the record's owner owns it, and refuses one of any other user before writing or giving away anything. A root `maki volume create` warns only about the trees that hold a root-owned entry. **Behaviour change:** a root run on a daemon-owned volume leaves a daemon-owned tree, so the guides drop the hand-back after offline checks, takeover, restore and `resume-enrollment`. A hand-back is still needed for a restored copy whose files lost their owners, for a volume or witness directory root had to create itself, which the create warning names, and after a root run that a crash interrupted between creating an entry and giving it away. A root process that cannot change the owner (CAP_CHOWN dropped, for one) now fails to create the entry instead of creating a root-owned one. The witness republish gives a root-owned anchor in the daemon's directory back to the daemon user, refuses an anchor of a third user and removes a leftover `anchor.next` instead of writing the record into it. What AUD-080 protects is kept: the republish stays, the owner is changed before any byte is written and synced with `fsync` before the rename, and a refused change refuses the open (SPEC §8, [volume lifecycle](operations.md#volume-lifecycle), [rollback protection](rollback-protection.md#local-configuration-and-creation)). | maki-backing `review_root_created_ownership.rs` (needs root; skips with the reason otherwise): `root_creates_a_missing_file_for_the_owner_of_its_directory`, `root_never_gives_away_a_file_it_did_not_create`, `a_refused_owner_change_creates_nothing`, `root_without_cap_dac_read_search_still_creates_for_the_owner`, `root_reopen_recreates_missing_rollback_files_for_the_daemon`, `root_takeover_and_reopen_create_the_writer_namespace_for_the_daemon`, `root_republish_returns_a_root_owned_anchor_to_the_directory_owner`, `root_refuses_to_republish_an_anchor_its_directory_owner_does_not_own`, `root_never_publishes_a_temporary_record_another_user_put_in_the_witness`; `review_root_created_ownership.rs` in `bins/maki` (`root_deep_check_recreates_a_missing_volume_lock_for_the_daemon`, `root_inspect_and_check_recreate_missing_rollback_files_for_the_daemon`, `root_create_into_daemon_owned_directories_leaves_nothing_to_hand_back`, `root_create_names_a_volume_directory_it_had_to_create`) and in `bins/maki-check`; unit tests that also run unprivileged: `crates/maki-backing/src/creation_owner_tests.rs` (eight) and, in `crates/maki-backing/src/witness.rs`, `root_publishes_for_the_directory_owner_and_refuses_a_third_anchor_owner`, `root_publishes_for_the_anchor_or_directory_owner_it_can_trust`, `a_temporary_record_left_in_the_directory_is_never_published`, `root_hands_over_a_temporary_record_put_back_only_by_root_or_the_record_owner`, `root_hands_over_only_a_temporary_record_of_root_or_the_record_owner` | [#344](https://github.com/seo-rii/maki/pull/344) |

### Tests

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-112 | The A/B metadata store's preserve-first step (BUG-001) rewrites and syncs the exact bytes of the other typed-valid side, and syncs its directory, before it overwrites the stale side. In the audit's planted-bug runs the randomized sweeps barely caught its removal: in one of 360 runs of one engine sweep configuration and in none of the flush-crash and recovery-interrupt runs. The dedicated tests that fail without it mostly check what the step does rather than what it prevents: the tests that fail because an acknowledged generation is lost all use allocation maps, and one of them depends on a random crash. In `retry_syncs_the_readable_copy_before_a_torn_write_to_the_other_side` the torn write never takes effect, because its target sync fails and the crash drops the uncertain write. At the volume level nothing covered the checkpoint state: the volume-level retry test and BUG-022's reclaim test both pass without the step. | Test only. The store-level test runs for every A/B record type (allocation and discard maps, the shard catalog, the checkpoint state, the durable proof, the key canary and the superblock): a failed store leaves its generation readable but volatile, a restart follows, the retry targets the side that holds the last acknowledged copy, its sync fails while its write is still dirty, and a power loss tears that write and drops every unproven one; an acknowledged generation must remain. It covers both sides acknowledged, and one acknowledged side whose readable partner is a new file whose name was never synced. The volume-level test covers the checkpoint state: a checkpoint reclaims the journal it covers, the next checkpoint's state sync fails, recovery after a restart re-stores that state (BUG-022), that re-store's target sync fails and a power loss tears its write; the next recovery must attach with every FUA-acknowledged unit. Both fail with the preserve step removed and with it syncing without rewriting the preserved bytes. Eleven other durability and security rules were removed in turn (the FLUSH and FUA journal syncs, checkpointing each unit's latest durable version, recovery's rewrite before it syncs, the journal's rewrite after a failed sync, zeroed read buffers, the cache's exact sequence match, the release of admission permits on cancellation, the overlay admission bound, the deep check writing nothing); each made between 2 and 23 existing test binaries fail or hang, so no test was added for them. | `torn_retry_after_restart_keeps_an_acknowledged_copy_of_every_metadata_type` (maki-format `review_ab_retry.rs`); `torn_checkpoint_state_restore_after_restart_keeps_a_bridging_checkpoint` (maki-core `review_ab_retry.rs`) | [#345](https://github.com/seo-rii/maki/pull/345) |

### Not closed in this pass

- The privileged helper still reads the whole mount table for NBD allocation
  with a 16 MiB bound and refuses a larger one; only memory-budget admission
  reads it as a stream (AUD-102).
- An `EndpointSet` built for one plaintext size (`with_plaintext_size`, as
  the daemon builds it) still lists every size its endpoints declare in its
  capabilities, and the scheduler's encrypt admission checks a unit against
  that list. A unit of another declared size is therefore still queued, and
  the dispatcher refuses the whole coalesced call for it (AUD-099). Found by
  reading; not reproduced.
  *Closed by AUD-117 ([#351](https://github.com/seo-rii/maki/pull/351)): a
  bound set lists only the size it is bound to, so the scheduler refuses a
  unit of another size alone at admission
  (`a_unit_the_stack_refuses_before_sending_fails_alone`, maki-crypto
  `review_scheduler_local_refusal.rs`).*
- Candidate builds are not hermetic: the release command records the Rust
  flag variables, the linker, the compiler wrappers, the native toolchain
  inputs and Cargo configuration outside the source, but does not refuse
  them. The repository records no digest for the upstream
  `nbd-3.27.1.tar.xz`, so verifying its signature stays an operator step
  (AUD-103, AUD-104). *The `nbd-client` part is closed by AUD-153
  ([#375](https://github.com/seo-rii/maki/pull/375)): no documented step builds `nbd-client` any
  more.*
- The volume configuration check does not cover the directories above the
  file, and the `maki-witness` configuration loader has the owner and mode
  rule but no single-link check (AUD-106).
- A root run that a crash interrupts between creating an entry and giving it
  away (a directory, or a file on a filesystem without `O_TMPFILE`) leaves an
  empty root-owned entry, which later runs open as it is; the tree then needs
  a hand-back. The non-Linux development `FileBacking` still creates every
  entry as the running user (AUD-111). *Since AUD-113
  ([#357](https://github.com/seo-rii/maki/pull/357)) remote GC reports such
  a leftover namespace directory under `skipped_unreadable` and goes on,
  instead of ending every pass at it; it still needs a hand-back or an
  `rmdir`.*
- `dropping_locked_buffers_releases_their_pages` (maki-crypto
  `review_secret.rs`) detects leaked page locks through a 1 MiB
  `RLIMIT_MEMLOCK`, which does not limit a process with CAP_IPC_LOCK, so it
  cannot fail when the suite runs as root. *Closed by AUD-130
  ([#361](https://github.com/seo-rii/maki/pull/361)): the test reads
  `VmLck` from `/proc/self/status`, which counts locked pages whether or not
  the limit binds, and fails with `munlock` removed as root and as an
  unprivileged user.*

## Internal audit, third round (2026-11-17): AUD-091–AUD-097

A third internal audit, also of `main` at `5a65e96`, reviewed the second
round's pull requests from their branches and covered the NBD adapter and its
native shim, release-build arithmetic, engine concurrency (a linearizability
oracle, FLUSH/FUA crash sweeps and admission fairness), the operator CLI and
packaged units, and the witness service. The adapter, release-arithmetic and
concurrency reviews found no defect. Four pull requests,
[#186](https://github.com/seo-rii/maki/pull/186) to
[#189](https://github.com/seo-rii/maki/pull/189), fixed its findings and were
merged into `main` on 2026-11-17. #186 completes AUD-060. The verify gate's permission limit that
#187 adds to the privileged-helper section is recorded with AUD-086, and a
root run recreating a missing `volume.lock` is in the second round's open
list. One finding needed no change of its own: parsing the request of a
client the allow-list does not name (AUD-077) reached the patched serde_json's
error-position parsing, whose cost AUD-070 makes linear, and both are merged.
Every code fix landed test-first. AUD-096 and AUD-097 correct documentation;
all rows are **Fixed**. AUD-094 and AUD-095 refuse input that was accepted
before (a `MAKI_LOG` directive without a level, `--timeout` on a command
without a control round trip). No change alters the on-disk format.

#186, #188 and #189 report Linux debug runs, in isolated build directories, of
the changed crates' suites and the dependents that exercise the change,
strict Clippy and `cargo fmt --check`, with mutation checks; #186 also ran the
test targets it shares with #185 on a tree merged with that branch. #187
checked `systemd-analyze` (systemd 255) against the packaged units in an
offline root and ran the documentation tests. No systemd service, real
nbdkit, NFS export or WORM storage was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-091 | AUD-060's classification of an adopted shard still counted the positions of a partial last shard at or past the device's last unit, which name no unit: the store never sets them, and `allocated_units()`, `unlisted_units()` and the truncation marks already skip them (R5-027). A CRC-valid map whose only set bits lay there made a never-written short orphan truncated: with seven units, five per shard and a zero-length data file for shard 1, a map listing only its position 2 or 4 made the deep check report units 5 and 6 as damage and attach return EIO for them. | `SlotStore::open` decides whether an adopted shard's map lists a slot from its in-device positions only, the bound `allocated_units()` uses, and the truncation-marking loop shares that bound. Bits past the device's end stay in the map as found; nothing reads them. | `positions_past_the_device_end_do_not_make_a_never_finished_shard_truncated` (maki-core `review_adopted_shard_padding.rs`); the control `a_listed_unit_still_makes_a_short_orphan_truncated` now covers the partial last shard | [#186](https://github.com/seo-rii/maki/pull/186) |

### Witness and rollback protection

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-092 | A local remote-witness authority (`maki-witness serve` with `state_dir`) publishes each change by writing and syncing `remote.next`, renaming it over `remote.state` and syncing the directory, and any failure of those steps poisoned the open store. A failure before the rename (EMFILE from a flood of connections waiting for TLS, or a transient ENOSPC or EIO while opening, writing or syncing `remote.next`, during a FLUSH's Advance for example) leaves `remote.state` byte for byte as published, yet every later request, Inspect included, was answered "remote witness state uncertain; reopen required" (`Unavailable`) until the process was restarted. `serve` kept running and logged nothing, so every volume using the witness refused reads, writes and FLUSHes until an operator noticed. | Publication is split into a stage (write and sync `remote.next`) and a commit (rename and directory sync). A failed stage fails only its request: the published state and the in-memory copy still agree, nothing reads `remote.next` as state, and the next stage truncates and rewrites all of it through a new descriptor, so bytes a failed write or sync left are never synced as they are. A failed commit still poisons the store until a reopen re-publishes the state it reads, because a failed rename may have happened and a failed directory sync leaves the new name visible but not durable; opening a store still refuses any publication failure. **Not changed:** `serve` does not exit when its store is poisoned. No packaged unit runs it, and a poison also records a `remote.state` changed behind the server's back, where an automatic restart would serve whatever valid state the file then holds; the [witness service guide](remote-witness-service.md#initialize-a-local-authority) says which failures need a restart and that such a change must be investigated first. | `a_publication_failure_before_the_rename_refuses_only_that_request` (maki-backing `remote_witness.rs`: failures opening, writing a prefix of and syncing `remote.next`) and `a_reopen_after_a_failure_before_the_rename_serves_the_published_state`; the pinned test, now `an_uncertain_publication_poisons_and_reopen_resolves_exact_old_or_new`, is narrowed to failed renames and directory syncs and keeps its assertions | [#189](https://github.com/seo-rii/maki/pull/189) |
| AUD-093 | `maki volume restore` and `RollbackBacking::restore_remote` only read the snapshot, but they opened its marker, `snapshot.json`, manifests and arena read-write and took its operation lock read-write, creating the file if missing. A snapshot kept where nothing can change it (a read-only mount, immutable files, a read-only export, files the administrator may not write) therefore failed with EROFS, EPERM or EACCES before the authority was asked anything. | A new `FileBacking::read_only` view opens an existing root without creating, probing or syncing anything, opens files read-only with the same no-follow, regular-file and single-link checks. The view rejects file creation, directory creation, removal, renames, directory sync and exclusive locks with `ReadOnlyFilesystem`; restore and the command's `snapshot.json` read go through it. Restore takes the snapshot's `remote.operation.lock` shared through a read-only descriptor. Every operation that changes a root (create, open, takeover, snapshot, GC) still takes that lock exclusively, so they stay excluded while the snapshot is read, and concurrent restores may now share one snapshot. The restore target keeps every check and its exclusive lock, and everything read from the snapshot is still authenticated against the approved descriptor. | maki-backing `review_restore_read_only_source.rs`: `restore_reads_a_snapshot_it_may_not_write`, `restore_reads_a_snapshot_on_a_read_only_mount`, `restore_reads_an_immutable_snapshot` (the last two need root and skip with the reason otherwise), `restore_refuses_a_snapshot_another_operation_holds`; `restore_reads_a_snapshot_it_may_not_write` (`bins/maki` `remote_admin.rs`, the CLI) | [#189](https://github.com/seo-rii/maki/pull/189) |

### Logging and command line

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-094 | `MAKI_LOG` is documented to mean `info` when unset or invalid, but a word that is not a level (`warning`, `err`, `notice`, a typo such as `wran`) is a valid `EnvFilter` directive: that target at trace and every other target off. The fallback never ran, and the plugin, `maki`, `maki-check` and `maki-attach` dropped every event of their own, ERROR included: checkpoint and journal-sync failures, a stopped control server, a panic at the NBD boundary, a halted rollback. An empty value (`Environment=MAKI_LOG=`) built a filter that enables nothing. | Both log sinks check `MAKI_LOG` before handing it to `EnvFilter`: every comma-separated directive must be a level or end in `=<level>`, a value with no directive means `info` like an unset one, and any invalid value (no level, an unknown level, a syntax error, non-UTF-8) falls back to `info`. Installing the sink then logs one `WARN` line, "MAKI_LOG is not a valid filter", with a fixed reason and the 1-based index of the failed directive, never the value or the parser's error text, which can hold user data such as span-field selector values. `maki-privileged` carries its own copy of the check, so it still links no crypto crate. **Behaviour change:** a bare target such as `MAKI_LOG=maki_core`, which meant that target at trace and everything else off, now falls back to `info` with the warning; `maki_core=trace` selects one target. | `a_maki_log_value_without_a_level_falls_back_to_info_and_says_so`, `an_empty_maki_log_means_info_like_an_unset_one` and `invalid_filter_diagnostics_never_expose_selector_values` (unit tests in `crates/maki-core/src/logging.rs` and `crates/maki-privileged/src/logging.rs`); `a_maki_log_value_that_is_not_a_level_keeps_warnings_and_says_so` (`bins/maki` `review_log_filter.rs`) | [#188](https://github.com/seo-rii/maki/pull/188) |
| AUD-095 | `maki` removed `--timeout <seconds>` from every command line before choosing the command, so `maki volume create`, `inspect` and `witness` and `maki check` accepted the option and ignored it (`maki volume create <config> --timeout 5` created the volume and exited 0), while `maki check <config> --timeout 0` failed on the value of an option `check` never uses. | `maki` finds the command word before it parses `--timeout`: only `status`, `metrics`, `checkpoint`, `drain` and `reload` take it, and every other command refuses it with the usage and exit status 2, whatever its value. A leading `--timeout` before `attach`, `detach` or `grow` keeps the existing delegation route. The operations guide and the usage text name the commands that take it. | `commands_without_a_control_round_trip_refuse_timeout`, `control_commands_keep_applying_timeout` (`bins/maki` `review_control_timeout_scope.rs`) | [#188](https://github.com/seo-rii/maki/pull/188) |

### Documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-096 | A remote restore runs automatic GC right after activation, and activation clears the record's restore source, so GC retires every lower-fence namespace whose lock is free. With the daemon stopped, as the procedure requires, that includes the namespace holding the newer state the restore replaces: the restore deletes that state from the backing root. Neither the restore procedure nor the rollback-protection summary said so. | Documentation only: the [remote witness guide](remote-witness-service.md#snapshot-takeover-and-restore) warns before the restore command that the deletion cannot be undone from the backing root, that a handle still open only postpones it and that the source snapshot stays in its backup directory. It says to snapshot the newer state first if it may be needed again (that snapshot raises the fence, so the restore must use the fence from a new inspection) and, if the current generation does not authenticate, to keep a copy of the stopped backing directory. Checked with a throwaway test on the `remote_rollback.rs` fixture, not committed. | — | [#187](https://github.com/seo-rii/maki/pull/187) |
| AUD-097 | The Debian installation guide said `systemd-analyze verify` reports the missing `/etc/maki/attach/demo.toml` assertion of `maki-attach@demo.service`, but `verify` does not evaluate `Assert*=` settings; the data-plane readiness section said `maki-attach@` waits for `READY=1` through `Requires=`, but the unit uses `BindsTo=`; and the quick start's cleanup left `/srv/demo`, so following it a second time on the same host stopped at the bootstrap's new-mountpoint guard. | Corrected: the guide says `verify` does not cover the assertion and names `systemd-analyze condition --unit=maki-attach@demo.service`; the readiness section names `BindsTo=`; the cleanup runs `rmdir /srv/demo` after every unit is inactive and before anything is deleted, so a mount left behind stops it. | — | [#187](https://github.com/seo-rii/maki/pull/187) |

### Not closed in this pass

- After a failed rename or directory sync of its state, a local witness
  authority answers every request as unavailable until it is restarted, and
  `serve` does not exit by itself; no packaged unit runs or restarts it
  (AUD-092).
- A restore from a snapshot that lacks its `remote.operation.lock` still
  creates that file, which needs write access to the snapshot directory
  (AUD-093).

## Internal audit, second round (2026-11-17): AUD-052–AUD-090

A second pass closed most of the gaps the
[first pass](#internal-audit-2026-11-16-aud-001aud-051) left open and fixed
the findings of a second internal audit of `main` at `5a65e96`, which contains
the first pass. That audit reviewed the merged durability, transport and
configuration fixes, fed CRC-valid but inconsistent metadata to recovery and
the deep check, ran randomized engine and rollback sweeps, and read the
operator documentation and the vendored parser. Sixteen pull requests,
[#170](https://github.com/seo-rii/maki/pull/170) to
[#185](https://github.com/seo-rii/maki/pull/185), were merged into `main` on
2026-11-17: #170 to #177 close items of the first pass's open list and gaps
found while fixing them, and #178 to #185 fix the audit's findings. Every code
fix landed test-first: its commit message and pull request name the
regression that failed before the change. AUD-064 and AUD-065 strengthen
tests that could not fail and add a missing one; AUD-081 and AUD-083 to
AUD-090 correct tooling and documentation. AUD-061 and AUD-062 record decoder behaviour a pull request
examined and deliberately kept; every other row is **Fixed**. Four rows
change documented behaviour: AUD-054 relaxes the
[fail-closed rule](#recovery-fail-closed-rules) for a final segment's header,
AUD-056 makes recovery refuse a volume whose counters leave no room for one
more record or segment, AUD-059 makes a lost key canary a deep-check error
only where attach must refuse, and AUD-068 lets a request that is not
retry-safe fail over, and under `stall` wait, while none of its attempts was
sent. The list after the tables records what remains open. No change alters
the on-disk format or the golden vectors. The operator-visible refusals are
listed in the [changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs, in isolated build directories, of
the changed crates' suites, the dependents that exercise the change, strict
Clippy, `cargo fmt --check` and the documentation link checker. The
crash-model, worker, journal, codec and recovery changes (#175, #176, #177,
#184, #185) also ran maki-core's ignored release gates one at a time (#185
all eight), #174 the maki-crypto phase 5 gates, and #182 the rollback
write-cost gate in release. Most code fixes also report mutation checks: the
new tests fail when the fix is removed or weakened. #185 also ran a CRC-valid
metadata mutation sweep over 2,438 volumes: on `main` the deep check passed 41
that recovery refused, 16 attached and then failed a write, a checkpoint or a
second recovery, and 57 served zeros or older data; with the fix the counts
are 0, 0 and 7, the 7 being checkpoint raises at or below the durable proof's
horizon (see the open list). These are repository tests with simulated
devices, local sockets, private mount namespaces and test authorities; no
kernel NBD/LVM/XFS stack, systemd unit, vendor endpoint or physical power loss
was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-052 | Every worker pass syncs before it checkpoints, but after a failed sync only a pass started by the journal watermark or by low free space still checkpointed the records that were already durable (AUD-005). A pass started only by the interval, the overlay watermark or a write refused for backing space deferred by one interval and returned, so while every journal sync failed those passes never applied durable records, deleted the sealed segments they cover or shrank the overlay. | A failed sync does not advance the durable mark and a checkpoint applies only records at or below it, so every worker pass now checkpoints after a failed sync when there is something to do without it (durable records above the checkpoint, covered segments, pending cleanup or a due reclamation); otherwise it returns without an empty checkpoint. BUG-101's one-interval retry deferral is kept, and the inline reclaim still refuses its write when its sync fails. | maki-core `review_watermark_volatile_tail.rs`: `interval_pass_reclaims_durable_segments_while_journal_sync_fails`, `overlay_pass_reclaims_durable_records_while_journal_sync_fails`, `refusal_pass_reclaims_durable_segments_while_journal_sync_fails` | [#176](https://github.com/seo-rii/maki/pull/176) |
| AUD-053 | The journal-size trigger compared all journal bytes on disk with the watermark, but a checkpoint never deletes the active segment. With a watermark at or below the segment size the active segment alone kept the journal above it, so every write above the watermark woke the worker into a journal sync and a checkpoint that gave nothing back. Validation keeps the watermark (half of `journal_max_bytes`) above one segment, so only an engine configured directly reached this. | The trigger, and the write path's wake-up of the worker, also require a sealed segment on disk, so a low watermark costs one pass per sealed segment. Three tests that used such a watermark only to wake the worker on every write (`review_checkpoint_backoff.rs`, `review_blocking_io.rs`, the volatile-tail watermark case) now seal a segment per write. | `watermark_below_the_segment_size_checkpoints_once_per_sealed_segment` (maki-core `review_watermark_active_segment.rs`) | [#176](https://github.com/seo-rii/maki/pull/176) |
| AUD-054 | A final journal segment exactly one header long whose header fails its checksum still refused attach, after a plain restart too, and the deep check reported it as damage. Writers before AUD-003 extended a new segment to the header length before writing the header, and left such a file when that write tore (or the header was later damaged there) and the failed creation's cleanup never finished. The file holds no record and the durable proof and mark name earlier segments; 39 of 192 random power losses taken while the torn file was volatile were refused. | Recovery discards such a file as an unfinished creation (removed, journal directory synced before the writer resumes) when the segment is final, exactly header-sized, fails its checksum and lies above the segments the durable proof (unless empty) and the durable mark name; without a proof (legacy v1 inspection) never. Every acknowledged record lies in or below the segment the proof names, and a segment that held one is longer than a header. A header followed by record bytes, one the proof or the mark names or lies below, one that is not final and an intact header that does not decode still fail closed. The deep check reports the discarded file as an info line. **Behaviour change:** this relaxes the rule, kept by AUD-003 and BUG-060, that any complete header failing validation is durable damage; the writer and its cleanup obligation are unchanged. | maki-core `review_journal_legacy_torn_header.rs`: `legacy_torn_header_only_final_segment_is_discarded`, `legacy_torn_header_survives_random_power_loss` and seven fail-closed cases; `review_journal_creation_cleanup.rs`: `an_unremoved_invalid_header_still_fails_closed_after_power_loss` (now record-like bytes after the damaged header, or an index the mark names) and `an_unremoved_damaged_header_only_creation_is_discarded_after_power_loss` | [#177](https://github.com/seo-rii/maki/pull/177) |
| AUD-055 | A CRC-valid checkpoint state whose sequence lay above the required durable proof's horizon was accepted: recovery treated the FUA-acknowledged records between the two as applied, those units read zeros, the next checkpoint pruned their journal, and the deep check reported the volume clean. Reaching it needs write access to the backing or media damage. | Recovery refuses such a checkpoint right after loading it, before any write, and the deep check applies the same function. No crash or restart produces it: a record becomes checkpoint-eligible only once both proof copies attest it, and recovery publishes the proof before it advances the checkpoint. | maki-core `review_checkpoint_horizon.rs`: `checkpoint_above_the_durable_proof_is_refused_by_recovery_and_the_deep_check`, `refused_checkpoint_horizon_leaves_the_acknowledged_journal_intact` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-056 | A v2/v3 volume whose recovered durable sequence was `u64::MAX - 1`, or whose highest segment index (of a surviving segment, the durable proof or the advisory mark) was `u64::MAX - 1`, attached and passed the deep check; every later write then failed as exhausted, forever. | The shared journal scan refuses, on v2/v3 volumes, a durable sequence that leaves no sequence for one more record and a highest index that leaves no index for one more segment; the advisory mark is refused like a segment index instead of being ignored. **Behaviour change:** the [durable recovery guide](durable-recovery.md#cost-and-verification-limits) said the last representable sequence and index stay readable after recovery. A writer that reaches the limit still refuses the append or roll before changing storage and serves its data until detach, but the next recovery refuses the volume: read availability of a state only damage produces is traded for agreement between the deep check and attach. Legacy v1 read-only inspection keeps the old bound. | maki-core `review_r3_recovery_counters.rs`: `durable_horizon_leaving_no_sequence_for_a_record_is_refused`, `record_at_the_last_sequence_leaving_no_successor_is_refused`, `segment_index_leaving_no_index_for_a_roll_is_refused`, `advisory_mark_index_leaving_no_index_for_a_roll_is_refused`, `durable_proof_index_leaving_no_index_for_a_roll_is_refused`; `last_accepted_horizon_remains_readable_with_exact_record_count` and `empty_segment_at_the_last_accepted_base_preserves_the_horizon` pin the highest accepted horizon | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-057 | A durable proof that the checkpoint covers, naming a later segment (or the same record end) than the newer surviving records end at, passed the deep check, while recovery refused it ("advancing durable sequence regressed its segment location") after it had already rewritten the superblock and checkpoint state. | The shared scan compares a covered proof's location with the record end recovery would publish for the newer records, so both refuse it, before any recovery write. | maki-core `review_durable_proof_location.rs`: `covered_proof_naming_a_later_segment_is_refused_by_check_and_recovery`, `covered_proof_ending_where_the_newer_record_ends_is_refused_by_check_and_recovery`; control `covered_proof_before_the_newer_record_still_recovers` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-058 | A generation near `u64::MAX` in the checkpoint state, the durable proof, an allocation or discard map or the key canary passed the deep check, while attach refused it as exhausted, or attached and a later checkpoint failed. | A read-only check that recovery and the deep check both run refuses A/B metadata (superblock, checkpoint state, durable proof, key canary, shard catalog, and each loaded shard's allocation and discard maps) whose raw generation, as the store ranks it, lies in the top quarter of the generation space (above `u64::MAX - 2^62`). No writer reaches it, and the `2^62` stores left are more than any attach, replay or checkpoint performs. `AbStore` gains a read-only `raw_generations` accessor. | maki-core `review_generation_headroom.rs`: `generations_without_store_headroom_are_refused_by_check_and_attach`, `generations_up_to_the_bound_are_accepted_by_check_and_attach` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-059 | With both key canary copies damaged or removed on a used volume that no longer held ciphertext (every unit trimmed), the deep check printed a `key canary: absent` warning and `check passed`, while every attach refused with "volume has history but no readable ciphertext to probe", whatever the provider. | The deep check tells damaged copies (`copies exist but no copy validates`) from missing ones and decides severity after reading the journal and slots, as attach does after recovery: an `ERROR` when the volume has history but no unit would hold ciphertext after replay, otherwise a warning saying what attach needs. It cannot know whether the provider offers integrity, so it never fails a volume some provider can attach. **Behaviour change:** the [operations guide](operations.md#volume-lifecycle) classified any canary metadata that failed validation as `unrecoverable`; a lost canary is now an error only where attach must refuse, and a damaged canary on a pristine volume, which attach re-binds, is a warning. Three journal tests that built canary-less volumes with history now bind a canary first. | maki-core `review_check_canary.rs`: `canary_loss_on_a_used_volume_without_ciphertext_fails_the_deep_check`, `canary_loss_on_a_volume_with_ciphertext_is_a_warning`, `canary_loss_on_a_pristine_volume_is_a_warning` | [#185](https://github.com/seo-rii/maki/pull/185) |
| AUD-060 | When a shard's unit count is not a multiple of eight, the last byte of its allocation bitmap (and of its v3 discard bitmap) holds padding bits. The decoder accepted a CRC-valid copy with padding bits set and `AllocationMap::set_count()` counted them. `SlotStore::open` uses that count to classify an adopted shard whose data file is short: with an empty map it was never checkpointed into and its holes stay holes, with a listed slot it was truncated and its cleared slots past the end read EIO (S-01). A map whose only set bits were padding therefore made a never-finished shard truncated: the deep check reported all its units as damage and attach returned EIO for units never written. No writer in this repository sets padding bits. | The decoder clears padding bits instead of carrying them into the map, so `set_count()`, `encode()` and equality see only real units. Every image accepted before is still accepted with the same unit bits; the decoder masks rather than refuses because the repository's history cannot show what earlier writers did. No encoder output, golden vector or format version changes. | `padding_bits_are_not_allocated_units` (maki-format `review_codec_canonical.rs`); `padding_bits_do_not_make_a_never_finished_shard_truncated` and the control `a_listed_unit_still_makes_a_short_orphan_truncated` (maki-core `review_adopted_shard_padding.rs`) | [#184](https://github.com/seo-rii/maki/pull/184) |
| AUD-061 | The decoders also ignore the slot header's flags word and 24 reserved bytes, the superblock's bytes between its last string and the CRC, and a key canary's bytes after its ciphertext, so non-canonical CRC-valid copies are accepted. | **Not changed**, deliberately: accepting them has no observable effect, and refusing them could break a volume an earlier writer produced. Every reader decodes a slot header identically, it is identified by its unit and write sequence, and its payload is verified by the ciphertext CRC; two superblock copies of one generation that differ in those bytes are already refused as conflicting, and copies are rewritten from their exact bytes; a successful attach rewrites both canary copies from the decoded record, whereas refusing their trailing bytes would make the canary absent, which attach refuses on a volume with data unless the provider offers integrity. A comment at each decoder says why. | `slot_header_flags_and_reserved_bytes_stay_accepted`, `key_canary_bytes_after_the_ciphertext_stay_accepted` (maki-format `review_codec_canonical.rs`); existing `same_generation_conflicts_include_ignored_padding` (`review_superblock_v2.rs`) | [#184](https://github.com/seo-rii/maki/pull/184) |
| AUD-062 | A v2 journal record of zero length is replayed as an empty slot write; on v3 the same record is a discard tombstone. | **Not changed**, deliberately: `Volume::write_ct(unit, &[], ..)` on a v2 volume produces such a record, and replay serves the same empty ciphertext the live view served. The engine never journals one, because `CheckedProvider` refuses an empty encrypt result. | — | [#185](https://github.com/seo-rii/maki/pull/185) |

### Crash model and test doubles

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-063 | Linux `FileBacking` refuses a directory name as a lock file and as a file to remove (EISDIR), but `CrashableBacking::try_lock` locked a directory name, and `remove` of a directory name returned `NotFound` in both `CrashableBacking` and `MemBacking` (AUD-010's open item), so a test could pass for code that confuses the two kinds of entry. | Both in-memory backings apply one rule, "the parent exists and the name is not a directory", to `remove` and `try_lock`, as they already did for `open` and rename targets. The namespace table moves to `crates/maki-backing/tests/common/namespace_parity.rs`, gains directory-removal cases and a file-removal control, and runs against both in-memory backings. | `mem_backing_namespace_follows_posix_path_rules` (maki-backing `review_mem_backing_parity.rs`) and `crashable_backing_namespace_follows_posix_path_rules` (maki-test-support `review_test_doubles.rs`); `file_backing_namespace_matches_the_expectations` checks the expected outcomes against Linux `FileBacking` | [#175](https://github.com/seo-rii/maki/pull/175) |
| AUD-064 | Three regressions in the first pass's open list did not fail when the code they are named after was removed. `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback` and `process_recovery_rewrites_clean_cache_bytes_before_sealing_the_journal` passed without recovery's prefix rewrite, because attach recovery replays the adopted records into synced slots before it returns, and the second test's wrapper failed a segment sync without the crash model seeing it, so recovery's own sync persisted the writes anyway. `a_failed_intermediate_sync_stops_append_and_can_resume` passed without the journal's rewrite after a failed sync, because its later FUA records re-dirtied the page holding the failed records (AUD-008). | Test only. The `review_writeback.rs` case stops recovery after a restart right after it syncs the durable mark, while the segment holds the only copy of the record, then loses power and requires the next attach to serve it. The `review_journal_writeback.rs` wrapper fails segment writeback inside `CrashableBacking`, and the test uses the full-replay `recovery::recover` before a power loss. The `review_journal_pending.rs` case uses a segment that holds exactly the two records pending at the failed sync, so later records go to a successor; its accounting assertions are unchanged. Each now fails when its rewrite is removed. | maki-core `review_writeback.rs`, `review_journal_writeback.rs`, `review_journal_pending.rs` | [#175](https://github.com/seo-rii/maki/pull/175) |
| AUD-065 | MAKI-011 (a transport error on the self-test's tamper probe must leave the integrity claim unproven) had no dedicated test. The only covering test answers every negative probe with a transport error, so the self-test stops at the first context-binding probe, and accepting any error at the tamper probe's call site passed every test. | Test only. A provider that fails only the decrypt of the flipped ciphertext, with a `Retryable`, `Throttled` or `EndpointFatal` error, must reach the tamper probe once and fail the self-test with that class (FUP-008); the same provider passes when the tamper probe gets `Integrity`. | `a_transport_error_on_the_tamper_probe_alone_leaves_integrity_unproven` (maki-crypto `review_audit2.rs`) | [#175](https://github.com/seo-rii/maki/pull/175) |

### Remote providers and transports

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-066 | The WebSocket reader parsed every text frame into a guarded tree of all its nodes before routing it, at 56 bytes per node, so a frame of small values within the default 8 MiB `max_frame_bytes` (extra empty items, padding inside an item or an error envelope) held about 43 times its size, 361 MB, at peak (AUD-024's open item). | The frame parser keeps only what response handling reads (the numeric `id`, the error's `class` and `reason`, each item's `unit` and `data`), and items only up to the largest item count among the requests registered on the frame's connection generation; later items are counted, so a longer array still fails the count check. Unread values go through a skipping visitor that keeps the syntax, UTF-8, number-range, trailing-input and recursion checks and never copies a string out of the guarded frame. | maki-crypto-websocket `review_response_memory.rs` (`json_frame_memory_is_bounded_by_its_size`: 43.0 times before, 1.0 after; bound three times); erasure unit tests moved to fields the parser reads | [#173](https://github.com/seo-rii/maki/pull/173) |
| AUD-067 | The gRPC provider decoded every repeated `CryptoItem` of a response before comparing the item count with the request. An empty item is two bytes on the wire but a 64-byte guarded item in memory, so a message of empty items within the default 4 MiB `max_message_bytes` held about 49 times its size, 206 MB, at peak. | The response codec carries the request's item count, and the decoder refuses the first item field beyond it before decoding that item, as a receive-contract error charged to the endpoint. Decoding is otherwise prost's own loop, so field replacement, unknown-field skipping and erasure of decoded items are unchanged. | maki-crypto-grpc `review_response_memory.rs` (`response_message_memory_is_bounded_by_its_size`: 49.0 and 25.0 times before, 1.1 to 1.3 after); a unit test of decoding at, below and above the count | [#173](https://github.com/seo-rii/maki/pull/173) |
| AUD-068 | `EndpointSet` sends a request of a provider that is not retry-safe at most once (M-010) and applied that to every failed attempt, including one that failed before any request byte left Maki. With `retry_safe = false` and a healthy peer, a request whose endpoint refused the TCP connection, failed or never finished the TLS handshake, or refused the WebSocket upgrade was returned as an I/O error, although sending it to the peer could not duplicate an operation. | Transports mark exactly the errors they can prove happened before the first request byte was written with `CryptoError::not_sent`, a `NotSent` wrapper whose class, message and `duplicate()` are the inner error's; only `Retryable`, `Throttled` and `EndpointFatal` errors can be marked. While every attempt so far was unsent, the request fails over and, under the availability policy, is retried like one not yet sent; once any attempt, or an earlier chunk of the same call, may have been sent, it is never sent again. WebSocket marks failures before the frame reaches the connection's writer, HTTP marks reqwest connect errors (and builds its client with `retry::never()`), and gRPC marks the connection attempt and channel readiness; errors the libraries cannot prove unsent stay unmarked. **Behaviour change:** M-010's "no retry, no failover" now applies only once an attempt may have been sent, so under `stall` a non-retry-safe request whose only endpoint refuses connections stays pending instead of failing at once. | maki-crypto `review_unsent_failover.rs`; `review_unsent_failover.rs` in maki-crypto-websocket, maki-crypto-http and maki-crypto-grpc (refused connections and TLS failures fail over; a request written before the connection died, a gRPC error status, a gRPC timeout after hand-over, a WebSocket reconnect after a written frame and an HTTP per-item call after an earlier unit are never sent again); `generic_4xx_upgrade_refusal_fails_over_and_opens_the_refusing_peer` (maki-crypto-websocket `review_error_class.rs`) now requires every non-retry-safe request to succeed | [#174](https://github.com/seo-rii/maki/pull/174) |
| AUD-069 | When the `bounded-error` deadline expired while an operation waited for endpoint admission (an endpoint had already failed it and the failover target's slots were taken by other operations), the dispatcher returned the generic `Retryable` "operation deadline exceeded" and dropped that endpoint's error. Its deadline exits at the top of a pass and after a failed RPC return the last endpoint error, so one outage was reported with a different message and class depending on where the deadline expired. | The admission exit returns the last endpoint error with its own class, like the other two exits; an operation that never reached an endpoint still gets the deadline error, and the deadline metric is unchanged. *Extended by AUD-109 ([#342](https://github.com/seo-rii/maki/pull/342)):* an RPC cut off by the deadline, and a batch scheduler caller that leaves at its own deadline, answer the same way, with the last endpoint error of the RPC batch in progress, and every expired operation counts once in the deadline metric. | maki-crypto `review_admission_deadline_error.rs`: `an_admission_deadline_reports_the_last_endpoint_error`, `an_admission_deadline_keeps_the_class_of_the_last_endpoint_error` | [#174](https://github.com/seo-rii/maki/pull/174) |
| AUD-070 | The patched serde_json keeps custom error messages in a `GuardedString` whose `Deref` validates the whole buffer as UTF-8, and `parse_line_col`, which recovers a trailing " at line L column C", indexed the guard once per digit. Serde puts untrusted text in these messages (wrong-type string values, unknown field names), so an authenticated witness client, a hostile witness response or a control-socket value with many digits after its last " at line " made one error cost O(length × digits): 160 to 179 ms for a 64 KiB witness request frame against about 2 ms for a same-size control. | `parse_line_col` derefs the guard once and runs upstream's unchanged index logic on the borrowed text, so building an error validates the message at most twice; `Deref` keeps its runtime UTF-8 check. `vendor/patches.json` records the new hashes. | vendored `error::tests::position_parse_validates_the_message_a_fixed_number_of_times` (`vendor/serde_json/src/error.rs`; 4,099 validations for 4,096 digits before) | [#183](https://github.com/seo-rii/maki/pull/183) |
| AUD-071 | The `&RawValue` seed implemented only `visit_borrowed_str`. On reader input, or when converting from a `Value` or `&Value`, the parser hands the seed owned raw text, and serde's default `visit_string` returned the invalid-type error and freed that String with the raw JSON still in it, although the vendor guide says the library's own visitors adopt such a String. Maki borrows `&RawValue` only through `from_slice`, so production did not reach this path. | A `visit_string` adopts the String into a `GuardedString` and returns the same error, so the text is erased when the guard drops, including on unwinding. | `borrowed_raw_rejection_of_owned_raw_text_erases_it` (`vendor/serde_json/tests/maki_raw.rs`) | [#183](https://github.com/seo-rii/maki/pull/183) |

### Configuration validation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-072 | Validation never inspected gRPC `encrypt_path` and `decrypt_path`; the provider parsed them with the HTTP URI type only at construction, during attach. An empty path, one without the leading `/`, or one with a space, control character, `<`, `>` or backtick validated and then failed every attach, and some paths construction accepted were not sent as written: a `#v2` fragment was dropped, and `*` or a bare `?tenant=demo` named no method. | maki-format owns the method-path rule (`check_grpc_method_path`), which validation and provider construction both apply before the URI parse: an RFC 3986 absolute path with an optional query (the HTTP/2 `:path` of RFC 9113 §8.3.1), only path and query characters and well-formed `%XX` escapes, no `#`, within the client's 65534-byte URI limit. Every accepted path parses unchanged; characters RFC 3986 requires to be percent-encoded (quotes, braces, brackets, backslash, caret, vertical bar, non-ASCII) now must be. maki-crypto-grpc gains maki-format as a normal dependency. | `method_paths_the_provider_cannot_send_as_written_are_refused` (maki-format `review_grpc_method_paths.rs`); `validation_and_construction_accept_exactly_the_paths_sent_as_written` (maki-crypto-grpc `review_method_path_rule.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |
| AUD-073 | In a `remote-http` batch body the top-level `fields` are evaluated once per request with no item, so a `payload`, `unit_index` or `batch_index` source there validated and was sent as an empty payload or 0 in every request; a per-item body (no `items_path`) never sends `item_fields`, which validated and were dropped. | `BodyConfig::request_mapping`, which validation and `HttpCryptoProvider::from_config` share, refuses an item source among a batch's top-level fields (pointing at `item_fields`) and a non-empty `item_fields` table on a per-item body. Context sources at a batch's top level, raw bodies and programmatic `OpSpec` mappings are unchanged. Two assertions that now meet the earlier refusal were adapted (`review_http_field_mappings.rs`, `review_r3b_config.rs`). | maki-format `review_http_item_sources.rs`: `item_sources_in_top_level_batch_fields_are_refused`, `item_fields_of_a_per_item_body_are_refused`; `fields_no_request_carries_are_refused_by_validation_and_construction` (maki-crypto-http `review_unsent_item_sources.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |
| AUD-074 | `env` credential names only had to be non-empty, but the development source reads `MAKI_CREDENTIAL_<NAME>` and no environment variable name can contain `=` or NUL. Such a name was not a clean miss: with glibc, `std::env::var("MAKI_CREDENTIAL_A=B")` returns the rest of `MAKI_CREDENTIAL_A` after a leading `B=`, so a key or token was read from part of another variable. | Validation and the `validate_credential_sources` preflight refuse an `env` name containing `=` or NUL in every credential reference, without quoting it. The rule is deliberately minimal: `env` is development-only and POSIX allows every other byte in a variable name. | `env_names_no_environment_variable_can_have_are_refused` (maki-format `review_env_credential_names.rs`) | [#172](https://github.com/seo-rii/maki/pull/172) |

### Rollback protection and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-075 | The `maki-witness` configuration loader refused a symlink, a non-regular or oversized file and group or other write, but not a foreign owner, who can rewrite the file whatever its mode (AUD-031's open item). A `0644` server configuration owned by an unprivileged user let that user add their own certificate as an administrator or point `key_file`, `state_dir` or `[etcd]` elsewhere; the same loader serves `init-etcd` and `inspect`, whose configurations name the backend and the server and CA the command trusts. | A configuration must be owned by root or by the process's effective user, checked on the descriptor opened with `O_NOFOLLOW` before the mode check; `serve`, `init-etcd` and `inspect` refuse anything else with `PermissionDenied` naming both uids and none of the content. Group and other read stays allowed: a configuration holds paths and fingerprints, not secrets. | `a_configuration_owned_by_another_user_is_refused_by_every_loader`, `root_owned_and_own_configurations_still_load` (`bins/maki-witness` `review_config_owner.rs`; root only) | [#170](https://github.com/seo-rii/maki/pull/170) |
| AUD-076 | `StateStore::open` and `StateStore::create`, which `maki-witness init` and `serve` use, pinned the authority's state directory without following a symlink but checked neither its owner and mode nor those of the `remote.state`, `remote.next` and `remote.lock` files in it (AUD-031's open item). Whoever could write the directory or one of those files could put an older record back and roll the freshness authority back across a restart; a planted `remote.next` was even renamed into place by the next publish. | The directory and every existing `remote.*` file must be owned by root or the effective user and have no group or other write bit (a sticky bit does not stop a stranger creating the next `remote.next`); a non-regular entry is refused. The directory is checked on the descriptor `FileBacking` pinned, a refused `create` writes nothing, and `serve` refuses before binding its listener. Group and other read stays allowed: the files hold the public record and domain-separated digests. Ancestors are not checked (documented). | maki-backing `review_witness_state_owner.rs`: `a_state_directory_another_user_owns_is_refused`, `a_state_directory_writable_by_group_or_others_is_refused`, `state_files_another_user_owns_or_can_write_are_refused`, `private_and_world_readable_state_still_opens`; `bins/maki-witness` `review_state_owner.rs` (`init` and `serve`); root only | [#170](https://github.com/seo-rii/maki/pull/170) |
| AUD-077 | A witness frontend checked the client certificate against its allow-list only after the TLS 1.3 handshake, and for a certificate its CA trusts but its allow-list does not name (a rotation that missed one frontend, a wrong role file) it closed the connection without an answer. The client saw `UnexpectedEof`, `BrokenPipe` or `ConnectionReset`: failover moved on and could be answered by another frontend, `transact` retried the mutation, and a remote rollback session refused each operation but kept running, so operators saw an unavailable witness instead of the documented terminal denial. | The server reads that connection's single request and answers it with the existing `permission_denied` wire error bound to the request's id, without calling the handler; clients already map it to `PermissionDenied`, which failover, `transact` and the remote session treat as final. The wire format is unchanged, and in the accept loop a denied connection never takes a worker slot. Rejecting the certificate inside the TLS verifier was not used: in TLS 1.3 the client has already written its request when the alert arrives. | maki-witness `review_witness_auth_denial.rs`: `an_unlisted_certificate_is_answered_with_a_denial_not_a_dropped_connection`, `failover_stops_at_a_frontend_that_denies_the_certificate`, `a_denied_freshness_check_stops_the_remote_session`, `a_denied_commit_is_not_retried` | [#179](https://github.com/seo-rii/maki/pull/179) |
| AUD-078 | One entry whose name is not UTF-8 in a remote rollback backing root (anyone who can write the root can create one) made the root listing fail with `InvalidData` before GC examined any candidate. `maki volume gc` always failed; the automatic pass after each activation, which ignores GC errors, left every predecessor namespace and its full arena on disk until the filesystem filled; and `resume-enrollment` of a never-activated authority refused the root. | The directory visitor passes each entry's exact name bytes, and the root listing sorts and pages by them. GC reports such a name under `skipped_unrecognized` (with U+FFFD in place of invalid sequences), never removes it and keeps scanning; enrollment recovery skips it like other unknown entries. The scan inside a namespace still fails closed, so a namespace holding such an entry is kept. | maki-backing `review_remote_gc_names.rs`: `non_utf8_root_entries_are_reported_and_kept_while_gc_reclaims`, `non_utf8_names_across_pages_are_each_counted_once`, `activation_retires_its_predecessor_past_a_non_utf8_root_entry`, `enrollment_recovery_keeps_a_non_utf8_root_entry`; control `control_a_non_utf8_entry_inside_a_retired_namespace_keeps_it` | [#181](https://github.com/seo-rii/maki/pull/181) |
| AUD-079 | Both rollback manifest loaders, local and remote, allocated a buffer of a slot's unauthenticated 8-byte length after checking it only against the slot size of a 1 GiB backing, so a damaged or planted length made each open, takeover and GC pass allocate about 72 MiB before the read failed on a slot file of about 8 MiB. | The loaders refuse a length the slot file cannot hold before they allocate. A canonical manifest always fits its slot, whose exact size is checked after decoding, so which manifest is selected does not change. | maki-backing `review_rollback_manifest_length.rs`: `local_manifest_length_beyond_its_slot_is_refused_before_allocating`, `remote_manifest_length_beyond_its_slot_is_refused_before_allocating` (peak under 9 KB after) | [#181](https://github.com/seo-rii/maki/pull/181) |
| AUD-080 | Every open of a local rollback witness republishes its anchor (written to `anchor.next`, synced, renamed over `anchor`, directory synced), and the new file belonged to the process that opened it. The rollback guide told operators to run `maki check --deep` and `maki volume inspect` on a detached volume without naming a user, so a root run replaced the anchor with a `root:root 0600` file and the daemon's next attach failed with EACCES. A root `maki volume create` also left the witness files root-owned, and its warning told the operator to chown only the volume tree. | The republish stays. When root publishes the anchor, the new file gets the replaced anchor's uid and gid with `fchown` on its own descriptor before any byte is written, and is synced with `fsync` (`fdatasync` need not persist an owner change) before the rename and directory sync; a refused owner change refuses the open. Other users still create it as themselves, and every publication stays owner-only (`0600`). `BackingFile` gains `owner`/`set_owner`, which `FileBacking` implements on Unix. A root create names both the backing root and the witness directory in its `chown -R maki:maki` warning, and the guide says to run create, `check --deep` and `inspect` as the daemon user. *Changed by AUD-111 ([#344](https://github.com/seo-rii/maki/pull/344)):* in a witness directory another user owns, a root-owned anchor is published for the directory's owner and an anchor of a third user is refused; a leftover `anchor.next` is removed instead of written into; root creates every other missing file for the owner of its directory, so the guide allows these commands as root; and the create warning names only a tree that holds a root-owned entry. | maki-backing `review_local_witness_owner.rs`: `root_republish_keeps_the_anchor_owner_and_mode`, `root_reopen_of_a_daemon_owned_rollback_backing_creates_no_root_owned_file`, `republish_by_the_anchor_owner_changes_neither_owner_nor_mode`; `bins/maki` `review_local_witness_owner.rs`: `root_offline_check_and_inspect_leave_the_daemon_able_to_open_its_witness`, `root_create_names_the_rollback_witness_among_the_paths_to_hand_back`; unit test `only_root_gives_a_new_record_the_replaced_owner_and_syncs_it_first` (`crates/maki-backing/src/witness.rs`); the root cases skip unprivileged | [#182](https://github.com/seo-rii/maki/pull/182) |
| AUD-081 | Since the witness client refuses a TLS key owned by another user (AUD-031), `maki volume snapshot` and `maki volume gc` with the daemon-owned writer configuration refuse to run as root, as `maki volume witness` does, but the guides showed them with no user. The rollback guide's enrollment-recovery procedure also lacked the `chown -R maki:maki` hand-back the remote witness guide gives after `resume-enrollment`, which runs as root and creates the new writer namespace owner-only. | Documentation only: the remote witness guide runs `witness`, `snapshot` and `gc` with the writer configuration as the daemon user, with a backup directory that user can create, and takeover, restore and `resume-enrollment` as root with the administrator configuration, followed by the hand-back; the enrollment-recovery procedure includes it. The root refusal was checked with the built binary. | — | [#182](https://github.com/seo-rii/maki/pull/182) |

### Daemon admission

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-082 | The daemon's `[security.memory_budget]` admission, which runs before attach and again before readiness, read `/proc/self/mountinfo` as UTF-8 and checked every mount's path with the cgroup path rules. One mount anywhere in `maki@`'s namespace whose path is not UTF-8 (a user's FUSE mount, a USB stick under a Latin-1 label), whose directory name contains a newline, or whose path has more than 256 components failed admission, and every memory-budgeted volume then failed to start. AUD-040 fixed only the privileged helper's parsers. | The table is read, compared on recheck and split into records and fields as bytes. Only the cgroup-v2 records are decoded and checked as before; every other mountpoint is unescaped into its exact bytes and compared with the cgroup mount path component by path component. A mount at or below the cgroup mount still refuses as shadowing whatever its bytes, a sibling that only shares its text prefix does not, and a mountpoint the kernel never emits (relative, NUL, an empty, `.` or `..` component, an unknown or truncated escape) still refuses. *Changed by AUD-101 and AUD-102 ([#337](https://github.com/seo-rii/maki/pull/337)):* records are split by field position, so an empty mount source is read as an empty field; the table is read as a stream with a 1 MiB bound per record instead of on the whole table; and the recheck compares SHA-256 digests of the bytes read. | maki-nbdkit `review_memory_budget_mountinfo.rs` (private mount namespace; prints the reason and checks nothing where mounts are not permitted); unit tests in `crates/maki-nbdkit/src/security/memory.rs`: `unrelated_mount_path_bytes_do_not_refuse_admission` (12 cases), `mounts_at_or_below_the_cgroup_mount_shadow_policy_whatever_their_bytes`, `cgroup2_records_and_undecodable_mountpoints_still_refuse` | [#180](https://github.com/seo-rii/maki/pull/180) |

### Validation tooling and documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-083 | `scripts/check_vendor_erasure.py` ran `cargo metadata` without feature flags, which resolves only the default features of workspace members, so a non-default member feature (such as `etcd-qualification` or `fake-provider`) could enable an unreviewed patched-crate feature, directly or through an optional dependency, and pass the contract while `cargo build --features …` compiled the unreviewed code. | The contract resolves with `--all-features`. Features are additive and the patched packages are excluded from the workspace, so this covers every feature selection a workspace build can make; the current tree resolves the same reviewed features with and without the flag. | `test_unreviewed_feature_behind_optional_workspace_feature_is_rejected`, `test_unreviewed_feature_behind_optional_dependency_is_rejected` (`scripts/test_vendor_erasure.py`) | [#183](https://github.com/seo-rii/maki/pull/183) |
| AUD-084 | The link checker read only inline links (AUD-047's open item): a reference definition with a missing file or anchor passed CI, a full or collapsed reference whose label matched no definition (which GitHub shows as literal brackets) was not reported, and a heading containing a full reference was slugged from its raw brackets, so a correct link to it failed. | The checker parses the definitions GitHub recognizes (CommonMark) and applies the inline target and anchor checks to each, reports full and collapsed references with no definition in the same document, and slugs headings from a reference's link text; CONTRIBUTING describes the rule. All 65 definitions in the repository, all in vendor documents, resolve. | `DocumentationReferenceLinks` in `scripts/test_docs_links.py` (9 of its 10 tests failed before) | [#171](https://github.com/seo-rii/maki/pull/171) |
| AUD-085 | The documentation covered only reflink-shared extents (AUD-049). On btrfs with its default copy-on-write data, `posix_fallocate` allocates a range, but every later overwrite of written data goes to new space, so a checkpoint's slot rewrite, the A/B metadata rewrites and recovery's journal rewrites can fail with ENOSPC on a full filesystem with no copy involved; ZFS always writes changed blocks to new space. The support matrix had no row for either. | Documentation only: the [support matrix](deployment/support-matrix.md#copy-on-write-filesystems) lists btrfs with copy-on-write data and ZFS as unsupported and btrfs with NOCOW backing files as not qualified, with the NOCOW conditions (`chattr +C` on the backing directory before `maki volume create`, no btrfs checksums or compression, snapshots and reflinks still share extents); the [status page](status.md#known-limitations), the configuration and operations guides and `BackingFile::allocate_range` say the same. Maki checks neither the filesystem nor the attribute. | — | [#171](https://github.com/seo-rii/maki/pull/171) |
| AUD-086 | The workload verify gate opens the mounted volume root and `.maki-sentinel` as root, but `ExecStartPre=!` keeps the unit's `CapabilityBoundingSet=`. In a unit that drops both CAP_DAC_READ_SEARCH and CAP_DAC_OVERRIDE, a workload-owned `0700`, `0750` or `0711` volume root, or a sentinel the workload replaced with its own `0600` file, makes the gate fail with EACCES and the workload never starts; the `O_NOATIME` retry (AUD-041) applies to EPERM only. Nothing documented this, and the privileged-helper section said the volume root carries the workload's ownership without the limit. | Documentation only: the example drop-in, the gate requirements in the operations guide and the storage-recovery sentinel description give the two remedies (keep CAP_DAC_READ_SEARCH or CAP_DAC_OVERRIDE in the bounding set, or keep the volume root readable and searchable by others with the workload's private directory below it); #187 adds the limit to the mountpoint paragraph. The gate still fails closed on EACCES. Checked as root on threads and under `setpriv` without those capabilities. | — | [#171](https://github.com/seo-rii/maki/pull/171), [#187](https://github.com/seo-rii/maki/pull/187) |
| AUD-087 | The configuration and space-reclamation guides said `fstrim` still returns space the filesystem had already freed while backing free space is inside the checkpoint headroom, as R5-011 below did. The status page and the 2026-10-03 pressure runs say otherwise: XFS `fstrim` forces a log write first and FITRIM failed with EIO there; only a raw discard of the exported device was admitted. | Documentation only: both guides say raw discards are admitted inside the headroom but a filesystem's deletes and XFS `fstrim` are refused, and link the [known limitations](status.md#known-limitations) instead of restating them. R5-011 now carries a note. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-088 | The credential-rotation guide starts `maki@` and `maki-attach@` by hand while the workloads are held stopped, but never masked `maki-recover@<volume>`. A failed daemon start reaches it through `OnFailure=` and a failed attach start requests it from `ExecStopPost`; with no attach record its cleanup succeeds and its `OnSuccess=` starts `maki-workload@<volume>.target`, registered workloads included, before the guide's peer, mount and database checks. | Documentation only: the procedure applies the operations guide's runtime mask before the target stop, keeps it through the rollback path and removes it only after the verification evidence is accepted. Checked against the packaged units and `cleanup_with`; systemd itself was not exercised. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-089 | SPEC §9 listed a "root-only secret file", the kernel keyring and a "secret-provider abstraction" as key sources. Validation accepts only `credential`, `file` and `env` and refuses `keyring`, and the loader accepts a file owned by root or by the loading user (AUD-029). | SPEC §9 lists the three implemented sources and the owner and mode rules the loader enforces, and says the keyring is not implemented; no requirement is added or relaxed. Two key-loader comments that quoted the old wording are updated. | — | [#178](https://github.com/seo-rii/maki/pull/178) |
| AUD-090 | Smaller statements were wrong or incomplete: the architecture page left `drain` out of the control verbs; SPEC §26 and the architecture page omitted the overlay checkpoint triggers and the immediate pass after a write refused for backing space; SPEC §14 counted five `maki volume inspect` layout values where inspect prints six; "mode `0600` or `0400`" read as the only accepted secret modes; the `memory_lock_mode = "off"` row did not say that `cache.lock_memory` defaults to true even with the cache off; the `~0`/`~1`-only escape rule applies to response pointers only; and the support matrix's daemon-user `0700` rule read as covering the backing directory's ancestors. | Corrected. A proposed exemption of HTTP/2 from the HTTP framing rule was dropped: the workspace builds `reqwest` without `http2`, so the provider speaks only HTTP/1.x. | The link checker and the documentation tests | [#178](https://github.com/seo-rii/maki/pull/178) |

### Not closed in this pass

- A CRC-valid checkpoint raise that stays at or below the durable proof's
  horizon is still accepted by recovery and the deep check; it drops the
  acknowledged records between the true and the forged checkpoint, and
  detecting it needs a comparison of slots with the covered journal (AUD-055).
  [#194](https://github.com/seo-rii/maki/pull/194) subsequently made recovery
  and the deep check compare the covered records that survive in the journal
  with their slot metadata and refuse such a raise before any recovery write
  (`raised_checkpoint_within_the_proof_is_refused_by_recovery_and_the_deep_check`,
  maki-core `review_checkpoint_raise.rs`). A raise whose covered records were
  already pruned leaves nothing to compare and is still accepted
  ([durable recovery](durable-recovery.md#recovery-corruption-and-checkpoint-pruning)).
- Allocation and discard map files of shards the store has not loaded are not
  generation-checked (AUD-058).
- `CrashableBacking` namespace operations (opening or creating a file,
  `remove`, `rename`, `sync_dir`) carry no crash epoch; only file handles and
  locks do (AUD-009). A volume, engine or worker that a test does not drop
  before `crash*()` can still create and sync files in the recovered state,
  so such a test can see a pre-crash volume acknowledge a FUA write that
  recovery then serves. [#192](https://github.com/seo-rii/maki/pull/192)
  subsequently made the simulated process view reject namespace operations
  after power loss.
- Renaming a directory still differs from `FileBacking` (the in-memory
  backings return `NotFound`), and `CrashableBacking::try_lock` creates no
  lock file (AUD-063). The in-memory backings have refused a directory rename
  as `Unsupported` since [#242](https://github.com/seo-rii/maki/pull/242),
  and `CrashableBacking::try_lock` has created its lock file since
  [#283](https://github.com/seo-rii/maki/pull/283) (`21a05a6`).
- A client certificate from a CA the witness does not trust is still refused
  inside the TLS handshake. In TLS 1.3 the client has already written its
  request by then, so it can see a broken pipe instead of the alert and treat
  the refusal as a transport failure (failover continues, a remote session
  keeps running) rather than a denial (AUD-077).
  [#191](https://github.com/seo-rii/maki/pull/191) subsequently made the
  client recover a queued TLS alert after a connection closes. Authentication
  alerts are reported as `PermissionDenied`. This depends on the socket
  retaining the alert after a reset, as it does on Linux.
- A root run of an offline command that has to recreate a missing
  `volume.lock`, a rollback-protected volume's `rollback.lock` or
  `witness.lock`, or an inactive manifest slot creates it owned by root, and the daemon then cannot attach
  until the paths are handed back (AUD-080). The
  [rollback protection guide](rollback-protection.md) says to run those
  commands as the daemon user and to hand the paths back after a root run;
  the operations guide does not say so for a plain volume's `volume.lock`.
  *Closed by AUD-111 ([#344](https://github.com/seo-rii/maki/pull/344)): a
  root process creates such a file for the owner of its directory, and the
  guides no longer ask for the hand-back; one is still needed after a crash
  between creating an entry and giving it away.*
- The `maki` commands and the daemon read a volume's TOML configuration
  without an owner, mode or symlink check (SPEC §8 lists its permissions as
  recommended only), and the local rollback witness directory has no owner or
  mode check, unlike the witness service's files (AUD-075, AUD-076).
  *The configuration half is closed by AUD-106
  ([#339](https://github.com/seo-rii/maki/pull/339)). The local rollback
  witness directory still has no owner or mode check of its own; since
  AUD-111 ([#344](https://github.com/seo-rii/maki/pull/344)) a root run
  compares the anchor's owner with the directory's and refuses a third user's
  anchor in a directory another user owns.*
- CIFS escapes only spaces and tabs in its mount source, so a source that
  holds a newline would split its `/proc/self/mountinfo` record in both the
  privileged helper's and the daemon's parsers (AUD-040, AUD-082). This is
  theoretical and has not been reproduced.
- An operation whose deadline has already passed when the dispatcher asks
  for endpoint admission or starts an RPC within a pass ends with the deadline
  error without incrementing `deadline_exceeded_total`, so that metric can
  undercount (AUD-069). *Closed: those exits have counted since
  [#243](https://github.com/seo-rii/maki/pull/243) (`1a879d5`), and since
  AUD-109 ([#342](https://github.com/seo-rii/maki/pull/342)) every deadline
  exit goes through one function that counts once
  (`an_admission_with_no_time_left_returns_the_last_endpoint_error`,
  maki-crypto `review_deadline_exits.rs`).*
- A `raw` HTTP body still accepts and ignores `fields` and `item_fields`;
  validation reads them only for JSON bodies (AUD-073).
- `FileBacking::list` still converts names lossily for its other callers; only
  the remote rollback root listing passes exact bytes (AUD-078). *Superseded:
  since [#236](https://github.com/seo-rii/maki/pull/236) `list` refuses a
  name that is not UTF-8 instead of converting it, and since AUD-098
  ([#338](https://github.com/seo-rii/maki/pull/338)) the scans of `data/` and
  `journal/` skip such a name; no listing converts a name lossily.*

## Internal audit (2026-11-16): AUD-001–AUD-051

An internal audit of `main` at `132cb6f` covered the journal, recovery and
engine, the crash model and test doubles, the remote transports, credential
loading and logging, configuration validation, rollback protection and the
witness, the privileged helper, and the validation tooling and documentation.
Nineteen pull requests, [#150](https://github.com/seo-rii/maki/pull/150) to
[#168](https://github.com/seo-rii/maki/pull/168), fixed its findings and were
merged into `main` on 2026-11-17. Every code fix landed test-first: its commit
message and pull request name the regression that failed before the change.
AUD-006, AUD-007 and AUD-016 to AUD-018 strengthen tests that could not fail
or that failed only because they ran as root; AUD-047 to AUD-051 correct
tooling and documentation. All rows are **Fixed**; the list after the tables
records the gaps their pull requests left open. No change alters the on-disk
format or the golden vectors. The operator-visible refusals are listed in the
[changelog](../CHANGELOG.md#breaking-changes).

The pull requests report Linux debug runs of the changed crates' suites, the
dependents that exercise the change, strict Clippy, `cargo fmt --check` and the
documentation link checker; the recovery, journal and engine changes (#164,
#166, #168) also ran the maki-core release gates one at a time. Four of them
(#155, #159, #160, #165) were also checked as an integrated tree: the workspace
suite (2,539 tests), strict Clippy, the Python contract tests, the vendor
integrity checks and the standalone vendor suites passed, and #159 and #165
report the integrated ignored release gates passing. These are repository tests
with simulated devices, local sockets and test authorities; no kernel
NBD/LVM/XFS stack, vendor endpoint or physical power loss was exercised.

### Durability and recovery

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-001 | Recovery selected a superblock copy and never wrote it back. A copy that existed only in the page cache (create's `fdatasync` of `superblock.a` failed, or the process died before it) was accepted: a retried create refused the root, attach acknowledged FLUSH and FUA, and the next power loss left no valid superblock. A create killed after A was durable but before B was written left one copy that nothing completed. | After the read-only journal scan and before any other repair, writable recovery rewrites each valid copy from its exact validated bytes and syncs it with the root directory, the selected copy first, then completes a missing or invalid copy through the preserve-first A/B store. Read-only paths still never write; legacy v1 is still refused first (SPEC §27). | maki-core `review_superblock_durability.rs`: failed sync at each publication step, a process-kill sweep over create, recovery stopped at every operation and followed by power loss or by a restart after writeback EIO, byte-identical repeated recoveries, read-only inspection writes nothing | [#164](https://github.com/seo-rii/maki/pull/164) |
| AUD-002 | Creation refused an existing superblock and any file in `data/`, `journal/` or `checkpoint/` (R5-018), but initialized a root that still held an earlier volume's `canary.a`/`canary.b` or `shard-catalog.a`/`shard-catalog.b`. A stale canary failed the new volume's first attach as a key mismatch; a stale catalog copy stayed the fallback side until the first catalog commit. | Creation refuses every root-level metadata name (`layout::ROOT_METADATA`) with `AlreadyExists` naming the file, before writing anything. A leftover `volume.lock` is still accepted. | maki-format `review_create_root_leftovers.rs`, both envelopes | [#164](https://github.com/seo-rii/maki/pull/164) |
| AUD-003 | A segment roll extended the new file to the 48-byte header length before writing the header, so a header write that persisted only a prefix left a complete-length header with a bad checksum. When the failed creation's cleanup (unlink, then directory sync) did not finish, recovery found that file as the final segment and refused attach as durable damage, after a plain restart too, although the segment never held a record. | The roll no longer preallocates the header: a torn header write leaves a file shorter than a header (or all zero), which recovery already discards as an unfinished creation. Recovery is unchanged; a complete header that fails validation is still durable damage (SPEC §23). *Relaxed by AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)):* a final segment exactly one header long whose header fails its checksum, above the segments the durable proof and mark name, is now discarded as an unfinished creation; every other invalid header still fails closed. | maki-core `review_journal_torn_header.rs`: restart with the deep check, power loss after writeback of the torn prefix, random torn power losses (22 of 256 crash states refused before). BUG-060's `an_unremoved_invalid_header_still_fails_closed_after_power_loss` now persists the whole header and damages one byte | [#166](https://github.com/seo-rii/maki/pull/166) |
| AUD-004 | A write over `backing.journal_max_bytes` or `limits.max_overlay_bytes` synced, released the volume lock, checkpointed and retried admission, up to four rounds, but nothing held the freed space for it: other writers appended into it and the write failed with ENOSPC although nothing had failed and the bound was reclaimable. Eight writers of maximal requests at the validated minimums lost 27 (journal) and 117 (overlay) of 1440 writes. | A write refused for either bound holds a FIFO reclaim gate until it has appended; every other write and discard queues behind it instead of appending, so its checkpoint covers every appended record and ENOSPC means the request does not fit even then. Reads, FLUSH and the worker never wait, and `limits.max_active_callbacks` bounds the queue. The round limit remains only as a termination bound (SPEC §26). | maki-core `review_reclaim_fairness.rs`; `review_r4_overlay_bound.rs` adapted | [#168](https://github.com/seo-rii/maki/pull/168) |
| AUD-005 | The worker's journal-watermark and low-free-space passes checkpointed without syncing first, and a checkpoint applies only durable records. With volatile records above the watermark every write woke a checkpoint that applied nothing (two exclusive volume-lock passes per write) while the journal grew toward its hard limit. | Both triggers sync first, like the interval trigger. When that sync fails, such a pass still checkpoints the records that were already durable and deletes the sealed segments they cover, keeping BUG-101's one-interval deferral of the failing sync. *Extended by AUD-052 ([#176](https://github.com/seo-rii/maki/pull/176)):* every worker pass does so, whatever started it. | maki-core `review_watermark_volatile_tail.rs`: volatile tail for both triggers; reclaim while every journal sync fails | [#168](https://github.com/seo-rii/maki/pull/168) |
| AUD-006 | Recovery rewrites every journal prefix its scan accepted before syncing it (SPEC §27, F01), but no test failed when that rewrite was removed: every case let recovery finish, and replay then made the records durable through the slots. | Test only. A sweep stops such a recovery after each backing operation, loses power and requires the next attach to match the durability oracle; without the rewrite it fails from the durable-mark sync to the directory sync that makes segment removal durable. A premise check refuses a crash model in which a plain sync persists lost writeback. | maki-core `review_recovery_prefix_rewrite.rs` | [#167](https://github.com/seo-rii/maki/pull/167) |
| AUD-007 | `recovery_refuses_bytes_that_changed_after_the_validated_scan` checked only that recovery fails. Replay fails on the changed record too, so the test passed when recovery skipped its fingerprint check, although the changed bytes were then synced and covered by the durable mark and both proof copies, and every later attach refused the volume. | Test only. The next attach must also succeed, with the acknowledged record and without the changed one. | maki-core `review_journal_writeback.rs` | [#167](https://github.com/seo-rii/maki/pull/167) |

### Crash model and test doubles

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-008 | `CrashableBacking` dropped a failed sync's dirty operations, turning "possibly written back" into "certainly lost": no later power loss could keep a page the flusher had already written, whole or torn, nor a truncation whose sync failed. Writeback was byte-range granular, so a later write that re-dirtied a page persisted only its own bytes, not the cached page. | A failed sync's operations become uncertain: a crash samples them like unsynced ones (torn when tearing is on), `crash_all_lost` and `crash_keep_torn_prefix` drop them, and no sync replays them, so a bare retry still writes nothing (F01). A successful sync writes back every re-dirtied 4 KiB page whole, zero past end-of-file. `fua_after_a_failed_sync_covers_every_pending_record` now keeps the failed records in a page the next FUA record does not touch. | maki-test-support `review_crash_writeback.rs`; maki-core `review_writeback.rs` | [#165](https://github.com/seo-rii/maki/pull/165) |
| AUD-009 | A file handle opened before `crash*()` could still read, write and sync into the recovered state, and the dead process's volume lock stayed held. | Each power loss starts a new epoch: every lock is released and every earlier handle fails with the model's EIO and changes nothing; dropping it releases nothing taken after the crash. A restart invalidates nothing. The Phase 0 oracle and `phase6.rs` `clean_detach_flushes_checkpoints_and_releases_lock` relied on the old behaviour and were adapted. | maki-test-support `review_crash_handles.rs` | [#165](https://github.com/seo-rii/maki/pull/165) |
| AUD-010 | `MemBacking` created files in directories that did not exist, renamed into them, listed or synced a missing directory as empty, looked up names below a regular file and opened or locked a directory name as a file, so a test could pass for code that fails on `FileBacking`. | The namespace applies the POSIX path rules `CrashableBacking` uses (`NotFound`, `NotADirectory`, `IsADirectory`). | maki-backing `review_mem_backing_parity.rs`: `mem_backing_namespace_follows_posix_path_rules` (14 of 21 cases failed before) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-011 | `allocate_range(offset, 0)` failed with EINVAL on Linux `FileBacking`, extended the file to the offset on `MemBacking` and `CrashableBacking`, and did nothing on `RollbackBacking`. | A zero-length range is a no-op on every backing, after the same overflow check. No production caller passes a zero length. | maki-backing `review_mem_backing_parity.rs`; maki-test-support `review_test_doubles.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-012 | With integrity off, `FakeCryptoProvider` still checked its magic bytes, so a zeroed or overwritten unit failed with `Integrity` where `local-aes-xts` returns garbage, and a test of an unauthenticated profile could pass on the fake's own framing check. | The magic is checked only with integrity on; a wrong length is still refused, as XTS does. | `an_unauthenticated_fake_decrypts_any_well_sized_ciphertext` (maki-test-support `review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-013 | `FakeCryptoProvider` declared `batch.max_bytes` but checked only the item count. | An over-limit batch is refused with `NonRetryableRequest`, measured as the crypto crate accounts batch bytes. | `the_fake_refuses_an_encrypt_batch_over_its_declared_byte_limit`, `the_fake_refuses_a_decrypt_batch_whose_plaintext_exceeds_the_byte_limit` (`review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-014 | `ManualClock` woke sleepers that share a deadline in `HashMap` order, which changes from run to run. | Sleepers wake by deadline, then registration order. | `manual_clock_wakes_due_sleepers_in_deadline_then_registration_order` (`review_test_doubles.rs`) | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-015 | `DeterministicScheduler` polled every unfinished task with a no-op waker, so a future that lost its wake-up completed in tests although tokio would never poll it again. | Each task has a waker that marks it runnable; with tasks left and none runnable, `run()` panics with a stall and `run_bounded()` returns false. | Three lost-wakeup cases in `review_test_doubles.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-016 | `unlink_failure_keeps_durable_retirement_and_restarts_without_touching_current` relied on a mode-0500 directory, which `CAP_DAC_OVERRIDE` ignores, so it failed when run as root. | The test clears the capability on its own thread, checks that the directory refuses a new entry, and skips with a message only if it cannot clear it. | maki-backing `remote_gc.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-017 | The `locking_failure` case of `secret_page_lifetimes` set `RLIMIT_MEMLOCK` to zero, which `CAP_IPC_LOCK` bypasses, so it failed when run as root. | The child process clears `CAP_IPC_LOCK` before lowering the limit. | maki-crypto `review_secret_page_lifetime.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |
| AUD-018 | `payloads_never_appear_in_logs` captured tracing on its own thread only and did not bridge `log`, so a payload logged from a runtime worker or through `log` could not make it fail. | The round trip runs in a child process with the daemon's sink at `MAKI_LOG=trace`; both a worker-thread and a `log` sentinel must arrive, and plaintext and ciphertext are refused in base64, hex and decimal. | maki-crypto-http `phase8.rs` | [#163](https://github.com/seo-rii/maki/pull/163) |

### Remote providers and transports

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-019 | tonic decodes `grpc-status-details-bin` with `expect()`, so a peer could panic a provider call; through `EndpointSet` the panic skipped failover and the breaker. A `grpc-message` that does not percent-decode to UTF-8 replaced the code with `Unknown`, turning `Integrity`, `PermissionDenied` and `Unauthenticated` into retryable errors (a tampered unit stalled instead of returning EIO) and an OK reply into an error. | Both headers are removed from initial headers and trailers before tonic parses a status; the class follows only `grpc-status` and the allowlisted `maki-crypto-error` metadata (SPEC §18). | maki-crypto-grpc `review_status_headers.rs` | [#150](https://github.com/seo-rii/maki/pull/150) |
| AUD-020 | An IPv6-literal gRPC endpoint such as `https://[2001:db8::10]:7443` passed validation, but the provider could never be built: rustls received the bracketed host as the server name. | The server name is the host without brackets, verified as an IP-address name against the certificate's IP SANs, as IPv4 literals already were. | maki-crypto-grpc `review_ip_literal_tls.rs` (the IPv6 handshake case skips without an IPv6 loopback) | [#150](https://github.com/seo-rii/maki/pull/150) |
| AUD-021 | After a `Contract` error the dispatcher ended the operation unless some endpoint was both untried and admitting a call at that moment. A validated peer that had failed transiently, or whose circuit was cooling, did not count, so under `stall` the outcome depended on routing order. | The violation is final only once every validated endpoint (a single one included; quarantined ones not) has broken the contract for the operation; until then the operation stays in the normal backoff loop with the violators excluded. A violator is never sent the operation again, and a request that is not retry-safe is still never re-sent. | maki-crypto `review_contract_finality.rs` | [#154](https://github.com/seo-rii/maki/pull/154) |
| AUD-022 | A WebSocket upgrade refused with a generic 4xx (400, 422, 426 from a proxy that cannot upgrade) was `NonRetryableRequest`: the dispatcher returned it at once without charging the breaker or failing over, and attach refused as a failed self-test instead of quarantining the endpoint. | Every 3xx and 4xx upgrade status except 408 (retryable) and 429 (throttled) is `EndpointFatal`: the upgrade GET carries no crypto request, so its refusal is the endpoint's fault. | maki-crypto-websocket `review_error_class.rs`, `review_upgrade_errors.rs`; maki-nbdkit `review_ws_upgrade_quarantine.rs` | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-023 | A 2xx HTTP/1.x response with neither `Content-Length` nor chunked coding ends at connection close, so the prefix an endpoint sent before dying was accepted as a complete body. With a raw mapping it became the unit's ciphertext; the write was acknowledged and the next read returned an integrity error. A well-framed short body, such as a proxy's HTML page, was accepted the same way. | A close-delimited success response is refused before its body is read, and a raw encrypt response shorter than its plaintext is refused, both as contract errors (breaker charged, retry-safe failover). The length rule is scoped to raw mappings, so BUG-049 and BUG-053's compact encodings are unaffected. | maki-crypto-http `review_short_raw_ciphertext.rs` | [#157](https://github.com/seo-rii/maki/pull/157) |
| AUD-024 | `max_response_bytes` capped wire bytes, but the JSON parser materialized every node of the body as a guarded tree: about 43 times the body size at peak, about 360 MB for a body within the default 8 MiB cap. | The parser keeps only what the response mapping reads (payload, echo and at most the requested batch elements); every other value is validated by a skipping visitor (syntax, UTF-8, number range, trailing input, recursion limit) and never copied out of the guarded body. | maki-crypto-http `review_response_memory.rs` (peak below three times the body; about 1.9 times measured); erasure tests in `sensitive_tests.rs` now place sensitive values on configured pointers | [#157](https://github.com/seo-rii/maki/pull/157) |
| AUD-025 | The pinned tungstenite `FrameCodec::read_in` zero-filled its whole spare capacity before every read and the patched `BytesMut::truncate` wiped it again, so after one large frame every read rewrote megabytes, and accumulating a frame in TLS-record-sized reads was quadratic in its size. | `read_in` hands the reader the spare capacity directly and zero-fills it once per allocation; erasure is unchanged for Maki's streams. The recorded vendor hash is updated. | maki-crypto-websocket `review_read_buffer_cost.rs` (page faults 15872 and 23344 before, 0 and 1265 after); vendored unit tests | [#160](https://github.com/seo-rii/maki/pull/160) |
| AUD-026 | Validation never inspected `remote-http` body mappings. Unknown sources or payload encodings failed only at attach, an encoding on a non-payload source was dropped silently, a pointer without a leading slash failed every request, overlapping pointers (or a field at, under or above `items_path`) dropped a context field the binding check had counted, and a declared context binding without a per-item `unit_index` validated although the self-test always refuses it. SPEC §18 listed `utf8`, `integer` and `uuid` encodings the provider never implemented. | maki-format owns the mapping parser that validation and the provider both use; it refuses each of these, and a declared context binding requires a per-item `unit_index`. SPEC §18 lists the payload encodings and the fixed representation of the other sources; the §19 example is valid TOML. | maki-format `review_http_field_mappings.rs`; maki-crypto-http `review_field_mapping_wire.rs` | [#161](https://github.com/seo-rii/maki/pull/161) |

### Credentials, secrets and logs

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-027 | Under `MAKI_LOG=trace`, or any directive enabling tungstenite, the vendored tungstenite logged every frame payload, received text message and the client upgrade request through the `log` bridge, so base64 unit plaintext and URL query credentials reached the journal. | The daemon's sink caps `tungstenite`, `tokio_tungstenite` and `reqwest` at `debug` under every directive, module and span directives included; Maki's own targets keep the operator's level. | maki-crypto-websocket `review_trace_logging.rs`; maki-core `logging.rs` `dependency_payload_targets_cannot_exceed_safe_levels_whatever_maki_log_says` | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-028 | At `MAKI_LOG=debug`, `tungstenite::protocol` logged the peer's close reason and reply frames, which may carry request contents. | That subtree is capped at `info`; WebSocket handshake debug diagnostics remain. | `raised_maki_log_never_writes_websocket_close_reason` (`review_trace_logging.rs`) | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-029 | The credential loader checked only the mode of an opened file. A `0600` key owned by an unprivileged user was loaded by any root process (`maki-benchmark`, a daemon started by hand), although its owner can read or replace it; the HTTP combined certificate and private-key PEM had the same gap. | A `file` credential, a file in the systemd credentials directory and a combined PEM holding a private key must be owned by root or by the process's effective user. A root process therefore refuses a key owned by the daemon user. | maki-crypto-local `review_secret_file_owner.rs`; maki-crypto-http `review_tls_files.rs` (root only) | [#158](https://github.com/seo-rii/maki/pull/158) |
| AUD-030 | An empty or whitespace-only credential file, environment variable or in-memory entry loaded as present, so the daemon built the HTTP provider with `Authorization: Bearer ` and the gRPC provider with the same empty metadata value. | Every key source refuses a value that is empty after trimming, with a `ProviderFatal` error naming the credential (SPEC §44); a padded token still loads verbatim (R5-035). | maki-crypto-local and maki-nbdkit `review_empty_credentials.rs` | [#158](https://github.com/seo-rii/maki/pull/158) |
| AUD-031 | The witness TLS key loader refused group or other access but not a foreign owner, so the witness server, the daemon's witness clients, the etcd backend client and the administrator commands loaded a `0600` key owned by an unrelated user. | A private key must be owned by root or by the process's effective user, checked on the opened descriptor while the TLS configuration is built, before any connection. Certificates and CA bundles keep their rules. | maki-witness `review_tls_key_owner.rs` (root only) | [#162](https://github.com/seo-rii/maki/pull/162) |
| AUD-032 | Validation never checked a credential `format` template. Without a `{}` the template text alone was sent, so a literal secret in `format` passed the SPEC §9 rule and a typo such as `Bearer {token}` dropped the credential; two placeholders sent it twice; `format` on `crypto.key` or a `tls.client_key` was ignored. | Validation and the provider's own credential preflight refuse a template without exactly one `{}` and `format` on keys; neither error quotes the template or the name. | maki-format `review_credential_template.rs`; adapted `review_header_template_erasure.rs` (maki-crypto-http) and `review_grpc_credential_erasure.rs` (maki-nbdkit) | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-033 | The error for a `[crypto.http.<op>] path` without a leading slash quoted the path, which can carry path or query tokens, to stderr and the journal. | The message names the operation and the rule only. | `an_invalid_http_operation_path_is_not_echoed` (maki-format `review_config_secret_echo.rs`) | [#159](https://github.com/seo-rii/maki/pull/159) |

### Configuration validation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-034 | nbdkit fails its `.block_size` callback, and with it every NBD handshake after READY, when the preferred block size exceeds 32 MiB; validation bounded only `nbd.minimum_io` and `nbd.maximum_io`. | An effective `nbd.preferred_io` above 32 MiB, configured or defaulted, is refused (SPEC §13). | maki-format `review_nbd_preferred_limit.rs` | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-035 | Attach refuses a volume whose units reach the reserved key-canary unit index, but validation and `volume create` accepted such a geometry (512-byte units from just over 2 EiB), producing a volume no attach would open. | `Geometry::compute` refuses a unit count above the canary index, for validation, creation and superblock decode. A superblock with such a geometry from an older binary, which can hold no data, loads as an invalid copy (SPEC §14). | maki-format `review_canary_geometry.rs` | [#159](https://github.com/seo-rii/maki/pull/159) |
| AUD-036 | Validation required only a non-empty credential name, while the loaders accept only `[A-Za-z0-9._-]` names without a leading dot (a `credential` name, the file name of a `file` path). `volume create` stored such a key name as the immutable key identity; every attach then refused, and correcting the name was an identity mismatch. | Validation applies the loader rule to every credential reference (`env` names are unchanged) without quoting the name. | maki-format `review_credential_names.rs`; maki-nbdkit `review_credential_name_rule.rs` compares the two copies of the rule | [#159](https://github.com/seo-rii/maki/pull/159) |

### Rollback protection and witness

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-037 | Enrollment recovery proved only the authority side. A root activated before the `remote.enrollment` binding existed received a binding for the approved identity; recovery then claimed and activated an empty namespace, and its GC retired the other volume's quiescent namespaces. A failed claim after the binding write left a wrong binding. | Before rewriting the marker, binding or claiming, recovery refuses a different or corrupt binding, any GC tombstone, and any namespace other than its own whose manifest slots hold anything but this identity's empty generation-0 manifest or a torn part of it. The post-activation GC retires only the namespaces that check examined. | maki-backing `review_remote_enrollment_identity.rs`; existing `remote_extensions.rs` enrollment cases | [#156](https://github.com/seo-rii/maki/pull/156) |
| AUD-038 | `maki volume resume-enrollment` validated without the provider-availability check (M-008), so a build without the `fake-provider` feature advanced the witness fence and wrote a superblock naming provider `fake`, a volume no release daemon can attach. | The library entry point and the CLI refuse a provider this build cannot construct before the first authority read. | `resume_enrollment_refuses_a_provider_this_build_cannot_construct` (`bins/maki` `remote_admin.rs`, under `cargo test -p maki`) | [#156](https://github.com/seo-rii/maki/pull/156) |
| AUD-039 | Linux returns EPERM or EACCES from `connect()` and `send()` when netfilter drops a local packet; the witness client passed that through as `PermissionDenied`, the kind it uses for the server's own denial. Frontend failover stopped at the first endpoint, and the rollback backing stopped the session instead of refusing one operation (BUG-103). | Client and server transport errors of a kind callers treat as final report `ConnectionAborted` with their OS text; `PermissionDenied` remains only the server's denial. TLS failures stayed `InvalidData` at the time. Since [#191](https://github.com/seo-rii/maki/pull/191), the witness client reports TLS authentication alerts as `PermissionDenied`. Other TLS failures still report `InvalidData`. | maki-witness `review_local_socket_denial.rs` (seccomp-injected EPERM; skips without seccomp), plus a classification unit test | [#156](https://github.com/seo-rii/maki/pull/156) |

### Privileged helper

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-040 | Every privileged observer read `/proc/self/mountinfo` as UTF-8. One mount anywhere in the helper's namespace whose path or source is not UTF-8 (a user's FUSE mount, a Latin-1 CIFS or USB mount) made attach preflight, detach, cleanup, `maki-recover@`, recovery proofs, NBD allocation and the verify gate fail with `InvalidData` for every volume, and the post-mount observer reported nothing mounted. | One reader reads the table as bytes; paths are unescaped and compared as bytes, never decoded lossily. `observe()` and `observe_mount()` return the read error instead of an empty observation. | maki-privileged `review_mountinfo_bytes.rs` (root, private mount namespace), `allocation_tests.rs`, parser cases in `detach_tests.rs`, `recover_tests.rs` and `workload_verify_tests.rs` | [#153](https://github.com/seo-rii/maki/pull/153) |
| AUD-041 | The workload verify gate opened the mount root and `.maki-sentinel` with `O_NOATIME`, which the kernel refuses unless the caller owns the inode or has `CAP_FOWNER`. Both can belong to the workload user and `ExecStartPre=!` keeps the unit's bounding set, so a workload unit that drops `CAP_FOWNER` could never start. | Each open retries once without `O_NOATIME`, only after EPERM; the other flags and the device checks are kept. The example drop-in now says that `!` skips only the user and group switch. | `descriptor_sentinel_reader_does_not_need_cap_fowner_for_workload_owned_files`, `sentinel_opens_drop_only_o_noatime_and_only_when_it_is_refused` (maki-privileged `workload_verify_tests.rs`) | [#153](https://github.com/seo-rii/maki/pull/153) |

### Validation tooling, CI and documentation

| ID | Finding | Fix | Regression | PR |
|---|---|---|---|---|
| AUD-042 | The unrelated-user socket probe and the unprivileged NBD disconnect probe of `scripts/privileged-linux-validation.sh` passed on any nonzero exit, so a sudo policy refusal, a missing command or an `nbd-client` usage error was logged as PASS. | Each probe requires the expected permission denial, with the run's own backend still connected; anything else stops the run and prints the output. The [runbook](qualification/privileged-linux-validation.md#denial-check-harness-correction--2026-11-16) names the earlier results those checks cover. | `scripts/test_privileged_denial_validation.py` | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-043 | The nightly plugin gate's `nm -D \| grep -q plugin_init` also matched an undefined or prefixed symbol, and the fake-provider gate passed on any `maki volume create` failure, including a configuration that no longer validates. | The gates require a defined text symbol named exactly `plugin_init` and the daemon's `provider "fake" is not compiled into this build` refusal. | `scripts/test_ci_gate_validation.py` | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-044 | On Linux `scripts/run_cargo_tests.py` added `--no-run` to every selection, including `--doc`, which Cargo refuses, so the wrapper could not run doc tests. | A `--doc` selection is forwarded verbatim. | `test_doc_test_selection_is_forwarded_without_a_compile_phase` (`scripts/test_cargo_tests_validation.py`) | [#151](https://github.com/seo-rii/maki/pull/151) |
| AUD-045 | The vendor erasure contract never compared resolved features, although the transport-memory guide said parser features were checked; the guides said no optional `serde_json` mode was enabled, yet `maki-witness` enables `raw_value`; and the inventory skipped every path with a `target` component. | `check()` compares each patched package's resolved features with a reviewed list and fails on a missing resolve section or node; only a package-root `target/` is skipped; the guides state what is enabled. | `scripts/test_vendor_erasure.py` | [#160](https://github.com/seo-rii/maki/pull/160) |
| AUD-046 | The standalone `hyper` and `tungstenite` vendor test graphs depended on unmaintained `humantime` (RUSTSEC-2026-0542) through their test loggers, which the per-lockfile `cargo audit --deny warnings` job refuses. | Both use `env_logger` 0.11.11; the manifest and lockfile hashes are recorded in `vendor/patches.json`. The workspace lockfile and production logging are unchanged. The same commit was merged into #159, #160 and #165. | The CI dependency audit and the standalone vendor suites | [#155](https://github.com/seo-rii/maki/pull/155) |
| AUD-047 | The link checker ignored fragments: an in-page `#anchor` was skipped and `other.md#anchor` checked only the file. The changelog linked to an anchor that GitHub's slug for "Correctness and recovery review — 2026-10-12" does not produce. | Fragments on Markdown targets must match a heading slug as GitHub computes it, or an explicit `<a id>`/`<a name>`; CONTRIBUTING describes the rule. 179 anchored links are checked; the changelog link was the only broken one. | `DocumentationAnchors` in `scripts/test_docs_links.py` | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-048 | Without a durable mark the deep check reported "heuristic torn-tail classification", a rule recovery has not used since M-007 and S-04. | The report describes the actual rule: the final segment is proven only as far as the durable proof names it, otherwise only its header. Message text only. | `deep_check_reports_the_rule_recovery_uses_without_a_durable_mark` (maki-core `review_check.rs`) | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-049 | `BackingFile::allocate_range` claimed that a successful `posix_fallocate` guarantees later writes cannot fail for space. On XFS with reflink (the `mkfs.xfs` default) a `cp --reflink` copy, which coreutils 9 makes by default, shares extents; `posix_fallocate` does not unshare them, so a later in-place slot write or recovery journal rewrite can fail with ENOSPC and the volume degrades. | Documentation only: the comment states the limit, and the support matrix, the [status page](status.md#known-limitations) and the operations guide require backing copies without shared extents (`cp --reflink=never`). Maki does not detect sharing. | — | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-050 | Several statements no longer matched the code: CLAUDE.md said a failed A/B store empties its unsynced side (N-09's approach, which BUG-001 replaced); SPEC §20 omitted that reload applies `cache.ttl`; the operations guide implied `maki-check --journal-segment-size` can change a verdict; this log cited renamed tests for M-015, F09, MAKI-011 and the S-01 truncation entry; and two counts in the performance and testing guides were wrong. | Corrected. MAKI-011 is stated to be covered only indirectly. | The link checker | [#152](https://github.com/seo-rii/maki/pull/152) |
| AUD-051 | SPEC, the configuration and operations guides and the storage-recovery page said recovery rechecks the `[lvm_identity]` pins (against a fresh LVM report); only attach runs that report. | Documentation only: recovery, and a detach that consumes a pre-activation intent, check the identity attach persisted against the pins and the live NBD geometry and device-mapper mappings against that identity, or after activation against the mapping proof. | Existing `recovery_rechecks_persisted_lvm_identity_against_administrator_pins` (maki-privileged `lvm_preflight_tests.rs`) | [#153](https://github.com/seo-rii/maki/pull/153) |

### Not closed in this pass

- A final journal segment that an earlier binary left with a complete-length
  torn header (it extended the file before writing the header) is still
  refused as durable damage (AUD-003). *Closed by AUD-054
  ([#177](https://github.com/seo-rii/maki/pull/177)).*
- With a journal watermark at or below the segment size, reachable only at
  exact equality in a daemon-validated configuration, every write above it
  still triggers a worker pass, which now syncs and checkpoints (AUD-005).
  *Closed by AUD-053 ([#176](https://github.com/seo-rii/maki/pull/176)),
  which also found that validation keeps the watermark above one segment, so
  only an engine configured directly reached this.*
- The `maki-witness` server configuration file is checked for group and other
  write but not for its owner, and the witness state directory has no owner
  or mode check (AUD-031). *Closed by AUD-075 and AUD-076
  ([#170](https://github.com/seo-rii/maki/pull/170)).*
- AUD-024 bounds HTTP JSON responses only; the WebSocket and gRPC response
  parsers are unchanged. *Closed by AUD-066 and AUD-067
  ([#173](https://github.com/seo-rii/maki/pull/173)).*
- `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback`
  (`review_writeback.rs`) and
  `process_recovery_rewrites_clean_cache_bytes_before_sealing_the_journal`
  (`review_journal_writeback.rs`) let recovery finish and do not detect the
  removal of its prefix rewrite; AUD-006's sweep does. Under page-granular
  writeback (AUD-008), `a_failed_intermediate_sync_stops_append_and_can_resume`
  (`review_journal_pending.rs`) no longer detects the removal of the journal's
  F01 rewrite either; it tests pending-byte accounting and is unchanged.
  *Closed by AUD-064 ([#175](https://github.com/seo-rii/maki/pull/175)): all
  three now fail without their rewrite.*
- The denial texts AUD-042 accepts follow libnbd's and `nbd-client`'s formats
  but have not yet been observed in a privileged run; a mismatch fails closed
  and prints the captured output. *Superseded in part by AUD-153
  ([#375](https://github.com/seo-rii/maki/pull/375)): the disconnect probe runs the helper's own
  `nbd-disconnect` and accepts only the kernel's `Operation not permitted`
  for `NBD_CMD_DISCONNECT`; it has not run against a real kernel either.*
- `CrashableBacking::try_lock` still accepts a directory name (AUD-010 changes
  `MemBacking` only), and the link checker does not verify reference-style
  link definitions (AUD-047). *Closed by AUD-063
  ([#175](https://github.com/seo-rii/maki/pull/175)) and AUD-084
  ([#171](https://github.com/seo-rii/maki/pull/171)).*

## Comprehensive review follow-up (2026-11-14)

This revision addresses twelve actionable findings from the review of
`d2380cf`. The changes preserve the volume format and the existing provider
trust policy. They do not expand the project's qualified deployment scope.

| Finding | Change | Portable regression evidence |
|---|---|---|
| BUG-178: ambiguous or missing final gRPC status | Require one valid final status before accepting a unary result; preserve legitimate remote errors and HTTP proxy failure classification. | `maki-crypto-grpc/tests/review_final_status.rs`, existing initial-status and HTTP-status suites |
| BUG-181: unusable custom CA material | Reject empty, certificate-free, malformed, or invalid-DER bundles in HTTP, gRPC and WebSocket, including a bad certificate mixed with a valid root; accept multiple valid roots using the existing additive policy. | All three providers' `tests/review_ca_bundle.rs`, existing TLS and custom-CA suites |
| BUG-083: capability lookup retains abandoned scheduler work | Cancel the asynchronous retry-safety lookup when the last caller cancels or expires, releasing inputs and the lane slot while preserving live siblings. | `maki-crypto/tests/review_scheduler_capability_cancellation.rs` |
| BUG-183: idle worker misses late checkpoint cleanup failure | Track unfinished journal cleanup independently of the published checkpoint horizon and retry its directory barrier with backoff. | `maki-core/tests/review_checkpoint_cleanup_retry.rs` |
| BUG-184: failed TRIM release blocks healthy ranges | Continue a bounded reclamation sweep past failed windows, then retry from the earliest failure after an independent interval. | `maki-core/tests/review_reclamation_progress.rs`, existing discard/reclamation and power-loss suites |
| BUG-182: fast checker overlooks unusable v3 orphan metadata | Validate the required discard map before claiming an in-geometry orphan can be adopted; preserve fallback warnings and inconclusive I/O errors. | `maki-core/tests/review_orphan_discard_check.rs` |
| BUG-179: disconnect acknowledgement prematurely retires cleanup state | Keep the trusted record until the backend is absent and resource observations are empty; incomplete teardown returns an error and remains retryable. | `maki-privileged/src/exec_tests.rs` |
| BUG-080: supported LV inventory exceeds the record limit | Bound both encoded writes and reads at 256 KiB, reject oversize before creating a temporary file, and enforce the existing 64-LV recovery limit during preflight. | `maki-privileged/src/state_tests.rs`, `exec_tests.rs` |
| BUG-137: hidden LV display names cannot be persisted | Normalize LVM's `[name]` spelling before recording identity; continue rejecting invalid, ambiguous, and hidden configured targets. | `maki-privileged/src/lvm_preflight_tests.rs`, `exec_tests.rs` |
| BUG-168: semantic configuration errors echo input | Report the field and constraint without embedding arbitrary configuration values. | Both helper/API and CLI `review_attach_config_diagnostics.rs` suites |
| DOC-002: failed workload startup still creates data | Gate quickstart writes and PostgreSQL initialization on successful start, active services, and attachment verification inside fail-fast subshells. | `scripts/test_workload_start_validation.py`, using the actual documentation blocks and harmless mocks |
| BUG-180: shared libraries accepted as CLI package inputs | Require executable loader metadata and a nonzero entry point while retaining dynamic/static PIE and ET_EXEC support. | `scripts/test_debian_package.py`, including a native shared-library fixture |

The retained regressions use private files, local providers, fault injection,
virtual clocks, and simulated device observations. They do not demonstrate
physical power-loss safety or qualify a real NBD/LVM/XFS stack. In particular,
delayed kernel disconnect still needs target-stack verification; the helper
now preserves the authority needed to retry it safely.

Six findings remain outside these fixes: first-write synchronization of all
adopted shard maps after reopen (PERF-006); crypto scratch/CPU budgets
(ARCH-007); HTTP JSON node/allocation budgets (ARCH-008); physical memory
retained by checkpoint snapshots beyond logical overlay accounting
(ARCH-009); the fail-closed policy for optional durable-mark I/O errors
(ARCH-010); and the non-atomic stop/recovery scheduling boundary (BUG-177).
Those require separate durability, resource-budget, or lifecycle decisions.
Keep using the documented maintenance serialization procedure for recovery
and stop; these changes do not claim to resolve that race.

Later update (2026-11-17): AUD-024
([#157](https://github.com/seo-rii/maki/pull/157)) makes the HTTP response
parser keep only the values the response mapping reads, so parsing a JSON
response takes about twice its size in memory (the regression bounds it below
three times) instead of about 43 times. That bounds what ARCH-008 describes for
HTTP responses; unselected values are validated but never allocated, so no
separate node-count budget was added. The other five items remain open.

## Sentinel diagnostic contents (BUG-167, 2026-10-26)

Mount identity rejection and an initialization attempt over an existing
sentinel included the observed file contents in their errors. The workload
owns that file, so a malformed sentinel could send decrypted payload bytes
to helper stderr or a service log. Both paths now report a value-free mismatch;
the verifier identifies a missing or unreadable sentinel separately. UUID
case handling and the atomic, no-replacement write/retry protocol are unchanged.

`maki-privileged`'s `review_sentinel_diagnostics.rs` first reproduced both
leaks, then checks `Display`, `Debug`, and the error source chain for arbitrary
text and a different well-formed UUID. It also covers missing sentinels,
preservation of rejected files, creation, and identical case-insensitive
retries. The executor tests use only disposable regular files; no mount,
LVM, NBD, service, or physical qualification runs are implied.

## Further reliability review (2026-09-05)

The next pass started from `aae6ee9` and reproduced seven more defects in the
journal, crypto scheduler, NBD boundary, detach recovery, and control socket.
Every fix followed RED (behavioral regression failure), implementation, and
GREEN. The journal changes preserve the on-disk format and use bounded scratch
space.

| Finding | Status | Result and regression evidence |
|---|---|---|
| BUG-010: detach cannot resume after partial completion | Fixed | Observe current mountinfo and sysfs before each step; skip verified completed work while retaining mount, VG, and live backend checks. Already-disconnected records can be retired only with no remaining mount, VG, NBD, or partition use. Fixture tests cover interrupted steps, foreign mounts/backends, escaped VG names, partition holders, and direct mounts. |
| BUG-011 / O-03: NBD limits are neither advertised nor enforced | Fixed | Publish the nbdkit `block_size` callback and reject invalid read/write lengths, ranges, and alignment before copying write plaintext or entering the engine. Configuration rejects minimum sizes above 64 KiB and maxima outside the NBD wire field. `review_nbd_limits.rs` verifies unchanged data on rejection, valid maximum I/O across reopen, and actual rootless NBD negotiation. |
| BUG-012: cancelled scheduler work retains payload, admission, or RPC slots | Fixed | Pending groups own payload and admission together. Closed callers are removed even behind a live blocked group; shared RPCs are cancelled only when their final caller leaves. Seven `review_scheduler_cancellation.rs` cases cover coalescing, slot waits, queued tails, cancellation of one group in a coalesced batch, and live peers. |
| BUG-013: bounded-error excludes time spent in the scheduler | Fixed | Forward the provider operation budget through wrappers and apply it around the entire scheduler submission. ManualClock tests cover admission, coalescing, waiting for a slot, and RPC under one deadline, with independent peer budgets and an unbounded stall control. |
| BUG-014: control socket bind changes permissions in unrelated threads | Fixed | Remove the process-wide umask override. Prepare the socket inside a mode-0700 directory, apply group/mode, then rename it to the public path. Concurrent mode-0700 directory creation previously produced mode 0600. Tests now preserve that mode, the existing path on failed group lookup, cleanup on failed publication, and Linux's maximum usable public path length. |
| BUG-020: a failed append leaves a corrupt tail after a shorter retry or roll | Fixed | Retain a tail-cleanup flag until truncation and sync succeed; remove unaccepted bytes before retrying, flushing, or sealing. `review_journal_retry.rs` injects a real partial BackingFile write and checks recovery after a shorter retry, roll without retry, and failed cleanup. |
| BUG-021: sync retry or process recovery acknowledges lost journal writeback | Fixed | After actual sync failure, rewrite the accepted pending range, compare an ephemeral streaming fingerprint, and sync before acknowledging. Recovery rewrites each prefix accepted by its scan before sealing. `review_journal_writeback.rs` models lost dirty bits, subsequent power loss, cache changes, self-consistent header mutation, and ranges larger than the 64 KiB buffer. |
| TEST-002: gRPC authentication regression depends on the winning deadline's error string | Fixed | `phase9_daemon.rs` now observes actual server-side Unauthenticated rejections and failed attach, with no rejection for valid metadata. A generic scheduler deadline is valid under BUG-013. The real-socket fixture has a two-second budget; precise deadline behavior remains covered by ManualClock tests. |

Linux iomap can clear dirty bits even when page-cache writeback fails, so the
writeback fixture models a documented kernel behavior. Recovery now pays an
additional read/write pass over accepted journal data; ordinary successful live
flushes avoid it. See the [kernel writeback documentation](https://www.kernel.org/doc/html/v6.17/filesystems/iomap/operations.html#pagecache-writeback).

NBD clients can ignore negotiated sizes, which is why both advertisement and
adapter validation are required. The installed C header and loaded plugin
agreed on the 384-byte prefix, API version 2, and `block_size` offset 376; an
actual nbdkit/libnbd connection reported the configured 4096/4096/8192 tuple.
See the [nbdkit callback contract](https://libguestfs.org/nbdkit-plugin.3.html#block_size).

All RED logs below returned **101** with behavioral failures; all GREEN logs
returned **0**. Filenames are relative to `/home/seorii/logs/`, with private
`.exit.json` sidecars preserving commands and exit status.

| Issue | RED log | GREEN log |
|---|---|---|
| BUG-010 | `maki-fix-bug010-red-20260905T121013.730111Z.log`; partition use: `maki-fix-bug010-partition-red-20260905T122825.502887Z.log` | `maki-fix-bug010-partition-green-20260905T122953.767108Z.log` |
| BUG-011 | `maki-fix-bug011-isolated-red-20260905T122132.775100Z.log` | `maki-fix-bug011-green-20260905T122308.662263Z.log` |
| BUG-012 | `maki-fix-bug012-red-20260905T121106.912502Z.log`; queued tail: `maki-fix-bug012-tail-red-20260905T122059.475151Z.log` | `maki-fix-bug012-tail-green-20260905T122212.004436Z.log` |
| BUG-013 | `maki-fix-bug013-red-20260905T121828.291381Z.log` | `maki-fix-bug013-green-20260905T122641.978514Z.log` |
| BUG-014 | `maki-fix-bug014-red-20260905T124750.878309Z.log`; failed publication: `maki-fix-bug014-publication-red-20260905T125158.193474Z.log` | `maki-fix-bug014-green-20260905T125347.498590Z.log` |
| BUG-020 | `maki-fix-bug020-red-20260905T121354.899842Z.log` | `maki-fix-bug020-green-20260905T121627.739081Z.log` |
| BUG-021 | `maki-fix-bug021-red-20260905T122051.918638Z.log`; valid-header mutation: `maki-fix-bug021-header-red-20260905T122447.223461Z.log` | `maki-fix-bug021-green-20260905T122652.551362Z.log` |
| TEST-002 | `maki-fix-test002-observed-auth-red-20260905T130857.232492Z.log` | `maki-fix-test002-auth-green-20260905T131019.262153Z.log` |

Final Linux verification for this round:

| Check | Result | Exit |
|---|---|---:|
| `cargo fmt --all --check` | Pass | 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass, no diagnostics | 0 |
| `cargo test --workspace --locked` | 484 passed, 0 failed, 7 ignored | 0 |
| `cargo test --workspace --release --locked -- --ignored` | 7 passed, 0 failed | 0 |
| Independent C ABI probe and rootless NBD negotiation | Configured block-size callback layout and 4096/4096/8192 negotiation verified | 0 |

Final baseline process PID `2886645` returned **0**:
`/home/seorii/logs/maki-fix-followup-baseline-final-20260905T131121.236462Z.log`.
Its `.exit.json` and `.summary.json` sidecars record the command and totals.
The release-gates command returned **0** in process PID `2786564`:
`/home/seorii/logs/maki-fix-followup-final-gates-20260905T125637.142287Z.log`.
That earlier combined wrapper returned **1** because of the now-fixed TEST-002
assertion; no production code changed after its successful release-gates step.
The independent C probe was PID `2533875`, exit **0**:
`/home/seorii/logs/maki-fix-bug011-abi-review-20260905T122540.302503Z.log`.

The detach changes use the helper's current mount namespace and require target
qualification for the installed kernel, nbd-client, LVM, XFS, and service
layout. This pass used simulated device observations and private userspace
sockets; it did not perform privileged device operations or deployment. The
existing database, vendor-provider, TLS, and hardware power-loss qualification
limits remain.

## Follow-up review (2026-09-05)

The [project assessment](qualification/historical-reviews/project-review-2026-09-05.md) of `8b06c53` found nine
additional defects and one formatting failure. All nine were reproduced by a
failing regression before implementation, then verified green. Each issue has
its own code commit. The changes preserve the on-disk format and golden vectors.

| Finding | Status | Result and regression evidence |
|---|---|---|
| BUG-001: A/B retries can overwrite the last durable copy | Fixed | Preserve the typed-valid copy by rewriting its exact bytes, syncing the file and its directory before replacing the other side. `review_ab_retry.rs` in `maki-format` and `maki-core` cover all A/B record types, failed sync/restart, sector tearing, lost dirty bits after writeback EIO, and actual volume recovery. The extra preservation write and syncs are a durability cost per update. |
| BUG-002: missing attach configuration skips the dependency | Fixed | `AssertPathExists` fails startup so an ordered `Requires` workload cannot start after that failure. `regression_missing_attach_config.rs` checks the template and evaluates assertions with `systemd-analyze`; dependency syntax was also verified offline. |
| BUG-003: privileged state is below a daemon-owned directory | Fixed | `/run/maki-attach` is root-controlled. Descriptor-relative state access rejects symlinks, unsafe ownership/modes, multiple links, oversized and malformed records. Records bind configuration identity and a unique live NBD backend identifier; pinned devices cannot bypass validation. `state_tests.rs`, `exec_tests.rs`, and `regression_attach_state.rs` cover refusal before side effects, attach/rollback ordering, stale devices, changed mountpoint/VG/LV, and cleanup errors. |
| BUG-004: HalfOpen probe permits leak on early exit | Fixed | A generation-bound guard returns admission on every exit, without charging neutral outcomes as endpoint failures. `review_probe_lifetime.rs` covers request/provider errors, deadline, cancellation, and retry-budget refusal followed by a healthy probe. |
| BUG-005: retired WebSocket connections leave tasks and sockets alive | Fixed | One task owns both socket halves; retirement aborts it and cleans only its generation. `review_connection_lifetime.rs` observes server-side closure after timeout, cancellation, and provider drop, and verifies successor reuse. |
| BUG-006: one SecretBuffer unlocks another buffer's shared page | Fixed | Page references are counted under the same lock as `mlock`/`munlock`; zeroization precedes the final owner's unlock. `review_secret_page_lifetime.rs` checks Linux page state for drop, duplicate, and `into_vec`, lock failures, and full-capacity zeroization in isolated child processes. |
| BUG-007: name-only credential routing overwrites a different source | Fixed | Validation and public provider construction reject one name used with conflicting sources before resolving credentials. `review_credential_sources.rs` also preserves repeated same-source references and distinct names. |
| BUG-008: HTTP error strings contain query credentials | Fixed | Strip the URL from reqwest errors before classification or formatting. `review_redirect.rs` asserts that connection, timeout, and response-body errors omit synthetic secrets and URLs in both Display and Debug. |
| BUG-009: administrators cannot traverse control socket directories | Fixed | Control sockets default to `/run/maki-control/<volume>/control.sock`; packaging gives the admin group traversal through that separate tree and keeps NBD private. `regression_control_packaging.rs` checks effective path access and default/example/custom paths, alongside the existing control integration suite. |
| TEST-001: control regression fixture fails rustfmt | Fixed | `review_control.rs` was formatted after reproducing the check's exit 1. The same check then returned exit 0. |

The RED runs below returned exit **101** with behavioral assertion failures;
TEST-001 returned **1**. Each corresponding focused GREEN run returned **0**.
Logs and per-process `.exit.json` files are local evidence under
`/home/seorii/logs/`; the committed regression suites are the portable evidence.

| Issue | RED log | GREEN log |
|---|---|---|
| BUG-001 | `maki-fix-bug001-format-red-20260905T103601.938579Z.log`; additional writeback case: `maki-fix-bug001-writeback-red-20260905T104307.770996Z.log` | `maki-fix-bug001-format-final-confirmed-20260905T104507.333205Z.log`; volume: `maki-fix-bug001-core-final-20260905T105157.024176Z.log` |
| BUG-002 | `maki-fix-bug002-red-20260905T103242.816339Z.log` | `maki-fix-bug002-green-20260905T103326.120353Z.log` |
| BUG-003 | `maki-fix-bug003-red-20260905T103535.254697Z.log`; target identity: `maki-fix-bug003-detach-target-red-20260905T105013.661352Z.log`; cleanup: `maki-fix-bug003-cleanup-red-20260905T105119.266743Z.log` | `maki-fix-bug003-final-green-20260905T105202.654573Z.log` |
| BUG-004 | `maki-fix-bug004-red-20260905T103222.480448Z.log` | `maki-fix-bug004-green-20260905T103408.635450Z.log` |
| BUG-005 | `maki-fix-bug005-red-20260905T103713.475681Z.log` | `maki-fix-bug005-green-20260905T103941.006699Z.log` |
| BUG-006 | `maki-fix-bug006-red-20260905T104229.660488Z.log` | `maki-fix-bug006-green-20260905T104425.713962Z.log` |
| BUG-007 | `maki-fix-bug-007-red-20260905T103256.830969Z.log` | `maki-fix-bug-007-green-20260905T103422.878678Z.log` |
| BUG-008 | `maki-fix-bug-008-red-20260905T103612.112163Z.log` | `maki-fix-bug-008-green-20260905T103658.813604Z.log` |
| BUG-009 | `maki-fix-bug009-red-20260905T104541.818204Z.log` | `maki-fix-bug009-green-20260905T104647.999531Z.log` |
| TEST-001 | `maki-fix-test-001-red-20260905T103628.521262Z.log` | `maki-fix-test-001-green-20260905T103730.833720Z.log` |

Final Linux verification:

| Check | Result | Exit |
|---|---|---:|
| `cargo fmt --all --check` | Pass | 0 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass, no diagnostics | 0 |
| `cargo test --workspace --locked` | 441 passed, 0 failed, 7 ignored | 0 |
| `cargo test --workspace --release --locked -- --ignored` | 7 passed, 0 failed | 0 |
| Final control packaging + control integration tests | 5 passed after removing reliance on the service umask; format check also passed | 0 |

The full verification process was PID `1512616`, aggregate exit **0**, with log
`/home/seorii/logs/maki-fix-final-gates-20260905T105411.243723Z.log`; its
`.exit.json` and `.summary.json` sidecars record the result and per-check totals.
The final packaging verification was PID `1698849`, exit **0**, with log
`/home/seorii/logs/maki-fix-packaging-final-20260905T110453.725787Z.log`.
The service umask is not an NBD socket-mode guarantee because nbdkit resets it;
the tested access boundary is the restricted runtime ancestor.

The helper now requires nbd-client 3.27.0 or later with netlink and kernel
backend-identifier support. Existing live attachments must be detached with the
old helper before upgrading; legacy device-only records are not imported.
Explicit old control socket paths also need migration. See the
[upgrade procedure](operations.md#upgrading-the-runtime-layout).
*Superseded by AUD-147 ([#375](https://github.com/seo-rii/maki/pull/375)):* the helper connects and
disconnects NBD devices itself and needs no NBD client, only a kernel whose
`nbd` netlink family takes the backend identifier.

This round used Linux fixtures and local sockets without activating services,
creating users/groups, or operating real NBD devices. Offline systemd assertion
and dependency checks do not replace a real service-start campaign. The new
helper protocol still needs target-host qualification; the earlier kernel
NBD/LVM/XFS reports describe older revisions. O-03 and queue deadlines remained
outside those nine fixes and were subsequently resolved as BUG-011 and BUG-013
above. Transport TLS, database, and power-loss qualification limits remain.

## Overall status (2026-09-03)

All 18 findings have code changes with regression tests: the three P0 data
safety defects (M-001 key canary, M-002 roll-vs-promotion, M-003 dirty-flag
ordering) plus fail-closed recovery (M-007, M-009), the bounded journal
(M-004), the wired control plane (M-005, M-017), configuration and transport
hardening (M-008, M-013, M-014, M-015), remote-provider hardening (M-010,
M-011, M-012), the deep checker (M-018), and the privileged helper (M-006,
M-016). Every batch was verified with `cargo fmt`, strict Clippy, and the
full workspace suite on Windows, and the Linux-only paths (Unix sockets,
`statvfs`, the privileged executor, process hardening) under WSL Ubuntu.

A follow-up pass added debug-build sanitizers and randomized suites (see
[Sanitizers and randomized suites](#sanitizers-and-randomized-suites-2026-09-03))
and re-ran the extended release gates, which had not been exercised after the
review changes. That pass found and fixed three more defects: S-01
(checkpointed data read as zeros after an allocation-map or catalog A/B
fallback), S-02 (overlay byte accounting), and S-03 (a healthy volume refused
after segment numbering restarted under a stale durable mark). Widening the
crash model to out-of-order sector persistence then found S-04 and S-05 in
recovery's torn-tail classification.

A second audit of the core, the crypto layer and the operational layers
followed (see [Second audit](#second-audit-2026-09-03-core-crypto-layer-operational-layers)):
27 confirmed findings, each reproduced by a failing test before the fix, among
them recovery accepting never-fsync'd page-cache bytes after a process restart
(K-01), HTTP redirects re-sending plaintext (C-01), the root helper following
symlinks in the mount root (O-01), credentials falling back to environment
variables (O-06), and detach disconnecting the wrong NBD device (O-02). The
final state passes strict Clippy, the full debug workspace suite (every
Unix-only suite included), and all seven `phase*_gate_full` release gates
under WSL Ubuntu, and strict Clippy plus the per-crate suites on Windows.

A third external review (2026-09-05) examined the boundaries where the code's
guarantees meet the operating system's partial failures, real device identity,
and memory ownership (see
[Third review](#third-review-2026-09-05-os-partial-failure-device-identity-memory-ownership)):
ten findings F01 to F10 plus two smaller items, every one confirmed against
HEAD and reproduced by a failing test before its fix. The two durability
findings changed what the journal does after an I/O error: a failed
`fdatasync` is answered by rewriting and verifying the unsynced records
before the next sync, never by a bare retry (F01), and a partial `write_at`
is truncated back to the logical end before anything is appended or sealed
(F03). `CrashableBacking` now models both failure modes by default.

Several of these findings were fixed independently on two branches (the
third-to-fifth passes below and the
[follow-up](#follow-up-review-2026-09-05) and
[further reliability](#further-reliability-review-2026-09-05) reviews); the
merge kept one implementation per finding and both sides' regression tests
wherever they agree. Where a row below names the superseding BUG entry, that
entry's implementation is the one in the tree.

A fourth, self-directed pass then read the normative sections of `SPEC.md`
against the code (see
[Fourth pass](#fourth-pass-2026-09-05-specification-contradictions-and-boundaries)):
eight findings N-01 to N-08, among them backing files created world-readable
against SPEC §8, most of the SPEC §40 required metrics missing, the
`preferred_io` default, key files loaded regardless of their permissions, and
control commands that could hang forever.

What still needs an environment this repository cannot provide:

- Real NBD/LVM/XFS attach, mount-identity verification, rollback, and device
  allocation on a privileged Linux target
  (`docs/qualification/privileged-linux-validation.md`).
- Vendor endpoint qualification of the remote transports, including the new
  batch identity contract (unit echo) and non-retry-safe behaviour.
- Long soaks under sustained writes with injected checkpoint faults, QEMU or
  bare-metal power cuts, and real database campaigns (`docs/testing.md`).
- `memory_lock_mode = "all"` and `require_secure_swap_policy = true` on the
  target distribution's limits and swap layout.

Design limits that remain and are documented: WebSocket and gRPC still have no
TLS (refused explicitly, not downgraded); `tls.server_name` is refused rather
than supported; a missing *last* journal segment cannot be detected without
additional metadata; `madv_dontdump` is honoured through the non-dumpable
process flag rather than per buffer.

## P0 — before storing any real data

| Finding | Status | Change | Regression tests |
|---|---|---|---|
| M-001 wrong key / provider not rejected at attach | Fixed | See [Key canary](#key-canary). Attach also compares the configured provider type and key name with the superblock (`AttachIdentity`, always set by the daemon). The fake provider gained `with_integrity_check(false)` to model an unauthenticated cipher. | `review_attach.rs` (maki-core): `attach_rejects_wrong_key_same_compatibility_id`, `attach_rejects_wrong_key_without_provider_integrity`, `first_attach_binds_key_durably`, `attach_rejects_provider_type_change_with_same_compatibility_id`, `attach_rejects_key_identity_change`, `legacy_volume_is_probed_with_integrity_provider_then_canaried`, `legacy_volume_without_integrity_is_refused`, `canary_transport_failure_is_not_reported_as_key_mismatch`, `canary_from_another_volume_is_rejected`; `review_daemon.rs` (maki-nbdkit, real AES-XTS/GCM-SIV through `attach_from_config`): `xts_wrong_key_is_refused_at_attach`, `provider_type_change_is_refused_at_attach`, `key_identity_change_is_refused_at_attach`; canary golden vectors in `review_format.rs` |
| M-002 automatic roll can drop a durable overwrite from the overlay | Fixed | The volume promotes the overlay to the journal's durable boundary after *every* `append` (including a failed one) and before publishing the new version; `checkpoint` re-promotes from the journal boundary before collecting. A roll whose fdatasync fails now keeps the segment active instead of dropping it, so a later FLUSH still syncs it. | `auto_roll_preserves_previous_durable_overwrite`, `failed_append_after_roll_still_promotes_durable_versions`, `failed_seal_sync_does_not_lose_active_segment_durability` |
| M-003 allocation-map retry can skip the directory fsync | Fixed | `persist_allocations` writes every dirty A/B copy, fsyncs the data directory, and only then clears the dirty flags; a new `checkpoint.alloc_dirsync` failpoint covers the fsync. | `checkpoint_retry_keeps_allocation_dirent_durable`; the failpoint joined `crash_mid_checkpoint_at_every_boundary_recovers_consistently` |
| M-007 recovery misclassifies durable corruption as a torn tail | Fixed | See [Recovery fail-closed rules](#recovery-fail-closed-rules). | `recovery_rejects_missing_first_uncheckpointed_segment`, `recovery_rejects_gap_after_checkpoint_boundary`, `recovery_rejects_full_final_segment_bad_header`, `recovery_rejects_corrupt_middle_record_header_in_final_segment`, `recovery_rejects_oversized_segment_before_allocation`, `recovery_rejects_damage_inside_durable_mark_even_at_the_tail`, `recovery_truncates_volatile_damage_despite_valid_successor`, `recovery_rejects_segment_shorter_than_durable_mark`, plus the bounded-scanner tests in `review_format.rs` |
| M-008 fake provider in the default release feature | Fixed | `maki-nbdkit` has `default = []`; the crate's own tests enable `fake-provider` through a dev-dependency on itself. `parse_and_validate` refuses `provider = "fake"` when the feature is off, so `maki volume create` and attach both fail closed. CI's nightly job builds the release `maki` binary and asserts a fake-provider config is refused. | `fake_provider_is_refused_without_the_feature` (`check_provider_available` with the feature flag passed explicitly, since feature unification makes the runtime flag always true under `cargo test`) plus the CI step |

## P1 — before a limited beta

| Finding | Status | Change | Regression tests |
|---|---|---|---|
| M-004 no automatic checkpointing; journal / free-space bounds unenforced | Fixed | See [Bounded journal](#bounded-journal): a background checkpoint worker (watermark, low free space, interval), a forced journal sync at `limits.max_journal_pending_bytes`, inline reclaim and ENOSPC at `backing.journal_max_bytes`, and fresh fail-closed admission unless free space covers `backing.journal_emergency_reserve_bytes` plus the projected record/segment-header footprint of the request. It also exposes a `Degraded` state and the `maki_backing_free_bytes` / `maki_journal_bytes` / `maki_checkpoint_lag_bytes` metrics. `Backing::free_bytes` (statvfs on Unix) feeds the reserves. Config validation requires `journal_max_bytes >= 2 * journal_segment_size`. | `review_bounded.rs` and `review_r3_space_admission.rs` (maki-core): hard journal bounds, forced sync, fresh high/low observations, exact append boundary, overflow, unknown and query-error rejection |
| M-005 control socket not started by the daemon; no-op reloads | Fixed | `NbdAdapter::open_config` binds the control socket (`control.socket`, default `/run/maki-control/<volume>/control.sock`) on the adapter's runtime before returning and serves `EngineControlBackend` on it; a bind failure fails attach; `shutdown` stops the server and removes the socket. `reload` returns an explicit "NOT applied" error for every section the engine cannot apply at runtime (`retry`, `circuit-breaker`, `batch`, `limits`, `timeouts`, `semaphores`, `endpoints`, `credentials`); only `cache` is applied, and it requires `max_bytes`. `status` reports the engine state, journal size, free space, and checkpoint counters. | `review_control.rs` (maki-nbdkit, Unix): `control_socket_is_created_served_and_removed`, `missing_control_socket_directory_fails_attach` |
| M-006 mount-identity verification is a no-op | Fixed | The Linux executor's `VerifyMountIdentity` step now gathers real observations (`/proc/self/mountinfo` fstype and source through the pure `parse_mountinfo`, `blkid` filesystem UUID, `<mountpoint>/.maki-sentinel`, sysfs NBD `pid` state, a write-fsync-read-remove probe) and runs the existing pure verifier; a failure rolls the attach back. The volume UUID comes from the root-owned attach config or `--uuid` and is required for execution (`--plan` still renders without it). `--init-sentinel` writes the sentinel on an empty filesystem, never overwriting a different value. The unit now carries `AssertPathExists` on the attach config (BUG-002) and documents that dependents must use both `Requires=` and `After=`. | `mountinfo_parsing_finds_the_visible_mount_and_decodes_escapes`, `verifier_rejects_wrong_device_and_missing_sentinel`, `execution_requires_a_volume_uuid_but_plan_rendering_does_not` (maki-privileged); `plan_mode_works_without_uuid_but_execution_requires_it` (maki-attach process). Real mount/rollback runs need the privileged Linux target (`docs/qualification/privileged-linux-validation.md`). |
| M-009 A/B reader collapses I/O errors into "invalid copy" | Fixed | `AbStore` reports any I/O failure other than not-found as an error; empty, short, and CRC-invalid copies remain "invalid". `create_volume` writes both checkpoint-state copies (sequence 0) and recovery requires a valid copy on every volume instead of defaulting to 0. | `recovery_requires_valid_checkpoint_state`, `recovery_surfaces_hard_io_error_on_checkpoint_state`, `ab_load_reports_hard_io_errors_instead_of_masking_them`, `ab_load_treats_missing_empty_and_corrupt_sides_as_invalid_copies`, `create_volume_writes_checkpoint_state_and_durable_mark` |
| M-010 retry ignores `retry_safe`; no absolute deadline | Fixed | `DispatchConfig` carries `retry_safe` and `max_operation_time`. A non-retry-safe provider is sent a request at most once (no retry, no failover; the WebSocket transport's transparent reconnect-and-resend is disabled too). *Refined by AUD-068 ([#174](https://github.com/seo-rii/maki/pull/174)):* an attempt whose transport proves that no request byte was written does not count as a send, so until one may have been sent the request fails over and, under the availability policy, is retried. `bounded-error` is an absolute deadline measured on the injectable clock: backoff sleeps are capped to the remaining time and an in-flight RPC is abandoned when it expires (`deadline_exceeded_total`). Retry budgets are now endpoint-local (SPEC §32) instead of one bucket for the set. | `review_dispatch.rs` (maki-crypto): `non_retry_safe_provider_is_never_retried`, `retry_safe_provider_fails_over_within_the_pass`, `bounded_error_obeys_wall_clock_deadline_during_an_rpc`, `retry_backoff_never_sleeps_past_the_deadline`; `non_retry_safe_websocket_never_resends_after_a_transport_failure` (maki-crypto-websocket) |
| M-011 unvalidated endpoints enter the serving pool | Fixed | `EndpointSet::with_quarantine` admits only validated endpoints. At attach the daemon first probes each endpoint on its own (three attempts, spaced by the retry delay) so an unreachable *reference* can no longer poison the check, cross-validates the reachable ones against the first reachable endpoint, quarantines the rest, and refuses attach when nothing is reachable or an endpoint is proven non-interchangeable. A validator reruns the cross-endpoint check for quarantined endpoints against a validated one under the real volume context, at most once per breaker interval; proven non-interchangeability excludes the endpoint permanently. *Changed by AUD-110 ([#343](https://github.com/seo-rii/maki/pull/343)):* after an inconclusive attempt (a transport error, a timeout, a malformed reply from either endpoint) the validator runs again after `circuit_breaker.open_initial`, the spacing doubling after each further inconclusive attempt up to `circuit_breaker.open_max`, and only proof that the endpoint serves another contract excludes it permanently. `endpoint_status()` exposes the flags. Retry budgets are per endpoint, charged only to repeat attempts on that endpoint. | `unverified_endpoint_never_enters_serving_pool`, `proven_incompatible_endpoint_is_excluded_permanently`, `capabilities_come_from_a_validated_endpoint` (maki-crypto) |
| M-012 reordered batch results undetected (WebSocket, positional HTTP) | Fixed | WebSocket response items must echo `unit` in request order (missing, reordered, duplicated, or wrong echoes are `Contract` errors); HTTP batch layouts require `item_index_path` at validation; gRPC already echoed `unit_index`. SPEC §18 now states the identity contract. | `ws_rejects_reordered_batch_items`, `ws_rejects_missing_unit_echo`, `ws_rejects_wrong_unit_echo`, `ws_accepts_correct_unit_echo` (maki-crypto-websocket); `http_batch_layout_requires_unit_echo` (maki-format) |
| M-013 incomplete configuration validation; placebo settings | Fixed | `validate_settings` and `validate_provider_sections` (see [Configuration](configuration.md#validation-rules)): positive counts and byte limits, finite ratios and probe rates, ordered delay and breaker ranges, batch targets within maxima, capability mode, bounded-error timing, NBD size ordering, cache and control values, memory-lock mode, provider-specific required and forbidden sections, endpoint URL parsing, and the `keyring` source refused. The `[security]` section is now applied by `maki_nbdkit::security::apply` before attach (Linux, fail closed): `disable_core_dump` via `prctl` + `RLIMIT_CORE`, `memory_lock_mode = "all"` via `mlockall`, `"secure-buffers"` via per-`SecretBuffer` `mlock` (opt-in in `maki-crypto`, failures counted), `require_secure_swap_policy` via `/proc/swaps` plus dm-crypt detection; `madv_dontdump` is honoured through the non-dumpable flag and validation refuses it without `disable_core_dump`; `cache.lock_memory` follows the lock mode and validation refuses it with `off`. The posture is reported under `security` in `status`. Non-Linux hosts report `unsupported-platform`. The secure-swap policy defaults to off (explicit production opt-in; the shipped example enables it). | `review_config.rs` (maki-format): `zero_and_inverted_bounds_are_rejected` (28 cases), `capability_mode_and_availability_policy_are_checked`, `keyring_credential_source_is_refused`, `local_provider_requires_key_and_rejects_transport_sections`, `duplicate_or_empty_endpoint_names_are_rejected`, `defaults_still_validate`; `review_security.rs` (maki-nbdkit): `inconsistent_security_settings_are_rejected_at_validation`, `swap_parser_is_strict`, `posture_is_recorded_and_reported`, `linux_disables_core_dumps_for_real` (Linux); `page_locking_is_opt_in_and_accounted` (maki-crypto) |
| M-014 production sample cannot attach | Fixed | `packaging/examples/postgres-prod.toml`, the SPEC §57 example, and the `full_config.toml` fixture now carry complete `[crypto.http.encrypt]` / `[crypto.http.decrypt]` batch mappings with unit echo and a credential-referenced bearer token; validation requires both mappings for `remote-http`. | `production_sample_and_full_fixture_validate`, `remote_http_requires_endpoints_and_both_mappings` (maki-format); `production_sample_builds_provider_successfully`, `production_sample_fails_without_its_credential` (maki-nbdkit `review_sample.rs`) |
| M-015 WebSocket / gRPC without TLS | Fixed | Validation refuses plaintext `http://`, `ws://`, and gRPC `http://` endpoints unless the host is loopback, refuses `wss://` / gRPC `https://` / transport TLS sections as not compiled in, and rejects URL userinfo. The HTTP provider fails closed on unreadable or invalid CA and client-certificate files, applies `client_key` from its credential source, and refuses `server_name` instead of ignoring it. The daemon's credential router reads path-like names as files. | `plaintext_transports_are_loopback_only`, `websocket_and_grpc_require_their_sections_and_accept_tls` (cited here originally as `..._and_reject_tls`; since WSS and gRPC TLS were implemented it accepts `wss://` and gRPC `https://` and refuses an unreadable transport `ca_file`), `tls_files_must_exist_and_server_name_is_refused`, `endpoint_url_parsing_and_loopback_detection` (maki-format); `unreadable_tls_material_refuses_the_provider`, `client_key_credential_is_appended_to_the_identity` (maki-nbdkit) |
| M-016 privileged attach: allocation, rollback, config-driven execution | Fixed | `maki_privileged::config` loads `/etc/maki/attach/<volume>.toml` (`packaging/examples/attach.toml`) and applies argument hygiene to every value (no option-like values, canonical absolute paths, LVM name charset, UUID shape). The plan carries the block size into `nbd-client -b` and `blockdev --setbsz`, and can leave the NBD device as `/dev/nbd<auto>`: the executor allocates the lowest free device from sysfs under `/run/maki-attach/attach.lock`, binds it into every step, and waits for readiness after connect. `rollback_steps` derives the compensating steps for the executed prefix and the executor runs them in reverse on any failure, reporting rollback failures. | `config_resolves_defaults_and_auto_device`, `overrides_win_and_are_validated`, `argument_hygiene`, `attach_plan_binds_the_allocated_device_everywhere`, `nbd_connect_uses_the_configured_block_size`, `init_sentinel_adds_a_write_step_before_verification`, `rollback_reverses_the_executed_prefix`, `free_nbd_allocation_picks_the_lowest_unconnected_device` (maki-privileged); `option_like_values_are_rejected_before_planning`, `attach_config_drives_the_plan` (maki-attach process) |
| M-017 control-socket group ownership | Fixed | `bind_control_socket` resolves `control.group` with `getgrnam_r`, `chown`s the socket to it and only then applies mode 0660, before any client can connect; an unknown group fails the bind. `packaging/sysusers.d` adds `maki` to `maki-admin` so the unprivileged daemon may perform that `chgrp`. | `review_uds.rs` (maki-control, Unix): `bind_sets_mode_replaces_stale_socket_and_cleans_up`, `bind_refuses_missing_directory`, `unknown_group_is_an_error`, `root_group_resolves_to_gid_zero` |
| M-018 offline checker too shallow | Fixed | `maki_core::check::deep_check` (exposed as `maki-check --deep` and `maki check <config> --deep`) runs the fast checks, takes the volume lock, then inspects both checkpoint-state copies (requiring one), the key canary, the durable mark, the whole journal through the recovery scanner refactored into a read-only `scan_journal` that reports the repairs it would make, and every allocated slot through the real slot reader. The fast check remains for volumes without data. | `review_check.rs` (maki-core): `deep_check_passes_on_a_healthy_volume_with_data_and_journal`, `deep_check_finds_slot_damage_the_fast_check_misses`, `deep_check_requires_checkpoint_state`, `deep_check_reports_journal_corruption_and_missing_segments`, `deep_check_tolerates_a_torn_tail_and_reports_the_repair`, `deep_check_refuses_to_race_an_attached_volume`; `review_deep.rs` (maki-check binary, real filesystem) |

## Follow-up audit (2026-09-03)

Issues found while re-reading the code after the review, all fixed with tests:

| Issue | Change | Regression tests |
|---|---|---|
| `[crypto.batch] target_*` / `max_wait` and `[limits] max_pending_crypto_*` / `max_ciphertext_bytes` were parsed and validated but nothing consumed them (the `Batcher` and `BoundedQueue` helpers had no call sites) | `maki_crypto::scheduler::BatchScheduler` coalesces concurrent requests into bounded provider calls (targets, maxima, `max_wait`, whole requests only, separate encrypt/decrypt lanes bounded by the pending limits). The daemon wraps remote providers with it; local providers are called directly. Counters are reported in `status` and metrics. | `review_scheduler.rs` (maki-crypto): `concurrent_requests_are_coalesced_into_one_provider_call`, `lone_request_flushes_after_max_wait`, `requests_are_never_split_and_max_items_is_respected`, `provider_error_reaches_every_request_in_the_batch`, `decrypt_lane_is_independent_and_round_trips`, `pending_work_is_bounded`, `capabilities_pass_through` |
| A FUA write whose fdatasync failed was already appended to the journal but never published to the overlay: live reads showed the old version while a later barrier or a restart surfaced the new one | `Volume::write_ct` publishes as soon as the append succeeded and only then performs the FUA sync, so the live view can never lag the on-disk journal | `failed_fua_sync_still_publishes_the_journaled_record` (maki-core) |
| `backing.journal_max_bytes >= 2 * journal_segment_size` still allowed a limit too small for the largest request to fit after an inline reclaim, leaving writes refused with ENOSPC forever | Validation requires two segments plus the largest request (`nbd.maximum_io` in records of `32 + max_ciphertext_size`) | `journal_hard_limit_must_leave_room_for_a_reclaim_and_the_largest_request` (maki-format) |
| The dispatcher computed its deadline with unchecked `Duration` addition | `saturating_add` | covered by the existing deadline tests |
| The plaintext cache found its LRU victim with a linear scan over every entry; a full cache of tens of thousands of units evicts on every insert, making the hot read path quadratic | Recency is an ordered index keyed by the monotonic tick, so eviction and touch are O(log n) | `eviction_order_survives_many_entries_and_touches` plus the existing cache suite |
| The superseded `maki_crypto::batch::Batcher` had no call sites | Removed; `BatchScheduler` is the batching layer | build |
| The two security tests in one binary raced on the process-global posture | Serialized with a test-local lock | `review_security.rs` |

## Sanitizers and randomized suites (2026-09-03)

Debug-build invariant checkers ("sanitizers") now run after every mutation of
the core structures, and new randomized suites drive the system through fault,
concurrency, and corruption spaces the hand-written tests did not reach. No
nightly toolchain is available on the development machines, so Miri and the
LLVM sanitizers are not part of this pass; the checkers below are ordinary
debug assertions that release builds compile out.

| Sanitizer / suite | What it checks | Result |
|---|---|---|
| `Overlay::check_invariants` (debug, after every publish/promote/retire; sampled above 4096 units) | byte accounting equals the live versions; a durable version never leads the latest one and equal sequences carry equal bytes; every version at or below the promoted boundary is promoted; pending promotions are above the boundary and name live units | found S-02 |
| `JournalWriter::check_invariants` (debug, after every append/sync/roll/seal/delete) | `durable <= appended = next - 1`; sealed segments strictly ordered, contiguous, never larger than their header allows, and fully durable; the active segment ends at `next`; synced prefix consistent with the unsynced flag and with `durable` | clean |
| `Volume::check_invariants` (debug, after every write/flush/checkpoint and at recovery) | `checkpoint <= durable`; both sub-audits; no overlay version beyond the appended sequence | clean |
| `review_fuzz.rs` (maki-format) | every on-disk decoder (superblock, segment header, durable mark, canary, slot header, allocation map, catalog, checkpoint state) rejects every single-bit flip of its image and never panics on 3000 random mutations or on garbage; the journal scanner never panics and never reports a torn tail inside the durable prefix; endpoint URL parsing and `validate()` on a mutated production sample never panic | clean |
| `review_stress.rs` (maki-core) | 4 writers + 2 readers on a 128 KiB journal with a 15 ms checkpoint worker and provider chaos, per-unit oracle of issued/acknowledged/durable stamps: no torn reads, no stamp that was never issued, journal and overlay stay bounded, the engine returns to `Ready`, and after a crash every FUA/flush-acknowledged stamp (or a newer acknowledged one) survives; plus a sweep of all 15 persistence failpoints through the engine with recovery to `Ready` and a crash check | clean |
| `review_corruption.rs` (maki-core) | 80 rounds of random single-file damage (bit flips, truncation, zeroed ranges) to any volume file after a checkpointed workload: the deep checker never panics; attach either refuses (journal or checkpoint-state damage only) or serves every unit exactly; data-shard damage yields EIO, never zeros or another version | found S-01 |
| `review_stress_crypto.rs` (maki-crypto) | scheduler and dispatcher under 48 concurrent tasks with random request shapes and random retryable / throttled / endpoint-fatal faults: request order and unit identity kept, every failure classified transient, no hangs, pending counters and permits return to zero, service resumes once faults stop | clean |
| `review_cache_model.rs` (maki-cache) | 12 seeds x 4000 random put/get/invalidate/resize/TTL steps against an independent LRU model: exact hit/miss, eviction order, byte accounting, budget after every step | clean |
| Extended gates (`cargo test --workspace --release -- --ignored`, Linux) | the historical `phase*_gate_full` randomized crash/recovery, endpoint, breaker, database-simulation and integration gates, re-run against the review changes | found S-03; all seven pass after the fix |
| Wider crash model (`CrashableBacking::with_tearing`, now used by the phase 3, 11 and 12 crash cycles and the engine stress) | any unsynced write, not only the last one, may persist partially: a sector-aligned prefix, or every sector but one (out-of-order sector persistence) | found S-04 |

### Findings

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| S-01 | **Checkpointed data read as zeros after an A/B fallback.** The allocation map and the shard catalog are A/B records. When the newest copy is unreadable (a torn write during a crash, or later damage to that one file) recovery legitimately falls back to the previous generation, which does not list the slots filled by the last checkpoint, nor a shard that checkpoint created. `read_slot` treated "bit 0" as unwritten, so those units silently read as zeros, and the journal segments that could have re-supplied them had already been deleted. Found by `review_corruption.rs` on its first run (truncating `shard-0000000a.alloc.a`). | Slot headers are authoritative (SPEC §22 and §27 updated). At open the store adopts shard data files the catalog copy does not list, and for a shard with an invalid or absent allocation copy it probes every cleared slot's header and marks the ones that decode for their unit; `read_slot` also probes a cleared slot before answering zeros. Repairs are persisted by the next checkpoint even when nothing new is durable, and `deep_check` reports them as warnings. A cataloged shard with no valid allocation copy still refuses attach (offline repair territory). | `allocation_map_fallback_never_reads_checkpointed_data_as_zeros`, `catalog_fallback_never_hides_a_shard`, `deep_check_reports_allocation_repair_and_idle_checkpoint_persists_it`, `missing_allocation_maps_refuse_attach`, `recovery_under_random_single_file_corruption` (maki-core `review_corruption.rs`) |
| S-02 | Overlay byte accounting drifted when a durable version was replaced by one of a different length (`promote` added the new length only when no durable copy existed yet). Invisible in practice because a volume's ciphertext length is fixed, but the admission counters would be wrong for a provider with variable overhead. | `promote` subtracts the replaced durable copy; the overlay sanitizer enforces exact accounting. | overlay sanitizer under every maki-core suite |
| S-03 | **Healthy volume refused after segment numbering restarted under a stale durable mark.** The M-007 durable mark is a plain, never-fsync'd, never-cleaned file naming the newest segment the writer synced. After recovery every surviving segment is sealed and none is active, so a checkpoint with nothing to add deletes *all* of them; recovery then restarted segment numbering at 0. The next crash left a fresh `seg-0` (header only) next to the old mark ("seg-0 durable to 2336 bytes"), and recovery failed closed with "durable mark covers 2336 bytes but file has 48". Availability, not durability: no data was at risk, but the volume could not attach. Found by `phase3_gate_full` (seed 172) in the release gates, which had not been re-run after M-007. | Recovery continues segment numbering above both the surviving segments and the mark's segment index, so an index is never reused while a mark for it can exist; the writer also points the mark at each new segment when it rolls (header-only durable size). | `segment_indexes_never_fall_below_the_durable_mark` (maki-core `review_storage.rs`); `phase3_gate_full` |
| S-04 | **Healthy crash state refused when the durable mark was lost.** The mark is written without fsync, so the crash it is meant to describe frequently loses it (or leaves an older mark naming a deleted segment). Recovery then fell back to the pre-M-007 heuristic for the final segment, which classifies a damaged record *followed by an intact one* as corruption in the durable body. Unsynced records persist in any order, so a torn record 2 next to an intact record 3 is a normal crash state; the volume was refused with "payload CRC failure in durable body". Availability only. Found within seconds by the widened crash model in `phase3_gate_full` (seed 1) and `phase11_gate_dbsim_full`; the old model only ever tore the last write of a file, which can never produce that pattern. | With no mark naming the final segment, recovery treats only the segment header as proven durable: all damage beyond it is a torn tail (truncate), never corruption. The heuristic mode of the scanner is no longer reachable from recovery or the deep check. The cost is documented: bit rot inside the final segment's synced-but-unmarked records is truncated rather than reported when the mark was lost. | `lost_or_stale_mark_never_turns_a_torn_middle_record_into_corruption` (maki-core `review_storage.rs`); `phase3_gate_full`, `phase11_gate_dbsim_full` with the wider crash model |
| S-05 | **Zero-filled tail accepted, then refused one crash later.** A torn unsynced record can survive a crash as an all-zero tail of the final segment (the file grew, none of the record's sectors arrived). The scanner treated that as a clean preallocated end and recovery left it in place. The writer then sealed the segment as-is when it opened a successor, and the next recovery, for which the segment was non-final and therefore durable in full, refused the volume with "zeroed record inside durable prefix". Availability only; found by the widened crash model (`phase3_gate_crash_recovery_smoke` seed 78, `phase11_gate_dbsim_full`). | Recovery normalizes the final segment to exactly its records: a clean scan that ends before the file length now produces a `Truncate` repair (fdatasync'd like every repair), so no sealed segment ever carries a zero tail. | `zero_tail_of_final_segment_is_truncated_before_it_can_be_sealed` (maki-core `review_storage.rs`); the crash gates |

## Second audit (2026-09-03): core, crypto layer, operational layers

After the sanitizer pass, three independent adversarial code reviews (core
engine and recovery; crypto layer and transports; daemon, control, privileged
helper, format and backing) produced 32 candidates. Each was reproduced with a
failing test before being fixed; the ones below survived verification. IDs:
K (core), C (crypto), O (operations).

### Durability and data

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| K-01 | **Recovery declared page-cache bytes durable and never synced them.** A process crash (SIGKILL, OOM, panic) is not a power loss: records appended without FUA sit in the page cache and are read back by the next recovery, which accepted them, sealed their segment and resumed with no active segment. A later FLUSH acknowledged them with nothing to sync (SPEC §12 violated by the next power loss), and the first append after the restart opened a successor, after which the same power loss tore a *non-final* segment and the volume was refused. | Recovery fdatasyncs every surviving segment, fsyncs the journal directory and publishes a durable mark for the final segment before handing the journal to the writer. | `recovery_fsyncs_page_cache_records_before_a_flush_acknowledges_them`, `resumed_segment_is_durable_before_a_successor_is_opened` (maki-core `review_audit.rs`) |
| K-08 / C-08 | Decrypted plaintext was checked against *any* size the provider declares, not the volume's unit size; a short unit was sliced out of range (a panic caught only at the NBD boundary), a long one silently re-encrypted at the wrong length. Oversized or empty ciphertexts could reach the journal and turn the next recovery into "corruption". | `CheckedProvider::pinned` and the engine pin decrypt results to the unit size and refuse ciphertexts above the volume maximum, as `Contract` errors. | `short_plaintext_is_a_contract_error_not_a_panic` (maki-core), `checked_provider_pins_decrypt_length_to_the_unit_size` (maki-crypto `review_audit2.rs`) |
| K-06 | A CRC-valid journal record naming a unit beyond the device, or carrying a payload above the volume's ciphertext size, was replayed and then checkpointed into an out-of-range shard that the next open rejects. | The scanner classifies such records as corruption. | `record_with_out_of_range_unit_is_corruption_not_replay`, `record_with_oversized_payload_is_corruption_not_replay` |
| C-01 | **HTTP redirects were followed.** reqwest's default policy replays the POST body (plaintext on encrypt) to whatever `Location` the endpoint names, possibly another host over plaintext HTTP, and turns 301/302/303 into a body-less GET parsed as ciphertext; a redirect loop was even classified retryable. | Redirect policy `none`; any 3xx is an `EndpointFatal` (fail over, never re-send). | `redirects_are_never_followed` (maki-crypto-http `review_redirect.rs`) |
| C-09 | The self-test could not tell a pass-through provider (debug/no-op endpoint, a response mapping echoing the request) from a real one, and never exercised a claimed context binding; attaching such a provider persists plaintext. | The self-test refuses ciphertext equal to plaintext and, when context binding is claimed, a decrypt under another unit index that yields the same plaintext. | `self_test_rejects_a_pass_through_provider`, `self_test_checks_a_claimed_context_binding` |
| O-01 | **The root helper followed symlinks in the tenant-writable mount root.** The rw probe opened `<mountpoint>/.maki-rw-probe` with create+truncate and the sentinel with an unbounded read: a planted symlink let the workload make root truncate any file, a FIFO could block the attach unit forever, a huge sentinel could exhaust memory. | Probe files are `O_CREAT\|O_EXCL\|O_NOFOLLOW` under an unpredictable name and read back through the same descriptor; the sentinel is opened `O_NOFOLLOW\|O_NONBLOCK`, must be a regular file and is read to a 4 KiB bound. | `sentinel_symlink_and_oversized_file_are_ignored`, `rw_probe_never_overwrites_a_planted_target` (maki-privileged, Linux) |
| O-06 | Header, metadata and TLS-key credentials ignored their declared `source`: a path-like name always read a file, anything else tried the systemd directory and silently fell back to `MAKI_CREDENTIAL_*` environment variables, so a production daemon could attach on a stray variable. | The router dispatches on the declared source exactly like the volume key does; `credential` fails closed without `CREDENTIALS_DIRECTORY`, undeclared names are refused. | `credential_source_never_falls_back_to_the_environment` (maki-nbdkit `review_sample.rs`) |

### Availability

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| K-02 | A checkpoint that stored its state but failed to delete the covered segments (transient unlink error, or the deletions lost in a crash) left them on disk forever: every later checkpoint took the "nothing new" path, the journal stayed at its hard limit, and every write failed with ENOSPC while the engine reported Ready — across restarts. | The idle checkpoint path deletes covered segments and fsyncs the journal directory; the worker runs when covered segments exist even with nothing new to apply. | `idle_checkpoint_reclaims_covered_segments_left_by_a_failed_deletion` |
| K-03 | `persist_allocations` (S-01) stored the catalog before the adopted shard's allocation map; a failure in between produced a cataloged shard with no allocation copy, which every later attach refuses. | Allocation maps are stored and the data directory fsynced before the catalog commits, the same order as shard creation. | `adopted_shard_is_never_cataloged_without_an_allocation_copy` |
| K-04 | The per-unit lock table swept idle entries on *every* insertion once it held more than 8192 entries, under the global mutex: with many locks held (large requests on small units, parallel callbacks) each unit acquisition scanned the whole table. | Sweeps are amortized: the next one runs only once the table has doubled since the last. | `sweeps_are_amortized_while_many_locks_are_held` (engine unit test) |
| K-07 | Recovery required every surviving segment to be contiguous, including checkpoint-covered ones; a crash that lost one covered unlink but not its neighbour's produced a "gap" and refused the volume. | Only records above the checkpoint must be contiguous (the first uncovered segment still has to bridge it); the journal sanitizer knows about covered holes. | `partially_resurrected_covered_prefix_is_accepted`, `gap_after_the_checkpoint_boundary_is_still_refused` |
| C-03 | Validation of a quarantined endpoint ran inline in every request with no deadline: one black-holed endpoint stalled every request behind its transport timeout, about once per validation interval, forever. | Validation runs in a background task (one per endpoint at a time); requests never wait for it. | `quarantined_endpoint_validation_never_blocks_requests` |
| C-04 | The batch scheduler awaited each provider call inline: one batch per round trip per lane, so the configured inflight limits were unreachable, "least inflight" selection degenerated to config order, and one stalled batch blocked every request behind it. | Batches are dispatched on their own tasks under a per-lane inflight bound (`limits.max_crypto_inflight_batches`). | `lane_keeps_several_batches_in_flight`, `lane_honours_its_inflight_limit` |
| C-05 | WebSocket TCP connect, handshake and send had no timeout and ran under the connection mutex: a peer that accepts and never answers held every request on the provider forever; a request timeout did not retire the connection, so every later request burned the timeout on the same dead socket. | Connect and send are bounded by the transport timeout; a timed-out request retires its connection so the next one reconnects. | `connect_to_a_silent_peer_fails_within_the_timeout`, `request_timeout_retires_the_connection_so_the_next_request_reconnects` (maki-crypto-websocket `review_hang.rs`) |
| C-06 | An RPC abandoned at the operation deadline never returned its inflight slot (a permanent drift in `endpoint_inflight`, deprioritizing the endpoint forever) and the deadline was charged to whichever endpoint happened to be in flight, opening its circuit. | Inflight is released by a drop guard; a deadline error is not an endpoint failure and charges nothing. | `deadline_abandoned_rpc_releases_inflight_and_does_not_charge_the_breaker` |
| C-07 | With `success_threshold` above `half_open_max_requests` (an accepted configuration) the breaker admitted one probe, counted its success and then admitted nothing ever again: a permanent stall on a single-endpoint volume. | Probe slots are returned when a probe completes; the bound applies to probes in flight. | `half_open_admits_new_probes_as_earlier_ones_complete`, `failed_probe_reopens_and_the_next_window_admits_again` |
| O-02 | **`maki-attach detach` with the packaged default (device on auto) disconnected the wrong device.** The detach plan carried the placeholder, the executor allocated the lowest *free* device for it and disconnected that, leaving the real device connected — and possibly racing another volume's attach, which held the lock while detach did not. | The executor records the bound device at attach; BUG-003 extends this to a trusted identity record under `/run/maki-attach/<volume>.nbd`. Detach resolves and verifies it under the attach lock before any side effects. | `detach_with_an_unrecorded_auto_device_is_unresolved_and_never_allocates` (maki-privileged) |
| O-04 | One `accept` error (EMFILE/ENFILE during a client burst) ended the control-socket loop and unlinked the socket for the rest of the daemon's life. | Accept errors are logged and retried after a short pause. | `accept_errors_do_not_kill_the_control_server` (maki-control, Linux, best effort) |
| O-05 / K-05 | Configuration accepted geometries the format layer cannot serve: a unit whose ciphertext exceeds the journal scanner's 16 MiB record bound (writes succeed, the first re-attach is refused as corrupt with the data intact), and shards with more than 2^32 units (the allocation map asserts on the first write). | `Geometry::compute` and validation refuse both. | `geometry_rejects_units_the_journal_or_allocation_map_cannot_hold`, `units_whose_ciphertext_exceeds_a_journal_record_are_rejected`, `shards_with_more_units_than_the_allocation_map_indexes_are_rejected` (maki-format) |
| O-07 | If `nbd-client` connected but the device did not become ready within the wait, the connect step was not recorded as executed and the rollback left the device connected; a retry connected a second device to the same volume. | The connect counts as executed as soon as `nbd-client` succeeds, so a readiness timeout rolls it back. | executor restructuring (Linux, root-only path; covered by the attach validation run) |
| O-08 | `docs/configuration.md` promised an `nbd.device_block_size` cross-check that did not exist; a mismatch made every kernel request fail alignment. | `nbd.device_block_size` is optional and, when set, must equal the volume's. | `nbd_device_block_size_must_match_the_volume` (maki-format) |
| O-09 | `maki reload <cfg> cache` could never succeed (the CLI sent no size) and the verb answered `ok` on a daemon running without a cache. | `maki reload <cfg> cache --max-bytes N`; the verb refuses when there is no cache to resize. | `reload_cache_without_a_cache_is_refused_not_silently_accepted` (maki-nbdkit, Unix) |
| O-10 | `AbStore::store` chose the side to overwrite by raw generation while `load` used the typed decode: a side that passes CRC but does not decode as the record type counted as newest, so the next store overwrote the only loadable copy. | The target side is chosen from the typed view; the generation still moves past every raw generation. | `ab_store_overwrites_the_side_that_does_not_decode_as_the_record_type` (maki-format) |

### Hygiene

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| C-02 | `SecretBuffer::drop` zeroized before unlocking, and zeroizing empties the vector, so `munlock` saw an empty range: with `memory_lock_mode = "secure-buffers"` every dropped buffer stayed pinned until `RLIMIT_MEMLOCK` made all later locks fail silently. | Originally unlocked before zeroize; BUG-006 now retains the original address range in a shared page-lock guard, zeroizes first, then releases the lock ownership. | `dropping_locked_buffers_releases_their_pages` (maki-crypto, Linux) |
| C-10 | `max_pending_crypto_items` took one permit per *request*, not per item. | Per-item permits. | `pending_item_limit_counts_items_not_requests` |
| C-11 | Resolved credentials (headers, query values, gRPC metadata, the mTLS private key, URL userinfo) lived in `#[derive(Debug)]` specs. | Manual `Debug` implementations redact values. | `spec_debug_output_redacts_credentials` (http), `spec_debug_output_is_redacted` (websocket) |
| K-09 | Plaintext left `SecretBuffer` into plain `Vec<u8>` on the read and write paths of the adapter. | `Engine::read_secret` returns a zeroizing buffer; the adapter copies from it and wraps incoming writes. | build (the daemon path only) |
| O-11 | The control socket existed with `0777 & ~umask` between `bind` and `chmod`. | `bind` runs under umask `0117`. | existing mode assertions |

The temporary umask approach for O-11 was replaced by private preparation and
atomic publication in BUG-014 above because a umask override also affected
unrelated threads and child processes.

The NBD maximum-I/O gap (O-03) and deadline starting only at dispatch (C-04
note) were subsequently fixed as BUG-011 and BUG-013 in the
[further reliability review](#further-reliability-review-2026-09-05).

Still documented as limits:

- The checkpoint worker can hold the volume lock for the duration of one
  checkpoint after the last engine handle is dropped (K-10).
- The accept-error test creates descriptor pressure in-process and is
  therefore best effort.

## Third review (2026-09-05): OS partial failure, device identity, memory ownership

The third external review (Korean, 2026-09-05) examined the source archive
of HEAD and rated the structure and test base sound while identifying where
the guarantees break at the operating-system boundary: partial I/O failures,
real device identity, and memory ownership. It listed one P0 candidate,
six P1 and three P2 findings (F01 to F10), and two smaller hardening items.
Every finding was confirmed against the tree (the review's line numbers
matched), reproduced by a failing test, and fixed in the same change; the
review's own verification limits (no Rust build, no NBD mount, no memory
dump) were closed by running the new tests, including the Linux-only ones
under WSL.

### Durability (P0 candidate and P1)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F01 | **A failed `fdatasync` was retried by calling it again.** Linux marks the dirty pages clean when writeback fails, so the retry succeeded without writing anything: the second FLUSH (or a later FUA) acknowledged records that never reached the disk, and recovery after a restart did the same for page-cache bytes (K-01 only synced them). | Same finding as BUG-021, whose implementation is the one in the tree: the writer fingerprints every record accepted since the last successful sync and, once a sync has failed, re-reads and rewrites that range in 64 KiB chunks, verifies the fingerprint, and only then syncs again; changed or lost bytes refuse the barrier. Recovery rewrites and verifies every accepted segment prefix before it syncs. `status`/`metrics` expose `journal_sync_failures_total` and `journal_writeback_uncertain`. `CrashableBacking` models the Linux behaviour by default (a failed sync loses its dirty writes but keeps them readable; `set_lenient_sync_failures(true)` restores the old model). *Superseded by AUD-008 ([#165](https://github.com/seo-rii/maki/pull/165)):* a failed sync's writes stay readable but uncertain (a later crash may keep them, whole or torn; `crash_all_lost` drops them), a bare retry still writes nothing, and a successful sync writes back every re-dirtied 4 KiB page whole. | `review_writeback.rs` (maki-core): `flush_after_a_failed_sync_rewrites_lost_records_before_acknowledging`, `fua_after_a_failed_sync_covers_every_pending_record`, `seal_after_a_failed_sync_rewrites_before_opening_a_successor`, `barriers_keep_failing_until_the_rewrite_persists`, `recovery_rewrites_page_cache_bytes_it_accepts_after_a_failed_writeback`; `failed_sync_marks_dirty_writes_clean_and_lost` (maki-test-support) |
| F03 | **A partial `write_at` left a torn tail the next seal carried as corruption.** `write_all_at` can persist a prefix and then fail; the logical offset did not move, a shorter retry record did not cover the torn bytes, and the roll sealed the file at its physical length. Recovery treats a non-final segment as durable in full and refused the volume. | Same finding as BUG-020, whose implementation is the one in the tree: the writer marks the tail on any append failure and truncates the file back to the logical end before the next append or seal, keeping the flag until the truncation has been synced; while that truncation fails, appends, rolls and barriers fail too. The debug sanitizer asserts the file length equals the logical end. `CrashableBacking` gained a partial-write hook. | `partial_append_failure_leaves_no_garbage_for_the_next_seal`, `crash_right_after_a_partial_append_is_a_torn_tail`, `appends_are_refused_while_the_torn_tail_cannot_be_normalized` (maki-core); `partial_write_hook_persists_a_prefix_and_fails` (maki-test-support) |

### Security and operations (P1)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F02 | **The mount was verified by filesystem type, UUID, sentinel and probe, never by which block device it was on.** With `init_sentinel` the helper wrote the expected sentinel onto whatever XFS it had mounted (a local LV of the right name) and then verified its own sentinel: application data could land outside Maki in plaintext. | A new `verify-mount-device` step runs right after `mount`, before the sentinel or the probe touch the filesystem: the mount's `major:minor` is walked through the sysfs `slaves` relation (device-mapper, MD) down to the leaf devices, and every leaf must be the NBD device this attach connected (partitions fold into their device). Mixed volume groups and unresolvable topologies are refused. `verify_mount_identity` repeats the check. | `a_filesystem_not_stored_only_on_the_bound_nbd_device_is_refused_before_it_is_touched`, `leaf_devices_are_resolved_through_the_device_mapper_stack`, `mountinfo_parsing_exposes_the_device_number`, updated `init_sentinel_adds_a_write_step_before_verification` and `verifier_rejects_wrong_device_and_missing_sentinel` (maki-privileged). A real LVM-over-NBD run still needs the privileged Linux target. |
| F04 | **Locked secret buffers shared heap pages.** `mlock`/`munlock` work on whole pages with no reference count: dropping one `SecretBuffer` unlocked the page of a live neighbour, which still reported itself locked. | Same finding as BUG-006, whose implementation is the one in the tree: page ownership is reference-counted under the same lock as `mlock`/`munlock`, so a page is unlocked only by its last owner, after zeroization. | `dropping_a_buffer_never_unlocks_a_live_neighbours_pages` (`review_secret.rs`, Linux: every survivor's address must still sit in a `VmFlags: lo` VMA in `/proc/self/smaps`), `review_secret_page_lifetime.rs`, existing `dropping_locked_buffers_releases_their_pages` |
| F05 | **The secure-swap check passed unsafe layouts.** Any path containing `zram` counted as safe (`/var/swap/zram-backup`), an unreadable `/proc/swaps` read as "no swap", and a real zram device with a writeback `backing_dev` was assumed RAM-only. | Classification is by device identity: `/dev/zramN` exactly, with `/sys/block/zramN/backing_dev` equal to `none` (or absent) for RAM-only, a dm-crypt backing for encrypted, anything else unsafe; dm-crypt by device-mapper UUID as before. `/proc/swaps` must be readable and start with its header line or attach is refused. SPEC §37 and the configuration reference say so. | `swap_classification_never_trusts_a_name`, `zram_writeback_target_is_read_from_sysfs_not_assumed`, `unparseable_proc_swaps_is_an_error_not_no_swap`, updated `swap_parser_is_strict` (maki-nbdkit) |
| F06 | **A detach decided its device outside the attach lock.** `plan_detach` read the bound-device record before `execute` locked; a detach, re-attach (to another device) and another volume's attach in between left a stale plan that unmounted the current mount and disconnected the other volume's device. The record was also written before `nbd-client` ran and was not removed when a failed attach rolled back. | Superseded by BUG-003 and BUG-010: the planner never reads runtime state; the executor resolves the trusted record (configuration identity plus a unique kernel connection identifier) under the root-controlled lock, refuses a detach whose request or live backend does not match it, and verifies the identity again immediately before every disconnect, rollback included. | `exec_tests.rs`, `state_tests.rs`, `regression_attach_state.rs` (maki-privileged); the process interleaving itself needs the privileged Linux target |
| F07 | **`nbd.maximum_io` and the plaintext budget were not hard limits.** The byte semaphore capped an oversized request to the whole budget instead of bounding it, admission charged the request length while a partial write holds whole units, and the adapter copied the entire NBD request before admission. | The engine refuses any request above `max_request_bytes` (= `nbd.maximum_io`); at the NBD boundary the limits are advertised through the `block_size` callback and a request outside them is refused with EINVAL before its plaintext is copied (BUG-011, which replaced this pass's request splitting; R5-038 restored splitting above the maximum, chunk by chunk, after the Linux 6.12 NBD driver was seen ignoring it); admission charges every touched crypto unit in full (`Engine::admission_cost`); validation requires `limits.max_plaintext_bytes >= nbd.maximum_io + crypto_unit_size`. | `requests_above_the_configured_maximum_are_refused`, `admission_charges_every_touched_unit_in_full` (maki-core `review_limits.rs`); `review_nbd_limits.rs` (maki-nbdkit); a new case in `zero_and_inverted_bounds_are_rejected` (maki-format) |

### Hygiene (P2 and additional items)

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| F08 | `can_fua` returned 1, which is `NBDKIT_FUA_EMULATE` (nbdkit-common.h: NONE 0, EMULATE 1, NATIVE 2), so nbdkit emulated FUA with a full flush after every FUA write and the engine's native FUA path was never exercised in production. | `can_fua` returns `NBDKIT_FUA_NATIVE`; every `NBDKIT_*` constant is named once. `review_abi.rs` compiles a C probe against the installed `nbdkit-plugin.h` (API version 2) and compares every field offset of the mirrored struct, up to the `block_size` callback the prefix now covers (BUG-011), and every constant; CI's nightly job installs `nbdkit-plugin-dev` and runs it; WSL has the header installed. | `fua_is_advertised_as_native_not_emulated`, `declared_prefix_ends_after_the_block_size_callback` (unit), `shim_constants_and_layout_match_the_installed_header` (Linux, header 1.46.2) |
| F09 | The HTTP provider copied plaintext into plain vectors, JSON documents and request bodies that were never wiped, and parsed decrypt responses through plain buffers. | Payload copies, the serialized body, response owner and decoded payloads use zeroizing owners. Fixed-size decoders erase malformed partial Base64/hex output; response growth wipes the replaced allocation; guarded JSON request trees drain and wipe keys, overwritten values and partial construction on every return. Resolved header/query values and the assembled mTLS identity PEM are erased on normal drop and construction errors, without an intermediate UTF-8 byte-vector copy. Source configuration strings, malformed-response allocations discarded inside serde_json, page locking, and copies inside reqwest, hyper, rustls and the kernel remain documented residuals. | provider conformance/chaos suites; `malformed_base64_erases_partial_decoded_output`, `malformed_hex_erases_partial_decoded_output`, `response_growth_erases_the_replaced_plaintext_allocation`, `zeroize_json_erases_object_key_allocations`, `pointer_error_erases_the_incoming_value`, `pointer_overwrite_erases_the_replaced_value`, `pointer_descent_erases_a_replaced_intermediate_value`, `per_item_build_error_does_not_copy_borrowed_request_metadata` and `batch_build_error_does_not_copy_borrowed_item_metadata` (requests are now serialized from borrowed input without a JSON tree, so these assert that a failed build makes no copy, not that a partial tree is wiped), `http_request_partial_fixed_serialization_erases_its_output`, `http_request_mapping_errors_and_duplicate_keys_erase_owned_key_storage`, `provider_drop_erases_owned_header_and_query_values`, `provider_construction_error_erases_owned_credentials`, `tls_spec_drop_erases_identity_pem`, `config_error_erases_a_resolved_credential_header` |
| F10 | Control sessions were unbounded: one task per connection, no idle or write deadline, and administrative verbs queued behind each other. | At most 64 sessions are served at once (the slot is taken before `accept`, so excess clients wait in the backlog); a session idle for 60 s or a client that does not drain a response within 10 s is closed; `checkpoint` and `reload` run one at a time and a concurrent one is answered `busy`. | `review_limits.rs` (maki-control): `idle_session_is_closed_after_the_idle_timeout`, `an_active_session_outlives_the_idle_timeout`, `a_client_that_never_reads_is_disconnected_after_the_write_timeout`, `concurrent_mutating_verbs_are_refused_with_busy`, `extra_sessions_wait_in_the_backlog_until_a_slot_frees` (Unix) |
| Backing paths | Lexical validation stopped `..` and absolute paths, but a symlink planted under the backing root redirected opens outside it. | No component under the root may be a symlink; Unix opens pass `O_NOFOLLOW`. | `symlinks_inside_the_root_are_never_followed` (maki-backing, Unix) |
| CI | The CI workflow ran without `--locked`, unlike the documented commands. | `--locked` on every CI cargo invocation; the nbdkit ABI check joined the nightly job. | the workflow |

Observability added for the operator (review item 5): `journal_sync_failures_total`
and `journal_writeback_uncertain` in `status` and `metrics`. Still open from
the review's recommendations: memory accounting for callbacks waiting in
admission (the adapter refuses anything above `maximum_io`, which bounds it
to one request per callback), lock-wait latency measurement, and the narrow
production profile (one geometry, one provider) that needs the Linux
qualification environment. The attach state machine with connection identity
the review asked for is BUG-003.

## Fourth pass (2026-09-05): specification contradictions and boundaries

A self-directed pass after the third review read the normative sections of
`SPEC.md` against the code and re-read the modules no review had covered
(overlay, slot store, cache, initialization, binaries). Every finding has a
failing test before its fix. IDs: N (new).

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| N-01 | **SPEC §8 contradiction: backing files and directories were created with the process umask** (`0644` / `0755` under the usual `022`), while the specification places the volume tree at `maki:maki 0700` and its files at `0600`. Ciphertext, metadata, the journal and the key canary were readable by every local user. | `FileBacking` creates directories with mode `0700` and files with `0600` regardless of the umask (existing entries keep their mode). | `created_directories_and_files_are_owner_only` (maki-backing, Unix) |
| N-02 | **SPEC §40 contradiction: most of the "required metrics" were absent** — active callbacks, plaintext bytes in flight, submission queue, inflight batches and bytes, per-endpoint inflight, crypto latency, retries, retry-budget tokens, circuit state, failover count, FLUSH and FUA latency. | The engine accounts admission usage and FLUSH/FUA latency (sum, count, max); the dispatcher accounts RPC latency and exposes per-endpoint budget tokens and global inflight; the scheduler counts inflight batches; the daemon hands the endpoint dispatcher to the control backend, whose `metrics` document now carries every name the specification lists (per-endpoint gauges as objects keyed by endpoint name, empty for local providers) and whose `status` lists each endpoint's circuit, validation, inflight and budget. | `every_spec_required_metric_is_reported_with_a_dispatcher`, `every_spec_required_metric_is_reported_without_a_dispatcher` (maki-nbdkit `review_metrics.rs`); `dispatcher_reports_latency_budget_and_inflight` (maki-crypto); `admission_usage_and_barrier_latencies_are_reported` (maki-core `review_state.rs`) |
| N-03 | **SPEC §13 contradiction: `nbd.preferred_io` defaulted to a fixed 4096**, not to the crypto unit; a volume with 8 KiB units advertised a 4 KiB preferred size. | `nbd.preferred_io` is optional and defaults to the crypto unit (raised to `nbd.minimum_io` when the unit is smaller, so the size ordering holds). | `preferred_io_defaults_to_the_crypto_unit` (maki-format) |
| N-04 | A journal whose sync had failed reported the volume `ready`: `maki_volume_state` said 1 while every FLUSH and FUA failed (SPEC §26 wants a persistence failure visible until it is resolved; the third review asked for a sticky, observable state). | The engine mirrors the journal's writeback-uncertain flag after every journal operation and reports `degraded` (with the reason) while it is set; a successful checkpoint does not clear it, only the barrier that rewrites and syncs does. | `a_failed_journal_sync_degrades_the_volume_until_a_barrier_succeeds` (maki-core) |
| N-05 | An engine request bound that is not a multiple of the device block size would be advertised as an NBD maximum no aligned request can reach exactly, failing every maximal request as invalid. | `Engine::attach` refuses a zero or non-block-multiple `max_request_bytes`. | `attach_refuses_a_request_bound_that_is_not_a_block_multiple` (maki-core) |
| N-06 | `maki status`, `metrics`, `checkpoint` and `reload` waited forever on a daemon that accepts but never answers (a stalled provider, a long checkpoint holding the volume lock). | Every control round trip is bounded: 60 s by default, 600 s for `checkpoint`, `--timeout <seconds>` to override; the failure names the socket and the bound. | `control_commands_time_out_against_a_silent_daemon` (maki binary, Unix) |
| N-07 | **SPEC §9 contradiction: a `file` credential was loaded whatever its permissions** — a world-readable key file, or a symlink to any file, was accepted as the "root-only secret file". | `FileKeySource` refuses a credential that is not a regular file or whose mode grants group or other access (`0600`/`0400` only; systemd's `LoadCredential` files are `0400`). | `group_or_world_readable_key_files_are_refused`, `a_symlink_or_special_file_is_not_a_credential` (maki-crypto-local, Unix) |
| N-08 | `backing.root` accepted a relative path, which resolves against nbdkit's working directory rather than the SPEC §8 layout. | Validation requires an absolute path. | two cases in `zero_and_inverted_bounds_are_rejected` (maki-format) |

Read and found consistent with the specification in this pass: the overlay's
latest/durable bookkeeping and byte accounting, the slot store's shard
creation protocol and read classification, the cache's version key and
eviction, volume initialization, the checkpoint triggers and inline ENOSPC
rules (SPEC §26), the per-unit concurrency and FUA/FLUSH sequences (§24, §25,
§28), the control socket's verb split (§7), and the secure-mount checklist
(§39). Known and documented deviations that remain: only the cache section is
hot-reloadable (§20 lists more); `madv_dontdump` is honoured through the
non-dumpable flag; FLUSH takes the volume's exclusive lock rather than an
append-ordered barrier (§25 describes the ordering, which the lock also
provides, at a concurrency cost the benchmark must quantify).

## Fifth pass (2026-09-05): A/B retry, breaker probes, packaging

A further pass over the A/B metadata store, the circuit breaker, the
dispatcher, the journal scanner, the deep checker, and the packaging
(systemd units, tmpfiles, sysusers) against SPEC §5, §7, §8 and §10.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| N-09 | **The A/B store retried a failed sync on the wrong side.** After a failed `fdatasync` the new record stays visible in the page cache (F01), so the retry read that side as the newer generation and overwrote the *other* side, the only copy proven durable; a crash tearing that retry left one torn side and one side two generations old, losing metadata acknowledged as durable (checkpoint state, allocation maps, catalog, canary). | Same finding as BUG-001, whose preserve-first implementation is the one in the tree and **subsumes** N-09: before the stale side is overwritten the preserved (typed-valid) side's exact bytes are rewritten and synced, file and directory, so the durable copy is safe before the target is touched. N-09's own fix (emptying the side whose sync failed) was **removed** in the merge — it discards a newer generation and contradicts BUG-001's tests, which keep the failed side readable for a later store to preserve. | `review_ab_retry.rs` (maki-format, maki-core: failed data/directory sync, repeated retries and restart, sector tearing, writeback that loses dirty bits, preservation across metadata types, and recovery of durable volume data). The N-09-specific `review_ab.rs` was deleted as redundant with, and contradictory to, these. |
| N-10 | A half-open probe abandoned at the operation deadline (its RPC future dropped, C-06) never reported back, so its slot was never returned: `half_open_max_requests` abandoned probes wedged the circuit half-open forever, and a single-endpoint `bounded-error` volume with a slow provider stopped probing for good. | Same finding as BUG-004, whose implementation is the one in the tree: the dispatcher holds a generation-bound `BreakerPermit` whose drop returns the slot on every exit, verdict or not. | `review_probe_lifetime.rs` (maki-crypto) |
| N-11 | **Administrators could not reach the control socket.** systemd creates `/run/maki/<volume>` as `maki:maki`, and `/run/maki` was `maki:maki`, so a `maki-admin` member could not traverse to the `0660` socket (SPEC §7 group access); SPEC §8 even asked for `0700`, contradicting §7. | Same finding as BUG-009, whose layout is the one in the tree: control sockets live under a separate `root:maki-admin` `/run/maki-control` tree, NBD sockets stay behind `root:maki` `/run/maki`, and SPEC §8 says so. (This pass's daemon-side `chgrp` of the socket directory and the unit-level `UMask` were dropped: nbdkit resets its own umask, so the unit setting never governed the NBD socket.) | `regression_control_packaging.rs` (maki-nbdkit) |
| N-12 | The documented `maki volume create` flow produced a tree the daemon cannot open: run as root it created `/var/lib/maki/<volume>` owned by root (now `0700` after N-01), while `/var/lib/maki` (`root:maki 0750`) does not let the daemon user create it either. | The operations guide creates the directory for the daemon user and runs the command as that user; `maki volume create` warns when run as root. `/etc/maki/attach` and `/etc/maki/secrets` joined the tmpfiles layout. *Changed by AUD-111 ([#344](https://github.com/seo-rii/maki/pull/344)):* a root run creates each entry below an existing directory for that directory's owner, so a root create into a volume directory the daemon user owns leaves a daemon-owned tree, and the warning is printed only for a tree that holds a root-owned entry, such as a volume directory the command had to create itself. | documentation; the warning has no root-only test. Since AUD-111: `root_create_into_daemon_owned_directories_leaves_nothing_to_hand_back`, `root_create_names_a_volume_directory_it_had_to_create` (`bins/maki` `review_root_created_ownership.rs`; root only) |
| N-13 | `control.socket` and `nbd.socket` accepted relative paths, which nbdkit and the helper resolve against their own working directories. | Validation requires absolute paths. | two cases in `zero_and_inverted_bounds_are_rejected` (maki-format) |

Read and found consistent: the retry budget (token bucket with the minimum
probe rate), the dispatcher's retry-safety and failover accounting, the
journal scanner's durable-prefix classification, the deep checker's use of
the real scanner and slot reader, and the attach helper unit's ordering
(`Requires=`/`After=` the daemon, `ConditionPathExists` on the attach config).

## Additional review (2026-09-05): eight further findings (BUG-015 … BUG-024)

A later external review of `1411ed5` listed eight defects that did not
overlap the earlier passes. Three of them were already closed on this branch
by fixes the merge with the third-to-fifth passes brought in, and were only
re-verified here; the other five were fixed. IDs follow the review (BUG-nn).

Already closed by the merged work (verified against the merged tree, not the
review's `1411ed5` baseline):

| ID | Finding | Where it is already handled |
|---|---|---|
| BUG-016 | Swap security trusted a device *name* containing `zram`, and an unreadable `/proc/swaps` read as "no swap". | F05: `zram_index` matches `/dev/zramN` exactly, classification is by device identity, and `parse_proc_swaps` refuses a file without the `Filename` header. `review_security.rs`. |
| BUG-019 | Attach never checked that the mounted LV is backed by the bound NBD device before writing the sentinel. | F02: the `verify-mount-device` step runs right after `mount`, before the sentinel or the probe, walking the sysfs `slaves` topology to the leaf devices. `review_priv.rs`, `phase7_priv.rs`. |
| BUG-023 | A symlink planted under the backing root redirected an open outside it. | The backing hardening: `resolve` rejects a symlink at *every* component under the root and opens pass `O_NOFOLLOW`. `symlinks_inside_the_root_are_never_followed` (maki-backing). |

Fixed in this change:

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-022 | **Journal reclaim could outrun the durability of the checkpoint state that authorized it.** A checkpoint-2 state whose sync failed could be read from the page cache after a restart, used to reclaim journal, and then lost to a power loss — leaving an older checkpoint whose covering segment was gone, so recovery refused to bridge. | Recovery re-persists the checkpoint state it selects before the writer resumes. Every A/B store first rewrites and syncs the other valid copy and its directory before overwriting the selected target; a failed target sync may leave volatile bytes readable, but cannot destroy the preserved durable copy. Recovery persists whichever valid state it selects before journal mutation, so reclaim rests only on durable state. | `journal_reclaim_never_outruns_checkpoint_state_durability` (maki-core `review_next_storage.rs`) |
| BUG-018 | **Grow ran `lvextend`/`xfs_growfs` with no trusted record and no attach lock**, so it could extend an LVM/XFS unrelated to any current attachment and race a detach. | `plan_grow` carries the attachment identity; the executor takes the attach lock for a grow and refuses one whose targets, or whose live NBD backend identity, do not match the trusted record before any command runs. | `review_next_grow_requires_trusted_attachment_before_commands`, `review_next_grow_rejects_reused_backend_and_changed_targets` (maki-privileged `exec_tests.rs`) |
| BUG-017 | **A gRPC server that stalled after the response headers, or between the message and the trailers, held the RPC open indefinitely** (`Channel::timeout` bounds only the connection), pinning the inflight slot and blocking that request's retry and failover. | The provider wraps readiness plus the unary exchange in one `tokio::time::timeout(spec.timeout, …)`; a timeout is a retryable error. The `bounded-error` outer deadline (BUG-013) still applies separately. | `a_stalled_grpc_response_is_bounded_by_the_transport_timeout` (maki-crypto-grpc `review_next_transport.rs`) |
| BUG-015 | **A clean `shutdown` stopped accepting but left live control sessions running**, each holding an `Engine` reference and so the volume lock; a detach that reported success left the volume `VOLUME_ALREADY_ATTACHED`. | Sessions run in a `JoinSet`; `serve_with_shutdown` aborts *and awaits* them on a shutdown signal, and the adapter signals then joins the serve task before releasing the engine, so no session outlives `shutdown`. | `shutdown_terminates_live_sessions_and_releases_the_volume_lock` (maki-nbdkit `review_next_control.rs`) |
| BUG-024 | **HTTP request JSON pointers were not RFC 6901-unescaped**, so a vendor field named `key/slot` (`/key~1slot`) was sent as the wrong field `key~1slot`; the response side already decoded with `Value::pointer`. | `pointer_set` decodes each reference token (`~1`→`/`, `~0`→`~`, in order) to match the response side. | `pointer_set_decodes_rfc6901_escapes`, `decode_pointer_token_matches_rfc6901_order` (maki-crypto-http, in-crate) |

## Deeper review pass (2026-09-07): two further findings (BUG-025, BUG-026)

A whole-codebase re-read (crypto flow control, core durability, control,
privileged, backing, local providers) plus four targeted review agents over
the daemon/config wiring, the remote providers, the format decoders, and the
privileged probes. The format decoders and the remote providers came back
clean; the other two surfaces each yielded one concrete finding. Both are
fail-*open*/availability gaps that contradict the project's fail-closed
stance, not data-loss bugs.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-025 | **`resolve_leaf_devices` dropped an over-deep subtree instead of failing closed.** The F02 topology walk (`probe.rs`) skipped any node past `MAX_DEPTH` with a bare `continue`, so a branching sysfs `slaves` stack with a *foreign* leaf hidden below depth 16 resolved to just the shallow NBD leaf; `verify_mount_device` then passed on an incomplete picture and the helper wrote plaintext onto a filesystem partly backed by a non-Maki device. (Low reachability — building an 18-deep dm/MD stack needs `CAP_SYS_ADMIN`, which the untrusted tenant lacks — but a genuine fail-open contradicting its sibling walker `detach.rs::depends_only_on`, which errors on the same condition.) | Exceeding the depth bound now returns *no leaves*, so the caller refuses (empty `backing_devices` ⇒ `verify_mount_device` fails). A diamond (a device reached by two paths) is still merely not re-walked. | `an_over_deep_topology_resolves_to_no_leaves_not_a_partial_set` (maki-privileged `review_priv.rs`) |
| BUG-026 | **Transport limits did not cover a reachable full crypto batch.** A whole batch is sent as one gRPC message / one WebSocket frame; an undersized limit validated but rejected large batches at runtime. Zero limits also passed. | `validate_provider_sections` checks the serialized maximum batch reachable under both the item and plaintext-byte limits, including maximum ciphertext and framing. Both transport limits must be positive and share defaults with the daemon. BUG-162 removes the old raw-byte floor, which incorrectly treated unused byte capacity as a message that could be sent. | `remote_transport_batch_must_fit_the_frame_or_message_limit` (maki-format `review_config.rs`), plus the singleton transport regressions described below |

## Fast-checker / recovery drift (2026-09-07): BUG-027

The offline `maki check` fast path (`maki-format::checker::check_volume`) and
recovery/attach (`maki-core::store::SlotStore::open`) disagreed on one state, so
`maki check` could report "passed" on a volume `maki attach` would refuse — the
opposite of the tool's purpose (a green pre-attach check that then fails to
attach). Not a durability bug; a fail-*open* diagnostic gap.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| BUG-027 | **`maki check` passed a volume `maki attach` would reject: a cataloged shard with a missing data file was only a warning when its allocation map was empty.** The fast checker errored on a missing data file *only* inside the `map.set_count() > 0` arm, then pushed an unconditional "data file not yet created" warning otherwise — so a cataloged shard with a valid but empty allocation map and no data file left the report error-free (`ok() == true`). `SlotStore::open`, though, opens every cataloged shard's data file with `create=false` regardless of its allocation map and returns `CoreError::Corrupt` if it is absent, so recovery refuses to attach. The "not yet created" state the warning described cannot arise for a *cataloged* shard: `ensure_shard` creates and `sync_dir`s the data file's dirent *before* the catalog names the shard (the reverse ordering only ever yields an orphan data file, which is adopted, not a cataloged shard with no file). | The missing-data-file check is a single unconditional error per cataloged shard, matching recovery, and the misleading warning is removed. `maki check` now fails exactly when attach would. | `fast_check_flags_a_cataloged_shard_with_no_data_file` (maki-core `review_check.rs`) |

## Deep-check metadata I/O failures (BUG-133, 2026-10-26)

An I/O failure while inspecting checkpoint copies, loading checkpoint state or
reading the key canary now stops the deep check with the original error kind
and OS error number. The same rule covers wrapped metadata I/O errors from the
journal scanner and slot store after the fast check has succeeded. An unreadable
file no longer contributes to an `unrecoverable` verdict; invalid bytes and
foreign-volume metadata retain their existing corruption classification.

[`review_deep_metadata_io.rs`](../crates/maki-core/tests/review_deep_metadata_io.rs)
injects one-shot failures into those five boundaries, including a successful
earlier inspection or later read. It checks that removing the fault restores a
clean report and the original checkpointed and journaled ciphertext. Controls
cover fast-check I/O propagation, damaged checkpoint copies, a foreign canary,
and valid A/B fallback. This changes diagnostics only; disk formats, recovery
ordering and durability guarantees are unchanged.

## Supplementary review (2026-09-07): R01–R08

A follow-up review (`maki-review-20260907`) of the privileged attach/detach/grow
lifecycle, the crypto scheduler's admission accounting, and the journal hard
bound, with six proposed RED regression tests it could not compile in its own
environment. Each finding below was reproduced (RED) against the actual source,
fixed, and reverified (GREEN); the proposed tests were adapted to the real
fixtures. R05 also has a landed service-boundary fix. Findings needing a
native-Linux VM, an allocation observer, or peak-RSS experiments are scoped
under "Tracked, not closed in this pass" below rather than closed here.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| R01 | **Attach rollback continued compensating even after an earlier step failed, and a command that failed *after* its effect was skipped.** After an attach failure the rollback ran every compensating step regardless of whether the previous one succeeded, so a failed umount did not stop the disconnect beneath it — the backing could be torn out from under a still-mounted filesystem. Separately, a command that reports failure after taking effect (a mount that mounted, a VG activation that mapped) never entered the executed prefix, so its compensation was skipped while a lower-level one still ran. | Rollback re-observes live state first and folds any effect that actually happened (mount, VG activation) into the compensation set in dependency order, and it **stops** at the first compensating failure rather than proceeding to the destructive step beneath it. Attach only — a failed detach is resumed, not rolled back. | `audit_20260907_failed_unmount_must_not_disconnect_live_mount`, `audit_20260907_mount_failure_after_effect_requires_reobservation` (maki-privileged `exec_tests.rs`) |
| R03 | **Grow trusted the saved config plus the NBD identity, not the current topology.** A correct stored record and a matching live NBD connection can coexist with a replaced mountpoint or a changed active VG mapping; the grow branch checked only `verify_connection`, then ran `lvextend`/`xfs_growfs` on the configured names. | Grow re-observes the live attachment (`verify_live_attachment`, sharing `verify_detach_state`'s mount/VG/leaf observation) and refuses on a foreign mount, a foreign VG, or an unreadable observation before any mutation, while still requiring the connection present. | `audit_20260907_grow_rechecks_live_mount_and_vg_topology` (maki-privileged `exec_tests.rs`) |
| R04 | **A single request larger than a lane's pending budget was admitted anyway, and `run_lane` took its first group without checking the batch maxima.** `DualSemaphore::acquire_n` clamps an oversized group's item/byte charge to the whole budget and serializes it, but the pending *stats* and the real allocations still counted the full group, so a two-item request slipped past a one-item pending budget. Separately, `run_lane` applied `max_items`/`max_bytes` only to *additional* groups, so a lone request above the batch maxima reached the provider whole. Positive-value config validation did not require the pending/inflight capacities to cover the configured maximum batch, so a config that validated could reject full batches at runtime. | The scheduler validates every request against the lane's admittable maximum (batch maxima capped by pending capacity) **before** copying the payload, and *rejects* an oversized one (it never splits a request; the reject charges nothing and copies no secret). Config validation now requires `max_pending_crypto_items ≥ batch.max_items`, `max_pending_crypto_bytes ≥ batch.max_bytes` (encrypt lane) and `max_ciphertext_bytes ≥ batch.max_bytes` (decrypt lane), so a validated config never rejects an in-spec request. | `audit_20260907_one_group_cannot_exceed_pending_budgets`, `audit_20260907_first_group_obeys_batch_maxima` (maki-crypto `review_scheduler.rs`); `audit_20260907_pending_capacity_must_cover_a_full_batch` (maki-format `review_config.rs`) |
| R05 | **A hung external command could hold the global attach lock indefinitely.** `Command::output` has no deadline, and systemd disables the *start* timeout by default for `Type=oneshot`, so a stuck `nbd-client`/`mount`/`umount` in one volume's helper would block every other volume's attach/detach/grow. | The packaged unit now sets a finite `TimeoutStartSec`/`TimeoutStopSec`, above the internal 15s NBD readiness wait plus expected XFS mount recovery, so systemd terminates a stuck helper and releases the lock; the next attempt re-observes actual kernel state. The finer in-process per-command deadline is tracked below. *Superseded in part by AUD-151 ([#375](https://github.com/seo-rii/maki/pull/375)):* the NBD steps are no longer commands, and the unit's timeout does not end a helper in the kernel's uninterruptible wait inside `NBD_CMD_DISCONNECT`; it ends, and releases the lock, only when that wait does. | `audit_20260907_attach_unit_bounds_a_hung_helper` (maki-privileged `regression_missing_attach_config.rs`) |
| R08 | **The journal hard limit counted record headers and payloads but not the 48-byte segment header an automatic roll creates.** With the on-disk total exactly at `journal_max_bytes` and the active segment full, admission's record-only check saw equality (not `>`), admitted the write, and the roll then pushed the on-disk total 48 bytes past the documented hard bound. Multiple rolls in one request could add several headers. | `JournalWriter::append_footprint` computes the exact bytes an append adds — records **plus** any new segment headers — by projecting `append`/`roll` step by step. `admit_journal` checks `journal_total_bytes + append_footprint` against the limit, recomputing the footprint after inline reclaim (reclaim can change the active segment). Record-byte accounting and the footprint share one `record_len` helper so they cannot drift. The `sustained_writes…` assertion was tightened from `+ SEGMENT + RECORD` slack to the strict bound. | `audit_20260907_journal_hard_limit_counts_new_segment_headers` and the tightened `sustained_writes_keep_journal_and_overlay_within_hard_limits` (maki-core `review_bounded.rs`) |

### Tracked, not closed in this pass

These findings from the same review need a native-Linux VM, an allocation
observer, or peak-RSS measurement — infrastructure the review itself calls for
and that WSL/CI simulation cannot substitute for. Each is scoped here so it is
not silently dropped; none is a data-durability defect.

- **R02 (P1) — mount target verified only after a read-write mount.** The plan
  activates the VG and mounts the LV read-write before `VerifyMountDevice`
  runs, and a read-write XFS mount can itself modify a filesystem (log
  recovery) before the post-mount check rejects it. The fix — resolve the
  LV device's PV/VG/LV identity and *all* backing leaves and confirm they are
  exactly the bound NBD device *before* the read-write mount, retaining the
  post-mount check — requires a device-path leaf probe (not the current
  mountpoint-based one) and must be qualified against a real dirty XFS in a VM
  (a rejected attach must perform no writes). Administrative accident-safety,
  not a privilege-escalation or plaintext-persistence path.
- **R05 in-process command deadline (P1).** The service-boundary timeout above
  is landed; the finer per-command deadline with bounded captured output and
  process-group cleanup/reaping (tested against a child that never exits, a
  descendant holding output pipes open, and a verbose child) is a careful
  systems change to root-privileged code that the review says to qualify in a
  VM before shipping.
- **R06 (P2) — WebSocket/gRPC make plaintext copies outside `SecretBuffer`.**
  The transports build JSON/Base64 strings and prost `Vec`s without explicit
  zeroization, and error/cancellation paths can drop decoded plaintext before
  it is wrapped. Closing this needs owned wire types with RAII zeroization and
  an allocation/deallocation observer to prove the lifetime; the review notes
  reading freed memory directly in a test is itself invalid, so a meaningful
  regression needs that observer harness first. Later transport-memory changes
  supersede these provider-owned WebSocket/gRPC gaps and add that observer;
  library copies, page locking and total resident accounting remain open.
- **R07 (P2) — recovery memory grows with all uncheckpointed records.**
  Recovery collects every newer journal record before reducing them into the
  overlay, so a GiB-sized journal needs comparable scratch memory even when the
  live overlay is small. A streaming/two-pass replay that reduces into the
  overlay as it scans would bound this, but it touches the recovery ordering
  the release gates guard (second-crash-during-recovery, superseded-record
  validation); it needs peak-RSS measurement and the full ignored release
  gates, done deliberately, not folded into this pass.
- **Additional improvements.** `plugin.rs` cold-open initialization is not
  serialized (concurrent first opens can both attempt the exclusive volume
  lock); synchronous storage calls remain on async engine paths; the CI comment
  references a `docs/ci.md` and weekly/release tiers the uploaded workflow does
  not implement. These are availability/accuracy items, not correctness bugs.

Later update: [native startup readiness](operations.md#data-plane-readiness)
now initializes the adapter once in `after_fork`, before any client opens it.
This supersedes the cold-open initialization finding above. The other bullets
describe that review's snapshot; consult the [current remediation status](qualification/historical-reviews/production-readiness-review-2026-09-08.md)
for their subsequent fixes and remaining limits.

## Comprehensive review (2026-09-07): MAKI-001–050

A 50-item review (`maki-review-2026-09-07`) spanning the privileged lifecycle,
crypto verification, durability, memory/scalability, performance, Docker
deployment, capacity, and qualification. The review compiled no Rust and marks
every item `runtime_reproduced: false`; most items are design constraints,
performance limits, deployment/ops gaps, or qualification work that need a
native-Linux VM, real databases, or measurement infrastructure. This pass
fixed the self-contained code defects with RED→GREEN regression tests; several
findings restate defects the earlier 2026-09-07 supplementary review already
closed.

### New code defects fixed this pass

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| MAKI-008 | **The nbdkit `unload` callback discarded a shutdown error** (`let _ = a.shutdown()`), so a failed final flush/checkpoint looked like a clean stop. | The error is recorded via structured tracing before `unload` returns (a void C callback cannot propagate it). No unit test — the C shim is covered by the ABI probe, not unit tests; the fuller shutdown-report feature is tracked below. | — |
| MAKI-010 | **The provider self-test sent all patterns in one batch**, rejecting a valid single-item or small-batch provider at attach. | The self-test splits every batch into capability-respecting RPCs (`batch_ranges`) in `provider_self_test`, `provider_conformance`, and `cross_endpoint_self_test`. | `self_test_splits_patterns_for_a_small_batch_provider` (maki-crypto `review_audit2.rs`) |
| MAKI-011 | **The tamper and context-binding self-tests accepted *any* error** as proof, so a provider that returns a transport error only on the tampered/moved request passed. | Both require a definitive bad-ciphertext rejection (`NonRetryableRequest` class); a transport/retryable error leaves the claim unproven and refuses attach. Context binding also accepts Ok-with-different-plaintext. | No dedicated test remains. `followup_inconclusive_negative_probe_preserves_retry_class` (maki-crypto `review_audit2.rs`, FUP-008) covers it indirectly: its provider answers every negative probe with a transport error and the self-test must fail; the first probe it reaches is context binding, so the tamper probe's transport-error case is exercised only through the shared `classify_probe_err`. *Since AUD-065 ([#175](https://github.com/seo-rii/maki/pull/175)):* `a_transport_error_on_the_tamper_probe_alone_leaves_integrity_unproven` (same file) fails only the tamper probe's decrypt with a transport error and requires the self-test to fail with that class |
| MAKI-016 | **gRPC/WebSocket embedded the remote error message verbatim** in an error, allowing log injection (newlines) or log flooding — unlike HTTP. | `maki_crypto::sanitize_external_message` (strips control chars, caps length) wraps both remote messages; the mapped error class is preserved. *Superseded by FUP-006 (below):* the remote message is no longer embedded at all, and `sanitize_external_message` was removed. | `sanitize_strips_control_chars_and_caps_length` (maki-crypto), `map_status_sanitizes_remote_message` (maki-crypto-grpc); both were removed with the function, and FUP-006's `followup_remote_status_does_not_expose_reflected_secrets` (maki-crypto-grpc `phase9_grpc.rs`) covers what replaced it |
| MAKI-017 | **An unreadable zram `backing_dev` (EACCES/EIO) was classified RAM-only**, so an unencrypted writeback target could be trusted as safe swap. | `classify_zram_backing` keeps a missing attribute (NotFound) as RAM-only but fails closed (Unsafe) on any other read failure. | `zram_backing_read_failure_is_unsafe_not_ram_only` (maki-nbdkit `security.rs`) |
| MAKI-026 | **A corrupt small metadata file was read up to the 1 GiB common cap**, and `Superblock::decode` accepts its valid prefix. | Per-type `AbRecord::MAX_ENCODED_LEN` rejects an over-long copy by size before allocating (Superblock = one block, KeyCanary = header + max canary ciphertext). | `oversized_superblock_copy_is_rejected_before_it_is_read` (maki-format `review_format.rs`) |
| MAKI-027 | **A/B `store` incremented the generation with an unchecked `+ 1`** (panics in debug, wraps in release at u64::MAX). | `checked_add` fails closed with `FormatError::Invalid` on exhaustion. | `storing_at_max_generation_fails_closed_instead_of_wrapping` (maki-format `review_format.rs`) |

### Already closed by the 2026-09-07 supplementary review (R01–R08)

- **MAKI-001** (attach rollback disconnecting beneath a failed step) = **R01** — fixed (observation-reconciled, stop-on-failure rollback).
- **MAKI-002** (grow re-verifying live mount/VG) = **R03** — fixed (`verify_live_attachment`). MAKI-002 additionally asks for per-step re-checks of PV/VG/LV/FS UUIDs and the sentinel immediately before *each* of lvextend and xfs_growfs; that finer per-step identity re-observation is tracked below.
- **MAKI-004 / MAKI-005** (hung-command global lock; pre-mount device topology) = **R05 / R02** — the in-process command deadline, pre-mount topology probe, and optional administrator PV/VG/target-LV UUID pins are landed. Target-host udev/root coordination and qualification remain tracked.

### Tracked, not closed in this pass

Each needs a native-Linux VM, real DB/transport servers, an allocation
observer, peak-RSS measurement, or a careful on-disk/attach-flow redesign that
the review itself says to qualify before shipping. None is a newly-introduced
regression.

- **MAKI-009 (P0) — multi-endpoint self-test uses `Uuid::nil`, not the real volume UUID.** `dispatch_endpoint_set` runs its per-endpoint and cross-endpoint checks under a synthetic nil-UUID context before `Engine::attach` reads the superblock, so two endpoints keyed identically for nil but differently for the real UUID pass interchangeability. The fix reads the superblock's real UUID/profile/version first and validates every endpoint (individually and cross) under that context and the real key canary. It restructures the attach flow, and its mismatch-rejection acceptance test needs UUID-divergent transport servers (integration/VM), so it is not landed as an untested change to the crypto-verification path.
- **MAKI-003 (P1) — relative-size grow is not idempotent.** `lvextend -L +bytes` then `xfs_growfs`: a retry after a mid-grow failure can extend the LV twice. Needs a persisted grow op (id, original size, absolute target), observed LV/FS sizes, and skip-completed-steps logic in the privileged executor — VM-qualified.
- **MAKI-023 / MAKI-025 / MAKI-028 / MAKI-035 (memory & scalability)** — deep-check builds the full allocated-unit list; recovery accumulates every replay record; the overlay holds latest+durable+checkpoint ciphertext copies; resident bitmaps and the fallback scan bound large-volume RTO. Each needs streaming/paged redesigns and peak-RSS measurement against real target sizes.
- **MAKI-029 / MAKI-030 / MAKI-031 / MAKI-032 / MAKI-033 / MAKI-034 / MAKI-036 (performance)** — checkpoint under the exclusive lock, synchronous backing I/O on async threads, serial per-chunk crypto, plaintext admission vs. real copies, per-unit syscalls, full-shard bitmap rewrites, per-FUA flush. Design/measurement work, not correctness bugs.
- **MAKI-006 / MAKI-007 / MAKI-040 / MAKI-042 / MAKI-043 / MAKI-044 / MAKI-045 / MAKI-046 / MAKI-047 (deployment & ops)** — readiness vs. process start, a whole-stack recovery controller, a container mount-identity gate, the DB write-path encryption boundary, boot-dependency cycles, failure-domain isolation, backup/restore/key/format procedures, installable packaging, and the systemd credential drop-ins. These are packaging and operational designs to build and qualify on the target host.
- **MAKI-012 / MAKI-013 / MAKI-014 / MAKI-015 / MAKI-018 / MAKI-019 (crypto policy & security)** — the postgres-prod example permitting unauthenticated crypto, replay/rollback outside the threat model, WSS/gRPC TLS unimplemented, transport plaintext copies outside `SecretBuffer` (MAKI-015 overlaps R06), Maki-backed encrypted swap recursion, and the credential/endpoint/key-rotation runbook. Policy decisions plus an allocation observer for MAKI-015.
- **MAKI-020 / MAKI-021 / MAKI-022 (durability & space)** — the durable-mark-plus-final-segment ambiguity threat model, physical-space reservation beyond the projected journal footprint of a write, and TRIM/deallocation. Durability-model and on-disk-format work requiring the release gates and power-loss campaigns.
- **MAKI-024 / MAKI-037 / MAKI-038 / MAKI-039 / MAKI-041 / MAKI-048 / MAKI-049 / MAKI-050 (observability, capacity, docs, qualification)** — deep-check grading vs. authenticated/recovery-view checks, thread-count config surfacing, remote-crypto I/O contract, lock-independent health, capacity/slot-span accounting, doc/CI drift, and the outstanding real-DB/power-loss/soak qualification and DB support matrix.

## Follow-up review (2026-09-08): FUP-001–015

A follow-up review (`maki-followup-review-2026-09-08`) of the updated tree
audited the fixes above, found several incomplete and one regression, and added
15 findings with twelve proposed RED tests. Each item below was reproduced,
fixed, and reverified (GREEN); the proposed tests were adapted to the real
fixtures.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| FUP-001 (P0) | Attach rollback ignored a re-observation *failure* (`if let Ok(observed)`) and gated disconnect only on backend identity, so it could disconnect a device with unknown live mappings. | Rollback is now fully observation-based (`attach_rollback`): tears down the top present layer, disconnects only our own backend, and **fails closed** — halting and keeping the record — on any unreadable observation, remaining holder, foreign backend, or step failure. | `followup_observation_failure_after_activation_must_not_disconnect` (maki-privileged) |
| FUP-002 | A new attach replaced the trusted record when the NBD backend was merely absent, even with a live mount/VG/holder. | Re-observe before replacement; refuse unless every upper-layer resource is also gone (unreadable observation fails closed). | `followup_stale_backend_with_live_mapping_must_not_replace_record` (maki-privileged) |
| FUP-003 | Grow required only `connected`, not a live mount/active VG. | `verify_live_attachment` now requires `mounted` and `vg_active` before any lvextend/xfs_growfs. (Relative-size idempotency of MAKI-003 still tracked.) | `followup_grow_requires_a_live_mount_before_extending_lv` (maki-privileged) |
| FUP-006 | The remote gRPC/WS error *text* was sanitized but still embedded, leaking reflected secrets. | Drop the remote message entirely; only the allowlisted gRPC code / WS class token (mapped to a fixed description) reaches the error. Removed `sanitize_external_message`. | `followup_remote_status_does_not_expose_reflected_secrets` (maki-crypto-grpc) |
| FUP-007 | The decrypt lane charged ciphertext bytes against the plaintext `crypto.batch.max_bytes`, rejecting even a single unit. | The decrypt lane is bounded by its ciphertext pending budget, not the plaintext `max_bytes`; plaintext and wire budgets are kept distinct. | `followup_single_plaintext_unit_budget_works_through_scheduler` (maki-crypto) |
| FUP-008 (regression) | The self-test folded a *transport* error on a negative probe into `ProviderFatal`, aborting the whole attach instead of quarantining one flaky endpoint. | `classify_probe_err` returns a transport error unchanged (inconclusive) so the dispatcher quarantines; only `Integrity` proves the claim. | `followup_inconclusive_negative_probe_preserves_retry_class` (maki-crypto) |
| FUP-009 | `NonRetryableRequest` (incl. generic bad-request) counted as integrity proof, and an empty/malformed `Ok` to a probe passed unchecked. | Only `CryptoError::Integrity` proves it; `Ok` responses are shape-validated. | `followup_empty_moved_reply_does_not_prove_context_binding` (maki-crypto) |
| FUP-010 | The first attach persisted a new key canary without decrypt-verifying it at the reserved index. | Decrypt-probe the new canary at the reserved index and compare to the known plaintext before publishing. | `followup_first_attach_verifies_new_canary_before_publication` (maki-core) |
| FUP-011 | Context-binding was probed only on the unit index, not the volume UUID. | Probe both the unit index and a different volume UUID; XTS (context_binding Absent) is unaffected, AEAD binds the full context. | `followup_context_binding_selftest_exercises_volume_uuid` (maki-crypto) |
| FUP-012 | The per-type A/B read cap missed CheckpointState (kept 1 GiB, ignored trailing bytes) and the `store` generation probe (read via unbounded `RawGeneration`). | CheckpointState declares `MAX_ENCODED_LEN = 32` and rejects trailing bytes; `generations::<T>` bounds the probe by `T::MAX_ENCODED_LEN`. | `followup_checkpoint_v1_has_a_tight_read_bound`, `followup_checkpoint_rejects_crc_valid_trailing_payload`, `followup_superblock_store_raw_generation_probe_is_also_bounded` (maki-format) |
| FUP-013 | Config allowed the in-flight byte budgets to fall below a batch, so the `DualSemaphore` clamped an over-budget RPC through. | Config validation requires `max_crypto_inflight_bytes` and `max_inflight_bytes_per_endpoint` ≥ `crypto.batch.max_bytes`. (Unifying the DualSemaphore oversize semantics still tracked.) | `followup_inflight_byte_budgets_must_cover_a_full_batch` (maki-format) |
| FUP-005 | The unload shutdown error used `tracing::error!` with no production subscriber. | Also write it to stderr (nbdkit captures it, as with open-path failures). (A fuller subscriber/`nbdkit_error` lifecycle with a subprocess log test remains tracked.) | — (C unload shim; not unit-testable) |
| FUP-015 | The failpoint-isolation fix had reduced growth stress to a single thread. | Restored to a 4-worker runtime while holding the failpoint lock (the `!Send` guard lives only in the `block_on`'d test body, never in spawned tasks). | restored `growth_during_workload_creates_shards_consistently` (maki-core) |

### Tracked, not closed in this pass

- **FUP-004 (P1)** — the in-process per-command deadline (bounded output,
  process-group reaping) — same as R05/MAKI-004, still needs the native-VM
  qualification.
- **FUP-014 (P2, later closed on Linux)** — at this review point a TOCTOU
  remained between `FileBacking::resolve` and open (`O_NOFOLLOW` covered only
  the final component). `df886a3` superseded this item on Linux: the backing
  root and every parent are pinned by directory descriptors and all operations
  are descriptor-relative with `O_NOFOLLOW`. Symlink, root-replacement, and
  ancestor-permission regressions pass. The pathname implementation on
  non-Linux development hosts does not claim the same guarantee.
- **Residual sub-parts** — MAKI-003 relative-grow idempotency (persist the
  absolute target), the FUP-007 config alignment to guarantee one max ciphertext
  unit fits every layer, the FUP-013 blocking/non-blocking DualSemaphore oversize
  semantics, and the FUP-005 full logging lifecycle.

## Third-round follow-up (2026-09-10): R3-004, R3-006, K-03 residual

The R3 review (`maki-review-r3`, 2026-09-08) left R3-004 and R3-006 open
after the first batch of R3 fixes. Both were confirmed with RED tests and
fixed. A new randomized multi-cycle durability sweep (workload → power loss
*or* restart → recovery → oracle, with random `fdatasync` failures) then
found two residual conditions of K-03 in the slot store, each minimised to a
named regression test.

| ID | Finding | Fix | Regression tests |
|---|---|---|---|
| R3-004 | `EndpointSet::capabilities` returned the first validated endpoint's contract, so a batch built against it could be routed (load balancing, failover, a quarantined endpoint admitted later) to an endpoint with smaller `max_items`/`max_bytes` or without a claimed security capability. | The set reports the intersection over *all* endpoints: minimum batch limits, intersected plaintext sizes, the largest ciphertext bound, and the weakest security claim (`Capability::weakest`, `CryptoCapabilities::intersect`). | `aggregate_batch_limits_are_the_minimum_over_all_endpoints`, `aggregate_security_capabilities_are_the_weakest_claim`, `quarantined_endpoints_count_towards_the_aggregate`, `aggregate_plaintext_sizes_are_the_intersection`, `batch_within_the_aggregate_survives_failover_to_the_weakest_endpoint` (maki-crypto `review_r3b_endpoints.rs`) |
| R3-006 | The context-binding self-test probed the unit index and the volume UUID only; a provider that normalized `format_version` or the compatibility id passed as fully bound. No wire transport even carried `format_version`. | Two more negative probes (format version, compatibility id); a field-specific `UnsupportedContext` rejection of the foreign value is accepted, while generic request/provider errors and a decrypt to the original plaintext are refused. HTTP gained the `format_version` field source, WebSocket the `format` request field, gRPC `CryptoBatchRequest.format_version = 4`; the reference fixtures bind all three fields (SPEC §18 "Context on the wire"). | `context_binding_selftest_exercises_format_version`, `context_binding_selftest_exercises_compatibility_id`, `explicit_rejection_of_a_foreign_context_passes_the_selftest`, `integrity_for_every_decrypt_never_certifies_a_provider`, `retryable_for_every_decrypt_never_certifies_a_provider` (maki-crypto `review_r3b_selftest.rs`); the authenticated pipelines in each transport's `review_integrity.rs` now run all four probes over the wire |
| K-03 (residual, creation path) | `ensure_shard`'s catalog commit publishes the whole in-memory catalog, which after open names any *adopted* orphan shard — before that shard's allocation map has ever reached disk (only `persist_allocations` had the K-03 ordering). An interrupted checkpoint after such a commit plus a power loss left a cataloged shard with no allocation copy: every later attach refused. | Every shard tracks `map_stored`; `commit_adopted_maps` stores and dir-syncs the maps of adopted shards before *any* catalog commit, in `ensure_shard` as well as `persist_allocations`. | `adopted_shard_is_never_cataloged_by_another_shards_creation` (maki-core `review_r3b_durability.rs`) |
| K-03 (residual, restart path) | After a plain restart an orphan's allocation copy can still be *readable* from the page cache although its sync failed (K-01); `open` loaded it as a valid copy and nothing re-stored it, so the next catalog commit named the shard and the next power loss dropped its only copy. | An adopted shard's loaded map is never trusted as durable: it is re-stored (preserve-first, so the readable copy becomes durable) before the shard can be cataloged. | `adopted_shards_page_cache_map_is_re_stored_before_it_is_cataloged`, plus the sweeps `random_workloads_survive_power_loss_and_restart_cycles`, `random_workloads_with_sync_failures_never_show_foreign_data`, `restart_followed_by_power_loss_keeps_recovered_state` and the `phase_r3b_durability_gate_full` release gate (maki-core `review_r3b_durability.rs`) |
| test hygiene | Four maki-privileged fixtures named temp directories by pid + nanosecond clock; WSL's coarse clock let two tests collide (`File exists`). | A per-process sequence number is folded into the name. | (flake fix; `detach::tests::observation_distinguishes_complete_and_partial_detach` and siblings) |
| R3-004 (addendum) | An `EndpointSet` whose *serving* endpoints report different compatibility ids has no common contract, yet `capabilities()` quietly reported the first one's id. | A validated endpoint with a foreign id is a `Contract` error; a quarantined one is skipped (the validator will never admit it). | `mismatched_compatibility_ids_have_no_aggregate_contract` (maki-crypto `review_r3b_endpoints.rs`) |
| R3-006 (config) | A `remote-http` configuration could declare `context_binding` while its request bodies never carried `volume_id`, `compatibility_id` or `format_version`; every attach then failed late at the self-test with a "decrypts to the original plaintext" probe error. | Config validation requires all three field sources in both bodies whenever `context_binding != "none"`. | `declared_context_binding_requires_every_context_field_on_the_wire`, `without_context_binding_the_context_fields_are_optional` (maki-format `review_r3b_config.rs`) |
| R3-007 (activation intent) | A helper crash after LVM activation but before complete proof publication left exact Maki mappings active without a product cleanup path. | Attach persists verified NBD geometry, partition and LVM intent before activation, then atomically replaces it with the complete proof. Absent-backend `recover` and connected-backend normal detach accept only exact, mount-free verified mappings and run device-list/VG-UUID-scoped deactivation; legacy no-proof/no-intent records stay fail closed. | `recover_tests.rs`, `exec_tests.rs`, and `lvm_preflight_tests.rs`: activation crash, corrupted intent, connected/absent backend, partial verified activation, foreign name/UUID/slave/holder/mount and unknown internal UUID suffix |
| MAKI-005 (administrator pins) | The live LVM inventory was contained to the NBD candidates but was not authenticated against a root-configured expected identity. | Optional all-or-nothing `[lvm_identity]` pins the complete PV set, VG and configured target LV. Attach compares the independent inventory before activation; pins persist into the trusted record and recovery rechecks them (clarified by AUD-051, [#153](https://github.com/seo-rii/maki/pull/153): recovery reads no LVM metadata; it checks the identity attach persisted against the pins, and the live mappings against that identity or the mapping proof). Grow/detach reject changed or omitted pins before mutation. Compatibility mode may omit them, but the production profile may not. | `configured_lvm_identity_pins_are_normalized_and_carried_into_plans`, `configured_lvm_identity_rejects_missing_duplicate_and_malformed_pins`, `administrator_lvm_pins_require_an_exact_pv_set_vg_and_target_lv`, `recovery_rechecks_persisted_lvm_identity_against_administrator_pins`, `lvm_pin_mismatch_stops_before_activation_or_lvm_teardown`, `changed_or_missing_lvm_pins_cannot_authorize_detach_mutations` |
| MAKI-015 (HTTP credential ownership) | Provider-owned resolved header/query values and the combined mTLS identity PEM remained in ordinary allocations after drop or a later construction error. | Operation/TLS specifications and construction guards erase these owners; UTF-8 credential validation borrows the key-source bytes instead of making an intermediate vector. Transport-library copies remain outside the guarantee. | `provider_drop_erases_owned_header_and_query_values`, `provider_construction_error_erases_owned_credentials`, `tls_spec_drop_erases_identity_pem`, `config_error_erases_a_resolved_credential_header` |
| coverage | Configuration drift (a `crypto_unit_size` that no longer matches the volume) through the daemon path; concurrent block-aligned partial-unit (RMW) writers racing FLUSH/checkpoints into power loss or restart; the same sweeps with a tiny plaintext cache (constant eviction and version turnover). No defect found; kept as regression coverage. | — | `crypto_unit_size_drift_refuses_attach_and_leaves_the_volume_intact` (maki-nbdkit `review_r3b_daemon.rs`); `concurrent_partial_unit_workloads_*`, `random_workloads_with_a_plaintext_cache_*`, `phase_r3b_concurrent_gate_full` (maki-core `review_r3b_durability.rs`) |
| S-01 (residual) | A checkpointed unit whose newest allocation-map copy was lost *and* whose slot header was damaged (partly overwritten, not zeroed) read as **zeros**: the older map copy did not list it and the header probe treated every undecodable header as "unwritten". Found by the media-damage sweep (seed 16) within seconds. | A hole is never partly written: on a cleared slot only an all-zero header is unwritten; any other undecodable header is damage ⇒ EIO in `read_slot`. The open-time audit still leaves such slots unmarked (a torn first write of a still-journaled unit is the benign cause and is served from the overlay). SPEC §22 updated. | `damaged_header_on_a_cleared_slot_is_eio_not_zeros`, `media_damage_after_power_loss_never_yields_foreign_data`, `phase_r3b_media_damage_gate_full` (maki-core `review_r3b_durability.rs`) |
| S-01 (residual, truncation) | The same sweep (seed 170): a shard data file truncated below a checkpointed slot whose newest allocation copy was lost too read that unit as **zeros**, because a header beyond EOF counted as "unwritten". A shard data file is created at its full sparse size and synced before it is ever used, so it never legitimately ends before a slot. | A slot beyond the end of a file shorter than its physical size (`units_per_shard × slot_size`) is damage, not a hole. The one legitimate short file belongs to a shard that was never checkpointed into (not named by the loaded catalog copy, empty allocation map): its creation never finished, its holes stay holes and its size is restored before its first slot write. Without that exception, adopting a zero-length orphan turned every unit of the shard into EIO, and later writes never restored the size. An earlier version of the exception required *no* allocation copy on disk; the full durability gate (seed 95) showed an interrupted creation leaving a stale empty copy next to a re-created, zero-length data file, which the rule then took for truncation (every unit EIO after a plain restart). The gate then found the K-01 twin (seed 388, sync faults): the data file's first sync failed, the process restarted, the page cache showed the full size the disk never got, and the next checkpoint wrote into and cataloged the shard — the power loss after that left a cataloged shard with a file ending at its last written slot, "truncated" by the new rule. Nothing proves an uncataloged, never-checkpointed shard's size, so `prove_data_file` sets and syncs it again before the first slot write and before either catalog commit that can name it (`commit_adopted_maps` under `ensure_shard`, and the repair checkpoint's commit in `persist_allocations` — the sync-fault sweep, seed 29, found the latter cataloging a zero-length orphan once checkpoint destinations moved to write admission, after which the next power loss read the whole shard as EIO); `reserve_slot` and the checkpoint slot plan prove it as well, since they grow the file without `write_slot`. Residual: a data file truncated *and* the catalog *and* every allocation copy listing its slots lost is indistinguishable from that orphan and serves zeros beyond the truncation point. *Narrowed on 2026-11-25 by AUD-181 ([#394](https://github.com/seo-rii/maki/pull/394)): the exception is a shard never written into, which also needs no slot below the end of its file to hold a header byte that is not zero, since only a slot write puts one there and the catalog and the map can both fall back to before the first checkpoint; a cut that leaves a written header below it reads EIO beyond the cut. A shard without a data file whose allocation map lists a slot refuses attach. What stays is a cut that leaves no written header byte below the end of the file (a file truncated to zero length, or one whose written slots all lie beyond the cut), or a lost data file, together with the loss of the catalog copy that names the shard and of every allocation copy that lists its slots.* | `truncated_shard_file_reads_eio_for_units_beyond_its_end_not_zeros`, `zero_length_orphan_shard_without_a_map_is_unwritten_not_damaged`, `zero_length_orphan_shard_with_a_stale_empty_map_is_unwritten_not_damaged`, `adopted_shards_data_file_size_is_re_proven_after_a_failed_sync_and_restart`, `adopted_orphan_is_sized_before_a_repair_checkpoint_catalogs_it` (maki-core `review_r3b_durability.rs`); `check_all` now reports the seed, cycle and op history of a failed read |
| S-01 (residual, truncation evidence) | Seed 58 of the same sweep, once the sweep logged its history: the truncated volume kept running, a checkpoint wrote a *later* slot of the shard, and that write grew the file back with zeros. A checkpointed unit in the zero-filled range whose newest allocation copy had been lost then read as **zeros** (all-zero header on a cleared bit), although the attach right after the truncation had reported EIO. The read-time rule above cannot hold once the evidence (the short file) is gone. | Open records the damage in the one place that persists: every cleared slot beyond the end of a truncated file is marked allocated, so it reads as allocated-but-invalid (EIO) until rewritten. Before the shard's first slot write grows the file (`SlotStore::prove_data_file` in maki-core `store.rs`), the marks are stored and dir-synced, then the size is restored and synced; a restart before that re-derives the same marks from the still-short file. The deep checker counts the marked slots as invalid and explains them in a warning. Cost: a unit never written beyond the cut is EIO as well until rewritten, since nothing distinguishes it from a removed slot (SPEC §22). | `truncation_damage_survives_the_file_growing_back` (maki-core `review_r3b_durability.rs`); the sweep failure report now carries the full op history and an on-disk state dump |
| S-04 (confirmed limitation) | The same sweep reproduces the documented S-04 trade-off (seed 56): with the durable mark lost in the crash, bit rot inside the final journal segment's synced records is truncated as a torn tail, so a FLUSH-acknowledged write reverts to its previous durable value instead of refusing attach. Not changed: making the mark durable costs an extra fsync per FLUSH; the sweep tolerates journal damage explicitly. | — | (documented in the sweep's assertion) |
| gate hygiene | `cargo test --workspace --release -- --ignored` (the documented release gate) failed on `exec::command_tests::child_fixture`, an ignored subprocess fixture that panicked when run without its driving test. | The fixture returns early when its scenario environment is absent. | (gate fix; the full gate is otherwise green) |

## Recovery fail-closed rules

Recovery (`maki-core/src/recovery.rs`) now refuses to attach on anything that
is not provably a crash artifact:

- **Bridging.** The oldest surviving segment must start at or before
  `checkpoint_sequence + 1`. A later base sequence means an uncheckpointed
  segment disappeared; internal contiguity of the survivors is no longer
  enough. (A missing *last* segment remains undetectable without additional
  metadata; the writer never acknowledges a record before the segment's
  directory entry is durable, so this needs external damage.)
- **Final-segment header.** A final segment shorter than a header, or entirely
  zero-filled, is a creation crash and is discarded. A complete header that
  fails magic, version, or CRC is durable damage, with one exception since
  AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)): a final segment
  exactly one header long whose header fails its CRC, at an index above the
  segments the durable proof (unless it is empty) and the durable mark name,
  never held an acknowledged record and is discarded as an unfinished
  creation, which the deep check reports as such. Since AUD-003
  ([#166](https://github.com/seo-rii/maki/pull/166)) the writer never extends a
  new segment before writing its header, so a torn header write leaves a file
  shorter than a header; the exception covers the complete-length torn headers
  earlier binaries left, which extended the file first, and such a header
  damaged later. A header followed by record bytes, one the proof or the mark
  names or lies below, one that is not final, and an intact header that does
  not decode are still refused.
- **Size cap.** A segment longer than `max_segment_file_size(segment_size)`
  is rejected before it is read into memory.
- **Durable mark.** After every successful segment fdatasync the journal
  writer records `(segment index, synced byte count)` in
  `journal/durable-mark` with a plain, unsynced write. The mark is only ever
  a lower bound. Recovery classifies damage *before* the mark as corruption
  even when it sits at the very end of the segment, and damage *after* the
  mark as a torn tail even when an intact record follows it. The second half
  matters: records after the last fdatasync may persist in any order, so a
  later unsynced record surviving while an earlier one is lost is a legal
  crash outcome, not corruption. Without a mark the scanner falls back to the
  previous heuristic (payload-CRC failure immediately followed by a valid
  successor is corruption). *Superseded by S-04:* without a mark the final
  segment is proven only as far as the durable proof names it, otherwise only
  its header, and damage beyond that is a torn tail. The deep check named the
  old heuristic until AUD-048
  ([#152](https://github.com/seo-rii/maki/pull/152)).

## Key canary

`maki-format/src/canary.rs`, verified in `Engine::attach` after the provider
self-test:

- **Plaintext.** `canary_plaintext(volume_uuid, unit_size)`: the ASCII tag
  `MAKI-KEY-CANARY-V1` followed by a deterministic pattern derived from the
  volume UUID. Not secret; frozen by a golden vector because an old canary
  must verify forever.
- **Index.** `CANARY_UNIT_INDEX = 0x0010_0000_4D41_4B49`: above any unit a
  volume can address (attach refuses geometries that reach it) and below
  2^53 so JSON-carrying remote providers represent it exactly. Context-bound
  providers therefore bind the canary to an index no data unit uses.
- **Record.** `MAKICNY1 | version | generation | volume_uuid | unit_index |
  ciphertext_len | ciphertext | crc32`, A/B-replicated as `canary.a` /
  `canary.b` in the volume root and made durable (both copies plus the root
  directory) before attach returns.
- **Verification.** Decrypt through `CheckedProvider` and compare with the
  expected plaintext. Integrity, request, provider-fatal and contract errors
  mean "wrong key or provider" (`AttachError::KeyMismatch`); retryable,
  throttled and endpoint-fatal errors are surfaced as the transport errors
  they are.
- **Establishment.** Only on a pristine volume (no checkpoint, no journal
  record, no shard). A volume with data but no canary is probed by decrypting
  one existing unit when the provider declares integrity, and the canary is
  written after a successful probe; without integrity attach is refused
  (`AttachError::MissingCanary`), because an unauthenticated cipher cannot
  prove anything about an old key.

Operational consequences are in [Operations](operations.md#key-binding-at-first-attach).

## Bounded journal

`Engine` (`maki-core/src/engine.rs`) enforces `CheckpointPolicy`, which the
daemon derives from configuration:

| Policy field | Source | Effect |
|---|---|---|
| `journal_high_watermark_bytes` | `backing.journal_max_bytes / 2` | Write path wakes the worker once journal bytes on disk reach it; the worker checkpoints. |
| `journal_max_bytes` | `backing.journal_max_bytes` | Hard limit. A write that would cross it first syncs the journal and checkpoints inline (under the volume lock); if the journal still cannot fit the write, it fails with ENOSPC. |
| `max_pending_bytes` | `limits.max_journal_pending_bytes` | Appended-but-unsynced bytes; the write path forces a journal sync before exceeding it. |
| `emergency_reserve_bytes` | `backing.journal_emergency_reserve_bytes` | Enables write-admission space checks; unknown/error fails closed and reads continue. |
| `low_space_checkpoint_bytes` | `backing.checkpoint_reserve_bytes` | While admission is enabled, its value is preserved as headroom after the exact next record/segment-header footprint; the worker also checkpoints eagerly below it. |
| `interval` | 30 s (engine default) | The worker syncs pending records and checkpoints at least this often while anything is unapplied. |

Since AUD-004 and AUD-005 ([#168](https://github.com/seo-rii/maki/pull/168))
the watermark and low-free-space passes sync the journal before they
checkpoint, as the interval pass does, and a write refused at the hard limit or
the overlay bound holds a reclaim gate until it has appended, so concurrent
writes cannot take the space its inline checkpoint frees. Since AUD-052 and
AUD-053 ([#176](https://github.com/seo-rii/maki/pull/176)) every worker pass,
whatever started it, still checkpoints the records that were already durable
when its journal sync fails, and the watermark trigger also requires a sealed
segment on disk, because a checkpoint never deletes the active segment.

The worker holds only a weak reference to the engine and exits when the
engine is dropped. Free space is queried through `Backing::free_bytes`
(`statvfs` on Unix; unknown elsewhere and in the in-memory backings unless a
test sets it) and cached for one second of the engine's clock.

A checkpoint failure on any path increments `checkpoint_failures_total` and
sets `EngineState::Degraded { reason }`; the next successful checkpoint
returns the engine to `Ready`. The control socket reports the state in
`status` and as `maki_volume_state` (1 ready, 2 degraded).

## On-disk additions

This section records the intermediate v1 state at the time of that remediation.
At that point the additions were new files and the format version remained 1.
The current release instead requires the v2 superblock envelope and dual
durable-proof records described in [Durable recovery](durable-recovery.md);
that later contract supersedes the current-tense v1 statements below. Volumes
created before the intermediate changes lacked these files:

- `canary.{a,b}`: established on the next attach as described above.

- `checkpoint/state.{a,b}` are now written at creation and **required** by
  recovery. A pre-existing volume that was never checkpointed will fail to
  attach with `no valid checkpoint state copy`.
- `journal/durable-mark` is created empty at creation and recreated lazily by
  the writer if absent. Its absence only weakens corruption detection.

### R3-006 context refusal classification after the remote follow-up

The full-context probes and all upstream transport fields remain in place.
Schema rejection now identifies the refused field with
`CryptoError::UnsupportedContext(ContextField)`. Only the probe changing that
same field accepts it; generic `ProviderFatal`/`NonRetryableRequest` errors,
wrong-field refusals, and schema errors during integrity tests never certify a
capability. Availability errors still propagate for endpoint retry/quarantine.
The local and reference providers identify compatibility-ID refusal explicitly.
HTTP/gRPC carry the allowlisted field token in one `maki-crypto-error` value;
WebSocket uses `unsupported-context` plus the same reason token. Duplicate or
ambiguous values are rejected and remote text is not reflected.

Validation: `review_r3_context` supplements the upstream `review_r3b_selftest`
with matching-field, wrong-field/generic-error, and inconclusive-probe tests.
Each transport's `review_integrity` covers exact field tokens and malformed
signals as well as the authenticated engine pipeline using the full context.

## R3 final status and lifecycle qualification (2026-09-13)

The direct R3-001–010 causes are closed in product paths and focused tests.
This table distinguishes that closure from broader production qualification
that the review bundle also tracks.

| R3 item | Final direct-finding status | Evidence |
|---|---|---|
| R3-001 wire integrity | Closed | `3703683`; authenticated ciphertext reaches the engine and wire mappings preserve integrity, schema, and timeout classes |
| R3-002 rollback ownership | Closed | `c834ff5`; foreign or unreadable backend identity stops teardown and preserves trusted state. *Superseded in part by AUD-134 ([#367](https://github.com/seo-rii/maki/pull/367)):* a trusted record whose device carries another connection is retired, without a command, when it names its VG UUID and nothing of its attachment remains; teardown still never touches a foreign backend |
| R3-003 request budgets | Closed | `4449a74`; logical, ciphertext, and RPC boundaries reject oversized requests before mutation |
| R3-004 endpoint capabilities | Closed | Preserved per-endpoint intersection plus `27dce14`; heterogeneous endpoint regressions pass |
| R3-005 UUID/canary identity | Closed | `8e725fc`; locked actual UUID, per-endpoint canary, and quarantine recovery tests |
| R3-006 full context | Closed | `dd87466`; only exact context-field refusal is accepted as capability evidence |
| R3-007 recovery lifecycle | Product path closed; installed crash and scoped topology qualification passed | Intent/recover/verify plus `3fc0404` convergent cleanup and `98a5b0e`/`90843db` packaged lifecycle; `448c0b2` combined the installed graph, actual storage, and SQLite through two automatic nbdkit crashes plus an open-LV cleanup failure/retry. The `3cac300` package campaign additionally refused a dead-backend two-LV fallback and a same-NBD foreign backend before mutation. Nested/internal mappings, partitions, holders, hot replacement and production topology remain |
| R3-008 shutdown result/logging | Closed for supported foreground mode | `dc646ef`; explicit drain result, admission closure, retry, subprocess logging, and concurrent shutdown tests |
| R3-009 response shape | Closed | `57ca845`; empty, extra, wrong-index, and wrong-length responses fail without panic |
| R3-010 capability mode | Closed | `40502a7`; only declared mode is accepted and remote declarations are contractual |

The earlier safe privileged run at `5a3bef6` used nbd-client 3.27.1 and passed
22 checks on a disposable Debian 12 GCE host: real kernel NBD, single-PV
LVM/XFS with all UUID pins, attach, verify, two cleanup calls, fio, SQLite WAL,
and an offline check. The actual systemd transaction used fixture daemon,
attach, verify, and workload components but proved stop, cleanup-success
restart, cleanup-failure hold, and per-start gate ordering. A separate Docker
run observed default `rprivate` propagation, distinct container IDs and
creation times, SQLite rows 1→2 with `integrity_check=ok`, and zero container
starts on a plain directory. Those two runs did not combine the Maki storage
stack and installed controller.

Revision `8bf0e941bd3501b972850240fb1050fbc2a90c0b` then passed 29 checks in one
combined campaign. A default-`rprivate` Docker container committed 32 SQLite
WAL `synchronous=FULL` rows individually and recorded each ACK in an external
fsynced ledger. The actual nbdkit process exited 137 after `SIGKILL`; kernel NBD
remained connected, and `maki-attach verify` still succeeded because it checks
storage identity and topology rather than server liveness. Cleanup used the
completed proof to remove the one exact closed mapping after normal `vgchange`
failed, disconnected NBD, and reattached after nbdkit restart. A distinct
container recovered all 32 ACK rows exactly and returned
`integrity_check=ok`. Final cleanup, its idempotent replay, and the offline
check passed.

The proof fallback is limited to cleanup of one exact top-level target mapping;
it rejects explicit detach/recover, pre-activation intent, multi-LV/internal or
open/changed mappings, backend identity changes, and command timeouts. The
combined campaign did not execute the installed systemd controller or cover a
remote provider, whole-VM/physical power loss, another database, repeated
crashes, or soak load.

Revision `448c0b2a46bd748eb473e34405175db9b3cfa102` then installed the shipped
systemd, sysusers, and tmpfiles artifacts over the actual single-PV/LV stack on
a new Debian 12 GCE host. Two successive daemon `SIGKILL` events automatically
recreated the daemon, attachment, per-start verification, and default-`rprivate`
container while preserving external ACK prefixes of 32 and 48 rows. On a third
crash, a root-held LV descriptor made both attach stop and recovery cleanup fail
closed. The workload stayed stopped, the ledger stayed at 48, and NBD, the
mapping, backend identity, and trusted volume record remained. Closing the
descriptor and explicitly retrying recovery produced a fourth container and 64
external-ACK rows. An independent reader matched every SQLite row and payload
hash with `integrity_check=ok`.

The final drain, target stop, ordered workload/attach/daemon completion, plugin
unload and offline check passed with no remaining mount, mapping, NBD holder,
volume record, or container. The result closes the earlier installed-controller
combination gap for this one local-provider topology. It does not qualify a
distribution package install or upgrade, multi-LV/internal mapping, foreign
device replacement, remote providers, another database, DB-native migration,
whole-VM loss on this topology, or soak load.

At that point, revision `ece7e39` passed a separate
[fresh-host backing restore](qualification/fresh-host-restore-validation-2026-09-17.md).
A source GCE VM wrote and externally acknowledged 32 SQLite rows, drained,
passed the offline check and exported the unchanged v2 backing, configuration,
attach identity and credential. That VM and disk were deleted before a distinct
target VM restored the artifacts, matched all 32 rows, advanced to 48 and
matched all 48 again after a lifecycle restart. Both SQLite integrity checks,
final drain, offline check and cloud cleanup passed. Three retained harness
failures occurred before the product path: a `sudo` home-directory mismatch, a
missing parent-directory mode in the ad hoc runtime tar, and non-idempotent
`reset-failed` handling. Distribution package install/upgrade, DB-native or
legacy migration and crash-time capture remain open.

Revision `c385c99` then passed a separate
[remote HTTP provider database campaign](qualification/remote-provider-db-validation-2026-09-18.md)
on a disposable Debian 12 GCE VM. Two authenticated loopback providers served
the actual packaged systemd, kernel NBD/LVM/XFS, and SQLite WAL path. Rows 0–7
used both endpoints, 8–15 used only B after A stopped, and 16–23 used only A
after B stopped. With both providers down, the next DB writer stayed blocked
and the fsynced external ledger stayed at 24; restoring B advanced it to
exactly 25 after a 4,094 ms observed outage. Both providers then returned and
the database reached 32 exact ACK rows. All row IDs and body hashes plus
`integrity_check=ok` matched before and after a packaged lifecycle restart.
Metrics recorded six failovers and nine retries, and provider journals recorded
21,326 encrypt/decrypt requests across both endpoints. This closes the narrow
database-through-provider fault observation, while real network/TLS/vendor
behavior, another DB, concurrent host loss, latency targets and soak remain.

Revision `5f50354` then passed a separate
[PostgreSQL process-crash campaign](qualification/postgresql-crash-validation-2026-09-18.md)
on a disposable Debian 12 GCE VM. PostgreSQL 15.19 ran with data checksums,
`fsync`, synchronous commit and full-page writes on the actual packaged Maki,
kernel NBD/LVM/XFS path. After 16 external ACK rows, a cgroup-wide postmaster
`SIGKILL` interrupted four pgbench clients after 590 transactions. A distinct
postmaster performed WAL redo and an end-of-recovery checkpoint, preserved the
entire ACK/hash prefix, and passed `pg_amcheck`. The cluster advanced to 32
rows, retained all 32 through a packaged Maki lifecycle restart, then reached
48 rows. Four `pg_amcheck` runs were clean. This narrows the other-database gap
for one short PostgreSQL profile; production sizing, backup/restore,
replication, DB-native migration, concurrent VM/storage loss and soak remain.

Revision `3cac300` then passed a separate
[package, topology, and migration campaign](qualification/package-topology-migration-validation-2026-09-19.md)
on one disposable Debian 12 GCE VM. A generated pre-upgrade package cleanly
installed and ran two simultaneous pinned NBD/LVM/XFS volumes, including a
sidecar LV. The generated current package preserved every config and token hash,
did not auto-start a volume, and reattached both SQLite databases with unchanged
logical hashes. A corrupt native restore failed before clean retry. A matching
old reader backed up a clean legacy-v1 volume; the current writer refused the
unchanged v1 superblocks, and the backup restored exactly into fresh v2.

After a daemon `SIGKILL`, packaged recovery preserved both top-level mappings
and the trusted proof when proof-scoped fallback refused the ambiguous topology.
Cleanup also preserved a same-number foreign NBD backend and trusted record.
Explicit cleanup then converged, both offline deep checks reported zero invalid
slots, and exact instance/disk lookups plus prefix queries proved cloud cleanup.
This closes those scoped package, multi-mapping, foreign-backend and SQLite
migration observations. Signed repositories, rollback, nested device stacks,
live backup/cutover and other databases remain open.
*Superseded in part by AUD-134 ([#367](https://github.com/seo-rii/maki/pull/367)):*
cleanup now retires a trusted record beside a foreign backend, without
touching the backend, when the record names its VG UUID and nothing of its
attachment remains; that path has not been qualified on a real kernel.

The disposable instances and their auto-delete boot disks were deleted. The
last fresh project queries found zero name-matched `maki-*` instances and disks,
and the latest combined disk's exact lookup returned 404. The CI run for
`448c0b2` passed on Linux and Windows.

Capacity follow-up `5803be8` partially closes MAKI-041's accounting gap. The
geometry API and `maki volume inspect` now report maximum units and shards,
full-shard slot span, and both copies of allocation-map and catalog metadata.
They reject shard counts above the supported catalog limit and `u64` layout
overflow. The standard 16 TiB geometry has an 18 TiB slot span before journal,
checkpoint, filesystem, or database overhead. This planning output does not
reserve physical blocks and does not close MAKI-021's external-consumer race.

Physical reservation follow-up `ced2bda` closes that race for accepted Maki
writes on Linux. The write path uses `posix_fallocate` for the exact journal
range and full checkpoint slot before appending, and creates and syncs both
allocation-map copies plus the catalog entry before a new shard can receive a
journal record. Injected slot and journal ENOSPC leave the sequence unchanged
and retry successfully. A real-filesystem regression verifies allocated slot
blocks and both metadata copies before the first record is accepted. Core
all-targets passed 204 tests with 6 ignored, and strict Clippy passed. This is
not full-volume preallocation: untouched slots, filesystem/COW overhead, and
database temporary space remain deployment-capacity inputs. The reservation
also does not hold for extents a backing file shares with a reflink copy,
which `posix_fallocate` does not unshare (AUD-049,
[#152](https://github.com/seo-rii/maki/pull/152)).

The later [GCE physical reservation campaign](qualification/physical-reservation-validation-2026-09-18.md)
exercised that path on ext4 over a separate standard Persistent Disk. A
4,608-byte slot owned 8,192 allocated bytes before the first FUA ACK, and both
allocation-map copies owned blocks. After consuming all 9,910,247,424 initially
free bytes, the next FUA returned ENOSPC while sequence 1, the journal hashes,
and slot allocation stayed unchanged. Releasing the space allowed sequence 2;
restart readback, deep check, and unmounted `e2fsck` passed. This qualifies one
Linux filesystem and storage class, not full-volume capacity or physical power
loss.

Bounded recovery follow-up `733833c` removes the attach-time map of retained
latest ciphertext. Recovery validates and repairs the full journal first, then
replays it through a 1 MiB batch into durable checkpoint slots. Controlled
tests held the measured replay peak near 1.1 MiB for 4,096 distinct records and
16,384 overwrites, and a slot-sync crash retried from the preserved journal.
The actual Docker cgroup campaign then recovered a 21.5 MiB pressure tail at a
32 MiB cap and matched 136 external ACK units, but touched the cap exactly.
This closes payload retention proportional to distinct units; metadata,
runtime/provider allocations, filesystem cache and a production RSS minimum
remain target-specific qualification inputs.

A later [constrained recovery RSS campaign](qualification/recovery-rss-validation-2026-09-19.md)
ran two fresh 48 MiB and two fresh 64 MiB post-OOM recoveries. All four matched
136 ACK units and passed deep checking; the maximum observed nbdkit `VmHWM` was
11,415,552 bytes. Both 64 MiB runs stayed below the cgroup cap with zero max
events, while both 48 MiB runs touched the cap. This supplies a scoped process
RSS high-water observation and cgroup sizing result, not a universal bound.

Revision `47058d2` then passed a separate
[cross-host TLS reference-provider campaign](qualification/cross-host-tls-provider-validation-2026-09-19.md).
Two GCE provider hosts required mTLS and a bearer credential over private VPC
addresses. Explicit TLS 1.2 and TLS 1.3 health gates passed; wrong CA, absent
client identity and wrong bearer all refused startup before
daemon readiness. Provider-VM stop/start exercised each endpoint alone and
both absent, after which SQLite reached 32 exact external ACK rows and retained
them through a Maki restart. The final deep check had zero invalid slots and all
three VMs and disks were deleted. This closes the scoped cross-host HTTPS
reference-provider observation, while commercial vendor behavior and target
network faults remain open.

Revision `bdb9113` then passed a separate
[credential rotation and key migration campaign](qualification/credential-rotation-key-migration-validation-2026-09-19.md)
on the same three-host class of topology. A stopped K1 volume rejected its old
bearer and mTLS client identity after rotation, validated the replacement
identity on both peers, preserved its superblock/canary hashes, and reached 16
external ACK rows. A SQLite DB-native backup restored into a distinct K2 volume;
an isolated K1 wrong-key canary was refused with unchanged superblock/canary
hashes, and 24 ACK rows survived a full restart. Both retained volumes had zero
invalid slots and all resources were deleted. This closes the tested
reference-provider client-credential and stopped K1-to-K2 migration profile.
Commercial vendors, target networks, key retirement and production
cutover/rollback remain open.

Revision `da89ae3` then passed a four-host
[server CA and endpoint-address campaign](qualification/server-ca-endpoint-rotation-validation-2026-09-19.md).
Stopped transitions exercised mixed old/new server certificates with overlapping
private roots, new-only trust, and wrong-trust NBD refusal in both directions.
A/B changed to distinct-IP C/B with A's nginx listener stopped and the encryption
key/profile, client credentials and volume identity unchanged. Both configured
peers validated at each restart, superblock/canary hashes matched across each
attach, and all 48 exact ACK rows survived. This qualifies that stopped
reference-provider path, not C-only service, hot reload, CA revocation or a
commercial deployment. The harness corrected two false failures in TDD: socket
existence was mistaken for readiness, then an outer operation-deadline error
was mistaken for an unrelated failure. Prior reports now describe the verified
startup-refusal boundary accurately.

The supplied R3 directory is retained because it also contains the inherited
MAKI/FUP production checklist. Universal and target-profile RSS bounds,
remaining transport-library copies, checkpoint stalls, actual provider
faults over a commercial vendor and target network, replay policy, key migration,
broader and live database migration, production database profiles and remaining
engines, physical power loss, and long-duration load remain open.
Direct R3 closure must not be read as general production approval.

## Fourth review (2026-09-23): R4-001–R4-007

A code and packaging review of the 2026-09-22 tree looked at observability,
memory protection scope, resource bounds, diagnostics and package behaviour
rather than at durability under crash. It reproduced the packaging finding
(R4-007) directly and reported the Rust findings from code analysis. None of
them is an acknowledged-data-loss defect. Each fix below starts from a
regression test that failed before the change.

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R4-001 (logging) | The default plugin execution path never installed a `tracing` subscriber, so `checkpoint worker: … failed`, `control socket server stopped`, provider quarantine and store repair warnings were dropped; only startup and unload failures used `eprintln!`. | `maki_core::logging::install_default_logging` installs a stderr `fmt` subscriber (no ANSI, target and fields, `MAKI_LOG` filter, default `info`). The plugin calls it in `config_complete` and again in `after_fork` (idempotent); `maki` and `maki-check` call it at startup. Follow-up (2026-09-29): `maki-attach` dropped its executed steps and halted-rollback errors the same way; `maki_privileged::logging` installs the equivalent sink without linking crypto crates (PRIV-010). Documented in [operations](operations.md#logging). | `logging::tests::*` (maki-core; a child process installs the subscriber and the parent checks its stderr and the `MAKI_LOG` filter), `runtime_warnings_reach_stderr_in_the_default_plugin_path`, `maki_log_filters_the_default_plugin_output` (maki-nbdkit `review_r4_native_logging.rs`: real nbdkit, an adopted orphan shard's `WARN` must appear in the captured stderr), `maki_privileged::logging::tests::*` |
| R4-002 (guarded plaintext) | `local-aes-gcm-siv` decrypted with the allocating AEAD API into an ordinary `Vec` and wrapped it in `SecretBuffer` afterwards; XTS copied ciphertext through a plain `Vec`; encryption copied plaintext into an unlocked vector before encrypting; key files were read into a plain `Vec` and hex-decoded into another. `secure-buffers` therefore did not cover plaintext or keys during their first moments. | The guarded buffer is allocated first and the AEAD/XTS operation runs in place (`encrypt_in_place_detached` / `decrypt_in_place_detached`, `encrypt_area` / `decrypt_area` on `expose_mut()`); key files are read straight into a `SecretBuffer` and hex-decoded into one; `SecretBuffer::from_vec` now counts `unguarded_wraps()`; `SecretBuffer::truncate` added; the `aes` crate's `zeroize` feature erases key schedules on drop. Follow-up (2026-09-29): the cipher objects moved into `SecretBox<T>`, a page-locked heap box that drops (erases) the value before unlocking and erases the move's staging copy, so the expanded key schedules are covered by `secure-buffers` too. Residual: cipher-crate stack temporaries ([transport memory](transport-memory.md#local-providers-and-key-material)). | `review_r4_guarded_buffers.rs` (maki-crypto-local: encrypt, decrypt, tampered-ciphertext failure and file/env key loading must not move `unguarded_wraps()`; `key_schedules_are_page_locked_under_secure_buffers`, `locked_key_schedules_still_encrypt_and_decrypt`), `truncate_keeps_the_allocation_and_erases_the_tail`, `guarded_constructors_are_not_counted_as_unguarded_wraps`, `secret_box_drops_its_value_exactly_once`, `secret_box_is_page_locked_when_enabled_and_redacted` (maki-crypto) |
| R4-003 (package removal) | The package had `postinst` and `postrm` only. `apt remove maki` under a live attachment deleted `maki-attach`, the very program `ExecStop=` and `maki-recover@` need to detach, leaving no normal cleanup path. | A `prerm` refuses `remove`/`deconfigure` while a trusted attachment record exists under `/run/maki-attach/` or a `maki@`, `maki-attach@` or `maki-workload@` unit is active, and prints the drain-then-deactivate procedure. `upgrade` is exempt and no maintainer script starts, stops or restarts a service. Follow-up (2026-09-29): a failed `systemctl list-units` was read as "no active units" (the pipeline status was `awk`'s); it now refuses the removal. | `test_prerm_refuses_removal_while_a_volume_is_attached`, `test_prerm_refuses_removal_while_a_maki_unit_is_active`, `test_prerm_allows_idle_removal_and_never_blocks_an_upgrade`, `test_prerm_fails_closed_when_systemd_cannot_be_queried`, and the no-`systemctl start/stop/restart` scan over every maintainer script (`scripts/test_debian_package.py`) |
| R4-007 (package inputs) | `build-deb.py` checked only the *format* of `--architecture`; x86-64 artifacts requested as `arm64` produced a valid-looking arm64 package (reproduced by the reviewer), and `Depends` never reflected the binaries' native libraries. | Every release file's ELF header (machine, class, byte order, type) must match the requested architecture; the plugin must be `ET_DYN` and the binaries executables; unknown architectures are refused. `--shlibdeps` runs `dpkg-shlibdeps` and appends the result to `Depends`, failing closed when the scan cannot analyse an artifact. The package tests now use ELF stubs instead of text files. Follow-up (2026-09-29): the scan is the default, a missing `dpkg-shlibdeps` fails the build, and `--no-shlibdeps` (test fixtures only) warns. | `test_package_architecture_must_match_the_elf_binaries`, `test_release_files_must_be_elf_images_of_the_right_kind`, `test_unknown_debian_architecture_is_refused_before_building`, `test_shlibdeps_option_fails_closed_on_artifacts_it_cannot_analyse`, `test_native_dependency_scan_is_on_by_default`, `test_opting_out_of_the_scan_keeps_the_static_depends_and_warns` |
| R4-004 (deep-check verdict) | `maki check --deep` reported every slot CRC failure as an error, although recovery rewrites a checkpointed slot from a validated journal record newer than the checkpoint. An operator could read a routinely recoverable volume as a data-loss incident. | The journal summary now also returns the set of units with an uncovered validated record (`ReplayRecords::Units`, one `u64` per unit, no payloads). A failing slot whose unit is in that set is reported as `warning: slot: recoverable: …` and does not fail the check; other damage stays an error. The report ends with `deep check verdict: clean \| recoverable \| unrecoverable` and counts both classes ([operations](operations.md#volume-lifecycle)). Follow-up (2026-09-29): the check walked only allocated units and called a volume clean whose unlisted slot held a damaged header, which the read path refuses (S-01 residual); it now probes those slots too (`SlotStore::unlisted_units`). | `review_r4_check_verdict.rs` (maki-core): recoverable damage passes with a warning and is repaired by the next recovery, damage without a source fails, mixed damage reports both classes, a healthy volume is `clean`, `damage_in_an_unlisted_slot_is_reported_like_the_read_path_refuses_it` |
| R4-005 (overlay bound) | `limits.max_ciphertext_bytes` only bounds the remote scheduler's pending queue (local providers bypass it), while the overlay that holds journaled, uncheckpointed ciphertext had no bound of its own: with a slow or failing checkpoint it could grow toward the multi-GiB `journal_max_bytes`, a disk budget that is not an instance's RAM budget. | New `limits.max_overlay_bytes` (default 256 MiB) and `limits.max_overlay_entries` (default 262144) reach `EngineLimits`. Admission charges a request at its eventual size (`max(bytes, 2 × latest_bytes) + 2 × payload`, since every unit ends up with a durable copy); a write that would exceed a bound syncs and checkpoints inline like the journal hard limit and returns ENOSPC after a failed reclaim; the worker checkpoints at half of either bound. The overlay tracks `latest_bytes` (sanitizer-checked). Validation requires the byte bound to hold the largest request (`nbd.maximum_io` plus one unit, as ciphertext) twice and the entry bound to hold it in units; `0` disables. Library callers keep the unbounded default. Follow-up (2026-09-29): a write still over a bound after its reclaim was refused even when concurrent writers' volatile records were what kept it out (a checkpoint retires only up to the durable mark); it now syncs and takes another round while volatile records exist, up to `MAX_RECLAIM_ROUNDS` (4), for the journal hard limit too. *Superseded by AUD-004 ([#168](https://github.com/seo-rii/maki/pull/168)):* concurrent writers could still take the freed space in every round; a refused write now holds a reclaim gate that other writes queue behind until it has appended, and the round limit remains only as a termination bound. | `review_r4_overlay_bound.rs` (maki-core: bytes and entries stay under their limits through 96/40 writes without journal pressure, the worker checkpoints on the watermark with a manual clock, a failed reclaim refuses the write and degrades, zero keeps library callers unbounded, `a_concurrent_volatile_write_during_inline_reclaim_does_not_cause_enospc`), `review_r4_overlay_limits.rs` (maki-format defaults, zero, minimums), `review_r4_overlay_options.rs` (maki-nbdkit mapping) |
| R4-006 (cache-first reads) | `read_secret` called `read_ct` (slot header, full ciphertext, CRC) *before* consulting the plaintext cache, so a hit only saved the provider call: the cache was a decryption cache, not a read cache. | The read path first establishes the unit's current write sequence (`Volume::current_sequence`: overlay entry, else the 64-byte slot header through `SlotStore::slot_sequence`, which applies every header-level refusal of `read_slot`) and serves a `(unit, sequence)` hit without reading the payload; misses read and decrypt as before. Versioning is unchanged (a newer write changes the sequence). Documented trade-off: a hit does not re-verify the on-disk payload CRC of an already validated version until the entry is evicted; header damage still refuses the read and the deep check still finds payload damage. Follow-up (2026-09-29): `cache.verify_on_hit = true` re-reads and CRC-checks the payload on every hit and uses the cache only to skip decryption. `CrashableBacking::read_bytes()` counts served read bytes for tests. | `review_r4_cache_reads.rs` (maki-core: a hit reads ≤ 64 bytes and no provider call, an overlay hit reads nothing, newer versions miss, header damage is EIO despite a cached entry, payload damage is served until eviction then EIO, no-cache reads still verify, `verify_on_hit_rereads_the_payload_but_skips_decryption`; maki-nbdkit `review_r4_cache_verify_options.rs`: off by default, reaches the engine) |

## Fifth review (2026-10-01): R5-001–R5-034

A whole-tree review of `10b0b25` found CI red on `main` and a set of
privileged, transport and discard defects; none loses FLUSH-acknowledged data
or returns zeros for damaged data. Each code fix starts from a regression test
that failed before the change.

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R5-001 (CI) | Every `main` run since `9122777` failed at `cargo fmt --all --check`, so clippy, the workspace tests, `cargo audit` and the docs-link check never ran for the R4 work. The nightly gate filter named seven gates and silently skipped the three R3b sweeps. | `cargo fmt --all`; the nightly job runs `-- --ignored` without a name filter ([testing](testing.md)). Stale untracked `review_next_*` reproductions of already-fixed BUG-016/023/024 were removed. | CI itself |
| R5-002 (mount options) | `maki-attach` mounted XFS as root with `-o noatime` only. The filesystem's bytes come from the unprivileged daemon and an untrusted provider, so a crafted image with a setuid-root binary or a device node for a host disk was a local privilege escalation. | Mount with `noatime,nosuid,nodev` (`plan::MOUNT_OPTIONS`); `verify_mount_device` (and so attach, `verify` and the post-mount check) refuses a mount whose mountinfo options lack `nosuid` or `nodev`. `maki@.service` adds `DevicePolicy=closed` (not `PrivateDevices=`, which would hide the `/dev` nodes the swap-policy check stats). | `review_r5_mount_options.rs` (maki-privileged: planned options, mountinfo option parsing, refusal without either flag) |
| R5-003 (environment proxy) | `reqwest` honours `HTTP_PROXY`/`ALL_PROXY` by default and the HTTP provider never disabled it, so a daemon inheriting `http_proxy` sent every loopback `http://` encrypt request (plaintext and credential headers) to the proxy and accepted its reply as ciphertext. | `Client::builder().no_proxy()`; documented in [architecture](architecture.md). | `review_r5_proxy.rs` (maki-crypto-http: a recording proxy in the environment and a closed endpoint; the proxy must see nothing and the request must fail) |
| R5-004 (scheduler re-send) | `1678e3e` re-sent each request of a coalesced batch that failed with a request-class error without checking `retry_safe`, so a provider declaring itself not retry-safe received the same plaintext units twice, breaking the M-010 promise the `EndpointSet` keeps. The re-send loop also awaited outside any cancellation `select!` while holding the lane slot and after `inflight_batches` was decremented: with `max_inflight_batches = 1` a hung re-send blocked every new request after its callers had gone. | The per-request path runs only when the inner provider's capabilities report `retry_safe`; otherwise the error fans out as before. Each re-send is counted in `inflight_batches` and raced against its caller's `closed()`, so an abandoned one releases the slot. | `review_r5_scheduler_resend.rs` (maki-crypto: exactly one provider call for a non-retry-safe provider, per-request verdicts kept for a retry-safe one, abandoned re-send frees the only lane slot) |
| R5-005 (endpoint attribution) | A `Contract` error (malformed response, wrong item count, bad encoding; `ProviderFatal` class) and a generic HTTP 4xx (`NonRetryableRequest`) returned from `dispatch` at once and dropped the breaker probe without a verdict. A misrouted endpoint (404, an HTML page) therefore never opened its circuit, and stable least-inflight ordering kept picking it: 100 of 100 requests failed with a healthy peer idle. | In a set, `Contract` charges the endpoint's breaker and a retry-safe request fails over to an endpoint it has not tried; with none left (a single endpoint included) the error is returned immediately, so the stall policy never retries into it. HTTP 404/405/410 map to `EndpointFatal`. Integrity, `UnsupportedContext` and other 4xx are unchanged. *Superseded by the follow-up below and AUD-021 ([#154](https://github.com/seo-rii/maki/pull/154)):* the violation is returned at once only when every validated endpoint (a single one included) has broken the contract for the operation; while another validated endpoint remains, even one that failed transiently or whose circuit is cooling, the operation stays in the normal backoff loop with the violators excluded. | `review_r5_endpoint_attribution.rs` (maki-crypto: failover plus open circuit, no re-send when not retry-safe, single endpoint reports the violation), `missing_operation_statuses_are_endpoint_faults` (maki-crypto-http `phase8.rs`) |
| R5-007 (literal secrets) | The SPEC §9 literal check was an exact match against nine names, so `X-Vault-Token`, `X-Goog-Api-Key`, `Ocp-Apim-Subscription-Key`, `X-Amz-Security-Token`, `apikey` and `X-Auth-Key` validated as inline literals. A credential reference on a header outside the list also skipped `validate_credential`. | `is_sensitive_header`: the exact list plus credential-like name fragments; every credential reference is validated whatever header carries it. Query parameters remain literal-only and are documented as never holding secrets. | `review_r5_sensitive_headers.rs` (maki-format: eleven vendor names refused as literals and accepted as references for HTTP and gRPC, ordinary headers keep literals, references on ordinary headers validated) |
| R5-008 (punch ordering) | `finish_checkpoint` punched discarded slots before storing the new `checkpoint_sequence`. With an older durable write of the unit still in the journal (superseded by the tombstone), a failed state store or power loss in that window made recovery replay the write into the punched hole: new blocks, ENOSPC on a full backing, against the reservation promise in [space reclamation](space-reclamation.md). The existing guard covered only versions newer than the tombstone. | Collect the punchable units first, punch after the checkpoint state and its directory are synced. A punch failure there is logged and schedules the reclamation scan instead of failing a checkpoint that is already durable. `partial_punch_failure_keeps_both_discards_and_the_gap_across_crash` now expects the checkpoint to succeed; its durability assertions are unchanged. | `review_r5_reclamation.rs::a_slot_is_punched_only_after_the_checkpoint_that_retires_it_is_durable` (maki-core), `review_discard_crash.rs` |
| R5-009 (catalog commit) | `ensure_shard` inserted the shard into the in-memory catalog before `catalog_ab.store` and the root directory sync. When either failed, the catalog listed a shard that was not open, and the reclamation cursor's next-shard search indexed `self.shards[next]` and panicked every checkpoint that finished the cursor's shard. | Commit a cloned catalog and adopt it only after the store and sync succeed; the reclamation scans look shards up with `get`. | `review_r5_reclamation.rs::a_failed_shard_catalog_commit_does_not_break_reclamation` (maki-core) |
| R5-010 (long trim) | The adapter and `Engine::trim` refused a trim longer than `nbd.maximum_io` with EINVAL. The NBD maximum block size limits payloads and TRIM has none; the Linux nbd driver sends discards up to its own `max_discard_sectors`, so `fstrim` and `-o discard` were refused in practice. Reproduced end to end: libnbd's 64 KiB `nbd_trim` against an 8 KiB maximum reached the plugin through nbdkit 1.32 and failed with `Invalid argument`. | Trim validates alignment and bounds only (`validate_extent`, `check_extent`) and the engine journals it in unit-aligned chunks of at most `max_request_bytes`, each with its own admission and unit locks; FUA applies to the last chunk, whose sync makes the earlier ones durable. | `review_discard.rs` (maki-nbdkit: `a_trim_longer_than_maximum_io_discards_every_whole_unit` across reopen; the native libnbd case now also trims 64 KiB) |
| R5-011 (discard admission) | `admit_journal` charged tombstone-only requests the emergency reserve *plus* the checkpoint headroom, like writes. With the defaults (1 GiB + 4 GiB) every discard failed with ENOSPC below about 5 GiB free, so the tombstones whose checkpoint would punch reserved slots could never be journaled. | A request made only of tombstones is admitted against the emergency reserve alone; the reserve itself still holds. The 2026-10-03 hardware runs showed the limit of this: inside the headroom a filesystem cannot delete files (that is a write), so a trim there only returns space freed earlier; the documentation says so. *Corrected by AUD-087 ([#178](https://github.com/seo-rii/maki/pull/178)):* XFS `fstrim` forces a log write before it discards, and FITRIM failed with EIO in those runs, so a filesystem cannot trim there either; only a raw discard of the exported device is admitted inside the headroom ([known limitations](status.md#known-limitations)). | `review_r5_trim_admission.rs::a_trim_is_admitted_inside_the_checkpoint_headroom` (maki-core) |
| R5-012 (discard of damaged units) | The engine's already-zero filter (`read_ct`) and `Volume::discard_ct` (`read_slot`) read and CRC-checked the full payload: a unit with a damaged payload or header could not be discarded (EIO) while a full overwrite succeeded, and each discarded unit was read twice under the exclusive volume lock. | Both decide from the slot header (`current_sequence` / `slot_sequence`): only `Ok(None)` skips the tombstone; any other outcome, damage included, journals one. | `review_r5_trim_admission.rs` (maki-core: damaged payload and damaged header are discarded, read zero across a checkpoint, the neighbour unit is untouched) |
| R5-013 (breaker overflow) | `MakiDuration` has no upper bound and the breaker computed `now + open_duration` and `open_duration * 2` with panicking `Duration` operators: `open_initial = "9223372036854775808s"` validated and panicked the dispatcher on the first trip. | `saturating_add` / `saturating_mul`: a huge duration means open for a very long time. | `review_r5_breaker_overflow.rs` (maki-crypto: opening and doubling after a failed probe) |
| R5-014 (`reload cache` bounds) | The control verb passed `max_bytes` straight to the cache: any `maki-admin` member could set `0` (refused by config validation at startup) or `u64::MAX`. | The verb applies the startup rule plus a device-size ceiling (a cache larger than the device can never fill) and answers "NOT applied" otherwise. | `review_control.rs::control_socket_is_created_served_and_removed` (maki-nbdkit, Unix) |
| R5-015 (`prerm` and recovery) | The removal guard queried `maki@`, `maki-attach@` and `maki-workload@` units only. `maki-recover@` runs the packaged `maki-attach` after a daemon failure and can still be activating (or waiting on stop jobs) after the record is gone. | The query includes `maki-recover@*.service`. | `test_prerm_refuses_removal_while_a_recovery_unit_runs` (`scripts/test_debian_package.py`; the fake `systemctl` reports the unit only when its pattern is queried) |
| R5-017 (`maki-benchmark`) | The benchmark takes a production-format configuration, swallowed every volume-creation error (`let _ =`) and wrote `0xA5` over the first `ops × io_size` bytes (40 MiB by default) of whatever volume it named, with no confirmation. A device smaller than `io_size` panicked on `i % 0`. | An existing volume is refused (exit 2) unless `--destroy-data` is given; other creation errors fail; `io_size` larger than the device is refused. | `bins/maki-benchmark/tests/e2e.rs` (a second run without the flag exits 2 and leaves every shard file and the journal unchanged; with it, the run re-attaches) |
| R5-018 (creation over leftovers) | `create_volume` refused only an existing superblock. Leftover `data/shard-*.dat` of an earlier volume (superblocks removed, a partial restore) were adopted by `SlotStore::open`; slot headers carry no volume UUID, so the new volume served old ciphertext (EIO with AEAD, garbage with XTS) where it should read zeros. | Creation refuses any file in `data/`, `journal/` or `checkpoint/` with `AlreadyExists`, before writing anything; empty directories are accepted. Binding the volume UUID into slot or shard headers remains a candidate for the next format version. | `review_r5_create_empty_root.rs` (maki-format: v2 and v3, one leftover in each directory, nothing written; empty roots and empty directories still initialize) |
| R5-019 (root mountpoint) | `mountpoint = "/"` passed `check_abs_path` (which special-cases `/`) and the pre-mount ancestor check (no ancestors), so a configuration or override could mount the volume over the host root; detach would then unmount `/`. | `into_request` refuses `/` for configuration and override alike. | `review_r5_mountpoint_root.rs` (maki-privileged) |
| R5-020 (cache order) | `VersionedLruCache::put` removed the unit's entry unconditionally and a `get` for a mismatching sequence evicted it. A reader that snapshotted `(U, S1)` and finished decrypting after another reader cached `(U, S2)` replaced (or evicted) the newer entry: never stale data, but a lost hit and another payload read and decryption. | `put` keeps a newer entry; a live newer entry survives a lookup for an older sequence. Stale and expired entries are still evicted on lookup. | `review_r5_cache_order.rs` (maki-cache); the randomized `review_cache_model.rs` reference model follows the same rule |
| R5-021 (header name before credential) | `from_config` loaded and formatted a header's credential into a plain `String` before checking the header *name*; the invalid-name error path dropped it without wiping (only the invalid-value path zeroized). | The name is validated before any credential is loaded. | `an_invalid_header_name_is_refused_before_its_credential_is_loaded` (maki-crypto-http `review_header_values.rs`: a counting key source sees no load) |
| R5-022 (create output) | `maki volume create` printed `created volume <provider type>`, labelling the provider as the volume name. | The line names the volume and the provider separately. | `volume_lifecycle_create_inspect_check` (maki `e2e.rs`) |
| R5-023 (command environment) | The attach, detach and grow steps (`mount`, `umount`, `nbd-client`, `lvextend`, `xfs_growfs`, `vgchange`, `modprobe`) and their `blkid`/`blockdev` probes ran through a bare `Command::new`, inheriting the caller's environment and `PATH`; only `recover` and the LVM preflight cleared it. | One `command::controlled` builder (cleared environment, systemd's default service `PATH` `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`) is used for every external command of the helper. | `step_commands_do_not_inherit_the_callers_environment` (maki-privileged `exec_tests.rs`) |

| R5-006 (detach sentinel) | Detach, cleanup and attach rollback of a live backend required `<mountpoint>/.maki-sentinel` to match. The mount root belongs to the workload, which could delete, rewrite or replace the file and make every `maki-attach@` stop fail with XFS still mounted. The same observation already bound the mount to the recorded LV (device number, root `/`, XFS, exclusive NBD dependency), so the sentinel added no proof. | `detach::observe` is kernel-only, like recovery; the `allow_missing_sentinel` rollback flag is gone. Attach and `verify` keep the sentinel as an identity input. This supersedes the earlier design whose tests asserted that ordinary detach stays strict (`initial_rollback_only_relaxes_a_missing_sentinel` and the sentinel half of the replacement-mount test are replaced). | `the_workload_cannot_block_detach_through_its_sentinel` (maki-privileged `detach_tests.rs`: deleted, rewritten, symlinked and directory sentinels; another device is still refused) |

| R5-024 (mountpoint ownership) | `check_mount_target` checked owner and mode of every ancestor but not of the mountpoint itself, which the documentation allowed to belong to the workload. A workload with FUSE access could `fusermount` over it between the check and `mount`: XFS stacked on the FUSE mount, `VerifyMountDevice` failed and `attach_rollback` halted with XFS mounted and the record kept. | The mountpoint directory must be owned by root and not group/other-writable, like its ancestors. It is hidden under the mounted volume, whose root carries the workload's ownership. | `a_mountpoint_owned_or_writable_by_others_is_refused` (maki-privileged `regression_mount_target.rs`) |

| R5-025 (bounded metadata reads) | Allocation maps, discard maps and the shard catalog used the generic 1 GiB `MAX_ENCODED_LEN`, so an over-long corrupt or tampered copy was read into memory in full, several times during recovery (29 MB for three 4 MiB copies), before decoding rejected it. | `AbStore::with_max_len`: the store and the offline checker open maps with their exact geometry size (`AllocationMap::encoded_len`) and the catalog with `ShardCatalog::max_encoded_len(num_shards)`; a longer copy is invalid by its length, as MAKI-026 already did for fixed-size records. No on-disk change. | `review_r5_bounded_metadata.rs` (maki-core: recovery reads less than one padding's worth and still opens from the intact copies) |

| R5-026 (`maki-check` mutated) | The checker opened its root with `FileBacking::new`, which creates missing directories, so `maki-check /typo/path` created `/typo/path`. | A root that is not an existing directory is refused before the backing is opened. | `check_of_a_missing_root_creates_nothing` (maki-check `e2e.rs`, fast and `--deep`) |
| R5-027 (truncated last shard) | Open marked every cleared slot beyond a truncated data file's end as allocated (EIO until rewritten), including positions of a partial last shard past the device's last unit, and `allocated_units()` did not filter them: the deep check reported nonexistent units as unrecoverable. | Marks and `allocated_units()` stop at `num_units`, as `unlisted_units()` already did. | `review_r5_truncated_last_shard.rs` (maki-core: units 9–11 reported, 12–15 not) |

| R5-028 (key in a certificate file) | `read_tls_file(.., may_hold_private_key = false)` (every `ca_file`, WebSocket and gRPC `client_cert_file`) skipped the credential checks and never wiped its buffer, so a combined certificate/key PEM there put the mTLS private key, unchecked, into ordinary memory. | Such a file is refused at attach and its bytes erased; the key belongs in `client_key`. | `a_private_key_in_a_certificate_only_file_is_refused` (maki-crypto-http `review_tls_files.rs`) |

| R5-029 (cache clock) | The engine built its plaintext cache with a fresh `SystemClock`, so cache TTLs ignored `EngineOptions::clock` and could not be tested with `ManualClock`, against the injectable-clock rule. | The cache uses the engine's clock. | `review_r5_cache_clock.rs` (maki-core: an entry past its TTL on the manual clock misses) |

| R5-030 (trusted attach config) | Only `verify` read the attach configuration through the root-owned, descriptor-anchored reader. Attach, detach, cleanup, recover and grow used `read_to_string` on any path, although they run as root on what the file says (mountpoint, VG, NBD socket): a config writable by a non-root user handed them those choices. | Executing verbs use `exec::load_trusted_config` (the `verify` reader: root-owned regular file with one link, no group/other write, root-owned ancestors, read through held descriptors); `--plan` still reads any file. | `executing_verbs_refuse_an_attach_config_a_non_root_user_controls` (maki-attach `e2e.rs`, Linux, skipped as root) |

| R5-031 (daemon sandbox) | `maki@.service`, which holds plaintext and keys, had no kernel-log, clock, hostname, realtime, namespace, syscall-ABI or address-family restriction. | `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `RestrictRealtime`, `RestrictNamespaces`, `SystemCallArchitectures=native`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK` (netlink for glibc `getaddrinfo`). `SystemCallFilter=@system-service` with `SystemCallErrorNumber=EPERM` was adopted after three packaged PostgreSQL lifecycles ran under it without a denial ([record](qualification/database-discard-pressure-validation-2026-10-03.md)); `MemoryDenyWriteExecute=yes` followed on 2026-10-04, after the local and all three remote providers round-tripped data under it with the filter. `systemd-analyze verify` accepts the unit. | `the_daemon_unit_is_sandboxed` (maki-nbdkit `regression_control_packaging.rs`) |

| R5-032 (RMW through the cache) | A partial-unit write always read and decrypted the unit, although reads serve a cached `(unit, sequence)` without the payload or the provider (R4-006): every small write over a cached unit cost a provider round trip. | The RMW path establishes the current sequence and uses a cache hit under the unit locks, honouring `verify_on_hit` like reads; misses read and decrypt as before. | `review_r5_rmw_cache.rs` (maki-core: no decryption for a cached unit with and without `verify_on_hit`; an uncached unit still decrypts once) |

Follow-ups from a review of the R5 commits themselves:

- **R5-008:** a punch that kept failing still failed the checkpoint, now
  *after* publication. The same call retried the just-failed units through
  the reclamation scan and returned its error once the state was stored,
  the journal deleted and the overlay retired, so the engine reported a
  durable checkpoint as failed (Degraded). After publication a reclamation
  failure is now logged and leaves its cursor; the next idle checkpoint
  retries it and still reports a persistent failure there, which keeps the
  worker from spinning. Two older tests that expected a failed punch to fail
  the checkpoint (`review_discard_model.rs`, and
  `failed_punch_is_retried_by_reclamation_even_when_bitmap_is_already_set`,
  formerly `failed_punch_keeps_journal_and_retries…`) now expect it to
  succeed, and still check that the failpoint fired and the data survives.
  Regression: `a_persistently_failing_punch_does_not_fail_a_published_checkpoint`.
- **R5-005:** an endpoint that broke the contract was skipped for the rest
  of the pass but sent the same request again on the next pass. It is now
  excluded for the whole operation, and the violation is reported once only
  such endpoints remain. Regression:
  `a_contract_violating_endpoint_is_not_retried_on_a_later_pass`. AUD-021
  ([#154](https://github.com/seo-rii/maki/pull/154)) makes that rule hold
  whatever order the endpoints were tried in.
- **R5-004 trade-off:** with a provider that is not retry-safe, one
  integrity failure in a coalesced decrypt batch fails every request in it
  (the error fans out, as before `1678e3e`). That is the cost of never
  sending a request twice.
- **R5-002 scope:** the post-mount checks of `maki-attach attach` required
  `nosuid,nodev` but the `maki-attach verify` workload gate did not, so a
  volume mounted before the change (or remounted `suid`) still opened to the
  workload. The gate now refuses such a mount and asks for a reattach
  (`missing_read_only_subtree_stacked_or_extra_mounts_refuse_the_gate`,
  cases `suid` and `dev`).

A second hunt over the journal, recovery scan, rollback backing, WebSocket
provider, control server and NBD adapter found two more:

| Finding | Problem | Fix | Tests |
|---|---|---|---|
| R5-033 (lowered segment size) | Recovery capped each segment file at four times the *configured* `journal_segment_size`. A checkpoint never deletes the active segment, so after a clean stop a segment of up to the old size stays on disk: lowering the setting by about 4x (256 MiB to 16 MiB) made attach and `maki check` report the clean volume as corrupt. | The setting is bounded by `MAX_JOURNAL_SEGMENT_SIZE` (1 GiB) and recovery caps segment files by the largest file any configuration's writer can produce; a larger file is still refused before it is read. The oversize regression moved to a sparse file on `FileBacking`. | `review_r5_segment_size.rs` (maki-core: 20 MiB segment written at 64 MiB, recovered at 1 MiB), `review_r5_segment_limit.rs` (maki-format), `recovery_rejects_oversized_segment_before_allocation` (maki-core `review_storage.rs`, Unix) |
| R5-034 (rollback write cost) | The rollback-protected backing rebuilt the committed and working slot sets and cloned the file's whole page map for every page write, and rebuilt every reservation coordinate for every write: a 64 KiB write into a reserved range took 152 ms with 128 MiB committed and filling 128 MiB took 263 s (release build). | A committed-slot set recomputed only after a successful commit; a cached used-slot set that allocation adds to and every slot-freeing path (commit, truncate, punch) invalidates, so it is never smaller than the slots in use; a rotating free-slot hint; page lookups instead of node clones; a reservation fast path when both views already reserve the range. 0.5 ms per write and 0.6 s to fill 128 MiB. | `phase_r5_rollback_write_cost_gate_full` (maki-backing `rollback_write_cost.rs`, release gate; fails on the previous implementation), all rollback suites unchanged |
| R5-035 (text credentials; found by the 2026-10-04 remote-provider campaign) | HTTP header and gRPC metadata credentials, and WebSocket/gRPC/HTTP `client_key` PEMs, were read through the key loader, which hex-decodes any even-length hex string because local provider keys may be stored as hex. A bearer token generated with `openssl rand -hex 32` became 32 random bytes: `maki@` refused to start (`credential is not valid UTF-8`), and a hex token whose decoded bytes happened to be printable would have been sent altered. `maki volume create` never loads it, so only the daemon failed. | `KeySource::load_text` returns a credential's exact bytes; headers, metadata and PEM keys use it. `load` still hex-decodes local provider keys. | `review_r5_text_credentials.rs` (maki-crypto-http: the recorded `Authorization` header equals the hex token; maki-nbdkit: the daemon builds HTTP and gRPC providers with one), keysource unit test |
| R5-036 (write zeroes; found preparing the 2026-10-04 follow-up campaign) | The plugin returned `can_zero = 0`, leaving WRITE_ZEROES to nbdkit, which emulates it with one `pwrite` of the whole range. The NBD maximum block size limits payloads only, so clients send longer zero requests (nbdcopy sent 64 and 128 MiB for the holes of a sparse image; the Debian 12 6.1 kernel's NBD driver sends no WRITE_ZEROES at all, `write_zeroes_max_bytes` 0, so the kernel path was not affected there), and the adapter refused every one above `nbd.maximum_io` with EINVAL. SPEC §48 required this "disabled native write-zeroes" design. | A native `zero` callback: `NbdAdapter::zero` writes zeros in requests of at most `maximum_io`; with `NBDKIT_FLAG_MAY_TRIM` on a v3 volume the complete units are discarded and only partial edges written; FUA on the last step. `can_fast_zero` is 0 and a FAST_ZERO request fails with ENOTSUP. SPEC §48 now requires native zeroing of any length. *Superseded in part by AUD-160 ([#381](https://github.com/seo-rii/maki/pull/381)): `can_fast_zero` is 1, because nbdkit asserts, rather than checks, that a fast zero request was advertised, and with 0 one such request aborted the server; the request still fails with ENOTSUP.* | `review_r5_write_zeroes.rs` (maki-nbdkit: legacy and discard volumes, with and without trim, unaligned edges, bounds; native libnbd `nbd_zero` of 128× the maximum block size on both formats), `phase6.rs` capability test updated, ABI probe checks the two new flags |
| R5-037 (systemd 257 credential mode; found by the 2026-10-04 Debian 13 campaign) | systemd 257 writes `LoadCredential=` files with mode `0440`. The key loader required `0600` or `0400` for every credential, so `maki@.service` refused to start on Debian 13 with any provider (`credential file "crypto-token" has mode 0440`). `maki volume create` does not load the credential, so only the daemon failed. | `FileKeySource::credentials_directory`, used for `$CREDENTIALS_DIRECTORY`, accepts group read when the file's group is the process's effective group or root; group write, other access, and every group bit on plain `file` credentials are still refused. | `review_r5_credentials_directory.rs` (maki-crypto-local: 0440/0640 accepted there, 0444/0460/0470/0644 refused, 0440 still refused for a plain file) |
| R5-038 (requests above `maximum_io`; found by the 2026-10-04 Debian 13 campaign) | The adapter refused any read or write longer than `nbd.maximum_io` with EINVAL (BUG-011). The NBD maximum block size is advisory, and the Linux NBD driver ignores it: Debian 13's 6.12 kernel reports `max_sectors_kb` 1280 and sent 1.25 MiB writes to a 1 MiB export. Buffered writeback lost those writes silently: `mkfs.xfs` exited 0 and the volume read back a zeroed XFS superblock (`can't read superblock` at mount, on the local provider too). ext4 happened to issue no such write. Debian 12's 6.1 kernel defaults NBD devices to `max_sectors_kb` 128 (read on a throwaway VM before connecting), so the earlier 6.1 campaigns were not exposed unless an administrator raised it. | Reads and writes above `maximum_io` are served in chunks of at most `maximum_io`, each copied into its own `SecretBuffer` and submitted as its own engine request (so the engine's per-request bound, the plaintext budget and journal headroom are unchanged, which was F07/BUG-011's concern); FUA on the last chunk. Zero-length, misaligned and out-of-range requests are still refused before any copy. SPEC §13 updated. | `review_nbd_limits.rs` (maki-nbdkit: chunked 20 KiB read/write against an 8 KiB maximum survives reopen; misaligned and out-of-range oversized requests still refused with buffer and volume untouched; real nbdkit with a libnbd client in non-strict mode, which failed with EINVAL before the change) |
| R5-039 (serialized provider calls; found by the 2026-10-04 Debian 13 campaign) | The engine awaited a request's provider batches one after another, and a `remote-http` mapping without `items_path` still declared `[crypto.batch] max_items` (64), so the scheduler grouped units that the HTTP provider then sent one request at a time. Every unit cost a full round trip: under 10 ms of netem latency the campaign read at about 100 KiB/s (4,123 s for one step that took 63 s over WebSocket). | `Engine::run_batches` runs a request's batches concurrently in order: the first under the request's own admission, each further one only under an idle `max_active_callbacks` slot taken with `try_acquire` (never waiting, so no deadlock and no starvation of queued requests, and provider concurrency stays within the limit, SPEC §30); the first error cancels the rest. `VolumeConfig::effective_batch_max_items` is 1 for a per-item HTTP mapping, used by the HTTP provider's own capabilities and the daemon's, and the scheduler's `target_items` follows it so units are not held back to coalesce; its `max_items` is unchanged, since the attach self-test sends multi-item requests (review R04 refuses a request above it). A first attempt set only the daemon's copy of the capability and changed nothing, which a benchmark showed. Local benchmark, 10 ms per provider request, two endpoints, sequential 128 KiB requests over 8 MiB: write 25.2 s → 2.8 s, read 25.0 s → 2.9 s. On Debian 13 with netem on loopback ([record](qualification/debian13-postgresql-http-validation-2026-10-05.md)): 0.61 MiB/s with 10 ms ± 5 ms delay and 0.16–0.17 MiB/s with 1 % loss added, where the slowest of the parallel unit requests (a TCP retransmission) dominates. | `review_r5_chunk_concurrency.rs` (maki-core: one request's eight single-unit batches run together, encrypt and decrypt; four concurrent requests never exceed `max_active_callbacks = 3`), `review_r5_per_item_http.rs` (maki-nbdkit: effective size, scheduler target, and the HTTP provider's own capability, which failed with 64 before the fix), `phase5_admission.rs` unchanged |

Also noted: cancelling or
timing out one WebSocket request retires its connection and fails the other
requests in flight on it as retryable, which a provider that is not
retry-safe turns into EIO.

The HTTP TLS `Debug`-text classification was initially left unchanged.
The later immediate circuit-open policy for `EndpointFatal` (BUG-094) made
misclassification observable: an EOF before any certificate arrived matched
"handshake" and immediately opened an otherwise healthy endpoint's circuit.
The 2026-11-14 follow-up (BUG-186) walks typed rustls errors through transport
and I/O wrappers instead. EOF/reset remains `Retryable`; certificate and TLS
protocol errors remain `EndpointFatal`, and HTTP framing violations remain
`Contract`. `maki-crypto-http/tests/review_tls_classification.rs` covers EOF,
reset, invalid records, a fatal alert, and the first error's actual
EndpointSet circuit state; the existing TLS suite retains CA/SAN/mTLS controls.

Considered and left as is: the gRPC provider's local size estimate omits
the context strings; an under-estimate is refused by tonic's encoder as
`OutOfRange`, which maps to the same `NonRetryableRequest`. Discard admission
charges plaintext bytes it never holds, but each chunk is bounded by
`nbd.maximum_io`, which `limits.max_plaintext_bytes` must already hold.

Considered and left as is: `lvextend` (grow) and the detach-time
`vgchange -an` address the VG by name rather than through `--devices` and
`--select vg_uuid=` as activation does. Before either runs, the kernel
observation proves every mapping of that VG depends only on the recorded NBD
device, and LVM refuses an ambiguous duplicate VG name; scoping them needs the
verified LVM identity at detach and grow time and a hardware campaign.
*Superseded by AUD-135 ([#368](https://github.com/seo-rii/maki/pull/368)):*
the kernel observation sees only active mappings, LVM refuses a duplicate
name only when its scan holds both VGs, and the trusted record already holds
the verified identity. With LVM 2.03.16 on loop devices, the by-name commands
extended and deactivated another disk's VG of the same name when the
volume's PV was outside LVM's scan or gone. Detach, cleanup and recovery now
deactivate with the recorded `--devices`, the recorded VG UUID where the
record names one, and the VG name; grow extends with the recorded
`--devices`, because `lvextend` has no selection.

Considered and left as is: the checkpoint worker does not wake for store
repairs found at open (an adopted orphan shard, a rebuilt allocation map) when
nothing else is pending. An unpersisted repair is redone at the next open and
every write path persists it before any catalog commit (K-03), so this costs
latency, not durability.

The 2026-10-03 hardware campaign found that the first R5-023 `PATH`
(`/usr/sbin:/usr/bin:/sbin:/bin`) hid a source-built `nbd-client` 3.27 in
`/usr/local/sbin`, which the helper had found through the inherited
environment before: `maki-attach attach` failed with "No such file or
directory" at its first `nbd-client` step. The controlled environment now uses
systemd's default service `PATH`, root-controlled locations only, including
`/usr/local`.

`scripts/privileged-linux-validation.sh` created its mountpoint inside a
user-owned `mktemp` tree (or under `/var/tmp`, mode 1777), which the
mount-target rule of `69514ea` and R5-024 refuses. It now uses a root-created
`/run/maki-validation-mnt.*` directory and removes it during cleanup. The
script needs sudo and kernel NBD, so this change has been syntax-checked only;
the next campaign is its first run.

`NbdAdapter::shutdown` has no panic guard of its own (R5-016, not changed):
storage and provider panics already become errors before it, and no reachable
panic was found.


## Correctness and recovery review — 2026-10-12

The review used `1c1e64f`. Each functional fix starts with a failing permanent
regression and retains existing success, retry, cancellation and persistence
contracts. The two journal paths use `CrashableBacking` with sector tearing;
concurrent initialization uses actual `FileBacking`; transport failover uses
real local HTTP/gRPC/TLS servers; sentinel partial writes use an isolated child
with an OS file-size limit. These are automated regressions, not a new external
kernel-NBD or hardware-power-loss campaign.

| Finding | Result | Permanent regression |
|---|---|---|
| BUG-020, journal length retries | Reassert accepted length together with verified bytes before retry sync, including recovery restarts | maki-core `review_journal_length_retry.rs` |
| BUG-033, writer ownership bypass | Authority/wire v2 private capability gates current-session mutations, including older sessions using the same credential; v1 requires explicit migration | maki-backing `remote_session_authorization.rs`; maki-witness `transport.rs`, `session_erasure.rs`, `etcd_ha.rs` |
| BUG-034, gRPC credential copies | Guard original resolved metadata, endpoint clones and constructor/error/drop paths; format from guarded bytes without intermediate copies | maki-crypto-grpc `review_credentials_erasure.rs`; maki-nbdkit `review_grpc_credential_erasure.rs` |
| BUG-035, later batch error | Consume completions immediately, cancel remaining work on error and restore successful input order | maki-core `review_batch_liveness.rs` |
| BUG-036, HTTP oversized response | Classify response bounds and arithmetic overflow as peer contract violations; preserve unsafe no-resend | maki-crypto-http `review_response_contract.rs`, `phase8.rs` |
| BUG-037, persisted geometry | Compare immutable saved fields and advertised minimum I/O before provider construction/readiness | maki-nbdkit `review_persisted_geometry.rs` |
| BUG-038, tiny probe rate | Configuration rejects unrepresentable intervals; direct library invalid rates disable free probes without panicking | maki-crypto `review_probe_interval.rs`; maki-format `review_probe_interval_config.rs` |
| BUG-039, concurrent create | Lock before the first root check through the final directory sync; preserve explicit lock-file durability | maki-core `review_create_concurrency.rs`; maki-format `review_create_lock.rs` |
| BUG-040, sentinel retry | Atomically publish fully synced bytes without replacement; rewrite/resync identical existing content and synchronize the directory | maki-privileged `review_atomic_sentinel.rs`, `sentinel_tests.rs` |
| BUG-041, gRPC unsupported method | Treat `Unimplemented` as endpoint-scoped; record breaker failure and route safe requests to a healthy peer | maki-crypto-grpc `phase9_grpc.rs` |
| BUG-042, attach CLI options | Reject missing values, unknown/duplicate options and extra positionals before loading configuration | maki-attach `review_strict_arguments.rs` |
| PERF-001, endpoint admission | FIFO capacity admission reselects after capacity release, validation promotion and open-circuit probe readiness, holding no RPC permits while waiting | maki-crypto `review_endpoint_admission.rs`, existing flow/dispatch/probe-lifetime suites |
| PERF-002, repeated witness failover | Prefer the last validated successful address, retaining one deadline, identical requests and terminal identity/authorization/conflict failures | maki-witness `failover.rs` |
| TOOL-001, new compiler warnings | Compatible CAS and fixed-array chunk APIs; pinned 1.94 baseline and separate latest stable jobs, with matrix cancellation disabled | Strict Clippy on Rust 1.99; exact-revision Linux/Windows CI |

Recovery also reduces slot writes within each existing 1 MiB batch to the
latest sequence per unit. All historical validation and allocation/discard
publication order remain. `review_recovery_batch_latest.rs` covers overwrites,
discard ordering, batch boundaries, allocation evidence, superseded corruption
and 96 restart/power-loss fault cases. The controlled fixtures reduced 24/4/300
slot writes to 2/1/2; this is a write-count result, not a throughput claim.

Request observability now separates actual Engine calls from retained admission
slots, records success/error/cancellation and measures complete per-operation
latency alongside explicit storage-sync time. The legacy gauges and successful
storage-only series retain their meanings; `review_request_metrics.rs` verifies
provider and storage cancellation separately and failed full-FLUSH/FUA timing.
See [measurement boundaries](observability.md#request-counts-and-latency-boundaries).

The benchmark adds bounded parallel jobs, deterministic random access, mixed
read/write ratios, configurable working sets and periodic drained barriers.
Setup, real latency, exact pending work, sampled resource peaks and optional
process RSS are reported separately. `concurrent_report.rs` exercises actual
AES at 1/2/8/32 callers; `synthetic_recovery.rs` verifies 768 requests across
12 virtual-time healthy/outage/recovery phases. These simulations are not a
hardware throughput result. See [benchmark guide](benchmark.md).

The state boundaries are isolated where they carry testable invariants:
indexed batch completions, FIFO endpoint admission, current-session capabilities,
recovered geometry comparison and request-lifetime guards. No arbitrary file
split is needed to establish these contracts.

Default tests, strict Clippy and formatting must pass on the pinned baseline
and latest stable. Journal/recovery changes additionally require the complete
ignored release gates before release acceptance. Push success is separate from
the exact-SHA GitHub Actions result; local Rust 1.94 results do not establish
Rust 1.99 or Windows CI success.

## Additional functional findings — 2026-10-12

The six additional findings were reproduced against the current implementation
before their fixes. Permanent regressions run the real Engine, deterministic
restart/power-loss model, local HTTP server, or CLI process as appropriate.

| Finding | Implementation | Permanent regression |
|---|---|---|
| BUG-043, recovered shard readiness | Treat loaded allocation copies as unproven in each session. Establish both copies and directory durability before reserving a slot or publishing the whole adopted catalog; failed preparation remains retryable. Reads defer this metadata work. | maki-core `review_shard_readiness.rs`: initial ENOSPC, v2/v3 retry, empty checkpoint, cached B after failed sync, second-copy/directory failures, and multiple adopted shards |
| BUG-044, per-request pending overflow | Enforce the tail budget before every record, and share the maximum framed-record size between configuration validation and core attach. Intermediate sync failure stops append. | maki-core `review_journal_pending.rs`; maki-format `review_pending_record_limit.rs` |
| BUG-045, no-progress checkpoint starvation | Update the periodic checkpoint reference time only when the checkpoint sequence advances. Preserve explicit checkpoint's durable-only behavior. | maki-core `review_checkpoint_progress.rs`: six administrative calls and four completed worker passes through 120 seconds, plus controls |
| BUG-046, HTTP URL components | Compose the endpoint path prefix and operation path separately from their queries. Preserve escapes and query-value slashes, append configured query pairs, and omit fragments from the wire. | maki-crypto-http `review_url_composition.rs`: actual received request targets |
| BUG-047, HTTP method spelling | Normalize validated configuration methods to uppercase in `from_config`, retaining explicit programmatic `OpSpec` methods. | maki-crypto-http `review_method_normalization.rs`: encrypt/decrypt with POST/post/PUT/pUt |
| BUG-048, missing-root CLI mutation | Inspect/check reject a missing or non-directory backing root before invoking its constructor; volume creation still accepts a new path. | maki `review_existing_repository.rs`: real inspect/check/deep, regular-file rejection, creation and existing-volume controls |

The lazy shard proof adds metadata I/O once per store session when reservation
or checkpoint first needs it, proportional to the loaded shard count. In the
single-shard controlled fixture, recovery alone adds no allocation I/O; the first
subsequent FUA adds four allocation writes, four allocation syncs and three data
directory syncs. This is an operation-count observation, not a throughput claim.

The new suites contain 30 regression functions. Their test-first results and
focused success do not replace the full workspace, complete ignored release
gates, or exact-revision Linux/Windows CI required above. Hardware power loss and
external kernel-NBD qualification remain separate.

## Batch, runtime reload and benchmark findings — 2026-10-12

The follow-up report inspected `11c5a66` without a Rust toolchain. Its models
were treated as proposed reproductions, then checked with compiled Rust
regressions against the current code before implementation.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-049, decrypt batch byte basis | Split Engine reads and RMW decrypts by the original volume unit size. Preserve the scheduler's separate resident-ciphertext admission. | maki-core `review_logical_read_batches.rs`: short reversible encodings, individual/combined/partial reads and RMW, expanded ciphertext resident limits |
| BUG-050, serialized split retries | Give each retry-safe caller an independent verdict under the same lane semaphore. Retain the failed batch's input reservation and reuse its first slot; extra retries acquire shared capacity. Observe cancellation of waiting and running callers. | maki-crypto `review_scheduler_split_retry.rs`: encrypt/decrypt progress, item order, width-one reuse, shared bounds, cancellation and retry-safety controls |
| BUG-051, ignored cache TTL | Validate the whole payload, including positive TTL and supported field names, before applying byte limit and TTL together. Size-only reloads preserve TTL; the CLI accepts `--ttl` in either option order. | maki-nbdkit `review_cache_ttl_reload.rs` with ManualClock; maki `review_cache_reload_cli.rs` with a real control request |
| BUG-052, false read-verification claim | Derive `read_verified` from actual compared read samples. Add `verified_read_operations` and `read_verification`, and print skipped when no reads ran. Read failures still exit without a success report. | maki-benchmark `review_read_verdict.rs`: zero-percent and short mixed workloads, actual reads, default phases and text output |

The shared stateless Engine/provider fixture encodes uniform plaintext as a
compact packet with the fake's integrity/context checks and retains full-size
ciphertext for other data.
Its zero and all-one attach probes are short too; scheduler admission stays
enabled throughout attach, reads and RMW. Independent fixture instances decode
one another's ciphertext without a shared dictionary.

**BUG-053, attach self-test byte basis.** The positive decrypt probes in
`provider_self_test`, wide/repeated `provider_conformance` probes, and both
directions of `cross_endpoint_self_test` now split by the caller's actual
plaintext unit size. Using encoded lengths previously sent two short units
against a one-unit byte limit, refusing an otherwise valid attach; ciphertext
overhead also caused unnecessarily small batches. Item limits, result-shape
validation, negative probes and independent resident-memory admission remain
enforced. `maki-crypto/tests/review_selftest_logical_batches.rs` covers those
paths and exact byte/item boundaries; `maki-core` exercises real scheduler
attach and subsequent reads/RMW with the same fixture.

Focused success remains separate from the complete workspace, ignored release
gates and exact-revision Linux/Windows CI.

The prior Windows CI reached workspace tests after all four Clippy matrix
steps passed. Its remote-witness configuration fixtures still used Unix TLS
paths, which Windows correctly rejects as nonabsolute. The fixtures now use
drive-qualified absolute paths there while keeping their invalid-path checks.
Linux tests are local evidence; Windows execution must be confirmed in CI.

## Additional functional corrections — 2026-10-12

The six findings were reproduced against `8d2b2fa` without changing product
code. Each correction has a permanent regression that failed before its fix;
the changes keep the existing on-disk formats and wire messages.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-054, local restore after failed writeback | Authenticate all selected evidence before mutation, then rewrite referenced arena pages, the selected manifest and marker, and reassert reserved file lengths before local readiness. Do not advance the witness. | maki-backing `rollback/review_restore.rs`: failed sync, plain restart, later acknowledged write, torn power loss, manifest/marker/length failures, partial rewrite, repeated failures and authentication controls |
| BUG-055, live control address replacement | Serialize publication and cleanup with a short directory lock. Refuse live or backlogged addresses; preserve stale-address recovery. Remove only the listener's own inode and eliminate adapter's duplicate unlink. | maki-control `review_socket_ownership.rs` and maki-nbdkit `review_control_collision.rs`: concurrent binds, stale sockets, full backlog, two volumes, predecessor shutdown and successor ownership |
| BUG-056, result validation after a success verdict | Validate both the peer and common result contracts inside the RPC attempt, before breaker success. Attribute bad successful payloads to that peer and use failover only when retransmission is safe. | maki-crypto `review_endpoint_result_contract.rs` and maki-crypto-http `review_endpoint_payload_contract.rs`: actual HTTP 200 size violations, shape/order/index errors, peer-specific limits, breaker state, permits and unsafe/single-peer controls |
| BUG-057, local gRPC receive errors | Bound incoming frame headers and mark local response decoding errors with private typed provenance. Classify those as `Contract`; preserve actual remote `OutOfRange` request semantics and the original protected wire decoder. | maki-crypto-grpc `review_receive_contract.rs` plus framing unit tests: actual TCP/HTTP2 failover, malformed protobuf, exact bounds, unsafe retransmission, remote status text, split headers, trailers and cancellation |
| BUG-058, unrelated maximum supported unit | Bind daemon dispatch to `crypto_unit_size + random_prefix_bytes`. Split decrypt calls using that logical size and reject a result of another supported size inside the endpoint attempt. Preserve the advertised capability intersection and actual ciphertext admission. *Superseded in part by AUD-117 ([#351](https://github.com/seo-rii/maki/pull/351)):* the bound set's capabilities list only the bound size, because the batch scheduler admits units by the reported sizes; limits and security claims are still the intersection over every endpoint. | maki-crypto `review_pinned_endpoint_unit.rs` and maki-nbdkit `review_endpoint_volume_unit.rs`: actual scheduler attach, FUA/read/checkpoint/reconnect, prefix settings, wrong-size failover, cached capabilities and input controls |
| BUG-059, oversized configured volume name | Require a 1–64 ASCII-byte operational name before opening backing storage; preserve `[A-Za-z0-9_-]`. Align the configuration guide and SPEC with the boundary. | maki-format `review_volume_name_bound.rs` and maki-nbdkit `review_volume_name_status.rs`: 64/65-byte boundary, 65536-byte rejection without backing side effects, maximum-name FUA and official status response |

There are 51 new regression cases across these fixes. Focused checks also ran
the complete backing and gRPC package suites, existing control/configuration
and daemon cases, and endpoint admission, capability, identity and batching
regressions. Rust 1.94 and 1.99 workspace strict Clippy and formatting passed.
Full workspace tests, the extended ignored release gates, and exact-revision
Linux/Windows CI are recorded separately; focused passes are not a substitute
for those results or for physical power-cut qualification.

Local reopen now adds a read and rewrite for every referenced arena page,
using a bounded 4 KiB page buffer. This cost is documented in
[rollback capacity and durability](rollback-protection.md#capacity-and-durability).
The remote restore path still copies a selected generation into a new
namespace. No hardware power-loss, kernel NBD or real mount campaign was
performed for these regressions.

## Additional functional corrections — 2026-10-13

The six findings were reproduced against the product implementation in
`0a9199a`. These fixes preserve the on-disk formats and wire messages.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-060, failed journal creation cleanup | Retain the failed inactive segment index until unlink and journal directory sync both succeed. FLUSH/FUA, index reuse and covered-segment reclamation first complete this obligation. Preserve the original creation error and reject genuinely corrupt headers. *Adapted by AUD-003 ([#166](https://github.com/seo-rii/maki/pull/166)):* a roll no longer extends the file before writing the header, so a torn header prefix leaves a short file that recovery discards; `an_unremoved_invalid_header_still_fails_closed_after_power_loss` now persists the whole header and damages one byte, and recovery must still refuse it. *Relaxed by AUD-054 ([#177](https://github.com/seo-rii/maki/pull/177)):* recovery now discards a final segment that holds only such a header when it lies above the segments the durable proof and mark name, since it never held an acknowledged record. The test proves the refusal for what BUG-060 protects instead (the damaged header followed by record-like bytes, and at an index the mark names), and its former state is `an_unremoved_damaged_header_only_creation_is_discarded_after_power_loss`, which attaches with every acknowledged record. The writer's cleanup obligation is unchanged. | maki-core `review_journal_creation_cleanup.rs`: first/successor header partial writes, remove/directory failures, retry and sequence bounds, v2/v3, checkpoint, restart and torn power loss |
| BUG-061, configured outer capacity mismatch | Compare configuration to the authenticated COW manifest capacity before provider initialization and READY, for both local and remote protected backing. Refuse mismatch without resizing; direct low-level open still uses stored geometry. | maki-nbdkit `review_rollback_capacity.rs`: actual local AES and remote mTLS, smaller/larger/matching capacity, reserve policy, credential-loading order, session release and data preservation |
| BUG-062, inaccurate gRPC request estimate | Check the completed protobuf request's exact encoded length before readiness or transmission. A local size violation remains a request error and does not charge endpoint breakers. Preserve genuine remote status semantics. | maki-crypto-grpc `review_request_size.rs`: fitting and oversized requests, context/varint boundaries, two-peer breaker neutrality and remote Internal failover |
| BUG-063, unknown WebSocket error class | Treat missing, malformed or unsupported remote error classifications as endpoint contract violations. Preserve recognized error classes and refuse unsafe retransmission. | maki-crypto-websocket `review_error_class.rs`: conformance followed by peer failure, healthy failover, malformed classes, all-peer terminal failure and unsafe controls |
| BUG-064, lost WebSocket receive verdict | Carry receive size/encoding/framing violations through generation cleanup as Contract. Publish death and sweep the same generation under one pending lock, so retirement cannot replace the verdict. Ordinary abrupt transport loss still reconnects when safe. | maki-crypto-websocket `review_receive_contract.rs`: single/fragmented size limits, invalid UTF-8, multiple pending callers, healthy successor, breaker failover, terminal stall and unsafe controls; existing connection-lifetime suites |
| BUG-065, omitted split-retry totals | Increment provider call and item totals when each ordinary or split call actually starts. Exclude unstarted cancelled groups and preserve coalesced, pending and inflight semantics. | maki-crypto `review_retry_metrics.rs`: encrypt/decrypt retries, cancellation before/after dispatch, mixed group sizes, coalescing and inflight counts |

There are 50 new permanent regression functions. The original implementations
failed the corresponding test-first checks. Focused verification includes the
complete crypto/gRPC, backing and WebSocket package suites, daemon capacity
tests and related journal durability regressions. The final workspace, complete
ignored release gates and exact-revision Linux/Windows CI are recorded
separately; focused checks do not establish those outcomes or physical
power-loss qualification.

The preceding Linux CI was blocked by the RustSec audit of `quinn-proto`
0.11.17. The lockfile now selects its fixed 0.11.18 patch while retaining other
dependency choices. The local dependency audit and pinned erasure contract pass;
the audit remains enabled in CI.

## Functional follow-up: metadata retries and endpoint validation

The eight findings below were reproduced against `fbbdbb4`. The fixes preserve
the on-disk formats, wire messages and public endpoint validator API.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-066, preserved metadata length | Reassert the exact validated preserved A/B file length before rewriting its bytes and syncing it, then update the other copy. A failed preservation step leaves the other copy untouched. | maki-format `review_ab_length_retry.rs`; maki-core `review_catalog_length_retry.rs`: shrinking/empty/same-size/growing metadata, failed length change, partial target write, restart, v2/v3 and preservation of earlier FUA data |
| BUG-067, uncharged validation RPCs | Wrap each validation capabilities/encrypt/decrypt call in the same global and endpoint admission as serving calls. Hold only one peer's permits per RPC and narrow probe batches to count and resident-byte capacity. | maki-crypto `review_endpoint_validation.rs`: independent global/local/count/byte limits, single-slot cross-test progress, large advertised batches and ordinary serving controls |
| BUG-068, reference failure attribution | Preserve the reference peer and operation stage before cross-test error conversion. Its contract/fatal/context errors defer candidate validation; candidate errors and actual cross-key failures remain conclusive. *Superseded in part by AUD-110 ([#343](https://github.com/seo-rii/maki/pull/343)):* a candidate's malformed reply (`Contract`) is inconclusive too, and the candidate is validated again with backoff; only evidence that it serves another contract (another key, compatibility id or canary, a claimed capability it does not honour, an explicit refusal of the volume's context) stays conclusive. | Same validation suite: malformed reference encrypt/decrypt, later reference recovery, malformed candidate and different-key candidate; since AUD-110 the last two are `malformed_candidate_is_never_admitted_but_is_revalidated` and `different_key_candidate_is_rejected_for_the_life_of_the_set` |
| BUG-069, nested metadata ENOSPC | Map storage-full I/O nested in a format error to ENOSPC at the NBD boundary. Keep other I/O and semantic format errors as EIO. | maki-nbdkit `review_metadata_enospc.rs`: public pwrite forcing checkpoint, metadata write/resize/sync failures, slot control, successful retry and generation exhaustion |
| BUG-070, protected benchmark reuse | Detect and open an existing validated volume before creation. Require explicit destruction authorization, reuse its identity/witness and retain normal attach geometry, capacity and key checks. | maki-benchmark `review_rollback_reuse.rs`: actual CLI, UUID/witness preservation, refusal and invalid/partial layouts; maki-nbdkit `review_rollback_capacity.rs`: actual mTLS identity/data preservation and session release |
| BUG-071, UUID spelling | Validate both filesystem UUID shapes and compare hex case independently. | maki-privileged `review_filesystem_uuid.rs`: configuration/full mount identity, both case directions and malformed/different/missing controls |
| BUG-072, validation task lifetime | Retain validation task handles in the dispatcher and abort them on final owner drop; cancellation guards return validation state and RPC permits. | Validation suite: final dispatcher drop, cancelled waiting caller, live-set validation ownership and capacity return |
| BUG-073, cross-pass failover metric | Track the previous actually called endpoint across retry passes and count peer identity changes. | maki-crypto `review_failover_metrics.rs`: later-pass recovery, same-pass failover and same-peer retry |

There are 49 new permanent regression functions. The test-first runs produced
25 expected-behavior failures and 18 passing controls before implementation;
the final focused suites pass. These include 39 A/B/catalog durability tests,
the complete crypto suite (215 passing tests), the complete privileged suite
(195 passing tests), benchmark tests and real mTLS daemon controls. Final
workspace, complete ignored release gates and exact-revision Linux/Windows CI
are recorded separately.

Reference responses with valid shape but wrong plaintext contents remain an
ambiguous cross-endpoint round-trip mismatch; the reference-error correction
above covers the reproduced contract and explicit-error attribution paths.
The storage regressions use the executable crash model, rather than physical
power-loss qualification.

## Functional follow-up: journal progress and operational bounds

The six findings below were reproduced against local `main` at `7551a54`.
Their corrections retain the existing on-disk formats and 64 KiB control
framing. Each fix has permanent regressions that failed before implementation.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-074, journal minimum progress budget | Include repeated segment headers and the retained active segment when validating room for the largest request after reclaim. Share checked append accounting with the writer. | maki-format and maki-core `review_journal_progress.rs`: exact boundary, many rolls, retained large records and maximum-request FUA/readback |
| BUG-075, aggregate endpoint output | Validate an aggregate endpoint report budget, including escaped names and repeated metrics. Refuse an oversized backend response explicitly before writing it. | maki-format `review_endpoint_control_budget.rs`; maki-control `review_response_bound.rs`: cardinality, escaped names, exact framing boundaries and subsequent commands on the same connection |
| BUG-076, stale mapping proof after growth | With a stored mapping proof, refuse unqualified partition-PV or layered growth layouts before either LV or filesystem mutation. Preserve exact mapping identity checks, legacy checks and qualified whole-device growth. | maki-privileged `review_growth_topology.rs`: partition refusal, unchanged whole-device mapping, already-extended retry and foreign-mapping controls |
| BUG-077, truncated exponential backoff | Grow the jitter cap with checked wide arithmetic until the actual maximum delay is reached. Sample over the complete capped duration. | maki-crypto `review_jitter_progress.rs`: attempts 31/32, extreme attempts, zero delays and the full Duration range |
| BUG-078, omitted unsafe contract refusal | Count the contract-error branch that refuses retransmission, without sending to another endpoint. | maki-crypto `review_contract_refusal_metrics.rs`: single/multiple peers, safe failover and request/provider-error controls |
| BUG-079, transient queue length underflow | Publish a pushed item's occupancy under the same queue lock that removes it. Keep notification and permit release outside that critical section. | maki-crypto `review_queue_accounting.rs`: concurrent FIFO transfers with occupancy observation, capacity reuse and serial controls |

The growth tests use the original executor with a simulated system and sysfs;
they do not establish new LVM/kernel or partition-PV qualification. The queue
finding concerns the public library's occupancy API; current volume paths do
not use that queue. Focused test results, full workspace and complete ignored
release gates, main push and exact-revision Linux/Windows CI are recorded
separately.

There are 42 new permanent regression functions. Test-first runs produced
18 expected-behavior failures and 15 passing controls before implementation.
Focused verification passes all new cases, 44 journal-related tests, the
complete crypto suite (229 passing tests), control suite (33 passing tests)
and privileged suite (201 passing tests), plus admitted endpoint snapshot
controls. Strict Clippy passes for the affected packages on Rust 1.94.0.

Repeated witness observations remain a measured optimization candidate
(PERF-003). These fixes preserve the existing authority freshness checks.

## Functional follow-up: attach retries and ready endpoint admission

The four findings below were reproduced against `0cc3539`. Each correction has
permanent test-first regressions and preserves the on-disk formats.

| Finding | Correction | Permanent regression |
|---|---|---|
| BUG-085, readable but unsynced key canary | Verify the existing key binding, then restore both canary copies and their directory entries before attach succeeds. Reject a wrong key before publication. | maki-core `review_canary_retry.rs`: first publication and retry sync failures, process restart followed by power loss, FUA readback, wrong-key refusal and authenticated fallback |
| BUG-086, unsent request waiting for endpoint readiness | Keep the caller's admission position while eligible peers are OPEN or probe-saturated. Wake on cooldown or capacity return without consuming a retry pass before the first RPC. Keep a peer eligible if a concurrent caller takes its probe slot before dispatch. | maki-crypto `review_endpoint_readiness.rs`: OPEN cooldown, successful/cancelled probe, waiting caller cancellation, deadline and actual failed-RPC retry control |
| BUG-087, duplicate HTTP media type | Add the JSON default only when no explicit Content-Type header is configured, ignoring header-name case. | maki-crypto-http `review_content_type.rs`: actual loopback HTTP, standard/vendor media types, single/batch encrypt/decrypt and raw/default controls |
| BUG-088, occupied automatic NBD choice | Choose the lowest unused device after checking connection state, root/partition holders and direct mounts. Keep the final executor recheck and refuse incomplete observations. | maki-privileged `allocation_tests.rs`: synthetic sysfs/mountinfo, occupied lower devices, numeric order, missing/malformed/bounded observations and existing explicit-device refusal controls |

There are 32 new permanent regression functions. Test-first runs produced 19
expected-behavior failures and 10 passing controls before implementation.
Focused suites pass for canary attach, crypto, HTTP and privileged operations,
including strict Clippy for the changed packages. Complete workspace checks,
ignored release gates and exact-revision Linux/Windows CI are recorded
separately. The canary tests use the executable crash model, and NBD allocation
tests use observation fixtures; neither constitutes physical power-loss or
kernel NBD/LVM campaign qualification.

## Project review (2026-10-14)

A static review of the whole tree at `b268798` covered the engine, journal and
recovery, formats and backing, rollback protection, the crypto layer and
remote transports, nbdkit and control, the privileged helper and packaging,
and the documentation and CI. Each correction below landed test-first in its
own pull request; the RED evidence is in each commit message. No on-disk
format changed. The findings that need a design decision, or were not yet
taken on, are listed after the table.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| TEST-003, nightly gates stopped at the first failing binary | The unfiltered `-- --ignored` run compiled the etcd quorum gate, which refuses to skip without `MAKI_ETCD_BIN`; without `--no-fail-fast` every gate after it silently did not run. The gate is behind the opt-in `etcd-qualification` feature and the nightly run uses `--no-fail-fast` | `scripts/test_ci_gate_validation.py` | #1 |
| BUG-089, spurious ENOSPC after an inline reclaim | `durable >= appended` did not prove nothing more could be reclaimed: a concurrent FUA is durable but newer than the checkpoint horizon. Refuse only when the checkpoint covers every appended record, or on the last round | maki-core `review_r4_overlay_bound.rs`: concurrent FUA during inline reclaim, volatile control | #2 |
| BUG-090, deep check passed without checking | A failed second superblock read returned an error-free report. I/O now fails the check; any other failure is reported | maki-core `review_check.rs`: the fast phase's reads succeed and the deep check's own read fails | #5 |
| BUG-091, non-canonical segment and shard names | `seg-000000000000000A` parsed as segment 10 and was scanned under one name but replayed and reclaimed under another. Names must round-trip through `layout`; the fast checker uses recovery's shard parser and reports adoption accurately | maki-format `review_format.rs`; maki-core `review_check.rs` | #5 |
| BUG-092, transport limits sized for plaintext | gRPC messages, WebSocket frames and batched HTTP responses carry ciphertext. Each limit must hold the larger of the plaintext and the ciphertext batch (base64 where encoded); zero WebSocket and gRPC timeouts are refused | maki-format `review_config.rs`: gRPC, WebSocket, batched HTTP and timeouts | #4 |
| BUG-093, HTTP mappings counted fields never sent | Context binding counted `fields` of a raw body and `item_fields` of a per-item body, and a raw body with `items_path` counted as a batch. Both use `BodyConfig::is_batch` | maki-format `review_r3b_config.rs` | #4 |
| BUG-094, endpoint-fatal answers charged like transient ones | A revoked credential or missing route kept its circuit closed for `failure_threshold` answers. `EndpointFatal` opens it at once; no-resend for non-retry-safe requests is unchanged | maki-crypto `review_r5_endpoint_attribution.rs`, with a retryable control | #3 |
| BUG-095, XTS key with identical halves | IEEE 1619 requires distinct data and tweak keys; a doubled 32-byte key loaded silently. It is refused like a wrong-length key | maki-crypto-local `phase2.rs` | #3 |
| BUG-096, root `blkid` read a mount source as an option | A stacked FUSE mount chooses the mountinfo source (`fsname=-c/etc/shadow`). Only absolute paths are probed, after `--` | maki-privileged `exec_tests.rs` | #6 |
| BUG-097, gRPC CA unusable with an empty host store | tonic refuses an empty native store even with a CA. Native roots are requested only when present or when no CA is configured; a CA still adds to the host roots. *Superseded by AUD-133 ([#369](https://github.com/seo-rii/maki/pull/369)):* gRPC no longer uses tonic's native-root loader: like the other transports it trusts the host's store, the compiled-in public roots and the CA, so the provider is always built, and a deployment that trusted only its CA on an empty host store now also trusts the public roots | maki-crypto-grpc `review_custom_ca_trust.rs` (own binary: it empties the store through `SSL_CERT_FILE`/`SSL_CERT_DIR`); since AUD-133 its test is `an_empty_host_trust_store_does_not_prevent_construction` | #8 |
| BUG-098, panics across nbdkit callbacks; failed requests unlogged | Every working callback runs behind a panic boundary that fails it with EIO; failed requests are logged as rate-limited `WARN` lines without payload | maki-nbdkit `plugin.rs` unit tests | #9 |
| Build: tokio `test-util` in production builds | The pausable clock is requested only as a dev-dependency | `scripts/test_dependency_features_validation.py` | #7 |

### Second pass (same day)

Six further reviewers covered the engine write paths, nbdkit and control,
the crypto scheduler, the witness and rollback client, the test tooling and
the packaging. Each correction below is test-first in its own pull request.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-099, control bind replaced any file | `control.socket` is configurable and the daemon owns the backing root; binding renamed the socket over whatever was there (`superblock.a`). Only a dead socket is reclaimed | maki-control `review_socket_ownership.rs`: regular file and symlink at the address | #11 |
| BUG-100, superblock published before the catalog | A crash between them left a root that looked initialized but could not attach. The superblock is written last, after every other file and dirent is durable | maki-format `review_init_crash.rs`: every cut point, then power loss | #12 |
| BUG-101, failing checkpoint retried on every write | Each write above the watermark woke the worker, which reran the failing checkpoint under the exclusive lock. A failure waits one interval | maki-core `review_checkpoint_backoff.rs` (ManualClock, counting failpoint) | #13 |
| BUG-102, one unit twice in a coalesced call | Two versions of a unit are interchangeable to every per-position check; a provider answering by unit index gave both callers one plaintext. A batch never carries a unit twice | maki-crypto `review_scheduler_duplicate_units.rs` | #14 |
| BUG-103, a transient witness outage stopped the session | A read-only Inspect that could not reach the witness stopped the session for good; only a final answer does now, and an outage refuses each operation without fallback | maki-backing `remote_rollback.rs`: outage then recovery, takeover during an outage | #15 |
| BUG-104, witness slots taken before TLS | Idle unauthenticated sockets held every worker. Workers are taken after authentication; pending handshakes are bounded and the oldest is cut off | maki-witness `transport.rs`: idle sockets, then a real client | #16 |
| BUG-105, plaintext echo accepted per call | Only the self-test looked, and only for an exact echo. Every encrypt result that carries its plaintext anywhere (exact, behind a nonce, before a tag, or both) is a contract violation of that call | maki-crypto `review_plaintext_echo.rs`: exact, tag, nonce and nonce‖plaintext‖tag framing; late echo; self-test | #17 |
| BUG-106, reserve refusal woke no checkpoint | Between the worker's low-space trigger and the admission requirement every write was ENOSPC until the interval. A refusal wakes the worker | maki-core `review_reserve_refusal_reclaims.rs` | #18 |
| BUG-107, remote claim before checking the root | A witness address naming another volume's authority raised its fence or revoked its writer before failing. The current manifest is authenticated in this root first | maki-backing `remote_rollback.rs`: two independent fixtures | #20 |
| TEST-004, crash model mixed names and inodes | A durable entry without synced data vanished; a re-created name showed the unlinked inode's bytes; rename over a file restored the old target or lost it. Inodes and names are separate and a rename is atomic | maki-test-support `review_crash_posix.rs` | #21 |
| TEST-005, sweeps accepted superseded failed writes | A failed write's data stayed acceptable after a newer write was acknowledged or durable. Live and post-crash views retire it separately | maki-core `review_r3b_durability.rs` oracle self-test | #21 |
| BUG-108, control commands needed the root-owned configuration | They read and fully validated it, so a `maki-admin` member could not reach the socket and an edited configuration blocked `drain`. `--socket` names the socket; a configuration is only parsed | `bins/maki` `review_control_cli_access.rs` against a fake daemon | #22 |
| Docs: stop waits ended early | `systemctl is-active` fails for `deactivating` and `failed`; the guides poll `ActiveState` and stop on failure | `scripts/test_docs_lifecycle_validation.py` | #19 |

### Third pass (same day)

Five reviewers covered the privileged helper, journal and recovery, the
remote transports, every unsafe block, and configuration, key and credential
handling; the earlier lists' remaining concrete items were taken on too.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-109, superblock flags and crypto format version ignored | Unknown flags or a format version other than 1 are refused, so a later incompatible format is never read with these rules | maki-format `review_superblock_fields.rs` | #23 |
| BUG-110, `maki-check --deep` wrote into a non-volume | The deep phase took the volume lock (creating `volume.lock`) after the fast check found no superblock; a rollback-protected root was reported as corrupt | `bins/maki-check` `review_deep.rs` | #24 |
| TEST-006, no power-loss sweep issued TRIM | Writes and unit-aligned trims, flushes, checkpoints, power loss or restart, against the reference model, with a 400-seed release gate | maki-core `review_trim_power_loss.rs` | #25 |
| BUG-111, witness `serve` exited on EMFILE | Accept errors are transient: pause and keep accepting, as the control socket does | maki-witness `accept_exhaustion.rs` (own binary) | #26 |
| BUG-112, no `--help`/`--version` | Help exits 0 on stdout; `--version` prints the package version | `bins/maki` `review_cli_help.rs`, maki-check e2e | #27 |
| BUG-113, configuration errors echoed secrets | TOML errors rendered the source line and their Debug the whole document; URL errors printed userinfo and query. Errors now give line, column and field, never a value | maki-format `review_config_secret_echo.rs` | #28 |
| BUG-114, any `CRYPT-` device counted as encrypted swap | Integrity-only, verity and helper devices carry the prefix too; only encrypting cryptsetup types count | maki-nbdkit `security_swap_tests.rs` | #29 |
| BUG-115, gRPC TLS handshake without a deadline | `connect_lazy` bounds only the TCP connect; a silent TLS peer pinned the channel. The connect timeout now covers TLS | maki-crypto-grpc `review_tls_handshake_deadline.rs` | #30 |
| BUG-116, `grow --size-bytes +N` | A leading `+` parsed as an absolute size; plain digits only, and a multiple of 512 bytes, which LVM requires | `bins/maki-attach` `review_strict_arguments.rs` | #31 |
| BUG-117, WebSocket frames outside the contract dropped | Non-JSON, id-less and binary frames now fail the generation as a contract error instead of timing out | maki-crypto-websocket `review_unmatched_frames.rs` | #32 |
| BUG-118, attach over existing submounts | A mount below the mountpoint is refused before connecting, as the verify gate does | maki-privileged `exec_tests.rs`, `detach_tests.rs` | #33 |
| BUG-119, key open errors all "not a regular file" | Permission and symlink errors say so | maki-crypto-local `review_keysource.rs` | #34 |
| BUG-120, lossy nbdkit config path | A non-UTF-8 `config=` value is refused instead of rewritten | maki-nbdkit `plugin.rs` unit test | #35 |
| TEST-007, racy page-lock test | A unit test compared the process-global lock-failure counter while other tests allocated buffers; on Windows each counts. The rule is checked directly | maki-crypto `secret.rs` unit test | #36 |
| TEST-008, flaky witness transport tests | Fixture clients had 500 ms (and 2 s) deadlines for calls expected to succeed; loaded runners timed out loopback connects. Fixture clients allow 5 s (10 s); expiry tests keep their own short deadlines | maki-witness `transport.rs`, `session_erasure.rs` | #37 |

### Fourth pass (2026-10-15)

The fourth pass took two items off the open list (BUG-121, BUG-122) and ran
five new reviews: the crypto self-test, grow and the benchmark, the operator
documentation, engine concurrency, and discard.

| Finding | Correction | Permanent regression | PR |
|---|---|---|---|
| BUG-121, truncated gRPC response retried | A response that ended inside a message, or an OK status with no message, reached the caller as tonic's local `Internal` (Retryable), so `stall` retried a broken endpoint forever. The bounded body checks message boundaries at the trailers and at the end of the stream; a remote status is unchanged | maki-crypto-grpc `review_truncated_response.rs` (raw h2 server), with a remote `UNAVAILABLE` control | #38 |
| BUG-122, relative secret and TLS paths | A `file` credential and TLS `ca_file`/`client_cert_file` resolved against each process's working directory (`/` under systemd). They must be absolute, like every other path | maki-format `review_secret_paths.rs` | #39 |
| BUG-123, idle checkpoint failed on a failed punch | Hole punching is a hint, but the idle path returned its error, so `maki drain`, `maki checkpoint` and shutdown failed on a v3 volume whose punches failed. It logs and marks the scan stalled; the next checkpoint or attach retries | maki-core `review_discard_reclaim_retry.rs` | #40 |
| Docs: operator procedures | `maki status` has no overlay fields (metrics do); a full backing reaches the filesystem as EIO and XFS shuts down; the daemon start limit and `systemctl reset-failed 'maki*@<volume>.*'`; the instance naming contract; quiesce before witness takeover or restore, and `chown` the namespace they create as root | `check_docs_links.py` | #41 |
| BUG-124, shard descriptors | Every cataloged shard keeps its data file open and systemd's soft limit is 1024, so about a thousand shards failed attach, reported as "data file missing" corruption. Openers raise the soft limit to the hard limit; only an absent file is corruption | maki-core `review_shard_open_errors.rs`; maki-backing `review_open_file_limit.rs` | #42 |
| BUG-125, panic under the volume lock | The async lock does not poison: after a storage task panicked mid-mutation the engine kept serving and acknowledging. The write guard latches the engine failed while unwinding, and every request fails until the volume is attached again | maki-core `review_engine_panic.rs` | #43 |

### Open after this pass

These findings were confirmed by reading the code but are not corrected yet.
The first group needs a design decision.

- **Volume isolation on a shared host.** Every `maki@` instance runs as the
  same `maki` user, and the plugin accepts any client on its NBD socket, so a
  compromised daemon for one volume can open another volume's socket
  (SPEC §5). Options: a user per volume or `DynamicUser=`, a peer-credential
  check, and `InaccessiblePaths=` for other volumes.
- **Read-only commands claim a remote writer.** `maki volume inspect`, `maki
  check` and the benchmark's existence probe open a remote-witness root
  through `open_remote`: they claim a fence, copy the namespace and release
  it in `Drop`, which an interrupted command skips. A tested design choice
  (`review_rollback_capacity.rs`); a read-only open would avoid both.
- **Root helper `PATH`.** Child commands search `/usr/local/sbin` and
  `/usr/local/bin` first, which the documented source-built `nbd-client`
  relies on; absolute tool paths would remove the shadowing risk.
- **Privileged lifecycle.** One global attach lock is held across fsyncs that
  cannot be interrupted, and `nbd-client` has no `-timeout`; a failed or
  timed-out `maki-attach@` start runs no cleanup (no `ExecStopPost=` or
  `OnFailure=`); the stop path refuses when the configuration was edited while
  attached; detach, recovery and grow address LVM by VG name without
  `--devices`/`--select` scoping; they also match device-mapper mappings by
  VG name only, so another daemon's metadata naming this volume's VG can be
  autoactivated on its NBD device and block this volume. A workload-owned
  FUSE mount at or below the mountpoint blocks detach, cleanup and recovery,
  and detach resolves the mountpoint path again for `umount`/`xfs_growfs`.
  `maki@` has no `TimeoutStopSec`: a final
  checkpoint longer than 90 s is killed, and `OnFailure` recovery then
  restarts the lifecycle the operator stopped. The guides drain before the
  unmount, which XFS then performs against a closed device, and key rotation
  stops the attach unit, which takes the daemon with it before the drain.
- **Settings validated but not applied.** `cache.lock_memory = false` does
  not stop cache entries from being page-locked under `secure-buffers`, and
  `memory_lock_mode = "off"` requires it even with the cache off;
  `crypto.max_operation_time` is ignored under the `stall` policy;
  `nbd.socket` and `nbd.connections` are not read at runtime; the attach
  `device_block_size` is never compared with `nbd.minimum_io`. Refusing them
  would reject configurations that attach today.
- **Remote transports.** A gRPC channel keeps reusing a dead HTTP/2 connection
  after an RPC deadline (retire it as the WebSocket provider does); WebSocket
  connects are serialized behind one lock with an unbounded wait; mTLS private
  key PEM copies are not wiped; HTTP formats credential templates with
  `str::replace`; the guarded response JSON tree has no node budget; HTTP and
  gRPC accept a CA file that holds no certificate. A frontend's own etcd
  401/403 reaches clients as a final denial, so they do not fail over.
  WebSocket has no TCP keepalive and no idle check before reusing a
  connection. Query-string literals (R5-007) pass validation.
- **Dependency advisories.** RUSTSEC-2026-0346 to 0349 (2026-10-14) affect
  the vendored, erasure-patched `rustls` 0.23.45 and fail the Linux CI audit
  step, which runs before the tests. 0.23.46 fixes them; re-vendoring it
  means re-applying the erasure patch (one hunk in `common_state.rs` moved)
  and refreshing `vendor/upstream.json`, `patches.json` and the fixture
  provenance.
- **Provider self-test.** There is no nonce or keystream reuse probe. Context
  probes accept a changed plaintext as proof even when integrity is claimed,
  where SPEC §18 reads as requiring a rejection. The unit-index probe moves
  index 0 to 1, so a provider that keeps only 32 bits passes, which matters
  above 2^32 units; probing high bits would refuse such a provider on small
  volumes too. With the random-prefix wrapper the compatibility-id probe is
  answered by the wrapper's own refusal. No configuration pins the volume
  UUID, so a whole backing can be swapped for another volume under the same
  key.
- **Engine and recovery robustness.** A stuck reclamation window blocks
  every later one, and a full checkpoint resets the scan cursor; the fast
  `maki check` passes a v3 orphan shard with no discard maps; the truncated
  shard damage count includes discarded units. The checkpoint snapshot pins
  superseded ciphertext the overlay bound does not count; the monitoring
  free-space sample is refreshed only by write admission. A stopped engine
  (BUG-125) waits for an operator restart instead of exiting for the
  packaged recovery unit. A failed journal directory sync can
  leave an idle volume degraded; bounded replay stores the allocation maps
  after every 1 MiB batch; the first write after attach re-stores both map
  copies of every shard under the exclusive lock. On a filesystem without
  native `fallocate`, glibc's `posix_fallocate` emulation writes zero bytes
  into a slot a running checkpoint may be writing. Bounded replay saves no
  progress, so a recovery longer than `TimeoutStartSec` restarts from the old
  checkpoint every time; every attach rewrites and syncs the whole accepted
  journal, not only the final segment's unproven tail; recovery fails on I/O
  to the advisory durable mark. Per-buffer `mlock` fragments the address
  space and a failed `munlock` is ignored.
- **Witness service.** A restored authority is not detected although the
  backing holds newer fences; online `maki volume gc` aborts while the writer
  advances; one bad endpoint certificate defeats etcd and frontend failover.
- **Benchmark.** Every write of an offset carries the same bytes, so read
  verification cannot detect a stale version; reads in the timed window can
  come from the overlay, and a checkpoint can land in it; `nbd.threads` is
  ignored; `--seed` shifts one address stream by one operation instead of
  choosing an independent one.
- **Test tooling.** A directory sync also makes the directory's own entry
  durable; the HTTP chaos server merges
  repeated headers; the fuzz targets omit `DurableProof`, the witness decoders
  and the privileged mountinfo parsers. *Since AUD-180 the format targets
  cover `DurableProof`.* *Since AUD-200
  ([#401](https://github.com/seo-rii/maki/pull/401)) `backing_records` covers
  `maki-backing`'s witness records (the local witness anchor and the remote
  witness state); `maki-witness`'s RPC has no target.*

Later update (2026-11-17): the guarded response JSON tree now keeps only the
values the response mapping reads (AUD-024,
[#157](https://github.com/seo-rii/maki/pull/157)).

Later update (2026-11-23): with the random-prefix wrapper the self-test's
compatibility-id probe now reaches the provider, and the wrapper's own
refusal is no longer the field refusal a context probe accepts (AUD-107,
[#340](https://github.com/seo-rii/maki/pull/340)). That closes only this item
of the provider self-test group. Checked against `main` at `e6f52d6`, these
items of the list have since been fixed, in whole or in part:

- A failed or timed-out `maki-attach@` start now has a cleanup path: the
  unit's `ExecStopPost=` runs `maki-attach recover-failed-start`, which
  queues the recovery coordinator
  ([systemd deployment](operations.md#systemd-deployment)).
- The vendored, erasure-patched `rustls` is 0.23.46, the version this list
  names as fixing RUSTSEC-2026-0346 to 0349.
- The gRPC provider retires an established channel after a retryable
  failure, a timeout or a cancelled call, so the next RPC opens a new
  connection
  (`unresponsive_established_channel_is_replaced_after_timeout_or_cancellation`,
  maki-crypto-grpc `phase9_grpc.rs`).
- HTTP and gRPC refuse a CA file that holds no certificate
  ([BUG-181](#comprehensive-review-follow-up-2026-11-14)).
- The fast `maki check` fails a v3 orphan shard whose discard maps are
  missing ([BUG-182](#comprehensive-review-follow-up-2026-11-14);
  `missing_v3_orphan_discard_map_must_not_claim_successful_adoption`,
  maki-core `review_orphan_discard_check.rs`).
- `nbd.socket` is read at runtime: when it is set, native start-up fails
  unless it names the plugin's one pathname listener (`b7107c6`;
  [NBD request limits](configuration.md#nbd-request-limits)).
  `nbd.connections` is still not read: validation requires `1`, and the
  plugin admits a single connection without consulting it.
- The `probe_parsers` fuzz target feeds `parse_mountinfo` raw bytes, and
  since AUD-101 every reader of the mount table in the privileged helper
  splits its records through the `probe::mount_record` that target reaches.
  The allocation, detach and recovery observations built on that splitter,
  `DurableProof` and the witness decoders still have no fuzz target.
  *Since AUD-180 the format targets cover `DurableProof`; the witness
  decoders still have none.* *Since AUD-200
  ([#401](https://github.com/seo-rii/maki/pull/401)) `backing_records` covers
  `maki-backing`'s witness records (the local witness anchor and the remote
  witness state); `maki-witness`'s RPC has no target.*

One more setting belongs to the list's "validated but not applied" group and
is still open: `cache.zeroize_on_evict` is accepted but never read. The
engine always builds its cache with `zeroize_on_evict: true`, and a cached
buffer is erased when its last owner drops it, whatever the setting says.

Later update (2026-11-23, fifth and sixth rounds): of the privileged
lifecycle item, detach, recovery and grow no longer address LVM by VG name
alone. They run with the trusted record's candidate devices as `--devices`,
and the deactivation also selects the recorded VG UUID where the record
names one (AUD-135, [#368](https://github.com/seo-rii/maki/pull/368)). The
failed-start hook also rolls back an attach that died between LVM
activation and its mapping proof, while the daemon still serves (AUD-118,
[#356](https://github.com/seo-rii/maki/pull/356); AUD-142 and AUD-143,
[#370](https://github.com/seo-rii/maki/pull/370)).

Later update (2026-11-24, seventh round): the helper runs no NBD client
(AUD-147, [#375](https://github.com/seo-rii/maki/pull/375)). Of the root helper `PATH` item, no
documented tool needs `/usr/local` any more, but the controlled `PATH` still
searches `/usr/local/sbin` and `/usr/local/bin` first for the external
commands the helper still runs; the daemon unit names nbdkit by its absolute
path (AUD-148, [#374](https://github.com/seo-rii/maki/pull/374)). Of the
privileged lifecycle item, `nbd-client`'s missing `-timeout` no longer
applies: the helper's own NBD waits are bounded, and the kernel's work on a
disconnect is not (AUD-151). The helper logs its socket peer's pid and uid
without checking them, so the volume-isolation item stays open.

## Boundary review follow-up (2026-10-15)

See the [PR, regression, commit and remaining-boundary map](review-boundaries-2026-10-15.md).
Open-PR evidence is separate from remote-main integration and release qualification.


## Ownership, recovery resources and operational follow-up (2026-10-19)

The review of `44d60ea` identified F01–F09 in package shutdown guidance,
volume identity, encrypted response cleanup/work, transport error and
cancellation ownership, recovery memory, native listener identity and durable
slot reservations. The [follow-up record](review-followup-2026-10-19.md)
tracks each fix's failing regression and post-fix evidence, with explicit
limits on the unexecuted host campaigns. F10–F15 remain an operational design
and qualification backlog; I01–I27 and T01–T56 are mapped there without being
reported as completed. Production qualification remains Pending.

## Additional reproduced boundaries (2026-10-19)

The additional audit used `b679b80`, whose source tree is identical to the
PR #82 merge `42e725a`. These five fixes preserve the on-disk format and do
not extend production qualification. Each has an executed failing regression
before implementation; passing observation tests from the audit were converted
to expected-behavior regressions for this change.

| Finding | Change | Regression and limits |
|---|---|---|
| BUG-134: rejected first-write reservations invisible to TRIM | A zero-only v3 TRIM marks existing unwritten slots in the discard bitmap and queues bounded checkpoint reclamation. No shard or journal record is created. Overlay versions and freshness checks still protect live reservations. | `review_failed_reservations.rs`: actual allocated-block release through Volume and Engine, TRIM after restart, both bitmap publications and directory-sync failure, failed punch retry, and later rewrite. Core unit tests cover overlapping checkpoint publication and revoked writers. Four additional reservation regressions failed before the fix. Physical power-loss qualification is separate; v2 does not gain TRIM. |
| BUG-135: gRPC TLS identity failures reported retryable | Preserve a safe typed connection-failure category and report TLS authentication/protocol errors as EndpointFatal; reset and timeout remain Retryable. | `review_grpc_tls_classification.rs`: wrong hostname and unknown CA failed before the fix; the server's TLS alert distinguishes both from socket errors. Reset is a passing control. Error text cannot spoof the classifier or expose the original URL. |
| BUG-136: inaccessible export tail | Require configured and stored export sizes to be multiples of the effective NBD minimum I/O size. Invalid creation refuses before backing files are created. | `review_export_alignment.rs`: config, creation and existing-volume attach regressions failed before the fix; aligned 512-byte and 4096-byte settings retain whole-export access. Actual new kernel attachment is not claimed. |
| BUG-137: extra unary gRPC response silently discarded | Reject bytes after the first complete unary response message, including partial second headers, before tonic can drain and ignore them. | `review_grpc_unary_cardinality.rs`: the original two-message regression failed; fragmented and partial-header cases reject, while singleton and remote-status controls preserve their contract. No data-loss or unbounded-memory claim. |
| BUG-138: daemon accepts names the helper rejects | Reject a leading `-` during configuration validation, preserving the helper's argument checks. | `review_volume_name_bound.rs` and `review_volume_name_helper.rs`: expected rejection failed before the fix; safe names and the existing 64-byte boundary remain valid. |

The targeted Linux storage suites, complete gRPC crate, and NBD/configuration
regressions passed after implementation. The pull request records final
workspace, strict lint, release-gate and platform-CI results against its code
revision. No installed systemd/LVM operation, physical power cut or long soak
is implied by these repository tests.

## BUG-153: admitted queue time and batch waiting (2026-10-23)

This change records when each group enters the admitted scheduler queue and
retains that time through dispatch-slot waits and incompatible-group carryover.
Coalescing uses the oldest live group's original `max_wait` deadline; cancelling
that group selects the surviving group's deadline. Queue admission waits remain
outside the coalescing window, and dispatch capacity still bounds concurrency.
The eleven ManualClock cases in
[`review_scheduler_queue_wait.rs`](../crates/maki-crypto/tests/review_scheduler_queue_wait.rs)
cover both lanes, expired and partly elapsed windows, a 180 ms operation budget,
context/unit incompatibility, cancellation, admission, and full/zero-wait/fresh
batch controls. Before this change, seven cases failed and four controls passed;
all eleven pass with the change. This is branch-local regression evidence;
integration and release qualification are separate.

## Mountinfo path whitespace (BUG-164, 2026-10-24)

Mount observation, detach, recovery and NBD allocation now split mountinfo
fields only at ASCII spaces. Unicode whitespace and unescaped control bytes
inside kernel path fields remain part of the path; the existing octal escapes
for spaces, tabs, newlines and backslashes still decode normally.

`maki-privileged/tests/regression_mountinfo_fields.rs` reproduces the missing
mount observation for accepted Unicode paths and covers source fields and
existing escapes. Fixture tests cover detach, nested mounts, recovery and
allocation. These are parser and simulated-sysfs regressions, not a new
privileged NBD/LVM/XFS qualification campaign.

## BUG-155 — validation launcher exits before its descendants (2026-10-23)

The GCP and Firecracker controllers retain their launcher PID until process-group
cleanup. Exit probes use `waitid(WNOWAIT)`, and normal SSH waits terminate the
owned group before reaping its leader. `close()` also cleans descendants after
an early launcher exit and never signals a group after its leader was reaped.

`scripts/test_validation_process_cleanup_validation.py` covers both controllers
with local launcher/descendant processes, including EOF, normal SSH waits,
pre-reset and crash checks, repeated cleanup, and preserved exit status. These
tests require no cloud resources, guest images, or devices; external GCE and
Firecracker qualification is unchanged.

## BUG-156 — test enumeration exceeds the campaign deadline (2026-10-23)

Storage-repeat preparation uses the remaining campaign budget for every build
and test-list invocation, checks the deadline around binary freezing, and starts
no further child after expiry or cancellation. A preparation timeout records
`incomplete`; an explicit stop retains `cancelled`. Per-child caps remain
1,800 seconds for builds and 30 seconds for enumeration.

The `bug156` regressions in `scripts/test_storage_repeat_validation.py` advance
an injected clock across build, binary copy, and enumeration stages. They check
shared-budget exhaustion, no launch after expiry, and terminal status alongside
successful preparation and explicit-stop controls. No Rust build or external
storage campaign is needed to exercise these scheduling boundaries.

## BUG-157: fractional retry-budget credit

Retry credit uses compensated accumulation for both earning and consumption,
so ten requests earn two retries at the default `0.2` ratio (one at `0.1`).
Eligibility includes the retained rounding error instead of granting credit
within an epsilon of one token; burst clipping discards the compensation too.
The ratio is the supplied binary `f64` value, not a rounded decimal fraction:
ten credits of `0.3` or `0.7` remain below three or seven tokens respectively.
Their retained deficits survive consumption of the preceding whole tokens.
Invalid ratios supplied directly to the library disable earning while the
minimum probe rate remains independent.

`review_retry_credit.rs` reproduces the lost fractional credits and covers
interleaved spending, values below the threshold, burst clipping, zero burst,
large finite credits and invalid direct-API ratios. This records the change
and regression coverage, not remote-main integration or release qualification.

## Initial attach retry safety (BUG-166, 2026-10-24)

Multi-endpoint attach probes honor the validation provider's `retry_safe`
capability. A provider that does not permit resending receives one attempt;
retry-safe providers retain up to three. This applies to both the self-test
and the key-canary probe. A failed endpoint remains quarantined while a
validated peer can serve requests, and no final backoff runs after exhaustion.

`maki-nbdkit/tests/review_attach_retry.rs` drops HTTP response bodies after
the server receives each complete request. It reproduces duplicate unsafe
self-test and canary requests, preserves safe retries and normal dispatcher
behavior, and checks the healthy peer's roundtrip. This is local transport
regression evidence; it does not establish external-provider qualification.

## BUG-158: return exhausted retry results before backoff

The endpoint dispatcher checks the completed pass against `max_attempts`
before scheduling backoff. A failed final pass returns its last provider
error immediately; peers within the pass still receive failover attempts.
Backoff remains between permitted passes, including the unlimited policy,
and the operation deadline still bounds in-flight RPCs.

`review_final_backoff.rs` reproduces the extra final sleep for encrypt,
decrypt, multiple peers and an exhausted pass with no admissible peer. It
also covers zero attempts, success, unlimited retries and operation deadlines.
This records the change and regression coverage, not remote-main integration
or release qualification.

## Scheduler deadline metrics (BUG-154, 2026-10-23)

The scheduler counts each encrypt/decrypt caller that receives an operation
deadline error, including expiry before dispatch. The control metric selects
this caller counter when batching is enabled and retains the dispatcher
counter otherwise; the two counters are never added. Coalesced callers each
contribute once, while ordinary errors and cancellation contribute nothing.

`maki-nbdkit/tests/review_deadline_metrics.rs` exercises both lanes, admission,
coalescing, batch-slot and RPC waits, inner-timer propagation, direct dispatch,
and cancellation/success/error controls with `ManualClock`. Five cases failed
before the change. This branch's tests are separate from main integration and
release qualification.

Later update (2026-11-23): AUD-109
([#342](https://github.com/seo-rii/maki/pull/342)) changes what the caller
counter counts: a caller whose own budget ran out, or whose dispatcher ended
the call at its deadline, whatever error it returns, instead of a caller that
receives the deadline error. A caller that leaves at its deadline now returns
the last endpoint error of the RPC batch in progress, and one whose error is
a nested endpoint set's deadline error, received before its own budget ran
out, is no longer counted. The same file gains
`an_endpoint_error_at_the_callers_deadline_is_exported` and
`an_endpoint_error_at_the_dispatchers_deadline_is_exported`.

## Endpoint port preflight (BUG-165, 2026-10-24)

Shared HTTP, WebSocket and gRPC configuration validation rejects nondecimal
and out-of-range endpoint ports. HTTP provider construction also parses its
actual endpoint URL, including direct construction and a `from_config` URL
override, so these errors surface before the first request.

`maki-format/tests/review_config.rs` calls semantic configuration validation
and covers IPv4, bracketed IPv6 and port boundaries. HTTP's
`review_endpoint_ports.rs` exercises both constructors and a real loopback
roundtrip with path and query composition. Empty/default ports, zero and
65535 retain their existing URL-parser behavior. No new dependency or
production-provider qualification is introduced.

## Reachable transport batch capacity (BUG-162, 2026-10-23)

The gRPC and WebSocket configuration bounds use the number of provider units
that can fit both the item and plaintext-byte ceilings. They retain the
maximum ciphertext size, protobuf/JSON framing, and attach probe overhead,
without requiring a transport to carry an unreachable raw byte ceiling.
For example, one 4096-byte unit with a 4384-byte maximum ciphertext fits a
16 KiB transport cap even when `batch.max_bytes` is 1 MiB.

Permanent transport regressions validate that configuration and exercise
maximum-size ciphertext roundtrips plus provider self-tests over real local
connections. They retain larger-batch rejection and byte-limit controls.
The older full-batch configuration regression now selects enough items to
make its large byte budget reachable. This describes the change and its
local regression coverage; remote CI and main integration remain separate.

## GCE configuration BOM compatibility (BUG-172, 2026-10-26)

The guest's provider check accepts one leading UTF-8 BOM, matching Maki's
Rust TOML parser. The provider-evidence check added in PR #114 previously
rejected such an otherwise valid configuration before starting nbdkit.
Strict UTF-8 decoding, TOML validation, provider matching and value-free
error diagnostics remain in place.

`scripts.test_gcp_provider_validation` uses a complete local-provider
configuration with and without a BOM through the guest's actual `main()`
for both reset profiles and write/verify-only boots. All four BOM subcases
failed before the fix; the plain-input controls passed. The suite also
checks malformed UTF-8/TOML, a different provider, repeated or misplaced
BOMs and a BOM inside the provider value. VM, NBD and process boundaries
are mocked; these tests do not perform an external reset campaign.

## Attach configuration diagnostics (BUG-168, 2026-10-26)

Attach configuration parsing retained `toml::de::Error`, whose renderings can
include rejected values, unknown field names, and the input document. An
accidentally pasted credential could therefore reach helper stderr even when
the configuration was rejected. Parsing now retains only a fixed error
classification and its line/column, following the volume parser's existing
policy. The original parser error is neither stored nor exposed as a source.
Accepted attach settings and request validation are unchanged.

`review_attach_config_diagnostics.rs` in `maki-privileged` covers type,
unknown-field, syntax, and nested-schema failures through `Display`, `Debug`,
and the error source chain, plus location and successful-parse controls. The
same-named `maki-attach` suite exercises actual unprivileged `--plan` processes
and a valid plan. The regressions failed before the change. These tests do not
perform mount, LVM, NBD, service, or physical qualification operations, and
the privileged crate gains no crypto dependency.


## Provider URL Debug redaction (BUG-174, 2026-10-28)

Public HTTP and gRPC specifications retained credential-bearing URL components
in their Debug output after the earlier header, query-field and metadata
redaction. HTTP's provider Debug also printed its endpoint URL, and operation
paths could contain the same path or query tokens. The observed boundary is
an API consumer formatting these objects; this does not establish an automatic
daemon or CLI log leak.

HTTP `HttpProviderSpec`, `HttpCryptoProvider` and `OpSpec`, and gRPC
`GrpcProviderSpec`, now render complete endpoint URLs and operation/method paths
as `<redacted>`. Masking the entire field covers invalid, not-yet-validated
values as well as userinfo, path, query and fragment tokens. Field names,
methods, header/metadata names, capabilities, limits and the existing TLS
redaction remain available for diagnostics. Request composition and stored
configuration values are unaffected.

The HTTP and gRPC `review_url_debug.rs` suites cover compact and pretty Debug,
valid and malformed endpoint values, endpoint and operation path/query tokens,
userinfo and fragments. Constructor-only gRPC coverage confirms that accepted
method paths can carry the same tokens. Controls retain existing header/query
and metadata redaction and useful nonsecret diagnostics. All credentials are
synthetic; these regressions do not make network requests.

## Secure-swap filename identity (BUG-173, 2026-10-28)

When `security.require_secure_swap_policy` is enabled, `/proc/swaps` filenames
reach the device classifier without changing their identity. Only space and
tab separate the kernel's columns; Unicode whitespace and literal vertical
tab, form feed, or carriage return remain filename characters. The four
kernel filename escapes for space, tab, newline, and backslash are decoded
once, so an escaped literal backslash cannot become a second escape.

The parser requires the complete five-column header and rows, known swap
types, numeric counters and priority, and an absolute filename without NUL.
Malformed rows fail before any classification; diagnostics report the row
number without repeating its contents. Device-identity and independent-backing
checks are unchanged, and the optional policy still defaults to disabled.

`review_swap_filename_identity.rs` covers full path preservation, rejection of
a different safe prefix, escaped safe devices, one-pass decoding, malformed
headers/rows/escapes, and numeric type boundaries. Ten assertions failed before
the fix while three controls passed. The tests use synthetic inventories and
classifiers and do not change host swap, device nodes, or security policy.

## gRPC proxy error pages (BUG-175, 2026-10-30)

A gRPC endpoint behind an HTTP/2 proxy (nginx `grpc_pass`, an ingress)
answers an upstream restart with an HTTP error page: `:status 502`,
`content-type: text/html`, an HTML body and no `grpc-status`. The receive
framing wrapper of BUG-057/121 framed that body, read `<` as a compression
flag and reported a receive contract violation. `Contract` is `ProviderFatal`
class, so a transient outage failed every request at once under the `stall`
policy and refused attach as proven misconfiguration instead of quarantining
the endpoint; an auth proxy's 401/403 page did not open the breaker either.
Tonic itself maps the HTTP status only when such a body ends without framing.
HTTP and WebSocket already classified 5xx by status.

A non-200 response without `grpc-status` now maps through gRPC's
HTTP-to-status table before its body is read: 429/502/503/504 `Unavailable`
(Retryable), 401 `Unauthenticated` and 403 `PermissionDenied`
(EndpointFatal), 404 `Unimplemented` (EndpointFatal), 400 `Internal`, others
`Unknown`. A trailers-only error with its own `grpc-status` keeps that status,
and an HTTP 200 response whose body is not gRPC framing remains a contract
violation (R5-005).

`maki-crypto-grpc/tests/review_http_status_mapping.rs` serves HTML error pages
and empty error responses for seven statuses from a raw HTTP/2 server. Before
the fix the first HTML page (502) was `Contract`; the empty-body cases and the
HTTP 200 control passed. The tests use loopback sockets only.

## Remote witness transient state reads (BUG-176, 2026-10-30)

The local remote-witness authority (`StateStore`) re-reads its published
state before every request. Any failure of that read poisoned the open
handle for good, including errors that prove nothing about the file: EMFILE
from a flood of unauthenticated connections pending TLS, ENOMEM, a transient
EIO. Nothing had been written and the in-memory state was still the durably
published one, yet every later request answered "reopen required" until the
witness was restarted, so every volume using it refused reads, writes and
FLUSHes long after the cause was gone.

Only proof of an external change poisons now: bytes that differ from the
published state, or a missing, short or undecodable file (`NotFound`,
`UnexpectedEof`, `InvalidData`). Other read failures refuse only their
request; the next request reads and compares again. A failed publication
still poisons, as before. `maki-witness serve` also raises its open-file soft
limit toward the hard limit, as BUG-124 did for the daemon and CLIs.

Later update (2026-11-17): AUD-092
([#189](https://github.com/seo-rii/maki/pull/189)) narrows the publication
rule. A failure before the rename (opening, writing or syncing `remote.next`)
leaves the published state unchanged and refuses only its request; a failed
rename or directory sync still poisons until a reopen.

`maki-backing/tests/remote_witness.rs` injects a failure into opening and into
reading the state file; before the fix the following inspect answered "reopen
required". A removed-then-restored state file stays poisoned, alongside the
existing corrupt-file and publication-failure tests. The tests use private
temporary directories.

## Readiness review follow-up (2026-11-13)

This change integrates the existing gRPC HTTP-status fix (PR #125) and remote
StateStore read-error fix (PR #126), then closes the corresponding local
witness recovery gap. A failed local freshness read now rejects that operation
without poisoning either FileWitness or its parent RollbackBacking. Missing,
truncated, corrupt or mismatched anchors and uncertain publications still stop
the session. A real, isolated EMFILE regression restores descriptors and uses
the existing handles to read, write and sync, then reopens to verify durability.

The first-volume guide now owns one fail-closed bootstrap script, linked from
Quickstart. It rejects occupied NBD/VG/LV names, checks size and unique backend
identity, verifies the live device-mapper UUID and backing device immediately
before formatting, and invokes mkfs.xfs without force. Mocked execution of the
actual documentation block checks failures without formatting real storage.

SlotStore now remembers reservations whose allocation and sync_all succeeded
in the current open session. TRIM punching invalidates the affected ranges
before the operation, including partial failures; reopening starts with no
reservation knowledge. The 256-unit, 4 KiB counting regression observes 256
allocation/sync calls initially and zero additional calls for overwrites after
checkpoint. It verifies flushed data after simulated power loss and ENOSPC.
The cost is one extra in-memory bit per loaded shard slot, with no disk-format
change. New-slot reservation batching and device throughput measurement remain
follow-up work; these counts do not establish an MB/s improvement.

Both affected lockfiles use rustix 1.1.6 for RUSTSEC-2026-0486. CI audits all
root/vendor lockfiles in an independent job, retaining --deny warnings, so an
advisory cannot prevent the baseline job's tests from running. Required-check
selection remains a repository branch-protection setting. The release guides
pin the Rust 1.94.0 baseline, identify the missing nbd-client build provenance,
and require installation/upgrade/restore evidence from the exact candidate
artifacts. README now states the remote provider's plaintext and cryptographic
trust boundary. These changes do not qualify or publish a production release.

The gRPC regression also drives a real loopback HTTP/2 peer through an outage
and recovery using EndpointSet's stall policy: encryption and decryption stay
pending through 502 HTML pages and complete after valid gRPC responses return.
It models an intermediary's wire behavior; it is not a deployed nginx, kernel
NBD, filesystem or database qualification run.

Validation also exposed a native-test fixture assumption when the latest-stable
CI job advanced to Rust/Cargo 1.100. Cargo now places the test executable and
cdylib in separate unit directories, and does not include cdylibs in its dynamic
Rust-library search path. The workspace test runner captures the exact nbdkit
plugin filename from Cargo's compiler-artifact JSON for the same no-run test
build, then supplies it to the test invocation. The fixture refuses a missing
or malformed explicit path; older adjacent `deps` layouts remain supported.
The production plugin is unchanged. The tungstenite lockfile's recorded hash in
`vendor/patches.json` is updated along with the security dependency resolution
and checked by the actual vendor source inventory gate.

## Rollback arena read availability (BUG-185, 2026-11-14)

A transient EIO while reading a rollback arena page stopped the entire open
session, even after storage recovered. The failed read changed neither the
witness nor the referenced page. Ordinary I/O errors now refuse only that
operation and preserve their original error; the next operation checks the
witness and authenticates the page again. Missing, truncated or invalid pages,
hash mismatches, failed arena writes and uncertain commits still stop every
handle until reopen. Local and remote rollback modes share this page path.

`maki-backing/src/rollback/arena_read_tests.rs` covers existing-handle and
freshness recovery, original errno preservation, unchanged witness state,
retry after a multi-page write prefix, damaged or truncated evidence that
remains rejected after restoration, and partial writes that still require
reopen. The maintained tests use an injected memory arena and private witness
files; the original reproduction used a real local arena with one failed
positional read. Neither test is a physical power-loss qualification.

## Remote restore target identity (BUG-187, 2026-11-14)

An administrator-approved snapshot and authority from volume A could be restored
into volume B's configured backing root. The new A namespace then satisfied GC's
current-generation check, allowing automatic GC to delete B's quiescent data.
Restore now checks the target's immutable enrollment identity and capacity before
claiming the authority. A matching binding permits repair of damaged current
data; an older root without that file must authenticate its exact current
generation instead. Corrupt or mismatched bindings never fall back to the backup.
GC independently checks an existing root binding against the authenticated
current generation before any reclamation, preserving legacy roots, abandoned
fork cleanup and partially removed tombstones.

`review_remote_restore_identity.rs` covers foreign identity and capacity refusal
without authority or data changes, source identity refusal, damaged-current
restoration, and missing/corrupt enrollment boundaries. `remote_gc.rs` covers
foreign/corrupt bindings despite a valid current manifest and successful partial
tombstone cleanup under a matching binding. The tests use private file-backed
roots and test authorities; they do not qualify a deployed witness or a physical
power-loss scenario.

## GCP one-shot command cleanup (BUG-196, 2026-11-16)

The final offline check uses `bounded_run()` rather than the guest session's
`RemoteProcess`. Its timeout previously killed only the gcloud launcher, leaving
an SSH child alive. One-shot commands now own a local process group and keep the
leader waitable until group cleanup, including normal and failed leader exits.
Output is collected within the existing combined 1 MiB limit; timeout, output
errors and interruption also clean the owned group before reaping the leader.

`scripts/test_gcp_command_cleanup_validation.py` covers descendants with closed
or inherited pipes, successful/nonzero/signal exits, timeout, interruption, read
errors and output limits, while preserving byte output and stderr diagnostics.
These are owned local-process tests. They do not establish termination of remote
guest commands or descendants that deliberately leave the local process group.
