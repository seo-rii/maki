# Testing and qualification

Maki combines ordinary unit and integration tests with deterministic fault
injection, model comparison, transport chaos, database simulation, and external
Linux or hardware qualification. Passing an automated tier does not imply that
the higher deployment tiers are complete.

Historical `phase*` test filenames and `phase*_gate_full` function names remain
stable internal identifiers. They do not represent the public documentation or
an active implementation plan.

What Maki currently supports is summarized in [status](status.md); the
"Current qualification status" section below is the evidence trail behind
that summary, and the dated reports it cites live under
[`qualification/`](qualification/README.md).

## Run checks locally

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 -B scripts/run_cargo_tests.py --workspace --locked
cargo test --workspace --release --locked -- --ignored
```

CI checks formatting on Linux only: on Windows `cargo fmt --all` hands every
target's root file to a single rustfmt command line, which the workspace has
outgrown ("The filename or extension is too long", os error 206). There,
check one package at a time with `cargo fmt -p <package> --check`.

On Linux, `run_cargo_tests.py` first compiles the same selection with
`--no-run --message-format=json` and passes the exact reported nbdkit cdylib
path into the test run. Windows cross-target tests use Cargo's configured
runner without a Linux plugin path. Cargo 1.100 puts integration tests and libraries in
separate unit directories, so native fixtures cannot infer the plugin path
from the test executable or loader search path. The wrapper uses the same
Cargo options, features and profile for both phases; it does not search old
build outputs. On other platforms it invokes Cargo directly, and so does a
`--doc` selection on Linux: Cargo cannot compile doc tests with `--no-run`,
and they never load the plugin. Use `CARGO` to select a Cargo executable, or
`RUSTUP_TOOLCHAIN=1.94.0` for the baseline.

The ignored release-mode suite is substantially more expensive than the default
workspace suite. It uses simulated backing stores and does not perform real
power cuts or privileged device operations.

The default (debug) suite also runs the core sanitizers: `Overlay`,
`JournalWriter`, and `Volume` check their invariants after every mutation and
panic on the first violation. Release builds compile the checks out, so run the
default suite, not only the release gates, after touching those structures.

## Automated CI

The executable workflow is [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
The parser fuzz qualification is a workflow of its own,
[`.github/workflows/fuzz-qualification.yml`](../.github/workflows/fuzz-qualification.yml),
which runs only when dispatched by hand ([Fuzz qualification](#fuzz-qualification)).

| Tier | Trigger | Platform | Enforcement |
|---|---|---|---|
| Baseline | Pull requests and pushes | Ubuntu and Windows, Rust 1.94.0 | Strict Clippy and workspace tests block, and formatting on Ubuntu; on Ubuntu the root-only test targets also run as root |
| Compatibility | Pull requests and pushes | Ubuntu and Windows, latest stable | Strict Clippy and workspace tests block independently, and formatting on Ubuntu |
| Service lifecycle | Pull requests and pushes | Disposable Ubuntu systemd host, Rust 1.94.0 | Real failed-start hook and private simulated-resource unit graph block independently |
| Kernel lifecycle | Pull requests and pushes | Disposable Ubuntu runner VM: its kernel, udev and systemd, Rust 1.94.0 | A whole attachment through kernel NBD, LVM, device-mapper and XFS with the privileged runner (attach, a capture of what the helper's readers parse, a detach held open by another process, a second attach, a cleanup after nbdkit is killed, a third attach, a second kill with the device disconnected and released by hand and cleanup's disconnected recovery, a fourth attach, a final detach), then the Debian install steps, quick start and first-volume bootstrap on the package built from the commit, the same with the bootstrap stopped once at `mkfs.xfs` and once at `vgchange` and continued from its record, and three volumes stopping together with every device held open, block independently |
| RHEL 9 userspace | Pull requests and pushes | CentOS Stream 9 container on Ubuntu, Rust 1.94.0 | Packaged build, nbdkit ABI against EL9's header, the `maki-privileged`, `maki-attach` and `maki-nbdkit` suites with EL9's nbdkit, the RPM contract, and install, check and removal of the built RPM block independently |
| Booted hosts | Pull requests and pushes | Cloud images of Debian 12 and of Rocky Linux 9 (SELinux enforcing on Rocky) booted as KVM guests under QEMU on Ubuntu runner VMs, not on bare metal; packages built in `debian:12` and CentOS Stream 9 containers, Rust 1.94.0 | In a fresh guest per suite, on the guest's kernel: as root, the installation guide's host steps, the quick start and the first-volume bootstrap with the package built from the commit; as the guest's user `ci` with passwordless sudo, the privileged runner's lifecycle with that package's binaries; on Rocky Linux also auditd active, no AVC naming Maki or NBD, `maki@`'s nbdkit in `unconfined_service_t` and the guide's file labels; each guest and suite blocks independently |
| Extended | Scheduled run | Ubuntu, Rust 1.94.0 | Ignored model, crash, HA, database, and power-loss gates block |
| etcd qualification | Scheduled run | Ubuntu, Rust 1.94.0, digest-pinned etcd v3.6.5 | Real three-member etcd quorum and witness frontend gate blocks |
| Big-endian seeds | Pull requests and pushes | Ubuntu, Rust 1.94.0, `s390x-unknown-linux-gnu` under `qemu-user` | The replay of every committed [fuzz seed](#fuzzing), cross-built for s390x and run under user-mode emulation, blocks |
| Fuzzing | Scheduled run | Ubuntu, pinned nightly `nightly-2026-11-24`, `cargo-fuzz` 0.13.2 | Every [fuzz target](#fuzzing) runs for 30 seconds from its committed seeds under libFuzzer and AddressSanitizer; a crash blocks |
| Fuzz qualification | Manual dispatch of `fuzz-qualification.yml` | Ubuntu hosted runners (4 vCPUs), the fuzzing tier's nightly and `cargo-fuzz` | Every [fuzz target](#fuzz-qualification), or a chosen list, for a given number of CPU-hours (24 by default) over several jobs; the summary fails unless every target qualified |

Both platform matrices set `fail-fast: false`, so a Linux failure cannot
cancel the Windows evidence. The pinned baseline is reproducible; latest stable
checks compiler changes separately. A local pass on one compiler or a successful
push does not establish the final commit's remote CI result. Use
`cargo +1.94.0` for baseline checks and an updated stable toolchain for
compatibility checks.

The baseline workspace suite includes unit tests, parser mutation smokes,
the replay of every committed [fuzz seed](#fuzzing), golden format vectors,
provider conformance, transport chaos, failpoints, manual-clock retry tests,
privilege-plan tests, NBD adapter tests, database and power-loss simulations,
and real-process tests for all five binaries (`maki`, `maki-attach`,
`maki-check`, `maki-benchmark` and `maki-witness`).
The Linux baseline installs `nbdkit`, `nbdkit-plugin-dev`, `libnbd-bin` and
`linux-libc-dev` before the workspace tests and checks their executables. This
runs the native startup, negotiation, drain, process-crash, and ABI regressions
instead of relying on optional tool availability. The workflow sets
`MAKI_TEST_REQUIRE_NBDKIT=1` and `MAKI_TEST_REQUIRE_NBD_HEADERS=1`, so the
helper's NBD handshake tests against nbdkit and its check of the NBD constants
against the UAPI headers fail there instead of skipping. It also sets
`MAKI_TEST_REQUIRE_IPV6=1`: the HTTP and gRPC tests of a connect to the other
address family need the IPv6 loopback address, and skip without it unless
that is set. Native startup uses disposable files and Unix sockets; it
does not attach a kernel NBD device or mount a filesystem. On developer hosts
without nbdkit, native cases explicitly report that they were skipped; such a
run is not native execution evidence.
The Linux baseline also runs the Python cgroup, Firecracker, and GCE reset
fault-oracle regressions. Actual Docker cgroup, KVM/Firecracker, and GCE reset
campaigns remain opt-in host qualification steps. The job runs every
`scripts/test_*.py` (`scripts/test_ci_gate_validation.py` fails for a module
the workflow would not run) and fails when those suites leave
`scripts/__pycache__` in the checkout. There, `scripts/test_rpm_package.py`
also builds the Debian package from the same stub artifacts and compares the
two packages file by file; `MAKI_TEST_REQUIRE_DPKG_DEB=1` makes a missing
`dpkg-deb` a failure instead of a skip.

The workspace tests run as the unprivileged runner user. Tests that give a
fixture to another user, run a binary as the daemon user, enter a private
mount or network namespace, set the immutable flag or connect a kernel NBD
device print why they are skipped there and pass. The Linux baseline therefore loads the
`nbd` module (from `linux-modules-extra` when the runner's kernel keeps it
there; the step fails when neither loads) and runs
`python3 -B scripts/run_root_tests.py --open-build-tree --workspace --locked`
next. The script reuses the compilation of the workspace run as the runner
user and starts only the test executables in its `ROOT_TARGETS` list as root
through `sudo -n`, each with a scratch `TMPDIR` under `/tmp` that other users
can search and that it removes afterwards. It fails when root is not
available (nothing is compiled or skipped), when a test that ran as root
still reports that it needs root, and when the run leaves an entry owned by
root in the checkout or the build tree. That step sets
`MAKI_TEST_REQUIRE_NBD=1`, and the script passes it and the other
`MAKI_TEST_REQUIRE_*` switches on, so the kernel NBD test fails instead of
skipping there. `--open-build-tree` lets the fixture
user (uid 65534) reach the built `maki` and `maki-check` binaries, and the
test executables that re-execute themselves as that user, below a `0750`
home directory for the duration of the run.
`scripts/test_root_tests_validation.py` fails for a test source that probes
its privilege (`geteuid`, a "needs root" notice, `chown`, `unshare`) and is
neither in `ROOT_TARGETS` nor classified in that test as not needing root, so
a new root-only test cannot be left out. Run the same command without
`--open-build-tree` locally as root or as a user with passwordless `sudo`.

Root does not make every host capable. The memory-budget mount-table tests
reach the final admission check only where root can create a group in a
single cgroup-v2 hierarchy with the memory controller; elsewhere they compare
earlier verdicts, which they print, or skip with a notice. The
immutable-snapshot restore test needs a filesystem under `/tmp` that accepts
the immutable flag, the mount-namespace tests need a kernel that lets root
unshare one, and so does the network-namespace test; otherwise they print why
they skip. As root that test also needs an `nft` or an `iptables` that
installs its rule, and fails without one. The script repeats
every skip notice at the end of its output, and a run with notices is not
evidence for the cases they name.

The independent `systemd-lifecycle` job builds the actual `maki-attach` hook
and runs `scripts/systemd-lifecycle-validation.py` on its disposable runner.
Random instance units preserve the packaged lifecycle dependency graph; marker
processes replace storage and workload commands. Cases cover failed start,
timeout, SIGKILL, refusal of recovery cleanup, a simulated foreign resource,
start-rate limiting, duplicate start, planned stop, failed stop and cancelled
startup. A marker command after the hook checks that no daemon stop precedes
the end of the attach unit's stop phase, during which the hook rolls back an
interrupted activation. The fixture removes only its own unit links and retains case results
and bounded diagnostics as a CI artifact. It does not attach devices or qualify
the Debian 12 NBD/LVM/XFS stack. The
[first production campaign](deployment/first-production-candidate.md) requires
those installed-package and workload results separately.

The independent `kernel-lifecycle` job runs on the runner VM itself, not in a
container, so it has the runner's kernel, udev and systemd as PID 1. It loads
the `nbd` module with the parameters the privileged runner asks for
(`nbds_max=16 max_part=8`, from `linux-modules-extra` when the runner's
kernel keeps it there; the step fails when neither loads), then runs
`scripts/privileged-linux-validation.sh --install-missing --kill-daemon
--device /dev/nbd15 --confirm-wipe /dev/nbd15` in the foreground as the
runner user, with the checks its
[runbook](qualification/privileged-linux-validation.md#scope) lists: apt
installs its tools, it builds `maki`, `maki-attach` and the plugin from a
snapshot of the commit, starts nbdkit as that user and goes through kernel
NBD, raw fio, LVM, XFS and the helper's attach, verify, file fio and SQLite.
After the first attach it captures, as root and read-only, what the
helper's readers parse, for the `helper_reports` and `helper_sysfs` fuzz
seeds: `scripts/privileged_validation_capture.py` runs LVM's `fullreport`,
the `blkid` label and filesystem probes, `dmsetup info`, the LV's size probe
and the mount source's UUID probe with the helper's own arguments,
environment and 15 s limit (the tests read them from the helper's sources),
and writes their output (the first 64 KiB of each stream, marked truncated
if longer, after reading it whole) with the device's nodes below `/sys/class/block`, in the
`helper_sysfs` input's line format, and the mount table into
`helper-outputs.json`.

It then writes and fsyncs 32 MiB beside the database and records their
hashes, and detaches while `scripts/privileged_validation_opener.py` holds
`/dev/nbd15` open (AUD-197). The opener requires that its reads fail with
`EIO` once the disconnect is acknowledged, that the device shows the
connection until the opener closes it and none after; the run requires that
the detach returned only once the opener had written that it was closing
the device, so the detach's final teardown must have waited for the close.
It attaches again with `init_sentinel` off and compares the hashes, kills
nbdkit with `SIGKILL` under the mount, requires `maki-attach cleanup` to
release the attachment without it, starts a new nbdkit on the same backing,
attaches a third time and compares the hashes. In the job's runs of
2026-11-26 the killed daemon's device still showed its connection, so that
cleanup took cleanup's detach path. The run then kills nbdkit again and
leaves the device showing no connection with the attach record in place:
`scripts/privileged_validation_nbd.py kernel-disconnect` sends the kernel's
`NBD_CMD_DISCONNECT` over generic netlink for the attachment's identifier,
which the helper's own `nbd-disconnect` refuses, and only while the device
still shows the connection does the run unmount XFS and then remove the
LV's mapping with `dmsetup remove`, logging what the device shows after each
step. `maki-attach cleanup` must then take its disconnected recovery
(AUD-203), and a new nbdkit and a fourth attach must compare the hashes
before the final detach. The helper logs the path cleanup takes, and the run
requires each cleanup to have taken the one for what the device showed when
it started. Read from the kernel's NBD driver, the device keeps a
connection's attributes while anything holds it open, a mount or a mapping
above all, so a device that shows no connection has neither left, and the
disconnected recovery that a kernel can reach only retires the record. The
job's runs with these steps (2026-11-27, Linux `7.0.0-1020-azure`) showed it
for the mapping: after `NBD_CMD_DISCONNECT` the device still showed the
connection with XFS mounted on the LV and again after the unmount, and
showed none once the mapping was removed (the mount sits on the mapping,
so its own effect is not told apart); cleanup then logged disconnected
recovery, ran no step and left nothing. Each attach must show the mount, the attachment's backend identifier
and the attach record; after each detach, and after each cleanup that ends
an attachment, the mount, the device's holders, its connection and size and
the attach record must be gone, and a look for the record that fails stops
the run.

The package built from the same commit (`packaging/debian/build-deb.py`) then
runs the documented procedure as written, also when the runner's step has
failed: `scripts/documented_quickstart.py` writes the Debian guide's "Install
the Maki package" blocks, the [quick start](getting-started/quickstart.md)'s
blocks and, as its step 4, the
[first-volume bootstrap](getting-started/first-volume.md#1-provision-and-record-the-layout)
(AUD-199) into one program that runs them in order in one root shell under
`set -e -o pipefail` and checks each block's status after it. It stops at a
failed command that `set -e` stops at, a pipeline included, and at a block
whose last command failed, an `&&` list that ends the block included. `set
-e` does not stop at a failure inside an `&&` or `||` list before a block's
last command. The writer refuses a block that Bash cannot read, and one with
`&&` or `||`, matched as text, on any line that Bash's `declare -f`
prints at the block's own level (a subshell's commands print there too) up to
the last such line, before the last line it prints at that level, that ends in `;` or
holds a here-document's command; so a condition, a test expression or quoted
text there is refused too. Below the block's level, in the bodies of `if`,
`while`, `for` or `case`, brace groups and functions at any depth, it
refuses every line with `&&` or `||` except those its allow-list
(`DEEPER_LISTS`) names for that block: the guides' only such lines, apart
from here-documents, which run in a shell of their own, are `wait_stopped`'s
returns and the unmount check's `|| echo`, each read and found to handle its
own failure, and the tests require the allow-list to be exactly those. It
does not see a negated or a background command, where a failure lets the
program go on. The check relies on the
layout of `declare -f`, against which it was written with Bash 5.2.21; the
`UnguardedLists` tests, which the pull-request job runs with the runner's
Bash, would show a change of it. The step then requires that no attach
record, mount, connection or active unit of the volume remains. That
covers the bootstrap's real `maki-attach nbd-connect` and `nbd-disconnect`,
LVM, device-mapper and XFS commands and the installed units: `maki@` under
its sandbox, the attach unit's start and its `ExecStop` cleanup on a planned
stop after `maki drain` and on `systemctl disable --now`.

Once that step has succeeded, the job runs the program twice more, each
written with `--stop-once`: the bootstrap's first run has a shim first on
`PATH` that fails one command, and the program requires that the run
stopped there (the shim leaves a mark, which the program reads, so a run
that failed before it reached that command stops the program), left its
record and that the device still shows its connection, then runs the same
block again as the guide's
[recovery notes](getting-started/first-volume.md#recovering-from-a-failed-bootstrap)
say. Stopped at `mkfs.xfs`, the record names no filesystem: the next run must
release the export, stop `maki@demo.service`, remove the record and fail;
the volume is reset as the notes say (its backing directory removed while
the daemon is stopped, the creation block run again) and a third run starts
over. Stopped at the release's `vgchange`, the record names the filesystem
and the next run must finish. The rest of the quick start follows each, and
each must leave nothing of the volume behind.

Then `scripts/stop-together-validation.py` runs as root: it provisions
three volumes `stop1` to `stop3` with the quick start's key, configuration
and creation blocks and the bootstrap, their `demo` replaced by the volume's
name and the bootstrap's device by `/dev/nbd8`, and starts each with the
quick start's start block. With every target started, the opener holds each
volume's device and keeps it 10 seconds after its disconnect, and one
`systemctl stop` stops the three targets (AUD-197). Each attach unit's stop
runs `maki-attach cleanup`, which waits for its opener without the global
attach lock. With that, the job's run at 31b7ef8 measured the three stops
overlapping, 10.183, 10.246 and 10.310 s, about the hold each; its runs
before the change measured them queued on the lock, about 10.2, 20.3 and
30.5 s. The driver requires neither. `systemctl stop` returns once the targets' own jobs are done, before
the attach units they are ordered after have stopped, so the driver looks at
each attach unit until it is inactive or failed, for up to 300 s. systemd
then garbage-collects an inactive unit, and `systemctl show` loads a fresh
one whose timestamps are all 0, so the times come from the journal of PID 1
for this boot: the monotonic timestamps of the messages that the unit's stop
job has begun and has finished (systemd's catalog `MESSAGE_ID`s, the same
`JOB_ID`, after the stop request), with the job's `JOB_RESULT` and the
`UNIT_RESULT` of a unit that failed. It prints, and keeps in
`stop-together.json`, when each attach unit's stop began and ended after the
request with each opener's account, and fails after that report if a
stop did not succeed, an opener did not see its disconnect and the
connection kept until it closed, or anything of a volume is left. It
measures today's behaviour; it requires neither that the stops overlap nor
that they queue.

When a step fails or the job is cancelled, the job prints the runner's status
and component logs, the kernel log, the units' journal, the NBD devices,
mappings, mounts and attach records; it always prints the tool versions and
keeps the logs, without the runner's source snapshot, builds and work tree or
any key file, as the `kernel-lifecycle-logs` artifact, with the directories of
the quick starts and of the stop together without the package. The runner is GitHub's
`ubuntu-latest` image, not the Debian 12 primary platform or RHEL 9, and its
kernel changes with the image; the job uses the local provider only and kills
nbdkit twice, each time while the filesystem is idle after a sync, which is
not a power loss.

The `rhel9` job runs in the `quay.io/centos/centos:stream9` container; CentOS
Stream 9 is the public upstream of RHEL 9. It installs its tools from BaseOS
and AppStream, plus `nbdkit-devel` from CRB for the ABI header, without EPEL:
`nbdkit-server` and `nbdkit-basic-plugins` rather than the `nbdkit`
metapackage the [RHEL guide](getting-started/installation-rhel.md#selinux)
warns about, and the kernel UAPI headers. It builds the four packaged
artifacts in release mode against glibc 2.34; runs `review_abi.rs` against
EL9's `nbdkit-plugin.h`; runs the `maki-privileged`, `maki-attach` and
`maki-nbdkit` suites through `run_cargo_tests.py` with `--no-fail-fast`, so
the native tests load Maki's plugin into EL9's nbdkit 1.38; and runs
`scripts/test_rpm_package.py`. It then builds the real RPM, requires that it
depends on glibc and on `GLIBC_2.34` symbols, installs it with dnf (its
`Requires` bring lvm2, xfsprogs and kmod; the metapackage and
`nbdkit-selinux` must stay absent), requires each of the package's three
user and group provides once, checks its files and units (`rpm -V`,
`systemd-analyze verify`). Under an attachment record it then requires dnf
to refuse to remove Maki, to remove a package Maki requires and to install
the `nbdkit` metapackage with `--allowerasing`, each for the reason dnf
prints, with the runtime packages still installed and `rpm -V` clean
afterwards; it reinstalls the package, requires `rpm -e` to refuse while the
record exists, and without the record requires dnf to refuse again and
`rpm -e` to remove the package and its protection file.

The container's steps run as root, but the workspace, `RUNNER_TEMP` and
`HOME` belong to the runner's uid 1001. `actions/checkout` trusts the
workspace only in a temporary git configuration, so the job adds it to root's
`safe.directory`, and because fixtures that require root-owned ancestors
closed to others (`regression_mount_target.rs`) refuse the workspace, `HOME`
and `/tmp`, the tests get a root-owned `0755` `TMPDIR` below `/var/lib`. The
root-only targets of those crates therefore run inline; those that need a
private mount namespace or a writable cgroup hierarchy print why they skip
there, and the Ubuntu job runs them as root. The kernel is the runner's: the
job covers RHEL 9's userspace, not its kernel, SELinux or an attachment.

The booted-host jobs run Maki on booted Debian 12 and EL9 hosts with their
own kernel, systemd, udev and, on EL9, SELinux in enforcing mode. Each host
is a KVM virtual machine that QEMU runs on a GitHub Ubuntu runner VM (nested
virtualization on GitHub's hardware), not a bare-metal host, and its disk is
a qcow2 overlay on the runner's disk. The `debian12-package` job builds the
Debian package from the commit in a `debian:12` container, against bookworm's
glibc and with `dpkg-shlibdeps`, as the release workflow does; `el9-package`
builds the RPM in the CentOS Stream 9 container the release workflow builds
the published RPM in. Both use version `0.0.0~ci` and upload the package with
its `source-revision` and `SHA256SUMS`.

`debian12-guest` and `el9-guest` then each run two suites, `guides` and
`runner`, in a guest booted fresh for each. `scripts/booted-host-validation.py`
downloads the guest's cloud image, pinned by name and digest:

- Debian 12's generic cloud image `debian-12-generic-amd64-20261112-2660`
  (SHA-512), which runs Debian's standard kernel (Linux 6.1) with all its
  modules, on ext4; the `genericcloud` image runs the cloud kernel, which
  leaves drivers out. Debian keeps dated builds for years (its listing went
  back to 2023 when the pin was taken).
- Rocky Linux 9.9's `Rocky-9-GenericCloud-Base-9.9-20261112.0` (SHA-256),
  whose root file system is XFS on a partition and whose SELinux is
  enforcing as shipped. Rocky Linux rebuilds RHEL's published sources
  unchanged, aiming at bug-for-bug compatibility; AlmaLinux has aimed at ABI
  compatibility since 2023 and builds from CentOS Stream, so Rocky Linux is
  the closer of the two to RHEL, though it is not RHEL. Rocky keeps a minor
  release's current image under `pub/` and moves the release's last image
  to the vault once the next minor release is out; the download tries the
  vault second, and the 9.9 vault address answers 404 until then.

The guest jobs cache the image with `actions/cache`, keyed by the pinned file
name, the digest algorithm and the digest (no fallback key, so another pin's
image is never restored), and save it right after a miss, also when a later
step fails. A cache saved by a run on `main` is shared with pull requests; one
saved by a pull request serves only that pull request's later runs. `fetch`
checks a restored image's digest as it checks a download, and downloads it
again if it differs. When the pinned image leaves `pub/` (Rocky replaces it,
or a new minor release moves it), a warm cache keeps the job passing until
GitHub evicts the entry (unused for 7 days, or the repository's 10 GB limit),
and a cold cache fails the `guest image` step at both addresses, saying to
pin the current image; that holds every pull request until the pin moves.

It refuses an image with another digest, checks that the package's
`SHA256SUMS` hold and that it was built from the checkout's `HEAD`, and boots
the image under QEMU with KVM (`/dev/kvm`, which a udev rule opens to every
user of the runner VM), 2 vCPUs, 4 GiB and a 30 GiB copy-on-write disk over
the image, the serial console in a log file and SSH forwarded from
`127.0.0.1` only. A cloud-init NoCloud seed creates the user `ci` with an SSH
key generated for the run, no password and passwordless sudo, and pins an
SSH host key generated for the run; SSH accepts only that key. The driver
waits for SSH and for `cloud-init status --wait`, asking again when the
connection drops while cloud-init restarts sshd, and copies the payload in.
Every step has a time limit. Each phase runs in the guest as root under
`sudo timeout`, so the limit runs as root and reaches the phase's children
(as `ci`, `timeout` could not signal the phase's root processes), and the host gives up on the connection 90 s after that limit; the
boot, its SSH probes, cloud-init's wait and the copy of the payload together
end within the boot step's limit. `scripts/booted-host-guest.py` runs each
phase in the guest as root:

- `facts` records the release, kernel, virtualization, security modules, the
  `nbd` module's file (and on EL9 its package), the LVM devices file and the
  package inventory; on EL9 `getenforce` must print `Enforcing`.
- `prepare` stops the package manager's timers and refreshes the package
  lists (`apt-get update --error-on=any`) or dnf's metadata, as on a
  maintained host; it installs nothing.
- `guides` runs the program `scripts/documented_quickstart.py` writes (with
  `--installation rhel` on EL9: the RHEL guide's "Repositories" and "Install
  the Maki package" blocks instead of the Debian guide's, then the same quick
  start and bootstrap) as root beside the package, and then requires that no
  attach record, mount or active unit of the volume and no NBD connection
  remains, as the `kernel-lifecycle` job does. The guide's own `apt install` or `dnf
  install` brings the package's dependencies onto the cloud image.
- `runner` installs what the privileged runner needs (on Debian `git` and
  `dmsetup`, the runner's `--install-missing` installs the rest; on EL9 its
  tools from BaseOS and AppStream with dnf, `nbdkit-server` rather than the
  metapackage, and `device-mapper` for `dmsetup`, which `--kill-daemon`'s
  release by hand and the capture of the helper's inputs run), takes `maki`, `maki-attach` and the plugin out of the package
  without installing it, loads `nbd` with `nbds_max=16 max_part=8` and runs
  `scripts/privileged-linux-validation.sh --kill-daemon --prebuilt DIR
  --device /dev/nbd15 --confirm-wipe /dev/nbd15` from a clone of the commit as
  `ci` (the runner refuses root and calls sudo itself). With `--prebuilt` the
  runner copies those three files into its run directory and records their
  hashes instead of building; its scripts still come from its snapshot of the
  commit. The lifecycle is the one the `kernel-lifecycle` job runs.
- `selinux` (EL9, after either suite, also when it failed): `getenforce` must
  still print `Enforcing` and auditd must be active (without it AVC records
  go to the kernel log and `ausearch` finds none); every AVC, USER_AVC and
  SELinux error since boot
  (`ausearch -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts boot -i`) is
  kept, and one that names Maki or an NBD device fails. After the guides, the
  nbdkit of `maki@demo.service` must have run in `unconfined_service_t`, and
  these must carry the labels the
  [RHEL guide](getting-started/installation-rhel.md#selinux) lists: `maki`,
  `maki-attach`, `maki-check` and `/usr/sbin/nbdkit` `bin_t`, the plugin
  `lib_t`, `/etc/maki` `etc_t`, `/var/lib/maki` `var_lib_t`, `/run/maki`,
  `/run/maki-control` and `/run/maki-attach` `var_run_t`, the four unit
  files `systemd_unit_file_t`, and `/dev/nbd0`, the device the quick start
  attaches, `fixed_disk_device_t` (no other NBD device is checked). A
  sampler records each nbdkit and `maki*` process with its unit and label
  every half second during either suite.
- `versions` records the kernel and the versions of the packages the guides
  and the runner use.

The last step always packs the results, the program and its output (not the
package), the runner's run directory (not its snapshot or builds), the
journal, the kernel log, cloud-init's logs and, on EL9, the audit log, copies
them out with the guest's console log, and powers the guest off. Neither key
(`/etc/maki/secrets`, the runner's work tree), no backing, no SSH key and not
the seed, which holds the host key, nor anything under `/var/lib/cloud` (its
copy of the seed) is kept, and a file that holds a private key stops the
collection. The artifacts are
`<guest>-guest-<suite>-logs`. The jobs use the local provider, one volume at
a time, QEMU's user-mode network and no power loss; the EL9 kernel is Rocky
Linux's build of RHEL's kernel, not RHEL's own, and `maki-attach grow` does
not run.

The 2026-09-18 bounded-replay follow-up at revision `733833c` reran the Docker
cgroup campaign. A 21.5 MiB distinct pressure tail recovered at 32 MiB with all
136 external ACK units intact, then passed the 192 MiB recovery and offline
deep check. Because `memory.peak` reached the exact 32 MiB cap, this is a
scenario result rather than a minimum-memory recommendation. See the
[cgroup evidence](qualification/cgroup-fault-validation-2026-09-12.md#bounded-replay-follow-up--2026-09-18).

The 2026-09-19 [constrained recovery RSS campaign](qualification/recovery-rss-validation-2026-09-19.md)
then ran two independent 48 MiB and two independent 64 MiB post-OOM recoveries.
All four matched 136 ACK units and passed deep checking. The largest observed
nbdkit `VmHWM` was 11,415,552 bytes. Both 48 MiB cgroups touched their cap; both
64 MiB runs stayed below it without max events. This qualifies that fixed
profile and does not define a universal deployment minimum.

Linux PR, push, and scheduled CI installs the pinned `cargo-audit 0.22.1` and
runs `cargo audit --deny warnings` for the workspace and each standalone
`vendor/*/Cargo.lock` used by the compatibility tests. A known vulnerability,
unmaintained or unsound advisory, or yanked crate therefore fails the job
against the fetched RustSec database. Revision `8ed9c03` raised the direct rustls minimum and lockfile
from affected 0.23.43 to 0.23.45 after `RUSTSEC-2026-0285`; the focused HTTP/TLS
package suite and a fresh warning-denying audit passed locally.
The current vendored pin is 0.23.46, which includes the subsequent
`RUSTSEC-2026-0346` through `RUSTSEC-2026-0349` fixes while retaining the local
plaintext-erasure patch and its allocator-observed regressions.

The scheduled `nightly-gates` job runs:

| Test identifier | Workload |
|---|---|
| `phase0_gate_full` | 10,000 seeded durability-model sequences |
| `phase3_gate_full` | 10,000 seeded crash/recovery sequences |
| `phase4_gate_full` | 110,000 randomized block operations |
| `phase5_gate_endpoint_cycles_full` | 10,000 endpoint-failure cycles |
| `phase5_gate_breaker_cycles_full` | 10,000 circuit-breaker lifecycles |
| `phase11_gate_dbsim_full` | 500 database-simulation runs |
| `phase12_gate_full` | 500 barrier and 500 FUA power-loss simulations |
| `phase_r3b_durability_gate_full` | Randomized workload → power loss or restart → oracle, with random sync failures. The seeds take turns between a journal segment of three records, one of sixteen and the default one, and the gate asserts a minimum of automatic rolls and of workloads that end with more than three unsynced journal records. Measured without faults (9,000 workloads): 40,249 rolls, 1,443 power losses and 631 restarts with such a tail, the longest 50 records; with sync failures (3,600): 2,738 rolls, 885 and 349, the longest 70 |
| `phase_r3b_concurrent_gate_full` | Concurrent partial-unit writers under the same crash/restart oracle, with the same turns and assertions. Measured (1,800 workloads): 29,147 rolls, 377 power losses and 134 restarts with more than three unsynced records, the longest 43; the tails vary from run to run |
| `phase_r3b_media_damage_gate_full` | Media damage to allocation-map copies and slot headers after a crash |
| `trim_power_loss_gate_full` | 400 seeds of writes and unit-aligned trims on a discard (v3) volume → power loss or restart → oracle, half of them with sync failures, with the same turns between journal segments and the same assertions. Measured (4,000 workloads): 7,253 rolls, 910 power losses and 379 restarts with more than three unsynced records, the longest 49 |
| `ab_torn_reuse_gate_full` | Chains of A/B stores cut at the record's sync, 2,000 to 4,000 seeds per record and torn-write unit (maps of five sectors, one page and 9000 bytes, checkpoint state, the durable proof through `advance`), and 1,000 to 2,000 seeds of mixed disturbances on the proof and the page-sized maps |
| `phase_r5_rollback_write_cost_gate_full` | Rollback-protected backing: 64 KiB write cost with 128 MiB committed (Linux, witness on a second filesystem) |

The durability sweeps behind these gates also run in the default suite over
fewer seeds (`review_r3b_durability.rs`, `review_trim_power_loss.rs`). A
journal roll seals and syncs the segment it leaves, so a workload that rolls
constantly never has more than a segment's records unsynced, and a workload
with the default segment never rolls: each seed runs with a segment of three
records, of sixteen, or the default, and every sweep asserts a minimum of
rolls and of workloads that end with more than three unsynced records at the
power loss or at the restart. Measured on the committed seeds:

| Sweep | Workloads | Rolls | Long tail at power loss | Long tail at restart | Longest tail |
|---|---|---|---|---|---|
| Sequential | 480 | 2,052 | 74 | 35 | 50 |
| Sequential, sync failures | 320 | 247 | 88 | 29 | 38 |
| Sequential, plaintext cache | 240 | 1,014 | 39 | 15 | 21 |
| Sequential, plaintext cache, sync failures | 160 | 110 | 51 | 11 | 38 |
| Concurrent writers | 72 | 1,173 | 12 to 15 | 2 to 10 | 19 to 28 |
| Concurrent writers, plaintext cache | 36 | 571 | 8 to 10 | 0 or 1 | 16 to 22 |
| Writes and trims | 144 | 472 | 27 | 16 | 21 |
| Writes and trims, sync failures | 144 | 73 to 92 | 32 to 37 | 12 to 15 | 41 |

With the default segment for every seed the sequential sweep had 119 power
losses and 52 restarts with a long tail and no roll; with three-record
segments for every seed it had 5,353 rolls and no long tail.

The job runs `cargo test --workspace --release --locked --no-fail-fast -- --ignored`
without a name filter, so every ignored test runs, including any new gate; the
`maki-privileged` subprocess fixture is a no-op there. `--no-fail-fast` keeps
one failing gate binary from hiding the result of every binary after it.

Gates that need operator-provided infrastructure refuse to skip, so they are
compiled only with an opt-in feature and are not part of that `-- --ignored`
run. The etcd gates have their own scheduled job, `etcd-qualification`, which
installs a digest-pinned etcd v3.6.5, builds `maki-witness` and runs the gates
one at a time (`--test-threads=1`): each starts a three-member cluster and a
frontend on ports it chose by binding port 0 and releasing it, so two started
together can take each other's ports. No CI job provides the delegated
cgroup, so the cgroup gate runs only on an operator's host:

| Feature | Gate | Requires |
|---|---|---|
| `maki-nbdkit/cgroup-qualification` | `memory_budget.rs` `delegated_cgroup_oom_enforces_memory_max` | `MAKI_MEMORY_TEST_CGROUP`, a disposable delegated cgroup v2 ([performance](performance.md)) |
| `maki-witness/etcd-qualification` | `etcd_ha.rs` `real_three_member_quorum_cas_leader_failover_and_majority_loss`, and `a_remote_volume_on_an_etcd_quorum_is_read_with_inspections_only` (the read-only view that `maki check` and `maki volume inspect` use, over the quorum behind a frontend: three inspections and nothing else) | `MAKI_ETCD_BIN` (verified etcd v3.6 with `etcdctl` beside it) and `MAKI_WITNESS_BIN` (built `maki-witness`) |

```bash
cargo build --release --locked -p maki-witness-cli
MAKI_ETCD_BIN=/opt/etcd-v3.6/etcd MAKI_WITNESS_BIN=$PWD/target/release/maki-witness \
  cargo test --release --locked -p maki-witness --features etcd-qualification \
  --test etcd_ha -- --ignored --test-threads=1 --nocapture
```

The `nightly-gates` job also builds the Linux cdylib, verifies the global
`plugin_init` symbol,
installs `nbdkit-plugin-dev` and runs `review_abi.rs`, which compiles a C probe
against the distribution's `nbdkit-plugin.h` and compares every field offset
and `NBDKIT_*` constant the shim depends on. The same test runs under WSL
when the header is installed there, and skips with a message otherwise.

The last step of the `nightly-gates` job builds `maki` alone in release mode
and requires `maki volume create` to refuse a configuration with
`provider = "fake"`: the command must fail with `provider "fake" is not
compiled into this build` and leave no `superblock.a`. The workspace test run
cannot show this, because feature unification compiles the fake provider into
`maki-nbdkit` for that crate's own tests.

### Fuzzing

The coverage-guided targets in [`fuzz/`](../fuzz/Cargo.toml) are a crate of
their own, built only by `cargo +nightly fuzz` (libFuzzer with
AddressSanitizer). Each is one line that hands libFuzzer's input to the
function of the same name in `fuzz/harness` (`maki-fuzz-harness`, a member of
the workspace):

| Target | What it reads |
|---|---|
| `format_decoders`, `format_records` | Every on-disk decoder of `maki-format`, on raw bytes and behind a repaired CRC-32 |
| `journal_scan` | Journal segments, with a durable prefix or without |
| `config_parse`, `endpoint_url` | The configuration file and endpoint URLs |
| `probe_parsers` | The helper's mountinfo and sysfs-name parsers |
| `nbd_handshake` (Linux) | The helper's NBD handshake client, which runs as root, against a server that sends the input |
| `nbd_netlink` (Linux) | The helper's reading of the kernel's netlink answer to the family lookup, `NBD_CMD_CONNECT` and `NBD_CMD_DISCONNECT` |
| `backing_records` | `maki-backing`'s own records: the witness anchor, the remote enrollment binding, the remote witness state, the rollback manifest, a manifest slot as the check of an interrupted creation reads it, and remote namespace names |
| `witness_rpc` | The witness's RPC after TLS: a client reading the server's answer frame (`read_frame`, the response envelope, the record's validation), and a server reading a request frame and handing its operation to the file authority's own handler over a state store in memory, whose answer the client must read back as sent |
| `witness_etcd` | The witness's etcd store reading etcd's answers: the body's JSON and pinned cluster, the range answer's exact key, lease, base64 value, revision and state, and the transaction's verdict and comparison range |
| `http_response` | The HTTP provider's reading of a response: the body's bounded accumulation, single-item and batch JSON mappings (JSON pointers, payload encodings, unit echoes and batch item matching), a raw body, and the status and `maki-crypto-error` header |
| `websocket_response` | The WebSocket provider's connection reader on one message (type, JSON, id, probe envelope) and its reading of a response's error class and items |
| `grpc_response` | The gRPC provider's reading of a response's initial headers, of its body as tonic polls it (framing, trailers, the status tonic reads from them) and of its message (decoding and unit echoes) |
| `helper_reports` (Linux) | The helper's readers of the output of the commands it runs as root: LVM's `fullreport`, `blkid`'s label and filesystem probes, `dmsetup info`, `blockdev --getsize64` and `blkid -o value` |
| `helper_sysfs` (Linux) | The helper's readers of a `/sys/class/block` tree and a mount table that the input builds: detach's observation, device allocation, recovery's mapping proof and observations, LVM preflight's candidates and mapping check, the displaced-record check and the connection attributes |

`maki-privileged`, `maki-backing`, `maki-witness` and the three remote
providers expose what their targets need behind a `fuzzing` feature that
only the harness enables; it adds no dependency, and `maki-privileged` still
has none on a crypto crate. Each target calls the production reader itself;
where a reader was inline (the witness client's and server's frame
handling, etcd's answer, the WebSocket connection's message handling, the
gRPC initial headers, a provider's item checks, two command outputs of the
helper) it is now a function of its own that production calls too. A
target's function panics where the code broke a rule the target checks (an
export the kernel may not use, a handshake client that reads beyond the
handshake, a verdict the kernel does not send, an accepted record that is
not its own encoding, a selective JSON parser that disagrees with
serde_json, a client that does not read back what the server sent, a
status classified from anything but its code and allowlisted metadata, an
identity preflight verifies that recovery refuses, a recovery proof that
does not authorize the state it was captured from), and otherwise returns
whether the code accepted the input.

`helper_sysfs` builds each input's tree in a directory of the process's
own below the temporary directory (`maki-fuzz-sysfs-trees-<pid>-…`), on
which the process holds an exclusive `flock` while it runs, and removes the
tree when the reader is done with it: when the reader's frame unwinds (the
replay) and, under libFuzzer, whose panic hook aborts the process on a
failed assertion, in a panic hook of the target's own that runs first. A
normal exit (libFuzzer's at its time limit) removes the directory. A
process that ends otherwise (libFuzzer ends one at a timeout or the memory
limit with `_exit`; an abort; a kill) leaves its directory, with at most
the tree of the input it was reading, and the next process that builds a
tree removes every such directory whose lock nobody holds before it makes
its own (`fuzz/harness/tests/review_sysfs_trees.rs`). Directories named as
before this scheme (`maki-fuzz-sysfs-<pid>-<n>`) are left alone.

Each target's seeds are committed in `fuzz/seeds/<target>/`: the code's own
encodings, or where the bytes come from another program, that program's
output in the form it documents (nbdkit's handshake, the kernel's netlink
answers and sysfs, etcd's JSON gateway, a provider speaking each documented
mapping, LVM's JSON report, `blkid` and `dmsetup`), with copies cut short or
changed. The `witness_etcd` seeds include etcd's answer at the store's
256 KiB limit and one byte beyond it, and witness states at the 64 KiB a
state may have, one byte beyond it and three bytes beyond it, the last a
value whose base64 is longer than a state's can be. A seed's name says what
the target must do with it: accept a `valid-` seed, refuse a `refused-` one,
and only not crash on `noise-`. `fuzz/harness/tests/review_fuzz_corpus.rs`,
in the default suite, feeds every committed seed through its target's
function on the stable toolchain, requires an entry function, a `[[bin]]`
and seeds for every target, and checks that the committed seeds are what
the generator (`fuzz/harness/src/seeds.rs`) writes. The kernel answers
netlink in the host's byte order, and the committed `nbd_netlink` seeds are
a little-endian host's: a big-endian host replays the seeds its generator
makes in its own byte order instead, under the same names, and neither
compares nor writes the committed files. The `big-endian-seeds` job runs
this replay on every change, cross-built for `s390x-unknown-linux-gnu` and
run under `qemu-user`: user-mode emulation of s390x on the x86 runner, not
an s390x machine or kernel. After changing an encoding, write them again:

```bash
MAKI_FUZZ_WRITE_SEEDS=1 cargo test -p maki-fuzz-harness --test review_fuzz_corpus
```

The `fuzz` job runs where `nightly-gates` runs: it installs the pinned nightly
and `cargo-fuzz`, copies the workspace's `Cargo.lock` to `fuzz/Cargo.lock`
(which is not committed) so the fuzzed code is built with the versions the
workspace pins, and runs every target `cargo fuzz list` names for 30 seconds
from its seeds, with the target's `-max_len` (below); a list that cannot be
read or is empty fails the job. Its
token may only read the repository. `fuzz/Cargo.toml` patches the vendored
`serde_json`, `bytes`, `hyper`, `rustls` and `tungstenite` as the workspace
does, so the fuzzed JSON decoder, HTTP client, TLS and WebSocket code are
the ones production uses, and pins `libfuzzer-sys` and `arbitrary`
exactly, which that lockfile does not list. New inputs stay in `fuzz/corpus/<target>`, which is not
committed either; a crash fails the job and its input is uploaded as
`fuzz-artifacts`. The same, locally:

```bash
cp Cargo.lock fuzz/Cargo.lock
cargo +nightly fuzz run nbd_handshake fuzz/corpus/nbd_handshake fuzz/seeds/nbd_handshake -- \
  -max_len=70000 -max_total_time=600
```

A target's `-max_len` is what `python3 -B scripts/fuzz_campaign.py max-len
<target>` prints: libFuzzer's default of 4096 bytes, unless the target's
readers check a bound on a longer input. libFuzzer neither generates an
input longer than `-max_len` nor reads more than that of a longer seed, so
each length lies beyond the bound and is at least the target's longest
seed; `scripts/test_fuzz_qualification_validation.py` reads each bound from
the Rust source and checks every committed seed against its length:

| Target | `-max_len` | Bound beyond it |
|---|---:|---|
| `format_decoders`, `format_records` | 8,192 | A superblock: a 4096-byte frame after the selector byte |
| `config_parse` | 70,000 | A gRPC method path of at most 65,534 bytes |
| `nbd_handshake` | 70,000 | The client reads at most 64 KiB |
| `nbd_netlink` | 140,000 | Up to eight datagrams of up to 16 KiB each |
| `backing_records` | 70,000 | The remote witness state, at most 64 KiB |
| `witness_rpc` | 70,000 | A frame of at most 64 KiB |
| `witness_etcd` | 270,000 | etcd's answer, at most 256 KiB, with a witness state of at most 64 KiB |
| `helper_reports` | 70,000 | LVM's report (`MAX_REPORT`), and the output of the filesystem probe and of `dmsetup info`, at most 64 KiB each |

A length only lets a run get there: a run keeps a longer input only when it
reaches code no shorter one did. Seeds reach the format targets' bound (a
whole superblock) and cross those of `nbd_handshake`, `nbd_netlink` (a
datagram longer than the buffer), `witness_rpc` (a frame header beyond
64 KiB) and `witness_etcd`; no seed of `config_parse`, `backing_records` or
`helper_reports` is as long as its bound.

A crash's input reproduces it with `cargo +nightly fuzz run <target>
<input>`; once the cause is fixed, commit it under `fuzz/seeds/<target>/`
with a `valid-` or `refused-` name so the replay keeps it fixed.

### Fuzz qualification

SPEC §56 asks for 24 CPU-hours of fuzzing per parser target.
[`.github/workflows/fuzz-qualification.yml`](../.github/workflows/fuzz-qualification.yml)
runs such a campaign on GitHub's hosted runners when it is dispatched by
hand, with every target or a chosen list (`targets`), the CPU-hours per
target (`cpu_hours`, 24 by default), the longest fuzzing time of one job
(`shard_hours`, at most 5, as a job may run 6 hours) and the number of
fuzzing jobs at once (`max_parallel`, at most 20, the account's limit):

```bash
gh workflow run fuzz-qualification.yml --ref main \
  -f targets=all -f cpu_hours=24 -f shard_hours=5 -f max_parallel=16
```

[`scripts/fuzz_campaign.py`](../scripts/fuzz_campaign.py) plans and records
it, in five jobs:

1. `plan` splits each target's CPU-hours into equal shares for the
   processes of equal shards: 4 libFuzzer processes a shard, one per vCPU
   of a hosted runner, each to be charged its share of CPU time within
   `shard_hours` of wall time, which is at least half again the share. 24
   CPU-hours are 2 shards of 4 processes, each charged 10,800 CPU seconds
   (3 hours) within 18,000 seconds (5 hours).
2. `build` builds every target once as the `fuzz` job does (the pinned
   nightly, `cargo-fuzz` 0.13.2, AddressSanitizer, the workspace's lockfile)
   and keeps the planned targets' binaries with their SHA-256 digests and
   the toolchain's versions.
3. Each `fuzz` job checks the build's digests and runs one shard: 4
   processes of the target's binary on one corpus, from the target's seeds,
   with the target's `-max_len`, `-timeout=25`, `-rss_limit_mb=2048` and
   `-print_final_stats=1`, `ASAN_OPTIONS` as `cargo fuzz run` sets it and a
   temporary directory of the shard's own on `/dev/shm`. `helper_sysfs`
   builds a tree for every input: in a run on the host this guide was
   written on, it was charged 36 % of its wall time with its trees on the
   disk and 91 % on `/dev/shm`; a runner's disk was not measured. Each
   process fuzzes in rounds on
   the shard's corpus: the first with `-max_total_time` its share, each
   further one as long as the CPU time it still lacks and at least a
   minute, until the kernel has charged it its share (user and system time,
   from `wait4`) or no round fits the wall time left. A process charged less
   than its wall time (a target that waits for a thread of its own or for
   the filesystem) so takes longer, not less CPU time; a process whose
   rounds exit 0 before half of their time three times in a row is not
   started again. A process still running 10 minutes after its round's time
   is interrupted, and killed a minute later. When GitHub interrupts the
   step (its time limit, a cancelled run), the runner sends the step's own
   process SIGINT, SIGTERM 7.5 seconds later and kills it 2.5 seconds after
   that; bash, which runs the step's script, does not hand a signal on to a
   command it waits for, so the step `exec`s the script. The script then
   interrupts every process at once, kills one still running 2 seconds
   later, and writes its record, marked interrupted, before the SIGTERM; a
   kill alone leaves no record. The job records, for each process and each round, its
   exit, the CPU time the kernel charged it, its wall time, its seed, its
   executions and its last coverage line; every input libFuzzer wrote (a
   crash, a timeout, an input beyond the memory limit or a leak fails the
   shard, and a slow unit is only listed); and what the processes left in
   their temporary directory. A process that stopped on an input, was
   interrupted, ended its rounds early or was charged less than its share
   fails the shard. The shard's output (its corpus, logs, failing inputs
   and record) is uploaded as one archive, `shard.tar` in
   `fuzz-shard-<target>-<n>`, kept for 30 days: `actions/upload-artifact@v4`
   fails with `Maximum call stack size exceeded` on a directory of more
   than about 123,000 entries, and a 24 CPU-hour shard's corpus held up to
   405,750 inputs. The archive takes that name only once `tar` succeeded.
   The record (`fuzz-stats-*`) and the failing inputs (`fuzz-crashes-*`)
   are also kept on their own, for 90 days.
4. `merge` unpacks the archive of each shard the plan has, from the
   directory its artifact was downloaded to, merges the target's seeds and
   those corpora with `-merge=1` and runs the merged corpus once
   (`-runs=0`), whose `INITED` line gives the edges and features it
   covers. A planned shard whose archive did not arrive, does not unpack
   (it is cut short, or holds anything but files and directories below
   `shard/`) or holds no corpus fails the merge (`the merge had no corpus
   of shard N`), whatever the shard's record says: the merge records the
   shards it merged (`sources`) and why it had no corpus of the others
   (`unmerged`). libFuzzer's merge survives an input that
   fails its inner process: it writes the input to the merge's artifacts as
   a crash, timeout or out-of-memory input, runs the inner process
   again (`MERGE-OUTER: attempt 2` in its log), which leaves the input out,
   and exits 0. The job records every input the merge wrote and the
   attempts its log shows: such an input, a second attempt or a log that
   shows none fails the merge, and a slow unit is only listed. The merged
   corpus, those inputs and the logs are uploaded as one archive too,
   `merged.tar` in `fuzz-corpus-<target>` (`tar -xf merged.tar` gives
   `merged/corpus/`), kept for 90 days, also after a shard failed.
   Interrupted like a shard's, the step stops unpacking and libFuzzer's
   processes (the merge runs one of its own) and writes `coverage.json`,
   marked interrupted.
5. `summary` writes a table to the run's summary and to
   `fuzz-qualification-summary` (`summary.md`, `summary.json`), kept for 90
   days: per target, the CPU-hours charged to its processes, their
   process-hours, executions, the merged corpus's edges, features and size,
   the inputs a process or the merge stopped on, and the verdict; with the
   revision, the run, the toolchain and the runners. It fails unless every
   target qualified.

A target qualifies when every planned shard reported, every round of
every process exited 0 and was neither stopped at its deadline nor
interrupted, no process ended three rounds in a row before half of their
time while it still lacked CPU time (a round may end early: the next one
runs for the CPU time still missing), every process was charged its share,
no process wrote a crash, timeout, out-of-memory or leak input,
the CPU time charged to its processes reaches the requested CPU-hours, the
merge had a corpus of every planned shard (the summary reads the merge's
`sources` against the plan) and exited 0 after one attempt without writing
such an input, its coverage run exited 0 and printed its `INITED` line, and
the shards and the merge ran the build's binary. A CPU-hour is an hour of
CPU time the kernel charged to the target's fuzzing processes; their wall
time is reported beside it. A hosted runner is a virtual machine on
GitHub's hardware, and its vCPUs may be hardware threads that share cores.

A campaign of all 16 targets at 24 CPU-hours is 32 shards. A process that
is charged nearly all of its wall time is done after about 3 hours, one
charged three quarters of it after 4; with the job's setup and uploads, a
shard takes about 3¼ to 4¼ hours. At 16 or 20 jobs at once the shards run
in two rounds, about 6½ to 8½ hours, and the build before them and the
merges and the summary after them add about 45 minutes. A dispatch with
`cpu_hours=0.1` checks the whole workflow in under an hour. No campaign has
been run yet: [Current qualification status](#current-qualification-status)
lists what has.

## Test model

### Opt-in discard validation

The v3 discard feature uses new volumes created with `--discard`; v2 behavior
remains unchanged. The focused suites are:

```bash
cargo test --locked -p maki-format --test review_discard_format
cargo test --locked -p maki-core --test review_discard_storage --test review_discard_engine --test review_discard_physical --test review_discard_crash
cargo test --locked -p maki-nbdkit --test review_discard -- --nocapture
cargo test --locked -p maki --test review_discard_create
```

The physical test measures allocated filesystem blocks for 126 adjacent
discarded slots between two retained neighbors, then checks reopening and
rewriting. It reports a skip if the filesystem does not support hole punching.
The crash matrix covers both discard-bit transitions, all four map data-sync
and three directory-sync boundaries, same-process retry, recovery with readable
failed-sync bytes, subsequent simulated power loss, and A/B fallback. It also
checks partial punch failure, unsupported punching, repeated FUA discard, and
ordered replay across multiple bounded batches.

On Linux, the native test uses actual nbdkit and Python `ctypes` with
`libnbd.so.0` to negotiate and issue FUA TRIM, check zero readback, and rewrite
the range. It does not require `nbdsh`, a kernel NBD attachment, or a mount.
See [space reclamation](space-reclamation.md) for supported semantics and limits.

### Encrypted transport validation

`maki-crypto-websocket/tests/wss_tls.rs` and
`maki-crypto-grpc/src/tls_tests.rs` run local TLS/mTLS peers, verify trust and
hostname rejection, and preserve the transport request contracts. The WSS suite
also uses a TLS-1.2-only peer and checks the exact upgrade URI. Each transport
crate's `tests/review_default_trust.rs` checks the shared default trust against
servers of three test CAs: one in the host's trust store, one in `ca_file` and
one in neither, then with the host's store emptied. It points `SSL_CERT_FILE`
and `SSL_CERT_DIR` at a test bundle, which is process-global, so each is a test
binary of its own with a single test. Unit tests in the same crates check that
the roots each transport builds hold every compiled-in public root.
`maki-nbdkit/tests/review_wss_tls_daemon.rs` and
`review_grpc_tls_daemon.rs` connect the configured provider through real daemon
construction, attach self-test/canary, adapter write/read and shutdown. The gRPC
daemon fixture additionally rejects wrong CA, hostname and missing mTLS identity.

These fixtures validate local integration. Subsequent campaigns covered all
three transports [across hosts under the shipped sandbox](qualification/cross-host-sandbox-validation-2026-10-05.md),
[provider-host hard resets](qualification/provider-host-reset-validation-2026-10-05.md)
and [PostgreSQL 15 over gRPC](qualification/remote-database-zero-mdwe-validation-2026-10-04.md).
Commercial services, the selected production network and long-running database
workloads still need separate qualification.

The HTTP response-tree regressions also check erasure of completed strings and
keys after malformed JSON, duplicate replacement, successful parsing and batch
errors. Their owned-buffer scope and the remaining serde/transport-private
copies are documented in [transport memory](transport-memory.md#http-decoded-payloads).

The combined 2026-09-20 implementation passed `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets --locked -- -D warnings`, and
`cargo test --workspace --locked`: 1,051 passing test invocations, zero failures
and ten ignored tests. This run used an immutable source snapshot and a private
`CARGO_TARGET_DIR`; evidence is in
`~/logs/maki-tls-final-20260920T090302Z/` (`exit.status` 0, `test.log`).
The ignored long-running and external-service gates were not part of this run.

`maki-test-support` provides the reusable verification environment:

| Component | Purpose |
|---|---|
| `ReferenceBlockModel` | Oracle for acknowledged, durable, and crash-possible data |
| `CrashableBacking` | Samples unsynchronized operations, retains namespace dependencies, and can model tearing. Failure semantics follow Linux writeback: a failed `sync_data` marks its dirty operations clean with *unknown* persistence (the page cache keeps showing them, a retried sync writes nothing, a later power loss may keep any of them, whole or torn, and the worst-case crash loses them), a successful sync writes back every page a dirty write touched as a whole 4 KiB cached page, and the partial-write hook makes a `write_at` persist a prefix before failing. A power loss kills every process: file and lock handles opened before it are dead, and so is every process view started before it (`CrashableBacking::process()`), whose `Backing` operations (open, create, remove, rename, list, `sync_dir`, `try_lock`, ...) then fail with an I/O error and change nothing. Tests start the code under test on a view, one per process (`Volume::recover(backing.process(), ...)`, `Engine::attach(backing.process(), ...)`, an adapter built on one), so a volume, engine or checkpoint worker still alive at a crash cannot create or sync files afterwards; the backing the test created is never killed and is what the test itself inspects and damages. Its namespace refuses what Linux `FileBacking` refuses (a missing or non-directory parent; a directory name opened, locked, renamed over or removed as a file), checked by the table `MemBacking` and `FileBacking` also run (`maki-backing/tests/common/namespace_parity.rs`) |
| `FakeCryptoProvider` | Deterministic crypto, latency, errors, and malformed provider responses. Refuses a batch over its declared `max_items` or `max_bytes` (plaintext bytes; one unit per decrypt item) with `NonRetryableRequest`, as a vendor endpoint would. With integrity off it behaves like an unauthenticated cipher: any ciphertext of the right length decrypts (to garbage when damaged) and only a wrong length is refused |
| `ManualClock` | Deterministic retry, timeout, cache TTL, and breaker timing. Sleepers due in one `advance` are woken by deadline, then in creation order |
| `DeterministicScheduler` | Reproducible seeded interleavings. A task is polled again only after its waker fires, so a lost wakeup stalls (`run` panics, `run_bounded` returns `false`) as it would hang under tokio |
| Failpoints | Named failures at journal, shard, and checkpoint persistence boundaries |

Golden vectors freeze the on-disk format. Self-checksummed images are hashed
without their trailing CRC because the CRC of a correctly self-checksummed image
has a constant residue.

## Coverage by subsystem

| Subsystem | Evidence |
|---|---|
| Format and parsing | Overflow checks, malformed input, A/B fallback, CRC, torn-tail and middle-corruption classification |
| Provider contract | Round trips, size/order/index validation, tamper checks, compatibility, and cross-endpoint decrypt |
| Journal and recovery | Persistence-boundary failpoints, sequence continuity, checkpoint ordering, ENOSPC, and double attach |
| Storage scheduling | `review_blocking_io.rs`: deliberately stalled reads, writes, FLUSH, checkpoint writes, recovery opens and free-space queries leave a single Tokio worker responsive; cancelling a dispatched write preserves admission and subsequent write order |
| Checkpoint concurrency | `review_checkpoint_concurrency.rs`: stalled slot writes permit overlay/slot reads, overwrites and new shards; the captured horizon remains fixed, failures retry without losing concurrent writes, and caller cancellation preserves checkpoint serialization |
| Block engine | RMW, concurrent access, FUA, FLUSH, provider batching, and differential model tests |
| Availability | Request and byte bounds, retry budget, jitter, breaker transitions, failover, and permit-leak checks |
| Transports | HTTP mapping/TLS/chaos, WebSocket reconnect/order/size, and gRPC status/metadata/size |
| Cache and growth | Version matching, stale-read prevention, eviction, zeroization, shard creation, and crash recovery |
| NBD adapter | Geometry, capability advertisement, read/write, panic boundary, parallel callbacks, and clean detach |
| Review regressions | `review_storage.rs`, `review_attach.rs`, `review_bounded.rs`, `review_check.rs` (maki-core), `review_deep.rs` (maki-check binary), `review_format.rs` and `review_config.rs` (maki-format), `review_daemon.rs`, `review_control.rs`, `review_sample.rs` and `review_security.rs` (maki-nbdkit), `review_uds.rs` (maki-control), `review_dispatch.rs` and `review_scheduler.rs` (maki-crypto), `review_ws.rs` (maki-crypto-websocket), `review_priv.rs` (maki-privileged), `review_attach.rs` (maki-attach binary): roll-vs-promotion ordering, allocation dirty-flag ordering, fail-closed recovery, durable mark, A/B error classification, key canary and identity checks, bounded journal and degraded state, control-socket lifecycle and ownership (Unix-only suites run under Linux CI and WSL), configuration validation matrix, plaintext-transport policy, TLS fail-closed, the production sample building its provider, retry-safety and absolute deadlines in the dispatcher, endpoint quarantine, and WebSocket unit echo; see the [remediation log](review-remediation.md) |
| Sanitizers and randomized suites | Debug-build `check_invariants` on `Overlay`, `JournalWriter`, and `Volume` after every mutation; `review_fuzz.rs` (maki-format: single-bit-flip and random-mutation fuzz of every decoder, the journal scanner, URL parsing, and `validate()` on a mutated production sample), `review_stress.rs` and `review_corruption.rs` (maki-core: concurrent engine stress with a per-unit oracle, provider chaos, background checkpoints and a crash; engine-level sweep of all persistence failpoints; random single-file corruption with deep check and re-attach), `review_stress_crypto.rs` (maki-crypto: scheduler and dispatcher under random faults), `review_cache_model.rs` (maki-cache: model-based LRU check); findings S-01 to S-05 in the [remediation log](review-remediation.md#sanitizers-and-randomized-suites-2026-09-03) |
| Second audit regressions | `review_audit.rs` (maki-core: process-restart durability, covered-segment reclaim, adoption ordering, scanner bounds, covered-prefix resurrection, decrypt length), `review_audit2.rs`, `review_secret.rs` (maki-crypto: breaker probes, deadline accounting, background validation, lane concurrency, self-test strictness, pending items, page unlocking), `review_redirect.rs` (maki-crypto-http), `review_hang.rs` (maki-crypto-websocket), and the O-series additions to `review_priv.rs`, `review_uds.rs`, `review_control.rs`, `review_sample.rs`, `review_config.rs`, `review_format.rs`; findings K/C/O in the [remediation log](review-remediation.md#second-audit-2026-09-03-core-crypto-layer-operational-layers) |
| Third review regressions | `review_writeback.rs` and `review_limits.rs` (maki-core: sync-retry rewrite, recovery rewrite of page-cache bytes with power lost right after recovery syncs its durable mark, torn-tail normalization, request-size cap and per-unit admission cost), `review_abi.rs` (maki-nbdkit: the nbdkit struct layout and constants, `block_size` callback included, checked against the installed header by a compiled C probe, Linux), F05 additions to `review_security.rs` (swap classification by device identity, unreadable `/proc/swaps` refused), `review_secret.rs` page-lifetime test (maki-crypto, Linux, reads `/proc/self/smaps`), `review_limits.rs` (maki-control: idle and write timeouts, busy refusal, session backlog), F02 additions to `review_priv.rs` (mount topology through device-mapper `slaves`), the symlink test in `maki-backing`; findings F01 to F10 in the [remediation log](review-remediation.md#third-review-2026-09-05-os-partial-failure-device-identity-memory-ownership) |
| Fourth pass (specification) | `review_state.rs` (maki-core: degraded state on journal sync failure, admission and barrier-latency counters), `review_metrics.rs` (maki-nbdkit: every SPEC §40 metric present with and without a dispatcher), `dispatcher_reports_latency_budget_and_inflight` (maki-crypto), `preferred_io_defaults_to_the_crypto_unit` and the absolute-root cases (maki-format), `created_directories_and_files_are_owner_only` (maki-backing, Unix), `review_keysource.rs` (maki-crypto-local, Unix), `control_commands_time_out_against_a_silent_daemon` (maki binary, Unix); findings N-01 to N-08 in the [remediation log](review-remediation.md#fourth-pass-2026-09-05-specification-contradictions-and-boundaries) |
| Fifth pass | socket-path cases (maki-format); findings N-09 to N-13 in the [remediation log](review-remediation.md#fifth-pass-2026-09-05-ab-retry-breaker-probes-packaging). N-09's A/B retry durability is covered by the preserve-first `review_ab_retry.rs` (maki-format, maki-core) after the merge; N-10 and N-11 by `review_probe_lifetime.rs` and `regression_control_packaging.rs` below |
| Additional review (BUG-015…BUG-024) | `review_next_storage.rs` (maki-core: journal reclaim never outruns checkpoint-state durability, BUG-022), `review_next_grow_*` in `exec_tests.rs` (maki-privileged: grow needs the trusted record and lock, BUG-018), `review_next_transport.rs` (maki-crypto-grpc: a stalled response is bounded by the transport timeout, BUG-017), `review_next_control.rs` (maki-nbdkit: shutdown drains live sessions and frees the volume lock, BUG-015), `pointer_tests` in `maki-crypto-http` (RFC 6901 request-pointer escaping, BUG-024); BUG-016/019/023 were already closed by the merged F05/F02/backing-symlink work. See the [remediation log](review-remediation.md#additional-review-2026-09-05-eight-further-findings-bug-015--bug-024) |

## September 2026 review regressions

These suites cover the repaired storage, resource-lifetime, and configuration
boundaries. They are part of the default workspace suite; Linux-specific checks
exercise kernel page-lock state, and the runtime permission check models the
packaged configuration without installing services or creating users.

| Boundary | Regression coverage |
|---|---|
| A/B retry durability (BUG-001) | `review_ab_retry.rs` in `maki-format` and `maki-core`: failed data/directory sync, repeated retries and restart, sector tearing, writeback that loses dirty bits, preservation across metadata types, and recovery of durable volume data |
| A/B torn side reuse | `maki-format/tests/review_ab_torn_reuse.rs`: a store cut by a power loss and a later cut store of the same generation never add up to a valid copy of the earlier record; an undecodable side is emptied and synced before it is written, the emptying is repeated after a failed sync, a decodable or absent side is not emptied, and seeded chains of cut stores over three record types and five tearing units never lose, regress or revive a record; chains of cut stores that revive a record without that rule cover a five-sector map, a map of one page and one of 9000 bytes, checkpoint state, and the durable proof through `DurableProofStore::advance` |
| Required attach configuration (BUG-002) | `maki-privileged/tests/regression_missing_attach_config.rs`: required assertion in the unit and actual offline systemd assertion evaluation for missing/present temporary configuration |
| Trusted helper state (BUG-003) | `maki-privileged/src/state_tests.rs`, `exec_tests.rs`, and `tests/regression_attach_state.rs`: protected state ancestors/files, configuration and live backend identity, stale records, fail-before-side-effects ordering, rollback, and cleanup failure; device operations are simulated |
| Stale and displaced attach records | `maki-privileged/src/review_stale_attach_record.rs` and `review_displaced_attach_record.rs`: the production executor, allocation, observers and trusted state for several volumes over one simulated kernel. A record that outlived its connection keeps its device from other volumes' attaches. `review_busy_allocated_device.rs`: an attach whose allocated device stays busy moves to the next free one, record first, never onto a device another record names, never from a pinned device, never past the step's time, and never when the device shows a connection. A record whose device carries another connection (another volume, or an NBD client outside the helper) is retired by attach, cleanup, recover and detach without a command only when it names its VG UUID and the host shows no mapping of that VG, no holder of the device or its partitions other than an LVM mapping of another VG, no mount at the mountpoint or of such a mapping, and no other record on the device with the same or no VG UUID; each of these, an unreadable observation, a changed backend and a mismatched cleanup configuration keeps the record, and grow always refuses. No real LVM, device-mapper or NBD is involved |
| LVM scope of detach and grow | `maki-privileged/src/review_lvm_device_scope.rs`: an LVM model in the same simulated kernel resolves VG names over the volumes' NBD exports and another disk whose inactive VG carries pg's name, on hosts whose LVM scan includes or leaves out the NBD devices. Grow, detach, cleanup (also after the daemon died, through its fallback) and recovery act only on the recorded VG; the commands built from a proof, an intent, pins or an old record carry its devices, and its VG UUID in the deactivation where the record names one (`lvextend` takes no selection). The command forms were also run against LVM 2.03.16 on loop devices without device-mapper; no activation, NBD or real attachment is involved |
| Golden vectors for every record | `maki-format/tests/review_golden_vectors.rs`: the allocation map, shard catalog, checkpoint state, durable proof, segment and journal record headers and the v2 and v3 superblock envelopes, each also assembled byte by byte from its documented layout and read back, and an inventory that fails for a record magic without a vector or a vector without a record; maki-backing's inline vectors for a populated manifest, a witness state with a descriptor and the local marker with a manifest slot |
| Documented configurations | `maki-format/tests/review_docs_config_examples.rs`: every complete volume configuration in README.md, SPEC.md, docs/ (without the dated reports), examples/ and packaging/ passes `parse_config` and `validate` as written, every fragment loads merged into the quick-start example, blocks of another schema are listed, and the configuration guide names exactly the byte keys that take only plain integers |
| Documents against their sources | `scripts/test_docs_accuracy_validation.py`: the refusals the rollback guide quotes for an interrupted creation are the strings maki-backing returns, and the guide tells the refusal of a claimed remote authority from the backing check that follows it; the `MAKI_LOG` fallback warning is described as both sinks print it, with a reason and never the value; the tier table above says where formatting runs; SPEC §11 lists every `packaging/` directory and the README names both package builders; no page says there is no tagged release; and in the guides sudo, which neither package depends on, never selects a user, wherever the option stands among its own, while each command that runs `runuser` (util-linux, which both require) in a code block or a code span has the form `runuser -u maki -- …`; `su`, which util-linux ships as well, is not checked. The prose pins look for an exact phrase: they keep a correction from being put back, and a page that says the same thing wrongly in other words passes. `scripts/test_docs_provisioning_validation.py` runs the quick start's creation block as written, with nothing on `PATH` but stand-ins for `install`, `maki` and `runuser`, and requires the provisioning guide to create its VG with autoactivation off |
| Remote GC progress | `maki-backing/tests/review_remote_gc_unreadable.rs`: GC goes on past a stale namespace it cannot open or examine (`skipped_unreadable`) and past a retirement stopped at a step that changes one namespace alone (`unfinished`), while a root it cannot read, a rename the root refuses and a failed authority still end the pass; the automatic pass logs both; a root takeover killed between `mkdirat` and `fchown`, and the immutable and append-only cases, need root |
| Interrupted creation | `maki-backing/tests/review_interrupted_enrollment.rs` and `review_interrupted_local_create.rs`: a real remote or local creation and a real witness initialization in a child process, killed by a seccomp filter or failed with ENOSPC, then the command that must continue it, with controls that a published or committed state is never created over. The crash models `maki-backing/src/rollback/remote_creation_tests.rs`, `src/rollback/local_creation_tests.rs` and `src/remote_witness_init_tests.rs` end each creation before every backing operation as a process death, a power loss with torn writes and a failed operation, and require one documented command to continue it; the remote model also interrupts chains of creations and enrollment recoveries and starts from a binding left without its marker, and `maki-backing/tests/review_binding_without_marker.rs` requires `volume create` to continue such a root on a real directory, never to read a staged binding, and to refuse another creation's binding, an unreadable one, a staged entry it cannot write again and a claimed or activated authority with the root unchanged; `maki-witness/tests/review_interrupted_init.rs` runs the binary |
| Rollback refusals that name their cause | `maki-backing/tests/review_remote_gc_foreign_root.rs`: GC refuses a remote root that does not hold the authority's current generation (the namespace missing, or holding an older generation) in the words attach uses, and changes neither the root nor the authority; `review_rollback_configured_dirs.rs`: a local backing root or witness directory that is missing, a regular file, a symbolic link, reached through one or below a file, or (for a user other than root) not openable is refused with its path, its setting and what is wrong, with the kind opening the pair gave before, and never created by opening, while `volume create` still creates a missing witness directory; `maki`'s `review_existing_repository.rs` and `maki-benchmark`'s `review_rollback_reuse.rs`: the backing-root checks of `check`, `inspect` and the benchmark word the same states; `review_unmarked_local_root.rs` and maki-format's `review_interrupted_volume_create.rs`: a root without its format marker is told that `volume create` continues it only when `create` does, otherwise which entries stop it (a reserved name that is not a regular file with one name among them, refused before anything is published), and nothing where its entries cannot all be listed; a staged marker the user may not open is replaced in one run, and an arena the user may not open is refused with the way out (for a user other than root); `review_root_staged_marker.rs` (root, re-executed as uid 65534): the root-owned staged marker and arena a root-run creation killed at its `fchown` leaves, as the daemon user's `volume create` meets them |
| HalfOpen probe lifetime (BUG-004) | `maki-crypto/tests/review_probe_lifetime.rs`: request/provider errors, operation deadline, future cancellation, and exhausted retry budget all leave a slot for a healthy recovery request |
| HTTP connect across addresses | `maki-crypto-http/src/connect_tests.rs` (Linux, paused time; the endpoint's name resolved through reqwest's override, and an address that never answers is a loopback listener whose full accept queue drops the SYNs sent to it): a dead address before a live one of its family keeps the request only for its share, half the `timeout` for two, and the live one serves it; a dead address before a refused one fails the request at that share as a connect timeout, retryable and unsent; two dead addresses hold it until its `timeout` and no longer, and it fails as a request timeout; a host with one address keeps the whole `timeout`, and a resolution that never returns and a TLS peer that never answers the handshake end at it, each as a request timeout that is not marked unsent; with the IPv6 loopback address, a dead IPv6 address before a live IPv4 one has IPv4 dialed after 300 ms with a 400 ms `timeout`, not halfway, and never with a 300 ms one. As root, `a_route_that_drops_packets_leaves_the_next_address_its_share` gives its thread a private network namespace whose packet filter (`nft`, or `iptables` where `nft` is missing or fails; it fails when neither installs the rule) drops every SYN sent to 127.0.0.2, a route that drops packets, and the address after it serves once its share has run out |
| gRPC connect across addresses | `maki-crypto-grpc/src/connect_tests.rs` (Linux, paused time; the connector resolves the endpoint's name through the crate's test resolver, `TestResolver`, and an address that never answers is a full accept queue, as for HTTP): a dead address before a live one of its family costs half the `timeout` and the live one serves the call; with the IPv6 loopback address, a dead IPv6 address gives way to IPv4 after 300 ms, and with a 200 ms `timeout` IPv4 is dialed at 100 ms and serves the call. `lib.rs` (`other_family_delay_tests`, every platform): the connector's delay is 300 ms, or half a `timeout` under 600 ms |
| HTTP short-timeout warning | `maki-nbdkit/tests/review_http_timeout_warning.rs`: the check report (`report_configuration_mismatches`) warns about an HTTP `timeout` of 150, 300 or 599 ms with one line that names it, not about 600 ms, 1 s or the default, nor about a WebSocket or gRPC `timeout` of 300 ms, and attach logs the warning for 300 ms and not for 600 ms; `maki/tests/review_http_timeout_warning.rs`: `maki volume create` (stderr) and `maki check` with and without `--deep` (stdout) print the `warning:` line for 300 and 450 ms and not for 600 ms or the default, and creation and both checks succeed |
| Configuration compared before an endpoint | `maki-nbdkit/tests/review_config_identity_attach.rs`: attach and `build_provider_with_endpoints` refuse a configuration whose provider type, key identity or compatibility id (with the random prefix's) the volume does not store, naming the setting and both values, before a credential is loaded, before a request reaches an HTTP endpoint and before a connection is opened to a WebSocket or gRPC endpoint; the tests of a changed compatibility id then attach through the endpoint they count, with the configuration the volume was created with |
| WebSocket connect across addresses | `maki-crypto-websocket/src/connect_address_tests.rs` (paused time, a substituted resolver and dialer): an address that never answers spends only its share of its family's time and the next one connects, a refused address leaves its share to those after it, a dead IPv6 address gives way to IPv4 after 300 ms and a refused IPv6 family at once, with less than 600 ms left (a short `timeout`, or what a request has left after waiting for the connection mutex) the other family starts halfway to the deadline, the attempt that loses is dropped, dead addresses of both families are dialed on each family's schedule and fail as a retryable, unsent connect timeout at the deadline, a connect made after the request waited for the connection mutex shares what the request has left, a TLS or upgrade failure at the first address is not retried at the next and keeps its class, a resolution that never returns ends there too, TLS names and verifies the URL's host, so a certificate for the resolved address alone is refused, and the system resolver reaches a listener by `localhost` |
| WebSocket connection lifetime (BUG-005) | `maki-crypto-websocket/tests/review_connection_lifetime.rs`: server-observed socket closure after timeout, outer cancellation, and idle provider drop; a healthy successor remains reusable |
| Secret-buffer page ownership (BUG-006) | `maki-crypto/tests/review_secret_page_lifetime.rs`: shared-page drop, `into_vec`, and duplicate lifetimes; last-owner unlock, lock failures, and full-capacity zeroization before deallocation, with process-wide settings isolated in child processes |
| Credential source identity (BUG-007) | `maki-nbdkit/tests/review_credential_sources.rs`: conflicting sources for one name rejected before loading credentials; repeated same-source references and distinct names remain valid |
| HTTP error redaction (BUG-008) | `maki-crypto-http/tests/review_redirect.rs`: connection failure, timeout, and truncated response errors omit request URLs and synthetic query secrets from both Display and Debug |
| Administrative socket access (BUG-009) | `maki-nbdkit/tests/regression_control_packaging.rs`: default/example/custom paths, admin traversal, daemon access, and isolation from NBD and helper state under the packaged directory modes |
| Interrupted detach (BUG-010) | `maki-privileged/src/detach_tests.rs`, `exec_tests.rs`, and `probe.rs`: retry after each completed step, safe record-only cleanup, wrong mount/backend refusal, escaped VG names, partition holders, and direct mounts; all device operations use fixtures |
| NBD request limits (BUG-011, supersedes O-03) | `maki-nbdkit/tests/review_nbd_limits.rs`: oversized reads leave caller buffers untouched, oversized writes leave volume data unchanged, minimum alignment applies to offsets and lengths, valid maximum writes survive reopen, invalid wire sizes fail configuration validation, and real nbdkit/libnbd negotiation reports the configured tuple |
| Fast zero requests | `maki-nbdkit/tests/review_fast_zero.rs`: a WRITE_ZEROES request with `NBD_CMD_FLAG_FAST_ZERO` sent to the plugin in a real nbdkit, on a default and on a discard volume, alone and with NO_HOLE or FUA, for whole units and for the whole export, is answered with `NBD_ENOTSUP`, leaves the export unchanged and the server running, and the same request without the flag is served; the export's transmission flags are pinned exactly, fast zero included (nbdkit asserts that a fast zero request was advertised, so an export without the flag lets one request abort the server). `plugin.rs` pins the plugin's two answers, and `review_helper_nbd_handshake.rs` and the native libnbd case of `review_r5_write_zeroes.rs` require the flag, the latter also a refused `nbd_zero` with `LIBNBD_CMD_FLAG_FAST_ZERO`. The nbdkit tests skip without nbdkit unless `MAKI_TEST_REQUIRE_NBDKIT=1` |
| Scheduler cancellation (BUG-012) | `maki-crypto/tests/review_scheduler_cancellation.rs`: queued payload and admission release, cancellation behind a live blocked group, active-RPC cancellation, cancellation of one group in a coalesced batch, and continued service for live callers; `review_r5_scheduler_resend.rs`: no per-request re-send to a provider that is not retry-safe, and an abandoned re-send releases its lane slot (R5-004); `review_scheduler_local_refusal.rs`: with such a provider, a request with a unit the endpoint set or random-prefix wrapper refuses before sending (empty or oversized ciphertext, unsupported plaintext size) fails alone at admission, while a rejection after sending still reaches the whole batch; `maki-core/tests/review_coalesced_empty_slot.rs`: a read of a slot recording an empty ciphertext does not fail a healthy read coalesced with it |
| Queue deadlines (BUG-013) | `maki-crypto/tests/review_queued_deadline.rs`: ManualClock deadlines cover admission, coalescing, slot wait, and RPC under one caller budget; a live peer retains its own budget and stall mode remains unbounded |
| Deadline exits | `maki-crypto/tests/review_deadline_exits.rs`: with ManualClock, an operation with no time left, the top of a pass, right after a failed RPC, admission with no time left, a cut-off RPC, scheduler callers on their own timer (both lanes, with and without the random prefix, coalesced, or re-sent alone after a request-specific rejection) and a dispatcher deadline reaching a scheduler caller all return the last endpoint error of the RPC batch in progress with its class (else the deadline error) and count once; a call split into several RPC batches, directly or through the scheduler, reports only the current one; a failure the dispatcher receives, or a batch it starts, at or after a scheduler caller's deadline but before the caller's task runs does not change the caller's answer; a nested set's expiry counts only in that set and never as a scheduler caller's deadline. `maki-nbdkit/tests/review_deadline_metrics.rs` checks the exported counter for an endpoint error at the deadline |
| Endpoint revalidation and transport errors | `maki-crypto/tests/review_endpoint_revalidation.rs` (ManualClock): only proof of another contract excludes a quarantined endpoint, while a malformed reply, a generic refusal from either peer, the set's admission refusal and the candidate's own provider failure defer it with backoff, and attach keeps its verdicts. `maki-crypto-websocket/tests/review_probe_envelope.rs`: an inexact probe error envelope fails only its request and retires the connection. `maki-crypto-grpc/tests/review_http2_errors.rs`: HTTP/2 resets and GOAWAY under a call, from a raw HTTP/2 peer, and failover of a refused call only when the provider is retry-safe |
| Concurrent socket permissions (BUG-014) | `maki-control/tests/review_uds_umask.rs`: bind concurrently with private directory creation and verify mode 0700 is preserved; `review_uds.rs` also checks prepared socket mode/group, preservation on failed group lookup, cleanup on failed publication, and actual Linux connection at the maximum public path length |
| Partial journal writes (BUG-020) | `maki-core/tests/review_journal_retry.rs`: a BackingFile that writes a prefix then returns EIO, shorter retries, roll/FLUSH without retry, cleanup failure, and recovery after sealing the segment |
| Journal writeback errors (BUG-021) | `maki-core/tests/review_journal_writeback.rs`: clean-but-unpersisted cache after EIO (failed inside `CrashableBacking`, so no later sync of other bytes persists it), retry, and full-replay process recovery followed by power loss, changes after the scan (refused before any proof covers them), valid-header mutation despite unchanged CRC residue, and pending ranges larger than the 64 KiB rewrite buffer; `review_recovery_prefix_rewrite.rs`: power loss after every backing operation of a recovery that adopted such bytes after a restart, including the window in which the synced mark and proof already cover records that only the journal segment holds |
| gRPC authentication evidence (TEST-002) | `maki-nbdkit/tests/phase9_daemon.rs`: attach without metadata must fail after the server actually rejects it with Unauthenticated; valid metadata roundtrips with no authentication rejection, independently of which deadline's error text wins |
| Convergent privileged cleanup (R3-007) | `maki-privileged/src/exec_tests.rs`, `recover.rs`, and `maki-attach/tests/e2e.rs`: no record succeeds without probing, an owned connected backend selects detach, an absent backend selects recovery, each logging the path it takes, and a foreign or unreadable backend preserves the record. The proof-scoped fallback runs only after an exited `vgchange` returns nonzero, accepts one exact closed target mapping, rechecks the backend, and rejects changed identity, multi-mapping topology, open count, or force/deferred/retry removal. A record that names its VG UUID is retired instead, beside a foreign backend, when nothing of its attachment remains (see the stale and displaced records row). On a manual clock, detach and cleanup wait after their disconnect for a backend that lingers (1, 7 or 150 looks every 100 ms) and retire the record in the same run without a second disconnect; one that outlives the 15 s keeps the record with the refusal "disconnect has not completed", and a later run finishes once the opener has let go; another backend identifier ends the wait and keeps the record, which a later cleanup retires only by the displaced-record rules, an unreadable one fails, and the wait ends by an earlier `finish_by` deadline. Except the deadline case, these run with the attach lock taken as the helper's own run takes it. `review_release_wait_lock.rs` (AUD-197): every sleep of the wait finds the attach lock free, and a device that lets go at the first look keeps the teardown's one turn on it (every look is made with the lock held); two volumes whose devices an opener lets go only once both are disconnected, torn down on two threads, both retire their records in one run (with the wait under the lock the first one waited out its 15 s while the other queued, and failed); a record that an attach of the same volume replaced during the wait is kept and the command fails, also when that attach connected the same device and its new identifier ended the wait (reported as replaced, not as "disconnect has not completed"), and one that another cleanup retired ends it as a success, also when the device then shows another client's connection; `recover_tests.rs` pins that the failed-start hook's rollback keeps the lock through its wait. The provisioning disconnect's wait runs on a manual clock too |
| Privileged step faults | `maki-privileged/src/review_step_faults.rs`: the production executor, observers and trusted state over a simulated kernel (fake sysfs tree and mount table; LVM needs the device served, `dmsetup` does not). Every command of attach, detach, cleanup and the failed-start hook's rollback exits nonzero, is killed by a signal, times out or loses its helper, before and after its effect, and every observation fails or loses its helper; the packaged order (hook, daemon stop, cleanup, new attach) must converge, with the interrupted activation nothing serves as the one documented refusal. The same sweeps run beside an opener of the device, which sysfs does not show (a connect refused as busy; `pid` and `backend` kept after an acknowledged disconnect until it closes), arriving or leaving before any command, with the daemon dying before any command, and with a second free device that an attach moves to: no record is retired while its device shows the connection, no other connection is disconnected, and every case ends once the opener lets go. Detach and cleanup wait for the opener on a manual clock: one that lets go during the wait (after 1, 12 or 150 looks) ends with the record retired in the same run, also through the proof-scoped removal after the daemon stopped, and one that stays keeps the record after 150 looks. The failed-start hook's rollback of an interrupted activation waits the same way (an opener that lets go after 1, 30 or 150 looks leaves nothing and no record; one that stays keeps the record for the coordinator's cleanup, which ends it once the opener has let go), and its deadline for its commands ends the wait. Attach, detach and cleanup take the attach lock as the helper's own run does, so detach's and cleanup's waits let go of it. No real LVM, device-mapper, NBD or systemd is involved |
| Command-line output and exit status | `review_closed_output.rs` in all five binaries: stdout or stderr is a pipe whose read end is closed before the child starts, or `/dev/full`; a closed stdout keeps the command's own verdict, another failure to write a result exits 1 and names the verdict, a completed change only warns, and a diagnostic nobody reads leaves the status. `review_cli_help.rs` (`maki-attach`, `maki-witness`, `maki-benchmark`): `--help` and `--version` only as the sole argument. `review_misuse_status.rs` (`maki`, `maki-witness`): misuse, an option where a path belongs included, exits 2 before anything is read or created, a failed command 1, an argument that is not UTF-8 2. `scripts/test_doc_output_validation.py`: no two workspace targets document into one directory |
| Test fixture locations | `maki-backing/tests/review_other_filesystem.rs`: the five copies of `tests/support/other_filesystem.rs` are identical, and a fixture without a second filesystem skips unless `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1`, which makes it fail. `tests/support/short_dir.rs` keeps socket paths short; `tests/support/private_dir.rs`, `shared_dir.rs` and `witness_config.rs` set fixture modes explicitly, whatever the umask |
| Packaged workload lifecycle (R3-007) | `maki-privileged/tests/regression_workload_lifecycle.rs`: daemon failure enters bounded recovery, registered workloads stop before attachment cleanup, cleanup success alone restarts the target, every workload start verifies identity, and target stop cleans attachment before daemon exit |
| Current privileged runner contract | `regression_runner_without_nbd_client.rs` and `phase7_priv.rs`: the runner neither requires nor installs nbd-client, its raw fixture connects and disconnects with `maki-attach nbd-connect`/`nbd-disconnect`, the unprivileged disconnect probe runs the helper's own request, root plans mode-0600 configuration, the control runtime is provisioned, and real cleanup is invoked twice; `scripts/test_privileged_denial_validation.py` accepts only the kernel's `Operation not permitted` for `NBD_CMD_DISCONNECT` as denial evidence. `scripts/test_privileged_lifecycle_validation.py`: after the workload, every run writes and fsyncs data, detaches while an opener holds the device, attaches again without creating the sentinel and compares the data; `--kill-daemon` reaches the worker and adds `SIGKILL` of nbdkit (exit status 137), cleanup, a new nbdkit that must negotiate, a third attach and the comparison, then a second kill, the release by hand, cleanup's disconnected recovery, a fourth attach, the comparison and a final detach, and without it cleanup ends the attachment; the exit trap asks an opener to close before any helper cleanup. Against mocks, a helper's output is kept with its exit status, a detach that returns before the opener has closed the device fails, each attach must show the mount, a backend identifier and the record, each leftover (mount, holder, backend, `pid`, size, attach record) fails the release check, a look for the record that fails fails both checks, changed data fails the comparison, an opener that does not hold the device stops the run, the wait for the opener reads its state from `/proc` and never signals it (sudo checks its policy with real, effective and saved uid 0, so for that moment the runner user's `kill -0` on its PID fails with EPERM; in the Debian 12 guest the wait stopped so) and still ends at once when the opener exits, a cleanup whose logged path is not the one for what the device showed fails, the release by hand disconnects first and unmounts and unmaps only while the device still shows the connection, and stops the run when the disconnect is refused, the connection stays or the record is gone, and is not started without an attachment's identifier, and the capture of the helper's inputs runs as root into the run directory and stops the run when it fails. The capture's commands, environment, limits and attributes are compared with the helper's sources, and its tree with a fixture's. `scripts/test_privileged_nbd_ownership_validation.py`: `kernel-disconnect` resolves the `nbd` family and sends `NBD_CMD_DISCONNECT` for the device's index as the kernel's headers lay it out, takes the kernel's errno for a refusal, ignores answers from another sender or to another request, and acts under the attach lock only on a device that shows the named attachment's identifier, which must be of the form `maki-<uuid>`. The opener's verdict is checked on a scripted device and clock: only whole blocks read while the device showed a connection, then `EIO`, with that connection shown at the failure and at the close and gone after it, pass; its hold after the disconnect is the caller's (`--hold`). `scripts/test_privileged_artifact_validation.py`: with `--prebuilt DIR` the run copies DIR's three artifacts into its run directory, runs and hashes the copies, never calls Cargo or rustc, refuses a directory without all three and a plugin without `plugin_init`, and the launcher passes the resolved directory to its worker. `scripts/test_documented_quickstart_validation.py`: the program holds every block of the Debian install section (or, with `--installation rhel`, of the RHEL guide's repository and install sections, whose SELinux-module check stops it only when the module is installed), the quick start and the bootstrap in order, stops at a failed command, pipeline stage or block, and is refused for a block Bash cannot read, for one with `&&` or `||` text at the block's own level or in a subshell there before its last command (conditions and quoted text included), and for one with such a line below its level, in compound-command bodies, brace groups and functions at any depth, that the allow-list does not name for that block; the allow-list is exactly the guides' current such lines, and a negated or a background command is still accepted, a known gap pinned with its cases. With `--stop-once`, only the first run has the shim on `PATH`, and a stand-in bootstrap that does not stop, stops without a record, then succeeds, keeps its record or connection, or leaves the daemon running each stops the program before the reset. `scripts/test_stop_together_validation.py`: each volume's blocks are the quick start's with its name, every device is held before one `systemctl stop` of every target, each attach unit's stop times are read only once the unit is inactive or failed, from PID 1's journal entries for its stop job after the request (a fake systemd returns before the attach units stop and forgets a stopped unit, as on GitHub, and writes a stop's last messages late), and a failed stop, a failed opener, a stop job that did not end `done`, an attach unit that does not stop within 300 s or a leftover fails after the report |
| Helper NBD handshake and netlink (SPEC §6) | `maki-privileged/src/nbd_kernel/handshake_tests.rs`: against scripted servers on a socketpair, the exact bytes sent (client flags, one `NBD_OPT_GO` for the default export), `NO_ZEROES` echoed only when offered, no fixed newstyle, oldstyle and bad magic, every GO error reply without an `EXPORT_NAME` fallback, a missing, repeated or malformed `NBD_INFO_EXPORT`, skipped information, unknown reply types and options, a reply over 4098 bytes refused before it is read, the 64 KiB total, truncation, stalls at the deadline, exports without `HAS_FLAGS`, `SEND_FLUSH` or `SEND_FUA`, size 0, and a negotiated socket left without timeouts. `netlink_tests.rs`: golden bytes of `CTRL_CMD_GETFAMILY`, `NBD_CMD_CONNECT` (libnl's order and `NLA_F_NESTED` nesting) and `NBD_CMD_DISCONNECT`, and the reading of replies (family id, connect index, ack, negative errno, truncation, sequence numbers, ports, senders). `header_tests.rs`: every constant against the installed UAPI headers through a C probe (`MAKI_TEST_REQUIRE_NBD_HEADERS=1` fails instead of skipping). `retry_tests.rs`, against a scripted daemon and kernel and a manual clock: an `EBUSY` connect retried every 100 ms on the negotiated connection after checking that the device still shows no connection, a fresh negotiation only for a connection that is no longer usable, an unavailable export (`NBD_REP_ERR_UNKNOWN`) retried the same way, the 5 s counted from the first busy answer, a device busy to the end told apart from every other refusal, an export unavailable to the end refused as busy with another connection or missing, no retry once the device shows a connection or past an earlier deadline, every other answer final; the family check (highest attribute 9 refused, 10 accepted). `property_tests.rs`: seeded noise and mutated transcripts never make the handshake read more than its limit, accept another export or read past the acknowledgement, 100,000 generated datagrams yield the kernel's verdict only in its own shape, and the socket reads its request's answer, another request's, a multipart answer and silence from the kernel's generic netlink controller. `tests.rs`, `command_tests.rs` and `exec_tests.rs`: flags and size forwarded unchanged, a blocking close-on-exec socket, a negotiated connection reusable only while open and silent, an earlier connection closed before the next negotiation, the deadline, the step limit and an earlier `finish_by` deadline, no program started for either step, an unanswered request kept as an I/O error of unknown outcome, and a device that stayed busy kept apart from a refusal |
| Helper NBD handshake against nbdkit | `maki-privileged/tests/review_nbd_handshake_nbdkit.rs`: a real `nbdkit memory` export negotiates, and eval exports without FLUSH or FUA are refused. `maki-nbdkit/tests/review_helper_nbd_handshake.rs` compiles the helper's handshake source by path and runs it against Maki's plugin: FLUSH, FUA and write zeroes always, TRIM exactly with discard, never read-only; a second connection is answered "not available", as the handshake tells it apart, until the first is closed, and the daemon's log says why. Both skip without nbdkit unless `MAKI_TEST_REQUIRE_NBDKIT=1`; maki-privileged's tests start nbdkit on a private socket through `tests/support/nbdkit.rs` |
| Kernel NBD connect (root) | `maki-privileged/tests/review_nbd_kernel.rs`, a root-only target: nbdkit serves a memory export, the helper connects a free `/dev/nbdN`, sysfs must show the backend identifier, the size, `queue/write_cache` `write back` and `queue/fua` 1, a second connect is the kernel's refusal, a write and an fsync pass, and the disconnect frees the device; the provisioning path (`connect_raw`/`disconnect_raw`) refuses another identifier's disconnect, and its own disconnect returns only once the device shows no connection; a device the test holds open is connected once it is released, not before. The three tests take different devices (the lowest and the two highest free ones), so none waits for udev's probe of another's device. It skips without root, the `nbd` module or nbdkit unless `MAKI_TEST_REQUIRE_NBD=1`, which CI's root-only step sets |
| Provisioning connects | `maki-attach/tests/review_nbd_provisioning.rs` and `exec_tests.rs`: `nbd-connect`/`nbd-disconnect` plans, strict options and value checks, an attach-record identifier refused, a connected, unreadable or record-reserved device refused before anything is connected, a disconnect only of the device's own connection, and a disconnect that waits until the device no longer shows it and fails when it still does; `scripts/test_docs_provisioning_validation.py` runs the provisioning guide with them, and runs its block again on the same host after it stops at each step. The stopped run has recorded every identity it had read, in copies synced under a staged name before they take the record's name, and prints the record. The next run takes the attach lock, refuses a record made with any other value or one it cannot read (not a regular file, another owner or mode, an unreadable, unknown, repeated or unterminated line, a missing value, an invalid identity) and says that it cannot continue, and reports a restart since the record was made. It then releases the export under the recorded identifier, deactivating the VG only once every holder is shown to be its mapping and with `--devices`, so that a VG of the same name on another disk is never touched. Finally it writes the attach configuration a run that does not stop writes, synced before the record goes, into a mountpoint it made itself; or it removes the record of a run that recorded no filesystem, after which a new run refuses an export the stopped run wrote to. It refuses, touching nothing, a backend, holder, mountpoint or configuration that is not the run's. A staged copy of the record or of the configuration whose name another process takes, with a link or a file, between the block's removal of it and its write is refused, and neither the link's target nor that file is written (`set -C`); a record without its boot ID is refused as one that cannot be continued from |
| Runtime logging (R4-001) | `maki-core/src/logging.rs` child-process tests, `maki-privileged/src/logging.rs` (the `maki-attach` sink: steps and halted rollbacks reach stderr) and `maki-nbdkit/tests/review_r4_native_logging.rs`: a real nbdkit run must show the store's `WARN` for an adopted orphan shard on its captured stderr, and `MAKI_LOG=error` must suppress it. `MAKI_LOG` values without a level (`warning`, `err`, a bare target, `target=`) fall back to `info` with one `WARN` (`MAKI_LOG is not a valid filter`) that gives a fixed reason and the directive's index, never the value, and an empty value means `info`, in both sinks and through `maki check` (`bins/maki/tests/review_log_filter.rs`) |
| Guarded plaintext and keys (R4-002) | `maki-crypto-local/tests/review_r4_guarded_buffers.rs`: encryption, decryption, tampered-ciphertext failure and file/env key loading never wrap a bare `Vec` (`unguarded_wraps()` stays constant); `SecretBuffer::truncate` unit tests |
| Package removal and inputs (R4-003, R4-007) | `scripts/test_debian_package.py`: `prerm` refuses removal under an attachment record or an active `maki@`/`maki-attach@`/`maki-workload@` unit or when `systemctl` cannot be queried but never blocks upgrades, no maintainer script starts/stops/restarts a service, ELF stubs of the wrong machine, class, type or a non-ELF file are refused, unknown architectures are refused, the dependency scan is on by default and fails closed on unanalysable artifacts or a missing `dpkg-shlibdeps`, `--no-shlibdeps` warns and keeps only the static `Depends` |
| RPM package (RHEL 9) | `scripts/test_rpm_package.py`: the RPM installs the Debian package's files with the same modes and root ownership (compared file by file where `dpkg-deb` exists; the deliberate differences are the unit's nbdkit path, the license text RHEL lacks and dnf's protection file), `maki@.service` runs `/usr/sbin/nbdkit` and a unit without exactly one Debian nbdkit `ExecStart=` is refused, `%preun` refuses an erase under an attachment record, an active unit or a failed `systemctl` query with the Debian `prerm`'s check and never blocks an upgrade, no scriptlet starts, stops or restarts a service, the Debian builder's artifact checks apply for `x86_64`, `aarch64`, `ppc64le` and `s390x`, a binary whose ELF interpreter no package of the build host owns is refused unless `--no-autoreq`, the plugin is not provided as a library, the package conflicts with `nbdkit-selinux` and the `nbdkit` metapackage, its one file below `/etc` is the `%config(noreplace)` `/etc/dnf/protected.d/maki.conf`, which names only `maki` and says how the package is removed, it provides the user and groups of its sysusers file and is the same file whether or not the build host has rpm's sysusers dependency generator (checked with a stand-in generator), versions rpm cannot express are refused and candidate versions keep their order, a missing `SOURCE_DATE_EPOCH` or one before 1990 (which rpm cannot put in the changelog) is refused, and the build is reproducible |
| Release workflow | `scripts/test_release_workflow_validation.py`: `.github/workflows/release.yml` runs only when dispatched with a tag, from `main`, and accepts only `v<workspace version>-rc.<n>` (a final tag is refused while production approval is pending); a taken tag or release is refused before anything is built; only the publish job may write; the Debian bundle comes from `prepare_release.py` in `debian:12` and the RPM from `build-rpm.py` in CentOS Stream 9, both from the dispatched commit with its whole history and no cache, and only first-party actions and the baseline toolchain are used; `scripts/release_assets.py` refuses bundles whose sums, manifests, commit or version disagree, gives the assets names GitHub keeps and writes one `SHA256SUMS`; the notes name every asset and its distribution and say that nothing is signed and the release is not qualified; against a stand-in `gh` the release is a draft pre-release until every asset is uploaded, a failure before publication leaves no release and no tag, and one after it is reported, not deleted |
| Booted-host jobs | `scripts/test_ci_gate_validation.py`: each guest's package is built from the commit in its distribution's container and uploaded with its checksums and revision; each guest job needs only its own package job, runs both suites in fresh guests on a runner VM with KVM opened and required, runs its steps in order, each with a time limit within the job's, caches the image under its pin and checks it after a hit, ends the boot and the copy within the boot step's limit, runs every guest phase as root under a limit inside sudo below its step's, the SELinux phase only on EL9, and always keeps the logs. `scripts/test_booted_host_validation.py`: the images are pinned by name and digest (Debian's generic image, Rocky's GenericCloud Base image with its vault address), an image with another digest is refused and not kept, the payload refuses a package whose checksums fail or that another commit built and holds the installation's program or a clone of `HEAD`; the guest runs with KVM on a copy-on-write overlay with SSH on `127.0.0.1` only, its seed creates a key-only user without a password and pins the host key that SSH alone accepts, cloud-init is awaited across the sshd restart it causes, a guest that does not come up fails with its console, a command runs under `timeout` (inside `sudo` for a root phase) and is given up after its limit, a copy into the guest is given up after its limit, an image already there is used only with the pinned digest and the cache key names the pin, and the logs kept never include a key, the seed or anything of `/var/lib/cloud`, nor a file that holds a private key. In the guest: the release decides the guest, EL9 requires enforcing, the sampler records each Maki process's unit and label once, the SELinux verdict fails for another mode, auditd not active, a denial naming Maki or NBD, a failed `ausearch`, `maki@`'s nbdkit outside `unconfined_service_t` or unsampled, and a label the RHEL guide does not list (every packaged unit file and `/dev/nbd0` are checked), the guides phase fails with the program's status and with a finished quick start's leftovers, the runner runs as `ci` on `/dev/nbd15` with the package's binaries, and the archive leaves out the package, the snapshot and the builds |
| RHEL 9 installation guide | `scripts/test_docs_rhel_installation_validation.py`: the guide and `packaging/rpm/README.md` quote the spec's static `Requires` and its `Conflicts` exactly and its `Provides`, and say that the package is removed with `rpm -e` (no command of the guide removes a package with dnf), every `dnf` command of the guide installs from BaseOS and AppStream only (no `--enablerepo`, `config-manager`, COPR or EPEL) and never the `nbdkit` metapackage, the one RPM builder call in each uses only options the builder accepts and keeps the automatic requirements, the guide says RHEL 9 is not qualified as the support matrix's row does, and the README, the documentation index, the status page and the support matrix link it |
| Deep-check verdict (R4-004) | `maki-core/tests/review_r4_check_verdict.rs`: recoverable slot damage passes with a warning and is repaired by recovery, damage without a journal source fails, mixed damage reports both classes, a healthy volume is `clean`, a damaged header on an unlisted slot is `unrecoverable` |
| Overlay memory bound (R4-005) | `maki-core/tests/review_r4_overlay_bound.rs`, `maki-format/tests/review_r4_overlay_limits.rs`, `maki-nbdkit/tests/review_r4_overlay_options.rs`: bytes and entries stay under their limits without journal pressure, the worker checkpoints on the overlay watermark with a manual clock, a failed reclaim refuses the write and degrades, a concurrent volatile write during an inline reclaim does not cause ENOSPC (multi-thread, `checkpoint.slot_write` hook), defaults/zero/minimum validation, and the daemon mapping |
| Inline reclaim fairness | `maki-core/tests/review_reclaim_fairness.rs`: eight concurrent writers of maximal, misaligned requests against a journal limit or an overlay limit at its validated minimum, with no injected fault, never get ENOSPC, keep the bound and read back their last data (multi-thread) |
| Worker sync before checkpoints | `maki-core/tests/review_watermark_volatile_tail.rs`: with only volatile records in the active segment, a pass woken by the journal watermark or started by low backing free space syncs first and applies them; with every journal sync failing (fault hook), a pass started by any worker trigger (watermark, low free space, interval, overlay watermark, a write refused for space) still applies the durable records, deletes their sealed segments and shrinks the overlay, the failed sync is retried only after an interval, and a retry with nothing durable to apply runs no checkpoint (ManualClock that counts the worker's sleeps) |
| Watermark below a segment | `maki-core/tests/review_watermark_active_segment.rs`: with an embedded-engine watermark far below the segment size, the worker syncs and checkpoints once per sealed segment, not on every write, and the pass at each roll applies everything (a clock that lets the test run one observed worker pass after each write) |
| Cache-first reads (R4-006) | `maki-core/tests/review_r4_cache_reads.rs`: a hit reads at most the 64-byte header and makes no provider call, an overlay hit reads nothing, newer versions miss, header damage is EIO despite a cached entry, payload damage is served until eviction then EIO, uncached reads still verify, `cache.verify_on_hit` re-reads the payload on a hit (damage is EIO at once) without a provider call; `maki-nbdkit/tests/review_r4_cache_verify_options.rs` maps the setting |

The native NBD negotiation case requires Linux, `nbdkit`, and `nbdinfo` from
libnbd. It uses Cargo's cdylib and an isolated child process with a private Unix
socket; absent optional programs skip that case. It passed
on this review host. An independent C probe against the installed
`nbdkit-plugin.h` also confirmed the 384-byte published prefix and the
`block_size` callback at offset 376 on this host. These checks qualify the
userspace ABI and negotiation, without operating a kernel NBD device.

## Current qualification status

Each campaign qualifies its recorded revision and configuration. The evidence
below runs through 2026-10-05; it does not claim that every later revision or
production configuration has repeated those campaigns. Production approval is
still pending, as stated in [status](status.md).

The latest additions are:

| Date | Scope | Result and evidence |
|---|---|---|
| 2026-10-03 | v3 discard after the R5 fixes | Ten workload-VM resets; XFS/LVM/NBD `fstrim`, mount and attach-config checks, and packaged quick start ([report](qualification/r5-hardware-validation-2026-10-03.md)) |
| 2026-10-03 | PostgreSQL 15, discard and pressure | Crash/lifecycle with trim under load and the syscall filter passed; raw discard recovered space, while XFS deletion and trim failed below backing headroom ([report](qualification/database-discard-pressure-validation-2026-10-03.md)) |
| 2026-10-04 | Remote transport sandbox and database | HTTP/WebSocket/gRPC passed mTLS, failover, outage/resume, trim and restart under the syscall filter ([report](qualification/remote-transport-syscall-filter-validation-2026-10-04.md)); PostgreSQL 15 over gRPC passed under the packaged unit including `MemoryDenyWriteExecute` ([report](qualification/remote-database-zero-mdwe-validation-2026-10-04.md)) |
| 2026-10-04–05 | Debian 13 and PostgreSQL 17 | All three transports passed the shipped sandbox, injected latency/loss and kernel NBD zeroing ([report](qualification/debian13-remote-transport-validation-2026-10-04.md)); PostgreSQL 17 passed crash and packaged LVM lifecycle checks over per-item HTTP ([report](qualification/debian13-postgresql-http-validation-2026-10-05.md)) |
| 2026-10-05 | Cross-host sandbox and provider reset | All three transports passed internal DNS, TLS/mTLS, failover, outage/resume, trim and restart across Debian 12 VMs ([report](qualification/cross-host-sandbox-validation-2026-10-05.md)); one hard reset per transport of the provider host preserved every acknowledged file ([report](qualification/provider-host-reset-validation-2026-10-05.md)) |

Earlier campaigns establish the following scoped results.

Revision `448c0b2` passed a disposable Debian 12 GCE campaign with
nbd-client 3.27.1, actual Maki nbdkit, kernel NBD, pinned single-PV LVM/XFS,
trusted attach/verify/cleanup, and a Docker SQLite external ACK oracle under the
installed shipped systemd graph. Two automatic nbdkit `SIGKILL` recoveries
advanced the fsynced ledger from 16 to 32 and 48 rows. A third crash while a
root process held the LV open failed cleanup closed without restarting the
workload; closing the descriptor and explicitly retrying recovery reached 64
acknowledged rows in a fourth distinct container. An independent container
matched all 64 rows and reported `integrity_check=ok`.
Follow the [runtime-layout upgrade procedure](operations.md#upgrading-the-runtime-layout).

Revision `ece7e39` then passed a separate two-host restore campaign. A source
VM wrote 32 SQLite WAL rows and a fsynced external ledger, drained and exported
the unchanged v2 backing, configuration, attach identity and credential, and
was deleted with its boot disk. A newly created VM restored the artifacts,
matched all 32 rows, added 16 rows, and matched all 48 after a full lifecycle
restart. Both final offline checks passed and both VMs and disks were deleted.
See the [fresh-host restore validation](qualification/fresh-host-restore-validation-2026-09-17.md).

Revision `c385c99` then passed a separate remote-provider database campaign on
one disposable GCE VM. Two authenticated loopback HTTP providers served the
actual Maki kernel NBD/LVM/XFS path. SQLite committed eight rows with both
providers, eight with only B, eight with only A, stalled one transaction while
both were down, resumed that exact transaction after B returned, and finished
at 32 rows. All IDs and body hashes matched an external fsynced ledger before
and after a packaged lifecycle restart. See the
[remote HTTP provider database validation](qualification/remote-provider-db-validation-2026-09-18.md).

Revision `47058d2` then passed a separate three-host HTTPS campaign. A client
used private VPC addresses to reach two nginx-terminated reference providers,
explicitly proved TLS 1.2 and TLS 1.3 with the expected mTLS identity, and
required a bearer credential. Wrong-CA, missing-client-certificate and
wrong-bearer attachments failed before daemon readiness. Provider A and B
were stopped separately while writes continued; with both down, the ledger
stayed at 24 until B returned. The run reached 32 exact ACK rows, retained them
through a Maki restart, passed deep checking with zero invalid slots, and
deleted all three VMs. See the
[cross-host TLS reference-provider validation](qualification/cross-host-tls-provider-validation-2026-09-19.md).

Revision `5f50354` then passed a checksummed PostgreSQL 15 campaign on another
disposable GCE VM. After 16 exact ACK rows, a cgroup-wide postmaster `SIGKILL`
interrupted four pgbench clients. Automatic WAL recovery produced a distinct
postmaster, preserved the whole ACK prefix, and passed `pg_amcheck`. The cluster
advanced to 32 rows, retained them through a packaged Maki lifecycle restart,
then reached 48 rows. Four `pg_amcheck` runs were clean. See the
[PostgreSQL process-crash validation](qualification/postgresql-crash-validation-2026-09-18.md).

Revision `3cac300` then passed a generated Debian package, topology, and
migration campaign. A clean pre-upgrade package install ran two simultaneous
kernel NBD/LVM/XFS volumes, including a second LV mapping, before the current
package upgrade preserved configuration, credentials and both SQLite hashes.
A corrupt DB-native restore was rejected before retry, a clean legacy-v1
old-reader backup restored exactly into v2 while the current writer refused the
unchanged v1 metadata, and multi-mapping plus foreign-backend cleanup both
failed closed before mutation. See the
[package, topology, and migration validation](qualification/package-topology-migration-validation-2026-09-19.md).

Revision `bdb9113` then passed a separate three-host credential-rotation and
new-key migration campaign. An existing K1 volume was stopped, detached and
drained before its bearer token and mTLS client identity/CA changed; the old
credentials were refused, both peers validated the new credentials, and the
superblock/canary hashes stayed unchanged. A DB-native SQLite backup then
restored into a distinct K2 volume, and an isolated K1 wrong-key canary was
refused with unchanged superblock/canary hashes. The 24 exact external ACK rows
survived a lifecycle restart.
Both volumes passed final deep checking with zero invalid slots, and all three
VMs and disks were deleted. See the
[credential rotation and key migration validation](qualification/credential-rotation-key-migration-validation-2026-09-19.md).

Revision `da89ae3` then passed a four-host stopped server-CA and endpoint
rotation campaign. Mixed old/new server leaves worked with overlapping private
roots; both peers then moved to the new CA before old trust was removed.
Correct-root HTTP 204 and wrong-root curl 60 controls accompanied failed actual
NBD negotiations in both trust directions. Replacing A's address with C's
distinct IP while A's nginx listener was stopped preserved the key/profile,
volume identity, superblock/canary hashes, and exact SQLite data. C/B reached
48 ACK rows through another restart. The negative oracle was corrected in TDD
to distinguish an early socket inode from readiness and an outer operation
deadline from an explicit TLS error. See the
[server CA and endpoint rotation validation](qualification/server-ca-endpoint-rotation-validation-2026-09-19.md).

For unattended repetition of the existing DB model, persistence, concurrency,
space-admission, recovery-allocation, and v3 discard crash/model/reclamation
tests, see the
[background storage runner](background-storage-validation.md). It freezes inputs,
builds each campaign in a target directory private to that frozen run, records
status and exit codes, and supports cancellation. The extended profile retains
the original five suites and adds `review_discard_crash`,
`review_discard_model`, and `review_discard_reclaim_retry`. The run at `9fec035`
finished on 2026-09-20 with 100/100 rounds, 500 successful suite invocations,
3,600 passing test invocations and supervisor exit 0; its result ledger and
source/binary hashes were verified. Repeated fixed-seed model runs do not
replace real-DB, physical-power or long-duration parser qualification.

A second extended campaign from `f5bde3e` ran from 2026-09-20 11:18:48 UTC to
17:04:40 UTC (2026-09-21 02:04:40 KST). It completed 100/100 rounds across all
eight suites: 800 successful suite executions and 4,800 passing test invocations
in 20,751.6 seconds, with supervisor exit 0. The private run directory is
`~/logs/maki-storage-20260920T111848Z-5111c6/`; `status.json`, the 800-row
`results.jsonl` ledger, frozen source and binary hashes, and per-suite logs retain
the evidence. The fixed-seed/model and simulated power-loss coverage does not
replace a real database, physical power loss, or production qualification.
Inspect the completed result without restarting it:

```bash
python3 -B scripts/storage-repeat-validation.py status --run-dir ~/logs/maki-storage-20260920T111848Z-5111c6
```

The separate [v3 GCE reset campaign](qualification/gce-discard-reset-validation-2026-09-20.md)
passed ten whole-instance resets with 160 verified units and a zero-invalid-slot
offline deep check, then deleted its disposable resources. It used native NBD
with the local provider; it was not a production database or physical Persistent
Disk power-loss campaign.

| Requirement | Target | Status | Evidence |
|---|---:|---|---|
| Randomized model operations | 100,000+ | Pass | 110,000-operation block-model gate |
| Crash/recovery cycles | 10,000+ | Partial | 10,000 in-process seeded runs plus native FLUSH/FUA SIGKILL regressions; not 10,000 OS process crashes |
| Endpoint failure cycles | 10,000+ | Pass in simulation | Deterministic dispatcher cycles with no failed requests or permit leaks |
| Circuit-breaker cycles | 10,000+ | Pass in simulation | Complete open, half-open, close, and failed-probe reopen cycles |
| Parser fuzzing | 24 CPU-hours per target | Partial | `review_fuzz.rs` (exhaustive single-bit-flip sweep of every on-disk decoder, ~30,000 seeded mutations, config and URL fuzz) and `review_fuzz_transport.rs` (random provider responses through the HTTP parse path); sixteen coverage-guided `cargo-fuzz` targets in `fuzz/`: `format_decoders`, `format_records`, `journal_scan`, `config_parse`, `endpoint_url`, `probe_parsers`, the root helper's `nbd_handshake`, `nbd_netlink`, `helper_reports` and `helper_sysfs`, `maki-backing`'s `backing_records`, the witness's `witness_rpc` and `witness_etcd`, and the remote providers' `http_response`, `websocket_response` and `grpc_response`. Their committed seeds are replayed by the default suite, and the scheduled `fuzz` job runs each target for 30 seconds from them ([Fuzzing](#fuzzing)). Only short runs have been made, all with libFuzzer and AddressSanitizer on one core and none with a crash. On 2026-11-24, from an empty corpus: `format_decoders` 5 minutes (36M inputs), `format_records` 10 minutes (47M), `journal_scan` 5 minutes (14M) and `config_parse` 30 minutes (1.9M). Every decoder checks a CRC-32 before it reads a field, and from an empty corpus `format_decoders` reached almost no image that passes one (256 covered edges); `format_records` repairs the checksum first and requires an accepted record to survive a round trip (712 edges). On 2026-11-25, from the committed seeds: `nbd_netlink`, `backing_records` and `nbd_handshake` 12 minutes each (37M, 29M and 1.3M inputs; 357, 4,318 and 333 edges), and 150 seconds each of `format_decoders` (34M, 378 edges), `format_records` (16M, 948), `journal_scan` (32M, 169), `config_parse` (3.0M, 4,291), `endpoint_url` (1.6M, 2,312) and `probe_parsers` (2.1M, 1,024). On 2026-11-26, from the committed seeds, 4 minutes each on a shared host: `witness_rpc` (1.4M inputs, 5,133 edges), `witness_etcd` (8.2M, 2,627), `http_response` (3.8M, 3,480), `websocket_response` (8.2M, 2,302), `grpc_response` (5.3M, 2,056), `helper_reports` (8.5M, 3,750) and `helper_sysfs` (0.18M, 3,465; each input builds and removes a directory tree). A 24 CPU-hour-per-target run remains outstanding; the [fuzz qualification](#fuzz-qualification) workflow runs one on GitHub's hosted runners when dispatched |
| Userspace nbdkit/libnbd/fio | Functional smoke | Pass on Debian 12/KVM | ABI probe, byte-identical copy, and CRC32C fio verification |
| Kernel NBD, LVM, XFS, and fio | Functional smoke and repeated server crash | Pass on Debian 12 GCE | `448c0b2` ran two automatic nbdkit SIGKILL recoveries and one open-target cleanup failure/retry through `/dev/nbd15` and pinned single-PV/LV storage |
| Packaged systemd lifecycle | Functional ordering and failure gates | Pass for scoped Debian 12 and 13 GCE profiles | Debian 12's installed templates recreated the daemon, attachment, workload and Docker container, withheld restart on open-LV cleanup failure, and recovered on retry; Debian 13 passed the PostgreSQL 17 crash and packaged LVM stop/start scenario |
| Debian package install and upgrade | Clean install, stopped-volume upgrade, and exact reattach | Pass for one generated-package Debian 12 profile | Pre-upgrade and current packages preserved volume/attach configs, all token hashes and two SQLite logical hashes, did not auto-start volumes, and reattached both after upgrade |
| Multi-mapping and foreign-backend refusal | Refuse ambiguous fallback and changed backend identity before mutation | Pass for one two-LV and one same-NBD foreign-backend topology | Packaged recovery preserved both mappings and proof after daemon death; cleanup preserved a foreign backend identifier and trusted record until explicit disconnect. Keeping the record beside a foreign backend was superseded for a record that names its VG UUID and leaves nothing of its attachment: cleanup now retires it without touching the backend, which has not been re-qualified on a real kernel |
| DB-native and legacy-v1 migration | Reject corrupt restore; old-reader backup into a fresh v2 volume | Pass for stopped-source SQLite profiles | Corrupt native restore failed before clean retry; current writer refused byte-stable v1 superblocks and the old-reader backup restored with the exact logical hash |
| Docker bind lifecycle | Functional rebind and start gate | Pass for one Debian 12 GCE topology | Four distinct default-`rprivate` containers preserved the exact external ACK prefix; the failed cleanup created no replacement container |
| Fresh-host backing restore | Graceful backup, new host, continued writes and restart | Pass for one unchanged v2/local-provider/SQLite topology | Distinct source and target VMs recovered 32 exact ACK rows, advanced to 48, retained 48 after restart, and passed SQLite integrity and offline checks |
| Remote HTTP provider database faults | Single-endpoint failover plus total-provider outage | Pass for one loopback two-provider/SQLite topology | A and B separately served after peer loss; a 4,094 ms total outage held the ledger at 24, then resumed exactly one commit and reached 32 exact rows before and after restart |
| Cross-host HTTPS reference provider | TLS/mTLS/auth refusal, host failover, and total-provider outage | Pass for one three-host private-VPC/SQLite topology | TLS 1.2 and 1.3 health gates recorded the client subject; wrong CA, absent client identity and wrong bearer failed closed; 32 ACK rows survived provider-VM stop/start and Maki restart |
| Cross-host HTTP/WebSocket/gRPC sandbox | Internal DNS, TLS/mTLS, failover, outage/resume, trim and restart | Pass for one Debian 12 private-VPC/reference-provider profile per transport | 33/33 checks passed under the shipped sandbox; deep checks were clean. XFS was directly on NBD in these transport campaigns |
| Provider-host hard reset | Stall, reconnect and acknowledged-file readback | Pass for one reset per transport | HTTP/WebSocket/gRPC resumed after approximately 12–20 s stalls with no failed write or lost ACK file, including readback after daemon restart; minutes-long outages, changed return addresses and database workloads were not covered |
| Stopped credentials and new-key migration | Replace bearer and mTLS client identity without changing the existing key; restore into a distinct provider key/volume | Pass for one three-host private-VPC/reference-provider/SQLite topology | Old bearer and client identity were refused, both peers validated the replacements, existing superblock/canary hashes matched, K1/K2 fingerprints and volume UUIDs differed, a wrong-key canary kept those hashes unchanged, and 24 ACK rows survived DB-native restore and restart |
| Server CA and endpoint-address rotation | Overlap private roots, replace leaves, remove old trust, then replace an address with the same key/profile | Pass for one four-host private-VPC/reference-provider/SQLite topology | Both wrong-trust directions refused real NBD negotiation; A/B changed to C/B with A's listener stopped; both peers validated, superblock/canary hashes matched across each attach, and 48 ACK rows survived restart |
| PostgreSQL process crash | Checksums, WAL recovery, logical check, and storage restart | Pass for scoped PostgreSQL 15/Debian 12 and PostgreSQL 17/Debian 13 profiles | Local-provider, gRPC and per-item HTTP scenarios preserved external ACK rows through postmaster SIGKILL and packaged lifecycle restart; `pg_amcheck` passed, including v3 discard and endpoint outage under load |
| Real databases | Required | Partial | SQLite WAL and short checksummed PostgreSQL 15/17 profiles passed scoped campaigns; production profiles, database operation under backing-space pressure, ClickHouse, MinIO, and broader application recovery contracts remain open |
| cgroup resource faults | Target-specific | Partial | Real AES userspace NBD passed CPU throttling, freeze/resume, SIGKILL and workload OOM readback. Four later constrained recoveries passed at 48/64 MiB; process `VmHWM` stayed at or below 11,415,552 bytes, while only 64 MiB avoided cgroup max events |
| Physical checkpoint-space reservation | Linux filesystem ENOSPC before ACK | Pass on one Debian 12/ext4/GCE PD topology | A 4,608-byte slot owned 8,192 allocated bytes before FUA ACK; with zero free bytes, the next FUA returned ENOSPC without changing sequence, journal bytes, or slot allocation, then retried and survived restart |
| Firecracker guest abrupt loss | Target-specific | Partial | 20 alternating FLUSH/FUA ACKs survived VMM SIGKILL and cold-boot authenticated readback on GCP nested KVM; L1 kernel and storage caches remained live |
| GCE whole-instance reset | Target-specific | Pass on disposable Debian 12 GCE, v2 and v3 | External ACK readback survived the v2 campaign and ten-reset v3 campaigns, including the 2026-10-03 run after the R5 fixes; GCE Persistent Disk service and physical storage stayed operational |
| QEMU hard power loss | 300+ cuts | Open | Simulation is not hardware evidence |
| Mixed workload | 72 hours | Open | Dedicated hardware run not recorded |

The detailed Debian run is preserved in the
[rootless Linux validation report](qualification/native-linux-validation-2026-09-02.md). The
later [privileged Linux validation report](qualification/privileged-linux-validation.md)
records the kernel NBD, LVM, XFS, raw and filesystem fio, privilege, helper, and
SQLite results, including the installed-systemd combined campaign and its
limits. The disposable instances and disks were deleted afterward, and fresh
name-scoped queries found no remaining `maki-*` resources.
The [September 12 fault report](qualification/cgroup-fault-validation-2026-09-12.md) records
the new native process and cgroup executions, external ACK evidence, reproduction
commands and the unresolved restart limit. The host was Debian, so no WSL
shutdown was executed.
The [Firecracker report](qualification/firecracker-validation-2026-09-12.md) records the
separate guest-kernel/page-cache loss campaign, its host-fsynced ACK ledger,
image hashes, cold-boot readbacks, and the boundary at the surviving L1 host.
The [GCE reset report](qualification/gce-reset-validation-2026-09-13.md) records the later
whole-workload-VM hard reset campaign, stable resource identities, shutdown
witness, Cloud Audit Log entries, authenticated readbacks, and cloud cleanup.
The [fresh-host restore report](qualification/fresh-host-restore-validation-2026-09-17.md)
records the later graceful export, source deletion, new-host restore, continued
writes, restart readback, harness corrections and cloud cleanup.
The [remote-provider database report](qualification/remote-provider-db-validation-2026-09-18.md)
records the two authenticated HTTP endpoints, per-endpoint failure, total
provider outage, SQLite ACK/hash oracle, lifecycle restart, harness correction,
and deletion of both attempted VMs and disks.
The [cross-host TLS reference-provider report](qualification/cross-host-tls-provider-validation-2026-09-19.md)
records private-VPC TLS 1.2/1.3, mTLS and bearer controls, provider-host
stop/start, SQLite ACK/hash readback, final deep checking, immutable harness
inputs, and deletion of all three VMs and disks.
The [PostgreSQL crash report](qualification/postgresql-crash-validation-2026-09-18.md)
records active durability settings, pgbench interruption, WAL redo, postmaster
replacement, four logical checks, ACK/hash readback, Maki lifecycle restart,
and deletion of the disposable VM and disk.
The [physical reservation report](qualification/physical-reservation-validation-2026-09-18.md)
records real ext4 block allocation before FUA acknowledgement, a zero-free-space
ENOSPC refusal with unchanged journal state, retry, restart readback, offline
checking, and deletion of the disposable VM and separate data disk.
The [package, topology, and migration report](qualification/package-topology-migration-validation-2026-09-19.md)
records clean install and upgrade, simultaneous volumes with a sidecar LV,
fail-closed multi-mapping and foreign-backend cleanup, SQLite DB-native and
legacy-v1 migration, final deep checks, and deletion of the disposable VM and
disk.
The [credential rotation and key migration report](qualification/credential-rotation-key-migration-validation-2026-09-19.md)
records the stopped bearer/mTLS-client transition, old-credential refusal,
unchanged existing-volume superblock/canary hashes, distinct provider-key
fingerprints and volume UUIDs, wrong-key canary refusal, DB-native cutover and
restart readback, final deep checks, immutable harness inputs, and deletion of
all three VMs and disks.

The [server CA and endpoint rotation report](qualification/server-ca-endpoint-rotation-validation-2026-09-19.md)
records private-CA overlap/removal, fresh server-leaf fingerprints, paired trust
controls and actual NBD refusal, same-key replacement on a distinct provider IP,
unchanged volume identity, and 48-row restart readback. It also preserves the
two invalid harness attempts and their corrections. It does not qualify hot
reload, public-CA revocation, or C-only availability while B remains configured.

## Database qualification

The automated database simulation models a WAL database with synchronous commit,
a durable epoch header, commit records, replay, and an external ledger oracle.
Crashes are injected before commit, after durable commit but before apply, and
after apply. Provider outages must abort uncommitted transactions without
damaging previously committed data.

Real-database qualification requires an attached disposable XFS volume:

- SQLite: WAL and DELETE journal modes, `synchronous=FULL`, process crashes,
  provider outages, `PRAGMA integrity_check`, and an external commit ledger.
- PostgreSQL: `fsync=on`, `synchronous_commit=on`, full-page writes, checksums,
  `pgbench`, forced process crashes, WAL recovery, and `pg_amcheck`.
- ClickHouse: inserts, merges, mutations, partition operations, crash cycles,
  `CHECK TABLE`, and an external hash oracle.
- MinIO: multipart upload, overwrite, range reads, restart and provider outage,
  with SHA-256 verification for every completed object.

The acceptance criterion is zero corruption, zero loss of acknowledged durable
transactions, and zero silent data substitution.

## Power-loss qualification

The automated simulator checks two durability contracts:

```text
WRITE A; WRITE B; FLUSH succeeds; WRITE C; crash
=> A and B are new; C may be old or new

WRITE A with FUA succeeds; crash
=> A is new
```

`CrashableBacking` samples pending operations and preserves the predecessor
dependencies of surviving namespace changes. Chained renames can recover at
intermediate names; independent names have no shared persistence order.
Directory names are published by syncing their parent, and a lost ancestor
makes all descendants unreachable. The model treats each rename as indivisible,
including a cross-directory rename when either parent is synced. That is a
model assumption, not a guarantee for every filesystem; directory-local rename
persistence needs additional simulation or real-filesystem testing. The main
power-loss gate (`phase12_powerloss.rs`) also enables tearing at 512-byte
granularity, so an unsynced write can survive in part.

A failed `sync_data` only reports that some writeback failed: the flusher, or
the failing sync before the page that failed, may already have written the
rest. The model therefore keeps a failed sync's operations as *uncertain*: a
later crash keeps each one independently, exactly like an unsynced operation
(torn too, with tearing enabled), while `crash_all_lost` and
`crash_keep_torn_prefix` drop them. A retried sync has nothing dirty to write
and makes none of them certain, so the rewrite-before-retry protocols remain
required (F01). Writeback is page granular: a successful sync persists every
page a dirty write touched as the page cache holds it (zero past end-of-file),
which makes the uncertain bytes in a re-dirtied page durable; bytes a
successful sync rewrote or truncated never come back. A length change dirties
no page. One whose sync failed may survive a crash until the next successful
sync of the file, after which the model treats it as lost, so a bare retry
cannot be relied on to persist a truncation.

A power loss also kills every process. After `crash*` every lock is released,
and each operation on a file handle opened before it fails with an
`ErrorKind::Other` I/O error (the model's EIO) without changing the recovered
state; dropping such a handle or lock releases nothing of the post-crash world.
A test therefore cannot keep writing through, or syncing, a handle that a real
power loss would have closed. A restart (`drop` + reopen, page cache intact)
invalidates nothing. Simulation is useful
development evidence, not proof that a real filesystem and device stack obeys
the same model.

Install `scripts/campaign_io.py` alongside either the Firecracker or GCE guest agent.
Use host and guest scripts from the same revision for matching block patterns.

The opt-in Firecracker runner boots the same writable data image after each
VMM `SIGKILL`. Its virtio data drive explicitly uses Firecracker `Writeback`
cache semantics and synchronous host I/O, while the root filesystem remains
read-only. A guest running the release Maki nbdkit plugin alternates FLUSH and
FUA. Only complete guest ACK frames are fsynced into the L1 ledger, and the
next boot reads and hashes the acknowledged units without receiving their
expected hashes. This removes the guest kernel and guest page cache from the
next recovery attempt. It does not cut power to the L1 kernel or persistent
disk and therefore is not physical power-loss evidence.

The opt-in GCE reset controller runs outside the disposable workload VM. It
fsyncs each validated ACK to its own ledger, then invokes only
`gcloud compute instances reset`. It requires the old SSH session to die and a
globally new boot ID to appear. The guest systemd `ExecStop` witness must
remain absent.
The guest agent requires Python 3.11 or later and reads the selected TOML
configuration before launching nbdkit. Both reset profiles require
`crypto.provider = "local-aes-gcm-siv"`; an unreadable, invalid, missing-provider,
or different-provider configuration fails before launch. The guest's READY
provider field comes from that validated configuration. These checks bind the
reported provider to configuration; they do not replace binary provenance or
the campaign's native I/O and durability checks.
A single leading UTF-8 BOM is accepted, matching Maki's configuration parser;
invalid UTF-8 or TOML and a different provider still fail before launch.
This removes the workload VM's RAM, kernel, and page cache, while the Persistent
Disk service and physical storage path stay operational. It is whole-VM reset
evidence rather than physical power-loss evidence.

QEMU qualification uses a guest on a dedicated virtual disk, an external
host-side acknowledgement ledger, randomized `virsh destroy` cuts, offline
checking after reboot, and at least 300 successful recovery cycles. Bare-metal
qualification uses a second machine for the ledger and a managed power cut; disk
write-cache behavior must be characterized first.

WSL is suitable for Linux syscall integration but not for power-loss claims.

## Optional random plaintext prefixes

The [prefix wrapper](random-plaintext-prefix.md) has focused provider, config
and daemon suites:

```sh
cargo test -p maki-crypto --test random_prefix --test review_prefix_context_probe
cargo test -p maki-format --test random_prefix_config
cargo test -p maki-nbdkit --test random_prefix --test random_prefix_remote --test random_prefix_admission
```

The tests inspect the actual expanded plaintext, fresh per-unit prefixes,
provider response validation, capabilities and batch sizes, compatibility
gates, authenticated-prefix corruption, partial writes, discard, reopen,
two-endpoint remote operation, and that the attach self-test's context probes
reach the provider and give the same verdict with and without the prefix. They
do not establish a randomness benefit for every possible provider algorithm;
existing nonce and integrity requirements still apply.

## Experimental rollback backing

The [local-witness format](rollback-protection.md) has separate qualification
requirements from default v2/v3 storage. Its focused suites are:

```sh
cargo test -p maki-backing --lib --test rollback_backing --test rollback_model
cargo test -p maki-core --test rollback_protection --test rollback_process
cargo test -p maki-format --test rollback_config
cargo test -p maki-nbdkit --test rollback_config
```

Linux storage fixtures place the backing on the normal temporary filesystem and
the witness in the first of `/dev/shm`, `/run/user/<uid>`, `/var/tmp`, `/tmp`,
`TMPDIR` and `/run` that is on another filesystem (a different device
identity); where there is none, each such test prints that it is skipped and
why, or fails when `MAKI_TEST_REQUIRE_OTHER_FILESYSTEM=1` is set, as CI and the
background runner's `rollback` profile set it. This fixture is deliberately not
a persistent witness deployment. Tests cover old whole-image rejection, page
authentication, immutable predecessor retention, namespace sync boundaries and
open handles, witness failures and reopen durability, full-capacity
acknowledged-write recovery, cache/overlay freshness, concurrent checkpoint/FUA
and v3 discard/rewrite. Fixed SHA-256 encoding vectors cover the witness
record, manifest and page domains.

The file model adds 1,600 deterministic operations against independent working
and durable byte images, plus capacity reuse and unlink/handle-lifetime checks.
The process suite runs eight SIGKILL/reopen cycles, checking every expected
FUA/FLUSH write and discard against acknowledgements recorded by the parent
outside the backing. It covers volatile writes after acknowledged operations
and alternating checkpoint paths; the host page cache remains alive. The
[background runner](background-storage-validation.md) can repeat these suites
unattended with `--profile rollback`, preserving exact source and binary hashes.

Requalify the new mode on independent persistent disks before production use,
including hard resets, a separate ACK ledger, maximum metadata/RSS, latency and
witness storage exhaustion. Earlier GCE/default-format campaigns do not establish
these results for the new format.

## External qualification checklist

Scoped campaigns already cover Debian 12 kernel NBD/LVM/XFS/fio (attached
with nbd-client, before the helper's own connect; CI's `kernel-lifecycle`
job runs the helper's own connect through the same layers on an Ubuntu
runner, and the booted-host jobs in Debian 12 and Rocky Linux 9 KVM guests),
installed
systemd recovery with a Docker SQLite ACK oracle, package install/upgrade,
fresh-host backing restore and SQLite migration. PostgreSQL 15 on Debian 12
and PostgreSQL 17 on Debian 13 passed short crash and packaged lifecycle
scenarios. Reference-provider HTTP/WebSocket/gRPC passed cross-host sandbox
and provider-host reset scenarios. These results and their exact configurations
are recorded [above](#current-qualification-status); they do not qualify every
target environment.

Record the chosen configuration, acceptance thresholds and evidence using the
[deployment qualification profile](deployment/qualification-profile.md).
Before production approval, complete its remaining coverage:

- Requalify kernel `/dev/nbd`, LVM, XFS, raw-device fio, effective capabilities,
  ACLs, core dumps, mounts and service restarts on the selected image/package
  and storage class. Combine the actual daemon, packaged recovery and the
  application's external DB/container ACK oracle; extend the existing Debian
  profiles only where their coverage matches the chosen configuration.
- Validate commercial vendor endpoints with production mapping and credentials,
  including the target network, extended total outages and recovery if a
  provider returns at a changed address. Existing hard-reset evidence covers
  a reference provider returning at the same address after a short outage.
- Repeat the scoped bearer/mTLS-client, server-certificate/private-CA, and
  same-key/profile endpoint-address rotation procedures against the selected
  commercial vendor and target network, including shared-client coordination,
  rollback, and failures at each transition.
- Extend SQLite/PostgreSQL checks to production workload settings, volume
  capacity/fill ratio and backing-space pressure. Qualify other database or
  object-store engines separately if they are selected for deployment.
- Repeat the unchanged-backing fresh-host restore on each supported package and
  distribution, and separately exercise DB-native backup or logical migration
  with credentials protected outside the general backup.
- Repeat GCE reset qualification on the selected deployment image and storage
  class. For stronger storage-failure tiers, run at least 300 QEMU power cuts
  and separately qualify bare-metal power loss with an independent
  acknowledgement ledger and characterized disk write-cache behavior.
- Establish total recovery RSS and memory headroom for the selected geometry,
  provider, cache and database settings using the
  [performance and memory profile](performance.md). The measured
  constrained-recovery profile does not establish a general minimum-memory
  recommendation.
- If using experimental rollback-protected backing, qualify its independent
  persistent witness as described [above](#experimental-rollback-backing).
- Long-duration (24 CPU-hour-per-target) `cargo-fuzz` corpus runs (the
  targets and their seeds are in `fuzz/`, CI runs each for 30 seconds in
  the scheduled tier, and the [fuzz qualification](#fuzz-qualification)
  workflow runs the campaign on hosted runners when dispatched; only short
  runs have been done) and long-duration provider and 72-hour mixed-I/O
  soaks.

These checks are privileged, destructive, externally credentialed, or
long-running. Run them only in explicitly authorized environments.
