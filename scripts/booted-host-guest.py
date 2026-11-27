#!/usr/bin/env python3
"""One phase of CI's booted-host jobs, inside the disposable guest, as root.

    booted-host-guest.py facts|prepare|guides|runner|versions|collect --guest GUEST
    booted-host-guest.py selinux --guest el9 --suite guides|runner

booted-host-validation.py copies this file, with the package and the suite's
payload, to /var/tmp/maki-ci and runs one phase per CI step. Python 3.9 or
later (EL9's python3), standard library only. Each phase prints what it ran
and what it found, and keeps it below /var/tmp/maki-ci/results.

- facts: the guest as booted (release, kernel, virtualization, LSMs, the nbd
  module's file, the LVM devices file, the package inventory). On EL9
  SELinux must be enforcing.
- prepare: stops the package manager's timers, which could hold its lock
  while a guide's step runs, and refreshes the package lists (apt) or the
  metadata (dnf), as on a maintained host. Nothing is installed.
- guides: runs quickstart.sh (the guide's install steps, the quick start and
  the first-volume bootstrap) from /var/tmp/maki-ci/quickstart as root,
  keeps its output in quickstart.log, and then requires that no attach
  record, mount, active unit or NBD connection of the volume remains.
- runner: installs what the privileged runner needs that the guest lacks,
  takes maki, maki-attach and the plugin out of the package without
  installing it, loads nbd as the runner asks, and runs
  scripts/privileged-linux-validation.sh --kill-daemon --prebuilt on
  /dev/nbd15 as the user `ci`, which has passwordless sudo: the runner refuses
  root and calls sudo itself (with --install-missing on Debian, the only
  distribution it installs for).
- selinux (EL9): SELinux still enforcing and auditd active; every AVC or
  SELinux error since boot kept, and one that names Maki or an NBD device
  fails; with the guides
  suite, the domain of maki@demo.service's nbdkit and the labels of the
  installed files must be those the RHEL guide states.
- versions: the kernel and the versions of the packages the guides and the
  runner use.
- collect: packs the results, the quick start's directory without the
  package, the runner's run directory without its source snapshot and
  builds, and the journal into /var/tmp/maki-ci-logs.tar.gz. Neither key
  (/etc/maki/secrets, the runner's work tree) nor a backing nor anything of
  /var/lib/cloud is collected, and a file that holds a private key stops it.

During guides and runner a sampler records, every half second, each nbdkit
or maki* process with its systemd unit and security label
(/proc/PID/attr/current) in results/contexts.jsonl.
"""
import argparse
import glob
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import threading


GUEST_DIRECTORY = Path("/var/tmp/maki-ci")
RESULTS = GUEST_DIRECTORY / "results"
QUICKSTART = GUEST_DIRECTORY / "quickstart"
SOURCE = GUEST_DIRECTORY / "source"
PREBUILT = GUEST_DIRECTORY / "prebuilt"
PACKAGE_ROOT = GUEST_DIRECTORY / "package-root"
ARCHIVE = Path("/var/tmp/maki-ci-logs.tar.gz")
USER = "ci"
RUNNER_DEVICE = "/dev/nbd15"
RUNNER_LOGS = Path("/home") / USER / "logs" / "maki-privileged-validation.latest"
PACKAGES = {"debian12": "maki.deb", "el9": "maki.rpm"}
VOLUME = "demo"
UNITS = (f"maki@{VOLUME}.service", f"maki-attach@{VOLUME}.service",
         f"maki-recover@{VOLUME}.service", f"maki-workload@{VOLUME}.target")
# The binaries the runner takes, from where the package installs them.
PACKAGED_BINARIES = (("usr/bin/maki", "maki", 0o755), ("usr/bin/maki-attach", "maki-attach", 0o755),
                     ("usr/lib/maki/maki-nbdkit.so", "libmaki_nbdkit.so", 0o644))
# What the RHEL guide's SELinux section says the policy gives them.
LABELS = (("/usr/bin/maki", "bin_t"), ("/usr/bin/maki-attach", "bin_t"),
          ("/usr/bin/maki-check", "bin_t"), ("/usr/lib/maki/maki-nbdkit.so", "lib_t"),
          ("/usr/sbin/nbdkit", "bin_t"), ("/etc/maki", "etc_t"), ("/var/lib/maki", "var_lib_t"),
          ("/run/maki", "var_run_t"), ("/run/maki-control", "var_run_t"),
          ("/run/maki-attach", "var_run_t"),
          ("/usr/lib/systemd/system/maki@.service", "systemd_unit_file_t"),
          ("/usr/lib/systemd/system/maki-attach@.service", "systemd_unit_file_t"),
          ("/usr/lib/systemd/system/maki-recover@.service", "systemd_unit_file_t"),
          ("/usr/lib/systemd/system/maki-workload@.target", "systemd_unit_file_t"),
          # The device the quick start attaches.
          ("/dev/nbd0", "fixed_disk_device_t"))
DAEMON_DOMAIN = "unconfined_service_t"
# The runner's tools on EL9, from BaseOS and AppStream: nbdkit-server as the
# RPM requires it (never the nbdkit metapackage), cpio to unpack the RPM.
EL9_RUNNER_PACKAGES = ("git-core", "fio", "libnbd", "nbdkit-server", "binutils", "sqlite",
                       "lvm2", "xfsprogs", "util-linux", "kmod", "cpio", "python3", "sudo")
DEBIAN_RUNNER_PACKAGES = ("git",)
VERSION_PACKAGES = {
    "debian12": ("nbdkit", "lvm2", "xfsprogs", "util-linux", "systemd", "udev", "kmod",
                 "cloud-init", "python3", "maki"),
    "el9": ("nbdkit-server", "lvm2", "xfsprogs", "util-linux", "systemd", "kmod", "cloud-init",
            "python3", "selinux-policy-targeted", "audit", "maki"),
}
DENIAL_TYPES = "AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR"
MAKI_RELATED = re.compile(r"maki|nbd", re.IGNORECASE)


def say(*words):
    print(*words, flush=True)


def record(log, argv, **options):
    """Run `argv`, print and append its output to `log`; return the result."""
    say("$ " + shlex.join(argv))
    try:
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace", **options)
    except FileNotFoundError:
        result = subprocess.CompletedProcess(argv, 127, "", f"{argv[0]}: not found\n")
    text = result.stdout + result.stderr
    if text:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    sys.stdout.write(f"[exit {result.returncode}]\n")
    sys.stdout.flush()
    with open(log, "a", encoding="utf-8") as output:
        output.write(f"$ {shlex.join(argv)}\n{text}[exit {result.returncode}]\n\n")
    return result


def step(argv, **options):
    say("$ " + shlex.join(argv))
    return subprocess.run(argv, **options).returncode


def os_release(path=Path("/etc/os-release")):
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            values[name.strip()] = value.strip().strip('"')
    return values


def guest_of(release):
    """debian12 or el9 for the release os-release describes, else None."""
    version = release.get("VERSION_ID", "")
    if release.get("ID") == "debian" and version == "12":
        return "debian12"
    family = release.get("ID_LIKE", "").split() + [release.get("ID", "")]
    if "rhel" in family and version.split(".")[0] == "9":
        return "el9"
    return None


def require_guest(guest, release=None):
    release = os_release() if release is None else release
    found = guest_of(release)
    if found != guest:
        raise SystemExit(f"this guest is {release.get('PRETTY_NAME', 'unknown')} ({found}), "
                         f"not {guest}")


def auditd_active():
    """Whether auditd runs: without it the kernel's AVC records go to the
    kernel log, and ausearch finds none."""
    try:
        return subprocess.run(["systemctl", "is-active", "--quiet", "auditd"]).returncode == 0
    except OSError:
        return False


def selinux_mode():
    try:
        return subprocess.run(["getenforce"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def inventory(guest, output):
    if guest == "debian12":
        argv = ["dpkg-query", "-W", "-f", "${Package} ${Version} ${Architecture}\n"]
    else:
        argv = ["rpm", "-qa", "--qf", "%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n"]
    listing = subprocess.run(argv, capture_output=True, text=True, check=True).stdout
    output.write_text("".join(sorted(listing.splitlines(keepends=True))), encoding="utf-8")
    say(f"{len(listing.splitlines())} packages listed in {output}")


def facts(guest):
    RESULTS.mkdir(parents=True, exist_ok=True)
    require_guest(guest)
    log = RESULTS / "facts.txt"
    for argv in (["cat", "/etc/os-release"], ["uname", "-a"], ["cat", "/proc/cmdline"],
                 ["systemd-detect-virt"], ["systemctl", "--version"],
                 ["timeout", "60", "systemctl", "is-system-running", "--wait"],
                 ["systemctl", "--failed", "--no-pager"],
                 ["nproc"], ["free", "-m"], ["df", "-h", "/", "/var/tmp"], ["lsblk"],
                 ["cat", "/sys/kernel/security/lsm"], ["modinfo", "-n", "nbd"],
                 ["lvmconfig", "--typeconfig", "full", "devices/use_devicesfile"],
                 ["ls", "-la", "/etc/lvm/devices"]):
        record(log, argv)
    if guest == "el9":
        for argv in (["getenforce"], ["sestatus"], ["rpm", "-q", "selinux-policy-targeted"],
                     ["systemctl", "is-active", "auditd"]):
            record(log, argv)
        module = subprocess.run(["modinfo", "-n", "nbd"], capture_output=True, text=True)
        if module.returncode == 0:
            record(log, ["rpm", "-qf", module.stdout.strip()])
        mode = selinux_mode()
        if mode != "Enforcing":
            raise SystemExit(f"SELinux is {mode}, not Enforcing: the EL9 guest must keep the "
                             "image's enforcing mode")
    inventory(guest, RESULTS / "packages-before.txt")
    return 0


def prepare(guest):
    require_guest(guest)
    if guest == "debian12":
        step(["systemctl", "stop", "apt-daily.timer", "apt-daily-upgrade.timer",
              "apt-daily.service", "apt-daily-upgrade.service", "unattended-upgrades.service"])
        # apt-get update otherwise exits 0 when an index could not be fetched.
        return step(["apt-get", "-o", "DPkg::Lock::Timeout=600", "update", "-q", "--error-on=any"])
    step(["systemctl", "stop", "dnf-makecache.timer", "dnf-makecache.service"])
    return step(["dnf", "-q", "makecache"])


class Sampler(threading.Thread):
    """Records each nbdkit or maki* process's unit and label once."""

    def __init__(self, output, proc=Path("/proc"), interval=0.5):
        super().__init__(daemon=True)
        self.output, self.proc, self.interval = output, proc, interval
        self.done = threading.Event()
        self.seen = set()

    def sample(self):
        found = []
        for entry in self.proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
                if comm != "nbdkit" and not comm.startswith("maki"):
                    continue
                cgroup = (entry / "cgroup").read_text(encoding="utf-8", errors="replace")
                label = (entry / "attr" / "current").read_bytes().rstrip(b"\0\n").decode(
                    "utf-8", "replace")
                arguments = (entry / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue
            unit = unit_of(cgroup)
            key = (comm, unit, label)
            if key in self.seen:
                continue
            self.seen.add(key)
            found.append({"pid": int(entry.name), "comm": comm, "unit": unit, "label": label,
                          "args": " ".join(part.decode("utf-8", "replace")
                                           for part in arguments if part)[:300]})
        if found:
            with open(self.output, "a", encoding="utf-8") as output:
                for sample in found:
                    output.write(json.dumps(sample, sort_keys=True) + "\n")
        return found

    def run(self):
        while True:
            self.sample()
            if self.done.wait(self.interval):
                return

    def finish(self):
        self.done.set()
        self.join(10)


def unit_of(cgroup):
    """The last component of the process's cgroup v2 path (its unit or scope)."""
    for line in cgroup.splitlines():
        if line.startswith("0::"):
            return line[3:].rstrip("/").rsplit("/", 1)[-1]
    return ""


def tee(argv, log, cwd):
    """Run `argv`, copying its output to stdout and to `log`; return its status."""
    say("$ " + shlex.join(argv))
    with open(log, "w", encoding="utf-8") as output:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, errors="replace")
        for line in process.stdout:
            sys.stdout.write(line)
            output.write(line)
        sys.stdout.flush()
        return process.wait()


def leftovers(root=Path("/"), findmnt="findmnt", systemctl="systemctl"):
    """What a finished quick start must not leave behind."""
    left = []
    record_path = root / "run" / "maki-attach" / f"{VOLUME}.nbd"
    if record_path.exists() or record_path.is_symlink():
        left.append(f"the attach record {record_path}")
    if subprocess.run([findmnt, f"/srv/{VOLUME}"], capture_output=True).returncode == 0:
        left.append(f"a mount at /srv/{VOLUME}")
    for unit in UNITS:
        state = subprocess.run([systemctl, "show", "-P", "ActiveState", unit], capture_output=True,
                               text=True).stdout.strip()
        if state != "inactive":
            left.append(f"{unit} is {state or 'unknown'}")
    for attribute in sorted(glob.glob(str(root / "sys" / "block" / "nbd*" / "backend"))):
        try:
            backend = Path(attribute).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if backend:
            left.append(f"{attribute} shows a connection: {backend}")
    return left


def guides(guest):
    require_guest(guest)
    RESULTS.mkdir(parents=True, exist_ok=True)
    package = QUICKSTART / PACKAGES[guest]
    for needed in (QUICKSTART / "quickstart.sh", QUICKSTART / "demo.toml", package):
        if not needed.is_file():
            raise SystemExit(f"{needed} is missing from the payload")
    sampler = Sampler(RESULTS / "contexts.jsonl")
    sampler.start()
    try:
        status = tee(["bash", "quickstart.sh"], QUICKSTART / "quickstart.log", QUICKSTART)
    finally:
        sampler.finish()
    if status != 0:
        say(f"the documented program stopped with status {status}")
        return status
    left = leftovers()
    for item in left:
        say(f"left behind: {item}")
    return 1 if left else 0


def extract_package(guest, package, root):
    """The package's files below `root`, without installing it."""
    root.mkdir(parents=True)
    if guest == "debian12":
        return step(["dpkg-deb", "-x", str(package), str(root)])
    unpacked = subprocess.Popen(["rpm2cpio", str(package)], stdout=subprocess.PIPE)
    status = step(["cpio", "-idm", "--quiet"], stdin=unpacked.stdout, cwd=root)
    unpacked.stdout.close()
    return unpacked.wait() or status


def prebuilt_from(root, prebuilt):
    """The runner's --prebuilt layout, from the package's files."""
    prebuilt.mkdir(mode=0o755)
    for source, name, mode in PACKAGED_BINARIES:
        data = (root / source).read_bytes()
        target = prebuilt / name
        target.write_bytes(data)
        target.chmod(mode)
        say(f"{target} from the package's /{source}")
    return prebuilt


def runner_command(guest):
    command = [str(SOURCE / "scripts" / "privileged-linux-validation.sh")]
    if guest == "debian12":
        command.append("--install-missing")
    command += ["--kill-daemon", "--prebuilt", str(PREBUILT), "--device", RUNNER_DEVICE,
                "--confirm-wipe", RUNNER_DEVICE]
    return ["sudo", "-u", USER, "-H", "--", *command]


def runner(guest):
    require_guest(guest)
    RESULTS.mkdir(parents=True, exist_ok=True)
    if guest == "debian12":
        status = step(["apt-get", "-o", "DPkg::Lock::Timeout=600", "install", "-y", "-q",
                       "--no-install-recommends", *DEBIAN_RUNNER_PACKAGES],
                      env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
    else:
        status = step(["dnf", "install", "-y", "-q", "--setopt=install_weak_deps=False",
                       *EL9_RUNNER_PACKAGES])
    if status != 0:
        raise SystemExit(f"installing the runner's tools failed (status {status})")
    if extract_package(guest, GUEST_DIRECTORY / PACKAGES[guest], PACKAGE_ROOT) != 0:
        raise SystemExit("unpacking the package failed")
    prebuilt_from(PACKAGE_ROOT, PREBUILT)
    # As the kernel-lifecycle job does: the runner's own modprobe then finds
    # the module loaded as it asks for it.
    if step(["modprobe", "nbd", "nbds_max=16", "max_part=8"]) != 0:
        raise SystemExit("the nbd module did not load")
    if not Path(RUNNER_DEVICE).is_block_device():
        raise SystemExit(f"{RUNNER_DEVICE} is missing after loading nbd")
    sampler = Sampler(RESULTS / "contexts.jsonl")
    sampler.start()
    try:
        status = step(runner_command(guest), cwd=SOURCE)
    finally:
        sampler.finish()
    say(f"the privileged runner exited with status {status}")
    return status


def label_type(path):
    try:
        label = os.getxattr(path, "security.selinux", follow_symlinks=False)
    except OSError as error:
        return f"(unreadable: {error.strerror})"
    parts = label.rstrip(b"\0").decode("utf-8", "replace").split(":")
    return parts[2] if len(parts) > 2 else ":".join(parts)


def denials(text):
    """The ausearch records of `text`, and those that name Maki or NBD."""
    records = [part.strip() for part in re.split(r"(?m)^----$", text) if part.strip()]
    return records, [part for part in records if MAKI_RELATED.search(part)]


def domain_verdict(samples, unit=f"maki@{VOLUME}.service"):
    """(problems, observed contexts) for the nbdkit processes of `unit`."""
    contexts = sorted({sample["label"] for sample in samples
                       if sample.get("unit") == unit and sample.get("comm") == "nbdkit"})
    if not contexts:
        return [f"no nbdkit process of {unit} was sampled"], contexts
    problems = [f"{unit}'s nbdkit ran as {context}, not in {DAEMON_DOMAIN}"
                for context in contexts if context.split(":")[2:3] != [DAEMON_DOMAIN]]
    return problems, contexts


def read_samples(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def selinux(guest, suite, labels=LABELS, search=None):
    require_guest(guest)
    if guest != "el9":
        raise SystemExit("the SELinux phase is for the EL9 guest")
    RESULTS.mkdir(parents=True, exist_ok=True)
    log = RESULTS / "selinux-commands.txt"
    report, problems = [], []
    mode = selinux_mode()
    report.append(f"getenforce: {mode}")
    if mode != "Enforcing":
        problems.append(f"SELinux is {mode}, not Enforcing")
    record(log, ["sestatus"])
    if auditd_active():
        report.append("auditd: active")
    else:
        report.append("auditd: not active")
        problems.append("auditd is not active: AVC records go to the kernel log, and ausearch "
                        "would find none")
    policy = record(log, ["rpm", "-q", "selinux-policy-targeted"]).stdout.strip()
    report.append(f"policy: {policy}")
    found = record(log, ["ausearch", "-m", DENIAL_TYPES, "-ts", "boot", "-i"]) if search is None \
        else search()
    text = found.stdout
    if found.returncode not in (0, 1) or (found.returncode == 1 and "<no matches>" not in found.stderr):
        problems.append(f"ausearch failed (status {found.returncode}): {found.stderr.strip()}")
    (RESULTS / "avc.txt").write_text(text, encoding="utf-8")
    records, related = denials(text)
    report.append(f"AVC and SELinux error records since boot: {len(records)}; "
                  f"naming Maki or NBD: {len(related)} (all kept in avc.txt)")
    problems += [f"a denial names Maki or NBD:\n{item}" for item in related]
    samples = read_samples(RESULTS / "contexts.jsonl")
    for sample in samples:
        report.append(f"process {sample['comm']} in {sample['unit'] or '?'}: {sample['label']}")
    if suite == "guides":
        domain_problems, contexts = domain_verdict(samples)
        problems += domain_problems
        if contexts and not domain_problems:
            report.append(f"maki@{VOLUME}.service ran in {DAEMON_DOMAIN}: unconfined by SELinux, "
                          "as the RHEL guide says")
        for path, expected in labels:
            actual = label_type(path)
            report.append(f"label {path}: {actual} (guide: {expected})")
            if actual != expected:
                problems.append(f"{path} is labelled {actual}, not {expected} as the guide says")
    (RESULTS / "selinux.txt").write_text("\n".join(report + [f"PROBLEM: {item}" for item in problems])
                                         + "\n", encoding="utf-8")
    for line in report:
        say(line)
    for item in problems:
        say(f"PROBLEM: {item}")
    return 1 if problems else 0


def versions(guest):
    require_guest(guest)
    RESULTS.mkdir(parents=True, exist_ok=True)
    log = RESULTS / "versions.txt"
    if log.exists():
        log.unlink()
    release = os_release()
    with open(log, "a", encoding="utf-8") as output:
        output.write(f"release: {release.get('PRETTY_NAME', '?')}\n")
    say(f"release: {release.get('PRETTY_NAME', '?')}")
    record(log, ["uname", "-srvm"])
    kernel = os.uname().release
    if guest == "debian12":
        record(log, ["dpkg-query", "-W", "-f", "${db:Status-Abbrev} ${Package} ${Version}\n",
                     f"linux-image-{kernel}", *VERSION_PACKAGES[guest]])
    else:
        record(log, ["rpm", "-qf", f"/lib/modules/{kernel}/vmlinuz"])
        record(log, ["rpm", "-q", *VERSION_PACKAGES[guest]])
    # The suites install LVM; what its devices file then is decides which
    # devices LVM commands without --devices see.
    for argv in (["nbdkit", "--version"], ["lvm", "version"], ["mkfs.xfs", "-V"],
                 ["systemctl", "--version"], ["python3", "--version"],
                 ["lvmconfig", "--typeconfig", "full", "devices/use_devicesfile"],
                 ["ls", "-la", "/etc/lvm/devices"]):
        record(log, argv, env=dict(os.environ, LVM_SUPPRESS_FD_WARNINGS="1"))
    inventory(guest, RESULTS / "packages-after.txt")
    return 0


def excluded(name, *prefixes):
    return any(name == prefix or name.startswith(prefix + "/") for prefix in prefixes)


PRIVATE_KEY = b"PRIVATE KEY-----"


def pack(archive, members):
    """Write `archive` from (path, name in archive, excluded names) triples.
    A file that holds a private key (a PEM or OpenSSH armour line) stops the
    packing, and no archive is left: the logs must never carry one."""
    try:
        with tarfile.open(archive, "w:gz") as output:
            for path, arcname, leave_out in members:
                if not path.exists():
                    continue

                def keep(info, path=path, leave_out=leave_out, arcname=arcname):
                    relative = info.name[len(arcname):].lstrip("/")
                    if relative and excluded(relative, *leave_out):
                        return None
                    source = path / relative if relative else path
                    if info.isfile() and PRIVATE_KEY in source.read_bytes():
                        raise SystemExit(f"{source} holds a private key: refusing to collect it")
                    return info

                output.add(str(path), arcname=arcname, filter=keep)
    except BaseException:
        if archive.exists():
            archive.unlink()
        raise
    archive.chmod(0o644)


def collect_members():
    """What collect packs: the results, the quick start's directory without
    the package, cloud-init's and the audit logs and the runner's run
    directory without its snapshot and builds. Nothing under /var/lib/cloud
    (whose copy of the seed's user-data holds the host key), /etc/maki or
    /var/lib/maki, and not the runner's work tree."""
    members = [(RESULTS, "results", ()),
               (QUICKSTART, "quickstart", ("maki.deb", "maki.rpm")),
               (Path("/var/log/cloud-init.log"), "logs/cloud-init.log", ()),
               (Path("/var/log/cloud-init-output.log"), "logs/cloud-init-output.log", ()),
               (Path("/var/log/audit/audit.log"), "logs/audit.log", ())]
    if RUNNER_LOGS.exists():
        members.append((RUNNER_LOGS.resolve(), "privileged-run", ("source", "target", "build")))
    return members


def collect(guest):
    RESULTS.mkdir(parents=True, exist_ok=True)
    journal = RESULTS / "journal"
    journal.mkdir(exist_ok=True)
    for name, argv in (("journal.log", ["journalctl", "-b", "--no-pager", "-o", "short-monotonic"]),
                       ("kernel.log", ["journalctl", "-b", "--no-pager", "-o", "short-monotonic", "-k"]),
                       ("maki-units.log", ["journalctl", "-b", "--no-pager", "-o", "short-monotonic",
                                           "-u", "maki*"])):
        with open(journal / name, "w", encoding="utf-8") as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT)
    pack(ARCHIVE, collect_members())
    say(f"packed {ARCHIVE} ({ARCHIVE.stat().st_size} bytes)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("phase", choices=("facts", "prepare", "guides", "runner", "selinux",
                                          "versions", "collect"))
    parser.add_argument("--guest", choices=sorted(PACKAGES), required=True)
    parser.add_argument("--suite", choices=("guides", "runner"))
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        raise SystemExit("run this phase as root (through sudo)")
    if args.phase == "selinux":
        if args.suite is None:
            parser.error("selinux needs --suite")
        return selinux(args.guest, args.suite)
    return {"facts": facts, "prepare": prepare, "guides": guides, "runner": runner,
            "versions": versions, "collect": collect}[args.phase](args.guest)


if __name__ == "__main__":
    sys.exit(main())
