#!/usr/bin/env python3
"""Boot a disposable Debian 12 or EL9 cloud image under QEMU and run commands
in it over SSH: the host side of CI's booted-host jobs.

    booted-host-validation.py image-key --guest GUEST
    booted-host-validation.py fetch --guest GUEST --directory IMAGES
    booted-host-validation.py payload --guest GUEST --suite SUITE \\
        --package PACKAGE_DIRECTORY --output PAYLOAD
    booted-host-validation.py boot --guest GUEST --images IMAGES --work WORK
    booted-host-validation.py copy-in --work WORK [--timeout SECONDS] PAYLOAD
    booted-host-validation.py run --work WORK [--timeout SECONDS] [--root] -- COMMAND...
    booted-host-validation.py finish --work WORK --output LOGS

`image-key` prints the actions/cache key of the guest's image (its pinned name
and digest). `fetch` downloads the guest's pinned cloud image and refuses one
whose digest is not the pinned one; an image already in IMAGES (restored from
that cache) is checked the same way and downloaded again if it differs. `payload` checks the package directory a package job
uploaded (its SHA256SUMS, and that its source-revision is this checkout's
HEAD) and assembles what the guest receives: the guest script, the package
and, for the `guides` suite, the program `documented_quickstart.py` writes
from the guides, or, for the `runner` suite, a clone of HEAD for the
privileged runner. `boot` makes a copy-on-write disk over the image, which is
never written, and a cloud-init NoCloud seed that creates the user `ci`
(passwordless sudo, key login only, no password) and pins the guest's SSH
host key; it starts QEMU in the background with KVM, the serial console in
WORK/console.log and SSH forwarded from 127.0.0.1 only, and waits for SSH and
for cloud-init to finish. `copy-in` unpacks PAYLOAD into /var/tmp/maki-ci in
the guest. `run` runs COMMAND in the guest as `ci`, or with `--root` as root
through sudo, under `timeout` (inside sudo with `--root`), and gives up on the
connection a little later than that limit. `finish` asks the guest
to pack its logs (booted-host-guest.py collect), copies them out, powers the
guest off (killing QEMU if it does not stop) and copies the console log,
never the keys, the seed or the disks.

Every external command is named on its own line before it runs. The guest
runs on GitHub's hardware as a KVM virtual machine: it is a booted host with
its own kernel, systemd, udev and SELinux, not a bare-metal one.
"""
import argparse
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import time


@dataclass(frozen=True)
class Guest:
    name: str
    title: str
    image: str
    urls: tuple
    algorithm: str
    digest: str
    package: str
    installation: str


# Debian keeps every dated build of its cloud images; the generic image runs
# Debian's standard kernel (genericcloud runs the cloud kernel, which leaves
# drivers out). Rocky Linux rebuilds RHEL's sources unchanged and keeps a
# minor release's current image under pub/ and the last one in the vault
# once the next minor release is out.
GUESTS = {
    "debian12": Guest(
        name="debian12",
        title="Debian 12 (bookworm) generic cloud image 20261112-2660",
        image="debian-12-generic-amd64-20261112-2660.qcow2",
        urls=("https://cloud.debian.org/images/cloud/bookworm/20261112-2660/"
              "debian-12-generic-amd64-20261112-2660.qcow2",),
        algorithm="sha512",
        digest="ef4e6f3302cf7951f869e8e01263ee9ab69661b67dc28d45d76eb317b81cf7f8"
               "7a75f85f26a3b30cbb772025f2edc27dee4f640f91d4cb3f4afe7662b6362e2a",
        package="maki.deb",
        installation="debian",
    ),
    "el9": Guest(
        name="el9",
        title="Rocky Linux 9.9 GenericCloud Base image 20261112.0",
        image="Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2",
        urls=("https://dl.rockylinux.org/pub/rocky/9.9/images/x86_64/"
              "Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2",
              "https://dl.rockylinux.org/vault/rocky/9.9/images/x86_64/"
              "Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2"),
        algorithm="sha256",
        digest="4f88f4209de50813d8054ab97309e7169a580206a0c4ea04f375d36c4846d50e",
        package="maki.rpm",
        installation="rhel",
    ),
}
SUITES = ("guides", "runner")
USER = "ci"
GUEST_DIRECTORY = "/var/tmp/maki-ci"
GUEST_ARCHIVE = "/var/tmp/maki-ci-logs.tar.gz"
GUEST_SCRIPT = Path(__file__).with_name("booted-host-guest.py")
QUICKSTART_WRITER = Path(__file__).with_name("documented_quickstart.py")
STATE = "guest.json"
# How much longer than a command's own limit in the guest the connection may
# take before the host gives up on it.
CONNECTION_MARGIN = 90
# What `finish` copies from the work directory: never the keys, the seed
# (whose user-data holds the host key) or the disks.
HOST_LOGS = ("console.log", "qemu.log", STATE)


def say(*words):
    print(*words, flush=True)


def command_line(argv):
    say("$ " + shlex.join(str(word) for word in argv))


def checked(argv, **options):
    command_line(argv)
    return subprocess.run([str(word) for word in argv], check=True, **options)


def file_digest(path, algorithm):
    digest = hashlib.new(algorithm)
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def cache_key(guest):
    """The actions/cache key of the guest's image: its pinned name and digest,
    so that no other pin's image is ever restored for it."""
    return f"booted-host-image-{guest.image}-{guest.algorithm}-{guest.digest}"


def fetch(guest, directory):
    """Download the guest's pinned image into `directory` and return its path.
    An image already there (restored from the cache) is used only if it has
    the pinned digest, and replaced otherwise."""
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / guest.image
    partial = directory / (guest.image + ".partial")
    if target.exists():
        actual = file_digest(target, guest.algorithm)
        if actual == guest.digest:
            say(f"image: {guest.title}")
            say(f"file: {guest.image} ({target.stat().st_size} bytes), already here (restored from the cache)")
            say(f"{guest.algorithm}: {actual} (the pinned digest)")
            return target
        say(f"{target} has {guest.algorithm} {actual}, not the pinned {guest.digest}: downloading it again")
        target.unlink()
    failures = []
    for url in guest.urls:
        if partial.exists():
            partial.unlink()
        argv = ["curl", "--fail", "--location", "--silent", "--show-error", "--retry", "3",
                "--connect-timeout", "30", "--speed-limit", "100000", "--speed-time", "60",
                "--output", partial, url]
        command_line(argv)
        status = subprocess.run([str(word) for word in argv]).returncode
        if status != 0:
            failures.append(f"{url}: curl exited with status {status}")
            continue
        actual = file_digest(partial, guest.algorithm)
        if actual != guest.digest:
            partial.unlink()
            raise SystemExit(f"{url} has {guest.algorithm} {actual}, not the pinned "
                             f"{guest.digest}: refusing it")
        partial.rename(target)
        say(f"image: {guest.title}")
        say(f"file: {guest.image} ({target.stat().st_size} bytes)")
        say(f"url: {url}")
        say(f"{guest.algorithm}: {actual} (the pinned digest)")
        return target
    raise SystemExit(f"could not download {guest.image}: " + "; ".join(failures) +
                     ". The pinned image may have been removed upstream: pin the current one "
                     "(name and digest) in GUESTS in scripts/booted-host-validation.py.")


def load_quickstart_writer():
    spec = importlib.util.spec_from_file_location("documented_quickstart", QUICKSTART_WRITER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def head_revision(checkout):
    return subprocess.run(["git", "-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"],
                          check=True, capture_output=True, text=True).stdout.strip()


def check_package(guest, package_directory, checkout):
    """The package job's artifact: its checksums hold and it was built from
    this checkout's HEAD."""
    sums = package_directory / "SHA256SUMS"
    listed = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        listed[name.lstrip("*")] = digest
    for name in (guest.package, "source-revision"):
        if name not in listed:
            raise SystemExit(f"{sums} does not list {name}")
    for name, digest in sorted(listed.items()):
        actual = file_digest(package_directory / name, "sha256")
        if actual != digest:
            raise SystemExit(f"{package_directory / name} has sha256 {actual}, "
                             f"not {digest} as SHA256SUMS lists")
        say(f"{name}: sha256 {actual}")
    built = (package_directory / "source-revision").read_text(encoding="utf-8").strip()
    head = head_revision(checkout)
    if built != head:
        raise SystemExit(f"the package was built from {built}, not from this checkout's {head}")
    say(f"built from {built}, this checkout's HEAD")
    return package_directory / guest.package


def payload(guest, suite, package_directory, output, checkout):
    """Assemble what the guest receives in /var/tmp/maki-ci."""
    package = check_package(guest, package_directory, checkout)
    output.mkdir(parents=True, exist_ok=False)
    shutil.copy2(GUEST_SCRIPT, output / GUEST_SCRIPT.name)
    if suite == "guides":
        quickstart = output / "quickstart"
        writer = load_quickstart_writer()
        say(f"writing the {guest.installation} guide's program to {quickstart}")
        if writer.main(["--installation", guest.installation, str(quickstart)]) != 0:
            raise SystemExit("documented_quickstart.py failed")
        # The guide installs the package from the directory the program runs in.
        shutil.copy2(package, quickstart / guest.package)
    else:
        source = output / "source"
        checked(["git", "-c", "advice.detachedHead=false", "clone", "--quiet", "--no-local",
                 "--depth", "1", f"file://{checkout.resolve()}", source])
        if head_revision(source) != head_revision(checkout):
            raise SystemExit(f"the clone in {source} is not at this checkout's HEAD")
        shutil.copy2(package, output / guest.package)
    (output / "source-revision").write_text(head_revision(checkout) + "\n", encoding="utf-8")
    return output


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def user_data(user_key, host_private, host_public):
    indented = "".join(f"      {line}\n" for line in host_private.splitlines())
    return f"""#cloud-config
users:
  - name: {USER}
    gecos: Maki CI
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - {user_key}
disable_root: true
ssh_pwauth: false
ssh_deletekeys: true
ssh_keys:
  ed25519_private: |
{indented}  ed25519_public: {host_public}
"""


def meta_data(guest):
    return f"instance-id: maki-ci-{guest.name}-{os.getpid()}\nlocal-hostname: maki-ci-{guest.name}\n"


def qemu_command(work, port, accel, cpus, memory):
    for path in (work,):
        if "," in str(path):
            raise SystemExit(f"QEMU cannot take a path with a comma: {path}")
    return ["qemu-system-x86_64", "-name", "maki-ci-guest",
            "-machine", f"q35,accel={accel}", "-cpu", "host" if accel == "kvm" else "max",
            "-smp", str(cpus), "-m", str(memory),
            "-drive", f"file={work / 'disk.qcow2'},if=virtio,format=qcow2",
            "-drive", f"file={work / 'seed.iso'},if=virtio,format=raw,readonly=on",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
            "-device", "virtio-net-pci,netdev=net0,romfile=",
            "-device", "virtio-rng-pci",
            "-display", "none", "-monitor", "none", "-serial", f"file:{work / 'console.log'}",
            "-no-reboot", "-daemonize", "-pidfile", str(work / "qemu.pid")]


def read_state(work):
    return json.loads((work / STATE).read_text(encoding="utf-8"))


def ssh_command(work, remote, connect_timeout=10):
    state = read_state(work)
    return ["ssh", "-F", "none", "-p", str(state["port"]), "-i", str(work / "id_ed25519"),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={work / 'known_hosts'}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", "HostKeyAlgorithms=ssh-ed25519",
            "-o", f"ConnectTimeout={connect_timeout}", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=8", "-o", "LogLevel=ERROR",
            f"{USER}@127.0.0.1", "--", remote]


def qemu_pid(work):
    try:
        return int((work / "qemu.pid").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None


def alive(pid):
    """Whether `pid` runs; a zombie that nothing has reaped yet does not."""
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return True
    return stat.rsplit(")", 1)[-1].split()[:1] != ["Z"]


def console_tail(work, lines=80):
    try:
        text = (work / "console.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(no console log)"
    return "\n".join(text.splitlines()[-lines:])


def boot(guest, images, work, *, accel="kvm", cpus=2, memory=4096, disk_size="30G",
         timeout=900, interval=5.0, clock=time.monotonic, sleep=time.sleep):
    """Start the guest and return once SSH answers and cloud-init is done."""
    image = (images / guest.image).resolve()
    if not image.is_file():
        raise SystemExit(f"{image} is missing: run fetch first")
    if accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise SystemExit("/dev/kvm is missing or not open to this user: the guest needs KVM "
                         "(only a local trial may pass --accel tcg)")
    work.mkdir(parents=True)
    deadline = clock() + timeout
    for name in ("id_ed25519", "host_ed25519"):
        checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"maki-ci-{name}",
                 "-f", work / name])
    user_key = (work / "id_ed25519.pub").read_text(encoding="ascii").strip()
    host_public = (work / "host_ed25519.pub").read_text(encoding="ascii").strip()
    host_private = (work / "host_ed25519").read_text(encoding="ascii")
    port = free_port()
    (work / "known_hosts").write_text(f"[127.0.0.1]:{port} {host_public}\n", encoding="ascii")
    seed = work / "seed"
    seed.mkdir()
    (seed / "user-data").write_text(user_data(user_key, host_private, host_public), encoding="utf-8")
    (seed / "meta-data").write_text(meta_data(guest), encoding="utf-8")
    checked(["genisoimage", "-quiet", "-output", work / "seed.iso", "-volid", "cidata",
             "-joliet", "-rock", seed / "user-data", seed / "meta-data"])
    # A copy-on-write layer: the downloaded image is never written.
    checked(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image,
             work / "disk.qcow2", disk_size])
    state = {"guest": guest.name, "image": guest.image, "port": port, "accel": accel,
             "cpus": cpus, "memory_mib": memory, "disk": disk_size}
    (work / STATE).write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    argv = qemu_command(work, port, accel, cpus, memory)
    command_line(argv)
    with open(work / "qemu.log", "w", encoding="utf-8") as log:
        started = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT)
    if started.returncode != 0:
        raise SystemExit(f"QEMU did not start (status {started.returncode}):\n"
                         + (work / "qemu.log").read_text(encoding="utf-8", errors="replace"))
    say(f"QEMU started (PID {qemu_pid(work)}); waiting up to {timeout} s for SSH on 127.0.0.1:{port}")
    began = clock()
    while True:
        if not alive(qemu_pid(work)):
            raise SystemExit("QEMU exited before SSH answered; the console's last lines:\n"
                             + console_tail(work))
        remaining = deadline - clock()
        if remaining <= 0:
            raise SystemExit(f"SSH did not answer within {timeout} s; the console's last lines:\n"
                             + console_tail(work))
        probe = subprocess.run(ssh_command(work, "true"), capture_output=True, text=True,
                               timeout=max(30, min(remaining, 60)))
        if probe.returncode == 0:
            break
        sleep(interval)
    say(f"SSH answered after {clock() - began:.0f} s")
    # cloud-init restarts sshd after it has applied ssh_pwauth, so a
    # connection can drop (255) before it is done: ask again until the
    # deadline. 0 is done; 2 is done with recoverable errors (cloud-init 23.4
    # and later), which the long status names.
    while True:
        remaining = int(deadline - clock())
        if remaining <= 0:
            raise SystemExit(f"cloud-init did not finish within {timeout} s; the console's "
                             "last lines:\n" + console_tail(work))
        waited = run(work, ["cloud-init", "status", "--wait", "--long"], timeout=remaining)
        if waited != 255:
            break
        if not alive(qemu_pid(work)):
            raise SystemExit("QEMU exited while cloud-init ran; the console's last lines:\n"
                             + console_tail(work))
        sleep(interval)
    if waited not in (0, 2):
        raise SystemExit(f"cloud-init did not finish cleanly (status {waited})")
    say(f"the guest is up after {clock() - began:.0f} s")
    return state


def run(work, command, timeout=600, root=False):
    """Run `command` in the guest as the CI user, or as root through sudo with
    `root`; return its status. With `root` the time limit runs inside sudo:
    there `timeout` signals the command's whole process group, root children
    included, where as the CI user it could not signal the phase's root
    processes."""
    limit = ["timeout", "--kill-after=30", str(int(timeout))]
    remote = shlex.join(["sudo", *limit, *command] if root else [*limit, *command])
    argv = ssh_command(work, remote)
    say("guest$ " + shlex.join(command))
    try:
        status = subprocess.run(argv, timeout=timeout + CONNECTION_MARGIN).returncode
    except subprocess.TimeoutExpired:
        say(f"the guest did not answer within {timeout + CONNECTION_MARGIN} s; "
            "gave up on the connection")
        return 124
    if status == 124:
        say(f"the command ran out of its {timeout} s in the guest")
    elif status == 255:
        say("ssh failed (status 255): the guest is unreachable or the connection broke")
    return status


def copy_in(work, source, timeout=300):
    """Unpack the directory `source` into the guest's /var/tmp/maki-ci,
    giving up after `timeout` seconds."""
    remote = (f"mkdir -p {GUEST_DIRECTORY} && chmod 0755 {GUEST_DIRECTORY} && "
              f"tar -C {GUEST_DIRECTORY} -xf -")
    say(f"copying {source} into the guest's {GUEST_DIRECTORY}")
    pack = subprocess.Popen(["tar", "-C", str(source), "-cf", "-", "."], stdout=subprocess.PIPE)
    try:
        status = subprocess.run(ssh_command(work, remote), stdin=pack.stdout, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        pack.kill()
        raise SystemExit(f"copying {source} into the guest did not finish within {timeout} s")
    finally:
        pack.stdout.close()
        packed = pack.wait()
    if packed != 0 or status != 0:
        raise SystemExit(f"copying {source} into the guest failed (tar {packed}, ssh {status})")


def copy_out(work, remote, local, timeout=180):
    say(f"copying the guest's {remote} to {local}")
    try:
        with open(local, "wb") as output:
            status = subprocess.run(ssh_command(work, shlex.join(["cat", "--", remote])),
                                    stdout=output, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        status = 124
    if status != 0:
        Path(local).unlink()
    return status


def stop(work, timeout=180, clock=time.monotonic, sleep=time.sleep):
    """Power the guest off; kill QEMU if it does not stop within `timeout`."""
    pid = qemu_pid(work)
    if not alive(pid):
        say("QEMU is not running")
        return True
    # The connection drops as the guest goes down: its status says nothing.
    run(work, ["systemctl", "poweroff"], timeout=30, root=True)
    deadline = clock() + timeout
    while alive(pid) and clock() < deadline:
        sleep(1)
    if not alive(pid):
        say("the guest powered off")
        return True
    say(f"the guest did not power off within {timeout} s: killing QEMU (PID {pid})")
    os.kill(pid, 15)
    for _ in range(20):
        if not alive(pid):
            return False
        time.sleep(0.5)
    os.kill(pid, 9)
    return False


def finish(work, output):
    """Collect the guest's logs and the console, and stop the guest. Every
    part is tried; the status is nonzero when one of them failed."""
    output.mkdir(parents=True, exist_ok=True)
    failed = []
    if (work / STATE).exists() and alive(qemu_pid(work)):
        if run(work, ["python3", "-B", f"{GUEST_DIRECTORY}/booted-host-guest.py",
                      "collect", "--guest", read_state(work)["guest"]], timeout=240, root=True) != 0:
            failed.append("the guest's collect phase")
        if copy_out(work, GUEST_ARCHIVE, output / "guest.tar.gz") != 0:
            failed.append("copying the guest's logs out")
        if not stop(work, timeout=120):
            failed.append("a clean power-off")
    else:
        failed.append("the guest's logs (the guest is not running)")
    for name in HOST_LOGS:
        if (work / name).exists():
            shutil.copy2(work / name, output / name)
    say("::group::guest console (last 200 lines)")
    say(console_tail(work, 200))
    say("::endgroup::")
    for name in sorted(path.name for path in output.iterdir()):
        say(f"kept {name}")
    if failed:
        say("not kept or not done: " + ", ".join(failed))
        return 1
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    keying = commands.add_parser("image-key")
    keying.add_argument("--guest", choices=sorted(GUESTS), required=True)
    fetching = commands.add_parser("fetch")
    fetching.add_argument("--guest", choices=sorted(GUESTS), required=True)
    fetching.add_argument("--directory", type=Path, required=True)
    assembling = commands.add_parser("payload")
    assembling.add_argument("--guest", choices=sorted(GUESTS), required=True)
    assembling.add_argument("--suite", choices=SUITES, required=True)
    assembling.add_argument("--package", type=Path, required=True)
    assembling.add_argument("--output", type=Path, required=True)
    booting = commands.add_parser("boot")
    booting.add_argument("--guest", choices=sorted(GUESTS), required=True)
    booting.add_argument("--images", type=Path, required=True)
    booting.add_argument("--work", type=Path, required=True)
    booting.add_argument("--accel", choices=("kvm", "tcg"), default="kvm",
                         help="kvm (the default, and CI's); tcg only for a local trial")
    booting.add_argument("--timeout", type=int, default=900)
    copying = commands.add_parser("copy-in")
    copying.add_argument("--work", type=Path, required=True)
    copying.add_argument("--timeout", type=int, default=300)
    copying.add_argument("source", type=Path)
    running = commands.add_parser("run")
    running.add_argument("--work", type=Path, required=True)
    running.add_argument("--timeout", type=int, default=600)
    running.add_argument("--root", action="store_true",
                         help="run COMMAND as root through sudo, with its time limit inside sudo")
    running.add_argument("guest_command", nargs=argparse.REMAINDER)
    finishing = commands.add_parser("finish")
    finishing.add_argument("--work", type=Path, required=True)
    finishing.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "image-key":
        # For $GITHUB_OUTPUT.
        print(f"key={cache_key(GUESTS[args.guest])}")
    elif args.command == "fetch":
        fetch(GUESTS[args.guest], args.directory)
    elif args.command == "payload":
        payload(GUESTS[args.guest], args.suite, args.package, args.output, Path.cwd())
    elif args.command == "boot":
        boot(GUESTS[args.guest], args.images, args.work, accel=args.accel, timeout=args.timeout)
    elif args.command == "copy-in":
        copy_in(args.work, args.source, args.timeout)
    elif args.command == "run":
        command = args.guest_command[1:] if args.guest_command[:1] == ["--"] else args.guest_command
        if not command:
            parser.error("run needs a command after --")
        return run(args.work, command, args.timeout, root=args.root)
    elif args.command == "finish":
        return finish(args.work, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
