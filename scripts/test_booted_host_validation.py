"""CI's booted-host jobs boot a pinned Debian 12 or EL9 cloud image under
QEMU with KVM and run the guides and the privileged runner in it. These tests
run the host-side driver (booted-host-validation.py) against stand-in
commands and the guest's phases (booted-host-guest.py) against fixture trees:
nothing here downloads, boots or runs as root."""
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DRIVER = Path(__file__).with_name("booted-host-validation.py")
GUEST_SCRIPT = Path(__file__).with_name("booted-host-guest.py")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Stands in for every external command the driver runs, by the name it is
# called by: it records each call and acts as STUB_PLAN says.
STUB = r"""#!@PYTHON@
import json
import os
from pathlib import Path
import sys
import time
name = Path(sys.argv[0]).name
args = sys.argv[1:]
root = Path(os.environ["STUB_ROOT"])
with (root / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps([name, *args]) + "\n")
plan = json.loads(os.environ.get("STUB_PLAN", "{}"))


def next_status(key, default=0):
    sequence = plan.get(key)
    if not sequence:
        return default
    counter = root / ("count-" + key)
    used = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(used + 1))
    return sequence[min(used, len(sequence) - 1)]


if name == "curl":
    output = Path(args[args.index("--output") + 1])
    url = args[-1]
    status = plan.get("curl_status", {}).get(url, 0)
    if status == 0:
        output.write_bytes(plan.get("curl_content", "image").encode())
    sys.exit(status)
if name == "ssh-keygen":
    path = Path(args[args.index("-f") + 1])
    path.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture " + path.name +
                    "\n-----END OPENSSH PRIVATE KEY-----\n")
    Path(str(path) + ".pub").write_text("ssh-ed25519 AAAAfixture" + path.name + " " +
                                        args[args.index("-C") + 1] + "\n")
    sys.exit(0)
if name == "genisoimage":
    Path(args[args.index("-output") + 1]).write_text("seed\n")
    sys.exit(0)
if name == "qemu-img":
    Path(args[-2]).write_text("overlay\n")
    sys.exit(0)
if name == "qemu-system-x86_64":
    status = plan.get("qemu_status", 0)
    if status == 0:
        Path(args[args.index("-pidfile") + 1]).write_text(str(plan["qemu_pid"]) + "\n")
    else:
        print("qemu: fixture failure", file=sys.stderr)
    sys.exit(status)
if name == "ssh":
    remote = args[-1]
    if remote == "true":
        sys.exit(next_status("probe"))
    if "cloud-init" in remote:
        sys.exit(next_status("cloud_init"))
    if "poweroff" in remote:
        if plan.get("poweroff_kills"):
            os.kill(int(plan["qemu_pid"]), 9)
        sys.exit(255)
    if remote.startswith("cat -- "):
        sys.stdout.write("archive")
        sys.exit(next_status("cat"))
    if remote.startswith("mkdir -p "):
        if plan.get("copy_sleep"):
            time.sleep(plan["copy_sleep"])
        (root / "copied.tar").write_bytes(sys.stdin.buffer.read())
        sys.exit(0)
    if plan.get("ssh_sleep"):
        time.sleep(plan["ssh_sleep"])
    sys.exit(next_status("command"))
sys.exit("fixture: unexpected command " + name)
"""

STUB_NAMES = ("curl", "ssh-keygen", "genisoimage", "qemu-img", "qemu-system-x86_64", "ssh")


class Stubs:
    def __init__(self, test):
        directory = tempfile.TemporaryDirectory(prefix="maki-booted-host-")
        test.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        binary = self.root / "bin"
        binary.mkdir()
        stub = binary / "stub"
        stub.write_text(STUB.replace("@PYTHON@", sys.executable))
        stub.chmod(0o700)
        for name in STUB_NAMES:
            (binary / name).symlink_to(stub)
        self.plan = {}
        patcher = mock.patch.dict(os.environ, {
            "PATH": str(binary) + os.pathsep + os.environ["PATH"], "STUB_ROOT": str(self.root)})
        patcher.start()
        test.addCleanup(patcher.stop)

    def set(self, **plan):
        self.plan.update(plan)
        os.environ["STUB_PLAN"] = json.dumps(self.plan)

    def calls(self, name=None):
        path = self.root / "calls.jsonl"
        if not path.exists():
            return []
        found = [json.loads(line) for line in path.read_text().splitlines()]
        return [call for call in found if name is None or call[0] == name]


def dead_pid():
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()
    return child.pid


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def quiet():
    return contextlib.redirect_stdout(io.StringIO())


class PinnedImages(unittest.TestCase):
    def setUp(self):
        self.driver = load(DRIVER, "booted_host_validation")

    def test_each_guest_is_a_pinned_image_of_its_distribution(self):
        guests = self.driver.GUESTS
        self.assertEqual(sorted(guests), ["debian12", "el9"])
        debian, el9 = guests["debian12"], guests["el9"]
        # Debian's generic image runs its standard kernel; genericcloud runs
        # the cloud kernel, which leaves drivers out.
        self.assertRegex(debian.image, r"^debian-12-generic-amd64-\d{8}-\d+\.qcow2$")
        self.assertEqual(debian.algorithm, "sha512")
        self.assertRegex(debian.digest, r"^[0-9a-f]{128}$")
        build = debian.image.removeprefix("debian-12-generic-amd64-").removesuffix(".qcow2")
        self.assertEqual(debian.urls, (f"https://cloud.debian.org/images/cloud/bookworm/{build}/"
                                       f"{debian.image}",))
        # Rocky Linux, RHEL's unchanged rebuild; its minor release's current
        # image, and the vault where the release's last image is kept.
        self.assertRegex(el9.image, r"^Rocky-9-GenericCloud-Base-9\.(\d+)-\d{8}\.\d+\.x86_64\.qcow2$")
        minor = el9.image.split("-")[4]
        self.assertEqual(el9.urls, (
            f"https://dl.rockylinux.org/pub/rocky/{minor}/images/x86_64/{el9.image}",
            f"https://dl.rockylinux.org/vault/rocky/{minor}/images/x86_64/{el9.image}"))
        self.assertEqual(el9.algorithm, "sha256")
        self.assertRegex(el9.digest, r"^[0-9a-f]{64}$")
        self.assertEqual((debian.package, debian.installation), ("maki.deb", "debian"))
        self.assertEqual((el9.package, el9.installation), ("maki.rpm", "rhel"))


class Fetch(unittest.TestCase):
    def setUp(self):
        self.driver = load(DRIVER, "booted_host_validation")
        self.stubs = Stubs(self)
        self.guest = dataclasses.replace(
            self.driver.GUESTS["el9"], urls=("https://first.example/image", "https://second.example/image"),
            digest=hashlib.sha256(b"image").hexdigest())
        self.images = self.stubs.root / "images"

    def test_an_image_with_the_pinned_digest_is_kept(self):
        self.stubs.set(curl_content="image")
        with quiet():
            path = self.driver.fetch(self.guest, self.images)
        self.assertEqual(path, self.images / self.guest.image)
        self.assertEqual(path.read_bytes(), b"image")
        self.assertEqual(sorted(entry.name for entry in self.images.iterdir()), [self.guest.image])
        [call] = self.stubs.calls("curl")
        for option in ("--fail", "--location", "--retry", "--speed-limit"):
            self.assertIn(option, call)
        self.assertEqual(call[-1], "https://first.example/image")

    def test_another_digest_is_refused_and_not_kept(self):
        self.stubs.set(curl_content="tampered")
        with quiet(), self.assertRaises(SystemExit) as refused:
            self.driver.fetch(self.guest, self.images)
        self.assertIn(hashlib.sha256(b"tampered").hexdigest(), str(refused.exception))
        self.assertIn(self.guest.digest, str(refused.exception))
        self.assertEqual(list(self.images.iterdir()), [])
        # A wrong image is not a missing one: the next address is not tried.
        self.assertEqual(len(self.stubs.calls("curl")), 1)

    def test_the_next_address_is_tried_when_one_fails(self):
        self.stubs.set(curl_content="image", curl_status={"https://first.example/image": 22})
        with quiet():
            path = self.driver.fetch(self.guest, self.images)
        self.assertEqual(path.read_bytes(), b"image")
        self.assertEqual([call[-1] for call in self.stubs.calls("curl")],
                         ["https://first.example/image", "https://second.example/image"])

    def test_an_image_already_there_with_the_pinned_digest_is_used_as_it_is(self):
        # As actions/cache restores it: checked like a download, not trusted.
        self.images.mkdir()
        (self.images / self.guest.image).write_bytes(b"image")
        with quiet():
            path = self.driver.fetch(self.guest, self.images)
        self.assertEqual(path.read_bytes(), b"image")
        self.assertEqual(self.stubs.calls("curl"), [])

    def test_an_image_already_there_with_another_digest_is_replaced(self):
        self.images.mkdir()
        (self.images / self.guest.image).write_bytes(b"restored, then changed")
        self.stubs.set(curl_content="image")
        with quiet():
            path = self.driver.fetch(self.guest, self.images)
        self.assertEqual(path.read_bytes(), b"image")
        self.assertEqual(len(self.stubs.calls("curl")), 1)

    def test_the_cache_key_names_the_pinned_file_and_its_digest(self):
        for name, guest in self.driver.GUESTS.items():
            with self.subTest(guest=name):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(self.driver.main(["image-key", "--guest", name]), 0)
                self.assertEqual(output.getvalue(),
                                 f"key=booted-host-image-{guest.image}-{guest.algorithm}-{guest.digest}\n")

    def test_an_image_no_address_serves_says_to_move_the_pin(self):
        self.stubs.set(curl_status={"https://first.example/image": 22, "https://second.example/image": 6})
        with quiet(), self.assertRaises(SystemExit) as refused:
            self.driver.fetch(self.guest, self.images)
        for text in ("https://first.example/image: curl exited with status 22",
                     "https://second.example/image: curl exited with status 6", "GUESTS"):
            self.assertIn(text, str(refused.exception))
        self.assertEqual(list(self.images.iterdir()), [])


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "git and Bash")
class Payload(unittest.TestCase):
    def setUp(self):
        self.driver = load(DRIVER, "booted_host_validation")
        directory = tempfile.TemporaryDirectory(prefix="maki-booted-payload-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.checkout = self.root / "checkout"
        (self.checkout / "scripts").mkdir(parents=True)
        (self.checkout / "scripts" / "tracked.txt").write_text("tracked\n")

        def git(*arguments):
            return subprocess.run(["git", "-C", str(self.checkout), *arguments], check=True,
                                  capture_output=True, text=True).stdout.strip()
        git("init", "-q")
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
            "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.head = git("rev-parse", "HEAD")

    def package(self, guest, revision=None, tamper=False, listed=True):
        directory = self.root / f"package-{guest.name}"
        directory.mkdir()
        (directory / guest.package).write_bytes(b"package " + guest.name.encode())
        (directory / "source-revision").write_text((revision or self.head) + "\n")
        lines = []
        for name in ((guest.package, "source-revision") if listed else ("source-revision",)):
            digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        (directory / "SHA256SUMS").write_text("".join(lines))
        if tamper:
            (directory / guest.package).write_bytes(b"changed")
        return directory

    def test_the_guides_suite_gets_the_installation_guides_program_and_the_package(self):
        for name, first_step in (("debian12", "installation-debian.md, Install the Maki package"),
                                 ("el9", "installation-rhel.md, Repositories")):
            with self.subTest(guest=name):
                guest = self.driver.GUESTS[name]
                output = self.root / f"payload-{name}"
                with quiet():
                    self.driver.payload(guest, "guides", self.package(guest), output, self.checkout)
                program = (output / "quickstart" / "quickstart.sh").read_text()
                self.assertIn(f"holds {guest.package} and demo.toml", program)
                self.assertIn(f"step='[1/", program)
                self.assertIn(first_step, program.split("step='[2/", 1)[0])
                self.assertTrue((output / "quickstart" / "demo.toml").is_file())
                self.assertEqual((output / "quickstart" / guest.package).read_bytes(),
                                 b"package " + name.encode())
                self.assertEqual((output / "booted-host-guest.py").read_bytes(), GUEST_SCRIPT.read_bytes())
                self.assertEqual((output / "source-revision").read_text(), self.head + "\n")
                self.assertFalse((output / "source").exists())

    def test_the_runner_suite_gets_a_clone_of_head_and_the_package(self):
        guest = self.driver.GUESTS["debian12"]
        output = self.root / "payload"
        with quiet():
            self.driver.payload(guest, "runner", self.package(guest), output, self.checkout)
        clone = output / "source"
        self.assertEqual(subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], check=True,
                                        capture_output=True, text=True).stdout.strip(), self.head)
        self.assertEqual((clone / "scripts" / "tracked.txt").read_text(), "tracked\n")
        self.assertEqual((output / "maki.deb").read_bytes(), b"package debian12")
        self.assertFalse((output / "quickstart").exists())

    def test_a_package_that_is_not_this_commits_or_does_not_check_out_is_refused(self):
        guest = self.driver.GUESTS["el9"]
        for case, arguments, expected in (
                ("another revision", {"revision": "0" * 40}, "was built from " + "0" * 40),
                ("changed after its checksums", {"tamper": True}, "not"),
                ("not listed", {"listed": False}, "does not list maki.rpm")):
            with self.subTest(case=case):
                package = self.package(guest, **arguments)
                output = self.root / "payload"
                with quiet(), self.assertRaises(SystemExit) as refused:
                    self.driver.payload(guest, "guides", package, output, self.checkout)
                self.assertIn(expected, str(refused.exception))
                self.assertFalse(output.exists())
                shutil.rmtree(package)


class Boot(unittest.TestCase):
    def setUp(self):
        self.driver = load(DRIVER, "booted_host_validation")
        self.stubs = Stubs(self)
        self.guest = self.driver.GUESTS["debian12"]
        self.images = self.stubs.root / "images"
        self.images.mkdir()
        (self.images / self.guest.image).write_text("image\n")
        self.work = self.stubs.root / "work"
        self.clock = FakeClock()
        access = mock.patch.object(self.driver.os, "access", return_value=True)
        self.access = access.start()
        self.addCleanup(access.stop)

    def boot(self, **options):
        with quiet():
            return self.driver.boot(self.guest, self.images, self.work, clock=self.clock,
                                    sleep=self.clock.sleep, **options)

    def test_without_kvm_the_guest_is_not_started_unless_tcg_is_asked_for(self):
        self.access.return_value = False
        with self.assertRaises(SystemExit) as refused:
            self.boot()
        self.assertIn("/dev/kvm", str(refused.exception))
        self.assertFalse(self.work.exists())
        self.assertEqual(self.stubs.calls(), [])
        self.stubs.set(qemu_pid=os.getpid())
        self.boot(accel="tcg")
        [qemu] = self.stubs.calls("qemu-system-x86_64")
        self.assertIn("q35,accel=tcg", qemu)

    def test_the_guest_runs_with_kvm_on_a_copy_on_write_disk_and_ssh_on_loopback(self):
        self.stubs.set(qemu_pid=os.getpid(), probe=[255, 255, 0])
        state = self.boot()
        port = state["port"]
        [overlay] = self.stubs.calls("qemu-img")
        image = str((self.images / self.guest.image).resolve())
        self.assertEqual(overlay[1:], ["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image,
                                       str(self.work / "disk.qcow2"), "30G"])
        [seed] = self.stubs.calls("genisoimage")
        self.assertEqual(seed[seed.index("-volid") + 1], "cidata")
        [qemu] = self.stubs.calls("qemu-system-x86_64")
        for pair in (("-machine", "q35,accel=kvm"), ("-cpu", "host"),
                     ("-serial", f"file:{self.work / 'console.log'}"),
                     ("-pidfile", str(self.work / "qemu.pid"))):
            self.assertEqual(qemu[qemu.index(pair[0]) + 1], pair[1])
        self.assertIn("-daemonize", qemu)
        self.assertIn("-no-reboot", qemu)
        self.assertIn(f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22", qemu)
        drives = [qemu[index + 1] for index, word in enumerate(qemu) if word == "-drive"]
        # The guest writes only its overlay; the seed is read-only.
        self.assertEqual(drives, [f"file={self.work / 'disk.qcow2'},if=virtio,format=qcow2",
                                  f"file={self.work / 'seed.iso'},if=virtio,format=raw,readonly=on"])
        self.assertNotIn(image, " ".join(qemu))
        # Three SSH probes, then cloud-init's wait under the guest's timeout.
        ssh = self.stubs.calls("ssh")
        self.assertEqual([call[-1] for call in ssh[:3]], ["true"] * 3)
        self.assertTrue(ssh[3][-1].startswith("timeout --kill-after=30 "))
        self.assertTrue(ssh[3][-1].endswith(" cloud-init status --wait --long"))
        self.assertEqual(json.loads((self.work / "guest.json").read_text())["port"], port)

    def test_the_seed_creates_a_key_only_user_and_pins_the_host_key(self):
        self.stubs.set(qemu_pid=os.getpid())
        port = self.boot()["port"]
        user_data = (self.work / "seed" / "user-data").read_text()
        user_key = (self.work / "id_ed25519.pub").read_text().strip()
        host_key = (self.work / "host_ed25519.pub").read_text().strip()
        self.assertTrue(user_data.startswith("#cloud-config\n"))
        for line in ("  - name: ci\n", "    lock_passwd: true\n", '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n',
                     f"      - {user_key}\n", "ssh_pwauth: false\n", "disable_root: true\n",
                     "ssh_deletekeys: true\n", f"  ed25519_public: {host_key}\n",
                     "      fixture host_ed25519\n"):
            self.assertIn(line, user_data)
        # No password of any kind, and no key types to generate: an empty
        # list fails cloud-init's schema.
        self.assertNotRegex(user_data, r"(?m)^\s*(?:passwd|hashed_passwd|plain_text_passwd|password|"
                                       r"chpasswd|ssh_genkeytypes):")
        self.assertEqual((self.work / "known_hosts").read_text(), f"[127.0.0.1]:{port} {host_key}\n")
        self.assertIn("local-hostname: maki-ci-debian12\n", (self.work / "seed" / "meta-data").read_text())

    def test_ssh_accepts_only_the_pinned_host_key_and_offers_only_the_generated_key(self):
        self.stubs.set(qemu_pid=os.getpid())
        port = self.boot()["port"]
        call = self.stubs.calls("ssh")[0]
        options = [call[index + 1] for index, word in enumerate(call) if word == "-o"]
        for option in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes",
                       f"UserKnownHostsFile={self.work / 'known_hosts'}", "GlobalKnownHostsFile=/dev/null",
                       "HostKeyAlgorithms=ssh-ed25519"):
            self.assertIn(option, options)
        self.assertEqual(call[call.index("-i") + 1], str(self.work / "id_ed25519"))
        self.assertEqual(call[call.index("-p") + 1], str(port))
        self.assertEqual(call[call.index("-F") + 1], "none")
        self.assertIn("ci@127.0.0.1", call)

    def test_cloud_init_is_awaited_across_the_sshd_restart_it_causes(self):
        # 2 is "done with recoverable errors" on cloud-init 23.4 and later.
        for statuses in ([255, 0], [255, 255, 2]):
            with self.subTest(statuses=statuses):
                shutil.rmtree(self.work, ignore_errors=True)
                for counter in self.stubs.root.glob("count-*"):
                    counter.unlink()
                self.stubs.set(qemu_pid=os.getpid(), cloud_init=statuses)
                self.boot()

    def test_a_guest_that_does_not_come_up_fails_with_its_console(self):
        cases = (("QEMU exited", dict(qemu_pid=dead_pid())),
                 ("SSH did not answer within 60 s", dict(qemu_pid=os.getpid(), probe=[255])),
                 ("cloud-init did not finish cleanly (status 1)",
                  dict(qemu_pid=os.getpid(), cloud_init=[1])),
                 ("QEMU did not start", dict(qemu_pid=os.getpid(), qemu_status=1)))
        for expected, plan in cases:
            with self.subTest(expected=expected):
                shutil.rmtree(self.work, ignore_errors=True)
                for counter in self.stubs.root.glob("count-*"):
                    counter.unlink()
                self.stubs.plan = {}
                self.stubs.set(**plan)
                with self.assertRaises(SystemExit) as failed:
                    self.boot(timeout=60)
                self.assertIn(expected, str(failed.exception))
                if expected != "QEMU did not start" and "cloud-init" not in expected:
                    self.assertIn("console", str(failed.exception))


class RunAndFinish(unittest.TestCase):
    def setUp(self):
        self.driver = load(DRIVER, "booted_host_validation")
        self.stubs = Stubs(self)
        self.work = self.stubs.root / "work"
        self.work.mkdir()
        (self.work / "guest.json").write_text(json.dumps({"guest": "el9", "port": 2222}))
        for name in ("id_ed25519", "id_ed25519.pub", "host_ed25519", "host_ed25519.pub",
                     "known_hosts", "disk.qcow2", "seed.iso", "qemu.log"):
            (self.work / name).write_text(name + "\n")
        (self.work / "seed").mkdir()
        (self.work / "seed" / "user-data").write_text("host key\n")
        (self.work / "console.log").write_text("".join(f"console line {n}\n" for n in range(300)))

    def test_a_command_runs_as_ci_under_a_time_limit_in_the_guest(self):
        self.stubs.set(command=[3])
        with quiet():
            status = self.driver.run(self.work, ["sudo", "python3", "phase", "--guest", "el9 x"], timeout=42)
        self.assertEqual(status, 3)
        [call] = self.stubs.calls("ssh")
        self.assertEqual(shlex.split(call[-1]),
                         ["timeout", "--kill-after=30", "42", "sudo", "python3", "phase", "--guest", "el9 x"])
        self.assertEqual(call[-3:-1], ["ci@127.0.0.1", "--"])

    def test_a_root_phase_has_its_time_limit_run_as_root(self):
        # Inside sudo, timeout signals the phase's whole process group, root
        # children such as `bash quickstart.sh` included; outside, as `ci`,
        # it could signal only sudo, whose relay reaches the phase alone.
        with quiet():
            self.driver.run(self.work, ["python3", "phase", "--guest", "el9"], timeout=42, root=True)
            self.driver.main(["run", "--work", str(self.work), "--timeout", "43", "--root", "--",
                              "python3", "phase"])
        first, second = [shlex.split(call[-1]) for call in self.stubs.calls("ssh")]
        self.assertEqual(first, ["sudo", "timeout", "--kill-after=30", "42", "python3", "phase", "--guest", "el9"])
        self.assertEqual(second, ["sudo", "timeout", "--kill-after=30", "43", "python3", "phase"])

    def test_a_copy_into_the_guest_is_given_up_after_its_limit(self):
        payload = self.stubs.root / "payload"
        payload.mkdir()
        (payload / "file").write_text("payload\n")
        with quiet():
            self.driver.copy_in(self.work, payload, timeout=30)
        self.assertTrue((self.stubs.root / "copied.tar").stat().st_size > 0)
        self.stubs.set(copy_sleep=5)
        with quiet(), self.assertRaises(SystemExit) as failed:
            self.driver.copy_in(self.work, payload, timeout=1)
        self.assertIn("within 1 s", str(failed.exception))

    def test_a_guest_that_stops_answering_is_given_up_after_the_limit(self):
        self.stubs.set(ssh_sleep=5)
        with quiet(), mock.patch.object(self.driver, "CONNECTION_MARGIN", 0):
            status = self.driver.run(self.work, ["sleep", "100"], timeout=1)
        self.assertEqual(status, 124)

    def test_finish_keeps_the_guests_logs_and_console_and_never_a_key_or_the_seed(self):
        qemu = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(qemu.kill)
        (self.work / "qemu.pid").write_text(f"{qemu.pid}\n")
        self.stubs.set(qemu_pid=qemu.pid, poweroff_kills=True)
        output = self.stubs.root / "logs"
        with quiet():
            status = self.driver.finish(self.work, output)
        qemu.wait(10)
        self.assertEqual(status, 0)
        self.assertEqual(sorted(entry.name for entry in output.iterdir()),
                         ["console.log", "guest.json", "guest.tar.gz", "qemu.log"])
        self.assertEqual((output / "guest.tar.gz").read_text(), "archive")
        remote = [call[-1] for call in self.stubs.calls("ssh")]
        self.assertTrue(remote[0].startswith("sudo timeout --kill-after=30 "), remote[0])
        self.assertIn("collect --guest el9", remote[0])
        self.assertIn("cat -- /var/tmp/maki-ci-logs.tar.gz", remote[1])
        self.assertIn("systemctl poweroff", remote[2])

    def test_finish_without_a_running_guest_keeps_the_console_and_fails(self):
        (self.work / "qemu.pid").write_text(f"{dead_pid()}\n")
        output = self.stubs.root / "logs"
        with quiet():
            status = self.driver.finish(self.work, output)
        self.assertEqual(status, 1)
        self.assertIn("console.log", [entry.name for entry in output.iterdir()])
        self.assertEqual(self.stubs.calls("ssh"), [])

    def test_a_guest_that_does_not_power_off_is_killed(self):
        qemu = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(qemu.kill)
        (self.work / "qemu.pid").write_text(f"{qemu.pid}\n")
        self.stubs.set(qemu_pid=qemu.pid)
        clock = FakeClock()
        with quiet():
            stopped = self.driver.stop(self.work, timeout=5, clock=clock, sleep=clock.sleep)
        self.assertFalse(stopped)
        self.assertEqual(qemu.wait(10), -15)


class GuestPhases(unittest.TestCase):
    def setUp(self):
        self.guest = load(GUEST_SCRIPT, "booted_host_guest")
        directory = tempfile.TemporaryDirectory(prefix="maki-booted-guest-")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        results = mock.patch.object(self.guest, "RESULTS", self.root / "results")
        results.start()
        self.addCleanup(results.stop)

    def test_the_guest_is_told_apart_by_its_os_release(self):
        cases = (({"ID": "debian", "VERSION_ID": "12"}, "debian12"),
                 ({"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.9"}, "el9"),
                 ({"ID": "almalinux", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "9.6"}, "el9"),
                 ({"ID": "centos", "ID_LIKE": "rhel fedora", "VERSION_ID": "9"}, "el9"),
                 ({"ID": "debian", "VERSION_ID": "11"}, None),
                 ({"ID": "rocky", "ID_LIKE": "rhel centos fedora", "VERSION_ID": "8.10"}, None),
                 ({"ID": "ubuntu", "ID_LIKE": "debian", "VERSION_ID": "24.04"}, None))
        for release, expected in cases:
            with self.subTest(release=release):
                self.assertEqual(self.guest.guest_of(release), expected)
        with self.assertRaises(SystemExit):
            self.guest.require_guest("el9", {"ID": "debian", "VERSION_ID": "12", "PRETTY_NAME": "Debian"})

    def test_the_el9_facts_require_selinux_enforcing(self):
        for mode, refused in (("Enforcing", False), ("Permissive", True), ("Disabled", True)):
            with self.subTest(mode=mode), mock.patch.object(self.guest, "require_guest"), \
                    mock.patch.object(self.guest, "record"), mock.patch.object(self.guest, "inventory"), \
                    mock.patch.object(self.guest.subprocess, "run",
                                      return_value=subprocess.CompletedProcess([], 1, "", "")), \
                    mock.patch.object(self.guest, "selinux_mode", return_value=mode):
                if refused:
                    with self.assertRaises(SystemExit) as failed:
                        self.guest.facts("el9")
                    self.assertIn(f"SELinux is {mode}", str(failed.exception))
                else:
                    self.assertEqual(self.guest.facts("el9"), 0)

    def test_the_sampler_records_each_maki_process_with_its_unit_and_label_once(self):
        proc = self.root / "proc"
        processes = {"101": ("nbdkit", "0::/system.slice/system-maki.slice/maki@demo.service\n",
                             b"system_u:system_r:unconfined_service_t:s0\0", b"/usr/sbin/nbdkit\0-U\0s\0"),
                     "102": ("maki-attach", "0::/system.slice/system-maki\\x2dattach.slice/"
                                            "maki-attach@demo.service\n", b"unconfined\n", b"maki-attach\0"),
                     "103": ("bash", "0::/user.slice\n", b"unconfined_t\0", b"bash\0")}
        for pid, (comm, cgroup, label, cmdline) in processes.items():
            (proc / pid / "attr").mkdir(parents=True)
            (proc / pid / "comm").write_text(comm + "\n")
            (proc / pid / "cgroup").write_text(cgroup)
            (proc / pid / "attr" / "current").write_bytes(label)
            (proc / pid / "cmdline").write_bytes(cmdline)
        (proc / "self").mkdir()
        output = self.root / "contexts.jsonl"
        sampler = self.guest.Sampler(output, proc=proc)
        found = sampler.sample()
        self.assertEqual(sorted((sample["comm"], sample["unit"], sample["label"]) for sample in found),
                         [("maki-attach", "maki-attach@demo.service", "unconfined"),
                          ("nbdkit", "maki@demo.service", "system_u:system_r:unconfined_service_t:s0")])
        self.assertEqual(sampler.sample(), [])
        recorded = [json.loads(line) for line in output.read_text().splitlines()]
        self.assertEqual(sorted(recorded, key=lambda sample: sample["pid"]),
                         sorted(found, key=lambda sample: sample["pid"]))
        self.assertEqual([sample["args"] for sample in recorded if sample["pid"] == 101],
                         ["/usr/sbin/nbdkit -U s"])

    def test_maki_at_must_run_in_the_domain_the_rhel_guide_states(self):
        def sample(label, unit="maki@demo.service", comm="nbdkit"):
            return {"comm": comm, "unit": unit, "label": label}
        unconfined = "system_u:system_r:unconfined_service_t:s0"
        cases = (([sample(unconfined)], []),
                 ([sample(unconfined), sample("system_u:system_r:nbdkit_t:s0")], ["nbdkit_t"]),
                 ([sample("system_u:system_r:init_t:s0")], ["init_t"]),
                 ([], ["no nbdkit process"]),
                 ([sample(unconfined, unit="session-3.scope")], ["no nbdkit process"]),
                 ([sample(unconfined, comm="maki-attach")], ["no nbdkit process"]))
        for samples, expected in cases:
            with self.subTest(samples=samples):
                problems, _contexts = self.guest.domain_verdict(samples)
                self.assertEqual(len(problems), len(expected), problems)
                for problem, text in zip(problems, expected):
                    self.assertIn(text, problem)

    def test_a_denial_naming_maki_or_nbd_is_told_apart_from_others(self):
        text = ("----\ntype=AVC msg=audit(1.0:1) : avc:  denied  { read } for comm=cloud-init "
                "scontext=system_u:system_r:cloud_init_t:s0 tclass=file\n"
                "----\ntype=AVC msg=audit(2.0:2) : avc:  denied  { execute } for comm=systemd "
                "name=nbdkit scontext=system_u:system_r:init_t:s0 "
                "tcontext=system_u:object_r:nbdkit_exec_t:s0 tclass=file\n"
                "----\ntype=AVC msg=audit(3.0:3) : avc:  denied  { open } for comm=maki-attach "
                "path=/dev/mapper/control tclass=chr_file\n")
        records, related = self.guest.denials(text)
        self.assertEqual(len(records), 3)
        self.assertEqual(len(related), 2)
        self.assertTrue(all("cloud-init" not in item for item in related))
        self.assertEqual(self.guest.denials(""), ([], []))

    def selinux(self, suite="guides", mode="Enforcing", found=None, samples=None, labels=None, auditd=True):
        unconfined = "system_u:system_r:unconfined_service_t:s0"
        if samples is None:
            samples = [{"comm": "nbdkit", "unit": "maki@demo.service", "label": unconfined}]
        (self.root / "results").mkdir(exist_ok=True)
        (self.root / "results" / "contexts.jsonl").write_text(
            "".join(json.dumps(sample) + "\n" for sample in samples))
        if found is None:
            found = subprocess.CompletedProcess([], 1, "", "<no matches>\n")
        observed = dict(labels or {})
        with mock.patch.object(self.guest, "require_guest"), \
                mock.patch.object(self.guest, "selinux_mode", return_value=mode), \
                mock.patch.object(self.guest, "auditd_active", return_value=auditd), \
                mock.patch.object(self.guest, "record",
                                  return_value=subprocess.CompletedProcess([], 0, "policy-38\n", "")), \
                mock.patch.object(self.guest, "label_type",
                                  side_effect=lambda path: observed.get(path, dict(self.guest.LABELS)[path])), \
                quiet():
            return self.guest.selinux("el9", suite, search=lambda: found)

    def test_selinux_passes_only_enforcing_without_maki_denials_unconfined_and_as_labelled(self):
        self.assertEqual(self.selinux(), 0)
        report = (self.root / "results" / "selinux.txt").read_text()
        self.assertIn("getenforce: Enforcing", report)
        self.assertIn("maki@demo.service ran in unconfined_service_t", report)
        self.assertIn("label /usr/sbin/nbdkit: bin_t (guide: bin_t)", report)
        unrelated = subprocess.CompletedProcess([], 0, "----\ntype=AVC avc: denied { read } comm=chronyd\n", "")
        self.assertEqual(self.selinux(found=unrelated), 0)
        self.assertIn("chronyd", (self.root / "results" / "avc.txt").read_text())
        for case, arguments in (
                ("permissive", dict(mode="Permissive")),
                ("a Maki denial", dict(found=subprocess.CompletedProcess(
                    [], 0, "----\ntype=AVC avc: denied { execute } comm=systemd name=nbdkit\n", ""))),
                ("ausearch failed", dict(found=subprocess.CompletedProcess([], 1, "", "error opening\n"))),
                ("ausearch broke", dict(found=subprocess.CompletedProcess([], 10, "", ""))),
                ("confined daemon", dict(samples=[{"comm": "nbdkit", "unit": "maki@demo.service",
                                                   "label": "system_u:system_r:nbdkit_t:s0"}])),
                ("no daemon seen", dict(samples=[])),
                ("relabelled nbdkit", dict(labels={"/usr/sbin/nbdkit": "nbdkit_exec_t"})),
                # Without auditd, denials go to the kernel log and ausearch
                # prints <no matches>.
                ("auditd stopped", dict(auditd=False))):
            with self.subTest(case=case):
                self.assertEqual(self.selinux(**arguments), 1)
                self.assertIn("PROBLEM:", (self.root / "results" / "selinux.txt").read_text())

    def test_the_runner_suite_checks_denials_but_not_the_packaged_daemon(self):
        self.assertEqual(self.selinux(suite="runner", samples=[]), 0)
        self.assertEqual(self.selinux(suite="runner", samples=[], found=subprocess.CompletedProcess(
            [], 0, "----\ntype=AVC avc: denied { ioctl } path=/dev/nbd15\n", "")), 1)

    def test_every_unit_the_package_installs_and_the_quick_starts_device_are_labelled(self):
        labels = dict(self.guest.LABELS)
        units = sorted(path.name for path in (ROOT / "packaging" / "systemd").iterdir())
        self.assertEqual(len(units), 4)
        for unit in units:
            with self.subTest(unit=unit):
                self.assertEqual(labels.get(f"/usr/lib/systemd/system/{unit}"), "systemd_unit_file_t")
        # The device the quick start attaches; no other is named.
        self.assertEqual([path for path in labels if path.startswith("/dev/")], ["/dev/nbd0"])

    def test_the_labels_are_those_the_rhel_guide_lists(self):
        guide = (ROOT / "docs" / "getting-started" / "installation-rhel.md").read_text()
        selinux = guide.split("\n## SELinux\n", 1)[1].split("\n## ", 1)[0]
        for path, expected in self.guest.LABELS:
            with self.subTest(path=path):
                self.assertIn(f"`{expected}`", selinux)
        self.assertIn(f"`{self.guest.DAEMON_DOMAIN}`", selinux)
        self.assertIn("`ls -Z /usr/sbin/nbdkit` should show `bin_t`", " ".join(selinux.split()))

    def test_a_finished_quick_start_must_leave_nothing_of_the_volume(self):
        binary = self.root / "bin"
        binary.mkdir()
        (binary / "findmnt").write_text("#!/bin/sh\n[ -n \"$MOUNTED\" ]\n")
        (binary / "systemctl").write_text("#!/bin/sh\necho \"${ACTIVE_STATE:-inactive}\"\n")
        for name in ("findmnt", "systemctl"):
            (binary / name).chmod(0o700)
        system = self.root / "system"
        (system / "run" / "maki-attach").mkdir(parents=True)
        (system / "sys" / "block" / "nbd0").mkdir(parents=True)
        (system / "sys" / "block" / "nbd0" / "backend").write_text("\n")

        def leftovers(**environment):
            with mock.patch.dict(os.environ, environment):
                return self.guest.leftovers(system, findmnt=str(binary / "findmnt"),
                                            systemctl=str(binary / "systemctl"))
        self.assertEqual(leftovers(), [])
        self.assertEqual(len(leftovers(MOUNTED="1")), 1)
        self.assertEqual(len(leftovers(ACTIVE_STATE="failed")), len(self.guest.UNITS))
        (system / "sys" / "block" / "nbd0" / "backend").write_text("maki-1234\n")
        (system / "run" / "maki-attach" / "demo.nbd").write_text("{}")
        found = leftovers()
        self.assertEqual(len(found), 2)
        self.assertIn("attach record", found[0])
        self.assertIn("maki-1234", found[1])

    def test_the_guides_phase_fails_with_the_program_and_with_what_it_left(self):
        # A program that stops before attaching leaves nothing behind: its
        # own status must still fail the phase.
        quickstart = self.root / "quickstart"
        quickstart.mkdir()
        for name in ("demo.toml", "maki.deb"):
            (quickstart / name).write_text("fixture\n")
        for program, left, expected in (("echo stopping\nexit 3\n", [], 3), ("echo done\n", [], 0),
                                        ("echo done\n", ["a mount at /srv/demo"], 1)):
            with self.subTest(program=program, left=left):
                (quickstart / "quickstart.sh").write_text(program)
                with mock.patch.object(self.guest, "QUICKSTART", quickstart), \
                        mock.patch.object(self.guest, "require_guest"), \
                        mock.patch.object(self.guest, "leftovers", return_value=left), quiet():
                    self.assertEqual(self.guest.guides("debian12"), expected)
                self.assertIn(program.split("\n")[0].split()[1], (quickstart / "quickstart.log").read_text())

    def test_the_runner_runs_as_ci_with_the_packages_binaries_on_nbd15(self):
        for name, install_missing in (("debian12", True), ("el9", False)):
            with self.subTest(guest=name):
                command = self.guest.runner_command(name)
                self.assertEqual(command[:5], ["sudo", "-u", "ci", "-H", "--"])
                self.assertEqual(command[5], str(self.guest.SOURCE / "scripts" / "privileged-linux-validation.sh"))
                self.assertEqual("--install-missing" in command, install_missing)
                words = command[5:]
                self.assertIn("--kill-daemon", words)
                self.assertEqual(words[words.index("--prebuilt") + 1], str(self.guest.PREBUILT))
                self.assertEqual(words[words.index("--device") + 1], "/dev/nbd15")
                self.assertEqual(words[words.index("--confirm-wipe") + 1], "/dev/nbd15")
        # EL9's tools come from BaseOS and AppStream: nbdkit-server, never the
        # metapackage that pulls in nbdkit-selinux.
        packages = self.guest.EL9_RUNNER_PACKAGES
        self.assertIn("nbdkit-server", packages)
        self.assertNotIn("nbdkit", packages)
        self.assertNotIn("nbdkit-selinux", packages)

    def test_the_runners_artifacts_are_the_packages_own_files(self):
        package = self.root / "package-root"
        for source, _name, _mode in self.guest.PACKAGED_BINARIES:
            (package / source).parent.mkdir(parents=True, exist_ok=True)
            (package / source).write_bytes(b"packaged " + source.encode())
        prebuilt = self.root / "prebuilt"
        with quiet():
            self.guest.prebuilt_from(package, prebuilt)
        self.assertEqual(sorted(entry.name for entry in prebuilt.iterdir()),
                         ["libmaki_nbdkit.so", "maki", "maki-attach"])
        for source, name, mode in self.guest.PACKAGED_BINARIES:
            self.assertEqual((prebuilt / name).read_bytes(), b"packaged " + source.encode())
            self.assertEqual((prebuilt / name).stat().st_mode & 0o777, mode)
        self.assertEqual(dict((name, source) for source, name, _ in self.guest.PACKAGED_BINARIES),
                         {"maki": "usr/bin/maki", "maki-attach": "usr/bin/maki-attach",
                          "libmaki_nbdkit.so": "usr/lib/maki/maki-nbdkit.so"})

    def test_the_archive_leaves_out_the_package_the_snapshot_and_the_builds(self):
        quickstart = self.root / "quickstart"
        quickstart.mkdir()
        for name in ("quickstart.sh", "quickstart.log", "demo.toml", "maki.deb", "maki.rpm"):
            (quickstart / name).write_text(name)
        run = self.root / "run"
        for name in ("source/scripts", "target/prebuilt", "build/debug", "sources-note"):
            (run / name).mkdir(parents=True)
            (run / name / "file").write_text("large")
        (run / "run.log").write_text("log")
        archive = self.root / "logs.tar.gz"
        self.guest.pack(archive, [(quickstart, "quickstart", ("maki.deb", "maki.rpm")),
                                  (run, "privileged-run", ("source", "target", "build")),
                                  (self.root / "missing", "missing", ())])
        with tarfile.open(archive) as members:
            names = sorted(member.name for member in members.getmembers())
        self.assertEqual(names, ["privileged-run", "privileged-run/run.log", "privileged-run/sources-note",
                                 "privileged-run/sources-note/file", "quickstart",
                                 "quickstart/demo.toml", "quickstart/quickstart.log",
                                 "quickstart/quickstart.sh"])
        self.assertEqual(archive.stat().st_mode & 0o777, 0o644)

    def test_nothing_is_collected_from_where_keys_or_backings_live(self):
        run = self.root / "maki-privileged-validation-20261127T000000Z-1"
        run.mkdir()
        latest = self.root / "maki-privileged-validation.latest"
        latest.symlink_to(run.name)
        with mock.patch.object(self.guest, "RUNNER_LOGS", latest):
            members = self.guest.collect_members()
        paths = [str(path) for path, _name, _leave_out in members]
        self.assertIn(str(run), paths)
        # cloud-init keeps the seed's user-data, with the guest's host key,
        # in /var/lib/cloud; the volume's key and backing live under
        # /etc/maki and /var/lib/maki, the runner's below its work tree.
        for path in paths:
            for forbidden in ("/var/lib/cloud", "/etc/maki", "/var/lib/maki", "/etc/ssh", "/root",
                              "/home/ci/.ssh", "/var/tmp/maki-privileged-validation."):
                with self.subTest(path=path, forbidden=forbidden):
                    self.assertFalse(path.startswith(forbidden), path)

    def test_a_file_that_holds_a_private_key_is_never_packed(self):
        logs = self.root / "logs"
        logs.mkdir()
        (logs / "plain.log").write_text("nothing secret\n")
        (logs / "leaked.log").write_text("user-data:\n-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n"
                                         "-----END OPENSSH PRIVATE KEY-----\n")
        archive = self.root / "logs.tar.gz"
        with self.assertRaises(SystemExit) as refused:
            self.guest.pack(archive, [(logs, "logs", ())])
        self.assertIn("leaked.log", str(refused.exception))
        self.assertFalse(archive.exists())
        (logs / "leaked.log").unlink()
        self.guest.pack(archive, [(logs, "logs", ())])
        self.assertTrue(archive.exists())

    def test_the_package_the_snapshot_and_the_builds_are_left_out(self):
        run = self.root / "run"
        run.mkdir()
        with mock.patch.object(self.guest, "RUNNER_LOGS", run):
            members = {name: leave_out for _path, name, leave_out in self.guest.collect_members()}
        self.assertEqual(members["quickstart"], ("maki.deb", "maki.rpm"))
        self.assertEqual(members["privileged-run"], ("source", "target", "build"))
        source = GUEST_SCRIPT.read_text()
        collect = source[source.index("def collect("):source.index("def main(")]
        self.assertIn("pack(ARCHIVE, collect_members())", collect)

    def test_every_phase_needs_root(self):
        with mock.patch.object(self.guest.os, "geteuid", return_value=1000), \
                self.assertRaises(SystemExit) as refused:
            self.guest.main(["facts", "--guest", "debian12"])
        self.assertIn("as root", str(refused.exception))

    def test_the_guest_script_runs_on_el9s_python(self):
        import ast
        for path in (GUEST_SCRIPT,):
            ast.parse(path.read_text(), str(path), feature_version=(3, 9))


if __name__ == "__main__":
    unittest.main()
