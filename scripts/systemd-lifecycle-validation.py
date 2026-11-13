#!/usr/bin/env python3
"""Exercise the packaged dependency graph with private simulated resources.

This opt-in test creates randomly named instance units on a disposable systemd
host. The real maki-attach failed-start hook runs; NBD, LVM, mounts, credentials
and application data are never used. It is a service-manager regression, not
storage or deployment qualification.
"""

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
SYSTEMCTL = "/usr/bin/systemctl"
CASES = (
    "exit-once", "timeout-once", "kill-once", "cleanup-failure",
    "foreign-resource", "repeated-failure", "normal-stop", "failed-stop",
    "cancel-start",
)


def require(condition, message):
    # Campaign oracles must remain enabled even with PYTHONOPTIMIZE set.
    if not condition:
        raise AssertionError(message)


def unit_argument(value):
    value = str(value)
    if any(ord(character) < 32 for character in value):
        raise ValueError("control character in unit argument")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace(
        "%", "%%").replace("$", "$$") + '"'


def names(volume):
    if not volume.startswith("mkci_") or not volume[5:].isalnum():
        raise ValueError("fixture instances require a private generated name")
    return {
        "daemon": f"maki@{volume}.service",
        "attach": f"maki-attach@{volume}.service",
        "recovery": f"maki-recover@{volume}.service",
        "target": f"maki-workload@{volume}.target",
        "workload": f"maki-fixture-workload@{volume}.service",
    }


def packaged_unit_section(template, volume):
    """Preserve lifecycle relationships; omit actual host/config prerequisites."""
    section = None
    result = ["[Unit]"]
    for line in (ROOT / "packaging/systemd" / template).read_text().splitlines():
        if line.startswith("["):
            section = line
        elif section == "[Unit]" and line and not line.startswith("#"):
            if line.startswith(("AssertPathExists=", "JobTimeoutSec=")):
                continue
            if line in ("After=network-online.target", "Wants=network-online.target"):
                continue
            result.append(line.replace("%i", volume))
    return "\n".join(result) + "\n"


def fixture_units(volume, directory, helper):
    units = names(volume)
    actor_command = " ".join(unit_argument(argument) for argument in
                             (sys.executable, Path(__file__).resolve(), "actor", directory))
    daemon = packaged_unit_section("maki@.service", volume)
    daemon += ("\n[Service]\nType=notify\nNotifyAccess=main\n"
               "TimeoutStartSec=3\nTimeoutStopSec=3\n"
               f"ExecStart={actor_command} daemon\n")
    attach = packaged_unit_section("maki-attach@.service", volume)
    attach += ("\n[Service]\nType=oneshot\nRemainAfterExit=yes\n"
               "TimeoutStartSec=2\nTimeoutStopSec=3\n"
               f"ExecStart={actor_command} attach\n"
               f"ExecStop={actor_command} cleanup-stop\n")
    # Exercise the actual packaged hook command, including any future changes.
    hooks = [line for line in (ROOT / "packaging/systemd/maki-attach@.service").read_text().splitlines()
             if line.startswith("ExecStopPost=")]
    if hooks != ["ExecStopPost=/usr/bin/maki-attach recover-failed-start --volume %i"]:
        raise ValueError("unexpected failed-start hook contract")
    attach += hooks[0].replace("/usr/bin/maki-attach", unit_argument(helper)).replace("%i", volume) + "\n"
    recovery = packaged_unit_section("maki-recover@.service", volume)
    recovery += ("JobTimeoutSec=12\n\n[Service]\nType=oneshot\nTimeoutStartSec=3\n"
                 f"ExecStart={actor_command} cleanup-recover\n")
    target = packaged_unit_section("maki-workload@.target", volume)
    # RequiredBy= from the shipped workload drop-in becomes this dependency
    # when installed. No enable operation or boot target is needed here.
    target += f"Requires={units['workload']}\n"
    workload = ("[Unit]\nDescription=Private Maki lifecycle fixture workload\n"
                f"BindsTo={units['attach']}\nAfter={units['attach']}\n"
                f"PartOf={units['target']}\nConflicts={units['recovery']}\n"
                "\n[Service]\nType=simple\nTimeoutStopSec=3\n"
                f"ExecStart={actor_command} workload\n")
    rendered = dict(zip(units.values(), (daemon, attach, recovery, target, workload)))
    relationship_keys = {"After", "Before", "Wants", "Requires", "BindsTo", "PartOf", "Conflicts",
                         "OnSuccess", "OnFailure"}
    for content in rendered.values():
        for line in content.splitlines():
            key, _, value = line.partition("=")
            if key in relationship_keys and not set(value.split()).issubset(rendered):
                raise ValueError("fixture dependency escaped its private unit set")
    return rendered


def event(directory, name, **fields):
    record = {"event": name, "monotonic_ns": time.monotonic_ns(), **fields}
    descriptor = os.open(directory / "events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, (json.dumps(record) + "\n").encode())
    finally:
        os.close(descriptor)


def actor(directory, action):
    mode = (directory / "mode").read_text().strip()
    resource = directory / "resource"
    workload = directory / "workload-running"
    if action == "attach":
        attempts = directory / "attempts"
        attempt = int(attempts.read_text()) + 1 if attempts.exists() else 1
        attempts.write_text(str(attempt))
        resource.write_text("foreign" if mode == "foreign-resource" else "owned")
        event(directory, "attach-start", attempt=attempt)
        if mode == "repeated-failure" or (attempt == 1 and mode in
                ("exit-once", "cleanup-failure", "foreign-resource")):
            return 1
        if attempt == 1 and mode in ("timeout-once", "cancel-start"):
            time.sleep(60)
            return 1
        if attempt == 1 and mode == "kill-once":
            os.kill(os.getpid(), signal.SIGKILL)
        event(directory, "attach-ready", attempt=attempt)
        return 0
    if action in ("cleanup-stop", "cleanup-recover"):
        event(directory, action)
        if workload.exists():
            event(directory, "unsafe-cleanup-before-workload-stop")
            return 40
        if resource.exists() and resource.read_text() != "owned":
            event(directory, "foreign-resource-preserved")
            return 41
        if ((action == "cleanup-recover" and mode == "cleanup-failure")
                or (action == "cleanup-stop" and mode == "failed-stop")):
            event(directory, "cleanup-refused")
            return 42
        resource.unlink(missing_ok=True)
        event(directory, "cleanup-complete")
        return 0
    if action in ("daemon", "workload"):
        def stop(_number, _frame):
            if action == "workload":
                workload.unlink(missing_ok=True)
            event(directory, action + "-stop")
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        if action == "workload":
            if not resource.exists() or resource.read_text() != "owned":
                event(directory, "unsafe-workload-start")
                return 43
            workload.write_text("running")
        event(directory, action + "-start")
        if action == "daemon":
            destination = os.environ["NOTIFY_SOCKET"]
            if destination.startswith("@"):
                destination = "\0" + destination[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notify:
                notify.sendto(b"READY=1", destination)
        while True:
            signal.pause()
    raise ValueError("unknown fixture actor")


class Fixture:
    def __init__(self, output, helper, mode):
        self.directory = output / mode
        self.directory.mkdir(mode=0o700)
        (self.directory / "mode").write_text(mode)
        self.volume = "mkci_" + uuid.uuid4().hex
        self.units = names(self.volume)
        self.files = fixture_units(self.volume, self.directory, helper)
        self.linked = []

    def ctl(self, *arguments, check=True, timeout=20):
        result = subprocess.run([SYSTEMCTL, "--no-ask-password", *arguments],
                                capture_output=True, text=True, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f"systemctl {arguments[0]} failed: {result.stderr[-2000:]}")
        return result

    def state(self, which):
        output = self.ctl("show", "--property=ActiveState", self.units[which]).stdout
        return output.strip().removeprefix("ActiveState=")

    def events(self):
        path = self.directory / "events.jsonl"
        if not path.exists():
            return []
        text = path.read_text()
        return [json.loads(line) for line in text.splitlines(keepends=True) if line.endswith("\n")]

    def count(self, name):
        return sum(record["event"] == name for record in self.events())

    def wait(self, condition, label, timeout=18):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if condition():
                return
            time.sleep(0.1)
        raise AssertionError(f"timed out: {label}")

    def install(self):
        for name, content in self.files.items():
            destination = Path("/run/systemd/system") / name
            if destination.exists() or destination.is_symlink():
                raise RuntimeError("generated fixture instance already exists")
            source = self.directory / name
            source.write_text(content)
            source.chmod(0o600)
            self.ctl("link", "--runtime", str(source))
            self.linked.append((destination, source))
        self.ctl("daemon-reload")

    def cleanup(self):
        if not self.linked:
            return
        # Remove automatic transitions before stopping these exact instances.
        # Otherwise a still-running failure scenario could restart itself while
        # the test removes its files. Nothing outside this owned list is touched.
        for _, source in self.linked:
            content = source.read_text()
            lines = [line for line in content.splitlines()
                     if not line.startswith(("OnSuccess=", "OnFailure=", "ExecStopPost=", "ExecStop="))]
            source.write_text("\n".join(lines) + "\n")
        self.ctl("daemon-reload")
        installed = [destination.name for destination, _ in self.linked]
        result = self.ctl("stop", *installed, check=False)
        remaining = [name for name in self.units if self.units[name] in installed
                     and self.state(name) not in ("inactive", "failed")]
        if remaining:
            raise RuntimeError(f"fixture units did not stop: {remaining}; {result.stderr[-1000:]}")
        self.ctl("reset-failed", *installed, check=False)
        for destination, source in self.linked:
            if not destination.is_symlink() or destination.resolve() != source.resolve():
                raise RuntimeError("fixture link identity changed; refusing removal")
            destination.unlink()
        self.ctl("daemon-reload")

    def diagnostics(self):
        status = self.ctl("show", "--property=ActiveState", "--property=Result",
                          "--property=ExecMainCode", "--property=ExecMainStatus",
                          *self.units.values(), check=False)
        (self.directory / "unit-states.txt").write_text(status.stdout[-16000:])
        command = ["/usr/bin/journalctl", "--no-pager", "--lines=120"]
        for unit in self.units.values():
            command += ["--unit", unit]
        journal = subprocess.run(command, capture_output=True, text=True, timeout=10)
        (self.directory / "journal.txt").write_text(journal.stdout[-32000:])

    def verify(self, mode):
        self.ctl("start", "--no-block", self.units["target"])
        if mode == "cancel-start":
            self.wait(lambda: self.count("attach-start") == 1, "attach started")
            self.ctl("stop", self.units["target"])
            time.sleep(0.5)
            require(self.count("cleanup-recover") == 0, "operator cancellation restarted recovery")
            require(self.count("attach-start") == 1, "cancelled start was retried")
            require(self.count("workload-start") == 0, "cancelled start ran a workload")
            require(self.state("target") == "inactive", "cancelled target did not stop")
            return
        if mode in ("exit-once", "timeout-once", "kill-once"):
            self.wait(lambda: self.count("attach-ready") == 1 and self.count("workload-start") == 1
                      and self.state("target") == "active", "failed target start recovered")
            require(self.count("attach-start") == 2, "unexpected attach attempt count")
            require(self.count("cleanup-recover") == 1, "failed start did not recover exactly once")
            events = [record["event"] for record in self.events()]
            require(events.index("cleanup-recover") < events.index("attach-ready"),
                    "reattach preceded recovery cleanup")
        elif mode in ("cleanup-failure", "foreign-resource"):
            self.wait(lambda: self.state("recovery") == "failed", "coordinator refusal")
            time.sleep(0.5)
            require(self.count("attach-start") == 1, "failed cleanup allowed a new attach")
            require(self.count("workload-start") == 0, "failed cleanup started the workload")
            require((self.directory / "resource").exists(), "refused resource was discarded")
            require(self.state("target") != "active", "refused cleanup activated target")
        elif mode == "repeated-failure":
            self.wait(lambda: self.count("attach-start") >= 3, "bounded retry attempts")
            time.sleep(1)
            count = self.count("attach-start")
            require(count == 3, f"start limit failed: {count} attempts")
            recoveries = self.count("cleanup-recover")
            require(recoveries <= 3, "coordinator start limit failed")
            time.sleep(0.5)
            require(self.count("cleanup-recover") == recoveries, "recovery loop did not settle")
            require(self.count("workload-start") == 0, "failed attach started the workload")
            require(self.state("target") != "active", "failed attach activated target")
        else:
            self.wait(lambda: self.count("workload-start") == 1, "workload start")
            self.ctl("start", self.units["target"], self.units["attach"])
            require(self.count("attach-start") == 1, "duplicate start reran attachment")
            self.ctl("stop", self.units["target"], check=False)
            self.wait(lambda: self.state("daemon") == "inactive", "daemon stopped")
            time.sleep(0.5)
            require(self.count("cleanup-recover") == 0, "planned stop scheduled recovery")
            require(self.count("attach-start") == 1, "planned stop allowed a new attach")
            require(self.count("workload-stop") == 1, "planned stop did not quiesce workload")
            if mode == "failed-stop":
                require(self.state("attach") == "failed", "failed stop was not reported")
                require((self.directory / "resource").exists(), "failed stop lost recovery state")
            else:
                require(self.state("attach") == "inactive", "normal attach stop did not finish")
                require(not (self.directory / "resource").exists(), "normal stop did not clean up")
        require(not any(record["event"].startswith("unsafe-") for record in self.events()),
                "unsafe ordering in simulated lifecycle")


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "actor":
        return actor(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-host", action="store_true", required=True,
                        help="acknowledge that this is an isolated systemd test host")
    parser.add_argument("--helper-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("the service-manager fixture requires Linux and root on a disposable host")
    helper = arguments.helper_binary.resolve(strict=True)
    if not helper.is_file() or not os.access(helper, os.X_OK):
        parser.error("helper binary must be an executable file")
    output = arguments.output.absolute()
    output.mkdir(mode=0o700)
    results = []
    for mode in CASES:
        fixture = Fixture(output, helper, mode)
        result = {"case": mode, "volume": fixture.volume, "status": "failed"}
        try:
            fixture.install()
            fixture.verify(mode)
            result["status"] = "passed"
        except Exception as error:
            result["error"] = str(error)
            print(f"FAIL {mode}: {error}", flush=True)
            try:
                fixture.diagnostics()
            except Exception as diagnostic_error:
                result["diagnostic_error"] = str(diagnostic_error)
        finally:
            try:
                fixture.cleanup()
            except Exception as error:
                result["status"] = "failed"
                result["cleanup_error"] = str(error)
            result["events"] = fixture.events()
            results.append(result)
            (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        print(f"{result['status'].upper()} {mode}", flush=True)
        if result["status"] != "passed":
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
