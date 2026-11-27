#!/usr/bin/env python3
"""Stop several attached volumes together on the installed package, each
device held open, and record how long each stop takes (AUD-197).

As root, on a disposable host where the Debian package is installed and the
quick start has run (CI's kernel-lifecycle job runs it after the quick
start):

    sudo python3 -B scripts/stop-together-validation.py [--volumes 3] [--hold 10] DIRECTORY

Each volume `stopN` is provisioned with the quick start's blocks and the
first-volume bootstrap, their `demo` replaced by its name, as an operator
edits the variables for another volume: the key, the configuration (written
to DIRECTORY), the creation and the bootstrap, which uses /dev/nbd8 (its
`dev` edited too) for one volume after the other. The quick start's start block then starts each
volume's target, whose attach takes the lowest free device. With every
target started, scripts/privileged_validation_opener.py holds each volume's
device open, and keeps it `--hold` seconds after its disconnect; one
`systemctl stop` then stops every target. Each attach unit's stop runs
`maki-attach cleanup`, whose disconnect waits for the opener to close the
device, while it holds the global attach lock.

It prints, and writes to DIRECTORY/stop-together.json, when each attach
unit's stop began and ended after the stop was requested (systemd's
monotonic timestamps) and each opener's account, then requires every stop
to have succeeded, every opener to have seen its disconnect and kept the
connection shown until it closed the device, and every attachment to be
gone. It measures: it requires neither that the stops overlap nor that
they queue. A run that passes removes the volumes as the quick start's
clean-up does; one that fails leaves them for inspection.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


HERE = Path(__file__).resolve().parent
OPENER = HERE / "privileged_validation_opener.py"
STATE = Path("/run/maki-attach")
SYSFS = Path("/sys/block")
PROVISION = ("1. Create the key", "2. Write the volume configuration", "3. Create the volume")
# The device the bootstraps use, one after the other: not the quick start's
# /dev/nbd0, which an earlier run on the host may have left attached.
PROVISIONING_DEVICE = "/dev/nbd8"
START = "6. Start the lifecycle and write data"
BLOCK_TIMEOUT = 600
# Above every unit's TimeoutStopSec=120.
STOP_TIMEOUT = 600
# A hold the helper's 15 s wait for the opener outlasts.
MAX_HOLD = 14


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUICKSTART = load("documented_quickstart")


def names(count):
    return [f"stop{index}" for index in range(1, count + 1)]


def documented(heading):
    """(label, block) of each block of the quick start's step `heading`
    (the bootstrap for its step 4)."""
    prefix = f"{QUICKSTART.QUICKSTART.name}, {heading}"
    found = [(label, block) for label, block in QUICKSTART.steps()
             if label == prefix or label.startswith(prefix + ",") or label.startswith(prefix + ":")]
    if not found:
        raise ValueError(f"the quick start has no step {heading!r}")
    return found


def provision_blocks(name):
    """The blocks that provision the volume `name`: the quick start's key,
    configuration and creation blocks and the bootstrap, `demo` replaced,
    and the bootstrap's device /dev/nbd0 by PROVISIONING_DEVICE."""
    found = [(label, block.replace("demo", name))
             for heading in (*PROVISION, QUICKSTART.PROVISION_STEP)
             for label, block in documented(heading)]
    label, block = found[-1]
    if block.count("\ndev=/dev/nbd0\n") != 1:
        raise ValueError("the bootstrap no longer provisions on dev=/dev/nbd0")
    found[-1] = (label, block.replace("\ndev=/dev/nbd0\n", f"\ndev={PROVISIONING_DEVICE}\n"))
    return found


def start_block(name):
    [(label, block)] = documented(START)
    return label, block.replace("demo", name)


def configuration(name):
    return QUICKSTART.configuration().replace("demo", name)


def announce(message):
    print(f"\n==> {message}", flush=True)


def run_block(name, label, block, directory, run):
    announce(f"{name}: {label}")
    result = run(["bash", "-c", block], cwd=directory, stdin=subprocess.DEVNULL,
                 timeout=BLOCK_TIMEOUT)
    if result.returncode:
        raise RuntimeError(f"{name}: {label} failed with status {result.returncode}")


def device_of(name, state=STATE):
    """The device the attach record of `name` names."""
    device = json.loads((state / f"{name}.nbd").read_text()).get("device", "")
    if not re.fullmatch(r"/dev/nbd(?:0|[1-9][0-9]{0,2})", str(device)):
        raise RuntimeError(f"the attach record of {name} names no NBD device ({device!r})")
    return device


def unit_times(name, started, run):
    """When the attach unit of `name` began and ended its stop, in seconds
    after `started` (time.monotonic, systemd's CLOCK_MONOTONIC), and its
    result."""
    shown = run(["systemctl", "show", "--property=ActiveExitTimestampMonotonic",
                 "--property=InactiveEnterTimestampMonotonic", "--property=Result",
                 f"maki-attach@{name}.service"], capture_output=True, text=True, timeout=30)
    values = dict(line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line)
    try:
        began = int(values["ActiveExitTimestampMonotonic"])
        ended = int(values["InactiveEnterTimestampMonotonic"])
    except (KeyError, ValueError):
        raise RuntimeError(f"systemd shows no stop of maki-attach@{name}.service: {shown.stdout!r}")
    if not 0 < began <= ended:
        raise RuntimeError(f"systemd shows no completed stop of maki-attach@{name}.service: "
                           f"{shown.stdout!r}")
    return {"stop_began": round(began / 1e6 - started, 3), "stop_ended": round(ended / 1e6 - started, 3),
            "stop_seconds": round((ended - began) / 1e6, 3), "result": values.get("Result")}


def unit_state(unit, run):
    return run(["systemctl", "show", "-P", "ActiveState", unit], capture_output=True, text=True,
               timeout=30).stdout.strip()


def leftovers(name, device, run, sleep, state=STATE, sysfs=SYSFS):
    """What is left of the attachment of `name` on `device`."""
    found = []
    # The attach unit queues the daemon's stop without waiting for it.
    for _ in range(600):
        if unit_state(f"maki@{name}.service", run) == "inactive":
            break
        sleep(0.1)
    for unit in (f"maki-attach@{name}.service", f"maki@{name}.service"):
        active = unit_state(unit, run)
        if active != "inactive":
            found.append(f"{name}: {unit} is {active}")
    if (state / f"{name}.nbd").exists():
        found.append(f"{name}: its attach record remains")
    if run(["findmnt", "-M", f"/srv/{name}"], capture_output=True, timeout=30).returncode == 0:
        found.append(f"{name}: /srv/{name} is still mounted")
    backend = sysfs / device.removeprefix("/dev/") / "backend"
    if backend.exists() and backend.read_text().strip():
        found.append(f"{name}: {device} still shows the connection {backend.read_text().strip()}")
    return found


def stop_together(volumes, hold, directory, *, run=subprocess.run, popen=subprocess.Popen,
                  clock=time.monotonic, sleep=time.sleep, state=STATE, sysfs=SYSFS):
    """Hold each started volume's device open, stop every target at once
    and report each attach unit's stop. Raises after the report if a stop
    failed, an opener did not see its disconnect, or anything is left."""
    devices = {name: device_of(name, state) for name in volumes}
    openers = {}
    try:
        for name, device in devices.items():
            log = directory / f"opener-{name}.txt"
            with log.open("w") as output:
                openers[name] = (popen([sys.executable, "-B", str(OPENER), "--device", device,
                                        "--stop-file", str(directory / f"stop-opener-{name}"),
                                        "--hold", str(hold)],
                                       stdout=output, stderr=subprocess.STDOUT), log)
        for name, (process, log) in openers.items():
            for _ in range(200):
                if " holding the device open" in log.read_text() or process.poll() is not None:
                    break
                sleep(0.05)
            if " holding the device open" not in log.read_text():
                raise RuntimeError(f"the opener did not start holding {devices[name]}: "
                                   f"{log.read_text()!r}")
        targets = [f"maki-workload@{name}.target" for name in volumes]
        announce(f"stopping {' '.join(targets)} together, each device held open for {hold} s "
                 "after its disconnect")
        started = clock()
        stop = run(["systemctl", "stop", *targets], timeout=STOP_TIMEOUT)
        stopped = clock()
        times = {name: unit_times(name, started, run) for name in volumes}
        accounts = {}
        for name, (process, log) in openers.items():
            accounts[name] = (process.wait(timeout=hold + 60), log.read_text())
    finally:
        for name in openers:
            (directory / f"stop-opener-{name}").touch()
        for process, _ in openers.values():
            try:
                process.wait(timeout=hold + 60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    report = {"hold_seconds": hold, "stop_status": stop.returncode,
              "stop_command_seconds": round(stopped - started, 3),
              "volumes": [{"volume": name, "device": devices[name], **times[name],
                           "opener_status": accounts[name][0]} for name in volumes]}
    (directory / "stop-together.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n{'volume':8} {'device':10} {'stop began':>11} {'stop ended':>11} {'stop took':>11}  result")
    for volume in report["volumes"]:
        print(f"{volume['volume']:8} {volume['device']:10} {volume['stop_began']:9.3f} s "
              f"{volume['stop_ended']:9.3f} s {volume['stop_seconds']:9.3f} s  {volume['result']}")
    print(f"systemctl stop returned {stop.returncode} after {report['stop_command_seconds']:.3f} s")
    for name in volumes:
        print(f"\n--- the opener of {devices[name]} ({name}), status {accounts[name][0]}")
        print(accounts[name][1], end="")
    problems = []
    if stop.returncode:
        problems.append(f"systemctl stop exited with status {stop.returncode}")
    for name in volumes:
        if times[name]["result"] != "success":
            problems.append(f"maki-attach@{name}.service stopped with result {times[name]['result']}")
        if accounts[name][0]:
            problems.append(f"the opener of {devices[name]} exited with status {accounts[name][0]}")
        problems += leftovers(name, devices[name], run, sleep, state, sysfs)
    if problems:
        raise RuntimeError("; ".join(problems))
    return report


def clean_up(name, run):
    """What the quick start's clean-up removes, for `name`."""
    for argv in (["rmdir", f"/srv/{name}"],
                 ["rm", "-rf", f"/var/lib/maki/{name}", f"/etc/maki/attach/{name}.toml",
                  f"/etc/maki/volumes/{name}.toml"],
                 ["shred", "-u", f"/etc/maki/secrets/{name}.token"]):
        if run(argv, timeout=60).returncode:
            raise RuntimeError(f"{name}: {' '.join(argv)} failed")


def bounded(low, high, kind):
    def parse(text):
        value = kind(text)
        if not low <= value <= high:
            raise argparse.ArgumentTypeError(f"must be from {low} to {high}")
        return value
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--volumes", type=bounded(2, 8, int), default=3)
    parser.add_argument("--hold", type=bounded(1, MAX_HOLD, int), default=10,
                        help="seconds each opener keeps its device after the disconnect")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error("run this as root on a disposable host with the package installed")
    volumes = names(args.volumes)
    for name in volumes:
        for path in (STATE / f"{name}.nbd", Path(f"/etc/maki/volumes/{name}.toml"),
                     Path(f"/var/lib/maki/{name}"), Path(f"/srv/{name}")):
            if path.exists() or path.is_symlink():
                parser.error(f"{path} exists: the volumes {', '.join(volumes)} must be new")
    args.directory.mkdir(parents=True, exist_ok=True)
    for name in volumes:
        (args.directory / f"{name}.toml").write_text(configuration(name), encoding="utf-8")
        for label, block in provision_blocks(name):
            run_block(name, label, block, args.directory, subprocess.run)
    for name in volumes:
        run_block(name, *start_block(name), args.directory, subprocess.run)
    stop_together(volumes, args.hold, args.directory)
    for name in volumes:
        clean_up(name, subprocess.run)
    announce("every volume stopped, released and removed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"\nstop-together validation failed: {error}", file=sys.stderr)
        sys.exit(1)
