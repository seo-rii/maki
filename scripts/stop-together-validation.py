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
device; it lets go of the global attach lock for that wait (AUD-197), so the
waits can overlap, where they used to queue on the lock.

`systemctl stop` of the targets returns once the targets' own jobs are
done, before the attach units they are ordered after have stopped, so the
program then looks at each attach unit until it is inactive or failed (for
up to 300 s). systemd forgets a unit once it is inactive, its timestamps
with it, so the times come from the journal of PID 1 for this boot: the
monotonic timestamps of the messages that the stop job of each attach unit
has begun and has finished, after the stop request. It prints, and writes
to DIRECTORY/stop-together.json, when each attach unit's stop began and
ended after the stop was requested, and each opener's account, then requires every stop
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
# How long the attach units may take to stop after `systemctl stop` of the
# targets returned, in looks at their state 0.5 s apart: 300 s, also above
# TimeoutStopSec=120 for each of three queued one after another.
STOP_LOOKS = 600
STOP_LOOK = 0.5
# How often the journal is looked at, 0.5 s apart, for a stop's last message.
JOURNAL_LOOKS = 20
JOURNAL_LOOK = 0.5
# systemd's catalog: a stop job has begun; has finished; a unit has failed.
STOPPING = "de5b426a63be47a7b6ac3eaac82e2f6f"
STOPPED = "9d1aaa27d60140bd96365438aad20286"
UNIT_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"
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


def journal_times(name, started, run, sleep):
    """When the stop job of the attach unit of `name` that began after
    `started` (time.monotonic, which is CLOCK_MONOTONIC as the journal's
    timestamps are) began and finished, in seconds after `started`, with the
    job's result and the unit's.

    They come from the journal of PID 1 for this boot: systemd
    garbage-collects a unit once it is inactive, and `systemctl show` then
    loads a fresh one whose timestamps are all 0, while the journal keeps the
    stop job's messages (systemd's catalog: STOPPING when it has begun,
    STOPPED with JOB_RESULT when it has finished, the same JOB_ID; a unit
    that failed adds UNIT_FAILED with UNIT_RESULT). The finished message can
    reach the journal after systemd shows the unit stopped, so the journal is
    looked at up to JOURNAL_LOOKS times."""
    unit = f"maki-attach@{name}.service"
    since = int(started * 1e6)
    for look in range(JOURNAL_LOOKS):
        if look:
            sleep(JOURNAL_LOOK)
        shown = run(["journalctl", "--boot", "--no-pager", "--output=json", "_PID=1",
                     f"UNIT={unit}"], capture_output=True, text=True, timeout=60)
        entries = []
        for line in shown.stdout.splitlines():
            try:
                item = json.loads(line)
                at = int(item["__MONOTONIC_TIMESTAMP"])
            except (ValueError, KeyError, TypeError):
                continue
            if at >= since and item.get("UNIT") == unit:
                entries.append((at, item))
        entries.sort(key=lambda found: found[0])
        begun = next(((at, item) for at, item in entries if item.get("MESSAGE_ID") == STOPPING),
                     None)
        if begun is None:
            continue
        ended = next(((at, item) for at, item in entries
                      if at >= begun[0] and item.get("MESSAGE_ID") == STOPPED
                      and item.get("JOB_ID") == begun[1].get("JOB_ID")), None)
        if ended is None:
            continue
        failure = next((item.get("UNIT_RESULT", "failed") for at, item in entries
                        if at >= begun[0] and item.get("MESSAGE_ID") == UNIT_FAILED), None)
        return {"stop_began": round(begun[0] / 1e6 - started, 3),
                "stop_ended": round(ended[0] / 1e6 - started, 3),
                "stop_seconds": round((ended[0] - begun[0]) / 1e6, 3),
                "result": failure or "success", "job_result": ended[1].get("JOB_RESULT")}
    raise RuntimeError(f"the journal shows no stop job of {unit} begun and finished after the "
                       "stop request")


def unit_state(unit, run):
    return run(["systemctl", "show", "-P", "ActiveState", unit], capture_output=True, text=True,
               timeout=30).stdout.strip()


def await_stops(volumes, run, sleep):
    """Look at each attach unit's state until it is inactive or failed,
    for up to STOP_LOOKS looks; return the units that were still stopping.

    `systemctl stop` of a target returns once the target's own job is done:
    a target stops before the units it is ordered after, and systemctl waits
    only for the jobs of the units it names. Until an attach unit has
    stopped, systemd shows no time for the end of its stop."""
    stopping = [f"maki-attach@{name}.service" for name in volumes]
    for _ in range(STOP_LOOKS):
        stopping = [unit for unit in stopping if unit_state(unit, run) not in ("inactive", "failed")]
        if not stopping:
            break
        sleep(STOP_LOOK)
    return stopping


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
        returned = clock()
        unfinished = await_stops(volumes, run, sleep)
        stopped = clock()
        times = {}
        for name in volumes:
            if f"maki-attach@{name}.service" in unfinished:
                times[name] = {"stop_began": None, "stop_ended": None, "stop_seconds": None,
                               "result": f"maki-attach@{name}.service did not stop within "
                                         f"{STOP_LOOKS * STOP_LOOK:.0f} s"}
                continue
            try:
                times[name] = journal_times(name, started, run, sleep)
            except RuntimeError as error:
                times[name] = {"stop_began": None, "stop_ended": None, "stop_seconds": None,
                               "result": f"unknown ({error})"}
        accounts = {}
        # An opener whose device was never disconnected lets go at its stop
        # file; one that saw its disconnect ends after its hold.
        patience = hold + 60 if stop.returncode == 0 else 5
        for name, (process, log) in openers.items():
            try:
                status = process.wait(timeout=patience)
            except subprocess.TimeoutExpired:
                (directory / f"stop-opener-{name}").touch()
                status = process.wait(timeout=hold + 10)
            accounts[name] = (status, log.read_text())
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
              "stop_command_seconds": round(returned - started, 3),
              "stopped_seconds": round(stopped - started, 3),
              "volumes": [{"volume": name, "device": devices[name], **times[name],
                           "opener_status": accounts[name][0]} for name in volumes]}
    (directory / "stop-together.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n{'volume':8} {'device':10} {'stop began':>11} {'stop ended':>11} {'stop took':>11}  result")
    def seconds(value):
        return "        - " if value is None else f"{value:9.3f} s"
    for volume in report["volumes"]:
        print(f"{volume['volume']:8} {volume['device']:10} {seconds(volume['stop_began'])} "
              f"{seconds(volume['stop_ended'])} {seconds(volume['stop_seconds'])}  {volume['result']}")
    print(f"systemctl stop returned {stop.returncode} after {report['stop_command_seconds']:.3f} s; "
          f"every attach unit had stopped, or was given up, after {report['stopped_seconds']:.3f} s")
    for name in volumes:
        print(f"\n--- the opener of {devices[name]} ({name}), status {accounts[name][0]}")
        print(accounts[name][1], end="")
    problems = []
    if stop.returncode:
        problems.append(f"systemctl stop exited with status {stop.returncode}")
    for name in volumes:
        if f"maki-attach@{name}.service" in unfinished:
            problems.append(times[name]["result"])
        elif times[name]["result"] != "success":
            problems.append(f"maki-attach@{name}.service stopped with result {times[name]['result']}")
        elif times[name].get("job_result") != "done":
            problems.append(f"the stop job of maki-attach@{name}.service ended {times[name]['job_result']}")
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
