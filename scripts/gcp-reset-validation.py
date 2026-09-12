#!/usr/bin/env python3
"""Qualify Maki durability across whole Google Compute Engine instance resets.

Run this from a machine outside the disposable instance. The script treats a
complete guest ACK as durable only after it validates the manifest and fsyncs a
local ledger plus its parent directory. It then invokes `gcloud compute
instances reset`, waits for that operation to finish and for its owned SSH
child to die, and verifies the data from a new boot with an independent hash
oracle. It never asks the guest to sync, unmount, drain, reboot, or power off
after ACK.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import selectors
import shlex
import signal
import subprocess
import time
import uuid


PREFIX = b"MAKI_GCP_RESET_V1 "
MAX_FRAME = 16384
MAX_OUTPUT = 8 << 20
BOOT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def mode_for_cycle(cycle):
    if type(cycle) is not int or not 0 <= cycle < 64:
        raise ValueError("invalid cycle")
    return "flush" if cycle % 2 == 0 else "fua"


def expected_records(cycle):
    mode_for_cycle(cycle)
    records = []
    for index in range(16):
        offset = (index % 8) * (16 << 20) + (index // 8) * 4096
        block = hashlib.sha256(f"maki-gcp-reset-v1:{cycle}:{index}".encode()).digest() * 128
        records.append({"offset": offset, "length": 4096,
                        "sha256": hashlib.sha256(block).hexdigest()})
    return records


def validate_boot_id(value):
    if not isinstance(value, str) or BOOT_ID.fullmatch(value) is None:
        raise ValueError("invalid boot identity")
    return value


def require_new_boot(previous, current):
    validate_boot_id(current)
    if previous is not None:
        validate_boot_id(previous)
        if previous == current:
            raise ValueError("boot ID did not change after reset")


def require_unique_boot(seen, current):
    validate_boot_id(current)
    if current in seen:
        raise ValueError("boot ID was reused during reset campaign")
    seen.add(current)


def validate_ready(ready, expected_fs_uuid):
    if (not isinstance(ready, dict) or ready.get("event") != "ready"
            or ready.get("provider") != "local-aes-gcm-siv"
            or ready.get("can_flush") is not True or ready.get("can_fua") is not True):
        raise ValueError("guest did not prove native provider FLUSH and FUA support")
    if (ready.get("witness_service") != "active"
            or ready.get("graceful_stop_witness") != "absent"):
        raise ValueError("graceful shutdown witness invalidated hard-reset evidence")
    fs_uuid = ready.get("fs_uuid")
    validate_boot_id(fs_uuid)
    if expected_fs_uuid is not None and fs_uuid != expected_fs_uuid:
        raise ValueError("persistent data filesystem UUID changed")
    return fs_uuid


def decode_frame(line, token, cycle):
    if len(line) > MAX_FRAME:
        raise ValueError("oversized SSH control line")
    if not line.startswith(PREFIX):
        return None
    try:
        value = json.loads(line[len(PREFIX):])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid SSH control frame") from error
    if not isinstance(value, dict):
        raise ValueError("control frame must be an object")
    if (value.get("token") != token or type(value.get("cycle")) is not int
            or value["cycle"] != cycle):
        raise ValueError("SSH frame identity mismatch")
    validate_boot_id(value.get("boot_id"))
    if not isinstance(value.get("event"), str):
        raise ValueError("missing event")
    return value


def validate_records(records, expected):
    if not isinstance(records, list) or json.dumps(records, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError("record manifest mismatch, missing, reordered, or duplicated")


def validate_ack(event, cycle):
    if not isinstance(event, dict):
        raise ValueError("ACK must be an object")
    validate_boot_id(event.get("boot_id"))
    if (event.get("event") != "ack" or event.get("command") != f"write-{cycle}"
            or type(event.get("cycle")) is not int or event["cycle"] != cycle
            or event.get("mode") != mode_for_cycle(cycle)):
        raise ValueError("false, incomplete, or unexpected durable ACK")
    validate_records(event.get("records"), expected_records(cycle))


def record_ack(ledger, event, cycle):
    validate_ack(event, cycle)
    record = {key: event[key] for key in
              ("event", "command", "cycle", "mode", "boot_id", "records")}
    descriptor = os.open(ledger, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(ledger.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def load_ledger(ledger):
    if ledger.stat().st_size > (1 << 20):
        raise ValueError("oversized ACK ledger")
    raw = ledger.read_text(encoding="utf-8")
    if not raw or not raw.endswith("\n"):
        raise ValueError("empty or truncated ACK ledger")
    latest = None
    seen_boots = set()
    for cycle, line in enumerate(raw.splitlines()):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("invalid ACK ledger") from error
        validate_ack(event, cycle)
        require_unique_boot(seen_boots, event["boot_id"])
        latest = event
    return latest


def verify_readbacks(expected, actual):
    validate_records(actual, expected)


def save_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def bounded_run(command, timeout):
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError(f"command deadline: {command[0]}") from error
    if len(result.stdout) + len(result.stderr) > (1 << 20):
        raise ValueError("gcloud output limit exceeded")
    if result.returncode != 0:
        detail = result.stderr[-4096:].decode(errors="replace")
        raise RuntimeError(f"gcloud exited {result.returncode}: {detail}")
    return result


def decode_json_result(result, what):
    try:
        value = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid {what} JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"invalid {what} response")
    return value


def resource_identity(args, timeout):
    instance_result = bounded_run(
        [args.gcloud, "compute", "instances", "describe", args.instance,
         "--project", args.project, "--zone", args.zone, "--format=json"], timeout)
    instance = decode_json_result(instance_result, "instance describe")
    attachments = instance.get("disks")
    if not isinstance(attachments, list):
        raise ValueError("instance disk attachments missing")
    matches = [attachment for attachment in attachments
               if isinstance(attachment, dict) and attachment.get("boot") is False
               and (attachment.get("deviceName") == args.data_disk
                    or str(attachment.get("source", "")).rsplit("/", 1)[-1] == args.data_disk)]
    if len(matches) != 1:
        raise ValueError("expected one attached persistent data disk")
    attachment = matches[0]
    disk_result = bounded_run(
        [args.gcloud, "compute", "disks", "describe", args.data_disk,
         "--project", args.project, "--zone", args.zone, "--format=json"], timeout)
    disk = decode_json_result(disk_result, "disk describe")
    values = {
        "instance_id": str(instance.get("id", "")),
        "data_disk_id": str(disk.get("id", "")),
        "data_disk_self_link": disk.get("selfLink"),
        "attachment_source": attachment.get("source"),
        "attachment_device_name": attachment.get("deviceName"),
        "status": instance.get("status"),
    }
    for field in ("instance_id", "data_disk_id", "data_disk_self_link",
                  "attachment_source", "attachment_device_name", "status"):
        if not isinstance(values[field], str) or not values[field]:
            raise ValueError(f"missing resource identity field: {field}")
    return values


def validate_resource_identity(baseline, current, require_running=True):
    for field in ("instance_id", "data_disk_id", "data_disk_self_link",
                  "attachment_source", "attachment_device_name"):
        if baseline.get(field) != current.get(field):
            raise ValueError(f"GCE resource identity changed: {field}")
    if require_running and current.get("status") != "RUNNING":
        raise ValueError("GCE instance is not RUNNING")


def wait_for_running(args, timeout, baseline):
    until = time.monotonic() + timeout
    last_status = None
    while True:
        remaining = until - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"instance did not return to RUNNING state: {last_status}")
        current = resource_identity(args, min(remaining, 30))
        validate_resource_identity(baseline, current, require_running=False)
        last_status = current["status"]
        if last_status == "RUNNING":
            return current
        time.sleep(min(2, max(0, until - time.monotonic())))


def reset_and_wait(args, command, baseline):
    result = bounded_run(command, args.timeout)
    wait_for_running(args, args.timeout, baseline)
    return result


def ssh_command(args, token, cycle, verify_only):
    guest = ["sudo", "-n", getattr(args, "guest_python", "python3"), args.guest_agent,
             "--token", token, "--cycle", str(cycle), "--config", args.guest_config,
             "--plugin", args.guest_plugin]
    if verify_only:
        guest.append("--verify-only")
    return [args.gcloud, "compute", "ssh", args.instance,
            "--project", args.project, "--zone", args.zone, "--quiet",
            "--command", shlex.join(guest),
            "--ssh-flag=-oBatchMode=yes",
            f"--ssh-flag=-oConnectTimeout={args.connect_timeout}",
            "--ssh-flag=-oServerAliveInterval=5", "--ssh-flag=-oServerAliveCountMax=3"]


def reset_instance(args, timeout):
    command = [args.gcloud, "compute", "instances", "reset", args.instance,
               "--project", args.project, "--zone", args.zone, "--quiet", "--format=json"]
    return bounded_run(command, timeout)


def offline_check_command(args):
    remote = shlex.join(["sudo", "-n", args.guest_maki, "check", args.guest_config, "--deep"])
    return [args.gcloud, "compute", "ssh", args.instance,
            "--project", args.project, "--zone", args.zone, "--quiet",
            "--command", remote, "--ssh-flag=-oBatchMode=yes",
            f"--ssh-flag=-oConnectTimeout={args.connect_timeout}"]


def run_offline_check(args, timeout):
    result = bounded_run(offline_check_command(args), timeout)
    return {"returncode": result.returncode,
            "stdout": result.stdout.decode(errors="replace"),
            "stderr": result.stderr.decode(errors="replace")}


class RemoteProcess:
    def __init__(self, command, directory, token, cycle):
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.token, self.cycle = token, cycle
        self.buffer, self.total = bytearray(), 0
        self.stdout_log = open(directory / "stdout.log", "xb")
        self.stderr_log = open(directory / "stderr.log", "xb")
        os.chmod(directory / "stdout.log", 0o600)
        os.chmod(directory / "stderr.log", 0o600)
        self.selector = selectors.DefaultSelector()
        self.child = None
        try:
            self.child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=self.stderr_log,
                                          start_new_session=True, bufsize=0)
            self.selector.register(self.child.stdout, selectors.EVENT_READ)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def event(self, timeout):
        until = time.monotonic() + timeout
        while True:
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                line = bytes(self.buffer[:newline]).rstrip(b"\r")
                del self.buffer[:newline + 1]
                frame = decode_frame(line, self.token, self.cycle)
                if frame is not None:
                    return frame
                continue
            if len(self.buffer) > MAX_FRAME:
                raise ValueError("unterminated oversized SSH control line")
            remaining = until - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise TimeoutError("guest SSH event deadline")
            chunk = os.read(self.child.stdout.fileno(), 4096)
            if not chunk:
                status = self.child.poll()
                raise RuntimeError(f"guest SSH closed before expected event: {status}")
            self.total += len(chunk)
            if self.total > MAX_OUTPUT:
                raise ValueError("SSH output limit exceeded")
            self.stdout_log.write(chunk)
            self.stdout_log.flush()
            self.buffer.extend(chunk)

    def expect(self, event, timeout):
        frame = self.event(timeout)
        if frame["event"] == "error":
            raise RuntimeError("guest failed: " + str(frame.get("message", "unknown"))[:2048])
        if frame["event"] != event:
            raise ValueError(f"expected {event}, received {frame['event']}")
        return frame

    def wait_after_reset(self, timeout):
        try:
            status = self.child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self._kill_owned()
            raise TimeoutError("old guest SSH remained alive after reset") from error
        return status

    def wait_clean(self, timeout):
        try:
            status = self.child.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self._kill_owned()
            raise TimeoutError("verification SSH did not exit") from error
        if status != 0:
            raise RuntimeError(f"verification SSH exited {status}")

    def _kill_owned(self):
        if self.child is not None and self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=5)

    def close(self):
        self._kill_owned()
        if self.child is not None and self.child.stdout is not None:
            self.child.stdout.close()
        self.selector.close()
        self.stdout_log.close()
        self.stderr_log.close()


def cut_instance(args, process, baseline=None):
    if process.child.poll() is not None:
        raise RuntimeError("guest SSH exited before reset was invoked")
    reset_result = reset_instance(args, args.timeout)
    running = None
    if baseline is not None:
        running = wait_for_running(args, args.timeout, baseline)
    ssh_status = process.wait_after_reset(args.timeout)
    return {"reset_returncode": reset_result.returncode, "ssh_returncode": ssh_status,
            "post_reset_status": None if running is None else running["status"]}


def launch_guest(args, token, cycle, verify_only, output):
    until = time.monotonic() + args.timeout
    attempt = 0
    errors = []
    while True:
        remaining = until - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("instance did not accept a guest qualification SSH session: " + "; ".join(errors[-3:]))
        process = RemoteProcess(ssh_command(args, token, cycle, verify_only),
                                output / f"attempt-{attempt}", token, cycle)
        try:
            ready = process.expect("ready", min(remaining, args.connect_timeout + 30))
            return process, ready
        except (RuntimeError, TimeoutError) as error:
            errors.append(str(error))
            process.close()
            attempt += 1
            time.sleep(min(2, max(0, until - time.monotonic())))
        except BaseException:
            process.close()
            raise


def campaign(args):
    os.umask(0o077)
    if not 2 <= args.cycles <= 64:
        raise ValueError("cycles must be 2..64")
    if not 10 <= args.timeout <= 900 or not 1 <= args.connect_timeout <= 60:
        raise ValueError("invalid timeout")
    for name, value, pattern in (
            ("project", args.project, r"[a-z][a-z0-9-]{4,61}[a-z0-9]"),
            ("zone", args.zone, r"[a-z0-9-]{3,63}"),
            ("instance", args.instance, r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?")):
        if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
            raise ValueError(f"invalid {name}")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    token = uuid.uuid4().hex
    ledger = args.output / "host-acks.jsonl"
    baseline = resource_identity(args, args.timeout)
    validate_resource_identity(baseline, baseline)
    result = {"passed": False, "fault_scope": "whole GCE instance reset",
              "instance": args.instance, "project": args.project, "zone": args.zone,
              "data_disk": args.data_disk, "resource_identity": baseline,
              "cycles": args.cycles, "token": token, "boots": []}
    seen_boots = set()
    fs_uuid = None
    try:
        for cycle in range(args.cycles + 1):
            verify_only = cycle == args.cycles
            entry = {"cycle": cycle, "verify_only": verify_only}
            result["boots"].append(entry)
            process, ready = launch_guest(args, token, cycle, verify_only,
                                          args.output / f"cycle-{cycle}")
            entry["ready"] = ready
            current_boot = ready["boot_id"]
            require_unique_boot(seen_boots, current_boot)
            fs_uuid = validate_ready(ready, fs_uuid)
            current_resources = resource_identity(args, args.timeout)
            validate_resource_identity(baseline, current_resources)
            try:
                if cycle:
                    readback = process.expect("readback", args.timeout)
                    if readback.get("generation") != cycle - 1:
                        raise ValueError("guest read back the wrong generation")
                    expected = expected_records(cycle - 1)
                    verify_readbacks(expected, readback.get("records"))
                    verified = process.expect("verified", args.timeout)
                    if verified.get("generation") != cycle - 1 or verified.get("count") != 16:
                        raise ValueError("incomplete readback verification")
                    entry["verified_generation"] = cycle - 1
                    entry["verified_units"] = 16
                if verify_only:
                    process.wait_clean(args.timeout)
                else:
                    ack = process.expect("ack", args.timeout)
                    if ack["boot_id"] != current_boot:
                        raise ValueError("ACK boot identity changed")
                    record_ack(ledger, ack, cycle)
                    entry["acked_units"] = 16
                    entry["mode"] = mode_for_cycle(cycle)
                    entry["reset_ssh_status"] = cut_instance(args, process, baseline)
            finally:
                process.close()
            save_json(args.output / "results.json", result)
        latest = load_ledger(ledger)
        if latest["cycle"] != args.cycles - 1:
            raise ValueError("ACK ledger did not cover every reset cycle")
        result["offline_deep_check"] = run_offline_check(args, args.timeout)
        final_resources = resource_identity(args, args.timeout)
        validate_resource_identity(baseline, final_resources)
        result["fs_uuid"] = fs_uuid
        result["passed"] = True
    except BaseException as error:
        result["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        save_json(args.output / "results.json", result)
    print(json.dumps({"passed": True, "cycles": args.cycles, "output": str(args.output)}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--instance", required=True)
    parser.add_argument("--data-disk", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--cycles", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument("--connect-timeout", type=int, default=10)
    parser.add_argument("--gcloud", default="gcloud")
    parser.add_argument("--guest-python", default="python3")
    parser.add_argument("--guest-agent", default="/opt/maki/gcp-reset-guest.py")
    parser.add_argument("--guest-config", default="/mnt/maki-data/config.toml")
    parser.add_argument("--guest-plugin", default="/opt/maki/libmaki_nbdkit.so")
    parser.add_argument("--guest-maki", default="/opt/maki/maki")
    campaign(parser.parse_args())


if __name__ == "__main__":
    main()
