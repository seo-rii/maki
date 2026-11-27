"""Capture what the helper's readers parse on a real attachment, for
privileged-linux-validation.sh only.

The fuzz targets `helper_reports` and `helper_sysfs` feed the readers of
`maki-attach` with command output and block topology made up from what the
code expects. This runs, as root and read-only, the commands those readers
are handed, as the helper runs them: the same arguments, an environment of
only `PATH` (systemd's default) and `LC_ALL=C`, no standard input and no
inherited descriptors, a probe's 15 seconds and 64 KiB. The label probe reads
the device through a descriptor this process holds (`/proc/<pid>/fd/<n>`),
as the helper's does.
It prints one JSON document: each command's argument vector, exit status,
standard output and standard error; the device's nodes below
/sys/class/block (the device, its partitions and every mapping above them)
in the `helper_sysfs` input's line format (`path=content`, `path/`,
`path>target`, relative to /sys/class/block); and the mount table the helper
reads. Nothing it captures is a key or a payload.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SYSFS = Path("/sys/class/block")
MOUNTINFO = Path("/proc/self/mountinfo")
# What `command::controlled` gives every command the helper runs.
ENVIRONMENT = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
               "LC_ALL": "C"}
# `command::Policy::PROBE`.
TIMEOUT = 15
MAX_OUTPUT = 64 * 1024
# The attributes the helper's sysfs readers open.
ATTRIBUTES = ("dev", "size", "partition", "start", "pid", "backend", "dm/name", "dm/uuid")


def lvm_report(devices):
    """`lvm_preflight::report_command`."""
    return ["lvm", "fullreport", "--readonly", "--all", "--foreign", "--shared",
            "--reportformat", "json", "--binary", "--devices", ",".join(devices),
            "--config", 'report { list_item_separator="," }',
            "--configreport", "vg", "--options",
            "vg_name,vg_uuid,vg_seqno,pv_count,vg_missing_pv_count,vg_partial,vg_exported,"
            "vg_systemid,vg_lock_type",
            "--configreport", "pv", "--options", "pv_name,pv_uuid,vg_uuid,pv_missing,pv_duplicate",
            "--configreport", "lv", "--options", "lv_name,lv_uuid,vg_uuid,lv_layout",
            "--configreport", "pvseg", "--options", "pv_uuid",
            "--configreport", "seg", "--options", "lv_uuid"]


def label_probe(path):
    """`lvm_preflight::read_labels`, on the descriptor path it pins."""
    return ["blkid", "--probe", "--output", "export", "--match-tag", "TYPE", "--match-tag", "UUID",
            "--match-tag", "PTTYPE", path]


def filesystem_probe(device):
    """The `VerifyFilesystemIdentity` step's probe."""
    return ["blkid", "--probe", "--output", "export", "--match-tag", "TYPE", "--match-tag", "UUID",
            device]


def mapping_info(name):
    """`recover::dmsetup_info_command`."""
    return ["dmsetup", "info", "--noheadings", "--columns", "--separator", "\t", "-o",
            "name,uuid,major,minor,open", name]


def lv_size(vg, lv):
    """The probe whose output `lv_size_of` reads."""
    return ["blockdev", "--getsize64", f"/dev/{vg}/{lv}"]


def uuid_value(source):
    """`blkid_uuid_command`, for a mount source."""
    return ["blkid", "-o", "value", "-s", "UUID", "--", source]


def run(argv):
    """Run `argv` as the helper runs a probe."""
    try:
        result = subprocess.run(argv, env=ENVIRONMENT, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "error": str(error)}
    return {"argv": argv, "status": result.returncode,
            "stdout": result.stdout[:MAX_OUTPUT].decode("utf-8", "backslashreplace"),
            "stderr": result.stderr[:MAX_OUTPUT].decode("utf-8", "backslashreplace"),
            "truncated": len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT}


def nodes(sysfs, name):
    """The device `name`, its partitions and every node above them, by
    their names in `sysfs`, in the order found."""
    found = [name] + sorted(entry.name for entry in sysfs.iterdir()
                            if re.fullmatch(re.escape(name) + r"p[0-9]+", entry.name))
    for node in found:
        holders = sysfs / node / "holders"
        if holders.is_dir():
            found += [holder for holder in sorted(entry.name for entry in holders.iterdir())
                      if holder not in found]
    return found


def tree(sysfs, name):
    """The lines of the `helper_sysfs` input that make `nodes(sysfs, name)`
    as they are."""
    lines = []
    for node in nodes(sysfs, name):
        lines.append(f"{node}/")
        for attribute in ATTRIBUTES:
            path = sysfs / node / attribute
            if path.is_file():
                lines.append(f"{node}/{attribute}={path.read_text(errors='backslashreplace').strip()}")
        for directory in ("holders", "slaves"):
            if (sysfs / node / directory).is_dir():
                lines.append(f"{node}/{directory}/")
                lines += [f"{node}/{directory}/{entry}>{entry}" for entry in
                          sorted(entry.name for entry in (sysfs / node / directory).iterdir())]
    return lines


def mount_source(mountinfo, mountpoint):
    """The source of the mount at `mountpoint` in `mountinfo`, or None."""
    for line in mountinfo.splitlines():
        fields = line.split(" ")
        if len(fields) > 4 and fields[4] == mountpoint and " - " in line:
            after = line.split(" - ", 1)[1].split(" ")
            if len(after) > 1:
                return after[1]
    return None


def capture(device, vg, lv, mountpoint, *, sysfs=SYSFS, mountinfo=MOUNTINFO, execute=run):
    name = os.path.basename(device)
    table = mountinfo.read_text(errors="backslashreplace")
    mapping = f"{vg.replace('-', '--')}-{lv.replace('-', '--')}"
    partitions = [f"/dev/{node}" for node in nodes(sysfs, name)[1:] if node.startswith(name + "p")]
    # The probe opens the device through this process's descriptor.
    descriptor = os.open(device, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        label = execute(label_probe(f"/proc/{os.getpid()}/fd/{descriptor}"))
    finally:
        os.close(descriptor)
    commands = {
        "lvm_report": execute(lvm_report([device, *partitions])),
        "pv_label": label,
        "filesystem": execute(filesystem_probe(f"/dev/{vg}/{lv}")),
        "dm_info": execute(mapping_info(mapping)),
        "lv_size": execute(lv_size(vg, lv)),
    }
    source = mount_source(table, mountpoint)
    if source is not None:
        commands["blkid_value"] = execute(uuid_value(source))
    return {"device": device, "vg": vg, "lv": lv, "mountpoint": mountpoint,
            "commands": commands, "sysfs": "\n".join(tree(sysfs, name)) + "\n",
            "mountinfo": table}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--device", required=True)
    parser.add_argument("--vg", required=True)
    parser.add_argument("--lv", required=True)
    parser.add_argument("--mountpoint", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"/dev/nbd(?:0|[1-9][0-9]{0,2})", args.device):
        parser.error("device must be a canonical /dev/nbdN")
    json.dump(capture(args.device, args.vg, args.lv, args.mountpoint), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
