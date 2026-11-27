"""Write the documented installation, quick start and first-volume bootstrap
as one Bash program, as an operator pastes them in order into one root shell.

The steps are the guides' own blocks, read the way the documentation tests
read them (each ```bash fence; the bootstrap is the first-volume guide's block
in its section 1): the Debian guide's "Install the Maki package" section, then
the quick start, whose step 4 is the bootstrap. The quick start's ```toml
block is the volume configuration that its step 2 installs from `demo.toml`.

    python3 -B scripts/documented_quickstart.py DIRECTORY

writes DIRECTORY/demo.toml and DIRECTORY/quickstart.sh. Run the program as
root in DIRECTORY, beside the package as `maki.deb`, on a disposable host:
`sudo bash quickstart.sh`. With `--stop-once mkfs.xfs` or `--stop-once
vgchange`, the bootstrap's first run has a shim first on PATH that fails
that command, and the program requires that the run stopped there with its
record and the device showing its connection, then runs the same block again
as the first-volume guide's recovery notes say: after `mkfs.xfs`, the next
run must release the export, stop the daemon, remove the record and fail;
the volume is reset (its backing directory removed while the daemon is
stopped, the creation block run again) and a third run starts over. After
`vgchange`, the next run must finish. It runs under `set -e -o pipefail` and checks
each block's status after it, so it stops at a failed command that `set -e`
stops at (a pipeline included, whichever of its commands failed) and at a
block whose last command failed, an `&&` list that ends the block included,
and says which step it was in. `set -e` does not stop at a failure inside an
`&&` or `||` list before a block's last command. The writer refuses a block
that Bash cannot read, and one with `&&` or `||`, matched as text, on any line that Bash's `declare -f`
prints at the block's own level (a subshell's commands print there too) up to
the last such line, before the last line it prints at that level, that ends in `;` or
holds a here-document's command; so a condition, a test expression, quoted
text or a command substitution there is refused too. Below the block's level
(the bodies of `if`, `while`, `for` or `case`, brace groups and functions,
at any depth) it refuses every line with `&&` or `||` that `DEEPER_LISTS`
does not name for that block: the guides' current ones, each read. It does
not see `set -e`'s other exemptions (a negated or a background command): a
failure there lets the program go on. Here-document bodies run in a shell of
their own and are not read. The check relies on the layout of `declare -f`.
"""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GUIDES = ROOT / "docs" / "getting-started"
INSTALLATION = GUIDES / "installation-debian.md"
QUICKSTART = GUIDES / "quickstart.md"
FIRST_VOLUME = GUIDES / "first-volume.md"
INSTALL_SECTION = "Install the Maki package"
PROVISION_STEP = "4. Provision LVM and XFS on the export"
BOOTSTRAP_SECTION = "1. Provision and record the layout"

PRELUDE = """\
# Written by scripts/documented_quickstart.py from the guides. Run it as root
# in the directory that holds maki.deb and demo.toml, on a disposable host.
set -e -o pipefail
step=''
documented_stop() {
    documented_status=$?
    if [ "$documented_status" -ne 0 ]; then
        printf '\\nstopped in %s with status %s\\n' "$step" "$documented_status" >&2
    fi
}
trap documented_stop EXIT
"""


def sections(path):
    """(heading, body) of each `## ` section of a guide, in order."""
    parts = re.split(r"(?m)^## (.+)\n", path.read_text(encoding="utf-8"))
    return list(zip(parts[1::2], parts[2::2]))


def fenced(body, language):
    return re.findall(rf"```{language}\n(.*?)```", body, re.S)


def section(path, heading):
    found = [body for name, body in sections(path) if name == heading]
    if len(found) != 1:
        raise ValueError(f"{path.name} has {len(found)} sections named {heading!r}")
    return found[0]


def steps():
    """(label, block) for each block, in the order an operator runs them."""
    found = [(f"{INSTALLATION.name}, {INSTALL_SECTION}, block {index}", block)
             for index, block in enumerate(fenced(section(INSTALLATION, INSTALL_SECTION), "bash"), 1)]
    bootstrap = fenced(section(FIRST_VOLUME, BOOTSTRAP_SECTION), "bash")
    if len(bootstrap) != 1:
        raise ValueError(f"{FIRST_VOLUME.name} section 1 has {len(bootstrap)} bash blocks")
    provisioned = False
    for heading, body in sections(QUICKSTART):
        blocks = fenced(body, "bash")
        if heading == PROVISION_STEP:
            if blocks:
                raise ValueError(f"{QUICKSTART.name} step 4 has a block of its own")
            found.append((f"{QUICKSTART.name}, {heading}: {FIRST_VOLUME.name}, "
                          f"{BOOTSTRAP_SECTION}", bootstrap[0]))
            provisioned = True
        found.extend((f"{QUICKSTART.name}, {heading}, block {index}", block)
                     for index, block in enumerate(blocks, 1))
    if not provisioned:
        raise ValueError(f"{QUICKSTART.name} has no section {PROVISION_STEP!r}")
    return found


def configuration():
    """The quick start's volume configuration, installed from demo.toml."""
    blocks = fenced(QUICKSTART.read_text(encoding="utf-8"), "toml")
    if len(blocks) != 1:
        raise ValueError(f"{QUICKSTART.name} has {len(blocks)} toml blocks")
    return blocks[0]


HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def without_heredoc_bodies(block):
    """The block without the bodies of its here-documents, which Bash prints
    as they are written and which are no commands of the block."""
    lines, terminator = [], None
    for line in block.splitlines():
        if terminator is not None:
            if line.lstrip("\t") == terminator:
                lines.append(line)
                terminator = None
            continue
        lines.append(line)
        found = HEREDOC.search(line)
        if found and "<<<" not in line:
            terminator = found.group(2)
    return "\n".join(lines) + "\n"


# The `&&` and `||` lists the guides hold below a block's own level, as
# `declare -f` prints them (stripped), by the label of their block. Each was
# read, and handles its own failure where it is: `wait_stopped`'s returns
# give the function's status to its caller, and the unmount check's
# alternative is what that step reports. Any other list below a block's
# level is refused: read a new one and add it here, or reword the block.
DEEPER_LISTS = {
    ("quickstart.md, 7. Planned stop with a durability acknowledgement, block 1",
     'state=$(systemctl show -P ActiveState "$unit") || return 1;'),
    ("quickstart.md, 7. Planned stop with a durability acknowledgement, block 1",
     '[ -n "$pending" ] || return 0;'),
    ("quickstart.md, 7. Planned stop with a durability acknowledgement, block 1",
     'findmnt /srv/demo || echo "unmounted"'),
}


def printed_lines(label, block):
    """The lines Bash prints for `block`, without its here-document
    bodies, as the body of a function (`declare -f`), each without the
    function's own four spaces of indentation: a line printed at the block's
    own level starts with no space, one printed deeper with one or more.

    The block is first only read (`bash -n`): a block that Bash reads alone
    cannot close the function it is put in, so defining that function runs
    none of it."""
    bash = shutil.which("bash")
    if bash is None:
        raise ValueError("Bash is needed to read the guides' blocks")
    body = without_heredoc_bodies(block)
    environment = {"PATH": os.defpath, "LC_ALL": "C"}
    read = subprocess.run([bash, "--noprofile", "--norc", "-n"], input=body, env=environment,
                          capture_output=True, text=True, timeout=10)
    if read.returncode:
        raise ValueError(f"Bash cannot read {label}: {read.stderr.strip()}")
    printed = subprocess.run(
        [bash, "--noprofile", "--norc", "-c",
         'eval "documented_block() {\n$1\n}" && declare -f documented_block', "bash", body],
        env=environment, capture_output=True, text=True, timeout=10, check=True).stdout
    return [line[4:] for line in printed.splitlines() if line.startswith("    ")]


def has_unguarded_list(lines):
    """Whether `lines` (`printed_lines`) have `&&` or `||`, matched as text,
    on a line printed at the block's own level up to the last such line,
    before the last line printed at that level, that ends in `;` or holds a
    here-document's command. The block-level lines after that one are not
    read."""
    level = [line for line in lines if not line.startswith(" ")]
    ends = [index for index, line in enumerate(level[:-1])
            if line.endswith(";") or HEREDOC.search(line)]
    return bool(ends) and any("&&" in line or "||" in line for line in level[:ends[-1] + 1])


def deeper_lists(lines):
    """The lines of `lines` (`printed_lines`) printed below the block's own
    level that have `&&` or `||`, matched as text, stripped."""
    return [line.strip() for line in lines
            if line.startswith(" ") and ("&&" in line or "||" in line)]


# A command of the bootstrap that a shim on PATH fails in the bootstrap's
# first run (`--stop-once`), by what the first-volume guide's recovery notes
# say the next run of the same block does then.
STOP_ONCE = {
    # The run stops before it records the filesystem: the next run releases
    # the export, stops the daemon, removes the record and fails. The volume
    # is reset as the notes say, created again, and a third run starts over.
    "mkfs.xfs": "unfinished",
    # The run stops after it, at the release: the next run finishes.
    "vgchange": "finished",
}
# Where the program looks for the device's backend identifier.
SYSFS = "/sys/block"
# The recovery notes' reset of a volume that never held data.
RESET = re.compile(r"remove `(/var/lib/maki/[^`\s]+)` while `(maki@[^`\s]+\.service)` is stopped "
                   r"and run its \[creation block\]\(quickstart\.md#3-create-the-volume\) again")
CREATION_STEP = "3. Create the volume"


def recovery_reset():
    """The backing directory and the daemon's unit of the first-volume
    guide's reset of a volume that never held data."""
    found = RESET.search(" ".join(FIRST_VOLUME.read_text(encoding="utf-8").split()))
    if found is None:
        raise ValueError(f"{FIRST_VOLUME.name} no longer says how to reset a volume that never held "
                         "data (remove its backing directory while its daemon is stopped and run "
                         "the creation block again)")
    return found.group(1), found.group(2)


def bootstrap_values(block):
    """The bootstrap's volume, device and record, as the block sets them."""
    values = {}
    for name, pattern in (("volume", r"[a-z0-9][a-z0-9_-]*"), ("dev", r"/dev/nbd[0-9]+"),
                          ("record", r"/[A-Za-z0-9_./-]+")):
        found = re.search(rf"(?m)^{name}=({pattern})$", block)
        if found is None:
            raise ValueError(f"the bootstrap block sets no plain {name}")
        values[name] = found.group(1)
    return values


def shimmed(command):
    """Program text that puts a `command` that fails first on PATH."""
    quoted = shlex.quote(command)
    return (f"documented_shim=$(mktemp -d)\n"
            f"printf '#!/bin/sh\\necho \"%s: failed once by documented_quickstart.py\" >&2\\n"
            f"exit 97\\n' {quoted} >\"$documented_shim\"/{quoted}\n"
            f"chmod 0755 \"$documented_shim\"/{quoted}\n"
            "documented_path=$PATH\n"
            'export PATH="$documented_shim:$PATH"\n'
            "set +e\n")


def backend_of(dev):
    return shlex.quote(f"{SYSFS}/{dev.removeprefix('/dev/')}/backend")


def stopped(command, values, formatted):
    """Program text that judges the first run: it stopped at `command`, and
    left the record of a run that had (`formatted`) or had not recorded the
    filesystem, with the device showing its connection."""
    record = shlex.quote(values["record"])
    must = "name" if formatted else "not name"
    return ("documented_status=$?\nset -e\n"
            'export PATH="$documented_path"\nrm -rf -- "$documented_shim"\n'
            'if [ "$documented_status" -eq 0 ]; then\n'
            f"    echo 'the bootstrap did not stop where {command} failed' >&2\n    exit 1\nfi\n"
            f"if [ ! -f {record} ]; then\n"
            f"    echo 'the stopped bootstrap left no record {values['record']}' >&2\n    exit 1\nfi\n"
            f"echo 'the stopped bootstrap'\"'\"'s record {values['record']}:'\ncat {record}\n"
            f"if grep -q '^fs_uuid=' {record}; then documented_formatted=yes; "
            "else documented_formatted=no; fi\n"
            f'if [ "$documented_formatted" != {"yes" if formatted else "no"} ]; then\n'
            f"    echo 'the record of a bootstrap stopped at {command} must {must} a filesystem' >&2\n"
            "    exit 1\nfi\n"
            f"documented_backend=$(cat {backend_of(values['dev'])} 2>/dev/null || true)\n"
            'case "$documented_backend" in\n'
            f"    maki-bootstrap-*) echo \"{values['dev']} shows the stopped bootstrap's connection "
            '$documented_backend" ;;\n'
            f"    *) echo \"{values['dev']} does not show the stopped bootstrap's connection "
            '(${documented_backend:-none})" >&2\n       exit 1 ;;\nesac\n')


def released(values):
    """Program text that judges the run after a stop that recorded no
    filesystem: it failed once it had released the export, stopped the
    daemon and removed the record."""
    record = shlex.quote(values["record"])
    unit = f"maki@{values['volume']}.service"
    return ("documented_status=$?\nset -e\n"
            'if [ "$documented_status" -eq 0 ]; then\n'
            "    echo 'the run after a stop that recorded no filesystem must fail once it has "
            "released the export' >&2\n    exit 1\nfi\n"
            f"if [ -e {record} ] || [ -L {record} ]; then\n"
            f"    echo 'the run that released the export kept its record {values['record']}' >&2\n"
            "    exit 1\nfi\n"
            f"documented_backend=$(cat {backend_of(values['dev'])} 2>/dev/null || true)\n"
            'if [ -n "$documented_backend" ]; then\n'
            f"    echo \"{values['dev']} still shows the connection $documented_backend\" >&2\n"
            "    exit 1\nfi\n"
            f"documented_state=$(systemctl show -P ActiveState {unit})\n"
            'if [ "$documented_state" != inactive ]; then\n'
            f'    echo "{unit} is $documented_state, not stopped" >&2\n    exit 1\nfi\n'
            f"echo 'the run released the export, stopped {unit} and removed its record'\n")


def reset(directory, unit):
    """Program text for the recovery notes' reset: remove the backing
    directory while the daemon is stopped."""
    return (f"documented_state=$(systemctl show -P ActiveState {unit})\n"
            'if [ "$documented_state" != inactive ]; then\n'
            f'    echo "{unit} is $documented_state: the volume is reset only while it is stopped" >&2\n'
            "    exit 1\nfi\n"
            f"rm -rf -- {shlex.quote(directory)}\n")


def interrupted(found, command):
    """(label, text) of each step of `found` with the bootstrap stopped once,
    in its first run, by a failure of `command`, and continued as the
    first-volume guide's recovery notes say. A block keeps its label, or has
    the run it is added to it; `text` is what the program runs for it. The
    text of a run that must fail judges its status itself and ends with a
    status of 0 once it has, so that the program's usual check after each
    step holds for every step."""
    provision = f"{QUICKSTART.name}, {PROVISION_STEP}: "
    creation = f"{QUICKSTART.name}, {CREATION_STEP}, block 1"
    [index] = [index for index, (label, _) in enumerate(found) if label.startswith(provision)]
    [(creation_label, creation_block)] = [step for step in found if step[0].startswith(creation)]
    label, block = found[index]
    values = bootstrap_values(block)
    outcome = STOP_ONCE[command]
    runs = 3 if outcome == "unfinished" else 2
    block = block if block.endswith("\n") else block + "\n"
    steps = list(found[:index])
    steps.append((f"{label} (run 1 of {runs}: {command} fails)",
                  shimmed(command) + block + stopped(command, values, outcome == "finished")))
    steps.append((f"{label} (run 2 of {runs}: continues from the record)",
                  block if outcome == "finished" else "set +e\n" + block + released(values)))
    if outcome == "unfinished":
        directory, unit = recovery_reset()
        steps.append((f"{FIRST_VOLUME.name}, Recovering from a failed bootstrap: remove {directory} "
                      f"while {unit} is stopped", reset(directory, unit)))
        steps.append((f"{creation_label} (again)", creation_block))
        steps.append((f"{label} (run 3 of 3)", block))
    steps.extend(found[index + 1:])
    return steps


def program(found, stop_once=None):
    """One Bash program that runs each (label, block) in order in one shell.

    `set -e -o pipefail` stops at a failed command or pipeline; one inside an
    `&&` or `||` list does not trigger it, so each block's own status is
    checked after it, and a block that `has_unguarded_list` finds with `&&`
    or `||` at its own level before its last command is refused, as is one
    with a list below its level (in a compound command's body, a brace group
    or a function, at any depth) that `DEEPER_LISTS` does not name for it.

    With `stop_once`, a command of `STOP_ONCE`, the bootstrap's first run
    has a shim on PATH that fails that command, and the program checks
    that it stopped there and that the next runs of the same block do what
    the first-volume guide's recovery notes say (`interrupted`)."""
    for label, block in found:
        lines = printed_lines(label, block)
        if has_unguarded_list(lines):
            raise ValueError(f"{label} has && or || at its own level before its last command: "
                             "set -e does not stop at a failed list there, and the block's status "
                             "is its last command's")
        unread = [line for line in deeper_lists(lines) if (label, line) not in DEEPER_LISTS]
        if unread:
            raise ValueError(f"{label} has && or || below its own level that DEEPER_LISTS does not "
                             f"name for it: {unread[0]!r}. set -e does not stop at a failed list "
                             "there either: read it and add it, or reword the block")
    if stop_once is not None:
        found = interrupted(found, stop_once)
    lines = [PRELUDE]
    for number, (label, block) in enumerate(found, 1):
        lines.append(f"step={shlex.quote(f'[{number}/{len(found)}] {label}')}\n")
        lines.append("printf '\\n==> %s\\n' \"$step\"\n")
        lines.append(block if block.endswith("\n") else block + "\n")
        lines.append('documented_status=$?\n'
                     'if [ "$documented_status" -ne 0 ]; then exit "$documented_status"; fi\n')
    lines.append("step=''\nprintf '\\n==> every documented step succeeded\\n'\n")
    return "".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--stop-once", choices=sorted(STOP_ONCE),
                        help="fail this command in the bootstrap's first run, and continue as "
                             "the first-volume guide's recovery notes say")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    args.directory.mkdir(parents=True, exist_ok=True)
    # Never replace what an earlier run left: it is evidence of that run.
    with open(args.directory / "demo.toml", "x", encoding="utf-8") as output:
        output.write(configuration())
    with open(args.directory / "quickstart.sh", "x", encoding="utf-8") as output:
        output.write(program(steps(), stop_once=args.stop_once))
    print(args.directory / "quickstart.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
