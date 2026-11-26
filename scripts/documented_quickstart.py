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
`sudo bash quickstart.sh`. It runs under `set -e -o pipefail` and checks
each block's status after it, so it stops at a failed command that `set -e`
stops at (a pipeline included, whichever of its commands failed) and at a
block whose last command failed, an `&&` list that ends the block included,
and says which step it was in. `set -e` does not stop at a failure inside an
`&&` or `||` list before a block's last command. The writer refuses a block
that Bash cannot read, and one with `&&` or `||` on a line that Bash prints
at the block's own level, or in a subshell there, of a command before its
last command (the last command's own lines, however many, are not read); it
matches them as text, so a condition, a test expression,
quoted text or a command substitution there is refused too. It does not see
lists inside the bodies of `if`, `while`, `for` or `case`, brace groups or
functions, nor `set -e`'s other exemptions (a negated or a background
command): a failure there lets the program go on. The check relies on the
layout of `declare -f`.
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


def has_unguarded_list(label, block):
    """Whether `block` has `&&` or `||`, matched as text, on a line that Bash
    prints at the block's own level or in a subshell there, up to the last
    such line that ends a command (in `;`, or a here-document's command
    line): the lines of every command before the last one. The last command's own lines, however many, are not read, nor are
    lists deeper down (in compound-command bodies, brace groups and
    functions).

    Bash prints a function's body four spaces in at its own level, a command
    that is not compound on one line and a compound one over several, each
    command but the last ended by `;` (a here-document's command line by its
    body). The block is first only read (`bash -n`): a
    block that Bash reads alone cannot close the function it is put in, so
    defining that function runs none of it."""
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
    level = [line[4:] for line in printed.splitlines()
             if line.startswith("    ") and not line.startswith("     ")]
    ends = [index for index, line in enumerate(level[:-1])
            if line.endswith(";") or HEREDOC.search(line)]
    return bool(ends) and any("&&" in line or "||" in line for line in level[:ends[-1] + 1])


def program(found):
    """One Bash program that runs each (label, block) in order in one shell.

    `set -e -o pipefail` stops at a failed command or pipeline; one inside an
    `&&` or `||` list does not trigger it, so each block's own status is
    checked after it, and a block that `has_unguarded_list` finds with `&&`
    or `||` at its own level before its last command is refused (lists in
    compound-command bodies, brace groups and functions are not seen)."""
    for label, block in found:
        if has_unguarded_list(label, block):
            raise ValueError(f"{label} has && or || at its own level before its last command: "
                             "set -e does not stop at a failed list there, and the block's status "
                             "is its last command's")
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
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    args.directory.mkdir(parents=True, exist_ok=True)
    # Never replace what an earlier run left: it is evidence of that run.
    with open(args.directory / "demo.toml", "x", encoding="utf-8") as output:
        output.write(configuration())
    with open(args.directory / "quickstart.sh", "x", encoding="utf-8") as output:
        output.write(program(steps()))
    print(args.directory / "quickstart.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main())
