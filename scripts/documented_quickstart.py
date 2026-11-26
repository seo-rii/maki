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
`sudo bash quickstart.sh`. It stops at the first command that fails, also
inside an `&&` list, and says which step it was in.
"""
import argparse
from pathlib import Path
import re
import shlex
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
set -e
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


def program(found):
    """One Bash program that runs each (label, block) in order in one shell.

    `set -e` stops at a failed command; a failed command inside an `&&` list
    does not trigger it, so each block's own status is checked as well."""
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
