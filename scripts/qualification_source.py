"""Extract the named Git commit for a qualification run."""

from pathlib import Path
import subprocess
import sys
import tempfile

try:
    from prepare_release import archive_source, git_command
except ModuleNotFoundError:
    from scripts.prepare_release import archive_source, git_command


def extract_revision(repo, revision, archive, source):
    epoch = int(subprocess.check_output(git_command("show", "-s", "--format=%ct", revision, repo=repo)))
    archive_source(archive, revision, ".", epoch, repo=repo)
    # The archive root is 0755; retain the private destination's original mode.
    subprocess.run(["tar", "--no-same-owner", "--no-overwrite-dir", "-xpf", str(archive),
                    "-C", str(source)], check=True)


if __name__ == "__main__":
    revision, destination = sys.argv[1:]
    source = Path(destination)
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(dir=source.parent) as work:
        extract_revision(repo, revision, Path(work) / "source.tar", source)
