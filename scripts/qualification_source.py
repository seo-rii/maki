"""Extract the named Git commit for a qualification run."""

from pathlib import Path
import subprocess
import sys
import tempfile

try:
    from prepare_release import archive_source, commit_epoch, tracked_changes
except ModuleNotFoundError:
    from scripts.prepare_release import archive_source, commit_epoch, tracked_changes


def clean_revision(repo):
    if tracked_changes(repo=repo):
        raise ValueError("Commit tracked changes before qualifying this revision.")
    return subprocess.check_output(["git", "--no-replace-objects", "rev-parse", "--verify", "HEAD^{commit}"],
                                   cwd=repo, text=True).strip()


def extract_revision(repo, revision, archive, source):
    epoch = commit_epoch(revision, repo=repo)
    archive_source(archive, revision, ".", epoch, repo=repo)
    # The archive root is 0755; retain the private destination's original mode.
    subprocess.run(["tar", "--no-same-owner", "--no-overwrite-dir", "-xpf", str(archive),
                    "-C", str(source)], check=True)


if __name__ == "__main__":
    selection, destination = sys.argv[1:]
    source = Path(destination)
    repo = Path(__file__).resolve().parents[1]
    revision = clean_revision(repo) if selection == "--clean-head" else selection
    with tempfile.TemporaryDirectory(dir=source.parent) as work:
        extract_revision(repo, revision, Path(work) / "source.tar", source)
    if selection == "--clean-head":
        print(revision)
