"""Exercise source and SQLite evidence without privileged host operations."""
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name("privileged-linux-validation.sh").read_text()


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("bash"), "Linux shell")
class PrivilegedEvidence(unittest.TestCase):
    def test_clean_shutdown_checks_exit_and_plugin_log_before_offline_check(self):
        stop = SCRIPT[SCRIPT.index("stop_process_normally() {"):SCRIPT.index("nbd_has_pid() {")]
        final = SCRIPT[SCRIPT.rindex('stop_process_normally "$nbdkit_pid"'):SCRIPT.index('pass "clean nbdkit')]
        setup = """
set -e
run_dir=$1
log() { :; }
die() { exit 1; }
maki_bin=true
config_path=unused
bash -c 'trap "exit $1" TERM; echo ready > "$2/ready"; while :; do sleep 0.05; done' bash "$2" "$1" &
nbdkit_pid=$!
while ! test -f "$run_dir/ready"; do sleep 0.01; done
"""
        for code, contents, ok in ((0, "", True), (42, "", False),
                                   (0, "maki-nbdkit: shutdown during unload failed: error", False)):
            with self.subTest(code=code, contents=contents), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "nbdkit.log").write_text(contents)
                proc = subprocess.run(["bash", "-c", setup + stop + final, "bash", tmp, str(code)],
                                      capture_output=True, timeout=5)
                self.assertEqual(proc.returncode == 0, ok)
                self.assertEqual((Path(tmp) / "maki-check.txt").exists(), ok)

    def test_wal_checkpoint_requires_mode_all_frames_and_integrity(self):
        check = SCRIPT[SCRIPT.index("verify_sqlite_result() {"):SCRIPT.index('log "running a safe SQLite')]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "database"
            writer = sqlite3.connect(path, timeout=0.01)
            reader = sqlite3.connect(path)
            try:
                mode = writer.execute("PRAGMA journal_mode=WAL").fetchone()[0]
                writer.execute("CREATE TABLE t(x)")
                writer.execute("INSERT INTO t VALUES(1)")
                writer.commit()
                reader.execute("BEGIN")
                reader.execute("SELECT * FROM t").fetchall()
                writer.execute("INSERT INTO t VALUES(2)")
                writer.commit()
                busy = writer.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
                integrity = writer.execute("PRAGMA integrity_check").fetchone()[0]
                reader.rollback()
                done = writer.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
            finally:
                reader.close()
                writer.close()
            self.assertEqual(busy[0], 1)
            self.assertNotEqual(busy[1], busy[2])
            for journal, fields, ok in [(mode, done, True), (mode, busy, False),
                                        ("delete", done, False), (mode, (0, 3, 2), False)]:
                report = Path(directory) / "sqlite.txt"
                report.write_text(f"{journal}\n{'|'.join(map(str, fields))}\n{integrity}\n")
                result = subprocess.run(["bash", "-c", check + '\nverify_sqlite_result "$1"',
                                         "bash", str(report)], check=False)
                self.assertEqual(result.returncode == 0, ok, (journal, fields))

    def test_foreground_and_background_workers_use_the_captured_commit(self):
        launcher = SCRIPT[SCRIPT.index("prepare_source_snapshot() {"):
                          SCRIPT.index('[[ "$background" == false ]] || die "--run-dir')]
        setup = """set -euo pipefail
run_dir=""
device=/dev/nbd0
confirmed_device="$device"
install_missing=false
discard=false
work_root=""
sudo() { echo later-edit > "$REPO_ROOT/version"; }
"""
        for mode in ["false", "true"]:
            with self.subTest(background=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo = root / "repo"
                repo.mkdir()
                def git(*arguments):
                    return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()
                git("init", "-q")
                (repo / "scripts").mkdir()
                for name in ("qualification_source.py", "prepare_release.py"):
                    shutil.copyfile(Path(__file__).with_name(name), repo / "scripts" / name)
                worker = repo / "scripts/privileged-linux-validation.sh"
                worker.write_text('#!/bin/sh\ncd "$(dirname "$0")/.."\n'
                                  'test ! -e extra && cp version ../result.tmp && mv ../result.tmp ../worker-result\n')
                worker.chmod(0o755)
                (repo / "version").write_text("qualified $Format:%H$\n")
                (repo / "fixture-data").write_text("required\n")
                git("add", ".")
                git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                    "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
                (repo / ".git/info/attributes").write_text("version export-subst\nfixture-data export-ignore\n")
                (repo / "extra").touch()
                logs = root / "logs"
                result = subprocess.run(["bash", "-c", setup + launcher], capture_output=True,
                                        text=True, timeout=15, env=dict(os.environ, REPO_ROOT=str(repo),
                                        background=mode, log_root=str(logs)))
                self.assertEqual(result.returncode, 0, result.stderr)
                live = logs / "maki-privileged-validation.latest"
                output = live / "worker-result"
                deadline = time.monotonic() + 5
                while not output.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(output.read_text(), "qualified $Format:%H$\n")
                self.assertEqual((live / "source/fixture-data").read_text(), "required\n")
                self.assertEqual((live / "source").stat().st_mode & 0o777, 0o700)
                self.assertEqual((repo / "version").read_text(), "later-edit\n")
                # The shared clean-revision check also covers files omitted
                # from the default working-tree status.
                git("update-index", "--assume-unchanged", "version")
                second = root / "other-logs"
                rejected = subprocess.run(["bash", "-c", setup + launcher], capture_output=True,
                                          text=True, timeout=10, env=dict(os.environ, REPO_ROOT=str(repo),
                                          background=mode, log_root=str(second)))
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("source-snapshot-failed", (second / "maki-privileged-validation.latest/status").read_text())

                self.assertEqual((live / "source-revision").read_text().strip(), git("rev-parse", "HEAD"))
