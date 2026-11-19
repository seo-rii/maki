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
