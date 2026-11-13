"""Execute the documented key blocks against private synthetic credentials.

Only the secret directory and, for unprivileged tests, install's requested
owner are changed. No host credential or service is read or modified.
"""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUIDES = {
    "quickstart": ("docs/getting-started/quickstart.md", "demo.token"),
    "postgres": ("docs/deployment/postgres.md", "postgres.token"),
}
SYNTHETIC_KEY = bytes(range(32))

# The shell and the documentation's Python are unmodified. This private
# interpreter shim injects failures at entropy and persistence boundaries.
INJECTOR = r'''
import errno
import os
import sys

fault = os.environ["MAKI_KEY_TEST_FAULT"]
real_fsync = os.fsync
sync_calls = 0

def sync(fd):
    global sync_calls
    sync_calls += 1
    if sync_calls == (2 if fault == "directory-sync" else 1):
        raise OSError(errno.EIO, "synthetic key sync failure")
    return real_fsync(fd)

def random_bytes(count):
    raise OSError(errno.EIO, "synthetic key entropy failure")

if fault == "entropy":
    os.urandom = random_bytes
else:
    os.fsync = sync
exec(compile(sys.stdin.read(), "documented-key-creation", "exec"))
'''


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires POSIX Bash")
class KeyCreationContract(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="maki-key-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def prepare(self, guide, variant="default"):
        relative, filename = GUIDES[guide]
        blocks = re.findall(r"```bash\n(.*?)```", (ROOT / relative).read_text(), re.S)
        selected = [block for block in blocks
                    if f"/etc/maki/secrets/{filename}" in block
                    and ("head -c 32" in block or "os.urandom(32)" in block)]
        self.assertEqual(len(selected), 1, "one self-contained key creation block")
        directory = self.root / f"{guide}-{variant}" / "secrets"
        directory.mkdir(parents=True, mode=0o700)
        program = selected[0].replace("/etc/maki/secrets", str(directory))
        if os.geteuid() != 0:
            program = program.replace("-o root -g root ", "")
        return directory, directory / filename, program

    def run_block(self, program, fault=None):
        environment = os.environ.copy()
        if fault:
            binaries = self.root / "bin"
            binaries.mkdir(exist_ok=True)
            interpreter = binaries / "python3"
            interpreter.write_text(f"#!{sys.executable}\n" + INJECTOR)
            interpreter.chmod(0o700)
            environment["PATH"] = str(binaries) + os.pathsep + environment["PATH"]
            environment["MAKI_KEY_TEST_FAULT"] = fault
        return subprocess.run(["bash", "-c", program], env=environment,
                              capture_output=True, text=True, timeout=15)

    def test_first_creation_publishes_one_complete_read_only_key(self):
        for guide in GUIDES:
            with self.subTest(guide=guide):
                directory, key, program = self.prepare(guide)
                result = self.run_block(program)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(key.read_bytes()), 32)
                self.assertEqual(key.stat().st_mode & 0o777, 0o400)
                self.assertEqual(key.stat().st_nlink, 1)
                self.assertEqual(set(directory.iterdir()), {key})

    def test_existing_writable_and_read_only_keys_are_preserved(self):
        for guide in GUIDES:
            for mode in [0o600, 0o400]:
                with self.subTest(guide=guide, mode=oct(mode)):
                    directory, key, program = self.prepare(guide, str(mode))
                    key.write_bytes(SYNTHETIC_KEY)
                    key.chmod(mode)
                    result = self.run_block(program)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(key.read_bytes(), SYNTHETIC_KEY)
                    self.assertEqual(key.stat().st_mode & 0o777, mode)
                    self.assertEqual(set(directory.iterdir()), {key})

    def test_existing_and_dangling_symlinks_are_preserved(self):
        for guide in GUIDES:
            for exists in [True, False]:
                with self.subTest(guide=guide, target_exists=exists):
                    directory, key, program = self.prepare(guide, str(exists))
                    target = directory.parent / "existing-key"
                    if exists:
                        target.write_bytes(SYNTHETIC_KEY)
                        target.chmod(0o400)
                    key.symlink_to(target)
                    result = self.run_block(program)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertTrue(key.is_symlink())
                    self.assertEqual(key.readlink(), target)
                    self.assertEqual(target.exists(), exists)
                    if exists:
                        self.assertEqual(target.read_bytes(), SYNTHETIC_KEY)
                        target.unlink()
                    self.assertEqual(set(directory.iterdir()), {key})
                    key.unlink()

    def test_concurrent_creation_has_one_winner(self):
        for guide in GUIDES:
            with self.subTest(guide=guide):
                directory, key, program = self.prepare(guide)
                with ThreadPoolExecutor(max_workers=4) as executor:
                    results = list(executor.map(self.run_block, [program] * 4))
                self.assertEqual(sum(result.returncode == 0 for result in results), 1)
                self.assertEqual(len(key.read_bytes()), 32)
                self.assertEqual(key.stat().st_mode & 0o777, 0o400)
                self.assertEqual(key.stat().st_nlink, 1)
                self.assertEqual(set(directory.iterdir()), {key})

    def test_entropy_and_file_sync_failures_do_not_publish_a_key(self):
        for guide in GUIDES:
            for fault in ["entropy", "file-sync"]:
                with self.subTest(guide=guide, fault=fault):
                    directory, key, program = self.prepare(guide, fault)
                    result = self.run_block(program, fault)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(key.exists())
                    self.assertEqual(list(directory.iterdir()), [])

    def test_directory_sync_failure_preserves_the_complete_published_key(self):
        for guide in GUIDES:
            with self.subTest(guide=guide):
                directory, key, program = self.prepare(guide)
                result = self.run_block(program, "directory-sync")
                self.assertNotEqual(result.returncode, 0)
                contents = key.read_bytes()
                self.assertEqual(len(contents), 32)
                self.assertEqual(key.stat().st_mode & 0o777, 0o400)
                self.assertEqual(set(directory.iterdir()), {key})
                retry = self.run_block(program)
                self.assertNotEqual(retry.returncode, 0)
                self.assertEqual(key.read_bytes(), contents)


if __name__ == "__main__":
    unittest.main()
