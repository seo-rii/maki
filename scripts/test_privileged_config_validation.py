"""Round-trip native validation paths without devices or privileged operations."""
import os
import pathlib
import subprocess
import tempfile
import tomllib
import unittest


class NativeConfigPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repository = pathlib.Path(__file__).resolve().parent.parent
        script = (cls.repository / "scripts/privileged-linux-validation.sh").read_text()
        start = script.index("choose_work_root() {\n")
        end = script.index("\n}\n\nchoose_work_root ||", start) + len("\n}")
        cls.selection = script[start:end]
        start = script.index('config_path="$run_dir/volume.toml"\n')
        end = script.index('\nif [[ "$discard" == true ]]; then', start)
        cls.generation = script[start:end]

    def round_trip(self, directory_name, *, volume_name="path-roundtrip", socket_names=None):
        with tempfile.TemporaryDirectory(prefix="maki-config-paths-") as temporary:
            parent = pathlib.Path(temporary)
            work_root = parent / directory_name
            work_root.mkdir()
            run_dir = parent / "run"
            run_dir.mkdir()
            if socket_names is None:
                socket_names = ("nbd.sock", "control.sock")
            socket_path, control_socket_path = (str(run_dir / name) for name in socket_names)
            environment = dict(os.environ, work_root=str(work_root), run_dir=str(run_dir),
                               volume_name=volume_name, socket_path=socket_path,
                               control_socket_path=control_socket_path,
                               user_home=str(parent / "unused-home"),
                               REPO_ROOT=str(self.repository), MIN_WORK_FREE_BYTES="0")
            program = ("set -euo pipefail\n" + self.selection + "\n"
                       "choose_work_root\n"
                       'work_dir="$(mktemp -d "$work_root/maki-privileged-validation.XXXXXX")"\n'
                       + self.generation + '\nprintf "%s" "$work_dir"\n')
            result = subprocess.run(["bash", "-c", program], env=environment,
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            work_dir = pathlib.Path(result.stdout.decode())
            self.assertTrue(work_dir.is_dir(), "the production selector must accept this work root")
            document = tomllib.loads((run_dir / "volume.toml").read_text(encoding="utf-8"))
            self.assertEqual(document["volume"]["name"], volume_name)
            self.assertEqual(document["crypto"]["key"]["name"],
                             str(work_dir / "local-aes-gcm-siv.key"))
            self.assertEqual(document["backing"]["root"], str(work_dir / "backing"))
            self.assertEqual(document["nbd"]["socket"], socket_path)
            self.assertEqual(document["control"]["socket"], control_socket_path)
            # These must identify the actual generated key and allocated directory.
            self.assertEqual(len(pathlib.Path(document["crypto"]["key"]["name"]).read_bytes()), 32)
            self.assertEqual(pathlib.Path(document["backing"]["root"]).parent, work_dir)

    def test_plain_work_root(self):
        self.round_trip("plain")

    def test_unicode_and_spaces(self):
        self.round_trip("운영 archive 😀")

    def test_leading_dash(self):
        self.round_trip("--archive")

    def test_double_quotes(self):
        self.round_trip('archive "A"')

    def test_backslash_escape_prefix(self):
        self.round_trip("archive\\release")

    def test_control_characters(self):
        self.round_trip("archive\n\t\b\f\r\x01\x1f\x7fsegment")

    def test_volume_and_socket_fields(self):
        value = 'quoted "value" \\ 😀\n\t\b\f\r\x01\x1f\x7fend'
        self.round_trip("plain", volume_name=value,
                        socket_names=(value + "-nbd.sock", value + "-control.sock"))


if __name__ == "__main__":
    unittest.main()
