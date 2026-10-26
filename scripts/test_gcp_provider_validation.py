"""GCE provider attribution through guest main; no VM or native NBD is used."""
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import traceback
import unittest
from unittest import mock


VALID_CONFIG = '''config_schema_version = 1
[volume]
name = "provider-contract"
max_virtual_size = "1GiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = { source = "env", name = "synthetic-provider-key" }
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/mnt/maki-data/synthetic-provider-backing"
'''


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GuestProviderContracts(unittest.TestCase):
    def setUp(self):
        self.host = load("gcp_provider_host", "gcp-reset-validation.py")
        self.guest = load("gcp_provider_guest", "gcp-reset-guest.py")
        temporary = tempfile.TemporaryDirectory(prefix="maki-gcp-provider-")
        self.addCleanup(temporary.cleanup)
        self.path = pathlib.Path(temporary.name)
        self.config = self.path / "config.toml"
        self.plugin = self.path / "libmaki_nbdkit.so"
        self.plugin.write_bytes(b"not-loaded-by-this-test")
        self.runtime = self.path / "runtime"
        self.runtime.mkdir()
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)

    def run_guest(self, text, *, profile="v2", verify_only=True, read_error=None):
        self.config.write_bytes(text.encode() if isinstance(text, str) else text)
        client = mock.Mock(can_fua=True, can_flush=True, can_trim=True)
        client.read.side_effect = lambda offset: self.guest.payload(
            0, self.guest.index_for_offset(offset))
        captured = io.BytesIO()
        stream = io.TextIOWrapper(captured, encoding="utf-8", write_through=True)
        resolve, open_path = pathlib.Path.resolve, pathlib.Path.open

        def redirect_mount(path, *args, **kwargs):
            if path == pathlib.Path("/mnt/maki-data"):
                return self.path
            return resolve(path, *args, **kwargs)

        def read_config(path, *args, **kwargs):
            if path == self.config and read_error is not None:
                raise read_error
            return open_path(path, *args, **kwargs)

        argv = ["gcp-reset-guest.py", "--token", "a" * 32,
                "--cycle", "1" if verify_only else "0", "--profile", profile,
                "--config", str(self.config), "--plugin", str(self.plugin)]
        if verify_only:
            argv.append("--verify-only")
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            stack.enter_context(mock.patch.object(pathlib.Path, "resolve", redirect_mount))
            stack.enter_context(mock.patch.object(pathlib.Path, "open", read_config))
            stack.enter_context(mock.patch.object(self.guest, "filesystem_uuid",
                                                 return_value="10000000-0000-0000-0000-000000000001"))
            stack.enter_context(mock.patch.object(self.guest, "shutdown_witness", return_value={
                "witness_service": "active", "graceful_stop_witness": "absent"}))
            stack.enter_context(mock.patch.object(self.guest.tempfile, "mkdtemp",
                                                 return_value=str(self.runtime)))
            launch = stack.enter_context(mock.patch.object(self.guest, "run_nbdkit", return_value=(
                mock.sentinel.process, None, self.runtime / "nbd.sock")))
            stack.enter_context(mock.patch.object(self.guest, "Nbd", return_value=client))
            stack.enter_context(mock.patch.object(self.guest, "wait_for_reset"))
            stack.enter_context(mock.patch.object(self.guest, "cleanup"))
            stack.enter_context(contextlib.redirect_stdout(stream))
            error = None
            try:
                self.guest.main()
            except Exception as caught:
                error = caught
        events = [json.loads(line[len(self.guest.PREFIX):])
                  for line in captured.getvalue().splitlines()]
        stream.detach()
        return error, events, launch, client

    def assert_rejected(self, text, **kwargs):
        error, events, launch, client = self.run_guest(text, **kwargs)
        emitted = [(event["event"], event.get("provider")) for event in events]
        self.assertIsInstance(error, ValueError, f"unexpectedly accepted config; emitted {emitted}")
        launch.assert_not_called()
        client.read.assert_not_called()
        client.write.assert_not_called()
        self.assertEqual(events, [])
        return error

    def test_expected_provider_runs_both_profiles_and_reports_validated_identity(self):
        for profile in ("v2", "v3-discard"):
            for verify_only in (False, True):
                for bom in ("", "\ufeff"):
                    with self.subTest(profile=profile, verify_only=verify_only, bom=bool(bom)):
                        error, events, launch, _ = self.run_guest(
                            bom + VALID_CONFIG, profile=profile, verify_only=verify_only)
                        self.assertIsNone(error)
                        launch.assert_called_once()
                        ready = events[0]
                        self.assertEqual(ready["event"], "ready")
                        self.assertEqual(ready["provider"], "local-aes-gcm-siv")
                        self.host.validate_ready(ready, None, profile)
                        self.assertEqual(events[-1]["event"], "verified" if verify_only else "ack")

    def test_bom_does_not_admit_wrong_provider_or_malformed_config(self):
        marker = "synthetic-bom-private-marker"
        cases = {
            "wrong-provider": "\ufeff" + VALID_CONFIG.replace(
                'provider = "local-aes-gcm-siv"', f'provider = "{marker}"'),
            "invalid-toml": "\ufeff" + VALID_CONFIG + f'\ninvalid = ["{marker}",',
            "invalid-utf8": b"\xef\xbb\xbf" + VALID_CONFIG.encode()
                + b"#" + marker.encode() + b"\xff",
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                error = self.assert_rejected(text)
                self.assertNotIn(marker, str(error))
                self.assertNotIn(marker, "".join(traceback.format_exception(error)))

    def test_only_one_initial_bom_is_accepted(self):
        for text in ("\ufeff\ufeff" + VALID_CONFIG,
                     "\ufeff" + VALID_CONFIG.replace("[crypto]", "\ufeff[crypto]")):
            with self.subTest(text=text):
                self.assert_rejected(text)

    def test_bom_inside_provider_value_is_preserved(self):
        self.assert_rejected("\ufeff" + VALID_CONFIG.replace(
            'provider = "local-aes-gcm-siv"', 'provider = "local-aes-\ufeffgcm-siv"'))

    def test_other_local_provider_is_rejected_before_launch(self):
        self.assert_rejected('[crypto]\nprovider = "local-aes-xts"\n')

    def test_remote_providers_are_rejected_before_launch(self):
        for provider in ("remote-http", "remote-grpc", "remote-websocket"):
            with self.subTest(provider=provider):
                self.assert_rejected(f'[crypto]\nprovider = "{provider}"\n')

    def test_missing_or_mistyped_provider_is_rejected_before_launch(self):
        for text in ('', '[crypto]\n', 'crypto = "secret-marker"\n',
                     '[crypto]\nprovider = 7\n', '[crypto]\nprovider = ["local-aes-gcm-siv"]\n'):
            with self.subTest(text=text):
                error = self.assert_rejected(text)
                self.assertNotIn("secret-marker", str(error))

    def test_invalid_toml_or_utf8_is_rejected_without_echoing_values(self):
        for text in ('[crypto]\nprovider = "secret-marker"\ninvalid = [',
                     b'[crypto]\nprovider = "local-aes-gcm-siv"\n#secret-marker\xff'):
            with self.subTest(text=text):
                error = self.assert_rejected(text)
                self.assertNotIn("secret-marker", str(error))
                self.assertTrue(error.__suppress_context__)

    def test_config_read_error_is_rejected_without_echoing_details(self):
        error = self.assert_rejected('[crypto]\nprovider = "local-aes-gcm-siv"\n',
                                     read_error=PermissionError("secret-marker"))
        self.assertNotIn("secret-marker", str(error))
        self.assertTrue(error.__suppress_context__)

    def test_host_still_rejects_a_mismatched_ready_provider(self):
        error, events, _, _ = self.run_guest('[crypto]\nprovider = "local-aes-gcm-siv"\n')
        self.assertIsNone(error)
        for provider in ("local-aes-xts", "remote-http", None):
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                self.host.validate_ready(dict(events[0], provider=provider), None)


if __name__ == "__main__":
    unittest.main()
