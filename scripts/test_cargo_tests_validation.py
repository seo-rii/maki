"""Native tests must use artifacts from the same Cargo invocation and feature graph."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "run_cargo_tests", Path(__file__).with_name("run_cargo_tests.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CargoTestRunnerTests(unittest.TestCase):
    def setUp(self):
        clean_environment = mock.patch.dict(os.environ, {"PATH": os.defpath}, clear=True)
        clean_environment.start()
        self.addCleanup(clean_environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = self.root / "libmaki_nbdkit.so"
        self.plugin.write_bytes(b"fixture")

    def artifact(self, path=None, **overrides):
        event = {"reason": "compiler-artifact", "target": {
            "name": "maki_nbdkit", "crate_types": ["lib", "cdylib"]},
            "profile": {"test": False}, "manifest_path": str(runner.MANIFEST),
            "filenames": [str(path or self.plugin)]}
        event.update(overrides)
        return event

    def compiled_test(self, manifest=None, kind="test", **overrides):
        event = {"reason": "compiler-artifact", "target": {
            "name": "review_native_plugin_path", "kind": [kind], "crate_types": ["bin"],
            "src_path": str(runner.MANIFEST.parent / "tests/review_native_plugin_path.rs")},
            "profile": {"test": True}, "manifest_path": str(manifest or runner.MANIFEST),
            "executable": str(self.root / "test-binary"), "filenames": []}
        event.update(overrides)
        return event

    def invoke(self, events, arguments=None, compile_status=0, test_status=0,
               platform="linux", native_tests=True):
        if native_tests:
            events = [self.compiled_test(), *events]
        compiler = mock.MagicMock()
        compiler.__enter__.return_value = compiler
        compiler.stdout = io.StringIO("\n".join(json.dumps(event) for event in events))
        compiler.wait.return_value = compile_status
        with mock.patch.object(runner.subprocess, "Popen", return_value=compiler) as build, \
                mock.patch.object(runner.subprocess, "call", return_value=test_status) as tests, \
                contextlib.redirect_stderr(io.StringIO()):
            status = runner.run(arguments or ["--workspace", "--locked"], platform=platform)
        return status, build, tests

    def test_same_test_graph_and_harness_arguments_are_forwarded(self):
        arguments = ["--locked", "-p", "maki-nbdkit", "--release", "--features", "fake-provider",
                     "--target-dir", "custom target", "--test", "review_discard", "--",
                     "native_nbd_negotiates_and_executes_trim", "--nocapture"]
        with mock.patch.dict(os.environ, {"CARGO": "/custom tools/cargo",
                                         runner.PLUGIN_ENV: "/stale/plugin.so"}):
            status, build, tests = self.invoke([self.artifact()], arguments, test_status=9)
        self.assertEqual(status, 9)
        self.assertEqual(build.call_args.args[0], ["/custom tools/cargo", "test",
                         *arguments[:arguments.index("--")], "--no-run", "--message-format=json"])
        self.assertEqual(tests.call_args.args[0], ["/custom tools/cargo", "test", *arguments])
        self.assertFalse(runner.PLUGIN_ENV in build.call_args.kwargs["env"])
        self.assertEqual(tests.call_args.kwargs["env"][runner.PLUGIN_ENV], str(self.plugin))
        self.assertEqual(build.call_args.kwargs["cwd"], runner.ROOT)

    def test_selections_without_native_integration_tests_run_without_plugin(self):
        core_manifest = runner.ROOT / "crates/maki-core/Cargo.toml"
        for arguments, event in [
            (["-p", "maki-core", "--locked"], self.compiled_test(manifest=core_manifest)),
            (["--workspace", "--exclude", "maki-nbdkit"], self.compiled_test(manifest=core_manifest)),
            (["--workspace", "--lib"], self.compiled_test(kind="lib")),
        ]:
            with self.subTest(arguments=arguments), mock.patch.dict(
                    os.environ, {runner.PLUGIN_ENV: "/stale/plugin.so"}):
                status, build, tests = self.invoke(
                    [event], arguments, test_status=7, native_tests=False)
                self.assertEqual(status, 7)
                self.assertEqual(tests.call_args.args[0][1:], ["test", *arguments])
                self.assertNotIn(runner.PLUGIN_ENV, build.call_args.kwargs["env"])
                self.assertNotIn(runner.PLUGIN_ENV, tests.call_args.kwargs["env"])

    def test_native_integration_selection_still_requires_plugin(self):
        status, _, tests = self.invoke([], ["-p", "maki-nbdkit", "--test", "review_native_plugin_path"])
        self.assertEqual(status, 1)
        tests.assert_not_called()

    def test_older_native_test_artifact_without_manifest_still_requires_plugin(self):
        event = self.compiled_test()
        del event["manifest_path"]
        status, _, tests = self.invoke([event], native_tests=False)
        self.assertEqual(status, 1)
        tests.assert_not_called()

    def test_present_unusable_or_ambiguous_plugin_is_not_ignored_without_native_tests(self):
        other = self.root / "other/libmaki_nbdkit.so"
        other.parent.mkdir()
        other.write_bytes(b"other")
        for events in [[self.artifact(self.root / "missing/libmaki_nbdkit.so")],
                       [self.artifact(filenames=[str(self.root / "wrong-name.so")])],
                       [self.artifact(), self.artifact(other)]]:
            with self.subTest(events=events):
                status, _, tests = self.invoke(events, native_tests=False)
                self.assertEqual(status, 1)
                tests.assert_not_called()

    def test_compile_failure_never_runs_tests_even_with_an_artifact(self):
        status, _, tests = self.invoke([self.artifact()], compile_status=17)
        self.assertEqual(status, 17)
        tests.assert_not_called()

    def test_wrong_artifacts_are_not_accepted(self):
        for event in [
            self.artifact(target={"name": "other", "crate_types": ["cdylib"]}),
            self.artifact(target={"name": "maki_nbdkit", "crate_types": ["lib"]}),
            self.artifact(profile={"test": True}),
            self.artifact(manifest_path=str(self.root / "foreign/Cargo.toml")),
            self.artifact(filenames=[str(self.root / "other.so")]),
        ]:
            with self.subTest(event=event):
                status, _, tests = self.invoke([event])
                self.assertEqual(status, 1)
                tests.assert_not_called()

    def test_missing_ambiguous_relative_and_unusable_artifacts_are_rejected(self):
        other = self.root / "other/libmaki_nbdkit.so"
        other.parent.mkdir()
        other.write_bytes(b"other")
        missing = self.root / "missing/libmaki_nbdkit.so"
        directory = self.root / "directory/libmaki_nbdkit.so"
        directory.mkdir(parents=True)
        for events in [[], [self.artifact(), self.artifact(other)],
                       [self.artifact(missing)], [self.artifact(directory)],
                       [self.artifact(Path("libmaki_nbdkit.so"))]]:
            with self.subTest(events=events):
                status, _, tests = self.invoke(events)
                self.assertEqual(status, 1)
                tests.assert_not_called()

    def test_duplicate_messages_for_the_same_artifact_are_unambiguous(self):
        status, _, tests = self.invoke([self.artifact(), self.artifact()])
        self.assertEqual(status, 0)
        tests.assert_called_once()

    def test_older_messages_without_manifest_still_require_the_exact_target(self):
        event = self.artifact()
        del event["manifest_path"]
        status, _, tests = self.invoke([event])
        self.assertEqual(status, 0)
        tests.assert_called_once()

    def test_non_linux_forwards_directly_without_a_native_plugin_requirement(self):
        arguments = ["--workspace", "--locked", "--", "--ignored"]
        for platform in ["win32", "darwin"]:
            with self.subTest(platform=platform):
                status, build, tests = self.invoke([], arguments, test_status=7, platform=platform)
                self.assertEqual(status, 7)
                build.assert_not_called()
                self.assertEqual(tests.call_args.args[0][1:], ["test", *arguments])

    def test_wrapper_rejects_options_that_would_override_its_compile_contract(self):
        for argument in ["--no-run", "--message-format=json", "--message-format"]:
            status, build, tests = self.invoke([], [argument])
            self.assertEqual(status, 2)
            build.assert_not_called()
            tests.assert_not_called()

    def test_compiler_errors_are_rendered(self):
        rendered = "error: fixture compile failure\n"
        stream = [json.dumps({"reason": "compiler-message", "message": {"rendered": rendered}})]
        with contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(runner.compiler_artifacts(stream), (set(), False))
        self.assertEqual(output.getvalue(), rendered)


if __name__ == "__main__":
    unittest.main()
