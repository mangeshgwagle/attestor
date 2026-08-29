import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import runtime_lab


class RuntimeLabTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "project"
        self.project.mkdir()
        (self.project / "app.py").write_text("VALUE = 1\n", encoding="utf-8")

    def policy(self, **values):
        defaults = {
            "timeout_seconds": 3,
            "cpu_seconds": 2,
            "max_output_bytes": 2048,
            "deterministic_seed": 4242,
        }
        defaults.update(values)
        return runtime_lab.RuntimePolicy.selected_tests(**defaults)

    def test_execution_and_target_execution_are_separate_default_deny_gates(self):
        command = [sys.executable, "-c", "print('should not run')"]
        default = runtime_lab.run_command(command, self.project, authorized=True)
        no_authorization = runtime_lab.run_command(
            command, self.project, policy=self.policy(), authorized=False)
        target = runtime_lab.run_command(
            command, self.project, policy=self.policy(), authorized=True,
            purpose="target-execution")

        self.assertEqual(default.status, "refused")
        self.assertEqual(no_authorization.status, "refused")
        self.assertEqual(target.status, "refused")
        self.assertIn("second", target.detail)

    def test_selected_python_test_gets_minimal_deterministic_environment(self):
        code = (
            "import os; "
            "assert os.environ['PYTHONHASHSEED'] == '4242'; "
            "assert os.environ['ATTESTOR_DETERMINISTIC_SEED'] == '4242'; "
            "assert 'ATTESTOR_RUNTIME_SECRET' not in os.environ; "
            "print('seed=' + os.environ['ATTESTOR_DETERMINISTIC_SEED'])"
        )
        with mock.patch.dict(os.environ, {"ATTESTOR_RUNTIME_SECRET": "never-copy-me"}):
            result = runtime_lab.run_selected_tests(
                [sys.executable, "-c", code], self.project,
                policy=self.policy(), authorized=True)

        self.assertTrue(result.passed, result)
        self.assertEqual(result.stdout.strip(), "seed=4242")
        self.assertNotIn("never-copy-me", result.stdout + result.stderr)

    def test_python_network_and_child_process_hooks_deny_common_apis(self):
        code = r'''
import socket
import subprocess

for operation in (
    lambda: socket.socket(),
    lambda: socket.getaddrinfo("localhost", 80),
    lambda: subprocess.run(["ignored"]),
):
    try:
        operation()
    except PermissionError:
        pass
    else:
        raise AssertionError("runtime policy operation unexpectedly succeeded")
print("policy-blocked")
'''
        result = runtime_lab.run_selected_tests(
            [sys.executable, "-c", code], self.project,
            policy=self.policy(), authorized=True)

        self.assertTrue(result.passed, result.stderr)
        self.assertEqual(result.stdout.strip(), "policy-blocked")
        self.assertEqual(result.network_policy, "python-language-guard")
        self.assertEqual(result.process_policy, "python-language-guard")

    def test_network_denied_refuses_non_python_and_python_guard_bypass_flags(self):
        source_as_executable = str(Path(runtime_lab.__file__).resolve())
        non_python_policy = self.policy(allowed_executables=(source_as_executable,))
        non_python = runtime_lab.run_command(
            [source_as_executable], self.project, policy=non_python_policy,
            authorized=True)
        bypass = runtime_lab.run_command(
            [sys.executable, "-I", "-c", "pass"], self.project,
            policy=self.policy(), authorized=True)

        self.assertEqual(non_python.status, "refused")
        self.assertEqual(non_python.network_policy, "unavailable")
        self.assertEqual(bypass.status, "refused")
        self.assertIn("kernel network isolation", bypass.detail)

    def _timed_sleeper(self, seconds: int):
        """Run a child that would sleep `seconds`, against an 0.08s timeout."""
        started = time.monotonic()
        result = runtime_lab.run_selected_tests(
            [sys.executable, "-c", "import time; time.sleep(%d)" % seconds],
            self.project, policy=self.policy(timeout_seconds=0.08),
            authorized=True)
        return result, time.monotonic() - started

    def test_timeout_and_retained_output_are_bounded(self):
        output = runtime_lab.run_selected_tests(
            [sys.executable, "-c",
             "import sys; sys.stdout.write('x'*20000); sys.stderr.write('y'*20000)"],
            self.project, policy=self.policy(max_output_bytes=128), authorized=True)

        # An absolute wall-clock budget here would mostly be measuring
        # interpreter startup and staging, which is unbounded on a loaded CI
        # box.  Time two children that differ only in how long they would sleep
        # if they were never killed: with the timeout enforced both return after
        # the same fixed overhead, and if the kill did not take effect the
        # second would block ~28s longer waiting the child out.
        brief, brief_elapsed = self._timed_sleeper(2)
        extended, extended_elapsed = self._timed_sleeper(30)

        self.assertTrue(output.passed)
        self.assertTrue(output.truncated)
        retained = (output.stdout.split("\n[output truncated", 1)[0]
                    + output.stderr.split("\n[output truncated", 1)[0])
        self.assertLessEqual(len(retained.encode("utf-8")), 128)
        for result in (brief, extended):
            self.assertEqual(result.status, "failed")
            self.assertTrue(result.timed_out)
        self.assertLess(extended_elapsed,
                        brief_elapsed + max(5.0, brief_elapsed))

    def test_stage_is_disposable_skips_links_and_reports_changes(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.project / "outside-link.txt"
        link_created = False
        try:
            link.symlink_to(outside)
            link_created = True
        except (OSError, NotImplementedError):
            pass

        with runtime_lab.staged_project(self.project) as stage:
            staged = Path(stage.root)
            self.assertEqual((staged / "app.py").read_text(encoding="utf-8"), "VALUE = 1\n")
            if link_created:
                self.assertFalse((staged / "outside-link.txt").exists())
                self.assertTrue(any("outside-link" in item for item in stage.skipped))
            result = runtime_lab.run_selected_tests(
                [sys.executable, "-c",
                 "from pathlib import Path; Path('test-marker').write_text('isolated')"],
                staged, policy=self.policy(), authorized=True)
            self.assertTrue(result.passed, result.stderr)
            self.assertIn("test-marker", result.changed_paths)

        self.assertFalse((self.project / "test-marker").exists())

    def test_executable_allowlist_and_argv_validation(self):
        refused = runtime_lab.run_selected_tests(
            [sys.executable, "-c", "pass"], self.project,
            policy=self.policy(allowed_executables=(str(self.project / "none"),)),
            authorized=True)
        self.assertEqual(refused.status, "refused")
        self.assertIn("allowlist", refused.detail)
        with self.assertRaises(TypeError):
            runtime_lab.run_command("python -c pass", self.project)
        with self.assertRaises(ValueError):
            runtime_lab.run_command([], self.project)

    def test_policy_limits_are_validated(self):
        with self.assertRaises(ValueError):
            runtime_lab.RuntimePolicy(timeout_seconds=0).validated()
        with self.assertRaises(ValueError):
            runtime_lab.RuntimePolicy(max_output_bytes=0).validated()
        with self.assertRaises(ValueError):
            runtime_lab.RuntimePolicy(memory_bytes=1).validated()
        with self.assertRaises(ValueError):
            runtime_lab.RuntimePolicy(max_processes=0).validated()
        with self.assertRaises(ValueError):
            runtime_lab._manifest(self.project, max_bytes=1)
        with self.assertRaises(ValueError):
            runtime_lab._manifest(self.project, max_files=0)

    def test_availability_is_honest_about_absent_hostile_code_sandbox(self):
        report = runtime_lab.availability()
        capabilities = {item.name: item for item in report.capabilities}

        self.assertFalse(report.safe_for_untrusted_code)
        self.assertFalse(capabilities["kernel-network-isolation"].available)
        self.assertEqual(capabilities["kernel-network-isolation"].strength, "unavailable")
        self.assertFalse(capabilities["hostile-code-containment"].available)
        json.dumps(runtime_lab._as_dict(report))


if __name__ == "__main__":
    unittest.main()
