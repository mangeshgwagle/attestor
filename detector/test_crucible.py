#!/usr/bin/env python3
"""Tests for crucible.py -- the execution gate. Runs real subprocesses (no LLM)."""
import unittest
import os
import sys
from unittest import mock

import crucible


class CrucibleTests(unittest.TestCase):
    def test_clean_module_imports_and_runs(self):
        v = crucible.verify("def add(a, b):\n    return a + b\n")
        self.assertTrue(v.ok)

    def test_import_time_crash_is_caught(self):
        v = crucible.imports("x = undefined_thing\n")
        self.assertFalse(v.ok)
        self.assertIn("NameError", v.detail)

    def test_statically_valid_runtime_crash_is_caught(self):
        # valid names, no known bad pattern -> both static engines pass it;
        # only running it reveals the ZeroDivisionError
        v = crucible.imports("result = 1 / 0\n")
        self.assertFalse(v.ok)
        self.assertIn("ZeroDivisionError", v.detail)

    def test_infinite_loop_hits_the_timeout(self):
        v = crucible.imports("while True:\n    pass\n", timeout=2)
        self.assertFalse(v.ok)
        self.assertIn("timed out", v.detail)

    def test_smoke_catches_a_logic_bug(self):
        # 'add' that subtracts: perfectly valid code, wrong behaviour
        buggy = "def add(a, b):\n    return a - b\n"
        self.assertFalse(crucible.smoke(buggy, "assert add(2, 3) == 5\n").ok)
        good = "def add(a, b):\n    return a + b\n"
        self.assertTrue(crucible.smoke(good, "assert add(2, 3) == 5\n").ok)

    def test_run_main_executes_main_block(self):
        src = ("def main():\n    print('hi')\n\n"
               "if __name__ == '__main__':\n    main()\n")
        self.assertTrue(crucible.run_main(src).ok)

    def test_generated_code_does_not_inherit_secrets(self):
        os.environ["ATTESTOR_CRUCIBLE_SECRET"] = "super-secret"
        try:
            v = crucible.imports(
                "import os\n"
                "raise RuntimeError(os.environ.get('ATTESTOR_CRUCIBLE_SECRET', 'missing'))\n")
        finally:
            os.environ.pop("ATTESTOR_CRUCIBLE_SECRET", None)
        self.assertFalse(v.ok)
        self.assertIn("missing", v.detail)

    def test_interpreter_runs_in_isolated_mode(self):
        v = crucible.imports("import sys\nassert sys.flags.isolated == 1\n")
        self.assertTrue(v.ok, v.detail)
        self.assertTrue(v.sandbox["python_isolated_mode"])

    def test_network_is_blocked_by_the_audit_policy(self):
        v = crucible.imports("import socket\nsocket.socket()\n")
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "policy-blocked")
        self.assertIn("sandbox denied socket", v.stderr)

    def test_child_processes_are_blocked_by_the_audit_policy(self):
        v = crucible.imports(
            "import subprocess, sys\nsubprocess.run([sys.executable, '-c', 'pass'])\n")
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "policy-blocked")
        # Which hook fires is a platform detail. Windows reaches the subprocess
        # audit event; on POSIX, importing `subprocess` pulls in
        # `_posixsubprocess` and the import hook refuses that first -- earlier,
        # and no weaker. Both are the sandbox refusing to start a child, so the
        # assertion is on that outcome rather than on one platform's wording.
        self.assertIn("sandbox denied", v.stderr)
        self.assertIn("subprocess", v.stderr)

    def test_low_level_native_process_escape_modules_are_blocked(self):
        v = crucible.imports("import ctypes\n")
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "policy-blocked")
        self.assertIn("sandbox denied import _ctypes", v.stderr)

    def test_filesystem_write_cannot_escape_temporary_directory(self):
        v = crucible.imports(
            "import os\n"
            "path = os.path.join(os.path.dirname(os.getcwd()), 'attestor-escape-test')\n"
            "open(path, 'w').write('nope')\n")
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "policy-blocked")
        self.assertIn("outside allowed roots", v.stderr)

    def test_candidate_tempfiles_are_redirected_into_the_sandbox(self):
        v = crucible.imports(
            "import os, tempfile\n"
            "fd, path = tempfile.mkstemp()\n"
            "os.close(fd)\n"
            "assert os.path.commonpath((os.getcwd(), path)) == os.getcwd()\n")
        self.assertTrue(v.ok, v.detail)

    def test_native_sqlite_file_access_cannot_escape_the_sandbox(self):
        local = crucible.imports(
            "import sqlite3\n"
            "db = sqlite3.connect('local.db')\n"
            "db.execute('create table ok (id integer)')\n"
            "db.close()\n")
        self.assertTrue(local.ok, local.detail)
        escaped = crucible.imports(
            "import os, sqlite3\n"
            "path = os.path.join(os.path.dirname(os.getcwd()), 'escape.db')\n"
            "sqlite3.connect(path)\n")
        self.assertFalse(escaped.ok)
        self.assertEqual(escaped.status, "policy-blocked")
        self.assertIn("sqlite database outside", escaped.stderr)

    def test_output_is_bounded(self):
        v = crucible.imports("print('x' * 100000)\n", max_output=1024)
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "output-limited")
        self.assertLessEqual(len(v.stdout.encode("utf-8")), 1024)

    def test_filesystem_growth_is_bounded(self):
        with mock.patch("crucible.MAX_FILESYSTEM_GROWTH_BYTES", 8192):
            v = crucible.imports("open('large.bin', 'wb').write(b'x' * 100000)\n")
        self.assertFalse(v.ok)
        self.assertEqual(v.status, "filesystem-limited")
        self.assertIn("filesystem write limit", v.detail)

    def test_trusted_commands_need_a_separate_explicit_opt_in(self):
        denied = crucible.run_trusted_command(
            [sys.executable, "-c", "print('ok')"], os.getcwd())
        self.assertFalse(denied.ok)
        self.assertEqual(denied.status, "disabled")
        allowed = crucible.run_trusted_command(
            [sys.executable, "-c", "print('ok')"], os.getcwd(), trusted=True)
        self.assertTrue(allowed.ok, allowed.detail)
        self.assertIn("ok", allowed.stdout)

    def test_sandbox_status_is_honest_about_not_being_a_container(self):
        status = crucible.sandbox_status()
        self.assertFalse(status["kernel_container"])
        self.assertTrue(status["bounded_output"])
        self.assertTrue(status["process_tree_termination"])

    def test_verdict_is_truthy(self):
        self.assertTrue(bool(crucible.Verdict(True)))
        self.assertFalse(bool(crucible.Verdict(False)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
