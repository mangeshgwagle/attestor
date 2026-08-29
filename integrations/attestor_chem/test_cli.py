from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
CLI = HERE / "cli.py"


class PharmaCliTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update({
            "PYTHONPATH": str(
                Path(tempfile.gettempdir()) / "attestor-untrusted-pythonpath"),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        return subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8", str(CLI),
             *arguments],
            cwd=Path(tempfile.gettempdir()).resolve(),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )

    def assert_no_traceback(self, completed: subprocess.CompletedProcess[str]) -> None:
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)

    def test_isolated_help_and_coverage(self) -> None:
        help_result = self.run_cli("--help")
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("pharmaceutical-formation study", help_result.stdout)

        coverage = self.run_cli("coverage")
        self.assertEqual(coverage.returncode, 0, coverage.stderr)
        self.assertIn("Not yet bound to a named board", coverage.stdout)
        self.assert_no_traceback(coverage)

    def test_teach_combines_answer_reasoning_and_recall(self) -> None:
        completed = self.run_cli("teach", "boric acid")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("WORKED EXAM ANSWER", completed.stdout)
        self.assertIn("TRANSFERABLE REASONING", completed.stdout)
        self.assertIn("CLOSE THE ANSWER", completed.stdout)
        self.assertIn("NOT A LABORATORY", completed.stdout)
        self.assert_no_traceback(completed)

    def test_unknown_entry_is_a_bounded_not_found_result(self) -> None:
        completed = self.run_cli("show", "definitely-not-an-entry")
        self.assertEqual(completed.returncode, 1)
        self.assertIn("nothing called", completed.stderr.lower())
        self.assert_no_traceback(completed)

    def test_recall_is_bounded_and_seeded(self) -> None:
        first = self.run_cli("recall", "3", "--seed", "42")
        second = self.run_cli("recall", "3", "--seed", "42")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        for invalid in ("-1", "0", "21", "not-a-number"):
            with self.subTest(invalid=invalid):
                completed = self.run_cli("recall", invalid)
                self.assertEqual(completed.returncode, 2)
                self.assert_no_traceback(completed)

    def test_invalid_list_kind_and_extra_arguments_are_rejected(self) -> None:
        for arguments in (("list", "unknown"), ("patterns", "ignored"),
                          ("coverage", "ignored"), ("check", "ignored")):
            with self.subTest(arguments=arguments):
                completed = self.run_cli(*arguments)
                self.assertEqual(completed.returncode, 2)
                self.assert_no_traceback(completed)

    def test_unknown_derivation_abstains_from_inventing_a_route(self) -> None:
        completed = self.run_cli("derive", "imaginaryium citrate")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("NO UNIQUE CHECKED MATCH", completed.stdout)
        self.assertIn("not inferring a substance-specific route", completed.stdout)
        self.assertIn("does not prove a reaction route", completed.stdout)
        self.assert_no_traceback(completed)


if __name__ == "__main__":
    unittest.main()
