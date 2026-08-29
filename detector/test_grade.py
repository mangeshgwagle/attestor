#!/usr/bin/env python3
"""Tests for grade.py -- the unified A-F verdict engine. Offline/deterministic."""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import grade
import metrics

LIMITS = metrics.DEFAULT_LIMITS


def _grade(src):
    return grade.grade_source(src, "<t>", LIMITS)


def _tmpfile(src):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


class LetterTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(grade.letter(95), "A")
        self.assertEqual(grade.letter(85), "B")
        self.assertEqual(grade.letter(75), "C")
        self.assertEqual(grade.letter(65), "D")
        self.assertEqual(grade.letter(40), "F")


class ScoringTests(unittest.TestCase):
    def test_clean_code_earns_an_A(self):
        fg, findings, _ = _grade("def add(a, b):\n    return a + b\n")
        self.assertEqual(findings, [])
        self.assertEqual(fg.score, 100)
        self.assertEqual(fg.grade, "A")

    def test_a_high_finding_drops_the_grade(self):
        # assert-tuple is a HIGH deepscan finding (always true, silently passes).
        fg, _, _ = _grade("def f(x):\n    assert (x > 0, 'must be positive')\n")
        self.assertEqual(fg.findings_high, 1)
        self.assertEqual(fg.score, 69)          # HIGH findings cannot receive A/B/C
        self.assertEqual(fg.grade, "D")

    def test_complexity_alone_costs_points_with_no_bugs(self):
        src = "def deep(x):\n" + "".join(
            "    " * (i + 1) + "if x:\n" for i in range(7)) + "    " * 8 + "return 1\n"
        fg, findings, _ = _grade(src)
        self.assertEqual(fg.findings_high + fg.findings_medium + fg.findings_low, 0)
        self.assertGreaterEqual(fg.over_threshold, 1)   # cognitive/nesting over limit
        self.assertLess(fg.score, 100)                  # clean but not free

    def test_syntax_error_is_a_high_finding(self):
        fg, _, _ = _grade("def f(:\n")
        self.assertGreaterEqual(fg.findings_high, 1)
        self.assertEqual(fg.grade, "F")
        self.assertLessEqual(fg.score, grade.SYNTAX_ERROR_SCORE_CAP)


class ImprovementTests(unittest.TestCase):
    def test_serious_findings_are_listed_before_complexity(self):
        src = ("def f(x):\n"
               "    assert (x, 'bad')\n"
               + "".join("    " * (i + 1) + "if x:\n" for i in range(7))
               + "    " * 8 + "return 1\n")
        _, findings, funcs = _grade(src)
        tips = grade.improvements(findings, funcs, LIMITS)
        self.assertTrue(tips[0].startswith("[HIGH]"))
        self.assertTrue(any("split" in t for t in tips))


class CliTests(unittest.TestCase):
    def test_exit_code_counts_files_below_pass(self):
        clean = _tmpfile("def ok(a, b):\n    return a + b\n")
        bad = _tmpfile("def a(x):\n    assert (x, '1')\n\n"
                       "def b(x):\n    assert (x, '2')\n\n"
                       "def c(x):\n    assert (x, '3')\n")   # 3 HIGH -> F
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = grade.main([clean, bad, "--pass", "B"])
        os.remove(clean); os.remove(bad)
        self.assertEqual(rc, 1)                       # only the bad file fails B
        self.assertIn("worst grade F", buf.getvalue())

    def test_json_output_is_valid(self):
        path = _tmpfile("def add(a, b):\n    return a + b\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            grade.main([path, "--json"])
        os.remove(path)
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["grade"], "A")
        self.assertIn("fix_first", data[0])

    def test_missing_and_unsupported_inputs_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing.py")
            unsupported = os.path.join(directory, "notes.txt")
            with open(unsupported, "w", encoding="utf-8") as handle:
                handle.write("plain text")
            for path, expected in ((missing, "does not exist"),
                                   (unsupported, "unsupported input type")):
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = grade.main([path])
                self.assertEqual(rc, 2)
                self.assertIn(expected, err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
