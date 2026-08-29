#!/usr/bin/env python3
"""Tests for nativegrade.py -- the A-F verdict for C/C++/Assembly. Offline."""
import io
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import nativegrade as ng


def _tmp(src, suffix=".c"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


class LetterTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(ng.letter(95), "A")
        self.assertEqual(ng.letter(85), "B")
        self.assertEqual(ng.letter(65), "D")
        self.assertEqual(ng.letter(30), "F")


class GradeTests(unittest.TestCase):
    def test_clean_c_earns_high(self):
        path = _tmp("int add(int a, int b) {\n    return a + b;\n}\n")
        fg, findings, _ = ng.grade_file(path)
        os.remove(path)
        if shutil.which("gcc") or shutil.which("clang") or shutil.which("cc"):
            self.assertEqual(findings, [])
            self.assertEqual(fg.grade, "A")
            self.assertEqual(fg.score, 100)
            self.assertTrue(fg.compiler_verified)
        else:
            self.assertNotEqual(fg.grade, "A")
            self.assertFalse(fg.compiler_verified)

    def test_buggy_c_sinks_to_f(self):
        path = _tmp("void f(char*u){ gets(u); strcpy(u,u); system(u); }\n")
        fg, _findings, _ = ng.grade_file(path)
        os.remove(path)
        self.assertEqual(fg.grade, "F")
        self.assertGreaterEqual(fg.critical, 1)     # gets()

    def test_high_native_finding_fails_default_c_gate(self):
        path = _tmp("#include <string.h>\nvoid f(char *dst, char *src) {\n    strcpy(dst, src);\n}\n")
        graded = ng.collect([path])
        os.remove(path)
        self.assertEqual(graded[0][0].grade, "D")
        self.assertEqual(len(ng.failures(graded, "C")), 1)

    @unittest.skipUnless(shutil.which("gcc") or shutil.which("clang") or shutil.which("cc"),
                         "C compiler required for syntax-verification regression")
    def test_invalid_c_is_compiler_rejected_and_forced_to_f(self):
        path = _tmp("int broken( { return 1; }\n")
        fg, findings, _ = ng.grade_file(path)
        os.remove(path)
        self.assertEqual(fg.compile_status, "failed")
        self.assertFalse(fg.compiler_verified)
        self.assertEqual(fg.grade, "F")
        self.assertIn("native-compile-error", {finding[1] for finding in findings})

    def test_missing_compiler_never_awards_an_a(self):
        path = _tmp("int add(int a, int b) { return a + b; }\n")
        with mock.patch("nativegrade.shutil.which", return_value=None):
            fg, findings, _ = ng.grade_file(path)
        os.remove(path)
        self.assertFalse(fg.compiler_verified)
        self.assertNotEqual(fg.grade, "A")
        self.assertIn("native-compile-unverified", {finding[1] for finding in findings})

    def test_complexity_alone_caps_above_f(self):
        # a bug-free but deeply nested function: complexity penalty is capped
        body = "".join("    " * (i + 1) + "if (x) {\n" for i in range(8))
        close = "".join("    " * (8 - i) + "}\n" for i in range(8))
        src = "int deep(int x) {\n" + body + "        return 1;\n" + close + "}\n"
        path = _tmp(src)
        # This test isolates complexity scoring. Compiler availability has its
        # own fail-closed regressions and must not make the unit environment-dependent.
        with mock.patch("nativegrade._compiler_check",
                        return_value=("verified", "fixture-cc", "accepted")):
            fg, findings, _ = ng.grade_file(path)
        os.remove(path)
        self.assertEqual(findings, [])              # no bugs
        self.assertGreaterEqual(ng._rank(fg.grade), ng._rank("D"))   # not below D


class CliTests(unittest.TestCase):
    def test_exit_code_counts_files_below_pass(self):
        clean = _tmp("int ok(int a) {\n    return a;\n}\n")
        bad = _tmp("void f(char*u){ gets(u); strcpy(u,u); system(u); sprintf(u,u); }\n")
        buf = io.StringIO()
        with mock.patch("nativegrade._compiler_check",
                        return_value=("verified", "fixture-cc", "accepted")), \
                redirect_stdout(buf):
            rc = ng.main([clean, bad, "--pass", "B"])
        os.remove(clean)
        os.remove(bad)
        self.assertEqual(rc, 1)                     # only the bad file fails B
        self.assertIn("worst grade F", buf.getvalue())

    def test_json_output(self):
        import json
        path = _tmp("int f(int a) {\n    return a;\n}\n")
        buf = io.StringIO()
        with mock.patch("nativegrade._compiler_check",
                        return_value=("verified", "fixture-cc", "accepted")), \
                redirect_stdout(buf):
            ng.main([path, "--json"])
        os.remove(path)
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["grade"], "A")
        self.assertIn("fix_first", data[0])

    def test_missing_and_unsupported_inputs_fail_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "missing.c")
            unsupported = os.path.join(directory, "notes.txt")
            with open(unsupported, "w", encoding="utf-8") as handle:
                handle.write("plain text")
            for path, expected in ((missing, "does not exist"),
                                   (unsupported, "unsupported native input")):
                err, out = io.StringIO(), io.StringIO()
                with redirect_stderr(err), redirect_stdout(out):
                    rc = ng.main([path])
                self.assertEqual(rc, 2)
                self.assertIn(expected, err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
