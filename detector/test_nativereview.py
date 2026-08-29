#!/usr/bin/env python3
"""Tests for nativereview.py -- change-only review of C/C++/Assembly. Offline."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import nativereview as nr


def _tmp(src, suffix=".c"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


CLEAN = "void f(char *a, char *b) {\n    (void)a;\n    (void)b;\n}\n"
ADDS_BUG = "void f(char *a, char *b) {\n    strcpy(a, b);\n}\n"


class ReviewTests(unittest.TestCase):
    def test_introduced_bug_is_reported(self):
        old = _tmp(CLEAN)
        new = _tmp(ADDS_BUG)
        result = nr.review(old, new)
        os.remove(old)
        os.remove(new)
        rules = [f[0] for f in result["introduced"]]
        self.assertIn("native-strcpy", rules)
        self.assertLess(result["after"].score, result["before"].score)

    def test_fixing_a_bug_shows_as_fixed_not_introduced(self):
        old = _tmp(ADDS_BUG)
        new = _tmp(CLEAN)
        result = nr.review(old, new)
        os.remove(old)
        os.remove(new)
        self.assertEqual(result["introduced"], [])
        self.assertIn("native-strcpy", {f[0] for f in result["fixed"]})

    def test_moving_a_preexisting_bug_is_not_introduced(self):
        # same bug, just shifted down by a blank line -> not a new finding
        old = _tmp("void f(char*a,char*b){\n    strcpy(a,b);\n}\n")
        new = _tmp("void f(char*a,char*b){\n\n\n    strcpy(a,b);\n}\n")
        result = nr.review(old, new)
        os.remove(old)
        os.remove(new)
        self.assertEqual(result["introduced"], [])

    def test_exit_code_is_number_introduced(self):
        old = _tmp(CLEAN)
        new = _tmp("void f(char*a,char*b){ strcpy(a,b); gets(a); }\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = nr.main([old, new])
        os.remove(old)
        os.remove(new)
        self.assertEqual(rc, 2)                       # strcpy + gets
        self.assertIn("introduced", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
