#!/usr/bin/env python3
"""Tests for refine.py -- the verification-gated improve-until-fixed-point loop."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import refine


def _refine(src):
    return refine.refine(src, "<t>")


class FixerTests(unittest.TestCase):
    def test_removes_an_unused_import(self):
        out, changes = _refine("import os\n\n\ndef f():\n    return 1\n")
        self.assertNotIn("import os", out)
        self.assertTrue(any("unused import" in c for c in changes))

    def test_keeps_an_import_that_is_used(self):
        src = "import os\n\n\ndef f():\n    return os.getcwd()\n"
        out, _ = _refine(src)
        self.assertIn("import os", out)          # used -> never removed

    def test_narrows_a_bare_except(self):
        src = "def f():\n    try:\n        return 1\n    except:\n        return 0\n"
        out, changes = _refine(src)
        self.assertIn("except Exception:", out)
        self.assertNotIn("except:", out)
        self.assertTrue(any("bare" in c for c in changes))

    def test_adds_a_missing_timeout(self):
        src = "import requests\n\n\ndef f(u):\n    return requests.get(u)\n"
        out, changes = _refine(src)
        self.assertIn("timeout=30", out)
        self.assertTrue(any("timeout" in c for c in changes))

    def test_none_comparison_becomes_identity(self):
        out, _ = _refine("def f(x):\n    if x == None:\n        return 1\n    return 0\n")
        self.assertIn("is None", out)
        self.assertNotIn("== None", out)
        out2, _ = _refine("def f(x):\n    return x != None\n")
        self.assertIn("is not None", out2)

    def test_is_on_a_literal_becomes_comparison(self):
        out, _ = _refine("def f(x):\n    if x is 5:\n        return 1\n    return 0\n")
        self.assertIn("== 5", out)
        self.assertNotIn("is 5", out)
        out2, _ = _refine("def f(x):\n    return x is not 7\n")
        self.assertIn("!= 7", out2)

    def test_is_none_is_left_alone(self):
        # the is-literal fixer must not touch the correct `is None`/`is True`
        src = "def f(x):\n    return x is None\n"
        out, changes = _refine(src)
        self.assertEqual(out, src)
        self.assertEqual(changes, [])


class SafetyTests(unittest.TestCase):
    def test_clean_code_is_a_fixed_point(self):
        src = "def add(a, b):\n    return a + b\n"
        out, changes = _refine(src)
        self.assertEqual(out, src)
        self.assertEqual(changes, [])

    def test_output_always_parses(self):
        src = "import os\nimport sys\ndef f():\n    try:\n        return 1\n    except:\n        return 0\n"
        out, _ = _refine(src)
        import ast
        ast.parse(out)                           # would raise if refine broke it

    def test_never_increases_findings(self):
        src = ("import os\nimport json\nimport subprocess\n\n\n"
               "def run(cmd):\n    try:\n        return subprocess.run(cmd)\n"
               "    except:\n        return None\n")
        before = len(refine._scan_all(src, "<t>"))
        out, _ = _refine(src)
        after = len(refine._scan_all(out, "<t>"))
        self.assertLess(after, before)           # strictly better on this input
        self.assertGreaterEqual(before - after, 1)


class CliTests(unittest.TestCase):
    def test_write_mode_rewrites_the_file(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as fh:
            fh.write("import os\n\n\ndef f():\n    return 1\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            refine.main([path, "--write"])
        with open(path, encoding="utf-8") as fh:
            result = fh.read()
        os.remove(path)
        self.assertNotIn("import os", result)
        self.assertEqual(buf.getvalue(), "")     # --write prints code to stderr, not stdout

    def test_default_prints_code_to_stdout(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as fh:
            fh.write("def f():\n    return 1\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            refine.main([path])
        os.remove(path)
        self.assertIn("def f():", buf.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
