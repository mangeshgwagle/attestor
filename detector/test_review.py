#!/usr/bin/env python3
"""Tests for review.py -- change-only Python review. Offline."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stdout

import review


CLEAN = "def f(a, b):\n    return a + b\n"
ADDS_BUG = "import os\n\n\ndef f(a, b):\n    return a + b\n"          # unused import


def _tmp(src):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


class ReviewTests(unittest.TestCase):
    def test_introduced_finding_is_reported(self):
        result = review.review(CLEAN, ADDS_BUG, "old.py", "new.py")
        rules = [f[0] for f in result["introduced"]]
        self.assertIn("unused-import", rules)

    def test_fixing_shows_as_fixed_not_introduced(self):
        result = review.review(ADDS_BUG, CLEAN, "old.py", "new.py")
        self.assertEqual(result["introduced"], [])
        self.assertIn("unused-import", {f[0] for f in result["fixed"]})

    def test_moving_a_preexisting_finding_is_not_introduced(self):
        old = "import os\ndef f():\n    return 1\n"
        new = "import os\n\n\n\ndef f():\n    return 1\n"      # same unused import, shifted
        result = review.review(old, new, "old.py", "new.py")
        self.assertEqual(result["introduced"], [])

    def test_clean_to_clean_is_silent(self):
        result = review.review(CLEAN, CLEAN, "old.py", "new.py")
        self.assertEqual(result["introduced"], [])
        self.assertIn("no new findings", review.render(result, "new.py"))


class CliTests(unittest.TestCase):
    def test_two_file_exit_code(self):
        old = _tmp(CLEAN)
        new = _tmp(ADDS_BUG)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = review.main([old, new])
        os.remove(old)
        os.remove(new)
        self.assertEqual(rc, 1)                        # one introduced finding
        self.assertIn("introduced", buf.getvalue())

    def test_json_mode(self):
        import json
        old = _tmp(CLEAN)
        new = _tmp(ADDS_BUG)
        buf = io.StringIO()
        with redirect_stdout(buf):
            review.main([old, new, "--json"])
        os.remove(old)
        os.remove(new)
        data = json.loads(buf.getvalue())
        self.assertIn("introduced", data)
        self.assertTrue(any(f["rule"] == "unused-import" for f in data["introduced"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
