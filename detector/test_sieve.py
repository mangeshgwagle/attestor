#!/usr/bin/env python3
"""Tests for sieve.py -- Attestor's repeated write/review/improve loop."""
import os
import tempfile
import unittest

import sieve


CLEAN = "def merge(a, b):\n    return sorted(a + b)\n"
BAD = "def merge(a, b):\n    return a + b\n"


class FakeBrain:
    def __init__(self, answers):
        self.answers = list(answers)

    def available(self):
        return True

    def generate(self, _prompt):
        return self.answers.pop(0)


class SieveTests(unittest.TestCase):
    def test_file_refinement_repeats_until_cleaner(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("import os\n\n\ndef f():\n    return 1\n")
        try:
            text, code = sieve.run(path, rounds=20)
        finally:
            os.remove(path)
        self.assertEqual(code, 0)
        self.assertIn("Sieve fixed-point refinement", text)
        self.assertNotIn("import os", text)

    def test_model_backed_loop_repairs_behavior(self):
        text, code = sieve.run("merge sorted lists", bus=FakeBrain([BAD, CLEAN]), rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Sieve model-backed coding loop", text)
        self.assertIn("BEHAVIOR-CHECKED CANDIDATE", text)
        self.assertIn("not proof of all correctness", text)

    def test_offline_known_snippet_is_checked(self):
        text, code = sieve.run("write fibonacci", bus=None, rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("vetted local solution", text)
        self.assertIn("def fib", text)

    def test_offline_novel_request_is_honest(self):
        text, code = sieve.run("write a compiler optimizer", bus=None, rounds=3)
        self.assertEqual(code, 1)
        self.assertIn("provider API", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
