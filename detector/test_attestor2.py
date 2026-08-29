#!/usr/bin/env python3
"""Tests for attestor2.py -- combined Attestor 2 maximum review."""
import os
import tempfile
import unittest

import attestor2


class Attestor2Tests(unittest.TestCase):
    def test_combined_review_runs_code_and_security(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "app.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("def add(a: int, b: int) -> int:\n    return a + b\n")
            text, code = attestor2.run(root, rounds=3)
        self.assertGreaterEqual(code, 0)
        self.assertIn("Attestor 2 Max Review", text)
        self.assertIn("Attestor 2 Code Power", text)
        self.assertIn("Attestor 2 Security Max", text)

    def test_prompt_path_uses_codepower_sieve(self):
        text, code = attestor2.run("write fibonacci", bus=None, rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Attestor 2 Max prompt pipeline", text)
        self.assertIn("def fib", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
