#!/usr/bin/env python3
"""Tests for codemax.py -- Attestor's maximum coding console."""
import os
import tempfile
import unittest

import codemax


CLEAN = """def add(left: int, right: int) -> int:
    \"\"\"Return the sum of two integers.\"\"\"
    return left + right
"""


class CodeMaxTests(unittest.TestCase):
    def test_api_surface_maps_public_functions(self):
        surface = codemax.api_surface(CLEAN, "sample.py")
        self.assertEqual(surface[0]["name"], "add")
        self.assertEqual(surface[0]["typed_args"], 2)
        self.assertTrue(surface[0]["has_return"])

    def test_call_graph_finds_direct_edges(self):
        source = ("def helper(x):\n    return x + 1\n\n"
                  "def main(x):\n    return helper(x)\n")
        self.assertEqual(codemax.call_graph(source), [("main", "helper")])

    def test_file_review_generates_report_and_tests(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(CLEAN)
        try:
            text, code = codemax.run(path, rounds=3)
        finally:
            os.remove(path)
        self.assertEqual(code, 0)
        self.assertIn("Code Max file review", text)
        self.assertIn("Generated smoke-test skeleton", text)
        self.assertIn("test_add_exists", text)

    def test_prompt_path_uses_sieve(self):
        text, code = codemax.run("write fibonacci", bus=None, rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Code Max prompt pipeline", text)
        self.assertIn("def fib", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
