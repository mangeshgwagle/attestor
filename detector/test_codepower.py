#!/usr/bin/env python3
"""Tests for codepower.py -- Attestor 2 coding-agent upgrade layer."""
import os
import tempfile
import unittest

import codepower


SAMPLE = """def helper(items):
    out = []
    for row in items:
        for value in row:
            out += [value]
    return out


def public(limit):
    return helper([[limit]])
"""


class CodePowerTests(unittest.TestCase):
    def _sample_file(self, root):
        path = os.path.join(root, "sample.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(SAMPLE)
        return path

    def test_analyze_reports_all_named_modes(self):
        with tempfile.TemporaryDirectory() as root:
            self._sample_file(root)
            report = codepower.analyze(root)
            text = codepower.render(report)
        self.assertIn("Architect Mode", text)
        self.assertIn("Test Smith", text)
        self.assertIn("Performance Lens", text)
        self.assertIn("Dead Code Surgeon", text)
        self.assertIn("Patch Ranker", text)

    def test_performance_lens_finds_nested_loop_and_concat(self):
        with tempfile.TemporaryDirectory() as root:
            path = self._sample_file(root)
            findings = "\n".join(codepower.performance_lens([path]))
        self.assertIn("nested-loop", findings)
        self.assertIn("loop-concat", findings)

    def test_prompt_path_uses_sieve(self):
        text, code = codepower.run("write fibonacci", bus=None, rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Code Power prompt pipeline", text)
        self.assertIn("def fib", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
