#!/usr/bin/env python3
"""Tests for benchmark.py -- the honest Attestor-vs-LLM scorecard. Offline/deterministic."""
import unittest

import benchmark


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.measured = benchmark.measure()

    def setUp(self):
        self.metrics = self.measured

    def test_has_all_metric_keys(self):
        for key in ("bug_recall_pct", "bugs_detected", "bugs_expected",
                    "generated_lines", "generated_files", "generated_regex_findings",
                    "generated_ast_findings", "deterministic", "cost_usd",
                    "corpus_scan_ms", "generation_ms"):
            self.assertIn(key, self.metrics)

    def test_full_bug_recall(self):
        # Attestor finds every planted/real bug in the labelled corpus
        self.assertEqual(self.metrics["bug_recall_pct"], 100.0)
        self.assertEqual(self.metrics["bugs_detected"], self.metrics["bugs_expected"])

    def test_generated_code_is_clean_under_both_engines(self):
        self.assertEqual(self.metrics["generated_regex_findings"], 0)
        self.assertEqual(self.metrics["generated_ast_findings"], 0)

    def test_deterministic_and_free(self):
        self.assertTrue(self.metrics["deterministic"])
        self.assertEqual(self.metrics["cost_usd"], 0.0)

    def test_generates_substantial_code(self):
        self.assertGreater(self.metrics["generated_lines"], 2900)

    def test_report_is_honest_about_scope(self):
        text = benchmark.report(self.metrics)
        self.assertIn("GPT-5.5", text)
        self.assertIn("NOT A FAIR FIGHT", text)     # the honesty is not optional
        self.assertIn("apples-to-oranges", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
