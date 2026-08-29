#!/usr/bin/env python3
"""Tests for codebench.py -- the honest '...and coding?' scorecard. Offline."""
import unittest

import codebench


class CodebenchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metrics = codebench.measure()

    def setUp(self):
        self.m = self.metrics

    def test_direct_generative_is_zero(self):
        # Attestor alone still has no offline natural-language -> novel-code model.
        self.assertEqual(self.m["direct_generative_solved"], 0)
        self.assertEqual(self.m["generative_solved"], 0)  # compatibility alias
        self.assertGreaterEqual(self.m["direct_generative_total"], 5)

    def test_assisted_gate_rejects_bad_code_and_accepts_repairs(self):
        self.assertEqual(self.m["assisted_gate_solved"], self.m["assisted_gate_total"])
        self.assertGreaterEqual(self.m["assisted_gate_total"], 3)

    def test_scaffolding_is_perfect(self):
        # the coding he does deterministically: a clean, compiling, reviewed service
        self.assertEqual(self.m["scaffolding_solved"], self.m["scaffolding_total"])

    def test_mechanical_fixes_land_but_reasoning_ones_go_through_forge(self):
        self.assertEqual(self.m["mechanical_fix_solved"], self.m["mechanical_fix_total"])
        self.assertEqual(self.m["reasoning_fix_solved"], 0)

    def test_attestor_solve_returns_empty_namespace(self):
        # direct Attestor-alone generation is still the honest zero baseline
        self.assertEqual(codebench.attestor_solve({"name": "x"}), {})

    def test_report_splits_direct_attestor_from_api_assisted_attestor(self):
        text = codebench.report(self.m)
        self.assertIn("Attestor alone: 0/6", text)
        self.assertIn("ATTESTOR + APIS", text)
        self.assertIn("behavior smoke tests", text)
        self.assertIn("VERDICT", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
