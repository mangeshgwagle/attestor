#!/usr/bin/env python3
"""Tests for coder.py -- Attestor's code-writing contract and scorecard."""
import unittest

import coder


class CoderTests(unittest.TestCase):
    def test_contract_adds_data_structure_rules(self):
        spec = coder.contract("implement an LRU cache")
        joined = "\n".join(spec["rules"])
        self.assertIn("data-structure invariants", joined)
        self.assertIn("capacity limits", joined)

    def test_generation_prompt_is_strict_code_only(self):
        prompt = coder.generation_prompt("write fibonacci")
        self.assertIn("Attestor Coding Contract", prompt)
        self.assertIn("Attestor Power Plan", prompt)
        self.assertIn("Return ONLY Python code", prompt)

    def test_power_plan_adds_graph_edge_cases(self):
        plan = coder.power_plan("write dijkstra shortest path")
        self.assertIn("disconnected graph", plan["edge_cases"])
        self.assertIn("choose the simplest correct algorithm", plan["phases"])

    def test_score_penalizes_runtime_failure(self):
        clean = coder.score_candidate("def f():\n    return 1\n", ran=True)
        failed = coder.score_candidate("def f():\n    return 1\n", ran=False)
        self.assertGreater(clean["score"], failed["score"])
        self.assertEqual(clean["grade"], "excellent")

    def test_score_penalizes_no_public_api(self):
        score = coder.score_candidate("value = 1\n", ran=True)
        self.assertLess(score["score"], 100)

    def test_empty_candidate_is_rejected_not_excellent(self):
        score = coder.score_candidate("")
        self.assertEqual(score["score"], 0)
        self.assertEqual(score["grade"], "reject")
        self.assertEqual(score["public_defs"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
