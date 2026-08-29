#!/usr/bin/env python3
"""Tests for detector/rankgate_trainer42.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import rankgate_trainer42 as rg  # noqa: E402


class TestTraining(unittest.TestCase):
    def setUp(self):
        self.outcome = rg.train(rg.DEMO_DATASET)
        self.model = self.outcome["model"]

    def test_converges_on_separable_corpus(self):
        self.assertTrue(self.model["converged"])
        self.assertEqual(self.model["final_epoch_errors"], 0)

    def test_punishments_were_recorded(self):
        self.assertGreater(self.model["updates_total"], 0)
        kinds = {r["update"] for r in self.outcome["ledger"]}
        self.assertTrue(kinds & {"punish-false-positive",
                                 "punish-false-negative"})

    def test_perfect_accuracy_after_training(self):
        evaluation = rg.evaluate_model(self.model, rg.DEMO_DATASET)
        self.assertEqual(evaluation["accuracy"], 1.0)

    def test_false_positive_punishment_lowers_weights(self):
        tricky = [{"id": "trap", "rule_confidence": 1.0,
                   "reachability": 1.0, "severity": 1.0,
                   "evidence_density": 1.0, "surface_proximity": 1.0,
                   "label": 0}]
        outcome = rg.train(tricky, max_epochs=1)
        after = outcome["model"]["weights_scaled"]
        initial = rg.SCALE // 10
        self.assertTrue(all(after[n] < initial for n in rg.FEATURE_ORDER))
        kinds = {r["update"] for r in outcome["ledger"]}
        self.assertIn("punish-false-positive", kinds)

    def test_training_deterministic(self):
        import json
        first = json.dumps(rg.train(rg.DEMO_DATASET)["model"],
                           sort_keys=True)
        second = json.dumps(rg.train(rg.DEMO_DATASET)["model"],
                            sort_keys=True)
        self.assertEqual(first, second)


class TestInference(unittest.TestCase):
    def test_obvious_true_positive_kept(self):
        outcome = rg.train(rg.DEMO_DATASET)
        result = rg.score_finding(
            outcome["model"],
            {"rule_confidence": 0.95, "reachability": 0.9,
             "severity": 0.95, "evidence_density": 0.85,
             "surface_proximity": 0.9})
        self.assertEqual(result["prediction"], "keep")

    def test_obvious_noise_demoted(self):
        outcome = rg.train(rg.DEMO_DATASET)
        result = rg.score_finding(
            outcome["model"],
            {"rule_confidence": 0.05, "reachability": 0.01,
             "severity": 0.1, "evidence_density": 0.02,
             "surface_proximity": 0.03})
        self.assertEqual(result["prediction"], "demote")

    def test_out_of_range_feature_refused(self):
        with self.assertRaises(rg.RgError):
            rg.parse_finding({"rule_confidence": 4.2, "reachability": 0.1,
                              "severity": 0.1, "evidence_density": 0.1,
                              "surface_proximity": 0.1}, require_label=False)


class TestLedger(unittest.TestCase):
    def test_chain_verifies(self):
        outcome = rg.train(rg.DEMO_DATASET)
        check = rg.verify_ledger(outcome["ledger"])
        self.assertTrue(check["valid"])

    def test_edit_breaks_chain_at_named_step(self):
        outcome = rg.train(rg.DEMO_DATASET)
        tampered = [dict(r) for r in outcome["ledger"]]
        target = tampered[2]
        key = next(iter(target["delta"]))
        target["delta"] = dict(target["delta"])
        target["delta"][key] += 7
        check = rg.verify_ledger(tampered)
        self.assertFalse(check["valid"])
        self.assertEqual(check.get("broken_at_step"), 3)

    def test_reorder_breaks_chain(self):
        outcome = rg.train(rg.DEMO_DATASET)
        if len(outcome["ledger"]) >= 2:
            shuffled = [outcome["ledger"][1], outcome["ledger"][0]]
            shuffled += outcome["ledger"][2:]
            check = rg.verify_ledger(shuffled)
            self.assertFalse(check["valid"])

    def test_empty_ledger_valid(self):
        check = rg.verify_ledger([])
        self.assertTrue(check["valid"])


class TestSelfTest(unittest.TestCase):
    def test_selftest_passes(self):
        result = rg.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
