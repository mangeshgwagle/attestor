#!/usr/bin/env python3
import os
import sys
import unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eval42 as ev

class EvalMetrics(unittest.TestCase):
    def test_remediation_threshold(self):
        ok = [{"fixed": True, "regression": False}]*8 + [{"fixed": False}]*2
        r = ev.remediation_correctness(ok)
        self.assertGreaterEqual(r["correctness_rate"], 0.8)
        self.assertTrue(r["passes_threshold"])
        bad = [{"fixed": True, "regression": False}]*5 + [{"fixed": False}]*5
        r2 = ev.remediation_correctness(bad)
        self.assertFalse(r2["passes_threshold"])

    def test_hallucination_threshold(self):
        claims = [{"kind":"value","text":"findings exist","evidence_path":"/findings","operator":"exists","supported":True}]
        hr = ev.hallucination_rate(claims, {"findings":[1]})
        self.assertLess(hr["rate"], 0.01)
        claims2 = [{"kind":"statement","text":"invented","supported":False}]*5
        hr2 = ev.hallucination_rate(claims2, {})
        self.assertGreaterEqual(hr2["rate"], 0.01)

    def test_triage_accuracy(self):
        r = ev.triage_accuracy([1,2,3],[1,2,3])
        self.assertEqual(r["accuracy"], 1.0)
        r2 = ev.triage_accuracy([1,1],[1,2])
        self.assertEqual(r2["accuracy"], 0.5)

    def test_held_out_no_overlap(self):
        corpus = list(range(10))
        s = ev.held_out_split(corpus, holdout_ratio=0.2, seed=1)
        self.assertEqual(s["train_size"]+s["held_out_size"], 10)
        self.assertTrue(s["clean_split"])

    def test_shuffled_control(self):
        labels = [0,0,0,0,1,1,1,1]
        c = ev.shuffled_label_control(labels, [0,0,0,0,1,1,1,1], seed=42)
        self.assertAlmostEqual(c["chance"], 0.5)
        self.assertFalse(c["leakage_detected"])

if __name__ == "__main__":
    unittest.main()
