#!/usr/bin/env python3
"""Verification suite for the pure-assembly triage kernel.

Expected values here are computed with independent integer arithmetic in
the TEST only; the engine under test is exclusively the assembled DLL.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0,
                str(Path(__file__).resolve().parent / "triage_kernel42"))

import triage_asm42 as tasm  # noqa: E402

DLL_PATH = str(Path(__file__).resolve().parent / "triage_kernel42"
               / "triage_kernel.dll")

WEIGHTS = [0.30, 0.20, 0.25, 0.15, 0.10]   # reach, no-auth, sev,
                                           # low-prereq, kev


def reference_score(weights_floats, features_floats):
    w = [int(round(v * 65536)) for v in weights_floats]
    f = [int(round(v * 65536)) for v in features_floats]
    acc = sum(a * b for a, b in zip(w, f))
    return acc >> 16


class TestAsmKernel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = tasm.load(DLL_PATH)

    def test_exports_bind(self):
        self.assertIsNotNone(self.dll.triage_score_q16)
        self.assertIsNotNone(self.dll.triage_grade)

    def test_matches_independent_reference(self):
        cases = [
            ([1.0] * 5, 1.0),
            ([0.0] * 5, None),
            (WEIGHTS, [1.0, 1.0, 1.0, 1.0, 0.0]),
            (WEIGHTS, [0.9, 0.8, 0.95, 0.7, 0.0]),
            (WEIGHTS, [0.2, 0.1, 0.15, 0.05, 0.0]),
            (WEIGHTS, [0.5, 0.5, 0.5, 0.5, 0.5]),
        ]
        for features, _ in cases:
            got = tasm.score(self.dll, WEIGHTS, features)["raw_q16"]
            want = reference_score(WEIGHTS, features)
            self.assertEqual(got, want, features)

    def test_empty_vector_scores_zero(self):
        result = tasm.score(self.dll, [], [])
        self.assertEqual(result["raw_q16"], 0)

    def test_grade_bands(self):
        bands = [
            (-100, 0),          # negative -> invalid
            (0, 0),             # zero -> invalid
            (1, 1),             # just above zero -> theoretical
            (19660, 1),         # just below 0.30
            (19661, 2),         # 0.30 boundary -> chained-only
            (32767, 2),
            (32768, 3),         # 0.50 boundary -> preconditions
            (45874, 3),
            (45875, 4),         # 0.70 boundary -> readily-exploitable
            (65535, 4),
        ]
        for score_q16, expected in bands:
            got = int(self.dll.triage_grade(score_q16, 0))
            self.assertEqual(got, expected,
                             "score %d -> grade %d, wanted %d"
                             % (score_q16, got, expected))

    def test_kev_escalation(self):
        self.assertEqual(int(self.dll.triage_grade(1, 1)), 3)      # 1 -> 3
        self.assertEqual(int(self.dll.triage_grade(20000, 1)), 3)  # 2 -> 3
        self.assertEqual(int(self.dll.triage_grade(40000, 1)), 3)  # stays 3
        self.assertEqual(int(self.dll.triage_grade(60000, 1)), 4)  # stays 4
        self.assertEqual(int(self.dll.triage_grade(0, 1)), 0)      # invalid

    def test_full_pipeline_labels(self):
        hot = tasm.score(self.dll, WEIGHTS,
                         [0.95, 1.0, 0.9, 0.85, 0.0])
        verdict = tasm.grade(self.dll, hot["score"], kev=False)
        self.assertIn(verdict["grade"], (3, 4))
        cold = tasm.score(self.dll, WEIGHTS,
                          [0.05, 0.02, 0.1, 0.01, 0.0])
        cold_verdict = tasm.grade(self.dll, cold["score"], kev=True)
        self.assertGreaterEqual(cold_verdict["grade"], 3)


if __name__ == "__main__":
    unittest.main()
