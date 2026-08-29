#!/usr/bin/env python3
"""Tests for versus.py -- the model-alone vs model+Attestor head-to-head. Offline."""
import unittest

import brain
import versus

CRASHES = "total = 1 / 0\n"                       # static-clean, crashes on run
CLEAN = "def safe_div(a, b):\n    return a / b if b else 0\n"
BUGGY = "def f(x):\n    return missing\n"          # undefined-name (static)


class Scripted:
    def __init__(self, answers):
        self._answers = list(answers)

    def available(self):
        return True

    def generate(self, _prompt):
        return self._answers.pop(0) if self._answers else CLEAN


class Exploding:
    def available(self):
        return True

    def generate(self, _prompt):
        raise brain.ProviderError("429 quota")


class VersusTests(unittest.TestCase):
    def test_attestor_turns_a_crashing_draft_into_running_code(self):
        v = versus.versus("safe division", Scripted([CRASHES, CRASHES, CLEAN]))
        self.assertFalse(v["raw"]["runs"])       # the model's raw output crashed
        self.assertTrue(v["attestor"]["runs"])         # after Attestor, it runs
        self.assertIn("running code", versus.render(v))

    def test_attestor_removes_static_findings(self):
        v = versus.versus("x", Scripted([BUGGY, BUGGY, CLEAN]))
        self.assertGreater(v["raw"]["findings"], 0)
        self.assertEqual(v["attestor"]["findings"], 0)

    def test_already_clean_raw_gets_an_honest_no_op_verdict(self):
        v = versus.versus("x", Scripted([CLEAN]))
        text = versus.render(v)
        self.assertIn("already clean", text)

    def test_provider_failure_is_handled(self):
        v = versus.versus("x", Exploding())
        self.assertIn("error", v["raw"])
        self.assertIn("both attempts failed", versus.render(v))

    def test_render_labels_both_columns(self):
        text = versus.render(versus.versus("x", Scripted([BUGGY, CLEAN])))
        self.assertIn("model alone", text)
        self.assertIn("model + Attestor", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
