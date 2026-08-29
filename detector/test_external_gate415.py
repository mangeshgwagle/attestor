#!/usr/bin/env python3
"""Regression tests for the external model-patch boundary."""
import unittest

import external_gate


ORIGINAL = """def first(user):
    return eval(user)

def second(user):
    return eval(user)
"""


class ExternalGate415Tests(unittest.TestCase):
    def review(self, candidate):
        return external_gate.review(
            "sample.py", ORIGINAL, candidate,
            [{"rule": "dangerous-eval", "line": 2}], fuzz_cases=1)

    def test_destructive_pass_rewrite_is_refused(self):
        with self.assertRaisesRegex(external_gate.GateError,
                                    "destructive rewrite"):
            self.review("pass\n")

    def test_fixing_a_different_duplicate_is_not_resolution(self):
        candidate = """def first(user):
    return eval(user)

def second(user):
    return user
"""
        result = self.review(candidate)
        self.assertFalse(result.accepted)
        self.assertIn("dangerous-eval", " ".join(result.reasons))
        self.assertEqual(result.resolved, ())

    def test_removing_public_callable_is_refused(self):
        candidate = """def first(user):
    return user
"""
        with self.assertRaisesRegex(external_gate.GateError,
                                    "destructive rewrite"):
            self.review(candidate)

    def test_bounded_fix_of_every_targeted_occurrence_is_accepted(self):
        candidate = """def first(user):
    return user

def second(user):
    return user
"""
        result = self.review(candidate)
        self.assertTrue(result.accepted, result.reasons)
        self.assertEqual(result.resolved, ("dangerous-eval",))


if __name__ == "__main__":
    unittest.main(verbosity=2)
