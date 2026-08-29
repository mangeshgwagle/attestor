#!/usr/bin/env python3
"""Auto-escalating synthesis: the working power reached without tuning.

The synthesizer could already write map/filter/fold programs, but only for a
caller who knew to pass `loops=True` and the right depth. `auto` climbs a ladder
of cheap-first tiers so a plain call from examples finds those programs, and a
node budget makes a hopeless search fail in about a second instead of grinding
for a minute.

Two properties matter and both are asserted: the program `auto` returns must
actually reproduce the examples it was given (a synthesizer that returned a
plausible-looking wrong function would be worse than one that returned nothing),
and the budget must terminate a search that the unbounded version would hang on.
"""
from __future__ import annotations

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import attestor_synth as s  # noqa: E402


def run(source: str, name: str, value):
    namespace: dict = {}
    exec(source, namespace)          # noqa: S102 - the source is ours, just synthesized
    return namespace[name](value)


class AutoReachesTheWorkingCases(unittest.TestCase):
    NUMERIC = [
        ("square_then_double", s.INT_OPS,
         [(1, 2), (2, 8), (3, 18), (5, 50)]),
        ("sum_of_squares", s.LIST_OPS,
         [([1, 2, 3], 14), ([2, 4], 20), ([5], 25)]),
        ("keep_positives", s.LIST_OPS,
         [([1, -2, 3, -4], [1, 3]), ([-1], []), ([5], [5])]),
        ("double_each", s.LIST_OPS,
         [([1, 2, 3], [2, 4, 6]), ([5], [10]), ([0, -1], [0, -2])]),
        ("count_evens", s.LIST_OPS,
         [([1, 2, 3, 4], 2), ([2, 4, 6], 3), ([1, 3], 0)]),
        ("second_largest", s.LIST_OPS,
         [([3, 1, 4, 1, 5], 4), ([9, 2, 7], 7), ([1, 8], 1)]),
    ]

    def test_each_case_is_solved_without_tuning(self):
        for name, ops, examples in self.NUMERIC:
            with self.subTest(task=name):
                program, tier = s.auto(examples, ops=ops)
                self.assertIsNotNone(program, "auto found no program for %s" % name)
                self.assertIsNotNone(tier)

    def test_the_returned_program_reproduces_its_examples(self):
        """A wrong program that merely looks right is the worst outcome."""
        for name, ops, examples in self.NUMERIC:
            program, _tier = s.auto(examples, ops=ops)
            source = s.render(program, name="f")
            with self.subTest(task=name):
                for value, expected in examples:
                    self.assertEqual(expected, run(source, "f", value),
                                     "%s: f(%r) wrong" % (name, value))

    def test_a_synthesized_function_generalises_to_held_out_input(self):
        """Not proof of correctness, but evidence it is not curve-fitting."""
        program, _ = s.auto([([1, 2, 3], 14), ([2, 4], 20), ([5], 25)],
                            ops=s.LIST_OPS)
        source = s.render(program, name="f")
        self.assertEqual(30, run(source, "f", [1, 2, 3, 4]))
        self.assertEqual(100, run(source, "f", [10]))


class CheapestTierWins(unittest.TestCase):
    def test_a_flat_problem_is_solved_on_the_first_rung(self):
        _program, tier = s.auto([(1, 2), (2, 8), (3, 18)], ops=s.INT_OPS)
        self.assertFalse(tier["loops"], "a flat program should not need loops")
        self.assertLessEqual(tier["max_size"], 4)

    def test_a_flat_problem_returns_quickly(self):
        started = time.time()
        s.auto([(1, 2), (2, 8), (3, 18)], ops=s.INT_OPS)
        self.assertLess(time.time() - started, 1.0)


class BudgetTerminates(unittest.TestCase):
    def test_an_out_of_reach_spec_fails_in_bounded_time(self):
        """Unbounded, this string task runs for the better part of a minute."""
        started = time.time()
        program, tier = s.auto([("alan turing", "AT"), ("grace hopper", "GH")],
                               ops=s.STR_OPS)
        elapsed = time.time() - started
        self.assertIsNone(program)
        self.assertIsNone(tier)
        self.assertLess(elapsed, 20.0, "the budget should cap the search")

    def test_the_budget_is_a_real_limit_not_a_timeout(self):
        """A tiny budget makes even a solvable task return None deterministically."""
        found = s.synthesize([([1, 2, 3], 14), ([2, 4], 20)], ops=s.LIST_OPS,
                             loops=True, max_size=5, node_budget=50)
        self.assertIsNone(found)
        # The same search with room succeeds, so the budget was the cause.
        solved = s.synthesize([([1, 2, 3], 14), ([2, 4], 20)], ops=s.LIST_OPS,
                             loops=True, max_size=5, node_budget=0)
        self.assertIsNotNone(solved)


class UnboundedBehaviourIsUnchanged(unittest.TestCase):
    def test_node_budget_zero_matches_the_old_default(self):
        """Existing callers pass no budget and must see identical results."""
        a = s.synthesize([(1, 1), (2, 4), (3, 9)], ops=s.INT_OPS)
        b = s.synthesize([(1, 1), (2, 4), (3, 9)], ops=s.INT_OPS, node_budget=0)
        self.assertEqual(s.render(a) if a else None, s.render(b) if b else None)


class WriteAutoIsVetted(unittest.TestCase):
    def test_the_returned_source_passed_attestor(self):
        source, tier = s.write_auto([([1, 2, 3], 14), ([2, 4], 20)],
                                    ops=s.LIST_OPS, name="sq")
        self.assertIsNotNone(source)
        self.assertIsNotNone(tier)
        self.assertIn("def sq(", source)
        self.assertEqual(30, run(source, "sq", [1, 2, 3, 4]))


if __name__ == "__main__":
    unittest.main()
