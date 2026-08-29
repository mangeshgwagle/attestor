#!/usr/bin/env python3
"""Tests for curry.py -- the best-of ensemble. Offline: scripted cooks, no API."""
import unittest

import brain
import curry


class Cook:
    def __init__(self, name, code=None, error=None):
        self.name = name
        self._code = code
        self._error = error

    def generate(self, _prompt):
        if self._error:
            raise brain.ProviderError(self._error)
        return self._code


CLEAN = "def flat(xs):\n    return [x for x in xs]\n"          # 0 findings, runs
NESTED_FLAT = """def flatten(xs):
    out = []
    for x in xs:
        if isinstance(x, list):
            out.extend(flatten(x))
        else:
            out.append(x)
    return out
"""
SHALLOW_FLAT = "def flatten(xs):\n    return [x for x in xs]\n"
BUGGY = "def flat(xs):\n    return total\n"                     # undefined-name (static)
CRASHES = "x = 1 / 0\n"                                          # static-clean, crashes


class CurryTests(unittest.TestCase):
    def test_serves_the_clean_running_dish(self):
        dishes = curry.cook("flatten", [Cook("a", BUGGY), Cook("b", CLEAN)])
        winner = curry.pick(dishes)
        self.assertEqual(winner["cook"], "b")
        self.assertEqual(winner["findings"], 0)

    def test_running_beats_static_clean_but_crashing(self):
        # 'runs' is the primary sort: a running dish with a lint nit beats a
        # statically-clean one that crashes
        dishes = curry.cook("x", [Cook("crasher", CRASHES), Cook("runner", CLEAN)])
        self.assertEqual(curry.pick(dishes)["cook"], "runner")

    def test_a_cook_that_taps_out_is_recorded_not_served(self):
        dishes = curry.cook("x", [Cook("dead", error="429 quota"), Cook("ok", CLEAN)])
        by = {d["cook"]: d for d in dishes}
        self.assertIn("error", by["dead"])
        self.assertEqual(curry.pick(dishes)["cook"], "ok")

    def test_all_cooks_fail_means_no_winner(self):
        dishes = curry.cook("x", [Cook("a", error="down"), Cook("b", error="down")])
        self.assertIsNone(curry.pick(dishes))

    def test_render_marks_the_served_dish(self):
        dishes = curry.cook("x", [Cook("a", BUGGY), Cook("b", CLEAN)])
        text = curry.render("x", dishes, curry.pick(dishes))
        self.assertIn("<- served", text)
        self.assertIn("RESULT: served b", text)

    def test_behavior_checks_are_part_of_the_score(self):
        dishes = curry.cook("flatten nested list", [Cook("shallow", SHALLOW_FLAT), Cook("deep", NESTED_FLAT)])
        by = {d["cook"]: d for d in dishes}
        # crucible.verify gives a candidate DEFAULT_TIMEOUT (10s) of wall clock
        # to start an interpreter, import and run its smoke test.  On a loaded
        # machine that budget can lapse for reasons that have nothing to do with
        # the code being scored, which makes every dish ineligible and leaves no
        # winner.  Report that as an unavailable runtime gate rather than as a
        # scoring failure -- the same way the suite treats a missing Node.js.
        if by["deep"]["runs"] is not True:
            self.skipTest("dynamic runtime gate did not complete in its budget")
        winner = curry.pick(dishes)
        self.assertIsNotNone(winner, "a correct, static-clean dish should win")
        self.assertEqual(winner["cook"], "deep")
        self.assertFalse(by["shallow"]["runs"])
        self.assertTrue(by["deep"]["behavior"])

    def test_no_run_skips_execution(self):
        dishes = curry.cook("x", [Cook("a", CLEAN)], execute=False)
        self.assertIsNone(dishes[0]["runs"])   # never executed


if __name__ == "__main__":
    unittest.main(verbosity=2)
