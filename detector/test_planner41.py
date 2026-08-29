#!/usr/bin/env python3
"""Tests for planner41.py.

The interesting cases are the ones where a step goes wrong. A planner that
only behaves when every fix works is not a planner, it is a for-loop -- what
makes it safe to give Attestor the ability to act is that every failure path is
pinned here.
"""
import unittest

import planner41 as planner

FINDINGS = [
    {"path": "b.py", "rule": "py-eq-none", "line": 12},
    {"path": "a.py", "rule": "weak-hash", "line": 3},
    {"path": "a.py", "rule": "py-yaml-load", "line": 30},
]


def accepted(_root, path, findings):
    return {"accepted": True, "path": path, "findings": list(findings)}


def refused(_root, _path, _findings):
    return {"accepted": False, "reason": "no candidate passed its tests"}


class PlanTests(unittest.TestCase):
    def test_a_plan_is_deterministic_regardless_of_input_order(self):
        first = planner.plan("/proj", FINDINGS)
        second = planner.plan("/proj", list(reversed(FINDINGS)))
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertTrue(planner.verify_plan(first)[0])

    def test_steps_are_ordered_by_path_then_line(self):
        steps = planner.plan("/proj", FINDINGS)["steps"]
        self.assertEqual([(s["path"], s["line"]) for s in steps],
                         [("a.py", 3), ("a.py", 30), ("b.py", 12)])

    def test_a_hint_permutes_the_order_but_never_the_set(self):
        hint = [{"rule": "py-eq-none", "line": 12}]
        hinted = planner.plan("/proj", FINDINGS, order_hint=hint)
        self.assertEqual(hinted["steps"][0]["rule"], "py-eq-none")
        self.assertEqual({(s["path"], s["rule"]) for s in hinted["steps"]},
                         {(f["path"], f["rule"]) for f in FINDINGS})
        self.assertIn("gate ranking", hinted["ordered_by"])

    def test_the_step_budget_truncates_and_says_so(self):
        report = planner.plan("/proj", FINDINGS, max_steps=2)
        self.assertEqual(report["planned_steps"], 2)
        self.assertTrue(report["truncated"])

    def test_bad_inputs_are_refused(self):
        with self.assertRaises(planner.PlannerError):
            planner.plan("", FINDINGS)
        for bad in (0, -1, planner.0 + 1, "4", 2.5, True):
            with self.subTest(max_steps=bad):
                with self.assertRaises(planner.PlannerError):
                    planner.plan("/proj", FINDINGS, max_steps=bad)
        with self.assertRaises(planner.PlannerError):
            planner.plan("/proj", [{"rule": "r", "line": 1}])   # no path

    def test_a_tampered_plan_does_not_verify(self):
        report = planner.plan("/proj", FINDINGS)
        report["steps"][0]["path"] = "elsewhere.py"
        self.assertFalse(planner.verify_plan(report)[0])


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.report = planner.plan("/proj", FINDINGS)
        self.applied = []
        self.rolled = []

    def apply_fix(self, verification):
        self.applied.append(verification)
        return {"applied": True}

    def clean_rescan(self, _path):
        return []

    def unchanged_rescan(self, _path):
        return [{"rule": f["rule"]} for f in FINDINGS]

    def go(self, **kwargs):
        options = dict(verify=accepted, apply_fix=self.apply_fix,
                       rescan=self.clean_rescan,
                       rollback=self.rolled.append, authorized=True)
        options.update(kwargs)
        return planner.execute(self.report, **options)

    def test_a_dry_run_writes_nothing(self):
        result = self.go(authorized=False)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["skipped"], len(FINDINGS))
        self.assertEqual(self.applied, [])
        self.assertTrue(planner.verify_result(result, self.report)[0])

    def test_an_authorised_run_applies_verified_fixes(self):
        result = self.go()
        self.assertEqual(result["applied"], len(FINDINGS))
        self.assertEqual(len(self.applied), len(FINDINGS))

    def test_an_unverified_fix_is_never_applied(self):
        result = self.go(verify=refused)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["rejected"], len(FINDINGS))
        self.assertEqual(self.applied, [])

    def test_a_fix_that_leaves_the_finding_behind_is_rolled_back(self):
        # Passing tests is not the same as having worked.
        result = self.go(rescan=self.unchanged_rescan)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["rolled_back"], len(FINDINGS))
        self.assertEqual(len(self.rolled), len(FINDINGS))

    def test_a_raising_verifier_is_recorded_not_propagated(self):
        def explode(*_args):
            raise RuntimeError("verifier died")
        result = self.go(verify=explode)
        self.assertEqual(result["failed"], len(FINDINGS))
        self.assertEqual(result["applied"], 0)

    def test_a_raising_apply_is_recorded_not_propagated(self):
        def explode(_verification):
            raise OSError("disk full")
        result = self.go(apply_fix=explode)
        self.assertEqual(result["failed"], len(FINDINGS))

    def test_a_raising_rescan_is_unknown_and_rolls_back(self):
        def explode(_path):
            raise RuntimeError("scanner unavailable")
        result = self.go(rescan=explode)
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["rolled_back"], len(FINDINGS))
        self.assertEqual(len(self.rolled), len(FINDINGS))
        self.assertTrue(all("re-scan failed" in row["detail"]
                            for row in result["outcomes"]))

    def test_a_raising_rollback_still_records_the_rollback(self):
        def explode(_result):
            raise RuntimeError("rollback died")
        result = self.go(rescan=self.unchanged_rescan, rollback=explode)
        self.assertEqual(result["rolled_back"], len(FINDINGS))
        self.assertTrue(any("rollback raised" in row["detail"]
                            for row in result["outcomes"]))

    def test_an_unverifiable_plan_is_refused_outright(self):
        broken = dict(self.report)
        broken["plan_sha256"] = "0" * 64
        with self.assertRaises(planner.PlannerError):
            planner.execute(broken, verify=accepted, apply_fix=self.apply_fix,
                            rescan=self.clean_rescan)

    def test_the_wall_clock_budget_stops_later_steps(self):
        # The budget is checked between steps, so the first one always runs;
        # what it bounds is how many more are started after time is up.
        import time as _time

        def slow(root, path, findings):
            _time.sleep(0.05)
            return accepted(root, path, findings)

        result = self.go(verify=slow, max_wall_seconds=0.04)
        self.assertGreaterEqual(result["skipped"], 1)
        self.assertTrue(any("wall-clock" in row.get("detail", "")
                            for row in result["outcomes"]))

    def test_bad_budgets_are_refused(self):
        for bad in (0, -1, planner.MAX_WALL_SECONDS + 1):
            with self.subTest(budget=bad):
                with self.assertRaises(planner.PlannerError):
                    self.go(max_wall_seconds=bad)


class ResultIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.report = planner.plan("/proj", FINDINGS)

    def result(self, **kwargs):
        options = dict(verify=accepted, apply_fix=lambda v: {"ok": True},
                       rescan=lambda p: [], authorized=True)
        options.update(kwargs)
        return planner.execute(self.report, **options)

    def test_a_clean_result_verifies(self):
        self.assertTrue(planner.verify_result(self.result(), self.report)[0])

    def test_a_tampered_result_is_caught(self):
        result = self.result()
        result["applied"] = 999
        self.assertFalse(planner.verify_result(result, self.report)[0])

    def test_a_result_cannot_be_claimed_for_another_plan(self):
        other = planner.plan("/other", FINDINGS)
        ok, problems = planner.verify_result(self.result(), other)
        self.assertFalse(ok)
        self.assertTrue(any("does not belong" in p for p in problems))

    def test_an_unauthorised_run_claiming_applied_changes_is_caught(self):
        result = self.result(authorized=False)
        result["applied"] = 3
        result["result_sha256"] = planner._sha(
            {k: v for k, v in result.items() if k != "result_sha256"})
        ok, problems = planner.verify_result(result, self.report)
        self.assertFalse(ok)
        self.assertTrue(any("unauthorised" in p for p in problems))


class RenderTests(unittest.TestCase):
    def test_a_dry_run_is_labelled_as_one(self):
        report = planner.plan("/proj", FINDINGS)
        result = planner.execute(report, verify=accepted,
                                 apply_fix=lambda v: {}, rescan=lambda p: [])
        self.assertIn("[dry run]", planner.render(report, result))

    def test_the_plan_lists_every_step(self):
        report = planner.plan("/proj", FINDINGS)
        text = planner.render(report)
        for finding in FINDINGS:
            self.assertIn(finding["rule"], text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
