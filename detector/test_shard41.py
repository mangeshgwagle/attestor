#!/usr/bin/env python3
"""Tests for shard41.py -- distributed scanning that stays verifiable."""
import unittest

import shard41 as shard

PATHS = ["src/a.py", "src/b.py", "src/c.py", "lib/d.py", "lib/e.py",
         "lib/f.py", "test/g.py", "test/h.py", "docs/i.md", "docs/j.md"]


class PlanTests(unittest.TestCase):
    def test_every_path_lands_in_exactly_one_shard(self):
        report = shard.plan(PATHS, 4)
        assigned = [p for row in report["assignments"] for p in row["paths"]]
        self.assertEqual(sorted(assigned), sorted(PATHS))
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(shard.verify_plan(report)[0])

    def test_assignment_is_identical_across_runs_and_input_order(self):
        first = shard.plan(PATHS, 4)
        second = shard.plan(list(reversed(PATHS)), 4)
        self.assertEqual(first["plan_root_sha256"], second["plan_root_sha256"])
        self.assertEqual(first["input_sha256"], second["input_sha256"])

    def test_duplicate_paths_are_collapsed(self):
        report = shard.plan(PATHS + PATHS, 3)
        self.assertEqual(report["total_paths"], len(set(PATHS)))

    def test_changing_shard_count_changes_the_root(self):
        self.assertNotEqual(shard.plan(PATHS, 2)["plan_root_sha256"],
                            shard.plan(PATHS, 5)["plan_root_sha256"])

    def test_single_shard_holds_everything(self):
        report = shard.plan(PATHS, 1)
        self.assertEqual(report["assignments"][0]["count"], len(PATHS))

    def test_bounds_are_enforced(self):
        for bad in (0, -1, shard.MAX_SHARDS + 1, 2.5, True, "4"):
            with self.subTest(shards=bad):
                with self.assertRaises(shard.ShardError):
                    shard.plan(PATHS, bad)
        with self.assertRaises(shard.ShardError):
            shard.plan([], 2)
        with self.assertRaises(shard.ShardError):
            shard.plan(["ok.py", ""], 2)


class MerkleTests(unittest.TestCase):
    def test_root_changes_when_any_leaf_changes(self):
        leaves = ["a" * 64, "b" * 64, "c" * 64]
        base = shard.merkle_root(leaves)
        for index in range(len(leaves)):
            altered = list(leaves)
            altered[index] = "d" * 64
            self.assertNotEqual(shard.merkle_root(altered), base)

    def test_root_is_order_sensitive(self):
        leaves = ["a" * 64, "b" * 64, "c" * 64]
        self.assertNotEqual(shard.merkle_root(leaves),
                            shard.merkle_root(list(reversed(leaves))))

    def test_odd_leaf_is_promoted_not_duplicated(self):
        # Duplicating the final leaf is the classic malleability bug: it lets
        # [a,b,c] and [a,b,c,c] share a root.
        three = shard.merkle_root(["a" * 64, "b" * 64, "c" * 64])
        four = shard.merkle_root(["a" * 64, "b" * 64, "c" * 64, "c" * 64])
        self.assertNotEqual(three, four)


class CompositionTests(unittest.TestCase):
    def build(self, shards=4):
        report = shard.plan(PATHS, shards)
        results = [shard.shard_result(row["shard"], report,
                                      [{"rule": "r%d" % row["shard"]}])
                   for row in report["assignments"]]
        return report, results

    def test_complete_composition_verifies(self):
        report, results = self.build()
        composed = shard.compose(report, results)
        self.assertTrue(composed["complete"])
        self.assertEqual(composed["problems"], [])
        self.assertEqual(composed["shards_received"], composed["shards_expected"])
        self.assertTrue(shard.verify_composition(composed, report)[0])

    def test_a_missing_shard_is_refused_not_averaged(self):
        report, results = self.build()
        composed = shard.compose(report, results[:-1])
        self.assertFalse(composed["complete"])
        self.assertTrue(any("no result for shard" in p
                            for p in composed["problems"]))

    def test_a_duplicate_shard_is_caught(self):
        report, results = self.build()
        composed = shard.compose(report, results + [results[0]])
        self.assertTrue(any("duplicate" in p for p in composed["problems"]))

    def test_a_shard_that_scanned_the_wrong_paths_is_caught(self):
        report, results = self.build()
        results[1]["assignment_sha256"] = "0" * 64
        composed = shard.compose(report, results)
        self.assertTrue(any("different path set" in p
                            for p in composed["problems"]))

    def test_findings_from_every_shard_survive(self):
        report, results = self.build()
        composed = shard.compose(report, results)
        rules = {item["rule"] for item in composed["findings"]}
        self.assertEqual(rules, {"r0", "r1", "r2", "r3"})

    def test_altered_findings_change_the_result_root(self):
        report, results = self.build()
        first = shard.compose(report, results)["result_root_sha256"]
        results[0]["findings"] = [{"rule": "tampered"}]
        second = shard.compose(report, results)["result_root_sha256"]
        self.assertNotEqual(first, second)

    def test_composition_cannot_be_claimed_for_another_plan(self):
        report, results = self.build()
        composed = shard.compose(report, results)
        other = shard.plan(PATHS + ["extra.py"], 4)
        ok, errors = shard.verify_composition(composed, other)
        self.assertFalse(ok)
        self.assertTrue(any("does not belong" in e for e in errors))

    def test_a_tampered_composition_fails_its_digest(self):
        report, results = self.build()
        composed = shard.compose(report, results)
        composed["finding_count"] = 999
        self.assertFalse(shard.verify_composition(composed, report)[0])

    def test_an_unknown_plan_is_refused_outright(self):
        with self.assertRaises(shard.ShardError):
            shard.compose({"schema": "wrong"}, [])

    def test_result_for_a_shard_outside_the_plan_is_refused(self):
        report, _ = self.build(2)
        with self.assertRaises(shard.ShardError):
            shard.shard_result(9, report, [])


class BalanceTests(unittest.TestCase):
    """Wall time is the slowest shard, so cost balance is the real metric."""

    # One heavy file plus many small ones: the shape that defeats hashing.
    COSTS = dict([("big.py", 1000)] + [("s%02d.py" % i, 10) for i in range(40)])

    def test_balanced_beats_hash_on_makespan(self):
        paths = list(self.COSTS)
        balanced = shard.plan(paths, 8, costs=self.COSTS, strategy="balanced")
        hashed = shard.plan(paths, 8, costs=self.COSTS, strategy="hash")
        self.assertLess(balanced["imbalance"], hashed["imbalance"])
        self.assertLessEqual(balanced["makespan_cost"], hashed["makespan_cost"])

    def test_both_strategies_report_cost_not_file_count(self):
        # A hash plan must not flatter itself by reporting count balance.
        hashed = shard.plan(list(self.COSTS), 8, costs=self.COSTS,
                            strategy="hash")
        self.assertEqual(hashed["total_cost"], sum(self.COSTS.values()))
        self.assertGreater(hashed["makespan_cost"], 0)

    def test_balancing_is_deterministic_regardless_of_input_order(self):
        paths = list(self.COSTS)
        first = shard.plan(paths, 6, costs=self.COSTS)
        second = shard.plan(list(reversed(paths)), 6, costs=self.COSTS)
        self.assertEqual(first["plan_root_sha256"], second["plan_root_sha256"])

    def test_balanced_plans_still_verify(self):
        report = shard.plan(list(self.COSTS), 5, costs=self.COSTS)
        self.assertTrue(shard.verify_plan(report)[0])

    def test_granularity_floor_is_reported(self):
        # 41 files, one of which is 1000 units: past a point, more shards
        # cannot help, and the plan must say so rather than look balanced.
        report = shard.plan(list(self.COSTS), 32, costs=self.COSTS)
        self.assertGreater(report["imbalance_floor"], 1.0)
        self.assertTrue(report["granularity_limited"])
        self.assertIn("granularity floor", shard.render(report))

    def test_uniform_costs_balance_perfectly(self):
        costs = {"f%02d.py" % i: 10 for i in range(40)}
        report = shard.plan(list(costs), 4, costs=costs)
        self.assertLessEqual(report["imbalance"], 1.01)
        self.assertFalse(report["granularity_limited"])

    def test_bad_costs_are_refused(self):
        for bad in ({"a.py": -1}, {"a.py": 1.5}, {"a.py": "10"}):
            with self.subTest(costs=bad):
                with self.assertRaises(shard.ShardError):
                    shard.plan(["a.py", "b.py"], 2, costs=bad)

    def test_unknown_strategy_is_refused(self):
        with self.assertRaises(shard.ShardError):
            shard.plan(PATHS, 2, strategy="round-robin")


class ExecutionTests(unittest.TestCase):
    COSTS = {p: 10 for p in PATHS}

    def test_run_local_then_compose_is_complete(self):
        report = shard.plan(PATHS, 4, costs=self.COSTS)
        results = shard.run_local(report, lambda path: [{"path": path}])
        composed = shard.compose(report, results)
        self.assertTrue(composed["complete"])
        self.assertEqual(composed["finding_count"], len(PATHS))
        self.assertTrue(shard.verify_composition(composed, report)[0])

    def test_a_failing_path_is_recorded_not_dropped(self):
        report = shard.plan(PATHS, 2, costs=self.COSTS)

        def scan(path):
            if path.endswith("c.py"):
                raise OSError("unreadable")
            return [{"path": path}]

        results = shard.run_local(report, scan)
        failed = sum(item["paths_failed"] for item in results)
        scanned = sum(item["paths_scanned"] for item in results)
        self.assertEqual(failed, 1)
        self.assertEqual(scanned + failed, len(PATHS))
        self.assertTrue(any(item["failures"] for item in results))

    def test_running_a_shard_outside_the_plan_is_refused(self):
        report = shard.plan(PATHS, 2, costs=self.COSTS)
        with self.assertRaises(shard.ShardError):
            shard.run_shard(7, report, lambda path: [])


class HonestyTests(unittest.TestCase):
    def test_plan_states_it_adds_no_detection(self):
        report = shard.plan(PATHS, 3)
        self.assertTrue(any("detects nothing new" in line
                            for line in report["limitations"]))

    def test_incomplete_composition_says_partial_coverage(self):
        report = shard.plan(PATHS, 3)
        composed = shard.compose(report, [])
        self.assertTrue(any("not a clean result" in line
                            for line in composed["limitations"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
