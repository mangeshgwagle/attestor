"""Endurance and accuracy, which are the same system.

Endurance is surviving a long unattended run. Accuracy is the claims still
being true at the end of it. A process that runs for a month and reports
stale numbers is worse than one that dies honestly, so both are tested
here and neither is allowed to pass alone.
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

import attestor_endure as oe


def probe(name, values):
    """A probe that returns each value in turn, so drift can be staged."""
    supply = iter(values)
    return oe.Probe(name, lambda: next(supply))


class ItRecordsThenCompares(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_first_cycle_records_a_baseline(self):
        ledger = oe.Ledger.load(self.path)
        report = oe.run_cycle([probe("a", [1]), probe("b", ["x"])], ledger)
        self.assertEqual(len(report["new"]), 2)
        self.assertEqual(ledger.baseline, {"a": 1, "b": "x"})

    def test_an_unchanged_cycle_reports_nothing(self):
        ledger = oe.Ledger.load(self.path)
        oe.run_cycle([probe("a", [1])], ledger)
        report = oe.run_cycle([probe("a", [1])], ledger)
        self.assertEqual(report["new"], [])
        self.assertEqual(report["drift"], [])

    def test_a_changed_value_is_reported_as_drift(self):
        ledger = oe.Ledger.load(self.path)
        moving = probe("a", [1, 2])
        oe.run_cycle([moving], ledger)
        report = oe.run_cycle([moving], ledger)
        self.assertEqual(len(report["drift"]), 1)
        _, was, now = report["drift"][0]
        self.assertEqual((was, now), (1, 2))

    def test_an_improvement_is_drift_too(self):
        """An unexplained improvement is as much a reason to look.

        CWE-89 went from 93.3% to 100% this week and it took a deliberate
        check to find out why. A monitor that only reports regressions would
        have said nothing.
        """
        ledger = oe.Ledger.load(self.path)
        better = probe("rate", ["93.3%", "100%"])
        oe.run_cycle([better], ledger)
        report = oe.run_cycle([better], ledger)
        self.assertEqual(len(report["drift"]), 1)

    def test_drift_does_not_overwrite_the_baseline(self):
        """Otherwise a slow slide is invisible: each cycle would only ever
        be compared against the last one."""
        ledger = oe.Ledger.load(self.path)
        sliding = probe("a", [100, 90, 80])
        for _ in range(3):
            oe.run_cycle([sliding], ledger)
        self.assertEqual(ledger.baseline["a"], 100)
        self.assertEqual(len(ledger.drifts), 2)

    def test_the_baseline_says_when_the_drift_happened(self):
        ledger = oe.Ledger.load(self.path)
        moving = probe("a", [1, 2])
        oe.run_cycle([moving], ledger)
        oe.run_cycle([moving], ledger)
        entry = ledger.drifts[-1]
        self.assertEqual(entry["cycle"], 2)
        self.assertEqual((entry["was"], entry["now"]), (1, 2))


class ItSurvivesBeingKilled(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "ledger.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_restart_resumes_the_same_run(self):
        """Not a fresh baseline, which would erase the drift it exists for."""
        first = oe.Ledger.load(self.path)
        oe.run_cycle([probe("a", [1])], first)
        resumed = oe.Ledger.load(self.path)
        self.assertEqual(resumed.baseline, {"a": 1})
        self.assertEqual(resumed.cycles, 1)
        report = oe.run_cycle([probe("a", [2])], resumed)
        self.assertEqual(len(report["drift"]), 1)

    def test_the_cycle_count_and_start_time_survive(self):
        ledger = oe.Ledger.load(self.path)
        for _ in range(3):
            oe.run_cycle([probe("a", [1])], ledger)
        started = ledger.started
        resumed = oe.Ledger.load(self.path)
        self.assertEqual(resumed.cycles, 3)
        self.assertAlmostEqual(resumed.started, started, places=3)

    def test_a_probe_that_raises_is_recorded_not_fatal(self):
        """The run has to still be going tomorrow."""
        def explode():
            raise RuntimeError("disk gone")
        ledger = oe.Ledger.load(self.path)
        report = oe.run_cycle(
            [oe.Probe("bad", explode), probe("good", [1])], ledger)
        self.assertEqual(len(report["broken"]), 1)
        self.assertIn("disk gone", report["broken"][0].error)
        self.assertEqual(ledger.baseline, {"good": 1})
        self.assertEqual(ledger.failures, 1)

    def test_a_failing_probe_does_not_poison_the_baseline(self):
        """It must not record `None` and then call the recovery drift."""
        calls = [0]

        def flaky():
            calls[0] += 1
            if calls[0] == 1:
                raise RuntimeError("transient")
            return 42
        ledger = oe.Ledger.load(self.path)
        oe.run_cycle([oe.Probe("f", flaky)], ledger)
        self.assertNotIn("f", ledger.baseline)
        report = oe.run_cycle([oe.Probe("f", flaky)], ledger)
        self.assertEqual(ledger.baseline["f"], 42)
        self.assertEqual(report["drift"], [])

    def test_the_ledger_is_written_atomically(self):
        """A kill mid-write must not leave an unreadable ledger."""
        ledger = oe.Ledger.load(self.path)
        oe.run_cycle([probe("a", [1])], ledger)
        self.assertTrue(self.path.is_file())
        self.assertFalse(self.path.with_suffix(".tmp").exists())
        body = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(body["schema"], oe.SCHEMA)

    def test_a_corrupt_ledger_is_refused_rather_than_replaced(self):
        """Treating it as empty would silently rebaseline a run in progress."""
        self.path.write_text("{ not json", encoding="utf-8")
        with self.assertRaises(RuntimeError) as caught:
            oe.Ledger.load(self.path)
        self.assertIn("readable ledger", str(caught.exception))

    def test_a_foreign_schema_is_refused(self):
        self.path.write_text(json.dumps({"schema": "something/else"}),
                             encoding="utf-8")
        with self.assertRaises(RuntimeError):
            oe.Ledger.load(self.path)

    def test_the_drift_log_is_bounded(self):
        """It runs for weeks; an unbounded log is a disk-full outage."""
        ledger = oe.Ledger.load(self.path)
        ledger.baseline["a"] = 0
        for cycle in range(1, 260):
            ledger.drifts.append({"cycle": cycle, "probe": "a"})
        ledger.save()
        self.assertLessEqual(
            len(json.loads(self.path.read_text(encoding="utf-8"))["drifts"]),
            200)


class TheRealProbes(unittest.TestCase):
    def test_every_probe_returns_something_comparable(self):
        import probes as attestor_probes
        for one in attestor_probes.PROBES:
            with self.subTest(probe=one.name):
                result = one.run()
                self.assertTrue(result.ok, result.error)
                self.assertIsNotNone(result.value)
                json.dumps(result.value)     # must survive the ledger

    def test_a_probe_gives_the_same_answer_twice(self):
        """A probe that is not deterministic reports drift forever."""
        import probes as attestor_probes
        for one in attestor_probes.PROBES:
            with self.subTest(probe=one.name):
                self.assertEqual(one.run().value, one.run().value)

    def test_every_probe_explains_why_it_matters(self):
        import probes as attestor_probes
        for one in attestor_probes.PROBES:
            self.assertTrue(one.detail, "%s has no detail" % one.name)


if __name__ == "__main__":
    unittest.main()
