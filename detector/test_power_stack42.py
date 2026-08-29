#!/usr/bin/env python3
"""Tests for coverage_fuzz42, concolic42, and crashforge42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import coverage_fuzz42 as cf  # noqa: E402
import concolic42 as cc  # noqa: E402
import crashforge42 as crf  # noqa: E402


class TestCoverageFuzzer(unittest.TestCase):
    def test_reaches_deep_planted_bug(self):
        def stepped(data):
            if len(data) < 4:
                return 0
            if data[0:1] != b"A":
                return 1
            if data[1:2] != b"T":
                return 2
            if data[2:3] != b"T":
                return 3
            if data[3:4] != b"A":
                return 4
            raise RuntimeError("deep")

        report = cf.fuzz(stepped, seeds=[b"B"], iterations=4000,
                         seconds=20.0, seed_rng=7)
        self.assertGreaterEqual(report["crashes_found"], 1)
        self.assertGreaterEqual(report["lines_discovered_total"], 6)

    def test_deterministic_runs(self):
        import json

        def target(data):
            if data[:2] == b"ZZ":
                raise ValueError("x")
            return 1

        first = json.dumps(cf.fuzz(target, seeds=[b"Q"], iterations=300,
                                   seconds=15.0, seed_rng=5),
                           sort_keys=True)
        second = json.dumps(cf.fuzz(target, seeds=[b"Q"], iterations=300,
                                    seconds=15.0, seed_rng=5),
                            sort_keys=True)
        self.assertEqual(first, second)


class TestConcolic(unittest.TestCase):
    def test_constraint_extraction_forms(self):
        def sample(data):
            if len(data) < 6:
                return "a"
            if data[0] != 67:
                return "b"
            if not data.startswith(b"C"):
                return "c"
            return "d"

        constraints = cc.extract_constraints(sample)
        forms = {c["form"] for c in constraints}
        self.assertEqual(forms, {"len_lt", "neq_byte", "startswith"})

    def test_solves_satisfying_input_and_finds_crash(self):
        def guarded(data):
            if len(data) < 6:
                return "too-short"
            if data[0] != 67:
                return "wrong-first"
            if data[5] != 70:
                return "wrong-sixth"
            raise RuntimeError("deep-planted-bug")

        report = cc.explore(guarded)
        crashing = [c for c in report["crashes"]
                    if "deep-planted-bug" in c["exception"]]
        self.assertTrue(crashing)
        solved = bytes.fromhex(crashing[0]["input_hex"])
        self.assertEqual(len(solved), 6)
        self.assertEqual(solved[0], 67)
        self.assertEqual(solved[5], 70)

    def test_alternate_paths_enumerated(self):
        def branchy(data):
            if len(data) < 4:
                return "short"
            if data[0] != 65:
                return "not-A"
            return "ok"

        report = cc.explore(branchy)
        self.assertGreaterEqual(report["paths_explored"], 3)

    def test_clean_target_no_crashes(self):
        def clean(data):
            return len(data)

        report = cc.explore(clean)
        self.assertEqual(report["crashes_found"], 0)


class TestCrashForge(unittest.TestCase):
    def test_end_to_end_pipeline(self):
        def parser_with_oob(data):
            if len(data) < 6:
                return None
            if data[0:3] != b"PWN":
                return None
            if data[5:6] != b"\x00":
                return None
            table = [1, 2]
            return table[data[4]]

        report = crf.run_pipeline(parser_with_oob, seeds=[b"PWN\x00\x00"],
                                  iterations=3000, seconds=20.0,
                                  seed_rng=3)
        self.assertGreaterEqual(report["crashes_processed"], 1)
        top = report["crashes"][0]
        self.assertEqual(top["classification"], "out-of-bounds-index")
        self.assertIn(top["engine"],
                      ("x86-64 assembly", "python-mirror"))
        self.assertLessEqual(top["minimized_len"], 16)
        self.assertTrue(bytes.fromhex(top["minimized_hex"])
                        .startswith(b"PWN"))
        self.assertEqual(len(report["report_sha256"]), 64)

    def test_clean_target_quiet(self):
        def clean(data):
            return sum(data) % 251

        report = crf.run_pipeline(clean, iterations=400, seconds=8.0,
                                  seed_rng=1)
        self.assertEqual(report["crashes_processed"], 0)

    def test_taxonomy_covers_common_exceptions(self):
        for name in ("IndexError", "TypeError", "struct.error",
                     "RuntimeError"):
            self.assertIn(name, crf.CRASH_TAXONOMY)


class TestSelfTests(unittest.TestCase):
    def test_all_module_selftests_pass(self):
        for result in (cf.run_selftest(), cc.run_selftest(),
                       crf.run_selftest()):
            self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
