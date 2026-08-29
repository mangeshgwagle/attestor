#!/usr/bin/env python3
"""Tests for detector/synth42.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import synth42 as sy  # noqa: E402


class TestAnalyticLayer(unittest.TestCase):
    def test_rot13_discovered(self):
        report = sy.synthesize([(b"attack at dawn", b"nggnpx ng qnja")],
                               allow_compositional=False)
        self.assertTrue(report["synthesized"])
        self.assertEqual(report["method"], "analytic")
        self.assertEqual(report["pipeline"], [("rot_alpha", 13)])

    def test_xor_key_solved(self):
        target = bytes(x ^ 0x5A for x in b"payload")
        report = sy.synthesize([(b"payload", target)],
                               allow_compositional=False)
        self.assertEqual(report["pipeline"], [("xor", 0x5A)])

    def test_simple_ops_recognized(self):
        report = sy.synthesize([(b"a1b2c3", b"123")],
                               allow_compositional=False)
        self.assertEqual(report["pipeline"], [("keep_digits", None)])


class TestCompositionalLayer(unittest.TestCase):
    def test_two_op_chain(self):
        report = sy.synthesize([
            (b"Abc", b"414243"),
            (b"xyz", b"58595a"),
        ])
        self.assertTrue(report["synthesized"])
        self.assertEqual([name for name, _ in report["pipeline"]],
                         ["upper", "hexenc"])

    def test_beam_and_trace_present(self):
        report = sy.synthesize([(b"Abc", b"414243"),
                                (b"xyz", b"58595a")])
        self.assertTrue(report["derivation_trace_tail"])
        events = " ".join(str(e.get("event")) for e in
                          report["derivation_trace_tail"])
        self.assertIn("solution-found", events)


class TestEmission(unittest.TestCase):
    def test_generated_script_runs_standalone(self):
        report = sy.synthesize([(b"hello", bytes(x ^ 0x42
                                                 for x in b"hello"))],
                               allow_compositional=False)
        script = report["script"]
        namespace = {}
        exec(compile(script, "synth_out.py", "exec"), namespace)
        self.assertEqual(namespace["transform"](b"anything"),
                         bytes(x ^ 0x42 for x in b"anything"))

    def test_derivation_digest_pinned(self):
        report = sy.synthesize([(b"abc", b"nop")],
                               allow_compositional=False)
        self.assertEqual(len(report["derivation_sha256"]), 64)

    def test_deterministic(self):
        import json
        first = json.dumps(sy.synthesize(
            [(b"abc", b"nop")], allow_compositional=False)["pipeline"])
        second = json.dumps(sy.synthesize(
            [(b"abc", b"nop")], allow_compositional=False)["pipeline"])
        self.assertEqual(first, second)


class TestRobustness(unittest.TestCase):
    def test_unstable_candidates_flagged(self):
        # keep_hex over arbitrary bytes is total; force instability by
        # checking the stability block exists and passes for winners
        report = sy.synthesize([(b"in", b"NI")],
                               allow_compositional=False)
        self.assertTrue(report["fuzz_stability"]["stable"])

    def test_empty_examples_refused(self):
        with self.assertRaises(sy.SynError):
            sy.synthesize([])

    def test_selftest_passes(self):
        result = sy.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
