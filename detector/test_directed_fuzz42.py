#!/usr/bin/env python3
"""Tests for detector/directed_fuzz42.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import directed_fuzz42 as df  # noqa: E402

TARGET = df.LAYERED_TARGET


class TestStaticModel(unittest.TestCase):
    def test_distance_layering(self):
        functions, edges = df.extract_callgraph(TARGET, {"sink"})
        distances = df.compute_distances(functions, edges)
        self.assertEqual(distances["sink"], 0)
        self.assertEqual(distances["decode"], 0)
        self.assertEqual(distances["validate"], 1)
        self.assertEqual(distances["run"], 2)

    def test_no_path_is_infinity(self):
        functions, edges = df.extract_callgraph(TARGET, {"nonexistent"})
        distances = df.compute_distances(functions, edges)
        for name in ("run", "validate", "decode", "sink"):
            self.assertEqual(distances[name], df.INF)


class TestDirectedEvolution(unittest.TestCase):
    def test_detonates_sink_with_guidance(self):
        namespace = {}
        exec(compile(TARGET, "t.py", "exec"), namespace)
        report = df.directed_fuzz(
            namespace["run"], source=TARGET, sink_names=("sink",),
            seeds=[b"OP"], iterations=4000, seconds=25.0, seed_rng=5,
            tokens=(b"PWN",))
        self.assertGreaterEqual(report["crashes_found"], 1)
        self.assertEqual(report["best_distance_reached"], 0)
        top = report["crashes"][0]
        self.assertTrue(top["sink_adjacent"])
        self.assertEqual(bytes.fromhex(top["input_hex"])[3:6], b"PWN")

    def test_distance_telemetry(self):
        namespace = {}
        exec(compile(TARGET, "t.py", "exec"), namespace)
        report = df.directed_fuzz(
            namespace["run"], source=TARGET, sink_names=("sink",),
            seeds=[b"OP"], iterations=200, seconds=15.0, seed_rng=1,
            tokens=(b"PWN",))
        self.assertIn("0", report["corpus_distance_histogram"])
        self.assertEqual(report["distances"]["run"], 2)

    def test_clean_target_quiet(self):
        namespace = {}
        exec(compile("def run(data):\n    return len(data)\n",
                     "t.py", "exec"), namespace)
        report = df.directed_fuzz(
            namespace["run"], source="def run(data):\n    return len(data)\n",
            sink_names=("sink",), seeds=[b"A"], iterations=300,
            seconds=10.0, seed_rng=2)
        self.assertEqual(report["crashes_found"], 0)

    def test_selftest_passes(self):
        result = df.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
