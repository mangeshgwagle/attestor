#!/usr/bin/env python3
"""Tests for detector/chainforge42.py and its kernel artifacts."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import chainforge42 as cf  # noqa: E402


DEMO_CHAIN = ["internet", "webapp.ssrf", "metadata.creds",
              "admin.panel", "db.exfiltrate"]


class TestEnumeration(unittest.TestCase):
    def test_demo_finds_full_chain(self):
        report = cf.run_demo()
        paths = [c["path"] for c in report["chains"]]
        self.assertIn(DEMO_CHAIN, paths)

    def test_decoy_cannot_reach_impact(self):
        report = cf.run_demo()
        for chain in report["chains"]:
            if "static.asset" in chain["path"]:
                self.assertNotEqual(chain["path"][-1], "db.exfiltrate")

    def test_capability_gating_blocks_unearned_chain(self):
        gated = cf.load_graph(inline={
            "entries": ["a"], "impacts": ["c"],
            "nodes": {"a": {"severity": 0.5},
                      "b": {"severity": 0.5, "requires": ["key"]},
                      "c": {"severity": 0.5, "requires": ["vault"]}},
            "edges": [["a", "b"], ["b", "c"]],
        })
        self.assertEqual(cf.find_chains(gated), [])

    def test_earned_capabilities_open_the_path(self):
        granted = cf.load_graph(inline={
            "entries": ["a"], "impacts": ["c"],
            "nodes": {"a": {"severity": 0.5, "grants": ["key"]},
                      "b": {"severity": 0.5, "requires": ["key"],
                            "grants": ["vault"]},
                      "c": {"severity": 0.5, "requires": ["vault"]}},
            "edges": [["a", "b"], ["b", "c"]],
        })
        chains = cf.find_chains(granted)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["path"], ["a", "b", "c"])
        self.assertEqual(set(chains[0]["held_capabilities"]),
                         {"key", "vault"})

    def test_cycles_do_not_hang_enumeration(self):
        cyclic = cf.load_graph(inline={
            "entries": ["a"], "impacts": ["z"],
            "nodes": {n: {"severity": 0.5} for n in ("a", "b", "c", "z")},
            "edges": [["a", "b"], ["b", "c"], ["c", "b"],
                      ["c", "z"]],
        })
        chains = cf.find_chains(cyclic)
        self.assertTrue(any(c["path"][-1] == "z" for c in chains))


class TestLinearScoring(unittest.TestCase):
    def test_unit_features_saturate(self):
        vec = [cf.WEIGHTS[n] for n in cf.FEATURE_ORDER]
        feats = [1.0] * len(vec)
        self.assertAlmostEqual(cf.dot_product_sixed(vec, feats), 1.0)

    def test_zero_features_score_zero(self):
        vec = [cf.WEIGHTS[n] for n in cf.FEATURE_ORDER]
        feats = [0.0] * len(vec)
        self.assertEqual(cf.dot_product_sixed(vec, feats), 0.0)

    def test_top_chain_matches_manual_recompute(self):
        report = cf.run_demo()
        top = report["chains"][0]
        manual = sum(cf.WEIGHTS[k] * top["features"][k]
                     for k in cf.FEATURE_ORDER)
        self.assertAlmostEqual(top["score"], round(manual, 6))

    def test_higher_severity_shorter_chain_outranks(self):
        strong = cf.load_graph(inline={
            "entries": ["in"], "impacts": ["boom"],
            "nodes": {"in": {"severity": 0.2},
                      "mid": {"severity": 0.9, "auth_bypass": True,
                              "novelty": 0.9},
                      "boom": {"severity": 1.0}},
            "edges": [["in", "mid"], ["mid", "boom"]],
        })
        weak = cf.load_graph(inline={
            "entries": ["in"], "impacts": ["boom"],
            "nodes": {"in": {"severity": 0.2},
                      "m1": {"severity": 0.1}, "m2": {"severity": 0.1},
                      "m3": {"severity": 0.1}, "m4": {"severity": 0.1},
                      "boom": {"severity": 1.0}},
            "edges": [["in", "m1"], ["m1", "m2"], ["m2", "m3"],
                      ["m3", "m4"], ["m4", "boom"]],
        })
        strong_top = max(
            c["score"] for c in cf.analyze_graph(strong)["chains"])
        weak_top = max(c["score"] for c in cf.analyze_graph(weak)["chains"])
        self.assertGreater(strong_top, weak_top)


class TestCentrality(unittest.TestCase):
    def test_converges_on_demo(self):
        cent = cf.run_demo()["centrality"]
        self.assertTrue(cent["converged"])
        self.assertLessEqual(cent["iterations_used"], cf.MAX_ITER)

    def test_star_hub_dominates(self):
        star = cf.load_graph(inline={
            "entries": ["leaf1"], "impacts": ["hub"],
            "nodes": {"hub": {"severity": 1.0},
                      "leaf1": {"severity": 0.1},
                      "leaf2": {"severity": 0.1}},
            "edges": [["leaf1", "hub"], ["leaf2", "hub"]],
        })
        values = cf.centrality(star)["values"]
        hub_node = max(values.items(), key=lambda kv: kv[1])[0]
        self.assertEqual(hub_node, "hub")

    def test_values_within_unit_interval(self):
        values = cf.run_demo()["centrality"]["values"]
        for value in values.values():
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.000001)


class TestDeterminism(unittest.TestCase):
    def test_demo_report_digest_stable(self):
        import json as _json
        first = _json.dumps(cf.run_demo(), sort_keys=True)
        second = _json.dumps(cf.run_demo(), sort_keys=True)
        self.assertEqual(first, second)


class TestKernelArtifacts(unittest.TestCase):
    def test_kernel_check_passes(self):
        result = cf.kernel_check()
        self.assertTrue(result["passed"], result["checks"])

    def test_asm_declares_structural_only_boundary(self):
        asm = (Path(__file__).parent / "chainforge_kernel42"
               / "chainforge_kernel_x86_64.asm").read_text(encoding="utf-8")
        self.assertIn("NEVER loaded or executed", asm)

    def test_weights_sum_to_one_in_q16(self):
        import json
        vectors = json.loads((Path(__file__).parent / "chainforge_kernel42"
                              / "EXPECTED_VECTORS.json").read_text())
        total = sum(vectors["dot_weights_q16"])
        self.assertIn(total, (1 << 16, (1 << 16) + 1))


if __name__ == "__main__":
    unittest.main()
