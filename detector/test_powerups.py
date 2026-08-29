#!/usr/bin/env python3
"""Offline tests for Attestor's newer power-ups."""
from __future__ import annotations

import os
import tempfile
import unittest

import codearena
import confidence
import fixmemory
import harvest
import mutation_gauntlet
import patchforge
import projectbrain
import reproducer
import superattestor


class FakePatchBrain:
    def __init__(self, answer: str):
        self.answer = answer

    def available(self):
        return True

    def generate(self, _prompt):
        return {"fake": self.answer}


class PowerUpTests(unittest.TestCase):
    def test_findings_have_confidence_metadata(self):
        finding = harvest.scan_content("def f(x):\n    return x == None\n", ".py")[0]
        self.assertEqual(finding.rule, "py-eq-none")
        self.assertGreater(finding.confidence, 0.0)
        self.assertEqual(finding.exploitability, "LOW")
        self.assertTrue(finding.safe_to_autofix)
        self.assertTrue(confidence.safe_to_autofix("py-eq-none"))

    def test_reproducer_minimizes_and_proves_rule(self):
        source = "def ok():\n    return 1\n\ndef bad(x):\n    return x == None\n"
        finding = harvest.scan_content(source, ".py")[0]
        repro = reproducer.make(source, "app.py", finding)
        self.assertIn("py-eq-none", repro["test_source"])
        self.assertLess(len(repro["bug_source"].splitlines()), len(source.splitlines()))
        self.assertIn("py-eq-none", {f.rule for f in harvest.scan_content(repro["bug_source"], ".py")})

    def test_patchforge_accepts_only_gated_patch(self):
        source = "def make(keys):\n    return dict.fromkeys(keys, [])\n"
        fixed = "def make(keys):\n    return {k: [] for k in keys}\n"
        result = patchforge.patch_source(source, "app.py", FakePatchBrain(fixed))
        self.assertTrue(result["ok"], patchforge.render(result))
        self.assertIn("fake", patchforge.render(result))
        self.assertEqual(harvest.scan_content(result["code"], ".py"), [])

    def test_patchforge_refuses_without_api_model(self):
        class NoBrain:
            def available(self):
                return False
        result = patchforge.patch_source("def f():\n    return 1\n", "app.py", NoBrain())
        self.assertFalse(result["ok"])
        self.assertIn("needs at least one", result["error"])

    def test_projectbrain_finds_routes_db_env_dead_code_and_flow(self):
        with tempfile.TemporaryDirectory() as d:
            app = os.path.join(d, "app.py")
            with open(app, "w", encoding="utf-8") as fh:
                fh.write(
                    "import os\n"
                    "from flask import request\n\n"
                    "SECRET = os.getenv('SECRET_KEY')\n\n"
                    "@app.get('/users')\n"
                    "def users():\n"
                    "    name = request.args['name']\n"
                    "    db.execute('SELECT 1')\n"
                    "    return eval(name)\n\n"
                    "def unused_helper():\n"
                    "    return 3\n")
            report = projectbrain.analyze(d)
        self.assertEqual(len(report["routes"]), 1)
        self.assertTrue(report["env"])
        self.assertTrue(report["db"])
        self.assertTrue(report["dead_code"])
        self.assertTrue(report["unsafe_flows"])

    def test_mutation_gauntlet_catches_known_mutants(self):
        source = (
            "import hashlib\n"
            "DEBUG=False\n"
            "def token(x):\n"
            "    if x is None:\n"
            "        return hashlib.sha256(b'x').hexdigest()\n"
            "    return x\n"
            "def fetch(requests, url):\n"
            "    return requests.get(url, verify=True, timeout=5)\n")
        result = mutation_gauntlet.run(source, "candidate.py")
        self.assertGreaterEqual(len(result["mutants"]), 3)
        self.assertEqual(result["gaps"], [])

    def test_fixmemory_promotes_repeated_pattern(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "memory.json")
            memory = {"version": 1, "patterns": {}}
            fixmemory.learn(memory, "weak-hash", "md5 -> sha256", 2, {"repo": "r", "path": "a.py"})
            fixmemory.save(memory, path)
            memory = fixmemory.load(path)
            fixmemory.learn(memory, "weak-hash", "md5 -> sha256", 1, {"repo": "r", "path": "b.py"})
            self.assertTrue(memory["patterns"]["md5 -> sha256"]["promoted"])

    def test_codearena_dashboard_metrics(self):
        metrics = codearena.measure()
        self.assertGreaterEqual(metrics["rule_count"], 15_000)
        self.assertTrue(metrics["advanced_rule_self_test"])
        self.assertTrue(metrics["precision_catalog_self_test"])
        self.assertEqual(metrics["planted_bug_recall_pct"], 100.0)
        self.assertIn("Code Arena", codearena.render(metrics))

    def test_superattestor_routes_new_powers(self):
        self.assertEqual(superattestor.decide("patchforge app.py")["action"], "patchforge")
        self.assertEqual(superattestor.decide("bug reproducer app.py")["action"], "reproduce")
        self.assertEqual(superattestor.decide("project brain .")["action"], "projectbrain")
        self.assertEqual(superattestor.decide("mutation gauntlet app.py")["action"], "gauntlet")
        self.assertEqual(superattestor.decide("code arena")["action"], "arena")


if __name__ == "__main__":
    unittest.main(verbosity=2)
