from __future__ import annotations

import json
import datetime
import tempfile
import unittest
from pathlib import Path

import supply_chain35
import supply_chain_center


class SupplyChain35Tests(unittest.TestCase):
    def test_package_lock_exact_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package-lock.json").write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"a": "1.0.0"}},
                    "node_modules/a": {"name": "a", "version": "1.0.0",
                                       "dependencies": {"b": "2.0.0"}},
                    "node_modules/b": {"name": "b", "version": "2.0.0"},
                }}), encoding="utf-8")
            report = supply_chain35.analyze_dependency_graph(root)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["nodes"]), 3)
        self.assertEqual(len(report["edges"]), 2)
        node_ids = {node["id"] for node in report["nodes"]}
        self.assertTrue(all(edge["source"] in node_ids and edge["target"] in node_ids
                            for edge in report["edges"]))
        self.assertFalse(report["execution"]["dependencies_installed"])

    def test_cargo_graph_and_ambiguous_version_gap(self):
        text = '''[[package]]
name = "app"
version = "1.0.0"
dependencies = ["lib"]
[[package]]
name = "lib"
version = "1.0.0"
[[package]]
name = "lib"
version = "2.0.0"
'''
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "Cargo.lock").write_text(text, encoding="utf-8")
            report = supply_chain35.analyze_dependency_graph(root)
        self.assertEqual(report["status"], "partial")
        self.assertTrue(any("ambiguous" in gap for gap in report["gaps"]))

    def test_missing_lockfiles_is_unavailable_not_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            report = supply_chain35.analyze_dependency_graph(folder)
        self.assertEqual(report["status"], "unavailable")

    def test_semver_and_pep440_are_ecosystem_aware(self):
        self.assertEqual(supply_chain35.compare_versions("npm", "1.2.3", "1.2.4"), -1)
        self.assertEqual(supply_chain35.compare_versions("cargo", "1.0.0-rc.1", "1.0.0"), -1)
        self.assertEqual(supply_chain35.compare_versions("pypi", "2.0rc1", "2.0"), -1)
        self.assertIsNone(supply_chain35.compare_versions("maven", "1.0.Final", "1.0"))
        self.assertIsNone(supply_chain35.compare_versions("npm", "latest", "1.0.0"))

    def test_bare_boolean_cannot_create_not_affected_vex(self):
        row = supply_chain35.vex_disposition("ADV-1", "pkg:npm/a@1", False)
        self.assertEqual(row["status"], "under_investigation")
        self.assertEqual(row["evidence_state"], "unknown")

    def test_verified_unreachable_proof_can_create_not_affected(self):
        proof = supply_chain35.make_reachability_proof(
            "pkg:npm/a@1", reachable=False,
            entrypoints=["<all-observed-entrypoints>", "route:/"], call_chains=[],
            analysis_sha256="a" * 64)
        self.assertTrue(supply_chain35.verify_reachability_proof(proof))
        row = supply_chain35.vex_disposition("ADV-1", "pkg:npm/a@1", proof)
        self.assertEqual(row["status"], "not_affected")

    def test_forged_unreachable_proof_is_rejected(self):
        proof = supply_chain35.make_reachability_proof(
            "pkg:npm/a@1", reachable=False,
            entrypoints=["<all-observed-entrypoints>"], call_chains=[],
            analysis_sha256="a" * 64)
        proof["component_id"] = "pkg:npm/other@9"
        self.assertFalse(supply_chain35.verify_reachability_proof(proof))

    def test_reachable_proof_requires_real_chain(self):
        proof = supply_chain35.make_reachability_proof(
            "pkg:npm/a@1", reachable=True, entrypoints=["route:/"],
            call_chains=[["route:/", "a.call"]], analysis_sha256="b" * 64)
        self.assertTrue(supply_chain35.verify_reachability_proof(proof))

    def test_signed_snapshot_rollback_is_rejected(self):
        key = b"k" * 32
        snapshot = {"schema": supply_chain_center.SNAPSHOT_SCHEMA,
                    "generated_at": "2026-01-02T00:00:00Z",
                    "source": {"name": "fixture", "url": "https://example.invalid/feed"},
                    "expires_at": "2099-01-01T00:00:00Z", "advisories": []}
        signed = supply_chain_center.sign_advisory_snapshot(snapshot, key, "main")
        prior = {"generated_at": "2026-02-01T00:00:00Z", "snapshot_sha256": "f" * 64}
        result = supply_chain35.verify_snapshot_progress(
            signed, {"main": key}, prior,
            now=datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc))
        self.assertFalse(result["accepted"])
        self.assertTrue(any("rollback" in error for error in result["errors"]))

    def test_graph_is_deterministic(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package-lock.json").write_text(
                '{"lockfileVersion":3,"packages":{"node_modules/a":{"name":"a","version":"1.0.0"}}}',
                encoding="utf-8")
            one = supply_chain35.analyze_dependency_graph(root)
            two = supply_chain35.analyze_dependency_graph(root)
        self.assertEqual(one, two)


if __name__ == "__main__":
    unittest.main()
