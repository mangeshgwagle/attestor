from __future__ import annotations

import json
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import attestor3
import truth_guard


class Attestor3Tests(unittest.TestCase):
    @staticmethod
    def _dense_truth_report(root: Path) -> dict:
        return {
            "schema": attestor3.SCHEMA,
            "version": attestor3.VERSION,
            "root": str(root),
            "status": "action-required",
            "summary": {
                "findings": 1,
                "attack_paths": 0,
                "dependencies": 0,
                "component_errors": 0,
                "verified_improvements": 0,
                "refused_improvements": 0,
                "severity": {
                    "CRITICAL": 0, "HIGH": 0, "MEDIUM": 1,
                    "LOW": 0, "INFO": 0,
                },
            },
            "findings": [{
                "rule": "fixture-rule", "path": "app.py", "line": 1,
                "severity": "MEDIUM", "fingerprint": "f" * 64,
            }],
            "top_findings": [],
            "priorities": [],
            "attack_paths": [],
            "improvements": [],
            "errors": [],
            "semantic": {
                "metrics": {"semantic_findings": 0, "files_discovered": 0},
                "findings": [], "files": [],
                "dense_graph": list(range(truth_guard.MAX_INPUT_NODES)),
            },
            "workspace": {
                "files_scanned": 1, "files_discovered": 1,
                "skipped": [], "errors": [],
            },
            "supply_chain": {
                "inventory": {"dependencies": []},
                "advisory_assessment": {
                    "state": "unavailable", "live_status": False,
                    "affected": "unknown",
                    "verification": {"valid": False, "authenticated": False},
                },
            },
        }

    def test_dense_truth_report_uses_digest_bound_replayable_projection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            report = self._dense_truth_report(root)
            first = attestor3._truth_assessment(report)
            self.assertEqual(first["status"], "partial")
            self.assertTrue(first["independent_validation"]["projected"])
            self.assertLessEqual(
                first["independent_validation"]["view_node_count"],
                truth_guard.MAX_INPUT_NODES)
            report["truth_guard"] = first
            payload = {
                key: value for key, value in report.items()
                if key != "report_sha256" and not key.startswith("_")
            }
            report["report_sha256"] = hashlib.sha256(
                truth_guard._canonical(payload)).hexdigest()

            replay = attestor3._truth_assessment(report)
            self.assertEqual(replay["report_integrity"]["state"], "verified")
            self.assertEqual(
                replay["independent_validation"]["source_document_sha256"],
                report["report_sha256"])
            public = attestor3.safe_public_report(report)
            self.assertEqual(len(public["findings"]), 1)
            self.assertEqual(public["findings"][0]["rule"], "fixture-rule")
            serialized = attestor3.deterministic_json(public)
            self.assertEqual(
                json.loads(serialized)["findings"][0]["rule"],
                "fixture-rule")
            self.assertEqual(attestor3.render(report, "classic"), serialized)

    def test_dense_truth_report_tamper_without_rehash_is_quarantined(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            report = self._dense_truth_report(root)
            report["truth_guard"] = attestor3._truth_assessment(report)
            payload = {
                key: value for key, value in report.items()
                if key != "report_sha256" and not key.startswith("_")
            }
            report["report_sha256"] = hashlib.sha256(
                truth_guard._canonical(payload)).hexdigest()
            report["semantic"]["dense_graph"][-1] = -1
            public = attestor3.safe_public_report(report)
            self.assertEqual(public["status"], "inconsistent")
            self.assertEqual(public["findings"], [])

    def test_dense_truth_hard_limit_precedes_independent_validation(self):
        report = {
            "root": ".",
            "dense": [0] * attestor3.MAX_TRUTH_DOCUMENT_NODES,
        }
        with mock.patch.object(
                attestor3.truth_guard, "validate_claims",
                side_effect=AssertionError(
                    "independent validator must not receive oversized source")) \
                as validator:
            with self.assertRaisesRegex(
                    attestor3.Attestor3Error, "500000-node hard boundary"):
                attestor3._truth_assessment(report)
        validator.assert_not_called()

    def test_supply_chain_never_expands_a_single_file_to_sibling_manifests(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            (root / "package-lock.json").write_text(
                '{"lockfileVersion": 3, "packages": {"node_modules/private-marker": '
                '{"name": "private-marker", "version": "1.0.0"}}}', encoding="utf-8")
            with mock.patch.object(
                    attestor3.supply_chain_center, "analyze_workspace",
                    side_effect=AssertionError("parent workspace must not be scanned")):
                report = attestor3.maximum(
                    target, components=("supply-chain",), improve=False, use_cache=False)
        self.assertEqual(report["supply_chain"]["status"], "not-run-file-scope")
        self.assertFalse(report["supply_chain"]["coverage"]["scope_expanded"])
        self.assertNotIn("supply-chain", report["coverage"]["completed_components"])
        self.assertIn("sibling manifests", " ".join(report["coverage"]["gaps"]))

    def test_security_component_honors_file_scope_and_directory_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "target.py"
            target.write_text("value = 1\n", encoding="utf-8")
            (root / "sibling.py").write_text(
                "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

            file_report = attestor3.maximum(
                target, components=("security",), improve=False, use_cache=False)
            directory_report = attestor3.maximum(
                root, components=("security",), improve=False, use_cache=False)

        self.assertEqual(file_report["security"]["summary"]["files_scanned"], 1)
        self.assertFalse(any(row["path"] == "sibling.py" for row in file_report["findings"]))
        self.assertTrue(any(row["path"] == "sibling.py" and row["rule"] == "hardcoded-secret"
                            for row in directory_report["findings"]))

    def test_maximum_finds_and_returns_verified_improved_source_without_applying(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); target = root / "app.py"
            original = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
            target.write_text(original, encoding="utf-8")
            report = attestor3.maximum(root, components=("scan",), use_cache=False,
                                   max_improvement_files=1)
            public = attestor3.public_report(report)
            self.assertGreater(public["summary"]["findings"], 0)
            accepted = [item for item in public["improvements"] if item["accepted"]]
            self.assertTrue(accepted, public["improvements"])
            self.assertIn("debug=False", accepted[0]["improved_source"])
            self.assertEqual(target.read_text(encoding="utf-8"), original)
            self.assertFalse(public["execution"]["changes_applied"])

    def test_single_file_improvement_preserves_exact_read_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "target.py"
            target.write_text("DEBUG = True\n", encoding="utf-8")
            (root / "sibling.py").write_text(
                "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
            report = attestor3.maximum(
                target, components=("scan",), use_cache=False,
                max_improvement_files=1)

        improvement = next(row for row in report["improvements"] if row["accepted"])
        verification = improvement["verification"]
        self.assertEqual(verification["scope"], "exact-target-file")
        self.assertNotIn("project_findings_before", verification)
        self.assertEqual(improvement["remaining_count"],
                         verification["findings_after"])

    def test_unfixable_findings_produce_an_explicit_refusal_not_a_fake_result(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "app.py").write_text("def f(x=[]):\n    return x\n", encoding="utf-8")
            report = attestor3.maximum(root, components=("scan",), use_cache=False,
                                   max_improvement_files=1)
            refused = report["improvements"][0]
            self.assertFalse(refused["accepted"])
            self.assertEqual(refused["improved_source"], "")
            self.assertIn("no guessed change", refused["reasons"][0].lower())

    def test_semantic_evidence_becomes_visual_attack_path(self):
        project = Path(".").resolve()
        semantic = {"findings": [{"fingerprint": "a" * 64, "message": "request reaches shell",
                                   "severity": "HIGH", "rule": "semantic-taint/command",
                                   "evidence": [{"kind": "source", "path": str(project / "app.py"), "line": 1,
                                                 "detail": "request query"},
                                                {"kind": "sink", "path": str(project / "app.py"), "line": 4,
                                                 "detail": "os.system"}]}]}
        paths = attestor3._attack_paths(project, semantic, {})
        self.assertEqual(len(paths), 1)
        self.assertEqual([node["kind"] for node in paths[0]["nodes"]], ["source", "sink"])

    def test_public_report_excludes_full_memory_manifest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "safe.py").write_text("x = 1\n", encoding="utf-8")
            report = attestor3.maximum(root, components=("scan",), improve=False, use_cache=False)
            public = attestor3.public_report(report)
            self.assertNotIn("_memory_snapshot", public)
            self.assertFalse(public["repository_memory"]["privacy"]["source_code_stored"])

    def test_sarif_and_text_surface_improvement_truth(self):
        report = {"findings": [{"rule": "r", "severity": "HIGH", "message": "bad", "fix": "fix",
                                "path": "app.py", "line": 1, "fingerprint": "f" * 64,
                                "source": "test", "confidence": 1.0}]}
        sarif = attestor3._generic_sarif(report)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["semanticVersion"], "3.0.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "r")

    def test_custom_rule_pack_is_integrated_but_bounded(self):
        pack = Path(__file__).resolve().parent / "rulepacks" / "attestor3-example.json"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "app.py").write_text("app.run(debug=True)\n", encoding="utf-8")
            reports, findings = attestor3._custom_rules(root, root, [str(pack)], None, False)
            self.assertEqual(reports[0]["rules"], 1)
            self.assertEqual(findings[0]["rule"], "attestor3-example-python-debug")

    def test_zero_or_partial_coverage_never_claims_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            empty = attestor3.maximum(root, components=(), improve=False, use_cache=False)
            self.assertEqual(empty["status"], "no-findings-with-gaps")
            self.assertIn("no analysis component", " ".join(empty["coverage"]["gaps"]))
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            supply = attestor3.maximum(
                root, components=("supply-chain",), improve=False, use_cache=False)
            self.assertEqual(supply["status"], "no-findings-with-gaps")
            self.assertEqual(supply["coverage"]["advisory_state"], "unavailable")

    def test_selected_test_execution_is_unknown_not_hard_coded_false(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bad.py").write_text("DEBUG = True\n", encoding="utf-8")
            report = attestor3.maximum(
                root, components=("scan",), use_cache=False,
                test_command=(sys.executable, "-c", "import bad"),
                authorize_tests=True, max_improvement_files=1)
            self.assertTrue(report["execution"]["selected_tests_executed"])
            self.assertTrue(report["execution"]["target_code_may_have_executed"])
            self.assertIsNone(report["execution"]["target_code_executed"])
            self.assertIsNone(report["execution"]["network_access"])
            self.assertEqual(report["execution"]["network_observed"], "unknown")

    def test_tampered_report_is_quarantined_before_text_or_sarif_rendering(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            report = attestor3.maximum(
                root, components=("scan",), improve=False, use_cache=False)
            self.assertEqual(
                attestor3._truth_assessment(report)["report_integrity"]["state"], "verified")
            report["findings"].append({
                "rule": "invented-rule", "path": "ghost.py", "line": 999,
                "severity": "HIGH", "message": "invented", "fingerprint": "f" * 64,
            })
            view = attestor3.safe_public_report(report)
            self.assertEqual(view["status"], "inconsistent")
            self.assertEqual(view["findings"], [])
            self.assertNotIn("ghost.py", attestor3.render(report))
            self.assertEqual(attestor3.to_sarif(report)["runs"][0]["results"], [])

    def test_forged_improvement_is_not_exported_even_with_recomputed_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            report = attestor3.maximum(
                root, components=("scan",), improve=False, use_cache=False)
            report["improvements"] = [{
                "target": "app.py", "status": "verified", "accepted": True,
                "complete": True, "improved_source": "value = 999\n", "diff": "fake",
                "resolved_count": 1, "remaining_count": 0,
                "verification": {}, "probes": [], "reasons": [],
            }]
            report["summary"]["verified_improvements"] = 1
            payload = {key: value for key, value in report.items()
                       if key != "report_sha256" and not key.startswith("_")}
            report["report_sha256"] = hashlib.sha256(attestor3._canonical(payload)).hexdigest()
            view = attestor3.safe_public_report(report)
            self.assertEqual(view["status"], "inconsistent")
            self.assertFalse(view["improvements"][0]["accepted"])
            self.assertEqual(view["improvements"][0]["improved_source"], "")
            destination = root / "exports"
            self.assertEqual(attestor3._write_improvements(report, destination), [])
            self.assertFalse((destination / "app.py").exists())


if __name__ == "__main__":
    unittest.main()
