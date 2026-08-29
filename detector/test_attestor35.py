from __future__ import annotations

import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import calibration35
import attestor35
import transactional_repair35
import truth_guard35


class Attestor35Tests(unittest.TestCase):
    def test_supply_graph_preserves_single_file_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"
            target.write_text("value = 1\n", encoding="utf-8")
            (root / "package-lock.json").write_text(
                '{"lockfileVersion": 3, "packages": {"node_modules/private-marker": '
                '{"name": "private-marker", "version": "1.0.0"}}}', encoding="utf-8")
            with mock.patch.object(
                    attestor35.supply_chain35, "analyze_dependency_graph",
                    side_effect=AssertionError("parent workspace must not be scanned")):
                report = attestor35.maximum(
                    target, improve=False, components=("supply-chain-graph",))
        graph = report["supply_chain_graph_35"]
        self.assertEqual(graph["root"], str(target.resolve()))
        self.assertEqual(graph["status"], "unavailable")
        self.assertFalse(graph["scope"]["expanded"])
        self.assertNotIn("supply-chain-graph", report["coverage"]["completed_components"])
        self.assertIn("sibling lockfiles", " ".join(report["coverage"]["gaps"]))

    def test_failed_compatibility_core_never_claims_legacy_completion(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
                attestor35.attestor3, "maximum", side_effect=RuntimeError("forced core failure")):
            report = attestor35.maximum(
                temporary, improve=False, components=("scan", "semantic"))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["coverage"]["completed_components"], [])
        self.assertIn("completion withheld", " ".join(report["coverage"]["gaps"]))
        self.assertTrue(truth_guard35.verify_guarded(report)["ok"])

    def test_core_component_errors_withhold_all_legacy_completion(self):
        compatibility_report = {
            "root": "fixture", "status": "failed", "summary": {},
            "findings": [], "top_findings": [], "priorities": [],
            "attack_paths": [], "improvements": [],
            "errors": [{"component": "scan", "error": "operational-error"}],
            "coverage": {
                "requested_components": ["scan", "semantic"],
                "completed_components": ["scan", "semantic"],
                "omitted_components": [], "gaps": [], "absence_proven": False,
            },
        }
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(attestor35.attestor3, "maximum", return_value={"fixture": True}), \
                mock.patch.object(attestor35.attestor3, "safe_public_report",
                                  return_value=compatibility_report):
            report = attestor35.maximum(
                temporary, improve=False, components=("scan", "semantic"))
        self.assertEqual(report["coverage"]["completed_components"], [])
        self.assertEqual(report["summary"]["component_errors"], 1)
        self.assertTrue(truth_guard35.verify_guarded(report)["ok"])

    def test_symbolic_polyglot_and_truth_guard_are_integrated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "from flask import request\nimport os\n"
                "def run():\n    os.system(request.args.get('cmd'))\n", encoding="utf-8")
            (root / "app.js").write_text(
                "export function ready(value) { return value; }\n", encoding="utf-8")
            report = attestor35.maximum(
                root, improve=False, use_cache=False,
                components=("symbolic", "polyglot-ir"))
            self.assertEqual(report["schema"], "attestor-maximum/3.5")
            self.assertTrue(truth_guard35.verify_guarded(report)["ok"])
            self.assertTrue(any(row["rule"] == "symbolic-taint/command"
                                for row in report["findings"]))
            self.assertEqual(report["summary"]["polyglot_files"], 1)
            self.assertGreaterEqual(len(report["attack_paths"]), 1)

    def test_tampering_is_withheld(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = attestor35.maximum(temporary, improve=False, components=())
            forged = copy.deepcopy(report)
            forged["summary"]["findings"] = 999
            safe = attestor35.safe_public_report(forged)
            self.assertEqual(safe["status"], "inconsistent")
            self.assertEqual(safe["findings"], [])

    def test_verified_calibration_profile_is_applied(self):
        rows = [{"confidence": 0.9, "outcome": index < 16, "rule": "fixture-rule",
                 "language": "python", "dataset_id": "fixture-v1",
                 "label_source": "independent-test", "label_verified": True}
                for index in range(20)]
        profile = calibration35.build_profile(rows, min_samples=20)
        finding = {"rule": "fixture-rule", "language": "python", "confidence": 0.9,
                   "severity": "HIGH", "path": "app.py", "line": 1,
                   "message": "fixture", "fingerprint": "f"}
        merged = attestor35._merge_findings([finding], None, Path.cwd(), profile)
        self.assertEqual(merged[0]["confidence"], 0.8)
        self.assertEqual(merged[0]["detector_score"], 0.9)

    def test_json_cli_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = attestor35.main([temporary, "--no-improve", "--component", "polyglot-ir",
                                    "--format", "json"])
            self.assertIn(code, (0, 1))
            self.assertEqual(json.loads(output.getvalue())["version"], "3.5.0")

    def test_sarif_uses_35_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = attestor35.maximum(temporary, improve=False, components=())
            driver = attestor35.to_sarif(report)["runs"][0]["tool"]["driver"]
            self.assertEqual(driver["name"], "Attestor 3.5")
            self.assertEqual(driver["semanticVersion"], "3.5.0")

    def test_transactional_repair_is_fail_closed_without_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "app.py"; target.write_text("value = 1\n", encoding="utf-8")
            import hashlib
            change = transactional_repair35.FileChange(
                "app.py", hashlib.sha256(target.read_bytes()).hexdigest(), "value = 2\n")
            plan = transactional_repair35.ChangeSet((change,), target_rules=("fixture-rule",))
            outcome = attestor35.transactional_repair(root, plan, [])
            self.assertEqual(outcome["status"], "refused")
            self.assertFalse(outcome["applied"])
            self.assertEqual(target.read_text(encoding="utf-8"), "value = 1\n")


if __name__ == "__main__":
    unittest.main()
