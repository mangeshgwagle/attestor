from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import attestor40
import transactional_repair35
import truth_guard40


def _component(schema: str, source: str, root: str | Path, *, path: str = "app.py") -> dict:
    finding = {
        "rule": source + "/fixture", "severity": "HIGH", "path": path,
        "line": 1, "message": "bounded fixture evidence", "remediation": "review",
        "fingerprint": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }
    value = {
        "schema": schema, "version": "4.0.0", "root": str(Path(root).resolve()),
        "status": "issues-observed" if source == "engineering" else "findings",
        "summary": {"findings": 1}, "findings": [finding],
        "coverage": {"gaps": [], "absence_proven": False},
    }
    if source == "engineering":
        value["analysis"] = {
            "target_code_executed": False, "network_accessed": False,
            "filesystem_writes": False,
        }
        value["execution"] = {
            "target_code": False, "imports": False, "processes": False,
            "network": False, "filesystem_writes": False, "compilers": False,
            "tests": False, "patch_apply": False,
        }
    else:
        value["assurance"] = {
            "defensive_static_only": True,
            "target_code_executed": False, "network_accessed": False,
            "network_probing": False, "external_processes_spawned": False,
            "dependencies_installed": False, "target_files_written": False,
            "automatic_remediation_applied": False,
            "raw_secret_material_in_report": False, "symlinks_followed": False,
            "root_containment_enforced": True,
        }
    value["report_sha256"] = attestor40._sha(value)
    return value


class Attestor40Tests(unittest.TestCase):
    def test_new_components_merge_into_a_truth_guarded_maximum_report(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "app.py").write_text("value = 1\n", encoding="utf-8")
            with mock.patch.object(
                    attestor40.engineering_engine40, "analyze",
                    return_value=_component("attestor-engineering/4.0", "engineering", folder)), \
                    mock.patch.object(
                        attestor40.security_fabric40, "analyze",
                        return_value=_component("attestor-security-fabric/4.0", "security", folder)):
                report = attestor40.maximum(
                    folder, improve=False, use_cache=False,
                    components=("engineering", "security-fabric"))
            self.assertEqual(report["schema"], "attestor-maximum/4.0")
            self.assertEqual(report["version"], "4.0.0")
            self.assertEqual(report["summary"]["findings"], 2)
            self.assertEqual(report["summary"]["engineering_findings"], 1)
            self.assertEqual(report["summary"]["security_fabric_findings"], 1)
            self.assertEqual(set(report["coverage"]["completed_components"]),
                             {"engineering", "security-fabric"})
            self.assertTrue(truth_guard40.verify_guarded(report)["ok"])
            self.assertNotEqual(report["truth_guard2"]["status"], "refuted")

    def test_component_digest_mismatch_fails_closed_and_withholds_completion(self):
        with tempfile.TemporaryDirectory() as folder:
            forged = _component("attestor-engineering/4.0", "engineering", folder)
            forged["report_sha256"] = "0" * 64
            with mock.patch.object(
                    attestor40.engineering_engine40, "analyze", return_value=forged):
                report = attestor40.maximum(
                    folder, improve=False, use_cache=False, components=("engineering",))
        self.assertEqual(report["status"], "failed")
        self.assertNotIn("engineering", report["coverage"]["completed_components"])
        self.assertEqual(report["engineering"]["status"], "not-run")
        self.assertTrue(truth_guard40.verify_guarded(report)["ok"])

    def test_static_component_may_not_claim_target_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            value = _component("attestor-engineering/4.0", "engineering", folder)
            value["analysis"]["target_code_executed"] = True
            value["report_sha256"] = attestor40._sha({
                key: item for key, item in value.items() if key != "report_sha256"})
            with self.assertRaises(attestor40.Attestor40Error):
                attestor40._validate_component(
                    "engineering", value, "attestor-engineering/4.0", Path(folder))

    def test_all_static_contract_sections_are_checked(self):
        with tempfile.TemporaryDirectory() as folder:
            value = _component("attestor-engineering/4.0", "engineering", folder)
            value["execution"]["network"] = True
            value["report_sha256"] = attestor40._sha({
                key: item for key, item in value.items() if key != "report_sha256"})
            with self.assertRaises(attestor40.Attestor40Error):
                attestor40._validate_component(
                    "engineering", value, "attestor-engineering/4.0", Path(folder))

    def test_component_version_root_and_status_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            for field, forged_value in (("version", "0.0.0"),
                                        ("root", str(Path(folder).parent)),
                                        ("status", "successfully-secure")):
                value = _component("attestor-engineering/4.0", "engineering", folder)
                value[field] = forged_value
                value["report_sha256"] = attestor40._sha({
                    key: item for key, item in value.items() if key != "report_sha256"})
                with self.subTest(field=field), self.assertRaises(attestor40.Attestor40Error):
                    attestor40._validate_component(
                        "engineering", value, "attestor-engineering/4.0", Path(folder))

    def test_critical_new_finding_survives_global_cap(self):
        base = [{"rule": "base-%04d" % index, "severity": "LOW", "path": "base.py",
                 "line": index + 1, "message": "low", "fix": "review",
                 "fingerprint": "b%04d" % index} for index in range(attestor40.MAX_FINDINGS)]
        security = {"findings": [{
            "id": "SF40-critical", "rule": "security/critical", "severity": "CRITICAL",
            "path": "app.py", "line": 1, "message": "critical evidence",
            "remediation": "fix critical", "fingerprint": "critical-fingerprint",
        }]}
        merged = attestor40._merge_findings(base, None, security, Path.cwd())
        self.assertEqual(len(merged), attestor40.MAX_FINDINGS)
        self.assertTrue(any(row["rule"] == "security/critical" for row in merged))
        self.assertEqual(merged[0]["severity"], "CRITICAL")

    def test_critical_component_tail_survives_per_source_cap(self):
        lows = [{
            "id": "low-%04d" % index, "rule": "security/low",
            "severity": "LOW", "path": "app.py", "line": index + 1,
            "message": "low evidence", "fingerprint": "low-%04d" % index,
        } for index in range(attestor40.MAX_FINDINGS)]
        critical = {
            "id": "critical-tail", "rule": "security/critical-tail",
            "severity": "CRITICAL", "path": "app.py", "line": 1,
            "message": "critical tail evidence",
            "fingerprint": "critical-tail",
        }
        merged = attestor40._merge_findings(
            [], None, {"findings": lows + [critical]}, Path.cwd())
        self.assertEqual(len(merged), attestor40.MAX_FINDINGS)
        self.assertEqual(merged[0]["rule"], "security/critical-tail")

    def test_tampering_is_replaced_by_an_inconsistent_public_report(self):
        with tempfile.TemporaryDirectory() as folder:
            report = attestor40.maximum(
                folder, improve=False, use_cache=False, components=())
        forged = copy.deepcopy(report)
        forged["summary"]["findings"] = 999
        safe = attestor40.safe_public_report(forged)
        self.assertEqual(safe["status"], "inconsistent")
        self.assertEqual(safe["findings"], [])

    def test_hmac_authenticated_report_and_wrong_key(self):
        key = b"k" * 32
        with tempfile.TemporaryDirectory() as folder:
            report = attestor40.maximum(
                folder, improve=False, use_cache=False, components=(),
                truth_key=key, truth_key_id="fixture")
            self.assertTrue(truth_guard40.verify_guarded(report, key=key)["authenticated"])
            self.assertFalse(truth_guard40.verify_guarded(report, key=b"x" * 32)["ok"])

    def test_sarif_uses_40_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            report = attestor40.maximum(
                folder, improve=False, use_cache=False, components=())
        driver = attestor40.to_sarif(report)["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["name"], "Attestor 4.0")
        self.assertEqual(driver["semanticVersion"], "4.0.0")

    def test_sarif_preserves_new_engine_provenance_and_attack_path_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "app.py").write_text("value = 1\n", encoding="utf-8")
            value = _component("attestor-security-fabric/4.0", "security", folder)
            value["findings"][0]["id"] = "SF40-fixture"
            value["threat_model"] = {"attack_paths": [{
                "id": "path-1", "finding_id": "SF40-fixture", "nodes": [
                    {"kind": "source", "path": "app.py", "line": 1},
                    {"kind": "sink", "path": "app.py", "line": 1}],
            }]}
            value["report_sha256"] = attestor40._sha({
                key: item for key, item in value.items() if key != "report_sha256"})
            with mock.patch.object(attestor40.security_fabric40, "analyze", return_value=value):
                report = attestor40.maximum(
                    folder, improve=False, use_cache=False, components=("security-fabric",))
            finding = report["findings"][0]
            self.assertEqual(finding["id"], "SF40-fixture")
            self.assertEqual(report["attack_paths"][0]["finding_id"], finding["id"])
            properties = attestor40.to_sarif(report)["runs"][0]["results"][0]["properties"]
            self.assertEqual(properties["source"], "security-fabric-4.0")

    def test_new_findings_get_precise_plan_only_improvement_results(self):
        with tempfile.TemporaryDirectory() as folder:
            value = _component("attestor-security-fabric/4.0", "security", folder)
            with mock.patch.object(attestor40.security_fabric40, "analyze", return_value=value):
                report = attestor40.maximum(
                    folder, improve=True, use_cache=False, components=("security-fabric",))
        self.assertEqual(len(report["improvement_plans_40"]), 1)
        plan = report["improvement_plans_40"][0]
        self.assertFalse(plan["accepted"])
        self.assertEqual(plan["status"], "plan-only-review-required")
        self.assertTrue(plan["suggested_result"])
        self.assertGreater(report["summary"]["refused_improvements"], 0)

    def test_empty_component_set_skips_compatibility_and_execution_flags(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(
                attestor40.attestor35, "maximum") as compatibility:
            report = attestor40.maximum(folder, improve=False, use_cache=False, components=())
        compatibility.assert_not_called()
        self.assertFalse(report["execution"]["engineering_static_analysis"])
        self.assertFalse(report["execution"]["security_fabric_static_analysis"])

    def test_missing_cli_configuration_fails_safely_without_traceback(self):
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(stderr):
            code = attestor40.main([folder, "--calibration-profile",
                                str(Path(folder, "missing.json"))])
        self.assertEqual(code, 2)
        self.assertIn("Attestor 4.0 failed safely: FileNotFoundError", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_unknown_component_and_oversized_issue_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(attestor40.Attestor40Error):
                attestor40.maximum(folder, components=("invented",))
            with self.assertRaises(attestor40.Attestor40Error):
                attestor40.maximum(folder, issue="x" * (64 * 1024 + 1), components=())

    def test_transactional_repair_remains_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "app.py")
            target.write_text("value = 1\n", encoding="utf-8")
            change = transactional_repair35.FileChange(
                "app.py", hashlib.sha256(target.read_bytes()).hexdigest(), "value = 2\n")
            plan = transactional_repair35.ChangeSet((change,), target_rules=("fixture",))
            result = attestor40.transactional_repair(folder, plan, [])
            self.assertEqual(result["status"], "refused")
            self.assertFalse(result["applied"])
            self.assertEqual(target.read_text(encoding="utf-8"), "value = 1\n")


if __name__ == "__main__":
    unittest.main()
