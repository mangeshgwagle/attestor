#!/usr/bin/env python3
"""Evidence, abstention, privacy, and determinism contracts for Truth Guard."""
from __future__ import annotations

import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import truth_guard


def seal(report: dict) -> dict:
    payload = dict(report)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    payload["report_sha256"] = hashlib.sha256(encoded).hexdigest()
    return payload


def claim_state(report: dict, index: int = 0) -> str:
    return report["claims"][index]["state"]


class ClaimStateTests(unittest.TestCase):
    def test_direct_value_is_observed_and_stable(self):
        evidence = {"status": "action-required", "summary": {"findings": 2},
                    "findings": [{"rule": "r1"}, {"rule": "r2"}]}
        claims = [{"kind": "value", "text": "Two findings require action",
                   "evidence_path": "/summary/findings", "expected": 2}]
        first = truth_guard.validate_claims(claims, evidence)
        second = truth_guard.validate_claims(claims, evidence)
        self.assertEqual(claim_state(first), "observed")
        self.assertEqual(first, second)
        self.assertRegex(first["claims"][0]["id"], r"^clm-[0-9a-f]{20}$")
        self.assertEqual(truth_guard.deterministic_json(first),
                         truth_guard.deterministic_json(second))

    def test_count_is_derived_and_wrong_count_is_refuted(self):
        evidence = {"items": [1, 2, 3]}
        report = truth_guard.validate_claims([
            {"kind": "count", "text": "three items", "collection_path": "/items", "expected": 3},
            {"kind": "count", "text": "four items", "collection_path": "/items", "expected": 4},
        ], evidence)
        self.assertEqual([row["state"] for row in report["claims"]], ["derived", "refuted"])
        self.assertIn("cannot substantiate", report["claims"][1]["safe_text"].lower())

    def test_free_form_unsupported_claim_abstains(self):
        report = truth_guard.validate_claims(
            [{"kind": "statement", "text": "This architecture is flawless."}], {})
        self.assertEqual(claim_state(report), "unknown")
        self.assertEqual(report["status"], "abstained")
        self.assertNotIn("flawless", report["safe_response"].lower())

    def test_absolute_safety_language_never_rides_on_zero_findings(self):
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "There are no vulnerabilities",
            "evidence_path": "/summary/findings", "expected": 0,
        }], {"summary": {"findings": 0}, "findings": []})
        self.assertEqual(claim_state(report), "unknown")

    def test_mutually_exclusive_claims_are_detected(self):
        report = truth_guard.validate_claims([
            {"kind": "value", "text": "status one", "evidence_path": "/count", "expected": 1},
            {"kind": "value", "text": "status two", "evidence_path": "/count", "expected": 2},
        ], {"count": 1})
        self.assertTrue(any(row["kind"] == "claim-contradiction"
                            for row in report["contradictions"]))
        self.assertEqual({row["state"] for row in report["claims"]}, {"observed", "refuted"})


class StructuredInputBoundaryTests(unittest.TestCase):
    def test_secret_and_long_object_keys_cannot_collapse_identity(self):
        first = {
            "password=supersecretvalue123": "alpha",
            "api_key=sk-abcdefghijklmnopqrstuvwxyz": "bravo",
        }
        changed = dict(first)
        changed["api_key=sk-abcdefghijklmnopqrstuvwxyz"] = "changed"
        self.assertNotEqual(truth_guard._digest(first), truth_guard._digest(changed))
        self.assertEqual(len(truth_guard.redact_tree(first)), 2)

        prefix = "x" * 1_024
        long_keys = {prefix + "A": 1, prefix + "B": 2}
        self.assertEqual(len(truth_guard.redact_tree(long_keys)), 2)

    def test_deep_structures_fail_closed_before_recursive_projection(self):
        nested: list = []
        cursor = nested
        for _ in range(1_500):
            child: list = []
            cursor.append(child)
            cursor = child
        with self.assertRaises(truth_guard.TruthGuardError):
            truth_guard.redact_tree(nested)
        with self.assertRaises(truth_guard.TruthGuardError):
            truth_guard._digest(nested)


class EvidenceConsistencyTests(unittest.TestCase):
    def test_fake_summary_count_uses_derived_collection_truth(self):
        evidence = {"summary": {"findings": 99},
                    "findings": [{"rule": "a"}, {"rule": "b"}]}
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "99 findings", "evidence_path": "/summary/findings",
            "expected": 99,
        }], evidence)
        self.assertEqual(claim_state(report), "refuted")
        check = next(row for row in report["numeric_checks"]
                     if row["reported_path"] == "/summary/findings")
        self.assertEqual((check["reported"], check["derived"], check["state"]),
                         (99, 2, "contradiction"))

    def test_clean_status_with_findings_is_refuted(self):
        evidence = {"status": "clean", "summary": {"findings": 1},
                    "findings": [{"rule": "danger", "path": "app.py", "line": 1}]}
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "report is clean", "evidence_path": "/status",
            "expected": "clean",
        }], evidence)
        self.assertEqual(claim_state(report), "refuted")
        self.assertTrue(any(row["kind"] == "status-inconsistency"
                            for row in report["contradictions"]))

    def test_matching_report_hash_is_verified(self):
        evidence = seal({"status": "clean", "summary": {"findings": 0}, "findings": []})
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "zero observed findings",
            "evidence_path": "/summary/findings", "expected": 0,
        }], evidence)
        self.assertEqual(report["report_integrity"]["state"], "verified")
        self.assertEqual(claim_state(report), "observed")

    def test_tampered_report_hash_downgrades_all_positive_claims(self):
        evidence = seal({"status": "clean", "summary": {"findings": 0}, "findings": []})
        evidence["summary"]["findings"] = 7
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "seven", "evidence_path": "/summary/findings",
            "expected": 7,
        }], evidence)
        self.assertEqual(report["report_integrity"]["state"], "mismatch")
        self.assertEqual(claim_state(report), "unknown")
        self.assertTrue(any(row["kind"] == "report-integrity"
                            for row in report["contradictions"]))


class LocationAndRuleTests(unittest.TestCase):
    def test_file_line_and_finding_rule_must_all_exist(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("first\nsecond\n", encoding="utf-8")
            evidence = {"findings": [{"rule": "unsafe-eval", "path": "app.py", "line": 2}]}
            report = truth_guard.validate_claims([
                {"kind": "file", "text": "app line two exists", "path": "app.py", "line": 2},
                {"kind": "finding", "text": "eval finding at line two", "rule": "unsafe-eval",
                 "path": "app.py", "line": 2},
                {"kind": "rule", "text": "rule exists", "rule": "unsafe-eval"},
            ], evidence, root=root)
        self.assertEqual([row["state"] for row in report["claims"]],
                         ["observed", "observed", "observed"])

    def test_forged_line_and_outside_path_are_not_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "app.py").write_text("only one\n", encoding="utf-8")
            evidence = {"findings": [{"rule": "r", "path": "app.py", "line": 9}]}
            report = truth_guard.validate_claims([
                {"kind": "finding", "text": "line nine", "rule": "r", "path": "app.py", "line": 9},
                {"kind": "file", "text": "outside", "path": "../outside.py"},
            ], evidence, root=root)
        self.assertEqual(claim_state(report, 0), "refuted")
        self.assertEqual(claim_state(report, 1), "unknown")


class ImprovementAndCoverageTests(unittest.TestCase):
    @staticmethod
    def verified_improvement() -> dict:
        return {
            "target": "app.py", "status": "verified", "accepted": True, "complete": True,
            "improved_source": "value = 1\n", "improved_source_withheld": False,
            "verification": {"accepted": True, "compiler_or_parser": "verified",
                             "findings_before": 1, "findings_after": 0,
                             "new_findings": [], "new_failures": []},
            "probes": [{"name": "parse", "status": "passed"},
                       {"name": "mutation", "status": "passed"}],
        }

    def test_verified_improvement_requires_real_validation_evidence(self):
        evidence = {"improvements": [self.verified_improvement()]}
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "app has a verified improved result",
            "target": "app.py", "expected": "verified",
        }], evidence)
        self.assertEqual(claim_state(report), "derived")
        self.assertEqual(report["evidence_audit"]["improvements"][0]["evidence_level"], "available")

    def test_partial_but_proven_improvement_is_not_mislabeled_as_complete(self):
        improvement = self.verified_improvement()
        improvement.update(complete=False, remaining_count=2)
        improvement["verification"].update(findings_before=3, findings_after=2)
        evidence = {"improvements": [improvement]}
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "verified partial improvement",
            "target": "app.py", "expected": "verified",
        }], evidence)
        self.assertEqual(claim_state(report), "derived")
        self.assertFalse(improvement["complete"])

    def test_complete_label_with_remaining_findings_is_refuted(self):
        improvement = self.verified_improvement()
        improvement.update(complete=True, remaining_count=2)
        improvement["verification"].update(findings_before=3, findings_after=2)
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "complete verified improvement",
            "target": "app.py", "expected": "verified",
        }], {"improvements": [improvement]})
        self.assertEqual(claim_state(report), "refuted")

    def test_forged_verified_improvement_is_refuted(self):
        evidence = {"improvements": [{"target": "app.py", "status": "verified",
                                       "accepted": True, "complete": True,
                                       "improved_source": "value = 1\n"}]}
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "verified", "target": "app.py",
            "expected": "verified",
        }], evidence)
        self.assertEqual(claim_state(report), "refuted")
        self.assertTrue(any(row["kind"] == "forged-improvement"
                            for row in report["contradictions"]))

    def test_skipped_probe_is_not_proof_of_verified_improvement(self):
        improvement = self.verified_improvement()
        improvement["probes"][1]["status"] = "skipped"
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "verified", "target": "app.py",
            "expected": "verified",
        }], {"improvements": [improvement]})
        self.assertEqual(claim_state(report), "refuted")
        self.assertIn("failed", report["evidence_audit"]["improvements"][0]["reasons"][0])

    def test_secret_removal_can_skip_reverse_mutation_without_retaining_secret(self):
        improvement = self.verified_improvement()
        improvement["edits"] = [
            {"rule": "hardcoded-secret", "kind": "externalize-secret",
             "mutation_before": ""},
            {"rule": "import", "kind": "add-required-import"},
        ]
        improvement["verification"]["resolved_findings"] = [
            {"path": "app.py", "line": 1, "rule": "hardcoded-secret"}
        ]
        improvement["probes"][1] = {
            "name": "mutation:reverse-fix", "status": "skipped", "cases": 0,
            "detail": "secret material is never retained for mutation",
        }
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "verified secret removal",
            "target": "app.py", "expected": "verified",
        }], {"improvements": [improvement]})
        self.assertEqual(claim_state(report), "derived")

    def test_secret_skip_exception_requires_bound_secret_edit_evidence(self):
        improvement = self.verified_improvement()
        improvement["probes"][1] = {
            "name": "mutation:reverse-fix", "status": "skipped", "cases": 0,
            "detail": "secret material is never retained for mutation",
        }
        report = truth_guard.validate_claims([{
            "kind": "improvement", "text": "verified", "target": "app.py",
            "expected": "verified",
        }], {"improvements": [improvement]})
        self.assertEqual(claim_state(report), "refuted")

    def test_string_false_is_never_counted_as_accepted(self):
        evidence = {"summary": {"verified_improvements": 0, "refused_improvements": 1},
                    "improvements": [{"accepted": "false"}]}
        report = truth_guard.validate_claims([], evidence)
        checks = {row["reported_path"]: row for row in report["numeric_checks"]}
        self.assertEqual(checks["/summary/verified_improvements"]["derived"], 0)
        self.assertEqual(checks["/summary/refused_improvements"]["derived"], 1)

    def test_empty_scan_is_not_complete_or_clean(self):
        evidence = {"workspace": {"files_discovered": 0, "files_scanned": 0,
                                  "skipped": [], "errors": []}}
        report = truth_guard.validate_claims([
            {"kind": "coverage", "text": "scan was complete", "scope": "scan", "expected": "complete"},
            {"kind": "coverage", "text": "repository has no vulnerabilities", "scope": "scan",
             "expected": "clean"},
        ], evidence)
        self.assertEqual(claim_state(report, 0), "refuted")
        self.assertEqual(claim_state(report, 1), "unknown")
        self.assertEqual(report["evidence_audit"]["coverage"]["scan"]["state"], "empty")

    def test_unavailable_advisory_cannot_be_called_authenticated_or_live(self):
        evidence = {"supply_chain": {"advisory_assessment": {
            "state": "unavailable", "live_status": False,
            "verification": {"valid": False, "authenticated": False}}}}
        report = truth_guard.validate_claims([
            {"kind": "coverage", "text": "advisories authenticated", "scope": "advisory",
             "expected": "authenticated"},
            {"kind": "coverage", "text": "live advisory status", "scope": "advisory",
             "expected": "live"},
        ], evidence)
        self.assertEqual([row["state"] for row in report["claims"]], ["unknown", "unknown"])

    def test_authenticated_offline_no_match_is_precisely_derived_not_live(self):
        evidence = {"supply_chain": {"advisory_assessment": {
            "state": "current", "live_status": False, "affected": 0,
            "verification": {"valid": True, "authenticated": True}}}}
        report = truth_guard.validate_claims([
            {"kind": "coverage", "text": "no match in authenticated snapshot",
             "scope": "advisory", "expected": "no-known-match"},
            {"kind": "coverage", "text": "live status", "scope": "advisory", "expected": "live"},
        ], evidence)
        self.assertEqual([row["state"] for row in report["claims"]], ["derived", "refuted"])


class ArtifactPrivacyAndBoundsTests(unittest.TestCase):
    def test_model_artifact_levels_require_passing_checks(self):
        evidence = {"model_artifacts": [
            {"id": "good", "evidence_level": "verified",
             "verification": {"passed": True, "checks": [{"status": "passed"}]}},
            {"id": "fake", "evidence_level": "verified"},
        ]}
        report = truth_guard.validate_claims([
            {"kind": "artifact", "text": "good verified", "artifact_id": "good", "expected": "verified"},
            {"kind": "artifact", "text": "fake verified", "artifact_id": "fake", "expected": "verified"},
        ], evidence)
        self.assertEqual([row["state"] for row in report["claims"]], ["derived", "refuted"])
        self.assertTrue(any(row["kind"] == "artifact-evidence"
                            for row in report["contradictions"]))

    def test_secret_is_neither_echoed_nor_hashed(self):
        secret = "ghp_" + "A1b2C3d4" * 5
        report = truth_guard.validate_claims([{
            "kind": "value", "text": "token is " + secret,
            "evidence_path": "/token", "expected": secret,
        }], {"token": secret})
        serialized = truth_guard.deterministic_json(report)
        self.assertNotIn(secret, serialized)
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(), serialized)
        self.assertIn("REDACTED", serialized)
        self.assertEqual(report["report_integrity"]["state"], "unknown")

    def test_machine_json_recursively_redacts_raw_reports(self):
        secret = "sk-proj-" + "A1b2C3d4" * 7
        secret_key = "ghp_" + "Z9y8X7w6" * 5
        raw = {"nested": {"api_key": secret, "password": 123456,
                          secret_key: "value"}, "safe": "visible"}
        redacted = truth_guard.redact_tree(raw)
        serialized = truth_guard.deterministic_json(raw)
        self.assertEqual(redacted["safe"], "visible")
        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret_key, serialized)
        self.assertNotIn("123456", serialized)
        self.assertIn("REDACTED", serialized)

    def test_text_claims_and_claim_count_are_bounded(self):
        claims = [
            {"kind": "statement", "text": "x" * 10_000},
            {"kind": "statement", "text": "second"},
        ]
        report = truth_guard.validate_claims(claims, {}, max_claims=1)
        self.assertEqual(report["summary"]["claims_truncated"], 1)
        self.assertLessEqual(len(report["claims"][0]["claim_text"]), truth_guard.MAX_TEXT_CHARS + 20)
        self.assertLess(len(truth_guard.deterministic_json(report)), 2 * 1024 * 1024)

    def test_guard_response_extracts_known_counts_and_execution_assurance(self):
        evidence = {"summary": {"findings": 2}, "findings": [{}, {}],
                    "execution": {"target_code_executed": False}}
        report = truth_guard.guard_response(
            "2 findings. No target code was executed.", evidence)
        self.assertEqual(report["summary"]["claims_evaluated"], 2)
        self.assertTrue(all(row["state"] in {"observed", "derived"}
                            for row in report["claims"]))

    def test_non_json_cycles_are_rejected_safely(self):
        evidence = {}
        evidence["self"] = evidence
        with self.assertRaises(truth_guard.TruthGuardError):
            truth_guard.validate_claims([], evidence)

    def test_module_has_no_execution_or_network_imports(self):
        source = Path(truth_guard.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {alias.name.split(".", 1)[0] for node in ast.walk(tree)
                   if isinstance(node, (ast.Import, ast.ImportFrom))
                   for alias in (node.names if isinstance(node, ast.Import) else
                                 [ast.alias(name=node.module or "")])}
        self.assertTrue({"subprocess", "socket", "urllib", "requests", "importlib"}.isdisjoint(imports))
        forbidden_calls = {"eval", "exec", "compile", "__import__"}
        calls = {node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertTrue(forbidden_calls.isdisjoint(calls))

    def test_truth_guard_output_hash_verifies(self):
        report = truth_guard.validate_claims([], {})
        claimed = report["report_sha256"]
        payload = {key: value for key, value in report.items() if key != "report_sha256"}
        self.assertEqual(claimed, hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
