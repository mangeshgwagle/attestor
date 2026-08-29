from __future__ import annotations

import copy
import math
import unittest

import adjudication414 as adjudication


class Adjudication414Tests(unittest.TestCase):
    @staticmethod
    def by_source_id(report: dict) -> dict[str, dict]:
        return {
            row["source_finding_id"]: row
            for row in report["findings"]
        }

    def test_classifies_and_preserves_every_original_finding(self) -> None:
        findings = [
            {"id": "F-1", "rule": "sql", "path": "a.py", "line": 10},
            {"id": "F-2", "rule": "auth", "path": "b.py", "line": 20},
            {"id": "F-3", "rule": "logic", "path": "c.py", "line": 30},
        ]
        evidence = [
            {"finding_id": "F-1", "stance": "supports", "source": "ast"},
            {"finding_id": "F-2", "verdict": "false-positive", "source": "proof"},
        ]
        report = adjudication.adjudicate(
            findings, evidence,
            [{"id": "R-1", "severity": "high", "covered": True}])
        rows = self.by_source_id(report)
        self.assertEqual(rows["F-1"]["classification"], adjudication.SUPPORTED)
        self.assertEqual(rows["F-2"]["classification"], adjudication.CONTESTED)
        self.assertEqual(rows["F-3"]["classification"], adjudication.INSUFFICIENT)
        self.assertCountEqual(
            [row["original_finding"] for row in report["findings"]],
            findings)
        self.assertEqual(report["summary"]["findings"], len(findings))
        self.assertTrue(adjudication.verify_report(report)[0])

    def test_mixed_evidence_is_a_contradiction_and_contested(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F", "rule": "r", "path": "x.py"}],
            [
                {"finding_id": "F", "stance": "support"},
                {"finding_id": "F", "stance": "contest"},
            ],
            [{"id": "R", "high_risk": True, "covered": True}])
        self.assertEqual(
            report["findings"][0]["classification"], adjudication.CONTESTED)
        self.assertEqual(report["contradictions"][0]["kind"], "mixed-evidence")
        self.assertEqual(report["status"], "review-required")

    def test_explicit_and_structured_finding_contradictions(self) -> None:
        report = adjudication.adjudicate([
            {
                "id": "A", "path": "app.py", "line": 4,
                "rule": "state", "claim_key": "authenticated",
                "claim_value": True, "contradicts": "B",
            },
            {
                "id": "B", "path": "app.py", "line": 4,
                "rule": "state", "claim_key": "authenticated",
                "claim_value": False,
            },
        ], high_risk_areas=[
            {"id": "R", "severity": "critical", "coverage": "covered"},
        ])
        kinds = {row["kind"] for row in report["contradictions"]}
        self.assertEqual(kinds, {
            "explicit-finding-reference",
            "structured-claim-disagreement",
        })
        self.assertEqual(report["summary"]["contested"], 2)

    def test_equivalent_integer_and_float_claims_do_not_contradict(self) -> None:
        report = adjudication.adjudicate([
            {
                "id": "A", "path": "app.py", "line": 4,
                "claim_key": "retry_count", "claim_value": 1,
            },
            {
                "id": "B", "path": "app.py", "line": 4,
                "claim_key": "retry_count", "claim_value": 1.0,
            },
        ], high_risk_areas=[
            {"id": "R", "severity": "high", "covered": True},
        ])
        self.assertEqual(report["contradictions"], [])

    def test_uncovered_and_unfamiliar_high_risk_areas_are_exposed(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F"}],
            high_risk_areas=[
                {"id": "payments", "severity": "critical", "covered": False},
                {
                    "id": "parser", "high_risk": True,
                    "covered": True, "familiar": False,
                },
                {"id": "docs", "severity": "low", "covered": False},
            ])
        self.assertEqual(
            report["summary"]["uncovered_high_risk_areas"], 1)
        self.assertEqual(
            report["summary"]["unfamiliar_high_risk_areas"], 1)
        self.assertEqual(
            report["uncovered_high_risk_areas"][0]["reasons"],
            ["coverage-not-demonstrated"])
        self.assertEqual(
            report["unfamiliar_high_risk_areas"][0]["reasons"],
            ["logic-marked-unfamiliar"])
        self.assertNotIn("docs", str(report["uncovered_high_risk_areas"]))

    def test_no_inventory_or_evidence_does_not_pretend_completeness(self) -> None:
        report = adjudication.adjudicate([{"id": "F"}])
        codes = {gap["code"] for gap in report["coverage"]["gaps"]}
        self.assertIn("insufficient-finding-evidence", codes)
        self.assertIn("high-risk-inventory-not-supplied", codes)
        self.assertFalse(report["coverage"]["complete"])
        self.assertFalse(report["coverage"]["absence_proven"])
        self.assertEqual(report["status"], "attention-required")

    def test_output_is_canonical_under_input_permutations(self) -> None:
        findings = [
            {"id": "B", "path": "b.py"},
            {"id": "A", "path": "a.py"},
        ]
        evidence = [
            {"finding_id": "B", "stance": "contest"},
            {"finding_id": "A", "stance": "support"},
        ]
        risks = [
            {"id": "B", "high_risk": True, "covered": True},
            {"id": "A", "high_risk": True, "covered": True},
        ]
        forward = adjudication.adjudicate(findings, evidence, risks)
        reverse = adjudication.adjudicate(
            list(reversed(findings)),
            list(reversed(evidence)),
            list(reversed(risks)))
        self.assertEqual(forward, reverse)

    def test_duplicate_findings_are_preserved_and_links_fail_ambiguous(self) -> None:
        duplicate = {"id": "same", "path": "x.py", "rule": "r"}
        report = adjudication.adjudicate(
            [duplicate, copy.deepcopy(duplicate)],
            [{"finding_id": "same", "stance": "support"}],
            [{"id": "R", "high_risk": True, "covered": True}])
        self.assertEqual(len(report["findings"]), 2)
        self.assertEqual(len({
            row["finding_ref"] for row in report["findings"]}), 2)
        self.assertEqual(report["summary"]["ambiguous_evidence"], 1)
        self.assertTrue(all(
            row["classification"] == adjudication.INSUFFICIENT
            for row in report["findings"]))

    def test_decisive_structured_locator_can_link_generic_evidence(self) -> None:
        report = adjudication.adjudicate(
            [{"rule": "unsafe-eval", "path": "app.py", "line": 8}],
            [{
                "rule_id": "unsafe-eval", "file": "app.py", "line_number": 8,
                "effect": "confirmed",
            }],
            [{"id": "R", "severity": "high", "covered": True}])
        self.assertEqual(
            report["findings"][0]["classification"], adjudication.SUPPORTED)
        self.assertEqual(report["evidence"][0]["link_reason"], "structured-locator")

    def test_unknown_and_unlinked_evidence_are_coverage_gaps(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F"}],
            [
                {"finding_id": "missing", "stance": "support"},
                {"finding_id": "F", "stance": "maybe"},
            ],
            [{"id": "R", "high_risk": True, "covered": True}])
        codes = {gap["code"] for gap in report["coverage"]["gaps"]}
        self.assertIn("unlinked-evidence", codes)
        self.assertIn("unknown-evidence-stance", codes)
        self.assertEqual(
            report["findings"][0]["classification"], adjudication.INSUFFICIENT)

    def test_risk_coverage_conflict_fails_closed_to_unknown(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F"}],
            high_risk_areas=[{
                "id": "R", "severity": "high",
                "covered": True, "coverage": "uncovered",
            }])
        self.assertEqual(report["risk_areas"][0]["coverage_state"], "unknown")
        codes = {gap["code"] for gap in report["coverage"]["gaps"]}
        self.assertIn("conflicting-risk-coverage-claims", codes)

    def test_unrecognized_risk_coverage_cannot_be_overridden_to_covered(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F"}],
            high_risk_areas=[{
                "id": "R", "severity": "high",
                "covered": True, "coverage": "partial",
            }])
        self.assertEqual(report["risk_areas"][0]["coverage_state"], "unknown")
        self.assertEqual(report["summary"]["uncovered_high_risk_areas"], 1)

    def test_report_digest_and_semantics_are_verified(self) -> None:
        report = adjudication.adjudicate(
            [{"id": "F"}],
            [{"finding_id": "F", "stance": "support"}],
            [{"id": "R", "severity": "high", "covered": True}])
        self.assertTrue(adjudication.verify_report(report)[0])

        tampered = copy.deepcopy(report)
        tampered["findings"][0]["classification"] = adjudication.CONTESTED
        valid, errors = adjudication.verify_report(tampered)
        self.assertFalse(valid)
        self.assertIn("report digest mismatch", errors)

        tampered["report_sha256"] = adjudication._sha({
            key: value for key, value in tampered.items()
            if key != "report_sha256"
        })
        valid, errors = adjudication.verify_report(tampered)
        self.assertFalse(valid)
        self.assertIn("report derived data is inconsistent", errors)

    def test_adjudication_does_not_mutate_inputs(self) -> None:
        findings = [{"id": "F", "nested": {"values": [1, 2]}}]
        evidence = [{"finding_id": "F", "stance": "support"}]
        risks = [{"id": "R", "severity": "high", "covered": True}]
        original = copy.deepcopy((findings, evidence, risks))
        adjudication.adjudicate(findings, evidence, risks)
        self.assertEqual((findings, evidence, risks), original)

    def test_strict_types_cycles_and_limits_are_rejected(self) -> None:
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate(iter([{"id": "F"}]))
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate([{"id": 7}])
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate([{"value": math.nan}])
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate([{"value": "\ud800"}])
        cyclic: dict = {}
        cyclic["self"] = cyclic
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate([cyclic])
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate(
                [{"id": "A"}, {"id": "B"}],
                limits=adjudication.Limits(max_findings=1))
        with self.assertRaises(adjudication.AdjudicationError):
            adjudication.adjudicate(
                [], limits=adjudication.Limits(
                    max_findings=adjudication.MAX_FINDINGS + 1))

    def test_malformed_verifier_inputs_fail_without_raising(self) -> None:
        for value in (
                None,
                {},
                {"schema": adjudication.SCHEMA},
                {"report_sha256": ["not-a-string"]},
                {"findings": "not-a-list"},
        ):
            with self.subTest(value=value):
                valid, errors = adjudication.verify_report(value)
                self.assertFalse(valid)
                self.assertTrue(errors)

    def test_execution_contract_is_static_offline_and_read_only(self) -> None:
        report = adjudication.adjudicate([])
        self.assertEqual(report["execution"], {
            "target_inspected": False,
            "target_code_executed": False,
            "network_accessed": False,
            "target_files_written": False,
            "subprocesses_started": False,
        })


if __name__ == "__main__":
    unittest.main()
