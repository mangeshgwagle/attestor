from __future__ import annotations

import copy
import unittest
from unittest import mock

import truth_guard40 as truth_guard35


def verified_improvement() -> dict:
    return {
        "target": "app.py", "status": "verified", "accepted": True,
        "complete": True, "improved_source": "value = 1\n",
        "verification": {"accepted": True, "compiler_or_parser": "verified",
                         "findings_before": 1, "findings_after": 0,
                         "new_findings": [], "new_failures": []},
        "probes": [{"name": "parse", "status": "passed"},
                   {"name": "mutation", "status": "passed"}],
    }


def sample() -> dict:
    return {
        "schema": "attestor-maximum/4.0", "version": "4.0.0",
        "status": "improved-with-review",
        "root": ".",
        "findings": [{"rule": "debug-enabled", "path": "README.md",
                      "line": 1, "severity": "MEDIUM", "message": "debug enabled"}],
        "attack_paths": [], "improvements": [verified_improvement()], "errors": [],
        "summary": {"findings": 1, "attack_paths": 0, "verified_improvements": 1,
                    "refused_improvements": 0, "component_errors": 0,
                    "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1,
                                 "LOW": 0, "INFO": 0}},
        "coverage": {"absence_proven": False, "gaps": ["one finding remains"]},
    }


def valid_component(kind: str, findings: list[dict] | None = None) -> dict:
    rows = list(findings or [])
    if kind == "engineering":
        value = {
            "schema": "attestor-engineering/4.0", "version": "4.0.0", "root": ".",
            "status": "issues-observed" if rows else "no-static-issues-from-bounded-checks",
            "summary": {"findings": len(rows)}, "findings": rows,
            "coverage": {"gaps": [], "absence_proven": False},
            "analysis": {"target_code_executed": False, "network_accessed": False,
                         "filesystem_writes": False},
            "execution": {"target_code": False, "imports": False, "processes": False,
                          "network": False, "filesystem_writes": False,
                          "compilers": False, "tests": False, "patch_apply": False},
        }
    else:
        value = {
            "schema": "attestor-security-fabric/4.0", "version": "4.0.0", "root": ".",
            "status": "findings" if rows else "clean",
            "summary": {"findings": len(rows)}, "findings": rows,
            "coverage": {"gaps": [], "absence_proven": False},
            "assurance": {
                "defensive_static_only": True, "target_code_executed": False,
                "network_accessed": False, "network_probing": False,
                "external_processes_spawned": False, "dependencies_installed": False,
                "target_files_written": False, "automatic_remediation_applied": False,
                "raw_secret_material_in_report": False, "symlinks_followed": False,
                "root_containment_enforced": True,
            },
        }
    value["report_sha256"] = truth_guard35._sha(value)
    return value


class TruthGuard40Tests(unittest.TestCase):
    def test_guard_is_deterministic_and_verifiable(self):
        one = truth_guard35.guard_document(sample())
        two = truth_guard35.guard_document(sample())
        self.assertEqual(one, two)
        verification = truth_guard35.verify_guarded(one)
        self.assertTrue(verification["ok"])
        self.assertEqual(verification["status"], "integrity-verified")
        self.assertFalse(verification["authenticated"])
        self.assertEqual(one["truth_guard2"]["status"], "verified")
        projection = one["truth_guard2"]["independent_validation"]
        self.assertFalse(projection["projected"])
        self.assertEqual(projection["view_node_count"],
                         projection["source_node_count_lower_bound"])
        self.assertTrue(all(
            row["omitted"] == 0
            for row in projection["collections"].values()))

    def test_dense_byte_bounded_document_uses_replayable_projection(self):
        document = sample()
        document["engineering_inventory"] = {
            "symbol_ids": list(range(truth_guard35.MAX_INDEPENDENT_NODES))
        }
        self.assertLess(
            len(truth_guard35._canonical(document)), 16 * 1024 * 1024)

        one = truth_guard35.guard_document(document)
        two = truth_guard35.guard_document(document)
        self.assertEqual(one, two)
        audit = one["truth_guard2"]
        projection = audit["independent_validation"]
        self.assertEqual(audit["status"], "partial")
        self.assertTrue(projection["projected"])
        self.assertGreater(projection["source_node_count_lower_bound"],
                           truth_guard35.MAX_INDEPENDENT_NODES)
        self.assertLessEqual(projection["view_node_count"],
                             truth_guard35.MAX_INDEPENDENT_NODES)
        self.assertEqual(projection["source_document_sha256"],
                         audit["source_document_sha256"])
        self.assertTrue(truth_guard35.verify_guarded(one)["ok"])

    def test_full_source_hash_binds_projected_away_tail(self):
        document = sample()
        document["engineering_inventory"] = {
            "symbol_ids": list(range(truth_guard35.MAX_INDEPENDENT_NODES))
        }
        guarded = truth_guard35.guard_document(document)
        forged = copy.deepcopy(guarded)
        forged["engineering_inventory"]["symbol_ids"][-1] = -1
        forged["report_sha256"] = truth_guard35._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"
        })
        result = truth_guard35.verify_guarded(forged)
        self.assertFalse(result["ok"])
        self.assertIn("source document digest mismatch", result["errors"])

    def test_projection_metadata_tamper_is_rejected_after_outer_rehash(self):
        document = sample()
        document["engineering_inventory"] = {
            "symbol_ids": list(range(truth_guard35.MAX_INDEPENDENT_NODES))
        }
        guarded = truth_guard35.guard_document(document)
        forged = copy.deepcopy(guarded)
        forged["truth_guard2"]["independent_validation"][
            "view_node_count"] += 1
        forged["report_sha256"] = truth_guard35._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"
        })
        result = truth_guard35.verify_guarded(forged)
        self.assertFalse(result["ok"])
        self.assertIn(
            "claim audit does not match independent reassessment",
            result["errors"])

    def test_local_node_hard_limit_precedes_recursive_redaction(self):
        document = sample()
        document["dense"] = [0] * truth_guard35.MAX_DOCUMENT_NODES
        with mock.patch.object(
                truth_guard35.truth_guard, "redact_tree",
                side_effect=AssertionError("redaction must not run")) as redactor:
            with self.assertRaisesRegex(
                    truth_guard35.TruthGuard40Error,
                    "500000-node hard boundary"):
                truth_guard35.guard_document(document)
        redactor.assert_not_called()

    def test_report_tamper_is_detected(self):
        guarded = truth_guard35.guard_document(sample())
        guarded["summary"]["findings"] = 999
        result = truth_guard35.verify_guarded(guarded)
        self.assertFalse(result["ok"])
        self.assertIn("public report digest mismatch", result["errors"])

    def test_chain_reorder_is_detected(self):
        guarded = truth_guard35.guard_document(sample())
        chain = guarded["truth_guard2"]["evidence_chain"]
        chain[0], chain[1] = chain[1], chain[0]
        self.assertFalse(truth_guard35.verify_guarded(guarded)["ok"])

    def test_numeric_list_order_above_ten_remains_verifiable(self):
        document = sample()
        document["ordered_rows"] = list(range(25))
        guarded = truth_guard35.guard_document(document)
        self.assertTrue(truth_guard35.verify_guarded(guarded)["ok"])

    def test_claim_state_tamper_with_recomputed_outer_hash_is_detected(self):
        guarded = truth_guard35.guard_document(sample())
        guarded["truth_guard2"]["claims"][0]["state"] = "forged"
        guarded["report_sha256"] = truth_guard35._sha({
            key: value for key, value in guarded.items() if key != "report_sha256"})
        result = truth_guard35.verify_guarded(guarded)
        self.assertFalse(result["ok"])
        self.assertIn("claim audit does not match independent reassessment", result["errors"])

    def test_claim_evidence_references_are_in_guarded_catalogs(self):
        guarded = truth_guard35.guard_document(sample())
        available = {row["id"] for row in guarded["truth_guard2"]["evidence_chain"]}
        available.update(row["id"] for row in guarded["truth_guard2"]["independent_evidence"])
        self.assertTrue(all(ref in available
                            for claim in guarded["truth_guard2"]["claims"]
                            for ref in claim["evidence_ids"]))

    def test_fake_summary_count_is_refuted(self):
        document = sample(); document["summary"]["findings"] = 44
        guarded = truth_guard35.guard_document(document)
        self.assertGreater(guarded["truth_guard2"]["summary"]["refuted"], 0)
        self.assertEqual(guarded["truth_guard2"]["status"], "refuted")

    def test_forged_improvement_is_refuted(self):
        document = sample()
        document["improvements"] = [{"target": "app.py", "accepted": True,
                                      "status": "verified", "improved_source": "x=9\n"}]
        guarded = truth_guard35.guard_document(document)
        self.assertGreater(guarded["truth_guard2"]["summary"]["refuted"], 0)

    def test_string_false_is_not_accepted(self):
        document = sample(); document["improvements"][0]["accepted"] = "false"
        document["summary"].update(verified_improvements=0, refused_improvements=1)
        guarded = truth_guard35.guard_document(document)
        claims = guarded["truth_guard2"]["claims"]
        self.assertFalse(any("verified improvement" in row["text"] for row in claims))

    def test_absolute_safety_status_is_refuted(self):
        document = sample(); document["status"] = "completely secure"
        guarded = truth_guard35.guard_document(document)
        self.assertEqual(guarded["truth_guard2"]["status"], "refuted")

    def test_secret_material_is_redacted_before_hashing(self):
        document = sample()
        document["api_key"] = "sk_live_1234567890abcdefghijklmnop"
        guarded = truth_guard35.guard_document(document)
        self.assertNotIn("sk_live_", truth_guard35.deterministic_json(guarded))

    def test_hmac_authentication_and_wrong_key(self):
        key = b"k" * 32
        guarded = truth_guard35.guard_document(sample(), key=key, key_id="release-key")
        authenticated = truth_guard35.verify_guarded(guarded, key=key)
        self.assertTrue(authenticated["authenticated"])
        self.assertEqual(authenticated["status"], "authenticated")
        self.assertFalse(truth_guard35.verify_guarded(guarded, key=b"x" * 32)["ok"])

    def test_authentication_key_cannot_accept_an_unsigned_ledger(self):
        guarded = truth_guard35.guard_document(sample())
        result = truth_guard35.verify_guarded(guarded, key=b"k" * 32)
        self.assertFalse(result["ok"])
        self.assertIn(
            "authentication key was supplied for an unsigned ledger",
            result["errors"])

    def test_short_hmac_key_is_refused(self):
        with self.assertRaises(truth_guard35.TruthGuard40Error):
            truth_guard35.guard_document(sample(), key=b"short", key_id="key")

    def test_unvalidated_free_form_output_abstains(self):
        guarded = truth_guard35.guard_output("chat", "everything is secure")
        self.assertEqual(guarded["status"], "abstained")
        self.assertIn("cannot substantiate", guarded["response"])

    def test_validated_output_envelope_is_guarded(self):
        guarded = truth_guard35.guard_output(
            "scan", "bounded explanation",
            evidence={"validated": True, "document": sample()})
        self.assertEqual(guarded["mode"], "scan")
        self.assertTrue(truth_guard35.verify_guarded(guarded)["ok"])

    def test_existing_guard_fields_do_not_change_source_identity(self):
        guarded = truth_guard35.guard_document(sample())
        again = truth_guard35.guard_document(guarded)
        self.assertEqual(guarded["truth_guard2"]["source_document_sha256"],
                         again["truth_guard2"]["source_document_sha256"])

    def test_attestor40_component_count_and_digest_are_independently_derived(self):
        document = sample()
        component = valid_component("engineering", [{"rule": "architecture/cycle"}])
        document["engineering"] = component
        document["summary"]["engineering_findings"] = 1
        document["coverage"]["completed_components"] = ["engineering"]
        guarded = truth_guard35.guard_document(document)
        matching = [row for row in guarded["truth_guard2"]["claims"]
                    if row["kind"].startswith("component-")]
        self.assertTrue(matching)
        self.assertTrue(all(row["state"] == "derived" for row in matching))

    def test_attestor40_component_count_contradiction_is_refuted(self):
        document = sample()
        component = valid_component("security")
        document["security_fabric"] = component
        document["summary"]["security_fabric_findings"] = 99
        document["coverage"]["completed_components"] = ["security-fabric"]
        guarded = truth_guard35.guard_document(document)
        self.assertEqual(guarded["truth_guard2"]["status"], "refuted")
        self.assertTrue(any("security_fabric" in item
                            for item in guarded["truth_guard2"]["contradictions"]))

    def test_component_identity_status_and_contract_are_independently_refuted(self):
        for field, forged in (("version", "0.0.0"), ("root", "../different-root"),
                              ("status", "successfully-secure")):
            document = sample()
            component = valid_component("engineering")
            component[field] = forged
            component["report_sha256"] = truth_guard35._sha({
                key: value for key, value in component.items() if key != "report_sha256"})
            document["engineering"] = component
            document["summary"]["engineering_findings"] = 0
            document["coverage"]["completed_components"] = ["engineering"]
            guarded = truth_guard35.guard_document(document)
            with self.subTest(field=field):
                self.assertEqual(guarded["truth_guard2"]["status"], "refuted")

        document = sample()
        component = valid_component("engineering")
        component["execution"]["network"] = True
        component["report_sha256"] = truth_guard35._sha({
            key: value for key, value in component.items() if key != "report_sha256"})
        document["engineering"] = component
        document["summary"]["engineering_findings"] = 0
        document["coverage"]["completed_components"] = ["engineering"]
        guarded = truth_guard35.guard_document(document)
        self.assertEqual(guarded["truth_guard2"]["status"], "refuted")
        self.assertTrue(any("static-analysis contract" in item
                            for item in guarded["truth_guard2"]["contradictions"]))

    def test_verifier_rejects_missing_ledger(self):
        self.assertFalse(truth_guard35.verify_guarded(sample())["ok"])


if __name__ == "__main__":
    unittest.main()
