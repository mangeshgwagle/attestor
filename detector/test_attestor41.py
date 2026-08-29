from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import attack_surface413
import attestor41
import security_posture413
import security_validation413
import truth_guard
import truth_guard35
import truth_guard40
import truth_guard41


class Attestor41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source = self.root / "app.py"
        self.source.write_text(
            "import os\n\ndef run(value):\n    return eval(value)\n",
            encoding="utf-8", newline="")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def base(self, *, path: str = "app.py") -> dict:
        engineering = {
            "schema": "attestor-engineering/4.0", "version": "4.0.0",
            "root": str(self.root),
            "status": "no-static-issues-with-gaps",
            "summary": {"findings": 0}, "findings": [],
            "coverage": {"complete": False, "gaps": ["fixture boundary"]},
            "analysis": {
                "target_code_executed": False,
                "network_accessed": False,
                "filesystem_writes": False,
            },
            "execution": {
                "target_code": False, "imports": False, "processes": False,
                "network": False, "filesystem_writes": False,
                "compilers": False, "tests": False, "patch_apply": False,
            },
        }
        engineering["report_sha256"] = attestor41._sha(engineering)
        security = {
            "schema": "attestor-security-fabric/4.0", "version": "4.0.0",
            "root": str(self.root), "status": "partial",
            "summary": {"findings": 0}, "findings": [],
            "coverage": {"complete": False, "gaps": ["fixture boundary"]},
            "assurance": {
                "defensive_static_only": True,
                "root_containment_enforced": True,
                "target_code_executed": False,
                "network_accessed": False,
                "network_probing": False,
                "external_processes_spawned": False,
                "dependencies_installed": False,
                "target_files_written": False,
                "automatic_remediation_applied": False,
                "raw_secret_material_in_report": False,
                "symlinks_followed": False,
            },
        }
        security["report_sha256"] = attestor41._sha(security)
        return {
            "schema": "attestor-maximum/4.0", "version": "4.0.0",
            "root": str(self.root), "status": "action-required",
            "summary": {
                "findings": 1, "engineering_findings": 0,
                "security_fabric_findings": 0,
                "verified_improvements": 0, "refused_improvements": 0,
            },
            "findings": [{"rule": "dangerous-eval", "severity": "HIGH",
                          "path": path, "line": 4,
                          "message": "Dynamic evaluation accepts untrusted text.",
                          "fix": "Use a constrained parser."}],
            "attack_paths": [], "priorities": [], "improvements": [],
            "errors": [],
            "coverage": {"completed_components": [
                              "compatibility", "engineering",
                              "security-fabric"],
                          "gaps": ["runtime behavior was not executed"],
                          "absence_proven": False},
            "execution": {"target_code_executed": False,
                          "network_accessed": False,
                          "filesystem_writes": False},
            "engineering": engineering,
            "security_fabric": security,
        }

    @staticmethod
    def augmented_worker(value: dict, action: str) -> dict:
        original = copy.deepcopy(value)
        boundary = {
            "shell": False, "target_code_executed": False,
            "preexec_fn_used": False, "network_kernel_blocked": True,
        }
        result_sha256 = attestor41._sha(original)
        request_sha256 = "1" * 64
        wrapper_body = {
            "schema": attestor41.bounded_worker41.SCHEMA,
            "version": attestor41.bounded_worker41.VERSION,
            "status": "completed", "action": action,
            "request_sha256": request_sha256,
            "result": original, "result_sha256": result_sha256,
            "error": "", "boundary": boundary,
        }
        augmented = copy.deepcopy(original)
        augmented.update({
            "worker_action": action,
            "worker_request_sha256": request_sha256,
            "worker_result_sha256": result_sha256,
            "worker_boundary": boundary,
            "worker_wrapper_sha256": attestor41._sha(wrapper_body),
            "worker_original_report_sha256": original["report_sha256"],
        })
        augmented["report_sha256"] = attestor41._sha({
            key: item for key, item in augmented.items()
            if key != "report_sha256"
        })
        return augmented

    @staticmethod
    def coding() -> dict:
        value = {
            "schema": "attestor-coding-fabric/4.1", "version": "4.1.3",
            "snapshot": {"coverage": {"complete": True, "gaps": []}},
            "semantic_graph": {
                "schema": "attestor.semantic-graph/4.1",
                "version": "4.1.3",
                "coverage": {"complete": False, "gaps": [
                    {"path": "app.py", "reason": "parameter-taint-not-fully-interprocedural"}]},
                "graph": {"taint_witnesses": [{
                    "id": "sg41-taint-test", "cwe": "CWE-95",
                    "precision": "bounded-parser-derived-source-to-sink",
                    "cross_file": False,
                    "source": {"path": "app.py", "line": 3, "kind": "parameter"},
                    "sink": {"path": "app.py", "line": 4, "callee": "eval"},
                }]},
            },
            "deep_correctness": {"coverage": {"complete": True, "gaps": []},
                                 "findings": []},
            "semantic_rule_reports": [],
            "execution": {
                "target_code_executed": False,
                "network_accessed": False, "filesystem_writes": False,
            },
        }
        value["semantic_graph"]["report_sha256"] = attestor41._sha(
            value["semantic_graph"])
        value["report_sha256"] = attestor41._sha(value)
        return Attestor41Tests.augmented_worker(value, "coding-static")

    @staticmethod
    def security() -> dict:
        value = {
            "schema": "attestor-security-static-fabric/4.1", "version": "4.1.3",
            "supply_chain_trust": {"status": "unavailable", "gaps": [],
                                   "unavailable_adapters": ["Bazel resolved graph"]},
            "secret_lifecycle": {"status": "complete", "gaps": [],
                                 "findings": []},
            "execution": {
                "target_code_executed": False,
                "network_accessed": False, "filesystem_writes": False,
            },
        }
        value["report_sha256"] = attestor41._sha(value)
        return Attestor41Tests.augmented_worker(value, "security-static")

    @staticmethod
    def repair() -> dict:
        return {
            "schema": "attestor-repair-director/4.1", "version": "4.1.3",
            "status": "no-qualified-candidate",
            "summary": {"candidates": 0, "static_qualified": 0,
                        "verified": 0, "applied": 0},
            "coverage": {"gaps": ["no concrete repair candidate was produced"]},
            "execution": {"target_code_executed": False,
                          "workspace_written": False},
        }

    def guarded_compatibility(self, evidence: dict) -> dict:
        guarded = copy.deepcopy(evidence)
        guarded["truth_guard2"] = truth_guard40.guard_document(
            self.base())["truth_guard2"]
        guarded["report_sha256"] = attestor41._sha(guarded)
        return guarded

    def maximum(self, base: dict | None = None,
                security_evidence: dict | None = None,
                legacy_error: Exception | None = None, **kwargs) -> dict:
        evidence = copy.deepcopy(base or self.base())
        guarded_evidence = self.guarded_compatibility(evidence)

        def worker(action, _payload):
            if action == "coding-static":
                return self.coding(), []
            if action == "security-static":
                return security_evidence or self.security(), []
            if action == "attack-static-413":
                result = attack_surface413.analyze(
                    self.root,
                    snapshot_or_documents={"safe.py": "value = 1\n"})
            elif action == "posture-static-413":
                result = security_posture413.scan_security_posture([])
            else:  # pragma: no cover - an allowlist regression
                raise AssertionError("unexpected worker action")
            original = result["report_sha256"]
            result = dict(result)
            result.update({
                "worker_boundary": {
                    "memory_limit": "rlimit-as",
                    "network_kernel_blocked": True,
                },
                "worker_wrapper_sha256": "a" * 64,
                "worker_original_report_sha256": original,
            })
            return result, []

        with mock.patch.object(
                attestor41.attestor40, "maximum", return_value={},
                side_effect=legacy_error), \
                mock.patch.object(attestor41.attestor40, "safe_public_report",
                                  return_value=guarded_evidence), \
                mock.patch.object(attestor41, "_worker", side_effect=worker), \
                mock.patch.object(attestor41.repair_director41, "direct",
                                  return_value=self.repair()):
            return attestor41.maximum(self.root, **kwargs)

    def test_legacy_truth_boundary_failure_is_isolated_as_a_verified_gap(self) -> None:
        report = self.maximum(
            legacy_error=truth_guard.TruthGuardError(
                "structured input exceeds node limit"),
            improve=False)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(
            report["compatibility_truth_guard_40"]["state"],
            "unavailable-failed-closed")
        self.assertEqual(
            report["compatibility_truth_guard_40"]["error"],
            "TruthGuardError")
        compatibility_errors = [
            row for row in report["errors"]
            if row.get("component") == "attestor-4.0-compatibility"
        ]
        self.assertEqual(
            compatibility_errors,
            [{"component": "attestor-4.0-compatibility",
              "error": "TruthGuardError"}])
        self.assertEqual(report["summary"]["component_errors"], 1)
        self.assertFalse(report["engineering"]["findings"])
        self.assertFalse(report["security_fabric"]["findings"])
        self.assertFalse(report["improvements"])
        self.assertNotIn(
            "compatibility", report["coverage"]["completed_components"])
        self.assertTrue(any(
            "compatibility evidence failed closed" in gap
            for gap in report["coverage"]["gaps"]))
        self.assertTrue(
            attack_surface413.verify_report(report["attack_surface_413"])[0])
        self.assertTrue(
            security_posture413.verify_report(report["security_posture_413"]))
        self.assertTrue(
            truth_guard41.verify_guarded(report, root=self.root)["ok"])
        self.assertFalse(report["execution"]["target_code_executed"])
        self.assertFalse(report["execution"]["changes_applied"])

    def test_truth_guard35_boundary_failure_is_isolated_as_a_verified_gap(self) -> None:
        report = self.maximum(
            legacy_error=truth_guard35.TruthGuard35Error(
                "document exceeds its hard node boundary"),
            improve=False)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(
            report["compatibility_truth_guard_40"]["state"],
            "unavailable-failed-closed")
        self.assertEqual(
            report["compatibility_truth_guard_40"]["error"],
            "TruthGuard35Error")
        self.assertTrue(any(
            row.get("error") == "TruthGuard35Error"
            for row in report["errors"]))
        self.assertTrue(
            truth_guard41.verify_guarded(report, root=self.root)["ok"])

        authorized = self.maximum(
            legacy_error=truth_guard.TruthGuardError(
                "structured input exceeds node limit"),
            improve=False, authorize_tests=True,
            test_command=("python", "-m", "unittest"),
            apply_improvements=True)
        self.assertIsNone(authorized["execution"]["target_code_executed"])
        self.assertTrue(
            authorized["execution"]["target_code_may_have_executed"])
        self.assertIsNone(authorized["execution"]["selected_tests_executed"])
        self.assertIsNone(authorized["execution"]["changes_applied"])
        self.assertTrue(
            truth_guard41.verify_guarded(authorized, root=self.root)["ok"])

        inconsistent = self.base()
        inconsistent["status"] = "inconsistent"
        withheld = self.maximum(base=inconsistent, improve=False)
        self.assertEqual(
            withheld["compatibility_truth_guard_40"]["error"],
            "integrity-verification-failed")
        self.assertFalse(any(
            row.get("rule") == "dangerous-eval"
            for row in withheld["findings"]))
        self.assertTrue(
            truth_guard41.verify_guarded(withheld, root=self.root)["ok"])

    def test_combines_source_bound_findings_and_labels_semantic_limits(self) -> None:
        report = self.maximum()
        verification = truth_guard41.verify_guarded(report, root=self.root)
        self.assertTrue(verification["ok"], verification)
        self.assertEqual(report["version"], "4.1.3")
        self.assertEqual(report["schema"], "attestor-maximum/4.1")
        self.assertEqual(len(report["findings"]), 2)
        semantic = next(row for row in report["findings"]
                        if row["rule"].startswith("ATTESTOR41-SEMANTIC"))
        self.assertIn("not established", semantic["message"])
        self.assertEqual(semantic["source_evidence"]["state"], "bound")
        self.assertFalse(report["coverage"]["absence_proven"])
        self.assertFalse(report["execution"]["attestor41_target_code_executed"])
        self.assertFalse(report["execution"]["research_network_accessed"])
        self.assertTrue(
            attack_surface413.verify_report(report["attack_surface_413"])[0])
        self.assertTrue(
            security_posture413.verify_report(report["security_posture_413"]))
        self.assertTrue(security_validation413.verify_report(
            report["security_command_center_413"],
            schema=security_validation413.COMMAND_CENTER_SCHEMA)[0])
        self.assertEqual(
            report["coding_fabric_41"]["schema"],
            attestor41.PUBLIC_PROJECTION_SCHEMA)
        self.assertEqual(
            report["security_static_fabric_41"]["schema"],
            attestor41.PUBLIC_PROJECTION_SCHEMA)
        self.assertEqual(
            report["semantic_graph_41"]["schema"],
            attestor41.PUBLIC_PROJECTION_SCHEMA)
        self.assertTrue(attestor41._projection_links_match(
            report["coding_fabric_41"], report))
        self.assertTrue(attestor41._projection_links_match(
            report["security_static_fabric_41"], report))
        self.assertEqual(
            report["analysis_snapshot_41"],
            self.coding()["snapshot"])
        self.assertTrue(any(
            "digest-bound projection" in gap
            for gap in report["coverage"]["gaps"]))

    def test_public_projection_digest_and_child_links_fail_closed(self) -> None:
        source = self.coding()
        projection = attestor41._public_component_projection(
            "coding-fixture", source,
            retain=("worker_boundary",),
            children={"snapshot": "analysis_snapshot_41"})
        public = {"analysis_snapshot_41": source["snapshot"]}
        self.assertTrue(
            attestor41._verify_public_component_projection(projection))
        self.assertTrue(attestor41._projection_links_match(projection, public))

        forged = copy.deepcopy(projection)
        forged["children"]["snapshot"]["source_sha256"] = "0" * 64
        forged["report_sha256"] = attestor41._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"
        })
        self.assertTrue(
            attestor41._verify_public_component_projection(forged))
        self.assertFalse(attestor41._projection_links_match(forged, public))

        snapshot_source = {
            "schema": "snapshot/fixture", "version": "4.1.3",
            "coverage": {"gaps": []},
        }
        snapshot_source["report_sha256"] = attestor41._sha(snapshot_source)
        wrapper_source = {
            "schema": "wrapper/fixture", "version": "4.1.3",
            "snapshot": snapshot_source,
        }
        wrapper_source["report_sha256"] = attestor41._sha(wrapper_source)
        nested_projection = attestor41._public_component_projection(
            "snapshot-fixture", snapshot_source, retain=("coverage",))
        wrapper_projection = attestor41._public_component_projection(
            "wrapper-fixture", wrapper_source,
            children={"snapshot": "analysis_snapshot_41"},
            embedded_children={"snapshot": nested_projection})
        self.assertTrue(attestor41._projection_links_match(
            wrapper_projection,
            {"analysis_snapshot_41": nested_projection}))
        changed_nested = copy.deepcopy(nested_projection)
        changed_nested["limitations"].append(
            "synthetic independently valid child-envelope change")
        changed_nested["report_sha256"] = attestor41._sha({
            key: value for key, value in changed_nested.items()
            if key != "report_sha256"
        })
        self.assertTrue(
            attestor41._verify_public_component_projection(changed_nested))
        self.assertFalse(attestor41._projection_links_match(
            wrapper_projection,
            {"analysis_snapshot_41": changed_nested}))

    def test_digest_only_retained_field_requires_original_replay(self) -> None:
        source = {
            "schema": "projection-large-retained/fixture",
            "version": "4.1.3",
            "summary": "x" * (attestor41.MAX_PROJECTION_RETAINED_BYTES + 1),
        }
        source["report_sha256"] = attestor41._sha(source)
        projection = attestor41._public_component_projection(
            "large-retained-fixture", source, retain=("summary",))
        self.assertTrue(
            attestor41._verify_public_component_projection(projection))
        self.assertIn("summary", projection["projected_retained_fields"])
        self.assertTrue(projection["requires_original_for_full_replay"])
        self.assertEqual(projection["omitted_fields"], [])

    def test_worker_digest_chain_rejects_rehashed_boundary_claims(self) -> None:
        coding = self.coding()
        original, attestation = attestor41._replay_augmented_worker_report(
            coding, "coding-static")
        self.assertEqual(
            attestation["result_report_sha256"],
            original["report_sha256"])
        self.assertTrue(attestation["replayed_during_generation"])
        self.assertFalse(
            attestation["independently_replayable_from_projection"])
        self.assertIn(
            "outer-truth-guard3-hmac",
            attestation["origin_authentication"])
        forged = copy.deepcopy(coding)
        forged["worker_request_sha256"] = "9" * 64
        forged["report_sha256"] = attestor41._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"
        })
        with self.assertRaisesRegex(
                attestor41.Attestor41Error, "worker wrapper"):
            attestor41._replay_augmented_worker_report(
                forged, "coding-static")

    def test_large_semantic_graph_projection_stays_below_public_boundary(
            self) -> None:
        coding, _attestation = attestor41._replay_augmented_worker_report(
            self.coding(), "coding-static")
        graph = coding["semantic_graph"]

        graph.pop("report_sha256")
        graph["graph"]["synthetic_bulk"] = "x" * (80 * 1024)
        graph["report_sha256"] = attestor41._sha(graph)

        coding.pop("report_sha256")
        coding["report_sha256"] = attestor41._sha(coding)
        coding = self.augmented_worker(coding, "coding-static")

        boundary = 128 * 1024
        graph_bytes = len(attestor41._canonical(graph))
        original_coding, _attestation = \
            attestor41._replay_augmented_worker_report(coding, "coding-static")
        worker_bytes = len(attestor41._canonical(original_coding))
        self.assertLess(graph_bytes, boundary)
        self.assertLess(worker_bytes, boundary)
        self.assertGreater(graph_bytes + worker_bytes, boundary)

        with mock.patch.object(self, "coding", return_value=coding), \
                mock.patch.object(attestor41, "MAX_PUBLIC_BYTES", boundary):
            report = self.maximum(improve=False)

        self.assertLessEqual(len(attestor41._canonical(report)), boundary)
        self.assertEqual(
            report["semantic_graph_41"]["schema"],
            attestor41.PUBLIC_PROJECTION_SCHEMA)
        self.assertEqual(
            report["semantic_graph_41"]["source"]["canonical_bytes"],
            graph_bytes)
        self.assertIn(
            "graph", report["semantic_graph_41"]["omitted_fields"])
        self.assertTrue(attestor41._projection_links_match(
            report["coding_fabric_41"], report))
        self.assertTrue(
            truth_guard41.verify_guarded(report, root=self.root)["ok"])

    def test_compatibility_audit_projection_commits_omitted_catalogs(self) -> None:
        audit = truth_guard40.guard_document(self.base())["truth_guard2"]
        projection = attestor41._compatibility_audit_projection(audit)
        self.assertTrue(
            attestor41._verify_compatibility_audit_projection(projection))
        self.assertFalse(
            projection["source_audit"]["complete_audit_embedded"])
        self.assertEqual(
            projection["source_signature"], audit["signature"])
        self.assertNotIn("signature", projection["retained"])
        self.assertTrue(any(
            "applies only to the original Truth Guard 2 audit" in row
            for row in projection["limitations"]))
        self.assertEqual(
            projection["omitted_collections"]["evidence_chain"][
                "source_sha256"],
            attestor41._sha(audit["evidence_chain"]))

        forged = copy.deepcopy(projection)
        forged["omitted_collections"]["evidence_chain"][
            "source_items"] += 1
        forged["report_sha256"] = attestor41._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"
        })
        self.assertFalse(
            attestor41._verify_compatibility_audit_projection(forged))
        future = copy.deepcopy(audit)
        future["future_uncommitted_field"] = {"state": "unsupported"}
        with self.assertRaisesRegex(
                attestor41.Attestor41Error, "exact Truth Guard 2 contract"):
            attestor41._compatibility_audit_projection(future)
        empty = copy.deepcopy(projection)
        empty["retained"] = {}
        empty["omitted_fields"] = []
        empty["omitted_commitments"] = {}
        empty["omitted_collections"] = {}
        empty["report_sha256"] = attestor41._sha({
            key: value for key, value in empty.items()
            if key != "report_sha256"
        })
        self.assertFalse(
            attestor41._verify_compatibility_audit_projection(empty))

    def test_rehashed_wrong_projection_schema_is_withheld(self) -> None:
        report = self.maximum()
        forged = copy.deepcopy(report)
        forged["engineering"] = {
            "schema": "attacker-controlled/non-projection",
            "payload": "ordinary mapping that must not skip verification",
        }
        reguarded = truth_guard41.guard_document(
            forged, root=self.root,
            config=forged["analysis_config"], analyzer=forged["analyzer"])
        self.assertTrue(
            truth_guard41.verify_guarded(reguarded, root=self.root)["ok"])
        public = attestor41.safe_public_report(reguarded, root=self.root)
        self.assertEqual(public["status"], "inconsistent")
        self.assertEqual(public["findings"], [])

    def test_unbound_observations_are_quarantined_not_claimed(self) -> None:
        report = self.maximum(self.base(path="workspace"))
        self.assertTrue(report["unbound_observations"])
        self.assertFalse(any(row["rule"] == "dangerous-eval"
                             for row in report["findings"]))
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.root)["ok"])

    def test_out_of_range_line_is_quarantined_before_truth_guard(self) -> None:
        base = self.base()
        base["findings"][0]["line"] = 999
        report = self.maximum(base)
        self.assertFalse(any(row["rule"] == "dangerous-eval"
                             for row in report["findings"]))
        observation = next(row for row in report["unbound_observations"]
                           if row["rule"] == "dangerous-eval")
        self.assertEqual(observation["line"], 999)
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.root)["ok"])

    def test_outside_absolute_path_cannot_alias_same_named_workspace_file(self) -> None:
        outside_root = Path(self.tmp.name).parent / (Path(self.tmp.name).name + "-outside")
        outside_root.mkdir()
        outside = outside_root / "app.py"
        outside.write_text("value = eval(data)\n", encoding="utf-8")
        try:
            report = self.maximum(self.base(path=str(outside)))
            self.assertFalse(any(row["rule"] == "dangerous-eval"
                                 for row in report["findings"]))
            observation = next(row for row in report["unbound_observations"]
                               if row["rule"] == "dangerous-eval")
            self.assertEqual(observation["path"], attestor41.UNBOUND_PATH)
            self.assertTrue(truth_guard41.verify_guarded(report, root=self.root)["ok"])
        finally:
            outside.unlink(missing_ok=True)
            outside_root.rmdir()

    def test_unbound_sentinel_never_binds_even_if_workspace_contains_that_name(self) -> None:
        sentinel = self.root / "__attestor_unbound__" / "outside-or-invalid-path"
        sentinel.parent.mkdir()
        sentinel.write_text("value = 1\n", encoding="utf-8")
        report = self.maximum(self.base(path=str(self.root.parent / "outside.py")))
        self.assertFalse(any(row["rule"] == "dangerous-eval"
                             for row in report["findings"]))
        self.assertTrue(any(row["path"] == attestor41.UNBOUND_PATH
                            for row in report["unbound_observations"]))

    def test_tampering_is_withheld(self) -> None:
        report = self.maximum()
        report["findings"][0]["message"] = "tampered"
        public = attestor41.safe_public_report(report, root=self.root)
        self.assertEqual(public["status"], "inconsistent")
        self.assertEqual(public["findings"], [])

    def test_staged_secret_is_not_misbound_to_current_worktree_bytes(self) -> None:
        security, _attestation = attestor41._replay_augmented_worker_report(
            self.security(), "security-static")
        security["secret_lifecycle"] = {
            "status": "complete", "gaps": [],
            "findings": [{"rule_id": "aws-access-key", "severity": "high",
                          "source_kind": "staged-diff", "path": "app.py",
                          "line": 1, "evidence": "secret-shaped value; material withheld",
                           "value_exposed": False, "value_hashed": False}],
        }
        security["report_sha256"] = attestor41._sha({
            key: item for key, item in security.items()
            if key != "report_sha256"
        })
        security = self.augmented_worker(security, "security-static")
        report = self.maximum(self.base(path="workspace"),
                              security_evidence=security,
                              staged_diff="+AKIAABCDEFGHIJKLMNOP")
        self.assertFalse(any(row["rule"] == "aws-access-key"
                             for row in report["findings"]))
        observation = next(row for row in report["unbound_observations"]
                           if row["rule"] == "aws-access-key")
        self.assertEqual(observation["source_kind"], "staged-diff")
        self.assertIn("not current worktree", observation["reason"])
        self.assertEqual(report["status"], "action-required")
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.root)["ok"])

    def test_exact_file_scope_is_not_widened_for_new_workers(self) -> None:
        base = self.base()
        base["root"] = str(self.source)
        guarded = self.guarded_compatibility(base)
        with mock.patch.object(attestor41.attestor40, "maximum", return_value={}), \
                mock.patch.object(attestor41.attestor40, "safe_public_report",
                                  return_value=guarded), \
                mock.patch.object(attestor41, "_worker") as worker:
            report = attestor41.maximum(self.source, improve=False)
        worker.assert_not_called()
        self.assertTrue(report["coverage"]["exact_file_scope_preserved"])
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.source)["ok"])

    def test_intentionally_omitted_legacy_components_remain_valid(self) -> None:
        report = attestor41.maximum(
            self.source, improve=False, max_improvement_files=0,
            use_cache=False, legacy_components=())
        self.assertEqual(report["engineering"]["status"], "not-run")
        self.assertEqual(report["security_fabric"]["status"], "not-run")
        self.assertTrue(
            attestor41._verify_expected_public_projection_layout(report))
        self.assertTrue(
            truth_guard41.verify_guarded(report, root=self.source)["ok"])

    def test_exact_file_scope_quarantines_a_different_same_named_file(self) -> None:
        other_root = self.root / "other"
        other_root.mkdir()
        outside = other_root / "app.py"
        outside.write_text("value = eval(data)\n", encoding="utf-8")
        base = self.base(path=str(outside))
        base["root"] = str(self.source)
        guarded = self.guarded_compatibility(base)
        with mock.patch.object(attestor41.attestor40, "maximum", return_value={}), \
                mock.patch.object(attestor41.attestor40, "safe_public_report",
                                  return_value=guarded):
            report = attestor41.maximum(self.source, improve=False)
        self.assertFalse(report["findings"])
        self.assertEqual(report["unbound_observations"][0]["path"],
                         attestor41.UNBOUND_PATH)
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.source)["ok"])

    def test_public_caps_report_every_omitted_finding_and_observation(self) -> None:
        base = self.base()
        base["findings"] = [
            {"rule": "bound-%d" % index, "severity": "MEDIUM",
             "path": "app.py", "line": index + 1,
             "message": "bound observation %d" % index, "fix": "review"}
            for index in range(3)
        ] + [
            {"rule": "unbound-%d" % index, "severity": "LOW",
             "path": "workspace", "line": 1,
             "message": "unbound observation %d" % index, "fix": "review"}
            for index in range(3)
        ]
        with mock.patch.object(attestor41, "MAX_FINDINGS", 1), \
                mock.patch.object(attestor41, "MAX_UNBOUND_OBSERVATIONS", 1):
            report = self.maximum(base)
        self.assertEqual(len(report["findings"]), 1)
        self.assertGreater(report["summary"]["findings_truncated"], 0)
        self.assertEqual(len(report["unbound_observations"]), 1)
        self.assertGreater(report["summary"]["unbound_observations_truncated"], 0)
        self.assertTrue(any("omitted" in gap for gap in report["coverage"]["gaps"]))
        self.assertTrue(truth_guard41.verify_guarded(report, root=self.root)["ok"])

    def test_analysis_config_binds_result_affecting_nonsecret_inputs(self) -> None:
        observations = ({"confidence": 0.75, "correct": True} for _ in range(1))
        report = self.maximum(
            issue="fix the parser", max_improvement_files=2,
            test_command=("python", "-m", "unittest"), authorize_tests=True,
            advisory_snapshot={"packages": []}, advisory_keys={"trusted-1": b"secret"},
            memory_baseline={"schema": "baseline"},
            calibration_profile={"threshold": 0.8},
            calibration_observations=observations,
            git_base="HEAD~1", symbolic_timeout=12.5,
            truth_key=b"k" * 32, truth_key_id="truth-test")
        config = report["analysis_config"]
        self.assertEqual(config["issue"]["bytes"], len("fix the parser"))
        self.assertTrue(config["test_command_sha256"])
        self.assertTrue(config["tests_authorized"])
        self.assertEqual(config["advisory_trusted_key_ids"], ["trusted-1"])
        self.assertNotIn("secret", str(config))
        self.assertTrue(config["calibration_observations_sha256"])
        self.assertEqual(config["git_base"], "HEAD~1")
        self.assertEqual(config["truth_authentication"]["key_id"], "truth-test")
        self.assertTrue(truth_guard41.verify_guarded(
            report, root=self.root, key=b"k" * 32)["ok"])

    def test_worker_boundary_errors_become_coverage_evidence(self) -> None:
        with mock.patch.object(attestor41.bounded_worker41, "run",
                              side_effect=attestor41.bounded_worker41.WorkerError("too large")):
            result, gaps = attestor41._worker("coding-static", {"root": str(self.root)})
        self.assertIsNone(result)
        self.assertIn("failed closed", gaps[0])

    def test_worker_failures_are_counted_as_component_errors(self) -> None:
        base = self.base()
        guarded = self.guarded_compatibility(base)
        with mock.patch.object(attestor41.attestor40, "maximum", return_value={}), \
                mock.patch.object(attestor41.attestor40, "safe_public_report",
                                  return_value=guarded), \
                mock.patch.object(attestor41, "_worker", return_value=(None, ["worker failed closed"])), \
                mock.patch.object(attestor41.repair_director41, "direct", return_value=self.repair()):
            report = attestor41.maximum(self.root, improve=False)
        self.assertEqual(report["summary"]["component_errors"], 4)
        self.assertFalse(report["coverage"]["complete"])

    def test_identical_regression_baseline_is_not_replayed_or_fatal(self) -> None:
        first = self.maximum()
        memory = first["security_regression_memory_413"]
        second = self.maximum(memory_baseline=memory)
        self.assertNotEqual(second["status"], "failed")
        self.assertEqual(
            second["security_regression_memory_413"]["report_sha256"],
            memory["report_sha256"])
        self.assertTrue(any(
            "already present" in gap for gap in second["coverage"]["gaps"]))
        self.assertTrue(
            truth_guard41.verify_guarded(second, root=self.root)["ok"])

    def test_aggregate_semantic_packs_fail_at_orchestrator_boundary(self) -> None:
        packs = [{"name": "a", "payload": "a" * 250_000},
                 {"name": "b", "payload": "b" * 160_000}]
        with self.assertRaisesRegex(attestor41.Attestor41Error, "aggregate"):
            attestor41._load_semantic_packs(packs)

    def test_semantic_pack_files_reject_duplicate_keys_and_bound_the_actual_read(self) -> None:
        pack_path = self.root / "rules.json"
        pack_path.write_text(
            '{"schema":"first","schema":"second","rules":[]}', encoding="utf-8")
        with self.assertRaisesRegex(attestor41.Attestor41Error, "duplicate"):
            attestor41._load_semantic_packs([pack_path])

        pack_path.write_text("{}", encoding="utf-8")
        opened = mock.mock_open()
        opened.return_value.read.return_value = b"x" * (attestor41.MAX_RULE_PACK_BYTES + 1)
        with mock.patch.object(Path, "open", opened), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
            with self.assertRaisesRegex(attestor41.Attestor41Error, "oversized"):
                attestor41._load_semantic_packs([pack_path])
        opened.return_value.read.assert_called_once_with(attestor41.MAX_RULE_PACK_BYTES + 1)

    def test_link_root_is_rejected_before_resolution(self) -> None:
        linked = self.root.parent / (self.root.name + "-link")
        try:
            linked.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest("directory symlink privilege unavailable: %s" % type(exc).__name__)
        try:
            with self.assertRaisesRegex(attestor41.Attestor41Error, "link|reparse"):
                attestor41.maximum(linked, improve=False)
        finally:
            linked.unlink(missing_ok=True)

    def test_research_wrapper_denies_network_by_default(self) -> None:
        report = attestor41.research("What caused the 1908 Tunguska event?")
        self.assertEqual(report["status"], "network-authorization-required")
        self.assertFalse(report["execution"]["network_accessed"])

    def test_hmac_report_replays_with_the_shared_key(self) -> None:
        key = b"k" * 32
        report = self.maximum(truth_key=key, truth_key_id="test")
        good = truth_guard41.verify_guarded(report, root=self.root, key=key)
        bad = truth_guard41.verify_guarded(report, root=self.root, key=b"x" * 32)
        self.assertTrue(good["ok"])
        self.assertTrue(good["authenticated"])
        self.assertFalse(bad["ok"])


if __name__ == "__main__":
    unittest.main()
