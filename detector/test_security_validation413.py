from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import security_validation413 as validation


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class SecurityValidation413Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        (self.root / "app.py").write_text("print('safe')\n", encoding="utf-8")
        self.key = b"k" * 32
        self.clock_value = 1_800_000_000
        self.registry = validation.ApprovalRegistry(
            self.key, clock=lambda: self.clock_value)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def plan(self) -> dict:
        return validation.create_sandbox_plan(
            self.root, [["python", "-m", "unittest"]],
            patch_sha256=digest("patch"),
            image="python@sha256:" + "1" * 64,
        )

    def test_tree_manifest_is_content_addressed_and_verified(self) -> None:
        first = validation.tree_manifest(self.root)
        second = validation.tree_manifest(self.root)
        self.assertEqual(first["report_sha256"], second["report_sha256"])
        self.assertEqual(first["file_count"], 1)
        self.assertTrue(validation.verify_report(
            first, schema="attestor-project-manifest/4.1")[0])

    def test_tree_manifest_rejects_link_when_supported(self) -> None:
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("x", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            self.skipTest("link creation is unavailable")
        with self.assertRaises(validation.ValidationError):
            validation.tree_manifest(self.root)

    def test_sandbox_plan_defaults_to_network_none_and_no_execution(self) -> None:
        plan = self.plan()
        self.assertEqual(plan["container"]["network"], "none")
        self.assertFalse(plan["execution"]["target_executed"])
        self.assertTrue(validation.verify_report(
            plan, schema="attestor-security-sandbox-plan/4.1")[0])
        argv = validation.container_invocations(plan, self.root)[0]
        self.assertIn("--network=none", argv)
        self.assertNotIn("shell", argv)

    def test_sandbox_rejects_unpinned_image_and_unapproved_executable(self) -> None:
        with self.assertRaises(validation.ValidationError):
            validation.create_sandbox_plan(
                self.root, [["python", "-V"]], patch_sha256=digest("p"),
                image="python:latest")
        with self.assertRaises(validation.ValidationError):
            validation.create_sandbox_plan(
                self.root, [["powershell", "-Command", "x"]],
                patch_sha256=digest("p"),
                image="python@sha256:" + "1" * 64)

    def test_authorization_requires_exact_true_and_is_one_use(self) -> None:
        plan = self.plan()
        root_digest = plan["project_root_identity_sha256"]
        with self.assertRaises(validation.ValidationError):
            self.registry.issue(
                root_identity_sha256=root_digest,
                patch_sha256=plan["patch_sha256"],
                plan_sha256=plan["report_sha256"],
                purpose="sandbox-execution", confirmed=1)
        token = self.registry.issue(
            root_identity_sha256=root_digest,
            patch_sha256=plan["patch_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            nonce="a" * 48,
        )
        result = validation.authorize_sandbox(
            plan, self.registry, token, current_root=self.root)
        self.assertEqual(result["status"], "authorized-once")
        self.assertFalse(result["execution_started"])
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                plan, self.registry, token, current_root=self.root)

    def test_authorization_is_patch_plan_and_root_bound(self) -> None:
        plan = self.plan()
        token = self.registry.issue(
            root_identity_sha256=plan["project_root_identity_sha256"],
            patch_sha256=plan["patch_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            nonce="b" * 48,
        )
        changed = dict(plan)
        changed["patch_sha256"] = digest("other")
        changed["report_sha256"] = validation._sha({
            key: value for key, value in changed.items()
            if key != "report_sha256"})
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                changed, self.registry, token, current_root=self.root)

    def test_authorization_expires(self) -> None:
        plan = self.plan()
        token = self.registry.issue(
            root_identity_sha256=plan["project_root_identity_sha256"],
            patch_sha256=plan["patch_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            ttl_seconds=2, nonce="c" * 48,
        )
        self.clock_value += 2
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                plan, self.registry, token, current_root=self.root)

    def test_authorization_cannot_replay_in_a_new_registry_or_reissue_nonce(self) -> None:
        plan = self.plan()
        token = self.registry.issue(
            root_identity_sha256=plan["project_root_identity_sha256"],
            patch_sha256=plan["patch_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            nonce="9" * 48)
        other = validation.ApprovalRegistry(
            self.key, clock=lambda: self.clock_value)
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                plan, other, token, current_root=self.root)
        with self.assertRaises(validation.ValidationError):
            self.registry.issue(
                root_identity_sha256=plan["project_root_identity_sha256"],
                patch_sha256=plan["patch_sha256"],
                plan_sha256=plan["report_sha256"],
                purpose="sandbox-execution", confirmed=True,
                nonce="9" * 48)
        accepted = validation.authorize_sandbox(
            plan, self.registry, token, current_root=self.root)
        self.assertEqual(accepted["status"], "authorized-once")

    def test_rehashed_fail_open_sandbox_shape_is_rejected(self) -> None:
        plan = self.plan()
        forged = copy.deepcopy(plan)
        forged["container"]["network"] = "host"
        forged["execution"]["target_executed"] = True
        forged["report_sha256"] = validation._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"})
        valid, errors = validation.verify_report(
            forged, schema="attestor-security-sandbox-plan/4.1")
        self.assertFalse(valid)
        self.assertTrue(any(
            "container" in error or "execution" in error for error in errors))
        token = self.registry.issue(
            root_identity_sha256=forged["project_root_identity_sha256"],
            patch_sha256=forged["patch_sha256"],
            plan_sha256=forged["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            nonce="8" * 48)
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                forged, self.registry, token, current_root=self.root)

    def test_container_invocation_refuses_stale_or_different_content(self) -> None:
        plan = self.plan()
        token = self.registry.issue(
            root_identity_sha256=plan["project_root_identity_sha256"],
            patch_sha256=plan["patch_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="sandbox-execution", confirmed=True,
            nonce="7" * 48)
        (self.root / "app.py").write_text(
            "print('changed')\n", encoding="utf-8")
        with self.assertRaises(validation.ValidationError):
            validation.authorize_sandbox(
                plan, self.registry, token, current_root=self.root)
        with self.assertRaises(validation.ValidationError):
            validation.container_invocations(plan, self.root)

    def test_sandbox_arguments_reject_controls_and_executable_paths(self) -> None:
        image = "python@sha256:" + "1" * 64
        for command in (
                ["python", "line\nbreak"],
                ["./python", "-V"],
                ["tools/python", "-V"]):
            with self.subTest(command=command):
                with self.assertRaises(validation.ValidationError):
                    validation.create_sandbox_plan(
                        self.root, [command], patch_sha256=digest("p"),
                        image=image)

    def test_test_plans_do_not_contain_exploit_payloads(self) -> None:
        report = validation.generate_test_plans(
            [{"id": "api.create", "path": "api.py"}],
            [{"rule": "AUTH-1"}])
        self.assertEqual(report["plan_count"], 3)
        self.assertTrue(all(
            row["generator"]["offensive_payloads"] is False
            for row in report["plans"]))
        self.assertFalse(report["execution"]["target_executed"])
        self.assertTrue(report["coverage"]["complete"])
        truncated = validation.generate_test_plans(
            [{"id": "api.create", "path": "api.py"}], [],
            maximum=2)
        self.assertFalse(truncated["coverage"]["complete"])
        self.assertEqual(truncated["plan_count"], 2)

    def test_unbounded_test_plan_iterable_fails_at_boundary(self) -> None:
        def entries():
            for index in range(4_001):
                yield {"id": "entry-%d" % index, "path": "api.py"}
        with self.assertRaises(validation.ValidationError):
            validation.generate_test_plans(entries(), [])

    def test_canonical_json_preflight_rejects_large_or_recursive_shapes(self) -> None:
        with self.assertRaises(validation.ValidationError):
            validation._canonical({
                "rows": [None] * (validation.MAX_ENTRIES + 1)})
        recursive = []
        recursive.append(recursive)
        with self.assertRaises(validation.ValidationError):
            validation._canonical(recursive)

    def test_minimizer_requires_authorization_and_is_bounded(self) -> None:
        predicate = digest("predicate")
        with self.assertRaises(validation.ValidationError):
            validation.minimize_observed_case(
                [1, 2, 3], lambda value: 3 in value,
                registry=self.registry, token={},
                predicate_sha256=predicate)
        plan = validation.create_minimization_plan(
            [1, 2, 3, 4], predicate_sha256=predicate,
            maximum_evaluations=20)
        token = self.registry.issue(
            root_identity_sha256=plan["case_sha256"],
            patch_sha256=plan["predicate_sha256"],
            plan_sha256=plan["report_sha256"],
            purpose="case-minimization", confirmed=True,
            nonce="f" * 48)
        report = validation.minimize_observed_case(
            [1, 2, 3, 4], lambda value: 3 in value,
            registry=self.registry, token=token,
            predicate_sha256=predicate, maximum_evaluations=20)
        self.assertEqual(report["minimized_case"], [3])
        self.assertLessEqual(report["evaluations"], 20)
        self.assertFalse(report["permission_retained"])

    def _complete_pipeline(self) -> dict:
        pipeline = validation.new_repair_pipeline(
            root_identity_sha256=digest("root"),
            patch_sha256=digest("patch"),
            baseline_sha256=digest("baseline"))
        current = digest("patch")
        for index, gate in enumerate(validation.GATE_ORDER):
            following = digest("gate-%d" % index)
            pipeline = validation.record_repair_gate(
                pipeline, gate, {
                    "status": "passed",
                    "input_sha256": current,
                    "output_sha256": following,
                    "executed": True,
                    "network_accessed": False,
                    "summary": "passed",
                })
            current = following
        return pipeline

    def test_repair_gates_are_ordered_and_apply_is_separately_authorized(self) -> None:
        pipeline = validation.new_repair_pipeline(
            root_identity_sha256=digest("root"),
            patch_sha256=digest("patch"),
            baseline_sha256=digest("baseline"))
        with self.assertRaises(validation.ValidationError):
            validation.record_repair_gate(pipeline, "test", {
                "status": "passed", "input_sha256": digest("patch"),
                "output_sha256": digest("o"), "executed": True,
                "network_accessed": False, "summary": "x"})
        pipeline = self._complete_pipeline()
        token = self.registry.issue(
            root_identity_sha256=pipeline["root_identity_sha256"],
            patch_sha256=pipeline["patch_sha256"],
            plan_sha256=pipeline["report_sha256"],
            purpose="repair-apply", confirmed=True, nonce="d" * 48)
        result = validation.authorize_repair_apply(
            pipeline, self.registry, token)
        self.assertFalse(result["source_changed"])
        self.assertFalse(result["permission_retained"])

    def test_incomplete_repair_cannot_be_approved(self) -> None:
        pipeline = validation.new_repair_pipeline(
            root_identity_sha256=digest("root"),
            patch_sha256=digest("patch"),
            baseline_sha256=digest("baseline"))
        token = self.registry.issue(
            root_identity_sha256=pipeline["root_identity_sha256"],
            patch_sha256=pipeline["patch_sha256"],
            plan_sha256=pipeline["report_sha256"],
            purpose="repair-apply", confirmed=True, nonce="e" * 48)
        with self.assertRaises(validation.ValidationError):
            validation.authorize_repair_apply(
                pipeline, self.registry, token)

    def test_repair_gate_rejects_network_access(self) -> None:
        pipeline = validation.new_repair_pipeline(
            root_identity_sha256=digest("root"),
            patch_sha256=digest("patch"),
            baseline_sha256=digest("baseline"))
        with self.assertRaises(validation.ValidationError):
            validation.record_repair_gate(pipeline, "static-scan", {
                "status": "passed", "input_sha256": digest("patch"),
                "output_sha256": digest("scan"), "executed": True,
                "network_accessed": True, "summary": "unexpected download"})

    def test_regression_memory_is_project_namespaced(self) -> None:
        first = validation.new_regression_memory(digest("root-a"))
        second = validation.new_regression_memory(digest("root-b"))
        self.assertNotEqual(
            first["project_namespace"], second["project_namespace"])
        first = validation.record_security_run(
            first, report_sha256=digest("r1"),
            finding_fingerprints=[digest("a"), digest("b")], observed_at=1)
        first = validation.record_security_run(
            first, report_sha256=digest("r2"),
            finding_fingerprints=[digest("b"), digest("c")], observed_at=2)
        comparison = validation.compare_security_runs(first)
        self.assertEqual(comparison["new"], [digest("c")])
        self.assertEqual(comparison["resolved"], [digest("a")])
        self.assertFalse(comparison["cross_project_comparison"])

    def test_regression_memory_rejects_time_rollback_and_report_replay(self) -> None:
        memory = validation.new_regression_memory(digest("root"))
        memory = validation.record_security_run(
            memory, report_sha256=digest("report-one"),
            finding_fingerprints=[], observed_at=10)
        with self.assertRaises(validation.ValidationError):
            validation.record_security_run(
                memory, report_sha256=digest("report-two"),
                finding_fingerprints=[], observed_at=9)
        with self.assertRaises(validation.ValidationError):
            validation.record_security_run(
                memory, report_sha256=digest("report-one"),
                finding_fingerprints=[], observed_at=11)

    def test_proven_claim_requires_exact_evidence(self) -> None:
        with self.assertRaises(validation.ValidationError):
            validation.claim_ledger([{
                "text": "safe", "state": "proven", "evidence": []}])
        scan_digest = digest("scan")
        ledger = validation.claim_ledger([{
            "text": "The check ran.", "state": "proven",
            "evidence": [{
                "kind": "report", "locator": "scan",
                "sha256": scan_digest}],
            "limitation": "bounded static evidence",
        }, {
            "text": "No runtime proof.", "state": "unavailable",
            "evidence": [], "limitation": "not executed",
        }], verified_evidence_sha256=[scan_digest])
        self.assertEqual(ledger["counts"]["proven"], 1)
        self.assertEqual(ledger["counts"]["unavailable"], 1)
        self.assertEqual(ledger["verified_evidence_sha256"], [scan_digest])
        self.assertTrue(validation.verify_report(
            ledger, schema=validation.LEDGER_SCHEMA)[0])
        forged = copy.deepcopy(ledger)
        forged_digest = digest("unverified-scan")
        forged["claims"][0]["evidence"][0]["sha256"] = forged_digest
        forged["claims"][0]["claim_id"] = validation._sha({
            "text": forged["claims"][0]["text"],
            "state": forged["claims"][0]["state"],
            "evidence": forged["claims"][0]["evidence"],
            "limitation": forged["claims"][0]["limitation"],
        })[:24]
        forged["report_sha256"] = validation._sha({
            key: value for key, value in forged.items()
            if key != "report_sha256"})
        self.assertFalse(validation.verify_report(
            forged, schema=validation.LEDGER_SCHEMA)[0])

    def test_command_center_escapes_controls_and_never_auto_applies(self) -> None:
        center = validation.command_center(
            findings=[{
                "rule": "AUTH\x1b[31m", "severity": "HIGH",
                "path": "api\u202efile.py", "line": 4,
                "evidence_state": "inferred",
            }],
            attack_paths=[{
                "id": "p1", "title": "request to database",
                "exploitability": "medium", "evidence_state": "inferred",
            }],
            coverage_gaps=["runtime not observed"])
        rendered = str(center)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertFalse(center["automatic_apply"])
        self.assertEqual(center["raw_secret_values_present"], "not-assessed")

    def test_command_center_counts_only_supported_rows_and_marks_gaps(self) -> None:
        center = validation.command_center(
            findings=[None, "invalid", {
                "rule": "AUTH-1", "severity": "HIGH", "path": "api.py",
                "line": 1, "evidence_state": "inferred"}],
            attack_paths=[None, {"id": "path", "title": "bounded",
                                 "evidence_state": "inferred"}],
            coverage_gaps=[{"reason": "runtime not observed"}])
        self.assertEqual(center["metrics"]["findings"], 1)
        self.assertEqual(center["metrics"]["attack_paths"], 1)
        self.assertEqual(center["metrics"]["coverage_gaps"], 1)
        self.assertEqual(center["status"], "action-required")
        self.assertEqual(center["coverage_gaps"], ["runtime not observed"])
        self.assertTrue(validation.verify_report(
            center, schema=validation.COMMAND_CENTER_SCHEMA)[0])
        malformed = copy.deepcopy(center)
        malformed["metrics"]["findings"] = "many"
        malformed["report_sha256"] = validation._sha({
            key: value for key, value in malformed.items()
            if key != "report_sha256"})
        self.assertFalse(validation.verify_report(
            malformed, schema=validation.COMMAND_CENTER_SCHEMA)[0])

    def test_command_center_ui_downgrades_unverified_proof_and_escapes_controls(self) -> None:
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        ui_root = Path(__file__).parent / "ui"
        script = (ui_root / "ui23.js").read_text(encoding="utf-8")
        html = (ui_root / "index.html").read_text(encoding="utf-8")
        integer = script[script.index("function safeInteger("):
                         script.index("function delay(")]
        helpers = script[script.index("function safeText("):
                         script.index("function firstDefined(")]
        command = script[script.index("function normalizedCommandCenter("):
                         script.index("function parseStructuredOutput(")]
        fixture = {
            "schema": validation.COMMAND_CENTER_SCHEMA,
            "version": validation.VERSION,
            "status": "no-findings-within-bounded-evidence",
            "metrics": {
                "findings": 0,
                "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                             "LOW": 0, "INFO": 0},
                "attack_paths": 1,
                "coverage_gaps": 0,
                "claim_states": {"proven": 1, "inferred": 0,
                                 "unverified": 0, "unavailable": 0},
            },
            "attack_paths": [{
                "id": "p1", "title": "path\u202e", "exploitability": "low",
                "evidence_state": "proven"}],
            "coverage_gaps": [],
            "repair_status": "not-started",
            "repair_proof_state": "unavailable",
            "regression_status": "not-compared",
            "source_reports": {
                "repair_pipeline_integrity_verified": False,
                "regression_integrity_verified": False,
                "claim_ledger_integrity_verified": False,
            },
            "automatic_apply": False,
            "permission_retained": False,
            "raw_secret_values_present": "not-assessed",
            "report_sha256": "a" * 64,
        }
        program = (
            integer + helpers +
            "\nfunction triState(value){return value===true?true:value===false?false:null;}\n" +
            command + "\nconst fixture=" + json.dumps(fixture) + ";\n" +
            "const center=normalizedCommandCenter({security_command_center_413:fixture});\n" +
            "if(!center||center.rawSecretsPresent!==null)process.exit(2);\n" +
            "bindCommandCenterIntegrity(center,null);\n" +
            "if(center.claims.proven!==0||center.claims.unverified!==1||" +
            "center.attackPaths[0].evidenceState!=='unverified')process.exit(3);\n" +
            "bindCommandCenterIntegrity(center,{applicable:true,verified:true,fresh:true});\n" +
            "if(center.claims.proven!==1||center.attackPaths[0].evidenceState!=='proven')process.exit(4);\n" +
            "const escaped=safeText('x\\u202ey\\u001b', '', 100);\n" +
            "if(escaped.includes('\\u202e')||escaped.includes('\\u001b')||" +
            "!escaped.includes('\\\\u202e')||!escaped.includes('\\\\u001b'))process.exit(5);\n" +
            "const bad={...fixture};delete bad.report_sha256;" +
            "if(normalizedCommandCenter({security_command_center_413:bad})!==null)process.exit(6);\n"
        )
        completed = subprocess.run(
            [node, "-e", program], capture_output=True, text=True,
            timeout=10)
        self.assertEqual(
            completed.returncode, 0, completed.stderr or completed.stdout)
        self.assertIn('id="commandCenterGrid" hidden', html)
        self.assertIn("Proof is shown only for freshly verified durable reports", html)
        self.assertNotIn("innerHTML", command)

    def test_capability_report_is_default_deny(self) -> None:
        report = validation.capability_report()
        self.assertEqual(report["status"], "available-default-deny")
        self.assertEqual(report["defaults"]["target_execution"], "denied")
        self.assertFalse(report["defaults"]["permission_retention"])
        self.assertTrue(validation.verify_report(report)[0])


if __name__ == "__main__":
    unittest.main()
