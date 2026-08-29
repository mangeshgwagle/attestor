from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import response41
import truth_guard41


class TruthGuard41Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "app.py"
        self.source.write_text("value = input()\nprint(value)\n", encoding="utf-8")
        self.report = {
            "schema": "fixture/4.1", "version": "4.1.3", "root": str(self.root),
            "coverage": {"complete": True, "gaps": []},
            "findings": [{"rule": "fixture-taint", "severity": "HIGH", "path": "app.py",
                          "line": 2, "message": "Untrusted value reaches output.",
                          "fix": "Encode the value."}],
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_exact_source_binding_and_replay(self):
        guarded = truth_guard41.guard_document(self.report, root=self.root)
        evidence = guarded["truth_guard3"]["finding_evidence"][0]
        self.assertEqual(evidence["state"], "bound")
        self.assertEqual(evidence["source"]["path"], "app.py")
        self.assertEqual(len(evidence["source"]["file_sha256"]), 64)
        result = truth_guard41.replay_verify(guarded, self.root)
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["fresh"])

    def test_stale_source_is_refused(self):
        guarded = truth_guard41.guard_document(self.report, root=self.root)
        self.source.write_text("value = 'changed'\nprint(value)\n", encoding="utf-8")
        result = truth_guard41.replay_verify(guarded, self.root)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "stale")

    def test_shared_key_authentication_is_not_mislabeled_public_key(self):
        key = b"k" * 32
        guarded = truth_guard41.guard_document(self.report, root=self.root, key=key, key_id="fixture")
        verified = truth_guard41.verify_guarded(guarded, root=self.root, key=key)
        self.assertTrue(verified["authenticated"])
        self.assertFalse(verified["public_key_authenticated"])
        self.assertFalse(guarded["truth_guard3"]["signature"]["non_repudiation"])

    def test_invalid_finding_does_not_misalign_later_claim(self):
        report = dict(self.report)
        report["findings"] = ["invalid", self.report["findings"][0]]
        guarded = truth_guard41.guard_document(report, root=self.root)
        facts = response41.build_fact_model(guarded, root=self.root)
        self.assertTrue(facts["verified"])
        self.assertEqual(facts["bound_findings"], 1)
        self.assertEqual(facts["claims"][0]["rule"], "fixture-taint")

    def test_response_abstains_after_source_changes(self):
        guarded = truth_guard41.guard_document(self.report, root=self.root)
        self.source.write_text("changed = True\n", encoding="utf-8")
        answer = response41.answer_question(guarded, "How do I fix fixture-taint?", root=self.root)
        self.assertFalse(answer["answered"])
        self.assertEqual(answer["scope"], "report-only")

    def test_partial_nested_coverage_prevents_clean_posture_claim(self):
        report = {**self.report, "coverage": {}, "findings": [],
                  "engineering": {"coverage": {"complete": False,
                                                   "gaps": [{"message": "parser unavailable"}]}}}
        guarded = truth_guard41.guard_document(report, root=self.root)
        rendered = response41.render_guarded(guarded, root=self.root)
        self.assertIn("coverage is partial", rendered.lower())
        self.assertIn("parser unavailable", rendered)

    def test_out_of_range_line_is_unbound_not_clamped_to_last_line(self):
        report = {**self.report, "findings": [{**self.report["findings"][0], "line": 999}]}
        guarded = truth_guard41.guard_document(report, root=self.root)
        evidence = guarded["truth_guard3"]["finding_evidence"][0]
        self.assertEqual(evidence["state"], "unbound")
        self.assertIn("outside the source file", evidence["reason"])
        self.assertEqual(evidence["source"]["snippet_bytes"], 0)
        self.assertEqual(guarded["truth_guard3"]["status"], "partial")

    def test_digest_consistent_byte_range_tamper_cannot_rebind_a_different_line(self):
        guarded = truth_guard41.guard_document(self.report, root=self.root)
        ledger = guarded["truth_guard3"]
        binding = ledger["finding_evidence"][0]
        raw = self.source.read_bytes()
        start, end = truth_guard41._line_range(raw, 1)
        binding["source"].update({"byte_start": start, "byte_end": end,
                                   "snippet_bytes": end - start,
                                   "snippet_sha256": truth_guard41._sha(raw[start:end])})
        binding["evidence_sha256"] = truth_guard41._sha(
            {key: value for key, value in binding.items() if key != "evidence_sha256"})
        ledger["finding_evidence_sha256"] = truth_guard41._sha(ledger["finding_evidence"])
        ledger["ledger_sha256"] = truth_guard41._sha(
            {key: value for key, value in ledger.items() if key != "ledger_sha256"})
        replay = truth_guard41.replay_verify(guarded, self.root)
        self.assertFalse(replay["ok"])
        self.assertEqual(replay["status"], "stale")
        self.assertTrue(any("source evidence is stale" in error for error in replay["errors"]))

    def test_empty_file_line_one_has_an_explicit_empty_binding(self):
        empty = self.root / "empty.py"
        empty.write_bytes(b"")
        report = {**self.report, "findings": [{**self.report["findings"][0],
                                                "path": "empty.py", "line": 1}]}
        guarded = truth_guard41.guard_document(report, root=self.root)
        evidence = guarded["truth_guard3"]["finding_evidence"][0]
        self.assertEqual(evidence["state"], "bound")
        self.assertEqual((evidence["source"]["byte_start"], evidence["source"]["byte_end"]), (0, 0))

    def test_full_root_inventory_detects_unreferenced_changes_and_tree_drift(self):
        extra = self.root / "unreferenced.py"
        extra.write_text("VERSION = 1\n", encoding="utf-8")
        guarded = truth_guard41.guard_document(self.report, root=self.root)
        ledger = guarded["truth_guard3"]
        self.assertEqual(ledger["input_manifest_scope"], "complete-selected-root-inventory")
        paths = {row["path"] for row in ledger["input_manifest"]}
        self.assertIn("unreferenced.py", paths)
        self.assertTrue(truth_guard41.replay_verify(guarded, self.root)["ok"])

        extra.write_text("VERSION = 2\n", encoding="utf-8")
        changed = truth_guard41.replay_verify(guarded, self.root)
        self.assertFalse(changed["ok"])
        self.assertEqual(changed["status"], "stale")
        self.assertTrue(any("input manifest is stale" in error for error in changed["errors"]))

        extra.write_text("VERSION = 1\n", encoding="utf-8")
        added = self.root / "new.py"
        added.write_text("NEW = True\n", encoding="utf-8")
        self.assertEqual(truth_guard41.replay_verify(guarded, self.root)["status"], "stale")
        added.unlink()
        self.assertTrue(truth_guard41.replay_verify(guarded, self.root)["ok"])
        extra.unlink()
        self.assertEqual(truth_guard41.replay_verify(guarded, self.root)["status"], "stale")

    def test_finding_paths_reject_lexical_file_and_parent_links(self):
        file_link = self.root / "alias.py"
        directory = self.root / "real"
        directory.mkdir()
        nested = directory / "nested.py"
        nested.write_text("print('ok')\n", encoding="utf-8")
        directory_link = self.root / "alias-dir"
        try:
            file_link.symlink_to(self.source)
            directory_link.symlink_to(directory, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("link creation is unavailable on this platform: %s" % exc)
        for path in ("alias.py", "alias-dir/nested.py"):
            with self.subTest(path=path):
                report = {**self.report, "findings": [{**self.report["findings"][0], "path": path}]}
                guarded = truth_guard41.guard_document(report, root=self.root)
                evidence = guarded["truth_guard3"]["finding_evidence"][0]
                self.assertEqual(evidence["state"], "unbound")
                self.assertIn("link or reparse point", evidence["reason"])
                self.assertEqual(guarded["truth_guard3"]["status"], "partial")

    def test_inconsistent_but_replay_valid_report_is_withheld(self):
        report = {**self.report, "status": "inconsistent", "findings": []}
        guarded = truth_guard41.guard_document(report, root=self.root)
        self.assertTrue(truth_guard41.replay_verify(guarded, self.root)["ok"])
        rendered = response41.render_guarded(guarded, root=self.root)
        self.assertIn("withheld", rendered.lower())
        self.assertIn("inconsistent", rendered.lower())
        answer = response41.answer_question(guarded, "Is this safe?", root=self.root)
        self.assertFalse(answer["answered"])
        self.assertEqual(answer["abstained_reason"], "inconsistent-report")

    def test_response_escapes_terminal_and_bidi_controls_and_normalizes_severity(self):
        report = {**self.report, "findings": [{**self.report["findings"][0],
                                                "severity": "invented",
                                                "message": "bad\x1b[31m\x85\u202efile"}]}
        guarded = truth_guard41.guard_document(report, root=self.root)
        rendered = response41.render_guarded(guarded, root=self.root)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x85", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn(r"bad\x1b[31m\x85\u202efile", rendered)
        self.assertIn("[MEDIUM]", rendered)
        answer = response41.answer_question(guarded, "How many medium findings?", root=self.root)
        self.assertEqual(answer["answer"], "1 matching source-bound finding(s).")

    def test_response_surfaces_command_center_without_promoting_static_proof(self):
        report = {
            **self.report,
            "findings": [{**self.report["findings"][0],
                          "evidence_state": "inferred"}],
            "security_command_center_413": {
                "schema": "attestor-security-command-center/4.1",
                "version": "4.1.3",
                "status": "action-required",
                "metrics": {
                    "attack_paths": 3,
                    "coverage_gaps": 2,
                    "claim_states": {
                        "proven": 1, "inferred": 4,
                        "unverified": 2, "unavailable": 1,
                    },
                },
                "repair_status": "candidate",
                "repair_proof_state": "unverified",
                "regression_status": "baseline-only",
                "automatic_apply": False,
                "permission_retained": False,
            },
        }
        guarded = truth_guard41.guard_document(report, root=self.root)
        rendered = response41.render_guarded(guarded, root=self.root)
        self.assertIn("Security command center", rendered)
        self.assertIn("static attack paths: 3", rendered)
        self.assertIn("Automatic apply: disabled", rendered)
        self.assertIn("evidence: inferred", rendered)
        attack = response41.answer_question(
            guarded, "How many attack paths?", root=self.root)
        self.assertEqual(
            attack["answer"],
            "3 bounded static attack path(s) are recorded; these are not runtime exploit proofs.")
        apply = response41.answer_question(
            guarded, "Will Attestor automatically apply it?", root=self.root)
        self.assertIn("Automatic apply is disabled", apply["answer"])
        repair = response41.answer_question(
            guarded, "What is the repair and regression status?", root=self.root)
        self.assertIn("Repair status is candidate", repair["answer"])

    def test_count_over_truncated_claims_cites_aggregate_report(self):
        report = {**self.report, "findings": [
            {**self.report["findings"][0], "rule": "fixture-taint-%d" % index}
            for index in range(response41.MAX_FINDINGS + 1)
        ]}
        guarded = truth_guard41.guard_document(report, root=self.root)
        answer = response41.answer_question(guarded, "How many findings?", root=self.root)
        self.assertEqual(answer["answer"], "51 matching source-bound finding(s).")
        self.assertIn("R1", answer["citations"])

    def test_final_guarded_document_obeys_public_byte_boundary(self):
        raw_bytes = len(truth_guard41._canonical(self.report))
        with mock.patch.object(truth_guard41, "MAX_PUBLIC_BYTES", raw_bytes + 64):
            with self.assertRaisesRegex(truth_guard41.TruthGuard41Error,
                                        "after evidence binding"):
                truth_guard41.guard_document(self.report, root=self.root)

    def test_verifier_rejects_non_json_values_without_throwing(self):
        verification = truth_guard41.verify_guarded({"payload": object()})
        self.assertFalse(verification["ok"])
        self.assertEqual(verification["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
