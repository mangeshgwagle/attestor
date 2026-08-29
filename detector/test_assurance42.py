from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

import assurance42


class Assurance42Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="attestor-assurance42-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, content: str | bytes) -> Path:
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        return target

    @staticmethod
    def reseal(report: dict) -> dict:
        report["report_sha256"] = assurance42.digest_json({
            key: value for key, value in report.items()
            if key != "report_sha256"
        })
        return report

    def test_deterministic_report_is_verified_bounded_and_honestly_incomplete(self) -> None:
        self.write("src/app.py", "answer = 42\n")
        first = assurance42.run_assurance(self.root)
        second = assurance42.run_assurance(self.root)
        self.assertEqual(first, second)
        valid, errors = assurance42.verify_report(first)
        self.assertTrue(valid, errors)
        self.assertEqual(first["schema"], assurance42.SCHEMA)
        self.assertEqual(first["status"], "incomplete")
        self.assertFalse(first["complete"])
        self.assertEqual(assurance42.exit_for_status(first), 3)
        self.assertEqual(first["snapshot"]["root"], ".")
        self.assertEqual(first["summary"]["file_count"], 1)
        self.assertEqual(set(first["analyzers"]), {
            "detect", "semantic_graph41", "attack_surface413",
            "security_posture413",
        })
        self.assertEqual(first["cost_profile"]["external_provider_charge_usd"], 0)
        self.assertIsNone(first["cost_profile"]["local_compute_cost_usd"])
        self.assertFalse(first["execution"]["captured_subject_code_executed"])
        encoded = assurance42.canonical_json(first)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn("answer = 42", encoded)

    def test_core_attack_and_semantic_findings_have_advisory_only_repairs(self) -> None:
        self.write("app.py", """import os
import subprocess
from flask import Flask, request
app = Flask(__name__)
value = os.getenv("COMMAND")
subprocess.run(value)
@app.get("/evaluate")
def evaluate():
    return eval(request.args["expression"])
""")
        report = assurance42.run_assurance(self.root)
        self.assertEqual(report["status"], "incomplete-findings")
        analyzers = {row["analyzer"] for row in report["evidence"]}
        self.assertIn("detect", analyzers)
        self.assertIn("semantic_graph41", analyzers)
        self.assertIn("attack_surface413", analyzers)
        semantic = [row for row in report["evidence"]
                    if row["analyzer"] == "semantic_graph41"]
        self.assertTrue(semantic)
        self.assertEqual(semantic[0]["details"]["runtime_exploitability"], "unverified")
        for row in report["evidence"]:
            self.assertEqual(row["advisory"]["kind"], "preview-only")
            self.assertIs(row["advisory"]["applied"], False)
            self.assertIs(row["advisory"]["verified"], False)
            self.assertIn(row["path"].casefold(), {
                item["path"].casefold() for item in report["snapshot"]["files"]})
        self.assertTrue(assurance42.verify_report(report)[0])

    def test_security_posture_redacts_secret_source_and_builds_sbom(self) -> None:
        canary = "AKIA1234567890ABCDEF"
        self.write(".env", "AWS_ACCESS_KEY_ID=" + canary + "\n")
        self.write("requirements.txt", "flask==3.0.0\n")
        report = assurance42.run_assurance(self.root)
        encoded = assurance42.canonical_json(report)
        self.assertNotIn(canary, encoded)
        self.assertNotIn("AWS_ACCESS_KEY_ID=", encoded)
        self.assertGreaterEqual(report["summary"]["posture_findings"], 1)
        self.assertGreaterEqual(report["summary"]["sbom_components"], 1)
        posture = [row for row in report["evidence"]
                   if row["analyzer"] == "security_posture413"]
        self.assertTrue(posture)
        self.assertTrue(all("snippet" not in row for row in posture))
        self.assertTrue(assurance42.verify_report(report)[0])

    def test_unknown_language_is_a_coverage_gap_not_a_clean_claim(self) -> None:
        self.write("program.xyz", "not actually a supported language\n")
        report = assurance42.run_assurance(self.root)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["summary"]["uncovered_files"], 1)
        self.assertIn("unsupported", report["language_coverage"]["by_language"])
        self.assertTrue(any(
            row["analyzer"] == "language_coverage42"
            for row in report["coverage"]["gaps"]))

    def test_hardlink_alias_is_skipped_and_outside_bytes_are_not_reported(self) -> None:
        outside = self.root.parent / (self.root.name + "-outside.txt")
        alias = self.root / "alias.txt"
        canary = "HARDLINK-OUTSIDE-CANARY-42"
        outside.write_text(canary, encoding="utf-8")
        try:
            os.link(outside, alias)
        except OSError as exc:
            outside.unlink(missing_ok=True)
            self.skipTest("hard links unavailable: %s" % type(exc).__name__)
        try:
            report = assurance42.run_assurance(self.root)
            encoded = assurance42.canonical_json(report)
            self.assertNotIn(canary, encoded)
            self.assertNotIn("alias.txt", {
                row["path"] for row in report["snapshot"]["files"]})
            self.assertTrue(any(
                row["reason"] == "multiple-hard-links-skipped"
                for row in report["coverage"]["gaps"]))
        finally:
            alias.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    def test_symlink_is_not_followed_or_leaked(self) -> None:
        outside = self.root.parent / (self.root.name + "-outside.py")
        link = self.root / "linked.py"
        canary = "SYMLINK-OUTSIDE-CANARY-42"
        outside.write_text(canary, encoding="utf-8")
        try:
            link.symlink_to(outside)
        except OSError as exc:
            outside.unlink(missing_ok=True)
            self.skipTest("symlinks unavailable: %s" % type(exc).__name__)
        try:
            report = assurance42.run_assurance(self.root)
            self.assertNotIn(canary, assurance42.canonical_json(report))
            self.assertTrue(any(
                row["reason"] == "symlink-or-reparse-skipped"
                for row in report["coverage"]["gaps"]))
        finally:
            link.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    def test_control_or_bidi_path_is_rejected_before_evidence_rendering(self) -> None:
        self.write("unsafe\u202efile.py", "x = 1\n")
        with self.assertRaises(assurance42.AssuranceInputError):
            assurance42.run_assurance(self.root)

    def test_deep_resealed_tampering_is_rejected(self) -> None:
        self.write("app.py", "eval(input())\n")
        original = assurance42.run_assurance(self.root)

        summary = copy.deepcopy(original)
        summary["summary"]["evidence_count"] += 1
        self.assertFalse(assurance42.verify_report(self.reseal(summary))[0])

        evidence = copy.deepcopy(original)
        evidence["evidence"][0]["advisory"]["applied"] = True
        self.assertFalse(assurance42.verify_report(self.reseal(evidence))[0])

        status = copy.deepcopy(original)
        status["status"] = "clean"
        status["complete"] = True
        self.assertFalse(assurance42.verify_report(self.reseal(status))[0])

        component = copy.deepcopy(original)
        component["analyzers"]["detect"]["metrics"]["findings"] += 1
        component["analyzers"]["detect"]["projection_sha256"] = \
            assurance42.digest_json({
                key: value for key, value in component["analyzers"]["detect"].items()
                if key != "projection_sha256"
            })
        self.assertFalse(assurance42.verify_report(self.reseal(component))[0])

        semantic_contract = copy.deepcopy(original)
        semantic = semantic_contract["analyzers"]["semantic_graph41"]
        semantic["static_contract"]["network_accessed"] = True
        semantic["projection_sha256"] = assurance42.digest_json({
            key: value for key, value in semantic.items()
            if key != "projection_sha256"
        })
        self.assertFalse(
            assurance42.verify_report(self.reseal(semantic_contract))[0])

        capture_contract = copy.deepcopy(original)
        capture_contract["snapshot"]["capture_contract"]["network_requests_made"] = True
        capture_contract["snapshot"]["projection_sha256"] = assurance42.digest_json({
            key: value for key, value in capture_contract["snapshot"].items()
            if key != "projection_sha256"
        })
        self.assertFalse(
            assurance42.verify_report(self.reseal(capture_contract))[0])

    def test_returned_contracts_do_not_alias_future_reports(self) -> None:
        self.write("app.py", "answer = 42\n")
        mutated = assurance42.run_assurance(self.root)
        mutated["execution"]["network_requests_made"] = True
        mutated["cost_profile"]["external_provider_charge_usd"] = 99
        mutated["limitations"].clear()
        self.assertFalse(assurance42.verify_report(self.reseal(mutated))[0])
        fresh = assurance42.run_assurance(self.root)
        self.assertIs(fresh["execution"]["network_requests_made"], False)
        self.assertEqual(fresh["cost_profile"]["external_provider_charge_usd"], 0)
        self.assertTrue(fresh["limitations"])
        self.assertTrue(assurance42.verify_report(fresh)[0])

    def test_redigested_language_coverage_cannot_remove_incomplete_state(self) -> None:
        self.write("program.xyz", "unsupported\n")
        forged = assurance42.run_assurance(self.root)
        forged["language_coverage"]["uncovered"] = []
        forged["language_coverage"]["report_sha256"] = assurance42.digest_json({
            key: value for key, value in forged["language_coverage"].items()
            if key != "report_sha256"
        })
        forged["coverage"]["gaps"] = [
            row for row in forged["coverage"]["gaps"]
            if row["analyzer"] != "language_coverage42"
        ]
        forged["coverage"]["complete"] = not forged["coverage"]["gaps"]
        forged["summary"]["uncovered_files"] = 0
        forged["summary"]["gap_count"] = len(forged["coverage"]["gaps"])
        forged["status"] = "incomplete" if forged["coverage"]["gaps"] else "clean"
        forged["complete"] = forged["status"] == "clean"
        self.assertFalse(assurance42.verify_report(self.reseal(forged))[0])

    def test_analyzers_do_not_start_network_processes_or_write(self) -> None:
        self.write("app.py", "answer = 42\n")
        real_io_open = io.open

        def guarded_open(file, mode="r", *args, **kwargs):
            if any(flag in mode for flag in ("w", "a", "x", "+")):
                raise AssertionError("write requested")
            return real_io_open(file, mode, *args, **kwargs)

        with mock.patch.object(subprocess, "run", side_effect=AssertionError("process")) as process, \
                mock.patch.object(socket, "create_connection", side_effect=AssertionError("network")) as network, \
                mock.patch("io.open", side_effect=guarded_open):
            report = assurance42.run_assurance(self.root)
        process.assert_not_called()
        network.assert_not_called()
        self.assertTrue(assurance42.verify_report(report)[0])

    def test_cli_invalid_and_operational_failures_are_bounded_without_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        missing = self.root / "missing"
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = assurance42.main(["--format", "json", "--", str(missing)])
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
                assurance42, "run_assurance",
                side_effect=assurance42.AssuranceOperationalError("private detail")), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = assurance42.main(["--", str(self.root)])
        self.assertEqual(code, 4)
        self.assertNotIn("Traceback", stderr.getvalue())
        self.assertLess(len(stderr.getvalue()), 500)


if __name__ == "__main__":
    unittest.main()
