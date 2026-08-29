from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import analysis_snapshot41 as snapshot41
import attack_surface413
import bounded_worker41 as worker
import deep_correctness41 as deep
import security_posture413


class BoundedWorker41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text(
            "def clean(value):\n    return value.strip()\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_coding_components_share_one_snapshot_in_a_child(self) -> None:
        report = worker.run("coding-static", {"root": str(self.root)}, timeout=20)
        self.assertEqual(report["status"], "completed", report)
        self.assertTrue(worker.verify_report(report)[0])
        result = report["result"]
        digest = result["shared_snapshot_sha256"]
        self.assertEqual(digest, result["snapshot"]["snapshot_sha256"])
        self.assertEqual(digest, result["semantic_graph"]["snapshot_sha256"])
        self.assertEqual(
            result["resource_limits"]["max_graph_nodes"], 250_000)
        self.assertLessEqual(
            result["resource_limits"]["observed_graph_nodes"], 250_000)
        self.assertFalse(result["execution"]["target_code_executed"])
        self.assertFalse(result["execution"]["network_accessed"])
        self.assertEqual((self.root / "app.py").read_text(encoding="utf-8"),
                         "def clean(value):\n    return value.strip()\n")
        self.assertFalse(report["boundary"]["preexec_fn_used"])
        self.assertEqual(
            report["boundary"]["max_memory_bytes"], worker.MAX_MEMORY_BYTES)

    def test_deep_correctness_internal_type_error_is_not_retried_by_path(self) -> None:
        with mock.patch.object(
                deep, "analyze", side_effect=TypeError("internal analyzer defect")) as analyzer:
            with self.assertRaisesRegex(TypeError, "internal analyzer defect"):
                worker._coding({"root": str(self.root)})
        analyzer.assert_called_once()
        self.assertIsInstance(analyzer.call_args.args[0], snapshot41.SourceSnapshot)

    def test_security_static_worker_is_bounded_and_offline(self) -> None:
        (self.root / "requirements.txt").write_text("demo==1.0\n", encoding="utf-8")
        report = worker.run("security-static", {"root": str(self.root)}, timeout=20)
        self.assertEqual(report["status"], "completed", report)
        self.assertTrue(worker.verify_report(report)[0])
        result = report["result"]
        self.assertIn("supply_chain_trust", result)
        self.assertIn("secret_lifecycle", result)
        self.assertFalse(result["execution"]["network_accessed"])

    def test_attack_surface_worker_is_verified_bounded_and_offline(self) -> None:
        (self.root / "app.py").write_text(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.get('/users/<user_id>')\n"
            "def user(user_id):\n"
            "    return request.args.get('next', user_id)\n",
            encoding="utf-8")
        report = worker.run(
            "attack-static-413", {"root": str(self.root)}, timeout=30)
        self.assertEqual(report["status"], "completed", report)
        self.assertTrue(worker.verify_report(report)[0], report)
        result = report["result"]
        self.assertTrue(attack_surface413.verify_report(result)[0], result)
        self.assertFalse(result["execution"]["target_code_executed"])
        self.assertFalse(result["execution"]["network_accessed"])
        self.assertFalse(result["execution"]["target_files_written"])

    def test_security_posture_worker_is_verified_bounded_and_offline(self) -> None:
        (self.root / "Dockerfile").write_text(
            "FROM python:latest\nUSER root\n", encoding="utf-8")
        (self.root / "main.tf").write_text(
            'resource "aws_s3_bucket" "demo" { acl = "public-read" }\n',
            encoding="utf-8")
        report = worker.run(
            "posture-static-413", {"root": str(self.root)}, timeout=30)
        self.assertEqual(report["status"], "completed", report)
        self.assertTrue(worker.verify_report(report)[0], report)
        result = report["result"]
        self.assertTrue(security_posture413.verify_report(result), result)
        self.assertFalse(result["execution"]["target_code_executed"])
        self.assertFalse(result["execution"]["network_accessed"])
        self.assertFalse(result["execution"]["files_written"])

    def test_unknown_action_and_oversized_request_fail_before_process(self) -> None:
        with self.assertRaises(worker.WorkerError):
            worker.run("arbitrary", {"root": str(self.root)})
        with self.assertRaises(worker.WorkerError):
            worker.run("coding-static", {"root": str(self.root),
                                          "padding": "x" * worker.MAX_REQUEST_BYTES})
        with self.assertRaisesRegex(worker.WorkerError, "strict JSON"):
            worker.run("coding-static", {"root": str(self.root), "object": object()})
        with self.assertRaisesRegex(worker.WorkerError, "unsupported fields"):
            worker.run("coding-static", {
                "root": str(self.root), "unexpected": "value"})
        with self.assertRaisesRegex(worker.WorkerError, "unsupported fields"):
            worker.dispatch("coding-static", {
                "root": str(self.root), "unexpected": "value"})

    def test_selected_graph_boundary_fails_closed_in_the_worker(self) -> None:
        graph = {"graph": {"symbols": [{}, {}]}}
        with mock.patch(
                "semantic_graph41.build", return_value=graph) as builder:
            with self.assertRaisesRegex(
                    worker.WorkerError, "selected profile boundary"):
                worker._coding({
                    "root": str(self.root),
                    "max_graph_nodes": 1,
                })
        self.assertEqual(builder.call_args.kwargs["max_nodes"], 1)
        with mock.patch.object(
                snapshot41, "capture",
                side_effect=AssertionError("snapshot must not be captured")
        ) as capture:
            for value in (True, "1", 0, 250_001):
                with self.subTest(value=value), self.assertRaisesRegex(
                        worker.WorkerError, "compiled boundary"):
                    worker._coding({
                        "root": str(self.root),
                        "max_graph_nodes": value,
                    })
        capture.assert_not_called()

    def test_direct_worker_enforces_selected_graph_boundary_during_build(
            self) -> None:
        result = worker.dispatch("coding-static", {
            "root": str(self.root),
            "max_graph_nodes": 1,
        })
        graph_rows = result["semantic_graph"]["graph"]
        self.assertEqual(sum(len(rows) for rows in graph_rows.values()), 1)
        self.assertEqual(result["resource_limits"]["max_graph_nodes"], 1)
        self.assertEqual(result["resource_limits"]["observed_graph_nodes"], 1)
        self.assertIn(
            "selected-graph-node-budget",
            {row["reason"] for row in
             result["semantic_graph"]["coverage"]["gaps"]},
        )

    def test_numeric_boundaries_reject_ambiguous_or_unbounded_values(self) -> None:
        for timeout in (True, "1", float("nan"), float("inf"), 0.01,
                        worker.MAX_TIMEOUT + 1):
            with self.subTest(timeout=timeout), self.assertRaises(worker.WorkerError):
                worker.run("coding-static", {"root": str(self.root)}, timeout=timeout)
        for output in (True, "1024", 1_023, worker.MAX_OUTPUT_BYTES + 1):
            with self.subTest(output=output), self.assertRaises(worker.WorkerError):
                worker.run("coding-static", {"root": str(self.root)},
                           max_output_bytes=output)
        for memory in (
                True, "67108864", worker.MIN_MEMORY_BYTES - 1,
                worker.MAX_MEMORY_BYTES + 1):
            with self.subTest(memory=memory), self.assertRaises(worker.WorkerError):
                worker.run("coding-static", {"root": str(self.root)},
                           max_memory_bytes=memory)

    def test_custom_memory_boundary_is_enforced_and_attested(self) -> None:
        memory = 384 * 1024 * 1024
        report = worker.run(
            "coding-static", {"root": str(self.root)}, timeout=20,
            max_memory_bytes=memory)
        self.assertEqual(report["status"], "completed", report)
        self.assertEqual(report["boundary"]["max_memory_bytes"], memory)
        self.assertTrue(worker.verify_report(report)[0], report)

        tampered = json.loads(json.dumps(report))
        tampered["boundary"]["max_memory_bytes"] = memory + 1
        self.assertFalse(worker.verify_report(tampered)[0])

    def test_relative_api_root_is_scoped_to_callers_working_directory(self) -> None:
        original = Path.cwd()
        try:
            os.chdir(self.root.parent)
            report = worker.run("coding-static", {"root": self.root.name}, timeout=20)
        finally:
            os.chdir(original)
        self.assertEqual(report["status"], "completed", report)
        files = report["result"]["snapshot"]["inventory"]["files"]
        self.assertEqual([row["path"] for row in files], ["app.py"])

    def test_relative_cli_root_is_scoped_to_callers_working_directory(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(Path(worker.__file__).resolve()),
             "--root", self.root.name, "--timeout", "20"],
            cwd=str(self.root.parent), capture_output=True, text=True,
            encoding="utf-8", timeout=30, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "completed", report)
        files = report["result"]["snapshot"]["inventory"]["files"]
        self.assertEqual([row["path"] for row in files], ["app.py"])

    def test_lexical_directory_link_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            nested = target / "nested"
            nested.mkdir(parents=True)
            link = base / "linked"
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            with mock.patch.object(worker.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(worker.WorkerError, "link|reparse"):
                    worker.run("coding-static", {"root": str(link / "nested")})
                launch.assert_not_called()

    def test_windows_reparse_attribute_is_treated_as_a_link(self) -> None:
        metadata = type("Metadata", (), {
            "st_mode": stat.S_IFDIR,
            "st_file_attributes": getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
        })()
        self.assertTrue(worker._is_link_or_reparse(metadata))

    def test_small_output_boundary_refuses_instead_of_buffering_result(self) -> None:
        report = worker.run(
            "coding-static", {"root": str(self.root)}, timeout=20,
            max_output_bytes=1_024)
        self.assertEqual(report["status"], "refused", report)
        self.assertEqual(report["error"], "output-boundary")
        self.assertLessEqual(report["boundary"]["output_bytes"], 1_025)
        self.assertTrue(worker.verify_report(report)[0], report)

    def test_child_validation_failure_is_structured_and_sanitized(self) -> None:
        report = worker.run(
            "security-static", {"root": str(self.root), "staged_diff": 42},
            timeout=20)
        self.assertEqual(report["status"], "failed", report)
        self.assertEqual(report["error"], "worker-error-WorkerError")
        self.assertIsNone(report["result"])
        self.assertTrue(worker.verify_report(report)[0], report)

    def test_timeout_is_evidence_not_an_exception(self) -> None:
        with mock.patch.object(worker.subprocess, "Popen",
                               side_effect=subprocess.TimeoutExpired(["python"], 1)):
            report = worker.run("coding-static", {"root": str(self.root)}, timeout=1)
        self.assertEqual(report["status"], "timed-out")
        self.assertEqual(report["error"], "wall-clock-boundary")
        self.assertTrue(worker.verify_report(report)[0])

    def test_tampering_is_detected(self) -> None:
        report = worker.run("coding-static", {"root": str(self.root)}, timeout=20)
        self.assertEqual(report["status"], "completed", report)
        report["boundary"]["shell"] = True
        valid, errors = worker.verify_report(report)
        self.assertFalse(valid)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
