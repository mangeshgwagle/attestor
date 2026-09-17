"""Assessment contracts; network calls are mocked except a loopback fixture."""
from contextlib import redirect_stdout
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import security_assessment as assessment


class SecurityAssessmentTests(unittest.TestCase):
    def plan(self, **kwargs):
        return assessment.create_plan(["https://example.test"], [443], **kwargs)

    def report(self):
        plan = self.plan()
        with mock.patch.object(assessment, "_resolve", return_value="192.0.2.1"), \
                mock.patch.object(assessment, "_perform", return_value={"outcome": "closed", "evidence": "Refused"}):
            return assessment.run_plan(plan, plan["sha256"], True)

    def test_preview_is_offline_and_normalizes_targets(self):
        with mock.patch.object(assessment.socket, "getaddrinfo") as resolve, \
                mock.patch.object(assessment.socket, "socket") as connect:
            plan = assessment.create_plan(["https://EXAMPLE.test", "https://example.test/"], [443, 443])
            self.assertEqual(plan["targets"], ["https://example.test/"])
            self.assertEqual(len(plan["checks"]), 2)
            assessment.validate_plan(plan)
            resolve.assert_not_called()
            connect.assert_not_called()

    def test_targets_and_budgets_reject_ambiguous_input(self):
        for target in ("*.test", "192.0.2.0/24", "https://user:secret@example.test", "https://example.test/?token=secret",
                       "https://example.test/#fragment", "file:///etc/passwd", "example.test\r\nX:a", "fe80::1%eth0"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                assessment.create_plan([target], [443])
        for ports in ([True], [0], [65536], []):
            with self.assertRaises(ValueError):
                assessment.create_plan(["example.test"], ports)
        with self.assertRaises(ValueError):
            self.plan(max_requests=1)

    def test_mutated_and_expired_plans_are_rejected_before_network(self):
        plan = self.plan()
        with mock.patch.object(assessment, "_resolve") as resolve:
            for field, value in (("targets", ["other.test"]), ("checks", []), ("max_seconds", 10000)):
                changed = {**plan, field: value}
                with self.assertRaises(ValueError):
                    assessment.run_plan(changed, changed["sha256"], True)
            with mock.patch.object(assessment.time, "time", return_value=plan["expires_at"] + 1), self.assertRaises(ValueError):
                assessment.run_plan(plan, plan["sha256"], True)
            resolve.assert_not_called()

    def test_confirmation_and_authorization_are_required(self):
        plan = self.plan()
        with mock.patch.object(assessment, "_resolve") as resolve:
            for confirm, authorization in (("bad", True), (plan["sha256"], False), (plan["sha256"], "true")):
                with self.assertRaises(ValueError):
                    assessment.run_plan(plan, confirm, authorization)
            resolve.assert_not_called()

    def test_cancel_before_start_keeps_valid_partial_report(self):
        plan = self.plan()
        cancel = threading.Event()
        cancel.set()
        with mock.patch.object(assessment, "_resolve") as resolve:
            report = assessment.run_plan(plan, plan["sha256"], True, cancel)
            resolve.assert_not_called()
        self.assertEqual(report["status"], "cancelled")
        self.assertEqual(report["checks"], [])
        self.assertTrue(assessment.verify_report(report)["ok"])

    def test_cancel_between_checks_does_not_start_the_next(self):
        plan = self.plan()
        cancel = threading.Event()
        def result(*_args):
            cancel.set()
            return {"outcome": "closed", "evidence": "Refused"}
        with mock.patch.object(assessment, "_resolve", return_value="192.0.2.1"), \
                mock.patch.object(assessment, "_perform", side_effect=result) as perform:
            report = assessment.run_plan(plan, plan["sha256"], True, cancel)
        self.assertEqual(perform.call_count, 1)
        self.assertEqual(report["status"], "cancelled")
        assessment.verify_report(report)

    def test_errors_produce_incomplete_evidence_and_resolve_once(self):
        plan = self.plan()
        with mock.patch.object(assessment, "_resolve", return_value="192.0.2.1") as resolve, \
                mock.patch.object(assessment, "_perform", side_effect=TimeoutError("timed out")):
            report = assessment.run_plan(plan, plan["sha256"], True)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(len(report["checks"]), 2)
        assessment.verify_report(report)

    def test_reports_detect_edited_evidence_and_broken_audit(self):
        report = self.report()
        changed = copy.deepcopy(report)
        changed["checks"][0]["evidence"] = "changed"
        with self.assertRaises(ValueError):
            assessment.verify_report(changed)
        changed = copy.deepcopy(report)
        changed["audit"][1]["data"]["sha256"] = "0" * 64
        changed["sha256"] = assessment._digest({k: v for k, v in changed.items() if k != "sha256"})
        with self.assertRaises(ValueError):
            assessment.verify_report(changed)

    def test_html_escapes_untrusted_labels_and_works_after_plan_expiration(self):
        plan = self.plan(label="<script>alert('x')</script>")
        with mock.patch.object(assessment, "_resolve", return_value="192.0.2.1"), \
                mock.patch.object(assessment, "_perform", return_value={"outcome": "open", "evidence": "<img onerror=x>"}):
            report = assessment.run_plan(plan, plan["sha256"], True)
        with mock.patch.object(assessment.time, "time", return_value=plan["expires_at"] + 100):
            output = assessment.render_html(report)
        self.assertNotIn("<script>", output)
        self.assertNotIn("<img onerror", output)
        self.assertIn("&lt;script&gt;", output)

    def test_cli_preview_and_report_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix="attestor-assessment-") as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(assessment.main(["plan", "--target", "https://example.test", "--ports", "443", "--out", str(plan_path), "--json"]), 0)
            plan = json.loads(output.getvalue())
            with mock.patch.object(assessment, "_resolve", return_value="192.0.2.1"), \
                    mock.patch.object(assessment, "_perform", return_value={"outcome": "closed", "evidence": "Refused"}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(assessment.main(["run", "--plan", str(plan_path), "--confirm", plan["sha256"], "--authorized", "--out", str(root / "result"), "--json"]), 0)
            report = json.loads((root / "result/report.json").read_text())
            self.assertTrue(assessment.verify_report(report)["ok"])
            self.assertTrue((root / "result/report.html").is_file())

    def test_json_duplicate_keys_and_existing_outputs_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="attestor-assessment-") as directory:
            path = Path(directory) / "existing.json"
            path.write_text('{"a":1,"a":2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                assessment._read_json(path)
            with self.assertRaises(FileExistsError):
                assessment._write_new(path, "replacement")
            self.assertEqual(path.read_text(), '{"a":1,"a":2}')

    def test_head_does_not_follow_redirect_or_store_cookies(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_HEAD(self):
                requests.append((self.command, self.path))
                self.send_response(302)
                self.send_header("Location", "https://example.test/unrequested")
                self.send_header("Set-Cookie", "private=do-not-store")
                self.end_headers()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_address[1]
            plan = assessment.create_plan([f"http://127.0.0.1:{port}/check"], [port])
            report = assessment.run_plan(plan, plan["sha256"], True)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
        self.assertEqual(requests, [("HEAD", "/check")])
        self.assertEqual(report["status"], "completed")
        self.assertNotIn("private=do-not-store", json.dumps(report))
        self.assertTrue(assessment.verify_report(report)["ok"])


if __name__ == "__main__":
    unittest.main()
