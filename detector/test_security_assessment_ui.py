"""Authenticated assessment workflow checks; no target connections are made."""
from __future__ import annotations

import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

import attestor_ui


class AssessmentUiTests(unittest.TestCase):
    def setUp(self):
        class QuietHandler(attestor_ui.Handler):
            def log_message(self, _format, *_args):
                pass

        self.plan = {
            "sha256": "a" * 64, "targets": ["127.0.0.1"],
            "checks": [{"kind": "tcp", "target": "127.0.0.1", "port": 443}],
            "max_requests": 1, "timeout_seconds": 10,
        }
        self.report = {
            "status": "completed", "findings": [{
                "severity": "info", "title": "Service responds", "target": "127.0.0.1",
                "evidence": "<untrusted>", "recommendation": "Review intended exposure.",
            }], "checks": [{"kind": "tcp", "status": "open"}],
            "audit": [{"event": "assessment-finished"}],
        }

        def validate(plan):
            if plan != self.plan:
                raise ValueError("Preview has changed or expired.")
            return dict(plan)

        self.patches = [
            mock.patch.object(attestor_ui.security_assessment, "create_plan", return_value=self.plan),
            mock.patch.object(attestor_ui.security_assessment, "validate_plan", side_effect=validate),
            mock.patch.object(attestor_ui.security_assessment, "run_plan", return_value=self.report),
            mock.patch.object(attestor_ui.security_assessment, "status", return_value={"metasploit": {"available": True}}),
            mock.patch.object(attestor_ui.security_assessment, "render_html", return_value="<!doctype html><p>Evidence &lt;untrusted&gt;</p>"),
        ]
        self.create, self.validate, self.run, self.status, self.html = [patch.start() for patch in self.patches]
        for patch in self.patches:
            self.addCleanup(patch.stop)
        self.server = attestor_ui.LimitedThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        port = self.server.server_address[1]
        self.server.allowed_hosts = {"127.0.0.1:%d" % port}
        self.server.session_token = "assessment-test-token"
        self.server.jobs = attestor_ui.JobManager(workers=1)
        self.base = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server.jobs.shutdown()
        self.thread.join(timeout=3)

    def request(self, path, *, method="GET", body=None, raw=None, token=True):
        headers = {"Origin": self.base}
        if token:
            headers["X-Attestor-Token"] = "assessment-test-token"
        data = raw
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        return urllib.request.urlopen(request, timeout=3)

    def request_json(self, path, **kwargs):
        with self.request(path, **kwargs) as response:
            return response.status, json.loads(response.read())

    def assert_error(self, code, path, **kwargs):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request(path, **kwargs)
        self.assertEqual(raised.exception.code, code)
        raised.exception.close()

    def run_request(self, **overrides):
        return {"plan": self.plan, "confirm_sha256": self.plan["sha256"],
                "authorized": True, **overrides}

    def await_job(self, job_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            _, job = self.request_json("/api/jobs/" + job_id)
            if job["status"] in {"done", "failed", "cancelled"}:
                return job
            time.sleep(.01)
        self.fail("Assessment job did not reach a terminal state.")

    def test_assessment_routes_require_the_session_token(self):
        for path, method, body in [
            ("/api/security/status", "GET", None),
            ("/api/security/plan", "POST", {"targets": ["127.0.0.1"]}),
            ("/api/security/run", "POST", self.run_request()),
            ("/api/security/jobs/missing/export/json", "GET", None),
        ]:
            with self.subTest(path=path):
                self.assert_error(403, path, method=method, body=body, token=False)
        self.create.assert_not_called()
        self.run.assert_not_called()
        self.status.assert_not_called()

    def test_preview_returns_checks_without_running_them(self):
        status, response = self.request_json("/api/security/plan", method="POST", body={
            "targets": ["127.0.0.1"], "ports": [443], "label": "Service review"})
        self.assertEqual(status, 200)
        self.assertEqual(response["plan"], self.plan)
        self.create.assert_called_once_with(targets=["127.0.0.1"], ports=[443], label="Service review")
        self.run.assert_not_called()

    def test_run_requires_exact_preview_confirmation_and_boolean_authorization(self):
        for authorization in (False, "true", 1, None):
            self.assert_error(400, "/api/security/run", method="POST",
                              body=self.run_request(authorized=authorization))
        self.assert_error(400, "/api/security/run", method="POST",
                          body=self.run_request(confirm_sha256="b" * 64))
        modified = {**self.plan, "targets": ["192.0.2.1"]}
        self.assert_error(400, "/api/security/run", method="POST", body=self.run_request(plan=modified))
        self.run.assert_not_called()

    def test_duplicate_keys_and_additional_inputs_are_rejected(self):
        self.assert_error(400, "/api/security/plan", method="POST",
                          raw=b'{"targets":[],"targets":["127.0.0.1"]}')
        self.assert_error(400, "/api/security/plan", method="POST",
                          body={"targets": ["127.0.0.1"], "module": "arbitrary"})
        self.assert_error(400, "/api/security/run", method="POST",
                          body={**self.run_request(), "command": "arbitrary"})
        self.assert_error(400, "/api/security/status?input=unexpected")
        self.assert_error(400, "/api/security/run?input=unexpected", method="POST", body=self.run_request())
        self.run.assert_not_called()

    def test_complete_job_and_exports_use_the_same_server_report(self):
        status, submitted = self.request_json("/api/security/run", method="POST", body=self.run_request())
        self.assertEqual(status, 202)
        job = self.await_job(submitted["id"])
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["result"]["report"], self.report)
        self.assertIn("history_skipped", job["result"])
        _, exported = self.request_json("/api/security/jobs/" + job["id"] + "/export/json")
        self.assertEqual(exported, self.report)
        with self.request("/api/security/jobs/" + job["id"] + "/export/html") as response:
            self.assertTrue(response.headers["Content-Disposition"].startswith("attachment;"))
            self.assertIn(b"&lt;untrusted&gt;", response.read())
        self.html.assert_called_once_with(self.report)
        self.assertIs(self.run.call_args.kwargs["authorized"], True)
        self.assertIsInstance(self.run.call_args.kwargs["cancel_event"], threading.Event)

    def test_generic_job_endpoint_cannot_bypass_assessment_authorization(self):
        _, submitted = self.request_json("/api/jobs", method="POST", body={
            "mode": "security-assessment", "plan": self.plan,
            "confirm_sha256": self.plan["sha256"], "authorized": "true"})
        job = self.await_job(submitted["id"])
        self.assertEqual(job["status"], "failed")
        self.run.assert_not_called()

    def test_cancel_reaches_the_backend_and_keeps_partial_evidence_exportable(self):
        entered = threading.Event()

        def wait_for_cancel(_plan, *, confirm_sha256, authorized, cancel_event):
            entered.set()
            if not cancel_event.wait(3):
                raise ValueError("Cancellation never arrived.")
            return {**self.report, "status": "cancelled"}

        self.run.side_effect = wait_for_cancel
        _, submitted = self.request_json("/api/security/run", method="POST", body=self.run_request())
        self.assertTrue(entered.wait(2))
        status, _ = self.request_json("/api/jobs/" + submitted["id"], method="DELETE")
        self.assertEqual(status, 202)
        job = self.await_job(submitted["id"])
        self.assertEqual(job["status"], "cancelled")
        _, report = self.request_json("/api/security/jobs/" + job["id"] + "/export/json")
        self.assertEqual(report["status"], "cancelled")

    def test_export_never_accepts_paths_or_unfinished_jobs(self):
        self.assert_error(404, "/api/security/jobs/missing/export/json")
        self.assert_error(404, "/api/security/jobs/missing/export/../../ui23.js")
        self.assert_error(404, "/api/security/jobs/missing/export/csv")


if __name__ == "__main__":
    unittest.main()
