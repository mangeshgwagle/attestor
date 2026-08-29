#!/usr/bin/env python3
"""Focused UI/API tests for Attestor 4.1.4's blind autonomous arena."""
from __future__ import annotations

import json
import inspect
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock


HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import blind_escape_arena414 as arena
import attestor_ui


class BlindArenaMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = attestor_ui.INDEX.read_text(encoding="utf-8")
        cls.js = attestor_ui.UI_SCRIPT.read_text(encoding="utf-8")

    def test_panel_has_fixed_objective_and_no_editable_input(self):
        start = self.html.index('<article class="panel raw-panel" id="blindArenaPanel"')
        panel = self.html[start:self.html.index("</article>", start)]
        self.assertIn('id="blindArenaObjective">Escape</dd>', panel)
        for editable in ("<input", "<textarea", "<select", "contenteditable"):
            self.assertNotIn(editable, panel.lower())
        for control in ("blindArenaStartBtn", "blindArenaStatusBtn",
                        "blindArenaCancelBtn", "blindArenaResetBtn"):
            self.assertIn('id="%s"' % control, panel)
        self.assertIn("no editable prompt, path, payload", panel.lower())

    def test_existing_data_only_lab_remains_separate(self):
        self.assertIn('value="escapelab"', self.html)
        self.assertIn('id="escapeLabControls"', self.html)
        self.assertLess(self.html.index('id="escapeLabControls"'),
                        self.html.index('id="blindArenaPanel"'))
        self.assertIn("never calls the data-only planted-path lab", self.html)

    def test_client_has_verified_only_success_and_exact_reset_confirmation(self):
        self.assertIn("api('/api/blind-arena/status')", self.js)
        self.assertIn("api('/api/blind-arena/start'", self.js)
        self.assertIn("api('/api/blind-arena', {method: 'DELETE'})", self.js)
        self.assertIn("api('/api/blind-arena/reset'", self.js)
        self.assertIn("body: '{}'", self.js)
        self.assertIn("window.confirm(", self.js)
        self.assertIn("JSON.stringify({confirmed: true})", self.js)
        gate = self.js[self.js.index("const escaped = snapshot.verified_escape"):
                       self.js.index("const terminal =", self.js.index(
                           "const escaped = snapshot.verified_escape"))]
        self.assertIn("verification.report === true", gate)
        self.assertIn("verification.hidden_token === true", gate)
        self.assertIn("verification.trace === true", gate)
        self.assertIn("snapshot.terminal === true", gate)
        self.assertNotIn("\u00c2\u00b7", self.js)


class BlindArenaManagerTests(unittest.TestCase):
    def test_controller_has_no_shell_runtime_lab_or_overall_deadline_path(self):
        controller_source = inspect.getsource(attestor_ui.BlindArenaManager)
        for forbidden in ("run_attestor(", "subprocess.", "escape_lab414",
                          "hypervisor", "socket.", "urllib."):
            self.assertNotIn(forbidden, controller_source)
        loop_source = inspect.getsource(
            attestor_ui.BlindArenaManager._run_background)
        self.assertIn("while True:", loop_source)
        self.assertIn("run_episode(", loop_source)
        self.assertNotIn("episode_budget", loop_source)
        self.assertNotIn("time.monotonic", loop_source)
        self.assertNotIn("time.time", loop_source)
        self.assertNotIn("timeout_seconds", loop_source)

    def test_background_run_persists_only_safe_verified_status(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "arena.json"
            manager = attestor_ui.BlindArenaManager(checkpoint)
            try:
                initial = manager.status()
                self.assertEqual(initial["objective"], "Escape")
                self.assertEqual(initial["status"], "not-started")
                manager.start_or_resume()
                deadline = time.monotonic() + 5
                while manager.status()["running"] and time.monotonic() < deadline:
                    time.sleep(0.01)
                completed = manager.status()
                self.assertFalse(completed["running"])
                self.assertTrue(completed["verified_escape"])
                self.assertEqual(completed["status"], "escaped")
                self.assertTrue(completed["verification"]["report"])
                self.assertTrue(completed["verification"]["hidden_token"])
                self.assertTrue(completed["verification"]["trace"])
                self.assertGreater(completed["episode_count"], 0)
                self.assertGreater(completed["total_steps"], 0)
                self.assertTrue(checkpoint.is_file())
                serialized = json.dumps(completed, sort_keys=True)
                self.assertNotIn("token-", serialized)
                self.assertNotIn('"trace": [', serialized)
                self.assertNotIn('"private"', serialized)
                self.assertNotIn('"graph"', serialized)
                self.assertNotIn('"escape_proof"', serialized)
                self.assertNotIn('"arena_id"', serialized)
                self.assertNotIn("checkpoint_path", serialized.lower())
                self.assertNotIn(str(checkpoint), serialized)
                controls = completed["simulation_controls"]
                for key in ("arbitrary_payloads_accepted", "commands_executed",
                            "network_accessed", "processes_started",
                            "real_escape_attempted"):
                    self.assertIs(controls[key], False)
            finally:
                manager.shutdown()

            restored = attestor_ui.BlindArenaManager(checkpoint)
            try:
                status = restored.status()
                self.assertTrue(status["verified_escape"])
                self.assertEqual(status["status"], "escaped")
            finally:
                restored.shutdown()

    def test_empty_status_uses_current_core_checkpoint_boundary_names(self):
        status = attestor_ui.BlindArenaManager._empty_status()
        controls = status["simulation_controls"]
        self.assertIs(controls["simulation_core_file_access"], False)
        self.assertIs(controls["controller_checkpoint_may_read_write"], True)
        self.assertNotIn("files_read_by_core", controls)
        self.assertNotIn("files_written_by_core", controls)

    def test_checkpoint_parent_must_be_real_directory_not_reparse_point(self):
        with tempfile.TemporaryDirectory() as directory:
            parent_file = Path(directory) / "not-a-directory"
            parent_file.write_text("x", encoding="utf-8")
            with self.assertRaises(arena.BlindEscapeArenaError):
                attestor_ui.BlindArenaManager(parent_file / "arena.json")

            fake_stat = mock.Mock(
                st_mode=attestor_ui.stat.S_IFDIR,
                st_file_attributes=getattr(
                    attestor_ui.stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            with mock.patch.object(attestor_ui.os, "lstat", return_value=fake_stat):
                with self.assertRaises(arena.BlindEscapeArenaError):
                    attestor_ui.BlindArenaManager(Path(directory) / "arena.json")

    def test_cancelled_episode_is_checkpointed_and_reported_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "arena.json"
            manager = attestor_ui.BlindArenaManager(checkpoint)
            entered = threading.Event()
            original = arena.run_episode

            def cancellable_episode(state, explorer=None, **kwargs):
                entered.set()
                cancel = kwargs["cancel"]
                while not cancel.is_set():
                    time.sleep(0.001)
                return original(state, explorer, max_steps=1, cancel=cancel,
                                checkpoint_path=kwargs["checkpoint_path"])

            try:
                with mock.patch.object(arena, "run_episode",
                                       side_effect=cancellable_episode):
                    manager.start_or_resume()
                    self.assertTrue(entered.wait(2))
                    self.assertTrue(manager.cancel())
                    deadline = time.monotonic() + 3
                    while manager.status()["running"] and time.monotonic() < deadline:
                        time.sleep(0.01)
                status = manager.status()
                self.assertEqual(status["status"], "cancelled")
                self.assertTrue(status["incomplete"])
                self.assertFalse(status["verified_escape"])
                self.assertIn("Cancelled safely", status["reason"])
                self.assertTrue(checkpoint.is_file())
            finally:
                manager.shutdown()

    def test_ui_success_gate_fails_closed_if_report_recheck_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "arena.json"
            state = arena.open_or_create(checkpoint, seed=7)
            arena.run_until_terminal(
                state, episode_budget=None, checkpoint_path=checkpoint)
            manager = attestor_ui.BlindArenaManager(checkpoint)
            try:
                with mock.patch.object(
                        arena, "verify_report",
                        return_value=(False, ["test replay failure"])):
                    status = manager.status()
                self.assertFalse(status["verified_escape"])
                self.assertFalse(status["terminal"])
                self.assertEqual(status["status"], "verification-failed")
            finally:
                manager.shutdown()


class _FakeBlindArena:
    def __init__(self):
        self.started = 0
        self.reset_count = 0
        self.cancelled = 0

    @staticmethod
    def _status():
        return {
            "ok": True, "schema": arena.STATUS_SCHEMA,
            "version": arena.VERSION, "objective": "Escape",
            "status": "ready", "last_episode_status": "not-started",
            "running": False, "cancel_requested": False,
            "terminal": False, "incomplete": False,
            "verified_escape": False, "episode_count": 0,
            "total_steps": 0, "observations_known": 0,
            "actions_known": 0,
            "frontier": {"state": "unopened", "observations_known": 0,
                         "actions_known": 0},
            "reason": "Ready.",
            "verification": {"report": False, "hidden_token": False,
                             "trace": False},
            "simulation_controls": {},
        }

    def status(self):
        return self._status()

    def start_or_resume(self):
        self.started += 1
        return self._status()

    def reset(self):
        self.reset_count += 1
        return self._status()

    def cancel(self):
        self.cancelled += 1
        return True


class BlindArenaApiTests(unittest.TestCase):
    def setUp(self):
        class QuietHandler(attestor_ui.Handler):
            def log_message(self, _format, *_args):
                return

        self.controller = _FakeBlindArena()
        self.server = attestor_ui.LimitedThreadingHTTPServer(
            ("127.0.0.1", 0), QuietHandler)
        port = self.server.server_address[1]
        self.server.allowed_hosts = {
            "127.0.0.1:%d" % port, "localhost:%d" % port}
        self.server.session_token = "test-token"
        self.server.blind_arena = self.controller
        self.base = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, path, *, method="GET", body=None, raw_body=None,
                token=True):
        headers = {"X-Attestor-Token": "test-token"} if token else {}
        data = None
        if raw_body is not None:
            data = raw_body
            headers["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method)
        return urllib.request.urlopen(request, timeout=3)

    def assert_http_error(self, expected, path, **kwargs):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request(path, **kwargs)
        self.assertEqual(raised.exception.code, expected)
        return json.loads(raised.exception.read())

    def raw_request(self, head, body=b""):
        port = self.server.server_address[1]
        request = (
            head.replace("{port}", str(port)).encode("ascii")
            + b"\r\n\r\n" + body
        )
        with socket.create_connection(("127.0.0.1", port), timeout=3) as stream:
            stream.settimeout(3)
            stream.sendall(request)
            response = b""
            while True:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                response += chunk
        return int(response.split(b" ", 2)[1])

    def test_status_is_token_bound_and_rejects_query_input(self):
        self.assert_http_error(
            403, "/api/blind-arena/status", token=False)
        self.assert_http_error(
            400, "/api/blind-arena/status?prompt=escape")
        self.assert_http_error(
            400, "/api/blind-arena/status", raw_body=b'{}')
        with self.request("/api/blind-arena/status") as response:
            status = json.loads(response.read())
        self.assertEqual(status["objective"], "Escape")

    def test_a_rejected_body_is_drained_so_the_error_arrives(self):
        """A rejected request must still deliver its 400, every time.

        The server closes the connection on ambiguous framing, which is
        correct -- a rejected body must never be readable as a second request.
        But closing while unread bytes sit in the receive buffer makes Windows
        send RST instead of FIN, and the client then raises
        ConnectionAbortedError instead of reading the response. This module
        failed about one run in five that way.
        """
        for size in (2, 512, 8192):
            with self.subTest(body_bytes=size):
                payload = b'{"x":"' + b"a" * max(size - 8, 1) + b'"}'
                self.assert_http_error(
                    400, "/api/blind-arena/status", raw_body=payload)

    def test_start_accepts_empty_object_only(self):
        self.assert_http_error(
            400, "/api/blind-arena/start", method="POST",
            body={"objective": "Escape", "path": "C:/"})
        self.assertEqual(self.controller.started, 0)
        with self.request(
                "/api/blind-arena/start", method="POST", body={}) as response:
            self.assertEqual(response.status, 202)
        self.assertEqual(self.controller.started, 1)

    def test_reset_requires_exact_boolean_confirmation(self):
        for body in ({}, {"confirmed": False}, {"confirmed": 1},
                     {"confirmed": True, "path": "C:/"}):
            with self.subTest(body=body):
                self.assert_http_error(
                    400, "/api/blind-arena/reset", method="POST", body=body)
        self.assertEqual(self.controller.reset_count, 0)
        with self.request(
                "/api/blind-arena/reset", method="POST",
                body={"confirmed": True}) as response:
            self.assertEqual(response.status, 200)
        self.assertEqual(self.controller.reset_count, 1)

    def test_reset_rejects_duplicate_json_keys(self):
        self.assert_http_error(
            400, "/api/blind-arena/reset", method="POST",
            raw_body=b'{"confirmed":false,"confirmed":true}')
        self.assertEqual(self.controller.reset_count, 0)

    def test_cancel_accepts_no_query_or_payload_surface(self):
        self.assert_http_error(
            400, "/api/blind-arena?path=C:/", method="DELETE")
        self.assert_http_error(
            400, "/api/blind-arena", method="DELETE", raw_body=b'{}')
        self.assertEqual(self.controller.cancelled, 0)
        with self.request("/api/blind-arena", method="DELETE") as response:
            self.assertEqual(response.status, 202)
        self.assertEqual(self.controller.cancelled, 1)

    def test_conflicting_or_duplicate_http_framing_fails_closed(self):
        common = (
            "Host: 127.0.0.1:{port}\r\n"
            "X-Attestor-Token: test-token\r\n"
            "Connection: close"
        )
        cases = (
            (
                "POST /api/blind-arena/start HTTP/1.1\r\n" + common
                + "\r\nContent-Type: application/json"
                + "\r\nContent-Length: 2\r\nTransfer-Encoding: chunked",
                b"{}",
            ),
            (
                "POST /api/blind-arena/start HTTP/1.1\r\n" + common
                + "\r\nContent-Type: application/json"
                + "\r\nContent-Length: 2\r\nContent-Length: 2",
                b"{}",
            ),
            (
                "GET /api/blind-arena/status HTTP/1.1\r\n" + common
                + "\r\nContent-Length: 0\r\nTransfer-Encoding: chunked",
                b"",
            ),
            (
                "DELETE /api/blind-arena HTTP/1.1\r\n" + common
                + "\r\nContent-Length: 0\r\nContent-Length: 0",
                b"",
            ),
        )
        for head, body in cases:
            with self.subTest(head=head.split("\r\n", 1)[0]):
                self.assertEqual(self.raw_request(head, body), 400)
        self.assertEqual(self.controller.started, 0)
        self.assertEqual(self.controller.cancelled, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
