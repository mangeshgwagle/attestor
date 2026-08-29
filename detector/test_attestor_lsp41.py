from __future__ import annotations

import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import attestor_lsp41


class AttestorLsp41Tests(unittest.TestCase):
    def setUp(self):
        self.server = attestor_lsp41.AttestorLanguageServer41()

    def test_initialize_advertises_incremental_multi_root_workspace_diagnostics(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                       "params": {"workspaceFolders": []}})[0]["result"]
        capabilities = response["capabilities"]
        self.assertEqual(response["serverInfo"]["version"], "4.1.3")
        self.assertEqual(response["serverInfo"]["name"], "Attestor 4.1.3")
        self.assertEqual(capabilities["experimental"]["attestor"]["presentationVersion"],
                         "4.1.3")
        self.assertEqual(capabilities["textDocumentSync"]["change"], 2)
        self.assertTrue(capabilities["diagnosticProvider"]["workspaceDiagnostics"])
        self.assertTrue(capabilities["workspace"]["workspaceFolders"]["supported"])
        self.assertTrue(capabilities["hoverProvider"])
        self.assertFalse(capabilities["experimental"]["attestor"]["workspaceWrites"])

    def test_incremental_utf16_change_and_stale_version_rejection(self):
        uri = "file:///C:/project/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1,
                             "text": "😀x\nif value is 0:\n    pass\n"}}})
        result = self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {
            "textDocument": {"uri": uri, "version": 2}, "contentChanges": [{
                "range": {"start": {"line": 0, "character": 2},
                          "end": {"line": 0, "character": 3}}, "text": "y"}]}})
        self.assertEqual(self.server.documents[uri]["text"].splitlines()[0], "😀y")
        self.assertTrue(any(row["code"] == "py-is-literal" for row in result[0]["params"]["diagnostics"]))
        stale = self.server.handle({"jsonrpc": "2.0", "id": 7, "method": "textDocument/didChange", "params": {
            "textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": "x = 1\n"}]}})[0]
        self.assertEqual(stale["error"]["code"], -32602)

    def test_workspace_diagnostics_are_bounded_multi_root_and_report_progress(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            first, second = Path(one), Path(two)
            (first / "a.py").write_text("if value is 0:\n    pass\n", encoding="utf-8")
            (second / "b.py").write_text("x = 1\n", encoding="utf-8")
            self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "workspaceFolders": [{"uri": first.as_uri(), "name": "one"},
                                     {"uri": second.as_uri(), "name": "two"}]}})
            responses = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "workspace/diagnostic",
                                            "params": {"workDoneToken": "scan"}})
            self.assertEqual(responses[0]["method"], "$/progress")
            self.assertEqual(responses[-2]["params"]["value"]["kind"], "end")
            items = responses[-1]["result"]["items"]
            self.assertEqual(len(items), 2)
            self.assertTrue(any(row["items"] for row in items))

    def test_workspace_diagnostic_response_bytes_are_partial_not_fatal(self):
        for index in range(10):
            uri = "file:///workspace/file-%02d.py" % index
            self.server.documents[uri] = {"text": "value = 1\n", "version": index,
                                          "languageId": "python"}
        diagnostic = {"range": {"start": {"line": 0, "character": 0},
                                  "end": {"line": 0, "character": 1}},
                      "message": "x" * 900, "source": "fixture", "data": {}}
        with mock.patch.object(attestor_lsp41, "MAX_WORKSPACE_RESPONSE_BYTES", 2_500), \
                mock.patch.object(self.server, "_analyze", return_value=[diagnostic]):
            response = self.server.handle({"jsonrpc": "2.0", "id": 22,
                                           "method": "workspace/diagnostic", "params": {}})[-1]
        coverage = response["result"]["attestorCoverage"]
        self.assertTrue(coverage["partial"])
        self.assertFalse(coverage["complete"])
        self.assertGreater(coverage["omittedDocuments"], 0)
        self.assertEqual(coverage["reason"], "workspace-response-byte-budget")
        self.assertLessEqual(len(attestor_lsp41._canonical(response)), 2_500)
        self.assertLess(len(response["result"]["items"]), 10)
        self.assertTrue(attestor_lsp41.encode_message(response))

    def test_cancellation_and_evidence_hover(self):
        self.server.handle({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 9}})
        completed = self.server.handle({"jsonrpc": "2.0", "id": 9,
                                        "method": "workspace/diagnostic", "params": {}})[0]
        self.assertIn("result", completed)
        self.assertFalse(self.server.active_requests)
        self.assertFalse(self.server.cancelled)
        self.server._activate_request(9)
        self.server.handle({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 9}})
        cancelled = self.server.handle({"jsonrpc": "2.0", "id": 9,
                                        "method": "workspace/diagnostic", "params": {}})[0]
        self.assertEqual(cancelled["error"]["code"], -32800)
        self.assertFalse(self.server.active_requests)
        self.assertFalse(self.server.cancelled)
        reused = self.server.handle({"jsonrpc": "2.0", "id": 9,
                                     "method": "workspace/diagnostic", "params": {}})[0]
        self.assertIn("result", reused)
        uri = "file:///C:/project/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1,
                             "text": "if value is 0:\n    pass\n"}}})
        hover = self.server.handle({"jsonrpc": "2.0", "id": 10, "method": "textDocument/hover", "params": {
            "textDocument": {"uri": uri}, "position": {"line": 0, "character": 2}}})[0]["result"]
        self.assertIn("Evidence `lsp41-", hover["contents"]["value"])
        self.assertIn("snippet `", hover["contents"]["value"])

    def test_stdio_cancel_is_observed_during_workspace_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.py").write_text("a = 1\n", encoding="utf-8")
            (root / "b.py").write_text("b = 2\n", encoding="utf-8")
            read_fd, write_fd = os.pipe()
            input_stream = os.fdopen(read_fd, "rb", buffering=0)
            output_stream = io.BytesIO()
            started = threading.Event()
            release = threading.Event()
            cancellation_seen = threading.Event()
            statuses: list[int] = []
            original_cancel = attestor_lsp41.AttestorLanguageServer41._cancel_request

            def slow_analyze(_server, _uri, _document):
                started.set()
                release.wait(3)
                return []

            def observed_cancel(server, request_id):
                original_cancel(server, request_id)
                if server._is_cancelled(request_id):
                    cancellation_seen.set()

            with os.fdopen(write_fd, "wb", buffering=0) as client, \
                    mock.patch.object(attestor_lsp41.AttestorLanguageServer41,
                                      "_analyze", slow_analyze), \
                    mock.patch.object(attestor_lsp41.AttestorLanguageServer41,
                                      "_cancel_request", observed_cancel):
                thread = threading.Thread(
                    target=lambda: statuses.append(
                        attestor_lsp41.serve(input_stream, output_stream)), daemon=True)
                thread.start()
                initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"workspaceFolders": [
                                  {"uri": root.as_uri(), "name": "fixture"}]}}
                scan = {"jsonrpc": "2.0", "id": 2, "method": "workspace/diagnostic",
                        "params": {}}
                client.write(attestor_lsp41.encode_message(initialize) +
                             attestor_lsp41.encode_message(scan))
                self.assertTrue(started.wait(3), "workspace scan did not start")
                client.write(attestor_lsp41.encode_message(
                    {"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 2}}))
                try:
                    self.assertTrue(cancellation_seen.wait(3),
                                    "stdio reader did not observe cancellation during the scan")
                finally:
                    release.set()
                client.write(attestor_lsp41.encode_message(
                    {"jsonrpc": "2.0", "id": 3, "method": "shutdown", "params": {}}))
                client.write(attestor_lsp41.encode_message(
                    {"jsonrpc": "2.0", "method": "exit", "params": {}}))
            thread.join(5)
            input_stream.close()
            self.assertFalse(thread.is_alive())
            self.assertEqual(statuses, [0])
            framed = io.BytesIO(output_stream.getvalue())
            messages = []
            while True:
                message = attestor_lsp41.read_message(framed)
                if message is None:
                    break
                messages.append(message)
            cancelled = next(row for row in messages if row.get("id") == 2)
            self.assertEqual(cancelled["error"]["code"], -32800)

    def test_verified_workspace_edit_is_preview_only_and_consent_gated(self):
        uri = "file:///C:/project/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1,
                             "text": "if value is 0:\n    pass\n"}}})
        denied = self.server.handle({"jsonrpc": "2.0", "id": 3, "method": "attestor/previewWorkspaceEdit",
                                     "params": {"uri": uri, "consent": False}})[0]["result"]
        self.assertFalse(denied["available"])
        self.assertTrue(denied["consentRequired"])
        accepted = {"accepted": True, "improved_source": "if value == 0:\n    pass\n"}
        with mock.patch("verified_remediation.improve_source", return_value=accepted):
            preview = self.server.handle({"jsonrpc": "2.0", "id": 4,
                "method": "attestor/previewWorkspaceEdit", "params": {"uri": uri, "consent": True}})[0]["result"]
        self.assertTrue(preview["previewOnly"])
        self.assertTrue(preview["consentRecorded"])
        self.assertIn("workspaceEdit", preview)
        self.assertNotIn("applyEdit", json.dumps(preview))
        self.assertEqual(self.server.documents[uri]["text"], "if value is 0:\n    pass\n")

    def test_framing_round_trip(self):
        message = {"jsonrpc": "2.0", "id": 5, "method": "shutdown"}
        self.assertEqual(attestor_lsp41.read_message(io.BytesIO(attestor_lsp41.encode_message(message))), message)


if __name__ == "__main__":
    unittest.main()
