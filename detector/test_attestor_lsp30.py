from __future__ import annotations

import io
import json
import unittest
from unittest import mock

import attestor_lsp


class AttestorLspTests(unittest.TestCase):
    def setUp(self):
        self.server = attestor_lsp.AttestorLanguageServer()

    def test_initialize_advertises_lsp_318_workflows(self):
        response = self.server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})[0]
        capabilities = response["result"]["capabilities"]
        self.assertEqual(response["result"]["serverInfo"], {"name": "Attestor 4.0", "version": "4.0.0"})
        self.assertEqual(capabilities["positionEncoding"], "utf-16")
        self.assertTrue(capabilities["codeActionProvider"])
        identity = capabilities["experimental"]["attestor"]
        self.assertEqual(identity["analysisEngine"], "deterministic-live-core/3.0")
        self.assertEqual(identity["compatibilityVersions"], ["3.5", "3.0"])

    def test_open_and_change_publish_bounded_in_memory_diagnostics(self):
        uri = "file:///C:/project/app.py"
        opened = self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": "if value is 0:\n    pass\n"}}})
        diagnostics = opened[0]["params"]["diagnostics"]
        self.assertTrue(any(item["code"] == "py-is-literal" for item in diagnostics))
        self.assertTrue(all(item["source"] == "Attestor 4.0" for item in diagnostics))
        self.assertTrue(all(item["data"]["analysis_engine"] == "deterministic-live-core/3.0"
                            for item in diagnostics))
        changed = self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {
            "textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": "if value == 0:\n    pass\n"}]}})
        self.assertFalse(any(item["code"] == "py-is-literal" for item in changed[0]["params"]["diagnostics"]))

    def test_code_actions_offer_preview_without_workspace_edit(self):
        uri = "file:///C:/project/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": "if value is 0:\n    pass\n"}}})
        response = self.server.handle({"jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": {
            "textDocument": {"uri": uri}, "range": {"start": {"line": 0, "character": 0},
                                                      "end": {"line": 0, "character": 10}}, "context": {}}})[0]
        self.assertTrue(response["result"])
        self.assertNotIn("edit", response["result"][0])
        self.assertEqual(response["result"][0]["command"]["command"], "attestor.previewImprovement")

    def test_close_clears_diagnostics_and_memory(self):
        uri = "file:///tmp/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1, "text": "x = 1\n"}}})
        result = self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didClose", "params": {
            "textDocument": {"uri": uri}}})
        self.assertEqual(result[0]["params"]["diagnostics"], [])
        self.assertNotIn(uri, self.server.documents)

    def test_framing_round_trip_and_duplicate_header_rejection(self):
        message = {"jsonrpc": "2.0", "id": 4, "method": "shutdown"}
        decoded = attestor_lsp.read_message(io.BytesIO(attestor_lsp.encode_message(message)))
        self.assertEqual(decoded, message)
        with self.assertRaises(attestor_lsp.LspProtocolError):
            attestor_lsp.read_message(io.BytesIO(b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}"))

    def test_invalid_params_error_never_echoes_source(self):
        secret = "super-secret-source-value"
        response = self.server.handle({"jsonrpc": "2.0", "id": 5, "method": "attestor/improvedResult",
                                       "params": {"textDocument": {"uri": secret}}})[0]
        self.assertNotIn(secret, json.dumps(response))

    def test_rejected_candidate_source_is_withheld_from_editor(self):
        uri = "file:///C:/project/app.py"
        self.server.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
            "textDocument": {"uri": uri, "languageId": "python", "version": 1,
                             "text": "DEBUG = True\n"}}})
        rejected = {"available": True, "accepted": False,
                    "improved_source": "DEBUG = False\n", "diff": "candidate diff",
                    "reasons": ["verification rejected the candidate"]}
        with mock.patch("verified_remediation.improve_source", return_value=rejected):
            response = self.server.handle({"jsonrpc": "2.0", "id": 7,
                "method": "attestor/improvedResult",
                "params": {"textDocument": {"uri": uri}}})[0]["result"]
        self.assertFalse(response["available"])
        self.assertEqual(response["improved_source"], "")
        self.assertEqual(response["diff"], "")
        self.assertIn("rejected", response["reason"])

    def test_shutdown_and_exit_lifecycle(self):
        self.server.handle({"jsonrpc": "2.0", "id": 6, "method": "shutdown"})
        self.server.handle({"jsonrpc": "2.0", "method": "exit"})
        self.assertTrue(self.server.shutdown_requested)
        self.assertTrue(self.server.exit_requested)


if __name__ == "__main__":
    unittest.main()
