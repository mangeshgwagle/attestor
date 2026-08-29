#!/usr/bin/env python3
"""Tests for malbolge42 and msf_lite42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import malbolge42 as mb  # noqa: E402
import msf_lite42 as msf  # noqa: E402


class TestMalbolgeCore(unittest.TestCase):
    def test_crazy_matrix_published_values(self):
        full_ones = (3 ** 10 - 1) // 2          # all trits = 1
        self.assertEqual(mb.crazy_op(0, 0), full_ones)
        # row a-trit=0 against column m-trit=1 is 0 in every position
        self.assertEqual(mb.crazy_op(0, full_ones), 0)
        # row a-trit=1 against column m-trit=0 is 1 in every position
        self.assertEqual(mb.crazy_op(full_ones, 0), full_ones)

    def test_rotate_right_moves_low_trit(self):
        self.assertEqual(mb.rotate_right(1), 3 ** 9)
        self.assertEqual(mb.rotate_right(3), 1)

    def test_immediate_halt_program(self):
        report = mb.analyze(bytes([81]))         # (81+0)%94 == hlt
        self.assertTrue(report["valid_program"])
        self.assertTrue(report["execution"]["halted"])

    def test_invalid_instruction_rejected(self):
        report = mb.analyze(b"!!")
        self.assertFalse(report["valid_program"])
        self.assertIn("invalid instruction", report["reason"])

    def test_nops_walk_until_budget_or_cycle(self):
        report = mb.analyze(bytes([68, 67]), max_steps=50_000)
        self.assertTrue(report["valid_program"])
        execution = report["execution"]
        self.assertTrue(execution["cycle_detected"]
                        or execution["steps_executed"] >= 50_000
                        or bool(execution.get("error")))

    def test_fuzz_entry_never_raises(self):
        import os
        for blob in (b"", b"\x00", bytes(range(33, 127)),
                     os.urandom(64)):
            try:
                mb.fuzz_entry(blob)
            except Exception as exc:  # noqa: BLE001
                self.fail("fuzz_entry raised %r" % exc)

    def test_selftest_passes(self):
        result = mb.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


class TestMsfLite(unittest.TestCase):
    def test_registry_and_refusals(self):
        listing = msf.list_modules()
        names = {m["name"] for m in listing["modules"]}
        self.assertIn("exploit.sqli_tautology", names)
        self.assertIn("payload.exec_marker", names)
        self.assertIn("reverse-shell", listing["refusal_list"])
        self.assertNotIn("reverse-shell",
                         {m["name"].lower() for m in listing["modules"]})

    def test_payload_module_is_marker_only(self):
        result = msf.run_module("payload.exec_marker", {}, True)
        self.assertEqual(result["marker"], ";cfmark42;")
        self.assertIn("reverse-shell", result["refused_alternatives"])

    def test_unknown_module_refused(self):
        with self.assertRaises(msf.MsfError):
            msf.run_module("persistence_service", {}, True)

    def test_modules_run_without_ceremony(self):
        outcome = msf.run_module("payload.exec_marker", {},
                                 authorized=False)
        self.assertEqual(outcome["marker"], ";cfmark42;")

    def test_sqli_exploit_confirms_on_loopback(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading
        import urllib.parse

        class App(BaseHTTPRequestHandler):
            def do_GET(self):
                query = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(self.path).query)
                user = query.get("user", ["x"])[0]
                if "1'='1" in user:
                    body = b"<html>" + b"W" * 1500 + b"</html>"
                else:
                    body = b"<html>none</html>"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = HTTPServer(("127.0.0.1", 0), App)
        threading.Thread(target=server.serve_forever,
                         daemon=True).start()
        port = server.server_address[1]
        try:
            outcome = msf.run_module(
                "exploit.sqli_tautology",
                {"url": "http://127.0.0.1:%d/?q=x&user=z" % port},
                authorized=True)
        finally:
            server.shutdown()
            server.server_close()
        self.assertTrue(outcome["runtime_confirmed"])
        self.assertEqual(outcome["status_baseline"],
                         outcome["status_payload"])

    def test_selftest_passes(self):
        result = msf.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
