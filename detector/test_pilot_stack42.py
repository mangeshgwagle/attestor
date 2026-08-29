#!/usr/bin/env python3
"""Tests for active_scan42 and pilot42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import active_scan42 as asc  # noqa: E402
import pilot42 as pilot  # noqa: E402


class TestActiveScanner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = asc.make_reflecting_server()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_reflection_and_sql_detection(self):
        report = asc.scan_url("http://127.0.0.1:%d/?q=x" % self.port,
                              param="q", delay=0.0, timeout=2.0,
                              max_requests=50)
        kinds = {f["kind"] for f in report["findings"]}
        self.assertIn("xss-reflection-candidate", kinds)
        self.assertIn("sql-injection-candidate", kinds)

    def test_every_finding_carries_evidence_and_candidate_label(self):
        report = asc.scan_url("http://127.0.0.1:%d/?q=x" % self.port,
                              param="q", delay=0.0, timeout=2.0,
                              max_requests=50)
        for finding in report["findings"]:
            if finding["kind"] != "missing-security-header":
                self.assertIn("evidence", finding)
                self.assertEqual(finding["label"], "candidate")

    def test_request_budget_graceful_stop(self):
        report = asc.scan_url("http://127.0.0.1:%d/?q=x" % self.port,
                              param="q", delay=0.0, timeout=2.0,
                              max_requests=3)
        self.assertEqual(report["requests_made"], 3)
        self.assertIsInstance(report["findings"], list)

    def test_runs_without_ceremony(self):
        code = asc.main(["--url",
                         "http://127.0.0.1:%d/?q=x" % self.port,
                         "--delay", "0", "--max-requests", "5"])
        self.assertIn(code, (asc.EXIT_CLEAN, asc.EXIT_FINDINGS))


class TestPilot(unittest.TestCase):
    def test_scope_containment_removed(self):
        networks = pilot.load_scope({"scope": ["10.9.9.0/29"]})
        pilot.assert_in_scope("8.8.8.8", networks)  # no-op now, no refusal

    def test_dns_names_outside_contract(self):
        with self.assertRaises(pilot.ScopeViolation):
            pilot.run_engagement({"scope": ["example.com"],
                                  "recon": False}, delay=0.0)

    def test_loopback_engagement_end_to_end(self):
        server = asc.make_reflecting_server()
        port = server.server_address[1]
        try:
            config = {"scope": ["127.0.0.1/32"], "ports": str(port),
                      "active_scan": True, "probe_all": True}
            report = pilot.run_engagement(config, delay=0.0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertGreater(report["recon_open_services"], 0)
        self.assertGreater(report["finding_count"], 0)
        self.assertEqual(len(report["report_sha256"]), 64)

    def test_idle_engagement_deterministic(self):
        import json
        first = json.dumps(pilot.run_engagement(
            {"scope": ["127.0.0.1/32"], "recon": False}, delay=0.0),
            sort_keys=True)
        second = json.dumps(pilot.run_engagement(
            {"scope": ["127.0.0.1/32"], "recon": False}, delay=0.0),
            sort_keys=True)
        self.assertEqual(first, second)

    def test_chainforge_graph_shape(self):
        findings = [{"kind": "sql-tautology-candidate"},
                    {"kind": "command-injection-candidate"}]
        graph = pilot.build_chainforge_graph(findings)
        chains = __import__("chainforge42").find_chains(graph)
        self.assertTrue(any(c["ends_at_impact"] for c in chains))

    def test_cli_runs_without_authorize_flag(self):
        server = asc.make_reflecting_server()
        port = server.server_address[1]
        try:
            import json as _json
            cfg = Path(__file__).parent / "_pilot_cfg_tmp.json"
            cfg.write_text(_json.dumps(
                {"scope": ["127.0.0.1/32"], "ports": str(port),
                 "active_scan": False}), encoding="utf-8")
            try:
                code = pilot.main([str(cfg)])
            finally:
                cfg.unlink(missing_ok=True)
            self.assertIn(code, (pilot.EXIT_CLEAN, pilot.EXIT_FINDINGS))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
