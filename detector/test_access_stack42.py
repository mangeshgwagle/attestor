#!/usr/bin/env python3
"""Tests for bola_hunter42, proxy42, and universal_fuzz42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bola_hunter42 as bh  # noqa: E402
import proxy42 as px  # noqa: E402
import universal_fuzz42 as uf  # noqa: E402


class TestBolaHunter(unittest.TestCase):
    def test_vulnerable_app_flagged_graph_aware(self):
        server = bh._make_app(enforce_owner=False)
        port = server.server_address[1]
        try:
            report = bh.hunt(
                [{"method": "GET", "path": "/api/invoice/101",
                  "headers": {}}],
                "http://127.0.0.1:%d" % port,
                {"a": {"headers": {"X-User": "alice"}},
                 "b": {"headers": {"X-User": "bob"}},
                 "unauthenticated": True},
                timeout=3.0)
        finally:
            server.shutdown()
            server.server_close()
        verdicts = {f["verdict"] for f in report["findings"]}
        self.assertIn("same-content-wrong-principal", verdicts)
        self.assertGreaterEqual(report["graph_nodes"], 1)

    def test_hardened_app_confirms_controls(self):
        server = bh._make_app(enforce_owner=True)
        port = server.server_address[1]
        try:
            report = bh.hunt(
                [{"method": "GET", "path": "/api/invoice/101",
                  "headers": {}}],
                "http://127.0.0.1:%d" % port,
                {"a": {"headers": {"X-User": "alice"}},
                 "b": {"headers": {"X-User": "bob"}}},
                timeout=3.0)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(report["finding_count"], 0)
        self.assertGreaterEqual(report["protected_controls_confirmed"], 1)

    def test_id_extraction_patterns(self):
        text = ("order 4711 ref 550e8400-e29b-41d4-a716-446655440000 "
                "mail a.b@x.co")
        kinds = {o["kind"] for o in bh.extract_object_ids(text)}
        self.assertEqual(kinds, {"numeric-id", "uuid", "email"})

    def test_compare_classification_bands(self):
        self.assertEqual(bh.compare_responses(200, 100, 403, 9),
                         "protected")
        self.assertEqual(bh.compare_responses(
            200, 100, 200, 104), "same-content-wrong-principal")
        self.assertEqual(bh.compare_responses(
            200, 900, 200, 400), "partial-divergence-review")


class TestProxy(unittest.TestCase):
    def test_match_replace_and_autorize_ledger(self):
        result = px.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])

    def test_rule_compilation_bounds(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.json"
            path.write_text(json.dumps([
                {"field": "any", "header": "authorization",
                 "match": "A-TOKEN", "replace": "B-TOKEN"},
            ]), encoding="utf-8")
            rules = px.load_rules(str(path))
            url, headers, body = px.apply_rules(
                rules, "http://x/", {"Authorization": "Bearer A-TOKEN 1"},
                b"data-A-TOKEN")
            self.assertEqual(headers["Authorization"], "Bearer B-TOKEN 1")
            self.assertEqual(body, b"data-B-TOKEN")

    def test_credential_swap_scope(self):
        merged = px.swap_credentials(
            {"Authorization": "Bearer A", "X-Keep": "yes"},
            {"Authorization": "Bearer B"})
        self.assertEqual(merged["Authorization"], "Bearer B")
        self.assertEqual(merged["X-Keep"], "yes")


class TestUniversalFuzz(unittest.TestCase):
    def test_subprocess_target_crash_found(self):
        script = Path(__file__).parent / "_uf_tmp_target.py"
        script.write_text(
            "import sys\n"
            "data = sys.stdin.buffer.read()\n"
            "if data.startswith(b'PWN'):\n"
            "    raise IndexError('planted')\n",
            encoding="utf-8")
        try:
            runner = uf.build_runner([sys.executable, str(script)],
                                     use_stdin=True, timeout=5.0)
            report = uf.fuzz_binary(runner, seeds=[b"PW"],
                                    iterations=5000, seconds=25.0,
                                    seed_rng=11, tokens=(b"PWN",))
            self.assertGreaterEqual(report["crashes_found"], 1)
            first = bytes.fromhex(report["crashes"][0]["input_hex"])
            self.assertTrue(first.startswith(b"PWN"))
        finally:
            script.unlink(missing_ok=True)

    def test_crash_signature_detection(self):
        self.assertTrue(uf.is_crash(-11, b"", expected_clean=(0,)))
        self.assertTrue(uf.is_crash(
            1, b"AddressSanitizer: heap-buffer-overflow"))
        self.assertFalse(uf.is_crash(0, b"all good"))
        self.assertTrue(uf.is_crash(99, b""))

    def test_selftest_passes(self):
        result = uf.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
