#!/usr/bin/env python3
"""Adversarial contracts for Attestor 4.1.3 attack-surface analysis."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import attack_surface413


def write(root: Path, relative: str, text: str) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def rule_names(report: dict) -> set[str]:
    return {row["rule"] for row in report["findings"]}


class AttackSurface413Tests(unittest.TestCase):
    def test_determinism_digest_schema_and_static_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "app.py", "def add(left, right):\n    return left + right\n")
            first = attack_surface413.analyze(root)
            second = attack_surface413.analyze(root)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "attestor.attack-surface/4.1")
        self.assertEqual(first["version"], "4.1.3")
        digest_body = {key: value for key, value in first.items()
                       if key != "report_sha256"}
        expected = hashlib.sha256(json.dumps(
            digest_body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(first["report_sha256"], expected)
        self.assertFalse(first["assurance"]["target_code_executed"])
        self.assertFalse(first["assurance"]["network_accessed"])
        self.assertFalse(first["assurance"]["target_files_written"])
        self.assertFalse(first["assurance"]["exploit_payloads_generated"])
        self.assertEqual(first["execution"]["target_code_executed"], False)
        valid, errors = attack_surface413.verify_report(first)
        self.assertTrue(valid, errors)

    def test_in_memory_documents_skip_filesystem_and_tampering_is_rejected(self):
        report = attack_surface413.analyze(
            "provided://unit-test",
            snapshot_or_documents={
                "api.py": (
                    "from flask import request\n"
                    "@app.get('/search')\n"
                    "def search():\n"
                    "    return cursor.execute(request.args.get('query'))\n"
                ),
            },
        )
        self.assertEqual(
            report["coverage"]["inventory"]["scope_kind"], "provided-snapshot")
        self.assertIn("as413-sql-injection", rule_names(report))
        valid, errors = attack_surface413.verify_report(report)
        self.assertTrue(valid, errors)
        tampered = json.loads(json.dumps(report))
        tampered["status"] = "clean"
        valid, errors = attack_surface413.verify_report(tampered)
        self.assertFalse(valid)
        self.assertIn("report digest mismatch", errors)

    def test_cross_file_route_call_to_sink_produces_static_attack_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "app.py", (
                "from flask import request\n"
                "from service import lookup\n"
                "@app.get('/items/<item_id>')\n"
                "def item(item_id):\n"
                "    return lookup(item_id)\n"
            ))
            write(root, "service.py", (
                "def lookup(item_id):\n"
                "    return database.query.get(item_id)\n"
            ))
            report = attack_surface413.analyze(root)
        self.assertIn("as413-potential-idor", rule_names(report))
        invokes = [row for row in report["graph"]["edges"]
                   if row["kind"] == "invokes"]
        self.assertTrue(invokes)
        paths = [row for row in report["attack_paths"]
                 if row["category"] == "authorization"]
        self.assertTrue(paths)
        self.assertTrue(all(row["evidence_state"] == "inferred" for row in paths))
        self.assertTrue(all(row["runtime_exploitability"] == "unverified"
                            for row in paths))
        self.assertTrue(any(
            factor["name"] == "entrypoint-to-sink-static-reachability"
            and factor["evidence_state"] == "inferred"
            for factor in paths[0]["exploitability"]["factors"]))
        self.assertTrue(report["threat_model"]["entry_points"])

    def test_python_injection_ssrf_and_cookie_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "api.py", (
                "from flask import request\n"
                "import os, requests\n"
                "@app.post('/work')\n"
                "def work():\n"
                "    value = request.args.get('value')\n"
                "    cursor.execute(value)\n"
                "    os.system(value)\n"
                "    eval(value)\n"
                "    requests.get(value)\n"
                "    response.set_cookie('session', value)\n"
            ))
            report = attack_surface413.analyze(root)
        expected = {
            "as413-sql-injection", "as413-command-injection",
            "as413-code-injection", "as413-ssrf", "as413-insecure-cookie",
        }
        self.assertTrue(expected <= rule_names(report), expected - rule_names(report))
        security = [row for row in report["findings"]
                    if row["rule"] != "as413-insecure-cookie"]
        self.assertTrue(all(row["evidence_state"] == "inferred" for row in security))
        self.assertTrue(all(row["exploitability"]["runtime_exploitability"]
                            == "unverified" for row in security))
        self.assertGreaterEqual(len(report["attack_paths"]), 4)

    def test_explicit_web_auth_and_request_framing_rules(self):
        source = (
            "WTF_CSRF_ENABLED = False\n"
            "Access-Control-Allow-Origin: *\n"
            "options = {'verify_signature': False}\n"
            "algorithms = ['none']\n"
            "validate_state = False\n"
            "use_pkce = False\n"
            "redirect_uri = 'https://*.example.test/callback'\n"
            "headers['Content-Length'] = incoming_length\n"
            "headers['Transfer-Encoding'] = incoming_encoding\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "security.cfg", source)
            report = attack_surface413.analyze(root)
        expected = {
            "as413-csrf-disabled", "as413-unsafe-cors",
            "as413-jwt-verification-disabled", "as413-jwt-none-algorithm",
            "as413-oauth-state-disabled", "as413-oauth-pkce-disabled",
            "as413-oauth-wildcard-redirect",
            "as413-request-smuggling-framing-conflict",
        }
        self.assertTrue(expected <= rule_names(report), expected - rule_names(report))
        framing = next(row for row in report["findings"]
                       if row["rule"] == "as413-request-smuggling-framing-conflict")
        self.assertIn("not proven", " ".join(framing["gaps"]))

    def test_js_lexical_adapter_is_labeled_and_never_claimed_parser_grade(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "api.js", (
                "router.get('/u/:id', authenticate, handler);\n"
                "db.query(`SELECT * FROM u WHERE id=${req.params.id}`);\n"
                "fetch(req.query.url);\n"
                "User.findById(req.params.id);\n"
                "res.cookie('sid', token, {});\n"
            ))
            report = attack_surface413.analyze(root)
        self.assertTrue({
            "as413-sql-injection", "as413-ssrf", "as413-potential-idor",
            "as413-insecure-cookie",
        } <= rule_names(report))
        self.assertTrue(any(row["kind"] == "lexical-language-adapter"
                            for row in report["coverage"]["gaps"]))
        self.assertEqual(
            report["threat_model"]["entry_points"][0]["authentication_state"],
            "proven-present")

    def test_limits_and_invalid_roots_fail_or_degrade_explicitly(self):
        failed = attack_surface413.analyze("definitely-does-not-exist-413")
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["findings"], [])
        with self.assertRaises(attack_surface413.AttackSurface413Error):
            attack_surface413.Limits(max_files=0)
        with self.assertRaises(attack_surface413.AttackSurface413Error):
            attack_surface413.analyze(Path.cwd(), limits={})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "a.py", "def a():\n    return 1\n")
            write(root, "b.py", "def b():\n    return 2\n")
            report = attack_surface413.analyze(
                root, limits=attack_surface413.Limits(max_files=1))
        self.assertIn("max_files", report["limits"]["hit"])
        self.assertFalse(report["coverage"]["complete"])

    def test_symlinks_are_excluded_and_root_link_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent / "root"
            root.mkdir()
            outside = write(parent, "outside.py", "eval(input())\n")
            child_link = root / "outside.py"
            root_link = parent / "root-link"
            try:
                os.symlink(outside, child_link)
                os.symlink(root, root_link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            report = attack_surface413.analyze(root)
            refused = attack_surface413.analyze(root_link)
        self.assertEqual(report["coverage"]["inventory"]["files_loaded"], 0)
        self.assertTrue(any(row["kind"] == "link-or-reparse-excluded"
                            for row in report["coverage"]["gaps"]))
        self.assertEqual(refused["status"], "failed")
        self.assertIn("symbolic link", refused["coverage"]["errors"][0])

    def test_source_controls_are_escaped_and_source_text_is_not_echoed(self):
        marker = "UNIQUE-SECRET-LIKE-MARKER-413"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "odd.py", (
                "@app.get('/safe\\u202Eroute')\n"
                "def route():\n"
                f"    marker = '{marker}'\n"
                "    return marker\n"
            ))
            report = attack_surface413.analyze(root)
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("\u202e", serialized)
        self.assertIn("\\\\u202E", serialized)
        self.assertNotIn(marker, serialized)

    def test_compose_service_boundary_and_literal_call_edge(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "compose.yaml", (
                "services:\n"
                "  api:\n"
                "    image: example/api\n"
                "  billing:\n"
                "    image: example/billing\n"
            ))
            write(root, "client.py", (
                "BILLING_URL = 'http://billing:8080/invoices'\n"))
            report = attack_surface413.analyze(root)
        self.assertTrue(any(row["kind"] == "calls-service"
                            for row in report["graph"]["edges"]))
        self.assertTrue(any(row["id"] == "TB413-service-to-service"
                            for row in report["threat_model"]["trust_boundaries"]))

    def test_django_cross_file_route_and_openapi_contract_entrypoints(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "urls.py", (
                "from django.urls import path\n"
                "from views import item\n"
                "urlpatterns = [path('items/<int:item_id>', item)]\n"
            ))
            write(root, "views.py", (
                "def item(request, item_id):\n"
                "    return database.query.get(item_id)\n"
            ))
            write(root, "openapi.yaml", (
                "openapi: 3.1.0\n"
                "paths:\n"
                "  /health:\n"
                "    get:\n"
                "      responses: {}\n"
            ))
            report = attack_surface413.analyze(root)
        routes = {
            row["route"] for row in report["threat_model"]["entry_points"]}
        self.assertIn("items/<int:item_id>", routes)
        self.assertIn("/health", routes)
        self.assertTrue(any(
            row["category"] == "authorization"
            and len(row["nodes"]) >= 3
            for row in report["attack_paths"]))

    def test_dynamic_oauth_redirect_is_inferred_not_claimed_exploitable(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "login.py", (
                "from flask import request\n"
                "@app.get('/login')\n"
                "def login():\n"
                "    target = request.args.get('next')\n"
                "    return oauth.authorize(redirect_uri=target)\n"
            ))
            report = attack_surface413.analyze(root)
        row = next(item for item in report["findings"]
                   if item["rule"] == "as413-oauth-dynamic-redirect")
        self.assertEqual(row["evidence_state"], "inferred")
        self.assertEqual(
            row["exploitability"]["runtime_exploitability"], "unverified")

    def test_context_specific_safe_shapes_do_not_trigger_unrelated_rules(self):
        report = attack_surface413.analyze(
            "provided://safe-shapes",
            snapshot_or_documents={
                "api.py": (
                    "from flask import request\n"
                    "def search():\n"
                    "    return requests.get('https://fixed.example/api', "
                    "params={'q': request.args.get('q')})\n"
                ),
                "api.js": (
                    "db.query('SELECT * FROM users WHERE id = ?', [req.params.id]);\n"
                    "fetch('https://fixed.example/api', {body: req.body});\n"
                ),
                "tls.cfg": "verify = false\n",
            },
        )
        self.assertNotIn("as413-ssrf", rule_names(report))
        self.assertNotIn("as413-sql-injection", rule_names(report))
        self.assertNotIn("as413-jwt-verification-disabled", rule_names(report))


if __name__ == "__main__":
    unittest.main()
