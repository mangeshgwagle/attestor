from __future__ import annotations

import time
from pathlib import Path
import tempfile
import unittest

import precision_catalog
import scanengine


class PrecisionCatalogContractTests(unittest.TestCase):
    def test_exact_count_unique_semantics_and_complete_metadata(self):
        self.assertEqual(len(precision_catalog.PROFILES), 25)
        self.assertEqual(len(precision_catalog.RULES), 15_000)
        self.assertEqual(
            {language: len(rows) for language, rows in precision_catalog.SINKS_BY_LANGUAGE.items()},
            {"python": 50, "javascript": 50, "java": 50, "csharp": 50, "php": 50})
        rules = tuple(precision_catalog.RULES)
        self.assertEqual(len({row.rid for row in rules}), 15_000)
        self.assertEqual(len({row.fingerprint for row in rules}), 15_000)
        self.assertTrue(all(row.cwe.startswith("CWE-") and row.owasp and row.references
                            and row.description and row.remediation for row in rules))

    def test_every_dimension_self_proves(self):
        self.assertEqual(precision_catalog.validate_catalog(), [])
        summary = precision_catalog.catalog_summary()
        self.assertEqual(summary["rules"], 15_000)
        self.assertEqual(set(summary["families"].values()), {1_500})
        self.assertEqual(set(summary["languages"].values()), {3_000})


class PrecisionCatalogFlowTests(unittest.TestCase):
    def rules(self, source: str, path: str) -> set[str]:
        return {row.rule for row in precision_catalog.analyze(source, path)}

    def test_direct_flows_cover_all_five_language_adapters(self):
        fixtures = (
            ("app.py", 'from flask import request\nvalue = eval(request.args.get("x"))\n', "python-flask"),
            ("app.js", "const express = require('express');\nvalue = eval(req.query['x']);\n", "javascript-express"),
            ("Controller.java", 'import org.springframework.web.bind.annotation.RestController;\nRuntime.getRuntime().exec(request.getParameter("x"));\n', "java-spring"),
            ("Controller.cs", 'using Microsoft.AspNetCore.Mvc;\nProcess.Start(Request.Query["x"]);\n', "csharp-aspnet-core"),
            ("Controller.php", '<?php\nuse Illuminate\\Http\\Request;\neval($request->query("x"));\n', "php-laravel"),
        )
        for path, source, ecosystem in fixtures:
            with self.subTest(path=path):
                findings = precision_catalog.analyze(source, path)
                self.assertEqual(len(findings), 1, findings)
                self.assertEqual(findings[0].ecosystem, ecosystem)

    def test_bounded_local_flow_and_reassignment_kill(self):
        unsafe = (
            "from flask import request\nimport os\n"
            "command = request.args.get('cmd')\n"
            "audit = 1\n"
            "os.system(command)\n")
        safe = unsafe.replace("audit = 1\n", "command = 'fixed'\n")
        self.assertTrue(any(row.sink_operation == "os-system"
                            for row in precision_catalog.analyze(unsafe, "app.py")))
        self.assertEqual(precision_catalog.analyze(safe, "app.py"), [])

    def test_parameterization_sanitization_comments_and_strings_are_negative(self):
        source = (
            "from flask import request\n"
            "cursor.execute('SELECT * FROM t WHERE id=?', (request.args.get('id'),))\n"
            "safe = Markup(html.escape(request.args.get('html')))\n"
            "# eval(request.args.get('comment'))\n"
            "example = \"eval(request.args.get('string'))\"\n")
        self.assertEqual(precision_catalog.analyze(source, "app.py"), [])

    def test_source_must_be_inside_sink_argument_and_profile_must_be_active(self):
        elsewhere = (
            "from flask import request\n"
            "eval('fixed'); value = request.args.get('x')\n")
        no_framework = "value = eval(request.args.get('x'))\n"
        self.assertEqual(precision_catalog.analyze(elsewhere, "app.py"), [])
        self.assertEqual(precision_catalog.analyze(no_framework, "app.py"), [])

    def test_specific_auth_channel_wins_over_generic_header(self):
        source = (
            "from flask import request\n"
            "value = eval(request.headers.get(AUTHORIZATION))\n")
        findings = precision_catalog.analyze(source, "app.py")
        self.assertEqual(len(findings), 1, findings)
        self.assertEqual(findings[0].source_channel, "auth")

    def test_scan_cost_is_indexed_not_proportional_to_catalog_size(self):
        source = "from flask import request\n" + "\n".join(
            "safe_%d = %d" % (index, index) for index in range(2_500))
        started = time.perf_counter()
        findings = precision_catalog.analyze(source, "app.py")
        elapsed = time.perf_counter() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 5.0, "indexed scan took %.3fs" % elapsed)

    def test_unified_scan_engine_emits_precision_catalog_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text(
                "from flask import request\nvalue = eval(request.args.get('x'))\n",
                encoding="utf-8")
            result = scanengine.scan([str(path)], jobs=1, use_cache=False)
        rows = [row for row in result.issues if row.source == "precision_catalog"]
        self.assertEqual(len(rows), 1, result.issues)
        self.assertEqual(rows[0].cwe, "CWE-94")
        self.assertEqual(rows[0].owasp, "A05:2025 Injection")
        self.assertEqual(len(rows[0].fingerprint), 64)
        self.assertTrue(rows[0].asvs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
