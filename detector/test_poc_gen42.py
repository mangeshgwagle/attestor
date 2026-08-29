#!/usr/bin/env python3
"""Tests for the CWE-to-PoC generator.

Every generated PoC must be:
1. Syntactically valid Python (ast.parse succeeds)
2. Parameterized with the finding's actual data (endpoint, param, file)
3. Complete (has a __main__ block, imports, exit codes)
4. Self-contained (no placeholder %%VAR%% left unfilled)
"""
from __future__ import annotations

import ast
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import poc_gen42 as pg  # noqa: E402


def _finding(cwe: int, **kw) -> pg.PocFinding:
    defaults = dict(
        rule="test-rule",
        file_path="src/App.java",
        line=42,
        language="java",
        source="userId",
        context={
            "endpoint": "http://app.internal/api/search",
            "param": "q",
            "method": "GET",
        },
    )
    defaults.update(kw)
    return pg.PocFinding(cwe=cwe, **defaults)


class EveryRegisteredCweProducesAPoc(unittest.TestCase):
    """If a CWE is registered, it must produce at least one valid PoC."""

    def test_supported_cwes_is_not_empty(self):
        self.assertTrue(len(pg.supported_cwes()) >= 10,
                        "expected at least 10 CWEs, got %d" % len(pg.supported_cwes()))

    def test_every_cwe_generates_at_least_one_poc(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                finding = _finding(cwe)
                pocs = pg.generate(finding)
                self.assertTrue(len(pocs) >= 1,
                                "CWE-%d registered but generated 0 PoCs" % cwe)

    def test_every_generated_poc_is_valid_python(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                finding = _finding(cwe)
                for p in pg.generate(finding):
                    ok, msg = pg.validate_poc(p)
                    self.assertTrue(ok, "CWE-%d PoC has %s" % (cwe, msg))

    def test_no_unfilled_placeholders_in_any_poc(self):
        pattern = re.compile(r"%%[A-Z_]+%%")
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                finding = _finding(cwe)
                for p in pg.generate(finding):
                    matches = pattern.findall(p.code)
                    self.assertEqual([], matches,
                                     "CWE-%d has unfilled placeholders: %s" % (cwe, matches))


class PocContentIsReal(unittest.TestCase):
    """The generated code must contain the finding's actual parameters."""

    def test_sqli_contains_endpoint_and_param(self):
        f = _finding(89, source="user",
                     context={"endpoint": "http://vuln.app/login", "param": "user"})
        pocs = pg.generate(f)
        self.assertTrue(any("vuln.app/login" in p.code for p in pocs))
        self.assertTrue(any('"user"' in p.code for p in pocs))

    def test_xss_contains_endpoint(self):
        f = _finding(79, context={"endpoint": "http://vuln.app/search"})
        pocs = pg.generate(f)
        self.assertTrue(any("vuln.app/search" in p.code for p in pocs))

    def test_cmdi_contains_finding_metadata(self):
        f = _finding(78, rule="java-command-injection", file_path="src/Exec.java", line=99)
        pocs = pg.generate(f)
        self.assertTrue(any("java-command-injection" in p.code for p in pocs))
        self.assertTrue(any("src/Exec.java" in p.code for p in pocs))

    def test_hardcoded_cred_contains_file_and_line(self):
        f = _finding(798, file_path="config/db.properties", line=7,
                     snippet='db.password=hunter2', message="hardcoded password")
        pocs = pg.generate(f)
        self.assertTrue(any("config/db.properties" in p.code for p in pocs))
        # Line number should appear
        self.assertTrue(any("7" in p.code for p in pocs))

    def test_xxe_contains_endpoint(self):
        f = _finding(611, context={"endpoint": "http://app.internal/api/xml"})
        pocs = pg.generate(f)
        self.assertTrue(any("app.internal/api/xml" in p.code for p in pocs))

    def test_ssrf_contains_param(self):
        f = _finding(918, source="url", context={"endpoint": "http://proxy/fetch", "param": "url"})
        pocs = pg.generate(f)
        code = pocs[0].code
        self.assertIn("proxy/fetch", code)

    def test_path_traversal_cwe23_works(self):
        f = _finding(23)
        pocs = pg.generate(f)
        self.assertTrue(len(pocs) >= 1)
        ok, _ = pg.validate_poc(pocs[0])
        self.assertTrue(ok)

    def test_path_traversal_cwe36_works(self):
        f = _finding(36)
        pocs = pg.generate(f)
        self.assertTrue(len(pocs) >= 1)

    def test_xss_cwe80_maps_to_cwe79_generator(self):
        f = _finding(80)
        pocs = pg.generate(f)
        self.assertTrue(len(pocs) >= 1)
        self.assertIn("XSS", pocs[0].code)


class PocStructureIsComplete(unittest.TestCase):
    """Each PoC script must be runnable, not a fragment."""

    def test_every_poc_has_a_main_block(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                f = _finding(cwe)
                for p in pg.generate(f):
                    self.assertIn('__name__', p.code,
                                  "CWE-%d PoC has no __main__ guard" % cwe)

    def test_every_poc_has_an_exit_code(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                f = _finding(cwe)
                for p in pg.generate(f):
                    self.assertIn('sys.exit', p.code,
                                  "CWE-%d PoC has no sys.exit" % cwe)

    def test_every_poc_has_a_shebang(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                f = _finding(cwe)
                for p in pg.generate(f):
                    self.assertTrue(p.code.startswith("#!/usr/bin/env python3"),
                                    "CWE-%d PoC missing shebang" % cwe)

    def test_every_poc_has_references(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                f = _finding(cwe)
                for p in pg.generate(f):
                    self.assertTrue(len(p.references) >= 1,
                                    "CWE-%d PoC has no references" % cwe)
                    self.assertTrue(any("cwe.mitre.org" in r for r in p.references))

    def test_every_poc_has_vectors(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                f = _finding(cwe)
                for p in pg.generate(f):
                    self.assertTrue(len(p.vectors) >= 1,
                                    "CWE-%d PoC has no attack vectors listed" % cwe)


class UnsupportedCweIsHandledGracefully(unittest.TestCase):
    def test_unknown_cwe_returns_empty_list(self):
        f = _finding(99999)
        self.assertEqual([], pg.generate(f))

    def test_supported_cwes_does_not_include_unknown(self):
        self.assertNotIn(99999, pg.supported_cwes())


class FindingValidation(unittest.TestCase):
    def test_cwe_must_be_positive(self):
        with self.assertRaises(ValueError):
            pg.PocFinding(cwe=0, rule="x", file_path="x", line=1)

    def test_cwe_must_be_int(self):
        with self.assertRaises((ValueError, TypeError)):
            pg.PocFinding(cwe="89", rule="x", file_path="x", line=1)

    def test_rule_must_not_be_empty(self):
        with self.assertRaises(ValueError):
            pg.PocFinding(cwe=89, rule="", file_path="x", line=1)


class TemplateHelpers(unittest.TestCase):
    def test_fill_replaces_placeholders(self):
        result = pg._fill("hello %%NAME%%, you are %%AGE%%", NAME="world", AGE="5")
        self.assertEqual("hello world, you are 5", result)

    def test_fill_leaves_unknown_placeholders(self):
        result = pg._fill("%%KNOWN%% and %%UNKNOWN%%", KNOWN="yes")
        self.assertEqual("yes and %%UNKNOWN%%", result)

    def test_default_endpoint(self):
        f = pg.PocFinding(cwe=89, rule="test", file_path="x.java", line=1)
        self.assertIn("TARGET", pg._endpoint(f))

    def test_context_endpoint(self):
        f = pg.PocFinding(cwe=89, rule="test", file_path="x.java", line=1,
                          context={"endpoint": "http://real.app/api"})
        self.assertEqual("http://real.app/api", pg._endpoint(f))


class FromDetectFinding(unittest.TestCase):
    """Test the adapter from detect.py's Finding to PocFinding."""

    def test_basic_adaptation(self):
        class FakeFinding:
            path = "src/Dao.java"
            line = 42
            rule = "java-sql-injection"
            severity = "HIGH"
            message = "tainted query"
            snippet = "stmt = conn.prepareStatement(sql)"

        cwe_map = {"java-sql-injection": "CWE-89"}
        pf = pg.from_detect_finding(FakeFinding(), cwe_map)
        self.assertEqual(89, pf.cwe)
        self.assertEqual("java-sql-injection", pf.rule)
        self.assertEqual("src/Dao.java", pf.file_path)
        self.assertEqual(42, pf.line)

    def test_adaptation_without_cwe_map_uses_attribute(self):
        class FakeFinding:
            path = "x.py"
            line = 1
            rule = "test"
            cwe = "CWE-78"

        pf = pg.from_detect_finding(FakeFinding())
        self.assertEqual(78, pf.cwe)


class DeserializationFormatDetection(unittest.TestCase):
    def test_java_finding_defaults_to_java_format(self):
        f = _finding(502, language="java")
        pocs = pg.generate(f)
        self.assertTrue(any("java" in p.title.lower() for p in pocs))

    def test_python_finding_defaults_to_python_format(self):
        f = _finding(502, language="python")
        pocs = pg.generate(f)
        self.assertTrue(any("python" in p.title.lower() for p in pocs))

    def test_explicit_format_overrides_language(self):
        f = _finding(502, language="java", context={"format": "dotnet",
                     "endpoint": "http://x/api"})
        pocs = pg.generate(f)
        self.assertTrue(any("dotnet" in p.title.lower() for p in pocs))


if __name__ == "__main__":
    unittest.main()
