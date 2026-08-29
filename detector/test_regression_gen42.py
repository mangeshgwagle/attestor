#!/usr/bin/env python3
"""Tests for the regression test generator.

Every generated regression test must:
1. Be syntactically valid Python
2. Actually run and pass (the generated tests test their own logic)
3. Contain both vulnerable and fixed functions
4. Have a __main__ block
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import regression_gen42 as rg  # noqa: E402
from poc_gen42 import PocFinding  # noqa: E402


def _finding(cwe: int, **kw) -> PocFinding:
    defaults = dict(
        rule="test-rule",
        file_path="src/App.java",
        line=42,
        language="java",
        source="user_input",
    )
    defaults.update(kw)
    return PocFinding(cwe=cwe, **defaults)


class EveryRegisteredCweProducesTests(unittest.TestCase):

    def test_supported_cwes_not_empty(self):
        self.assertTrue(len(rg.supported_cwes()) >= 10)

    def test_every_cwe_generates_at_least_one_test(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                tests = rg.generate_test(_finding(cwe))
                self.assertTrue(len(tests) >= 1,
                                "CWE-%d generated 0 tests" % cwe)

    def test_every_generated_test_is_valid_python(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    try:
                        ast.parse(t.test_code)
                    except SyntaxError as e:
                        self.fail("CWE-%d test has syntax error at line %d: %s"
                                  % (cwe, e.lineno or 0, e.msg))

    def test_no_unfilled_placeholders(self):
        pattern = re.compile(r"%%[A-Z_]+%%")
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    matches = pattern.findall(t.test_code)
                    self.assertEqual([], matches,
                                     "CWE-%d has unfilled: %s" % (cwe, matches))


class TestStructureIsComplete(unittest.TestCase):

    def test_every_test_has_main_block(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    self.assertIn("__name__", t.test_code)
                    self.assertIn("unittest.main", t.test_code)

    def test_every_test_has_shebang(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    self.assertTrue(t.test_code.startswith("#!/usr/bin/env python3"))

    def test_every_test_has_vulnerable_and_fixed_patterns(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    code_lower = t.test_code.lower()
                    has_vuln = ("vulnerable" in code_lower or
                                "unsafe" in code_lower or
                                "pickle.loads" in code_lower or
                                "not resolve" in code_lower)
                    has_fix = ("fixed" in code_lower or
                               "safe" in code_lower or
                               "json.loads" in code_lower or
                               "defused" in code_lower or
                               "restricted" in code_lower)
                    self.assertTrue(has_vuln,
                                    "CWE-%d test has no vulnerable pattern" % cwe)
                    self.assertTrue(has_fix,
                                    "CWE-%d test has no fixed pattern" % cwe)

    def test_every_test_has_references(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    self.assertTrue(len(t.references) >= 1)

    def test_every_test_has_fail_and_pass_conditions(self):
        for cwe in rg.supported_cwes():
            with self.subTest(cwe=cwe):
                for t in rg.generate_test(_finding(cwe)):
                    self.assertTrue(len(t.fail_condition) > 0)
                    self.assertTrue(len(t.pass_condition) > 0)


class GeneratedTestsActuallyRun(unittest.TestCase):
    """The generated test files must execute and pass."""

    def _run_generated_test(self, cwe: int) -> tuple[int, str]:
        tests = rg.generate_test(_finding(cwe))
        self.assertTrue(len(tests) >= 1)
        code = tests[0].test_code
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                             delete=False, encoding="utf-8") as f:
                f.write(code)
                tmp_path = f.name
            result = subprocess.run(
                [sys.executable, tmp_path, "-v"],
                capture_output=True, text=True, timeout=30,
                env={**os.environ, "APP_SECRET": "test-secret"},
            )
            return result.returncode, result.stdout + result.stderr
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except PermissionError:
                    pass

    def test_sqli_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(89)
        self.assertEqual(0, rc, "SQLi regression test failed:\n%s" % output)

    def test_xss_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(79)
        self.assertEqual(0, rc, "XSS regression test failed:\n%s" % output)

    def test_cmdi_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(78)
        self.assertEqual(0, rc, "CMDi regression test failed:\n%s" % output)

    def test_pathtr_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(22)
        self.assertEqual(0, rc, "Path traversal regression test failed:\n%s" % output)

    def test_deser_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(502)
        self.assertEqual(0, rc, "Deserialization regression test failed:\n%s" % output)

    def test_code_inj_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(94)
        self.assertEqual(0, rc, "Code injection regression test failed:\n%s" % output)

    def test_ssrf_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(918)
        self.assertEqual(0, rc, "SSRF regression test failed:\n%s" % output)

    def test_hardcoded_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(798)
        self.assertEqual(0, rc, "Hardcoded cred regression test failed:\n%s" % output)

    def test_ldap_regression_runs_and_passes(self):
        rc, output = self._run_generated_test(90)
        self.assertEqual(0, rc, "LDAP injection regression test failed:\n%s" % output)


class UnsupportedCweIsHandled(unittest.TestCase):

    def test_unknown_cwe_returns_empty(self):
        self.assertEqual([], rg.generate_test(_finding(99999)))


class SiblingCwesWork(unittest.TestCase):

    def test_cwe23_works(self):
        self.assertTrue(len(rg.generate_test(_finding(23))) >= 1)

    def test_cwe36_works(self):
        self.assertTrue(len(rg.generate_test(_finding(36))) >= 1)

    def test_cwe80_works(self):
        self.assertTrue(len(rg.generate_test(_finding(80))) >= 1)


class FindingContextIsUsed(unittest.TestCase):

    def test_rule_name_appears_in_generated_test(self):
        f = _finding(89, rule="java-sql-injection")
        tests = rg.generate_test(f)
        self.assertTrue(any("java-sql-injection" in t.test_code for t in tests))

    def test_file_path_appears_in_generated_test(self):
        f = _finding(89, file_path="src/dao/UserDao.java")
        tests = rg.generate_test(f)
        self.assertTrue(any("UserDao.java" in t.test_code for t in tests))

    def test_variable_name_is_parameterized(self):
        f = _finding(78, source="filename")
        tests = rg.generate_test(f)
        self.assertTrue(any("filename" in t.test_code for t in tests))


if __name__ == "__main__":
    unittest.main()
