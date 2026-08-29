#!/usr/bin/env python3
"""Tests for the patch generator.

Every patch must be:
1. Concrete (contains actual replacement code, not advice)
2. Language-appropriate (Java fix for Java finding, etc.)
3. Complete (has both vulnerable and fixed patterns)
4. Findable (diff_hint is a valid regex that would match the vulnerable code)
"""
from __future__ import annotations

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import patch_gen42 as pg  # noqa: E402
from poc_gen42 import PocFinding  # noqa: E402


def _finding(cwe: int, **kw) -> PocFinding:
    defaults = dict(
        rule="test-rule",
        file_path="src/App.java",
        line=42,
        language="java",
        source="userId",
    )
    defaults.update(kw)
    return PocFinding(cwe=cwe, **defaults)


class EveryRegisteredCweProducesPatches(unittest.TestCase):

    def test_supported_cwes_is_not_empty(self):
        self.assertTrue(len(pg.supported_cwes()) >= 10)

    def test_every_cwe_generates_at_least_one_patch(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                finding = _finding(cwe)
                patches = pg.generate_patch(finding)
                self.assertTrue(len(patches) >= 1,
                                "CWE-%d registered but generated 0 patches" % cwe)

    def test_every_patch_has_vulnerable_and_fixed_code(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                for p in pg.generate_patch(_finding(cwe)):
                    self.assertTrue(len(p.vulnerable) > 20,
                                    "CWE-%d patch has empty vulnerable pattern" % cwe)
                    self.assertTrue(len(p.fixed) > 20,
                                    "CWE-%d patch has empty fixed pattern" % cwe)

    def test_every_patch_has_an_explanation(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                for p in pg.generate_patch(_finding(cwe)):
                    self.assertTrue(len(p.explanation) > 10,
                                    "CWE-%d patch has no explanation" % cwe)

    def test_every_patch_has_references(self):
        for cwe in pg.supported_cwes():
            with self.subTest(cwe=cwe):
                for p in pg.generate_patch(_finding(cwe)):
                    self.assertTrue(len(p.references) >= 1)
                    self.assertTrue(any("cwe.mitre.org" in r for r in p.references))


class PatchesAreLanguageSpecific(unittest.TestCase):

    def test_java_finding_gets_java_patch(self):
        patches = pg.generate_patch(_finding(89, language="java"))
        java_patches = [p for p in patches if p.language == "java"]
        self.assertTrue(len(java_patches) >= 1)
        self.assertIn("PreparedStatement", java_patches[0].fixed)

    def test_python_finding_gets_python_patch(self):
        patches = pg.generate_patch(_finding(89, language="python"))
        py_patches = [p for p in patches if p.language == "python"]
        self.assertTrue(len(py_patches) >= 1)
        self.assertIn("cursor.execute", py_patches[0].fixed)

    def test_csharp_finding_gets_csharp_patch(self):
        patches = pg.generate_patch(_finding(89, language="csharp"))
        cs_patches = [p for p in patches if p.language == "csharp"]
        self.assertTrue(len(cs_patches) >= 1)
        self.assertIn("Parameters", cs_patches[0].fixed)

    def test_go_finding_gets_go_patch(self):
        patches = pg.generate_patch(_finding(89, language="go"))
        go_patches = [p for p in patches if p.language == "go"]
        self.assertTrue(len(go_patches) >= 1)
        self.assertIn("$1", go_patches[0].fixed)

    def test_unknown_language_gets_all_languages(self):
        patches = pg.generate_patch(_finding(89, language="unknown"))
        languages = {p.language for p in patches}
        self.assertTrue(len(languages) >= 3,
                        "unknown language should produce multi-language patches")

    def test_js_xss_uses_textcontent(self):
        patches = pg.generate_patch(_finding(79, language="js"))
        js_patches = [p for p in patches if p.language == "javascript"]
        self.assertTrue(len(js_patches) >= 1)
        self.assertIn("textContent", js_patches[0].fixed)

    def test_python_cmdi_uses_subprocess_list(self):
        patches = pg.generate_patch(_finding(78, language="python"))
        py_patches = [p for p in patches if p.language == "python"]
        self.assertTrue(len(py_patches) >= 1)
        self.assertIn("shell=False", py_patches[0].fixed)


class PatchesContainFindingContext(unittest.TestCase):

    def test_sqli_patch_uses_finding_variable_name(self):
        patches = pg.generate_patch(_finding(89, source="searchTerm", language="java"))
        java_patches = [p for p in patches if p.language == "java"]
        self.assertTrue(any("searchTerm" in p.fixed for p in java_patches))

    def test_cmdi_patch_uses_finding_variable_name(self):
        patches = pg.generate_patch(_finding(78, source="filename", language="python"))
        py_patches = [p for p in patches if p.language == "python"]
        self.assertTrue(any("filename" in p.fixed for p in py_patches))


class DiffHintsAreValidRegex(unittest.TestCase):

    def test_every_diff_hint_compiles(self):
        for cwe in pg.supported_cwes():
            for p in pg.generate_patch(_finding(cwe)):
                with self.subTest(cwe=cwe, lang=p.language):
                    if p.diff_hint:
                        try:
                            re.compile(p.diff_hint)
                        except re.error as e:
                            self.fail("CWE-%d %s diff_hint is invalid regex: %s"
                                      % (cwe, p.language, e))

    def test_diff_hint_matches_vulnerable_code(self):
        for cwe in pg.supported_cwes():
            for p in pg.generate_patch(_finding(cwe)):
                with self.subTest(cwe=cwe, lang=p.language):
                    if p.diff_hint:
                        self.assertTrue(
                            re.search(p.diff_hint, p.vulnerable),
                            "CWE-%d %s diff_hint '%s' does not match vulnerable code"
                            % (cwe, p.language, p.diff_hint))


class UnsupportedCweIsHandled(unittest.TestCase):

    def test_unknown_cwe_returns_empty_list(self):
        self.assertEqual([], pg.generate_patch(_finding(99999)))

    def test_supported_cwes_are_sorted(self):
        cwes = pg.supported_cwes()
        self.assertEqual(cwes, tuple(sorted(cwes)))


class SiblingCwesWork(unittest.TestCase):

    def test_cwe23_produces_same_as_cwe22(self):
        p22 = pg.generate_patch(_finding(22))
        p23 = pg.generate_patch(_finding(23))
        self.assertEqual(len(p22), len(p23))

    def test_cwe36_produces_same_as_cwe22(self):
        p22 = pg.generate_patch(_finding(22))
        p36 = pg.generate_patch(_finding(36))
        self.assertEqual(len(p22), len(p36))

    def test_cwe80_produces_same_as_cwe79(self):
        p79 = pg.generate_patch(_finding(79))
        p80 = pg.generate_patch(_finding(80))
        self.assertEqual(len(p79), len(p80))


class PatchFixIsNotVulnerable(unittest.TestCase):
    """The fixed code should not contain the vulnerable pattern's key weakness."""

    def test_sqli_fix_has_no_string_concatenation_in_query(self):
        for p in pg.generate_patch(_finding(89, language="java")):
            if p.language == "java":
                lines = [l for l in p.fixed.split("\n")
                         if "SELECT" in l or "INSERT" in l or "UPDATE" in l]
                for line in lines:
                    self.assertNotIn(" + ", line,
                                     "Fixed SQL query still uses string concatenation")

    def test_cmdi_fix_has_no_shell_true(self):
        for p in pg.generate_patch(_finding(78, language="python")):
            if p.language == "python":
                fixed_lines = [l for l in p.fixed.split("\n")
                               if "subprocess" in l and "run" in l]
                for line in fixed_lines:
                    self.assertNotIn("shell=True", line)

    def test_xss_fix_has_no_innerhtml(self):
        for p in pg.generate_patch(_finding(79, language="js")):
            if p.language == "javascript":
                self.assertNotIn("innerHTML", p.fixed)


class ConfidenceLevels(unittest.TestCase):

    def test_all_patches_have_confidence(self):
        for cwe in pg.supported_cwes():
            for p in pg.generate_patch(_finding(cwe)):
                self.assertIn(p.confidence, ("mechanical", "contextual"),
                              "CWE-%d %s has invalid confidence" % (cwe, p.language))


if __name__ == "__main__":
    unittest.main()
