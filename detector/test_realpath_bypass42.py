#!/usr/bin/env python3
"""Tests for the realpath bypass payload generator."""
from __future__ import annotations

import ast
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import realpath_bypass42 as rb  # noqa: E402


class PayloadCoverage(unittest.TestCase):

    def test_all_payloads_not_empty(self):
        self.assertTrue(len(rb.all_payloads()) >= 10)

    def test_techniques_not_empty(self):
        self.assertTrue(len(rb.techniques()) >= 8)

    def test_every_payload_has_required_fields(self):
        for p in rb.all_payloads():
            self.assertTrue(len(p.technique) > 0, "missing technique")
            self.assertTrue(len(p.payload) > 0, "missing payload for %s" % p.technique)
            self.assertTrue(len(p.platform) > 0, "missing platform for %s" % p.technique)
            self.assertTrue(len(p.requires) > 0, "missing requires for %s" % p.technique)
            self.assertTrue(len(p.description) > 0, "missing description for %s" % p.technique)
            self.assertIn(p.platform, ("windows", "linux", "macos", "any"),
                          "invalid platform for %s" % p.technique)
            self.assertIn(p.severity, ("high", "medium", "low"),
                          "invalid severity for %s" % p.technique)

    def test_every_payload_has_references(self):
        for p in rb.all_payloads():
            if p.references:
                self.assertTrue(any("cwe.mitre.org" in r for r in p.references),
                                "payload %s has refs but no CWE link" % p.technique)


class PlatformFiltering(unittest.TestCase):

    def test_windows_filter(self):
        payloads = rb.all_payloads(platform_filter="windows")
        for p in payloads:
            self.assertIn(p.platform, ("windows", "any"))

    def test_linux_filter(self):
        payloads = rb.all_payloads(platform_filter="linux")
        for p in payloads:
            self.assertIn(p.platform, ("linux", "any"))

    def test_unfiltered_has_all_platforms(self):
        platforms = {p.platform for p in rb.all_payloads()}
        self.assertTrue(len(platforms) >= 3)

    def test_payloads_by_technique(self):
        for tech in ["toctou", "case", "unc", "proc", "null", "symlink"]:
            payloads = rb.payloads_by_technique(tech)
            self.assertTrue(len(payloads) >= 1,
                            "technique %s has 0 payloads" % tech)
            for p in payloads:
                self.assertTrue(p.technique.startswith(tech))


class ScriptGeneration(unittest.TestCase):

    def test_every_technique_generates_a_script(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www/uploads", "/etc/passwd")
            self.assertIsNotNone(script, "technique %s returned None" % prefix)
            self.assertTrue(len(script.code) > 100,
                            "technique %s has trivial code" % prefix)

    def test_every_generated_script_is_valid_python(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www/uploads", "/etc/passwd")
            try:
                ast.parse(script.code)
            except SyntaxError as e:
                self.fail("technique %s script has syntax error at line %d: %s"
                          % (prefix, e.lineno or 0, e.msg))

    def test_no_unfilled_placeholders(self):
        pattern = re.compile(r"%%[A-Z_]+%%")
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/opt/app/data", "/etc/shadow")
            matches = pattern.findall(script.code)
            self.assertEqual([], matches,
                             "technique %s has unfilled: %s" % (prefix, matches))

    def test_base_dir_appears_in_script(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/srv/uploads", "/etc/passwd")
            self.assertIn("/srv/uploads", script.code,
                          "technique %s doesn't reference base dir" % prefix)

    def test_goal_file_appears_in_script(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www", "/etc/shadow")
            self.assertIn("/etc/shadow", script.code,
                          "technique %s doesn't reference goal file" % prefix)

    def test_every_script_has_main_block(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www", "/etc/passwd")
            self.assertIn("__name__", script.code)
            self.assertIn("__main__", script.code)

    def test_every_script_has_exit_codes(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www", "/etc/passwd")
            self.assertIn("sys.exit", script.code)

    def test_every_script_has_shebang(self):
        for prefix in rb._TECHNIQUE_SCRIPTS:
            script = rb.generate_script(prefix, "/var/www", "/etc/passwd")
            self.assertTrue(script.code.startswith("#!/usr/bin/env python3"))

    def test_unknown_technique_returns_none(self):
        self.assertIsNone(rb.generate_script("nonexistent", "/var/www"))


class GenerateAllScripts(unittest.TestCase):

    def test_generates_multiple_scripts(self):
        scripts = rb.generate_all_scripts("/var/www/uploads")
        self.assertTrue(len(scripts) >= 6)

    def test_platform_filter_reduces_count(self):
        all_scripts = rb.generate_all_scripts("/var/www")
        linux_scripts = rb.generate_all_scripts("/var/www", platform_filter="linux")
        windows_scripts = rb.generate_all_scripts("/var/www", platform_filter="windows")
        self.assertTrue(len(linux_scripts) <= len(all_scripts))
        self.assertTrue(len(windows_scripts) <= len(all_scripts))

    def test_all_generated_scripts_are_valid_python(self):
        for script in rb.generate_all_scripts("/var/www"):
            try:
                ast.parse(script.code)
            except SyntaxError as e:
                self.fail("script %s has syntax error: %s" % (script.technique, e.msg))


class DetectPlatform(unittest.TestCase):

    def test_returns_known_platform(self):
        plat = rb.detect_platform()
        self.assertIn(plat, ("windows", "linux", "macos", "unknown"))

    def test_windows_detection(self):
        if sys.platform == "win32":
            self.assertEqual("windows", rb.detect_platform())


class TechniqueDescriptions(unittest.TestCase):

    def test_toctou_targets_race_condition(self):
        payloads = rb.payloads_by_technique("toctou")
        self.assertTrue(any("race" in p.description.lower() for p in payloads))

    def test_case_targets_case_sensitivity(self):
        payloads = rb.payloads_by_technique("case")
        self.assertTrue(any("case" in p.description.lower() for p in payloads))

    def test_proc_is_linux_only(self):
        payloads = rb.payloads_by_technique("proc")
        for p in payloads:
            self.assertEqual("linux", p.platform)

    def test_unc_is_windows_only(self):
        payloads = rb.payloads_by_technique("unc")
        for p in payloads:
            self.assertEqual("windows", p.platform)

    def test_unicode_has_normalization_context(self):
        payloads = rb.payloads_by_technique("unicode")
        self.assertTrue(any("normalization" in p.description.lower()
                            or "NFKC" in p.description for p in payloads))


if __name__ == "__main__":
    unittest.main()
