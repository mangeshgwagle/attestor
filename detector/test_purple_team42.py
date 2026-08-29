#!/usr/bin/env python3
"""Tests for purple_team42, cve_matcher42, and source_hardening42."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import purple_team42 as pt  # noqa: E402
import cve_matcher42 as cve  # noqa: E402
import source_hardening42 as hard  # noqa: E402


class TestAttackMapper(unittest.TestCase):
    def test_finding_mapping(self):
        mapped = pt.map_finding("jwt-weak-secret")
        self.assertEqual(mapped["technique_ids"], ["T1110.002"])
        self.assertTrue(mapped["techniques"][0]["name"])

    def test_unknown_finding_refused(self):
        with self.assertRaises(pt.PtError):
            pt.map_finding("not-a-kind")

    def test_tool_mapping_roundtrip(self):
        result = pt.map_tool_to_attack("jwt-crack")
        self.assertIn("T1110.002", result["technique_ids"])

    def test_unmapped_tool_refused(self):
        with self.assertRaises(pt.PtError):
            pt.map_tool_to_attack("helloworld")


class TestSigmaEngine(unittest.TestCase):
    def test_every_template_rule_validates(self):
        verification = pt.verify_rules()
        self.assertTrue(verification["passed"],
                        verification["failed"])

    def test_positive_and_negative_shape(self):
        template = next(t for t in pt.ATTACK_TEMPLATES
                        if t["id"] == "AT-JWT-NONE-001")
        rule = template["sigma"]
        self.assertTrue(pt.evaluate_rule(rule, template["positive_event"]))
        for negative in template["negative_events"]:
            self.assertFalse(pt.evaluate_rule(rule, negative), negative)

    def test_modifier_contains(self):
        rule = {"detection": {"sel": {"a|contains": "x"},
                              "condition": "sel"}}
        self.assertTrue(pt.evaluate_rule(rule, {"a": "wxyz"}))
        self.assertFalse(pt.evaluate_rule(rule, {"a": "wyzz"}))

    def test_modifier_re(self):
        rule = {"detection": {"sel": {"a|re": r"\d{3}"}, "condition": "sel"}}
        self.assertTrue(pt.evaluate_rule(rule, {"a": "abc123def"}))
        self.assertFalse(pt.evaluate_rule(rule, {"a": "abcdef"}))

    def test_unknown_modifier_refused(self):
        rule = {"detection": {"sel": {"a|hologram": "x"}, "condition": "sel"}}
        with self.assertRaises(pt.PtError):
            pt.evaluate_rule(rule, {"a": "x"})

    def test_condition_and_not_shape(self):
        rule = {"detection": {
            "sel": {"a": "1"}, "fil": {"b": "2"},
            "condition": "sel and not fil"}}
        self.assertTrue(pt.evaluate_rule(rule, {"a": "1", "b": "3"}))
        self.assertFalse(pt.evaluate_rule(rule, {"a": "1", "b": "2"}))

    def test_emit_includes_digest(self):
        emission = pt.emit_rules(["AT-REDOS-001"])
        rule = emission["rules"][0]["rule"]
        self.assertEqual(len(rule["rule_sha256"]), 64)

    def test_gap_scorer_full_coverage_after_verify(self):
        gaps = pt.detection_gaps()
        self.assertEqual(gaps["missing_templates"], [])
        self.assertEqual(gaps["coverage_ratio"], 1.0)


class TestCveMatcher(unittest.TestCase):
    FEED = cve.load_feed()

    def _match(self, name, version):
        return cve.match_dependencies(
            [{"name": name, "version": version, "source": "test"}],
            self.FEED)

    def test_log4shell_vulnerable_version(self):
        outcome = self._match("log4j-core", "2.14.1")
        self.assertEqual(outcome["match_count"], 1)
        self.assertEqual(outcome["matches"][0]["cve"], "CVE-2021-44228")

    def test_log4shell_patched_version_clean(self):
        outcome = self._match("log4j-core", "2.17.1")
        self.assertEqual(outcome["match_count"], 0)

    def test_requests_range_match(self):
        outcome = self._match("requests", "2.30.0")
        self.assertEqual(outcome["match_count"], 1)

    def test_requests_patched_clean(self):
        outcome = self._match("requests", "2.31.0")
        self.assertEqual(outcome["match_count"], 0)

    def test_spring4shell_range_bounds(self):
        self.assertEqual(self._match("spring-beans", "5.3.17")["match_count"], 1)
        self.assertEqual(self._match("spring-beans", "5.3.18")["match_count"], 0)

    def test_inconclusive_versions_surfaced(self):
        outcome = self._match("log4j-core", "banana")
        self.assertEqual(outcome["matches"], [])
        self.assertEqual(len(outcome["inconclusive"]), 1)

    def test_version_comparison_edges(self):
        self.assertEqual(cve.compare_versions("2.14.1", "2.14.1"), 0)
        self.assertLess(cve.compare_versions("2.9.9", "2.10.0"), 0)
        self.assertIsNone(cve.compare_versions("abc", "1.2"))

    def test_requirements_parsing(self, ):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as tmp:
            req = os.path.join(tmp, "requirements.txt")
            with open(req, "w", encoding="utf-8") as handle:
                handle.write("requests==2.30.0\n# comment\nflask>=2\n")
            deps = cve._parse_requirements(req)
            names = {d["name"] for d in deps}
            self.assertEqual(names, {"requests"})

    def test_selftest_passes(self):
        result = cve.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


class TestSourceHardening(unittest.TestCase):
    def test_bidi_override_detected_with_location(self):
        text = 'if (admin) {\n  \u202e }\n  grant();\n'
        hits = hard.scan_bidi(text)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 2)
        self.assertEqual(hits[0]["character"], "U+202E")

    def test_all_nine_bidi_characters_recognized(self):
        blob = "".join(hard.BIDI_CHARS)
        hits = hard.scan_bidi(blob)
        self.assertEqual(len(hits), len(hard.BIDI_CHARS))

    def test_clean_source_quiet(self):
        self.assertEqual(hard.scan_text("def f():\n    return 1\n"), [])

    def test_mixed_script_identifier_flagged(self):
        hits = hard.scan_mixed_script('total_\u0430mount = 5\n')
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["check"], "mixed-script-context")

    def test_secret_assignment_redacted(self):
        text = 'api_key = "ZXk1N0pobkJIYmZqUk5tUHdLcVZ4eUJnS2ZQcg=="'
        hits = hard.scan_secrets(text)
        self.assertEqual(len(hits), 1)
        preview = hits[0]["value_preview"]
        self.assertTrue(preview.startswith("ZXk1"))
        self.assertNotEqual(preview,
                            "ZXk1N0pobkJIYmZqUk5tUHdLcVZ4eUJnS2ZQcg==")

    def test_placeholder_and_low_entropy_skipped(self):
        self.assertEqual(
            hard.scan_secrets('password = "aaaaaaaaaaaaaaaaaaaa"'), [])
        self.assertEqual(
            hard.scan_secrets('password = "changeme"'), [])

    def test_entropy_function_sane(self):
        self.assertEqual(hard.shannon_entropy(""), 0.0)
        self.assertEqual(hard.shannon_entropy("aaaa"), 0.0)
        self.assertGreater(hard.shannon_entropy("Ab3$Zx9!"), 2.0)

    def test_selftest_passes(self):
        result = hard.run_selftest()
        self.assertTrue(result["passed"], result["checks_failed"])


if __name__ == "__main__":
    unittest.main()
