from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import rule_sdk


def sample_rule(rule_id="attestor3-python-debug-enabled"):
    return {
        "id": rule_id, "version": "1.0.0", "title": "Debug mode enabled",
        "language": "python", "extensions": [".py"], "severity": "HIGH",
        "confidence": 0.96, "category": "security-configuration", "cwe": "CWE-489",
        "description": "Production debug mode exposes internals.",
        "remediation": "Disable debug mode outside an isolated development environment.",
        "match_all": ["debug", "True"], "match_any": [], "exclude_any": ["# safe-example"],
        "case_sensitive": True,
        "positive_fixtures": [{"path": "app.py", "source": "app.run(debug=True)\n", "expected_lines": [1]}],
        "negative_fixtures": [
            {"path": "app.py", "source": "app.run(debug=False)\n", "expected_lines": []},
            {"path": "app.py", "source": "app.run(debug=True)  # safe-example\n", "expected_lines": []},
        ],
    }


class RuleSdkTests(unittest.TestCase):
    def test_valid_pack_proves_positive_and_negative_fixtures(self):
        report = rule_sdk.validate_pack({"schema": rule_sdk.SCHEMA, "rules": [sample_rule()]})
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(report["rules"], 1)
        self.assertEqual(report["fixtures"], 3)

    def test_scan_returns_stable_evidence_and_fingerprint(self):
        rule = rule_sdk.RuleSpec.parse(sample_rule())
        first = rule.scan("app.run(debug=True)\n", "service.py")
        second = rule.scan("app.run(debug=True)\n", "service.py")
        self.assertEqual(first, second)
        self.assertRegex(first[0]["fingerprint"], r"^[0-9a-f]{64}$")
        self.assertNotIn("app.run(debug=True)", repr(first[0]["evidence"]))
        self.assertTrue(first[0]["evidence"][0]["source_text_withheld"])

    def test_rule_requires_both_fixture_classes(self):
        broken = sample_rule(); broken["negative_fixtures"] = []
        report = rule_sdk.validate_pack({"schema": rule_sdk.SCHEMA, "rules": [broken]})
        self.assertFalse(report["ok"])
        self.assertIn("negative fixtures", report["errors"][0])

    def test_fixture_mismatch_and_duplicate_ids_fail_closed(self):
        broken = sample_rule(); broken["positive_fixtures"][0]["expected_lines"] = [2]
        report = rule_sdk.validate_pack({"schema": rule_sdk.SCHEMA, "rules": [broken]})
        self.assertFalse(report["ok"])
        duplicate = {"schema": rule_sdk.SCHEMA, "rules": [sample_rule(), sample_rule()]}
        report = rule_sdk.validate_pack(duplicate)
        self.assertFalse(report["ok"])
        self.assertTrue(any("duplicate rule id" in error for error in report["errors"]))

    def test_declarative_tokens_do_not_create_dynamic_code_surface(self):
        hostile = sample_rule(); hostile["match_any"] = ["(?=a)(a+)+$"]
        rule = rule_sdk.RuleSpec.parse(hostile)
        self.assertEqual(rule.scan("a" * 100_000, "x.py"), [])

    def test_extension_gating_prevents_cross_language_noise(self):
        rule = rule_sdk.RuleSpec.parse(sample_rule())
        self.assertEqual(rule.scan("app.run(debug=True)", "app.js"), [])

    def test_authenticated_pack_detects_tampering(self):
        pack = {"schema": rule_sdk.SCHEMA, "rules": [sample_rule()]}
        key = b"correct horse battery staple"
        signed = rule_sdk.sign_pack(pack, key, "ci-release")
        self.assertTrue(rule_sdk.verify_signature(signed, key))
        signed["rules"][0]["severity"] = "LOW"
        self.assertFalse(rule_sdk.verify_signature(signed, key))

    def test_loader_enforces_validation_before_returning_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pack.json"
            path.write_text(json.dumps({"schema": rule_sdk.SCHEMA, "rules": [sample_rule()]}), encoding="utf-8")
            rules, report = rule_sdk.load_pack(path)
            self.assertTrue(report["ok"])
            self.assertEqual(len(rules), 1)

    def test_bundled_example_pack_is_self_proving(self):
        path = Path(__file__).resolve().parent / "rulepacks" / "attestor3-example.json"
        rules, report = rule_sdk.load_pack(path)
        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual(len(rules), 1)


if __name__ == "__main__":
    unittest.main()
