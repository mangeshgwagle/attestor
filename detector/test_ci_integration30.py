from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import ci_integration


class CiIntegrationTests(unittest.TestCase):
    def test_diff_parser_and_changed_line_filter(self):
        diff = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -4,0 +5,2 @@
+bad
+worse
"""
        changed = ci_integration.parse_unified_diff(diff)
        self.assertEqual(changed, {"app.py": [(5, 6)]})
        findings = [{"path": "app.py", "line": 5, "rule": "one"},
                    {"path": "app.py", "line": 8, "rule": "two"}]
        self.assertEqual([item["rule"] for item in ci_integration.changed_findings(findings, changed)], ["one"])

    def test_traversal_paths_are_not_annotated(self):
        lines = ci_integration.github_annotations([
            {"path": "../secret.py", "line": 1, "severity": "HIGH", "rule": "r", "message": "bad"}])
        self.assertEqual(lines, [])

    def test_annotations_escape_workflow_control_characters(self):
        line = ci_integration.github_annotations([{
            "path": "src/app.py", "line": 4, "severity": "HIGH", "rule": "sql,rule",
            "message": "line1\n::warning:: forged", "fix": "use 100% parameters"}])[0]
        self.assertNotIn("\n", line)
        self.assertIn("%0A", line)
        self.assertIn("%25", line)
        self.assertIn("%2C", line)

    def test_baseline_hides_only_exact_known_fingerprints(self):
        finding = {"path": "app.py", "line": 1, "severity": "HIGH", "rule": "sql", "message": "dynamic"}
        fingerprint = ci_integration.finding_fingerprint(finding)
        passed = ci_integration.evaluate([finding], baseline_fingerprints={fingerprint})
        blocked = ci_integration.evaluate([finding], baseline_fingerprints=set())
        self.assertEqual(passed["status"], "passed")
        self.assertEqual(blocked["status"], "blocked")

    def test_baseline_loader_rejects_malformed_fingerprints(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "baseline.json"
            path.write_text(json.dumps({"schema": ci_integration.BASELINE_SCHEMA,
                                        "fingerprints": ["not-a-hash"]}), encoding="utf-8")
            with self.assertRaises(ci_integration.CiError):
                ci_integration.load_baseline(path)

    def test_git_revisions_cannot_inject_options(self):
        with self.assertRaises(ci_integration.CiError):
            ci_integration.git_diff(".", "--output=/tmp/pwn")


if __name__ == "__main__":
    unittest.main()
