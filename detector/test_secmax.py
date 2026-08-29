#!/usr/bin/env python3
"""Tests for secmax.py -- Attestor 2 Security Max."""
import json
import os
import tempfile
import unittest
from pathlib import Path

import secmax


class SecurityMaxTests(unittest.TestCase):
    def _write(self, root, rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def _rules(self, report):
        return {item.rule for item in report["findings"]}

    def test_entropy_and_dependency_rules(self):
        with tempfile.TemporaryDirectory() as root:
            token_value = "".join([
                "sample-aB3dE5fG7",
                "hI9jK2LmN4OpQ6",
                "RsT8UvW0XyZ",
            ])
            self._write(root, "app.py", "api_key = '%s'\n" % token_value)
            self._write(root, "package.json", json.dumps({
                "scripts": {"postinstall": "node setup.js"},
                "dependencies": {"demo": "latest"},
            }))
            report = secmax.scan([root])
        rules = self._rules(report)
        self.assertIn("secmax-high-entropy-secret", rules)
        self.assertIn("secmax-node-lockfile-missing", rules)
        self.assertIn("secmax-install-hook", rules)

    def test_entropy_requires_a_credential_assignment_not_a_nearby_word(self):
        value = "sample-aB3dE5fGhI9jK2LmN4OpQ6RsT8UvW0XyZ"
        mapping = secmax._scan_entropy("{'token': '%s'}" % value, "mapping.py")
        detector_metadata = secmax._scan_entropy(
            '"patch_apply", "automatic_remediation_applied", "raw_secret_material_in_report"',
            "contract.py")
        self.assertEqual([row.rule for row in mapping], ["secmax-high-entropy-secret"])
        self.assertEqual(detector_metadata, [])

    def test_digest_pinned_action_with_comment_is_still_pinned(self):
        digest = "a" * 40
        findings = secmax._scan_crypto_iac_supply(
            "- uses: actions/checkout@%s # v5.0.0\n" % digest,
            Path(".github/workflows/ci.yml"))
        self.assertNotIn("secmax-unpinned-github-action",
                         {row.rule for row in findings})

    def test_regex_rule_literal_is_not_ecb_behavior(self):
        findings = secmax._scan_crypto_iac_supply(
            '        (r"(?i)\\b(?:MODE_ECB|DES)\\b", "crypto-rule"),\n',
            Path("detector_rules.py"))
        self.assertNotIn("secmax-ecb-mode", {
            row.rule for row in findings
        })

    def test_web_iac_and_sarif(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "app.py",
                        "@app.route('/pay', methods=['POST'])\n"
                        "def pay():\n    return redirect(request.args['next'])\n")
            self._write(root, ".github/workflows/ci.yml",
                        "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n")
            report = secmax.scan([root])
            sarif = secmax.to_sarif(report)
        rules = self._rules(report)
        self.assertIn("secmax-post-route-without-csrf-shape", rules)
        self.assertIn("secmax-unpinned-github-action", rules)
        self.assertEqual(sarif["version"], "2.1.0")

    def test_render_includes_threat_model_and_reproducer(self):
        with tempfile.TemporaryDirectory() as root:
            self._write(root, "requirements.txt", "git+https://example.invalid/repo.git\n")
            text = secmax.render(secmax.scan([root]))
        self.assertIn("Threat model generator", text)
        self.assertIn("defensive reproducer", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
