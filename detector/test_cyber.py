#!/usr/bin/env python3
"""Tests for cyber.py -- Attestor's Cyber Sentinel scanner."""
import os
import tempfile
import unittest

import cyber


class CyberTests(unittest.TestCase):
    def _write(self, root, rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _rules(self, report):
        return {finding.rule for finding in report["findings"]}

    def test_secrets_hunter_detects_committed_keys(self):
        with tempfile.TemporaryDirectory() as d:
            key = "sk-" + ("A" * 32)
            self._write(d, "app.env", "OPENAI_API_KEY=" + key + "\n")
            report = cyber.scan([d])
        self.assertIn("cyber-openai-key", self._rules(report))
        self.assertIn("cyber-hardcoded-credential", self._rules(report))

    def test_placeholder_example_is_low_confidence(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "keys.env.example", "API_KEY=CHANGEME\n")
            report = cyber.scan([d])
        self.assertEqual(report["findings"], [])

    def test_crypto_auth_taint_and_config_rules(self):
        with tempfile.TemporaryDirectory() as d:
            body = "\n".join([
                "import hashlib",
                "digest = hashlib." + "md5" + "(b'x').hexdigest()",
                "cursor." + "execute" + "(f\"SELECT * FROM users WHERE id={user_id}\")",
                "app.config['DEBUG'] = True",
                "resp.set_cookie('sid', token)",
                "jwt.decode(token, options={'verify_signature': False})",
            ])
            self._write(d, "app.py", body)
            report = cyber.scan([d])
            rules = self._rules(report)
        self.assertIn("cyber-weak-hash", rules)
        self.assertIn("cyber-sql-string-built", rules)
        self.assertIn("cyber-debug-enabled", rules)
        self.assertIn("cyber-weak-cookie-flags", rules)
        self.assertIn("cyber-jwt-verification-disabled", rules)

    def test_dependency_and_docker_rules(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "requirements.txt", "requests\nflask==3.0.0\n")
            self._write(d, "package.json", '{"dependencies": {"left-pad": "latest"}}')
            self._write(d, "Dockerfile", "FROM python:3.12-slim\nCMD python app.py\n")
            report = cyber.scan([d])
            rules = self._rules(report)
        self.assertIn("cyber-unpinned-python-dependency", rules)
        self.assertIn("cyber-floating-node-dependency", rules)
        self.assertIn("cyber-docker-missing-user", rules)

    def test_render_includes_score_fields(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "requirements.txt", "requests\n")
            text = cyber.render(cyber.scan([d]))
        self.assertIn("Cyber Sentinel report", text)
        self.assertIn("confidence", text)
        self.assertIn("safe_to_autofix", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
