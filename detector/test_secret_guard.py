from __future__ import annotations

import json
import unittest

import secret_guard


class SecretGuardTests(unittest.TestCase):
    def assert_redacted(self, findings, *values):
        rendered = json.dumps(findings, sort_keys=True)
        for value in values:
            self.assertNotIn(value, rendered)
        self.assertTrue(all(row["secret_material_redacted"] for row in findings))
        self.assertFalse(any("secret_fingerprint" in row for row in findings))

    def test_provider_formats_are_detected_without_value_material(self):
        openai = "sk-proj-" + "Ab9_" * 15
        github = "ghp_" + "A9bC" * 9
        findings = secret_guard.scan_text(
            'OPENAI_API_KEY="%s"\nGITHUB_TOKEN="%s"\n' % (openai, github),
            "config.env",
        )
        kinds = {row["secret_kind"] for row in findings}
        self.assertIn("openai-project-key", kinds)
        self.assertIn("github-token", kinds)
        self.assert_redacted(findings, openai, github)

    def test_placeholders_and_runtime_references_are_suppressed(self):
        text = "\n".join([
            "API_KEY=changeme",
            "TOKEN=${TOKEN}",
            "CLIENT_SECRET={{ vault_client_secret }}",
            'OPENAI_API_KEY="sk-proj-example_' + ("x" * 50) + '"',
            "PASSWORD=xxxxxxxxxxxxxxxx",
        ])
        self.assertEqual(secret_guard.scan_text(text, ".env.example"), [])

    def test_identifiers_require_paired_secret_evidence(self):
        aws_id = "AKIA" + "A1B2C3D4E5F6G7H8"
        aws_secret = "Ab3/" * 10
        twilio_id = "AC" + "a1" * 16
        twilio_secret = "0123456789abcdef" * 2
        self.assertEqual(secret_guard.scan_text("AWS_ACCESS_KEY_ID=" + aws_id, ".env"), [])
        findings = secret_guard.scan_text(
            "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n"
            "TWILIO_ACCOUNT_SID=%s\nTWILIO_AUTH_TOKEN=%s\n" %
            (aws_id, aws_secret, twilio_id, twilio_secret), ".env")
        rules = {row["rule"] for row in findings}
        self.assertIn("secctx-aws-credential-pair", rules)
        self.assertIn("secctx-twilio-credential-pair", rules)
        self.assert_redacted(findings, aws_id, aws_secret, twilio_id, twilio_secret)

    def test_contextual_cloud_keys_and_pem_variants(self):
        datadog = "a1b2" * 8
        cloudflare = "Aa1_" * 10
        azure = "Ab1+" * 12
        text = "\n".join([
            "DATADOG_API_KEY=" + datadog,
            "CLOUDFLARE_API_TOKEN=" + cloudflare,
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + azure,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ])
        findings = secret_guard.scan_text(text, "production.env")
        kinds = {row["secret_kind"] for row in findings}
        self.assertIn("datadog-api-key", kinds)
        self.assertIn("cloudflare-api-token", kinds)
        self.assertIn("azure-storage-account-key", kinds)
        self.assertIn("private-key", kinds)
        self.assert_redacted(findings, datadog, cloudflare, azure)

    def test_gcp_service_account_private_key_gets_context(self):
        findings = secret_guard.scan_text(
            '{"type":"service_account",\n"private_key":"-----BEGIN PRIVATE KEY-----\\n..."}',
            "service-account.json",
        )
        self.assertIn("secctx-gcp-service-account-key", {row["rule"] for row in findings})

    def test_entropy_is_stable_and_secret_mapping_is_versioned(self):
        self.assertAlmostEqual(secret_guard.shannon_entropy("aaaaaaaa"), 0.0)
        self.assertGreater(secret_guard.shannon_entropy("aB3$zQ8!"), 2.5)
        value = "A9b_Z7x-Q2m.V8k_N4p-R6t.Y3c_"
        row = secret_guard.scan_text("CLIENT_SECRET=" + value, "settings.ini")[0]
        self.assertEqual(row["owasp_2025"], "A07:2025 Authentication Failures")
        self.assertEqual(row["nist_ssdf"], ["PW.7.2"])

    def test_source_expressions_are_not_mistaken_for_literal_credentials(self):
        dynamic = "\n".join([
            'token = request.headers.get("Authorization", "")',
            'key = hashlib.sha256(identity.encode()).hexdigest()',
            'findings.sort(key=Finding.sort_key)',
        ])
        self.assertEqual(secret_guard.scan_text(dynamic, "app.py"), [])
        literal = "A9b_Z7x-Q2m.V8k_N4p-R6t.Y3c_"
        findings = secret_guard.scan_text('CLIENT_SECRET="%s"' % literal, "app.py")
        self.assertIn("secctx-hardcoded-credential", {row["rule"] for row in findings})
        self.assert_redacted(findings, literal)


if __name__ == "__main__":
    unittest.main()
