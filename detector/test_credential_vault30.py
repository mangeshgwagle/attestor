from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import credential_vault


class CredentialVaultTests(unittest.TestCase):
    def test_status_never_claims_plaintext_fallback(self):
        report = credential_vault.status()
        self.assertFalse(report["plaintext_fallback"])

    def test_invalid_names_fail_before_backend_use(self):
        with self.assertRaises(credential_vault.VaultError):
            credential_vault._validate_name("../escape")

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
    def test_dpapi_round_trip_never_writes_plaintext_or_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.json"
            vault = credential_vault.CredentialVault(path, purpose="unit-test")
            secret = "vault-only-super-secret-value"
            vault.put("service.api", secret)
            stored = path.read_text(encoding="utf-8")
            self.assertNotIn(secret, stored)
            self.assertNotIn("sha256", stored.lower())
            self.assertEqual(vault.get("service.api"), secret.encode("utf-8"))
            self.assertEqual(vault.names(), ["service.api"])
            self.assertTrue(vault.delete("service.api"))

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI test")
    def test_ciphertext_is_bound_to_record_name_and_purpose(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.json"
            vault = credential_vault.CredentialVault(path, purpose="one")
            vault.put("service.api", "secret-value")
            data = json.loads(path.read_text(encoding="utf-8"))
            data["records"]["other.api"] = data["records"].pop("service.api")
            path.write_text(json.dumps(data), encoding="utf-8")
            tampered = credential_vault.CredentialVault(path, purpose="one")
            with self.assertRaises(credential_vault.VaultError):
                tampered.get("other.api")


if __name__ == "__main__":
    unittest.main()
