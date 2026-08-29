from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest

import scanengine


class AdvancedIntegrationTests(unittest.TestCase):
    def test_workspace_scan_discovers_new_languages_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.php").write_text("<?php eval($source);\n", encoding="utf-8")
            (root / "safe.rb").write_text("puts value\n", encoding="utf-8")
            result = scanengine.scan([tmp], jobs=2, use_cache=False)
        self.assertEqual(result.files_scanned, 2)
        finding = next(item for item in result.issues if item.rule == "adv-php-eval")
        self.assertEqual(finding.source, "advanced_rules")
        self.assertEqual(finding.cwe, "CWE-95")
        self.assertEqual(finding.pack, "advanced-2.2")
        self.assertEqual(result.status, "findings")

    def test_sarif_preserves_rule_taxonomy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "main.tf"
            path.write_text("publicly_accessible = true\n", encoding="utf-8")
            result = scanengine.scan([str(path)], jobs=1, use_cache=False)
        sarif = scanengine.to_sarif(result)
        row = next(item for item in sarif["runs"][0]["results"]
                   if item["ruleId"] == "adv-tf-rds-public")
        self.assertEqual(row["properties"]["cwe"], "CWE-732")
        self.assertEqual(row["properties"]["pack"], "advanced-2.2")
        json.dumps(asdict(result))

    def test_unknown_but_textual_extension_gets_generic_secret_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.customext"
            path.write_text("API_KEY=sk_live_1234567890abcdefghijklmnop\n", encoding="utf-8")
            result = scanengine.scan([str(path)], jobs=1, use_cache=False)
        self.assertFalse(result.errors)
        self.assertNotEqual(result.status, "failed")
        self.assertTrue(any("secret" in issue.rule or "key" in issue.rule
                            for issue in result.issues), result.issues)


if __name__ == "__main__":
    unittest.main()
