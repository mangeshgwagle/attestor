from __future__ import annotations

import unittest
from pathlib import Path

import engineering_engine40
import attestor40
import attestor_lsp
import release_hardening
import security_fabric40
import truth_guard40


ROOT = Path(__file__).resolve().parent.parent


class Attestor40VersionContractTests(unittest.TestCase):
    def test_legacy_40_modules_remain_explicit_compatibility_surfaces(self):
        expected = "4.0.0"
        observed = {
            "engineering_engine40.VERSION": engineering_engine40.VERSION,
            "attestor40.VERSION": attestor40.VERSION,
            "attestor_lsp.SERVER_VERSION": attestor_lsp.SERVER_VERSION,
            "security_fabric40.VERSION": security_fabric40.VERSION,
            "truth_guard40.VERSION": truth_guard40.VERSION,
        }
        for source, value in observed.items():
            with self.subTest(source=source):
                self.assertEqual(value, expected)

    def test_release_marker_has_advanced_without_relabeling_40(self):
        self.assertEqual((ROOT / "VERSION").read_text(encoding="utf-8").strip(),
                         "4.2")
        self.assertEqual(release_hardening.PRODUCT_VERSION, "4.2")


if __name__ == "__main__":
    unittest.main()
