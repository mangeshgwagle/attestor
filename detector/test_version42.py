from __future__ import annotations

from pathlib import Path
import unittest

import evidence_store41
import attestor414
import release_hardening
import variant414


ROOT = Path(__file__).resolve().parent.parent


class Attestor42DistributionVersionTests(unittest.TestCase):
    def test_distribution_and_release_packager_are_42(self) -> None:
        self.assertEqual(
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "4.2",
        )
        self.assertEqual(release_hardening.PRODUCT_VERSION, "4.2")

    def test_inherited_414_analysis_contracts_are_not_relabelled(self) -> None:
        self.assertEqual(
            {
                attestor414.VERSION,
                evidence_store41.VERSION,
                variant414.VERSION,
            },
            {"4.1.4"},
        )

    def test_root_launchers_identify_the_42_distribution(self) -> None:
        for name in (
            "Start_Attestor_UI.bat",
        ):
            with self.subTest(name=name):
                text = (ROOT / name).read_text(encoding="utf-8")
                self.assertIn("Attestor 4.2", text)


if __name__ == "__main__":
    unittest.main()
