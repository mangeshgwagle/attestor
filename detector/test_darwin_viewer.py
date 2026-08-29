"""Security contracts for the inert Darwin payload viewer."""
from __future__ import annotations

import re
import json
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
VIEWER = HERE / "darwin_payloads"


class DarwinViewerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (VIEWER / "index.html").read_text(encoding="utf-8")
        cls.js = (VIEWER / "viewer.js").read_text(encoding="utf-8")
        cls.catalog_text = (VIEWER / "payloads.json").read_text(encoding="utf-8")
        cls.catalog = json.loads(cls.catalog_text)

    def test_payload_viewer_uses_external_assets_and_strict_csp(self):
        self.assertIn('Content-Security-Policy', self.html)
        self.assertIn("script-src 'self'", self.html)
        self.assertIn("object-src 'none'", self.html)
        self.assertNotIn("'unsafe-inline'", self.html)
        self.assertRegex(self.html, r'<script\s+src="viewer\.js"\s+defer></script>')
        script_bodies = re.findall(
            r'<script\b[^>]*>(.*?)</script>', self.html,
            flags=re.IGNORECASE | re.DOTALL)
        self.assertTrue(script_bodies)
        self.assertTrue(all(not body.strip() for body in script_bodies))

    def test_untrusted_catalog_content_is_never_parsed_as_markup_or_code(self):
        combined = self.html + "\n" + self.js
        for dangerous in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(dangerous, combined)
        self.assertNotRegex(self.html, r'\son\w+\s*=')
        self.assertIn("code.textContent = preview", self.js)
        self.assertIn("pre.textContent = source", self.js)

    def test_copy_handlers_do_not_embed_payloads_in_event_attributes(self):
        self.assertNotIn("onclick=", self.html)
        self.assertIn("copy.addEventListener('click'", self.js)
        self.assertIn("MAX_SEARCH_RESULTS = 100", self.js)
        self.assertIn("MAX_INTRUDER_PREVIEW = 50", self.js)

    def test_catalog_records_provenance_without_extractor_machine_paths(self):
        provenance = self.catalog.get("provenance", {})
        self.assertEqual(provenance.get("license"), "MIT")
        self.assertEqual(
            provenance.get("primary_source"),
            "https://github.com/swisskyrepo/PayloadsAllTheThings")
        self.assertNotIn("F:\\\\temp\\\\darwin_extracted", self.catalog_text)
        self.assertTrue(all(
            category.get("path") == category.get("category")
            for category in self.catalog["categories"]))


if __name__ == "__main__":
    unittest.main()
