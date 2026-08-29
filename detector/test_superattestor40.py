from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import superattestor


class SuperAttestor40Tests(unittest.TestCase):
    def test_explicit_40_routes_remain_compatibility_surfaces(self):
        for request in ("attestor 4 .", "attestor 4.0 .", "attestor40 ."):
            with self.subTest(request=request):
                self.assertEqual(superattestor.decide(request)["action"], "attestor40")

    def test_unversioned_maximum_routes_advance_to_414(self):
        for request in ("maximum attestor .", "maximum review .", "maximum analysis ."):
            with self.subTest(request=request):
                self.assertEqual(superattestor.decide(request)["action"], "attestor414")

    def test_perform_returns_truth_guarded_40_json(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "app.py").write_text("value = 1\n", encoding="utf-8")
            fixture = superattestor.attestor40.truth_guard40.guard_document({
                "schema": "attestor-maximum/4.0", "version": "4.0.0",
                "root": folder, "status": "no-findings-with-gaps",
                "summary": {"findings": 0, "component_errors": 0,
                            "engineering_findings": 0, "security_fabric_findings": 0},
                "findings": [], "attack_paths": [], "improvements": [], "errors": [],
                "coverage": {"gaps": ["bounded dispatcher fixture"],
                             "completed_components": [], "absence_proven": False},
                "engineering": {"schema": "attestor-engineering/4.0", "version": "4.0.0",
                                "root": folder, "status": "not-run",
                                "summary": {"findings": 0}, "findings": []},
                "security_fabric": {"schema": "attestor-security-fabric/4.0",
                                    "version": "4.0.0", "root": folder,
                                    "status": "not-run", "summary": {"findings": 0},
                                    "findings": []},
            })
            with mock.patch.object(superattestor.attestor40, "maximum", return_value=fixture):
                text, code = superattestor.perform(
                    {"action": "attestor40", "path": folder}, output_format="json",
                    use_cache=False, max_improvement_files=0)
            document = json.loads(text)
            self.assertEqual(document["schema"], "attestor-maximum/4.0")
            self.assertEqual(document["version"], "4.0.0")
            self.assertIn("engineering", document)
            self.assertIn("security_fabric", document)
            self.assertTrue(superattestor.attestor40.truth_guard40.verify_guarded(document)["ok"])
            self.assertIn(code, (0, 1))

    def test_versioned_compatibility_routes_remain_explicit(self):
        self.assertEqual(superattestor.decide("attestor 3.5 .")["action"], "attestor35")
        self.assertEqual(superattestor.decide("attestor 3.0 .")["action"], "attestor3")


if __name__ == "__main__":
    unittest.main()
