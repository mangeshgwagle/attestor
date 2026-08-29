from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import superattestor


class SuperAttestor35Tests(unittest.TestCase):
    def test_natural_language_routes_35(self):
        self.assertEqual(superattestor.decide("attestor 3.5 .")["action"], "attestor35")
        self.assertEqual(superattestor.decide("attestor35 .")["action"], "attestor35")
        self.assertEqual(superattestor.decide("maximum 3.5 .")["action"], "attestor35")

    def test_perform_returns_truth_guarded_35_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "app.py").write_text("value = 1\n", encoding="utf-8")
            text, code = superattestor.perform(
                {"action": "attestor35", "path": temporary}, output_format="json",
                use_cache=False, max_improvement_files=0)
            document = json.loads(text)
            self.assertEqual(document["schema"], "attestor-maximum/3.5")
            self.assertIn("truth_guard2", document)
            self.assertIn(code, (0, 1))

    def test_perform_can_authenticate_report_for_a_trust_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "app.py").write_text("value = 1\n", encoding="utf-8")
            key = b"authenticated-report-test-key-35!"
            text, _code = superattestor.perform(
                {"action": "attestor35", "path": temporary}, output_format="json",
                use_cache=False, max_improvement_files=0,
                truth_key=key, truth_key_id="test-key")
            document = json.loads(text)
            verification = superattestor.attestor35.truth_guard35.verify_guarded(
                document, key=key)
            self.assertTrue(verification["ok"])
            self.assertTrue(verification["authenticated"])
            self.assertEqual(document["truth_guard2"]["signature"]["key_id"], "test-key")

    def test_legacy_attestor3_route_remains_available(self):
        self.assertEqual(superattestor.decide("attestor 3 .")["action"], "attestor3")
        self.assertEqual(superattestor.decide("attestor 3.0 .")["action"], "attestor3")

    def test_improve_returns_complete_verified_source_without_writing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "app.py"
            original = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
            target.write_text(original, encoding="utf-8")
            text, code = superattestor.perform(
                {"action": "improve", "path": str(root)},
                output_format="json", use_cache=False, max_improvement_files=1)
            report = json.loads(text)
            improvement = next(row for row in report["improvements"]
                               if row.get("accepted") is True)
            self.assertEqual(report["schema"], "attestor-maximum/4.1.4")
            self.assertEqual(
                report["variant_414"]["selected_profile"]["slug"],
                "south-park")
            self.assertEqual(code, 1)
            self.assertTrue(improvement["complete"])
            self.assertEqual(improvement["status"], "verified")
            self.assertIn("debug=False", improvement["improved_source"])
            self.assertEqual(report["compatibility_truth_guard_40"]["state"],
                             "verified-before-embedding")
            self.assertTrue(
                report["compatibility_truth_guard_40"][
                    "truth_guard2_projected"])
            self.assertEqual(
                report["compatibility_truth_guard_40"]["truth_guard2"][
                    "schema"],
                "attestor-compatibility-audit-projection/4.1")
            self.assertEqual(target.read_text(encoding="utf-8"), original)
            self.assertFalse(report["execution"]["repair_apply_performed"])

    def test_improve_route_uses_current_attestor414_not_compatibility_engines(self):
        guarded = {"status": "complete", "summary": {"findings": 0},
                   "repair_director_41": {"selected_candidate_output": None}}
        current = mock.Mock()
        current.maximum.return_value = {"engine": "4.1.4"}
        current.safe_public_report.return_value = guarded
        current.render.return_value = "Attestor 4.1.4 result"
        with mock.patch.object(superattestor, "_attestor414_module", return_value=current), \
                mock.patch.object(superattestor.attestor40, "maximum") as maximum40, \
                mock.patch.object(superattestor.attestor35, "maximum") as maximum35, \
                mock.patch.object(superattestor.attestor3, "maximum") as maximum3:
            text, code = superattestor.perform({"action": "improve", "path": "."})
        self.assertEqual((text, code), ("Attestor 4.1.4 result", 0))
        current.maximum.assert_called_once()
        self.assertTrue(current.maximum.call_args.kwargs["improve"])
        self.assertTrue(
            current.maximum.call_args.kwargs["include_candidate_source"])
        self.assertIs(
            current.maximum.call_args.kwargs["variant"],
            superattestor.variant414.SOUTH_PARK)
        maximum40.assert_not_called()
        maximum35.assert_not_called()
        maximum3.assert_not_called()


if __name__ == "__main__":
    unittest.main()
