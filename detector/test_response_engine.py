from __future__ import annotations

import unittest

import response_engine


class ResponseEngineTests(unittest.TestCase):
    def test_finding_exit_is_not_misreported_as_operational_failure(self):
        text = "findings=3\nHIGH=1\n"
        evidence = {"validated": True, "counts": {"findings": 3, "high": 1},
                    "operational_errors": []}
        response = response_engine.wrap_text(
            text, 3, "workspace", "professional", evidence=evidence)
        self.assertIn("reported 3 item(s)", response)
        self.assertNotIn("could not complete", response)
        self.assertIn("CRITICAL/HIGH", response)

    def test_raw_text_cannot_fabricate_measured_counts(self):
        response = response_engine.wrap_text(
            "findings=999\nCOMPLETELY SECURE", 3, "workspace", "professional")
        self.assertNotIn("reported 999 item", response)
        self.assertIn("no validated evidence envelope", response)

    def test_clean_result_does_not_claim_perfect_safety(self):
        response = response_engine.wrap_text("No findings from enabled checks.", 0,
                                             "workspace", "concise")
        self.assertIn("enabled checks", response)
        self.assertNotIn("completely secure", response.lower())

    def test_styles_are_deterministic_and_classic_is_unchanged(self):
        raw = "details"
        self.assertEqual(response_engine.wrap_text(raw, 0, style="classic"), raw)
        for style in response_engine.STYLES:
            self.assertIsInstance(response_engine.wrap_text(raw, 0, style=style), str)
        with self.assertRaises(ValueError):
            response_engine.wrap_text(raw, 0, style="chaos")

    def test_structured_response_leads_with_outcome_and_priorities(self):
        report = {"status": "action-required", "readiness": {"score": 61, "label": "needs-work"},
                  "summary": {"files_scanned": 9, "findings": 2},
                  "priorities": [{"priority": "HIGH", "fix": "parameterize SQL"}],
                  "top_findings": [{"severity": "HIGH", "path": "app.py", "line": 9,
                                    "rule": "sql", "message": "dynamic SQL"}],
                  "assurance": ["Static evidence is bounded."]}
        text = response_engine.structured(report, "professional")
        self.assertTrue(text.startswith("Outcome"))
        self.assertIn("parameterize SQL", text)
        self.assertIn("app.py:9", text)

    def test_structured_response_surfaces_verified_improved_source(self):
        report = {
            "status": "action-required", "summary": {"findings": 1},
            "improvements": [{
                "target": "app.py", "accepted": True, "resolved_count": 1,
                "remaining_count": 0, "improved_source": "if value == 0:\n    pass\n",
                "reasons": [],
                "verification": {
                    "accepted": True, "compiler_or_parser": "verified",
                    "findings_after": 0, "new_findings": [], "new_failures": [],
                    "resolved_findings": [{"rule": "example"}],
                },
                "probes": [{"name": "parse", "status": "passed"}],
                "selected_tests": {"status": "not-run"},
            }],
        }
        text = response_engine.structured(report, "professional")
        self.assertIn("Verified improved results", text)
        self.assertIn("app.py: VERIFIED", text)
        self.assertIn("if value == 0", text)

    def test_truthy_string_cannot_forge_verified_improvement(self):
        text = response_engine.structured({
            "status": "action-required", "summary": {"findings": 1},
            "improvements": [{
                "target": "ghost.py", "accepted": "false", "resolved_count": 99,
                "remaining_count": 0, "improved_source": "x = 1\n",
            }],
        })
        self.assertNotIn("ghost.py: VERIFIED", text)
        self.assertIn("ghost.py: REFUSED", text)

    def test_findings_without_safe_fix_are_not_misrepresented_as_improved(self):
        text = response_engine.structured(
            {"status": "action-required", "summary": {"findings": 2}},
            "professional")
        self.assertIn("No change was presented as safe", text)


if __name__ == "__main__":
    unittest.main()
