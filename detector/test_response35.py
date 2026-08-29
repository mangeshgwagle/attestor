from __future__ import annotations

import copy
import unittest

import response35
import truth_guard35


def report():
    return truth_guard35.guard_document({
        "schema": "attestor-maximum/3.5", "version": "3.5.0",
        "status": "action-required", "root": ".",
        "summary": {"findings": 1, "component_errors": 0},
        "findings": [{"rule": "r", "path": "app.py", "line": 2,
                      "severity": "HIGH", "message": "unsafe input",
                      "confidence": 0.9}],
        "improvements": [], "priorities": [{"fix": "Validate the input."}],
        "errors": [], "coverage": {"gaps": ["runtime path not exercised"],
                                      "absence_proven": False},
    })


class Response35Tests(unittest.TestCase):
    def test_response_is_outcome_first_and_bounded(self):
        text = response35.render_guarded(report())
        self.assertIn("1 finding(s) observed", text)
        self.assertIn("Limits and unknowns", text)
        self.assertIn("not empirically calibrated", text)
        self.assertIn("not authenticated for a trust boundary", text)

    def test_tampered_report_is_withheld(self):
        value = copy.deepcopy(report()); value["status"] = "no bugs"
        text = response35.render_guarded(value)
        self.assertIn("withheld", text)
        self.assertNotIn("no bugs", text)

    def test_no_findings_is_not_no_bugs(self):
        value = truth_guard35.guard_document({
            "status": "no-findings-from-enabled-checks", "findings": [],
            "improvements": [], "errors": [],
            "summary": {"findings": 0, "component_errors": 0},
            "coverage": {"gaps": [], "absence_proven": False}})
        text = response35.render_guarded(value, "concise")
        self.assertIn("cannot prove", text)
        self.assertNotIn("no bugs", text.lower())

    def test_unknown_style_is_rejected(self):
        with self.assertRaises(ValueError):
            response35.render_guarded(report(), "hype")

    def test_signed_report_renders_only_with_key(self):
        key = b"k" * 32
        value = truth_guard35.guard_document({
            "status": "action-required", "findings": [], "improvements": [],
            "errors": [], "summary": {"findings": 0},
            "coverage": {"gaps": ["fixture"], "absence_proven": False}},
            key=key, key_id="fixture")
        self.assertIn("withheld", response35.render_guarded(value))
        signed = response35.render_guarded(value, truth_key=key)
        self.assertIn("Attestor 3.5", signed)
        self.assertIn("HMAC-SHA256 authenticated as fixture", signed)


if __name__ == "__main__":
    unittest.main()
