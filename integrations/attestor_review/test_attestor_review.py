#!/usr/bin/env python3
"""Tests for the professional review voice and its TCS route.

Imported as `attestor_review`: `detector/review.py` is a different, older
tool that reviews a *diff*, and with the detector on `sys.path` a plain
`import review` silently picks that one up instead.

Two properties carry the weight. The register must stay clean, because the
whole reason this module exists beside `attestor4kids` is that one of them can be
shown to a client. And the TCS route must refuse by default, because material
supplied by another organization is exactly what a tool should not open on its
own authority.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
DETECTOR = str(HERE.parent.parent / "detector")
sys.path.insert(0, str(HERE))
sys.path.insert(0, DETECTOR)

import attestor_review as review

DEFECTIVE = (
    "import subprocess\n"
    "def go(tag):\n"
    "    if tag == None:\n"
    "        return 1\n"
    "    subprocess.run('git push ' + tag, shell=True)\n"
)
CLEAN = "def add(left, right):\n    return left + right\n"

# The point of the module. If any of these appear, the wrong twin was edited.
VULGAR = ("fuck", "shit", "damn", "crap", "idiot", "stupid", "moron",
          "garbage", "bloody")


def temp_file(text: str, suffix: str = ".py") -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8", newline="\n")
    handle.write(text)
    handle.close()
    return handle.name


class Register(unittest.TestCase):
    def test_the_module_contains_no_vulgarity(self):
        source = pathlib.Path(review.__file__).read_text(encoding="utf-8")
        lowered = source.lower()
        for word in VULGAR:
            with self.subTest(word=word):
                self.assertNotIn(word, lowered)

    def test_rendered_output_contains_no_vulgarity(self):
        findings = review.scan_file(temp_file(DEFECTIVE), DETECTOR)
        rendered = review.render(findings).lower()
        for word in VULGAR:
            with self.subTest(word=word):
                self.assertNotIn(word, rendered)

    def test_every_severity_carries_guidance(self):
        self.assertEqual(set(review.GUIDANCE), set(review.SEVERITY_ORDER))


class Rendering(unittest.TestCase):
    def test_findings_are_reported_worst_first(self):
        findings = [
            {"path": "a.py", "line": 9, "rule": "low-one", "severity": "LOW",
             "message": "", "fix": ""},
            {"path": "a.py", "line": 2, "rule": "high-one", "severity": "HIGH",
             "message": "", "fix": ""},
        ]
        rendered = review.render(findings)
        self.assertLess(rendered.index("high-one"), rendered.index("low-one"))

    def test_absence_is_not_reported_as_safety(self):
        rendered = review.render([])
        self.assertIn("not a statement", rendered)
        self.assertNotIn("is safe", rendered)

    def test_a_clean_file_produces_no_findings(self):
        self.assertEqual(review.scan_file(temp_file(CLEAN), DETECTOR), [])

    def test_findings_carry_rule_line_and_severity(self):
        findings = review.scan_file(temp_file(DEFECTIVE), DETECTOR)
        self.assertTrue(findings)
        for item in findings:
            self.assertTrue(item["rule"])
            self.assertGreater(item["line"], 0)
            self.assertIn(item["severity"], review.SEVERITY_ORDER)


class Improving(unittest.TestCase):
    def test_a_proposal_never_writes_to_the_file(self):
        path = temp_file(DEFECTIVE)
        before = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        findings = review.scan_file(path, DETECTOR)
        review.propose_improvements(path, findings, DETECTOR)
        after = hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
        self.assertEqual(before, after, "the reviewed file was modified")

    def test_an_unrepairable_finding_is_explained_not_silently_dropped(self):
        path = temp_file("import os\nos.system('ls')\n")
        findings = review.scan_file(path, DETECTOR)
        outcome = review.propose_improvements(path, findings, DETECTOR)
        if not outcome["proposed"]:
            self.assertTrue(outcome["reason"])

    def test_a_clean_file_proposes_nothing(self):
        path = temp_file(CLEAN)
        outcome = review.propose_improvements(path, [], DETECTOR)
        self.assertFalse(outcome["proposed"])


class TcsRoute(unittest.TestCase):
    def _request(self, **overrides):
        payload = {
            "schema": "attestor-cjp-control-request/4.1.4",
            "profile": "cockroach-janta-party",
            "action": "inspect-files",
            "root": str(pathlib.Path(temp_file(DEFECTIVE)).parent),
            "files": [pathlib.Path(temp_file(DEFECTIVE)).name],
            "organization": "TCS", "issuer": "issuer",
            "owner_statement": "the owner agreed", "purpose": "review",
            "ttl_seconds": 60, "candidate_bundle": "", "backup_root": "",
        }
        payload.update(overrides)
        return temp_file(json.dumps(payload), suffix=".json")

    def test_it_refuses_when_permission_is_not_confirmed(self):
        """The default must be refusal.

        `permission_confirmed` stands for a person having agreed, so this
        module has no business supplying it on their behalf.
        """
        result = review.review_tcs(self._request(), DETECTOR)
        self.assertFalse(result["authorized"])
        self.assertTrue(result["reason"])
        self.assertEqual(result["findings"], [])

    def test_a_foreign_organization_is_refused(self):
        result = review.review_tcs(
            self._request(organization="Some Other Company"), DETECTOR,
            permission_confirmed=True)
        self.assertFalse(result["authorized"])

    def test_a_missing_request_is_reported(self):
        with self.assertRaises(review.ReviewError):
            review.review_tcs("no-such-request.json", DETECTOR)

    def test_a_malformed_request_is_reported(self):
        path = temp_file("{not json", suffix=".json")
        with self.assertRaises(review.ReviewError):
            review.review_tcs(path, DETECTOR)

    def test_it_does_not_reimplement_the_authorization_check(self):
        # A second, quieter door into the same material is the one that is
        # wrong. The organization allowlist must be consulted, not copied.
        source = pathlib.Path(review.__file__).read_text(encoding="utf-8")
        self.assertNotIn("ALLOWED_ORGANIZATIONS", source)
        self.assertIn("cjp_control414", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
