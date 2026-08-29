#!/usr/bin/env python3
"""Tests for the house-profile review layer.

The behaviour that matters is what *blocks*. A profile that reads as strict
and silently enforces nothing is the failure worth testing for, because it
produces a clean report and nobody learns the check never ran.
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
DETECTOR = str(pathlib.Path(__file__).resolve().parent.parent.parent
               / "detector")
sys.path.insert(0, DETECTOR)

import attestor_pro

FLAWED = (
    "import subprocess\n"
    "\n"
    "def deploy(tag):\n"
    "    subprocess.run('git push ' + tag, shell=True)\n"
)


def write(text: str, suffix: str = ".py") -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8", newline="\n")
    handle.write(text)
    handle.close()
    return handle.name


def profile_file(body: dict) -> str:
    return write(json.dumps(body), suffix=".json")


def a_real_rule() -> str:
    import detect
    return next(r.rid for r in detect.RULES
                if r.rid == "py-subprocess-shell")


class ProfileLoading(unittest.TestCase):
    def test_unknown_rule_ids_are_refused_not_ignored(self):
        path = profile_file({"schema": attestor_pro.SCHEMA,
                             "mandatory": ["no-such-rule-at-all"]})
        with self.assertRaises(attestor_pro.ProfileError) as caught:
            attestor_pro.load_profile(path, DETECTOR)
        self.assertIn("does not have", str(caught.exception))

    def test_a_waiver_needs_a_stated_reason(self):
        path = profile_file({"schema": attestor_pro.SCHEMA,
                             "waived": {a_real_rule(): ""}})
        with self.assertRaises(attestor_pro.ProfileError):
            attestor_pro.load_profile(path, DETECTOR)

    def test_a_foreign_schema_is_refused(self):
        path = profile_file({"schema": "something/else"})
        with self.assertRaises(attestor_pro.ProfileError):
            attestor_pro.load_profile(path, DETECTOR)

    def test_a_bad_severity_override_is_refused(self):
        path = profile_file({"schema": attestor_pro.SCHEMA,
                             "severity_overrides": {a_real_rule(): "URGENT"}})
        with self.assertRaises(attestor_pro.ProfileError):
            attestor_pro.load_profile(path, DETECTOR)

    def test_the_template_only_names_rules_that_exist(self):
        template = attestor_pro.template_profile(DETECTOR)
        path = profile_file({k: v for k, v in template.items()
                             if not k.startswith("_")})
        loaded = attestor_pro.load_profile(path, DETECTOR)
        self.assertTrue(loaded.mandatory)

    def test_the_template_does_not_claim_to_be_anybody_s_standard(self):
        template = attestor_pro.template_profile(DETECTOR)
        self.assertIn("REPLACE", template["organisation"])
        self.assertNotIn("TCS", json.dumps(template))


class WhatBlocks(unittest.TestCase):
    def _review(self, profile):
        return attestor_pro.review(write(FLAWED), profile, DETECTOR)

    def test_a_mandatory_rule_blocks(self):
        profile = attestor_pro.Profile(mandatory=frozenset({a_real_rule()}))
        self.assertGreater(self._review(profile)["blocking"], 0)

    def test_an_advisory_rule_reports_without_blocking(self):
        profile = attestor_pro.Profile(advisory=frozenset({a_real_rule()}),
                                   unlisted=attestor_pro.ADVISORY)
        report = self._review(profile)
        self.assertEqual(report["blocking"], 0)
        self.assertTrue(report["findings"], "it should still be reported")

    def test_a_waived_rule_reports_with_its_reason_and_does_not_block(self):
        reason = "internal tooling only; reviewed 2026-08-09"
        profile = attestor_pro.Profile(waived={a_real_rule(): reason},
                                   unlisted=attestor_pro.ADVISORY)
        report = self._review(profile)
        self.assertEqual(report["blocking"], 0)
        waived = [f for f in report["findings"]
                  if f["disposition"] == attestor_pro.WAIVED]
        self.assertTrue(waived)
        self.assertEqual(waived[0]["reason"], reason)

    def test_unlisted_rules_follow_the_configured_default(self):
        strict = attestor_pro.Profile(unlisted=attestor_pro.MANDATORY)
        relaxed = attestor_pro.Profile(unlisted=attestor_pro.ADVISORY)
        self.assertGreater(self._review(strict)["blocking"], 0)
        self.assertEqual(self._review(relaxed)["blocking"], 0)

    def test_severity_can_be_raised_by_the_house(self):
        rule = a_real_rule()
        profile = attestor_pro.Profile(mandatory=frozenset({rule}),
                                   severity_overrides={rule: "HIGH"})
        report = self._review(profile)
        promoted = [f for f in report["findings"] if f["rule"] == rule]
        self.assertTrue(promoted)
        self.assertEqual(promoted[0]["severity"], "HIGH")


class Rendering(unittest.TestCase):
    def test_the_report_is_free_of_the_4kids_register(self):
        profile = attestor_pro.Profile(mandatory=frozenset({a_real_rule()}))
        text = attestor_pro.render(attestor_pro.review(write(FLAWED), profile,
                                               DETECTOR))
        lowered = text.lower()
        for word in ("shit", "fuck", "idiot", "stupid", "damn", "crap"):
            self.assertNotIn(word, lowered)

    def test_a_clean_report_does_not_claim_the_code_is_safe(self):
        report = attestor_pro.review(write("x = 1\n"), attestor_pro.Profile(),
                                 DETECTOR)
        text = attestor_pro.render(report)
        self.assertIn("unexamined", text)

    def test_findings_are_grouped_with_mandatory_first(self):
        rule = a_real_rule()
        profile = attestor_pro.Profile(mandatory=frozenset({rule}),
                                   unlisted=attestor_pro.ADVISORY)
        text = attestor_pro.render(attestor_pro.review(write(FLAWED), profile,
                                               DETECTOR))
        self.assertIn("Must be resolved before delivery", text)


class LabellingIsHonest(unittest.TestCase):
    def test_an_advisory_reason_is_not_labelled_a_waiver(self):
        # "waiver: not named by the house profile" reads as though somebody
        # signed the finding off. Nobody did; it simply was not listed.
        profile = attestor_pro.Profile(unlisted=attestor_pro.ADVISORY)
        text = attestor_pro.render(attestor_pro.review(write(FLAWED), profile,
                                               DETECTOR))
        self.assertIn("note:", text)
        self.assertNotIn("waiver:", text)

    def test_a_real_waiver_is_still_labelled_a_waiver(self):
        profile = attestor_pro.Profile(waived={a_real_rule(): "signed off"},
                                   unlisted=attestor_pro.ADVISORY)
        text = attestor_pro.render(attestor_pro.review(write(FLAWED), profile,
                                               DETECTOR))
        self.assertIn("waiver: signed off", text)

    def test_unreviewable_languages_are_declared_in_the_report(self):
        # Ruby now, not C#: this used `.java` until Java gained rules, then
        # `.cs` until the C# pack landed, at which point the banner correctly
        # stopped appearing and this test correctly failed. The example has to
        # be a language Attestor still cannot review, and the set of those
        # shrinks every time a rule pack is written -- PHP, Kotlin and Swift are
        # the next candidates when Ruby gains rules.
        import tempfile, pathlib as _p
        folder = _p.Path(tempfile.mkdtemp())
        (folder / "a.rb").write_text("class A\nend\n", encoding="utf-8")
        text = attestor_pro.render(attestor_pro.review(str(folder),
                                               attestor_pro.Profile(), DETECTOR))
        self.assertIn("NOT REVIEWED", text)
        self.assertIn("unexamined, not clean", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)

