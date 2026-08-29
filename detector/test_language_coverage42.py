#!/usr/bin/env python3
"""Tests for language coverage reporting.

The point is a single distinction: "scanned and clean" versus "never had a
rule to run". A test suite that only checked the counts would pass while the
report still conflated the two.
"""
from __future__ import annotations

import pathlib
import tempfile
import unittest

import detect
import language_coverage42 as coverage

# Ruby with a command injection and a broken digest. Attestor has no Ruby rules,
# so this must be reported as unexamined -- never as clean.
#
# This example was Java until Java gained rules, then C# until C# gained them,
# which is the whole point of the module: the set of unreviewable languages
# shrinks as rules are written, and the report has to keep telling the truth
# about which is which. When Ruby gains rules this moves again -- PHP, Kotlin
# and Swift are all still `text` and all still carry defects Attestor cannot see.
UNCOVERED = """class Deploy
  def run(args)
    system("git push #{args[0]}")
    Digest::MD5.hexdigest(args[1])
  end
end
"""
UNCOVERED_SUFFIX = ".rb"

PYTHON = "import subprocess\nsubprocess.run(cmd, shell=True)\n"


def write(text: str, suffix: str) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False,
                                         encoding="utf-8", newline="\n")
    handle.write(text)
    handle.close()
    return handle.name


class Counts(unittest.TestCase):
    def test_counts_match_the_registered_rules(self):
        counts = coverage.rule_counts()
        total = sum(1 for rule in detect.RULES
                    if set(getattr(rule, "langs", ()) or ()) - {"*"})
        self.assertLessEqual(len(counts), total)
        self.assertIn("c", counts)
        self.assertIn("python", counts)

    def test_wildcard_rules_are_not_counted_as_coverage(self):
        # They run on any text, so counting them would make every file type
        # look supported -- which is the illusion this module exists to break.
        self.assertNotIn("*", coverage.rule_counts())
        self.assertGreater(coverage.wildcard_rules(), 0)

    def test_the_uncovered_example_is_still_uncovered(self):
        """Guards the fixture above, not Ruby specifically.

        The suite's premise is that `UNCOVERED` names a language Attestor has no
        rules for. If that stops being true the other tests here start passing
        for the wrong reason, so this asserts the premise directly rather than
        naming a language that will eventually gain rules like Java and C# did.
        """
        language = detect.language_for("example" + UNCOVERED_SUFFIX)
        self.assertNotIn(language, coverage.covered_languages())
        self.assertEqual(0, coverage.rule_counts().get(language, 0))


class TheDistinctionThatMatters(unittest.TestCase):
    def test_an_uncovered_language_reports_zero_findings(self):
        """The premise: real defects, no rules, no findings.

        If this ever fails, Attestor grew rules for this language too and the
        example needs moving again -- which already happened once, when
        it was Java.
        """
        path = write(UNCOVERED, UNCOVERED_SUFFIX)
        language = coverage.language_of(path)
        findings = detect.scan_source(UNCOVERED, path, language, deep=True)
        self.assertEqual(len(findings), 0)

    def test_coverage_calls_that_file_unexamined(self):
        verdict = coverage.assess(write(UNCOVERED, UNCOVERED_SUFFIX))
        self.assertFalse(verdict["covered"])
        self.assertIn("unexamined", verdict["note"])

    def test_java_became_covered(self):
        # It was not, until rules were written. The module has to notice.
        self.assertIn("java", coverage.covered_languages())

    def test_a_python_file_is_examined(self):
        verdict = coverage.assess(write(PYTHON, ".py"))
        self.assertTrue(verdict["covered"])
        self.assertGreater(verdict["specific_rules"], 0)

    def test_survey_separates_the_two(self):
        report = coverage.survey([write(UNCOVERED, UNCOVERED_SUFFIX), write(PYTHON, ".py")])
        self.assertEqual(report["files"], 2)
        self.assertEqual(report["examined"], 1)
        self.assertEqual(report["unexamined"], 1)

    def test_survey_names_the_languages_it_could_not_review(self):
        report = coverage.survey([write(UNCOVERED, UNCOVERED_SUFFIX)])
        self.assertTrue(report["unexamined_languages"])

    def test_an_all_covered_survey_reports_nothing_unexamined(self):
        report = coverage.survey([write(PYTHON, ".py")])
        self.assertEqual(report["unexamined"], 0)
        self.assertEqual(report["unexamined_languages"], [])


class CliContract(unittest.TestCase):
    def test_exit_status_flags_unexamined_files(self):
        # A pipeline needs to be able to notice, not just read prose.
        self.assertEqual(coverage.main([write(UNCOVERED, UNCOVERED_SUFFIX)]), 1)

    def test_exit_status_is_zero_when_everything_was_reviewed(self):
        self.assertEqual(coverage.main([write(PYTHON, ".py")]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
