#!/usr/bin/env python3
"""Tests for the ICSE Class 10 layer.

Every check is a pair, for the same reason the Java rules are: a check that
fires on the corrected program as well has taught the student nothing. The
other half of these tests is about what the report *claims* -- a tool aimed at
a fifteen-year-old must never let "I found nothing" read as "this is right".
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import attestor_icse


def java(body: str) -> str:
    handle = tempfile.NamedTemporaryFile("w", suffix=".java", delete=False,
                                         encoding="utf-8", newline="\n")
    handle.write("public class Prog {\n%s\n}\n" % body)
    handle.close()
    return handle.name


def rules(path, syllabus=None):
    return [f["rule"] for f in attestor_icse.review(path, syllabus)["findings"]]


def profile(**over):
    body = attestor_icse.template_syllabus()
    body.update(over)
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
    json.dump({k: v for k, v in body.items() if not k.startswith("_")}, handle)
    handle.close()
    return handle.name


class TheClassicMistakes(unittest.TestCase):
    def pair(self, rule, wrong, right):
        with self.subTest(rule=rule, form="wrong"):
            self.assertIn(rule, rules(java(wrong)))
        with self.subTest(rule=rule, form="right"):
            self.assertNotIn(rule, rules(java(right)))

    def test_string_compared_with_double_equals(self):
        self.pair("icse-string-equality",
                  '    void run() {\n'
                  '        String a = "yes";\n'
                  '        String b = "yes";\n'
                  '        if (a == b) { System.out.println("same"); }\n'
                  '    }',
                  '    void run() {\n'
                  '        String a = "yes";\n'
                  '        String b = "yes";\n'
                  '        if (a.equals(b)) { System.out.println("same"); }\n'
                  '    }')

    def test_string_compared_against_a_literal(self):
        # The commonest spelling of the mistake, and the one the first
        # version missed: `blank` keeps a literal's quotes but replaces its
        # contents, so the right-hand side stops being a word to match on.
        self.pair("icse-string-equality",
                  '    void run() {\n'
                  '        String grade = "A";\n'
                  '        if (grade == "A") { System.out.println("top"); }\n'
                  '    }',
                  '    void run() {\n'
                  '        String grade = "A";\n'
                  '        if (grade.equals("A")) { System.out.println("top"); }\n'
                  '    }')

    def test_a_character_literal_is_not_a_string(self):
        # char == 'A' is correct Java. Reporting it would teach the student
        # to distrust the tool.
        self.assertNotIn("icse-string-equality", rules(java(
            '    void run() {\n'
            "        char g = 'A';\n"
            "        if (g == 'A') { System.out.println(\"top\"); }\n"
            '    }')))

    def test_numbers_may_still_use_double_equals(self):
        # int == int is correct Java and must not be reported, or the check
        # becomes noise the student learns to ignore.
        self.assertNotIn("icse-string-equality", rules(java(
            '    void run() {\n'
            '        int a = 3;\n'
            '        int b = 4;\n'
            '        if (a == b) { System.out.println("same"); }\n'
            '    }')))

    def test_integer_division_stored_in_a_double(self):
        self.pair("icse-integer-division",
                  '    void run() {\n'
                  '        int total = 7;\n'
                  '        int count = 2;\n'
                  '        double avg = total / count;\n'
                  '    }',
                  '    void run() {\n'
                  '        int total = 7;\n'
                  '        int count = 2;\n'
                  '        double avg = (double) total / count;\n'
                  '    }')

    def test_array_loop_running_one_past_the_end(self):
        self.pair("icse-array-off-by-one",
                  '    void run() {\n'
                  '        int marks[] = new int[5];\n'
                  '        for (int i = 0; i <= marks.length; i++) { }\n'
                  '    }',
                  '    void run() {\n'
                  '        int marks[] = new int[5];\n'
                  '        for (int i = 0; i < marks.length; i++) { }\n'
                  '    }')

    def test_scanner_newline_left_in_the_buffer(self):
        self.pair("icse-scanner-newline",
                  '    void run() {\n'
                  '        int age = sc.nextInt();\n'
                  '        String name = sc.nextLine();\n'
                  '    }',
                  '    void run() {\n'
                  '        int age = sc.nextInt();\n'
                  '        System.out.println(age);\n'
                  '        String name = sc.next();\n'
                  '    }')

    def test_a_mistake_written_inside_a_string_is_not_reported(self):
        # The detector blanks literals first. Without that, a program that
        # merely prints the words "a == b" would be reported.
        self.assertEqual(rules(java(
            '    void run() {\n'
            '        String a = "compare with a == b here";\n'
            '        System.out.println(a);\n'
            '    }')), [])


class ScopeAgainstASyllabus(unittest.TestCase):
    def test_a_construct_outside_the_profile_is_flagged(self):
        path = java('    void run() {\n'
                    '        java.util.ArrayList list = new java.util.ArrayList();\n'
                    '    }')
        self.assertIn("icse-out-of-scope", rules(path, attestor_icse.load_syllabus(profile())))

    def test_a_permitted_construct_is_not_flagged(self):
        path = java('    void run() {\n'
                    '        int marks[] = new int[5];\n'
                    '    }')
        self.assertNotIn("icse-out-of-scope",
                         rules(path, attestor_icse.load_syllabus(profile())))

    def test_scope_is_not_checked_at_all_without_a_profile(self):
        path = java('    void run() {\n'
                    '        java.util.ArrayList list = new java.util.ArrayList();\n'
                    '    }')
        report = attestor_icse.review(path)
        self.assertFalse(report["scope_checked"])
        self.assertNotIn("icse-out-of-scope", [f["rule"] for f in report["findings"]])

    def test_a_profile_naming_an_unknown_construct_is_refused(self):
        # A typo must not silently disable a check.
        bad = profile(permitted=["array", "reccursion"])
        with self.assertRaises(attestor_icse.SyllabusError) as caught:
            attestor_icse.load_syllabus(bad)
        self.assertIn("reccursion", str(caught.exception))

    def test_a_foreign_schema_is_refused(self):
        bad = profile(schema="something/else")
        with self.assertRaises(attestor_icse.SyllabusError):
            attestor_icse.load_syllabus(bad)


class WhatTheReportClaims(unittest.TestCase):
    def test_the_template_does_not_claim_to_be_the_board_syllabus(self):
        template = attestor_icse.template_syllabus()
        self.assertIsNone(template["verified_against"])
        self.assertIn("Not checked against the CISCE document",
                      template["_note"])

    def test_a_clean_report_never_says_the_program_is_correct(self):
        text = attestor_icse.render(attestor_icse.review(java(
            '    void run() { System.out.println("hi"); }')))
        lowered = text.lower()
        for claim in ("correct", "full marks", "well done", "no errors",
                      "passes", "is right"):
            self.assertNotIn(claim, lowered)

    def test_a_clean_report_says_what_was_not_looked_at(self):
        text = attestor_icse.render(attestor_icse.review(java(
            '    void run() { System.out.println("hi"); }')))
        self.assertIn("did not check whether the program answers the "
                      "question", text)

    def test_an_unverified_profile_is_declared_as_such(self):
        path = java('    void run() { }')
        text = attestor_icse.render(
            attestor_icse.review(path, attestor_icse.load_syllabus(profile())))
        self.assertIn("NOT been verified", text)

    def test_a_verified_profile_stops_saying_so(self):
        path = java('    void run() { }')
        loaded = attestor_icse.load_syllabus(
            profile(verified_against="CISCE Computer Applications (86), 2026"))
        text = attestor_icse.render(attestor_icse.review(path, loaded))
        self.assertNotIn("NOT been verified", text)

    def test_missing_scope_check_is_declared_rather_than_implied(self):
        text = attestor_icse.render(attestor_icse.review(java('    void run() { }')))
        self.assertIn("Scope was NOT checked", text)

    def test_findings_explain_why_and_not_only_what(self):
        report = attestor_icse.review(java(
            '    void run() {\n'
            '        String a = "x";\n'
            '        String b = "y";\n'
            '        if (a == b) { }\n'
            '    }'))
        self.assertTrue(report["findings"])
        for item in report["findings"]:
            self.assertGreater(len(item["why"]), 60,
                               "a student needs the reason, not just a label")


if __name__ == "__main__":
    unittest.main(verbosity=2)
