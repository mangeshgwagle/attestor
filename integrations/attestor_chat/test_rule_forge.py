#!/usr/bin/env python3
"""Tests for the parts of the forge that do not need a model or a corpus.

The propose/measure loop needs 6 GB of weights and 153 MB of NIST material,
so it is exercised by running it. What is tested here is everything that
decides whether a proposal is *allowed* to be measured -- the parsing, the
refusals, and the counting -- because those are what stand between a model's
guess and a number somebody might believe.
"""
from __future__ import annotations

import subprocess
import time
import unittest
from typing import NamedTuple
from unittest import mock

import rule_forge


class Row(NamedTuple):
    text: str
    label: int


class ExtractPattern(unittest.TestCase):
    def test_fenced_regex_block(self):
        reply = "Here you go:\n```regex\nmalloc\\([^)]*\\)\n```\nHope that helps."
        self.assertEqual(rule_forge.extract_pattern(reply),
                         r"malloc\([^)]*\)")

    def test_fence_without_language(self):
        self.assertEqual(
            rule_forge.extract_pattern("```\nfree\\(\\w+\\)\n```"),
            r"free\(\w+\)")

    def test_unfenced_reply_takes_the_pattern_not_the_prose(self):
        reply = ("This pattern should work well for your case.\n"
                 "strcpy\\([^,]+,[^)]+\\)\n")
        self.assertEqual(rule_forge.extract_pattern(reply),
                         r"strcpy\([^,]+,[^)]+\)")

    def test_python_raw_string_is_unwrapped(self):
        self.assertEqual(rule_forge.extract_pattern("```\nr'\\bgets\\b'\n```"),
                         r"\bgets\b")

    def test_empty_reply_is_refused(self):
        with self.assertRaises(rule_forge.ForgeError):
            rule_forge.extract_pattern("   \n  \n")


class CompileCandidate(unittest.TestCase):
    def test_ordinary_pattern_compiles(self):
        self.assertTrue(rule_forge.compile_candidate(r"free\(\w+\)"))

    def test_nested_quantifier_is_refused(self):
        # (\w+)+ is not slow on these inputs -- it is slow on *some* input,
        # and `re` gives no way to stop it once it starts. The brace forms
        # count: (\d{2,})+ backtracks exponentially just as (\d+)+ does.
        for pattern in (r"(\w+)+x", r"(a*)*b", r"(\d{2,})+",
                        r"(?:\w+)+", r"(\d{1,4})*"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(rule_forge.ForgeError):
                    rule_forge.compile_candidate(pattern)

    def test_ambiguous_and_deeply_nested_catastrophic_shapes_are_refused(self):
        # These were all accepted by the former one-level textual guard.  Do
        # not execute them here: structural validation must reject them before
        # CPython's backtracking engine sees attacker-controlled text.
        for pattern in (r"(a|aa)+$", r"((a+))+$", r"(a?){20}a{20}"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(rule_forge.ForgeError):
                    rule_forge.compile_candidate(pattern)

    def test_safe_groups_are_not_refused(self):
        # The guard is a blunt instrument, so it is worth knowing it does not
        # reject the ordinary shapes a real rule is built from.
        for pattern in (r"(malloc|calloc)\(", r"free\((\w+)\)",
                        r"\bmemcpy\([^,]+,[^,]+,\s*\d+\)"):
            with self.subTest(pattern=pattern):
                self.assertTrue(rule_forge.compile_candidate(pattern))

    def test_invalid_regex_is_refused(self):
        # Note `free\(\w+` is *valid* -- the paren is escaped, so nothing is
        # unbalanced. These are genuinely malformed.
        for pattern in (r"[a-", r"(unclosed", r"*leading", r"(?P<"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(rule_forge.ForgeError):
                    rule_forge.compile_candidate(pattern)

    def test_overlong_pattern_is_refused(self):
        with self.assertRaises(rule_forge.ForgeError):
            rule_forge.compile_candidate("a" * 401)


class Evaluate(unittest.TestCase):
    ROWS = [
        Row("char buf[10];\nstrcpy(buf, src);", 1),
        Row("char buf[10];\nstrcpy(buf, src);", 1),
        Row("char buf[10];\nstrncpy(buf, src, 9);", 0),
        Row("char buf[10];\nstrncpy(buf, src, 9);", 0),
    ]

    def test_perfect_discriminator(self):
        score = rule_forge.evaluate(
            rule_forge.compile_candidate(r"\bstrcpy\("), self.ROWS)
        self.assertEqual((score.true_positives, score.false_positives), (2, 0))
        self.assertEqual(score.recall, 1.0)

    def test_pattern_that_fires_on_both_scores_false_positives(self):
        score = rule_forge.evaluate(
            rule_forge.compile_candidate(r"char buf"), self.ROWS)
        self.assertEqual(score.false_positives, 2)

    def test_pattern_that_fires_on_nothing(self):
        score = rule_forge.evaluate(
            rule_forge.compile_candidate(r"\bmemcpy\("), self.ROWS)
        self.assertEqual(score.true_positives, 0)
        self.assertEqual(score.recall, 0.0)

    def test_recall_is_zero_rather_than_dividing_by_zero(self):
        score = rule_forge.evaluate(
            rule_forge.compile_candidate(r"x"), [Row("y", 0)])
        self.assertEqual(score.recall, 0.0)

    def test_a_worker_timeout_fails_closed(self):
        candidate = rule_forge.CompiledCandidate(r"literal", 0)
        timeout = subprocess.TimeoutExpired(["python"], 0.1)
        with mock.patch.object(rule_forge.subprocess, "run", side_effect=timeout):
            with self.assertRaisesRegex(rule_forge.ForgeError,
                                        "worker terminated"):
                rule_forge.evaluate(candidate, [Row("literal", 1)])

    def test_even_a_bypassed_catastrophic_pattern_is_really_terminated(self):
        # Construct the transport object directly to prove the process boundary
        # still protects callers that bypass compile_candidate's shape guard.
        candidate = rule_forge.CompiledCandidate(r"(a+)+$", 0)
        started = time.monotonic()
        with mock.patch.object(rule_forge, "REGEX_BATCH_TIMEOUT_SECONDS", 0.2):
            with self.assertRaisesRegex(rule_forge.ForgeError,
                                        "worker terminated"):
                rule_forge.evaluate(candidate, [Row("a" * 4095 + "!", 1)])
        self.assertLess(time.monotonic() - started, 2.0)

    def test_compiled_candidate_exposes_no_in_process_search_method(self):
        candidate = rule_forge.compile_candidate(r"literal")
        self.assertFalse(hasattr(candidate, "search"))


class AcceptanceBar(unittest.TestCase):
    def test_a_false_positive_disqualifies(self):
        self.assertEqual(rule_forge.MAX_HOLDOUT_FALSE_POSITIVES, 0)

    def test_recall_floor_is_above_zero(self):
        # A rule that fires on nothing has zero false positives too; without a
        # recall floor the bar would accept patterns that detect nothing.
        self.assertGreater(rule_forge.MIN_HOLDOUT_RECALL, 0.0)


class CorpusRefusal(unittest.TestCase):
    def test_missing_archive_is_reported_not_worked_around(self):
        with self.assertRaises(rule_forge.ForgeError) as caught:
            rule_forge.load_corpus("no-such-file.zip", "CWE190",
                                   str(__import__("pathlib").Path(__file__)
                                       .resolve().parent.parent.parent
                                       / "detector"))
        self.assertIn("corpus-unavailable", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
