"""The patterns must actually describe the preparations they claim to.

A reasoning guide that has drifted from the worked examples is worse than
none: it teaches a pattern and then the examples do not show it. So the
cross-references are resolved, and every preparation is required to be
reachable through at least one pattern -- otherwise the claim that "there
are about a dozen patterns, reused" is false and this file is decoration.
"""
from __future__ import annotations

import unittest

import preparations
import principles


class TheCrossReferencesResolve(unittest.TestCase):
    def test_every_cited_example_exists(self):
        self.assertTrue(principles.check_examples())

    def test_the_check_can_fail(self):
        """A renamed preparation must break the reference, not be ignored."""
        bad = principles.Pattern(
            key="bad", name="x", idea="x", recognise="x", moves=(),
            examples=("no_such_preparation",))
        original = principles._PATTERNS
        try:
            principles._PATTERNS = original + [bad]
            with self.assertRaises(principles.CrossReferenceError):
                principles.check_examples()
        finally:
            principles._PATTERNS = original

    def test_every_preparation_is_explained_by_some_pattern(self):
        """If a substance matches no pattern, either the pattern set is
        incomplete or that substance is being memorised rather than
        understood. Both are worth knowing about."""
        orphans = [key for key in preparations.PREPARATIONS
                   if not principles.patterns_for(key)]
        self.assertEqual(orphans, [],
                         "no pattern covers: %s" % ", ".join(orphans))

    def test_each_pattern_has_at_least_one_example(self):
        for key, pattern in principles.PATTERNS.items():
            with self.subTest(pattern=key):
                self.assertTrue(pattern.examples,
                                "%s claims a pattern with nothing showing it"
                                % key)


class ThePatternsAreUsable(unittest.TestCase):
    def test_each_pattern_says_when_it_applies(self):
        """A pattern you cannot recognise is a pattern you cannot use."""
        for key, pattern in principles.PATTERNS.items():
            with self.subTest(pattern=key):
                self.assertTrue(pattern.recognise.strip())
                self.assertGreater(len(pattern.idea), 40)

    def test_each_move_carries_its_reason(self):
        for key, pattern in principles.PATTERNS.items():
            for index, (move, why) in enumerate(pattern.moves, start=1):
                with self.subTest(pattern=key, move=index):
                    self.assertTrue(move.strip())
                    self.assertGreater(len(why), 30)

    def test_the_derivation_checklist_is_ordered_and_complete(self):
        """It must reach an answer: route, separation, drying, tests,
        assay and storage all have to be asked about."""
        questions = " ".join(q for q, _ in principles.DERIVATION).lower()
        for topic in ("soluble", "excess", "separate", "temperature",
                      "washed", "dried", "impurity", "assayed", "stored"):
            self.assertIn(topic, questions, "the checklist never asks about %s"
                          % topic)
        self.assertGreaterEqual(len(principles.DERIVATION), 10)

    def test_derive_renders_every_question(self):
        text = principles.derive("zinc oxide")
        self.assertIn("zinc oxide", text)
        for question, _guidance in principles.DERIVATION:
            self.assertIn(question, text)

    def test_derive_does_not_overclaim(self):
        """It produces defensible chemistry, not necessarily the official
        industrial route -- and it has to say so."""
        self.assertIn("not always reproduce", principles.derive())


class TheReasoningMatchesTheWorkedAnswers(unittest.TestCase):
    """Spot checks tying a pattern to the preparation that shows it."""

    def test_amphoterism_points_at_aluminium(self):
        keys = [p.key for p in principles.patterns_for("aluminium_hydroxide_gel")]
        self.assertIn("amphoterism", keys)

    def test_ferrous_sulphate_is_about_protecting_an_oxidation_state(self):
        keys = [p.key for p in principles.patterns_for("ferrous_sulphate")]
        self.assertIn("protecting_an_oxidation_state", keys)

    def test_barium_sulphate_is_a_precipitation_with_a_safety_constraint(self):
        keys = [p.key for p in principles.patterns_for("barium_sulphate")]
        self.assertIn("double_decomposition", keys)
        self.assertIn("safety", principles.show("double_decomposition").lower())

    def test_the_assay_pattern_covers_the_main_titration_families(self):
        text = principles.show("assay_follows_chemistry").lower()
        for family in ("permanganate", "iodometry", "edetate", "back-",
                       "silver nitrate", "mannitol"):
            self.assertIn(family, text)

    def test_the_limit_test_pattern_starts_from_the_reagents(self):
        text = principles.show("impurity_comes_from_the_method").lower()
        self.assertIn("reagents", text)
        self.assertIn("soluble barium", text)

    def test_show_names_the_examples_in_full(self):
        text = principles.show("solubility_difference")
        self.assertIn("Boric acid", text)
        self.assertIn("THE IDEA", text)
        self.assertIn("HOW IT IS GOT WRONG", text)

    def test_an_unknown_pattern_says_so(self):
        with self.assertRaises(KeyError):
            principles.show("not_a_pattern")


if __name__ == "__main__":
    unittest.main()
