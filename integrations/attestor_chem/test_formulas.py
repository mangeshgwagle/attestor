"""Every formula computes its own worked example.

This is the whole point of the file. A formula sheet with a typo is worse
than no formula sheet, because the typo gets memorised and survives into the
exam. Here a mistyped formula stops reproducing its own example and this
suite fails, so the reference cannot rot silently.
"""
from __future__ import annotations

import unittest

import formulas


class EveryFormulaChecksOut(unittest.TestCase):
    def test_each_one_reproduces_its_worked_example(self):
        for key, entry in formulas.FORMULAS.items():
            with self.subTest(formula=key):
                self.assertIn("answer", entry.example,
                              "%s has no worked example to check it" % key)
                got = entry.run_example()
                want = entry.example["answer"]
                tolerance = entry.example.get("tolerance", 0.01)
                self.assertAlmostEqual(
                    got, want, delta=tolerance,
                    msg="%s: computed %s, example says %s" % (key, got, want))

    def test_each_one_says_where_its_example_comes_from(self):
        for key, entry in formulas.FORMULAS.items():
            with self.subTest(formula=key):
                self.assertTrue(entry.example.get("source"),
                                "%s does not say where its example is from" % key)

    def test_every_symbol_is_explained(self):
        """A formula whose variables are unlabelled is unusable under exam
        pressure, which is the only time it will be read."""
        for key, entry in formulas.FORMULAS.items():
            with self.subTest(formula=key):
                self.assertTrue(entry.variables, "%s labels nothing" % key)

    def test_the_keys_are_unique_and_the_topics_are_real(self):
        self.assertEqual(len(formulas.FORMULAS), len(formulas._ENTRIES))
        self.assertGreaterEqual(len(formulas.topics()), 6)


class KnownAnswers(unittest.TestCase):
    """Values a marker would accept, checked independently of the examples."""

    def test_normal_saline(self):
        self.assertAlmostEqual(
            formulas.compute("percent_wv", grams=9, millilitres=1000), 0.9)

    def test_dilution(self):
        self.assertAlmostEqual(
            formulas.compute("c1v1", c1=70, v1=100, c2=20), 350.0)

    def test_mosteller_bsa(self):
        self.assertAlmostEqual(
            formulas.compute("bsa_mosteller", height_cm=170, weight_kg=70),
            1.818, delta=0.001)

    def test_cockcroft_gault_applies_the_female_correction(self):
        """The 0.85 is the part most often forgotten."""
        male = formulas.compute("cockcroft_gault", age=60, weight_kg=70,
                                creatinine=1.0)
        female = formulas.compute("cockcroft_gault", age=60, weight_kg=70,
                                  creatinine=1.0, female=True)
        self.assertAlmostEqual(male, 77.78, delta=0.01)
        self.assertAlmostEqual(female, male * 0.85, delta=0.01)

    def test_half_life_and_rate_constant_are_inverses(self):
        k = formulas.compute("elimination_rate", half_life=6)
        self.assertAlmostEqual(formulas.compute("half_life", k=k), 6.0,
                               delta=0.001)

    def test_clearance_chain_is_consistent(self):
        """k, Vd, CL and t½ must agree with each other."""
        k = formulas.compute("elimination_rate", half_life=6)
        vd = formulas.compute("volume_distribution", dose_mg=500,
                              concentration=10)
        cl = formulas.compute("clearance", k=k, vd=vd)
        self.assertAlmostEqual(cl, 0.693 / 6 * 50, delta=0.001)
        self.assertAlmostEqual(formulas.compute("half_life", k=cl / vd), 6.0,
                               delta=0.001)

    def test_paediatric_rules_at_their_landmarks(self):
        """Young's rule gives exactly half the adult dose at 12 years, and
        Clark's at 75 lb -- easy to check under pressure."""
        self.assertAlmostEqual(
            formulas.compute("youngs_rule", adult_dose=500, age_years=12), 250.0)
        self.assertAlmostEqual(
            formulas.compute("clarks_rule", adult_dose=500, weight_lb=75), 250.0)

    def test_drop_rate(self):
        self.assertAlmostEqual(
            formulas.compute("drops_per_min", volume_ml=1000, drop_factor=20,
                             minutes=480), 41.67, delta=0.01)

    def test_henderson_hasselbalch_at_equal_concentrations(self):
        self.assertAlmostEqual(
            formulas.compute("henderson_hasselbalch", pka=4.76, salt=1, acid=1),
            4.76, delta=0.001)


class Lookup(unittest.TestCase):
    def test_find_matches_name_topic_and_expression(self):
        self.assertTrue(formulas.find("clearance"))
        self.assertTrue(formulas.find("dilution"))
        self.assertTrue(formulas.find("BSA") or formulas.find("surface"))

    def test_show_lays_out_the_formula_and_its_example(self):
        text = formulas.show("cockcroft_gault")
        self.assertIn("140 - age", text)
        self.assertIn("worked:", text)
        self.assertIn("0.85", text)

    def test_show_accepts_an_unambiguous_partial_name(self):
        self.assertIn("Mosteller", formulas.show("mosteller"))

    def test_an_unknown_name_says_so(self):
        with self.assertRaises(KeyError):
            formulas.compute("not_a_formula", x=1)


if __name__ == "__main__":
    unittest.main()
