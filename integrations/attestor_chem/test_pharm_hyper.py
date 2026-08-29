"""Pharmacy calculations and the hyperoperation hierarchy.

Both are checked against something rather than asserted: the pharmacy
functions against the conservation law each rests on, the hyperoperations
against the closed forms and published values they must agree with.
"""
from __future__ import annotations

import unittest

import hyperop as h
import attestor_pharm as ph


class Dilution(unittest.TestCase):
    def test_a_worked_example(self):
        result = ph.dilute(70, 100, strength_after=20)
        self.assertAlmostEqual(result["volume_after"], 350.0)
        self.assertAlmostEqual(result["diluent_to_add"], 250.0)

    def test_solute_is_conserved(self):
        """The law the answer rests on, checked on the answer."""
        for before, volume, after in ((70, 100, 20), (1, 500, 0.25),
                                      (10, 250, 2.5), (95, 40, 70)):
            with self.subTest(case=(before, volume, after)):
                result = ph.dilute(before, volume, strength_after=after)
                self.assertAlmostEqual(
                    before * volume,
                    result["strength_after"] * result["volume_after"], 6)

    def test_either_unknown_can_be_solved(self):
        by_strength = ph.dilute(1, 500, strength_after=0.25)
        by_volume = ph.dilute(1, 500, volume_after=2000)
        self.assertAlmostEqual(by_strength["volume_after"], 2000.0)
        self.assertAlmostEqual(by_volume["strength_after"], 0.25)

    def test_it_refuses_to_concentrate(self):
        """Adding diluent cannot raise the strength."""
        with self.assertRaises(ph.PharmError) as caught:
            ph.dilute(20, 100, strength_after=70)
        self.assertIn("concentrates", str(caught.exception))

    def test_exactly_one_unknown(self):
        with self.assertRaises(ph.PharmError):
            ph.dilute(70, 100)
        with self.assertRaises(ph.PharmError):
            ph.dilute(70, 100, strength_after=20, volume_after=350)

    def test_the_arithmetic_is_exact(self):
        """A third of 30 mL is exactly 10, not 9.999999999999998.

        The exact answer deliberately does *not* equal the float one --
        Fraction(10, 3) != 3.3333333333333335 -- which is the whole reason
        for using Fraction, and which this test originally asserted the
        wrong way round.
        """
        from fractions import Fraction
        third = ph.solve_c1v1(c1=1, v1=10, c2=3)
        self.assertEqual(third, Fraction(10, 3))
        self.assertNotEqual(third, 10 / 3)
        self.assertEqual(ph.solve_c1v1(c1=1, v1=30, c2=3), Fraction(10))
        self.assertEqual(float(ph.solve_c1v1(c1=3, v1=10, c2=1)), 30.0)


class Alligation(unittest.TestCase):
    def test_the_classic_case(self):
        result = ph.alligation(70, 20, 40, total=500)
        self.assertAlmostEqual(result["volume_strong"], 200.0)
        self.assertAlmostEqual(result["volume_weak"], 300.0)

    def test_both_volume_and_drug_are_conserved(self):
        """Getting the two subtractions the wrong way round produces a
        plausible-looking wrong ratio, which is why both are checked."""
        for strong, weak, wanted, total in ((70, 20, 40, 500),
                                            (95, 50, 70, 1000),
                                            (10, 0, 2, 250)):
            with self.subTest(case=(strong, weak, wanted)):
                result = ph.alligation(strong, weak, wanted, total=total)
                self.assertAlmostEqual(
                    result["volume_strong"] + result["volume_weak"], total, 6)
                self.assertAlmostEqual(
                    result["volume_strong"] * strong
                    + result["volume_weak"] * weak, total * wanted, 6)

    def test_the_target_must_lie_between(self):
        with self.assertRaises(ph.PharmError):
            ph.alligation(70, 20, 90, total=500)
        with self.assertRaises(ph.PharmError):
            ph.alligation(70, 20, 10, total=500)


class OtherCalculations(unittest.TestCase):
    def test_percentage_strength(self):
        self.assertAlmostEqual(ph.percent_strength(9, 1000), 0.9)
        self.assertAlmostEqual(ph.percent_strength(5, 100, "w/w"), 5.0)

    def test_the_kind_must_be_named(self):
        """5% means three different quantities; conflating them is the
        classic error, so the kind is required rather than defaulted."""
        with self.assertRaises(ph.PharmError):
            ph.percent_strength(5, 100, "w/x")

    def test_ratio_strength(self):
        self.assertAlmostEqual(ph.ratio_strength(1, 5000, 250), 0.05)
        self.assertAlmostEqual(ph.ratio_strength(1, 1000, 1000), 1.0)

    def test_ppm(self):
        self.assertAlmostEqual(ph.ppm(0.001, 1000), 1.0)

    def test_molarity_and_milliequivalents(self):
        self.assertAlmostEqual(ph.molarity(5.85, 58.44, 0.5), 0.2002, 4)
        self.assertAlmostEqual(ph.millieq(0.585, 58.5), 10.0)

    def test_dose_by_weight_separates_per_dose_from_per_day(self):
        """"5 mg/kg/day in 3 divided doses" against "5 mg/kg per dose" is a
        three-fold error, so both numbers are returned."""
        result = ph.dose_by_weight(12, 70, 3)
        self.assertAlmostEqual(result["per_dose"], 840.0)
        self.assertAlmostEqual(result["per_day"], 2520.0)
        self.assertIn("daily total", result["note"])

    def test_impossible_inputs_are_refused(self):
        for call in (lambda: ph.percent_strength(5, 0),
                     lambda: ph.molarity(5, 58, 0),
                     lambda: ph.dose_by_weight(5, 70, 0),
                     lambda: ph.percent_strength(-1, 100)):
            with self.assertRaises(ph.PharmError):
                call()


class TheHierarchy(unittest.TestCase):
    def test_the_published_values(self):
        self.assertEqual(h.hyper(1, 2, 3), 5)
        self.assertEqual(h.hyper(2, 2, 3), 6)
        self.assertEqual(h.hyper(3, 2, 3), 8)
        self.assertEqual(h.hyper(4, 2, 3), 16)
        self.assertEqual(h.hyper(5, 2, 3), 65536)

    def test_tetration_is_right_associated(self):
        """3↑↑3 is 3^(3^3) = 3^27, not (3^3)^3 = 3^9. Seven trillion
        against nineteen thousand."""
        self.assertEqual(h.tetrate(3, 3), 3 ** 27)
        self.assertEqual(h.tetrate(3, 3), 7625597484987)
        self.assertNotEqual(h.tetrate(3, 3), (3 ** 3) ** 3)

    def test_each_level_agrees_with_its_closed_form(self):
        """The recursion and the arithmetic must not drift apart."""
        for a in range(2, 6):
            for b in range(1, 6):
                self.assertEqual(h.hyper(2, a, b), a * b)
                self.assertEqual(h.hyper(3, a, b), a ** b)

    def test_a_level_is_the_one_below_it_repeated(self):
        """H4(a,3) = a^(a^a), built from H3."""
        for a in (2, 3, 4):
            self.assertEqual(h.tetrate(a, 3), a ** (a ** a))
            self.assertEqual(h.tetrate(a, 2), a ** a)

    def test_height_zero_is_one(self):
        for fn in (h.tetrate, h.pentate, h.hexate):
            self.assertEqual(fn(5, 0), 1)

    def test_it_refuses_rather_than_hanging(self):
        """2↑↑5 is 2^65536 -- about twenty thousand digits. A naive version
        does not give a wrong answer, it stops responding."""
        for call in (lambda: h.tetrate(2, 5),
                     lambda: h.tetrate(3, 4),
                     lambda: h.pentate(3, 3),
                     lambda: h.hexate(3, 3)):
            with self.assertRaises(h.TooLarge):
                call()

    def test_the_budget_can_be_raised(self):
        value = h.tetrate(2, 5, budget=50_000)
        self.assertEqual(value, 2 ** 65536)
        self.assertEqual(h.digits(value), 19729)

    def test_the_digit_count_avoids_the_stringify_limit(self):
        """CPython refuses to stringify an integer above 4,300 digits, so a
        guard written with len(str(n)) raises ValueError instead of TooLarge
        and any budget above 4,300 becomes unreachable."""
        big = 2 ** 65536
        self.assertEqual(h.digits(big), 19729)
        with self.assertRaises(ValueError):
            len(str(big))
        self.assertEqual(h.digits(0), 1)
        self.assertEqual(h.digits(999), 3)
        self.assertEqual(h.digits(1000), 4)

    def test_an_unknown_level_is_refused(self):
        for level in (0, 7, -1):
            with self.assertRaises(ValueError):
                h.hyper(level, 2, 3)


if __name__ == "__main__":
    unittest.main()
