"""The valency check: catch FeCl9 without rejecting KMnO4.

Balancing is arithmetic. `2Fe + 18HCl -> 2FeCl9 + 9H2` conserves every atom
and FeCl9 does not exist. The hard part was never catching it -- it was
catching it without refusing real chemistry, because a check that rejects
H2SO4 is one the student stops believing and then ignores when it is right.
"""
from __future__ import annotations

import unittest

import attestor_chem as ch


class ItRejectsNothingReal(unittest.TestCase):
    """The failure that would matter most, tested first."""

    # Includes the two that broke it: C3H8 and NO are real and were being
    # rejected, because valency arithmetic is a fact about ions and propane
    # is covalent. CO2, CH4 and NH3 had been passing by luck.
    REAL = ("H2O", "NaCl", "FeCl3", "FeCl2", "CaO", "Al2O3", "CO2", "CO",
            "CH4", "NH3", "Fe2O3", "MgO", "ZnCl2", "CuO", "PbO2", "SO2",
            "SO3", "P2O5", "HCl", "H2S", "AlCl3", "KBr", "CaS",
            "C3H8", "NO", "N2O5", "C2H6", "C6H6", "PCl3", "SF6")

    def test_no_real_binary_compound_is_called_impossible(self):
        for text in self.REAL:
            with self.subTest(formula=text):
                verdict, why = ch.plausible(text)
                self.assertIsNot(verdict, False, "%s rejected: %s" % (text, why))

    def test_polyatomic_compounds_are_unchecked_not_approved(self):
        """None, not True. Reporting 'fine' for something never examined is
        how a check gets believed about a case it never looked at."""
        for text in ("KMnO4", "H2SO4", "CuSO4", "Ca(OH)2", "NaHCO3",
                     "K2Cr2O7", "CaCO3"):
            with self.subTest(formula=text):
                verdict, why = ch.plausible(text)
                self.assertIsNone(verdict)
                self.assertIn("binary", why)

    def test_an_ion_written_bare_is_unchecked_not_condemned(self):
        """CO3 is not a molecule; carbonate is an ion. Without charge the
        check cannot distinguish them, so it declines to."""
        self.assertIsNone(ch.plausible("CO3")[0])

    def test_covalent_binaries_are_unchecked_not_approved(self):
        """Propane is real and does not obey ionic valency arithmetic."""
        for text in ("C3H8", "NO", "CO2", "SO2", "H2O"):
            with self.subTest(formula=text):
                verdict, why = ch.plausible(text)
                self.assertIsNone(verdict)
                self.assertIn("covalent", why)

    def test_a_bare_element_is_unchecked(self):
        for text in ("Fe", "O2", "H2", "Cl2"):
            self.assertIsNone(ch.plausible(text)[0])


class ItRejectsWhatCannotExist(unittest.TestCase):
    # CO3 is deliberately absent. As a neutral molecule it does not exist,
    # but carbonate (CO3 2-) certainly does, and without charge the check
    # cannot tell them apart -- so it reports unchecked rather than guessing.
    IMPOSSIBLE = ("FeCl9", "NaCl2", "CaCl3", "AlO", "MgCl3", "KO2", "CuCl5")

    def test_impossible_binary_compounds(self):
        for text in self.IMPOSSIBLE:
            with self.subTest(formula=text):
                self.assertIs(ch.plausible(text)[0], False)

    def test_the_reason_names_the_valency_it_would_need(self):
        verdict, why = ch.plausible("FeCl9")
        self.assertIs(verdict, False)
        self.assertIn("9", why)
        self.assertIn("2 or 3", why)

    def test_a_fractional_valency_is_refused(self):
        verdict, why = ch.plausible("Ca3Cl5")
        self.assertIs(verdict, False)
        self.assertIn("whole number", why)


class BalancingRefusesImpossibleChemistry(unittest.TestCase):
    def test_the_equation_that_prompted_this(self):
        with self.assertRaises(ch.ChemError) as caught:
            ch.balance("Fe + HCl -> FeCl9 + H2")
        self.assertIn("cannot exist", str(caught.exception))
        self.assertIn("FeCl9", str(caught.exception))

    def test_the_correct_version_still_balances(self):
        self.assertEqual(ch.balance("Fe + HCl -> FeCl3 + H2"),
                         "2Fe + 6HCl -> 2FeCl3 + 3H2")

    def test_polyatomic_equations_are_unaffected(self):
        self.assertEqual(
            ch.balance("KMnO4 + HCl -> KCl + MnCl2 + H2O + Cl2"),
            "2KMnO4 + 16HCl -> 2KCl + 2MnCl2 + 8H2O + 5Cl2")

    def test_the_check_can_be_turned_off_for_arithmetic_only(self):
        """Sometimes you do want the arithmetic on a hypothetical."""
        self.assertEqual(ch.balance("Fe + HCl -> FeCl9 + H2",
                                    check_valency=False),
                         "2Fe + 18HCl -> 2FeCl9 + 9H2")

    def test_implausible_species_lists_every_offender(self):
        bad = ch.implausible_species("NaCl2 + CaCl3 -> NaCl + CaCl2")
        self.assertEqual({name for name, _ in bad}, {"NaCl2", "CaCl3"})


if __name__ == "__main__":
    unittest.main()
