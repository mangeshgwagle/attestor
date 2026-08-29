"""Chemistry Attestor can check rather than recite.

Every answer here is verifiable by counting, which is why chemistry suits
this project: a balanced equation is a claim about atoms, not a fact to be
looked up and hoped about.
"""
from __future__ import annotations

import unittest

import attestor_chem as ch


class Formulae(unittest.TestCase):
    def test_simple_and_bracketed(self):
        self.assertEqual(ch.formula("H2O"), {"H": 2, "O": 1})
        self.assertEqual(ch.formula("Ca(OH)2"), {"Ca": 1, "O": 2, "H": 2})
        self.assertEqual(ch.formula("Al2(SO4)3"), {"Al": 2, "S": 3, "O": 12})

    def test_nested_brackets(self):
        self.assertEqual(ch.formula("K4[Fe(CN)6]".replace("[", "(")
                                    .replace("]", ")")),
                         {"K": 4, "Fe": 1, "C": 6, "N": 6})

    def test_a_hydrate_is_not_a_full_stop(self):
        """`CuSO4·5H2O` -- most of the mole-concept questions are hydrates,
        and reading the dot as punctuation halves the mass of every one."""
        self.assertEqual(ch.formula("CuSO4.5H2O"),
                         {"Cu": 1, "S": 1, "O": 9, "H": 10})
        self.assertEqual(ch.formula("CuSO4·5H2O"), ch.formula("CuSO4.5H2O"))

    def test_two_letter_symbols_are_not_split(self):
        self.assertEqual(ch.formula("Co"), {"Co": 1})       # cobalt
        self.assertEqual(ch.formula("CO"), {"C": 1, "O": 1})  # carbon monoxide

    def test_masses_match_the_textbook(self):
        for text, expected in (("H2O", 18.02), ("H2SO4", 98.08),
                               ("NaCl", 58.44), ("CaCO3", 100.09),
                               ("CuSO4.5H2O", 249.68), ("KMnO4", 158.03)):
            with self.subTest(formula=text):
                self.assertAlmostEqual(ch.molar_mass(text), expected, delta=0.02)

    def test_a_malformed_formula_is_refused(self):
        for bad in ("", "   ", "H2(O", "H2O)", "Xx2", "H2$O"):
            with self.subTest(formula=bad), self.assertRaises(ch.ChemError):
                ch.formula(bad)


class Balancing(unittest.TestCase):
    KNOWN = (
        ("H2 + O2 -> H2O", "2H2 + O2 -> 2H2O"),
        ("Fe + O2 -> Fe2O3", "4Fe + 3O2 -> 2Fe2O3"),
        ("C3H8 + O2 -> CO2 + H2O", "C3H8 + 5O2 -> 3CO2 + 4H2O"),
        ("Ca(OH)2 + HCl -> CaCl2 + H2O", "Ca(OH)2 + 2HCl -> CaCl2 + 2H2O"),
        ("KMnO4 + HCl -> KCl + MnCl2 + H2O + Cl2",
         "2KMnO4 + 16HCl -> 2KCl + 2MnCl2 + 8H2O + 5Cl2"),
    )

    def test_known_equations(self):
        for equation, expected in self.KNOWN:
            with self.subTest(equation=equation):
                self.assertEqual(ch.balance(equation), expected)

    def test_the_result_actually_conserves_atoms(self):
        """The check is run against the answer, not assumed from the solver."""
        for equation, _ in self.KNOWN:
            with self.subTest(equation=equation):
                balanced = ch.balance(equation)
                left, right = balanced.split(" -> ")
                counts = []
                names = []
                for side in (left, right):
                    for part in side.split(" + "):
                        digits = ""
                        while part and part[0].isdigit():
                            digits += part[0]
                            part = part[1:]
                        counts.append(int(digits) if digits else 1)
                        names.append(part)
                split = len(left.split(" + "))
                self.assertTrue(ch.conserves(counts, names[:split],
                                             names[split:]))

    def test_an_impossible_equation_is_refused_not_guessed(self):
        with self.assertRaises(ch.ChemError) as caught:
            ch.balance("H2 + O2 -> NaCl")
        self.assertIn("cannot be balanced", str(caught.exception))

    def test_an_equation_with_no_arrow_is_refused(self):
        with self.assertRaises(ch.ChemError):
            ch.balance("H2 + O2 H2O")

    def test_alternative_arrows_are_accepted(self):
        self.assertEqual(ch.balance("H2 + O2 = H2O"), "2H2 + O2 -> 2H2O")


class TheConservationCheckIsThePoint(unittest.TestCase):
    def test_it_rejects_a_wrong_hand_written_equation(self):
        """Usable on an equation Attestor did not produce -- a student's, say."""
        self.assertFalse(ch.conserves([1, 1, 1], ["H2", "O2"], ["H2O"]))
        self.assertTrue(ch.conserves([2, 1, 2], ["H2", "O2"], ["H2O"]))

    def test_a_species_on_both_sides_is_counted_by_position(self):
        """Deciding the sign by membership counts it as a reactant twice.

        Water on both sides of an equation is extremely ordinary, and the
        membership version passed equations that do not balance.
        """
        # H2O + H2O -> H2O is only balanced with coefficients 1, 0, ... so
        # the honest answer for (1, 1, 1) is that it does not conserve.
        self.assertFalse(ch.conserves([1, 1, 1], ["H2O", "H2O"], ["H2O"]))
        self.assertTrue(ch.conserves([1, 1, 2], ["H2O", "H2O"], ["H2O"]))

    def test_balancing_is_arithmetic_not_chemistry(self):
        """It will balance a reaction that does not occur, and says so in
        the module docstring rather than implying otherwise."""
        self.assertEqual(ch.balance("N2 + O2 -> NO"), "N2 + O2 -> 2NO")


if __name__ == "__main__":
    unittest.main()
