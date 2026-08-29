"""Every stated reaction is balanced by the conservation check, not by me.

The equations in `preparations` are the load-bearing part of an answer, and
a wrong coefficient is invisible on rereading because it still looks like
chemistry. Running each one through `attestor_chem.conserves` turns them from
remembered arithmetic into checked arithmetic.
"""
from __future__ import annotations

import unittest

import attestor_chem
import preparations as P


class EveryEquationBalances(unittest.TestCase):
    def test_all_of_them(self):
        for key, prep in P.PREPARATIONS.items():
            with self.subTest(preparation=key):
                self.assertTrue(P.check_reactions(prep))

    def test_the_check_can_fail(self):
        """A check that cannot fail proves nothing.

        Borax gives four molecules of boric acid, not three. If this passes,
        the suite above is decoration.
        """
        broken = P.Preparation(
            key="broken", name="x", formula="x", category="x", principle="x",
            reactions=("Na2B4O7 + 2HCl + 5H2O -> 3H3BO3 + 2NaCl",),
            procedure=())
        with self.assertRaises(P.ReactionError):
            P.check_reactions(broken)

    def test_a_single_wrong_coefficient_is_caught(self):
        """The realistic error: right species, one number off."""
        broken = P.Preparation(
            key="broken", name="x", formula="x", category="x", principle="x",
            reactions=("Al2(SO4)3 + 5NaOH -> 2Al(OH)3 + 3Na2SO4",),
            procedure=())
        with self.assertRaises(P.ReactionError):
            P.check_reactions(broken)

    def test_split_equation_separates_coefficients_from_species(self):
        coefficients, reactants, products = P.split_equation(
            "2MnO2 + 4KOH + O2 -> 2K2MnO4 + 2H2O")
        self.assertEqual(coefficients, [2, 4, 1, 2, 2])
        self.assertEqual(reactants, ["MnO2", "KOH", "O2"])
        self.assertEqual(products, ["K2MnO4", "H2O"])

    def test_an_equation_with_no_arrow_is_refused(self):
        with self.assertRaises(P.ReactionError):
            P.split_equation("NaCl + AgNO3")


class EveryPreparationIsAnswerShaped(unittest.TestCase):
    """The marked structure: principle, reaction, procedure, tests, uses."""

    def test_the_required_sections_are_present(self):
        for key, prep in P.PREPARATIONS.items():
            with self.subTest(preparation=key):
                self.assertTrue(prep.principle.strip())
                self.assertTrue(prep.reactions)
                self.assertGreaterEqual(len(prep.procedure), 3)
                self.assertTrue(prep.identification)
                self.assertTrue(prep.assay.strip())
                self.assertTrue(prep.uses)
                self.assertTrue(prep.storage.strip())

    def test_every_procedure_step_says_why(self):
        for key, prep in P.PREPARATIONS.items():
            for index, (step, why) in enumerate(prep.procedure, start=1):
                with self.subTest(preparation=key, step=index):
                    self.assertTrue(step.strip())
                    self.assertGreater(
                        len(why), 30,
                        "step %d of %s has a token reason" % (index, key))

    def test_every_formula_parses_as_chemistry(self):
        """The stated formula must be something the chemistry module can
        read -- a typo here would go unnoticed in prose."""
        for key, prep in P.PREPARATIONS.items():
            with self.subTest(preparation=key):
                composition = attestor_chem.formula(prep.formula)
                self.assertTrue(composition)
                self.assertGreater(attestor_chem.molar_mass(prep.formula), 0)

    def test_the_product_appears_in_its_own_reaction(self):
        """A preparation whose equations never produce the substance is
        describing something else."""
        skip = {"bleaching_powder"}   # CaOCl2 is a mixed salt, written loosely
        for key, prep in P.PREPARATIONS.items():
            if key in skip:
                continue
            with self.subTest(preparation=key):
                base = prep.formula.split(".")[0]     # ignore hydration
                joined = " ".join(prep.reactions)
                self.assertIn(base, joined,
                              "%s never appears in its own reactions" % base)

    def test_the_keys_are_unique(self):
        self.assertEqual(len(P.PREPARATIONS), len(P._PREPARATIONS))


class TheChemistryIsRight(unittest.TestCase):
    """Specific facts a marker checks, pinned so an edit cannot lose them."""

    def test_boric_acid_gives_four_molecules_from_borax(self):
        coefficients, reactants, products = P.split_equation(
            P.PREPARATIONS["boric_acid"].reactions[0])
        self.assertEqual(products, ["H3BO3", "NaCl"])
        self.assertEqual(coefficients[len(reactants)], 4)

    def test_ferrous_sulphate_answer_covers_oxidation(self):
        """Fe(II) -> Fe(III) is the whole difficulty; an answer that omits
        it has missed why the method looks the way it does."""
        text = P.show("ferrous_sulphate").lower()
        self.assertIn("oxidis", text)
        self.assertIn("excess iron", text)
        self.assertIn("well-filled", text)

    def test_aluminium_hydroxide_mentions_amphoteric_ph_control(self):
        text = P.show("aluminium_hydroxide_gel").lower()
        self.assertIn("amphoteric", text)
        self.assertIn("excess alkali", text)

    def test_barium_sulphate_keeps_sulphate_in_excess(self):
        """Excess barium in a radiographic medium is a poisoning risk. The
        direction of addition is the safety-critical part."""
        text = P.show("barium_sulphate").lower()
        self.assertIn("excess sulphate, never excess barium", text)
        self.assertIn("soluble barium", text)

    def test_permanganate_records_the_organic_incompatibility(self):
        text = P.show("potassium_permanganate").lower()
        self.assertIn("organic", text)

    def test_potassium_iodide_reduces_the_iodate(self):
        """Without the charcoal reduction the yield is five sixths and the
        product carries iodate."""
        prep = P.PREPARATIONS["potassium_iodide"]
        self.assertEqual(len(prep.reactions), 2)
        self.assertIn("KIO3", prep.reactions[1])
        self.assertIn("iodate", P.show("potassium_iodide").lower())

    def test_boric_acid_assay_needs_a_polyol(self):
        """Boric acid is too weak to titrate directly -- mannitol or
        glycerol is the standard trick and is examinable."""
        assay = P.PREPARATIONS["boric_acid"].assay.lower()
        self.assertTrue("mannitol" in assay or "glycerol" in assay)
        self.assertIn("too weak", assay)

    def test_hydrogen_peroxide_explains_volume_strength(self):
        self.assertIn("volume", P.show("hydrogen_peroxide").lower())

    def test_hydrates_are_recognised_as_hydrates(self):
        """FeSO4.7H2O must weigh more than FeSO4, or the parser is dropping
        the water and every calculation from it would be wrong."""
        anhydrous = attestor_chem.molar_mass("FeSO4")
        hydrated = attestor_chem.molar_mass("FeSO4.7H2O")
        self.assertGreater(hydrated, anhydrous)
        self.assertAlmostEqual(hydrated - anhydrous,
                               7 * attestor_chem.molar_mass("H2O"), delta=0.01)


class Lookup(unittest.TestCase):
    def test_find_matches_name_formula_category_and_use(self):
        self.assertTrue(P.find("boric"))
        self.assertTrue(P.find("KMnO4"))
        self.assertTrue(P.find("antacid"))
        self.assertTrue(P.find("antidote"))

    def test_show_lays_out_the_marked_sections(self):
        text = P.show("ferrous_sulphate")
        for heading in ("PRINCIPLE", "REACTION", "PROCEDURE", "PURIFICATION",
                        "IDENTIFICATION", "LIMIT TESTS", "ASSAY", "USES",
                        "STORAGE"):
            self.assertIn(heading, text)

    def test_show_accepts_an_unambiguous_partial_name(self):
        self.assertIn("Epsom", P.show("epsom"))

    def test_an_unknown_name_says_so(self):
        with self.assertRaises(KeyError):
            P.show("not_a_substance")

    def test_the_categories_are_real(self):
        self.assertGreaterEqual(len(P.categories()), 6)


if __name__ == "__main__":
    unittest.main()
