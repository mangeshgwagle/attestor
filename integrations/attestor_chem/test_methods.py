"""The methods are checked for order, not just for existing.

A prose description of a procedure is untestable, which is exactly why a
wrong one survives so comfortably. Declaring the prerequisites makes the
sequence a property that can fail: transpose two steps and this suite says
so, in the same way that reversing levigation and dilution would ruin the
preparation on the bench.
"""
from __future__ import annotations

import unittest

import methods


class EveryMethodIsInAWorkableOrder(unittest.TestCase):
    def test_the_prerequisites_are_satisfied(self):
        for key, method in methods.METHODS.items():
            with self.subTest(method=key):
                self.assertTrue(methods.check_order(method))

    def test_a_transposed_method_is_caught(self):
        """The check has to be able to fail, or it proves nothing.

        Suspension with the vehicle added before levigation -- the single
        most common way to ruin one -- must not pass.
        """
        good = methods.METHODS["suspension"]
        steps = list(good.steps)
        levigate = next(i for i, s in enumerate(steps) if s.tag == "levigated")
        vehicle = next(i for i, s in enumerate(steps) if s.tag == "vehicle_added")
        steps[levigate], steps[vehicle] = steps[vehicle], steps[levigate]
        broken = methods.Method(
            key=good.key, form=good.form, name=good.name,
            principle=good.principle, apparatus=good.apparatus,
            steps=tuple(steps))
        with self.assertRaises(methods.OrderError):
            methods.check_order(broken)

    def test_a_mistyped_prerequisite_cannot_hide(self):
        """A tag that no step produces must fail, not be ignored."""
        broken = methods.Method(
            key="x", form="x", name="x", principle="x", apparatus=(),
            steps=(methods.Step("do a thing", "because", ("nonexistent",)),))
        with self.assertRaises(methods.OrderError):
            methods.check_order(broken)


class EveryStepEarnsItsMarks(unittest.TestCase):
    def test_every_step_says_why(self):
        """The action alone is a description; the reason is the answer."""
        for key, method in methods.METHODS.items():
            for index, step in enumerate(method.steps, start=1):
                with self.subTest(method=key, step=index):
                    self.assertTrue(step.why.strip())
                    self.assertGreater(len(step.why), 30,
                                       "step %d of %s has a token reason"
                                       % (index, key))

    def test_every_method_has_a_principle_and_apparatus(self):
        for key, method in methods.METHODS.items():
            with self.subTest(method=key):
                self.assertTrue(method.principle.strip())
                self.assertTrue(method.apparatus)
                self.assertGreaterEqual(len(method.steps), 4)

    def test_the_keys_are_unique(self):
        self.assertEqual(len(methods.METHODS), len(methods._METHODS))


class TheContentIsRight(unittest.TestCase):
    """Facts a marker would check, asserted so a later edit cannot lose them."""

    def test_dry_gum_keeps_the_mortar_dry_before_the_gum_meets_oil(self):
        m = methods.METHODS["emulsion_dry_gum"]
        tags = [step.tag for step in m.steps if step.tag]
        self.assertLess(tags.index("dry_mortar"), tags.index("gum_in_oil"))
        self.assertLess(tags.index("gum_in_oil"), tags.index("water_added"))

    def test_the_three_oil_ratios_are_all_stated(self):
        """One ratio for every oil is the error; all three must be present."""
        text = methods.show("emulsion_dry_gum")
        for ratio in ("4:2:1", "3:2:1", "2:2:1"):
            self.assertIn(ratio, text)

    def test_wet_gum_is_the_reverse_of_dry_gum(self):
        wet = [s.tag for s in methods.METHODS["emulsion_wet_gum"].steps if s.tag]
        dry = [s.tag for s in methods.METHODS["emulsion_dry_gum"].steps if s.tag]
        self.assertEqual(wet[0], "mucilage")      # water first
        self.assertEqual(dry[1], "gum_in_oil")    # oil first
        self.assertLess(wet.index("mucilage"), wet.index("oil_added"))

    def test_fusion_takes_the_melt_off_the_heat_before_volatiles(self):
        m = methods.METHODS["ointment_fusion"]
        tags = [step.tag for step in m.steps if step.tag]
        self.assertLess(tags.index("off_heat"), tags.index("drug_added"))
        self.assertLess(tags.index("drug_added"), tags.index("stirred_cold"))

    def test_lubricant_goes_in_after_drying_and_before_compression(self):
        tags = [s.tag for s in methods.METHODS["tablet_wet_granulation"].steps
                if s.tag]
        self.assertLess(tags.index("dried"), tags.index("lubricated"))
        self.assertLess(tags.index("lubricated"), tags.index("compressed"))

    def test_geometric_dilution_starts_with_the_smallest_quantity(self):
        tags = [s.tag for s in methods.METHODS["powder_divided"].steps if s.tag]
        self.assertLess(tags.index("smallest_first"), tags.index("first_dilution"))

    def test_suppositories_calculate_displacement_before_anything_else(self):
        m = methods.METHODS["suppository_fusion"]
        self.assertEqual(m.steps[0].tag, "calculated")
        self.assertIn("displacement", m.steps[0].why.lower())

    def test_disperse_systems_carry_shake_well_and_solutions_do_not(self):
        """Putting 'Shake well' on a solution, or leaving it off a
        suspension, is a mark lost every time."""
        for key in ("suspension", "emulsion_dry_gum", "emulsion_wet_gum"):
            with self.subTest(method=key):
                self.assertIn("shake well", methods.show(key).lower())
        solution = methods.show("solution_simple").lower()
        self.assertIn("does not carry 'shake well'", solution)

    def test_solutions_are_made_to_volume_not_dissolved_in_it(self):
        text = methods.show("solution_simple").lower()
        self.assertIn("make up to", text)
        self.assertIn("never dissolve", text)


class Lookup(unittest.TestCase):
    def test_find_matches_form_and_name(self):
        self.assertTrue(methods.find("emulsion"))
        self.assertTrue(methods.find("suppositor"))
        # "dry gum" also matches the wet gum method, whose principle defines
        # itself against it -- that is useful, not a bug. What matters is
        # that the named method is among the matches.
        self.assertIn("emulsion_dry_gum",
                      [m.key for m in methods.find("dry gum")])

    def test_show_accepts_an_unambiguous_partial_name(self):
        self.assertIn("Displacement", methods.show("suppository"))

    def test_show_lays_out_principle_apparatus_method_and_errors(self):
        text = methods.show("suspension")
        for heading in ("PRINCIPLE", "APPARATUS", "METHOD",
                        "CRITICAL POINTS", "COMMON ERRORS"):
            self.assertIn(heading, text)
        self.assertIn("why:", text)

    def test_an_unknown_name_says_so(self):
        with self.assertRaises(KeyError):
            methods.show("not_a_dosage_form")

    def test_the_topics_cover_the_main_forms(self):
        forms = methods.topics()
        for expected in ("Solutions", "Suspensions", "Emulsions",
                         "Semisolids", "Suppositories", "Powders", "Tablets"):
            self.assertIn(expected, forms)


if __name__ == "__main__":
    unittest.main()
