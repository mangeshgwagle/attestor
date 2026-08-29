#!/usr/bin/env python3
"""Tests for the three tiers.

The thing worth testing is not that three objects exist. It is that the
ordering they claim is real: each tier must actually carry more than the one
below it, and a catalogue a tier names must actually run. Both of those were
false in the first two drafts, and neither failure raised anything -- the
tiers simply measured the same and looked fine.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import attestor_models as om

FLAWED = (
    "import subprocess\n"
    "import hashlib\n"
    "def deploy(tag):\n"
    "    subprocess.run('git push ' + tag, shell=True)\n"
    "    return hashlib.md5(tag.encode()).hexdigest()\n"
)


class TheOrderingIsReal(unittest.TestCase):
    def test_each_tier_carries_at_least_the_one_below(self):
        allegro, belladonna, cioccolata = (
            {r.rid for r in m.rules()} for m in om.MODELS)
        self.assertTrue(allegro < belladonna,
                        "Allegro must be a strict subset of Belladonna")
        self.assertTrue(belladonna <= cioccolata,
                        "Cioccolata must carry everything Belladonna does")

    def test_potency_is_strictly_increasing_in_rule_count(self):
        counts = [len(m.rules()) for m in om.MODELS]
        self.assertEqual(counts, sorted(counts))
        self.assertLess(counts[0], counts[-1],
                        "if the ends are equal the ordering is decoration")

    def test_only_cioccolata_runs_deep_rules(self):
        self.assertFalse(om.ALLEGRO.deep)
        self.assertFalse(om.BELLADONNA.deep)
        self.assertTrue(om.CIOCCOLATA.deep)

    def test_cioccolata_finds_at_least_what_belladonna_finds(self):
        # The regression that prompted this file: Cioccolata named four extra
        # catalogues, ran none of them, and scored identically to Belladonna
        # while presenting as the most powerful tier.
        belladonna = len(om.BELLADONNA.scan(FLAWED, "d.py", "python"))
        cioccolata = len(om.CIOCCOLATA.scan(FLAWED, "d.py", "python"))
        self.assertGreaterEqual(cioccolata, belladonna)


class CataloguesActuallyRun(unittest.TestCase):
    def test_every_named_catalogue_can_be_run(self):
        """A catalogue that is named must execute or raise, never no-op.

        Both earlier versions returned an empty list when they could not
        find an entry point, so a tier could lose a whole catalogue and
        still look like it had run it.
        """
        for name in om.EXTRA_CATALOGUES:
            with self.subTest(catalogue=name):
                try:
                    om._run_catalogue(name, FLAWED, "d.py", "python")
                except om.ModelError as error:
                    self.fail("%s is named but cannot run: %s" % (name, error))

    def test_an_unrunnable_catalogue_raises_rather_than_returning_nothing(self):
        with self.assertRaises(om.ModelError):
            om._run_catalogue("no_such_catalogue_module", FLAWED, "d.py", "python")

    def test_unwired_catalogues_are_declared_not_hidden(self):
        # Empty is the correct state. A name here is a gap being admitted.
        for name in om.UNWIRED_CATALOGUES:
            with self.subTest(catalogue=name):
                self.assertNotIn(name, om.EXTRA_CATALOGUES)


class WhatAllegroDrops(unittest.TestCase):
    def test_the_dropped_rules_are_the_measured_ones(self):
        self.assertEqual(om.ALLEGRO.drop, om.NOISY_ON_REAL_CODE)

    def test_every_dropped_rule_still_exists(self):
        import detect
        known = {r.rid for r in detect.RULES}
        for rid in om.NOISY_ON_REAL_CODE:
            with self.subTest(rule=rid):
                self.assertIn(rid, known,
                              "dropping a rule that no longer exists hides "
                              "that the exclusion list has gone stale")

    def test_allegro_is_quieter_than_belladonna_on_attestors_own_source(self):
        root = HERE.parent.parent / "detector"
        sample = [p for p in sorted(root.glob("*.py"))
                  if not p.name.startswith("test_")][:12]
        self.assertTrue(sample, "no production source found to measure against")
        counts = {}
        for model in (om.ALLEGRO, om.BELLADONNA):
            total = 0
            for path in sample:
                text = path.read_text(encoding="utf-8", errors="replace")
                total += len(model.scan(text, str(path), "python"))
            counts[model.name] = total
        self.assertLessEqual(counts["Attestor Allegro"], counts["Attestor Belladonna"])


class Lookup(unittest.TestCase):
    def test_models_resolve_by_short_and_full_name(self):
        self.assertIs(om.get("cioccolata"), om.CIOCCOLATA)
        self.assertIs(om.get("Attestor Allegro"), om.ALLEGRO)
        self.assertIs(om.get("  BELLADONNA "), om.BELLADONNA)

    def test_an_unknown_name_is_refused_with_the_alternatives(self):
        with self.assertRaises(om.ModelError) as caught:
            om.get("attestor espresso")
        self.assertIn("allegro", str(caught.exception))

    def test_inventory_reports_counts_rather_than_adjectives(self):
        for row in om.inventory():
            self.assertIsInstance(row["detector_rules"], int)
            self.assertGreater(row["detector_rules"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
