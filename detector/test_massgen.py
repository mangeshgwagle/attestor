#!/usr/bin/env python3
"""Tests for massgen.py -- the deterministic code factory. Offline."""
import unittest

import massgen


class FactoryTests(unittest.TestCase):
    def test_generates_and_verifies_clean(self):
        totals = massgen.factory(services=1, resources=1, jobs=1)
        self.assertEqual(totals["services"], 1)
        self.assertGreater(totals["py_files"], 0)
        self.assertGreater(totals["lines"], 0)
        self.assertEqual(totals["defects"], [])              # generated code verifies clean
        self.assertEqual(totals["clean"], totals["py_files"])   # every file grade A

    def test_scales_linearly(self):
        one = massgen.factory(services=1, resources=1, jobs=1)
        two = massgen.factory(services=2, resources=1, jobs=1)
        self.assertEqual(two["py_files"], 2 * one["py_files"])   # deterministic

    def test_render_reports_all_clean(self):
        totals = massgen.factory(services=1, resources=1, jobs=1)
        out = massgen.render(totals)
        self.assertIn("ALL CLEAN", out)
        self.assertIn("lines of code", out)

    def test_parallel_matches_serial(self):
        serial = massgen.factory(services=2, resources=1, jobs=1)
        parallel = massgen.factory(services=2, resources=1, jobs=2)
        self.assertEqual(serial["py_files"], parallel["py_files"])
        self.assertEqual(serial["lines"], parallel["lines"])
        self.assertEqual(parallel["defects"], [])

    def test_rejects_nonsensical_sizes(self):
        with self.assertRaises(ValueError):
            massgen.factory(services=-1, resources=1, jobs=1)
        with self.assertRaises(ValueError):
            massgen.factory(services=1, resources=0, jobs=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
