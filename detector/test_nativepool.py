#!/usr/bin/env python3
"""Tests for nativepool.py -- the shared parallel map. Offline."""
import unittest

import nativepool


def _square(n):                 # top-level so the process pool can pickle it
    return n * n


class PoolTests(unittest.TestCase):
    def test_serial_and_parallel_agree(self):
        items = list(range(20))
        serial = nativepool.pmap(_square, items, jobs=1)
        parallel = nativepool.pmap(_square, items, jobs=4)
        expected = [n * n for n in items]
        self.assertEqual(serial, expected)
        self.assertEqual(parallel, expected)          # same values, same order

    def test_resolve(self):
        self.assertEqual(nativepool.resolve(3), 3)
        self.assertEqual(nativepool.resolve(0), nativepool.default_jobs())
        self.assertGreaterEqual(nativepool.resolve(None), 1)

    def test_empty_and_single(self):
        self.assertEqual(nativepool.pmap(_square, [], jobs=4), [])
        self.assertEqual(nativepool.pmap(_square, [5], jobs=4), [25])


if __name__ == "__main__":
    unittest.main(verbosity=2)
