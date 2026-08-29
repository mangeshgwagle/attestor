#!/usr/bin/env python3
"""Tests for clones.py -- copy-paste duplication detection. Offline."""
import os
import tempfile
import unittest

import clones


BLOCK = ("    total = 0\n    for x in seq:\n        if x > 0:\n"
         "            total += x\n        else:\n            total -= x\n    return total\n")


def _tmp(src):
    fd, path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as fh:
        fh.write(src)
    return path


class CloneTests(unittest.TestCase):
    def test_detects_a_duplicated_block(self):
        src = "def a(seq):\n" + BLOCK + "\ndef b(seq):\n" + BLOCK
        path = _tmp(src)
        found = clones.find_clones([path], min_lines=5)
        os.remove(path)
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(found[0].lines, 5)

    def test_distinct_code_has_no_clones(self):
        src = ("def a():\n    return 1\n\ndef b():\n    x = 2\n    y = 3\n    return x + y\n")
        path = _tmp(src)
        self.assertEqual(clones.find_clones([path], min_lines=4), [])
        os.remove(path)

    def test_min_lines_threshold(self):
        src = "def a(seq):\n" + BLOCK + "\ndef b(seq):\n" + BLOCK
        path = _tmp(src)
        # BLOCK normalizes to 7 code lines; a threshold above that finds nothing
        self.assertEqual(clones.find_clones([path], min_lines=20), [])
        os.remove(path)

    def test_cross_file_duplication(self):
        a = _tmp("def a(seq):\n" + BLOCK)
        b = _tmp("def b(seq):\n" + BLOCK)
        found = clones.find_clones([a, b], min_lines=5)
        os.remove(a)
        os.remove(b)
        self.assertEqual(len(found), 1)
        files = {block[0] for block in found[0].blocks}
        self.assertEqual(files, {a, b})            # the two blocks live in different files

    def test_render_and_empty(self):
        self.assertIn("clean", clones.render([]))
        clone = clones.Clone(6, [("a.py", 1, 6), ("b.py", 10, 15)])
        self.assertIn("6 lines", clones.render([clone]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
