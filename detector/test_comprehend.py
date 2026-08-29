#!/usr/bin/env python3
"""Tests for comprehend.py -- the multi-pass reader. Offline/deterministic."""
import unittest

import comprehend

MESSY = '''\
"""A module with problems."""
import os
import hashlib


def handle(uid, cache={}):
    if uid == None:
        return None
    token = hashlib.md5(str(uid).encode()).hexdigest()
    return finalize(token)


def finalize(t):
    return reslt
'''

CLEAN = '''\
"""A tidy module."""


def add(a, b):
    """Sum two numbers."""
    return a + b
'''


class ComprehendTests(unittest.TestCase):
    def test_multiple_passes(self):
        report = comprehend.comprehend(MESSY, "messy.py")
        # a real multi-pass read: skim, parse, deps, defs, complexity, docs,
        # call graph, two scans, improvements
        self.assertGreaterEqual(len(report["passes"]), 8)

    def test_forms_a_structural_picture(self):
        report = comprehend.comprehend(MESSY, "messy.py")
        self.assertIn("how messy.py works", report["image"])
        self.assertIn("call graph", report["image"])
        self.assertIn("handle -> finalize", report["image"])

    def test_finds_issues_including_ast_only(self):
        report = comprehend.comprehend(MESSY, "messy.py")
        rules = {f.rule for f in report["findings"]}
        self.assertIn("undefined-name", rules)     # only the AST engine sees 'reslt'
        self.assertIn("py-mutable-default", rules)

    def test_applies_safe_fixes(self):
        report = comprehend.comprehend(MESSY, "messy.py")
        notes = " ".join(note for _, _, note in report["applied"])
        self.assertIn("is None", notes)
        self.assertIn("sha256", notes)
        self.assertIn("is None", report["improved"])
        self.assertIn("sha256", report["improved"])

    def test_clean_file_needs_no_work(self):
        report = comprehend.comprehend(CLEAN, "clean.py")
        self.assertEqual(report["findings"], [])

    def test_render_is_honest_about_limits(self):
        text = comprehend.render(comprehend.comprehend(MESSY, "messy.py"))
        self.assertIn("STRUCTURAL read", text)
        self.assertIn("not understanding of intent", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
