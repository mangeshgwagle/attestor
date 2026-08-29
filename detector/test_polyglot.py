#!/usr/bin/env python3
"""Tests for polyglot.py -- C/C++/Haskell/Assembly tiny-bug scanner."""
import os
import tempfile
import unittest

import polyglot


class PolyglotTests(unittest.TestCase):
    def _write(self, root, rel, text):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _rules(self, report):
        return {finding.rule for finding in report["findings"]}

    def test_c_tiny_bugs(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bug.c", "\n".join([
                "void f(char *s) {",
                "  if (s);",
                "  char *p = malloc(sizeof(p));",
                "  p = realloc(p, 32);",
                "  scanf(\"%s\", s);",
                "}",
            ]))
            rules = self._rules(polyglot.scan([d]))
        self.assertIn("polyglot-empty-control-body", rules)
        self.assertIn("polyglot-malloc-sizeof-pointer", rules)
        self.assertIn("polyglot-direct-realloc", rules)
        self.assertIn("polyglot-unbounded-scanf-string", rules)

    def test_cpp_tiny_bugs(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bug.cpp", "\n".join([
                "#include <mutex>",
                "void f(std::mutex& m) { std::lock_guard<std::mutex>(m); }",
                "char const* g() { std::string s = \"x\"; return s.c_str(); }",
                "void h() { int *p = new int[4]; delete p; }",
            ]))
            rules = self._rules(polyglot.scan([d]))
        self.assertIn("polyglot-temporary-lock-guard", rules)
        self.assertIn("polyglot-return-local-cstr", rules)
        self.assertIn("polyglot-delete-array-with-delete", rules)

    def test_haskell_tiny_bugs(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "Bug.hs", "\n".join([
                "module Bug where",
                "x xs = head xs",
                "sumBad xs = foldl (+) 0 xs",
                "empty xs = length xs == 0",
                "boom = undefined",
            ]))
            rules = self._rules(polyglot.scan([d]))
        self.assertIn("polyglot-hs-partial-function", rules)
        self.assertIn("polyglot-hs-lazy-foldl", rules)
        self.assertIn("polyglot-hs-length-emptiness", rules)
        self.assertIn("polyglot-hs-bottom-value", rules)

    def test_assembly_tiny_bugs(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bug.asm", "\n".join([
                "main:",
                "  push rbx",
                "  mov eax, 10",
                "  div ecx",
                "  rep movsb",
                "  ret",
            ]))
            rules = self._rules(polyglot.scan([d]))
        self.assertIn("polyglot-asm-division-high-half", rules)
        self.assertIn("polyglot-asm-direction-flag", rules)
        self.assertIn("polyglot-asm-stack-imbalance", rules)

    def test_render_mentions_languages(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "bug.hs", "x xs = head xs\n")
            text = polyglot.render(polyglot.scan([d]))
        self.assertIn("Polyglot tiny-error report", text)
        self.assertIn("language: haskell", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
