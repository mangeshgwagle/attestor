#!/usr/bin/env python3
"""Tests for nativemetrics.py -- C/C++/Assembly complexity. Offline, pinned numbers."""
import time
import unittest

import nativemetrics as nm


def one(src, lang="c"):
    ms = nm.analyze_text(src, "t." + ("c" if lang == "c" else lang), lang)
    assert len(ms) == 1, "expected one function, got %d" % len(ms)
    return ms[0]


class CTests(unittest.TestCase):
    def test_flat_function(self):
        m = one("void f(void) {\n    return;\n}\n")
        self.assertEqual(m.cyclomatic, 1)
        self.assertEqual(m.cognitive, 0)
        self.assertEqual(m.nesting, 0)

    def test_single_if(self):
        m = one("int f(int x) {\n    if (x) {\n        return 1;\n    }\n    return 0;\n}\n")
        self.assertEqual(m.cyclomatic, 2)
        self.assertEqual(m.cognitive, 1)
        self.assertEqual(m.nesting, 1)

    def test_nested_costs_more_than_flat(self):
        nested = one("int f(int x) {\n    if (x) {\n        if (x) {\n            return 1;\n        }\n    }\n    return 0;\n}\n")
        flat = one("int f(int x) {\n    if (x) {\n        return 1;\n    }\n    if (x) {\n        return 2;\n    }\n    return 0;\n}\n")
        self.assertEqual(nested.cyclomatic, flat.cyclomatic)   # cyclomatic: both 3
        self.assertLess(flat.cognitive, nested.cognitive)      # cognitive: 2 < 3
        self.assertEqual(flat.cognitive, 2)
        self.assertEqual(nested.cognitive, 3)

    def test_boolean_and_ternary_count(self):
        m = one("int f(int a, int b) {\n    return a && b ? 1 : 0;\n}\n")
        # 1 + && + ternary = 3 cyclomatic; && = 1 cognitive
        self.assertEqual(m.cyclomatic, 3)
        self.assertEqual(m.cognitive, 1)

    def test_loop_and_case(self):
        src = ("int f(int x) {\n    switch (x) {\n    case 1:\n        return 1;\n"
               "    case 2:\n        return 2;\n    }\n    return 0;\n}\n")
        # 1 + two cases = 3 cyclomatic
        self.assertEqual(one(src).cyclomatic, 3)

    def test_two_functions_are_separated(self):
        src = "int a(void) {\n    return 1;\n}\nint b(int x) {\n    if (x) return 1;\n    return 0;\n}\n"
        got = {m.name: m for m in nm.analyze_text(src, "t.c", "c")}
        self.assertIn("a", got)
        self.assertIn("b", got)
        self.assertEqual(got["a"].cyclomatic, 1)
        self.assertEqual(got["b"].cyclomatic, 2)

    def test_keywords_in_strings_are_ignored(self):
        # 'if' and '&&' live in a string literal -> blanked, not counted
        m = one('int f(void) {\n    const char *s = "if a && b for while";\n    return 0;\n}\n')
        self.assertEqual(m.cyclomatic, 1)
        self.assertEqual(m.cognitive, 0)


class HeaderRegexTests(unittest.TestCase):
    """The header pattern must stay linear: it runs on untrusted sources."""

    def test_hostile_header_does_not_backtrack(self):
        # Every "-> a " run used to be splittable between the trailing-return
        # character class and the standalone '\s' branch, so this header cost
        # O(2**n).  At 24 repeats it took ~19s; 40 repeats never finished.
        src = "void f() " + "-> a " * 40 + "=\n{\n    return;\n}\n"
        started = time.perf_counter()
        nm.analyze_text(src, "t.c", "c")
        self.assertLess(time.perf_counter() - started, 5.0,
                        "function-header matching is backtracking")

    def test_hostile_header_is_still_rejected_as_a_function(self):
        src = "void f() " + "-> a " * 40 + "=\n{\n    return;\n}\n"
        self.assertEqual(nm.analyze_text(src, "t.c", "c"), [])

    def test_trailing_return_and_qualifiers_still_name_the_function(self):
        for header in ("auto make(int x) -> std::vector<int>",
                       "auto make(int x) -> const T&",
                       "void run() const",
                       "void run() noexcept override",
                       "auto run() noexcept -> bool",
                       "auto run() -> a -> b"):
            with self.subTest(header=header):
                metrics = nm.analyze_text(
                    header + " {\n    return;\n}\n", "t.cpp", "cpp")
                self.assertEqual([m.name for m in metrics],
                                 [header.split("(")[0].split()[-1]])

    def test_control_keywords_are_not_reported_as_functions(self):
        for header in ("if (x)", "while (x)", "for (int i = 0; i < 2; i++)",
                       "switch (x)"):
            with self.subTest(header=header):
                self.assertEqual(
                    nm.analyze_text("void f(void) {\n" + header
                                    + " {\n        g();\n    }\n}\n",
                                    "t.c", "c")[0].name, "f")


class AsmTests(unittest.TestCase):
    def test_labels_and_branches(self):
        src = ("main:\n    mov eax, 1\n    cmp eax, 0\n    je done\n    jne loop\ndone:\n    ret\n")
        got = {m.name: m for m in nm.analyze_text(src, "t.s", "asm")}
        self.assertIn("main", got)
        self.assertIn("done", got)
        self.assertEqual(got["main"].cyclomatic, 3)   # 1 + je + jne
        self.assertEqual(got["done"].cyclomatic, 1)   # just ret


class ReportTests(unittest.TestCase):
    def test_language_for(self):
        self.assertEqual(nm.language_for("x.cpp"), "cpp")
        self.assertEqual(nm.language_for("x.S"), "asm")
        self.assertEqual(nm.language_for("x.py"), "")

    def test_exceeded_reports_the_blown_limit(self):
        m = nm.FuncMetric("t.c", "f", 1, "c", cyclomatic=20, cognitive=1, length=5, nesting=1)
        self.assertIn("cyclomatic", m.exceeded(nm.DEFAULT_LIMITS))
        self.assertNotIn("cognitive", m.exceeded(nm.DEFAULT_LIMITS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
