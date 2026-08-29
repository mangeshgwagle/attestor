#!/usr/bin/env python3
"""Tests for nl.py -- the honest natural-language front-end. Offline/deterministic."""
import unittest

import codegen
import nl


class ParseTests(unittest.TestCase):
    def test_scaffold_intent_and_fields(self):
        r = nl.interpret("make a rest api for Book with fields title, author, year (int)")
        self.assertEqual(r["intent"], "scaffold")
        res = r["spec"]["resources"][0]
        self.assertEqual(res["name"], "Book")
        self.assertEqual(res["fields"],
                         {"title": "str", "author": "str", "year": "int"})

    def test_field_type_forms(self):
        fields = nl.parse_fields("total (float), paid (bool), qty: int, note")
        self.assertEqual(fields, {"total": "float", "paid": "bool",
                                  "qty": "int", "note": "str"})

    def test_scaffold_spec_is_valid_for_codegen(self):
        r = nl.interpret("create a service for Order with fields amount (float)")
        files = codegen.generate(r["spec"])
        self.assertIn("models/order.py", files)
        compile(files["models/order.py"], "order.py", "exec")

    def test_snippet_intent(self):
        r = nl.interpret("write fibonacci")
        self.assertEqual(r["intent"], "snippet")
        self.assertIn("def fib", r["code"])

    def test_snippet_needs_all_keywords(self):
        # "reverse a string" matches; "reverse a linked list" must NOT (no snippet)
        self.assertEqual(nl.interpret("reverse a string")["intent"], "snippet")
        self.assertEqual(nl.interpret("reverse a linked list")["intent"], "unknown")

    def test_review_intent(self):
        r = nl.interpret("review codegen.py")
        self.assertEqual(r["intent"], "review")
        self.assertEqual(r["path"], "codegen.py")

    def test_unknown_is_honest(self):
        self.assertEqual(nl.interpret("implement a red-black tree")["intent"], "unknown")


class RunTests(unittest.TestCase):
    def test_run_scaffold_reports_resource(self):
        text = nl.run(nl.interpret("make an api for Widget with fields label, qty (int)"))
        self.assertIn("Widget", text)
        self.assertIn("lines", text)

    def test_run_unknown_refuses_without_faking(self):
        text = nl.run(nl.interpret("prove the Riemann hypothesis"))
        self.assertIn("won't fake it", text)

    def test_run_snippet_labels_as_retrieval(self):
        text = nl.run(nl.interpret("write gcd"))
        self.assertIn("recognition, not reasoning", text)
        self.assertIn("def gcd", text)

    def test_expanded_snippet_library(self):
        cases = {
            "solve two sum": "def two_sum",
            "merge sorted lists": "def merge_sorted_lists",
            "valid parentheses": "def valid_parentheses",
            "implement an lru cache": "class LRUCache",
            "write a trie": "class Trie",
            "write dijkstra": "def dijkstra",
            "topological sort": "def topological_sort",
            "memoize decorator": "def memoize",
            "slugify text": "def slugify",
        }
        for request, needle in cases.items():
            with self.subTest(request=request):
                result = nl.interpret(request)
                self.assertEqual(result["intent"], "snippet")
                self.assertIn(needle, result["code"])


class _FakeBrain:
    def available(self):
        return True

    def generate(self, prompt):
        return "def solved():\n    return 42"


class BrainRoutingTests(unittest.TestCase):
    def test_unknown_request_uses_the_brain_when_present(self):
        out = nl.run({"intent": "unknown"}, brain=_FakeBrain(), request="do a novel thing")
        self.assertIn("def solved", out)

    def test_known_request_ignores_the_brain(self):
        # a recognized intent is still handled locally, not sent to the LLM
        r = nl.interpret("make an api for Thing with fields a, b (int)")
        out = nl.run(r, brain=_FakeBrain(), request="...")
        self.assertIn("scaffold a service for Thing", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
