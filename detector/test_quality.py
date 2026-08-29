#!/usr/bin/env python3
"""Tests for quality.py -- request-aware behavior smoke tests."""
import unittest

import crucible
import quality


def _verdict(request, code):
    label, snippet = quality.behavior_check(request)
    if not snippet:
        raise AssertionError("request did not produce a behavior check: " + request)
    return crucible.verify(code, snippet=snippet)


class QualityTests(unittest.TestCase):
    def test_unknown_request_has_no_behavior_gate(self):
        self.assertEqual(quality.behavior_check("build a tiny web server"), ("", ""))
        self.assertEqual(quality.prompt_addendum("build a tiny web server"), "")

    def test_prompt_addendum_contains_smoke_test(self):
        text = quality.prompt_addendum("write fibonacci")
        self.assertIn("behavioral smoke test", text)
        self.assertIn("assert fn(10) == 55", text)

    def test_common_algorithm_implementations_pass(self):
        cases = [
            ("write fibonacci", "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n"),
            ("write fizzbuzz", "def fizzbuzz(n):\n    return ['FizzBuzz' if i % 15 == 0 else 'Fizz' if i % 3 == 0 else 'Buzz' if i % 5 == 0 else i for i in range(1, n + 1)]\n"),
            ("solve two sum", "def two_sum(nums, target):\n    seen = {}\n    for i, value in enumerate(nums):\n        if target - value in seen:\n            return [seen[target - value], i]\n        seen[value] = i\n"),
            ("valid parentheses", "def valid_parentheses(s):\n    pairs = {')': '(', ']': '[', '}': '{'}\n    stack = []\n    for ch in s:\n        if ch in pairs.values():\n            stack.append(ch)\n        elif ch in pairs and (not stack or stack.pop() != pairs[ch]):\n            return False\n    return not stack\n"),
            ("slugify text", "import re\n\ndef slugify(text):\n    text = text.lower().strip()\n    text = re.sub(r'[^a-z0-9]+', '-', text)\n    return text.strip('-')\n"),
        ]
        for request, code in cases:
            with self.subTest(request=request):
                self.assertTrue(_verdict(request, code), request)

    def test_common_data_structures_pass(self):
        lru = """
class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self.items = {}
        self.order = []
    def get(self, key):
        if key not in self.items:
            return -1
        self.order.remove(key)
        self.order.append(key)
        return self.items[key]
    def put(self, key, value):
        if key in self.items:
            self.order.remove(key)
        elif len(self.order) >= self.capacity:
            old = self.order.pop(0)
            del self.items[old]
        self.items[key] = value
        self.order.append(key)
"""
        trie = """
class Trie:
    def __init__(self):
        self.root = {}
        self.end = '#'
    def insert(self, word):
        node = self.root
        for ch in word:
            node = node.setdefault(ch, {})
        node[self.end] = True
    def search(self, word):
        node = self.root
        for ch in word:
            if ch not in node:
                return False
            node = node[ch]
        return self.end in node
    def starts_with(self, prefix):
        node = self.root
        for ch in prefix:
            if ch not in node:
                return False
            node = node[ch]
        return True
"""
        self.assertTrue(_verdict("implement an LRU cache", lru))
        self.assertTrue(_verdict("write a trie", trie))

    def test_wrong_behavior_fails(self):
        bad_cases = [
            ("merge sorted lists", "def merge(a, b):\n    return a + b\n"),
            ("flatten nested list", "def flatten(xs):\n    return [x for x in xs]\n"),
            ("write fibonacci", "def fib(n):\n    return n\n"),
        ]
        for request, code in bad_cases:
            with self.subTest(request=request):
                self.assertFalse(_verdict(request, code), request)


if __name__ == "__main__":
    unittest.main(verbosity=2)
