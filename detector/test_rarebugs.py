#!/usr/bin/env python3
"""Tests for rarebugs.py -- Attestor's rare Python error oracle."""
import os
import tempfile
import unittest

import rarebugs


def _rules(source: str):
    return {item.rule for item in rarebugs.analyze(source, "sample.py")}


class RareBugTests(unittest.TestCase):
    def test_mutating_method_assignment_and_fromkeys(self):
        source = ("items = [3, 1]\n"
                  "items = items.sort()\n"
                  "table = dict.fromkeys(['a', 'b'], [])\n")
        rules = _rules(source)
        self.assertIn("rare-mutating-method-assigned", rules)
        self.assertIn("rare-dict-fromkeys-shared-mutable", rules)

    def test_custom_update_and_add_are_not_flagged(self):
        # 'update'/'add' are common custom method names that DO return a value;
        # only a provable container literal should be flagged (no false positives).
        self.assertNotIn("rare-mutating-method-assigned",
                         _rules("x = repo.update(row)\n"))
        self.assertNotIn("rare-mutating-method-assigned",
                         _rules("x = self._cache.add(item)\n"))
        self.assertIn("rare-mutating-method-assigned",
                      _rules("x = {}.update(other)\n"))          # literal: still caught

    def test_assigning_attribute_back_to_list_mutator_is_flagged(self):
        source = ("class Bag:\n"
                  "    def tidy(self):\n"
                  "        self.items = self.items.sort()\n")
        self.assertIn("rare-mutating-method-assigned", _rules(source))

    def test_non_mutating_method_assignment_is_clean(self):
        # a method that is not a known None-returner must never be flagged
        self.assertNotIn("rare-mutating-method-assigned",
                         _rules("x = repo.get(key)\n"))
        self.assertNotIn("rare-mutating-method-assigned",
                         _rules("row = db.fetch_one(sql)\n"))

    def test_context_manager_and_suppress_rules(self):
        source = ("from contextlib import suppress\n\n"
                  "class Guard:\n"
                  "    def __exit__(self, exc_type, exc, tb):\n"
                  "        return True\n\n"
                  "with suppress(Exception):\n"
                  "    work()\n")
        rules = _rules(source)
        self.assertIn("rare-exit-swallows-exception", rules)
        self.assertIn("rare-broad-contextlib-suppress", rules)

    def test_regex_dataclass_decimal_nan_and_async(self):
        source = ("import re, math, asyncio, requests\n"
                  "from dataclasses import field\n"
                  "from decimal import Decimal\n\n"
                  "pattern = re.compile('\\bword\\b')\n"
                  "items = field(default_factory=list())\n"
                  "price = Decimal(0.1)\n"
                  "bad = math.nan == math.nan\n\n"
                  "async def main():\n"
                  "    asyncio.create_task(worker())\n"
                  "    requests.get('https://example.com')\n")
        rules = _rules(source)
        self.assertIn("rare-regex-backspace-boundary", rules)
        self.assertIn("rare-default-factory-called", rules)
        self.assertIn("rare-decimal-from-float", rules)
        self.assertIn("rare-nan-comparison", rules)
        self.assertIn("rare-untracked-asyncio-task", rules)
        self.assertIn("rare-blocking-http-in-async", rules)

    def test_method_cache_property_setter_and_enum_alias(self):
        source = ("from functools import lru_cache\n"
                  "from enum import Enum\n\n"
                  "class Service:\n"
                  "    @lru_cache()\n"
                  "    def compute(self, x):\n"
                  "        return x\n\n"
                  "    @property\n"
                  "    def name(self):\n"
                  "        return self._name\n\n"
                  "    @name.setter\n"
                  "    def name(self, value):\n"
                  "        self._name = value\n"
                  "        return value\n\n"
                  "class Color(Enum):\n"
                  "    RED = 1\n"
                  "    ALSO_RED = 1\n")
        rules = _rules(source)
        self.assertIn("rare-lru-cache-on-method", rules)
        self.assertIn("rare-property-setter-return", rules)
        self.assertIn("rare-enum-duplicate-value", rules)

    def test_cli_scans_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "bad.py")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("xs = [2, 1]\nxs = xs.sort()\n")
            code = rarebugs.main([path])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
