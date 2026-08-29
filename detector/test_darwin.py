#!/usr/bin/env python3
"""Tests for darwin.py -- Attestor's bundled Darwin payload library."""
from __future__ import annotations

import csv
import json
import os
import tempfile
import unittest

import darwin


class DarwinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = darwin.load()

    def test_stats_match_bundled_payloads(self):
        stats = darwin.stats(self.data)
        self.assertEqual(stats["categories"], 64)
        self.assertGreater(stats["total_payloads"], 40000)
        self.assertIn("Darwin payloads", darwin.render_stats(self.data))

    def test_search_finds_api_security_payloads(self):
        results = darwin.search("graphql", limit=10, data=self.data)
        self.assertTrue(results)
        self.assertLessEqual(len(results), 10)
        self.assertTrue(any("GraphQL" in r["category"] or "graphql" in r["payload"].lower()
                            for r in results))

    def test_partial_category_lookup_and_render(self):
        cat = darwin.find_category("api security", self.data)
        self.assertIsNotNone(cat)
        text = darwin.render_category("api security", limit=3, data=self.data)
        self.assertIn("API Security", text)

    def test_exports_burp_csv_json(self):
        with tempfile.TemporaryDirectory() as d:
            burp = os.path.join(d, "payloads.txt")
            csv_path = os.path.join(d, "payloads.csv")
            json_path = os.path.join(d, "payloads.json")
            darwin.export("API Security", "burp", burp, self.data)
            darwin.export("API Security", "csv", csv_path, self.data)
            darwin.export("API Security", "json", json_path, self.data)
            self.assertGreater(os.path.getsize(burp), 0)
            with open(csv_path, newline="", encoding="utf-8") as fh:
                rows = list(csv.reader(fh))
            self.assertEqual(rows[0], ["Category", "Source", "Payload"])
            with open(json_path, encoding="utf-8") as fh:
                exported = json.load(fh)
            self.assertEqual(exported["category"], "API Security")

    def test_bad_export_format_is_rejected(self):
        with self.assertRaises(ValueError):
            darwin.export("API Security", "madeup", data=self.data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
