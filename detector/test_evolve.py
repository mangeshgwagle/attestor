#!/usr/bin/env python3
# Tests for evolve.py -- GitHub harvest -> repeated review -> safe improvement.
import unittest

import evolve

BUGGY = (
    "import hashlib\n"
    "import requests\n"
    "\n"
    "DEBUG = True\n"
    "\n"
    "\n"
    "def token(user):\n"
    "    if user == None:\n"
    "        return None\n"
    "    digest = hashlib.md5(user.encode()).hexdigest()\n"
    "    requests.get(\"https://example.com\", verify=False)\n"
    "    return digest\n"
)


class EvolveTests(unittest.TestCase):
    def source(self, content=BUGGY):
        return {
            "content": content,
            "repo": "owner/repo",
            "path": "src/app.py",
            "url": "https://github.com/owner/repo/blob/main/src/app.py",
            "license": "MIT",
            "ext": ".py",
        }

    def test_evolve_source_reduces_findings_and_keeps_rereading(self):
        result = evolve.evolve_source(self.source(), cycles=5)
        first = result["history"][0]
        self.assertGreater(first["findings_before"], first["findings_after"])
        self.assertGreaterEqual(first["passes"], 8)
        self.assertIn("hashlib.sha256", result["code"])
        self.assertIn("verify=True", result["code"])
        self.assertIn("is None", result["code"])
        self.assertIn("DEBUG=False", result["code"])
        self.assertTrue(result["findings"])  # no timeout is intentionally left for a human/forge

    def test_clean_source_stops_after_one_stable_cycle(self):
        clean = "def add(a, b):\n    return a + b\n"
        result = evolve.evolve_source(self.source(clean), cycles=5)
        self.assertEqual(len(result["history"]), 1)
        self.assertFalse(result["history"][0]["changed"])
        self.assertEqual(result["findings"], [])

    def test_render_reports_cycles_and_lessons(self):
        run = {"target": "verify=False", "total": 12, "results": [evolve.evolve_source(self.source())]}
        text = evolve.render(run)
        self.assertIn("cycle 1", text)
        self.assertIn("learned fixes", text)
        self.assertIn("owner/repo/src/app.py", text)

    def test_load_targets_direct_github_url(self):
        old_fetch = evolve.harvest.fetch_url
        try:
            evolve.harvest.fetch_url = lambda repo, ref, path: (BUGGY, repo, path, "url", "MIT")
            sources, total = evolve.load_targets(
                "https://github.com/owner/repo/blob/main/src/app.py", lang="python")
        finally:
            evolve.harvest.fetch_url = old_fetch
        self.assertIsNone(total)
        self.assertEqual(sources[0]["repo"], "owner/repo")
        self.assertEqual(sources[0]["ext"], ".py")

    def test_load_targets_search_window(self):
        old_search = evolve.harvest.search
        old_fetch = evolve.harvest.fetch
        try:
            evolve.harvest.search = lambda query, lang, per_page=5: ([
                {"repository": {"full_name": "o/r"}, "path": "a.py", "html_url": "u0"},
                {"repository": {"full_name": "o/r"}, "path": "b.py", "html_url": "u1"},
            ], 2)
            evolve.harvest.fetch = lambda item: (BUGGY, item["repository"]["full_name"], item["path"], item["html_url"], "MIT")
            sources, total = evolve.load_targets("verify=False", lang="python", pick=1, limit=1)
        finally:
            evolve.harvest.search = old_search
            evolve.harvest.fetch = old_fetch
        self.assertEqual(total, 2)
        self.assertEqual(len(sources), 1)
        self.assertEqual(sources[0]["path"], "b.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
