#!/usr/bin/env python3
"""
Tests for harvest.py.

The detect/improve logic is tested offline on synthetic snippets (deterministic).
The live GitHub round-trip is gated behind ATTESTOR_LIVE_TESTS=1 so the suite stays
hermetic and never depends on network, rate limits, or a specific repo's contents.
"""
import os
import unittest

import harvest

BUGGY_PY = '''\
import hashlib
import requests

def check(user):
    digest = hashlib.md5(user.encode()).hexdigest()
    resp = requests.get("https://x", verify=False)
    if user == None:
        return None
    try:
        resp.raise_for_status()
    except:
        pass
    return digest

DEBUG = True
'''


class HarvestOfflineTests(unittest.TestCase):
    def test_improve_applies_safe_fixes(self):
        improved, applied = harvest.improve(BUGGY_PY)
        # the mechanical fixes landed...
        self.assertIn("hashlib.sha256", improved)
        self.assertNotIn("hashlib.md5", improved)
        self.assertIn("verify=True", improved)
        self.assertNotIn("verify=False", improved)
        self.assertIn("is None", improved)
        self.assertNotIn("== None", improved)
        self.assertIn("except Exception:", improved)
        self.assertIn("DEBUG=False", improved)
        # ...and each was reported
        rules = {rid for rid, _, _ in applied}
        self.assertLessEqual(
            {"weak-hash", "tls-verify-disabled", "py-eq-none",
             "py-bare-except", "debug-enabled"}, rules)

    def test_scan_then_improve_reduces_findings(self):
        before = harvest.scan_content(BUGGY_PY, ".py")
        improved, _ = harvest.improve(BUGGY_PY)
        after = harvest.scan_content(improved, ".py")
        self.assertGreater(len(before), len(after))
        # the auto-fixed classes are gone from the improved scan
        after_rules = {f.rule for f in after}
        for gone in ("tls-verify-disabled", "py-eq-none", "py-bare-except",
                     "weak-hash", "debug-enabled"):
            self.assertNotIn(gone, after_rules)

    def test_header_cites_source_and_license(self):
        h = harvest.header(".py", "owner/repo", "src/app.py",
                           "https://github.com/owner/repo/blob/x/src/app.py",
                           None, [], [])
        self.assertIn("owner/repo", h)
        self.assertIn("license", h)
        self.assertIn("UNKNOWN", h)   # missing license is surfaced, not hidden

    def test_parse_blob_url(self):
        got = harvest.parse_github_url(
            "https://github.com/psf/requests/blob/main/src/requests/api.py")
        self.assertEqual(got, ("psf/requests", "main", "src/requests/api.py"))

    def test_parse_raw_url(self):
        got = harvest.parse_github_url(
            "https://raw.githubusercontent.com/psf/requests/main/setup.py")
        self.assertEqual(got, ("psf/requests", "main", "setup.py"))

    def test_parse_strips_query_and_fragment(self):
        got = harvest.parse_github_url(
            "https://github.com/o/r/blob/dev/a/b/c.py?raw=1#L10")
        self.assertEqual(got, ("o/r", "dev", "a/b/c.py"))

    def test_parse_non_url_is_none(self):
        self.assertIsNone(harvest.parse_github_url("verify=False"))
        self.assertIsNone(harvest.parse_github_url("https://example.com/x.py"))

    def test_scan_uses_ast_engine_on_python(self):
        # a NameError only the AST engine (deepscan) can see, not the regex one
        findings = harvest.scan_content("def f():\n    return undefined_thing\n", ".py")
        self.assertIn("undefined-name", {f.rule for f in findings})

    def test_scan_uses_rare_error_oracle_on_python(self):
        findings = harvest.scan_content("xs = [2, 1]\nxs = xs.sort()\n", ".py")
        self.assertIn("rare-mutating-method-assigned", {f.rule for f in findings})

    @unittest.skipUnless(os.environ.get("ATTESTOR_LIVE_TESTS") == "1",
                         "set ATTESTOR_LIVE_TESTS=1 to hit the live GitHub API")
    def test_live_github_search(self):
        items, total = harvest.search("verify=False", "python", per_page=2)
        self.assertGreaterEqual(total, 0)
        if items:
            content, repo, path, url, lic = harvest.fetch(items[0])
            self.assertTrue(content)
            self.assertIn("/", repo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
