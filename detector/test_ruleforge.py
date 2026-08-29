#!/usr/bin/env python3
"""Tests for ruleforge.py -- candidate detector rules with proofs."""
import os
import tempfile
import unittest

import ruleforge

PY_SOURCE = """\
import requests
import contextlib
from datetime import datetime


def fetch(url):
    return requests.get(url, timeout=None)

with contextlib.suppress(Exception):
    risky()

stamp = datetime.utcnow()
"""

JS_SOURCE = """\
const n = parseInt(input);
const p = new Promise(async (resolve) => { resolve(await load()); });
"""

CPP_SOURCE = """\
#include <mutex>
#include <string>
#include <string_view>
void f(std::mutex& m) { std::lock_guard<std::mutex>(m); shared++; }
std::string_view v = std::string("abc");
"""


class RuleForgeTests(unittest.TestCase):
    def source(self, content=PY_SOURCE, path="app.py"):
        return {"content": content, "repo": "local", "path": path, "url": "", "license": None}

    def test_discovers_python_candidates_and_proves_them(self):
        candidates = ruleforge.discover_in_source(self.source(), forced_lang="python")
        ids = {c.rid for c in candidates}
        self.assertIn("py-timeout-none", ids)
        self.assertIn("py-suppress-broad-exception", ids)
        self.assertIn("py-naive-utcnow", ids)
        self.assertTrue(all(c.proven for c in candidates))

    def test_discovers_candidate_whose_pattern_spans_lines(self):
        source = self.source(
            "import requests\nresult = requests.get(\n    url,\n    timeout=None,\n)\n")
        candidates = ruleforge.discover_in_source(source, forced_lang="python")
        timeout = [candidate for candidate in candidates if candidate.rid == "py-timeout-none"]
        self.assertEqual(len(timeout), 1)
        self.assertEqual(timeout[0].line, 2)

    def test_discovers_js_and_cpp_candidates(self):
        js = ruleforge.discover_in_source(self.source(JS_SOURCE, "app.js"))
        cpp = ruleforge.discover_in_source(self.source(CPP_SOURCE, "lock.cpp"))
        self.assertIn("js-parseint-no-radix", {c.rid for c in js})
        self.assertIn("js-async-promise-executor", {c.rid for c in js})
        self.assertIn("cpp-lock-guard-temporary", {c.rid for c in cpp})
        self.assertIn("cpp-string-view-temporary", {c.rid for c in cpp})

    def test_template_proofs_have_negative_controls(self):
        for template in ruleforge.CATALOG:
            with self.subTest(template=template.rid):
                proven, pos, neg = ruleforge.prove(template)
                self.assertTrue(pos)
                self.assertTrue(neg)
                self.assertTrue(proven)

    def test_forge_reads_local_file_and_renders(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "app.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(PY_SOURCE)
            run = ruleforge.forge(path, lang="python")
        text = ruleforge.render(run)
        self.assertIn("Rule Forge", text)
        self.assertIn("py-timeout-none", text)
        self.assertIn("PROVEN", text)

    def test_write_results_emits_reviewable_artifacts(self):
        run = {"target": "local", "total": None, "sources": [self.source()],
               "candidates": ruleforge.discover_in_source(self.source(), forced_lang="python")}
        with tempfile.TemporaryDirectory() as d:
            written = ruleforge.write_results(run, d)
            self.assertEqual(len(written), 3)
            with open(os.path.join(d, "candidate_rules.py"), encoding="utf-8") as fh:
                rules = fh.read()
            with open(os.path.join(d, "test_candidate_rules.py"), encoding="utf-8") as fh:
                tests = fh.read()
        self.assertIn("@rule('py-timeout-none'", rules)
        self.assertIn("test_candidate_py_timeout_none", tests)
        compile(rules, "candidate_rules.py", "exec")

    def test_load_sources_search_window_is_mockable(self):
        old_search = ruleforge.harvest.search
        old_fetch = ruleforge.harvest.fetch
        try:
            ruleforge.harvest.search = lambda query, lang, per_page=5: ([
                {"repository": {"full_name": "o/r"}, "path": "a.py", "html_url": "u0"},
                {"repository": {"full_name": "o/r"}, "path": "b.py", "html_url": "u1"},
            ], 2)
            ruleforge.harvest.fetch = lambda item: (PY_SOURCE, item["repository"]["full_name"], item["path"], item["html_url"], "MIT")
            sources, total = ruleforge.load_sources("timeout=None", lang="python", pick=1, limit=1)
        finally:
            ruleforge.harvest.search = old_search
            ruleforge.harvest.fetch = old_fetch
        self.assertEqual(total, 2)
        self.assertEqual(sources[0]["path"], "b.py")


if __name__ == "__main__":
    unittest.main(verbosity=2)
