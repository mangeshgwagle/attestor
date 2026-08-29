#!/usr/bin/env python3
"""Tests for superattestor.py -- the one-door dispatcher. Offline/deterministic."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

import superattestor

CLEAN = "def merge(a, b):\n    if a is None:\n        return b\n    return sorted(a + b)\n"


class FakeBrain:
    def __init__(self, answer=CLEAN):
        self._answer = answer

    def available(self):
        return True

    def provider_names(self):
        return ["groq"]

    def generate(self, _prompt):
        return self._answer


class DecideTests(unittest.TestCase):
    def test_path_routes_to_comprehend(self):
        d = superattestor.decide("harvest.py")
        self.assertEqual(d["action"], "comprehend")
        self.assertTrue(os.path.exists(d["target"]))
        self.assertEqual(os.path.basename(d["target"]), "harvest.py")

    def test_github_url_routes_to_comprehend(self):
        d = superattestor.decide("https://github.com/o/r/blob/main/app.py")
        self.assertEqual(d["action"], "comprehend")

    def test_self_improve_routes_to_evolve(self):
        d = superattestor.decide("self improve https://github.com/o/r/blob/main/app.py")
        self.assertEqual(d["action"], "evolve")
        self.assertEqual(d["target"], "https://github.com/o/r/blob/main/app.py")

    def test_ruleforge_routes(self):
        d = superattestor.decide("ruleforge timeout=None")
        self.assertEqual(d["action"], "ruleforge")
        self.assertEqual(d["target"], "timeout=None")

    def test_darwin_routes(self):
        d = superattestor.decide("darwin search graphql")
        self.assertEqual(d["action"], "darwin")
        self.assertEqual(d["cmd"], "search")
        self.assertEqual(d["query"], "graphql")

    def test_cyber_routes(self):
        d = superattestor.decide("cyber sentinel .")
        self.assertEqual(d["action"], "cyber")
        self.assertEqual(d["path"], ".")

    def test_polyglot_routes(self):
        d = superattestor.decide("polyglot .")
        self.assertEqual(d["action"], "polyglot")
        self.assertEqual(d["path"], ".")

    def test_sieve_routes(self):
        d = superattestor.decide("sieve write fibonacci")
        self.assertEqual(d["action"], "sieve")
        self.assertEqual(d["target"], "write fibonacci")

    def test_codemax_routes(self):
        d = superattestor.decide("code max sample.py")
        self.assertEqual(d["action"], "codemax")
        self.assertEqual(d["target"], "sample.py")

    def test_codepower_securitymax_and_attestor2_route(self):
        self.assertEqual(superattestor.decide("code power sample.py")["action"], "codepower")
        self.assertEqual(superattestor.decide("rare errors sample.py")["action"], "rarebugs")
        self.assertEqual(superattestor.decide("security max .")["action"], "securitymax")
        self.assertEqual(superattestor.decide("attestor 2 .")["action"], "attestor2")

    def test_scaffold_english(self):
        d = superattestor.decide("make an api for Book with fields title, year (int)")
        self.assertEqual(d["action"], "scaffold")

    def test_review_routes_to_comprehend(self):
        d = superattestor.decide("review codegen.py")
        self.assertEqual(d["action"], "comprehend")
        self.assertTrue(os.path.exists(d["target"]))
        self.assertEqual(os.path.basename(d["target"]), "codegen.py")

    def test_snippet_offline_but_forge_when_brain_awake(self):
        self.assertEqual(superattestor.decide("write fibonacci")["action"], "snippet")
        self.assertEqual(
            superattestor.decide("write fibonacci", FakeBrain())["action"], "forge")

    def test_novel_request_needs_the_brain(self):
        self.assertEqual(superattestor.decide("write a compiler optimizer")["action"], "unknown")
        self.assertEqual(
            superattestor.decide("write a compiler optimizer", FakeBrain())["action"], "forge")


class PerformTests(unittest.TestCase):
    def test_forge_runs_the_verified_loop(self):
        bus = FakeBrain()
        text, code = superattestor.perform(
            {"action": "forge", "request": "merge two sorted lists"}, bus=bus)
        self.assertEqual(code, 0)
        self.assertIn("STATIC-SCAN-CLEAN CANDIDATE", text)

    def test_unknown_refuses_honestly(self):
        text, code = superattestor.perform({"action": "unknown"})
        self.assertEqual(code, 1)
        self.assertIn("won't fake it", text)

    def test_ruleforge_perform_on_local_file(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "app.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("import requests\nrequests.get(url, timeout=None)\n")
            text, code = superattestor.perform({"action": "ruleforge", "target": path}, evolve_lang="python")
        self.assertEqual(code, 0)
        self.assertIn("py-timeout-none", text)

    def test_ruleforge_cli_flag_runs(self):
        import contextlib
        import io
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "app.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("import requests\nrequests.get(url, timeout=None)\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = superattestor.main(["--ruleforge", path, "--lang", "python"])
        self.assertEqual(code, 0)
        self.assertIn("py-timeout-none", out.getvalue())

    def test_darwin_perform_searches_payloads(self):
        text, code = superattestor.perform(
            {"action": "darwin", "cmd": "search", "query": "graphql"},
            evolve_limit=5)
        self.assertEqual(code, 0)
        self.assertIn("Darwin search", text)

    def test_scaffold_reports_service(self):
        d = superattestor.decide("make an api for Widget with fields label")
        text, code = superattestor.perform(d)
        self.assertEqual(code, 0)
        self.assertIn("Widget", text)

    def test_cyber_perform_reports_security_findings(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("requests\n")
            text, code = superattestor.perform({"action": "cyber", "path": d})
        self.assertEqual(code, 1)
        self.assertIn("Cyber Sentinel report", text)

    def test_polyglot_perform_reports_tiny_bugs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bug.hs")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x xs = head xs\n")
            text, code = superattestor.perform({"action": "polyglot", "path": d})
        self.assertEqual(code, 1)
        self.assertIn("Polyglot tiny-error report", text)

    def test_sieve_perform_uses_verified_loop(self):
        text, code = superattestor.perform(
            {"action": "sieve", "target": "merge sorted lists"},
            bus=FakeBrain(CLEAN), rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Sieve model-backed coding loop", text)

    def test_codemax_perform_reviews_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sample.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("def add(a: int, b: int) -> int:\n    return a + b\n")
            text, code = superattestor.perform(
                {"action": "codemax", "target": path}, rounds=3)
        self.assertEqual(code, 0)
        self.assertIn("Code Max file review", text)

    def test_attestor2_modes_perform(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sample.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("def add(a: int, b: int) -> int:\n    return a + b\n")
            text, code = superattestor.perform({"action": "codepower", "target": d}, rounds=3)
            self.assertEqual(code, 0)
            self.assertIn("Attestor 2 Code Power", text)
            text, code = superattestor.perform({"action": "securitymax", "path": d}, rounds=3)
            self.assertEqual(code, 0)
            self.assertIn("Attestor 2 Security Max", text)
            text, code = superattestor.perform({"action": "attestor2", "target": d}, rounds=3)
            self.assertIn("Attestor 2 Max Review", text)

    def test_rarebugs_perform_reports_rare_findings(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "rare.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("xs = [2, 1]\nxs = xs.sort()\n")
            text, code = superattestor.perform({"action": "rarebugs", "path": path})
        self.assertEqual(code, 1)
        self.assertIn("rare-mutating-method-assigned", text)


class ProviderTests(unittest.TestCase):
    KEYS = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY", "MISTRAL_API_KEY", "OPENAI_API_KEY", "OLLAMA_MODEL", "OLLAMA_HOST")

    def setUp(self):
        self._saved = {k: os.environ.pop(k, None) for k in self.KEYS}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v

    def test_all_configured_apis_are_awake(self):
        os.environ["GEMINI_API_KEY"] = "fake"
        os.environ["GROQ_API_KEY"] = "fake"
        names = superattestor.build_brain().provider_names()
        self.assertIn("gemini", names)
        self.assertIn("groq", names)

    def test_no_brain_at_all_without_keys(self):
        self.assertFalse(superattestor.build_brain().available())


class LauncherIsolationTests(unittest.TestCase):
    def test_entry_point_starts_under_isolated_mode(self):
        completed = subprocess.run(
            [sys.executable, "-I", "-B", "-X", "utf8",
             str(Path(superattestor.__file__).resolve()), "--help"],
            cwd=str(Path(superattestor.__file__).resolve().parent.parent),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("superattestor.py", completed.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
