#!/usr/bin/env python3
"""Tests for fuzzer_gen42.py — Fuzzer harness generator."""
import unittest

from fuzzer_gen42 import (
    FuzzTarget, FuzzStrategy, FuzzInput, FuzzHarness, FuzzerGen,
    CWE_FUZZ_TARGET, CWE_STRATEGY, CWE_DICTIONARY,
    generate, VERSION,
    SQLI_DICT, XSS_DICT, CMDI_DICT, PATH_DICT,
)


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "4.2")

    def test_cwe_fuzz_targets(self):
        self.assertGreater(len(CWE_FUZZ_TARGET), 10)

    def test_dictionaries_populated(self):
        self.assertGreater(len(SQLI_DICT), 5)
        self.assertGreater(len(XSS_DICT), 5)
        self.assertGreater(len(CMDI_DICT), 5)
        self.assertGreater(len(PATH_DICT), 5)


class TestFuzzInput(unittest.TestCase):
    def test_basic(self):
        fi = FuzzInput(name="param", input_type="string")
        self.assertEqual(fi.name, "param")
        self.assertEqual(fi.dictionary, [])


class TestFuzzHarness(unittest.TestCase):
    def test_harness_id(self):
        h = FuzzHarness(
            name="test", target_file="app.py", target_line=10,
            cwe=89, language="python", target_type=FuzzTarget.QUERY_BUILDER,
            strategy=FuzzStrategy.GRAMMAR, inputs=[], code="pass",
        )
        self.assertIn("cwe89", h.harness_id)
        self.assertIn("python", h.harness_id)


class TestFuzzerGenPython(unittest.TestCase):
    def test_sqli_http(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 89, "file_path": "app.py", "line": 10,
            "language": "python", "endpoint": "/api/users",
        })
        self.assertIsNotNone(h)
        self.assertIn("hypothesis", h.code)
        self.assertIn("requests", h.code)
        self.assertIn("CWE-89", h.code)

    def test_cmdi_func(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 78, "file_path": "util.py", "line": 25,
            "language": "python", "function": "run_cmd",
        })
        self.assertIn("hypothesis", h.code)
        self.assertIn("run_cmd", h.code)

    def test_buffer_overflow(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 120, "file_path": "parser.py", "line": 50,
            "language": "python",
        })
        self.assertEqual(h.target_type, FuzzTarget.FUNCTION_CALL)
        self.assertIn("hypothesis", h.code)


class TestFuzzerGenJavaScript(unittest.TestCase):
    def test_xss(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 79, "file_path": "routes.js", "line": 15,
            "language": "javascript", "endpoint": "/search",
            "param": "q",
        })
        self.assertIn("fast-check", h.code)
        self.assertIn("axios", h.code)
        self.assertIn("CWE-79", h.code)


class TestFuzzerGenJava(unittest.TestCase):
    def test_sqli_java(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 89, "file_path": "UserDao.java", "line": 42,
            "language": "java",
        })
        self.assertIn("JQF", h.code)
        self.assertIn("@Fuzz", h.code)
        self.assertIn("CWE-89", h.code)


class TestFuzzerGenGeneric(unittest.TestCase):
    def test_unknown_language(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": 89, "file_path": "handler.rb", "line": 10,
            "language": "ruby",
        })
        self.assertIn("#!/bin/bash", h.code)
        self.assertIn("curl", h.code)


class TestFuzzerGenBatch(unittest.TestCase):
    def test_from_findings(self):
        gen = FuzzerGen()
        findings = [
            {"cwe": 89, "file_path": "a.py", "line": 1, "language": "python"},
            {"cwe": 79, "file_path": "b.js", "line": 2, "language": "javascript"},
            {"cwe": 78, "file_path": "c.py", "line": 3, "language": "python"},
        ]
        harnesses = gen.from_findings(findings)
        self.assertEqual(len(harnesses), 3)
        self.assertEqual(len(gen.harnesses), 3)

    def test_summary(self):
        gen = FuzzerGen()
        gen.from_findings([
            {"cwe": 89, "file_path": "a.py", "line": 1, "language": "python"},
            {"cwe": 79, "file_path": "b.js", "line": 2, "language": "javascript"},
        ])
        s = gen.summary()
        self.assertIn("Harnesses generated: 2", s)
        self.assertIn("By language:", s)

    def test_cwe_string_parsing(self):
        gen = FuzzerGen()
        h = gen.from_finding({
            "cwe": "CWE-89", "file_path": "a.py", "line": 1,
            "language": "python",
        })
        self.assertEqual(h.cwe, 89)


class TestGenerateFunction(unittest.TestCase):
    def test_generate(self):
        harnesses = generate([
            {"cwe": 89, "file_path": "a.py", "line": 1, "language": "python"},
        ])
        self.assertEqual(len(harnesses), 1)

    def test_generate_empty(self):
        harnesses = generate([])
        self.assertEqual(harnesses, [])


if __name__ == "__main__":
    unittest.main()
