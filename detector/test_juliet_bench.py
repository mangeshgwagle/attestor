#!/usr/bin/env python3
"""Tests for juliet_bench.py.

The corpus itself is ~153 MB of separately downloaded NIST material and is not
shipped, so corpus-dependent tests skip when it is absent -- the same way this
suite already skips when Node.js or symlink privilege is unavailable.  Set
ATTESTOR_JULIET_CORPUS to a Juliet C/C++ zip to run them.

Everything that does not need the corpus -- the variant split, the report
contract, verification, bounds -- is tested unconditionally.
"""
import json
import os
import tempfile
import unittest
import zipfile

import juliet_bench as bench

CORPUS = os.environ.get("ATTESTOR_JULIET_CORPUS", "")

PAIRED = """\
#include "std_testcase.h"

#ifndef OMITBAD
void bad()
{
    char * data = (char *)ALLOCA(10 * sizeof(char));
    strcpy(data, "AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
}
#endif /* OMITBAD */

#ifndef OMITGOOD
static void goodG2B()
{
    char data[64];
    strncpy(data, "AAAA", sizeof(data) - 1);
}
#endif /* OMITGOOD */
"""


class VariantSplitTests(unittest.TestCase):
    def test_paired_case_splits_into_two_variants(self):
        split = bench.split_variants(PAIRED)
        self.assertIsNotNone(split)
        flawed, fixed = split
        self.assertIn("void bad()", flawed)
        self.assertNotIn("goodG2B", flawed)
        self.assertIn("goodG2B", fixed)
        self.assertNotIn("void bad()", fixed)

    def test_both_variants_keep_the_shared_scaffolding(self):
        flawed, fixed = bench.split_variants(PAIRED)
        for text in (flawed, fixed):
            self.assertIn('#include "std_testcase.h"', text)

    def test_a_file_without_both_guards_is_not_a_pair(self):
        for text in ("int main(void) { return 0; }\n",
                     "#ifndef OMITBAD\nvoid bad(){}\n#endif /* OMITBAD */\n"):
            with self.subTest(text=text[:24]):
                self.assertIsNone(bench.split_variants(text))


class BoundsTests(unittest.TestCase):
    def test_a_missing_corpus_is_refused_not_invented(self):
        with self.assertRaises(bench.JulietError):
            bench.measure(os.path.join(tempfile.gettempdir(), "no-such.zip"))

    def test_a_non_archive_is_refused(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
            handle.write(b"not a zip file")
            path = handle.name
        self.addCleanup(os.unlink, path)
        with self.assertRaises(bench.JulietError):
            bench.measure(path)

    def test_an_archive_without_test_cases_is_refused(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as handle:
            path = handle.name
        self.addCleanup(os.unlink, path)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "nothing here")
        with self.assertRaises(bench.JulietError):
            bench.measure(path)

    def test_sample_size_is_bounded(self):
        for bad in (0, -1, bench.MAX_PER_CWE + 1, 2.5, True, "8"):
            with self.subTest(per_cwe=bad):
                with self.assertRaises(bench.JulietError):
                    bench.measure("ignored.zip", per_cwe=bad)


class SyntheticCorpusTests(unittest.TestCase):
    """A tiny hand-built archive exercises the full path without 153 MB."""

    def build(self):
        handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        with zipfile.ZipFile(handle.name, "w") as archive:
            for index in range(3):
                archive.writestr(
                    "C/testcases/CWE121_Stack_Based_Buffer_Overflow/"
                    "CWE121_case_%02d.c" % index, PAIRED)
            # Multi-file variants must be ignored: the flaw spans files.
            archive.writestr(
                "C/testcases/CWE121_Stack_Based_Buffer_Overflow/"
                "CWE121_case_73a.c", PAIRED)
        return handle.name

    def test_measures_and_verifies(self):
        report = self.build()
        result = bench.measure(report, per_cwe=8)
        self.assertEqual(result["schema"], bench.SCHEMA)
        self.assertEqual(result["classes"], 1)
        self.assertEqual(result["paired_cases"], 3)      # the 73a file excluded
        self.assertIn("CWE-121", result["by_cwe"])
        ok, errors = bench.verify_report(result)
        self.assertTrue(ok, errors)

    def test_a_rewritten_score_fails_verification(self):
        result = bench.measure(self.build(), per_cwe=8)
        result["by_cwe"]["CWE-121"]["pairs"] = 99
        ok, errors = bench.verify_report(result)
        self.assertFalse(ok)
        self.assertTrue(any("disagrees" in error or "digest" in error
                            for error in errors))

    def test_report_states_what_a_zero_means(self):
        result = bench.measure(self.build(), per_cwe=8)
        self.assertTrue(any("never that the code under test is safe" in line
                            for line in result["limitations"]))
        self.assertIn("differential", result["criterion"])

    def test_render_is_readable_and_carries_the_caveats(self):
        text = bench.render(bench.measure(self.build(), per_cwe=8))
        self.assertIn("Attestor vs NIST Juliet", text)
        self.assertIn("classes never detected", text)
        self.assertIn("note:", text)

    def test_sampling_is_deterministic(self):
        path = self.build()
        first = bench.measure(path, per_cwe=8)
        second = bench.measure(path, per_cwe=8)
        self.assertEqual(first["report_sha256"], second["report_sha256"])


@unittest.skipUnless(CORPUS and os.path.isfile(CORPUS),
                     "Juliet corpus unavailable; set ATTESTOR_JULIET_CORPUS")
class RealCorpusTests(unittest.TestCase):
    def test_the_real_corpus_produces_a_verifiable_report(self):
        report = bench.measure(CORPUS, per_cwe=4)
        self.assertGreater(report["classes"], 50)
        self.assertTrue(bench.verify_report(report)[0])
        self.assertLess(report["exact_percent"], 100.0)

    def test_classes_with_a_matching_rule_outperform_those_without(self):
        report = bench.measure(CORPUS, per_cwe=6)
        with_rule = [row["exact_percent"] for row in report["by_cwe"].values()
                     if row["has_rule_for_this_cwe"]]
        without = [row["exact_percent"] for row in report["by_cwe"].values()
                   if not row["has_rule_for_this_cwe"]]
        self.assertTrue(with_rule and without)
        self.assertEqual(max(without), 0.0,
                         "a class with no rule reported its own CWE")
        self.assertGreater(max(with_rule), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
