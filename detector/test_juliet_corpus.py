#!/usr/bin/env python3
"""Tests for juliet_corpus.py.

Most of these pin a *leak*.  Juliet is easy to score well on for reasons that
have nothing to do with finding defects, and each removed leak is worth a test
because re-introducing one does not break anything visibly -- it just makes the
held-out number go up, which looks like progress.
"""
import pathlib
import stat
import tempfile
import unittest
import warnings
import zipfile
from unittest import mock

import juliet_corpus as jc

FLAWED_BLOCK = """
#ifndef OMITBAD
void CWE476_NULL_Pointer_Dereference__struct_01_bad()
{
    twoIntsStruct * data;
    /* POTENTIAL FLAW: Set data to NULL */
    data = NULL;
    printIntLine(data->intOne);
}
#endif /* OMITBAD */
#ifndef OMITGOOD
static void goodB2G()
{
    twoIntsStruct * data;
    data = NULL;
    /* FIX: Check for NULL before dereferencing */
    if (data != NULL)
    {
        printIntLine(data->intOne);
    }
}
#endif /* OMITGOOD */
"""

ARCHIVE_MEMBER = "Juliet/testcases/CWE476_Null/case.c"


class DeclassifyTests(unittest.TestCase):
    def test_comments_that_announce_the_answer_are_removed(self):
        cleaned = jc.declassify(FLAWED_BLOCK)
        for leak in ("POTENTIAL FLAW", "FIX:", "OMITBAD"):
            self.assertNotIn(leak, cleaned)

    def test_identifiers_that_announce_the_answer_are_neutralised(self):
        cleaned = jc.declassify(FLAWED_BLOCK)
        for leak in ("CWE476", "_bad", "goodB2G"):
            self.assertNotIn(leak, cleaned)
        self.assertIn("fn", cleaned)

    def test_storage_class_is_dropped_because_it_is_perfectly_correlated(self):
        # Juliet exports every flawed function and makes every fix `static`,
        # so the keyword alone separates the classes.
        self.assertNotIn("static", jc.declassify(FLAWED_BLOCK))

    def test_ordinary_identifiers_survive(self):
        cleaned = jc.declassify(FLAWED_BLOCK)
        for kept in ("data", "printIntLine", "twoIntsStruct", "NULL"):
            self.assertIn(kept, cleaned)

    def test_a_comment_inside_a_string_literal_is_not_a_comment(self):
        source = 'printLine("/* not a comment */"); int x = 1;'
        self.assertIn("/* not a comment */", jc.strip_comments(source))
        self.assertIn("int x = 1;", jc.strip_comments(source))

    def test_an_escaped_quote_does_not_end_the_string(self):
        source = 'printLine("a \\" /* still string */ b"); int y = 2;'
        self.assertIn("int y = 2;", jc.strip_comments(source))

    def test_line_comments_go_and_code_after_the_newline_stays(self):
        self.assertNotIn("secret", jc.strip_comments("int a; // secret\nint b;"))
        self.assertIn("int b;", jc.strip_comments("int a; // secret\nint b;"))


class SplitTests(unittest.TestCase):
    def test_both_variants_are_recovered(self):
        flawed, fixed = jc.split_variants(FLAWED_BLOCK)
        self.assertIn("printIntLine", flawed)
        self.assertNotIn("goodB2G", flawed)
        self.assertIn("goodB2G", fixed)
        self.assertNotIn("_bad()", fixed)

    def test_a_file_without_both_halves_is_refused(self):
        self.assertIsNone(jc.split_variants("int main(void) { return 0; }"))

    def test_cwe_is_read_from_the_path_only(self):
        self.assertEqual(jc.cwe_of("x/testcases/CWE476_Null/a.c"), "CWE-476")
        self.assertEqual(jc.cwe_of("x/testcases/thing.c"), "CWE-unknown")


class ExampleTests(unittest.TestCase):
    def rows(self):
        return jc.examples_from(FLAWED_BLOCK, "case.c", "CWE-476")

    def test_both_labels_are_produced_when_the_fix_only_inserts(self):
        # The fix here adds a guard and changes nothing else, so the flawed
        # lines are a subsequence of the fixed ones.  Emitting only the side
        # with lines would yield negatives and no positive at all -- which is
        # most of Juliet's NULL-dereference families.
        rows = self.rows()
        self.assertTrue(any(row.label == 1 for row in rows))
        self.assertTrue(any(row.label == 0 for row in rows))

    def test_the_positive_windows_carry_the_defect(self):
        flawed = [row.text for row in self.rows() if row.label == 1]
        self.assertTrue(any("data = NULL;" in text and "data->intOne" in text
                            for text in flawed))

    def test_no_example_carries_a_leak(self):
        for row in self.rows():
            for leak in ("FLAW", "FIX", "CWE476", "static", "goodB2G"):
                self.assertNotIn(leak, row.text)

    def test_every_example_names_its_pair_and_class(self):
        for row in self.rows():
            self.assertEqual(row.pair, "case.c")
            self.assertEqual(row.cwe, "CWE-476")

    def test_a_file_without_both_halves_yields_nothing(self):
        self.assertEqual(jc.examples_from("int main(void){return 0;}", "p", "c"), [])

    def test_windows_are_capped_per_changed_region(self):
        long_source = FLAWED_BLOCK.replace(
            "printIntLine(data->intOne);",
            "\n".join("    step%d();" % i for i in range(40)))
        rows = jc.examples_from(long_source, "case.c", "CWE-476")
        positives = sum(1 for row in rows if row.label == 1)
        self.assertLessEqual(positives, jc.MAX_WINDOWS_PER_REGION * 4)


class WindowTests(unittest.TestCase):
    def test_windows_are_contiguous_and_complete(self):
        text = "\n".join("l%d" % i for i in range(6))
        self.assertEqual(jc.windows(text, 4)[0], "l0\nl1\nl2\nl3")
        self.assertEqual(len(jc.windows(text, 4)), 3)

    def test_a_source_shorter_than_the_window_yields_one(self):
        self.assertEqual(jc.windows("only", 4), ["only"])

    def test_bad_window_sizes_are_refused(self):
        for bad in (0, -1, 2.5, True, "4", jc.MAX_WINDOW_LINES + 1):
            with self.subTest(size=bad):
                with self.assertRaises(jc.CorpusError):
                    jc.windows("a\nb", bad)


class SplitGroupingTests(unittest.TestCase):
    ROWS = [jc.Example("t%d" % i, i % 2, "pair%d" % (i // 4), "CWE-1")
            for i in range(40)]

    def test_no_pair_appears_on_both_sides(self):
        train, test = jc.group_split(self.ROWS, holdout=0.25)
        self.assertTrue(train and test)
        self.assertFalse({row.pair for row in train} &
                         {row.pair for row in test})

    def test_the_split_is_deterministic(self):
        first = jc.group_split(self.ROWS, holdout=0.25)[1]
        second = jc.group_split(self.ROWS, holdout=0.25)[1]
        self.assertEqual([row.text for row in first],
                         [row.text for row in second])

    def test_a_different_seed_moves_the_boundary(self):
        a = {row.pair for row in jc.group_split(self.ROWS, 0.25, seed=1)[1]}
        b = {row.pair for row in jc.group_split(self.ROWS, 0.25, seed=7)[1]}
        self.assertNotEqual(a, b)

    def test_bad_holdout_is_refused(self):
        for bad in (0.0, 1.0, -0.5, 2.0):
            with self.subTest(holdout=bad):
                with self.assertRaises(jc.CorpusError):
                    jc.group_split(self.ROWS, bad)


class SummaryTests(unittest.TestCase):
    def test_counts_and_digest_are_reported(self):
        rows = jc.examples_from(FLAWED_BLOCK, "case.c", "CWE-476")
        summary = jc.summarise(rows)
        self.assertEqual(summary["schema"], jc.SCHEMA)
        self.assertEqual(summary["examples"], len(rows))
        self.assertEqual(summary["positive"] + summary["negative"], len(rows))
        self.assertEqual(summary["pairs"], 1)
        self.assertRegex(summary["corpus_sha256"], r"^[0-9a-f]{64}$")

    def test_the_label_caveat_is_stated(self):
        summary = jc.summarise(jc.examples_from(FLAWED_BLOCK, "p", "CWE-476"))
        self.assertTrue(any("not that the window is itself the defect" in line
                            for line in summary["limitations"]))

    def test_an_unreadable_archive_is_refused(self):
        with self.assertRaises(jc.CorpusError):
            list(jc.iter_archive("no-such-archive.zip"))


class ArchiveBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.temporary.name) / "juliet.zip"

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, entries, compression=zipfile.ZIP_STORED):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.path, "w", compression=compression) as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)

    def assert_refused(self, fragment=None):
        with self.assertRaises(jc.CorpusError) as caught:
            list(jc.iter_archive(str(self.path)))
        if fragment:
            self.assertIn(fragment, str(caught.exception))

    def test_valid_member_is_streamed_without_zipfile_read(self):
        self.write([(ARCHIVE_MEMBER, FLAWED_BLOCK)], zipfile.ZIP_DEFLATED)
        with mock.patch.object(zipfile.ZipFile, "read",
                               side_effect=AssertionError("unbounded read")):
            rows = list(jc.iter_archive(str(self.path)))
        self.assertTrue(rows)
        self.assertEqual({row.cwe for row in rows}, {"CWE-476"})

    def test_entry_count_is_bounded_before_payload_reads(self):
        self.write([("one.txt", b"1"), ("two.txt", b"2")])
        with mock.patch.object(jc, "MAX_ARCHIVE_ENTRIES", 1):
            self.assert_refused("entries")

    def test_per_entry_and_aggregate_sizes_are_bounded(self):
        # An oversized member the reader *could* open is still fatal.
        self.write([("x/testcases/one.c", b"123456"),
                    ("x/testcases/two.c", b"abcdef")])
        with mock.patch.object(jc, "MAX_ENTRY_UNCOMPRESSED_BYTES", 5):
            self.assert_refused("member exceeds")
        with mock.patch.object(jc, "MAX_TOTAL_UNCOMPRESSED_BYTES", 10):
            self.assert_refused("uncompressed bytes")

    def test_an_oversized_member_outside_testcases_is_skipped(self):
        """Scaffolding the reader never opens must not fail the archive.

        NIST's own Juliet ships `C/testcasesupport/main.cpp` at 19.2 MB. It
        sits outside `/testcases/`, so `iter_archive` never opens it -- and
        refusing the whole corpus over it made `train_gate` and `rule_forge`
        unusable against the only external ground truth this project has.
        """
        self.write([(ARCHIVE_MEMBER, FLAWED_BLOCK),
                    ("C/testcasesupport/main.cpp", b"Z" * 4096)])
        with mock.patch.object(jc, "MAX_ENTRY_UNCOMPRESSED_BYTES", 1024):
            rows = list(jc.iter_archive(str(self.path)))
        self.assertTrue(rows, "the testcase should still have been read")
        self.assertEqual({row.cwe for row in rows}, {"CWE-476"})

    def test_an_oversized_testcase_member_is_still_refused(self):
        """The narrowing must not become a way past the limit."""
        self.write([("x/testcases/CWE476_big_01.c", b"Z" * 4096)])
        with mock.patch.object(jc, "MAX_ENTRY_UNCOMPRESSED_BYTES", 1024):
            self.assert_refused("member exceeds")

    def test_compression_ratio_is_bounded(self):
        self.write([("compressed.txt", b"A" * 4096)], zipfile.ZIP_DEFLATED)
        with mock.patch.object(jc, "MAX_COMPRESSION_RATIO", 2.0):
            self.assert_refused("compression ratio")

    def test_archive_file_size_is_bounded(self):
        self.write([("one.txt", b"1")])
        with mock.patch.object(jc, "MAX_ARCHIVE_BYTES", 1):
            self.assert_refused("archive exceeds")

    def test_traversal_absolute_and_backslash_paths_are_refused(self):
        for name in ("../evil.c", "/absolute.c", r"C:\evil.c",
                     "safe/../evil.c"):
            with self.subTest(name=name):
                self.write([(name, b"x")])
                self.assert_refused("member path")

        # ``writestr`` normalises the platform separator on Windows, so craft
        # the central and local names after creating an otherwise valid ZIP.
        self.write([("safe/evil.c", b"x")])
        data = self.path.read_bytes().replace(b"safe/evil.c", b"safe\\evil.c")
        self.path.write_bytes(data)
        self.assert_refused("member path")

    def test_duplicates_and_case_collisions_are_refused(self):
        for names in (("same.c", "same.c"), ("Case.c", "case.c"),
                      ("caf\u00e9.c", "cafe\u0301.c")):
            with self.subTest(names=names):
                self.write([(names[0], b"one"), (names[1], b"two")])
                self.assert_refused("duplicate/case-colliding")

    def test_encrypted_flag_is_rejected_during_preflight(self):
        self.write([("secret.c", b"secret")])
        data = bytearray(self.path.read_bytes())
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = data.find(signature)
            self.assertGreaterEqual(position, 0)
            flags = int.from_bytes(data[position + offset:position + offset + 2],
                                   "little") | 0x1
            data[position + offset:position + offset + 2] = flags.to_bytes(2, "little")
        self.path.write_bytes(data)
        self.assert_refused("encrypted")

    def test_symlink_member_is_not_treated_as_source(self):
        link = zipfile.ZipInfo("Juliet/testcases/CWE1/link.c")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.path, "w") as archive:
            archive.writestr(link, b"../../outside")
        self.assert_refused("non-regular")

    def test_limit_and_window_arguments_are_validated(self):
        self.write([(ARCHIVE_MEMBER, FLAWED_BLOCK)])
        self.assertEqual(list(jc.iter_archive(str(self.path), limit=0)), [])
        for bad in (-1, True, 1.5):
            with self.subTest(limit=bad):
                with self.assertRaises(jc.CorpusError):
                    list(jc.iter_archive(str(self.path), limit=bad))


if __name__ == "__main__":
    unittest.main(verbosity=2)
