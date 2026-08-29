#!/usr/bin/env python3
"""Tests for the manifest reader.

Built on synthetic archives rather than the real corpus, which is 146 MB and
not shipped. The one test that touches the real archive skips when it is
absent, so this suite is meaningful on a machine that has never downloaded it.
"""
from __future__ import annotations

import pathlib
import tempfile
import unittest
import zipfile

import juliet_manifest as jm

REAL_ARCHIVE = pathlib.Path(r"C:\Users\mange\attestor-corpus\juliet-c-cpp-v1.3.zip")

SIMPLE = b"""<?xml version="1.0" encoding="utf-8"?>
<container>
  <testcase>
    <file path="CWE114_Process_Control__w32_char_01.c">
      <flaw line="121" name="CWE-114: Process Control"/>
    </file>
  </testcase>
  <testcase>
    <file path="CWE121_Stack_Based_Buffer_Overflow__x_01.c">
      <flaw line="33" name="CWE-121: Stack Based Buffer Overflow"/>
      <flaw line="44" name="CWE-121: Stack Based Buffer Overflow"/>
    </file>
    <file path="CWE121_Stack_Based_Buffer_Overflow__x_01b.c"/>
  </testcase>
</container>
"""

BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE container [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<container><testcase><file path="x.c"><flaw line="1" name="&c;"/></file></testcase></container>
"""


def archive_with(manifest: bytes, name: str = "C/manifest.xml") -> str:
    handle = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    handle.close()
    with zipfile.ZipFile(handle.name, "w") as archive:
        archive.writestr(name, manifest)
    return handle.name


class Parsing(unittest.TestCase):
    def test_reads_flaw_lines(self):
        flaws = list(jm.iter_flaws(archive_with(SIMPLE)))
        self.assertEqual(len(flaws), 3)
        self.assertEqual(flaws[0].line, 121)
        self.assertEqual(flaws[0].cwe, "CWE-114")
        self.assertEqual(flaws[0].path, "CWE114_Process_Control__w32_char_01.c")

    def test_a_file_may_carry_several_flaws(self):
        grouped = jm.index(archive_with(SIMPLE))
        self.assertEqual(
            [f.line for f in grouped["CWE121_Stack_Based_Buffer_Overflow__x_01.c"]],
            [33, 44])

    def test_a_file_with_no_flaw_is_absent_not_empty(self):
        # The `good` half of a pair has no <flaw>. Callers must be able to
        # tell "no flaws listed" from "file not in the manifest".
        grouped = jm.index(archive_with(SIMPLE))
        self.assertNotIn("CWE121_Stack_Based_Buffer_Overflow__x_01b.c", grouped)

    def test_cwe_is_normalised_without_padding(self):
        # "CWE-114", never "CWE-0114": the rest of the project spells them
        # unpadded, and a mismatch would silently join nothing.
        flaws = list(jm.iter_flaws(archive_with(SIMPLE)))
        self.assertTrue(all(f.cwe.startswith("CWE-") for f in flaws))
        self.assertNotIn("0", [f.cwe.split("-")[1][0] for f in flaws])

    def test_summary_counts(self):
        report = jm.summarise(archive_with(SIMPLE))
        self.assertEqual(report["flaws"], 3)
        self.assertEqual(report["files_with_flaws"], 2)
        self.assertEqual(report["cwe_classes"], 2)


class Refusals(unittest.TestCase):
    def test_entity_expansion_is_refused_before_parsing(self):
        with self.assertRaises(jm.ManifestError) as caught:
            list(jm.iter_flaws(archive_with(BILLION_LAUGHS)))
        self.assertIn("DOCTYPE", str(caught.exception))

    def test_missing_manifest_is_reported(self):
        path = archive_with(b"not a manifest", name="C/readme.txt")
        with self.assertRaises(jm.ManifestError):
            list(jm.iter_flaws(path))

    def test_malformed_xml_is_reported(self):
        with self.assertRaises(jm.ManifestError) as caught:
            list(jm.iter_flaws(archive_with(b"<container><testcase>")))
        self.assertIn("well-formed", str(caught.exception))

    def test_a_missing_archive_is_reported(self):
        with self.assertRaises(jm.ManifestError):
            list(jm.iter_flaws("no-such-archive.zip"))

    def test_nonsense_line_numbers_are_dropped_not_crashed_on(self):
        manifest = SIMPLE.replace(b'line="121"', b'line="not-a-number"')
        flaws = list(jm.iter_flaws(archive_with(manifest)))
        self.assertEqual(len(flaws), 2)


class AgainstTheRealArchive(unittest.TestCase):
    def setUp(self):
        if not REAL_ARCHIVE.is_file():
            self.skipTest("the 146 MB NIST archive is not on this machine")

    def test_the_shipped_manifest_parses(self):
        report = jm.summarise(str(REAL_ARCHIVE))
        self.assertGreater(report["flaws"], 60_000)
        self.assertGreater(report["cwe_classes"], 100)

    def test_flaw_lines_land_inside_their_files(self):
        """A line number past the end of its file would be a parse error."""
        grouped = jm.index(str(REAL_ARCHIVE))
        checked = 0
        with zipfile.ZipFile(REAL_ARCHIVE) as archive:
            for info in archive.infolist():
                base = info.filename.rsplit("/", 1)[-1]
                flaws = grouped.get(base)
                if not flaws or "/testcases/" not in info.filename:
                    continue
                lines = archive.read(info).decode("utf-8", "replace").count("\n")
                for flaw in flaws:
                    self.assertLessEqual(
                        flaw.line, lines + 1,
                        "%s: flaw at line %d but the file has %d lines"
                        % (base, flaw.line, lines))
                checked += 1
                if checked >= 200:
                    return
        self.assertGreater(checked, 0, "no manifest entry matched a testcase")


if __name__ == "__main__":
    unittest.main(verbosity=2)
