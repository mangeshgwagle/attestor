#!/usr/bin/env python3
"""Filesystem-boundary tests for Attestor 4Kids' reversible prank mode."""
from __future__ import annotations

import json
import os
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import attestor4kids


class PrankSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_round_trip_creates_only_recorded_files(self):
        self.assertEqual(attestor4kids.prank(str(self.root), count=3, seed=4), 0)
        manifest = self.root / attestor4kids.MANIFEST
        names = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(len(names), 3)
        self.assertEqual(set(names) | {attestor4kids.MANIFEST},
                         {path.name for path in self.root.iterdir()})
        self.assertEqual(attestor4kids.unprank(str(self.root)), 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_regular_file_is_never_clobbered(self):
        name = sorted(attestor4kids.PRANKS)[0]
        existing = self.root / name
        existing.write_text("user data\n", encoding="utf-8")
        self.assertEqual(attestor4kids.prank(
            str(self.root), count=len(attestor4kids.PRANKS), seed=1), 0)
        self.assertEqual(existing.read_text(encoding="utf-8"), "user data\n")
        self.assertNotIn(name, json.loads(
            (self.root / attestor4kids.MANIFEST).read_text(encoding="utf-8")))

    def test_a_hardlinked_collision_refuses_before_writing_anything(self):
        outside = self.root.parent / (self.root.name + "-outside")
        outside.write_text("important", encoding="utf-8")
        collision = self.root / sorted(attestor4kids.PRANKS)[0]
        try:
            os.link(outside, collision)
        except OSError as error:
            outside.unlink(missing_ok=True)
            self.skipTest("hard links unavailable: %s" % error)
        try:
            with self.assertRaisesRegex(SystemExit, "hard-linked"):
                attestor4kids.prank(str(self.root),
                                count=len(attestor4kids.PRANKS), seed=2)
            self.assertEqual({path.name for path in self.root.iterdir()},
                             {collision.name})
            self.assertEqual(outside.read_text(encoding="utf-8"), "important")
        finally:
            collision.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    def test_symlinked_target_directory_is_refused(self):
        real = self.root / "real"
        link = self.root / "link"
        real.mkdir()
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError as error:
            self.skipTest("directory symlinks unavailable: %s" % error)
        with self.assertRaisesRegex(SystemExit, "symlink/reparse"):
            attestor4kids.prank(str(link), count=1)
        self.assertEqual(list(real.iterdir()), [])

    def test_windows_reparse_attribute_is_refused(self):
        fake = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700,
                               st_file_attributes=0x400)
        with mock.patch.object(attestor4kids.os, "lstat", return_value=fake):
            with self.assertRaisesRegex(SystemExit, "symlink/reparse"):
                attestor4kids._validate_directory(self.root)

    def test_symlinked_manifest_is_refused_without_touching_target(self):
        outside = self.root.parent / (self.root.name + "-manifest")
        outside.write_text("[]\n", encoding="utf-8")
        manifest = self.root / attestor4kids.MANIFEST
        try:
            manifest.symlink_to(outside)
        except OSError as error:
            outside.unlink(missing_ok=True)
            self.skipTest("file symlinks unavailable: %s" % error)
        try:
            with self.assertRaisesRegex(SystemExit, "symlink/reparse"):
                attestor4kids.prank(str(self.root), count=1)
            self.assertEqual(outside.read_text(encoding="utf-8"), "[]\n")
        finally:
            manifest.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    def test_unprank_refuses_a_hardlinked_prank_and_keeps_manifest(self):
        self.assertEqual(attestor4kids.prank(str(self.root), count=1, seed=8), 0)
        manifest = self.root / attestor4kids.MANIFEST
        name = json.loads(manifest.read_text(encoding="utf-8"))[0]
        alias = self.root / "alias.txt"
        try:
            os.link(self.root / name, alias)
        except OSError as error:
            self.skipTest("hard links unavailable: %s" % error)
        self.assertEqual(attestor4kids.unprank(str(self.root)), 1)
        self.assertTrue((self.root / name).exists())
        self.assertTrue(alias.exists())
        self.assertTrue(manifest.exists())

    def test_modified_prank_is_preserved_and_remains_in_manifest(self):
        self.assertEqual(attestor4kids.prank(str(self.root), count=1, seed=5), 0)
        manifest = self.root / attestor4kids.MANIFEST
        name = json.loads(manifest.read_text(encoding="utf-8"))[0]
        (self.root / name).write_text("the user owns this now\n", encoding="utf-8")
        self.assertEqual(attestor4kids.unprank(str(self.root)), 0)
        self.assertEqual((self.root / name).read_text(encoding="utf-8"),
                         "the user owns this now\n")
        self.assertEqual(json.loads(manifest.read_text(encoding="utf-8")),
                         [name])


if __name__ == "__main__":
    unittest.main(verbosity=2)
