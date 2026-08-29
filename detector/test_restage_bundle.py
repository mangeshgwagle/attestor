#!/usr/bin/env python3
"""Security-boundary tests for the VS Code bundle restager."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import restage_bundle


class RestageSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.detector = self.root / "detector"
        self.server = self.root / "integrations" / "vscode" / "server"
        self.detector.mkdir()
        self.server.mkdir(parents=True)
        self.source = self.detector / "a.py"
        self.staged = self.server / "a.py"
        self.source.write_bytes(b"fresh\n")

    def tearDown(self):
        self.temporary.cleanup()

    def write_manifest(self, paths=("a.py",)):
        files = [{"path": path, "size": 0, "sha256": "0" * 64}
                 for path in paths]
        (self.server / restage_bundle.MANIFEST).write_text(
            json.dumps({"schema": "test", "files": files}) + "\n",
            encoding="utf-8")

    def restage(self, check_only=False):
        with mock.patch.object(restage_bundle, "_root", return_value=self.root):
            return restage_bundle.restage(check_only)

    def test_valid_staging_updates_bytes_and_digest_then_checks_clean(self):
        self.staged.write_bytes(b"old\n")
        self.write_manifest()
        self.assertEqual(self.restage(), 0)
        self.assertEqual(self.staged.read_bytes(), b"fresh\n")
        manifest = json.loads((self.server / restage_bundle.MANIFEST)
                              .read_text(encoding="utf-8"))
        item = manifest["files"][0]
        self.assertEqual(item["size"], len(b"fresh\n"))
        self.assertEqual(item["sha256"],
                         hashlib.sha256(b"fresh\n").hexdigest())
        self.assertEqual(self.restage(check_only=True), 0)

    def test_traversal_and_noncanonical_paths_are_rejected_before_writes(self):
        for unsafe in ("../outside.py", "sub/../a.py", "./a.py", "a//b.py",
                       "/absolute.py", r"C:\absolute.py", r"sub\a.py"):
            with self.subTest(path=unsafe):
                self.staged.write_bytes(b"keep\n")
                self.write_manifest(("a.py", unsafe))
                self.assertEqual(self.restage(), 2)
                self.assertEqual(self.staged.read_bytes(), b"keep\n")

    def test_case_colliding_manifest_paths_are_rejected(self):
        self.staged.write_bytes(b"keep\n")
        self.write_manifest(("a.py", "A.PY"))
        self.assertEqual(self.restage(), 2)
        self.assertEqual(self.staged.read_bytes(), b"keep\n")

    def test_nonregular_destination_is_refused_not_replaced(self):
        self.staged.mkdir()
        self.write_manifest()
        self.assertEqual(self.restage(), 2)
        self.assertTrue(self.staged.is_dir())

    def test_symlink_source_is_refused(self):
        outside = self.root / "outside.py"
        outside.write_bytes(b"outside\n")
        self.source.unlink()
        try:
            self.source.symlink_to(outside)
        except OSError as error:
            self.skipTest("file symlinks unavailable: %s" % error)
        self.write_manifest()
        self.assertEqual(self.restage(), 2)
        self.assertEqual(outside.read_bytes(), b"outside\n")
        self.assertFalse(self.staged.exists())

    def test_symlink_destination_is_refused_not_followed(self):
        outside = self.root / "outside.py"
        outside.write_bytes(b"outside\n")
        try:
            self.staged.symlink_to(outside)
        except OSError as error:
            self.skipTest("file symlinks unavailable: %s" % error)
        self.write_manifest()
        self.assertEqual(self.restage(), 2)
        self.assertEqual(outside.read_bytes(), b"outside\n")

    def test_windows_reparse_attribute_is_refused(self):
        fake = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                               st_file_attributes=0x400)
        with mock.patch.object(restage_bundle.os.path, "lexists", return_value=True), \
                mock.patch.object(restage_bundle.os, "lstat", return_value=fake):
            with self.assertRaisesRegex(restage_bundle.BundleError,
                                        "symlink/reparse"):
                restage_bundle._regular_info(self.source)

    def test_check_mode_does_not_create_a_missing_destination(self):
        self.write_manifest()
        self.assertEqual(self.restage(check_only=True), 1)
        self.assertFalse(self.staged.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
