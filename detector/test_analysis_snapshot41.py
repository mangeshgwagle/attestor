from __future__ import annotations

from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import analysis_snapshot41 as snapshot


class AnalysisSnapshot41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_snapshot_is_content_addressed_immutable_and_reproducible(self) -> None:
        target = self.write("src/app.py", b"print('old')\n")
        first = snapshot.capture(self.root)
        second = snapshot.capture(self.root)
        self.assertEqual(first.snapshot_sha256, second.snapshot_sha256)
        self.assertEqual(first.report(), second.report())
        self.assertEqual(first.get("src/app.py").content, b"print('old')\n")
        target.write_bytes(b"print('new')\n")
        self.assertEqual(first.get("src/app.py").content, b"print('old')\n")
        third = snapshot.capture(self.root)
        self.assertNotEqual(first.snapshot_sha256, third.snapshot_sha256)
        with self.assertRaises(FrozenInstanceError):
            first.files[0].path = "changed.py"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            first._index["x.py"] = first.files[0]  # type: ignore[index]

    def test_paths_links_exclusions_and_bounds_fail_closed(self) -> None:
        for unsafe in ("../x", "a/../x", "a//x", "./x", "/x", r"C:\x", r"\\server\x"):
            with self.subTest(unsafe=unsafe), self.assertRaises(snapshot.SnapshotError):
                snapshot.safe_relative(unsafe)
        self.write("large.py", b"x" * 20)
        self.write("node_modules/ignored.js", b"danger()")
        report = snapshot.capture(
            self.root, snapshot.SnapshotLimits(max_files=10, max_file_bytes=10,
                                               max_total_bytes=100, max_path_chars=100))
        reasons = {row["reason"] for row in report.gaps}
        self.assertIn("max-file-bytes", reasons)
        self.assertIn("excluded-directory-policy", reasons)
        self.assertFalse(report.report()["coverage"]["complete"])
        link = self.root / "linked.py"
        try:
            link.symlink_to(self.root / "large.py")
        except OSError:
            pass
        else:
            linked = snapshot.capture(self.root)
            self.assertNotIn("linked.py", {item.path for item in linked.files})
            self.assertIn("symlink-or-reparse-skipped",
                          {row["reason"] for row in linked.gaps})

    def test_mid_capture_change_becomes_gap_not_mixed_bytes(self) -> None:
        target = self.write("race.py", b"before\n")
        original = snapshot._assert_real_components
        calls = 0

        def checked(path, *, start=None):
            nonlocal calls
            result = original(path, start=start)
            if Path(path).name == "race.py":
                calls += 1
                if calls == 2:
                    target.write_bytes(b"different-size\n")
            return result

        with mock.patch.object(snapshot, "_assert_real_components", side_effect=checked):
            captured = snapshot.capture(self.root)
        self.assertNotIn("race.py", {item.path for item in captured.files})
        self.assertIn("file-changed-during-capture",
                      {row["reason"] for row in captured.gaps})

    def test_multiply_linked_file_is_not_read_into_the_snapshot(self) -> None:
        outside = Path(self.tmp.name).parent / (self.root.name + "-outside.txt")
        alias = self.root / "alias.txt"
        outside.write_bytes(b"outside-hardlink-canary")
        try:
            os.link(outside, alias)
        except OSError as exc:
            outside.unlink(missing_ok=True)
            self.skipTest("hard links are unavailable: %s" % type(exc).__name__)
        try:
            captured = snapshot.capture(self.root)
            self.assertNotIn("alias.txt", {item.path for item in captured.files})
            self.assertIn(
                "multiple-hard-links-skipped",
                {row["reason"] for row in captured.gaps},
            )
            self.assertNotIn(
                b"outside-hardlink-canary",
                {item.content for item in captured.files},
            )
        finally:
            alias.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    def test_limits_and_gaps_participate_in_snapshot_identity(self) -> None:
        self.write("a.py", b"a=1\n")
        broad = snapshot.capture(self.root)
        narrow = snapshot.capture(
            self.root, snapshot.SnapshotLimits(max_files=1, max_file_bytes=1024,
                                               max_total_bytes=1024, max_path_chars=1024))
        smaller_gap_budget = snapshot.capture(
            self.root, snapshot.SnapshotLimits(max_gaps=1))
        smaller_directory_budget = snapshot.capture(
            self.root, snapshot.SnapshotLimits(max_entries_per_directory=1))
        self.assertNotEqual(broad.snapshot_sha256, narrow.snapshot_sha256)
        self.assertNotEqual(broad.snapshot_sha256,
                            smaller_gap_budget.snapshot_sha256)
        self.assertNotEqual(broad.snapshot_sha256,
                            smaller_directory_budget.snapshot_sha256)
        valid, errors = snapshot.verify_report(broad.report())
        self.assertTrue(valid, errors)
        self.assertEqual(broad.report()["limits"]["max_gaps"], 20_000)
        self.assertEqual(
            broad.report()["limits"]["max_entries_per_directory"], 20_000)
        tampered = broad.report()
        tampered["inventory"]["file_count"] = 99
        self.assertFalse(snapshot.verify_report(tampered)[0])

        tampered_limit = broad.report()
        tampered_limit["limits"]["max_gaps"] += 1
        tampered_limit["report_sha256"] = snapshot._sha({
            key: value for key, value in tampered_limit.items()
            if key != "report_sha256"
        })
        valid, errors = snapshot.verify_report(tampered_limit)
        self.assertFalse(valid)
        self.assertIn("snapshot manifest digest mismatch", errors)

    def test_directory_entry_budget_is_bounded_and_deterministic(self) -> None:
        for name in ("e.py", "d.py", "c.py", "b.py", "a.py"):
            self.write(name, b"x=1\n")
        captured = snapshot.capture(
            self.root,
            snapshot.SnapshotLimits(
                max_files=10,
                max_file_bytes=1024,
                max_total_bytes=10_240,
                max_path_chars=1024,
                max_gaps=10,
                max_entries_per_directory=2,
            ),
        )
        self.assertEqual([item.path for item in captured.files],
                         ["a.py", "b.py"])
        self.assertIn("max-entries-per-directory",
                      {row["reason"] for row in captured.gaps})
        self.assertEqual(
            captured.report()["limits"]["max_entries_per_directory"], 2)

    def test_gap_budget_stops_with_explicit_coverage_marker(self) -> None:
        for name in ("a.py", "b.py", "c.py"):
            self.write(name, b"xx")
        captured = snapshot.capture(
            self.root,
            snapshot.SnapshotLimits(
                max_files=10,
                max_file_bytes=1,
                max_total_bytes=10,
                max_path_chars=1024,
                max_gaps=2,
                max_entries_per_directory=10,
            ),
        )
        self.assertEqual(len(captured.gaps), 2)
        self.assertEqual(
            {row["reason"] for row in captured.gaps},
            {"max-file-bytes", "max-gaps-reached"},
        )
        self.assertFalse(captured.report()["coverage"]["complete"])
        valid, errors = snapshot.verify_report(captured.report())
        self.assertTrue(valid, errors)

    def test_diff_reports_added_changed_removed_and_unchanged(self) -> None:
        self.write("same.py", b"same\n")
        changed = self.write("changed.py", b"before\n")
        removed = self.write("removed.py", b"gone\n")
        before = snapshot.capture(self.root)
        changed.write_bytes(b"after\n")
        removed.unlink()
        self.write("added.py", b"new\n")
        after = snapshot.capture(self.root)
        report = snapshot.diff(after, before)
        self.assertEqual(report["added"], ["added.py"])
        self.assertEqual(report["changed"], ["changed.py"])
        self.assertEqual(report["removed"], ["removed.py"])
        self.assertEqual(report["unchanged"], ["same.py"])


if __name__ == "__main__":
    unittest.main()
