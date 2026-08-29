from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import repository_memory


class RepositoryMemoryTests(unittest.TestCase):
    def test_snapshot_stores_hashes_and_not_source_or_absolute_paths(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); (root / "app.py").write_text("PASSWORD='do-not-store-this'\n", encoding="utf-8")
            snap = repository_memory.snapshot(root, [{"rule": "hardcoded-secret", "path": str(root / "app.py"), "line": 1,
                                                       "message": "do-not-store-this"}])
            encoded = json.dumps(snap)
            self.assertNotIn("do-not-store-this", encoded)
            self.assertNotIn(str(root), encoded)
            self.assertEqual(snap["files"][0]["path"], "app.py")
            self.assertFalse(snap["privacy"]["source_code_stored"])

    def test_compare_reports_files_findings_and_architecture(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / "app.py"; path.write_text("x = 1\n", encoding="utf-8")
            before = repository_memory.snapshot(root)
            path.write_text("def main():\n    return 2\n", encoding="utf-8")
            after = repository_memory.snapshot(root, [{"rule": "r", "path": str(path), "line": 1}])
            diff = repository_memory.compare(before, after)
            self.assertEqual(diff["files"]["changed"], ["app.py"])
            self.assertEqual(len(diff["findings"]["new"]), 1)
            self.assertTrue(diff["architecture_changed"])

    def test_single_file_snapshot_does_not_expand_to_siblings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "selected.py"
            target.write_text("value = 1\n", encoding="utf-8")
            (root / "private-sibling.py").write_text("TOKEN='do-not-read'\n", encoding="utf-8")
            snap = repository_memory.snapshot_target(target)
            self.assertEqual([row["path"] for row in snap["files"]], ["selected.py"])
            self.assertEqual(snap["scope"], {"kind": "file", "siblings_read": False})
            self.assertNotIn("private-sibling", json.dumps(snap))

    def test_memory_chain_is_tamper_evident_and_rationale_is_digest_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "memory.json"; repo_id = "a" * 64
            log = repository_memory.MemoryLog(path, repo_id, b"memory authentication key")
            event = log.append("finding-decision", "b" * 64, "fixed", "private reasoning", "SQL fix")
            self.assertNotIn("private reasoning", json.dumps(event))
            log.save()
            loaded = repository_memory.MemoryLog(path, repo_id, b"memory authentication key")
            self.assertTrue(loaded.verify())
            data = json.loads(path.read_text(encoding="utf-8")); data["events"][0]["outcome"] = "rejected"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(repository_memory.MemoryError):
                repository_memory.MemoryLog(path, repo_id, b"memory authentication key")

    def test_credential_like_labels_are_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            log = repository_memory.MemoryLog(Path(folder) / "memory.json", "c" * 64)
            event = log.append("finding-decision", "d" * 64, "deferred", "reason", "api_key=sk-proj-secret")
            self.assertEqual(event["label"], "[redacted: credential-like text]")

    def test_snapshots_from_different_repositories_cannot_compare(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            with self.assertRaises(repository_memory.MemoryError):
                repository_memory.compare(repository_memory.snapshot(one), repository_memory.snapshot(two))


if __name__ == "__main__":
    unittest.main()
