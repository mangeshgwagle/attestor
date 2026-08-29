import tempfile
import unittest
from pathlib import Path

import scanengine


class ScanEngineTests(unittest.TestCase):
    def test_missing_input_is_failed_not_clean(self):
        result = scanengine.scan(["definitely-missing-attestor-path"], jobs=1, use_cache=False)
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.errors)

    def test_incremental_cache_hits_on_second_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "app.py"
            source.write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
            cache = str(Path(tmp) / "cache.json")
            first = scanengine.scan([tmp], jobs=1, use_cache=True, cache_path=cache)
            second = scanengine.scan([tmp], jobs=1, use_cache=True, cache_path=cache)
            self.assertEqual(first.cache_hits, 0)
            self.assertEqual(second.cache_hits, second.files_scanned)

    def test_python_syntax_is_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            result = scanengine.scan([str(path)], jobs=1, use_cache=False)
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.files[0].verification, "failed")

    def test_extended_language_finding_is_normalized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "main.tf"
            path.write_text('cidr_blocks = ["0.0.0.0/0"]\n', encoding="utf-8")
            result = scanengine.scan([str(path)], jobs=1, use_cache=False)
            self.assertIn("tf-public-ingress", {issue.rule for issue in result.issues})

    def test_binary_and_oversized_inputs_are_not_silently_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "blob.py").write_bytes(b"\x00\x01")
            result = scanengine.scan([tmp], jobs=1, use_cache=False)
            self.assertEqual(result.status, "unsupported")
            self.assertTrue(result.skipped)

    def test_exports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text("FROM python:latest\n", encoding="utf-8")
            result = scanengine.scan([tmp], jobs=1, use_cache=False)
            self.assertEqual(scanengine.to_sarif(result)["version"], "2.1.0")
            self.assertIn("Attestor 3.0", scanengine.render_markdown(result))
            self.assertIn("<table>", scanengine.render_html(result))


if __name__ == "__main__":
    unittest.main()
