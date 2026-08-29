from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

import mayhem
import response_engine


class MayhemTests(unittest.TestCase):
    def test_vulnerable_multilanguage_project_gets_actionable_max_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.php").write_text("<?php eval($source);\n", encoding="utf-8")
            (root / "main.tf").write_text("publicly_accessible = true\n", encoding="utf-8")
            report = mayhem.run(tmp, jobs=2, use_cache=False, mutation_limit=0,
                                min_grade="F", max_high=99)
        self.assertEqual(report["status"], "action-required")
        self.assertGreater(report["summary"]["security_findings"], 0)
        self.assertTrue(report["priorities"])
        self.assertLess(report["readiness"]["score"], 100)
        text = response_engine.structured(report, "direct")
        self.assertIn("No padding", text)
        self.assertIn("Fix first", text)

    def test_mutation_is_static_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            path.write_text("def value(x):\n    return x is None\n", encoding="utf-8")
            report = mayhem.run(tmp, jobs=1, use_cache=False, mutation_limit=4,
                                min_grade="F", max_high=99)
        self.assertFalse(report["mutation"]["execution_enabled"])
        self.assertGreaterEqual(report["mutation"]["mutants"], 1)

    def test_candidate_is_verified_but_not_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.py"
            original = "def same(x):\n    return x == None\n"
            candidate = "def same(x):\n    return x is None\n"
            path.write_text(original, encoding="utf-8")
            report = mayhem.run(tmp, jobs=1, use_cache=False, mutation_limit=0,
                                min_grade="F", max_high=99, target="app.py",
                                candidate_source=candidate)
            after = path.read_text(encoding="utf-8")
        self.assertTrue(report["candidate_patch"]["accepted"], report["candidate_patch"])
        self.assertEqual(after, original)

    def test_missing_workspace_fails(self):
        report = mayhem.run("missing-mayhem-workspace", use_cache=False)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["readiness"]["score"], 0)


if __name__ == "__main__":
    unittest.main()
