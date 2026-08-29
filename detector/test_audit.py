#!/usr/bin/env python3
"""Tests for audit.py -- the whole-tree code reviewer. Offline/deterministic."""
import os
import shutil
import tempfile
import unittest

import audit

BUGGY_PY = "def handle(u, cache={}):\n    if u == None:\n        return None\n    return total\n"
BUGGY_C = '#include <stdio.h>\nint main(){ char b[8]; gets(b); return 0; }\n'
CLEAN_PY = "x = 1\nprint(x)\n"


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "src"))
        with open(os.path.join(self.d, "src", "svc.py"), "w") as fh:
            fh.write(BUGGY_PY)
        with open(os.path.join(self.d, "src", "io.c"), "w") as fh:
            fh.write(BUGGY_C)
        with open(os.path.join(self.d, "ok.py"), "w") as fh:
            fh.write(CLEAN_PY)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_scans_the_whole_tree_with_both_engines(self):
        result = audit.audit([self.d])
        self.assertEqual(result["files_scanned"], 3)
        rules = {f.rule for f in result["findings"]}
        self.assertIn("undefined-name", rules)   # deepscan (AST) on the .py
        self.assertIn("unsafe-libc", rules)        # detect (regex) on the .c
        self.assertIn("py-mutable-default", rules)

    def test_clean_file_contributes_no_findings(self):
        result = audit.audit([self.d])
        self.assertNotIn(os.path.join(self.d, "ok.py"), result["per_file"])

    def test_severity_filter(self):
        result = audit.audit([self.d], min_severity="HIGH")
        self.assertTrue(result["findings"])
        self.assertTrue(all(f.severity == "HIGH" for f in result["findings"]))

    def test_text_report_has_a_summary(self):
        text = audit.report_text(audit.audit([self.d]), self.d)
        self.assertIn("Code review", text)
        self.assertIn("HIGH", text)
        self.assertIn("files needing the most attention", text)

    def test_markdown_report_is_a_deliverable(self):
        md = audit.report_markdown(audit.audit([self.d]), self.d)
        self.assertIn("# Code review", md)
        self.assertIn("## Summary", md)
        self.assertIn("## Findings", md)
        self.assertIn("| Severity | Count |", md)

    def test_clean_tree_says_so(self):
        clean = tempfile.mkdtemp()
        try:
            with open(os.path.join(clean, "a.py"), "w") as fh:
                fh.write(CLEAN_PY)
            result = audit.audit([clean])
            self.assertEqual(result["findings"], [])
            self.assertIn("no issues found", audit.report_text(result, clean))
        finally:
            shutil.rmtree(clean, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
