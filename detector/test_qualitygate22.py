import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import qualitygate


class QualityGate22Tests(unittest.TestCase):
    def _clean_workspace(self, root: Path) -> None:
        (root / "app.py").write_text(
            "def add(left, right):\n    return left + right\n", encoding="utf-8")

    def test_gate_is_dry_by_default_even_when_command_is_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._clean_workspace(root)
            marker = root / "executed.txt"
            command = [sys.executable, "-I", "-c",
                       "from pathlib import Path; Path(r'%s').write_text('ran')" % marker]
            report = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                          test_command=command, use_cache=False)
            self.assertEqual(report.tests["status"], "not-run")
            self.assertFalse(marker.exists())

    def test_explicit_test_argv_runs_without_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._clean_workspace(root)
            report = qualitygate.evaluate(
                root, min_grade="F", max_high=99, run_tests=True,
                test_command=[sys.executable, "-I", "-c", "print('quality-ok')"],
                use_cache=False)
            self.assertEqual(report.tests["status"], "passed")
            self.assertIn("quality-ok", report.tests["output"])

    def test_high_threshold_and_grade_failures_have_specific_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "unsafe.py").write_text(
                "def dangerous(value):\n    return eval(value)\n", encoding="utf-8")
            report = qualitygate.evaluate(root, min_grade="A", max_high=0,
                                          use_cache=False)
            codes = {reason.code for reason in report.reasons}
            self.assertFalse(report.passed)
            self.assertIn("high-threshold", codes)
            self.assertIn("minimum-grade", codes)

    def test_missing_workspace_is_failed_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing"
            report = qualitygate.evaluate(missing, min_grade="F", max_high=99,
                                          use_cache=False)
            codes = {reason.code for reason in report.reasons}
            self.assertIn("invalid-workspace", codes)
            self.assertIn("scan-failed", codes)
            self.assertFalse(report.passed)

    def test_inventory_and_sbom_cover_common_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "dependencies": {"lodash": "4.17.21"},
                "devDependencies": {"eslint": "^9.0.0"},
            }), encoding="utf-8")
            (root / "Cargo.lock").write_text(
                'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.203"\n',
                encoding="utf-8")
            (root / "go.mod").write_text(
                "module example.test/app\n\nrequire example.test/lib v1.2.3\n", encoding="utf-8")
            inventory = qualitygate.inventory_dependencies(root)
            names = {(dep.ecosystem, dep.name) for dep in inventory.dependencies}
            self.assertFalse(inventory.errors)
            self.assertTrue({("pypi", "requests"), ("npm", "lodash"),
                             ("npm", "eslint"), ("cargo", "serde"),
                             ("golang", "example.test/lib")} <= names)
            sbom = qualitygate.build_sbom(root, inventory)
            self.assertEqual(sbom["bomFormat"], "CycloneDX")
            self.assertEqual(len(sbom["components"]), len(inventory.dependencies))

    def test_malformed_manifest_is_a_truthful_gate_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._clean_workspace(root)
            (root / "package.json").write_text("{not-json", encoding="utf-8")
            report = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                          use_cache=False)
            self.assertIn("inventory-error", {reason.code for reason in report.reasons})
            self.assertTrue(report.inventory.errors)

    def test_native_static_grade_does_not_invoke_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "main.c").write_text("int add(int a, int b) { return a + b; }\n",
                                         encoding="utf-8")
            with mock.patch.object(qualitygate.nativegrade.subprocess, "run",
                                   side_effect=AssertionError("compiler invoked")):
                report = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                              external_tools=False, use_cache=False)
            native = [row for row in report.grades["files"] if row["engine"] == "nativegrade"]
            self.assertEqual(len(native), 1)
            self.assertEqual(native[0]["verification"], "static-only")

    def test_invalid_explicit_command_becomes_test_failure_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._clean_workspace(root)
            report = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                          run_tests=True, test_command=["--not-an-executable"],
                                          use_cache=False)
            self.assertEqual(report.tests["status"], "error")
            self.assertIn("tests-error", {reason.code for reason in report.reasons})

    def test_bounded_test_output_and_deterministic_static_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._clean_workspace(root)
            test = qualitygate.run_test_command(
                root, [sys.executable, "-I", "-c", "print('x' * 5000)"],
                output_bytes=1024)
            self.assertTrue(test["truncated"])
            first = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                         use_cache=False)
            second = qualitygate.evaluate(root, min_grade="F", max_high=99,
                                          use_cache=False)
            self.assertEqual(qualitygate.render_json(first), qualitygate.render_json(second))
            self.assertIn("Attestor 3.0 quality gate", qualitygate.render_markdown(first))


if __name__ == "__main__":
    unittest.main()
