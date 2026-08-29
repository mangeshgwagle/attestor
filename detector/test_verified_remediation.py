import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import runtime_lab
import verified_remediation as remediation


class VerifiedRemediationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.project.mkdir()

    def write(self, relative, source):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8", newline="")
        return path

    def verify(self, source, rule, line, **options):
        self.write("app.py", source)
        return remediation.verify_remediation(
            self.project, "app.py", [{"rule": rule, "line": line}],
            fuzz_cases=3, **options)

    def test_eval_fix_returns_full_source_diff_and_deterministic_evidence(self):
        source = "def parse(value):\n    return eval(value)\n"
        report = self.verify(source, "dangerous-eval", 2)
        repeated = remediation.propose_fixes(
            source, "app.py", [{"rule": "dangerous-eval", "line": 2}])

        self.assertTrue(report.accepted, report.reasons)
        self.assertTrue(report.complete)
        self.assertEqual(report.proposal.improved_source,
                         "import ast\ndef parse(value):\n    return ast.literal_eval(value)\n")
        self.assertEqual(report.proposal.improved_source, repeated.improved_source)
        self.assertEqual(report.proposal.unified_diff, repeated.unified_diff)
        self.assertIn("--- a/app.py", report.proposal.unified_diff)
        self.assertIn("+++ b/app.py", report.proposal.unified_diff)
        self.assertEqual({item.rule for item in report.validation.resolved_issues},
                         {"dangerous-eval"})
        self.assertFalse(report.validation.new_issues)
        self.assertTrue(all(item.passed for item in report.probes))
        self.assertEqual({item.seed for item in report.probes}, {remediation.DEFAULT_SEED})
        self.assertEqual(self.project.joinpath("app.py").read_text(encoding="utf-8"), source)

    def test_required_import_preserves_shebang_docstring_and_future_order(self):
        source = (
            "#!/usr/bin/env python3\n"
            '"""module documentation"""\n'
            "from __future__ import annotations\n"
            "def parse(value):\n"
            "    return eval(value)\n"
        )
        proposal = remediation.propose_fixes(
            source, "app.py", [{"rule": "dangerous-eval", "line": 5}])

        self.assertTrue(proposal.changed)
        expected_prefix = (
            "#!/usr/bin/env python3\n"
            '"""module documentation"""\n'
            "from __future__ import annotations\n"
            "import ast\n"
        )
        self.assertTrue(proposal.improved_source.startswith(expected_prefix))
        compile(proposal.improved_source, "app.py", "exec")

    def test_rebound_standard_library_name_blocks_import_based_fix(self):
        source = "ast = object()\ndef parse(value):\n    return eval(value)\n"
        proposal = remediation.propose_fixes(
            source, "app.py", [{"rule": "dangerous-eval", "line": 3}])

        self.assertFalse(proposal.changed)
        self.assertIn("rebound", proposal.refusals[0].reason)

    def test_yaml_tls_debug_and_safe_subprocess_fixers_are_ast_confirmed(self):
        cases = (
            ("import yaml\ndef load(v):\n    return yaml.load(v)\n",
             "py-yaml-load", 3, "yaml.safe_load(v)"),
            ("import httpx\nclient = httpx.Client(verify=False)\n",
             "adv-py-httpx-no-tls", 2, "verify=True"),
            ("DEBUG = True\n", "debug-enabled", 1, "DEBUG = False"),
            ("import subprocess\nsubprocess.run(['tool', 'arg'], shell=True, timeout=2)\n",
             "py-subprocess-shell", 2, "shell=False"),
        )
        for source, rule, line, expected in cases:
            with self.subTest(rule=rule):
                proposal = remediation.propose_fixes(
                    source, "app.py", [{"rule": rule, "line": line}])
                self.assertTrue(proposal.changed, proposal.refusals)
                self.assertIn(expected, proposal.improved_source)
                compile(proposal.improved_source, "app.py", "exec")

        unsafe_shell = remediation.propose_fixes(
            "import subprocess\nsubprocess.run(command, shell=True)\n", "app.py",
            [{"rule": "py-subprocess-shell", "line": 2}])
        self.assertFalse(unsafe_shell.changed)
        self.assertIn("explicit argument vector", unsafe_shell.refusals[0].reason)

    def test_sqlite_f_string_becomes_parameterized_but_driver_ambiguity_is_refused(self):
        source = (
            "import sqlite3\n"
            "def lookup(cursor, user_id):\n"
            "    return cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
        )
        proposal = remediation.propose_fixes(
            source, "app.py", [{"rule": "py-sql-injection", "line": 3}])

        self.assertTrue(proposal.changed, proposal.refusals)
        self.assertIn("cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                      proposal.improved_source)
        self.assertNotIn("f\"SELECT", proposal.improved_source)

        unknown_driver = remediation.propose_fixes(
            "def f(cursor, value):\n    return cursor.execute(f'SELECT {value}')\n",
            "app.py", [{"rule": "py-sql-injection", "line": 2}])
        quoted_value = remediation.propose_fixes(
            "import sqlite3\ndef f(c, v):\n    return c.execute(f\"SELECT '{v}'\")\n",
            "app.py", [{"rule": "py-sql-injection", "line": 3}])
        identifier = remediation.propose_fixes(
            "import sqlite3\ndef f(c, column):\n    return c.execute(f\"SELECT * FROM t ORDER BY {column}\")\n",
            "app.py", [{"rule": "py-sql-injection", "line": 3}])
        self.assertFalse(unknown_driver.changed)
        self.assertIn("driver-specific", unknown_driver.refusals[0].reason)
        self.assertFalse(quoted_value.changed)
        self.assertIn("value position", quoted_value.refusals[0].reason)
        self.assertFalse(identifier.changed)
        self.assertIn("identifiers", identifier.refusals[0].reason)

    def test_hardcoded_secret_is_externalized_and_never_echoed_in_public_evidence(self):
        secret = "sk-live-" + "do-not-repeat-123456789"
        source = "API_KEY = %r\n" % secret
        report = self.verify(source, "hardcoded-secret", 1)
        rendered = remediation.render(report)
        encoded = json.dumps(remediation.report_dict(report), sort_keys=True)

        self.assertTrue(report.accepted, report.reasons)
        self.assertIn("import os", report.proposal.improved_source)
        self.assertIn("API_KEY = os.environ['API_KEY']", report.proposal.improved_source)
        self.assertNotIn(secret, report.proposal.improved_source)
        self.assertNotIn(secret, report.proposal.unified_diff)
        self.assertNotIn(secret, rendered)
        self.assertNotIn(secret, encoded)
        self.assertIn("<redacted-secret>", report.proposal.unified_diff)

    def test_comments_strings_wrong_lines_and_ambiguous_rules_are_refused(self):
        source = (
            "text = 'eval(value)'\n"
            "# eval(value)\n"
            "def parse(value):\n"
            "    return value\n"
        )
        proposal = remediation.propose_fixes(
            source, "app.py", [
                {"rule": "dangerous-eval", "line": 1},
                {"rule": "dangerous-eval", "line": 2},
                {"rule": "weak-hash", "line": 4},
                {"rule": "unknown-rule", "line": 999},
            ])

        self.assertFalse(proposal.changed)
        self.assertEqual(len(proposal.refusals), 4)
        self.assertEqual(proposal.improved_source, source)
        self.assertNotIn("ast.literal_eval", proposal.improved_source)

    def test_non_python_and_syntax_broken_sources_are_not_rewritten(self):
        javascript = remediation.propose_fixes(
            "eval(input);\n", "app.js", [{"rule": "dangerous-eval", "line": 1}])
        broken = remediation.propose_fixes(
            "def broken(:\n", "app.py", [{"rule": "dangerous-eval", "line": 1}])

        self.assertFalse(javascript.changed)
        self.assertEqual(javascript.language, "unsupported")
        self.assertIn("require Python", javascript.refusals[0].reason)
        self.assertFalse(broken.changed)
        self.assertEqual(broken.refusals[0].rule, "syntax-error")

    def test_selected_tests_require_authorization_run_in_copy_and_may_not_change_target(self):
        source = "def parse(value):\n    return eval(value)\n"
        self.write("app.py", source)
        self.write(
            "test_app.py",
            "import unittest\nfrom app import parse\n"
            "class TestParse(unittest.TestCase):\n"
            "    def test_data(self): self.assertEqual(parse('[1, 2]'), [1, 2])\n",
        )
        command = [sys.executable, "-m", "unittest", "discover", "-s", "."]
        with self.assertRaises(PermissionError):
            remediation.verify_remediation(
                self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
                test_command=command, fuzz_cases=2)
        report = remediation.verify_remediation(
            self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
            test_command=command, authorize_tests=True, fuzz_cases=2)

        self.assertTrue(report.accepted, report.reasons)
        self.assertEqual(report.selected_tests.status, "passed")
        self.assertEqual(report.selected_tests.network_policy, "python-language-guard")
        self.assertEqual(self.project.joinpath("app.py").read_text(encoding="utf-8"), source)

        modifying = remediation.verify_remediation(
            self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
            test_command=[sys.executable, "-c",
                          "from pathlib import Path; Path('app.py').write_text('changed')"],
            authorize_tests=True, fuzz_cases=2)
        self.assertFalse(modifying.accepted)
        self.assertIn("selected tests modified the candidate target", modifying.reasons)
        self.assertEqual(self.project.joinpath("app.py").read_text(encoding="utf-8"), source)

    def test_failing_selected_test_rejects_candidate_with_bounded_evidence(self):
        source = "def parse(value):\n    return eval(value)\n"
        report = self.verify(
            source, "dangerous-eval", 2,
            test_command=[sys.executable, "-c", "raise SystemExit(7)"],
            authorize_tests=True,
            runtime_policy=runtime_lab.RuntimePolicy.selected_tests(max_output_bytes=128))

        self.assertFalse(report.accepted)
        self.assertEqual(report.selected_tests.status, "failed")
        self.assertEqual(report.selected_tests.returncode, 7)
        self.assertTrue(any("selected tests did not pass" in item for item in report.reasons))

    def test_static_regression_and_failed_assurance_probe_reject_candidate(self):
        original = "def parse(value):\n    return eval(value)\n"
        self.write("app.py", original)
        malicious = "import ast\ndef parse(value):\n    eval(value)\n    return eval(value)\n"
        proposal = remediation.FixProposal(
            remediation.ENGINE_VERSION, "app.py", "python",
            remediation._sha(original), remediation._sha(malicious), malicious,
            "synthetic diff", (
                remediation.FixEdit("dangerous-eval", 2, "synthetic", "eval", "ast.literal_eval", "test", mutation_before="eval"),
            ), ())
        with mock.patch.object(remediation, "propose_fixes", return_value=proposal):
            report = remediation.verify_remediation(
                self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
                fuzz_cases=2)

        self.assertFalse(report.accepted)
        self.assertTrue(report.validation.new_issues)
        self.assertIn("candidate introduced new static findings", report.reasons)
        self.assertTrue(any(not probe.passed for probe in report.probes))

    def test_apply_needs_consent_creates_backup_and_supports_safe_rollback(self):
        original = "def parse(value):\n    return eval(value)\n"
        target = self.write("app.py", original)
        report = remediation.verify_remediation(
            self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
            fuzz_cases=2)
        with self.assertRaises(PermissionError):
            remediation.apply_remediation(report)

        applied = remediation.apply_remediation(
            report, authorized=True, backup_root=self.base / "backups")
        self.assertTrue(applied.applied)
        self.assertIn("ast.literal_eval", target.read_text(encoding="utf-8"))
        self.assertEqual(Path(applied.backup).read_text(encoding="utf-8"), original)
        with self.assertRaises(PermissionError):
            remediation.rollback_remediation(applied)
        rolled_back = remediation.rollback_remediation(applied, authorized=True)
        self.assertTrue(rolled_back.rolled_back)
        self.assertEqual(target.read_text(encoding="utf-8"), original)

    def test_stale_project_prevents_apply_and_rejected_report_cannot_apply(self):
        original = "def parse(value):\n    return eval(value)\n"
        target = self.write("app.py", original)
        report = remediation.verify_remediation(
            self.project, "app.py", [{"rule": "dangerous-eval", "line": 2}],
            fuzz_cases=2)
        self.write("new_file.py", "VALUE = 2\n")
        with self.assertRaises(RuntimeError):
            remediation.apply_remediation(report, authorized=True)
        self.assertEqual(target.read_text(encoding="utf-8"), original)

        refused = remediation.verify_remediation(
            self.project, "app.py", [{"rule": "weak-hash", "line": 2}],
            fuzz_cases=2)
        with self.assertRaises(ValueError):
            remediation.apply_remediation(refused, authorized=True)

    def test_render_and_json_include_reasoning_evidence_and_improved_result(self):
        report = self.verify(
            "def parse(value):\n    return eval(value)\n",
            "dangerous-eval", 2)
        text = remediation.render(report)
        payload = remediation.report_dict(report)

        self.assertIn("RESULT: ACCEPTED", text)
        self.assertIn("Improved full source", text)
        self.assertIn("Unified diff", text)
        self.assertIn("mutation:reverse-fix", text)
        self.assertEqual(payload["proposal"]["improved_source"],
                         report.proposal.improved_source)
        self.assertEqual(payload["validation"]["new_findings"], [])
        json.dumps(payload)

    def test_cli_auto_scans_and_emits_machine_readable_improved_result(self):
        self.write("app.py", "def parse(value):\n    return eval(value)\n")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = remediation.main([
                str(self.project), "app.py", "--fuzz-cases", "2", "--json"])
        payload = json.loads(stdout.getvalue())

        self.assertEqual(status, 0)
        self.assertTrue(payload["accepted"])
        self.assertIn("ast.literal_eval", payload["proposal"]["improved_source"])
        self.assertIn("@@", payload["proposal"]["unified_diff"])

    def test_in_memory_editor_adapter_filters_selection_and_returns_json_shape(self):
        source = (
            "def first(value):\n    return eval(value)\n"
            "def second(value):\n    return eval(value)\n"
        )
        findings = [
            {"rule": "dangerous-eval", "line": 2},
            {"rule": "dangerous-eval", "line": 4},
        ]
        result = remediation.improve_source(
            source, "C:/editor/unsaved.py", findings=findings,
            selection={"rule": "dangerous-eval", "line": 2}, verify=True)

        self.assertEqual(set(result), {
            "available", "accepted", "improved_source", "diff",
            "resolved_count", "remaining_count", "reasons"})
        self.assertTrue(result["available"])
        self.assertTrue(result["accepted"], result["reasons"])
        self.assertEqual(result["resolved_count"], 1)
        self.assertEqual(result["remaining_count"], 0)
        self.assertIn("ast.literal_eval(value)", result["improved_source"])
        self.assertEqual(result["improved_source"].count("eval(value)"), 2)
        # One occurrence is the suffix inside ast.literal_eval; the other finding remains untouched.
        self.assertIn("return eval(value)", result["improved_source"])
        json.dumps(result)

    def test_in_memory_adapter_refuses_unmatched_or_unverified_preview(self):
        source = "def parse(value):\n    return eval(value)\n"
        findings = [{"rule": "dangerous-eval", "line": 2}]
        unmatched = remediation.improve_source(
            source, "app.py", findings=findings,
            selection={"rule": "dangerous-eval", "line": 99})
        preview = remediation.improve_source(
            source, "app.py", findings=findings, verify=False)

        self.assertFalse(unmatched["available"])
        self.assertFalse(unmatched["accepted"])
        self.assertEqual(unmatched["improved_source"], source)
        self.assertTrue(preview["available"])
        self.assertFalse(preview["accepted"])
        self.assertIn("verification was disabled", preview["reasons"][-1])


if __name__ == "__main__":
    unittest.main()
