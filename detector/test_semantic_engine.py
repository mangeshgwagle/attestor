#!/usr/bin/env python3
"""Precision and performance contracts for Attestor 3.0 semantic analysis."""
from __future__ import annotations

import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import semantic_engine


def write_project(root: Path, files: dict[str, str]) -> None:
    for relative, source in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")


class WholeProgramGraphTests(unittest.TestCase):
    def test_cross_file_route_alias_and_three_function_taint_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "routes.py": (
                    "import service\n"
                    "@app.get('/run/{command}')\n"
                    "def run(command):\n"
                    "    return service.dispatch(command)\n"),
                "service.py": (
                    "from runner import execute as do_execute\n"
                    "def dispatch(value):\n"
                    "    alias = value\n"
                    "    return do_execute(alias)\n"),
                "runner.py": (
                    "import os\n"
                    "def execute(command):\n"
                    "    return os.system(command)\n"),
            })
            report = semantic_engine.analyze_repository(root)

        self.assertEqual(report["version"], "3.0.0")
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["metrics"]["python_modules"], 3)
        self.assertEqual(report["metrics"]["semantic_findings"], 1, report["findings"])
        finding = report["findings"][0]
        self.assertEqual(finding["sink"]["name"], "os.system")
        self.assertEqual(finding["source"]["kind"], "route.parameter")
        self.assertEqual(finding["call_depth"], 2)
        self.assertEqual([step["kind"] for step in finding["evidence"]],
                         ["source", "call", "call", "sink"])
        self.assertTrue(all(edge["resolved"] for edge in report["call_graph"]["edges"]
                            if edge["callee"] in {"service.dispatch", "do_execute"}))

    def test_source_returned_by_imported_helper_reaches_code_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "source.py": (
                    "from flask import request\n"
                    "def read_command():\n"
                    "    value = request.args.get('command')\n"
                    "    return value\n"),
                "sink.py": (
                    "from source import read_command as get_command\n"
                    "def handle():\n"
                    "    command = get_command()\n"
                    "    return eval(command)\n"),
            })
            report = semantic_engine.analyze_repository(root)
        self.assertEqual(len(report["findings"]), 1)
        finding = report["findings"][0]
        self.assertEqual(finding["rule"], "semantic-taint/code")
        self.assertEqual(finding["cwe"], "CWE-95")
        self.assertEqual(finding["call_depth"], 1)

    def test_import_cycles_classes_routes_and_control_flow_are_modeled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "a.py": (
                    "import b\n"
                    "class Runner:\n"
                    "    def execute(self, value):\n"
                    "        if value:\n"
                    "            return eval(value)\n"
                    "        return None\n"
                    "@app.get('/x/{value}')\n"
                    "def route(value):\n"
                    "    runner = Runner()\n"
                    "    return runner.execute(value)\n"),
                "b.py": "import a\ndef ok():\n    return 1\n",
            })
            report = semantic_engine.analyze_repository(root)
        self.assertEqual(report["module_graph"]["cycles"], [["a", "b"]])
        self.assertIn("a.Runner", {row["name"] for row in report["symbols"]["classes"]})
        self.assertIn("a.route", report["entrypoints"])
        self.assertIn("a.Runner.execute", report["reachable_functions"])
        self.assertEqual(report["control_flow"]["a.Runner.execute"]["cyclomatic_complexity"], 2)
        self.assertEqual(len(report["findings"]), 1)

    def test_package_root_relative_import_resolves(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp, "example_pkg")
            write_project(root, {
                "__init__.py": "from .worker import work\n",
                "worker.py": "def work(value):\n    return value.strip()\n",
                "api.py": (
                    "from .worker import work\n"
                    "def handle(value):\n"
                    "    return work(value)\n"),
            })
            report = semantic_engine.analyze_repository(root)
        self.assertIn("example_pkg.worker", report["module_graph"]["nodes"])
        edge = next(item for item in report["call_graph"]["edges"] if item["callee"] == "work")
        self.assertEqual(edge["target"], "example_pkg.worker.work")

    def test_function_alias_is_resolved_without_executing_assignment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "runner.py": "import os\ndef execute(value):\n    os.system(value)\n",
                "app.py": (
                    "from flask import request\n"
                    "from runner import execute\n"
                    "def handle():\n"
                    "    invoke = execute\n"
                    "    return invoke(request.form.get('cmd'))\n"),
            })
            report = semantic_engine.analyze_repository(root)
        self.assertEqual(len(report["findings"]), 1)
        edge = next(item for item in report["call_graph"]["edges"] if item["callee"] == "invoke")
        self.assertEqual(edge["target"], "runner.execute")


class TaintPrecisionTests(unittest.TestCase):
    def analyze_source(self, source: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "app.py")
            path.write_text(source, encoding="utf-8")
            return semantic_engine.analyze_repository(tmp)

    def test_reassignment_kills_taint(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def safe():\n"
            "    command = request.args.get('cmd')\n"
            "    command = 'fixed-command'\n"
            "    return os.system(command)\n")
        self.assertEqual(report["findings"], [])
        self.assertGreaterEqual(report["data_flow"]["app.safe"]["reassignments"], 1)

    def test_alias_then_reassignment_kills_only_reassigned_name(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def unsafe():\n"
            "    command = request.args.get('cmd')\n"
            "    alias = command\n"
            "    command = 'fixed'\n"
            "    return os.system(alias)\n")
        self.assertEqual(len(report["findings"]), 1)

    def test_context_specific_shell_sanitizer_and_parameterized_sql_are_safe(self):
        report = self.analyze_source(
            "from flask import request\nimport os, shlex\n"
            "def safe(cursor):\n"
            "    value = request.args.get('value')\n"
            "    os.system(shlex.quote(value))\n"
            "    cursor.execute('SELECT * FROM t WHERE id=?', (value,))\n")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["data_flow"]["app.safe"]["sanitized_assignments"], 0)

    def test_wrong_context_sanitizer_does_not_hide_command_injection(self):
        report = self.analyze_source(
            "from flask import request\nimport os, html\n"
            "def unsafe():\n"
            "    value = html.escape(request.args.get('cmd'))\n"
            "    os.system(value)\n")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["rule"], "semantic-taint/command")

    def test_branch_join_keeps_possible_unsafe_path(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def maybe(trusted):\n"
            "    command = request.args.get('cmd')\n"
            "    if trusted:\n"
            "        command = 'fixed'\n"
            "    os.system(command)\n")
        self.assertEqual(len(report["findings"]), 1)

    def test_safe_constant_and_comparison_result_are_not_tainted(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def safe():\n"
            "    requested = request.args.get('cmd')\n"
            "    allowed = requested == 'status'\n"
            "    os.system('status' if allowed else 'help')\n")
        self.assertEqual(report["findings"], [])

    def test_tainted_mapping_key_does_not_taint_allowlisted_mapping_value(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def safe():\n"
            "    requested = request.args.get('operation')\n"
            "    command = {'health': 'status', 'help': 'help'}.get(requested, 'help')\n"
            "    os.system(command)\n")
        self.assertEqual(report["findings"], [])

    def test_unreachable_sink_after_return_is_not_reported(self):
        report = self.analyze_source(
            "from flask import request\nimport os\n"
            "def safe():\n"
            "    value = request.args.get('cmd')\n"
            "    if value:\n"
            "        return 'yes'\n"
            "    else:\n"
            "        return 'no'\n"
            "    os.system(value)\n")
        self.assertEqual(report["findings"], [])
        self.assertIn(9, report["control_flow"]["app.safe"]["unreachable_lines"])


class FrontendSafetyTests(unittest.TestCase):
    def test_commands_are_argument_vectors_with_explicit_no_execution_modes(self):
        root = Path(tempfile.gettempdir(), "folder with spaces")
        cases = {
            "javascript": "--check", "typescript": "--noEmit",
            "c": "-fsyntax-only", "cpp": "-fsyntax-only", "java": "-proc:none",
            "csharp": "/noconfig", "ruby": "-c", "php": "-l",
            "swift": "-parse", "shell": "-n", "rust": "--check",
        }
        for language, required in cases.items():
            with self.subTest(language=language):
                command = semantic_engine.build_frontend_command(
                    root / ("target." + language), language, executable="parser", output_dir=root)
                self.assertIsInstance(command, list)
                self.assertIn(required, command)
                self.assertEqual(command[-1], str((root / ("target." + language)).resolve()))

    def test_json_adapter_reports_errors_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good.json"; bad = root / "bad.json"
            good.write_text('{"ok": true}', encoding="utf-8")
            bad.write_text('{broken', encoding="utf-8")
            rows = semantic_engine.run_frontend_checks([bad, good], root)
        self.assertEqual({Path(row["path"]).name: row["status"] for row in rows},
                         {"bad.json": "failed", "good.json": "passed"})
        self.assertTrue(all(row["tool"] == "python-json" for row in rows))

    def test_python_frontend_adapter_rejects_invalid_syntax(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "broken.py")
            path.write_text("def broken(:\n", encoding="utf-8")
            row = semantic_engine.run_frontend_checks([path], tmp)[0]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["tool"], "python-ast")

    def test_javascript_check_cannot_execute_target_side_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "EXECUTED"
            script = root / "payload.js"
            script.write_text(
                "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'bad');\n",
                encoding="utf-8")
            row = semantic_engine.run_frontend_checks([script], root)[0]
            self.assertIn(row["status"], {"passed", "unavailable"}, row)
            self.assertFalse(marker.exists(), "syntax front end executed target JavaScript")
            if row["status"] == "passed":
                self.assertIn("--check", row["command"])

    def test_external_frontend_is_always_shell_false_bounded_and_noninteractive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "check.sh")
            path.write_text("if true; then echo ok; fi\n", encoding="utf-8")
            completed = semantic_engine.subprocess.CompletedProcess([], 0, "", "")
            with mock.patch.object(semantic_engine.shutil, "which", return_value="/safe/bash"), \
                    mock.patch.object(semantic_engine.subprocess, "run", return_value=completed) as run:
                row = semantic_engine.run_frontend_checks([path], tmp, timeout=1.5)[0]
        self.assertEqual(row["status"], "passed")
        _, kwargs = run.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["stdin"], semantic_engine.subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 1.5)
        self.assertNotIn("BASH_ENV", kwargs["env"])
        self.assertIn("-n", run.call_args.args[0])


class ReportContractTests(unittest.TestCase):
    def test_report_is_json_serializable_and_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root, {
                "pkg/__init__.py": "from .worker import work\n",
                "pkg/worker.py": "def work(value):\n    return value.strip()\n",
            })
            first = semantic_engine.analyze_repository(root)
            second = semantic_engine.analyze_repository(root)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(json.dumps(first)), first)
        self.assertFalse(first["analysis"]["target_code_executed"])

    def test_finding_fingerprint_is_stable_when_repository_moves(self):
        source = (
            "from flask import request\nimport os\n"
            "def unsafe():\n    os.system(request.args.get('cmd'))\n")
        with tempfile.TemporaryDirectory() as tmp:
            one = Path(tmp, "one"); two = Path(tmp, "two")
            write_project(one, {"app.py": source})
            write_project(two, {"app.py": source})
            first = semantic_engine.analyze_repository(one)
            second = semantic_engine.analyze_repository(two)
        self.assertEqual(first["findings"][0]["fingerprint"],
                         second["findings"][0]["fingerprint"])

    def test_parse_error_is_explicit_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.py").write_text("def broken(:\n", encoding="utf-8")
            report = semantic_engine.analyze_repository(tmp)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["metrics"]["parse_errors"], 1)
        self.assertEqual(report["files"][0]["status"], "parse-error")

    def test_cli_json_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "clean.py").write_text("def clean():\n    return 1\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                result = semantic_engine.main([tmp, "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue())["schema"], semantic_engine.SCHEMA)

    def test_medium_repository_performance_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            functions = ["def function_%d(value):\n    return value.strip()\n" % index
                         for index in range(250)]
            Path(root, "many.py").write_text("\n".join(functions), encoding="utf-8")
            started = time.perf_counter()
            report = semantic_engine.analyze_repository(root)
            elapsed = time.perf_counter() - started
        self.assertEqual(report["metrics"]["functions"], 250)
        self.assertEqual(report["findings"], [])
        self.assertLess(elapsed, 5.0, "semantic analysis took %.3fs" % elapsed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
